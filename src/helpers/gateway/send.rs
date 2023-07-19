use crate::{sync::Arc, ff::Serializable};
use dashmap::DashMap;
use futures::Stream;
use std::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll}, collections::HashMap,
};
use typenum::Unsigned;

use crate::{
    helpers::{buffers::OrderingSender,buffers::SenderStatus, buffers::GatherWaitingMessage, ChannelId, Error, Message, Role, TotalRecords},
    protocol::RecordId,
    telemetry::{
        labels::{ROLE, STEP},
        metrics::{BYTES_SENT, RECORDS_SENT},
    },
};

/// Sending end of the gateway channel.
pub struct SendingEnd<M: Message> {
    sender_role: Role,
    channel_id: ChannelId,
    inner: Arc<GatewaySender>,
    _phantom: PhantomData<M>,
}

/// Sending channels, indexed by (role, step).
#[derive(Default, Clone)]
pub(super) struct GatewaySenders {
    inner: DashMap<ChannelId, Arc<GatewaySender>>,
}

pub(super) struct GatewaySender {
    channel_id: ChannelId,
    ordering_tx: OrderingSender,
    total_records: TotalRecords,
    message_size: usize,
}

impl GatherWaitingMessage for GatewaySender {
}

pub(super) struct GatewaySendStream {
    inner: Arc<GatewaySender>,
}

impl GatewaySender {
    fn new(channel_id: ChannelId, tx: OrderingSender, total_records: TotalRecords, message_size: usize) -> Self {
        Self {
            channel_id,
            ordering_tx: tx,
            total_records,
            message_size,
        }
    }

    pub async fn send<M: Message>(&self, record_id: RecordId, msg: M) -> Result<(), Error> {
        debug_assert!(
            !self.total_records.is_unspecified(),
            "total_records cannot be unspecified when sending"
        );
        if let TotalRecords::Specified(count) = self.total_records {
            if usize::from(record_id) >= count.get() {
                return Err(Error::TooManyRecords {
                    record_id,
                    channel_id: self.channel_id.clone(),
                    total_records: self.total_records,
                });
            }
        }

        // TODO: make OrderingSender::send fallible
        // TODO: test channel close
        let i = usize::from(record_id);
        self.ordering_tx.send(i, msg).await;
        if self.total_records.is_last(record_id) {
            self.ordering_tx.close(i + 1).await;
        }
        Ok(())
    }

    fn check_idle_and_reset(&self) -> bool {
        self.ordering_tx.check_idle_and_reset()
    }

    fn get_missing_records(&self,)->String {
        let waiting_messages = self.ordering_tx.get_waiting_messages();
        let last_pending_message = waiting_messages.iter().cloned().max();
        if let None = last_pending_message {
           return String::new();
        }
        let last_pending_message = last_pending_message.unwrap();
        let SenderStatus {next, current_written , buf_size} = self.ordering_tx.get_status();
        let chunk_head = next - current_written/self.message_size;
        let chunk_size = buf_size / self.message_size;
        let chunk_count = (last_pending_message - chunk_head + chunk_size - 1) / chunk_size;
        let mut response = String::new();
        for i in 0..chunk_count {
            let chunk_response_head = format!("The next, {}-th chunk, missing: ", i);
            let mut chunk_response = Vec::new();
            for j in (chunk_head + i * chunk_size).. chunk_head + (i+1)* chunk_size {
                if !waiting_messages.contains(&j) {
                    chunk_response.push(j);
                }
            }
            if chunk_response.len() > 0 {
                response = response + &chunk_response_head + &self.compress_numbers(&chunk_response) + " if not closed early.\n";
            }
        }
        response
    }
}

impl<M: Message> SendingEnd<M> {
    pub(super) fn new(sender: Arc<GatewaySender>, role: Role, channel_id: &ChannelId) -> Self {
        Self {
            sender_role: role,
            channel_id: channel_id.clone(),
            inner: sender,
            _phantom: PhantomData,
        }
    }

    /// Sends the given message to the recipient. This method will block if there is no enough
    /// capacity to hold the message and will return only after message has been confirmed
    /// for sending.
    ///
    /// ## Errors
    /// If send operation fails or `record_id` exceeds the channel limit set by [`set_total_records`]
    /// call.
    ///
    /// [`set_total_records`]: crate::protocol::context::Context::set_total_records
    pub async fn send(&self, record_id: RecordId, msg: M) -> Result<(), Error> {
        let r = self.inner.send(record_id, msg).await;
        metrics::increment_counter!(RECORDS_SENT,
            STEP => self.channel_id.gate.as_ref().to_string(),
            ROLE => self.sender_role.as_static_str()
        );
        metrics::counter!(BYTES_SENT, M::Size::U64,
            STEP => self.channel_id.gate.as_ref().to_string(),
            ROLE => self.sender_role.as_static_str()
        );

        r
    }
}

impl GatewaySenders {
    /// Returns or creates a new communication channel. In case if channel is newly created,
    /// returns the receiving end of it as well. It must be send over to the receiver in order for
    /// messages to get through.
    pub(crate) fn get_or_create<M: Message>(
        &self,
        channel_id: &ChannelId,
        capacity: NonZeroUsize,
        total_records: TotalRecords, // TODO track children for indeterminate senders
    ) -> (Arc<GatewaySender>, Option<GatewaySendStream>) {
        assert!(!total_records.is_unspecified());
        let senders = &self.inner;
        if let Some(sender) = senders.get(channel_id) {
            (Arc::clone(&sender), None)
        } else {
            const SPARE: Option<NonZeroUsize> = NonZeroUsize::new(64);
            // a little trick - if number of records is indeterminate, set the capacity to 1.
            // Any send will wake the stream reader then, effectively disabling buffering.
            // This mode is clearly inefficient, so avoid using this mode.
            let write_size = if total_records.is_indeterminate() {
                NonZeroUsize::new(1).unwrap()
            } else {
                // capacity is defined in terms of number of elements, while sender wants bytes
                // so perform the conversion here
                capacity
                    .checked_mul(
                        NonZeroUsize::new(M::Size::USIZE)
                            .expect("Message size should be greater than 0"),
                    )
                    .expect("capacity should not overflow")
            };

            let sender = Arc::new(GatewaySender::new(
                channel_id.clone(),
                OrderingSender::new(write_size, SPARE.unwrap()),
                total_records,
                <M as Serializable>::Size::to_usize()
            ));
            if senders
                .insert(channel_id.clone(), Arc::clone(&sender))
                .is_some()
            {
                panic!("TODO - make sender creation contention less dangerous");
            }
            let stream = GatewaySendStream {
                inner: Arc::clone(&sender),
            };
            (sender, Some(stream))
        }
    }


    pub fn check_idle_and_reset(&self) -> bool {
        let mut rst = true;
        for entry in self.inner.iter() {
            rst &= entry.value().check_idle_and_reset();
         }
       rst
    }

    pub fn get_all_missing_records(&self) -> HashMap<ChannelId, String> {
        self.inner.iter()
        .filter_map(|entry|
            {
                let message = entry.value().get_missing_records();
                if message.is_empty() {
                    None
                } else {
                    Some((entry.key().clone(), message))
                }
            }
        )
        .collect()
    }
}

impl Stream for GatewaySendStream {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::get_mut(self).inner.ordering_tx.take_next(cx)
    }
}
