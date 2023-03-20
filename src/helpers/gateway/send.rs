use dashmap::DashMap;
use std::{marker::PhantomData, num::NonZeroUsize};

use crate::{
    helpers::{
        buffers::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender},
        gateway::wrapper::Wrapper,
        ChannelId, Error, Message, Role, TotalRecords,
    },
    protocol::RecordId,
    telemetry::{
        labels::{ROLE, STEP},
        metrics::RECORDS_SENT,
    },
};

/// Sending end of the gateway channel.
pub struct SendingEnd<M: Message> {
    channel_id: ChannelId,
    my_role: Role,
    ordering_tx: OrderingMpscSender<Wrapper>,
    total_records: TotalRecords,
    _phantom: PhantomData<M>,
}

/// Sending channels, indexed by (role, step).
#[derive(Default)]
pub(super) struct GatewaySenders {
    inner: DashMap<ChannelId, OrderingMpscSender<Wrapper>>,
}

impl<M: Message> SendingEnd<M> {
    pub(super) fn new(
        channel_id: ChannelId,
        my_role: Role,
        tx: OrderingMpscSender<Wrapper>,
        total_records: TotalRecords,
    ) -> Self {
        Self {
            channel_id,
            my_role,
            ordering_tx: tx,
            total_records,
            _phantom: PhantomData,
        }
    }

    /// Sends the given message to the recipient. This method will block if there is no enough
    /// capacity to hold the message and will return only after message has been confirmed
    /// for sending.
    ///
    /// ## Errors
    /// If send operation fails or [`record_id`] exceeds the channel limit set by [`set_total_records`]
    /// call.
    ///
    /// [`set_total_records`]: crate::protocol::context::Context::set_total_records
    pub async fn send(&self, record_id: RecordId, msg: M) -> Result<(), Error> {
        if let TotalRecords::Specified(count) = self.total_records {
            if usize::from(record_id) >= count.get() {
                return Err(Error::TooManyRecords {
                    record_id,
                    channel_id: self.channel_id.clone(),
                    total_records: self.total_records,
                });
            }
        }

        metrics::increment_counter!(RECORDS_SENT,
            STEP => self.channel_id.step.as_ref().to_string(),
            ROLE => self.my_role.as_static_str()
        );

        self.ordering_tx
            .send(record_id.into(), Wrapper::wrap(&msg))
            .await
            .map_err(|e| Error::send_error(self.channel_id.clone(), e))
    }
}

impl GatewaySenders {
    /// Returns or creates a new communication channel. In case if channel is newly created,
    /// returns the receiving end of it as well. It must be send over to the receiver in order for
    /// messages to get through.
    pub(crate) fn get_or_create(
        &self,
        channel_id: &ChannelId,
        capacity: NonZeroUsize,
        total_records: TotalRecords, // TODO track children for indeterminate senders
    ) -> (
        OrderingMpscSender<Wrapper>,
        Option<OrderingMpscReceiver<Wrapper>>,
    ) {
        assert!(!total_records.is_unspecified());
        let senders = &self.inner;
        if let Some(sender) = senders.get(channel_id) {
            (sender.clone(), None)
        } else {
            let (tx, rx) = ordering_mpsc::<Wrapper, _>(format!("{channel_id:?}"), capacity);
            senders.insert(channel_id.clone(), tx.clone());
            (tx, Some(rx))
        }
    }
}
