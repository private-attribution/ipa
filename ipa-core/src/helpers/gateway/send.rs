use std::{
    borrow::Borrow,
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use dashmap::{mapref::entry::Entry, DashMap};
use futures::Stream;
#[cfg(all(test, feature = "shuttle"))]
use shuttle::future as tokio;
use typenum::Unsigned;

use crate::{
    helpers::{
        buffers::OrderingSender, routing::RouteId, ChannelId, Error, Message, TotalRecords,
        Transport, TransportIdentity,
    },
    protocol::{QueryId, RecordId},
    sync::Arc,
    telemetry::{
        labels::{ROLE, STEP},
        metrics::{BYTES_SENT, RECORDS_SENT},
    },
};

/// Sending end of the gateway channel.
pub struct SendingEnd<I: TransportIdentity, M> {
    sender_id: I,
    inner: Arc<GatewaySender<I>>,
    /// This makes this struct [`Send`] even if [`M`] is not [`Sync`].
    _phantom: PhantomData<fn() -> M>,
}

/// Sending channels, indexed by identity and gate.
pub(super) struct GatewaySenders<I> {
    pub(super) inner: DashMap<ChannelId<I>, Arc<GatewaySender<I>>>,
}

pub(super) struct GatewaySender<I> {
    channel_id: ChannelId<I>,
    ordering_tx: OrderingSender,
    total_records: TotalRecords,
}

struct GatewaySendStream<I> {
    inner: Arc<GatewaySender<I>>,
}

impl<I: TransportIdentity> Default for GatewaySenders<I> {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
        }
    }
}

impl<I: TransportIdentity> GatewaySender<I> {
    fn new(channel_id: ChannelId<I>, tx: OrderingSender, total_records: TotalRecords) -> Self {
        Self {
            channel_id,
            ordering_tx: tx,
            total_records,
        }
    }

    pub async fn send<M: Message, B: Borrow<M>>(
        &self,
        record_id: RecordId,
        msg: B,
    ) -> Result<(), Error<I>> {
        debug_assert!(
            self.total_records.is_specified(),
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

    #[cfg(feature = "stall-detection")]
    pub fn waiting(&self) -> std::collections::BTreeSet<usize> {
        self.ordering_tx.waiting()
    }

    #[cfg(feature = "stall-detection")]
    pub fn total_records(&self) -> TotalRecords {
        self.total_records
    }

    pub fn is_closed(&self) -> bool {
        self.ordering_tx.is_closed()
    }

    pub async fn close(&self, at: RecordId) {
        self.ordering_tx.close(at.into()).await;
    }
}

impl<I: TransportIdentity, M: Message> SendingEnd<I, M> {
    pub(super) fn new(sender: Arc<GatewaySender<I>>, id: I) -> Self {
        Self {
            sender_id: id,
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
    #[tracing::instrument(level = "trace", "send", skip_all, fields(
        i = %record_id,
        total = %self.inner.total_records,
        to = ?self.inner.channel_id.peer,
        gate = ?self.inner.channel_id.gate.as_ref()
    ))]
    pub async fn send<B: Borrow<M>>(&self, record_id: RecordId, msg: B) -> Result<(), Error<I>> {
        let r = self.inner.send(record_id, msg).await;
        metrics::increment_counter!(RECORDS_SENT,
            STEP => self.inner.channel_id.gate.as_ref().to_string(),
            ROLE => self.sender_id.as_str(),
        );
        metrics::counter!(BYTES_SENT, M::Size::U64,
            STEP => self.inner.channel_id.gate.as_ref().to_string(),
            ROLE => self.sender_id.as_str(),
        );

        r
    }

    /// Closes the sending channel at the specified record. After calling it, it will no longer be
    /// possible to send data through it, even from another thread that uses a different instance
    /// of [`Self`].
    ///
    /// ## Panics
    /// This may panic if method is called twice and futures created by it are awaited concurrently.
    pub async fn close(&self, at: RecordId) {
        if !self.inner.is_closed() {
            self.inner.close(at).await;
        }
    }
}

impl<I: TransportIdentity> GatewaySenders<I> {
    /// Returns a communication channel for the given [`ChannelId`]. If it does not exist, it will
    /// be created using the provided [`Transport`] implementation.
    pub fn get<M: Message, T: Transport<Identity = I>>(
        &self,
        channel_id: &ChannelId<I>,
        transport: &T,
        capacity: NonZeroUsize,
        query_id: QueryId,
        total_records: TotalRecords, // TODO track children for indeterminate senders
    ) -> Arc<GatewaySender<I>> {
        assert!(
            total_records.is_specified(),
            "unspecified total records for {channel_id:?}"
        );

        // TODO: raw entry API would be nice to have here but it's not exposed yet
        match self.inner.entry(channel_id.clone()) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                let sender = Self::new_sender::<M>(capacity, channel_id.clone(), total_records);
                entry.insert(Arc::clone(&sender));

                tokio::spawn({
                    let ChannelId { peer, gate } = channel_id.clone();
                    let transport = transport.clone();
                    let stream = GatewaySendStream {
                        inner: Arc::clone(&sender),
                    };
                    async move {
                        // TODO(651): In the HTTP case we probably need more robust error handling here.
                        transport
                            .send(peer, (RouteId::Records, query_id, gate), stream)
                            .await
                            .expect("{channel_id:?} receiving end should be accepted by transport");
                    }
                });

                sender
            }
        }
    }

    fn new_sender<M: Message>(
        capacity: NonZeroUsize,
        channel_id: ChannelId<I>,
        total_records: TotalRecords,
    ) -> Arc<GatewaySender<I>> {
        // Spare buffer is not required when messages have uniform size and buffer is a
        // multiple of that size.
        const SPARE: usize = 0;
        // a little trick - if number of records is indeterminate, set the capacity to one
        // message.  Any send will wake the stream reader then, effectively disabling
        // buffering.  This mode is clearly inefficient, so avoid using this mode.
        let write_size = if total_records.is_indeterminate() {
            NonZeroUsize::new(M::Size::USIZE).unwrap()
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

        Arc::new(GatewaySender::new(
            channel_id,
            OrderingSender::new(write_size, SPARE),
            total_records,
        ))
    }
}

impl<I> Stream for GatewaySendStream<I> {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::get_mut(self).inner.ordering_tx.take_next(cx)
    }
}
