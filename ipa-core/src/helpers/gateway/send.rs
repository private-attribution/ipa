use std::{
    borrow::Borrow,
    fmt::Debug,
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use dashmap::{DashMap, mapref::entry::Entry};
use futures::Stream;
use ipa_metrics::counter;
#[cfg(all(test, feature = "shuttle"))]
use shuttle::future as tokio;
use typenum::Unsigned;

use crate::{
    helpers::{
        ChannelId, Error, GatewayConfig, Message, TotalRecords, Transport, TransportIdentity,
        buffers::OrderingSender, routing::RouteId,
    },
    protocol::{QueryId, RecordId},
    sync::Arc,
    telemetry::{
        labels::{ROLE, STEP},
        metrics::{BYTES_SENT, RECORDS_SENT},
    },
    utils::non_zero_prev_power_of_two,
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

/// Configuration for each [`GatewaySender`]. All values stored here
/// are interpreted in bytes.
#[derive(Debug, PartialEq, Eq)]
struct SendChannelConfig {
    /// The total capacity of send buffer.
    total_capacity: NonZeroUsize,
    /// The size of a single record written in [`OrderingSender`].
    /// Must be the same for all records.
    record_size: NonZeroUsize,
    /// How many bytes are read from [`OrderingSender`] when it is
    /// polled.
    read_size: NonZeroUsize,
    /// The maximum number of records that can be sent through this
    /// channel
    total_records: TotalRecords,
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
        counter!(RECORDS_SENT, 1,
            STEP => &self.inner.channel_id.gate,
            ROLE => &self.sender_id
        );
        counter!(BYTES_SENT, M::Size::U64,
            STEP => &self.inner.channel_id.gate,
            ROLE => &self.sender_id
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
        config: GatewayConfig,
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
                let config = SendChannelConfig::new::<M>(config, total_records);
                tracing::trace!("send configuration for {channel_id:?}: {config:?}");
                let sender = Self::new_sender(&config, channel_id.clone());
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

    fn new_sender(config: &SendChannelConfig, channel_id: ChannelId<I>) -> Arc<GatewaySender<I>> {
        Arc::new(GatewaySender::new(
            channel_id,
            OrderingSender::new(config.total_capacity, config.record_size, config.read_size),
            config.total_records,
        ))
    }
}

impl<I: Debug> Stream for GatewaySendStream<I> {
    type Item = Vec<u8>;

    #[tracing::instrument(level = "trace", name = "send_stream", skip_all, fields(to = ?self.inner.channel_id.peer, gate = ?self.inner.channel_id.gate))]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::get_mut(self).inner.ordering_tx.take_next(cx)
    }
}

impl SendChannelConfig {
    fn new<M: Message>(gateway_config: GatewayConfig, total_records: TotalRecords) -> Self {
        Self::new_with(gateway_config, total_records, M::Size::USIZE)
    }
    fn new_with(
        gateway_config: GatewayConfig,
        total_records: TotalRecords,
        record_size: usize,
    ) -> Self {
        assert!(record_size > 0, "Message size cannot be 0");

        let total_capacity = gateway_config.active.get() * record_size;
        // define read size as a multiplier of record size. The multiplier must be
        // a power of two to align perfectly with total capacity. We don't want to exceed
        // the target read size, so multiplier * record_size <= read_size. We want to get
        // as close as possible to read_size.
        let read_size_multiplier = {
            let target = gateway_config.read_size.get() / record_size;
            // If record_size is greater than read_size, we set the multiplier to 1
            // as read size cannot be 0.
            non_zero_prev_power_of_two(target)
        };

        let this = Self {
            total_capacity: total_capacity.try_into().unwrap(),
            record_size: record_size.try_into().unwrap(),
            read_size: if total_records.is_indeterminate() {
                record_size
            } else {
                std::cmp::min(total_capacity, read_size_multiplier * record_size)
            }
            .try_into()
            .unwrap(),
            total_records,
        };

        // If capacity can't fit all active work items, the protocol deadlocks on
        // inserts above the total capacity.
        assert!(this.total_capacity.get() >= record_size * gateway_config.active.get());
        // if capacity is not aligned with read size, we can get a deadlock
        // described in ipa/1300
        assert_eq!(0, this.total_capacity.get() % this.read_size.get());

        this
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::num::NonZeroUsize;

    use proptest::proptest;
    use typenum::Unsigned;

    use crate::{
        ff::{
            Serializable,
            boolean_array::{BA3, BA7, BA16, BA20, BA32, BA256},
        },
        helpers::{GatewayConfig, TotalRecords, gateway::send::SendChannelConfig},
        secret_sharing::SharedValue,
    };

    impl Default for SendChannelConfig {
        fn default() -> Self {
            Self {
                total_capacity: NonZeroUsize::new(1).unwrap(),
                record_size: NonZeroUsize::new(1).unwrap(),
                read_size: NonZeroUsize::new(1).unwrap(),
                total_records: TotalRecords::Unspecified,
            }
        }
    }

    #[allow(clippy::needless_update)] // to allow progress_check_interval to be conditionally compiled
    fn send_config<V: SharedValue, const A: usize, const R: usize>(
        total_records: TotalRecords,
    ) -> SendChannelConfig {
        let gateway_config = GatewayConfig {
            active: A.try_into().unwrap(),
            read_size: R.try_into().unwrap(),
            ..Default::default()
        };

        SendChannelConfig::new::<V>(gateway_config, total_records)
    }

    #[test]
    fn config_basic() {
        const TOTAL_CAPACITY: usize = 2048;
        const READ_SIZE: usize = 2048;
        const RECORD_SIZE: usize = <BA3 as Serializable>::Size::USIZE;

        let total_records = TotalRecords::Specified(2.try_into().unwrap());
        let send_config = send_config::<BA3, TOTAL_CAPACITY, READ_SIZE>(total_records);

        assert_eq!(
            SendChannelConfig {
                total_capacity: TOTAL_CAPACITY.try_into().unwrap(),
                record_size: RECORD_SIZE.try_into().unwrap(),
                read_size: READ_SIZE.try_into().unwrap(),
                total_records,
            },
            send_config
        );
    }

    /// This ensures the previous behavior of the sender is preserved for `TotalRecords::Indeterminate`
    /// case - if it is set, then read size is always the size of one record
    #[test]
    fn config_indeterminate() {
        const RECORD_SIZE: usize = <BA7 as Serializable>::Size::USIZE;

        let send_config = send_config::<BA7, 2048, 2048>(TotalRecords::Indeterminate);

        assert_eq!(RECORD_SIZE, send_config.read_size.get());
    }

    #[test]
    fn config_capacity_scales() {
        let send_config = send_config::<BA16, 2048, 2048>(TotalRecords::Unspecified);

        assert_eq!(
            2048 * <BA16 as Serializable>::Size::USIZE,
            send_config.total_capacity.get()
        );
    }

    #[test]
    fn config_read_size_scales() {
        let send_config =
            send_config::<BA256, 2048, 16>(TotalRecords::Specified(2.try_into().unwrap()));

        assert_eq!(
            <BA256 as Serializable>::Size::USIZE,
            send_config.read_size.get()
        );
    }

    #[test]
    fn config_read_size_cannot_exceed_capacity() {
        let send_config =
            send_config::<BA16, 2048, 24096>(TotalRecords::Specified(2.try_into().unwrap()));

        assert_eq!(
            2048 * <BA16 as Serializable>::Size::USIZE,
            send_config.read_size.get()
        );
    }

    #[test]
    fn config_read_size_closest_multiple_to_record_size() {
        assert_eq!(
            6,
            send_config::<BA20, 16, 7>(TotalRecords::Specified(2.try_into().unwrap()))
                .read_size
                .get()
        );
        assert_eq!(
            6,
            send_config::<BA20, 16, 8>(TotalRecords::Specified(2.try_into().unwrap()))
                .read_size
                .get()
        );
    }

    #[test]
    fn config_read_size_record_size_misalignment() {
        ensure_config(Some(15), 90, 16, 3);
    }

    #[test]
    fn config_read_size_multiple_of_record_size() {
        // 4 bytes * 8 = 32 bytes total capacity.
        // desired read size is 15 bytes, and the closest multiple of BA32
        // to it that is a power of two is 2 (4 gets us over 15 byte target)
        assert_eq!(8, send_config::<BA32, 8, 15>(50.into()).read_size.get());

        // here, read size is already a power of two
        assert_eq!(16, send_config::<BA32, 8, 16>(50.into()).read_size.get());

        // read size can be ridiculously small, config adjusts it to fit
        // at least one record
        assert_eq!(3, send_config::<BA20, 8, 1>(50.into()).read_size.get());
    }

    fn ensure_config(
        total_records: Option<usize>,
        active: usize,
        read_size: usize,
        record_size: usize,
    ) {
        #[allow(clippy::needless_update)] // stall detection feature wants default value
        let gateway_config = GatewayConfig {
            active: active.next_power_of_two().try_into().unwrap(),
            read_size: read_size.try_into().unwrap(),
            ..Default::default()
        };
        let config = SendChannelConfig::new_with(
            gateway_config,
            total_records.map_or(TotalRecords::Indeterminate, |v| {
                TotalRecords::specified(v).unwrap()
            }),
            record_size,
        );

        // total capacity checks
        assert!(config.total_capacity.get() > 0);
        assert!(config.total_capacity.get() >= config.read_size.get());
        assert_eq!(0, config.total_capacity.get() % config.record_size.get());
        assert_eq!(
            config.total_capacity.get(),
            record_size * gateway_config.active.get()
        );

        // read size checks
        assert!(config.read_size.get() > 0);
        assert!(config.read_size.get() >= config.record_size.get());
        assert_eq!(0, config.total_capacity.get() % config.read_size.get());
    }

    proptest! {
        #[test]
        fn config_prop(
            total_records in proptest::option::of(1_usize..1 << 32),
            active in 1_usize..100_000,
            read_size in 1_usize..32768,
            record_size in 1_usize..4096,
        ) {
            ensure_config(total_records, active, read_size, record_size);
        }
    }
}
