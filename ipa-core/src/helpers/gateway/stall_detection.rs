use std::{
    fmt::{Debug, Display, Formatter},
    ops::{RangeInclusive, Sub},
};

pub use gateway::InstrumentedGateway;

use crate::sync::{
    atomic::{AtomicUsize, Ordering},
    Weak,
};

/// Trait for structs that can report their current state.
pub trait ObserveState {
    type State: Debug;
    fn get_state(&self) -> Option<Self::State>;
}

/// This object does not own the sequence number, it must be stored outside and dropped when
/// observing entity goes out of scope. If that happens, any attempt to increment it through this
/// instance will result in a panic.
///
/// Observing and incrementing sequence numbers do not introduce happens-before relationship.
pub struct Observed<T> {
    /// Each time a state change occurs inside the observable object `T`, its sequence number is
    /// incremented by 1. It is up to the caller to decide what is a state change.
    ///
    /// The sequence number is stored as a weak reference, so it can be dropped when the observed
    /// object is dropped.
    ///
    /// External observers watching this object will declare it stalled if it's sequence number
    /// hasn't been incremented for long enough time. It can happen for two reasons: either there is
    /// no work to do for this object, or its state is not drained/consumed by the clients. In the
    /// former case, the bottleneck is somewhere else, otherwise if `T` implements `ObserveState`,
    /// the current state of `T` is also reported.
    sn: Weak<AtomicUsize>,
    inner: T,
}

impl<T> Observed<T> {
    fn wrap(sn: Weak<AtomicUsize>, inner: T) -> Self {
        Self { sn, inner }
    }

    fn get_sn(&self) -> &Weak<AtomicUsize> {
        &self.sn
    }

    /// Advances the sequence number ahead.
    ///
    /// ## Panics
    /// This will panic if the sequence number is dropped.
    fn advance(&self) {
        let sn = self.sn.upgrade().unwrap();
        sn.fetch_add(1, Ordering::Relaxed);
    }

    fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: ObserveState> Observed<T> {
    pub fn get_state(&self) -> Option<T::State> {
        self.inner().get_state()
    }
}

mod gateway {
    use std::num::NonZeroUsize;

    use delegate::delegate;

    use super::{receive, send, AtomicUsize, Debug, Formatter, ObserveState, Observed, Weak};
    use crate::{
        helpers::{
            gateway::{Gateway, ShardTransportImpl, State},
            GatewayConfig, HelperChannelId, Message, MpcMessage, MpcReceivingEnd, MpcTransportImpl,
            Role, RoleAssignment, SendingEnd, ShardChannelId, ShardReceivingEnd, TotalRecords,
        },
        protocol::QueryId,
        sharding::ShardIndex,
        sync::Arc,
    };

    pub struct InstrumentedGateway {
        gateway: Gateway,
        // Gateway owns the sequence number associated with it. When it goes out of scope, sn is destroyed
        // and external observers can see that they no longer need to watch it.
        _sn: Arc<AtomicUsize>,
    }

    impl Observed<InstrumentedGateway> {
        delegate! {
            to self.inner().gateway {

                #[inline]
                pub fn role(&self) -> Role;

                #[inline]
                pub fn config(&self) -> &GatewayConfig;
            }
        }

        #[allow(clippy::let_and_return)]
        pub fn new(
            query_id: QueryId,
            config: GatewayConfig,
            roles: RoleAssignment,
            mpc_transport: MpcTransportImpl,
            shard_transport: ShardTransportImpl,
        ) -> Self {
            let version = Arc::new(AtomicUsize::default());
            let r = Self::wrap(
                Arc::downgrade(&version),
                InstrumentedGateway {
                    gateway: Gateway::new(query_id, config, roles, mpc_transport, shard_transport),
                    _sn: version,
                },
            );

            // spawn the watcher
            #[cfg(not(feature = "shuttle"))]
            {
                use tracing::Instrument;

                tokio::spawn({
                    let gateway = r.to_observed();
                    async move {
                        let mut last_sn_seen = 0;
                        loop {
                            ::tokio::time::sleep(config.progress_check_interval).await;
                            let now = gateway.get_sn().upgrade().map(|v| v.load(core::sync::atomic::Ordering::Relaxed));
                            if let Some(now) = now {
                                if now == last_sn_seen {
                                    if let Some(state) = gateway.get_state() {
                                        tracing::warn!(sn = now, state = ?state, "Helper is stalled");
                                    }
                                }
                                last_sn_seen = now;
                            } else {
                                break;
                            }
                        }
                    }.instrument(tracing::info_span!("stall_detector", role = ?r.role()))
                });
            }

            r
        }

        #[must_use]
        pub fn get_mpc_sender<M: MpcMessage>(
            &self,
            channel_id: &HelperChannelId,
            total_records: TotalRecords,
            active_work: NonZeroUsize,
        ) -> SendingEnd<Role, M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner()
                    .gateway
                    .get_mpc_sender(channel_id, total_records, active_work),
            )
        }

        pub fn get_shard_sender<M: Message>(
            &self,
            channel_id: &ShardChannelId,
            total_records: TotalRecords,
        ) -> SendingEnd<ShardIndex, M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner
                    .gateway
                    .get_shard_sender(channel_id, total_records),
            )
        }

        #[must_use]
        pub fn get_mpc_receiver<M: MpcMessage>(
            &self,
            channel_id: &HelperChannelId,
        ) -> MpcReceivingEnd<M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner().gateway.get_mpc_receiver(channel_id),
            )
        }

        pub fn get_shard_receiver<M: Message>(
            &self,
            channel_id: &ShardChannelId,
        ) -> ShardReceivingEnd<M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner().gateway.get_shard_receiver(channel_id),
            )
        }

        pub fn to_observed(&self) -> Observed<Weak<State>> {
            // todo: inner.inner
            Observed::wrap(
                Weak::clone(self.get_sn()),
                Arc::downgrade(&self.inner().gateway.inner),
            )
        }
    }

    pub struct GatewayWaitingTasks<MS, MR, SS, SR> {
        mpc_send: Option<MS>,
        mpc_recv: Option<MR>,
        shard_send: Option<SS>,
        shard_recv: Option<SR>,
    }

    impl<MS: Debug, MR: Debug, SS: Debug, SR: Debug> Debug for GatewayWaitingTasks<MS, MR, SS, SR> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            if let Some(senders_state) = &self.mpc_send {
                write!(f, "\n{{{senders_state:?}\n}}")?;
            }
            if let Some(receivers_state) = &self.mpc_recv {
                write!(f, "\n{{{receivers_state:?}\n}}")?;
            }
            if let Some(senders_state) = &self.shard_send {
                write!(f, "\n{{{senders_state:?}\n}}")?;
            }
            if let Some(receivers_state) = &self.shard_recv {
                write!(f, "\n{{{receivers_state:?}\n}}")?;
            }

            Ok(())
        }
    }

    impl ObserveState for Weak<State> {
        type State = GatewayWaitingTasks<
            send::WaitingTasks<Role>,
            receive::WaitingTasks<Role>,
            send::WaitingTasks<ShardIndex>,
            receive::WaitingTasks<ShardIndex>,
        >;

        fn get_state(&self) -> Option<Self::State> {
            self.upgrade().and_then(|state| {
                match (
                    state.mpc_senders.get_state(),
                    state.mpc_receivers.get_state(),
                    state.shard_senders.get_state(),
                    state.shard_receivers.get_state(),
                ) {
                    (None, None, None, None) => None,
                    (mpc_send, mpc_recv, shard_send, shard_recv) => Some(Self::State {
                        mpc_send,
                        mpc_recv,
                        shard_send,
                        shard_recv,
                    }),
                }
            })
        }
    }
}

mod receive {
    use std::{
        collections::BTreeMap,
        fmt::{Debug, Formatter},
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::Stream;

    use super::{ObserveState, Observed};
    use crate::{
        helpers::{
            error::Error,
            gateway::{
                receive::{GatewayReceivers, ShardReceiveStream, ShardReceivingEnd, UR},
                MpcReceivingEnd,
            },
            ChannelId, Message, MpcMessage, Role, TransportIdentity,
        },
        protocol::RecordId,
        sharding::ShardIndex,
    };

    impl<M: MpcMessage> Observed<MpcReceivingEnd<M>> {
        delegate::delegate! {
            to { self.advance(); self.inner() } {
                #[inline]
                pub async fn receive(&self, record_id: RecordId) -> Result<M, Error<Role>>;
            }
        }
    }

    impl<M: Message> Stream for Observed<ShardReceivingEnd<M>> {
        type Item = <ShardReceivingEnd<M> as Stream>::Item;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.advance();
            Pin::new(&mut self.inner).poll_next(cx)
        }
    }

    pub struct WaitingTasks<I: TransportIdentity>(BTreeMap<ChannelId<I>, Vec<String>>);

    impl<I: TransportIdentity> Debug for WaitingTasks<I> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            for (channel, records) in &self.0 {
                write!(
                    f,
                    "\n\"{:?}\", from={:?}. Waiting to receive records {:?}.",
                    channel.gate, channel.peer, records
                )?;
            }

            Ok(())
        }
    }

    impl ObserveState for GatewayReceivers<Role, UR> {
        type State = WaitingTasks<Role>;

        fn get_state(&self) -> Option<Self::State> {
            let mut map = BTreeMap::default();
            for entry in &self.inner {
                let channel = entry.key();
                if let Some(waiting) = super::to_ranges(entry.value().waiting()).get_state() {
                    map.insert(channel.clone(), waiting);
                }
            }

            (!map.is_empty()).then_some(WaitingTasks(map))
        }
    }

    impl ObserveState for GatewayReceivers<ShardIndex, ShardReceiveStream> {
        type State = WaitingTasks<ShardIndex>;

        fn get_state(&self) -> Option<Self::State> {
            let mut map = BTreeMap::default();
            for entry in &self.inner {
                let channel = entry.key();
                map.insert(
                    channel.clone(),
                    vec!["Shard receiver state is not implemented yet".to_string()],
                );
            }

            (!map.is_empty()).then_some(WaitingTasks(map))
        }
    }
}

mod send {
    use std::{
        borrow::Borrow,
        collections::BTreeMap,
        fmt::{Debug, Formatter},
    };

    use super::{ObserveState, Observed};
    use crate::{
        helpers::{
            error::Error,
            gateway::send::{GatewaySender, GatewaySenders},
            ChannelId, Message, TotalRecords, TransportIdentity,
        },
        protocol::RecordId,
    };

    impl<I: TransportIdentity, M: Message> Observed<crate::helpers::gateway::send::SendingEnd<I, M>> {
        delegate::delegate! {
            to { self.advance(); self.inner() } {
                #[inline]
                pub async fn send<B: Borrow<M>>(&self, record_id: RecordId, msg: B) -> Result<(), Error<I>>;
                #[inline]
                pub async fn close(&self, at: RecordId);
            }
        }
    }

    pub struct WaitingTasks<I>(BTreeMap<ChannelId<I>, (TotalRecords, Vec<String>)>);

    impl<I: TransportIdentity> Debug for WaitingTasks<I> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            for (channel, (total, records)) in &self.0 {
                write!(
                    f,
                    "\n\"{:?}\", to={:?}. Waiting to send records {:?} out of {total:?}.",
                    channel.gate, channel.peer, records
                )?;
            }

            Ok(())
        }
    }

    impl<I: TransportIdentity> ObserveState for GatewaySenders<I> {
        type State = WaitingTasks<I>;

        fn get_state(&self) -> Option<Self::State> {
            let mut state = BTreeMap::new();
            for entry in &self.inner {
                let channel = entry.key();
                let sender = entry.value();
                if let Some(sender_state) = sender.get_state() {
                    state.insert(channel.clone(), (sender.total_records(), sender_state));
                }
            }

            (!state.is_empty()).then_some(WaitingTasks(state))
        }
    }

    impl<I: TransportIdentity> ObserveState for GatewaySender<I> {
        type State = Vec<String>;

        fn get_state(&self) -> Option<Self::State> {
            let waiting_indices = self.waiting();
            super::to_ranges(waiting_indices).get_state()
        }
    }
}

/// Converts a vector of numbers into a vector of ranges.
/// For example, [1, 2, 3, 4, 5, 7, 9, 10, 11] produces [(1..=5), (7..=7), (9..=11)].
fn to_ranges<I: IntoIterator<Item = usize>>(nums: I) -> Vec<std::ops::RangeInclusive<usize>> {
    nums.into_iter()
        .fold(Vec::<RangeInclusive<usize>>::new(), |mut ranges, num| {
            if let Some(last_range) = ranges.last_mut().filter(|r| *r.end() == num - 1) {
                *last_range = *last_range.start()..=num;
            } else {
                ranges.push(num..=num);
            }
            ranges
        })
}

/// Range formatter that prints one-element wide ranges as single numbers.
impl<U> ObserveState for Vec<RangeInclusive<U>>
where
    U: Copy + Display + Eq + PartialOrd + Ord + Sub<Output = U> + From<u8>,
{
    type State = Vec<String>;
    fn get_state(&self) -> Option<Self::State> {
        let r = self
            .iter()
            .map(
                |range| match (*range.end() - *range.start()).cmp(&U::from(1)) {
                    std::cmp::Ordering::Less => format!("{}", range.start()),
                    std::cmp::Ordering::Equal => format!("[{}, {}]", range.start(), range.end()),
                    std::cmp::Ordering::Greater => format!("[{}..{}]", range.start(), range.end()),
                },
            )
            .collect::<Vec<_>>();

        (!r.is_empty()).then_some(r)
    }
}
