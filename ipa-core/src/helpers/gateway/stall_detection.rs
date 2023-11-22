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
    use delegate::delegate;

    use super::*;
    use crate::{
        helpers::{
            gateway::{Gateway, State},
            ChannelId, GatewayConfig, Message, ReceivingEnd, Role, RoleAssignment, SendingEnd,
            TotalRecords, TransportImpl,
        },
        protocol::QueryId,
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
            transport: TransportImpl,
        ) -> Self {
            let version = Arc::new(AtomicUsize::default());
            let r = Self::wrap(
                Arc::downgrade(&version),
                InstrumentedGateway {
                    gateway: Gateway::new(query_id, config, roles, transport),
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
                            let now = gateway.get_sn().upgrade().map(|v| v.load(Ordering::Relaxed));
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
        pub fn get_sender<M: Message>(
            &self,
            channel_id: &ChannelId,
            total_records: TotalRecords,
        ) -> SendingEnd<M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner().gateway.get_sender(channel_id, total_records),
            )
        }

        #[must_use]
        pub fn get_receiver<M: Message>(&self, channel_id: &ChannelId) -> ReceivingEnd<M> {
            Observed::wrap(
                Weak::clone(self.get_sn()),
                self.inner().gateway.get_receiver(channel_id),
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

    pub struct GatewayWaitingTasks<S, R> {
        senders_state: Option<S>,
        receivers_state: Option<R>,
    }

    impl<S: Debug, R: Debug> Debug for GatewayWaitingTasks<S, R> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            if let Some(senders_state) = &self.senders_state {
                write!(f, "\n{{{senders_state:?}\n}}")?;
            }
            if let Some(receivers_state) = &self.receivers_state {
                write!(f, "\n{{{receivers_state:?}\n}}")?;
            }

            Ok(())
        }
    }

    impl ObserveState for Weak<State> {
        type State = GatewayWaitingTasks<send::WaitingTasks, receive::WaitingTasks>;

        fn get_state(&self) -> Option<Self::State> {
            self.upgrade().and_then(|state| {
                match (state.senders.get_state(), state.receivers.get_state()) {
                    (None, None) => None,
                    (senders_state, receivers_state) => Some(Self::State {
                        senders_state,
                        receivers_state,
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
    };

    use super::*;
    use crate::{
        helpers::{
            error::Error,
            gateway::{receive::GatewayReceivers, ReceivingEnd},
            ChannelId, Message,
        },
        protocol::RecordId,
    };

    impl<M: Message> Observed<ReceivingEnd<M>> {
        delegate::delegate! {
            to { self.advance(); self.inner() } {
                #[inline]
                pub async fn receive(&self, record_id: RecordId) -> Result<M, Error>;
            }
        }
    }

    pub struct WaitingTasks(BTreeMap<ChannelId, Vec<String>>);

    impl Debug for WaitingTasks {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            for (channel, records) in &self.0 {
                write!(
                    f,
                    "\n\"{:?}\", from={:?}. Waiting to receive records {:?}.",
                    channel.gate, channel.role, records
                )?;
            }

            Ok(())
        }
    }

    impl ObserveState for GatewayReceivers {
        type State = WaitingTasks;

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
}

mod send {
    use std::{
        collections::BTreeMap,
        fmt::{Debug, Formatter},
    };

    use super::*;
    use crate::{
        helpers::{
            error::Error,
            gateway::send::{GatewaySender, GatewaySenders},
            ChannelId, Message, TotalRecords,
        },
        protocol::RecordId,
    };

    impl<M: Message> Observed<crate::helpers::gateway::send::SendingEnd<M>> {
        delegate::delegate! {
            to { self.advance(); self.inner() } {
                #[inline]
                pub async fn send(&self, record_id: RecordId, msg: M) -> Result<(), Error>;
            }
        }
    }

    pub struct WaitingTasks(BTreeMap<ChannelId, (TotalRecords, Vec<String>)>);

    impl Debug for WaitingTasks {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            for (channel, (total, records)) in &self.0 {
                write!(
                    f,
                    "\n\"{:?}\", to={:?}. Waiting to send records {:?} out of {total:?}.",
                    channel.gate, channel.role, records
                )?;
            }

            Ok(())
        }
    }

    impl ObserveState for GatewaySenders {
        type State = WaitingTasks;

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

    impl ObserveState for GatewaySender {
        type State = Vec<String>;

        fn get_state(&self) -> Option<Self::State> {
            let waiting_indices = self.waiting();
            super::to_ranges(waiting_indices).get_state()
        }
    }
}

/// Converts a vector of numbers into a vector of ranges.
/// For example, [1, 2, 3, 4, 5, 7, 9, 10, 11] produces [(1..=5), (7..=7), (9..=11)].
fn to_ranges(nums: Vec<usize>) -> Vec<std::ops::RangeInclusive<usize>> {
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
