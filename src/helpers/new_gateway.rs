use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::mem;
use std::num::NonZeroUsize;
use crate::sync::{Arc, Mutex};
use async_trait::async_trait;
use futures::Stream;
use futures_util::stream::FuturesUnordered;
use generic_array::{ArrayLength, GenericArray};
use tinyvec::array_vec;
use ::tokio::sync::mpsc::Sender;
use typenum::{U8, Unsigned};
use crate::bits::Serializable;
use crate::helpers::buffers::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender, UnorderedReceiver};
use crate::helpers::{Error, GatewayConfig, HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES, Role, RoleAssignment};
use crate::helpers::messaging::{Message, TotalRecords};
use crate::helpers::network::{ChannelId, MessageEnvelope};
use crate::helpers::transport::{ChannelledTransport, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding};
use crate::protocol::{QueryId, RecordId, Step};
use crate::telemetry::metrics::RECORDS_SENT;
use crate::telemetry::labels::STEP;
use crate::telemetry::labels::ROLE;
use std::cell::RefCell;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use thread_local::ThreadLocal;

#[derive(Debug)]
struct Wrapper([u8; Self::SIZE]);

impl Wrapper {
    const SIZE: usize = 8;
}

impl Serializable for Wrapper {
    type Size = U8;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self((*buf).into())
    }
}

impl Message for Wrapper {}

impl Wrapper {
    fn wrap<M: Message>(v: M) -> Self {
        let mut buf = GenericArray::default();
        v.serialize(&mut buf);
        let mut this = [0_u8; Self::SIZE];
        this[..buf.len()].copy_from_slice(&buf);
        Self(this)
    }
}


pub struct SendingEnd<M: Message> {
    channel_id: ChannelId,
    my_role: Role,
    ordering_tx: OrderingMpscSender<Wrapper>,
    total_records: TotalRecords,
    _phantom: PhantomData<M>,
}

pub struct ReceivingEnd<M: Message> {
    unordered_rx: UR<TransportImpl>,
    _phantom: PhantomData<M>
}

impl<M: Message> SendingEnd<M> {
    fn new(channel_id: ChannelId, my_role: Role, tx: OrderingMpscSender<Wrapper>, total_records: TotalRecords) -> Self {
        Self {
            channel_id,
            my_role,
            ordering_tx: tx,
            total_records,
            _phantom: PhantomData
        }
    }

    pub async fn send(&self, record_id: RecordId, msg: M) -> Result<(), Error> {
        if let TotalRecords::Specified(count) = self.total_records {
            assert!(
                usize::from(record_id) < usize::from(count),
                "record ID {:?} is out of range for {:?} (expected {:?} records)",
                record_id,
                self.channel_id,
                self.total_records,
            );
        }

        metrics::increment_counter!(RECORDS_SENT, STEP => self.channel_id.step.as_ref().to_string(), ROLE => self.my_role.as_static_str());
        Ok(self.ordering_tx.send(record_id.into(), Wrapper::wrap(msg)).await.unwrap())
    }
}

impl <M: Message> ReceivingEnd<M> {
    fn new(rx: UR<TransportImpl>) -> Self {
        Self {
            unordered_rx: rx,
            _phantom: PhantomData
        }
    }

    pub async fn receive(&self, record_id: RecordId) -> Result<M, Error> {
        // TODO: proper error handling
        let v = self.unordered_rx.recv::<Wrapper, _>(record_id).await.unwrap();
        let mut buf = GenericArray::default();
        let sz = buf.len();

        buf.copy_from_slice(&v.0[..sz]);
        Ok(M::deserialize(&buf))
    }
}

struct GatewaySenders {
    inner: DashMap<ChannelId, OrderingMpscSender<Wrapper>>,
    cache: ThreadLocal<RefCell<HashMap<ChannelId, OrderingMpscSender<Wrapper>>>>,
}

impl Default for GatewaySenders {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
            cache: ThreadLocal::new(),
        }
    }
}

impl GatewaySenders {
    /// Returns or creates a new communication channel. In case if channel is newly created,
    /// returns the receiving end of it as well. It must be send over to the receiving side.
    fn get_or_create(&self, channel_id: &ChannelId, total_records: TotalRecords, capacity: NonZeroUsize) -> (OrderingMpscSender<Wrapper>, Option<OrderingMpscReceiver<Wrapper>>) {
        let senders = &self.inner;
        match senders.get(&channel_id) {
            Some(entry) => {
                (entry.value().clone(), None)
            }
            None => {
                match senders.entry(channel_id.clone()) {
                    Entry::Occupied(entry) => {
                        (entry.get().clone(), None)
                    }
                    Entry::Vacant(entry) => {
                        let (tx, rx) = ordering_mpsc::<Wrapper, _>(
                            format!("{:?}", entry.key()),
                            capacity
                        );
                        (entry.insert(tx).clone(), Some(rx))
                    }
                }
            }
        }
    }
}

struct GatewayReceivers<T: ChannelledTransport> {
    inner: DashMap<ChannelId, UR<T>>,
}

impl <T: ChannelledTransport> Default for GatewayReceivers<T> {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
        }
    }
}

impl <T: ChannelledTransport> GatewayReceivers<T> {

    pub fn get_or_create<M: Message, F: FnOnce() -> UR<T>>(&self, channel_id: &ChannelId, ctr: F) -> UR<T> {
        let receivers = &self.inner;
        let recv = match receivers.get(&channel_id) {
            Some(recv) => recv.clone(),
            None => {
                match receivers.entry(channel_id.clone()) {
                    Entry::Occupied(entry) => {
                        entry.get().clone()
                    },
                    Entry::Vacant(entry) => {
                        let stream = ctr();
                        entry.insert(stream).clone()
                    }
                }
            }
        };
        recv
    }
}

type UR<T> = UnorderedReceiver<<T as ChannelledTransport>::RecordsStream, <<T as ChannelledTransport>::RecordsStream as Stream>::Item>;

#[derive(Clone)]
struct RoleResolvingTransport<T> {
    query_id: QueryId,
    roles: RoleAssignment,
    config: GatewayConfig,
    inner: T
}

impl <T: ChannelledTransport> RoleResolvingTransport<T> {
    async fn send(&self, channel_id: &ChannelId, data: OrderingMpscReceiver<Wrapper>) {
        let dest_identity = self.roles.identity(channel_id.role);
        assert_ne!(dest_identity, self.inner.identity(), "can't send message to itself");

        self.inner.send(dest_identity, (RouteId::Records, self.query_id, channel_id.step.clone()), data).await.unwrap()
    }

    fn receive(&self, channel_id: &ChannelId) -> UR<T> {
        let peer = self.roles.identity(channel_id.role);
        assert_ne!(peer, self.inner.identity(), "can't receive message from itself");

        UnorderedReceiver::new(
            Box::pin(self.inner.receive(peer, (self.query_id, channel_id.step.clone()))),
         self.config.recv_outstanding)
    }

    fn role(&self) -> Role {
        self.roles.role(self.inner.identity())
    }
}


pub struct Gateway {
    config: GatewayConfig,
    transport: RoleResolvingTransport<TransportImpl>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<TransportImpl>,
}

impl Gateway {

    pub fn new(query_id: QueryId, config: GatewayConfig, roles: RoleAssignment, transport: TransportImpl) -> Self {
        Self {
            config,
            transport: RoleResolvingTransport {
                query_id,
                roles,
                inner: transport,
                config
            },
            senders: GatewaySenders::default(),
            receivers: GatewayReceivers::default(),
        }
    }

    pub fn role(&self) -> Role {
        self.transport.role()
    }

    pub fn get_sender<M: Message>(&self, channel_id: &ChannelId, total_records: TotalRecords) -> SendingEnd<M> {
        let (tx, maybe_recv) = self.senders.get_or_create(channel_id, total_records, self.config.send_outstanding);
        if let Some(recv) = maybe_recv {
            tokio::spawn({
                let channel_id = channel_id.clone();
                let transport = self.transport.clone();
                async move {
                    transport.send(&channel_id, recv).await;
                }
            });
        }

        SendingEnd::new(channel_id.clone(), self.role(), tx, total_records)
    }

    pub fn get_receiver<M: Message>(&self, channel_id: &ChannelId) -> ReceivingEnd<M> {
        ReceivingEnd::new(self.receivers.get_or_create::<M, _>(channel_id, || {
            self.transport.receive(channel_id)
        }))
    }
}

/// Exists to dispatch calls to various [`ChannelledTransport`] implementations without the need
/// of dynamic dispatch. DD is not even possible with this trait, so that is the only way to prevent
/// [`Gateway`] to be generic over it. We want to avoid that as it pollutes our protocol code.
#[derive(Clone)]
pub enum TransportImpl {
    #[cfg(any(test, feature = "test-fixture"))]
    InMemory(std::sync::Weak<crate::test_fixture::transport::InMemoryChannelledTransport>)
}

#[async_trait]
impl ChannelledTransport for TransportImpl {
    #[cfg(any(test, feature = "test-fixture"))]
    type RecordsStream = <std::sync::Weak<crate::test_fixture::transport::InMemoryChannelledTransport> as ChannelledTransport>::RecordsStream;
    // TODO: it is likely that this ends up being the only type we could use here.
    #[cfg(not(any(test, feature = "test-fixture")))]
    type RecordsStream = std::pin::Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

    fn identity(&self) -> HelperIdentity {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(ref inner) => inner.identity(),
            // https://github.com/rust-lang/rust/issues/78123
            _ => unreachable!()
        }
    }

    async fn send<D, Q, S, R>(&self, dest: HelperIdentity, route: R, data: D) -> Result<(), std::io::Error> where Option<QueryId>: From<Q>, Option<Step>: From<S>, Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>, D: Stream<Item=Vec<u8>> + Send + 'static {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(inner) => inner.send(dest, route, data).await,
            _ => unreachable!()
        }
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(&self, from: HelperIdentity, route: R) -> Self::RecordsStream {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(inner) => inner.receive(from, route),
            _ => unreachable!()
        }
    }
}
