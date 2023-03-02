use std::any::Any;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, RwLock};
use async_trait::async_trait;
use futures::Stream;
use futures_util::stream::FuturesUnordered;
use generic_array::{ArrayLength, GenericArray};
use tinyvec::array_vec;
use tokio::sync::mpsc::Sender;
use typenum::{U8, Unsigned};
use crate::bits::Serializable;
use crate::helpers::buffers::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender, UnorderedReceiver};
use crate::helpers::{Error, HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES, Role};
use crate::helpers::messaging::{Message, TotalRecords};
use crate::helpers::network::{ChannelId, MessageEnvelope};
use crate::helpers::transport::{ChannelledTransport, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding};
use crate::protocol::{QueryId, RecordId, Step};

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
        Self((*buf).try_into().expect("Message fits into 8 bytes"))
    }
}


struct SendingEnd<'a, M: Message> {
    channel_id: &'a ChannelId,
    ordering_tx: OrderingMpscSender<Wrapper>,
    total_records: TotalRecords,
    _phantom: PhantomData<M>,
}

struct ReceivingEnd<T: ChannelledTransport, M: Message> {
    unordered_rx: UR<T>,
    _phantom: PhantomData<M>
}

impl<'a, M: Message> SendingEnd<'a, M> {
    pub fn new(channel_id: &'a ChannelId, tx: OrderingMpscSender<Wrapper>, total_records: TotalRecords) -> Self {
        Self {
            channel_id,
            ordering_tx: tx,
            total_records,
            _phantom: PhantomData
        }
    }

    pub async fn send(&self, record_id: RecordId, msg: M) {
        if let TotalRecords::Specified(count) = self.total_records {
            assert!(
                usize::from(record_id) < usize::from(count),
                "record ID {:?} is out of range for {:?} (expected {:?} records)",
                record_id,
                self.channel_id,
                self.total_records,
            );
        }

        self.ordering_tx.send(record_id.into(), Wrapper::wrap(msg)).await.unwrap()
    }
}

impl <T: ChannelledTransport, M: Message> ReceivingEnd<T, M> {
    pub fn new(rx: UR<T>) -> Self {
        Self {
            unordered_rx: rx,
            _phantom: PhantomData
        }
    }

    pub async fn receive(&self, record_id: RecordId) -> M {
        self.unordered_rx.recv::<M, _>(record_id).await.unwrap()
    }
}

struct GatewaySenders {
    inner: RwLock<HashMap<ChannelId, OrderingMpscSender<Wrapper>>>,
}

impl GatewaySenders {
    const CAPACITY: NonZeroUsize = unsafe {
        // don't put 0, I beg you
        NonZeroUsize::new_unchecked(16)
    };

    /// Returns or creates a new communication channel. In case if channel is newly created,
    /// returns the receiving end of it as well. It must be send over to the receiving side.
    pub fn get_or_create<'a, 'b: 'a, M: Message>(&'a self, channel_id: &'b ChannelId, total_records: TotalRecords) -> (SendingEnd<'a, M>, Option<OrderingMpscReceiver<Wrapper>>) {
        let senders = self.inner.read().unwrap();
        match senders.get(&channel_id) {
            Some(sender) => {
                (SendingEnd::new(channel_id, sender.clone(), total_records), None)
            }
            None => {
                drop(senders);
                let mut senders = self.inner.write().unwrap();
                match senders.entry(channel_id.clone()) {
                    Entry::Occupied(sender) => {
                        (SendingEnd::new(channel_id, sender.get().clone(), total_records), None)
                    }
                    Entry::Vacant(entry) => {
                        let (tx, rx) = ordering_mpsc::<Wrapper, _>(
                            format!("{:?}", entry.key()),
                            Self::CAPACITY
                        );
                        (SendingEnd::new(channel_id, entry.insert(tx).clone(), total_records), None)
                    }
                }
            }
        }
    }
}

struct GatewayReceivers<T: ChannelledTransport> {
    inner: RwLock<HashMap<ChannelId, UR<T>>>
}

impl <T: ChannelledTransport> GatewayReceivers<T> {

    pub fn get_or_create<M: Message, F: FnOnce() -> UR<T>>(&self, channel_id: &ChannelId, ctr: F) -> UR<T> {
        let receivers = self.inner.read().unwrap();
        match receivers.get(&channel_id) {
            Some(recv) => recv.clone(),
            None => {
                let mut receivers = self.inner.write().unwrap();
                match receivers.entry(channel_id.clone()) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let stream = ctr();
                        entry.insert(stream).clone()
                    }
                }
            }
        }
    }
}

type UR<T> = UnorderedReceiver<<T as ChannelledTransport>::RecordsStream, <<T as ChannelledTransport>::RecordsStream as Stream>::Item>;

struct RoleResolvingTransport<T> {
    roles: [HelperIdentity; 3],
    inner: T
}

impl <T: ChannelledTransport> RoleResolvingTransport<T> {
    /// SAFETY: 16 is a valid non-zero usize value
    const RECV_CAPACITY: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(16) };

    async fn send(&self, channel_id: &ChannelId, data: OrderingMpscReceiver<Wrapper>) {
        let dest_identity = self.roles[channel_id.role];
        assert_ne!(dest_identity, self.inner.identity(), "can't send message to itself");

        self.inner.send(dest_identity, (RouteId::Records, QueryId, channel_id.step.clone()), data).await.unwrap()
    }

    fn receive(&self, channel_id: &ChannelId) -> UR<T> {
        let peer = self.roles[channel_id.role];
        assert_ne!(peer, self.inner.identity(), "can't receive message from itself");

        UnorderedReceiver::new(
            Box::pin(self.inner.receive(peer, (QueryId, channel_id.step.clone()))),
         Self::RECV_CAPACITY)
    }
}


struct Gateway<'a> {
    transport: &'a RoleResolvingTransport<Transport>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<Transport>,
}

impl Gateway<'_> {

    pub async fn get_sender<'a, 'b: 'a, M: Message>(&'a self, channel_id: &'b ChannelId, total_records: TotalRecords) -> SendingEnd<'a, M> {
        let (sending_end, maybe_recv) = self.senders.get_or_create(channel_id, total_records);
        if let Some(recv) = maybe_recv {
            self.transport.send(channel_id, recv).await;
        }

        sending_end
    }

    pub async fn get_receiver<M: Message>(&self, channel_id: &ChannelId) -> ReceivingEnd<Transport, M> {
        ReceivingEnd::new(self.receivers.get_or_create::<M, _>(channel_id, || {
            self.transport.receive(channel_id)
        }))
    }
}


enum Transport {
    #[cfg(feature = "test-fixture")]
    InMemory(crate::test_fixture::transport::InMemoryChannelledTransport)
}

#[async_trait]
impl ChannelledTransport for Transport {
    #[cfg(feature = "test-fixture")]
    type RecordsStream = crate::test_fixture::transport::InMemoryChannelledTransport;
    // TODO: it is likely that this ends up being the only type we could use here.
    #[cfg(not(feature = "test-fixture"))]
    type RecordsStream = std::pin::Pin<Box<dyn Stream<Item = Vec<u8>>>>;

    fn identity(&self) -> HelperIdentity {
        match self {
            #[cfg(feature = "test-fixture")]
            Transport::InMemory(ref inner) => inner.identity(),
            // https://github.com/rust-lang/rust/issues/78123
            _ => unreachable!()
        }
    }

    async fn send<D, Q, S, R>(&self, dest: HelperIdentity, route: R, data: D) -> Result<(), std::io::Error> where Option<QueryId>: From<Q>, Option<Step>: From<S>, Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>, D: Stream<Item=Vec<u8>> + Send + 'static {
        match self {
            #[cfg(feature = "test-fixture")]
            Transport::InMemory(inner) => inner.send(dest, route, data),
            _ => unreachable!()
        }
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(&self, from: HelperIdentity, route: R) -> Self::RecordsStream {
        match self {
            #[cfg(feature = "test-fixture")]
            Transport::InMemory(inner) => inner.receive(from, route),
            _ => unreachable!()
        }
    }
}
