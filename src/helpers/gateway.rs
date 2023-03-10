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
use crate::helpers::{ChannelId, Error, HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES, Role, RoleAssignment};
use crate::helpers::{Message, TotalRecords};
use crate::helpers::transport::{Transport, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding, TransportImpl};
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

/// Gateway into IPA Infrastructure systems. This object allows sending and receiving messages
pub struct Gateway {
    config: GatewayConfig,
    transport: RoleResolvingTransport<TransportImpl>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<TransportImpl>,
}

/// Sending end of the gateway channel.
pub struct SendingEnd<M: Message> {
    channel_id: ChannelId,
    my_role: Role,
    ordering_tx: OrderingMpscSender<Wrapper>,
    total_records: TotalRecords,
    _phantom: PhantomData<M>,
}

/// Receiving end end of the gateway channel.
pub struct ReceivingEnd<M: Message> {
    unordered_rx: UR<TransportImpl>,
    _phantom: PhantomData<M>,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// The maximum number of items that can be outstanding for sending.
    pub send_outstanding: NonZeroUsize,
    /// The maximum number of items that can be outstanding for receiving.
    pub recv_outstanding: NonZeroUsize,
}

/// An adapter to send messages of the fixed size because [`OrderingMpscSender`] is generic over
/// message type.
#[derive(Debug)]
struct Wrapper([u8; Self::SIZE]);

/// Sending channels, indexed by (role, step).
struct GatewaySenders {
    inner: DashMap<ChannelId, OrderingMpscSender<Wrapper>>,
}

/// Receiving channels, indexed by (role, step).
struct GatewayReceivers<T: Transport> {
    inner: DashMap<ChannelId, UR<T>>,
}

/// Transport adapter that resolves [`Role`] -> [`HelperIdentity`] mapping. As gateways created
/// per query, it is not ambiguous.
#[derive(Clone)]
struct RoleResolvingTransport<T> {
    query_id: QueryId,
    roles: RoleAssignment,
    config: GatewayConfig,
    inner: T,
}

impl Gateway {
    pub fn new(query_id: QueryId, config: GatewayConfig, roles: RoleAssignment, transport: TransportImpl) -> Self {
        Self {
            config,
            transport: RoleResolvingTransport {
                query_id,
                roles,
                inner: transport,
                config,
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

impl<M: Message> SendingEnd<M> {
    fn new(channel_id: ChannelId, my_role: Role, tx: OrderingMpscSender<Wrapper>, total_records: TotalRecords) -> Self {
        Self {
            channel_id,
            my_role,
            ordering_tx: tx,
            total_records,
            _phantom: PhantomData,
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

impl<M: Message> ReceivingEnd<M> {
    fn new(rx: UR<TransportImpl>) -> Self {
        Self {
            unordered_rx: rx,
            _phantom: PhantomData,
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


impl Default for GatewaySenders {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
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
                            capacity,
                        );
                        (entry.insert(tx).clone(), Some(rx))
                    }
                }
            }
        }
    }
}


impl<T: Transport> Default for GatewayReceivers<T> {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
        }
    }
}

impl<T: Transport> GatewayReceivers<T> {
    pub fn get_or_create<M: Message, F: FnOnce() -> UR<T>>(&self, channel_id: &ChannelId, ctr: F) -> UR<T> {
        let receivers = &self.inner;
        let recv = match receivers.get(&channel_id) {
            Some(recv) => recv.clone(),
            None => {
                match receivers.entry(channel_id.clone()) {
                    Entry::Occupied(entry) => {
                        entry.get().clone()
                    }
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

type UR<T> = UnorderedReceiver<<T as Transport>::RecordsStream, <<T as Transport>::RecordsStream as Stream>::Item>;


impl<T: Transport> RoleResolvingTransport<T> {
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::Fp31,
        helpers::{TotalRecords, Role},
        protocol::{context::Context, RecordId, Step},
        test_fixture::{TestWorld, TestWorldConfig},
    };
    use std::num::NonZeroUsize;
    use futures_util::future::{try_join, try_join_all};
    use tokio_stream::StreamExt;

    #[tokio::test]
    pub async fn handles_reordering() {
        let mut config = TestWorldConfig::default();
        config.gateway_config.send_outstanding = 2.try_into().unwrap();

        let world = Box::leak(Box::new(TestWorld::new_with(config).await));
        let contexts = world.contexts();
        let sender_ctx = contexts[0].narrow("reordering-test").set_total_records(2);
        let recv_ctx = contexts[1].narrow("reordering-test").set_total_records(2);

        // send record 1 first and wait for confirmation before sending record 0.
        // when gateway received record 0 it triggers flush so it must make sure record 1 is also
        // sent (same batch or different does not matter here)
        tokio::spawn(async move {
            let channel = sender_ctx.send_channel(Role::H2);
            channel
                .send(RecordId::from(1), Fp31::from(1_u128))
                .await
                .unwrap();
            channel
                .send(RecordId::from(0), Fp31::from(0_u128))
                .await
                .unwrap();
        });

        let recv_channel = recv_ctx.recv_channel::<Fp31>(Role::H1);
        let result = try_join(
            recv_channel.receive(RecordId::from(1)),
            recv_channel.receive(RecordId::from(0)),
        ).await.unwrap();

        assert_eq!((Fp31::from(1u128), Fp31::from(0u128)), result)
    }
}
