use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    io,
    pin::Pin,
    task::{Context, Poll},
};

use ::tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

use crate::{
    error::BoxError,
    helpers::{
        in_memory_config,
        in_memory_config::DynStreamInterceptor,
        transport::routing::{Addr, RouteId},
        ApiError, BodyStream, HandlerRef, HelperIdentity, HelperResponse, NoResourceIdentifier,
        QueryIdBinding, ReceiveRecords, RequestHandler, RouteParams, ShardedTransport, StepBinding,
        StreamCollection, Transport, TransportIdentity,
    },
    protocol::{Gate, QueryId},
    sharding::{ShardIndex, Sharded},
    sync::{Arc, Weak},
};

type Packet<I> = (
    Addr<I>,
    InMemoryStream,
    oneshot::Sender<Result<HelperResponse, ApiError>>,
);
type ConnectionTx<I> = Sender<Packet<I>>;
type ConnectionRx<I> = Receiver<Packet<I>>;
type StreamItem = Result<Bytes, BoxError>;

#[derive(Debug, thiserror::Error)]
pub enum Error<I> {
    #[error(transparent)]
    Io {
        #[from]
        inner: io::Error,
    },
    #[error("Request rejected by remote {dest:?}: {inner:?}")]
    Rejected {
        dest: I,
        #[source]
        inner: BoxError,
    },
    #[error(transparent)]
    DeserializationFailed {
        #[from]
        inner: serde_json::Error,
    },
}

/// In-memory implementation of [`Transport`] backed by Tokio mpsc channels.
/// Use [`Setup`] to initialize it and call [`Setup::start`] to make it actively listen for
/// incoming messages.
pub struct InMemoryTransport<I> {
    identity: I,
    connections: HashMap<I, ConnectionTx<I>>,
    record_streams: StreamCollection<I, InMemoryStream>,
    config: TransportConfig,
}

impl<I: TransportIdentity> InMemoryTransport<I> {
    #[must_use]
    fn with_config(
        identity: I,
        connections: HashMap<I, ConnectionTx<I>>,
        config: TransportConfig,
    ) -> Self {
        Self {
            identity,
            connections,
            record_streams: StreamCollection::default(),
            config,
        }
    }

    #[must_use]
    pub fn identity(&self) -> I {
        self.identity
    }

    /// TODO: maybe it shouldn't be active, but rather expose a method that takes the next message
    /// out and processes it, the same way as query processor does. That will allow all tasks to be
    /// created in one place (driver). It does not affect the [`Transport`] interface,
    /// so I'll leave it as is for now.
    fn listen(self: &Arc<Self>, handler: Option<HandlerRef<I>>, mut rx: ConnectionRx<I>) {
        tokio::spawn(
            {
                let streams = self.record_streams.clone();
                async move {
                    while let Some((addr, stream, ack)) = rx.recv().await {
                        tracing::trace!("received new message: {addr:?}");

                        let result = match addr.route {
                            RouteId::Records => {
                                let query_id = addr.query_id.unwrap();
                                let gate = addr.gate.unwrap();
                                let from = addr.origin.unwrap();
                                streams.add_stream((query_id, from, gate), stream);
                                Ok(HelperResponse::ok())
                            }
                            RouteId::ReceiveQuery
                            | RouteId::PrepareQuery
                            | RouteId::QueryInput
                            | RouteId::QueryStatus
                            | RouteId::CompleteQuery
                            | RouteId::KillQuery => {
                                handler
                                    .as_ref()
                                    .expect("Handler is set")
                                    .handle(addr, BodyStream::from_bytes_stream(stream))
                                    .await
                            }
                        };

                        ack.send(result).map_err(|_| "Channel closed").unwrap();
                    }
                }
            }
            .instrument(tracing::info_span!("transport_loop", id=?self.identity).or_current()),
        );
    }

    fn get_channel(&self, dest: I) -> ConnectionTx<I> {
        self.connections
            .get(&dest)
            .unwrap_or_else(|| {
                panic!(
                    "Should have an active connection from {:?} to {:?}",
                    self.identity, dest
                );
            })
            .clone()
    }

    /// Resets this transport, making it forget its state and be ready for processing another query.
    pub fn reset(&self) {
        self.record_streams.clear();
    }
}

#[async_trait]
impl<I: TransportIdentity> Transport for Weak<InMemoryTransport<I>> {
    type Identity = I;
    type RecordsStream = ReceiveRecords<I, InMemoryStream>;
    type Error = Error<I>;

    fn identity(&self) -> I {
        self.upgrade().unwrap().identity
    }

    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: I,
        route: R,
        data: D,
    ) -> Result<(), Error<I>>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        let this = self.upgrade().unwrap();
        let channel = this.get_channel(dest);
        let addr = Addr::from_route(Some(this.identity), route);
        let gate = addr.gate.clone();

        let (ack_tx, ack_rx) = oneshot::channel();
        let context = gate
            .map(|gate| dest.inspect_context(this.config.shard_config, this.config.identity, gate));

        channel
            .send((
                addr,
                InMemoryStream::wrap(data.map({
                    move |mut chunk| {
                        if let Some(ref context) = context {
                            this.config.stream_interceptor.peek(context, &mut chunk);
                        }
                        Ok(Bytes::from(chunk))
                    }
                })),
                ack_tx,
            ))
            .await
            .map_err(|_e| {
                io::Error::new::<String>(io::ErrorKind::ConnectionAborted, "channel closed".into())
            })?;

        ack_rx
            .await
            .map_err(|_recv_error| Error::Rejected {
                dest,
                inner: "channel closed".into(),
            })?
            .map_err(|e| Error::Rejected {
                dest,
                inner: e.into(),
            })?;

        Ok(())
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: I,
        route: R,
    ) -> Self::RecordsStream {
        ReceiveRecords::new(
            (route.query_id(), from, route.gate()),
            self.upgrade().unwrap().record_streams.clone(),
        )
    }
}

impl ShardedTransport for Weak<InMemoryTransport<ShardIndex>> {
    fn config(&self) -> Sharded {
        self.upgrade().unwrap().config.shard_config.unwrap()
    }
}

/// Convenience struct to support heterogeneous in-memory streams
pub struct InMemoryStream {
    /// There is only one reason for this to have dynamic dispatch: tests that use `from_iter` method.
    inner: Pin<Box<dyn Stream<Item = StreamItem> + Send>>,
}

impl InMemoryStream {
    fn wrap<S: Stream<Item = StreamItem> + Send + 'static>(value: S) -> Self {
        Self {
            inner: Box::pin(value),
        }
    }
}

impl From<Receiver<StreamItem>> for InMemoryStream {
    fn from(value: Receiver<StreamItem>) -> Self {
        Self {
            inner: Box::pin(ReceiverStream::new(value)),
        }
    }
}

impl Stream for InMemoryStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::get_mut(self);
        this.inner.poll_next_unpin(cx)
    }
}

impl Debug for InMemoryStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryStream")
    }
}

pub struct Setup<I> {
    identity: I,
    tx: ConnectionTx<I>,
    rx: ConnectionRx<I>,
    connections: HashMap<I, ConnectionTx<I>>,
    config: TransportConfig,
}

impl Setup<HelperIdentity> {
    #[must_use]
    #[allow(unused)]
    pub fn new(identity: HelperIdentity) -> Self {
        Self::with_config(
            identity,
            TransportConfigBuilder::for_helper(identity).not_sharded(),
        )
    }
}

impl<I: TransportIdentity> Setup<I> {
    #[must_use]
    pub fn with_config(identity: I, config: TransportConfig) -> Self {
        let (tx, rx) = channel(16);
        Self {
            identity,
            tx,
            rx,
            connections: HashMap::default(),
            config,
        }
    }

    /// Establishes a link between this helper and another one
    ///
    /// ## Panics
    /// Panics if there is a link already.
    pub fn connect(&mut self, other: &mut Self) {
        assert!(self
            .connections
            .insert(other.identity, other.tx.clone())
            .is_none());
        assert!(other
            .connections
            .insert(self.identity, self.tx.clone())
            .is_none());
    }

    pub(crate) fn start(self, handler: Option<HandlerRef<I>>) -> Arc<InMemoryTransport<I>> {
        self.into_active_conn(handler).1
    }

    fn into_active_conn(
        self,
        handler: Option<HandlerRef<I>>,
    ) -> (ConnectionTx<I>, Arc<InMemoryTransport<I>>) {
        let transport = Arc::new(InMemoryTransport::with_config(
            self.identity,
            self.connections,
            self.config,
        ));
        transport.listen(handler, self.rx);

        (self.tx, transport)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        collections::HashMap,
        io,
        io::ErrorKind,
        num::NonZeroUsize,
        panic::AssertUnwindSafe,
        sync::{Mutex, Weak},
        task::Poll,
    };

    use bytes::Bytes;
    use futures::{stream, Stream};
    use futures_util::{stream::poll_immediate, FutureExt, StreamExt};
    use tokio::sync::{mpsc::channel, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use typenum::Unsigned;

    use crate::{
        ff::{FieldType, Fp31, Serializable},
        helpers::{
            make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            transport::{
                in_memory::{
                    transport::{Addr, ConnectionTx, Error, InMemoryStream, InMemoryTransport},
                    InMemoryMpcNetwork, Setup,
                },
                routing::RouteId,
            },
            HandlerBox, HelperIdentity, HelperResponse, OrderingSender, Role, RoleAssignment,
            Transport, TransportIdentity,
        },
        protocol::{Gate, QueryId},
        sync::Arc,
    };

    const STEP: &str = "in-memory-transport";

    async fn send_and_ack<I: TransportIdentity, S: Stream<Item = Vec<u8>> + Send + 'static>(
        sender: &ConnectionTx<I>,
        addr: Addr<I>,
        data: S,
    ) {
        let data = InMemoryStream::wrap(data.map(Bytes::from).map(Ok));
        let (tx, rx) = oneshot::channel();
        sender.send((addr, data, tx)).await.unwrap();
        let _ = rx
            .await
            .map_err(|_e| Error::<I>::Io {
                inner: io::Error::new(ErrorKind::ConnectionRefused, "channel closed"),
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn handler_is_called() {
        let (signal_tx, signal_rx) = oneshot::channel();
        let signal_tx = Arc::new(Mutex::new(Some(signal_tx)));
        let handler = make_owned_handler(move |addr: Addr<HelperIdentity>, _| {
            let signal_tx = Arc::clone(&signal_tx);
            async move {
                let RouteId::ReceiveQuery = addr.route else {
                    panic!("unexpected call: {addr:?}")
                };
                let query_config = addr.into::<QueryConfig>().unwrap();

                // this works because callback is only called once
                signal_tx
                    .lock()
                    .unwrap()
                    .take()
                    .expect("query callback invoked more than once")
                    .send(query_config)
                    .unwrap();
                Ok(HelperResponse::from(PrepareQuery {
                    query_id: QueryId,
                    config: query_config,
                    roles: RoleAssignment::try_from([Role::H1, Role::H2, Role::H3]).unwrap(),
                }))
            }
        });
        let (tx, _) = Setup::new(HelperIdentity::ONE)
            .into_active_conn(Some(HandlerBox::owning_ref(&handler)));
        let expected = QueryConfig::new(TestMultiply, FieldType::Fp32BitPrime, 1u32).unwrap();

        send_and_ack(
            &tx,
            Addr::from_route(Some(HelperIdentity::TWO), expected),
            stream::empty(),
        )
        .await;

        assert_eq!(expected, signal_rx.await.unwrap());
    }

    #[tokio::test]
    async fn receive_not_ready() {
        let (tx, transport) = Setup::new(HelperIdentity::ONE).into_active_conn(None);
        let transport = Arc::downgrade(&transport);
        let expected = vec![vec![1], vec![2]];

        let mut stream = transport
            .receive(HelperIdentity::TWO, (QueryId, Gate::from(STEP)))
            .into_bytes_stream();

        // make sure it is not ready as it hasn't received the records stream yet.
        assert!(matches!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Pending)
        ));
        send_and_ack(
            &tx,
            Addr::records(HelperIdentity::TWO, QueryId, Gate::from(STEP)),
            stream::iter(expected.clone()),
        )
        .await;

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn receive_ready() {
        let (tx, transport) = Setup::new(HelperIdentity::ONE).into_active_conn(None);
        let expected = vec![vec![1], vec![2]];

        send_and_ack(
            &tx,
            Addr::records(HelperIdentity::TWO, QueryId, Gate::from(STEP)),
            stream::iter(expected.clone()),
        )
        .await;

        let stream = Arc::downgrade(&transport)
            .receive(HelperIdentity::TWO, (QueryId, Gate::from(STEP)))
            .into_bytes_stream();

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn two_helpers() {
        async fn send_and_verify(
            from: HelperIdentity,
            to: HelperIdentity,
            transports: &HashMap<HelperIdentity, Weak<InMemoryTransport<HelperIdentity>>>,
        ) {
            let (stream_tx, stream_rx) = channel(1);
            let stream = ReceiverStream::new(stream_rx);

            let from_transport = transports.get(&from).unwrap();
            let to_transport = transports.get(&to).unwrap();
            let gate = Gate::from(STEP);

            let mut recv = to_transport
                .receive(from, (QueryId, gate.clone()))
                .into_bytes_stream();
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            from_transport
                .send(to, (RouteId::Records, QueryId, gate.clone()), stream)
                .await
                .unwrap();
            stream_tx.send(vec![1, 2, 3]).await.unwrap();
            assert_eq!(vec![1, 2, 3], recv.next().await.unwrap());
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            stream_tx.send(vec![4, 5, 6]).await.unwrap();
            assert_eq!(vec![4, 5, 6], recv.next().await.unwrap());
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            drop(stream_tx);
            assert!(poll_immediate(&mut recv).next().await.is_none());
        }

        let mut setup1 = Setup::new(HelperIdentity::ONE);
        let mut setup2 = Setup::new(HelperIdentity::TWO);

        setup1.connect(&mut setup2);

        let transport1 = setup1.start(None);
        let transport2 = setup2.start(None);
        let transports = HashMap::from([
            (HelperIdentity::ONE, Arc::downgrade(&transport1)),
            (HelperIdentity::TWO, Arc::downgrade(&transport2)),
        ]);

        send_and_verify(HelperIdentity::ONE, HelperIdentity::TWO, &transports).await;
        send_and_verify(HelperIdentity::TWO, HelperIdentity::ONE, &transports).await;
    }

    #[tokio::test]
    async fn panic_if_stream_received_twice() {
        let (tx, owned_transport) = Setup::new(HelperIdentity::ONE).into_active_conn(None);
        let gate = Gate::from(STEP);
        let (stream_tx, stream_rx) = channel(1);
        let stream = ReceiverStream::from(stream_rx);
        let transport = Arc::downgrade(&owned_transport);

        let mut recv_stream = transport
            .receive(HelperIdentity::TWO, (QueryId, gate.clone()))
            .into_bytes_stream();
        send_and_ack(
            &tx,
            Addr::records(HelperIdentity::TWO, QueryId, gate.clone()),
            stream,
        )
        .await;

        stream_tx.send(vec![4, 5, 6]).await.unwrap();
        assert_eq!(vec![4, 5, 6], recv_stream.next().await.unwrap());

        // the same stream cannot be received again
        let mut err_recv = transport.receive(HelperIdentity::TWO, (QueryId, gate.clone()));
        let err = AssertUnwindSafe(err_recv.next()).catch_unwind().await;
        assert_eq!(
            Some(true),
            err.unwrap_err()
                .downcast_ref::<String>()
                .map(|s| { s.contains("stream has been consumed already") })
        );

        // even after the input stream is closed
        drop(stream_tx);
        let mut err_recv = transport.receive(HelperIdentity::TWO, (QueryId, gate.clone()));
        let err = AssertUnwindSafe(err_recv.next()).catch_unwind().await;
        assert_eq!(
            Some(true),
            err.unwrap_err()
                .downcast_ref::<String>()
                .map(|s| { s.contains("stream has been consumed already") })
        );
    }

    #[tokio::test]
    async fn can_consume_ordering_sender() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let tx = Arc::new(OrderingSender::new(
            capacity,
            <Fp31 as Serializable>::Size::USIZE.try_into().unwrap(),
            capacity,
        ));
        let rx = Arc::clone(&tx).as_rc_stream();
        let network = InMemoryMpcNetwork::default();
        let transport1 = network.transport(HelperIdentity::ONE);
        let transport2 = network.transport(HelperIdentity::TWO);

        let gate = Gate::from(STEP);
        transport1
            .send(
                HelperIdentity::TWO,
                (RouteId::Records, QueryId, gate.clone()),
                rx,
            )
            .await
            .unwrap();
        let mut recv = transport2
            .receive(HelperIdentity::ONE, (QueryId, gate))
            .into_bytes_stream();

        tx.send(0, Fp31::try_from(0_u128).unwrap()).await;
        // can't receive the value at index 0 because of buffering inside the sender
        assert_eq!(Some(Poll::Pending), poll_immediate(&mut recv).next().await);

        // make the sender ready
        tx.send(1, Fp31::try_from(1_u128).unwrap()).await;
        tx.close(2).await;
        // drop(tx);

        // must be received by now
        assert_eq!(vec![vec![0, 1]], recv.collect::<Vec<_>>().await);
    }
}

pub struct TransportConfig {
    pub shard_config: Option<Sharded>,
    pub identity: HelperIdentity,
    pub stream_interceptor: DynStreamInterceptor,
}

pub struct TransportConfigBuilder {
    identity: HelperIdentity,
    stream_interceptor: DynStreamInterceptor,
}

impl TransportConfigBuilder {
    pub fn for_helper(identity: HelperIdentity) -> Self {
        Self {
            identity,
            stream_interceptor: in_memory_config::passthrough(),
        }
    }

    pub fn with_interceptor(&mut self, interceptor: &DynStreamInterceptor) -> &mut Self {
        self.stream_interceptor = Arc::clone(interceptor);

        self
    }

    pub fn with_sharding(&self, shard_config: Option<Sharded>) -> TransportConfig {
        TransportConfig {
            shard_config,
            identity: self.identity,
            stream_interceptor: Arc::clone(&self.stream_interceptor),
        }
    }

    pub fn not_sharded(&self) -> TransportConfig {
        TransportConfig {
            shard_config: None,
            identity: self.identity,
            stream_interceptor: Arc::clone(&self.stream_interceptor),
        }
    }
}
