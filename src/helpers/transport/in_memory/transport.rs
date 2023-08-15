use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    convert,
    fmt::{Debug, Formatter},
    io,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use ::tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use serde::de::DeserializeOwned;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

use crate::{
    error::BoxError,
    helpers::{
        query::{PrepareQuery, QueryConfig},
        HelperIdentity, NoResourceIdentifier, QueryIdBinding, ReceiveRecords, RouteId, RouteParams,
        StepBinding, StreamCollection, Transport, TransportCallbacks,
    },
    protocol::{step::Gate, QueryId},
};

type Packet = (Addr, InMemoryStream, oneshot::Sender<Result<(), Error>>);
type ConnectionTx = Sender<Packet>;
type ConnectionRx = Receiver<Packet>;
type StreamItem = Vec<u8>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io {
        #[from]
        inner: io::Error,
    },
    #[error("Request rejected by remote {dest:?}: {inner:?}")]
    Rejected {
        dest: HelperIdentity,
        #[source]
        inner: BoxError,
    },
}

/// In-memory implementation of [`Transport`] backed by Tokio mpsc channels.
/// Use [`Setup`] to initialize it and call [`Setup::start`] to make it actively listen for
/// incoming messages.
pub struct InMemoryTransport {
    identity: HelperIdentity,
    connections: HashMap<HelperIdentity, ConnectionTx>,
    record_streams: StreamCollection<InMemoryStream>,
}

impl InMemoryTransport {
    #[must_use]
    fn new(identity: HelperIdentity, connections: HashMap<HelperIdentity, ConnectionTx>) -> Self {
        Self {
            identity,
            connections,
            record_streams: StreamCollection::default(),
        }
    }

    #[must_use]
    pub fn identity(&self) -> HelperIdentity {
        self.identity
    }

    /// TODO: maybe it shouldn't be active, but rather expose a method that takes the next message
    /// out and processes it, the same way as query processor does. That will allow all tasks to be
    /// created in one place (driver). It does not affect the [`Transport`] interface,
    /// so I'll leave it as is for now.
    fn listen(self: &Arc<Self>, callbacks: TransportCallbacks<Weak<Self>>, mut rx: ConnectionRx) {
        tokio::spawn(
            {
                let streams = self.record_streams.clone();
                let this = Arc::downgrade(self);
                let dest = this.identity();
                async move {
                    let mut active_queries = HashSet::new();
                    while let Some((addr, stream, ack)) = rx.recv().await {
                        tracing::trace!("received new message: {addr:?}");

                        let result = match addr.route {
                            RouteId::ReceiveQuery => {
                                let qc = addr.into::<QueryConfig>();
                                (callbacks.receive_query)(Transport::clone_ref(&this), qc)
                                    .await
                                    .map(|query_id| {
                                        assert!(
                                            active_queries.insert(query_id),
                                            "the same query id {query_id:?} is generated twice"
                                        );
                                    })
                                    .map_err(|e| Error::Rejected {
                                        dest,
                                        inner: Box::new(e),
                                    })
                            }
                            RouteId::Records => {
                                let query_id = addr.query_id.unwrap();
                                let gate = addr.gate.unwrap();
                                let from = addr.origin.unwrap();
                                streams.add_stream((query_id, from, gate), stream);
                                Ok(())
                            }
                            RouteId::PrepareQuery => {
                                let input = addr.into::<PrepareQuery>();
                                (callbacks.prepare_query)(Transport::clone_ref(&this), input)
                                    .await
                                    .map_err(|e| Error::Rejected {
                                        dest,
                                        inner: Box::new(e),
                                    })
                            }
                        };

                        ack.send(result).unwrap();
                    }
                }
            }
            .instrument(tracing::info_span!("transport_loop", id=?self.identity).or_current()),
        );
    }

    fn get_channel(&self, dest: HelperIdentity) -> ConnectionTx {
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
impl Transport for Weak<InMemoryTransport> {
    type RecordsStream = ReceiveRecords<InMemoryStream>;
    type Error = Error;

    fn identity(&self) -> HelperIdentity {
        self.upgrade().unwrap().identity
    }

    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: HelperIdentity,
        route: R,
        data: D,
    ) -> Result<(), Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        let this = self.upgrade().unwrap();
        let channel = this.get_channel(dest);
        let addr = Addr::from_route(this.identity, route);
        let (ack_tx, ack_rx) = oneshot::channel();

        channel
            .send((addr, InMemoryStream::wrap(data), ack_tx))
            .await
            .map_err(|_e| {
                io::Error::new::<String>(io::ErrorKind::ConnectionAborted, "channel closed".into())
            })?;

        ack_rx
            .await
            .map_err(|_recv_error| Error::Rejected {
                dest,
                inner: "channel closed".into(),
            })
            .and_then(convert::identity)
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Self::RecordsStream {
        ReceiveRecords::new(
            (route.query_id(), from, route.gate()),
            self.upgrade().unwrap().record_streams.clone(),
        )
    }
}

/// Convenience struct to support heterogeneous in-memory streams
pub struct InMemoryStream {
    /// There is only one reason for this to have dynamic dispatch: tests that use from_iter method.
    inner: Pin<Box<dyn Stream<Item = StreamItem> + Send>>,
}

impl InMemoryStream {
    #[cfg(all(test, unit_test))]
    fn empty() -> Self {
        Self::from_iter(std::iter::empty())
    }

    fn wrap<S: Stream<Item = StreamItem> + Send + 'static>(value: S) -> Self {
        Self {
            inner: Box::pin(value),
        }
    }

    #[cfg(all(test, unit_test))]
    fn from_iter<I>(input: I) -> Self
    where
        I: IntoIterator<Item = StreamItem>,
        I::IntoIter: Send + 'static,
    {
        use futures_util::stream;
        Self {
            inner: Box::pin(stream::iter(input.into_iter())),
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

struct Addr {
    route: RouteId,
    origin: Option<HelperIdentity>,
    query_id: Option<QueryId>,
    gate: Option<Gate>,
    params: String,
}

impl Addr {
    #[allow(clippy::needless_pass_by_value)] // to avoid using double-reference at callsites
    fn from_route<Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>>(
        origin: HelperIdentity,
        route: R,
    ) -> Self
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        Self {
            route: route.resource_identifier(),
            origin: Some(origin),
            query_id: route.query_id().into(),
            gate: route.gate().into(),
            params: route.extra().borrow().to_string(),
        }
    }

    fn into<T: DeserializeOwned>(self) -> T {
        serde_json::from_str(&self.params).unwrap()
    }

    #[cfg(all(test, unit_test))]
    fn records(from: HelperIdentity, query_id: QueryId, gate: Gate) -> Self {
        Self {
            route: RouteId::Records,
            origin: Some(from),
            query_id: Some(query_id),
            gate: Some(gate),
            params: String::new(),
        }
    }
}

impl Debug for Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Addr[route={:?}, query_id={:?}, step={:?}, params={}]",
            self.route, self.query_id, self.gate, self.params
        )
    }
}

pub struct Setup {
    identity: HelperIdentity,
    tx: ConnectionTx,
    rx: ConnectionRx,
    connections: HashMap<HelperIdentity, ConnectionTx>,
}

impl Setup {
    #[must_use]
    pub fn new(identity: HelperIdentity) -> Self {
        let (tx, rx) = channel(16);
        Self {
            identity,
            tx,
            rx,
            connections: HashMap::default(),
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

    fn into_active_conn(
        self,
        callbacks: TransportCallbacks<Weak<InMemoryTransport>>,
    ) -> (ConnectionTx, Arc<InMemoryTransport>) {
        let transport = Arc::new(InMemoryTransport::new(self.identity, self.connections));
        transport.listen(callbacks, self.rx);

        (self.tx, transport)
    }

    #[must_use]
    pub fn start(
        self,
        callbacks: TransportCallbacks<Weak<InMemoryTransport>>,
    ) -> Arc<InMemoryTransport> {
        self.into_active_conn(callbacks).1
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{io::ErrorKind, num::NonZeroUsize, panic::AssertUnwindSafe, sync::Mutex};

    use futures_util::{stream::poll_immediate, FutureExt, StreamExt};
    use tokio::sync::{mpsc::channel, oneshot};

    use super::*;
    use crate::{
        ff::{FieldType, Fp31},
        helpers::{
            query::QueryType::TestMultiply, transport::in_memory::InMemoryNetwork, HelperIdentity,
            OrderingSender,
        },
    };

    const STEP: &str = "in-memory-transport";

    async fn send_and_ack(sender: &ConnectionTx, addr: Addr, data: InMemoryStream) {
        let (tx, rx) = oneshot::channel();
        sender.send((addr, data, tx)).await.unwrap();
        rx.await
            .map_err(|_e| Error::Io {
                inner: io::Error::new(ErrorKind::ConnectionRefused, "channel closed"),
            })
            .and_then(convert::identity)
            .unwrap();
    }

    #[tokio::test]
    async fn callback_is_called() {
        let (signal_tx, signal_rx) = oneshot::channel();
        let signal_tx = Arc::new(Mutex::new(Some(signal_tx)));
        let (tx, _transport) =
            Setup::new(HelperIdentity::ONE).into_active_conn(TransportCallbacks {
                receive_query: Box::new(move |_transport, query_config| {
                    let signal_tx = Arc::clone(&signal_tx);
                    Box::pin(async move {
                        // this works because callback is only called once
                        signal_tx
                            .lock()
                            .unwrap()
                            .take()
                            .expect("query callback invoked more than once")
                            .send(query_config)
                            .unwrap();
                        Ok(QueryId)
                    })
                }),
                ..Default::default()
            });
        let expected = QueryConfig::new(TestMultiply, FieldType::Fp32BitPrime, 1u32).unwrap();

        send_and_ack(
            &tx,
            Addr::from_route(HelperIdentity::TWO, &expected),
            InMemoryStream::empty(),
        )
        .await;

        assert_eq!(expected, signal_rx.await.unwrap());
    }

    #[tokio::test]
    async fn receive_not_ready() {
        let (tx, transport) =
            Setup::new(HelperIdentity::ONE).into_active_conn(TransportCallbacks::default());
        let transport = Arc::downgrade(&transport);
        let expected = vec![vec![1], vec![2]];

        let mut stream = transport.receive(HelperIdentity::TWO, (QueryId, Gate::from(STEP)));

        // make sure it is not ready as it hasn't received the records stream yet.
        assert!(matches!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Pending)
        ));
        send_and_ack(
            &tx,
            Addr::records(HelperIdentity::TWO, QueryId, Gate::from(STEP)),
            InMemoryStream::from_iter(expected.clone()),
        )
        .await;

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn receive_ready() {
        let (tx, transport) =
            Setup::new(HelperIdentity::ONE).into_active_conn(TransportCallbacks::default());
        let expected = vec![vec![1], vec![2]];

        send_and_ack(
            &tx,
            Addr::records(HelperIdentity::TWO, QueryId, Gate::from(STEP)),
            InMemoryStream::from_iter(expected.clone()),
        )
        .await;

        let stream =
            Arc::downgrade(&transport).receive(HelperIdentity::TWO, (QueryId, Gate::from(STEP)));

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn two_helpers() {
        async fn send_and_verify(
            from: HelperIdentity,
            to: HelperIdentity,
            transports: &HashMap<HelperIdentity, Weak<InMemoryTransport>>,
        ) {
            let (stream_tx, stream_rx) = channel(1);
            let stream = InMemoryStream::from(stream_rx);

            let from_transport = transports.get(&from).unwrap();
            let to_transport = transports.get(&to).unwrap();
            let gate = Gate::from(STEP);

            let mut recv = to_transport.receive(from, (QueryId, gate.clone()));
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
            assert!(matches!(poll_immediate(&mut recv).next().await, None));
        }

        let mut setup1 = Setup::new(HelperIdentity::ONE);
        let mut setup2 = Setup::new(HelperIdentity::TWO);

        setup1.connect(&mut setup2);

        let transport1 = setup1.start(TransportCallbacks::default());
        let transport2 = setup2.start(TransportCallbacks::default());
        let transports = HashMap::from([
            (HelperIdentity::ONE, Arc::downgrade(&transport1)),
            (HelperIdentity::TWO, Arc::downgrade(&transport2)),
        ]);

        send_and_verify(HelperIdentity::ONE, HelperIdentity::TWO, &transports).await;
        send_and_verify(HelperIdentity::TWO, HelperIdentity::ONE, &transports).await;
    }

    #[tokio::test]
    async fn panic_if_stream_received_twice() {
        let (tx, owned_transport) =
            Setup::new(HelperIdentity::ONE).into_active_conn(TransportCallbacks::default());
        let gate = Gate::from(STEP);
        let (stream_tx, stream_rx) = channel(1);
        let stream = InMemoryStream::from(stream_rx);
        let transport = Arc::downgrade(&owned_transport);

        let mut recv_stream = transport.receive(HelperIdentity::TWO, (QueryId, gate.clone()));
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
        let tx = Arc::new(OrderingSender::new(
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        ));
        let rx = Arc::clone(&tx).as_rc_stream();
        let network = InMemoryNetwork::default();
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
        let mut recv = transport2.receive(HelperIdentity::ONE, (QueryId, gate));

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
