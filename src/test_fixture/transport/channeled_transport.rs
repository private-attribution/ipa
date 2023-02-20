#![allow(dead_code)]

use crate::helpers::query::QueryConfig;
use crate::helpers::transport::{
    ChannelledTransport, NoResourceIdentifier, QueryIdBinding, RouteId, RouteParams, StepBinding,
};
use crate::helpers::HelperIdentity;
use crate::protocol::{QueryId, Step};
use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;
use futures_util::future::Either;
use futures_util::stream;
use serde::de::DeserializeOwned;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

struct InMemoryPacket {
    addr: RouteId,
    origin: Option<HelperIdentity>,
    query_id: Option<QueryId>,
    step: Option<Step>,
    params: String,
}

impl InMemoryPacket {
    fn from_route<Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>>(
        origin: HelperIdentity,
        route: &R,
    ) -> Self
    where
        Option<QueryId>: From<Q>,
        Option<Step>: From<S>,
    {
        Self {
            addr: route.resource_identifier(),
            origin: Some(origin),
            query_id: route.query_id().into(),
            step: route.step().into(),
            params: route.extra().to_string(),
        }
    }
}

impl Debug for InMemoryPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InMemoryPacket[addr={:?}, query_id={:?}, step={:?}, params={}]",
            self.addr, self.query_id, self.step, self.params
        )
    }
}

type ConnectionTx = Sender<(InMemoryPacket, InMemoryStream)>;
type ConnectionRx = Receiver<(InMemoryPacket, InMemoryStream)>;

type StreamCollection<S> = HashMap<(QueryId, HelperIdentity, Step), Either<S, Waker>>;

pub struct ReceiveRecords<S> {
    inner: ReceiveRecordsInner<S>,
}

struct StreamWaiter<S> {
    addr: (QueryId, HelperIdentity, Step),
    coll_ptr: Arc<Mutex<StreamCollection<S>>>,
}

impl<S: Stream> StreamWaiter<S> {
    fn check(&self, waker: &Waker) -> Option<S> {
        let mut streams = self.coll_ptr.lock().unwrap();
        match streams.insert(self.addr.clone(), Either::Right(waker.clone())) {
            None => None,
            Some(either) => {
                match either {
                    Either::Left(stream) => {
                        // TODO: if stream has been consumed, nothing prevents transport client
                        // to call receive again with the same arguments. It may be fine though
                        // as it won't ever return `Poll::Ready`
                        Some(stream)
                    }
                    Either::Right(old_waker) => {
                        assert!(old_waker.will_wake(waker));
                        None
                    }
                }
            }
        }
    }
}

enum ReceiveRecordsInner<S> {
    Uninitialized(StreamWaiter<S>),
    Initialized(S),
}

impl<S: Stream + Unpin> Stream for ReceiveRecords<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl<S: Stream + Unpin> Stream for ReceiveRecordsInner<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::get_mut(self);
        loop {
            match this {
                ReceiveRecordsInner::Uninitialized(waiter) => match waiter.check(cx.waker()) {
                    None => {
                        return Poll::Pending;
                    }
                    Some(stream) => *this = ReceiveRecordsInner::Initialized(stream),
                },
                ReceiveRecordsInner::Initialized(stream) => {
                    return stream.poll_next_unpin(cx);
                }
            }
        }
    }
}

type StreamItem = Vec<u8>;

struct InMemoryStream {
    /// There is only one reason for this to have dynamic dispatch: tests that use from_iter method.
    inner: Option<Pin<Box<dyn Stream<Item = StreamItem> + Send>>>,
}

impl Debug for InMemoryStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryStream")
    }
}

impl InMemoryStream {
    fn empty() -> Self {
        Self { inner: None }
    }

    fn from_iter<I>(input: I) -> Self
    where
        I: IntoIterator<Item = StreamItem>,
        I::IntoIter: Send + 'static,
    {
        Self {
            inner: Some(Box::pin(stream::iter(input.into_iter()))),
        }
    }
}

impl From<Receiver<StreamItem>> for InMemoryStream {
    fn from(value: Receiver<StreamItem>) -> Self {
        Self {
            inner: Some(Box::pin(ReceiverStream::new(value))),
        }
    }
}

impl Stream for InMemoryStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::get_mut(self);
        match &mut this.inner {
            None => Poll::Ready(None),
            Some(s) => s.poll_next_unpin(cx),
        }
    }
}

impl InMemoryPacket {
    pub fn into<T: DeserializeOwned>(self) -> T {
        serde_json::from_str(&self.params).unwrap()
    }

    pub fn receive_query(config: QueryConfig) -> Self {
        Self {
            addr: RouteId::ReceiveQuery,
            origin: None,
            query_id: None,
            step: None,
            params: serde_json::to_string(&config).unwrap(),
        }
    }

    pub fn records(from: HelperIdentity, query_id: QueryId, step: Step) -> Self {
        Self {
            addr: RouteId::Records,
            origin: Some(from),
            query_id: Some(query_id),
            step: Some(step),
            params: String::new(),
        }
    }
}

trait ReceiveQueryCallback:
    FnMut(QueryConfig) -> Pin<Box<dyn Future<Output = Result<QueryId, String>> + Send>> + Send
{
}

impl<
        F: FnMut(QueryConfig) -> Pin<Box<dyn Future<Output = Result<QueryId, String>> + Send>> + Send,
    > ReceiveQueryCallback for F
{
}

struct TransportCallbacks<RQC: ReceiveQueryCallback> {
    receive_query: RQC,
}

struct Setup<CB: ReceiveQueryCallback> {
    identity: HelperIdentity,
    tx: ConnectionTx,
    rx: ConnectionRx,
    callbacks: TransportCallbacks<CB>,
    connections: HashMap<HelperIdentity, ConnectionTx>,
}

impl<CB: ReceiveQueryCallback + 'static> Setup<CB> {
    pub fn new(identity: HelperIdentity, callbacks: TransportCallbacks<CB>) -> Self {
        let (tx, rx) = channel(1);
        Self {
            identity,
            tx,
            rx,
            callbacks,
            connections: HashMap::default(),
        }
    }

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

    pub fn finish(self) -> (ConnectionTx, InMemoryChannelledTransport) {
        let transport = InMemoryChannelledTransport::new(self.identity, self.connections);
        transport.listen(self.callbacks, self.rx);

        (self.tx, transport)
    }
}

struct InMemoryChannelledTransport {
    identity: HelperIdentity,
    connections: HashMap<HelperIdentity, ConnectionTx>,
    record_streams: Arc<Mutex<StreamCollection<InMemoryStream>>>,
}

impl InMemoryChannelledTransport {
    pub fn listen<CB: ReceiveQueryCallback + 'static>(
        &self,
        mut callbacks: TransportCallbacks<CB>,
        mut rx: ConnectionRx,
    ) {
        tokio::spawn({
            let streams = Arc::clone(&self.record_streams);
            async move {
                while let Some((msg, stream)) = rx.recv().await {
                    tracing::trace!("received new packet: {msg:?}");

                    match msg.addr {
                        RouteId::ReceiveQuery => {
                            let qc = msg.into::<QueryConfig>();
                            let _query_id = (callbacks.receive_query)(qc)
                                .await
                                .expect("Should be able to receive a new query request");
                        }
                        RouteId::Records => {
                            let query_id = msg.query_id.unwrap();
                            let step = msg.step.unwrap();
                            let from = msg.origin.unwrap();
                            let mut streams = streams.lock().unwrap();
                            match streams.entry((query_id, from, step)) {
                                Entry::Occupied(mut entry) => {
                                    match entry.get_mut() {
                                        Either::Left(_) => {
                                            panic!("{:?} entry already has an active stream", entry.key());
                                        }
                                        waker_entry @ Either::Right(_) => {
                                            let Either::Right(waker) = std::mem::replace(waker_entry, Either::Left(stream)) else {
                                                unreachable!()
                                            };
                                            waker.wake();
                                        }
                                    }
                                }
                                Entry::Vacant(entry) => {
                                    entry.insert(Either::Left(stream));
                                }
                            }
                        }
                    }
                };
            }
        }.instrument(tracing::info_span!("transport_loop", id=?self.identity).or_current()));
    }
}

impl InMemoryChannelledTransport {
    pub fn new(
        identity: HelperIdentity,
        connections: HashMap<HelperIdentity, ConnectionTx>,
    ) -> Self {
        Self {
            identity,
            connections,
            record_streams: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

impl InMemoryChannelledTransport {
    fn get_channel(&self, dest: HelperIdentity) -> ConnectionTx {
        self.connections
            .get(&dest)
            .unwrap_or_else(|| {
                panic!(
                    "Should have an active connection from {:?} to {:?}",
                    self.identity, dest
                )
            })
            .clone()
    }
}

#[async_trait]
impl ChannelledTransport for InMemoryChannelledTransport {
    type DataStream = InMemoryStream;
    type RecordsStream = ReceiveRecords<Self::DataStream>;

    fn identity(&self) -> HelperIdentity {
        self.identity
    }

    async fn send<Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>>(
        &self,
        dest: HelperIdentity,
        route: R,
        data: Self::DataStream,
    ) -> Result<(), io::Error>
    where
        Option<QueryId>: From<Q>,
        Option<Step>: From<S>,
    {
        let channel = self.get_channel(dest);
        let packet = InMemoryPacket::from_route(self.identity, &route);

        channel.send((packet, data)).await.map_err(|_e| {
            io::Error::new::<String>(io::ErrorKind::ConnectionAborted, "channel closed".into())
        })
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Result<Self::RecordsStream, io::Error> {
        let query_id = route.query_id();
        let step = route.step();
        Ok(ReceiveRecords {
            inner: ReceiveRecordsInner::Uninitialized(StreamWaiter {
                addr: (query_id, from, step),
                coll_ptr: Arc::clone(&self.record_streams),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ff::FieldType;
    use crate::helpers::query::QueryType;
    use crate::helpers::HelperIdentity;
    use crate::protocol::Step;
    use futures_util::stream::poll_immediate;
    use tokio::sync::mpsc::channel;
    use tokio::sync::oneshot;

    const STEP: &str = "in-memory-transport";

    fn stub_callbacks() -> TransportCallbacks<impl ReceiveQueryCallback> {
        TransportCallbacks {
            receive_query: move |_| Box::pin(async { unimplemented!() }),
        }
    }

    fn one_transport_setup<I: Into<i32>, C: ReceiveQueryCallback + 'static>(
        id: I,
        cb: TransportCallbacks<C>,
    ) -> Setup<C> {
        let id = HelperIdentity::from(id.into());

        Setup::new(id, cb)
    }

    fn one_transport<I: Into<i32>, C: ReceiveQueryCallback + 'static>(
        id: I,
        cb: TransportCallbacks<C>,
    ) -> (ConnectionTx, InMemoryChannelledTransport) {
        one_transport_setup(id, cb).finish()
    }

    #[tokio::test]
    async fn callback_is_called() {
        let (signal_tx, signal_rx) = oneshot::channel();
        let signal_tx = Arc::new(Mutex::new(Some(signal_tx)));
        let (tx, _transport) = one_transport(
            1,
            TransportCallbacks {
                receive_query: move |query_config| {
                    Box::pin({
                        let signal_tx = Arc::clone(&signal_tx);
                        async move {
                            // this works because callback is only called once
                            signal_tx
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send(query_config)
                                .unwrap();
                            Ok(QueryId)
                        }
                    })
                },
            },
        );
        let expected = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };
        tx.send((
            InMemoryPacket::receive_query(expected),
            InMemoryStream::empty(),
        ))
        .await
        .unwrap();

        assert_eq!(expected, signal_rx.await.unwrap());
    }

    #[tokio::test]
    async fn receive_not_ready() {
        let (tx, transport) = one_transport(1, stub_callbacks());
        let from = HelperIdentity::from(2);
        let expected = vec![vec![1], vec![2]];

        let mut stream = transport
            .receive(from, (QueryId, Step::from(STEP)))
            .unwrap();

        // make sure it is not ready as it hasn't received the records stream yet.
        assert!(matches!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Pending)
        ));
        tx.send((
            InMemoryPacket::records(from, QueryId, Step::from(STEP)),
            InMemoryStream::from_iter(expected.clone()),
        ))
        .await
        .unwrap();

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn receive_ready() {
        let (tx, transport) = one_transport(1, stub_callbacks());
        let from = HelperIdentity::from(2);
        let expected = vec![vec![1], vec![2]];

        tx.send((
            InMemoryPacket::records(from, QueryId, Step::from(STEP)),
            InMemoryStream::from_iter(expected.clone()),
        ))
        .await
        .unwrap();
        let stream = transport
            .receive(from, (QueryId, Step::from(STEP)))
            .unwrap();

        assert_eq!(expected, stream.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn two_helpers() {
        async fn send_and_verify(
            from: HelperIdentity,
            to: HelperIdentity,
            transports: &HashMap<HelperIdentity, InMemoryChannelledTransport>,
        ) {
            let (sink, stream) = channel(1);
            let stream = InMemoryStream::from(stream);

            let from_transport = transports.get(&from).unwrap();
            let to_transport = transports.get(&to).unwrap();
            let step = Step::from(STEP);

            let mut recv = to_transport.receive(from, (QueryId, step.clone())).unwrap();
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            from_transport
                .send(to, (RouteId::Records, QueryId, step.clone()), stream)
                .await
                .unwrap();
            sink.send(vec![1, 2, 3]).await.unwrap();
            assert_eq!(vec![1, 2, 3], recv.next().await.unwrap());
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            sink.send(vec![4, 5, 6]).await.unwrap();
            assert_eq!(vec![4, 5, 6], recv.next().await.unwrap());
            assert!(matches!(
                poll_immediate(&mut recv).next().await,
                Some(Poll::Pending)
            ));

            drop(sink);
            assert!(matches!(poll_immediate(&mut recv).next().await, None));
        }

        let mut setup1 = one_transport_setup(1, stub_callbacks());
        let mut setup2 = one_transport_setup(2, stub_callbacks());

        setup1.connect(&mut setup2);

        let (_, transport1) = setup1.finish();
        let (_, transport2) = setup2.finish();
        let transports = HashMap::from([
            (HelperIdentity::from(1), transport1),
            (HelperIdentity::from(2), transport2),
        ]);

        send_and_verify(
            HelperIdentity::from(1),
            HelperIdentity::from(2),
            &transports,
        )
        .await;
        send_and_verify(
            HelperIdentity::from(2),
            HelperIdentity::from(1),
            &transports,
        )
        .await;
    }
}
