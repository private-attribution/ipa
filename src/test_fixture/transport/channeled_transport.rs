use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::io;
use std::iter::Once;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::Waker;
use async_trait::async_trait;
use futures::Stream;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::helpers::HelperIdentity;
use crate::helpers::query::{QueryConfig, QueryType};
use crate::helpers::transport::{ChannelledTransport, SendData};
use crate::protocol::QueryId;
use futures::StreamExt;
use futures_util::stream;
use sha2::digest::Output;
use crate::ff::FieldType;

#[derive(Debug)]
struct InMemoryPacket {
    meta: String,
    data: Vec<u8>,
}

type ConnectionTx = Sender<InMemoryPacket>;
type ConnectionRx = Receiver<InMemoryPacket>;

impl SendData for InMemoryPacket {
    type Body = stream::Iter<Once<Vec<u8>>>;

    fn into(self) -> (String, Self::Body) {
        (self.meta, stream::iter(std::iter::once(self.data)))
    }
}


impl InMemoryPacket {
    async fn new_from<S: SendData>(input: S) -> Self {
        let (meta, body) = input.into();
        let body = body.map(|chunk| stream::iter(chunk)).flatten().collect::<Vec<u8>>().await;

        Self {
            meta,
            data: body,
        }
    }

    pub fn receive_query(config: QueryConfig) -> Self {
        todo!()
    }
}

struct Callbacks<RCQ> {
    receive_query: RCQ,
}

type InMemoryCallbacks = Callbacks<
    // receive
    fn(QueryConfig) -> Pin<Box<dyn Future<Output=Result<QueryId, String>> + Send>>
>;

// trait TransportCallbacks {
//     type RQC: Fn(QueryConfig) -> Pin<Box<dyn Future<Output = Result<QueryId, String>> + Send>>;
//
//     fn receive_query() -> Self::RQC;
// }
//
// struct Foo {}
//
// impl TransportCallbacks for Foo {
//     type RQC = ();
//
//     fn receive_query() -> Self::RQC {
//         todo!()
//     }
// }

trait ReceiveQueryCallback: FnMut(QueryConfig) -> Pin<Box<dyn Future<Output=Result<QueryId, String>> + Send>> + Send {}

impl<F: FnMut(QueryConfig) -> Pin<Box<dyn Future<Output=Result<QueryId, String>> + Send>> + Send> ReceiveQueryCallback for F {}

struct MyCallbacks<RQC: ReceiveQueryCallback> {
    receive_query: RQC,
}


struct LockedBox<V> {
    value: Arc<Mutex<Option<V>>>,
    waker: Option<Waker>,
}

impl<V> LockedBox<V> {
    pub fn new(value: Arc<Mutex<Option<V>>>, waker: Waker) -> Self {
        Self {
            value,
            waker: Some(waker),
        }
    }
    pub fn set(mut self, value: V) {
        *self.value.lock().unwrap() = Some(value);
        self.waker.take().expect("waker should not be taken").wake();
    }
}

impl<V> Drop for LockedBox<V> {
    fn drop(&mut self) {
        assert!(self.waker.is_none())
    }
}

struct Envelope<I, O> {
    input: I,
    output: Arc<Mutex<Option<O>>>,
    waker: Waker,
}

impl<I, O> Envelope<I, O> {
    fn consume(self) -> (I, LockedBox<O>) {
        (self.input, LockedBox::new(self.output, self.waker))
    }
}

#[async_trait]
trait CustomizedTransport {
    async fn receive_query(&self) -> Envelope<QueryConfig, QueryId>;
}


struct Setup {
    identity: HelperIdentity,
    rx: ConnectionRx,
    callbacks: InMemoryCallbacks,
    connections: HashMap<HelperIdentity, ConnectionTx>,
}

impl Setup {
    pub fn new(identity: HelperIdentity, rx: ConnectionRx, callbacks: InMemoryCallbacks) -> Self {
        Self {
            identity,
            rx,
            callbacks,
            connections: HashMap::default(),
        }
    }

    pub fn connect(&mut self, peer: HelperIdentity, tx: ConnectionTx) {
        self.connections.insert(peer, tx).unwrap();
    }

    pub fn setup(self) -> InMemoryChannelledTransport {
        let transport = InMemoryChannelledTransport::new(
            self.identity,
            self.connections,
        );
        InMemoryChannelledTransport::listen(self.callbacks, self.rx);

        transport
    }
}

struct InMemoryChannelledTransport {
    identity: HelperIdentity,
    connections: HashMap<HelperIdentity, ConnectionTx>,
}

impl InMemoryChannelledTransport {
    pub fn listen2<F: ReceiveQueryCallback + 'static + Sync>(mut callbacks: MyCallbacks<F>, mut rx: ConnectionRx) {
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                println!("received a packet: {msg:?}");
                let qc = QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                };
                let query_id = (callbacks.receive_query)(qc)
                    .await
                    .expect("Should be able to receive a new query request");
            };
        });
    }
    pub fn listen(callbacks: InMemoryCallbacks, mut rx: ConnectionRx) {
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                println!("received a packet: {msg:?}");
                let qc = QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                };
                let query_id = (callbacks.receive_query)(qc)
                    .await
                    .expect("Should be able to receive a new query request");
            };
        });
    }
}

impl InMemoryChannelledTransport {
    pub fn new(identity: HelperIdentity, connections: HashMap<HelperIdentity, ConnectionTx>) -> Self {
        Self {
            identity,
            connections,
        }
    }
}


impl InMemoryChannelledTransport {
    async fn get_channel(&self, dest: HelperIdentity) -> ConnectionTx {
        self.connections.get(&dest).expect(&format!("Should have an active connection from {:?} to {:?}", self.identity, dest)).clone()
    }
}


fn upgrade(transport: &Weak<InMemoryChannelledTransport>) -> Arc<InMemoryChannelledTransport> {
    let this = transport.upgrade().expect("Transport should not be destroyed");
    this
}


#[async_trait]
impl ChannelledTransport for Weak<InMemoryChannelledTransport> {
    fn identity(&self) -> HelperIdentity {
        upgrade(self).identity
    }

    async fn send<S: SendData>(&self, dest: HelperIdentity, data: S) -> Result<(), io::Error> {
        let channel = upgrade(self)
            .get_channel(dest)
            .await;

        let packet = InMemoryPacket::new_from(data).await;

        channel.send(packet).await.map_err(|e| io::Error::new::<String>(io::ErrorKind::ConnectionAborted, "channel closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::channel;
    use tokio::sync::oneshot;
    use crate::helpers::HelperIdentity;
    use super::*;

    // async fn test_cb_trait<T: TransportCallbacks>() {
    //     let rqc = T::receive_query();
    //     let qc = QueryConfig {
    //         field_type: FieldType::Fp31,
    //         query_type: QueryType::TestMultiply,
    //     };
    //     let query_id = rqc(qc).await.unwrap();
    //     println!("query id = {query_id:?}");
    // }

    #[tokio::test]
    async fn callback() {
        let id = HelperIdentity::try_from(1).unwrap();
        let (tx, rx) = channel(1);
        let (signal_tx, signal_rx) = oneshot::channel::<()>();
        let cb = InMemoryCallbacks {
            receive_query: |(query_config)| Box::pin(async move {
                println!("received: {query_config:?}");
                // signal_tx.send(()).unwrap();
                Ok(QueryId)
            })
        };

        // let mut signal_tx2 = Some(signal_tx);
        let signal_tx2 = Some(signal_tx);
        let my_cb = MyCallbacks {
            receive_query: |(query_config)| Box::pin(async {
                println!("received: {query_config:?}");
                let y = signal_tx2.as_ref();
                // signal_tx2.take().unwrap().send(()).unwrap();
                Ok(QueryId)
            })
        };

        let setup = Setup::new(id, rx, cb);
        tx.send(InMemoryPacket::receive_query(QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        })).await.unwrap();

        // signal_rx.await.unwrap();
    }

    // #[tokio::test]
    // async fn basic_comm() {
    //     let re
    //     let identities = HelperIdentity::make_three()
    //         .map(|id| {
    //             let (tx, rx) = channel(1);
    //             Setup::new(id, rx)
    //         });
    //
    //
    // }
}
