use crate::{
    helpers::network::{MessageChunks, Network, NetworkSink},
    net::{
        discovery::{peer, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::QueryId,
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Http implementation of a [`Network`]. Uses channels for both [`Sink`] and [`Stream`]
/// implementations.
/// # Panics
/// if `recv_stream` or `recv_messages` called more than once.
#[allow(dead_code)] // TODO: WIP
pub struct HttpNetwork<'a> {
    peers: &'a [peer::Config; 3],
    query_id: QueryId,
    sink_sender: mpsc::Sender<MessageChunks>,
    sink_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
    message_stream_sender: mpsc::Sender<MessageChunks>,
    message_stream_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
}

impl<'a> HttpNetwork<'a> {
    #[must_use]
    #[allow(unused)]
    pub fn new<'b: 'a, D: PeerDiscovery>(peer_discovery: &'b D, query_id: QueryId) -> Self {
        let (stx, srx) = mpsc::channel(1);
        let (mstx, msrx) = mpsc::channel(1);
        HttpNetwork {
            peers: peer_discovery.peers(),
            query_id,
            sink_sender: stx,
            sink_receiver: Arc::new(Mutex::new(Some(srx))),
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        }
    }

    /// TODO: implement event loop for receiving.
    ///       this function will be removed when that loop exists
    /// # Panics
    /// if called more than once
    #[must_use]
    #[allow(unused)] // See TODO
    pub fn recv_messages(&self) -> mpsc::Receiver<MessageChunks> {
        self.sink_receiver
            .lock()
            .unwrap()
            .take()
            .expect("recv_messages called more than once")
    }

    #[must_use]
    #[allow(unused)]
    pub fn message_stream_sender(&self) -> mpsc::Sender<MessageChunks> {
        self.message_stream_sender.clone()
    }

    #[allow(unused)]
    fn clients(&self) -> [MpcHelperClient; 3] {
        self.peers
            .iter()
            .map(|peer_conf| {
                // no https for now
                MpcHelperClient::new(peer_conf.http.origin.clone())
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<'a> Network for HttpNetwork<'a> {
    type Sink = NetworkSink<MessageChunks>;

    type MessageStream = ReceiverStream<MessageChunks>;

    fn sink(&self) -> Self::Sink {
        Self::Sink::new(self.sink_sender.clone())
    }

    fn recv_stream(&self) -> Self::MessageStream {
        ReceiverStream::new(
            self.message_stream_receiver
                .lock()
                .unwrap()
                .take()
                .expect("recv_stream called more than once"),
        )
    }
}
