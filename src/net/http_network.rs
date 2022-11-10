use crate::{
    helpers::{
        fabric::{MessageChunks, Network},
        Error,
    },
    net::{
        discovery::{peer, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::QueryId,
};
use futures::{ready, Sink};
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::{PollSendError, PollSender};

/// Wrapper around a [`PollSender`] to modify the error message to match what the [`Network`] trait
/// requires. The only error that [`PollSender`] will generate is "channel closed", and thus is the
/// only error message forwarded from this [`Sink`].
#[pin_project]
pub struct HttpMessageSink<T> {
    #[pin]
    inner: PollSender<T>,
}

impl<T: Send + 'static> HttpMessageSink<T> {
    #[must_use]
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self {
            inner: PollSender::new(sender),
        }
    }
}

impl<T: Send + 'static> Sink<T> for HttpMessageSink<T>
where
    Error: From<PollSendError<T>>,
{
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().inner.poll_ready(cx)?);
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.project().inner.start_send(item)?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().inner.poll_flush(cx)?);
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().inner.poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

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

impl<'a, 'b: 'a> HttpNetwork<'a> {
    #[must_use]
    #[allow(unused)]
    pub fn new<D: PeerDiscovery>(
        peer_discovery: &'b D,
        sink_queue_depth: usize,
        message_stream_queue_depth: usize,
        query_id: QueryId,
    ) -> Self {
        let (stx, srx) = mpsc::channel(sink_queue_depth);
        let (mstx, msrx) = mpsc::channel(message_stream_queue_depth);
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
            .unwrap_or_else(|arr: Vec<_>| {
                panic!("unexpected change in array length: {}", arr.len())
            })
    }
}

impl<'a> Network for HttpNetwork<'a> {
    type Sink = HttpMessageSink<MessageChunks>;

    type MessageStream = ReceiverStream<MessageChunks>;

    fn sink(&self) -> Self::Sink {
        HttpMessageSink::new(self.sink_sender.clone())
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
