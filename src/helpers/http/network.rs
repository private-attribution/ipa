use crate::{
    helpers::{
        network::{MessageChunks, Network, NetworkSink},
        Role,
    },
    net::{discovery::peer, HttpSendMessagesArgs, MpcHelperClient},
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::body::Bytes;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

/// Http implementation of a [`HttpNetwork`]. Uses channels for both [`NetworkSink`] and [`ReceiverStream`]
/// implementations.
/// # Panics
/// if `recv_stream` or `recv_messages` called more than once.
#[allow(dead_code)] // TODO: WIP
pub struct HttpNetwork {
    query_id: QueryId,
    sink_sender: mpsc::Sender<MessageChunks>,
    message_stream_sender: mpsc::Sender<MessageChunks>,
    message_stream_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
}

impl HttpNetwork {
    /// * Creates an [`HttpNetwork`]
    /// * spawns a task that consumes incoming data from the infra layer intended for other helpers
    /// # Panics
    /// if client is unable to send message to other helper
    #[must_use]
    pub fn new(role: Role, peers_conf: &[peer::Config; 3], query_id: QueryId) -> Self {
        let (stx, mut srx) = mpsc::channel::<MessageChunks>(1);
        let (mstx, msrx) = mpsc::channel(1);

        let clients = Self::clients(role, peers_conf);
        tokio::spawn(
            async move {
                let mut last_seen_messages = HashMap::new();

                while let Some((channel_id, messages)) = srx.recv().await {
                    tracing::debug!("sending {} bytes to {channel_id:?}", messages.len());
                    // increment `offset` each time, per `ChannelId`
                    let offset = last_seen_messages.entry(channel_id.clone()).or_default();
                    let args = HttpSendMessagesArgs {
                        query_id,
                        step: &channel_id.step,
                        offset: *offset,
                        messages: Bytes::from(messages),
                    };
                    *offset += 1;

                    clients[channel_id.role].send_messages(args).await.unwrap();
                }
                tracing::debug!("channel is closed and loop is terminated");
            }
            .instrument(tracing::info_span!("client_send_loop", role=?role)),
        );
        HttpNetwork {
            query_id,
            sink_sender: stx,
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        }
    }

    /// as this does not initialize the clients, it does not initialize the read-side of the
    /// [`NetworkSink`]. This allows tests to grab the read-side directly, bypassing the HTTP layer.
    #[must_use]
    #[cfg(test)]
    pub fn new_without_clients(query_id: QueryId, buffer_size: Option<usize>) -> Self {
        let (stx, _) = mpsc::channel(buffer_size.unwrap_or(1));
        let (mstx, msrx) = mpsc::channel(buffer_size.unwrap_or(1));
        HttpNetwork {
            query_id,
            sink_sender: stx,
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        }
    }

    #[must_use]
    pub fn message_stream_sender(&self) -> mpsc::Sender<MessageChunks> {
        self.message_stream_sender.clone()
    }

    fn clients(role: Role, peers_conf: &[peer::Config; 3]) -> [MpcHelperClient; 3] {
        peers_conf
            .iter()
            .map(|peer_conf| {
                // no https for now
                MpcHelperClient::new(peer_conf.origin.clone(), role)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl Network for HttpNetwork {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture::net::localhost_config;
    use crate::{
        helpers::{network::ChannelId, Direction, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{discovery::PeerDiscovery, BindTarget, MessageSendMap, MpcHelperServer},
        protocol::Step,
    };
    use futures::{Stream, StreamExt};
    use futures_util::SinkExt;

    async fn setup() -> (Role, [peer::Config; 3], impl Stream<Item = MessageChunks>) {
        // setup server
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let rx_stream = network.recv_stream();
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);

        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;

        // only H2 is valid
        let peer_discovery = localhost_config([0, addr.port(), 0]);

        (Role::H2, peer_discovery.peers().clone(), rx_stream)
    }

    #[tokio::test]
    async fn send_multiple_messages() {
        const DATA_LEN: usize = 3;
        let (target_role, peers_conf, mut rx_stream) = setup().await;
        let self_role = target_role.peer(Direction::Left);
        let network = HttpNetwork::new(self_role, &peers_conf, QueryId);
        let mut sink = network.sink();

        // build request
        let step = Step::default().narrow("mul_test");
        let body = &[123; MESSAGE_PAYLOAD_SIZE_BYTES * DATA_LEN];

        let num_reqs = 10;

        // consume request on server-side
        let spawned = tokio::spawn({
            let expected_channel_id = ChannelId::new(self_role, step.clone());
            let expected_body = body.to_vec();
            async move {
                for _ in 0..num_reqs {
                    let (channel_id, body) = rx_stream.next().await.unwrap();
                    assert_eq!(expected_channel_id, channel_id);
                    assert_eq!(expected_body, body);
                }
            }
        });

        // send request on client-side
        for _ in 0..num_reqs {
            sink.send((ChannelId::new(target_role, step.clone()), body.to_vec()))
                .await
                .expect("send should succeed");
        }

        // ensure server had no errors
        spawned.await.unwrap();
    }
}
