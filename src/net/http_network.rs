use crate::{
    helpers::{
        network::{MessageChunks, Network, NetworkSink},
        Role,
    },
    net::{
        client::HttpSendMessagesArgs,
        discovery::{peer, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::QueryId,
};
use axum::body::Bytes;
use std::collections::HashMap;
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
    message_stream_sender: mpsc::Sender<MessageChunks>,
    message_stream_receiver: Arc<Mutex<Option<mpsc::Receiver<MessageChunks>>>>,
}

impl<'a> HttpNetwork<'a> {
    /// * Creates an [`HttpNetwork`]
    /// * spawns a task that consumes incoming data from the infra layer intended for other helpers
    #[must_use]
    #[allow(unused)]
    pub fn new<'b: 'a, D: PeerDiscovery>(
        role: Role,
        peer_discovery: &'b D,
        query_id: QueryId,
    ) -> Self {
        let (stx, mut srx) = mpsc::channel(1);
        let (mstx, msrx) = mpsc::channel(1);
        let network = HttpNetwork {
            peers: peer_discovery.peers(),
            query_id,
            sink_sender: stx,
            message_stream_sender: mstx,
            message_stream_receiver: Arc::new(Mutex::new(Some(msrx))),
        };

        let clients = network.clients(role);
        tokio::spawn(async move {
            let mut last_seen_messages = HashMap::new();

            while let Some((channel_id, messages)) = srx.recv().await {
                // increment `offset` each time, per `ChannelId`
                let offset = last_seen_messages.entry(channel_id.clone()).or_default();
                let args = HttpSendMessagesArgs {
                    query_id,
                    step: &channel_id.step,
                    offset: *offset,
                    messages: Bytes::from(messages),
                };
                *offset += 1;

                clients[channel_id.role]
                    .send_messages(args)
                    .await
                    .unwrap_or_else(|err| {
                        tracing::error!("could not send message to client: {err}");
                    });
            }
        });
        network
    }

    #[must_use]
    #[allow(unused)]
    pub fn message_stream_sender(&self) -> mpsc::Sender<MessageChunks> {
        self.message_stream_sender.clone()
    }

    #[allow(unused)]
    fn clients(&self, role: Role) -> [MpcHelperClient; 3] {
        self.peers
            .iter()
            .map(|peer_conf| {
                // no https for now
                MpcHelperClient::new(peer_conf.http.origin.clone(), role)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        helpers::{network::ChannelId, Direction, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{discovery::conf::Conf, BindTarget, MessageSendMap, MpcHelperServer},
        protocol::Step,
    };
    use futures_util::SinkExt;
    use std::str::FromStr;

    fn h2_peer_valid(h2_port: u16) -> Conf {
        let peer_discovery_str = format!(
            r#"
[h1]
    [h1.http]
        origin = "http://localhost:3000"
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"
    [h1.prss]
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

[h2]
    [h2.http]
        origin = "http://localhost:{}"
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"
    [h2.prss]
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

[h3]
    [h3.http]
        origin = "http://localhost:3002"
        public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
    [h3.prss]
        public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#,
            h2_port
        );
        Conf::from_str(&peer_discovery_str).unwrap()
    }

    async fn setup() -> (Role, Conf, mpsc::Receiver<MessageChunks>) {
        // setup server
        let (tx, rx) = mpsc::channel(1);
        let message_send_map = MessageSendMap::filled(tx);
        let server = MpcHelperServer::new(message_send_map);

        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;

        let peer_discovery = h2_peer_valid(addr.port());

        (Role::H2, peer_discovery, rx)
    }

    #[tokio::test]
    async fn send_multiple_messages() {
        const DATA_LEN: usize = 3;
        let (target_role, peer_discovery, mut rx) = setup().await;
        let self_role = target_role.peer(Direction::Left);
        let network = HttpNetwork::new(self_role, &peer_discovery, QueryId);
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
                    let (channel_id, body) = rx.recv().await.unwrap();
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
