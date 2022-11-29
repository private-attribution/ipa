mod network;

pub use network::HttpNetwork;

use crate::{
    ff::Field,
    helpers::{messaging::Gateway, Direction, Error, GatewayConfig, Role},
    net::{
        discovery::{peer, PeerDiscovery},
        BindTarget, MessageSendMap, MpcHelperServer,
    },
    protocol::{
        boolean::random_bits_generator::RandomBitsGenerator, context::SemiHonestContext, prss,
        QueryId,
    },
    task::JoinHandle,
};
use rand::thread_rng;
use std::net::SocketAddr;

pub struct HttpHelper {
    role: Role,
    peers: [peer::Config; 3],
    gateway_config: GatewayConfig,
    participant: prss::Endpoint,
    server: MpcHelperServer,
}

impl HttpHelper {
    pub fn new<D: PeerDiscovery>(
        role: Role,
        peer_discovery: &D,
        gateway_config: GatewayConfig,
    ) -> Self {
        // Prss
        let peers = peer_discovery.peers();
        let participant_setup = prss::Endpoint::prepare(&mut thread_rng());
        let participant = participant_setup.setup(
            &peers[role.peer(Direction::Left)].prss.public_key,
            &peers[role.peer(Direction::Right)].prss.public_key,
        );

        Self {
            role,
            peers,
            gateway_config,
            participant,
            server: MpcHelperServer::new(MessageSendMap::default()),
        }
    }

    /// binds server as defined in the peers config list
    /// # Panics
    /// if peers config does not specify port
    pub async fn bind(&self) -> (SocketAddr, JoinHandle<()>) {
        let this_conf = &self.peers[self.role];
        let port = this_conf.http.origin.port().unwrap();
        let target = BindTarget::Http(format!("127.0.0.1:{}", port.as_str()).parse().unwrap());
        tracing::info!("starting server; binding to port {}", port.as_str());
        self.server.bind(target).await
    }

    /// adds a query to the running server so that it knows where to send arriving data
    /// # Errors
    /// if a query has been previously added
    pub fn query(&self, query_id: QueryId) -> Result<Gateway, Error> {
        tracing::debug!("starting query {}", query_id.as_ref());
        let network = HttpNetwork::new(self.role, &self.peers, query_id);

        let gateway = Gateway::new(self.role, &network, self.gateway_config);
        // allow for server to forward requests to this network
        // TODO: how to remove from map?
        self.server.add_query(query_id, network)?;
        Ok(gateway)
    }

    /// TODO: can the participant be shared across queries?
    pub fn context<'a, 'b: 'a, 'c: 'a, 'd: 'a, F: Field>(
        &'b self,
        gateway: &'c Gateway,
        rbg: &'d RandomBitsGenerator<F>,
    ) -> SemiHonestContext<'a, F> {
        SemiHonestContext::new(self.role, &self.participant, gateway, rbg)
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::{
        ff::Fp31,
        helpers::SendBufferConfig,
        net::discovery,
        protocol::{mul::SecureMul, RecordId},
        test_fixture::{logging, share, Reconstruct},
    };
    use rand::rngs::mock::StepRng;
    use x25519_dalek::PublicKey;

    fn public_key_from_hex(hex: &str) -> PublicKey {
        let decoded = hex::decode(hex).unwrap();
        let decoded_arr: [u8; 32] = decoded.try_into().unwrap();
        PublicKey::from(decoded_arr)
    }

    fn peer_discovery() -> discovery::literal::Literal {
        discovery::literal::Literal {
            h1: peer::Config {
                http: peer::HttpConfig {
                    origin: "http://127.0.0.1:3000".parse().unwrap(),
                    public_key: public_key_from_hex(
                        "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924",
                    ),
                },
                prss: peer::PrssConfig {
                    public_key: public_key_from_hex(
                        "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924",
                    ),
                },
            },
            h2: peer::Config {
                http: peer::HttpConfig {
                    origin: "http://127.0.0.1:3001".parse().unwrap(),
                    public_key: public_key_from_hex(
                        "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b",
                    ),
                },
                prss: peer::PrssConfig {
                    public_key: public_key_from_hex(
                        "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b",
                    ),
                },
            },
            h3: peer::Config {
                http: peer::HttpConfig {
                    origin: "http://127.0.0.1:3002".parse().unwrap(),
                    public_key: public_key_from_hex(
                        "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074",
                    ),
                },
                prss: peer::PrssConfig {
                    public_key: public_key_from_hex(
                        "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074",
                    ),
                },
            },
        }
    }

    fn gateway_config() -> GatewayConfig {
        GatewayConfig {
            send_buffer_config: SendBufferConfig {
                items_in_batch: 1,
                batch_count: 40,
            },
        }
    }

    async fn init_helper(role: Role, peer_discovery: &discovery::literal::Literal) -> HttpHelper {
        let gateway_conf = gateway_config();
        let helper = HttpHelper::new(role, peer_discovery, gateway_conf);
        helper.bind().await;
        helper
    }

    #[tokio::test]
    async fn basic_mul() {
        logging::setup();

        let peer_discovery = peer_discovery();
        let h1 = init_helper(Role::H1, &peer_discovery).await;
        let h2 = init_helper(Role::H2, &peer_discovery).await;
        let h3 = init_helper(Role::H3, &peer_discovery).await;

        let gateway1 = h1.query(QueryId).unwrap();
        let gateway2 = h2.query(QueryId).unwrap();
        let gateway3 = h3.query(QueryId).unwrap();

        let rbg = RandomBitsGenerator::<Fp31>::new();
        let ctx1 = h1.context(&gateway1, &rbg);
        let ctx2 = h2.context(&gateway2, &rbg);
        let ctx3 = h3.context(&gateway3, &rbg);

        let mut rand = StepRng::new(1, 1);

        let record_id = RecordId::from(0u32);
        let a = 5u128;
        let b = 6u128;
        let a_shared = share(Fp31::from(a), &mut rand);
        let b_shared = share(Fp31::from(b), &mut rand);

        let input = tokio::try_join!(
            ctx1.multiply(record_id, &a_shared[0], &b_shared[0]),
            ctx2.multiply(record_id, &a_shared[1], &b_shared[1]),
            ctx3.multiply(record_id, &a_shared[2], &b_shared[2])
        )
        .unwrap();

        let reconstructed = [input.0, input.1, input.2].reconstruct();
        assert_eq!(a * b, reconstructed.as_u128());
    }
}
