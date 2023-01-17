mod network;
mod prss_exchange_protocol;

pub use network::HttpNetwork;

use crate::{
    ff::Field,
    helpers::{messaging::Gateway, Direction, Error, GatewayConfig, Role},
    net::{
        discovery::{peer, PeerDiscovery},
        BindTarget, MessageSendMap, MpcHelperServer,
    },
    protocol::{context::SemiHonestContext, prss, QueryId, RecordId, Step},
    task::JoinHandle,
};
use futures_util::future::try_join4;
use prss_exchange_protocol::{PrssExchangeStep, PublicKeyBytesBuilder, PublicKeyChunk};
use rand_core::{CryptoRng, RngCore};
use std::iter::zip;
use std::net::SocketAddr;

pub struct HttpHelper<'p> {
    role: Role,
    peers: &'p [peer::Config; 3],
    _gateway_config: GatewayConfig,
    server: MpcHelperServer,
}

impl<'p> HttpHelper<'p> {
    pub fn new<D: PeerDiscovery>(
        role: Role,
        peer_discovery: &'p D,
        gateway_config: GatewayConfig,
    ) -> Self {
        let peers = peer_discovery.peers();

        Self {
            role,
            peers,
            _gateway_config: gateway_config,
            server: MpcHelperServer::new(MessageSendMap::default()),
        }
    }

    /// binds server as defined in the peers config list
    /// # Panics
    /// if peers config does not specify port
    pub async fn bind(&self) -> (SocketAddr, JoinHandle<()>) {
        // TODO: using role as index in the peer configuration is wrong (roles are configured per query),
        // but we are getting rid of this struct anyway, so no point in fixing it
        let this_conf = &self.peers[self.role];
        let port = this_conf.origin.port().unwrap();
        let target = BindTarget::Http(format!("127.0.0.1:{}", port.as_str()).parse().unwrap());
        tracing::info!("starting server; binding to port {}", port.as_str());
        self.server.bind(target).await
    }

    /// adds a query to the running server so that it knows where to send arriving data
    /// # Errors
    /// if a query has been previously added
    pub fn query(&self, _query_id: QueryId) -> Result<Gateway, Error> {
        // TODO: This requires `HttpNetwork` to implement Transport
        unimplemented!();
        // tracing::debug!("starting query {}", query_id.as_ref());
        // let network = HttpNetwork::new(self.role, self.peers, query_id);
        //
        // let gateway = Gateway::new(self.role, network, self.gateway_config);
        // // allow for server to forward requests to this network
        // // TODO: how to remove from map?
        // self.server.add_query(query_id, network)?;
        // Ok(gateway)
    }

    /// establish the prss endpoint by exchanging public keys with the other helpers
    /// # Errors
    /// if communication with other helpers fails
    pub async fn prss_endpoint<R: RngCore + CryptoRng>(
        &self,
        gateway: &Gateway,
        step: &Step,
        rng: &mut R,
    ) -> Result<prss::Endpoint, Error> {
        // setup protocol to exchange prss public keys
        let step = step.narrow(&PrssExchangeStep);
        let channel = gateway.mesh(&step);
        let left_peer = self.role.peer(Direction::Left);
        let right_peer = self.role.peer(Direction::Right);

        // setup local prss endpoint
        let ep_setup = prss::Endpoint::prepare(rng);
        let (send_left_pk, send_right_pk) = ep_setup.public_keys();
        let send_left_pk_chunks = PublicKeyChunk::chunks(send_left_pk);
        let send_right_pk_chunks = PublicKeyChunk::chunks(send_right_pk);

        // exchange public keys
        // TODO: since we have a limitation that max message size is 8 bytes, we must send 4
        //       messages to completely send the public key. If that max message size is removed, we
        //       can eliminate the chunking
        let mut recv_left_pk_builder = PublicKeyBytesBuilder::empty();
        let mut recv_right_pk_builder = PublicKeyBytesBuilder::empty();

        for (i, (send_left_chunk, send_right_chunk)) in
            zip(send_left_pk_chunks, send_right_pk_chunks).enumerate()
        {
            let record_id = RecordId::from(i);
            let send_to_left = channel.send(left_peer, record_id, send_left_chunk);
            let send_to_right = channel.send(right_peer, record_id, send_right_chunk);
            let recv_from_left = channel.receive::<PublicKeyChunk>(left_peer, record_id);
            let recv_from_right = channel.receive::<PublicKeyChunk>(right_peer, record_id);
            let (_, _, recv_left_key_chunk, recv_right_key_chunk) =
                try_join4(send_to_left, send_to_right, recv_from_left, recv_from_right).await?;
            recv_left_pk_builder.append_chunk(recv_left_key_chunk);
            recv_right_pk_builder.append_chunk(recv_right_key_chunk);
        }

        let recv_left_pk = recv_left_pk_builder
            .build()
            .map_err(|err| Error::serialization_error(err.record_id(), &step, err))?;
        let recv_right_pk = recv_right_pk_builder
            .build()
            .map_err(|err| Error::serialization_error(err.record_id(), &step, err))?;

        Ok(ep_setup.setup(&recv_left_pk, &recv_right_pk))
    }

    pub fn context<'a, 'b: 'a, 'c: 'a, 'd: 'a, 'e: 'a, F: Field>(
        &'b self,
        gateway: &'c Gateway,
        participant: &'d prss::Endpoint,
    ) -> SemiHonestContext<'a, F> {
        SemiHonestContext::new(self.role, participant, gateway)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use futures_util::future::try_join3;
    use std::num::NonZeroUsize;

    use super::*;
    use crate::secret_sharing::IntoShares;
    use crate::{
        ff::Fp31,
        helpers::SendBufferConfig,
        net::discovery,
        protocol::{basics::mul::SecureMul, context::Context, prss::SharedRandomness, RecordId},
        test_fixture::{logging, Reconstruct},
    };
    use rand::rngs::mock::StepRng;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;
    use x25519_dalek::PublicKey;

    fn public_key_from_hex(hex: &str) -> PublicKey {
        let decoded = hex::decode(hex).unwrap();
        let decoded_arr: [u8; 32] = decoded.try_into().unwrap();
        PublicKey::from(decoded_arr)
    }

    // randomly grabs open port
    fn open_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn peer_discovery() -> discovery::literal::Literal {
        discovery::literal::Literal::new(
            peer::Config {
                origin: format!("http://127.0.0.1:{}", open_port()).parse().unwrap(),
                tls: peer::HttpConfig {
                    public_key: public_key_from_hex(
                        "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924",
                    ),
                },
            },
            peer::Config {
                origin: format!("http://127.0.0.1:{}", open_port()).parse().unwrap(),
                tls: peer::HttpConfig {
                    public_key: public_key_from_hex(
                        "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b",
                    ),
                },
            },
            peer::Config {
                origin: format!("http://127.0.0.1:{}", open_port()).parse().unwrap(),
                tls: peer::HttpConfig {
                    public_key: public_key_from_hex(
                        "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074",
                    ),
                },
            },
        )
    }

    fn gateway_config() -> GatewayConfig {
        GatewayConfig {
            send_buffer_config: SendBufferConfig {
                items_in_batch: NonZeroUsize::new(1).unwrap(),
                batch_count: NonZeroUsize::new(40).unwrap(),
            },
            send_outstanding: 16,
            recv_outstanding: 16,
        }
    }

    async fn init_helper(role: Role, peer_discovery: &discovery::literal::Literal) -> HttpHelper {
        let gateway_conf = gateway_config();
        let helper = HttpHelper::new(role, peer_discovery, gateway_conf);
        helper.bind().await;
        helper
    }

    #[tokio::test]
    #[ignore] // TODO (thurstonsand): enable after `HttpNetwork` implements `Transport`
    async fn prss_key_exchange() {
        logging::setup();

        let peer_discovery = peer_discovery();
        let h1 = init_helper(Role::H1, &peer_discovery).await;
        let h2 = init_helper(Role::H2, &peer_discovery).await;
        let h3 = init_helper(Role::H3, &peer_discovery).await;

        let gateway1 = h1.query(QueryId).unwrap();
        let gateway2 = h2.query(QueryId).unwrap();
        let gateway3 = h3.query(QueryId).unwrap();

        let step = Step::default();
        let mut rng1 = StdRng::from_entropy();
        let mut rng2 = StdRng::from_entropy();
        let mut rng3 = StdRng::from_entropy();

        let participant1 = h1.prss_endpoint(&gateway1, &step, &mut rng1);
        let participant2 = h2.prss_endpoint(&gateway2, &step, &mut rng2);
        let participant3 = h3.prss_endpoint(&gateway3, &step, &mut rng3);
        let (participant1, participant2, participant3) =
            try_join3(participant1, participant2, participant3)
                .await
                .unwrap();

        let ctx1 = h1.context::<Fp31>(&gateway1, &participant1);
        let ctx2 = h2.context::<Fp31>(&gateway2, &participant2);
        let ctx3 = h3.context::<Fp31>(&gateway3, &participant3);

        let idx = 0u128;
        let (left1, right1) = ctx1.prss().generate_values(idx);
        let (left2, right2) = ctx2.prss().generate_values(idx);
        let (left3, right3) = ctx3.prss().generate_values(idx);

        assert_eq!(left1, right3);
        assert_eq!(right1, left2);
        assert_eq!(right2, left3);

        // recreate participants and ensure values are different
        let step = step.narrow("second_time");
        let participant1 = h1.prss_endpoint(&gateway1, &step, &mut rng1);
        let participant2 = h2.prss_endpoint(&gateway2, &step, &mut rng2);
        let participant3 = h3.prss_endpoint(&gateway3, &step, &mut rng3);
        let (participant1, participant2, participant3) =
            try_join3(participant1, participant2, participant3)
                .await
                .unwrap();

        let ctx1 = h1.context::<Fp31>(&gateway1, &participant1);
        let ctx2 = h2.context::<Fp31>(&gateway2, &participant2);
        let ctx3 = h3.context::<Fp31>(&gateway3, &participant3);

        let idx = 0u128;
        let (second_left1, second_right1) = ctx1.prss().generate_values(idx);
        let (second_left2, second_right2) = ctx2.prss().generate_values(idx);
        let (second_left3, second_right3) = ctx3.prss().generate_values(idx);

        assert_eq!(second_left1, second_right3);
        assert_eq!(second_right1, second_left2);
        assert_eq!(second_right2, second_left3);

        // different from first instantiation
        assert_ne!(left1, second_left1);
        assert_ne!(right1, second_right1);
        assert_ne!(left2, second_left2);
        assert_ne!(right2, second_right2);
        assert_ne!(left3, second_left3);
        assert_ne!(right3, second_right3);
    }

    #[tokio::test]
    #[ignore] // TODO (thurstonsand): enable after `HttpNetwork` implements `Transport`
    async fn basic_mul() {
        logging::setup();

        let peer_discovery = peer_discovery();
        let h1 = init_helper(Role::H1, &peer_discovery).await;
        let h2 = init_helper(Role::H2, &peer_discovery).await;
        let h3 = init_helper(Role::H3, &peer_discovery).await;

        let gateway1 = h1.query(QueryId).unwrap();
        let gateway2 = h2.query(QueryId).unwrap();
        let gateway3 = h3.query(QueryId).unwrap();

        let step = Step::default().narrow(&PrssExchangeStep);
        let mut rng1 = StdRng::from_entropy();
        let mut rng2 = StdRng::from_entropy();
        let mut rng3 = StdRng::from_entropy();

        let participant1 = h1.prss_endpoint(&gateway1, &step, &mut rng1);
        let participant2 = h2.prss_endpoint(&gateway2, &step, &mut rng2);
        let participant3 = h3.prss_endpoint(&gateway3, &step, &mut rng3);
        let (participant1, participant2, participant3) =
            try_join3(participant1, participant2, participant3)
                .await
                .unwrap();

        let ctx1 = h1.context::<Fp31>(&gateway1, &participant1);
        let ctx2 = h2.context::<Fp31>(&gateway2, &participant2);
        let ctx3 = h3.context::<Fp31>(&gateway3, &participant3);

        let mut rand = StepRng::new(1, 1);

        let record_id = RecordId::from(0u32);
        let a = 5u128;
        let b = 6u128;

        let a_shared = Fp31::from(a).share_with(&mut rand);
        let b_shared = Fp31::from(b).share_with(&mut rand);

        let input = try_join3(
            ctx1.multiply(record_id, &a_shared[0], &b_shared[0]),
            ctx2.multiply(record_id, &a_shared[1], &b_shared[1]),
            ctx3.multiply(record_id, &a_shared[2], &b_shared[2]),
        )
        .await
        .unwrap();
        let reconstructed = [input.0, input.1, input.2].reconstruct();
        assert_eq!(a * b, reconstructed.as_u128());
    }
}
