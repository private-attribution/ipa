mod error;

pub use error::Error;

use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        transport::ByteArrStream,
        HelperIdentity,
    },
    net::{discovery::peer, http_serde},
    protocol::{QueryId, Step},
};
use axum::{body::StreamBody, http::uri};
use hyper::{body, client::HttpConnector, Body, Client, Response, Uri};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;

/// TODO: we need a client that can be used by any system that is not aware of the internals
///       of the helper network. That means that create query and send inputs API need to be
///       separated from prepare/step data etc.
#[allow(clippy::type_complexity)] // TODO: maybe alias a type for the `dyn Stream`
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    streaming_client: Client<HttpsConnector<HttpConnector>, StreamBody<ByteArrStream>>,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn from_conf(peers_conf: &[peer::Config; 3]) -> [MpcHelperClient; 3] {
        peers_conf
            .iter()
            .map(|conf| Self::new(conf.origin.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build(https.clone());
        let streaming_client = Client::builder().build(https);
        let parts = addr.into_parts();
        Self {
            client,
            streaming_client,
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    /// same as new, but first parses the addr from a [&str]
    /// # Errors
    /// if addr is an invalid [Uri], this will fail
    pub fn with_str_addr(addr: &str) -> Result<Self, Error> {
        Ok(Self::new(addr.parse()?))
    }

    /// Responds with whatever input is passed to it
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn echo(&self, s: &str) -> Result<String, Error> {
        const FOO: &str = "foo";

        let req =
            http_serde::echo::Request::new(HashMap::from([(FOO.into(), s.into())]), HashMap::new());
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        if status.is_success() {
            let result = hyper::body::to_bytes(resp.into_body()).await?;
            let http_serde::echo::Request {
                mut query_params, ..
            } = serde_json::from_slice(&result)?;
            query_params.remove(FOO).ok_or(Error::FailedRequest {
                status,
                reason: "did not receive mirrored response".into(),
            })
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    async fn resp_ok(resp: Response<Body>) -> Result<(), Error> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Intended to be called externally, by the report collector. Informs the MPC ring that
    /// the external party wants to start a new query.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn create_query(&self, data: QueryConfig) -> Result<QueryId, Error> {
        let req = http_serde::query::create::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let http_serde::query::create::ResponseBody { query_id } =
                serde_json::from_slice(&body_bytes)?;
            Ok(query_id)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Used to communicate from one helper to another. Specifically, the helper that receives a
    /// "create query" from an external party must communicate the intent to start a query to the
    /// other helpers, which this prepare query does.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn prepare_query(
        &self,
        origin: HelperIdentity,
        data: PrepareQuery,
    ) -> Result<(), Error> {
        let req = http_serde::query::prepare::Request::new(origin, data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Intended to be called externally, e.g. by the report collector. After the report collector
    /// calls "create query", it must then send the data for the query to each of the clients. This
    /// query input contains the data intended for a helper.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn query_input(&self, data: QueryInput) -> Result<(), Error> {
        let req = http_serde::query::input::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.streaming_client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Sends a batch of messages associated with a query's step to another helper. Messages are a
    /// contiguous block of records. Also includes [`crate::protocol::RecordId`] information and
    /// [`crate::helpers::network::ChannelId`].
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// If messages size > max u32 (unlikely)
    pub async fn step(
        &self,
        origin: HelperIdentity,
        query_id: QueryId,
        step: &Step,
        payload: Vec<u8>,
        offset: u32,
    ) -> Result<(), Error> {
        let req =
            http_serde::query::step::Request::new(origin, query_id, step.clone(), payload, offset);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Wait for completion of the query and pull the results of this query. This is a blocking
    /// API so it is not supposed to be used outside of CLI context.
    ///
    /// ## Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// if there is a problem reading the response body
    #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))]
    pub async fn query_results(&self, query_id: QueryId) -> Result<body::Bytes, Error> {
        let req = http_serde::query::results::Request::new(query_id);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;

        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await.unwrap())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::{FieldType, Fp31},
        helpers::{
            query::{QueryCommand, QueryType},
            CommandEnvelope, CommandOrigin, RoleAssignment, TransportCommand,
            MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::{server::BindTarget, MpcHelperServer},
        query::ProtocolResult,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        sync::{Arc, Mutex},
    };
    use futures::join;
    use hyper_tls::native_tls::TlsConnector;
    use std::fmt::Debug;
    use std::future::Future;
    use tokio::sync::mpsc;

    async fn setup_server(
        bind_target: BindTarget,
    ) -> (
        u16,
        mpsc::Receiver<CommandEnvelope>,
        Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(tx, Arc::clone(&ongoing_queries));
        let (addr, _) = server.bind(bind_target).await;
        (addr.port(), rx, ongoing_queries)
    }

    async fn setup_server_http() -> (
        mpsc::Receiver<CommandEnvelope>,
        Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
        MpcHelperClient,
    ) {
        let (port, rx, ongoing_queries) =
            setup_server(BindTarget::Http("0.0.0.0:0".parse().unwrap())).await;
        let client = MpcHelperClient::with_str_addr(&format!("http://localhost:{port}")).unwrap();
        (rx, ongoing_queries, client)
    }

    async fn setup_server_https() -> (
        mpsc::Receiver<CommandEnvelope>,
        Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
        MpcHelperClient,
    ) {
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (port, rx, ongoing_queries) =
            setup_server(BindTarget::Https("0.0.0.0:0".parse().unwrap(), config)).await;

        // requires custom client to use self signed certs
        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let hyper_client = hyper::Client::builder().build(https.clone());
        let streaming_hyper_client = hyper::Client::builder().build(https);
        let client = MpcHelperClient {
            client: hyper_client,
            streaming_client: streaming_hyper_client,
            scheme: uri::Scheme::HTTPS,
            authority: uri::Authority::try_from(format!("localhost:{port}")).unwrap(),
        };

        (rx, ongoing_queries, client)
    }

    /// tests that a query command runs as expected. Since query commands require the server to
    /// actively respond to a client request, the test must handle both ends of the request
    /// simultaneously. That means taking the client behavior (`clientf`) and the server behavior
    /// (`serverf`), and executing them simultaneously (via a `join!`). Finally, return the results
    /// of `clientf` for final checks.
    ///
    /// Also tests that the same functionality works for both `http` and `https`. In order to ensure
    /// this, the return type of `clientf` must be `Eq + Debug` so that the results of `http` and
    /// `https` can be compared.
    async fn test_query_command<ClientOut, ClientFut, ClientF, ServerFut, ServerF>(
        clientf: ClientF,
        serverf: ServerF,
    ) -> ClientOut
    where
        ClientOut: Eq + Debug,
        ClientFut: Future<Output = ClientOut>,
        ClientF: Fn(MpcHelperClient) -> ClientFut,
        ServerFut: Future<Output = ()>,
        ServerF: Fn(mpsc::Receiver<CommandEnvelope>) -> ServerFut,
    {
        let (rx, _, http_client) = setup_server_http().await;
        let clientf_res = clientf(http_client);
        let serverf_res = serverf(rx);
        let (clientf_res_http, _) = join!(clientf_res, serverf_res);

        let (rx, _, https_client) = setup_server_https().await;
        let clientf_res = clientf(https_client);
        let serverf_res = serverf(rx);
        let (clientf_res_https, _) = join!(clientf_res, serverf_res);

        assert_eq!(clientf_res_http, clientf_res_https);
        clientf_res_http
    }

    #[tokio::test]
    async fn echo() {
        let expected_output = "asdf";

        let output = test_query_command(
            |client| async move { client.echo(expected_output).await.unwrap() },
            |_| futures::future::ready(()),
        )
        .await;
        assert_eq!(expected_output, &output);
    }

    #[tokio::test]
    async fn create() {
        let expected_query_id = QueryId;
        let expected_query_config = QueryConfig {
            field_type: FieldType::Fp31,
            query_type: QueryType::TestMultiply,
        };
        let query_id = test_query_command(
            |client| async move { client.create_query(expected_query_config).await.unwrap() },
            |mut rx| async move {
                let command = rx.recv().await.unwrap();
                assert_eq!(command.origin, CommandOrigin::Other);
                match command.payload {
                    TransportCommand::Query(QueryCommand::Create(query_config, responder)) => {
                        assert_eq!(query_config, expected_query_config);
                        responder.send(expected_query_id).unwrap();
                    }
                    other => panic!("expected Create command, but got {other:?}"),
                };
            },
        )
        .await;
        assert_eq!(query_id, expected_query_id);
    }

    #[tokio::test]
    async fn prepare() {
        let identities = HelperIdentity::make_three();
        let origin = identities[0];
        let expected_data = PrepareQuery {
            query_id: QueryId,
            config: QueryConfig {
                field_type: FieldType::Fp31,
                query_type: QueryType::TestMultiply,
            },
            roles: RoleAssignment::new(identities),
        };
        test_query_command(
            |client| {
                let client_data = expected_data.clone();
                async move { client.prepare_query(origin, client_data).await.unwrap() }
            },
            |mut rx| {
                let expected_data = expected_data.clone();
                async move {
                    let command = rx.recv().await.unwrap();
                    assert_eq!(command.origin, CommandOrigin::Helper(origin));
                    match command.payload {
                        TransportCommand::Query(QueryCommand::Prepare(data, responder)) => {
                            assert_eq!(expected_data, data);
                            responder.send(()).unwrap();
                        }
                        other => panic!("expected Prepare command, but got {other:?}"),
                    }
                }
            },
        )
        .await;
    }

    #[tokio::test]
    async fn input() {
        let expected_query_id = QueryId;
        let expected_input = vec![8u8; 25];
        test_query_command(
            |client| {
                let data = QueryInput {
                    query_id: expected_query_id,
                    input_stream: expected_input.clone().into(),
                };
                async move { client.query_input(data).await.unwrap() }
            },
            |mut rx| {
                let expected_input = expected_input.clone();
                async move {
                    let command = rx.recv().await.unwrap();
                    assert_eq!(command.origin, CommandOrigin::Other);
                    match command.payload {
                        TransportCommand::Query(QueryCommand::Input(query_input, responder)) => {
                            assert_eq!(query_input.query_id, expected_query_id);
                            let input_vec = query_input.input_stream.to_vec().await;
                            assert_eq!(input_vec, expected_input);
                            responder.send(()).unwrap();
                        }
                        other => panic!("expected Input command, but got {other:?}"),
                    }
                }
            },
        )
        .await;
    }

    #[tokio::test]
    async fn step() {
        let origin = HelperIdentity::try_from(1).unwrap();
        let expected_query_id = QueryId;
        let expected_step = Step::default().narrow("test-step");
        let expected_payload = vec![7u8; MESSAGE_PAYLOAD_SIZE_BYTES];
        let expected_offset = 0;

        let (_, ongoing_queries, http_client) = setup_server_http().await;
        let (tx, mut rx) = mpsc::channel(1);
        {
            // inside parenthesis to drop the lock
            let mut ongoing_queries = ongoing_queries.lock().unwrap();
            ongoing_queries.insert(expected_query_id, tx);
        }

        http_client
            .step(
                origin,
                expected_query_id,
                &expected_step,
                expected_payload.clone(),
                expected_offset,
            )
            .await
            .unwrap();
        let command = rx.recv().await.unwrap();
        assert_eq!(command.origin, CommandOrigin::Helper(origin));
        match command.payload {
            TransportCommand::StepData {
                query_id,
                step,
                payload,
                offset,
            } => {
                assert_eq!(query_id, expected_query_id);
                assert_eq!(step, expected_step);
                assert_eq!(payload, expected_payload);
                assert_eq!(offset, expected_offset);
            }
            other @ TransportCommand::Query(_) => {
                panic!("expected Step command, but got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn results() {
        let expected_query_id = QueryId;
        let expected_results = Box::new(vec![Replicated::from((
            Fp31::from(1u128),
            Fp31::from(2u128),
        ))]);
        let results = test_query_command(
            |client| async move { client.query_results(expected_query_id).await.unwrap() },
            |mut rx| {
                let results = expected_results.clone();
                async move {
                    let command = rx.recv().await.unwrap();
                    assert_eq!(command.origin, CommandOrigin::Other);
                    match command.payload {
                        TransportCommand::Query(QueryCommand::Results(query_id, responder)) => {
                            assert_eq!(query_id, expected_query_id);
                            responder.send(results).unwrap();
                        }
                        other => panic!("expected Results command, but got {other:?}"),
                    }
                }
            },
        )
        .await;
        assert_eq!(results.to_vec(), expected_results.into_bytes());
    }
}
