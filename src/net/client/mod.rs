mod error;

pub use error::MpcHelperClientError;

use crate::{
    helpers::Role,
    net::RecordHeaders,
    protocol::{QueryId, Step},
};
use axum::{
    body::Bytes,
    http::{
        uri::{self, PathAndQuery},
        Request,
    },
};
use hyper::{client::HttpConnector, Body, Client, Uri};
use hyper_tls::HttpsConnector;

pub struct HttpSendMessagesArgs<'a> {
    pub query_id: QueryId,
    pub step: &'a Step,
    pub offset: u32,
    pub messages: Bytes,
}

#[allow(clippy::module_name_repetitions)] // follows standard naming convention
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    role: Role,
    client: Client<HttpsConnector<HttpConnector>>,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri, role: Role) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https);
        let parts = addr.into_parts();
        Self {
            role,
            client,
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    /// same as new, but first parses the addr from a [&str]
    /// # Errors
    /// if addr is an invalid [Uri], this will fail
    pub fn with_str_addr(addr: &str, role: Role) -> Result<Self, MpcHelperClientError> {
        Ok(Self::new(addr.parse()?, role))
    }

    fn build_uri<T>(&self, p_and_q: T) -> Result<Uri, MpcHelperClientError>
    where
        PathAndQuery: TryFrom<T>,
        <PathAndQuery as TryFrom<T>>::Error: Into<axum::http::Error>,
    {
        Ok(uri::Builder::new()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(p_and_q)
            .build()?)
    }

    /// Responds with whatever input is passed to it
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn echo(&self, s: &str) -> Result<Vec<u8>, MpcHelperClientError> {
        let uri = self.build_uri(format!("/echo?foo={s}"))?;

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;
        Ok(result.to_vec())
    }

    /// Sends a batch of messages to another helper. Messages are a contiguous block of records in
    /// some state of transformation within a protocol. Also includes [`crate::protocol::RecordId`] information and
    /// [`crate::helpers::network::ChannelId`].
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// If messages size > max u32 (unlikely)
    pub async fn send_messages(
        &self,
        args: HttpSendMessagesArgs<'_>,
    ) -> Result<(), MpcHelperClientError> {
        let uri = self.build_uri(format!(
            "/query/{}/step/{}?role={}",
            args.query_id.as_ref(),
            args.step.as_ref(),
            self.role.as_ref(),
        ))?;
        let headers = RecordHeaders {
            content_length: u32::try_from(args.messages.len()).unwrap(),
            offset: args.offset,
        };
        let req = headers
            .add_to(Request::post(uri))
            .body(Body::from(args.messages))?;
        let response = self.client.request(req).await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(MpcHelperClientError::from_failed_resp(response).await)
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        helpers::{
            http::HttpNetwork,
            network::{ChannelId, MessageChunks, Network},
            Role, MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::{server::MessageSendMap, BindTarget, MpcHelperServer},
    };
    use futures::{Stream, StreamExt};
    use hyper_tls::native_tls::TlsConnector;

    async fn setup_server(bind_target: BindTarget) -> (u16, impl Stream<Item = MessageChunks>) {
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let rx_stream = network.recv_stream();
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        // setup server
        let (addr, _) = server.bind(bind_target).await;
        (addr.port(), rx_stream)
    }

    async fn send_messages_req<St: Stream<Item = MessageChunks> + Unpin>(
        client: MpcHelperClient,
        mut rx_stream: St,
    ) {
        const DATA_LEN: u32 = 3;
        let query_id = QueryId;
        let step = Step::default().narrow("mul_test");
        let role = Role::H1;
        let offset = 0;
        let body = &[123; MESSAGE_PAYLOAD_SIZE_BYTES * (DATA_LEN as usize)];

        client
            .send_messages(HttpSendMessagesArgs {
                query_id,
                step: &step,
                offset,
                messages: Bytes::from_static(body),
            })
            .await
            .expect("send should succeed");

        let channel_id = ChannelId { role, step };
        let server_recvd = rx_stream.next().await.unwrap(); // should already have been received
        assert_eq!(server_recvd, (channel_id, body.to_vec()));
    }

    #[tokio::test]
    async fn send_messages_req_http() {
        let (port, rx_stream) =
            setup_server(BindTarget::Http("127.0.0.1:0".parse().unwrap())).await;

        // setup client
        let client =
            MpcHelperClient::with_str_addr(&format!("http://localhost:{port}"), Role::H1).unwrap();

        // test
        send_messages_req(client, rx_stream).await;
    }

    #[tokio::test]
    async fn send_messages_req_https() {
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (port, rx_stream) =
            setup_server(BindTarget::Https("127.0.0.1:0".parse().unwrap(), config)).await;

        // setup client
        // requires custom client to use self signed certs
        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let hyper_client = hyper::Client::builder().build(https);
        let client = MpcHelperClient {
            role: Role::H1,
            client: hyper_client,
            scheme: uri::Scheme::HTTPS,
            authority: uri::Authority::try_from(format!("localhost:{port}")).unwrap(),
        };

        // test
        send_messages_req(client, rx_stream).await;
    }
}
