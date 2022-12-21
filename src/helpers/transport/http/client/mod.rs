mod error;

pub use error::Error;

use crate::{
    helpers::{
        transport::{
            http::{discovery::peer, PrepareQueryBody, StepBody, StepHeaders},
            MulData, PrepareQueryData, StepData,
        },
        HelperIdentity,
    },
    net::ByteArrStream,
    protocol::{QueryId, Step},
};
use axum::{
    body::{Bytes, StreamBody},
    http::{
        uri::{self, PathAndQuery},
        Request,
    },
};
use hyper::{client::HttpConnector, Body, Client, Response, Uri};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;

pub struct HttpSendMessagesArgs<'a> {
    pub query_id: QueryId,
    pub step: &'a Step,
    pub offset: u32,
    pub messages: Bytes,
}

#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    streaming_client: Client<HttpsConnector<HttpConnector>, StreamBody<ByteArrStream>>,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    #[must_use]
    pub fn from_conf(
        peers_conf: &'static HashMap<HelperIdentity, peer::Config>,
    ) -> HashMap<HelperIdentity, MpcHelperClient> {
        let mut clients = HashMap::with_capacity(peers_conf.len());
        for (id, conf) in peers_conf {
            clients.insert(id.clone(), Self::new(conf.origin.clone()));
        }
        clients
    }

    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https.clone());
        let streaming_client = Client::builder().build::<_, StreamBody<ByteArrStream>>(https);
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

    fn build_uri<T>(&self, p_and_q: T) -> Result<Uri, Error>
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
    pub async fn echo(&self, s: &str) -> Result<Vec<u8>, Error> {
        let uri = self.build_uri(format!("/echo?foo={s}"))?;

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;
        Ok(result.to_vec())
    }

    async fn resp_ok(resp: Response<Body>) -> Result<(), Error> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    pub async fn prepare_query(&self, data: PrepareQueryData) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}?field_type={}",
            data.query_id.as_ref(),
            data.field_type
        ))?;
        let body = PrepareQueryBody {
            helper_positions: data.helper_positions,
            helpers_to_roles: data.helpers_to_roles,
        };
        let body = Body::from(serde_json::to_string(&body)?);
        let req = Request::post(uri).body(body)?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    pub async fn mul(&self, data: MulData) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}/mul?field_type={}",
            data.query_id.as_ref(),
            data.field_type
        ))?;
        let body = StreamBody::from(data.data_stream);
        let req = Request::post(uri).body(body)?;
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
    pub async fn step(&self, data: StepData) -> Result<(), Error> {
        let uri = self.build_uri(format!(
            "/query/{}/step/{}?role={}",
            data.query_id.as_ref(),
            data.message_chunks.0.step.as_ref(),
            data.message_chunks.0.role.as_ref()
        ))?;
        // TODO: content_length and offset Headers
        let headers = StepHeaders {
            content_length: u32::try_from(data.message_chunks.1.len()).unwrap(),
            offset: data.offset,
        };
        let body = StepBody {
            roles_to_helpers: data.roles_to_helpers,
            chunk: data.message_chunks.1,
        };
        let body = Body::from(serde_json::to_string(&body)?);
        let req = headers.add_to(Request::post(uri)).body(body)?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }
}
