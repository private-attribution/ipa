mod error;

pub use error::Error;

use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        HelperIdentity, TransportError,
    },
    net::{discovery::peer, http_serde},
    protocol::{QueryId, Step},
};
use axum::{
    body::{Bytes, StreamBody},
    http::{
        uri::{self, PathAndQuery},
        Request,
    },
};
use futures::Stream;
use hyper::{body, client::HttpConnector, header::CONTENT_TYPE, Body, Client, Response, Uri};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;
use std::pin::Pin;

/// TODO: we need a client that can be used by any system that is not aware of the internals
///       of the helper network. That means that create query and send inputs API need to be
///       separated from prepare/step data etc.
#[allow(clippy::type_complexity)] // TODO: maybe alias a type for the `dyn Stream`
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    streaming_client: Client<
        HttpsConnector<HttpConnector>,
        StreamBody<Pin<Box<dyn Stream<Item = Result<Vec<u8>, TransportError>> + Send>>>,
    >,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    #[must_use]
    pub fn from_conf(
        peers_conf: &HashMap<HelperIdentity, peer::Config>,
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
        let uri = self.build_uri(http_serde::echo_uri(s))?;

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

    /// Intended to be called externally, e.g. by the report collector. Informs the MPC ring that
    /// the external party wants to start a new query.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn create_query(&self, data: QueryConfig) -> Result<QueryId, Error> {
        let uri = self.build_uri(http_serde::create_query_uri(data))?;
        let req = Request::post(uri).body(Body::empty())?;
        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let http_serde::CreateQueryResp { query_id } = serde_json::from_slice(&body_bytes)?;
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
        origin: &HelperIdentity,
        data: PrepareQuery,
    ) -> Result<(), Error> {
        let uri = self.build_uri(http_serde::prepare_query_uri(data.query_id, data.config))?;
        let origin_header = http_serde::OriginHeader {
            origin: origin.clone(),
        };
        let body = http_serde::PrepareQueryBody { roles: data.roles };
        let body = Body::from(serde_json::to_string(&body)?);
        let req = origin_header
            .add_to(Request::post(uri))
            .header(CONTENT_TYPE, "application/json")
            .body(body)?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Intended to be called externally, e.g. by the report collector. After the report collector
    /// calls "create query", it must then send the data for the query to each of the clients. This
    /// query input contains the data intended for a helper.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn query_input(&self, data: QueryInput) -> Result<(), Error> {
        // TODO: uri must be shared between server and client
        let uri = self.build_uri(http_serde::query_input_uri(data.query_id, data.field_type))?;
        let body = StreamBody::new(data.input_stream);
        let req = Request::post(uri)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(body)?;
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
        origin: &HelperIdentity,
        query_id: QueryId,
        step: &Step,
        payload: Vec<u8>,
        offset: u32,
    ) -> Result<(), Error> {
        let uri = self.build_uri(http_serde::step_uri(query_id, step))?;
        let headers = http_serde::StepHeaders { offset };
        let origin_header = http_serde::OriginHeader {
            origin: origin.clone(),
        };

        let body = Body::from(payload);
        let req = Request::post(uri);
        let req = headers
            .add_to(origin_header.add_to(req))
            .header(CONTENT_TYPE, "application/octet-stream");
        let req = req.body(body)?;
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
    #[cfg(feature = "cli")]
    pub async fn query_results(&self, query_id: QueryId) -> Result<Bytes, Error> {
        let uri = self.build_uri(http_serde::query_results_uri(query_id))?;

        let req = Request::get(uri).body(Body::empty())?;

        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await.unwrap())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }
}
