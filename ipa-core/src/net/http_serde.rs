//! This module provides structs and functions to transform requests into
//! internal representations and and vice-versa into the corresponding
//! responses. This module uses Serde to define Json bodies of the requests.
//!
//! This module provides helpers used by
//! [`crate::net::server::MpcHelperServer`] and
//! [`crate::net::client::MpcHelperClient`] among others. The server API is
//! defined as Axum handlers, with the the main Axum router is defined in
//! [`crate::net::server::MpcHelperServer::router`], with sub-routers for each
//! of the APIs under a separate handler file under
//! [`crate::net::server::handlers`]. This module provides functions to accept
//! requests for each of the server APIs.
//!
//! This module is organized into the submodules "echo" and "query" for their
//! respective APIs. Each module might have a Request struct used by the client
//! to provide request parameters using [`crate::transport`] types.

type OutgoingRequest = Result<hyper::Request<axum::body::Body>, crate::net::Error>;

pub mod echo {
    use std::collections::HashMap;

    use axum::body::Body;
    use hyper::http::uri;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Request {
        pub query_params: HashMap<String, String>,
        pub headers: HashMap<String, String>,
    }

    impl Request {
        pub fn new(
            query_params: HashMap<String, String>,
            headers: HashMap<String, String>,
        ) -> Self {
            Self {
                query_params,
                headers,
            }
        }
        pub fn try_into_http_request(
            self,
            scheme: uri::Scheme,
            authority: uri::Authority,
        ) -> crate::net::http_serde::OutgoingRequest {
            let qps = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            let uri = uri::Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(format!("/echo?{qps}"))
                .build()?;

            let req = self
                .headers
                .into_iter()
                .fold(hyper::Request::get(uri), |req, (k, v)| req.header(k, v));
            Ok(req.body(Body::empty())?)
        }
    }

    pub const AXUM_PATH: &str = "/echo";
}

pub mod metrics {

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Request {}

    pub const AXUM_PATH: &str = "/metrics";
}

pub mod query {
    use std::fmt::{Display, Formatter};

    use async_trait::async_trait;
    use axum::{
        extract::{FromRequestParts, Query},
        http::request::Parts,
        RequestPartsExt,
    };
    use serde::Deserialize;

    use crate::{
        ff::FieldType,
        helpers::query::{QueryConfig, QuerySize, QueryType},
        net::Error,
    };

    /// wrapper around [`QueryConfig`] to enable extraction from an `Axum` request. To be used with
    /// the `create` and `prepare` commands
    pub struct QueryConfigQueryParams(pub QueryConfig);

    impl std::ops::Deref for QueryConfigQueryParams {
        type Target = QueryConfig;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for QueryConfigQueryParams
    where
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(req: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
            #[derive(Deserialize)]
            struct QueryTypeParam {
                size: QuerySize,
                field_type: FieldType,
                query_type: String,
            }
            let Query(QueryTypeParam {
                size,
                field_type,
                query_type,
            }) = req.extract().await?;

            let query_type = match query_type.as_str() {
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TEST_MULTIPLY_STR => Ok(QueryType::TestMultiply),
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TEST_ADD_STR => Ok(QueryType::TestAddInPrimeField),
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TEST_SHARDED_SHUFFLE_STR => Ok(QueryType::TestShardedShuffle),
                QueryType::SEMI_HONEST_OPRF_IPA_STR => {
                    let Query(q) = req.extract().await?;
                    Ok(QueryType::SemiHonestOprfIpa(q))
                }
                QueryType::MALICIOUS_OPRF_IPA_STR => {
                    let Query(q) = req.extract().await?;
                    Ok(QueryType::MaliciousOprfIpa(q))
                }
                QueryType::MALICIOUS_HYBRID_STR => {
                    let Query(q) = req.extract().await?;
                    Ok(QueryType::MaliciousHybrid(q))
                }
                other => Err(Error::bad_query_value("query_type", other)),
            }?;
            Ok(QueryConfigQueryParams(QueryConfig {
                size,
                field_type,
                query_type,
            }))
        }
    }

    impl Display for QueryConfigQueryParams {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "query_type={qt}&field_type={f:?}&size={size}",
                qt = self.query_type.as_ref(),
                f = self.field_type,
                size = self.size
            )?;
            match self.query_type {
                #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
                QueryType::TestMultiply | QueryType::TestAddInPrimeField => Ok(()),
                #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
                QueryType::TestShardedShuffle => Ok(()),
                QueryType::SemiHonestOprfIpa(config) | QueryType::MaliciousOprfIpa(config) => {
                    write!(
                        f,
                        "&per_user_credit_cap={}&max_breakdown_key={}&with_dp={}&epsilon={}",
                        config.per_user_credit_cap,
                        config.max_breakdown_key,
                        config.with_dp,
                        config.epsilon,
                    )?;

                    if config.plaintext_match_keys {
                        write!(f, "&plaintext_match_keys=true")?;
                    }

                    if let Some(window) = config.attribution_window_seconds {
                        write!(f, "&attribution_window_seconds={}", window.get())?;
                    }

                    Ok(())
                }
                QueryType::MaliciousHybrid(config) => {
                    write!(
                        f,
                        "&max_breakdown_key={}&with_dp={}&epsilon={}",
                        config.max_breakdown_key, config.with_dp, config.epsilon,
                    )?;

                    if config.plaintext_match_keys {
                        write!(f, "&plaintext_match_keys=true")?;
                    }

                    Ok(())
                }
            }
        }
    }

    pub const BASE_AXUM_PATH: &str = "/query";

    pub mod create {

        use axum::body::Body;
        use hyper::http::uri;
        use serde::{Deserialize, Serialize};

        use crate::{
            helpers::{query::QueryConfig, HelperResponse},
            net::http_serde::query::{QueryConfigQueryParams, BASE_AXUM_PATH},
            protocol::QueryId,
        };

        #[derive(Debug, Clone)]
        pub struct Request {
            pub query_config: QueryConfig,
        }

        impl Request {
            pub fn new(query_config: QueryConfig) -> Request {
                Request { query_config }
            }

            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = uri::Builder::new()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}?{}",
                        BASE_AXUM_PATH,
                        QueryConfigQueryParams(self.query_config)
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri).body(Body::empty())?)
            }
        }

        #[derive(Serialize, Deserialize)]
        pub struct ResponseBody {
            pub query_id: QueryId,
        }

        impl TryFrom<HelperResponse> for ResponseBody {
            type Error = serde_json::Error;

            fn try_from(value: HelperResponse) -> Result<Self, Self::Error> {
                value.try_into_owned()
            }
        }

        pub const AXUM_PATH: &str = "/";
    }

    pub mod prepare {
        use axum::{body::Body, http::uri};
        use hyper::header::CONTENT_TYPE;
        use serde::{Deserialize, Serialize};

        use crate::{
            helpers::{query::PrepareQuery, RoleAssignment},
            net::{
                http_serde::query::{QueryConfigQueryParams, BASE_AXUM_PATH},
                APPLICATION_JSON,
            },
        };

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Request {
            pub data: PrepareQuery,
        }

        impl Request {
            pub fn new(data: PrepareQuery) -> Self {
                Self { data }
            }
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}?{}",
                        BASE_AXUM_PATH,
                        self.data.query_id.as_ref(),
                        QueryConfigQueryParams(self.data.config),
                    ))
                    .build()?;
                let body = RequestBody {
                    roles: self.data.roles,
                };
                let body = serde_json::to_string(&body)?;
                let body = Body::from(body);
                Ok(hyper::Request::post(uri)
                    .header(CONTENT_TYPE, APPLICATION_JSON)
                    .body(body)?)
            }
        }

        #[derive(Serialize, Deserialize)]
        pub struct RequestBody {
            pub roles: RoleAssignment,
        }

        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod input {
        use axum::{
            async_trait,
            body::Body,
            extract::FromRequestParts,
            http::{request::Parts, uri},
        };
        use hyper::{
            header::{HeaderValue, CONTENT_TYPE},
            Uri,
        };

        use crate::{
            helpers::query::QueryInput,
            net::{
                http_serde::query::BASE_AXUM_PATH, Error, APPLICATION_OCTET_STREAM,
                HTTP_QUERY_INPUT_URL_HEADER,
            },
        };

        #[derive(Debug)]
        pub struct Request {
            pub query_input: QueryInput,
        }

        impl Request {
            pub fn new(query_input: QueryInput) -> Self {
                Self { query_input }
            }

            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/input",
                        BASE_AXUM_PATH,
                        self.query_input.query_id().as_ref(),
                    ))
                    .build()?;
                let query_input_url = self.query_input.url().map(ToOwned::to_owned);
                let body = self
                    .query_input
                    .input_stream()
                    .map_or_else(Body::empty, Body::from_stream);
                let mut request =
                    hyper::Request::post(uri).header(CONTENT_TYPE, APPLICATION_OCTET_STREAM);
                if let Some(url) = query_input_url {
                    request.headers_mut().unwrap().insert(
                        &HTTP_QUERY_INPUT_URL_HEADER,
                        HeaderValue::try_from(url).unwrap(),
                    );
                }
                Ok(request.body(body)?)
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/input";

        pub struct QueryInputUrl(Option<Uri>);

        #[async_trait]
        impl<S: Send + Sync> FromRequestParts<S> for QueryInputUrl {
            type Rejection = Error;

            async fn from_request_parts(
                req: &mut Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                match req.headers.get(&HTTP_QUERY_INPUT_URL_HEADER) {
                    None => Ok(QueryInputUrl(None)),
                    Some(value) => {
                        let value_str = value.to_str()?;
                        let uri = value_str.parse()?;
                        Ok(QueryInputUrl(Some(uri)))
                    }
                }
            }
        }

        impl From<QueryInputUrl> for Option<Uri> {
            fn from(value: QueryInputUrl) -> Self {
                value.0
            }
        }
    }

    pub mod step {
        use axum::{body::Body, http::uri};

        use crate::{
            net::{http_serde::query::BASE_AXUM_PATH, Error},
            protocol::{Gate, QueryId},
        };

        // When this type is used on the client side, `B` is `hyper::Body`. When this type
        // is used on the server side, `B` can be any body type supported by axum.
        #[derive(Debug)]
        pub struct Request<B> {
            pub query_id: QueryId,
            pub gate: Gate,
            pub body: B,
        }

        impl<B> Request<B> {
            pub fn new(query_id: QueryId, gate: Gate, body: B) -> Self {
                Self {
                    query_id,
                    gate,
                    body,
                }
            }
        }

        /// Convert to hyper request. Used on client side.
        impl Request<Body> {
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<Body>, Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/step/{}",
                        BASE_AXUM_PATH,
                        self.query_id.as_ref(),
                        self.gate.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri).body(self.body)?)
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/step/*step";
    }

    pub mod status {
        use serde::{Deserialize, Serialize};

        use crate::{
            helpers::{routing::RouteId, HelperResponse, NoStep, RouteParams},
            protocol::QueryId,
            query::QueryStatus,
        };

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct Request {
            pub query_id: QueryId,
        }

        impl RouteParams<RouteId, QueryId, NoStep> for Request {
            type Params = String;

            fn resource_identifier(&self) -> RouteId {
                RouteId::QueryStatus
            }

            fn query_id(&self) -> QueryId {
                self.query_id
            }

            fn gate(&self) -> NoStep {
                NoStep
            }

            fn extra(&self) -> Self::Params {
                serde_json::to_string(self).unwrap()
            }
        }

        impl Request {
            #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))] // needed because client is blocking; remove when non-blocking
            pub fn new(query_id: QueryId) -> Self {
                Self { query_id }
            }

            #[cfg(any(all(test, not(feature = "shuttle")), feature = "cli"))] // needed because client is blocking; remove when non-blocking
            pub fn try_into_http_request(
                self,
                scheme: axum::http::uri::Scheme,
                authority: axum::http::uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = axum::http::uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}",
                        crate::net::http_serde::query::BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::get(uri).body(axum::body::Body::empty())?)
            }
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ResponseBody {
            pub status: QueryStatus,
        }

        impl From<HelperResponse> for ResponseBody {
            fn from(value: HelperResponse) -> Self {
                serde_json::from_slice(value.into_body().as_slice()).unwrap()
            }
        }

        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod results {
        use crate::{
            helpers::{routing::RouteId, NoStep, RouteParams},
            protocol::QueryId,
        };

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct Request {
            pub query_id: QueryId,
        }

        impl RouteParams<RouteId, QueryId, NoStep> for Request {
            type Params = String;

            fn resource_identifier(&self) -> RouteId {
                RouteId::CompleteQuery
            }

            fn query_id(&self) -> QueryId {
                self.query_id
            }

            fn gate(&self) -> NoStep {
                NoStep
            }

            fn extra(&self) -> Self::Params {
                serde_json::to_string(self).unwrap()
            }
        }

        impl Request {
            pub fn new(query_id: QueryId) -> Self {
                Self { query_id }
            }

            pub fn try_into_http_request(
                self,
                scheme: axum::http::uri::Scheme,
                authority: axum::http::uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = axum::http::uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/complete",
                        crate::net::http_serde::query::BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::get(uri).body(axum::body::Body::empty())?)
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/complete";
    }

    pub mod kill {
        use serde::{Deserialize, Serialize};

        use crate::{
            helpers::{routing::RouteId, HelperResponse, NoStep, RouteParams},
            protocol::QueryId,
        };

        pub struct Request {
            pub query_id: QueryId,
        }

        impl RouteParams<RouteId, QueryId, NoStep> for Request {
            type Params = String;

            fn resource_identifier(&self) -> RouteId {
                RouteId::KillQuery
            }

            fn query_id(&self) -> QueryId {
                self.query_id
            }

            fn gate(&self) -> NoStep {
                NoStep
            }

            fn extra(&self) -> Self::Params {
                String::new()
            }
        }

        impl Request {
            /// Currently, it is only possible to kill
            /// a query by issuing an HTTP request manually.
            /// Maybe report collector can support this API,
            /// but for now, only tests exercise this path
            /// hence methods here are hidden behind feature
            /// flags
            #[cfg(all(test, unit_test))]
            pub fn new(query_id: QueryId) -> Self {
                Self { query_id }
            }

            #[cfg(all(test, unit_test))]
            pub fn try_into_http_request(
                self,
                scheme: axum::http::uri::Scheme,
                authority: axum::http::uri::Authority,
            ) -> crate::net::http_serde::OutgoingRequest {
                let uri = axum::http::uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/kill",
                        crate::net::http_serde::query::BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri).body(axum::body::Body::empty())?)
            }
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ResponseBody {
            pub query_id: QueryId,
            pub status: String,
        }

        impl From<HelperResponse> for ResponseBody {
            fn from(value: HelperResponse) -> Self {
                serde_json::from_slice(value.into_body().as_slice()).unwrap()
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/kill";
    }

    pub mod status_match {
        use serde::{Deserialize, Serialize};

        use crate::{helpers::query::CompareStatusRequest, query::QueryStatus};

        #[derive(Serialize, Deserialize)]
        pub struct StatusQueryString {
            pub status: QueryStatus,
        }

        impl StatusQueryString {
            fn url_encode(&self) -> String {
                // todo: serde urlencoded
                format!("status={}", self.status)
            }
        }

        impl From<QueryStatus> for StatusQueryString {
            fn from(value: QueryStatus) -> Self {
                Self { status: value }
            }
        }

        pub fn try_into_http_request(
            req: &CompareStatusRequest,
            scheme: axum::http::uri::Scheme,
            authority: axum::http::uri::Authority,
        ) -> crate::net::http_serde::OutgoingRequest {
            let uri = axum::http::uri::Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(format!(
                    "{}/{}/status-match?{}",
                    crate::net::http_serde::query::BASE_AXUM_PATH,
                    req.query_id.as_ref(),
                    StatusQueryString::from(req.status).url_encode(),
                ))
                .build()?;
            Ok(hyper::Request::get(uri).body(axum::body::Body::empty())?)
        }

        pub const AXUM_PATH: &str = "/:query_id/status-match";
    }
}
