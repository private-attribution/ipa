// there isn't an easy way to compose const strings at compile time, so we will hard-code
// everything
// I'm not sure what the preceding comment was referring to hard coding, but the way
// to compose const strings at compile time is concat!()

pub mod echo {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};
    use hyper::http::uri;

    use crate::net::Error;

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
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
        ) -> Result<hyper::Request<hyper::Body>, Error> {
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
            Ok(req.body(hyper::Body::empty())?)
        }
    }

    #[cfg(feature = "enable-serde")]
    #[async_trait]
    impl<B: Send> FromRequest<B> for Request {
        type Rejection = Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            let Query::<HashMap<String, String>>(query_params) = req.extract().await?;
            let headers = req
                .headers()
                .iter()
                .filter_map(|(name, value)| match value.to_str() {
                    Ok(header_value) => Some((name.to_string(), header_value.to_string())),
                    Err(_) => None,
                })
                .collect();
            Ok(Request {
                query_params,
                headers,
            })
        }
    }

    pub const AXUM_PATH: &str = "/echo";
}

pub mod query {
    use std::{
        fmt::{Display, Formatter},
        num::NonZeroU32,
    };

    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};

    use crate::{
        ff::FieldType,
        helpers::query::{IpaQueryConfig, QueryConfig, QuerySize, QueryType},
        net::Error,
    };

    /// wrapper around [`QueryConfig`] to enable extraction from an `Axum` request. To be used with
    /// the `create` and `prepare` commands
    struct QueryConfigQueryParams(pub QueryConfig);

    impl std::ops::Deref for QueryConfigQueryParams {
        type Target = QueryConfig;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[async_trait]
    impl<B: Send> FromRequest<B> for QueryConfigQueryParams {
        type Rejection = Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            #[derive(serde::Deserialize)]
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
                QueryType::SEMIHONEST_IPA_STR | QueryType::MALICIOUS_IPA_STR => {
                    #[derive(serde::Deserialize)]
                    struct IPAQueryConfigParam {
                        per_user_credit_cap: u32,
                        max_breakdown_key: u32,
                        attribution_window_seconds: Option<NonZeroU32>,
                        num_multi_bits: u32,
                        #[serde(default)]
                        plaintext_match_keys: bool,
                    }
                    let Query(IPAQueryConfigParam {
                        per_user_credit_cap,
                        max_breakdown_key,
                        attribution_window_seconds,
                        num_multi_bits,
                        plaintext_match_keys,
                    }) = req.extract().await?;

                    match query_type.as_str() {
                        QueryType::SEMIHONEST_IPA_STR => {
                            Ok(QueryType::SemiHonestIpa(IpaQueryConfig {
                                per_user_credit_cap,
                                max_breakdown_key,
                                attribution_window_seconds,
                                num_multi_bits,
                                plaintext_match_keys,
                            }))
                        }
                        QueryType::MALICIOUS_IPA_STR => {
                            Ok(QueryType::MaliciousIpa(IpaQueryConfig {
                                per_user_credit_cap,
                                max_breakdown_key,
                                attribution_window_seconds,
                                num_multi_bits,
                                plaintext_match_keys,
                            }))
                        }
                        &_ => unreachable!(),
                    }
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
                QueryType::TestMultiply => Ok(()),
                QueryType::SemiHonestIpa(config) | QueryType::MaliciousIpa(config) => {
                    write!(
                        f,
                        "&per_user_credit_cap={}&max_breakdown_key={}&num_multi_bits={}",
                        config.per_user_credit_cap, config.max_breakdown_key, config.num_multi_bits,
                    )?;

                    if config.plaintext_match_keys {
                        write!(f, "&plaintext_match_keys=true")?;
                    }

                    if let Some(window) = config.attribution_window_seconds {
                        write!(f, "&attribution_window_seconds={}", window.get())?;
                    }

                    Ok(())
                }
            }
        }
    }

    pub const BASE_AXUM_PATH: &str = "/query";

    pub mod create {
        use async_trait::async_trait;
        use axum::extract::{FromRequest, RequestParts};
        use hyper::http::uri;

        use crate::{
            helpers::query::QueryConfig,
            net::{
                http_serde::query::{QueryConfigQueryParams, BASE_AXUM_PATH},
                Error,
            },
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
            ) -> Result<hyper::Request<hyper::Body>, Error> {
                let uri = uri::Builder::new()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}?{}",
                        BASE_AXUM_PATH,
                        QueryConfigQueryParams(self.query_config)
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri).body(hyper::Body::empty())?)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Request {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let QueryConfigQueryParams(query_config) = req.extract().await?;
                Ok(Self { query_config })
            }
        }

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct ResponseBody {
            pub query_id: QueryId,
        }

        pub const AXUM_PATH: &str = "/";
    }

    pub mod prepare {
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
            Json,
        };
        use hyper::header::CONTENT_TYPE;

        use crate::{
            helpers::{query::PrepareQuery, RoleAssignment},
            net::{
                http_serde::query::{QueryConfigQueryParams, BASE_AXUM_PATH},
                Error,
            },
        };

        #[derive(Debug, Clone)]
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
            ) -> Result<hyper::Request<hyper::Body>, Error> {
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
                let body = hyper::Body::from(serde_json::to_string(&body)?);
                Ok(hyper::Request::post(uri)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)?)
            }
        }

        #[async_trait]
        impl FromRequest<hyper::Body> for Request {
            type Rejection = Error;

            async fn from_request(
                req: &mut RequestParts<hyper::Body>,
            ) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                let QueryConfigQueryParams(config) = req.extract().await?;
                let Json(RequestBody { roles }) = req.extract().await?;
                Ok(Request {
                    data: PrepareQuery {
                        query_id,
                        config,
                        roles,
                    },
                })
            }
        }

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        struct RequestBody {
            roles: RoleAssignment,
        }

        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod input {
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
        };
        use hyper::{header::CONTENT_TYPE, Body};

        use crate::{
            helpers::query::QueryInput,
            net::{http_serde::query::BASE_AXUM_PATH, Error},
        };

        #[derive(Debug)]
        pub struct Request {
            pub query_input: QueryInput,
        }

        impl Request {
            pub fn new(query_input: QueryInput) -> Self {
                Self { query_input }
            }

            #[allow(clippy::type_complexity)] // to be addressed in follow-up
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<Body>, Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/input",
                        BASE_AXUM_PATH,
                        self.query_input.query_id.as_ref(),
                    ))
                    .build()?;
                let body = Body::wrap_stream(self.query_input.input_stream);
                Ok(hyper::Request::post(uri)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(body)?)
            }
        }

        #[async_trait]
        impl FromRequest<Body> for Request {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                let input_stream = req.extract().await?;

                Ok(Request {
                    query_input: QueryInput {
                        query_id,
                        input_stream,
                    },
                })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/input";
    }

    pub mod step {
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
        };

        use crate::{
            helpers::BodyStream,
            net::{http_serde::query::BASE_AXUM_PATH, Error},
            protocol::{step::Gate, QueryId},
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
        impl Request<hyper::Body> {
            pub fn try_into_http_request(
                self,
                scheme: uri::Scheme,
                authority: uri::Authority,
            ) -> Result<hyper::Request<hyper::Body>, Error> {
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

        /// Convert from axum request. Used on server side.
        #[async_trait]
        impl<B> FromRequest<B> for Request<BodyStream>
        where
            B: Send,
            BodyStream: FromRequest<B>,
            Error: From<<BodyStream as FromRequest<B>>::Rejection>,
        {
            type Rejection = Error;

            // Rust pedantry: letting Rust infer the type parameter for the first `extract()` call
            // from the LHS of the assignment kind of works, but it requires additional guidance (in
            // the form of trait bounds on the impl) to see that PathRejection can be converted to
            // Error. Writing `Path` twice somehow avoids that.
            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let Path((query_id, gate)) = req.extract::<Path<_>>().await?;
                let body = req.extract().await?;
                Ok(Self {
                    query_id,
                    gate,
                    body,
                })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/step/*step";
    }

    pub mod status {
        use async_trait::async_trait;
        use axum::extract::{FromRequest, Path, RequestParts};
        use serde::{Deserialize, Serialize};

        use crate::{net::Error, protocol::QueryId, query::QueryStatus};

        #[derive(Debug, Clone)]
        pub struct Request {
            pub query_id: QueryId,
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
            ) -> Result<hyper::Request<hyper::Body>, Error> {
                let uri = axum::http::uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}",
                        crate::net::http_serde::query::BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::get(uri).body(hyper::Body::empty())?)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Request {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                Ok(Request { query_id })
            }
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ResponseBody {
            pub status: QueryStatus,
        }

        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod results {
        use async_trait::async_trait;
        use axum::extract::{FromRequest, Path, RequestParts};

        use crate::{net::Error, protocol::QueryId};

        #[derive(Debug, Clone)]
        pub struct Request {
            pub query_id: QueryId,
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
            ) -> Result<hyper::Request<hyper::Body>, Error> {
                let uri = axum::http::uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/complete",
                        crate::net::http_serde::query::BASE_AXUM_PATH,
                        self.query_id.as_ref()
                    ))
                    .build()?;
                Ok(hyper::Request::get(uri).body(hyper::Body::empty())?)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Request {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                Ok(Request { query_id })
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/complete";
    }
}
