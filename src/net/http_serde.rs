// there isn't an easy way to compose const strings at compile time, so we will hard-code
// everything

pub mod echo {
    use crate::net::Error;
    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};
    use hyper::http::uri;
    use std::collections::HashMap;

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

    #[cfg(never)]
    pub const AXUM_PATH: &str = "/echo";
}

pub mod query {
    use crate::{
        ff::FieldType,
        helpers::{
            query::{QueryConfig, QueryType},
            HelperIdentity,
        },
        net::Error,
    };
    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};
    use hyper::header::HeaderName;
    use std::{
        fmt::{Display, Formatter},
        str::FromStr,
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
                field_type: FieldType,
                query_type: String,
            }
            let Query(QueryTypeParam {
                field_type,
                query_type,
            }) = req.extract().await?;

            let query_type = match query_type.as_str() {
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TEST_MULTIPLY_STR => Ok(QueryType::TestMultiply),
                QueryType::IPA_STR => {
                    let Query(config) = req.extract().await?;
                    Ok(QueryType::Ipa(config))
                }
                other => Err(Error::bad_query_value("query_type", other)),
            }?;
            Ok(QueryConfigQueryParams(QueryConfig {
                field_type,
                query_type,
            }))
        }
    }

    impl Display for QueryConfigQueryParams {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "field_type={:?}&", self.field_type)?;
            match &self.query_type {
                #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
                QueryType::TestMultiply => write!(f, "query_type={}", QueryType::TEST_MULTIPLY_STR),
                QueryType::Ipa(config) => write!(
                    f,
                    "query_type={}&per_user_credit_cap={}&max_breakdown_key={}&attribution_window_seconds={}&num_multi_bits={}",
                    QueryType::IPA_STR,
                    config.per_user_credit_cap,
                    config.max_breakdown_key,
                    config.attribution_window_seconds,
                    config.num_multi_bits,
                ),
            }
        }
    }

    /// name of the `origin` header to use for [`OriginHeader`]
    static ORIGIN_HEADER_NAME: HeaderName = HeaderName::from_static("origin");

    fn get_header<B, H: FromStr>(req: &RequestParts<B>, header_name: HeaderName) -> Result<H, Error>
    where
        Error: From<<H as FromStr>::Err>,
    {
        let header_name_string = header_name.to_string();
        req.headers()
            .get(header_name)
            .ok_or(Error::MissingHeader(header_name_string))
            .and_then(|header_value| header_value.to_str().map_err(Into::into))
            .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
    }

    /// Header indicating the originating `HelperIdentity`.
    /// May be replaced in the future with a method with better security
    #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
    struct OriginHeader {
        origin: HelperIdentity,
    }

    impl OriginHeader {
        fn add_to(self, req: axum::http::request::Builder) -> axum::http::request::Builder {
            req.header(ORIGIN_HEADER_NAME.clone(), self.origin)
        }
    }

    #[async_trait]
    impl<B: Send> FromRequest<B> for OriginHeader {
        type Rejection = Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            let origin: usize = get_header(req, ORIGIN_HEADER_NAME.clone())?;
            let origin =
                HelperIdentity::try_from(origin).map_err(|err| Error::InvalidHeader(err.into()))?;
            Ok(OriginHeader { origin })
        }
    }

    pub const BASE_AXUM_PATH: &str = "/query";

    pub mod create {
        use crate::{
            helpers::query::QueryConfig,
            net::{
                http_serde::query::{QueryConfigQueryParams, BASE_AXUM_PATH},
                Error,
            },
            protocol::QueryId,
        };
        use async_trait::async_trait;
        use axum::extract::{FromRequest, RequestParts};
        use hyper::http::uri;

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

        #[cfg(never)]
        pub const AXUM_PATH: &str = "/";
    }

    pub mod prepare {
        use crate::{
            helpers::{query::PrepareQuery, HelperIdentity, RoleAssignment},
            net::{
                http_serde::query::{OriginHeader, QueryConfigQueryParams, BASE_AXUM_PATH},
                Error,
            },
        };
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
            Json,
        };
        use hyper::header::CONTENT_TYPE;

        #[derive(Debug, Clone)]
        pub struct Request {
            pub origin: HelperIdentity,
            pub data: PrepareQuery,
        }

        impl Request {
            pub fn new(origin: HelperIdentity, data: PrepareQuery) -> Self {
                Self { origin, data }
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
                let origin_header = OriginHeader {
                    origin: self.origin,
                };
                let body = RequestBody {
                    roles: self.data.roles,
                };
                let body = hyper::Body::from(serde_json::to_string(&body)?);
                Ok(origin_header
                    .add_to(hyper::Request::post(uri))
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
                let origin_header = req.extract::<OriginHeader>().await?;
                let Json(RequestBody { roles }) = req.extract().await?;
                Ok(Request {
                    origin: origin_header.origin,
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

        #[cfg(never)]
        pub const AXUM_PATH: &str = "/:query_id";
    }

    pub mod input {
        use crate::{
            helpers::{query::QueryInput, ByteArrStream},
            net::{http_serde::query::BASE_AXUM_PATH, Error},
        };
        use async_trait::async_trait;
        use axum::{
            body::StreamBody,
            extract::{BodyStream, FromRequest, Path, RequestParts},
            http::uri,
        };
        use hyper::{
            body::{Bytes, HttpBody},
            header::CONTENT_TYPE,
            Body,
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
            ) -> Result<hyper::Request<StreamBody<ByteArrStream>>, Error> {
                let uri = uri::Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(format!(
                        "{}/{}/input",
                        BASE_AXUM_PATH,
                        self.query_input.query_id.as_ref(),
                    ))
                    .build()?;
                Ok(hyper::Request::post(uri)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(StreamBody::new(self.query_input.input_stream))?)
            }
        }

        struct ByteArrStreamFromReq(ByteArrStream);

        #[async_trait]
        impl<B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + 'static> FromRequest<B>
            for ByteArrStreamFromReq
        {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let body: BodyStream = req.extract().await?;

                Ok(ByteArrStreamFromReq(body.into()))
            }
        }

        #[async_trait]
        impl FromRequest<Body> for Request {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<Body>) -> Result<Self, Self::Rejection> {
                let Path(query_id) = req.extract().await?;
                let ByteArrStreamFromReq(input_stream) = req.extract().await?;

                Ok(Request {
                    query_input: QueryInput {
                        query_id,
                        input_stream,
                    },
                })
            }
        }

        #[cfg(never)]
        pub const AXUM_PATH: &str = "/:query_id/input";
    }

    pub mod step {
        use crate::{
            helpers::HelperIdentity,
            net::{
                http_serde::query::{OriginHeader, BASE_AXUM_PATH},
                Error,
            },
            protocol::{QueryId, Step},
        };
        use async_trait::async_trait;
        use axum::{
            extract::{FromRequest, Path, RequestParts},
            http::uri,
        };

        // When this type is used on the client side, `B` is `hyper::Body`. When this type
        // is used on the server side, `B` can be any body type supported by axum.
        #[derive(Debug)]
        pub struct Request<B> {
            pub origin: HelperIdentity,
            pub query_id: QueryId,
            pub step: Step,
            pub body: B,
        }

        impl<B> Request<B> {
            pub fn new(origin: HelperIdentity, query_id: QueryId, step: Step, body: B) -> Self {
                Self {
                    origin,
                    query_id,
                    step,
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
                        self.step.as_ref()
                    ))
                    .build()?;
                // TODO(597): this is a misuse of the origin header, and is insecure.
                // need to authenticate clients with TLS.
                let origin_header = OriginHeader {
                    origin: self.origin,
                };
                let req = hyper::Request::post(uri);
                let req = origin_header.add_to(req);
                Ok(req.body(self.body)?)
            }
        }

        /// Convert from axum request. Used on server side.
        #[async_trait]
        impl<B: Send> FromRequest<B> for Request<B> {
            type Rejection = Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let Path((query_id, step)) = req.extract().await?;
                let origin_header = req.extract::<OriginHeader>().await?;
                let body = req.take_body().unwrap();
                Ok(Self {
                    origin: origin_header.origin,
                    query_id,
                    step,
                    body,
                })
            }
        }

        #[cfg(never)]
        pub const AXUM_PATH: &str = "/:query_id/step/*step";
    }

    pub mod results {
        use crate::{net::Error, protocol::QueryId};
        use async_trait::async_trait;
        use axum::extract::{FromRequest, Path, RequestParts};

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

        #[cfg(never)]
        pub const AXUM_PATH: &str = "/:query_id/complete";
    }
}
