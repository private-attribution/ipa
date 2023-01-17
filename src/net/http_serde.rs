// there isn't an easy way to compose const strings at compile time, so we will hard-code
// everything

pub mod echo {
    pub const AXUM_PATH: &str = "/echo";

    pub fn uri(payload: &str) -> String {
        format!("/echo?foo={payload}")
    }
}

pub mod query {
    use crate::{
        ff::FieldType,
        helpers::{
            query::{IPAQueryConfig, QueryConfig, QueryType},
            HelperIdentity,
        },
        net::server,
    };
    use async_trait::async_trait;
    use axum::extract::{FromRequest, Query, RequestParts};
    use hyper::header::HeaderName;
    use std::fmt::{Display, Formatter};
    use std::str::FromStr;

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
    impl<B: Send> FromRequest<B> for QueryConfigQueryParams {
        type Rejection = server::Error;

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
                    #[derive(serde::Deserialize)]
                    struct IPAQueryConfigParam {
                        num_bits: u32,
                        per_user_credit_cap: u32,
                        max_breakdown_key: u128,
                    }
                    let Query(IPAQueryConfigParam {
                        num_bits,
                        per_user_credit_cap,
                        max_breakdown_key,
                    }) = req.extract().await?;

                    Ok(QueryType::IPA(IPAQueryConfig {
                        num_bits,
                        per_user_credit_cap,
                        max_breakdown_key,
                    }))
                }
                other => Err(server::Error::bad_query_value("query_type", other)),
            }?;
            Ok(QueryConfigQueryParams(QueryConfig {
                field_type,
                query_type,
            }))
        }
    }

    impl Display for QueryConfigQueryParams {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "field-type={}&", self.field_type.as_ref())?;
            match self.query_type {
                QueryType::TestMultiply => write!(f, "query-type={}", QueryType::TEST_MULTIPLY_STR),
                QueryType::IPA(config) => write!(
                    f,
                    "query-type={}&num-bits={}&per-user-credit-cap={}&max-breakdown-key={}",
                    QueryType::IPA_STR,
                    config.num_bits,
                    config.per_user_credit_cap,
                    config.max_breakdown_key
                ),
            }
        }
    }

    /// name of the `origin` header to use for [`OriginHeader`]
    static ORIGIN_HEADER_NAME: HeaderName = HeaderName::from_static("origin");

    fn get_header<B, H: FromStr>(
        req: &RequestParts<B>,
        header_name: HeaderName,
    ) -> Result<H, server::Error>
    where
        server::Error: From<<H as FromStr>::Err>,
    {
        let header_name_string = header_name.to_string();
        req.headers()
            .get(header_name)
            .ok_or(server::Error::MissingHeader(header_name_string))
            .and_then(|header_value| header_value.to_str().map_err(Into::into))
            .and_then(|header_value_str| header_value_str.parse().map_err(Into::into))
    }

    /// Header indicating the originating `HelperIdentity`.
    /// May be replaced in the future with a method with better security
    #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
    pub struct OriginHeader {
        pub origin: HelperIdentity,
    }

    impl OriginHeader {
        pub(crate) fn add_to(
            self,
            req: axum::http::request::Builder,
        ) -> axum::http::request::Builder {
            req.header(ORIGIN_HEADER_NAME.clone(), self.origin)
        }
    }

    #[async_trait]
    impl<B: Send> FromRequest<B> for OriginHeader {
        type Rejection = server::Error;

        async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
            let origin: usize = get_header(req, ORIGIN_HEADER_NAME.clone())?;
            let origin = HelperIdentity::try_from(origin)
                .map_err(|err| server::Error::InvalidHeader(err.into()))?;
            Ok(OriginHeader { origin })
        }
    }

    pub const BASE_AXUM_PATH: &str = "/query";

    pub mod create {
        use crate::{
            helpers::query::QueryConfig, net::http_serde::query::QueryConfigQueryParams,
            protocol::QueryId,
        };

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct ResponseBody {
            pub query_id: QueryId,
        }

        pub const AXUM_PATH: &str = "/";

        pub fn uri(data: QueryConfig) -> String {
            format!("/query?{}", QueryConfigQueryParams(data))
        }
    }

    pub mod prepare {
        use crate::{
            helpers::{query::QueryConfig, RoleAssignment},
            net::http_serde::query::QueryConfigQueryParams,
            protocol::QueryId,
        };

        #[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct RequestBody {
            pub roles: RoleAssignment,
        }

        pub const AXUM_PATH: &str = "/:query_id";

        pub fn uri(query_id: QueryId, data: QueryConfig) -> String {
            format!(
                "/query/{}?{}",
                query_id.as_ref(),
                QueryConfigQueryParams(data)
            )
        }
    }

    pub mod input {
        use crate::{ff::FieldType, protocol::QueryId};

        pub const AXUM_PATH: &str = "/:query_id/input";

        pub fn uri(query_id: QueryId, field_type: FieldType) -> String {
            format!(
                "/query/{}/input?field_name={}",
                query_id.as_ref(),
                field_type.as_ref()
            )
        }
    }

    pub mod step {
        use crate::{
            helpers::MESSAGE_PAYLOAD_SIZE_BYTES,
            net::{http_serde::query::get_header, server},
            protocol::{QueryId, Step},
        };
        use async_trait::async_trait;
        use axum::extract::{FromRequest, RequestParts};
        use hyper::header::HeaderName;

        /// name of the `content-type` header used to get the length of the body, to verify valid `data-size`
        static CONTENT_LENGTH_HEADER_NAME: HeaderName = HeaderName::from_static("content-length");
        /// name of the `offset` header to use for [`Headers`]
        static OFFSET_HEADER_NAME: HeaderName = HeaderName::from_static("offset");

        /// Headers that are expected on `Step` commands
        /// # `offset`
        /// For any given batch, their `record_id`s must be known. The first record in the batch will have
        /// id `offset`, and subsequent records will be in-order from there.
        #[derive(Copy, Clone)]
        pub struct Headers {
            pub offset: u32,
        }

        impl Headers {
            pub(crate) fn add_to(
                self,
                req: axum::http::request::Builder,
            ) -> axum::http::request::Builder {
                req.header(OFFSET_HEADER_NAME.clone(), self.offset)
            }
        }

        #[async_trait]
        impl<B: Send> FromRequest<B> for Headers {
            type Rejection = server::Error;

            async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
                let content_length: u32 = get_header(req, CONTENT_LENGTH_HEADER_NAME.clone())?;
                let offset: u32 = get_header(req, OFFSET_HEADER_NAME.clone())?;
                // content_length must be aligned with the size of an element
                if content_length as usize % MESSAGE_PAYLOAD_SIZE_BYTES == 0 {
                    Ok(Headers { offset })
                } else {
                    Err(server::Error::WrongBodyLen {
                        body_len: content_length,
                        element_size: MESSAGE_PAYLOAD_SIZE_BYTES,
                    })
                }
            }
        }

        pub const AXUM_PATH: &str = "/:query_id/step/*step";

        pub fn uri(query_id: QueryId, step: &Step) -> String {
            format!("/query/{}/step/{}", query_id.as_ref(), step.as_ref())
        }
    }

    pub mod results {
        use crate::protocol::QueryId;

        pub const AXUM_PATH: &str = "/:query_id/complete";

        pub fn uri(query_id: QueryId) -> String {
            format!("/query/{}/complete", query_id.as_ref())
        }
    }
}
