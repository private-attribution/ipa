use std::sync::Weak;

use async_trait::async_trait;

use crate::{
    executor::IpaRuntime,
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        routing::{Addr, RouteId},
        ApiError, BodyStream, HandlerBox, HandlerRef, HelperIdentity, HelperResponse,
        MpcTransportImpl, RequestHandler, ShardTransportImpl, Transport,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    protocol::QueryId,
    query::{NewQueryError, QueryProcessor, QueryStatus},
    sync::Arc,
    utils::NonZeroU32PowerOfTwo,
};

#[derive(Default)]
pub struct AppConfig {
    active_work: Option<NonZeroU32PowerOfTwo>,
    key_registry: Option<KeyRegistry<PrivateKeyOnly>>,
    runtime: IpaRuntime,
}

impl AppConfig {
    #[must_use]
    pub fn with_active_work(mut self, active_work: Option<NonZeroU32PowerOfTwo>) -> Self {
        self.active_work = active_work;
        self
    }

    #[must_use]
    pub fn with_key_registry(mut self, key_registry: KeyRegistry<PrivateKeyOnly>) -> Self {
        self.key_registry = Some(key_registry);
        self
    }

    #[must_use]
    pub fn with_runtime(mut self, runtime: IpaRuntime) -> Self {
        self.runtime = runtime;
        self
    }
}

pub struct Setup {
    query_processor: QueryProcessor,
    handler: HandlerRef,
}

/// The API layer to interact with a helper.
#[must_use]
pub struct HelperApp {
    inner: Arc<Inner>,
}

struct Inner {
    query_processor: QueryProcessor,
    /// For HTTP implementation this transport is also behind an [`Arc`] which causes double indirection
    /// on top of atomics and all fun stuff associated with it. I don't see an easy way to avoid that
    /// if we want to keep the implementation leak-free, but one may be aware if this shows up on
    /// the flamegraph
    mpc_transport: MpcTransportImpl,
    shard_transport: ShardTransportImpl,
}

impl Setup {
    #[must_use]
    pub fn new(config: AppConfig) -> (Self, HandlerRef) {
        let key_registry = config.key_registry.unwrap_or_else(KeyRegistry::empty);
        let query_processor = QueryProcessor::new(key_registry, config.active_work, config.runtime);
        let handler = HandlerBox::empty();
        let this = Self {
            query_processor,
            handler: handler.clone(),
        };

        // TODO: weak reference to query processor to prevent mem leak
        (this, handler)
    }

    #[must_use]
    pub fn with_key_registry(key_registry: KeyRegistry<PrivateKeyOnly>) -> (Self, HandlerRef) {
        Self::new(AppConfig::default().with_key_registry(key_registry))
    }

    /// Instantiate [`HelperApp`] by connecting it to the provided transport implementation
    pub fn connect(
        self,
        mpc_transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
    ) -> HelperApp {
        let app = Arc::new(Inner {
            query_processor: self.query_processor,
            mpc_transport,
            shard_transport,
        });
        self.handler.set_handler(
            Arc::downgrade(&app) as Weak<dyn RequestHandler<Identity = HelperIdentity>>
        );

        // Handler must be kept inside the app instance. When app is dropped, handler, transport and
        // query processor are destroyed.
        HelperApp { inner: app }
    }
}

impl HelperApp {
    /// Initiates a new query on this helper. In case if query is accepted, the unique [`QueryId`]
    /// identifier is returned, otherwise an error indicating what went wrong is reported back.
    ///
    /// ## Errors
    /// If query is rejected for any reason.
    pub async fn start_query(&self, query_config: QueryConfig) -> Result<QueryId, NewQueryError> {
        Ok(self
            .inner
            .query_processor
            .new_query(
                Transport::clone_ref(&self.inner.mpc_transport),
                query_config,
            )
            .await?
            .query_id)
    }

    /// Sends query input to a helper.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    pub fn execute_query(&self, input: QueryInput) -> Result<(), ApiError> {
        let mpc_transport = Transport::clone_ref(&self.inner.mpc_transport);
        let shard_transport = Transport::clone_ref(&self.inner.shard_transport);
        self.inner
            .query_processor
            .receive_inputs(mpc_transport, shard_transport, input)?;
        Ok(())
    }

    /// Retrieves the status of a query.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    pub fn query_status(&self, query_id: QueryId) -> Result<QueryStatus, ApiError> {
        Ok(self.inner.query_processor.query_status(query_id)?)
    }

    /// Waits for a query to complete and returns the result.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    pub async fn complete_query(&self, query_id: QueryId) -> Result<Vec<u8>, ApiError> {
        Ok(self
            .inner
            .query_processor
            .complete(query_id)
            .await?
            .to_bytes())
    }
}

#[async_trait]
impl RequestHandler for Inner {
    type Identity = HelperIdentity;

    async fn handle(
        &self,
        req: Addr<Self::Identity>,
        data: BodyStream,
    ) -> Result<HelperResponse, ApiError> {
        fn ext_query_id(req: &Addr<HelperIdentity>) -> Result<QueryId, ApiError> {
            req.query_id.ok_or_else(|| {
                ApiError::BadRequest("Query input is missing query_id argument".into())
            })
        }

        let qp = &self.query_processor;

        Ok(match req.route {
            r @ RouteId::Records => {
                return Err(ApiError::BadRequest(
                    format!("{r:?} request must not be handled by query processing flow").into(),
                ))
            }
            RouteId::ReceiveQuery => {
                let req = req.into::<QueryConfig>()?;
                HelperResponse::from(
                    qp.new_query(Transport::clone_ref(&self.mpc_transport), req)
                        .await?,
                )
            }
            RouteId::PrepareQuery => {
                let req = req.into::<PrepareQuery>()?;
                HelperResponse::from(qp.prepare(&self.mpc_transport, req)?)
            }
            RouteId::QueryInput => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.receive_inputs(
                    Transport::clone_ref(&self.mpc_transport),
                    Transport::clone_ref(&self.shard_transport),
                    QueryInput {
                        query_id,
                        input_stream: data,
                    },
                )?)
            }
            RouteId::QueryStatus => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.query_status(query_id)?)
            }
            RouteId::CompleteQuery => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.complete(query_id).await?)
            }
            RouteId::KillQuery => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.kill(query_id)?)
            }
        })
    }
}
