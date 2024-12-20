use std::sync::Weak;

use async_trait::async_trait;

use crate::{
    cli::LoggingHandle,
    executor::IpaRuntime,
    helpers::{
        query::{CompareStatusRequest, PrepareQuery, QueryConfig, QueryInput},
        routing::{Addr, RouteId},
        ApiError, BodyStream, HandlerBox, HandlerRef, HelperIdentity, HelperResponse,
        MpcTransportImpl, RequestHandler, ShardTransportImpl, Transport, TransportIdentity,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    protocol::QueryId,
    query::{NewQueryError, QueryProcessor, QueryStatus},
    sharding::ShardIndex,
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
    mpc_handler: HandlerRef<HelperIdentity>,
    shard_handler: HandlerRef<ShardIndex>,
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
    logging_handle: LoggingHandle,
}

impl Setup {
    #[must_use]
    pub fn new(config: AppConfig) -> (Self, HandlerRef<HelperIdentity>, HandlerRef<ShardIndex>) {
        let key_registry = config.key_registry.unwrap_or_else(KeyRegistry::empty);
        let query_processor = QueryProcessor::new(key_registry, config.active_work, config.runtime);
        let mpc_handler = HandlerBox::empty();
        let shard_handler = HandlerBox::empty();
        let this = Self {
            query_processor,
            mpc_handler: mpc_handler.clone(),
            shard_handler: shard_handler.clone(),
        };

        // TODO: weak reference to query processor to prevent mem leak
        (this, mpc_handler, shard_handler)
    }

    #[must_use]
    pub fn with_key_registry(
        key_registry: KeyRegistry<PrivateKeyOnly>,
    ) -> (Self, HandlerRef<HelperIdentity>, HandlerRef<ShardIndex>) {
        Self::new(AppConfig::default().with_key_registry(key_registry))
    }

    /// Instantiate [`HelperApp`] by connecting it to the provided transport implementation
    pub fn connect(
        self,
        mpc_transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
        logging_handle: LoggingHandle,
    ) -> HelperApp {
        let app = Arc::new(Inner {
            query_processor: self.query_processor,
            mpc_transport,
            shard_transport,
            logging_handle,
        });
        self.mpc_handler
            .set_handler(Arc::downgrade(&app) as Weak<dyn RequestHandler<HelperIdentity>>);
        self.shard_handler
            .set_handler(Arc::downgrade(&app) as Weak<dyn RequestHandler<ShardIndex>>);

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
                self.inner.mpc_transport.clone_ref(),
                self.inner.shard_transport.clone_ref(),
                query_config,
            )
            .await?
            .query_id)
    }

    /// Sends query input to a helper.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    /// ## Panics
    /// If `input` asks to obtain query input from a remote URL.
    pub fn execute_query(&self, input: QueryInput) -> Result<(), ApiError> {
        let mpc_transport = self.inner.mpc_transport.clone_ref();
        let shard_transport = self.inner.shard_transport.clone_ref();
        let QueryInput::Inline {
            query_id,
            input_stream,
        } = input
        else {
            panic!("this client does not support pulling query input from a URL");
        };
        self.inner.query_processor.receive_inputs(
            mpc_transport,
            shard_transport,
            query_id,
            input_stream,
        )?;
        Ok(())
    }

    /// Retrieves the status of a query.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    pub async fn query_status(&self, query_id: QueryId) -> Result<QueryStatus, ApiError> {
        let shard_transport = self.inner.shard_transport.clone_ref();
        Ok(self
            .inner
            .query_processor
            .query_status(shard_transport, query_id)
            .await?)
    }

    /// Waits for a query to complete and returns the result.
    ///
    /// ## Errors
    /// Propagates errors from the helper.
    pub async fn complete_query(&self, query_id: QueryId) -> Result<Vec<u8>, ApiError> {
        Ok(self
            .inner
            .query_processor
            .complete(query_id, self.inner.shard_transport.clone_ref())
            .await?
            .to_bytes())
    }
}

fn ext_query_id<I: TransportIdentity>(req: &Addr<I>) -> Result<QueryId, ApiError> {
    req.query_id
        .ok_or_else(|| ApiError::BadRequest("Query input is missing query_id argument".into()))
}

#[async_trait]
impl RequestHandler<ShardIndex> for Inner {
    async fn handle(
        &self,
        req: Addr<ShardIndex>,
        data: BodyStream,
    ) -> Result<HelperResponse, ApiError> {
        let qp = &self.query_processor;

        Ok(match req.route {
            RouteId::PrepareQuery => {
                let req = req.into::<PrepareQuery>()?;
                HelperResponse::from(qp.prepare_shard(&self.shard_transport, req)?)
            }
            RouteId::QueryStatus => {
                let req = req.into::<CompareStatusRequest>()?;
                HelperResponse::from(qp.shard_status(&self.shard_transport, &req)?)
            }
            RouteId::CompleteQuery => {
                // The processing flow for this API is exactly the same, regardless
                // whether it was received from a peer shard or from report collector.
                // Authentication is handled on the layer above, so we erase the identity
                // and pass it down to the MPC handler.
                RequestHandler::<HelperIdentity>::handle(self, req.erase_origin(), data).await?
            }
            r => {
                return Err(ApiError::BadRequest(
                    format!("{r:?} request must not be handled by shard query processing flow")
                        .into(),
                ))
            }
        })
    }
}

#[async_trait]
impl RequestHandler<HelperIdentity> for Inner {
    async fn handle(
        &self,
        req: Addr<HelperIdentity>,
        data: BodyStream,
    ) -> Result<HelperResponse, ApiError> {
        let qp = &self.query_processor;
        Ok(match req.route {
            r @ RouteId::Records => {
                return Err(ApiError::BadRequest(
                    format!("{r:?} request must not be handled by MPC query processing flow")
                        .into(),
                ))
            }
            RouteId::ReceiveQuery => {
                let req = req.into::<QueryConfig>()?;
                HelperResponse::from(
                    qp.new_query(
                        self.mpc_transport.clone_ref(),
                        self.shard_transport.clone_ref(),
                        req,
                    )
                    .await?,
                )
            }
            RouteId::PrepareQuery => {
                let req = req.into::<PrepareQuery>()?;
                HelperResponse::from(
                    qp.prepare_helper(
                        self.mpc_transport.clone_ref(),
                        self.shard_transport.clone_ref(),
                        req,
                    )
                    .await?,
                )
            }
            RouteId::QueryInput => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.receive_inputs(
                    Transport::clone_ref(&self.mpc_transport),
                    Transport::clone_ref(&self.shard_transport),
                    query_id,
                    data,
                )?)
            }
            RouteId::QueryStatus => {
                let query_id = ext_query_id(&req)?;
                let shard_transport = Transport::clone_ref(&self.shard_transport);
                let query_status = qp.query_status(shard_transport, query_id).await?;
                HelperResponse::from(query_status)
            }
            RouteId::CompleteQuery => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(
                    qp.complete(query_id, self.shard_transport.clone_ref())
                        .await?,
                )
            }
            RouteId::KillQuery => {
                let query_id = ext_query_id(&req)?;
                HelperResponse::from(qp.kill(query_id)?)
            }
            RouteId::Metrics => {
                let logging_handler = &self.logging_handle;
                let metrics_handle = &logging_handler.metrics_handle;
                HelperResponse::from(metrics_handle.scrape_metrics())
            }
        })
    }
}
