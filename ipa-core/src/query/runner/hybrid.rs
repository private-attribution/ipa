use std::{marker::PhantomData, sync::Arc};

use crate::{
    error::Error,
    helpers::{
        query::{HybridQueryParams, QuerySize},
        BodyStream,
    },
    hpke::PrivateKeyRegistry,
    secret_sharing::{replicated::semi_honest::AdditiveShare as ReplicatedShare, SharedValue},
};

pub struct Query<C, HV, R: PrivateKeyRegistry> {
    _config: HybridQueryParams,
    _key_registry: Arc<R>,
    phantom_data: PhantomData<(C, HV)>,
}

impl<C, HV: SharedValue, R: PrivateKeyRegistry> Query<C, HV, R> {
    pub fn new(query_params: HybridQueryParams, key_registry: Arc<R>) -> Self {
        Self {
            _config: query_params,
            _key_registry: key_registry,
            phantom_data: PhantomData,
        }
    }

    #[tracing::instrument("hybrid_query", skip_all, fields(sz=%query_size))]
    pub async fn execute(
        self,
        _ctx: C,
        query_size: QuerySize,
        _input_stream: BodyStream,
    ) -> Result<Vec<ReplicatedShare<HV>>, Error> {
        unimplemented!()
    }
}
