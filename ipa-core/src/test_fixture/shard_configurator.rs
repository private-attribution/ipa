use std::{marker::PhantomData, sync::Arc};

use rand::rngs::StdRng;
use rand_core::SeedableRng;

use crate::{
    helpers::Role,
    protocol::prss::Endpoint as PrssEndpoint,
    sharding::{NotSharded, ShardBinding, ShardIndex, Sharded},
    test_fixture::{make_participants, world::ShardingScheme, Distribute, WithShards},
};

/// This trait serves the purpose of setting up shard contexts. Each shard shares some
/// global state with others (cross-shard PRSS) and also owns its own state (per-shard PRSS).
/// This construction allows [`ShardWorld`] to be agnostic to shard vs non-shard configuration
/// setup.
pub trait ShardConfigurator<B: ShardBinding> {
    fn shard_id(&self) -> Option<ShardIndex>;
    fn bind(&self, role: Role) -> B;
}

/// Universal configurator, capable of configuring shards in non-sharded
/// and sharded environments
pub struct Configurator<S: ShardingScheme> {
    shard_id: Option<ShardIndex>,
    // Per-helper shared randomness shared across all shards. For non-sharded environments,
    // there is no access to it.
    helper_participants: Option<[Arc<PrssEndpoint>; 3]>,
    _marker: PhantomData<S>,
}

impl Default for Configurator<NotSharded> {
    fn default() -> Self {
        Self {
            shard_id: None,
            helper_participants: None,
            _marker: PhantomData,
        }
    }
}

impl<const SHARDS: usize, D: Distribute> Configurator<WithShards<SHARDS, D>> {
    pub fn new(shard_id: ShardIndex, cs_prss_seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(cs_prss_seed);
        Self {
            shard_id: Some(shard_id),
            helper_participants: Some(make_participants(&mut rng).map(Arc::new)),
            _marker: PhantomData,
        }
    }
}

impl<const SHARDS: usize, D: Distribute> ShardConfigurator<Sharded>
    for Configurator<WithShards<SHARDS, D>>
{
    fn shard_id(&self) -> Option<ShardIndex> {
        self.shard_id
    }

    fn bind(&self, role: Role) -> Sharded {
        Sharded {
            shard_id: self.shard_id.unwrap(),
            shard_count: SHARDS.try_into().unwrap(),
            prss: Arc::clone(&self.helper_participants.as_ref().unwrap()[role]),
        }
    }
}

impl ShardConfigurator<NotSharded> for Configurator<NotSharded> {
    fn shard_id(&self) -> Option<ShardIndex> {
        None
    }

    fn bind(&self, _role: Role) -> NotSharded {
        NotSharded
    }
}
