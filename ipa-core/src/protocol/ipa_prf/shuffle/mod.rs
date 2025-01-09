use std::future::Future;

use futures::FutureExt;

use crate::{
    error::Error,
    helpers::Role,
    protocol::{
        context::{MaliciousContext, SemiHonestContext},
        ipa_prf::shuffle::sharded::ShuffleContext,
    },
    sharding::Sharded,
};

mod malicious;
mod sharded;
pub(crate) mod step; // must be pub(crate) for compact gate gen

use malicious::malicious_sharded_shuffle;
use sharded::shuffle as sharded_shuffle;
pub use sharded::{MaliciousShuffleable, Shuffleable};

/// This struct stores some intermediate messages during the shuffle.
/// In a maliciously secure shuffle,
/// these messages need to be checked for consistency across helpers.
/// `H1` stores `x1`, `H2` stores `x2` and `H3` stores `y1` and `y2`.
#[derive(Debug, Clone)]
enum IntermediateShuffleMessages<S> {
    H1 { x1: Vec<S> },
    H2 { x2: Vec<S> },
    H3 { y1: Vec<S>, y2: Vec<S> },
}

impl<S> IntermediateShuffleMessages<S> {
    pub fn role(&self) -> Role {
        match *self {
            IntermediateShuffleMessages::H1 { .. } => Role::H1,
            IntermediateShuffleMessages::H2 { .. } => Role::H2,
            IntermediateShuffleMessages::H3 { .. } => Role::H3,
        }
    }
}

/// Trait used by protocols to invoke either semi-honest or malicious sharded shuffle,
/// depending on the type of context being used.
pub trait ShardedShuffle: ShuffleContext {
    fn sharded_shuffle<S>(
        self,
        shares: Vec<S>,
    ) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable;
}

impl ShardedShuffle for SemiHonestContext<'_, Sharded> {
    fn sharded_shuffle<S>(
        self,
        shares: Vec<S>,
    ) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
    {
        let fut = sharded_shuffle::<_, S, _>(self, shares);
        fut.map(|res| res.map(|(output, _intermediates)| output))
    }
}

impl ShardedShuffle for MaliciousContext<'_, Sharded> {
    fn sharded_shuffle<S>(
        self,
        shares: Vec<S>,
    ) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
    {
        malicious_sharded_shuffle::<_, S>(self, shares)
    }
}
