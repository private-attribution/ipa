use std::future::Future;

use futures::FutureExt;

use crate::{
    error::Error,
    helpers::Role,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        ipa_prf::shuffle::sharded::ShuffleContext,
    },
    sharding::Sharded,
};

mod base;
mod malicious;
mod sharded;
pub(crate) mod step; // must be pub(crate) for compact gate gen

use base::shuffle_protocol as base_shuffle;
use malicious::{malicious_sharded_shuffle, malicious_shuffle};
use sharded::shuffle as sharded_shuffle;
pub use sharded::{MaliciousShuffleable, Shuffleable};

use crate::sharding::NotSharded;

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

    /// Return an empty `IntermediateShuffleMessages` for the currrent helper.
    pub fn empty<C: Context>(ctx: &C) -> Self {
        match ctx.role() {
            Role::H1 => IntermediateShuffleMessages::H1 { x1: vec![] },
            Role::H2 => IntermediateShuffleMessages::H2 { x2: vec![] },
            Role::H3 => IntermediateShuffleMessages::H3 {
                y1: vec![],
                y2: vec![],
            },
        }
    }
}

/// Trait used by protocols to invoke either semi-honest or malicious non-sharded
/// shuffle, depending on the type of context being used.
pub trait Shuffle: Context {
    fn shuffle<S>(self, shares: Vec<S>) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable;
}

impl Shuffle for SemiHonestContext<'_, NotSharded> {
    fn shuffle<S>(self, shares: Vec<S>) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
    {
        let fut = base_shuffle::<_, S, _>(self, shares);
        fut.map(|res| res.map(|(output, _intermediates)| output))
    }
}

impl Shuffle for MaliciousContext<'_, NotSharded> {
    fn shuffle<S>(self, shares: Vec<S>) -> impl Future<Output = Result<Vec<S>, Error>> + Send
    where
        S: MaliciousShuffleable,
    {
        malicious_shuffle::<_, S>(self, shares)
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
