#![allow(dead_code)] // until sharded shuffle is used in OPRF
//! This implements the 3-way shuffle protocol from paper
//! "Secure Graph Analysis at Scale" by
//! Toshinori Araki, Jun Furukawa, Benny Pinkas, Kazuma Ohara, Hanan Rosemarin, and Hikaru Tsuchida.
//!
//! Concretely, it implements 2 round, 4 message Shuffle from section 5.2.
//! This protocol was augmented to operate over sharded MPC networks. In addition to 4 rounds of
//! MPC communication, it uses 6 rounds of intra-helper communications to send data between shards.
//! In this implementation, this operation is called "resharding".

use std::{
    borrow::Borrow,
    future::Future,
    num::NonZeroUsize,
    ops::{Add, AddAssign},
};

use futures::{future::try_join, stream, StreamExt};
use rand::seq::SliceRandom;
use typenum::Unsigned;

use crate::{
    const_assert_eq,
    error::LengthError,
    ff::{
        boolean_array::{BA112, BA144, BA32, BA64, BA96},
        Gf32Bit, Serializable, U128Conversions,
    },
    helpers::{Direction, Error, Role, TotalRecords},
    protocol::{
        context::{reshard_iter, ShardedContext},
        ipa_prf::shuffle::{
            step::{ShardedShufflePermuteStep as PermuteStep, ShardedShuffleStep as ShuffleStep},
            IntermediateShuffleMessages,
        },
        prss::{FromRandom, SharedRandomness},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        Block, Sendable, SharedValue,
    },
    seq_join::{assert_send, seq_join},
};

/// This context is only useful for sharded shuffle modules because it implements common operations
/// that all shards on all helpers perform to achieve the perfect shuffle.
///
/// This trait is `pub`, which is required, because it is a supertrait of `pub trait ShardedShuffle`.
/// `mod sharded` is not `pub`, which makes the situation a variant of the sealed trait pattern.
/// Specifically, it prevents types outside `mod shuffle` from implementing `trait ShuffleContext`.
/// Note that this structure does NOT prevent calling these methods outside of `mod shuffle`, but
/// please don't do that.
pub trait ShuffleContext: ShardedContext {
    /// This sends a single machine word (8 byte value) to one of the helpers specified in
    /// `direction` parameter.
    fn send_word(
        self,
        direction: Direction,
        val: usize,
    ) -> impl Future<Output = Result<(), crate::error::Error>> + Send {
        async move {
            Ok(self
                .set_total_records(TotalRecords::ONE)
                .send_channel::<BA64>(self.role().peer(direction))
                .send(
                    RecordId::FIRST,
                    BA64::truncate_from(u128::try_from(val).unwrap()),
                )
                .await?)
        }
    }

    /// This receives a single machine word (8 byte value) from one of the helpers specified in
    /// `direction` parameter.
    fn recv_word(
        self,
        direction: Direction,
    ) -> impl Future<Output = Result<usize, crate::error::Error>> + Send {
        async move {
            let val: [u8; 8] = self
                .recv_channel::<BA64>(self.role().peer(direction))
                .receive(RecordId::FIRST)
                .await?
                .as_raw_slice()
                .try_into()
                .unwrap();
            Ok(usize::try_from(u64::from_le_bytes(val)).unwrap())
        }
    }

    /// In sharded shuffle, it is a common operation to apply a mask to the input and then permute
    /// it, with all shards involved in the process. This routine implements it, so helper-specific
    /// code does not need to do this repetitive work.
    ///
    /// The destination shard for each masked row is decided based on value obtained from sampling
    /// PRSS. Which value to use (left or right) is decided based on `direction` parameter.
    fn mask_and_shuffle<I, S>(
        self,
        direction: Direction,
        data: I,
    ) -> impl Future<Output = Result<Vec<S>, crate::error::Error>> + Send
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator + Send,
        I::Item: Borrow<S>,
        S: ShuffleShare,
    {
        let data = data.into_iter();
        async move {
            let masking_ctx = self.narrow(&PermuteStep::Mask);
            let mut resharded = assert_send(reshard_iter(
                self.clone(),
                data.enumerate().map(|(i, item)| {
                    masking_ctx
                        .prss()
                        .generate_one_side::<S, _>(RecordId::from(i), direction)
                        + item.borrow()
                }),
                |ctx, record_id, _| ctx.pick_shard(record_id, direction),
            ))
            .await?;

            let ctx = self.narrow(&PermuteStep::LocalShuffle);
            resharded.shuffle(&mut match direction {
                Direction::Left => ctx.prss_rng().0,
                Direction::Right => ctx.prss_rng().1,
            });

            Ok(resharded)
        }
    }

    /// Receive all the values from the specified helper. It is assumed that this context is narrowed
    /// to the correct step, before receiving.
    fn recv_all<S>(
        &self,
        direction: Direction,
    ) -> impl Future<Output = Result<Vec<S>, crate::error::Error>> + Send
    where
        S: ShuffleShare,
    {
        async move {
            let mut rid = RecordId::FIRST;
            let mut buf = Vec::new();
            let recv_channel = self.recv_channel(self.role().peer(direction));
            loop {
                match recv_channel.receive(rid).await {
                    Ok(v) => buf.push(v),
                    Err(Error::EndOfStream { .. }) => break,
                    Err(e) => return Err(e.into()),
                }

                rid += 1;
            }

            Ok(buf)
        }
    }

    /// Send all values to the specified helper. It is assumed that this context is narrowed
    /// to the correct step, before receiving.
    ///
    /// It works for empty input too - this shard will open a connection and then immediately close
    /// it, sending a signal to the receiver that the stream has been closed.
    fn send_all<I, S>(
        &self,
        shares: I,
        direction: Direction,
    ) -> impl Future<Output = Result<(), crate::error::Error>>
    where
        I: IntoIterator<Item = S>,
        I::IntoIter: ExactSizeIterator + Send,
        S: ShuffleShare,
    {
        let shares = shares.into_iter();
        let sz = shares.len();
        let ctx = self.set_total_records(TotalRecords::specified(sz).unwrap_or(TotalRecords::ONE));

        async move {
            let send_channel = ctx.send_channel::<S>(ctx.role().peer(direction));

            let mut send_stream = seq_join(
                self.active_work(),
                stream::iter(shares)
                    .enumerate()
                    .map(|(i, v)| send_channel.send(RecordId::from(i), v)),
            );
            while let Some(v) = send_stream.next().await {
                v?;
            }

            send_channel.close(RecordId::from(sz)).await;

            Ok(())
        }
    }
}

impl<C: ShardedContext> ShuffleContext for C {}

/// Marker trait for share values that can be shuffled. In simple cases where we shuffle events
/// that consists of a single share, it is not required to implement it, because there exists a
/// blanket implementation for all shares.
///
/// It becomes useful for complex structs that require a shuffle. [`ReplicatedSecretSharing`] assumes
/// that the data it holds is small (a pair of shared values) which is not true for impressions and
/// conversions that are fed into the shuffle.
///
/// [`ShuffleShare`] and [`Shuffleable`] are added to bridge the gap. They can be implemented for
/// arbitrary structs as long as `Add` operation can be defined on them.
pub trait ShuffleShare:
    Sendable
    + Clone
    + Serializable
    + FromRandom
    + Add<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
{
    const BITS: u32;
    const ZERO: Self;
}

impl<V> ShuffleShare for V
where
    V: SharedValue
        + Serializable
        + FromRandom
        + for<'a> Add<&'a Self, Output = Self>
        + for<'a> AddAssign<&'a Self>,
{
    const BITS: u32 = <V as SharedValue>::BITS;
    const ZERO: Self = <V as SharedValue>::ZERO;
}

/// Trait for shuffle inputs that consists of two values (left and right).
pub trait Shuffleable: Send + Sync + 'static {
    type Share: ShuffleShare;

    fn left(&self) -> Self::Share;
    fn right(&self) -> Self::Share;

    fn new(l: Self::Share, r: Self::Share) -> Self;
}

impl<V> Shuffleable for AdditiveShare<V>
where
    V: SharedValue
        + Serializable
        + FromRandom
        + for<'a> Add<&'a V, Output = V>
        + for<'a> AddAssign<&'a V>,
{
    type Share = V;

    fn left(&self) -> Self::Share {
        ReplicatedSecretSharing::left(self)
    }

    fn right(&self) -> Self::Share {
        ReplicatedSecretSharing::right(self)
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        ReplicatedSecretSharing::new(l, r)
    }
}

/// Trait for inputs to malicious shuffle.
///
/// Do not implement this trait directly. Implement `Shuffleable` and add an invocation
/// of `impl_malicious_shuffle_share` for your `<T as Shuffleable>::Share` type, if it
/// does not already exist.
pub trait MaliciousShuffleable:
    Shuffleable<Share = Self::MaliciousShare> + Clone + Default
{
    /// The `Shuffleable::Share` type, with additional bounds for malicious shuffle.
    type MaliciousShare: ShuffleShare + MaliciousShuffleShare;

    /// Same as `Self::MaliciousShare::ShareAndTag`.
    ///
    /// Having an alias here makes it easier to reference in the code, because the
    /// shuffle routines have an `S: MaliciousShuffleable` type parameter.
    type ShareAndTag: ShuffleShare;

    /// Same as `Self::MaliciousShare::TAG_OFFSET`.
    ///
    /// Having an alias here makes it easier to reference in the code, because the
    /// shuffle routines have an `S: MaliciousShuffleable` type parameter.
    const TAG_OFFSET: usize;

    fn to_gf32bit(
        &self,
    ) -> Result<impl Iterator<Item = AdditiveShare<Gf32Bit>> + Send, crate::error::Error> {
        let left_shares: Vec<Gf32Bit> = self.left().try_into()?;
        let right_shares: Vec<Gf32Bit> = self.right().try_into()?;
        Ok(left_shares
            .into_iter()
            .zip(right_shares)
            .map(|(left, right)| ReplicatedSecretSharing::new(left, right)))
    }
}

impl<T> MaliciousShuffleable for T
where
    T: Shuffleable + Clone + Default,
    T::Share: MaliciousShuffleShare,
{
    type MaliciousShare = T::Share;
    type ShareAndTag = <T::Share as MaliciousShuffleShare>::ShareAndTag;
    const TAG_OFFSET: usize = <T::Share as MaliciousShuffleShare>::TAG_OFFSET;
}

/// Trait for a share of an input to malicious shuffle.
///
/// This trait should be implemented using the `impl_malicious_shuffleable!` macro,
/// which will check the size of the `ShareAndTag` type and compute `TAG_OFFSET`
/// automatically.
pub trait MaliciousShuffleShare: TryInto<Vec<Gf32Bit>, Error = LengthError> {
    /// A type that can hold `<Self as Shuffleable>::Share` along with a 32-bit MAC.
    type ShareAndTag: ShuffleShare;

    /// The offset to the MAC in `ShareAndTag`.
    const TAG_OFFSET: usize;
}

/// Implement `MaliciousShuffleShare`, checking that the type combination is valid.
macro_rules! impl_malicious_shuffle_share {
    ($share:ty, $share_and_tag:ty) => {
        impl MaliciousShuffleShare for $share {
            type ShareAndTag = $share_and_tag;
            const TAG_OFFSET: usize = <<$share as SharedValue>::Storage as Block>::Size::USIZE;
        }

        const_assert_eq!(
            <$share_and_tag as SharedValue>::BITS as usize,
            <$share as MaliciousShuffleShare>::TAG_OFFSET * 8 + 32,
            concat!(
                stringify!($share_and_tag),
                " is not the right size to hold ",
                "share and tag for ",
                stringify!($share),
            ),
        );
    };
}

impl_malicious_shuffle_share!(BA32, BA64);
impl_malicious_shuffle_share!(BA64, BA96);
impl_malicious_shuffle_share!(BA112, BA144);

/// Sharded shuffle as performed by shards on H1.
pub(super) async fn h1_shuffle_for_shard<I, S, C>(
    ctx: C,
    shares: I,
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), crate::error::Error>
where
    I: IntoIterator<Item = S>,
    I::IntoIter: Send + ExactSizeIterator,
    C: ShardedContext,
    S: Shuffleable,
{
    // Generate X_1 = perm_12(left ⊕ right ⊕ z_12).
    let x1: Vec<S::Share> = ctx
        .narrow(&ShuffleStep::Permute12)
        .mask_and_shuffle(
            Direction::Right,
            shares.into_iter().map(|share| share.left() + share.right()),
        )
        .await?;

    // Generate X_2 = perm_31(X_1 ⊕ z_31) and reshard it using the randomness
    // shared with the left helper.
    let x2: Vec<S::Share> = ctx
        .narrow(&ShuffleStep::Permute31)
        .mask_and_shuffle(Direction::Left, &x1)
        .await?;

    // X_2 is masked now and cannot reveal anything to the helper on the right.
    ctx.narrow(&ShuffleStep::TransferXY)
        .send_all(x2, Direction::Right)
        .await?;

    // H1 does not know anything about C. In a non-sharded world, the cardinality of C
    // can be derived from input, sharding makes it impossible to derive because shares
    // are not distributed evenly across shards. Thus, each shard on H2 must inform H1 peer
    // about the size of C, so H1 can use PRSS to set its own shares.
    let sz = ctx
        .narrow(&ShuffleStep::Cardinality)
        .recv_word(Direction::Right)
        .await?;

    // set our shares
    let ctx = ctx.narrow(&ShuffleStep::PseudoRandomTable);
    let res = (0..sz)
        .map(|i| {
            // This may be confusing as paper specifies Ã and B̃ as independent tables, but
            // there is really no reason to generate them using unique PRSS keys.
            let (a, b) = ctx.prss().generate(RecordId::from(i));

            S::new(a, b)
        })
        .collect();

    Ok((res, IntermediateShuffleMessages::H1 { x1 }))
}

/// Sharded shuffle as performed by shards on H2.
pub(super) async fn h2_shuffle_for_shard<I, S, C>(
    ctx: C,
    shares: I,
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), crate::error::Error>
where
    I: IntoIterator<Item = S>,
    I::IntoIter: Send + ExactSizeIterator,
    C: ShardedContext,
    S: Shuffleable,
{
    // Generate Y_1 = perm_12(right ⊕ z_12)
    let y1 = ctx
        .narrow(&ShuffleStep::Permute12)
        .mask_and_shuffle(
            Direction::Left,
            shares.into_iter().map(|share| share.right()),
        )
        .await?;

    // Share y1 to the right. Safe to do because input has been masked with randomness
    // known to H1 and H2 only.
    ctx.narrow(&ShuffleStep::TransferXY)
        .send_all(y1, Direction::Right)
        .await?;

    let x2 = ctx
        .narrow(&ShuffleStep::TransferXY)
        .recv_all::<S::Share>(Direction::Left)
        .await?;

    // generate X_3 = perm_23(X_2 ⊕ z_23)
    let x3: Vec<S::Share> = ctx
        .narrow(&ShuffleStep::Permute23)
        .mask_and_shuffle(Direction::Right, &x2)
        .await?;

    // at this moment we know the cardinality of C, and we let H1 know it, so it can start
    // setting up its own shares.
    ctx.narrow(&ShuffleStep::Cardinality)
        .send_word(Direction::Left, x3.len())
        .await?;

    let Some(x3_len) = NonZeroUsize::new(x3.len()) else {
        return Ok((Vec::new(), IntermediateShuffleMessages::H2 { x2 }));
    };

    // Generate c_1 = X_3 ⊕ b, stream it to H3 and receive c_2 from it at the same time.
    // Knowing b, c_1 and c_2 lets us set our resulting share, according to the paper it is
    // (b, c_1 + c_2)
    let send_channel = ctx
        .narrow(&ShuffleStep::TransferC)
        .set_total_records(x3_len)
        .send_channel::<S::Share>(ctx.role().peer(Direction::Right));
    let recv_channel = ctx
        .narrow(&ShuffleStep::TransferC)
        .recv_channel::<S::Share>(ctx.role().peer(Direction::Right));

    let res = ctx
        .try_join(x3.into_iter().enumerate().map(|(i, x3)| {
            let record_id = RecordId::from(i);
            let b: S::Share = ctx
                .narrow(&ShuffleStep::PseudoRandomTable)
                .prss()
                .generate_one_side(RecordId::from(i), Direction::Left);
            let send_channel_ref = &send_channel;
            let recv_channel_ref = &recv_channel;
            async move {
                let c1 = x3 + &b;
                let ((), c2) = try_join(
                    send_channel_ref.send(record_id, &c1),
                    recv_channel_ref.receive(record_id),
                )
                .await?;
                Ok::<_, Error<_>>(S::new(b, c1 + c2))
            }
        }))
        .await?;

    Ok((res, IntermediateShuffleMessages::H2 { x2 }))
}

/// Sharded shuffle as performed by shards on H3. Note that in semi-honest setting, H3 does not
/// use its input. Adding support for active security will change that.
pub(super) async fn h3_shuffle_for_shard<I, S, C>(
    ctx: C,
    _: I,
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), crate::error::Error>
where
    I: IntoIterator<Item = S>,
    I::IntoIter: Send + ExactSizeIterator,
    C: ShardedContext,
    S: Shuffleable,
{
    // Receive y1 from the left
    let y1 = ctx
        .narrow(&ShuffleStep::TransferXY)
        .recv_all::<S::Share>(Direction::Left)
        .await?;

    // Generate y2 = perm_31(y_1 ⊕ z_31)
    let y2: Vec<S::Share> = ctx
        .narrow(&ShuffleStep::Permute31)
        .mask_and_shuffle(Direction::Right, &y1)
        .await?;

    // Generate y3 = perm_23(y_2 ⊕ z_23)
    let y3: Vec<S::Share> = ctx
        .narrow(&ShuffleStep::Permute23)
        .mask_and_shuffle(Direction::Left, &y2)
        .await?;

    let Some(y3_len) = NonZeroUsize::new(y3.len()) else {
        return Ok((Vec::new(), IntermediateShuffleMessages::H3 { y1, y2 }));
    };

    // Generate c_2 = y_3 ⊕ a, stream it to H2 and receive c_1 from it at the same time.
    // Set our share to be (c_1 + c_2, a)
    let send_channel = ctx
        .narrow(&ShuffleStep::TransferC)
        .set_total_records(y3_len)
        .send_channel::<S::Share>(ctx.role().peer(Direction::Left));
    let recv_channel = ctx
        .narrow(&ShuffleStep::TransferC)
        .recv_channel::<S::Share>(ctx.role().peer(Direction::Left));
    let res = ctx
        .try_join(y3.into_iter().enumerate().map(|(i, y3)| {
            let record_id = RecordId::from(i);
            let a: S::Share = ctx
                .narrow(&ShuffleStep::PseudoRandomTable)
                .prss()
                .generate_one_side(RecordId::from(i), Direction::Right);
            let send_channel_ref = &send_channel;
            let recv_channel_ref = &recv_channel;
            async move {
                let c2 = y3 + &a;
                let ((), c1) = try_join(
                    send_channel_ref.send(record_id, &c2),
                    recv_channel_ref.receive(record_id),
                )
                .await?;
                Ok::<_, Error<_>>(S::new(c1 + c2, a))
            }
        }))
        .await?;

    Ok((res, IntermediateShuffleMessages::H3 { y1, y2 }))
}

/// Internal entry point to sharded shuffle protocol, excluding validation of
/// intermediates for malicious security. Protocols should use `trait Shuffle`.
///
/// ## Errors
/// Failure to communicate over the network, either to other MPC helpers, and/or to other shards
/// will generate a shuffle error.
pub(super) async fn shuffle<I, S, C>(
    ctx: C,
    shares: I,
) -> Result<(Vec<S>, IntermediateShuffleMessages<S::Share>), crate::error::Error>
where
    I: IntoIterator<Item = S>,
    I::IntoIter: Send + ExactSizeIterator,
    C: ShardedContext,
    S: Shuffleable,
{
    match ctx.role() {
        Role::H1 => h1_shuffle_for_shard(ctx, shares).await,
        Role::H2 => h2_shuffle_for_shard(ctx, shares).await,
        Role::H3 => h3_shuffle_for_shard(ctx, shares).await,
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
mod tests {

    use crate::{
        ff::{boolean_array::BA8, U128Conversions},
        protocol::ipa_prf::shuffle::sharded::shuffle,
        test_executor::run,
        test_fixture::{
            Distribute, RandomInputDistribution, Reconstruct, RoundRobinInputDistribution, Runner,
            TestWorld, TestWorldConfig, WithShards,
        },
    };

    async fn sharded_shuffle<const SHARDS: usize, D: Distribute>(input: Vec<BA8>) -> Vec<BA8> {
        let world: TestWorld<WithShards<SHARDS, D>> =
            TestWorld::with_shards(TestWorldConfig::default());
        let sharded_result = world
            .semi_honest(input.into_iter(), |ctx, input| async move {
                shuffle(ctx, input).await.unwrap().0
            })
            .await;

        assert_eq!(sharded_result.len(), SHARDS);

        sharded_result
            .into_iter()
            .flat_map(|v| v.reconstruct())
            .collect::<Vec<_>>()
    }

    #[test]
    fn non_empty_input() {
        async fn shuffle_using<const SHARDS: usize, D: Distribute>() {
            // sufficiently large to keep the probability of shuffle generating the same permutation
            // very low: 12! ~ 1/4*10^8
            let inputs = [1_u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
                .map(BA8::truncate_from)
                .to_vec();
            let mut result = sharded_shuffle::<SHARDS, D>(inputs.clone()).await;

            assert_ne!(inputs, result);
            result.sort_by_key(U128Conversions::as_u128);

            assert_eq!(inputs, result);
        }

        run(|| async move {
            type Distribution = RoundRobinInputDistribution;

            shuffle_using::<1, Distribution>().await;
            shuffle_using::<2, Distribution>().await;
            shuffle_using::<3, Distribution>().await;
            shuffle_using::<5, Distribution>().await;
            shuffle_using::<8, Distribution>().await;
        });

        run(|| async move {
            type Distribution = RandomInputDistribution;
            type FixedSeedDistribution = RandomInputDistribution<123>;

            shuffle_using::<1, Distribution>().await;
            shuffle_using::<2, Distribution>().await;
            shuffle_using::<3, Distribution>().await;
            shuffle_using::<5, Distribution>().await;
            shuffle_using::<8, Distribution>().await;
            shuffle_using::<1, FixedSeedDistribution>().await;
            shuffle_using::<2, FixedSeedDistribution>().await;
            shuffle_using::<3, FixedSeedDistribution>().await;
            shuffle_using::<5, FixedSeedDistribution>().await;
            shuffle_using::<8, FixedSeedDistribution>().await;
        });
    }

    #[test]
    fn empty() {
        run(|| async move {
            let result = sharded_shuffle::<1, RoundRobinInputDistribution>(Vec::new()).await;
            assert!(result.is_empty());
            let result = sharded_shuffle::<3, RandomInputDistribution>(Vec::new()).await;
            assert!(result.is_empty());
        });
    }
}
