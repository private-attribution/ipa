use std::{
    future::ready,
    iter::{self, zip},
};

use futures::{
    stream::{self, TryStreamExt},
    StreamExt,
};
use futures_util::future::{try_join, try_join3};
use generic_array::GenericArray;
use subtle::ConstantTimeEq;
use typenum::Const;

use crate::{
    error::Error,
    ff::{Expand, Field, Gf32Bit, Serializable},
    helpers::{
        hashing::{compute_possibly_empty_hash, Hash},
        stream::{div_round_up, process_slice_by_chunks, TryFlattenItersExt},
        Direction, Role, TotalRecords,
    },
    protocol::{
        basics::{malicious_reveal, mul::semi_honest_multiply},
        boolean::step::EightBitStep,
        context::{Context, ShardedContext},
        ipa_prf::shuffle::{
            base::shuffle_protocol,
            sharded::{
                h1_shuffle_for_shard, h2_shuffle_for_shard, h3_shuffle_for_shard,
                MaliciousShuffleable, ShuffleShare, Shuffleable,
            },
            step::{OPRFShuffleStep, ShardedShuffleStep, VerifyShuffleStep},
            IntermediateShuffleMessages,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue,
    },
    seq_join::seq_join,
    sharding::ShardIndex,
};

/// Container for left and right shares with tags attached to them.
/// Looks like an additive share, but it is not because it does not need
/// many traits that additive shares require to implement
#[derive(Clone, Debug, Default)]
struct Pair<S: ShuffleShare> {
    left: S,
    right: S,
}

impl<S: ShuffleShare> Shuffleable for Pair<S> {
    type Share = S;

    fn left(&self) -> Self::Share {
        self.left.clone()
    }

    fn right(&self) -> Self::Share {
        self.right.clone()
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        Self { left: l, right: r }
    }
}

impl<S: ShuffleShare + SharedValue> From<AdditiveShare<S>> for Pair<S> {
    fn from(value: AdditiveShare<S>) -> Self {
        let (l, r) = value.as_tuple();
        Shuffleable::new(l, r)
    }
}

impl<S: ShuffleShare + SharedValue> From<Pair<S>> for AdditiveShare<S> {
    fn from(value: Pair<S>) -> Self {
        ReplicatedSecretSharing::new(value.left, value.right)
    }
}

/// This function executes the maliciously secure shuffle protocol on the input: `shares`.
///
/// ## Errors
/// Propagates network, multiplication and conversion errors from sub functions.
///
/// ## Panics
/// Panics when `S::Bits + 32 != B::Bits` or type conversions fail.
pub(super) async fn malicious_shuffle<C, S>(ctx: C, shares: Vec<S>) -> Result<Vec<S>, Error>
where
    C: Context,
    S: MaliciousShuffleable,
{
    // assert lengths
    assert_eq!(S::Share::BITS + 32, <S::ShareAndTag as ShuffleShare>::BITS);
    // compute amount of MAC keys
    let amount_of_keys: usize = (usize::try_from(S::Share::BITS).unwrap() + 31) / 32;
    // // generate MAC keys
    let keys = (0..amount_of_keys)
        .map(|i| ctx.prss().generate(RecordId::from(i)))
        .collect::<Vec<AdditiveShare<Gf32Bit>>>();

    // compute and append tags to rows
    let shares_and_tags: Vec<Pair<S::ShareAndTag>> =
        compute_and_add_tags(ctx.narrow(&OPRFShuffleStep::GenerateTags), &keys, shares).await?;

    // shuffle
    let (shuffled_shares, messages) = shuffle_protocol(ctx.clone(), shares_and_tags).await?;

    // verify the shuffle
    verify_shuffle::<_, S>(
        ctx.narrow(&OPRFShuffleStep::VerifyShuffle),
        &keys,
        shuffled_shares.as_slice(),
        messages,
    )
    .await?;

    // truncate tags from output_shares
    // verify_shuffle ensures that truncate_tags yields the correct rows
    Ok(truncate_tags(&shuffled_shares))
}

async fn setup_keys<C>(ctx: C, amount_of_keys: usize) -> Result<Vec<AdditiveShare<Gf32Bit>>, Error>
where
    C: ShardedContext,
{
    // We reshuffle among the shards, so all the shards need to use the same MAC keys.
    // The first shard generates the keys and sends them to all the others.
    let key_dist_ctx = ctx.set_total_records(TotalRecords::specified(amount_of_keys).unwrap());
    if ctx.shard_id() == ShardIndex::FIRST {
        // generate MAC keys
        let keys = (0..amount_of_keys)
            .map(|i| ctx.prss().generate(RecordId::from(i)))
            .collect::<Vec<AdditiveShare<Gf32Bit>>>();

        for shard in ctx.shard_count().iter().skip(1) {
            ctx.parallel_join(keys.iter().enumerate().map(|(i, key)| {
                let key_dist_ctx = key_dist_ctx.clone();
                async move {
                    key_dist_ctx
                        .shard_send_channel::<AdditiveShare<Gf32Bit>>(shard)
                        .send(RecordId::from(i), key)
                        .await
                }
            }))
            .await?;
        }

        Ok(keys)
    } else {
        key_dist_ctx
            .shard_recv_channel(ShardIndex::FIRST)
            .take(amount_of_keys)
            .try_collect()
            .await
    }
}

/// Entry point to execute malicious-secure sharded shuffle.
/// ## Errors
/// Failure to communicate over the network, either to other MPC helpers, and/or to other shards
/// will generate a shuffle error, as will detection of data inconsistencies that could indicate
/// a malicious helper.
#[allow(dead_code)]
pub async fn malicious_sharded_shuffle<C, S>(
    ctx: C,
    shares: Vec<S>,
) -> Result<Vec<S>, crate::error::Error>
where
    C: ShardedContext,
    S: MaliciousShuffleable,
{
    // assert lengths
    assert_eq!(S::Share::BITS + 32, <S::ShareAndTag as ShuffleShare>::BITS);

    // prepare keys
    let amount_of_keys: usize = (usize::try_from(S::Share::BITS).unwrap() + 31) / 32;
    let keys = setup_keys(ctx.narrow(&ShardedShuffleStep::SetupKeys), amount_of_keys).await?;

    // compute and append tags to rows
    let shares_and_tags: Vec<Pair<S::ShareAndTag>> =
        compute_and_add_tags(ctx.narrow(&ShardedShuffleStep::GenerateTags), &keys, shares).await?;

    let (shuffled_shares, messages) = match ctx.role() {
        Role::H1 => h1_shuffle_for_shard(ctx.clone(), shares_and_tags).await,
        Role::H2 => h2_shuffle_for_shard(ctx.clone(), shares_and_tags).await,
        Role::H3 => h3_shuffle_for_shard(ctx.clone(), shares_and_tags).await,
    }?;

    // verify the shuffle
    verify_shuffle::<_, S>(
        ctx.narrow(&ShardedShuffleStep::VerifyShuffle),
        &keys,
        &shuffled_shares,
        messages,
    )
    .await?;

    // truncate tags from output_shares
    // verify_shuffle ensures that truncate_tags yields the correct rows
    Ok(truncate_tags::<S>(&shuffled_shares))
}

/// This function truncates the tags from the output shares of the shuffle protocol
///
/// ## Panics
/// Panics when `S::Bits > B::Bits`.
fn truncate_tags<S>(shares_and_tags: &[Pair<S::ShareAndTag>]) -> Vec<S>
where
    S: MaliciousShuffleable,
{
    shares_and_tags
        .iter()
        .map(|row_with_tag| {
            Shuffleable::new(
                split_row_and_tag::<S>(&row_with_tag.left).0,
                split_row_and_tag::<S>(&row_with_tag.right).0,
            )
        })
        .collect()
}

/// This function splits a row with tag into
/// a row without tag and a tag.
///
/// When `row_with_tag` does not have the correct format,
/// i.e. deserialization returns an error,
/// the output row and tag will be zero.
fn split_row_and_tag<S: MaliciousShuffleable>(
    row_with_tag: &S::ShareAndTag,
) -> (S::Share, Gf32Bit) {
    let mut buf = GenericArray::default();
    row_with_tag.serialize(&mut buf);
    (
        S::Share::deserialize(GenericArray::from_slice(&buf.as_slice()[0..S::TAG_OFFSET]))
            .unwrap_or(S::Share::ZERO),
        Gf32Bit::deserialize(GenericArray::from_slice(&buf.as_slice()[S::TAG_OFFSET..]))
            .unwrap_or(<Gf32Bit as SharedValue>::ZERO),
    )
}

/// This function verifies the `shuffled_shares` and the `IntermediateShuffleMessages`.
///
/// ## Errors
/// Propagates network errors.
/// Further, returns an error when messages are inconsistent with the MAC tags.
async fn verify_shuffle<C: Context, S: MaliciousShuffleable>(
    ctx: C,
    key_shares: &[AdditiveShare<Gf32Bit>],
    shuffled_shares: &[Pair<S::ShareAndTag>],
    messages: IntermediateShuffleMessages<S::ShareAndTag>,
) -> Result<(), Error> {
    // reveal keys
    let k_ctx = ctx
        .narrow(&VerifyShuffleStep::RevealMACKey)
        .set_total_records(TotalRecords::specified(key_shares.len())?);
    let keys = reveal_keys(&k_ctx, key_shares).await?;

    assert_eq!(messages.role(), ctx.role());

    // verify messages and shares
    match messages {
        IntermediateShuffleMessages::H1 { x1 } => {
            h1_verify::<_, S>(ctx, &keys, shuffled_shares, x1).await
        }
        IntermediateShuffleMessages::H2 { x2 } => {
            h2_verify::<_, S>(ctx, &keys, shuffled_shares, x2).await
        }
        IntermediateShuffleMessages::H3 { y1, y2 } => {
            h3_verify::<_, S>(ctx, &keys, shuffled_shares, y1, y2).await
        }
    }
}

/// This is the verification function run by `H1`.
/// `H1` computes the hash for `x1` and `a_xor_b`.
/// Further, he receives `hash_y1` and `hash_c_h3` from `H3`
/// and `hash_c_h2` from `H2`.
///
/// ## Errors
/// Propagates network errors. Further it returns an error when
/// `hash_x1 != hash_y1` or `hash_c_h2 != hash_a_xor_b`
/// or `hash_c_h3 != hash_a_xor_b`.
async fn h1_verify<C: Context, S: MaliciousShuffleable>(
    ctx: C,
    keys: &[Gf32Bit],
    share_a_and_b: &[Pair<S::ShareAndTag>],
    x1: Vec<S::ShareAndTag>,
) -> Result<(), Error> {
    // compute hashes
    // compute hash for x1
    let hash_x1 = compute_and_hash_tags::<S, _>(keys, x1);
    // compute hash for A xor B
    let hash_a_xor_b = compute_and_hash_tags::<S, _>(
        keys,
        share_a_and_b
            .iter()
            .map(|share| Shuffleable::left(share) + Shuffleable::right(share)),
    );

    // setup channels
    let h3_ctx = ctx
        .narrow(&VerifyShuffleStep::HashesH3toH1)
        .set_total_records(TotalRecords::specified(2)?);
    let h2_ctx = ctx
        .narrow(&VerifyShuffleStep::HashH2toH1)
        .set_total_records(TotalRecords::ONE);
    let channel_h3 = &h3_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Left));
    let channel_h2 = &h2_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Right));

    // receive hashes
    let (hash_y1, hash_h3, hash_h2) = try_join3(
        channel_h3.receive(RecordId::FIRST),
        channel_h3.receive(RecordId::from(1usize)),
        channel_h2.receive(RecordId::FIRST),
    )
    .await?;

    // check y1
    if hash_x1.ct_ne(&hash_y1).into() {
        return Err(Error::ShuffleValidationFailed(format!(
            "Y1 is inconsistent: hash of x1: {hash_x1:?}, hash of y1: {hash_y1:?}"
        )));
    }

    // check c from h3
    if hash_a_xor_b.ct_ne(&hash_h3).into() {
        return Err(Error::ShuffleValidationFailed(format!(
            "C from H3 is inconsistent: hash of a_xor_b: {hash_a_xor_b:?}, hash of C: {hash_h3:?}"
        )));
    }

    // check h2
    if hash_a_xor_b.ct_ne(&hash_h2).into() {
        return Err(Error::ShuffleValidationFailed(format!(
            "C from H2 is inconsistent: hash of a_xor_b: {hash_a_xor_b:?}, hash of C: {hash_h2:?}"
        )));
    }

    Ok(())
}

/// This is the verification function run by `H2`.
/// `H2` computes the hash for `x2` and `c`
/// and sends the latter to `H1`.
/// Further, he receives `hash_y2` from `H3`
///
/// ## Errors
/// Propagates network errors. Further it returns an error when
/// `hash_x2 != hash_y2`.
async fn h2_verify<C: Context, S: MaliciousShuffleable>(
    ctx: C,
    keys: &[Gf32Bit],
    share_b_and_c: &[Pair<S::ShareAndTag>],
    x2: Vec<S::ShareAndTag>,
) -> Result<(), Error> {
    // compute hashes
    // compute hash for x2
    let hash_x2 = compute_and_hash_tags::<S, _>(keys, x2);
    // compute hash for C
    let hash_c = compute_and_hash_tags::<S, _>(keys, share_b_and_c.iter().map(Shuffleable::right));

    // setup channels
    let h1_ctx = ctx
        .narrow(&VerifyShuffleStep::HashH2toH1)
        .set_total_records(TotalRecords::specified(1)?);
    let h3_ctx = ctx
        .narrow(&VerifyShuffleStep::HashH3toH2)
        .set_total_records(TotalRecords::specified(1)?);
    let channel_h1 = &h1_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Left));
    let channel_h3 = &h3_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Right));

    // send and receive hash
    let ((), hash_h3) = try_join(
        channel_h1.send(RecordId::FIRST, hash_c),
        channel_h3.receive(RecordId::FIRST),
    )
    .await?;

    // check x2
    if hash_x2.ct_ne(&hash_h3).into() {
        return Err(Error::ShuffleValidationFailed(format!(
            "X2 is inconsistent: hash of x2: {hash_x2:?}, hash of y2: {hash_h3:?}"
        )));
    }

    Ok(())
}

/// This is the verification function run by `H3`.
/// `H3` computes the hash for `y1`, `y2` and `c`
/// and sends `y1`, `c` to `H1` and `y2` to `H2`.
///
/// ## Errors
/// Propagates network errors.
async fn h3_verify<C: Context, S: MaliciousShuffleable>(
    ctx: C,
    keys: &[Gf32Bit],
    share_c_and_a: &[Pair<S::ShareAndTag>],
    y1: Vec<S::ShareAndTag>,
    y2: Vec<S::ShareAndTag>,
) -> Result<(), Error> {
    // compute hashes
    // compute hash for y1
    let hash_y1 = compute_and_hash_tags::<S, _>(keys, y1);
    // compute hash for y2
    let hash_y2 = compute_and_hash_tags::<S, _>(keys, y2);
    // compute hash for C
    let hash_c = compute_and_hash_tags::<S, _>(keys, share_c_and_a.iter().map(Shuffleable::left));

    // setup channels
    let h1_ctx = ctx
        .narrow(&VerifyShuffleStep::HashesH3toH1)
        .set_total_records(TotalRecords::specified(2)?);
    let h2_ctx = ctx
        .narrow(&VerifyShuffleStep::HashH3toH2)
        .set_total_records(TotalRecords::specified(1)?);
    let channel_h1 = &h1_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Right));
    let channel_h2 = &h2_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Left));

    // send and receive hash
    let _ = try_join3(
        channel_h1.send(RecordId::FIRST, hash_y1),
        channel_h1.send(RecordId::from(1usize), hash_c),
        channel_h2.send(RecordId::FIRST, hash_y2),
    )
    .await?;

    Ok(())
}

/// This function computes for each item in the iterator the inner product with `keys`.
/// It concatenates all inner products and hashes them.
///
/// ## Panics
/// Panics when conversion from `BooleanArray` to `Vec<Gf32Bit` fails.
fn compute_and_hash_tags<S, I>(keys: &[Gf32Bit], row_iterator: I) -> Hash
where
    S: MaliciousShuffleable,
    I: IntoIterator<Item = S::ShareAndTag>,
{
    let iterator = row_iterator.into_iter().map(|row_with_tag| {
        // when split_row_and_tags returns the default value, the verification will fail
        // except 2^-security_parameter, i.e. 2^-32
        let (row, tag) = split_row_and_tag::<S>(&row_with_tag);
        <S::Share as TryInto<Vec<Gf32Bit>>>::try_into(row)
            .unwrap()
            .into_iter()
            .chain(iter::once(tag))
    });
    compute_possibly_empty_hash(iterator.map(|row_entry_iterator| {
        row_entry_iterator
            .zip(keys)
            .fold(<Gf32Bit as SharedValue>::ZERO, |acc, (row_entry, key)| {
                acc + row_entry * *key
            })
    }))
}

/// This function reveals the MAC keys,
/// stores them in a vector
/// and appends a `Gf32Bit::ONE`
///
/// It uses `parallel_join` and therefore vector elements are a `StdArray` of length `1`.
///
/// ## Errors
/// Propagates errors from `parallel_join` and `malicious_reveal`.
async fn reveal_keys<C: Context>(
    ctx: &C,
    key_shares: &[AdditiveShare<Gf32Bit>],
) -> Result<Vec<Gf32Bit>, Error> {
    // reveal MAC keys
    let keys = ctx
        .parallel_join(key_shares.iter().enumerate().map(|(i, key)| async move {
            // uses malicious_reveal directly since we malicious_shuffle always needs the malicious_revel
            malicious_reveal(ctx.clone(), RecordId::from(i), None, key)
                .await
                .map(|v| Gf32Bit::from_array(&v.unwrap()))
        }))
        .await?
        .into_iter()
        // add a one, since last row element is tag which is not multiplied with a key
        .chain(iter::once(Gf32Bit::ONE))
        .collect::<Vec<_>>();

    Ok(keys)
}

const TAG_CHUNK: usize = 32;

/// This function computes the MAC tag for each row and appends it to the row.
/// It outputs the vector of rows concatenated with the tags.
///
/// The tag is the inner product between keys and row entries,
/// i.e. `Sum_i key_i * row_entry_i`.
///
/// The multiplication is in `Gf32Bit`.
/// Therefore, each row is split into `32 bit` row entries
///
/// ## Error
/// Propagates MPC multiplication errors.
///
/// ## Panics
/// When conversion fails, when `S::Bits + 32 != B::Bits`
/// or when `rows` is empty or elements in `rows` have length `0`.
async fn compute_and_add_tags<C, S>(
    ctx: C,
    keys: &[AdditiveShare<Gf32Bit>],
    rows: Vec<S>,
) -> Result<Vec<Pair<S::ShareAndTag>>, Error>
where
    C: Context,
    S: MaliciousShuffleable,
{
    let length = rows.len();
    if length == 0 {
        return Ok(Vec::new());
    }
    let row_length = keys.len();
    // Make sure `total_records` is not zero.
    debug_assert!(row_length != 0);
    let total_records = TotalRecords::specified(div_round_up(length, Const::<TAG_CHUNK>))?;
    let tag_ctx = (0..row_length)
        .map(|i| {
            ctx.narrow(&EightBitStep::from(i))
                .set_total_records(total_records)
        })
        .collect::<Vec<_>>();
    let tag_ctx_ref = tag_ctx.as_slice();

    seq_join(
        tag_ctx[0].active_work(),
        process_slice_by_chunks::<_, _, _, _, TAG_CHUNK>(&rows, |i, chunk| async move {
            // Make TAG_CHUNK copies of each key
            let expanded_keys = keys
                .iter()
                .map(AdditiveShare::<Gf32Bit, TAG_CHUNK>::expand)
                .collect::<Vec<_>>();
            // Split each row into 32-bit words
            let split_rows: Vec<Vec<AdditiveShare<Gf32Bit>>> = chunk
                .iter()
                .map(|row| MaliciousShuffleable::to_gf32bit(row).map(Vec::from_iter))
                .collect::<Result<_, _>>()?;
            // Transpose rows to columns
            let cols: Vec<AdditiveShare<Gf32Bit, TAG_CHUNK>> = (0..keys.len())
                .map(|col| (0..TAG_CHUNK).map(|i| split_rows[i][col].clone()).collect())
                .collect();
            // Compute tags
            let tags: Vec<AdditiveShare<Gf32Bit>> =
                stream::iter(tag_ctx_ref.iter().zip(zip(expanded_keys, cols)))
                    .then(|(ctx, (key, data))| async move {
                        semi_honest_multiply(ctx.clone(), RecordId::from(i), &key, &data).await
                    })
                    .try_fold(AdditiveShare::ZERO, |acc, x| ready(Ok(acc + x)))
                    .await?
                    .into_unpacking_iter()
                    .collect::<Vec<_>>();
            // Join tags to rows
            Ok((0..TAG_CHUNK)
                .map(|i| concatenate_row_and_tag(&chunk[i], &tags[i]))
                .collect::<Vec<_>>())
        }),
    )
    .try_flatten_iters()
    .try_collect()
    .await
}

/// This helper function concatenates `row` and `row_tag`
/// and outputs the concatenation.
///
/// ## Panics
/// Panics when `S::Bits +32 != B::Bits`.
fn concatenate_row_and_tag<S: MaliciousShuffleable>(
    row: &S,
    tag: &AdditiveShare<Gf32Bit>,
) -> Pair<S::ShareAndTag> {
    let mut row_left = GenericArray::default();
    let mut row_right = GenericArray::default();
    let mut tag_left = GenericArray::default();
    let mut tag_right = GenericArray::default();
    row.left().serialize(&mut row_left);
    row.right().serialize(&mut row_right);
    tag.left().serialize(&mut tag_left);
    tag.right().serialize(&mut tag_right);
    Shuffleable::new(
        S::ShareAndTag::deserialize(&row_left.into_iter().chain(tag_left).collect()).unwrap(),
        S::ShareAndTag::deserialize(&row_right.into_iter().chain(tag_right).collect()).unwrap(),
    )
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    use super::*;
    use crate::{
        ff::{
            boolean_array::{BA112, BA144, BA32, BA64},
            Serializable, U128Conversions,
        },
        helpers::{
            in_memory_config::{MaliciousHelper, MaliciousHelperContext},
            Role,
        },
        protocol::ipa_prf::shuffle::base::shuffle_protocol,
        secret_sharing::{IntoShares, SharedValue},
        test_executor::{run, run_random},
        test_fixture::{
            RandomInputDistribution, Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards,
        },
    };

    /// Test the hashing of `BA112` and tag equality.
    #[test]
    fn hash() {
        run(|| async {
            let world = TestWorld::default();

            let mut rng = world.rng();
            let record = rng.gen::<BA112>();

            let (keys, result) = world
                .semi_honest(record, |ctx, record| async move {
                    // compute amount of MAC keys
                    let amount_of_keys: usize =
                        (usize::try_from(<BA112 as SharedValue>::BITS).unwrap() + 31) / 32;
                    // // generate MAC keys
                    let keys = (0..amount_of_keys)
                        .map(|i| ctx.prss().generate(RecordId::from(i)))
                        .collect::<Vec<AdditiveShare<Gf32Bit>>>();

                    // compute and append tags to rows
                    let shares_and_tags: Vec<AdditiveShare<BA144>> = compute_and_add_tags(
                        ctx.narrow(&OPRFShuffleStep::GenerateTags),
                        &keys,
                        vec![record],
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(AdditiveShare::from)
                    .collect();

                    (keys, shares_and_tags)
                })
                .await
                .reconstruct();

            let result_ba = BA112::deserialize_from_slice(&result[0].as_raw_slice()[0..14]);

            assert_eq!(record, result_ba);

            let tag = Vec::<Gf32Bit>::try_from(record)
                .unwrap()
                .iter()
                .zip(keys)
                .fold(<Gf32Bit as SharedValue>::ZERO, |acc, (entry, key)| {
                    acc + *entry * key
                });

            let tag_mpc = Vec::<Gf32Bit>::try_from(BA32::deserialize_from_slice(
                &result[0].as_raw_slice()[14..18],
            ))
            .unwrap();
            assert_eq!(tag, tag_mpc[0]);
        });
    }

    /// This test checks the correctness of the malicious shuffle.
    /// It does not check the security against malicious behavior.
    #[test]
    fn check_shuffle_correctness() {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = world.rng();
            let mut records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen())
                .collect::<Vec<BA112>>();

            let mut result = world
                .semi_honest(records.clone().into_iter(), |ctx, records| async move {
                    malicious_shuffle::<_, AdditiveShare<BA112>>(ctx, records)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();

            records.sort_by_key(BA112::as_u128);
            result.sort_by_key(BA112::as_u128);

            assert_eq!(records, result);
        });
    }

    #[test]
    fn empty() {
        run(|| async {
            assert_eq!(
                TestWorld::default()
                    .semi_honest(iter::empty::<BA32>(), |ctx, records| async move {
                        malicious_shuffle(ctx, records).await.unwrap()
                    })
                    .await
                    .reconstruct(),
                Vec::<BA32>::new(),
            );
        });
    }

    /// This test checks the correctness of the malicious shuffle
    /// when all parties behave honestly
    /// and all the MAC keys are `Gf32Bit::ONE`.
    /// Further, each row consists of a `BA32` and a `BA32` tag.
    #[test]
    fn check_shuffle_with_simple_mac() {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = world.rng();
            let records = (0..RECORD_AMOUNT)
                .map(|_| {
                    let entry = rng.gen::<[u8; 4]>();
                    let mut entry_and_tag = [0u8; 8];
                    entry_and_tag[0..4].copy_from_slice(&entry);
                    entry_and_tag[4..8].copy_from_slice(&entry);
                    BA64::deserialize_from_slice(&entry_and_tag)
                })
                .collect::<Vec<BA64>>();

            let _ = world
                .semi_honest(records.into_iter(), |ctx, rows| async move {
                    // trivial shares of Gf32Bit::ONE
                    let key_shares = vec![ReplicatedSecretSharing::new(Gf32Bit::ONE, Gf32Bit::ONE)];
                    // run shuffle
                    let (shares, messages) =
                        shuffle_protocol(ctx.narrow("shuffle"), rows).await.unwrap();
                    // verify it
                    verify_shuffle::<_, AdditiveShare<BA32>>(
                        ctx.narrow("verify"),
                        &key_shares,
                        shares
                            .into_iter()
                            .map(Pair::from)
                            .collect::<Vec<_>>()
                            .as_slice(),
                        messages,
                    )
                    .await
                    .unwrap();
                })
                .await;
        });
    }

    /// Helper function for tests below.
    ///
    /// `S::ShareAndTag::bITS` needs to be large enough to hold `S::Share::BITS`,
    /// followed by padding to a byte boundary, followed by `S::ShareAndTag::BITS`.
    ///
    /// The function concatenates random rows and tags
    /// and checks whether the concatenation
    /// is still consistent with the original rows and tags
    fn check_concatenate<S>(rng: &mut impl Rng)
    where
        S: MaliciousShuffleable,
        Standard: Distribution<S::Share>,
    {
        let row = <S as Shuffleable>::new(rng.gen(), rng.gen());
        let tag = AdditiveShare::<Gf32Bit>::new(rng.gen::<Gf32Bit>(), rng.gen::<Gf32Bit>());
        let row_and_tag: Pair<S::ShareAndTag> = concatenate_row_and_tag(&row, &tag);

        let mut buf = GenericArray::default();
        let mut buf_row = GenericArray::default();
        let mut buf_tag = GenericArray::default();

        // check left shares
        Shuffleable::left(&row_and_tag).serialize(&mut buf);
        Shuffleable::left(&row).serialize(&mut buf_row);
        assert_eq!(buf[0..S::TAG_OFFSET], buf_row[..]);
        ReplicatedSecretSharing::left(&tag).serialize(&mut buf_tag);
        assert_eq!(buf[S::TAG_OFFSET..], buf_tag[..]);

        // check right shares
        Shuffleable::right(&row_and_tag).serialize(&mut buf);
        Shuffleable::right(&row).serialize(&mut buf_row);
        assert_eq!(buf[0..S::TAG_OFFSET], buf_row[..]);
        ReplicatedSecretSharing::right(&tag).serialize(&mut buf_tag);
        assert_eq!(buf[S::TAG_OFFSET..], buf_tag[..]);
    }

    #[test]
    fn check_concatenate_for_boolean_arrays() {
        run_random(|mut rng| async move {
            check_concatenate::<AdditiveShare<BA32>>(&mut rng);
            check_concatenate::<AdditiveShare<BA112>>(&mut rng);
        });
    }

    /// Helper function for checking the tags
    /// `S::Bits + 32` needs to be the same as `B::Bits`
    ///
    /// The function runs the MPC protocol to compute the tags,
    /// i.e. `compute_and_add_tags`
    /// and compares the tags with the tags computed in the clear
    fn check_tags<S>()
    where
        S: MaliciousShuffleable,
        S::Share: IntoShares<S>,
        S::ShareAndTag: SharedValue,
        Standard: Distribution<S::Share>,
    {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = world.rng();
            let records = (0..RECORD_AMOUNT)
                .map(|_| rng.gen::<S::Share>())
                .collect::<Vec<_>>();
            // last key is not uniform when S:Bits is not a multiple of 32
            // since there will be a padding with zeros
            // but that is ok for test
            let keys = rng.gen::<S::Share>();

            // convert from S to Vec<Gf32Bit>
            let converted_keys: Vec<Gf32Bit> = keys.clone().try_into().unwrap();

            let expected_tags = records
                .iter()
                .cloned()
                .map(|row| {
                    // convert from S to Vec<Gf32Bit>
                    let converted_row: Vec<Gf32Bit> = row.try_into().unwrap();

                    // compute tag via inner product between row_entries and keys
                    converted_row
                        .into_iter()
                        .zip(converted_keys.iter())
                        .fold(<Gf32Bit as SharedValue>::ZERO, |acc, (row_entry, &key)| {
                            acc + row_entry * key
                        })
                })
                .collect::<Vec<Gf32Bit>>();

            let rows_and_tags: Vec<S::ShareAndTag> = world
                .semi_honest(
                    (records.into_iter(), keys),
                    |ctx, (row_shares, key_shares)| async move {
                        // convert key
                        let mac_key: Vec<AdditiveShare<Gf32Bit>> =
                            key_shares.to_gf32bit().unwrap().collect::<Vec<_>>();
                        compute_and_add_tags(
                            ctx.narrow(&OPRFShuffleStep::GenerateTags),
                            &mac_key,
                            row_shares,
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .map(AdditiveShare::from)
                        .collect::<Vec<_>>()
                    },
                )
                .await
                .reconstruct();

            // conversion
            let tags: Vec<Gf32Bit> = rows_and_tags
                .into_iter()
                .map(|x| {
                    // get last 32 bits from rows_and_tags
                    let mut buf = GenericArray::default();
                    x.serialize(&mut buf);
                    <Gf32Bit>::deserialize(GenericArray::from_slice(
                        &buf.as_slice()[S::TAG_OFFSET..],
                    ))
                    .unwrap()
                })
                .collect();

            assert_eq!(tags, expected_tags);
        });
    }

    #[test]
    fn check_tags_for_boolean_arrays() {
        check_tags::<AdditiveShare<BA32>>();
        check_tags::<AdditiveShare<BA112>>();
    }

    #[allow(clippy::ptr_arg)] // to match StreamInterceptor trait
    fn interceptor_h1_to_h2(
        ctx: &MaliciousHelperContext,
        target_shard: Option<ShardIndex>,
        data: &mut Vec<u8>,
    ) {
        // H1 runs an additive attack against H2 by
        // changing x2
        if ctx.gate.as_ref().contains("transfer_x_y")
            && ctx.dest == Role::H2
            && ctx.shard == target_shard
        {
            data[0] ^= 1u8;
        }
    }

    #[allow(clippy::ptr_arg)] // to match StreamInterceptor trait
    fn interceptor_h2_to_h3(
        ctx: &MaliciousHelperContext,
        target_shard: Option<ShardIndex>,
        data: &mut Vec<u8>,
    ) {
        // H2 runs an additive attack against H3 by
        // changing y1
        if ctx.gate.as_ref().contains("transfer_x_y")
            && ctx.dest == Role::H3
            && ctx.shard == target_shard
        {
            data[0] ^= 1u8;
        }
    }

    #[allow(clippy::ptr_arg)] // to match StreamInterceptor trait
    fn interceptor_h3_to_h2(
        ctx: &MaliciousHelperContext,
        target_shard: Option<ShardIndex>,
        data: &mut Vec<u8>,
    ) {
        // H3 runs an additive attack against H2 by
        // changing c_hat_2
        if ctx.gate.as_ref().contains("transfer_c")
            && ctx.dest == Role::H2
            && ctx.shard == target_shard
        {
            data[0] ^= 1u8;
        }
    }

    /// This test checks that the malicious shuffle fails
    /// under a simple bit flip attack by H1.
    ///
    /// `x2` will be inconsistent which is checked by `H2`.
    #[test]
    #[should_panic(expected = "X2 is inconsistent")]
    fn fail_under_bit_flip_attack_on_x2() {
        const RECORD_AMOUNT: usize = 10;

        run(move || async move {
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H1, config.role_assignment(), move |ctx, data| {
                    interceptor_h1_to_h2(ctx, None, data);
                });

            let world = TestWorld::new_with(config);
            let mut rng = world.rng();
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let [_, h2, _] = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    malicious_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;

            let _ = h2.unwrap();
        });
    }

    /// This test checks that the malicious shuffle fails
    /// under a simple bit flip attack by H2.
    ///
    /// `y1` will be inconsistent which is checked by `H1`.
    #[test]
    #[should_panic(expected = "Y1 is inconsistent")]
    fn fail_under_bit_flip_attack_on_y1() {
        const RECORD_AMOUNT: usize = 10;

        run(move || async move {
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H2, config.role_assignment(), move |ctx, data| {
                    interceptor_h2_to_h3(ctx, None, data);
                });

            let world = TestWorld::new_with(config);
            let mut rng = world.rng();
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let [h1, _, _] = world
                .malicious(records.into_iter(), |ctx, shares| async move {
                    malicious_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;
            let _ = h1.unwrap();
        });
    }

    /// This test checks that the malicious shuffle fails
    /// under a simple bit flip attack by H3.
    ///
    /// `c` from `H2` will be inconsistent
    /// which is checked by `H1`.
    #[test]
    #[should_panic(expected = "C from H2 is inconsistent")]
    fn fail_under_bit_flip_attack_on_c() {
        const RECORD_AMOUNT: usize = 10;

        run(move || async move {
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), move |ctx, data| {
                    interceptor_h3_to_h2(ctx, None, data);
                });

            let world = TestWorld::new_with(config);
            let mut rng = world.rng();
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let [h1, h2, _] = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    malicious_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;

            // x2 should be consistent with y2
            let _ = h2.unwrap();

            // but this should fail
            let _ = h1.unwrap();
        });
    }

    #[test]
    fn sharded_correctness_small() {
        const SHARDS: usize = 3;
        const RECORD_AMOUNT: usize = 2; // some shard will have no output
        type Distribution = RandomInputDistribution;
        run(|| async {
            let world = TestWorld::<WithShards<SHARDS, Distribution>>::with_shards(
                TestWorldConfig::default(),
            );
            let mut rng = world.rng();
            let mut records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let sharded_result = world
                .semi_honest(records.clone().into_iter(), |ctx, input| async move {
                    malicious_sharded_shuffle::<_, AdditiveShare<BA32>>(ctx, input)
                        .await
                        .unwrap()
                })
                .await;

            assert_eq!(sharded_result.len(), SHARDS);

            let mut result = sharded_result
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            // unshuffle by sorting
            records.sort_by_key(U128Conversions::as_u128);
            result.sort_by_key(U128Conversions::as_u128);

            assert_eq!(records, result);
        });
    }

    #[test]
    fn sharded_correctness_large() {
        const SHARDS: usize = 3;
        const RECORD_AMOUNT: usize = 100; // all shards will have output w.h.p.
        type Distribution = RandomInputDistribution;
        run(|| async {
            let world = TestWorld::<WithShards<SHARDS, Distribution>>::with_shards(
                TestWorldConfig::default(),
            );
            let mut rng = world.rng();
            let mut records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();

            let sharded_result = world
                .semi_honest(records.clone().into_iter(), |ctx, input| async move {
                    malicious_sharded_shuffle::<_, AdditiveShare<BA32>>(ctx, input)
                        .await
                        .unwrap()
                })
                .await;

            assert_eq!(sharded_result.len(), SHARDS);

            let mut result = sharded_result
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            // unshuffle by sorting
            records.sort_by_key(U128Conversions::as_u128);
            result.sort_by_key(U128Conversions::as_u128);

            assert_eq!(records, result);
        });
    }

    /// This test checks that the sharded malicious shuffle fails
    /// under a simple bit flip attack by H1.
    ///
    /// `x2` will be inconsistent which is checked by `H2`.
    #[test]
    #[should_panic(expected = "X2 is inconsistent")]
    fn sharded_fail_under_bit_flip_attack_on_x2() {
        const SHARDS: usize = 3;
        const RECORD_AMOUNT: usize = 100; // all shards will have output w.h.p.
        type Distribution = RandomInputDistribution;

        run_random(|mut rng| async move {
            let target_shard = ShardIndex::from(rng.gen_range(0..u32::try_from(SHARDS).unwrap()));
            let mut config = TestWorldConfig::default().with_seed(rng.gen());
            config.stream_interceptor =
                MaliciousHelper::new(Role::H1, config.role_assignment(), move |ctx, data| {
                    interceptor_h1_to_h2(ctx, Some(target_shard), data);
                });

            let world = TestWorld::<WithShards<SHARDS, Distribution>>::with_shards(config);
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let sharded_results = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    malicious_sharded_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;

            assert_eq!(sharded_results.len(), SHARDS);
            sharded_results[target_shard][Role::H2].as_ref().unwrap();
        });
    }

    /// This test checks that the sharded malicious shuffle fails
    /// under a simple bit flip attack by H2.
    ///
    /// `y1` will be inconsistent which is checked by `H1`.
    #[test]
    #[should_panic(expected = "Y1 is inconsistent")]
    fn sharded_fail_under_bit_flip_attack_on_y1() {
        const SHARDS: usize = 3;
        const RECORD_AMOUNT: usize = 100; // all shards will have output w.h.p.
        type Distribution = RandomInputDistribution;

        run_random(|mut rng| async move {
            let target_shard = ShardIndex::from(rng.gen_range(0..u32::try_from(SHARDS).unwrap()));
            let mut config = TestWorldConfig::default().with_seed(rng.gen());
            config.stream_interceptor =
                MaliciousHelper::new(Role::H2, config.role_assignment(), move |ctx, data| {
                    interceptor_h2_to_h3(ctx, Some(target_shard), data);
                });

            let world = TestWorld::<WithShards<SHARDS, Distribution>>::with_shards(config);
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let sharded_results = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    malicious_sharded_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;

            assert_eq!(sharded_results.len(), SHARDS);
            sharded_results[target_shard][Role::H1].as_ref().unwrap();
        });
    }

    /// This test checks that the malicious sharded shuffle fails
    /// under a simple bit flip attack by H3.
    ///
    /// `c` from `H2` will be inconsistent
    /// which is checked by `H1`.
    #[test]
    #[should_panic(expected = "C from H2 is inconsistent")]
    fn sharded_fail_under_bit_flip_attack_on_c() {
        const SHARDS: usize = 3;
        const RECORD_AMOUNT: usize = 100; // all shards will have output w.h.p.
        type Distribution = RandomInputDistribution;

        run_random(|mut rng| async move {
            let target_shard = ShardIndex::from(rng.gen_range(0..u32::try_from(SHARDS).unwrap()));
            let mut config = TestWorldConfig::default().with_seed(rng.gen());
            config.stream_interceptor =
                MaliciousHelper::new(Role::H3, config.role_assignment(), move |ctx, data| {
                    interceptor_h3_to_h2(ctx, Some(target_shard), data);
                });

            let world = TestWorld::<WithShards<SHARDS, Distribution>>::with_shards(config);
            let records = (0..RECORD_AMOUNT).map(|_| rng.gen()).collect::<Vec<BA32>>();
            let sharded_results = world
                .semi_honest(records.into_iter(), |ctx, shares| async move {
                    malicious_sharded_shuffle::<_, AdditiveShare<BA32>>(ctx, shares).await
                })
                .await;

            assert_eq!(sharded_results.len(), SHARDS);
            sharded_results[target_shard][Role::H1].as_ref().unwrap();
        });
    }
}
