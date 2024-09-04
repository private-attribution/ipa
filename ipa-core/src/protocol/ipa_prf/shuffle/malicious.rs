use std::{borrow::Borrow, iter};

use futures_util::future::{try_join, try_join3};

use crate::{
    error::Error,
    ff::{boolean_array::BooleanArray, Field, Gf32Bit},
    helpers::{
        hashing::{compute_hash, Hash},
        Direction, Role, TotalRecords,
    },
    protocol::{
        basics::malicious_reveal,
        context::Context,
        ipa_prf::shuffle::{base::IntermediateShuffleMessages, step::OPRFShuffleStep},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        SharedValue, StdArray,
    },
};

/// This function verifies the `shuffled_shares` and the `IntermediateShuffleMessages`.
///
/// ## Errors
/// Propagates network errors.
/// Further, returns an error when messages are inconsistent with the MAC tags.
async fn verify_shuffle<C: Context, S: BooleanArray>(
    ctx: C,
    key_shares: &[AdditiveShare<Gf32Bit>],
    shuffled_shares: &[AdditiveShare<S>],
    messages: IntermediateShuffleMessages<S>,
) -> Result<(), Error> {
    // reveal keys
    let k_ctx = ctx
        .narrow(&OPRFShuffleStep::RevealMACKey)
        .set_total_records(TotalRecords::specified(key_shares.len())?);
    let keys = reveal_keys(&k_ctx, key_shares).await?;

    // verify messages and shares
    match ctx.role() {
        Role::H1 => h1_verify(ctx, &keys, shuffled_shares, messages.get_x1_or_y1()).await,
        Role::H2 => h2_verify(ctx, &keys, shuffled_shares, messages.get_x2_or_y2()).await,
        Role::H3 => {
            h3_verify(
                ctx,
                &keys,
                shuffled_shares,
                messages.get_x1_or_y1(),
                messages.get_x2_or_y2(),
            )
            .await
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
async fn h1_verify<C: Context, S: BooleanArray>(
    ctx: C,
    keys: &[StdArray<Gf32Bit, 1>],
    share_a_and_b: &[AdditiveShare<S>],
    x1: &[S],
) -> Result<(), Error> {
    // compute hashes
    // compute hash for x1
    let hash_x1 = compute_row_hash::<S, _, _>(keys, x1);
    // compute hash for A xor B
    let hash_a_xor_b = compute_row_hash::<S, _, _>(
        keys,
        share_a_and_b
            .iter()
            .map(|share| share.left() + share.right()),
    );

    // setup channels
    let h3_ctx = ctx
        .narrow(&OPRFShuffleStep::HashesH3toH1)
        .set_total_records(TotalRecords::specified(2)?);
    let h2_ctx = ctx
        .narrow(&OPRFShuffleStep::HashH2toH1)
        .set_total_records(TotalRecords::specified(1)?);
    let channel_h3 = &h3_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Left));
    let channel_h2 = &h2_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Right));

    // receive hashes
    let (hashes_h3, hash_h2) = try_join(
        h3_ctx.parallel_join(
            (0usize..=1).map(|i| async move { channel_h3.receive(RecordId::from(i)).await }),
        ),
        channel_h2.receive(RecordId::FIRST),
    )
    .await?;

    // check y1
    if hash_x1 != hashes_h3[0] {
        return Err(Error::ShuffleValidationFailed(format!(
            "Y1 is inconsistent: hash of x1: {hash_x1:?}, hash of y1: {:?}",
            hashes_h3[0]
        )));
    }

    // check c from h3
    if hash_a_xor_b != hashes_h3[1] {
        return Err(Error::ShuffleValidationFailed(format!(
            "C from H3 is inconsistent: hash of a_xor_b: {hash_a_xor_b:?}, hash of C: {:?}",
            hashes_h3[1]
        )));
    }

    // check h2
    if hash_a_xor_b != hash_h2 {
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
async fn h2_verify<C: Context, S: BooleanArray>(
    ctx: C,
    keys: &[StdArray<Gf32Bit, 1>],
    share_b_and_c: &[AdditiveShare<S>],
    x2: &[S],
) -> Result<(), Error> {
    // compute hashes
    // compute hash for x2
    let hash_x2 = compute_row_hash::<S, _, _>(keys, x2);
    // compute hash for C
    let hash_c = compute_row_hash::<S, _, _>(
        keys,
        share_b_and_c.iter().map(ReplicatedSecretSharing::right),
    );

    // setup channels
    let h1_ctx = ctx
        .narrow(&OPRFShuffleStep::HashH2toH1)
        .set_total_records(TotalRecords::specified(1)?);
    let h3_ctx = ctx
        .narrow(&OPRFShuffleStep::HashH3toH2)
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
    if hash_x2 != hash_h3 {
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
async fn h3_verify<C: Context, S: BooleanArray>(
    ctx: C,
    keys: &[StdArray<Gf32Bit, 1>],
    share_c_and_a: &[AdditiveShare<S>],
    y1: &[S],
    y2: &[S],
) -> Result<(), Error> {
    // compute hashes
    // compute hash for y1
    let hash_y1 = compute_row_hash::<S, _, _>(keys, y1);
    // compute hash for y2
    let hash_y2 = compute_row_hash::<S, _, _>(keys, y2);
    // compute hash for C
    let hash_c = compute_row_hash::<S, _, _>(
        keys,
        share_c_and_a.iter().map(ReplicatedSecretSharing::left),
    );

    // setup channels
    let h1_ctx = ctx
        .narrow(&OPRFShuffleStep::HashesH3toH1)
        .set_total_records(TotalRecords::specified(2)?);
    let h2_ctx = ctx
        .narrow(&OPRFShuffleStep::HashH3toH2)
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
fn compute_row_hash<S, B, I>(keys: &[StdArray<Gf32Bit, 1>], row_iterator: I) -> Hash
where
    S: BooleanArray,
    B: Borrow<S>,
    I: IntoIterator<Item = B>,
{
    let iterator = row_iterator
        .into_iter()
        .map(|s| (*(s.borrow())).try_into().unwrap());
    compute_hash(iterator.map(|row| {
        row.iter()
            .zip(keys)
            .fold(Gf32Bit::ZERO, |acc, (row_entry, key)| {
                acc + *row_entry * *key.first()
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
) -> Result<Vec<StdArray<Gf32Bit, 1>>, Error> {
    // reveal MAC keys
    let mut keys = ctx
        .parallel_join(key_shares.iter().enumerate().map(|(i, key)| async move {
            malicious_reveal(ctx.clone(), RecordId::from(i), None, key).await
        }))
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    // add a one, since last row element is tag which is not multiplied with a key
    keys.push(iter::once(Gf32Bit::ONE).collect());
    Ok(keys)
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::{
        ff::{boolean_array::BA64, Serializable},
        protocol::ipa_prf::shuffle::base::shuffle,
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    /// This test checks the correctness of the malicious shuffle
    /// when all parties behave honestly
    /// and all the MAC keys are `Gf32Bit::ONE`.
    /// Further, each row consists of a `BA32` and a `BA32` tag.
    #[test]
    fn check_shuffle_with_simple_mac() {
        const RECORD_AMOUNT: usize = 10;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = thread_rng();
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
                    let key_shares = vec![AdditiveShare::new(Gf32Bit::ONE, Gf32Bit::ONE); 1];
                    // run shuffle
                    let (shares, messages) = shuffle(ctx.narrow("shuffle"), rows).await.unwrap();
                    // verify it
                    verify_shuffle(ctx.narrow("verify"), &key_shares, &shares, messages)
                        .await
                        .unwrap();
                })
                .await;
        });
    }
}
