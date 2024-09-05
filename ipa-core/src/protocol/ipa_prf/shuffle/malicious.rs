use std::ops::Add;

use proptest::num::usize;
use rand::distributions::{Distribution, Standard};

use crate::{
    error::Error,
    ff::{boolean_array::BooleanArray, Gf32Bit},
    protocol::{
        context::Context,
        ipa_prf::shuffle::{base::shuffle, step::OPRFShuffleStep},
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
};

/// This function executes the maliciously secure shuffle protocol on the input: `shares`.
///
/// ## Errors
/// Propagates network, multiplication and conversion errors from sub functions.
pub async fn malicious_shuffle<C, I, S>(ctx: C, shares: I) -> Result<Vec<AdditiveShare<S>>, Error>
where
    C: Context,
    I: IntoIterator<Item = AdditiveShare<S>>,
    I::IntoIter: ExactSizeIterator,
    S: BooleanArray,
    for<'a> &'a S: Add<S, Output = S>,
    for<'a> &'a S: Add<&'a S, Output = S>,
    Standard: Distribution<S>,
{
    // compute amount of MAC keys
    let amount_of_keys: usize = usize::try_from(S::BITS).unwrap() + 31 / 32;
    // generate MAC keys
    let keys = (0..amount_of_keys)
        .map(|i| ctx.prss().generate_fields(RecordId::from(i)))
        .map(|(left, right)| AdditiveShare::new(left, right))
        .collect::<Vec<AdditiveShare<Gf32Bit>>>();

    // call
    // async fn compute_tags<C: Context, S: BooleanArray>(
    //     ctx: C,
    //     keys: &[AdditiveShare<Gf32Bit>],
    //     rows: &[AdditiveShare<S>],
    // ) -> Result<Vec<AdditiveShare<Gf32Bit>>, Error>
    //
    // i.e. let shares_and_tags = compute_tags(ctx.narrow(&OPRFShuffleStep::GenerateTags, keys, shares).await?
    // placeholder
    let shares_and_tags =
        vec![vec![AdditiveShare::<Gf32Bit>::ZERO; amount_of_keys + 1]; shares.into_iter().len()];

    // call
    // pub async fn shuffle<C, I, S>(
    //     ctx: C,
    //     shares: I,
    // ) -> Result<(Vec<AdditiveShare<S>>, IntermediateShuffleMessages<S>), Error>
    //
    // i.e. let (output_shares, messages) = shuffle(ctx.narrow(&OPRFShuffleStep::ShuffleProtocol, shares_and_tags).await?
    // placeholder
    let output_shares = shuffle(
        ctx.narrow(&OPRFShuffleStep::ShuffleProtocol),
        shares_and_tags,
    )
    .await?;

    // call
    // async fn verify_shuffle<C: Context, S: BooleanArray>(
    //     ctx: C,
    //     key_shares: &[AdditiveShare<Gf32Bit>],
    //     shuffled_shares: &[AdditiveShare<S>],
    //     messages: IntermediateShuffleMessages<S>,
    // ) -> Result<(), Error>
    //
    // i.e. verify_shuffle(ctx.narrow(&OPRFShuffleStep::VerifyShuffle), keys, output_shares, messages).await?

    // truncate tags from output_shares
    // create function to do this

    // placeholder
    Ok(vec![AdditiveShare::ZERO; 1])
}
