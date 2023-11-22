use std::cmp::min;

use embed_doc_image::embed_doc_image;
use futures::stream::{iter as stream_iter, Stream, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        context::{
            Context, UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext,
            Validator,
        },
        modulus_conversion::{convert_bits, BitConversionTriple, ToBitConversionTriples},
        sort::{
            compose::compose,
            generate_permutation::{shuffle_and_reveal_permutation, ShuffledPermutationWrapper},
            multi_bit_permutation::multi_bit_permutation,
            secureapplyinv::secureapplyinv_multi,
            SortStep,
        },
        step::IpaProtocolStep::Sort,
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        Linear as LinearSecretSharing,
    },
};

#[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
#[embed_doc_image("malicious_sort", "images/sort/malicious-sort.png")]
/// This is an implementation of `OptGenPerm` (Algorithm 12) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol generates optimized permutation of a stable sort for the given shares of inputs.
///
/// Steps
/// For the `num_multi_bits`
/// 1. Get replicated shares in Field using modulus conversion
/// 2. Compute bit permutation that sorts 0..`num_multi_bits`
/// For `num_multi_bits` to N-1th bit of input share
/// 1. Shuffle and reveal the i-1th composition
/// 2. Get replicated shares in Field using modulus conversion
/// 3. Sort i..i+`num_multi_bits` bits based on i-1th bits by applying i-1th composition on all these bits
/// 4  Compute bit permutation that sorts i..i+`num_multi_bits`
/// 5. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, n-1th composition is returned. This is the permutation which sorts the inputs
///
/// ![Semi-honest sort permutation steps][semi_honest_sort]
///
/// If the malicious sort is enabled, this returns a sort permutation in a malicious context.
///
/// This runs sort in a malicious context. The caller is responsible to validate the accumulator contents
/// and downgrade context to Semi-honest before calling this function
/// The function takes care of upgrading and validating while the sort protocol runs.
/// It then returns a semi honest context with output in Replicated format.
/// The caller should then upgrade the output and context before moving forward
///
/// Steps
/// 1. [Malicious Special] Upgrade the context from semihonest to malicious and get a validator
/// 2. [Malicious Special] Upgrade 0..`num_multi_bits` sort bit keys
/// 3. Compute bit permutation that sorts 0..`num_multi_bits` bit
///
/// For `num_multi_bits` to N-1th bit of input share
/// 1. i. Shuffle the i-1th composition
///   ii. [Malicious Special] Validate the accumulator contents
///  iii. [Malicious Special] Malicious reveal
///   iv. [Malicious Special] Downgrade context to semihonest
/// 2. i. [Malicious Special] Upgrade ith sort bit keys
///   ii. Sort i..i+`num_multi_bits` bits based on i-1th bits by applying i-1th composition on i..i+`num_multi_bits` bits
/// 3. Compute bit permutation that sorts i..i+`num_multi_bits` bits
/// 4. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, following is returned
///    i. n-1th composition: This is the permutation which sorts the inputs
///   ii. Validator which can be used to validate the leftover items in the accumulator
///
/// ![Malicious sort permutation steps][malicious_sort]
///
/// # Panics
/// If sort keys dont have num of bits same as `num_bits`
/// # Errors
pub async fn generate_permutation_opt<'a, F, C, S, I>(
    sh_ctx: C,
    sort_keys: I,
    num_multi_bits: u32,
    max_bits: u32, // TODO: use a const generic on I::Item; see comment on ToBitConversionTriples::bits.
) -> Result<(C::Validator<F>, Vec<S>), Error>
where
    F: PrimeField + ExtendableField,
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F> + 'static,
    I: Stream,
    I::Item: ToBitConversionTriples<Residual = ()> + Clone + Send + Sync,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    for<'u> UpgradeContext<'u, C::UpgradedContext<F>, F, RecordId>:
        UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<S>>,
{
    let mut malicious_validator = sh_ctx.clone().validator();
    let sort_keys = sort_keys.collect::<Vec<_>>().await;
    if sort_keys.is_empty() {
        return Ok((malicious_validator, Vec::new()));
    }

    let mut m_ctx = malicious_validator.context();
    let chunk = 0..min(num_multi_bits, max_bits);
    let key_chunk = convert_bits(
        m_ctx
            .narrow(&SortStep::ModulusConversion)
            .set_total_records(sort_keys.len()),
        stream_iter(sort_keys.iter().cloned()),
        chunk,
    )
    .try_collect::<Vec<_>>()
    .await?;

    let lsb_permutation =
        multi_bit_permutation(m_ctx.narrow(&SortStep::BitPermutation), &key_chunk).await?;
    let mut composed_less_significant_bits_permutation = lsb_permutation;

    for (chunk_num, chunk_start) in (num_multi_bits..max_bits)
        .step_by(usize::try_from(num_multi_bits).unwrap())
        .enumerate()
    {
        let revealed_and_random_permutations = shuffle_and_reveal_permutation::<C, _, _>(
            m_ctx.narrow(&SortStep::ShuffleRevealPermutation),
            composed_less_significant_bits_permutation,
            malicious_validator,
        )
        .await?;

        malicious_validator = sh_ctx.narrow(&Sort(chunk_num)).validator();
        m_ctx = malicious_validator.context();

        // TODO (richaj) it might even be more efficient to apply sort permutation to XorReplicated sharings,
        // and convert them to a Vec<MaliciousReplicated> after this step, as the re-shares will be cheaper for XorReplicated sharings

        let chunk = chunk_start..min(chunk_start + num_multi_bits, max_bits);
        let key_chunk = convert_bits(
            m_ctx
                .narrow(&SortStep::ModulusConversion)
                .set_total_records(sort_keys.len()),
            stream_iter(sort_keys.iter().cloned()),
            chunk,
        )
        .try_collect::<Vec<_>>()
        .await?;

        let (randoms_for_shuffle0, randoms_for_shuffle1, revealed) = (
            revealed_and_random_permutations
                .randoms_for_shuffle
                .0
                .as_slice(),
            revealed_and_random_permutations
                .randoms_for_shuffle
                .1
                .as_slice(),
            revealed_and_random_permutations.revealed.as_slice(),
        );

        let next_few_bits_sorted_by_less_significant_bits = secureapplyinv_multi(
            m_ctx.narrow(&SortStep::MultiApplyInv(chunk_num.try_into().unwrap())),
            key_chunk,
            (randoms_for_shuffle0, randoms_for_shuffle1),
            revealed,
        )
        .await?;

        let next_few_bits_permutation = multi_bit_permutation(
            m_ctx.narrow(&SortStep::BitPermutation),
            &next_few_bits_sorted_by_less_significant_bits,
        )
        .await?;

        composed_less_significant_bits_permutation = compose(
            m_ctx.narrow(&SortStep::Compose),
            (randoms_for_shuffle0, randoms_for_shuffle1),
            revealed,
            next_few_bits_permutation,
        )
        .await?;
    }
    Ok((
        malicious_validator,
        composed_less_significant_bits_permutation,
    ))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::zip;

    use futures::stream::iter as stream_iter;

    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, GaloisField},
        protocol::{
            context::{Context, Validator},
            sort::generate_permutation_opt::generate_permutation_opt,
            MatchKey,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{join3, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MatchKey>());

        let mut expected = match_keys.iter().map(Field::as_u128).collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(
                match_keys.clone().into_iter(),
                |ctx, mk_shares| async move {
                    let (_validator, result) = generate_permutation_opt::<Fp32BitPrime, _, _, _>(
                        ctx.narrow("sort"),
                        stream_iter(mk_shares),
                        NUM_MULTI_BITS,
                        MatchKey::BITS,
                    )
                    .await
                    .unwrap();
                    result
                },
            )
            .await;

        let mut mpc_sorted_list = (0..u128::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }

    async fn sortn(count: usize) {
        const NUM_MULTI_BITS: u32 = 3;
        let world = TestWorld::default();
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(count);
        match_keys.resize_with(count, || rng.gen::<MatchKey>());

        let mut expected = match_keys.iter().map(Field::as_u128).collect::<Vec<_>>();
        if count > 1 {
            // Explicitly don't sort if sorting isn't needed (for noop test).
            expected.sort_unstable();
        }

        let [(v0, result0), (v1, result1), (v2, result2)] = world
            .malicious(
                match_keys.clone().into_iter(),
                |ctx, mk_shares| async move {
                    generate_permutation_opt::<Fp31, _, _, _>(
                        ctx.narrow("sort"),
                        stream_iter(mk_shares),
                        NUM_MULTI_BITS,
                        MatchKey::BITS,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let result = join3(
            v0.validate(result0),
            v1.validate(result1),
            v2.validate(result2),
        )
        .await;
        let mut mpc_sorted_list = (0..u128::try_from(count).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }

    #[tokio::test]
    pub async fn malicious() {
        sortn(10).await;
    }

    /// Passing 32 records for Fp31 doesn't work.
    #[tokio::test]
    #[should_panic = "prime field ipa::ff::prime_field::fp31::Fp31 is too small to sort 32 records"]
    async fn fp31_overflow() {
        const COUNT: usize = 32;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MatchKey>());

        _ = world
            .malicious(
                match_keys.clone().into_iter(),
                |ctx, mk_shares| async move {
                    generate_permutation_opt::<Fp31, _, _, _>(
                        ctx.narrow("sort"),
                        stream_iter(mk_shares),
                        NUM_MULTI_BITS,
                        MatchKey::BITS,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
    }

    /// These are totally silly, but the code handles them elegantly, if necessary.
    #[tokio::test]
    pub async fn noop_sorts() {
        sortn(1).await;
        sortn(0).await;
    }
}
