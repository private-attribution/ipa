use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, SemiHonestContext},
        malicious::MaliciousValidator,
        sort::{
            compose::compose,
            generate_permutation::{
                malicious_shuffle_and_reveal_permutation, shuffle_and_reveal_permutation,
            },
            multi_bit_permutation::multi_bit_permutation,
            secureapplyinv::secureapplyinv_multi,
            SortStep::{BitPermutationStep, ComposeStep, MultiApplyInv, ShuffleRevealPermutation},
        },
        IpaProtocolStep::Sort,
    },
    secret_sharing::replicated::{
        malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
    },
};
use embed_doc_image::embed_doc_image;

#[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
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
/// # Errors
/// If any underlying protocol fails
/// # Panics
/// Panics if input doesn't have same number of bits as `num_bits`
pub async fn generate_permutation_opt<F>(
    ctx: SemiHonestContext<'_>,
    mut sort_keys: impl Iterator<Item = &Vec<Vec<Replicated<F>>>>,
    //TODO (richaj) implement MultiBitChunk which is discussed in PR #425
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let ctx_0 = ctx.clone();
    let first_keys = sort_keys.next().unwrap();

    let lsb_permutation =
        multi_bit_permutation(ctx_0.narrow(&BitPermutationStep), first_keys.as_slice()).await?;

    let mut composed_less_significant_bits_permutation = lsb_permutation;
    for (bit_num, one_slice) in sort_keys.enumerate() {
        let ctx_bit = ctx.narrow(&Sort(bit_num));
        let revealed_and_random_permutations = shuffle_and_reveal_permutation(
            ctx_bit.narrow(&ShuffleRevealPermutation),
            composed_less_significant_bits_permutation,
        )
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
            ctx_bit.narrow(&MultiApplyInv(bit_num.try_into().unwrap())),
            one_slice.clone(),
            (randoms_for_shuffle0, randoms_for_shuffle1),
            revealed,
        )
        .await?;

        let next_few_bits_permutation = multi_bit_permutation(
            ctx_bit.narrow(&BitPermutationStep),
            &next_few_bits_sorted_by_less_significant_bits,
        )
        .await?;

        composed_less_significant_bits_permutation = compose(
            ctx_bit.narrow(&ComposeStep),
            (
                revealed_and_random_permutations
                    .randoms_for_shuffle
                    .0
                    .as_slice(),
                revealed_and_random_permutations
                    .randoms_for_shuffle
                    .1
                    .as_slice(),
            ),
            &revealed_and_random_permutations.revealed,
            next_few_bits_permutation,
        )
        .await?;
    }
    Ok(composed_less_significant_bits_permutation)
}

#[embed_doc_image("malicious_sort", "images/sort/malicious-sort.png")]
/// Returns a sort permutation in a malicious context.
/// This runs sort in a malicious context. The caller is responsible to validate the accumulator contents and downgrade context to Semi-honest before calling this function
/// The function takes care of upgrading and validating while the sort protocol runs.
/// It then returns a semi honest context with output in Replicated format. The caller should then upgrade the output and context before moving forward
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
/// # Panics
/// If sort keys dont have num of bits same as `num_bits`
/// # Errors
pub async fn malicious_generate_permutation_opt<'a, F, I>(
    sh_ctx: SemiHonestContext<'_>,
    sort_keys: I,
) -> Result<(MaliciousValidator<'_, F>, Vec<MaliciousReplicated<F>>), Error>
where
    F: Field,
    I: IntoIterator<Item = &'a Vec<Vec<Replicated<F>>>>,
{
    let mut malicious_validator = MaliciousValidator::new(sh_ctx.clone());
    let mut m_ctx_bit = malicious_validator.context();
    let mut sort_keys = sort_keys.into_iter();

    let first_keys = sort_keys.next().unwrap();

    let upgraded_sort_keys = m_ctx_bit.upgrade(first_keys.clone()).await?;
    let lsb_permutation =
        multi_bit_permutation(m_ctx_bit.narrow(&BitPermutationStep), &upgraded_sort_keys).await?;
    let mut composed_less_significant_bits_permutation = lsb_permutation;

    for (chunk_num, chunk) in sort_keys.enumerate() {
        let revealed_and_random_permutations = malicious_shuffle_and_reveal_permutation(
            m_ctx_bit.narrow(&ShuffleRevealPermutation),
            composed_less_significant_bits_permutation,
            malicious_validator,
        )
        .await?;

        malicious_validator = MaliciousValidator::new(sh_ctx.narrow(&Sort(chunk_num)));
        m_ctx_bit = malicious_validator.context();

        // TODO (richaj) it might even be more efficient to apply sort permutation to XorReplicated sharings,
        // and convert them to a Vec<MaliciousReplicated> after this step, as the re-shares will be cheaper for XorReplicated sharings
        let upgraded_sort_keys = m_ctx_bit.upgrade(chunk.clone()).await?;

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
            m_ctx_bit.narrow(&MultiApplyInv(chunk_num.try_into().unwrap())),
            upgraded_sort_keys,
            (randoms_for_shuffle0, randoms_for_shuffle1),
            revealed,
        )
        .await?;

        let next_few_bits_permutation = multi_bit_permutation(
            m_ctx_bit.narrow(&BitPermutationStep),
            &next_few_bits_sorted_by_less_significant_bits,
        )
        .await?;

        composed_less_significant_bits_permutation = compose(
            m_ctx_bit.narrow(&ComposeStep),
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::{Field, Fp31, GaloisField, Gf40Bit},
        protocol::{
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            sort::generate_permutation_opt::{
                generate_permutation_opt, malicious_generate_permutation_opt,
            },
            MatchKey,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{join3, Reconstruct, Runner, TestWorld},
    };
    use std::iter::zip;

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
            .semi_honest(match_keys.clone(), |ctx, mk_shares| async move {
                let local_lists =
                    convert_all_bits_local::<Fp31, _>(ctx.role(), mk_shares.into_iter());
                let converted_shares =
                    convert_all_bits(&ctx, &local_lists, Gf40Bit::BITS, NUM_MULTI_BITS)
                        .await
                        .unwrap();

                generate_permutation_opt(ctx.narrow("sort"), converted_shares.iter())
                    .await
                    .unwrap()
            })
            .await;

        let mut mpc_sorted_list = (0..u128::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }

    #[tokio::test]
    pub async fn malicious_sort_in_semi_honest() {
        const COUNT: usize = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::default();
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MatchKey>());

        let mut expected = match_keys.iter().map(Field::as_u128).collect::<Vec<_>>();
        expected.sort_unstable();

        let [(v0, result0), (v1, result1), (v2, result2)] = world
            .semi_honest(match_keys.clone(), |ctx, mk_shares| async move {
                let local_lists = convert_all_bits_local(ctx.role(), mk_shares.into_iter());
                let converted_shares =
                    convert_all_bits(&ctx, &local_lists, Gf40Bit::BITS, NUM_MULTI_BITS)
                        .await
                        .unwrap();

                malicious_generate_permutation_opt::<Fp31, _>(
                    ctx.narrow("sort"),
                    converted_shares.iter(),
                )
                .await
                .unwrap()
            })
            .await;

        let result = join3(
            v0.validate(result0),
            v1.validate(result1),
            v2.validate(result2),
        )
        .await;
        let mut mpc_sorted_list = (0..u128::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }
}
