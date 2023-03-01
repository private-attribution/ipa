use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{Reshare, Reveal},
        context::{Context, MaliciousContext, NoRecord},
        malicious::MaliciousValidator,
        sort::{
            bit_permutation::bit_permutation,
            ShuffleRevealStep::{RevealPermutation, ShufflePermutation},
            SortStep::{
                ApplyInv, BitPermutationStep, ComposeStep, ShuffleRevealPermutation, SortKeys,
            },
        },
        IpaProtocolStep::Sort,
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated,
        },
        SecretSharing,
    },
};

use super::{
    compose::compose,
    generate_permutation_opt::{generate_permutation_opt, malicious_generate_permutation_opt},
    secureapplyinv::secureapplyinv,
    shuffle::{get_two_of_three_random_permutations, shuffle_shares},
};
use crate::protocol::{context::SemiHonestContext, sort::ShuffleRevealStep::GeneratePermutation};
use embed_doc_image::embed_doc_image;

#[derive(Debug)]
/// This object contains the output of `shuffle_and_reveal_permutation`
/// i) `revealed` permutation after shuffling
/// ii) Random permutations: each helper knows 2/3 of random permutations. This is then used for shuffle protocol.
pub struct RevealedAndRandomPermutations {
    pub revealed: Vec<u32>,
    pub randoms_for_shuffle: (Vec<u32>, Vec<u32>),
}

pub struct ShuffledPermutationWrapper<T, C: Context> {
    pub perm: Vec<T>,
    pub ctx: C,
}

/// This is an implementation of `OptApplyInv` (Algorithm 13) and `OptCompose` (Algorithm 14) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
pub(super) async fn shuffle_and_reveal_permutation<
    F: Field,
    S: SecretSharing<F> + Reshare<C, RecordId> + Reveal<C, RecordId, Output = F>,
    C: Context,
>(
    ctx: C,
    input_permutation: Vec<S>,
) -> Result<RevealedAndRandomPermutations, Error> {
    let random_permutations_for_shuffle = get_two_of_three_random_permutations(
        u32::try_from(input_permutation.len()).expect("Input size fits into u32"),
        ctx.narrow(&GeneratePermutation).prss_rng(),
    );

    let shuffled_permutation = shuffle_shares(
        input_permutation,
        (
            random_permutations_for_shuffle.0.as_slice(),
            random_permutations_for_shuffle.1.as_slice(),
        ),
        ctx.narrow(&ShufflePermutation),
    )
    .await?;

    let reveal_ctx = ctx.narrow(&RevealPermutation);
    let wrapper = ShuffledPermutationWrapper {
        perm: shuffled_permutation,
        ctx,
    };
    let revealed_permutation = wrapper.reveal(reveal_ctx, NoRecord).await?;

    Ok(RevealedAndRandomPermutations {
        revealed: revealed_permutation,
        randoms_for_shuffle: random_permutations_for_shuffle,
    })
}

/// This is a malicious implementation of shuffle and reveal.
///
/// Steps
/// 1. Get random permutation 2/3 shared across helpers
/// 2. Shuffle shares three times
/// 3. Validate the accumulated macs - this returns the revealed permutation
pub(super) async fn malicious_shuffle_and_reveal_permutation<F: Field>(
    m_ctx: MaliciousContext<'_, F>,
    input_permutation: Vec<MaliciousReplicated<F>>,
    malicious_validator: MaliciousValidator<'_, F>,
) -> Result<RevealedAndRandomPermutations, Error> {
    let random_permutations_for_shuffle = get_two_of_three_random_permutations(
        input_permutation.len().try_into().unwrap(),
        m_ctx.narrow(&GeneratePermutation).prss_rng(),
    );

    let shuffled_permutation = shuffle_shares(
        input_permutation,
        (
            random_permutations_for_shuffle.0.as_slice(),
            random_permutations_for_shuffle.1.as_slice(),
        ),
        m_ctx.narrow(&ShufflePermutation),
    )
    .await?;

    let revealed_permutation = malicious_validator
        .validate(ShuffledPermutationWrapper {
            perm: shuffled_permutation,
            ctx: m_ctx,
        })
        .await?;

    Ok(RevealedAndRandomPermutations {
        revealed: revealed_permutation,
        randoms_for_shuffle: random_permutations_for_shuffle,
    })
}

#[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
/// This is an implementation of `GenPerm` (Algorithm 6) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
/// This protocol generates permutation of a stable sort for the given shares of inputs.
///
/// Steps
/// For the 0th bit
/// 1. Get replicated shares in Field using modulus conversion
/// 2. Compute bit permutation that sorts 0th bit
/// For 1st to N-1th bit of input share
/// 1. Shuffle and reveal the i-1th composition
/// 2. Get replicated shares in Field using modulus conversion
/// 3. Sort ith bit based on i-1th bits by applying i-1th composition on ith bit
/// 4  Compute bit permutation that sorts ith bit
/// 5. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, n-1th composition is returned. This is the permutation which sorts the inputs
///
/// ![Generate sort permutation steps][semi_honest_sort]
pub async fn generate_permutation<F>(
    ctx: SemiHonestContext<'_>,
    sort_keys: &[Vec<Replicated<F>>],
    num_bits: u32,
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let ctx_0 = ctx.narrow(&Sort(0));
    assert_eq!(sort_keys.len(), num_bits as usize);

    let bit_0_permutation =
        bit_permutation(ctx_0.narrow(&BitPermutationStep), &sort_keys[0]).await?;

    let mut composed_less_significant_bits_permutation = bit_0_permutation;
    for bit_num in 1..num_bits {
        let ctx_bit = ctx.narrow(&Sort(bit_num.try_into().unwrap()));

        let revealed_and_random_permutations = shuffle_and_reveal_permutation(
            ctx_bit.narrow(&ShuffleRevealPermutation),
            composed_less_significant_bits_permutation,
        )
        .await?;

        let bit_i_sorted_by_less_significant_bits = secureapplyinv(
            ctx_bit.narrow(&ApplyInv),
            sort_keys[bit_num as usize].clone(),
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
        )
        .await?;

        let bit_i_permutation = bit_permutation(
            ctx_bit.narrow(&BitPermutationStep),
            &bit_i_sorted_by_less_significant_bits,
        )
        .await?;

        let composed_i_permutation = compose(
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
            bit_i_permutation,
        )
        .await?;
        composed_less_significant_bits_permutation = composed_i_permutation;
    }
    Ok(composed_less_significant_bits_permutation)
}

/// This function takes in a semihonest context and sort keys, generates a sort permutation, shuffles and reveals it and
/// returns both shuffle-revealed permutation and 2/3 randoms which were used to shuffle the permutation
/// The output of this can be applied to any of semihonest/malicious context
/// # Panics
/// If unable to convert sort keys length to u32
/// # Errors
/// If unable to convert sort keys length to u32
pub async fn generate_permutation_and_reveal_shuffled<F: Field>(
    ctx: SemiHonestContext<'_>,
    sort_keys: impl Iterator<Item = &Vec<Vec<Replicated<F>>>>,
) -> Result<RevealedAndRandomPermutations, Error> {
    let sort_permutation = generate_permutation_opt(ctx.narrow(&SortKeys), sort_keys).await?;
    shuffle_and_reveal_permutation(ctx.narrow(&ShuffleRevealPermutation), sort_permutation).await
}

/// This function takes in a semihonest context and sort keys, generates a sort permutation, shuffles and reveals it and
/// returns both shuffle-revealed permutation and 2/3 randoms which were used to shuffle the permutation
/// The output of this can be applied to any of semihonest/malicious context
/// # Panics
/// If unable to convert sort keys length to u32
/// # Errors
/// If unable to convert sort keys length to u32
pub async fn malicious_generate_permutation_and_reveal_shuffled<F: Field>(
    sh_ctx: SemiHonestContext<'_>,
    sort_keys: impl Iterator<Item = &Vec<Vec<Replicated<F>>>>,
) -> Result<RevealedAndRandomPermutations, Error> {
    let (malicious_validator, sort_permutation) =
        malicious_generate_permutation_opt(sh_ctx.narrow(&SortKeys), sort_keys).await?;

    let m_ctx = malicious_validator.context();

    malicious_shuffle_and_reveal_permutation(
        m_ctx.narrow(&ShuffleRevealPermutation),
        sort_permutation,
        malicious_validator,
    )
    .await
}

#[allow(dead_code)]
#[embed_doc_image("malicious_sort", "images/sort/malicious-sort.png")]
/// Returns a sort permutation in a malicious context.
/// This runs sort in a malicious context. The caller is responsible to validate the accumulator contents and downgrade context to Semi-honest before calling this function
/// The function takes care of upgrading and validating while the sort protocol runs.
/// It then returns a semi honest context with output in Replicated format. The caller should then upgrade the output and context before moving forward
///
/// Steps
/// 1. [Malicious Special] Upgrade the context from semihonest to malicious and get a validator
/// 2. [Malicious Special] Upgrade 0th sort bit keys
/// 3. Compute bit permutation that sorts 0th bit
///
/// For 1st to N-1th bit of input share
/// 1. i. Shuffle the i-1th composition
///   ii. [Malicious Special] Validate the accumulator contents
///  iii. [Malicious Special] Malicious reveal
///   iv. [Malicious Special] Downgrade context to semihonest
/// 2. i. [Malicious Special] Upgrade ith sort bit keys
///   ii. Sort ith bit based on i-1th bits by applying i-1th composition on ith bit
/// 3. Compute bit permutation that sorts ith bit
/// 4. Compute ith composition by composing i-1th composition on ith permutation
/// In the end, following is returned
///    i. n-1th composition: This is the permutation which sorts the inputs
///   ii. Validator which can be used to validate the leftover items in the accumulator
///
/// ![Malicious sort permutation steps][malicious_sort]
/// # Panics
/// If sort keys dont have num of bits same as `num_bits`
/// # Errors
pub async fn malicious_generate_permutation<'a, F>(
    sh_ctx: SemiHonestContext<'a>,
    sort_keys: &[Vec<Replicated<F>>],
    num_bits: u32,
) -> Result<(MaliciousValidator<'a, F>, Vec<MaliciousReplicated<F>>), Error>
where
    F: Field,
{
    let mut malicious_validator = MaliciousValidator::new(sh_ctx.clone());
    let mut m_ctx_bit = malicious_validator.context();
    assert_eq!(sort_keys.len(), num_bits as usize);

    let upgraded_sort_keys = m_ctx_bit.upgrade(sort_keys[0].clone()).await?;
    let bit_0_permutation =
        bit_permutation(m_ctx_bit.narrow(&BitPermutationStep), &upgraded_sort_keys).await?;

    let mut composed_less_significant_bits_permutation = bit_0_permutation;
    for bit_num in 1..num_bits {
        let revealed_and_random_permutations = malicious_shuffle_and_reveal_permutation(
            m_ctx_bit.narrow(&ShuffleRevealPermutation),
            composed_less_significant_bits_permutation,
            malicious_validator,
        )
        .await?;

        malicious_validator =
            MaliciousValidator::new(sh_ctx.narrow(&Sort(bit_num.try_into().unwrap())));
        m_ctx_bit = malicious_validator.context();
        let upgraded_sort_keys = m_ctx_bit
            .upgrade(sort_keys[bit_num as usize].clone())
            .await?;
        let bit_i_sorted_by_less_significant_bits = secureapplyinv(
            m_ctx_bit.narrow(&ApplyInv),
            upgraded_sort_keys,
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
        )
        .await?;

        let bit_i_permutation = bit_permutation(
            m_ctx_bit.narrow(&BitPermutationStep),
            &bit_i_sorted_by_less_significant_bits,
        )
        .await?;

        let composed_i_permutation = compose(
            m_ctx_bit.narrow(&ComposeStep),
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
            bit_i_permutation,
        )
        .await?;
        composed_less_significant_bits_permutation = composed_i_permutation;
    }
    Ok((
        malicious_validator,
        composed_less_significant_bits_permutation,
    ))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::zip;

    use rand::seq::SliceRandom;

    use crate::{
        bits::Fp2Array,
        protocol::{
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            sort::generate_permutation_opt::generate_permutation_opt,
            MatchKey,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
    };

    use crate::{
        ff::{Field, Fp31},
        protocol::{context::Context, sort::generate_permutation::shuffle_and_reveal_permutation},
        test_fixture::{generate_shares, join3, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;
        const NUM_MULTI_BITS: u32 = 3;
        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MatchKey>());

        let mut expected = match_keys.iter().map(|mk| mk.as_u128()).collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(match_keys.clone(), |ctx, mk_shares| async move {
                let local_lists =
                    convert_all_bits_local::<Fp31, _>(ctx.role(), mk_shares.into_iter());
                let converted_shares =
                    convert_all_bits(&ctx, &local_lists, MatchKey::BITS, NUM_MULTI_BITS)
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
    pub async fn test_shuffle_and_reveal_permutation() {
        const BATCHSIZE: u32 = 25;

        let mut rng = thread_rng();

        let mut permutation: Vec<u32> = (0..BATCHSIZE).collect();
        permutation.shuffle(&mut rng);

        let world = TestWorld::new().await;
        let [ctx0, ctx1, ctx2] = world.contexts();
        let permutation: Vec<u128> = permutation.iter().map(|x| u128::from(*x)).collect();

        let [perm0, perm1, perm2] = generate_shares::<Fp31>(&permutation);

        let h0_future = shuffle_and_reveal_permutation(ctx0.narrow("shuffle_reveal"), perm0);
        let h1_future = shuffle_and_reveal_permutation(ctx1.narrow("shuffle_reveal"), perm1);
        let h2_future = shuffle_and_reveal_permutation(ctx2.narrow("shuffle_reveal"), perm2);

        let perms_and_randoms = join3(h0_future, h1_future, h2_future).await;

        assert_eq!(perms_and_randoms[0].revealed, perms_and_randoms[1].revealed);
        assert_eq!(perms_and_randoms[1].revealed, perms_and_randoms[2].revealed);

        assert_eq!(
            perms_and_randoms[0].randoms_for_shuffle.0,
            perms_and_randoms[2].randoms_for_shuffle.1
        );
        assert_eq!(
            perms_and_randoms[1].randoms_for_shuffle.0,
            perms_and_randoms[0].randoms_for_shuffle.1
        );
        assert_eq!(
            perms_and_randoms[2].randoms_for_shuffle.0,
            perms_and_randoms[1].randoms_for_shuffle.1
        );
    }
}
