use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        sort::{SortStep::{
            ApplyInv, BitPermutationStep, ComposeStep, ShuffleRevealPermutation, SortKeys,
        }, multi_bit_permutation::multi_bit_permutation},
        sort::{
            bit_permutation::bit_permutation, generate_permutation::shuffle_and_reveal_permutation,
        },
        IpaProtocolStep::Sort,
    },
    secret_sharing::Replicated,
};

use super::{
    compose::compose, generate_permutation::RevealedAndRandomPermutations,
    secureapplyinv::secureapplyinv,
};
use crate::protocol::context::SemiHonestContext;
use embed_doc_image::embed_doc_image;

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
pub async fn generate_permutation_multi<F>(
    ctx: SemiHonestContext<'_, F>,
    sort_keys: &[Vec<Replicated<F>>],
    num_bits: u32,
    num_multi_bits: u32
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let ctx_0 = ctx.narrow(&Sort(0));
    assert_eq!(sort_keys.len(), num_bits as usize);

    let bit_0_permutation = if num_multi_bits > num_bits {
        multi_bit_permutation(ctx_0.narrow(&BitPermutationStep), &sort_keys[0..num_bits.try_into().unwrap()]).await?
    } else {
        multi_bit_permutation(ctx_0.narrow(&BitPermutationStep), &sort_keys[0..num_multi_bits.try_into().unwrap()]).await?
    };

    let input_len = u32::try_from(sort_keys[0].len()).unwrap(); // safe, we don't sort more that 1B rows

    let mut composed_less_significant_bits_permutation = bit_0_permutation;
    for bit_num in num_multi_bits..num_bits {
    //.step_by(num_multi_bits.try_into().unwrap()) {
        let ctx_bit = ctx.narrow(&Sort(bit_num));
        let revealed_and_random_permutations = shuffle_and_reveal_permutation(
            ctx_bit.narrow(&ShuffleRevealPermutation),
            input_len,
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
    ctx: SemiHonestContext<'_, F>,
    sort_keys: &[Vec<Replicated<F>>],
    num_bits: u32,
) -> Result<RevealedAndRandomPermutations, Error> {
    let sort_permutation =
        generate_permutation_multi(ctx.narrow(&SortKeys), sort_keys, num_bits, 3).await?;
    shuffle_and_reveal_permutation(
        ctx.narrow(&ShuffleRevealPermutation),
        u32::try_from(sort_keys[0].len()).unwrap(),
        sort_permutation,
    )
    .await
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::zip;

    use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
    use crate::rand::{thread_rng, Rng};

    use crate::protocol::context::{Context, SemiHonestContext};
    use crate::test_fixture::{MaskedMatchKey, Runner};
    use crate::{
        ff::{Field, Fp31},
        protocol::sort::generate_permutation_multi::{
            generate_permutation_multi
        },
        test_fixture::{Reconstruct, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || MaskedMatchKey::mask(rng.gen()));

        let mut expected = match_keys
            .iter()
            .map(|mk| u64::from(*mk))
            .collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(
                match_keys.clone(),
                |ctx: SemiHonestContext<Fp31>, mk_shares| async move {
                    let local_lists =
                        convert_all_bits_local(ctx.role(), &mk_shares, MaskedMatchKey::BITS);
                    let converted_shares = convert_all_bits(&ctx, &local_lists).await.unwrap();
                    generate_permutation_multi(
                        ctx.narrow("sort"),
                        &converted_shares,
                        MaskedMatchKey::BITS,
                        3
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let mut mpc_sorted_list = (0..u64::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = u64::from(match_key);
        }

        assert_eq!(expected, mpc_sorted_list);
    }
}
