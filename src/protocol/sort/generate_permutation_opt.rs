use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        sort::{
            generate_permutation::shuffle_and_reveal_permutation,
            secureapplyinv::secureapplyinv_multi,
        },
        sort::{
            multi_bit_permutation::multi_bit_permutation,
            SortStep::{BitPermutationStep, ComposeStep, MultiApplyInv, ShuffleRevealPermutation},
        },
        IpaProtocolStep::Sort,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

use super::compose::compose;
use crate::protocol::context::SemiHonestContext;

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
    ctx: SemiHonestContext<'_, F>,
    sort_keys: &[Vec<Vec<Replicated<F>>>],
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    assert_ne!(sort_keys.len(), 0);
    let ctx_0 = ctx.narrow(&Sort(0));

    let lsb_permutation =
        multi_bit_permutation(ctx_0.narrow(&BitPermutationStep), &sort_keys[0]).await?;

    let input_len = u32::try_from(sort_keys[0].len()).unwrap(); // safe, we don't sort more that 1B rows

    let mut composed_less_significant_bits_permutation = lsb_permutation;
    for (bit_num, one_slice) in sort_keys.iter().enumerate().skip(1) {
        let ctx_bit = ctx.narrow(&Sort(bit_num.try_into().unwrap()));
        let revealed_and_random_permutations = shuffle_and_reveal_permutation(
            ctx_bit.narrow(&ShuffleRevealPermutation),
            input_len,
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::zip;

    use crate::bits::{BitArray, BitArray40};
    use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
    use crate::rand::{thread_rng, Rng};

    use crate::protocol::context::{Context, SemiHonestContext};
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::{MaskedMatchKey, Runner};
    use crate::{
        ff::{Field, Fp31},
        protocol::sort::generate_permutation_opt::generate_permutation_opt,
        test_fixture::{Reconstruct, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 10;
        const NUM_MULTI_BITS: u32 = 3;

        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || rng.gen::<MaskedMatchKey>());

        let mut expected = match_keys.iter().map(|mk| mk.as_u128()).collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(
                match_keys.clone(),
                |ctx: SemiHonestContext<Fp31>, mk_shares| async move {
                    let local_lists =
                        convert_all_bits_local(ctx.role(), &mk_shares, BitArray40::BITS);
                    let converted_shares =
                        convert_all_bits(&ctx, local_lists, BitArray40::BITS, NUM_MULTI_BITS)
                            .await
                            .unwrap();

                    generate_permutation_opt(
                        ctx.narrow("sort"),
                        &converted_shares.collect::<Vec<_>>(),
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let mut mpc_sorted_list = (0..u128::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = match_key.as_u128();
        }

        assert_eq!(expected, mpc_sorted_list);
    }
}
