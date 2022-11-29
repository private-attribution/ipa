use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::Context,
        modulus_conversion::convert_shares_for_a_bit,
        reveal::reveal_permutation,
        sort::SortStep::{
            ApplyInv, BitPermutationStep, ComposeStep, ModulusConversion, ShuffleRevealPermutation,
        },
        sort::{
            bit_permutation::bit_permutation,
            ShuffleRevealStep::{RevealPermutation, ShufflePermutation},
        },
        IpaProtocolStep::Sort,
    },
    secret_sharing::{Replicated, SecretSharing, XorReplicated},
};

use super::{
    compose::compose,
    secureapplyinv::secureapplyinv,
    shuffle::{get_two_of_three_random_permutations, shuffle_shares},
};
use crate::protocol::context::SemiHonestContext;
use crate::protocol::sort::ShuffleRevealStep::GeneratePermutation;
use embed_doc_image::embed_doc_image;
use futures::future::try_join;

/// This is an implementation of `OptApplyInv` (Algorithm 13) and `OptCompose` (Algorithm 14) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
pub(super) async fn shuffle_and_reveal_permutation<
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
>(
    ctx: C,
    input_len: u32,
    input_permutation: Vec<S>,
) -> Result<(Vec<u32>, (Vec<u32>, Vec<u32>)), Error> {
    let random_permutations_for_shuffle = get_two_of_three_random_permutations(
        input_len,
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

    // TODO: THIS IS WHERE VALIDATOR WILL BE CALLED!
    let revealed_permutation =
        reveal_permutation(ctx.narrow(&RevealPermutation), &shuffled_permutation).await?;

    Ok((revealed_permutation, random_permutations_for_shuffle))
}

/// This is an implementation of `GenPerm` (Algorithm 6) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
#[embed_doc_image("semi_honest_sort", "images/sort/semi-honest-sort.png")]
/// This protocol generates permutation of a stable sort for the given shares of inputs.
/// ![Generate sort permutation steps][semi_honest_sort]
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
pub async fn generate_permutation<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[XorReplicated],
    num_bits: u32,
) -> Result<Vec<Replicated<F>>, Error> {
    let ctx_0 = ctx.narrow(&Sort(0));
    let bit_0 =
        convert_shares_for_a_bit(ctx_0.narrow(&ModulusConversion), input, num_bits, 0).await?;
    let bit_0_permutation = bit_permutation(ctx_0.narrow(&BitPermutationStep), &bit_0).await?;
    let input_len = u32::try_from(input.len()).unwrap(); // safe, we don't sort more that 1B rows

    let mut composed_less_significant_bits_permutation = bit_0_permutation;
    for bit_num in 1..num_bits {
        let ctx_bit = ctx.narrow(&Sort(bit_num));
        let ((shuffled_compose_permutation, random_permutations_for_shuffle), bit_i) = try_join(
            shuffle_and_reveal_permutation(
                ctx_bit.narrow(&ShuffleRevealPermutation),
                input_len,
                composed_less_significant_bits_permutation,
            ),
            convert_shares_for_a_bit(ctx_bit.narrow(&ModulusConversion), input, num_bits, bit_num),
        )
        .await?;

        let bit_i_sorted_by_less_significant_bits = secureapplyinv(
            ctx_bit.narrow(&ApplyInv),
            bit_i,
            (
                random_permutations_for_shuffle.0.as_slice(),
                random_permutations_for_shuffle.1.as_slice(),
            ),
            &shuffled_compose_permutation,
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
                random_permutations_for_shuffle.0.as_slice(),
                random_permutations_for_shuffle.1.as_slice(),
            ),
            &shuffled_compose_permutation,
            bit_i_permutation,
        )
        .await?;
        composed_less_significant_bits_permutation = composed_i_permutation;
    }
    Ok(composed_less_significant_bits_permutation)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::zip;

    use rand::{seq::SliceRandom, Rng};

    use crate::protocol::context::Context;
    use crate::test_fixture::{join3, MaskedMatchKey, Runner};
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{
            sort::generate_permutation::{generate_permutation, shuffle_and_reveal_permutation},
            QueryId,
        },
        test_fixture::{generate_shares, logging, Reconstruct, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        const COUNT: usize = 5;

        logging::setup();
        let world = TestWorld::<Fp32BitPrime>::new(QueryId);
        let mut rng = rand::thread_rng();

        let mut match_keys = Vec::with_capacity(COUNT);
        match_keys.resize_with(COUNT, || MaskedMatchKey::mask(rng.gen()));

        let mut expected = match_keys
            .iter()
            .map(|mk| u64::from(*mk))
            .collect::<Vec<_>>();
        expected.sort_unstable();

        let result = world
            .semi_honest(match_keys.clone(), |ctx, mk_shares| async move {
                generate_permutation(ctx, &mk_shares, MaskedMatchKey::BITS)
                    .await
                    .unwrap()
            })
            .await;

        let mut mpc_sorted_list = (0..u64::try_from(COUNT).unwrap()).collect::<Vec<_>>();
        for (match_key, index) in zip(match_keys, result.reconstruct()) {
            mpc_sorted_list[index.as_u128() as usize] = u64::from(match_key);
        }

        assert_eq!(expected, mpc_sorted_list);
    }

    #[tokio::test]
    pub async fn test_shuffle_and_reveal_permutation() {
        const BATCHSIZE: u32 = 25;

        let mut rng = rand::thread_rng();

        let mut permutation: Vec<u32> = (0..BATCHSIZE).collect();
        permutation.shuffle(&mut rng);

        let world = TestWorld::new(QueryId);
        let [ctx0, ctx1, ctx2] = world.contexts();
        let permutation: Vec<u128> = permutation.iter().map(|x| u128::from(*x)).collect();

        let [perm0, perm1, perm2] = generate_shares::<Fp31>(&permutation);

        let h0_future =
            shuffle_and_reveal_permutation(ctx0.narrow("shuffle_reveal"), BATCHSIZE, perm0);
        let h1_future =
            shuffle_and_reveal_permutation(ctx1.narrow("shuffle_reveal"), BATCHSIZE, perm1);
        let h2_future =
            shuffle_and_reveal_permutation(ctx2.narrow("shuffle_reveal"), BATCHSIZE, perm2);

        let perms_and_randoms = join3(h0_future, h1_future, h2_future).await;

        assert_eq!(perms_and_randoms[0].0, perms_and_randoms[1].0);
        assert_eq!(perms_and_randoms[1].0, perms_and_randoms[2].0);

        assert_eq!(perms_and_randoms[0].1 .0, perms_and_randoms[2].1 .1);
        assert_eq!(perms_and_randoms[1].1 .0, perms_and_randoms[0].1 .1);
        assert_eq!(perms_and_randoms[2].1 .0, perms_and_randoms[1].1 .1);
    }
}
