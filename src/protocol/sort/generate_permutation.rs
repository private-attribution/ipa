use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        basics::Reveal,
        context::{
            Context, UpgradableContext, UpgradedContext, UpgradedMaliciousContext,
            UpgradedSemiHonestContext, Validator,
        },
        sort::{
            generate_permutation_opt::generate_permutation_opt,
            shuffle::{get_two_of_three_random_permutations, shuffle_shares},
            ShuffleRevealPermutationStep, SortStep,
        },
        BasicProtocols, NoRecord,
    },
    secret_sharing::{
        replicated::{
            malicious::{
                AdditiveShare as MaliciousReplicated, DowngradeMalicious, ExtendableField,
                UnauthorizedDowngradeWrapper,
            },
            semi_honest::AdditiveShare as Replicated,
        },
        BitDecomposed, Linear as LinearSecretSharing, SecretSharing,
    },
};
use async_trait::async_trait;

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
///
/// Steps
/// 1. Get random permutation 2/3 shared across helpers
/// 2. Shuffle shares three times
/// 3. Validate the accumulated macs - this returns the revealed permutation
pub(super) async fn shuffle_and_reveal_permutation<C, S, F>(
    m_ctx: C::UpgradedContext<F>,
    input_permutation: Vec<S>,
    malicious_validator: C::Validator<F>,
) -> Result<RevealedAndRandomPermutations, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    F: ExtendableField,
    S: SecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F>,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
{
    let random_permutations_for_shuffle = get_two_of_three_random_permutations(
        input_permutation.len().try_into().unwrap(),
        m_ctx
            .narrow(&ShuffleRevealPermutationStep::Generate)
            .prss_rng(),
    );

    let shuffled_permutation = shuffle_shares(
        input_permutation,
        (
            random_permutations_for_shuffle.0.as_slice(),
            random_permutations_for_shuffle.1.as_slice(),
        ),
        m_ctx.narrow(&ShuffleRevealPermutationStep::Shuffle),
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

/// This function takes in a semihonest context and sort keys, generates a sort permutation, shuffles and reveals it and
/// returns both shuffle-revealed permutation and 2/3 randoms which were used to shuffle the permutation
/// The output of this can be applied to any of semihonest/malicious context
/// # Panics
/// If unable to convert sort keys length to u32
/// # Errors
/// If unable to convert sort keys length to u32
#[tracing::instrument(name = "sort_permutation", skip_all)]
pub async fn generate_permutation_and_reveal_shuffled<C, S, F>(
    ctx: C,
    sort_keys: impl Iterator<Item = &Vec<BitDecomposed<Replicated<F>>>>,
) -> Result<RevealedAndRandomPermutations, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F> + 'static,
    F: PrimeField + ExtendableField,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
{
    let (validator, sort_permutation) =
        generate_permutation_opt(ctx.narrow(&SortStep::SortKeys), sort_keys).await?;

    let m_ctx = validator.context();
    shuffle_and_reveal_permutation::<C, _, _>(
        m_ctx.narrow(&SortStep::ShuffleRevealPermutation),
        sort_permutation,
        validator,
    )
    .await
}

#[async_trait]
impl<'a, F: ExtendableField> DowngradeMalicious
    for ShuffledPermutationWrapper<MaliciousReplicated<F>, UpgradedMaliciousContext<'a, F>>
{
    type Target = Vec<u32>;
    /// For ShuffledPermutationWrapper on downgrading, we reveal the permutation. This runs reveal on the malicious context
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let output = self
            .reveal(
                self.ctx.narrow(&ShuffleRevealPermutationStep::Reveal),
                NoRecord,
            )
            .await
            .unwrap();
        UnauthorizedDowngradeWrapper::new(output)
    }
}

#[async_trait]
impl<'a, F: ExtendableField> DowngradeMalicious
    for ShuffledPermutationWrapper<Replicated<F>, UpgradedSemiHonestContext<'a, F>>
{
    type Target = Vec<u32>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let output = self
            .reveal(
                self.ctx.narrow(&ShuffleRevealPermutationStep::Reveal),
                NoRecord,
            )
            .await
            .unwrap();
        UnauthorizedDowngradeWrapper::new(output)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::zip;

    use rand::seq::SliceRandom;

    use crate::{
        ff::GaloisField,
        protocol::{
            context::{SemiHonestContext, UpgradableContext, Validator},
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
                    let local_lists =
                        convert_all_bits_local::<Fp31, _>(ctx.role(), mk_shares.into_iter());
                    let converted_shares =
                        convert_all_bits(&ctx, &local_lists, MatchKey::BITS, NUM_MULTI_BITS)
                            .await
                            .unwrap();
                    let (_validator, result) =
                        generate_permutation_opt(ctx.narrow("sort"), converted_shares.iter())
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

    #[tokio::test]
    pub async fn shuffle_and_reveal() {
        const BATCHSIZE: u32 = 25;

        let mut rng = thread_rng();

        let mut permutation: Vec<u32> = (0..BATCHSIZE).collect();
        permutation.shuffle(&mut rng);

        let world = TestWorld::default();
        let [ctx0, ctx1, ctx2] = world.contexts();
        let permutation: Vec<u128> = permutation.iter().map(|x| u128::from(*x)).collect();

        let [perm0, perm1, perm2] = generate_shares::<Fp31>(&permutation);

        let v0 = ctx0.validator();
        let v1 = ctx1.validator();
        let v2 = ctx2.validator();

        let ctx0 = v0.context().narrow("shuffle_reveal");
        let ctx1 = v1.context().narrow("shuffle_reveal");
        let ctx2 = v2.context().narrow("shuffle_reveal");

        let h0_future = shuffle_and_reveal_permutation::<SemiHonestContext, _, _>(ctx0, perm0, v0);
        let h1_future = shuffle_and_reveal_permutation::<SemiHonestContext, _, _>(ctx1, perm1, v1);
        let h2_future = shuffle_and_reveal_permutation::<SemiHonestContext, _, _>(ctx2, perm2, v2);

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
