use crate::modulus_convert::RandomShareGenerationHelper;
use crate::modulus_convert::ReplicatedFp31SecretSharing;

// Helper functions
#[must_use]
pub fn gen_mult_input(
    shares: &[ReplicatedFp31SecretSharing],
    helper: &RandomShareGenerationHelper,
) -> Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)> {
    // Step1: Calculate x and 1 - x
    let mut x_and_one_minus_x: Vec<ReplicatedFp31SecretSharing> = shares
        .iter()
        .map(|x| helper.get_share_of_one() - *x)
        .collect();
    x_and_one_minus_x.append(&mut shares.to_vec());

    // Step2: Calculate cumulative sum
    let length = x_and_one_minus_x.len();
    let mut cumulative_sum = Vec::with_capacity(length);
    cumulative_sum.push(x_and_one_minus_x[0]);
    for i in 1..length {
        cumulative_sum.push(cumulative_sum[i - 1] + x_and_one_minus_x[i]);
    }

    // Step3: Consolidate step 1 and step 2 output
    x_and_one_minus_x
        .iter()
        .zip(cumulative_sum.iter())
        .map(|(x_and_one_minus, cumulative_sum)| (*x_and_one_minus, *cumulative_sum))
        .collect()
}

#[must_use]
pub fn gen_permutation_share(
    mult_output: &[ReplicatedFp31SecretSharing],
) -> Vec<ReplicatedFp31SecretSharing> {
    let len = mult_output.len() / 2;

    // Fold the result
    let mut permutation_share = Vec::new();
    (0..len).for_each(|j| {
        permutation_share.push(mult_output[j] + mult_output[j + len]);
    });
    permutation_share
}

#[cfg(test)]
mod tests {

    use crate::{
        field::Fp31,
        modulus_convert::{
            HelperIdentity, RandomShareGenerationHelper, ReplicatedFp31SecretSharing,
        },
        prss::ParticipantSetup,
    };

    use itertools::izip;
    use rand::thread_rng;

    use super::{gen_mult_input, gen_permutation_share};

    type ReplicatedShares = (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    );

    type RandomShareGenerationHelpers = (
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
    );

    type HelperMultInputShares = (
        Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)>,
        Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)>,
        Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)>,
    );

    fn mpc_find_sorted_position(shared_secrets: &[ReplicatedShares]) -> Vec<ReplicatedShares> {
        let input_length = shared_secrets.len();

        let helpers = make_three();
        let (helpers, mult_inputs) = helpers_gen_mult_inputs(helpers, shared_secrets);
        assert_eq!(input_length * 2, mult_inputs.0.len());
        assert_eq!(input_length * 2, mult_inputs.1.len());
        assert_eq!(input_length * 2, mult_inputs.2.len());

        let (_, mult_output) = helpers_do_multiplication(helpers, &mult_inputs);

        assert_eq!(input_length * 2, mult_output.len());

        helpers_gen_permutations(&mult_output)
    }

    fn secret_share(a: u8, b: u8, c: u8) -> ReplicatedShares {
        (
            ReplicatedFp31SecretSharing::construct(Fp31::from(a), Fp31::from(b)),
            ReplicatedFp31SecretSharing::construct(Fp31::from(b), Fp31::from(c)),
            ReplicatedFp31SecretSharing::construct(Fp31::from(c), Fp31::from(a)),
        )
    }

    fn make_three() -> (
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
    ) {
        let mut r = thread_rng();
        let setup1 = ParticipantSetup::new(&mut r);
        let setup2 = ParticipantSetup::new(&mut r);
        let setup3 = ParticipantSetup::new(&mut r);
        let (pk1_l, pk1_r) = setup1.public_keys();
        let (pk2_l, pk2_r) = setup2.public_keys();
        let (pk3_l, pk3_r) = setup3.public_keys();

        let p1 = setup1.setup(&pk3_r, &pk2_l);
        let p2 = setup2.setup(&pk1_r, &pk3_l);
        let p3 = setup3.setup(&pk2_r, &pk1_l);

        // Helper 1
        let h1 = RandomShareGenerationHelper::init(p1, HelperIdentity::H1);

        // Helper 2
        let h2 = RandomShareGenerationHelper::init(p2, HelperIdentity::H2);

        // Helper 3
        let h3 = RandomShareGenerationHelper::init(p3, HelperIdentity::H3);

        (h1, h2, h3)
    }

    // Wrapper functions over helper functions
    fn helpers_gen_mult_inputs(
        helpers: RandomShareGenerationHelpers,
        shared_secrets: &[ReplicatedShares],
    ) -> (RandomShareGenerationHelpers, HelperMultInputShares) {
        fn get_helper_specific_shares(
            shares: &[ReplicatedShares],
        ) -> (
            Vec<ReplicatedFp31SecretSharing>,
            Vec<ReplicatedFp31SecretSharing>,
            Vec<ReplicatedFp31SecretSharing>,
        ) {
            let mut helper1_share = Vec::new();
            let mut helper2_share = Vec::new();
            let mut helper3_share = Vec::new();

            (0..shares.len()).for_each(|i| {
                helper1_share.push(shares[i].0);
                helper2_share.push(shares[i].1);
                helper3_share.push(shares[i].2);
            });

            (helper1_share, helper2_share, helper3_share)
        }

        let shares = get_helper_specific_shares(shared_secrets);
        let (h1, h2, h3) = helpers;

        let mult_inputs = (
            gen_mult_input(&shares.0, &h1),
            gen_mult_input(&shares.1, &h2),
            gen_mult_input(&shares.2, &h3),
        );

        ((h1, h2, h3), mult_inputs)
    }

    fn helpers_do_multiplication(
        helpers: RandomShareGenerationHelpers,
        mult_inputs: &HelperMultInputShares,
    ) -> (RandomShareGenerationHelpers, Vec<ReplicatedShares>) {
        let (h1, h2, h3) = helpers;
        let mut mult_outputs = Vec::new();
        (0..mult_inputs.0.len()).for_each(|i| {
            // TODO This code will be moved out of test once mult implementation is done

            let a1 = mult_inputs.0[i].0;
            let a2 = mult_inputs.1[i].0;
            let a3 = mult_inputs.2[i].0;
            let b1 = mult_inputs.0[i].1;
            let b2 = mult_inputs.1[i].1;
            let b3 = mult_inputs.2[i].1;

            let (h1_res, d1) = a1.mult_step1(b1, &h1.rng, 1, true, true);
            let (h2_res, d2) = a2.mult_step1(b2, &h2.rng, 1, true, true);
            let (h3_res, d3) = a3.mult_step1(b3, &h3.rng, 1, true, true);

            mult_outputs.push((
                ReplicatedFp31SecretSharing::mult_step2(h1_res, d3),
                ReplicatedFp31SecretSharing::mult_step2(h2_res, d1),
                ReplicatedFp31SecretSharing::mult_step2(h3_res, d2),
            ));
        });
        ((h1, h2, h3), mult_outputs)
    }

    fn helpers_gen_permutations(mult_output: &[ReplicatedShares]) -> Vec<ReplicatedShares> {
        // Helpers compute sum
        let mut permutations: Vec<ReplicatedShares> = Vec::new();
        let mut shares1 = Vec::new();
        let mut shares2 = Vec::new();
        let mut shares3 = Vec::new();

        for mult_output_share in mult_output {
            shares1.push(mult_output_share.0);
            shares2.push(mult_output_share.1);
            shares3.push(mult_output_share.2);
        }
        let permutations1 = gen_permutation_share(&shares1);
        let permutations2 = gen_permutation_share(&shares2);
        let permutations3 = gen_permutation_share(&shares3);

        for (x, y, z) in izip!(&permutations1, &permutations2, &permutations3) {
            permutations.push((*x, *y, *z));
        }
        permutations
    }

    #[test]
    fn find_sorted_position() {
        let input = [
            (1, 0, 0),
            (0, 0, 0),
            (0, 1, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ]
        .to_vec();
        let mut shares = Vec::new();
        for iter in input {
            shares.push(secret_share(iter.0, iter.1, iter.2));
        }

        let mpc_replicated_output = mpc_find_sorted_position(&shares);
        let expected_sort_output = [5_u128, 1, 6, 2, 3, 4].as_ref();

        (0..mpc_replicated_output.len()).for_each(|i| {
            assert_eq!(
                mpc_replicated_output[i].0
                    + mpc_replicated_output[i].1
                    + mpc_replicated_output[i].2,
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(expected_sort_output[i]),
                    Fp31::from(expected_sort_output[i])
                )
            );
        });
    }
}
