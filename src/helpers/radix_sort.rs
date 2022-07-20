use crate::modulus_convert::make_three;
use crate::modulus_convert::multiply_secret_shares;
use crate::modulus_convert::RandomShareGenerationHelper;
use crate::modulus_convert::ReplicatedFp31SecretSharing;

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

#[must_use]
pub fn mpc_sort(shared_secrets: &[ReplicatedShares]) -> Vec<ReplicatedShares> {
    let helpers = make_three();
    let (helpers, mult_inputs) = helpers_gen_mult_inputs(helpers, shared_secrets);
    let (_, mult_output) = helpers_do_multiplication(helpers, &mult_inputs);
    helpers_gen_permutations(&mult_output)
}

// Wrapper functions over helper functions
fn helpers_gen_mult_inputs(
    helpers: RandomShareGenerationHelpers,
    shared_secrets: &[ReplicatedShares],
) -> (
    RandomShareGenerationHelpers,
    Vec<Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)>>,
) {
    let shares = get_helper_specific_shares(shared_secrets);
    let (h1, h2, h3) = helpers;

    let mut mult_inputs = vec![helper_gen_mult_input(&shares[0], &h1)];
    mult_inputs.push(helper_gen_mult_input(&shares[1], &h2));
    mult_inputs.push(helper_gen_mult_input(&shares[2], &h3));

    ((h1, h2, h3), mult_inputs)
}

fn helpers_do_multiplication(
    helpers: RandomShareGenerationHelpers,
    mult_inputs: &[Vec<(ReplicatedFp31SecretSharing, ReplicatedFp31SecretSharing)>],
) -> (RandomShareGenerationHelpers, Vec<ReplicatedShares>) {
    let (h1, h2, h3) = helpers;
    let mut mult_outputs = Vec::new();
    (0..mult_inputs[0].len()).for_each(|i| {
        let a1 = mult_inputs[0][i].0;
        let a2 = mult_inputs[1][i].0;
        let a3 = mult_inputs[2][i].0;
        let b1 = mult_inputs[0][i].1;
        let b2 = mult_inputs[1][i].1;
        let b3 = mult_inputs[2][i].1;
        mult_outputs.push(multiply_secret_shares(
            &h1, &h2, &h3, a1, a2, a3, b1, b2, b3,
        ));
    });
    ((h1, h2, h3), mult_outputs)
}

fn helpers_gen_permutations(mult_output: &[ReplicatedShares]) -> Vec<ReplicatedShares> {
    // Helpers compute sum
    let mut gen_permutation: Vec<ReplicatedShares> = Vec::new();
    let mut shares1 = Vec::new();
    let mut shares2 = Vec::new();
    let mut shares3 = Vec::new();

    for iter in mult_output {
        shares1.push(iter.0);
        shares2.push(iter.1);
        shares3.push(iter.2);
    }
    let permutations1 = helper_gen_permutation_share(&shares1);
    let permutations2 = helper_gen_permutation_share(&shares2);
    let permutations3 = helper_gen_permutation_share(&shares3);

    (0..permutations1.len()).for_each(|i| {
        gen_permutation.push((permutations1[i], permutations2[i], permutations3[i]));
    });
    gen_permutation
}

// Helper functions
fn helper_gen_mult_input(
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
    let mut mult_input = Vec::with_capacity(length);
    for i in 0..cumulative_sum.len() {
        mult_input.push((x_and_one_minus_x[i], cumulative_sum[i]));
    }
    mult_input
}

fn helper_gen_permutation_share(
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

fn get_helper_specific_shares(
    shares: &[ReplicatedShares],
) -> Vec<Vec<ReplicatedFp31SecretSharing>> {
    let mut helper_shares: Vec<Vec<ReplicatedFp31SecretSharing>> = Vec::new();
    let mut helper1_share = Vec::new();
    let mut helper2_share = Vec::new();
    let mut helper3_share = Vec::new();

    (0..shares.len()).for_each(|i| {
        helper1_share.push(shares[i].0);
        helper2_share.push(shares[i].1);
        helper3_share.push(shares[i].2);
    });

    helper_shares.push(helper1_share);
    helper_shares.push(helper2_share);
    helper_shares.push(helper3_share);

    helper_shares
}

#[cfg(test)]
mod tests {

    use crate::{
        field::Fp31,
        helpers::radix_sort::{helpers_do_multiplication, helpers_gen_permutations},
        modulus_convert::{make_three, secret_share, ReplicatedFp31SecretSharing},
    };

    use super::{helpers_gen_mult_inputs, mpc_sort};

    #[test]
    fn replicated_share_sort() {
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

        let mpc_replicated_output = mpc_sort(&shares);
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

    #[test]
    fn gen_mult_inputs() {
        let helpers = make_three();
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
        let output = helpers_gen_mult_inputs(helpers, &shares);
        let mult_output = output.1;

        assert_eq!(3, mult_output.len());
        assert_eq!(shares.len() * 2, mult_output[0].len());
        assert_eq!(shares.len() * 2, mult_output[1].len());
        assert_eq!(shares.len() * 2, mult_output[2].len());
    }

    #[test]
    fn replicated_share_sort_test_individual_components_size_check() {
        let helpers = make_three();
        let input = [
            (1, 0, 0),
            (0, 0, 0),
            (0, 1, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ]
        .to_vec();
        let input_length = input.len();
        let mut shares = Vec::new();
        for iter in input {
            shares.push(secret_share(iter.0, iter.1, iter.2));
        }
        let (helpers, mult_inputs) = helpers_gen_mult_inputs(helpers, &shares);

        assert_eq!(3, mult_inputs.len());
        assert_eq!(input_length * 2, mult_inputs[0].len());
        assert_eq!(input_length * 2, mult_inputs[1].len());
        assert_eq!(input_length * 2, mult_inputs[2].len());

        let (_, mult_outputs) = helpers_do_multiplication(helpers, &mult_inputs);
        assert_eq!(input_length * 2, mult_outputs.len());

        let permutations = helpers_gen_permutations(&mult_outputs);
        assert_eq!(input_length, permutations.len());
    }
}
