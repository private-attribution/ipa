use ff::{PrimeField};
use rand::thread_rng;

const TOTAL_HELPERS: usize = 3;

pub fn mpc_sort<F: PrimeField>(shared_secrets: Vec<Vec<F>>) -> Vec<Vec<F>>{
    let (linear_randoms, quadratic_randoms, ) = get_random_nos_for_mult(shared_secrets.len());
    let mult_inputs = helpers_gen_mult_inputs(shared_secrets, quadratic_randoms);
    let mult_output = king_do_mult(mult_inputs);
    helpers_gen_permutations(
        toggle_row_and_columns_of_shares(mult_output), 
        toggle_row_and_columns_of_shares(linear_randoms))
}

// Wrapper functions over helper functions
fn helpers_gen_mult_inputs<F: PrimeField>(shared_secrets: Vec<Vec<F>>, quadratic_randoms: Vec<Vec<F>>) -> Vec<Vec<F>> {
    let quadratic_random_streams = toggle_row_and_columns_of_shares(quadratic_randoms);

    // Calculate 1-x and x and cumulative sum consuming quadratic randoms
    let shares = toggle_row_and_columns_of_shares(shared_secrets);

    let mut mult_inputs: Vec<Vec<F>> = Vec::new();
    (0..TOTAL_HELPERS).for_each(|j| {
        mult_inputs.push(helper_get_mult_input(shares[j].clone(),quadratic_random_streams[j].clone()));
    });
    mult_inputs
}

fn helpers_gen_permutations<F: PrimeField>(mult_output: Vec<Vec<F>>, linear_randoms: Vec<Vec<F>>) -> Vec<Vec<F>> {
    // Helpers incorporate their linear random coefficients and compute sum
    let mut get_permutations = Vec::new();
    (0..TOTAL_HELPERS).for_each(|j| {
        get_permutations.push(helper_get_permutation_share(
            mult_output[j].clone(), 
            linear_randoms[j].clone()));
    });
    get_permutations
}

// King functions
fn king_do_mult<F: PrimeField>(mult_inputs: Vec<Vec<F>>) -> Vec<Vec<F>> {
    // King multiplies all the outputs and reshares with helpers
    let mult_protocol_output = mult_protocol(toggle_row_and_columns_of_shares(mult_inputs));
    get_helper_shares_with_h1_0(mult_protocol_output)
}

fn mult_protocol<F: PrimeField>(mult_inputs: Vec<Vec<F>>) -> Vec<F> {
    let mut revealed = Vec::new();
    for mult_input in mult_inputs {
        revealed.push(mult_input[0] * F::from(3_u64) - mult_input[1] * F::from(3_u64) + mult_input[2] * F::from(1_u64));
    }
    revealed
}    

fn get_helper_shares_with_h1_0<F: PrimeField>(mult_protocol_output: Vec<F>) -> Vec<Vec<F>> {
    let mut output = Vec::new();
    (0..mult_protocol_output.len()).for_each(|i| {
        let mut vec = Vec::new();
        let linear_secret_share = -mult_protocol_output[i];
        (1..=3).for_each(|j| {
        vec.push(mult_protocol_output[i] + linear_secret_share * F::from(j as u64));
        });
        output.push(vec);
    });
    output
}

// Helper functions
fn helper_get_mult_input<F: PrimeField>(mut shares: Vec<F>, quadratic_randoms: Vec<F>) -> Vec<F>{
    // Step1: Calculate x and 1 - x 
    let mut x_and_one_minus_x:Vec<F> = shares.iter().map(|x| F::from(1) - x).collect();
    x_and_one_minus_x.append(&mut shares);

    // Step2: Calculate cumulative sum
    let length = x_and_one_minus_x.len();
    let mut cumulative_sum:Vec<F> = Vec::with_capacity(length);
    cumulative_sum.push(x_and_one_minus_x[0]);
    for i in 1 .. length {
        cumulative_sum.push(cumulative_sum[i-1] + x_and_one_minus_x[i]) ;
    }

    // Step3: Add output of step 1 and step 2
    let mut mult_input = Vec::with_capacity(length);
    for i in 0..cumulative_sum.len() {
        mult_input.push(x_and_one_minus_x[i] * cumulative_sum[i] + quadratic_randoms[i]);
    }
    mult_input
}

fn helper_get_permutation_share<F: PrimeField>(mult_output: Vec<F>, linear_randoms: Vec<F>) -> Vec<F> {
    let len = linear_randoms.len()/2;
    let mut actual_mult = Vec::new();

    // Subtract linear random from mult_output
    (0..len*2).for_each(|j| {
        actual_mult.push(mult_output[j] - linear_randoms[j]);  
    });

    // Fold the result
    let mut permutation_share = Vec::new();
    (0..len).for_each(|j| {
        permutation_share.push(actual_mult[j] + actual_mult[j + len]);
    });
    permutation_share
}

// Miscellaneous functions
fn get_random_nos_for_mult<F: PrimeField>(count: usize) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    // Generate random coefficients for linear and quadratic equations
    let mut rand_nos = Vec::new();
    (0..count*2).for_each(|_row| {
        let mut rand_row = Vec::new();
        (0..4).for_each(|_i| {
            rand_row.push(F::random(thread_rng()));
        });
        rand_nos.push(rand_row);
    });
    let mut linear_randoms: Vec<Vec<F>> = Vec::new();
    let mut quadratic_randoms: Vec<Vec<F>> = Vec::new();
    (0..rand_nos.len()).for_each(|i| {
        linear_randoms.push(Vec::new());
        quadratic_randoms.push(Vec::new());
        (1..=TOTAL_HELPERS).for_each(|j: usize| {
            let j_fp = F::from(j as u64);
            linear_randoms[i].push(rand_nos[i][0] + j_fp * rand_nos[i][1]);
            quadratic_randoms[i].push(rand_nos[i][0] + j_fp * rand_nos[i][2] + j_fp * j_fp * rand_nos[i][3]);
        });
    });
    (linear_randoms, quadratic_randoms)
}

fn toggle_row_and_columns_of_shares<F: PrimeField>(shares: Vec<Vec<F>>) -> Vec<Vec<F>> {
    let mut toggled = Vec::new();
    (0..shares[0].len()).for_each(|row: usize| {
        toggled.push(Vec::new());
        (0..shares.len()).for_each(|col| {
            toggled[row].push(shares[col][row])
        });
    });
    toggled
}

#[cfg(test)]
mod tests {

    use ff::PrimeField;
    use super::{helpers_gen_permutations, helpers_gen_mult_inputs, king_do_mult, mpc_sort, toggle_row_and_columns_of_shares, TOTAL_HELPERS};

    #[derive(PrimeField)]
    #[PrimeFieldModulus = "7"]
    #[PrimeFieldGenerator = "7"]
    #[PrimeFieldReprEndianness = "little"]
    struct Fp([u64; 1]);

    fn convert_int_to_field_2d<F: PrimeField>(shares: Vec<Vec<u64>>) -> Vec<Vec<F>> {
        shares.iter().map (
            |share| (
            convert_int_to_field_1d(share))
        ).collect()
    }
    
    fn convert_int_to_field_1d<F: PrimeField>(share: &Vec<u64>) -> Vec<F> {
        share.iter().map (
            |helper_share| F::from(*helper_share)
        ).collect()
    }

    // Generate secret shares with random coefficients
    fn get_shares_with_randoms(secret: Vec<u64>, randoms: Vec<u64>) -> Vec<Vec<Fp>> {
        let mut shares: Vec<Vec<u64>> = Vec::new();
        (0..secret.len()).for_each(|i| {
            let mut one_share: Vec<u64>= Vec::new();
            (1..=TOTAL_HELPERS).for_each(|j| {
                one_share.push(secret[i] + randoms[i] * (j as u64));
            });
            shares.push(one_share);
        });
        convert_int_to_field_2d(shares)
    }

    #[test]
    fn radix_sort() {

        let input = [1,0,1,0,0,0].to_vec();
        // Generate secret shares with random coefficients
        let shared_secret_randoms = [1,2,0,3,3,5].to_vec();
        let shares = get_shares_with_randoms(input, shared_secret_randoms);

        let mpc_sort_output = toggle_row_and_columns_of_shares(mpc_sort(shares));
        let mut sort_output = Vec::new();
        (0..mpc_sort_output.len()).for_each(|row| {
            sort_output.push(mpc_sort_output[row][0] * Fp::from(2) - mpc_sort_output[row][1]);
        });
        
        let expected_sort_output = convert_int_to_field_1d::<Fp>(&[5, 1, 6, 2, 3, 4].to_vec());
        assert_eq!(sort_output, expected_sort_output);
    }

    #[test]
    fn individual_modules() {
        let input = [1,0,1,0,0,0].to_vec();
        let shared_secret_randoms= [1,2,0,3,3,5].to_vec();
        let shares = get_shares_with_randoms(input, shared_secret_randoms);

        // multiplication protocol
        // Generate random coefficients for linear and quadratic equations
        let mult_randoms: Vec<Vec<Fp>> = convert_int_to_field_2d([
            [0, 4, 3, 0].to_vec(),
            [4, 0, 4, 6].to_vec(),
            [1, 6, 0, 2].to_vec(),
            [0, 5, 0, 5].to_vec(),
            [0, 0, 6, 2].to_vec(),
            [6, 4, 2, 2].to_vec(),
            [3, 6, 2, 0].to_vec(),
            [4, 6, 2, 4].to_vec(),
            [5, 2, 2, 2].to_vec(),
            [1, 2, 5, 6].to_vec(),
            [0, 0, 1, 3].to_vec(),
            [1, 2, 4, 3].to_vec()
        ].to_vec());

        let mut linear_randoms: Vec<Vec<Fp>> = Vec::new();
        let mut quadratic_randoms: Vec<Vec<Fp>> = Vec::new();
        (0..mult_randoms.len()).for_each(|i| {
            linear_randoms.push(Vec::new());
            quadratic_randoms.push(Vec::new());
            (1..=TOTAL_HELPERS).for_each(|j: usize| {
                let j_fp = Fp::from(j as u64);
                linear_randoms[i].push(mult_randoms[i][0] + j_fp * mult_randoms[i][1]);
                quadratic_randoms[i].push(mult_randoms[i][0] + j_fp * mult_randoms[i][2] + j_fp * j_fp * mult_randoms[i][3]);
            });
        });
        
        // let quadratic_random_streams = toggle_row_and_columns_of_shares(quadratic_randoms);
        let mult_inputs = helpers_gen_mult_inputs(shares, quadratic_randoms);

        // King multiplies all the outputs and reshares with helpers
        let helper_shares = king_do_mult(mult_inputs);

        // Helpers incorporate their linear random coefficients and compute sum
        let permutations_output = helpers_gen_permutations(
            toggle_row_and_columns_of_shares(helper_shares), 
            toggle_row_and_columns_of_shares(linear_randoms));
        
        let expected_permutations_output = convert_int_to_field_2d([
            [1,4,0].to_vec(),
            [0,6,5].to_vec(),
            [0,1,2].to_vec(),
            [6,3,0].to_vec(),
            [0,4,1].to_vec(),
            [1,5,2].to_vec()
            ].to_vec());
        
            assert_eq!(toggle_row_and_columns_of_shares(permutations_output), expected_permutations_output);

    }

}
