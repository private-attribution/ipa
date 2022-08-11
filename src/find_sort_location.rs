#![allow(dead_code)]

use futures::future::join_all;

use crate::{
    field::Field,
    helpers::ring::Ring,
    replicated_secret_sharing::ReplicatedSecretSharing,
    securemul::{ProtocolContext, SecureMul},
};

pub struct SecureSort<'a, R, F> {
    context: &'a ProtocolContext<'a, R>,
    share_of_one: ReplicatedSecretSharing<F>,
}

impl<F: Field, R: Ring> SecureSort<'_, R, F> {
    pub async fn execute(
        self,
        shares: &[ReplicatedSecretSharing<F>],
    ) -> Vec<ReplicatedSecretSharing<F>> {
        let gen_permutation_share = |mult_output: Vec<ReplicatedSecretSharing<F>>| {
            let len = mult_output.len() / 2;

            // Fold the result
            let mut permutation_share = Vec::new();
            (0..len).for_each(|j| {
                permutation_share.push(mult_output[j] + mult_output[j + len]);
            });
            permutation_share
        };
        gen_permutation_share(self.secure_multiply(self.prepare_mult_inputs(shares)).await)
    }

    fn prepare_mult_inputs(
        &self,
        shares: &[ReplicatedSecretSharing<F>],
    ) -> Vec<(ReplicatedSecretSharing<F>, ReplicatedSecretSharing<F>)> {
        // Step1: Calculate x and 1 - x
        let mut x_and_one_minus_x: Vec<ReplicatedSecretSharing<F>> =
            shares.iter().map(|x| self.share_of_one - *x).collect();
        x_and_one_minus_x.append(&mut shares.to_owned());

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

    async fn secure_multiply(
        &self,
        mult_inputs: Vec<(ReplicatedSecretSharing<F>, ReplicatedSecretSharing<F>)>,
    ) -> Vec<ReplicatedSecretSharing<F>> {
        // Spawn all multiplication, wait for them to finish in parallel and then collect the results
        let async_multiply = mult_inputs.iter().enumerate().map(|(index, input)| {
            let output = SecureMul {
                a_share: input.0,
                b_share: input.1,
                index: index as u128,
            };
            output.execute(self.context)
        });
        join_all(
            async_multiply
                .into_iter()
                .map(|handle| async { handle.await.unwrap() }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        field::Fp31,
        helpers::{self, ring::mock::TestHelper},
        replicated_secret_sharing::ReplicatedSecretSharing,
    };

    use super::SecureSort;

    #[tokio::test]
    async fn find_sorted_position() {
        let ring = helpers::ring::mock::make_three();
        let participants = crate::prss::test::make_three();
        let context = crate::securemul::tests::make_context(&ring, &participants);
        let mut secure_sort_output = Vec::new();

        let input = [
            (1, 0, 0),
            (0, 0, 0),
            (0, 1, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ]
        .to_vec();
        let mut shares = [Vec::new(), Vec::new(), Vec::new()];

        for iter in input {
            let replicated_ss =
                crate::replicated_secret_sharing::tests::secret_share(iter.0, iter.1, iter.2);
            shares[0].push(replicated_ss.0);
            shares[1].push(replicated_ss.1);
            shares[2].push(replicated_ss.2);
        }

        for i in 0..3 {
            let secure_sort = SecureSort::<TestHelper, Fp31> {
                context: &context[i],
                share_of_one: match i {
                    0 => ReplicatedSecretSharing::new(Fp31::from(1_u8), Fp31::from(0_u8)),
                    1 => ReplicatedSecretSharing::new(Fp31::from(0_u8), Fp31::from(0_u8)),
                    _ => ReplicatedSecretSharing::new(Fp31::from(0_u8), Fp31::from(1_u8)),
                },
            };
            secure_sort_output.push(secure_sort.execute(&shares[i]).await);
        }

        let expected_sort_output = [5_u128, 1, 6, 2, 3, 4].as_ref();

        (0..secure_sort_output[0].len()).for_each(|i| {
            assert_eq!(
                secure_sort_output[0][i] + secure_sort_output[1][i] + secure_sort_output[2][i],
                ReplicatedSecretSharing::new(
                    Fp31::from(expected_sort_output[i]),
                    Fp31::from(expected_sort_output[i])
                )
            );
        });
    }
}
