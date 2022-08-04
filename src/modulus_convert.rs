use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::ring::Ring;
use crate::prss::Participant;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use crate::securemul::{ProtocolContext, SecureMul};
use bit_vec::BitVec;
use futures::future::try_join_all;

#[derive(Debug)]
pub enum HelperIdentity {
    H1,
    H2,
    H3,
}

pub struct RandomShareGenerationHelper<'a> {
    rng: &'a Participant,
    identity: HelperIdentity,
}

impl<'a> RandomShareGenerationHelper<'a> {
    #[must_use]
    pub fn new(rng: &'a Participant, identity: HelperIdentity) -> Self {
        Self { rng, identity }
    }

    #[must_use]
    pub fn split_binary<T: Field>(
        &self,
        left: bool,
        right: bool,
    ) -> (
        ReplicatedSecretSharing<T>,
        ReplicatedSecretSharing<T>,
        ReplicatedSecretSharing<T>,
    ) {
        let left = u128::from(left);
        let right = u128::from(right);
        match self.identity {
            HelperIdentity::H1 => (
                ReplicatedSecretSharing::new(T::from(left), T::ZERO),
                ReplicatedSecretSharing::new(T::ZERO, T::from(right)),
                ReplicatedSecretSharing::new(T::ZERO, T::ZERO),
            ),
            HelperIdentity::H2 => (
                ReplicatedSecretSharing::new(T::ZERO, T::ZERO),
                ReplicatedSecretSharing::new(T::from(left), T::ZERO),
                ReplicatedSecretSharing::new(T::ZERO, T::from(right)),
            ),
            HelperIdentity::H3 => (
                ReplicatedSecretSharing::new(T::ZERO, T::from(right)),
                ReplicatedSecretSharing::new(T::ZERO, T::ZERO),
                ReplicatedSecretSharing::new(T::from(left), T::ZERO),
            ),
        }
    }

    /// Runs the protocol to generate a pair of secret sharings of a random value "r" in [0, 1]
    /// None of the three helpers will know what the value of "r" is
    ///
    /// ## Errors
    /// Lots of things may go wrong here, as this method calls the "Secure Mult" implementation
    /// If there is a timeout (or other error) it should be signalled in the response
    pub async fn gen_r_pairs<T: Field, R: Ring>(
        &self,
        idx: u128,
        ctx: &ProtocolContext<'_, R>,
    ) -> Result<Vec<(bool, ReplicatedSecretSharing<T>)>, BoxError> {
        let mut idx = idx;
        let (left, right) = self.rng.generate_values(idx);
        let size: usize = u128::BITS.try_into().unwrap();
        let mut output = Vec::with_capacity(size);
        let left_bits = BitVec::from_bytes(&left.to_be_bytes());
        let right_bits = BitVec::from_bytes(&right.to_be_bytes());
        let mut mult_1_futures = Vec::with_capacity(size);
        for i in 0..size {
            let left_bit = left_bits[i];
            let right_bit = right_bits[i];
            let r_shares = self.split_binary(left_bit, right_bit);

            let future = match self.identity {
                HelperIdentity::H1 => {
                    SecureMul::new(r_shares.0, r_shares.1, idx, true, false, false)
                }
                HelperIdentity::H2 => {
                    SecureMul::new(r_shares.0, r_shares.1, idx, false, true, false)
                }
                HelperIdentity::H3 => {
                    SecureMul::new(r_shares.0, r_shares.1, idx, false, false, true)
                }
            }
            .execute(ctx);
            mult_1_futures.push(future);

            idx += 1;
        }

        let r1_x_r2_shares = try_join_all(mult_1_futures).await.unwrap();

        let mut mult_2_futures = Vec::with_capacity(size);
        let mut r1_xor_r2_shares = Vec::with_capacity(size);

        for i in 0..size {
            let left_bit = left_bits[i];
            let right_bit = right_bits[i];
            let r_shares = self.split_binary(left_bit, right_bit);

            let r1_x_r2 = r1_x_r2_shares[i];

            let r1_xor_r2 = r_shares.0 + r_shares.1 - (r1_x_r2 * T::from(2));
            r1_xor_r2_shares.push(r1_xor_r2);

            let future = match self.identity {
                HelperIdentity::H1 => SecureMul::new(r1_xor_r2, r_shares.2, idx, false, true, true),
                HelperIdentity::H2 => SecureMul::new(r1_xor_r2, r_shares.2, idx, true, false, true),
                HelperIdentity::H3 => {
                    SecureMul::new(r1_xor_r2, r_shares.2, idx, true, false, false)
                }
            }
            .execute(ctx);
            mult_2_futures.push(future);

            idx += 1;
        }

        let r1_xor_r2_x_r3_shares = try_join_all(mult_2_futures).await.unwrap();

        for i in 0..size {
            let left_bit = left_bits[i];
            let right_bit = right_bits[i];
            let r_shares = self.split_binary(left_bit, right_bit);

            let r1_xor_r2_x_r3 = r1_xor_r2_x_r3_shares[i];
            let r1_xor_r2 = r1_xor_r2_shares[i];

            let r1_xor_r2_xor_r3 = r1_xor_r2 + r_shares.2 - (r1_xor_r2_x_r3 * T::from(2));

            output.push((left_bit, r1_xor_r2_xor_r3));
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::BoxError;
    use crate::modulus_convert::{HelperIdentity, RandomShareGenerationHelper};

    use crate::field::Fp31;
    use crate::helpers::ring::mock::make_three as make_ring_of_three;
    use crate::helpers::ring::mock::TestHelper;
    use crate::prss::test::make_three as make_three_participants;
    use crate::replicated_secret_sharing::tests::assert_secret_shared_value;
    use crate::replicated_secret_sharing::tests::assert_valid_secret_sharing;
    use crate::securemul::tests::make_context;

    #[tokio::test]
    async fn gen_pairs() -> Result<(), BoxError> {
        let ring = make_ring_of_three();
        let participants = make_three_participants();
        let context = make_context(&ring, &participants);

        let h1 = RandomShareGenerationHelper::new(&participants.0, HelperIdentity::H1);
        let h2 = RandomShareGenerationHelper::new(&participants.1, HelperIdentity::H2);
        let h3 = RandomShareGenerationHelper::new(&participants.2, HelperIdentity::H3);

        let idx = 10;

        let result_shares = tokio::try_join!(
            h1.gen_r_pairs::<Fp31, TestHelper>(idx, &context[0]),
            h2.gen_r_pairs::<Fp31, TestHelper>(idx, &context[1]),
            h3.gen_r_pairs::<Fp31, TestHelper>(idx, &context[2]),
        )?;

        for i in 0..128 {
            let h1_share = result_shares.0[i];
            let h2_share = result_shares.1[i];
            let h3_share = result_shares.2[i];

            let expected_value: u128 = u128::from(h1_share.0 ^ h2_share.0 ^ h3_share.0);

            assert_valid_secret_sharing(h1_share.1, h2_share.1, h3_share.1);
            assert_secret_shared_value(h1_share.1, h2_share.1, h3_share.1, expected_value);
        }

        Ok(())
    }
}
