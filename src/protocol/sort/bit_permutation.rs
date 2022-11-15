use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};

use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        context::ProtocolContext, sort::BitPermutationStep::ShareOfOne, RecordId, RECORD_0,
    },
    secret_sharing::SecretSharing,
};

use crate::protocol::mul::SecureMul;
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

/// This is an implementation of `GenBitPerm` (Algorithm 3) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
#[derive(Debug)]
pub struct BitPermutation<'a, F, S> {
    input: &'a [S],
    _marker: PhantomData<F>,
}

impl<'a, S: SecretSharing<F> + Copy, F: Field> BitPermutation<'a, F, S> {
    pub fn new(input: &'a [S]) -> BitPermutation<'a, F, S> {
        Self {
            input,
            _marker: PhantomData,
        }
    }

    #[embed_doc_image("bit_permutation", "images/sort/bit_permutations.png")]
    /// Protocol to compute a secret sharing of a permutation, after sorting on just one bit.
    ///
    /// At a high level, the protocol works as follows:
    /// 1. Start with a list of `n` secret shares `[x_1]` ... `[x_n]` where each is a secret sharing of either zero or one.
    /// 2. Create a vector of length `2*n` where the first `n` rows have the values `[1 - x_1]` ... `[1 - x_n]`
    /// and the next `n` rows have the value `[x_1]` ... `[x_n]`
    /// 3. Compute a new vector of length `2*n` by computing the running sum of the vector from step 2.
    /// 4. Compute another vector of length `2*n` by multipling the vectors from steps 2 and 3 element-wise.
    /// 5. Compute the final output, a vector of length `n`. Each element `i` in this output vector is the sum of
    /// the elements at index `i` and `i+n` from the vector computed in step 4.
    ///
    /// ![Bit Permutation steps][bit_permutation]
    /// ## Panics
    /// In case the function is unable to get double size of output from multiplication step, the code will panic
    ///
    /// ## Errors
    /// It will propagate errors from multiplication protocol.
    pub async fn execute(&self, ctx: ProtocolContext<'a, S, F>) -> Result<Vec<S>, BoxError>
    where
        ProtocolContext<'a, S, F>: SecureMul<F, Share = S>,
    {
        let share_of_one = S::one(
            ctx.role(),
            ctx.narrow(&ShareOfOne).prss().generate_replicated(RECORD_0),
        );

        let mult_input = self
            .input
            .iter()
            .map(move |x: &S| share_of_one - *x)
            .chain(self.input.iter().copied())
            .scan(S::default(), |sum, x| {
                *sum += x;
                Some((x, *sum))
            });

        let async_multiply =
            zip(repeat(ctx), mult_input)
                .enumerate()
                .map(|(i, (ctx, (x, sum)))| async move {
                    ctx.multiply(RecordId::from(i), x, sum).await
                });
        let mut mult_output = try_join_all(async_multiply).await?;

        assert_eq!(mult_output.len(), self.input.len() * 2);
        // Generate permutation location
        let len = mult_output.len() / 2;
        for i in 0..len {
            let val = mult_output[i + len];
            // we are subtracting "1" from the result since this protocol returns 1-index permutation whereas all other
            // protocols expect 0-indexed permutation
            mult_output[i] += val - share_of_one;
        }
        mult_output.truncate(len);

        Ok(mult_output)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        ff::Fp31,
        protocol::{sort::bit_permutation::BitPermutation, QueryId},
        test_fixture::{make_contexts, make_world, share, validate_list_of_shares},
    };

    #[tokio::test]
    pub async fn bit_permutation() {
        let world = make_world(QueryId);
        let [ctx0, ctx1, ctx2] = make_contexts::<Fp31>(&world);
        let mut rand = StepRng::new(100, 1);

        // With this input, for stable sort we expect all 0's to line up before 1's. The expected sort order is same as expected_sort_output
        let input: Vec<u128> = vec![1, 0, 1, 0, 0, 1, 0];
        let expected_sort_output = [4_u128, 0, 5, 1, 2, 6, 3];

        let input_len = input.len();
        let mut shares = [
            Vec::with_capacity(input_len),
            Vec::with_capacity(input_len),
            Vec::with_capacity(input_len),
        ];
        for iter in input {
            let share = share(Fp31::from(iter), &mut rand);
            for i in 0..3 {
                shares[i].push(share[i]);
            }
        }

        let bitperms0 = BitPermutation::new(&shares[0]);
        let bitperms1 = BitPermutation::new(&shares[1]);
        let bitperms2 = BitPermutation::new(&shares[2]);
        let h0_future = bitperms0.execute(ctx0);
        let h1_future = bitperms1.execute(ctx1);
        let h2_future = bitperms2.execute(ctx2);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), input_len);
        assert_eq!(result.1.len(), input_len);
        assert_eq!(result.2.len(), input_len);

        validate_list_of_shares(&expected_sort_output, &result);
    }
}
