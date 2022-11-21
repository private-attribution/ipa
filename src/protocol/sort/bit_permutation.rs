use std::iter::{repeat, zip};

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::ProtocolContext, context_traits::ShareOfOne, RecordId},
    secret_sharing::SecretSharing,
};

use crate::protocol::mul::SecureMul;
use embed_doc_image::embed_doc_image;
use futures::future::try_join_all;

/// This is an implementation of `GenBitPerm` (Algorithm 3) described in:
/// "An Efficient Secure Three-Party Sorting Protocol with an Honest Majority"
/// by K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, N. Kiribuchi, and B. Pinkas
/// <https://eprint.iacr.org/2019/695.pdf>.
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
pub async fn bit_permutation<'a, F: Field, S: SecretSharing<F>>(
    ctx: ProtocolContext<'a, S, F>,
    input: &[S],
) -> Result<Vec<S>, Error>
where
    ProtocolContext<'a, S, F>: SecureMul<F, Share = S> + ShareOfOne<F, Share = S>,
{
    let share_of_one = ctx.share_of_one();

    let mult_input = zip(repeat(share_of_one.clone()), input)
        .map(|(one, x)| one - x)
        .chain(input.iter().cloned())
        .scan(S::default(), |sum, x| {
            *sum += &x;
            Some((x, sum.clone()))
        });

    let async_multiply =
        zip(repeat(ctx), mult_input)
            .enumerate()
            .map(|(i, (ctx, (x, sum)))| async move {
                let record_id = RecordId::from(i);
                ctx.bind(record_id).multiply(record_id, &x, &sum).await
            });
    let mut mult_output = try_join_all(async_multiply).await?;

    debug_assert!(mult_output.len() == input.len() * 2);
    // Generate permutation location
    let len = mult_output.len() / 2;
    for i in 0..len {
        // we are subtracting "1" from the result since this protocol returns 1-index permutation whereas all other
        // protocols expect 0-indexed permutation
        let less_one = mult_output[i + len].clone() - &share_of_one;
        mult_output[i] = less_one + &mult_output[i];
    }
    mult_output.truncate(len);
    Ok(mult_output)
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use futures::future::try_join_all;
    use rand::rngs::mock::StepRng;
    use std::iter::{repeat, zip};

    use crate::{
        ff::Fp31,
        protocol::{
            malicious::SecurityValidator, sort::bit_permutation::bit_permutation, QueryId, RecordId,
        },
        secret_sharing::MaliciousReplicated,
        test_fixture::{
            make_contexts, make_world, share, validate_list_of_shares,
            validate_list_of_shares_malicious,
        },
    };

    #[tokio::test]
    pub async fn test_bit_permutation() {
        // With this input, for stable sort we expect all 0's to line up before 1's.
        // The expected sort order is same as expected_sort_output.
        const INPUT: &[u128] = &[1, 0, 1, 0, 0, 1, 0];
        const EXPECTED: &[u128] = &[4, 0, 5, 1, 2, 6, 3];

        let world = make_world(QueryId);
        let [ctx0, ctx1, ctx2] = make_contexts::<Fp31>(&world);
        let mut rand = StepRng::new(100, 1);

        let mut shares = [
            Vec::with_capacity(INPUT.len()),
            Vec::with_capacity(INPUT.len()),
            Vec::with_capacity(INPUT.len()),
        ];
        for i in INPUT {
            let share = share(Fp31::from(*i), &mut rand);
            for (i, share) in share.into_iter().enumerate() {
                shares[i].push(share);
            }
        }

        let h0_future = bit_permutation(ctx0, shares[0].as_slice());
        let h1_future = bit_permutation(ctx1, shares[1].as_slice());
        let h2_future = bit_permutation(ctx2, shares[2].as_slice());

        let result: [_; 3] = try_join_all([h0_future, h1_future, h2_future])
            .await
            .unwrap()
            .try_into()
            .unwrap();

        validate_list_of_shares(EXPECTED, &result);
    }

    #[tokio::test]
    pub async fn test_bit_permutation_malicious() -> Result<(), Error> {
        // With this input, for stable sort we expect all 0's to line up before 1's.
        // The expected sort order is same as expected_sort_output.
        const INPUT: &[u128] = &[1, 0, 1, 0, 0, 1, 0];
        const EXPECTED: &[u128] = &[4, 0, 5, 1, 2, 6, 3];

        let world = make_world(QueryId);
        let contexts = make_contexts::<Fp31>(&world);
        let contexts_vector: Vec<_> = contexts.to_vec();

        let validators: Vec<_> = contexts_vector
            .iter()
            .map(|ctx| SecurityValidator::new(ctx.narrow("MaliciousValidate")))
            .collect();

        let mut rand = StepRng::new(100, 1);

        let mut helper0_shares = Vec::with_capacity(10);
        let mut helper1_shares = Vec::with_capacity(10);
        let mut helper2_shares = Vec::with_capacity(10);
        for i in 0..INPUT.len() {
            let [sh0, sh1, sh2] = share(Fp31::from(INPUT[i]), &mut rand);
            helper0_shares.push(sh0);
            helper1_shares.push(sh1);
            helper2_shares.push(sh2);
        }

        let malicious_inputs = try_join_all(
            zip(
                zip(contexts_vector, validators.iter()),
                [helper0_shares, helper1_shares, helper2_shares],
            )
            .map(|((ctx, v), shares)| async move {
                try_join_all(
                    zip(
                        repeat(v.r_share()),
                        zip(repeat(v.accumulator().clone()), zip(shares, repeat(ctx))),
                    )
                    .enumerate()
                    .map(|(i, (r_share, (acc, (s, ctx))))| async move {
                        let record_id = RecordId::from(i);
                        ctx.narrow("upgrade_inputs")
                            .upgrade_to_malicious(acc, r_share.clone(), record_id, s)
                            .await
                    }),
                )
                .await
            }),
        )
        .await?;

        let h0_shares: Vec<MaliciousReplicated<Fp31>> = malicious_inputs[0]
            .iter()
            .map(|bit| bit.1.clone())
            .collect();
        let h1_shares: Vec<MaliciousReplicated<Fp31>> = malicious_inputs[1]
            .iter()
            .map(|bit| bit.1.clone())
            .collect();
        let h2_shares: Vec<MaliciousReplicated<Fp31>> = malicious_inputs[2]
            .iter()
            .map(|bit| bit.1.clone())
            .collect();

        let h0_future = bit_permutation(
            malicious_inputs[0][0].0.narrow("bit_permutation"),
            &h0_shares,
        );
        let h1_future = bit_permutation(
            malicious_inputs[1][0].0.narrow("bit_permutation"),
            &h1_shares,
        );
        let h2_future = bit_permutation(
            malicious_inputs[2][0].0.narrow("bit_permutation"),
            &h2_shares,
        );

        let result: [_; 3] = try_join_all([h0_future, h1_future, h2_future])
            .await?
            .try_into()
            .unwrap();

        validate_list_of_shares_malicious(EXPECTED, &result);

        let _validation_results = try_join_all(zip(validators, malicious_inputs).map(
            |(v, contexts_and_shares)| async move {
                v.validate(contexts_and_shares[0].0.narrow("validate_circuit"))
                    .await
            },
        ))
        .await?;

        Ok(())
    }
}
