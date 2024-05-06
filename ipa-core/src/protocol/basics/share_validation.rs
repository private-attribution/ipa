use futures_util::future::try_join;

use crate::{
    error::Error,
    helpers::{
        hashing::{compute_hash, Hash},
        Direction,
    },
    protocol::{context::Context, RecordId},
    secret_sharing::SharedValue,
};

/// This function checks that a vector of shares are consistent across helpers
/// i.e. `H1` holds `(x0,x1)`, `H2` holds `(x1,x2)`, `H3` holds `(x2,x0)`
/// the function verifies that `H1.x0 == H3.x0`, `H1.x1 == H2.x1`, `H2.x2 == H3.x2`
///
/// We use a hash based approach that is secure in the random oracle model
/// further, only one of left and right helper check that it is zero
/// this is might not be sufficient in some applications to prevent malicious behavior
///
/// The left helper simply hashes the vector and sends it to the right,
/// the right helper negates his vector, hashes it and compares it to the received hash
///
/// # Errors
/// propagates errors from send and receive
pub async fn validate_replicated_shares<'a, 'b, C, I, J, S>(
    ctx: C,
    input_left: I,
    input_right: J,
) -> Result<(), Error>
where
    C: Context,
    I: IntoIterator<Item = &'a S>,
    J: IntoIterator<Item = &'b S>,
    S: SharedValue,
{
    // compute hash of `left`
    let hash_left = compute_hash(input_left);

    // set up context
    let ctx_new = &(ctx.set_total_records(1usize));
    // set up channels
    let send_channel = &ctx_new.send_channel::<Hash>(ctx.role().peer(Direction::Right));
    let receive_channel = &ctx_new.recv_channel::<Hash>(ctx.role().peer(Direction::Left));

    let ((), hash_right) = try_join(
        // send hash
        send_channel.send(RecordId::FIRST, compute_hash(input_right)),
        receive_channel.receive(RecordId::FIRST),
    )
    .await?;

    if hash_left == hash_right {
        Ok(())
    } else {
        Err(Error::InconsistentShares)
    }
}

/// This function is similar to validate the consistency of shares with the difference
/// that it validates that the shares sum to zero rather than being identical
/// i.e. `H1` holds `(x0,x1)`, `H2` holds `(x1,x2)`, `H3` holds `(x2,x0)`
/// the function verifies that `H1.x0 == -H3.x0`, `H1.x1 == -H2.x1`, `H2.x2 == -H3.x2`
///
/// We use a hash based approach that is secure in the random oracle model
/// further, only one of left and right helper check that it is zero
/// this is sufficient for Distributed Zero Knowledge Proofs
/// but might not be sufficient for other applications
///
/// The left helper simply hashes the vector and sends it to the right,
/// the right helper negates his vector, hashes it and compares it to the received hash
///
/// # Errors
/// propagates errors from `validate_replicated_shares`
pub async fn validate_sum_to_zero<'a, C, I, S>(
    ctx: C,
    input_left: I,
    input_right: I,
) -> Result<(), Error>
where
    C: Context,
    I: IntoIterator<Item = &'a S>,
    S: SharedValue,
{
    // compute left.neg
    let left_neg = input_left.into_iter().map(|x| x.neg()).collect::<Vec<_>>();

    validate_replicated_shares(ctx, &left_neg, input_right).await
}

#[cfg(all(test, unit_test))]
mod test {
    use std::ops::Neg;

    use ipa_macros::Step;
    use rand::{thread_rng, Rng};

    use crate::{
        error::Error,
        ff::{Field, Fp61BitPrime},
        protocol::{basics::share_validation::validate_sum_to_zero, context::Context},
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    #[derive(Step)]
    pub(crate) enum Step {
        Correctness,
        Misaligned,
        Changed,
    }

    // Test sum to zero
    // by generating a vec of zero values
    // secret share it
    // and run the sum to zero protocol
    #[test]
    fn validate_sum_to_zero_test() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let len: usize = rng.gen_range(50..100);

            let mut r = vec![Fp61BitPrime::ZERO; len];
            r.iter_mut().for_each(|x| *x = rng.gen());

            let _ = world
                .semi_honest(r.into_iter(), |ctx, input| async move {
                    let r_right = input.iter().map(|x| x.right().neg()).collect::<Vec<_>>();
                    let mut r_left = input
                        .iter()
                        .map(ReplicatedSecretSharing::left)
                        .collect::<Vec<_>>();

                    validate_sum_to_zero(ctx.narrow(&Step::Correctness), &r_left, &r_right)
                        .await
                        .unwrap();

                    // check misaligned causes error
                    let error = validate_sum_to_zero(
                        ctx.narrow(&Step::Misaligned),
                        &r_left[0..len - 1],
                        &r_right[1..len],
                    )
                    .await;

                    assert!(matches!(error, Err(Error::InconsistentShares)));

                    // check changing causes error
                    r_left[5] += Fp61BitPrime::ONE;

                    let error = validate_sum_to_zero(
                        ctx.narrow(&Step::Changed),
                        &r_left[0..len - 1],
                        &r_right[1..len],
                    )
                    .await;

                    assert!(matches!(error, Err(Error::InconsistentShares)));
                })
                .await;
        });
    }
}
