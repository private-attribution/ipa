use futures_util::future::try_join;

use crate::{
    error::Error,
    helpers::{Direction, MpcReceivingEnd, SendingEnd},
    protocol::{
        context::Context,
        ipa_prf::malicious_security::hashing::{compute_hash, Hash},
        RecordId,
    },
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
pub async fn validate_replicated_shares<C, S>(
    ctx: C,
    input_left: &[S],
    input_right: &[S],
) -> Result<(), Error>
where
    C: Context,
    S: SharedValue,
{
    // compute hash of `left.neg` and `right`
    let hash_left = compute_hash(input_left);

    // set up context
    let ctx_new = &(ctx.set_total_records(1usize));
    // set up channels
    let send_channel: &SendingEnd<_, Hash> =
        &ctx_new.send_channel(ctx.role().peer(Direction::Right));
    let receive_channel: &MpcReceivingEnd<Hash> =
        &ctx_new.recv_channel(ctx.role().peer(Direction::Left));

    let ((), hash_right) = try_join(
        // send hash
        send_channel.send(RecordId::from(0usize), compute_hash(input_right)),
        receive_channel.receive(RecordId::from(0usize)),
    )
    .await?;

    debug_assert_eq!(hash_left, hash_right);

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
pub async fn validate_sum_to_zero<C, S>(
    ctx: C,
    input_left: &[S],
    input_right: &[S],
) -> Result<(), Error>
where
    C: Context,
    S: SharedValue,
{
    validate_replicated_shares(
        ctx,
        input_left,
        &input_right.iter().map(|x| x.neg()).collect::<Vec<_>>(),
    )
    .await
}

#[cfg(all(test, unit_test))]
mod test {
    use std::ops::Neg;

    use rand::{thread_rng, Rng};

    use crate::{
        ff::Fp61BitPrime,
        protocol::basics::share_validation::validate_sum_to_zero,
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    // Test sum to zero
    // by generating a vec of zero values
    // secret share it
    // and run the sum to zero protocol
    #[test]
    fn validate_sum_to_zero_test() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let len: usize = rng.gen::<usize>() % 99usize + 1;

            let mut r = vec![Fp61BitPrime::ZERO; len];
            r.iter_mut().for_each(|x| *x = rng.gen());

            let _ = world
                .semi_honest(r.into_iter(), |ctx, input| async move {
                    let r_right = input.iter().map(|x| x.right().neg()).collect::<Vec<_>>();
                    let r_left = input
                        .iter()
                        .map(ReplicatedSecretSharing::left)
                        .collect::<Vec<_>>();

                    validate_sum_to_zero(ctx, &r_left, &r_right).await.unwrap();
                })
                .await;
        });
    }
}
