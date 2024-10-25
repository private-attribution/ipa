use futures_util::future::try_join;
use subtle::ConstantTimeEq;

use crate::{
    error::Error,
    helpers::{
        hashing::{compute_hash, Hash},
        Direction, TotalRecords,
    },
    protocol::{context::Context, RecordId},
    secret_sharing::SharedValue,
};

/// This function checks that a vector of shares are consistent across helpers
/// i.e. `H1` holds `(x0,x1)`, `H2` holds `(x1,x2)`, `H3` holds `(x2,x0)`
/// the function verifies that `H1.x0 == H3.x0`, `H1.x1 == H2.x1`, `H2.x2 == H3.x2`
///
/// We use a hash based approach that is secure in the random oracle model
/// further, only one of left and right helper check the equality of the shares
/// this is might not be sufficient in some applications to prevent malicious behavior
///
/// The left helper simply hashes the vector and sends it to the right,
/// the right helper hashes his vector and compares it to the received hash
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
    let ctx_new = &(ctx.set_total_records(TotalRecords::ONE));
    // set up channels
    let send_channel = ctx_new.send_channel::<Hash>(ctx.role().peer(Direction::Right));
    let receive_channel = ctx_new.recv_channel::<Hash>(ctx.role().peer(Direction::Left));

    let ((), hash_received) = try_join(
        // send hash
        send_channel.send(RecordId::FIRST, compute_hash(input_right)),
        receive_channel.receive(RecordId::FIRST),
    )
    .await?;

    if hash_left.ct_eq(&hash_received).into() {
        Ok(())
    } else {
        Err(Error::InconsistentShares)
    }
}

/// This function is similar to validate the consistency of shares with the difference
/// that it validates that tuple of shares sum to zero rather than being identical
/// i.e. `H1` holds `(H1_x0,H1_x1)`, `H2` holds `(H2_x1,H2_x2)`, `H3` holds `(H3_x2,H3_x0)`
/// the function verifies that `H1_x0 == -H3_x0`, `H1_x1 == -H2_x1`, `H2_x2 == -H3_x2`
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
pub async fn validate_three_two_way_sharing_of_zero<'a, C, I, S>(
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

    use rand::{thread_rng, Rng};

    use crate::{
        error::Error,
        ff::{Field, Fp61BitPrime},
        protocol::{
            basics::share_validation::validate_three_two_way_sharing_of_zero, context::Context,
        },
        secret_sharing::replicated::ReplicatedSecretSharing,
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    // Test three two way shares of zero
    // we generated replicated shares of a vector of random values
    // each helper party negates one of its shares
    // we then check whether validate_three_two_way_sharing_of_zero succeeds
    // we also test for failure when the shares are misaligned or one of them has been changed
    #[test]
    fn three_two_way_shares_of_zero() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let len: usize = rng.gen_range(50..100);

            let r = (0..len)
                .map(|_| rng.gen::<Fp61BitPrime>())
                .collect::<Vec<Fp61BitPrime>>();

            let _ = world
                .semi_honest(r.into_iter(), |ctx, input| async move {
                    let r_right = input
                        .iter()
                        .map(|x| x.right().neg())
                        .collect::<Vec<Fp61BitPrime>>();
                    let mut r_left = input
                        .iter()
                        .map(ReplicatedSecretSharing::left)
                        .collect::<Vec<Fp61BitPrime>>();

                    validate_three_two_way_sharing_of_zero(
                        ctx.narrow("correctness"),
                        &r_left,
                        &r_right,
                    )
                    .await
                    .unwrap();

                    // check misaligned causes error
                    let error = validate_three_two_way_sharing_of_zero(
                        ctx.narrow("misaligned"),
                        &r_left[0..len - 1],
                        &r_right[1..len],
                    )
                    .await;

                    assert!(matches!(error, Err(Error::InconsistentShares)));

                    // check changing causes error
                    r_left[5] += Fp61BitPrime::ONE;

                    let error = validate_three_two_way_sharing_of_zero(
                        ctx.narrow("changed"),
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
