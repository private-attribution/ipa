use subtle::ConstantTimeEq;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        RecordId,
        basics::{malicious_reveal, mul::semi_honest_multiply, step::CheckZeroStep as Step},
        context::Context,
        prss::{FromRandom, SharedRandomness},
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

/// A very simple protocol to check if a replicated secret sharing is a sharing of zero.
///
/// NOTE: this protocol leaks information about `v` the helpers. Please only use this in cases where
/// this type of information leakage is acceptable, such as where `v` is the product of a secret value
/// and a random, unknown value.
///
/// This is an implementation of PROTOCOL 3.7 from the paper:
/// Fast Large-Scale Honest-Majority MPC for Malicious Adversaries
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// The parties start out holding a replicated secret sharing of a value `v`, which they would like to check for equality to zero.
/// First, the parties generate a secret sharing of a random value `r`, which is not known to any of them.
/// Next, the parties compute a secret sharing of `r * v` using a multiplication protocol that is secure up to an additive attack.
/// Then, the parties reveal (sometimes called "open") the secret sharing of `r * v`
/// If `v` was a secret sharing of zero, this revealed value will also be zero.
/// On the other hand, if `v` was NOT a secret sharing of zero, then there are two possibilities:
/// 1.) If the randomly chosen value `r` just so happenned to be zero, then the revealed value will be zero.
/// This will happen with probability `1/|F|` (where `|F|` denotes the cardinality of the field)
/// 2.) If the randomly chosen value `r` is any other value in the field aside from zero, then the revealed value will NOT be zero.
///
/// Clearly, the accuracy of this protocol is highly dependent on the field that is used.
/// In a large field, like the integers modulo 2^31 - 1, the odds of `malicious_check_zero` returning "true"
/// when `v` is NOT actually a sharing of zero is extrmely small; it is less than one two billion odds.
/// In a silly field, like our test field of the integers modulo 31, the odds are very good. It'll incorrectly return "true"
/// about 3.2% of the time.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// If the full reveal of `rv_share` does not return a value, which would only happen if the
/// reveal implementation is broken.
pub async fn malicious_check_zero<C, F>(
    ctx: C,
    record_id: RecordId,
    v: &Replicated<F>,
) -> Result<bool, Error>
where
    C: Context,
    F: Field + FromRandom + ConstantTimeEq,
{
    let r_sharing: Replicated<F> = ctx.prss().generate(record_id);

    let rv_share =
        semi_honest_multiply(ctx.narrow(&Step::MultiplyWithR), record_id, &r_sharing, v).await?;
    let rv = F::from_array(
        &malicious_reveal(ctx.narrow(&Step::RevealR), record_id, None, &rv_share)
            .await?
            .expect("full reveal should always return a value"),
    );

    Ok(rv.ct_eq(&F::ZERO).into())
}

#[cfg(all(test, unit_test))]
mod tests {
    use futures_util::future::try_join3;

    use super::malicious_check_zero;
    use crate::{
        error::Error,
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::{RecordId, context::Context},
        rand::thread_rng,
        secret_sharing::{IntoShares, SharedValue},
        test_fixture::TestWorld,
    };

    #[tokio::test]
    async fn basic() -> Result<(), Error> {
        let world = TestWorld::default();
        let context = world.contexts().map(|ctx| ctx.set_total_records(1));
        let mut rng = thread_rng();
        let mut counter = 0_u32;

        for v in 0..u32::from(Fp31::PRIME) {
            let v = Fp31::truncate_from(v);
            let mut num_false_positives = 0;
            for _ in 0..10 {
                let v_shares = v.share_with(&mut rng);
                let record_id = RecordId::from(0_u32);
                let iteration = format!("{counter}");
                counter += 1;

                let protocol_output = try_join3(
                    malicious_check_zero(context[0].narrow(&iteration), record_id, &v_shares[0]),
                    malicious_check_zero(context[1].narrow(&iteration), record_id, &v_shares[1]),
                    malicious_check_zero(context[2].narrow(&iteration), record_id, &v_shares[2]),
                )
                .await?;

                // All three helpers should always get the same result
                assert_eq!(protocol_output.0, protocol_output.1);
                assert_eq!(protocol_output.1, protocol_output.2);

                if v == Fp31::ZERO {
                    // When it actually is a secret sharing of zero
                    // the helpers should definitely all receive "true"
                    assert!(protocol_output.0);
                    assert!(protocol_output.1);
                    assert!(protocol_output.2);
                } else if protocol_output.0 {
                    // Unfortunately, there is a small chance of an incorrect
                    // "true", even in when the secret shared value is NOT zero.
                    // Since we will test out 10 different random secret sharings
                    // let's count how many false positives we get. Odds are there
                    // will be 0, 1, or maybe 2 out of 10
                    if protocol_output.0 {
                        num_false_positives += 1;
                    }
                }
            }

            // Fp31 is just too small of a field.
            // Through random chance, it'll incorrectly return "true"
            // one time in 31. The odds of incorrectly returning "true"
            // 5 times or more is... small...
            assert!(num_false_positives < 5);
        }

        Ok(())
    }
}
