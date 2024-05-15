use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{mul::semi_honest_multiply, semi_honest_reveal, step::CheckZeroStep as Step},
        context::Context,
        prss::{FromRandom, SharedRandomness},
        RecordId,
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
/// In a large field, like the integers modulo 2^31 - 1, the odds of `semi_honest_check_zero` returning "true"
/// when `v` is NOT actually a sharing of zero is extrmely small; it is less than one two billion odds.
/// In a silly field, like our test field of the integers modulo 31, the odds are very good. It'll incorrectly return "true"
/// about 3.2% of the time.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
///
/// ## Panics
/// Panics if `semi_honest_reveal` reveal returns `None`, which should not happen, because we are
/// not doing a partial reveal.
pub async fn semi_honest_check_zero<C: Context, F: Field + FromRandom>(
    ctx: C,
    record_id: RecordId,
    v: &Replicated<F>,
) -> Result<bool, Error> {
    let r_sharing: Replicated<F> = ctx.prss().generate(record_id);

    let rv_share =
        semi_honest_multiply(ctx.narrow(&Step::MultiplyWithR), record_id, &r_sharing, v).await?;
    // TODO: is it really okay to be doing a semi-honest reveal here?
    let rv = F::from_array(
        &semi_honest_reveal(&rv_share, ctx.narrow(&Step::RevealR), record_id, None)
            .await?
            .expect("non-partial reveal should always return a value"),
    );

    Ok(rv == F::ZERO)
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::semi_honest_check_zero;
    use crate::{
        error::Error,
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::{context::Context, RecordId},
        secret_sharing::SharedValue,
        test_fixture::{Runner, TestWorld},
    };

    #[tokio::test]
    async fn basic() -> Result<(), Error> {
        let world = TestWorld::default();

        for v in 0..u32::from(Fp31::PRIME) {
            let v = Fp31::truncate_from(v);
            let mut num_false_positives = 0;
            for _ in 0..10 {
                let results = world
                    .semi_honest(v, |ctx, v_share| async move {
                        semi_honest_check_zero(ctx.set_total_records(1), RecordId::FIRST, &v_share)
                            .await
                    })
                    .await
                    .map(Result::unwrap);

                // All three helpers should always get the same result
                assert_eq!(results[0], results[1]);
                assert_eq!(results[1], results[2]);

                if v == Fp31::ZERO {
                    // When it actually is a secret sharing of zero
                    // the helpers should definitely all receive "true"
                    assert!(results[0]);
                    assert!(results[1]);
                    assert!(results[2]);
                } else if results[0] {
                    // Unfortunately, there is a small chance of an incorrect
                    // "true", even in when the secret shared value is NOT zero.
                    // Since we will test out 10 different random secret sharings
                    // let's count how many false positives we get. Odds are there
                    // will be 0, 1, or maybe 2 out of 10
                    if results[0] {
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
