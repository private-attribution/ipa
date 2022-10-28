use crate::{
    error::BoxError,
    field::Field,
    helpers::fabric::Network,
    protocol::{context::ProtocolContext, reveal::reveal, RecordId},
    secret_sharing::Replicated,
};

use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've multiplied their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DValue<F> {
    d: F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    MultiplyWithR,
    RevealR,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MultiplyWithR => "multiply_with_r",
            Self::RevealR => "reveal_r",
        }
    }
}

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
/// In a large field, like the integers modulo 2^31 - 1, the odds of `check_zero` returning "true"
/// when `v` is NOT actually a sharing of zero is extrmely small; it is less than one two billion odds.
/// In a silly field, like our test field of the integers modulo 31, the odds are very good. It'll incorrectly return "true"
/// about 3.2% of the time.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
#[allow(dead_code)]
pub async fn check_zero<F: Field, N: Network>(
    ctx: ProtocolContext<'_, N, F>,
    record_id: RecordId,
    v: Replicated<F>,
) -> Result<bool, BoxError> {
    let prss = &ctx.prss();
    let r_sharing = prss.generate_replicated(record_id);

    let rv_share = ctx
        .narrow(&Step::MultiplyWithR)
        .multiply(record_id)
        .await
        .execute(r_sharing, v)
        .await?;
    let rv = reveal(ctx.narrow(&Step::RevealR), record_id, rv_share).await?;

    Ok(rv == F::ZERO)
}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::field::{Field, Fp31};
    use crate::protocol::{check_zero::check_zero, QueryId, RecordId};
    use crate::test_fixture::{logging, make_contexts, make_world, share, TestWorld};

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = rand::thread_rng();
        let mut counter = 0;

        for v in 0..u32::from(Fp31::PRIME) {
            let v = Fp31::from(v);
            let mut num_false_positives = 0;
            for _ in 0..10 {
                let v_shares = share(v, &mut rng);
                let record_id = RecordId::from(counter);
                let iteration = format!("{}", counter);
                counter += 1;

                let protocol_output = tokio::try_join!(
                    check_zero(context[0].narrow(&iteration), record_id, v_shares[0],),
                    check_zero(context[1].narrow(&iteration), record_id, v_shares[1],),
                    check_zero(context[2].narrow(&iteration), record_id, v_shares[2],),
                )?;

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
