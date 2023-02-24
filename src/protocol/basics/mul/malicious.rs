use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{MultiplyZeroPositions, SecureMul, ZeroPositions},
        context::{Context, MaliciousContext},
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::AdditiveShare as MaliciousReplicated,
        semi_honest::AdditiveShare as SemiHonestReplicated,
    },
};
use futures::future::try_join;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    DuplicateMultiply,
    RandomnessForValidation,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::DuplicateMultiply => "duplicate_multiply",
            Self::RandomnessForValidation => "randomness_for_validation",
        }
    }
}

///
/// Implementation drawn from:
/// "Fast Large-Scale Honest-Majority MPC for Malicious Adversaries"
/// by by K. Chida, D. Genkin, K. Hamada, D. Ikarashi, R. Kikuchi, Y. Lindell, and A. Nof
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// Protocol 5.3 "Computing Arithmetic Circuits Over Any Finite F"
/// Step 5: "Circuit Emulation"
/// (In our case, simplified slightly because δ=1)
/// When `G_k` is a multiplication gate:
/// Given tuples:  `([x], [r · x])` and `([y], [r · y])`
/// (a) The parties call `F_mult` on `[x]` and `[y]` to receive `[x · y]`
/// (b) The parties call `F_mult` on `[r · x]` and `[y]` to receive `[r · x · y]`.
///
/// As each multiplication gate affects Step 6: "Verification Stage", the Security Validator
/// must be provided. The two outputs of the multiplication, `[x · y]` and  `[r · x · y]`
/// will be provided to this Security Validator, and will update two information-theoretic MACs.
///
/// It's cricital that the functionality `F_mult` is secure up to an additive attack.
/// `SecureMult` is an implementation of the IKHC multiplication protocol, which has this property.
///

/// Executes two parallel multiplications;
/// `A * B`, and `rA * B`, yielding both `AB` and `rAB`
/// both `AB` and `rAB` are provided to the security validator
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// Panics if the mutex is found to be poisoned
pub async fn multiply<F>(
    ctx: MaliciousContext<'_, F>,
    record_id: RecordId,
    a: &MaliciousReplicated<F>,
    b: &MaliciousReplicated<F>,
    zeros_at: MultiplyZeroPositions,
) -> Result<MaliciousReplicated<F>, Error>
where
    F: Field,
{
    use crate::{
        protocol::context::SpecialAccessToMaliciousContext,
        secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
    };

    let duplicate_multiply_ctx = ctx.narrow(&Step::DuplicateMultiply);
    let random_constant_ctx = ctx.narrow(&Step::RandomnessForValidation);
    let (ab, rab) = try_join(
        SemiHonestReplicated::multiply_sparse(
            ctx.semi_honest_context(),
            record_id,
            a.x().access_without_downgrade(),
            b.x().access_without_downgrade(),
            zeros_at,
        ),
        SemiHonestReplicated::multiply_sparse(
            duplicate_multiply_ctx.semi_honest_context(),
            record_id,
            a.rx(),
            b.x().access_without_downgrade(),
            (ZeroPositions::Pvvv, zeros_at.1),
        ),
    )
    .await?;

    let malicious_ab = MaliciousReplicated::new(ab, rab);
    random_constant_ctx.accumulate_macs(record_id, &malicious_ab);

    Ok(malicious_ab)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use crate::{
        ff::Fp31,
        protocol::{basics::SecureMul, context::Context, RecordId},
        rand::{thread_rng, Rng},
        secret_sharing::replicated::malicious::AdditiveShare as MaliciousReplicated,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::new().await;

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let res = world
            .malicious((a, b), |ctx, (a, b)| async move {
                MaliciousReplicated::multiply(ctx.set_total_records(1), RecordId::from(0), &a, &b)
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }
}
