use std::fmt::Debug;

use futures::future::try_join;
use ipa_macros::step;
use strum::AsRefStr;

use crate::{
    error::Error,
    protocol::{
        basics::{MultiplyZeroPositions, SecureMul, ZeroPositions},
        context::{Context, UpgradedMaliciousContext},
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
        ReplicatedSecretSharing,
    },
};

#[step]
pub(crate) enum Step {
    DuplicateMultiply,
    RandomnessForValidation,
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
    ctx: UpgradedMaliciousContext<'_, F>,
    record_id: RecordId,
    a: &MaliciousReplicated<F>,
    b: &MaliciousReplicated<F>,
    zeros_at: MultiplyZeroPositions,
) -> Result<MaliciousReplicated<F>, Error>
where
    F: ExtendableField,
{
    use crate::{
        protocol::context::SpecialAccessToUpgradedContext,
        secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
    };

    let duplicate_multiply_ctx = ctx.narrow(&Step::DuplicateMultiply);
    let random_constant_ctx = ctx.narrow(&Step::RandomnessForValidation);
    let b_x = b.x().access_without_downgrade();

    //
    // This code is an optimization to our malicious compiler that is drawn from:
    // "Field Extension in Secret-Shared Form and Its Applications to Efficient Secure Computation"
    // R. Kikuchi, N. Attrapadung, K. Hamada, D. Ikarashi, A. Ishida, T. Matsuda, Y. Sakai, and J. C. N. Schuldt
    // <https://eprint.iacr.org/2019/386.pdf>
    //
    // See protocol 4.15
    // In Step 4: "Circuit emulation:", it says:
    //
    // If G_j is a multiplication gate: Given pairs `([x], [[ȓ · x]])` and `([y], [[ȓ · y]])` on the left and right input wires
    // respectively, the parties compute `([x · y], [[ȓ · x · y]])` as follows:
    // (a) The parties call `F_mult` on `[x]` and `[y]` to receive `[x · y]`.
    // (b) The parties locally compute the induced share [[y]] = f([y], 0, . . . , 0).
    // (c) The parties call `Ḟ_mult` on `[[ȓ · x]]` and `[[y]]` to receive `[[ȓ · x · y]]`.
    //
    let b_induced_share = Replicated::new(b_x.left().to_extended(), b_x.right().to_extended());
    let (ab, rab) = try_join(
        a.x().access_without_downgrade().multiply_sparse(
            b_x,
            ctx.base_context(),
            record_id,
            zeros_at,
        ),
        a.rx().multiply_sparse(
            &b_induced_share,
            duplicate_multiply_ctx.base_context(),
            record_id,
            (ZeroPositions::Pvvv, zeros_at.1),
        ),
    )
    .await?;

    let malicious_ab = MaliciousReplicated::new(ab, rab);
    random_constant_ctx.accumulate_macs(record_id, &malicious_ab);

    Ok(malicious_ab)
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::Fp31,
        protocol::{basics::SecureMul, context::Context, RecordId},
        rand::{thread_rng, Rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let res = world
            .upgraded_malicious((a, b), |ctx, (a, b)| async move {
                a.multiply(&b, ctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }
}
