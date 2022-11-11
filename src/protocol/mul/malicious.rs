use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::mul::SemiHonestMul;
use crate::protocol::{
    context::ProtocolContext, malicious::SecurityValidatorAccumulator, RecordId,
};
use crate::secret_sharing::MaliciousReplicated;
use futures::future::try_join;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    DuplicateMultiply,
    RandomnessForValidation,
}

impl crate::protocol::Step for Step {}

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
pub struct MaliciouslySecureMul<'a, F: Field> {
    ctx: ProtocolContext<'a, MaliciousReplicated<F>, F>,
    record_id: RecordId,
    accumulator: SecurityValidatorAccumulator<F>,
}

impl<'a, F: Field> MaliciouslySecureMul<'a, F> {
    #[must_use]
    pub fn new(
        ctx: ProtocolContext<'a, MaliciousReplicated<F>, F>,
        record_id: RecordId,
        accumulator: SecurityValidatorAccumulator<F>,
    ) -> Self {
        Self {
            ctx,
            record_id,
            accumulator,
        }
    }

    /// Executes two parallel multiplications;
    /// `A * B`, and `rA * B`, yielding both `AB` and `rAB`
    /// both `AB` and `rAB` are provided to the security validator
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    /// ## Panics
    /// Panics if the mutex is found to be poisoned
    pub async fn execute(
        self,
        a: MaliciousReplicated<F>,
        b: MaliciousReplicated<F>,
    ) -> Result<MaliciousReplicated<F>, BoxError> {
        // being clever and assuming a clean context...
        let duplicate_multiply_ctx = self.ctx.narrow(&Step::DuplicateMultiply);
        let random_constant_prss = self.ctx.narrow(&Step::RandomnessForValidation).prss();
        let (ab, rab) = {
            // Convince compiler that neither a nor b will be used across the await point
            // to relax the requirement for either of them to be Sync
            let a_x = a.x();
            let a_rx = a.rx();
            let b_x = b.x();
            try_join(
                SemiHonestMul::new(self.ctx.to_semi_honest(), self.record_id).execute(a_x, b_x),
                SemiHonestMul::new(duplicate_multiply_ctx.to_semi_honest(), self.record_id)
                    .execute(a_rx, b_x),
            )
            .await?
        };

        let malicious_ab = MaliciousReplicated::new(ab, rab);

        self.accumulator
            .accumulate_macs(&random_constant_prss, self.record_id, malicious_ab);

        Ok(malicious_ab)
    }
}
