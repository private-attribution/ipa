use crate::error::Error;
use crate::ff::Field;
use crate::protocol::basics::sum_of_product::SecureSop;
use crate::protocol::{
    context::{Context, MaliciousContext},
    RecordId,
};
use crate::secret_sharing::MaliciousReplicated;
use futures::future::try_join;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    DuplicateSop,
    RandomnessForValidation,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::DuplicateSop => "duplicate_sop",
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
/// (a) The parties call `sum of product` on `[x1, x2, .., xn]` and `[y1, y2, .., yn]` to receive `[x1 · y1 + x2 · y2 + ... + xn · yn]`
/// (b) The parties call `sum of product` on `[r · (x1, x2, .., xn)]` and `[y1, y2, .., yn]` to receive `[r · (x1 · y1 + x2 · y2 + ... + xn · yn))]`.
///
/// As each multiplication gate affects Step 6: "Verification Stage", the Security Validator
/// must be provided. The two outputs of the multiplication, `[Σx · y]` and  `[Σr ·  x · y]`
/// will be provided to this Security Validator, and will update two information-theoretic MACs.
///
/// It's cricital that the functionality `F_mult` is secure up to an additive attack.
/// `SecureMult` is an implementation of the IKHC multiplication protocol, which has this property.
///

/// Executes two parallel sum of products;
/// `ΣA * B`, and `ΣrA * B`, yielding both `ΣAB` and `ΣrAB`
/// both `ΣAB` and `ΣrAB` are provided to the security validator
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// Panics if the mutex is found to be poisoned
pub async fn sum_of_products<F>(
    ctx: MaliciousContext<'_, F>,
    record_id: RecordId,
    a: &[&MaliciousReplicated<F>],
    b: &[&MaliciousReplicated<F>],
) -> Result<MaliciousReplicated<F>, Error>
where
    F: Field,
{
    use crate::protocol::context::SpecialAccessToMaliciousContext;
    use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;

    assert_eq!(a.len(), b.len());

    let duplicate_multiply_ctx = ctx.narrow(&Step::DuplicateSop);
    let random_constant_ctx = ctx.narrow(&Step::RandomnessForValidation);
    let ax = a
        .iter()
        .map(|a| a.x().access_without_downgrade())
        .collect::<Vec<_>>();
    let arx = a.iter().map(|a| a.rx()).collect::<Vec<_>>();

    let bx = b
        .iter()
        .map(|b| b.x().access_without_downgrade())
        .collect::<Vec<_>>();

    let (ab, rab) = try_join(
        ctx.semi_honest_context()
            .sum_of_products(record_id, ax.as_slice(), bx.as_slice()),
        duplicate_multiply_ctx
            .semi_honest_context()
            .sum_of_products(record_id, arx.as_slice(), bx.as_slice()),
    )
    .await?;

    let malicious_ab = MaliciousReplicated::new(ab, rab);
    random_constant_ctx.accumulate_macs(record_id, &malicious_ab);

    Ok(malicious_ab)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use crate::{
        ff::{Field, Fp31},
        protocol::{basics::sum_of_product::SecureSop, QueryId, RecordId},
        rand::{thread_rng, Rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        const MULTI_BIT_LEN: usize = 10;
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();

        let (mut av, mut bv) = (
            Vec::with_capacity(MULTI_BIT_LEN),
            Vec::with_capacity(MULTI_BIT_LEN),
        );
        let mut expected = Fp31::ZERO;
        for _ in 0..MULTI_BIT_LEN {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();
            expected += a * b;
            av.push(a);
            bv.push(b);
        }

        let res = world
            .malicious((av, bv), |ctx, (a_share, b_share)| async move {
                let a_refs = a_share.iter().collect::<Vec<_>>();
                let b_refs = b_share.iter().collect::<Vec<_>>();
                ctx.sum_of_products(RecordId::from(0), a_refs.as_slice(), b_refs.as_slice())
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(expected, res.reconstruct());
    }
}
