use async_trait::async_trait;
use futures::future::try_join;

use crate::{
    error::Error,
    protocol::{
        RecordId,
        basics::{
            SecureMul,
            mul::{semi_honest_multiply, step::MaliciousMultiplyStep},
        },
        context::{Context, UpgradedMaliciousContext},
        prss::FromPrss,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableFieldSimd},
        semi_honest::AdditiveShare as Replicated,
    },
    sharding::ShardBinding,
};

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
pub async fn mac_multiply<F, B: ShardBinding, const N: usize>(
    ctx: UpgradedMaliciousContext<'_, F, B>,
    record_id: RecordId,
    a: &MaliciousReplicated<F, N>,
    b: &MaliciousReplicated<F, N>,
) -> Result<MaliciousReplicated<F, N>, Error>
where
    F: ExtendableFieldSimd<N>,
    Replicated<F::ExtendedField, N>: FromPrss,
{
    use crate::{
        protocol::context::SpecialAccessToUpgradedContext,
        secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
    };

    let duplicate_multiply_ctx = ctx.narrow(&MaliciousMultiplyStep::DuplicateMultiply);
    let random_constant_ctx = ctx.narrow(&MaliciousMultiplyStep::RandomnessForValidation);
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
    let b_induced_share = b_x.induced();
    let (ab, rab) = try_join(
        semi_honest_multiply(
            ctx.base_context(),
            record_id,
            a.x().access_without_downgrade(),
            b_x,
        ),
        semi_honest_multiply(
            duplicate_multiply_ctx.base_context(),
            record_id,
            a.rx(),
            &b_induced_share,
        ),
    )
    .await?;

    let malicious_ab = MaliciousReplicated::new(ab, rab);
    random_constant_ctx.accumulate_macs(record_id, &malicious_ab);

    Ok(malicious_ab)
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: ExtendableFieldSimd<N>, B: ShardBinding, const N: usize>
    SecureMul<UpgradedMaliciousContext<'a, F, B>> for MaliciousReplicated<F, N>
where
    Replicated<F::ExtendedField, N>: FromPrss,
{
    async fn multiply<'fut>(
        &self,
        rhs: &Self,
        ctx: UpgradedMaliciousContext<'a, F, B>,
        record_id: RecordId,
    ) -> Result<Self, Error>
    where
        UpgradedMaliciousContext<'a, F, B>: 'fut,
    {
        mac_multiply(ctx, record_id, self, rhs).await
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::Fp31,
        protocol::basics::SecureMul,
        rand::{Rng, thread_rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.r#gen::<Fp31>();
        let b = rng.r#gen::<Fp31>();

        let res =
            world
                .upgraded_malicious(
                    vec![(a, b)].into_iter(),
                    |ctx, record_id, (a, b)| async move {
                        a.multiply(&b, ctx, record_id).await.unwrap()
                    },
                )
                .await;

        assert_eq!(a * b, res.reconstruct()[0]);
    }
}
