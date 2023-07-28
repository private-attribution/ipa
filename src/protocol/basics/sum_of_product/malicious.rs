use crate::{
    error::Error,
    helpers::Direction,
    protocol::{
        context::{Context, UpgradedMaliciousContext},
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
        ReplicatedSecretSharing,
    },
};
use futures::future::try_join;
use ipa_macros::step;
use std::fmt::Debug;
use strum::AsRefStr;

#[step]
pub(crate) enum Step {
    DuplicateSop,
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
    ctx: UpgradedMaliciousContext<'_, F>,
    record_id: RecordId,
    a: &[MaliciousReplicated<F>],
    b: &[MaliciousReplicated<F>],
) -> Result<MaliciousReplicated<F>, Error>
where
    F: ExtendableField,
{
    use crate::{
        protocol::context::SpecialAccessToUpgradedContext,
        secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
    };

    assert_eq!(a.len(), b.len());
    let vec_len = a.len();

    let duplicate_multiply_ctx = ctx.narrow(&Step::DuplicateSop);

    // generate shared randomness.
    let prss = ctx.prss();
    let duplicate_prss = duplicate_multiply_ctx.prss();
    let (s0, s1): (F, F) = prss.generate_fields(record_id);
    let (s0_m, s1_m): (F::ExtendedField, F::ExtendedField) =
        duplicate_prss.generate_fields(record_id);
    let role = ctx.role();

    // compute the value (d_i) we want to send to the right helper (i+1)
    let mut right_sops: F = s1 - s0;
    let mut right_sops_m: F::ExtendedField = s1_m - s0_m;

    for i in 0..vec_len {
        let ax = a[i].x().access_without_downgrade();
        let bx = b[i].x().access_without_downgrade();
        let arx = a[i].rx();

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
        // As "sum of products" is essentially just a multiplication, which is also secure up to an additive attack, the same applies here
        //
        let bx_induced = Replicated::new(bx.left().to_extended(), bx.right().to_extended());
        right_sops += ax.right() * bx.right() + ax.left() * bx.right() + ax.right() * bx.left();
        right_sops_m += arx.right() * bx_induced.right()
            + arx.left() * bx_induced.right()
            + arx.right() * bx_induced.left();
    }

    // notify helper on the right that we've computed our value
    try_join(
        ctx.send_channel(role.peer(Direction::Right))
            .send(record_id, right_sops),
        duplicate_multiply_ctx
            .send_channel(role.peer(Direction::Right))
            .send(record_id, right_sops_m),
    )
    .await?;

    // Sleep until helper on the left sends us their (d_i-1) value
    let (left_sops, left_sops_m): (F, F::ExtendedField) = try_join(
        ctx.recv_channel(role.peer(Direction::Left))
            .receive(record_id),
        duplicate_multiply_ctx
            .recv_channel(role.peer(Direction::Left))
            .receive(record_id),
    )
    .await?;

    let malicious_ab = MaliciousReplicated::new(
        Replicated::new(left_sops, right_sops),
        Replicated::new(left_sops_m, right_sops_m),
    );

    let random_constant_ctx = ctx.narrow(&Step::RandomnessForValidation);
    random_constant_ctx.accumulate_macs(record_id, &malicious_ab);

    Ok(malicious_ab)
}

#[cfg(all(test, unit_test))]
mod test {
    use super::sum_of_products;
    use crate::{
        ff::Fp31,
        protocol::{context::Context, RecordId},
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        const BATCHSIZE: usize = 10;
        let world = TestWorld::default();

        let mut rng = thread_rng();

        let (mut av, mut bv) = (Vec::with_capacity(BATCHSIZE), Vec::with_capacity(BATCHSIZE));
        let mut expected = Fp31::ZERO;
        for _ in 0..BATCHSIZE {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();
            expected += a * b;
            av.push(a);
            bv.push(b);
        }

        let res = world
            .upgraded_malicious((av.into_iter(), bv.into_iter()), |ctx, (a, b)| async move {
                sum_of_products(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    a.as_slice(),
                    b.as_slice(),
                )
                .await
                .unwrap()
            })
            .await;

        assert_eq!(expected, res.reconstruct());
    }
}
