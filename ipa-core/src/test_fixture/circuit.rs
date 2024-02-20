use futures_util::future::join_all;
use rand::distributions::{Distribution, Standard};

use super::join3v;
use crate::{
    ff::Field,
    helpers::TotalRecords,
    protocol::{
        basics::SecureMul,
        context::{Context, SemiHonestContext},
        RecordId,
    },
    rand::thread_rng,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, IntoShares},
    test_fixture::{narrow_contexts, ReconstructArr, TestWorld},
};

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F, const N: usize>(width: u32, depth: u16)
where
    F: Field + FieldSimd<N>,
    for<'a> Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
    Standard: Distribution<F>,
{
    let world = TestWorld::default();
    // Re-use contexts for the entire execution because record identifiers are contiguous.
    let contexts = world.contexts();

    let mut multiplications = Vec::new();
    for record in 0..width {
        let circuit_result = circuit(&contexts, RecordId::from(record), depth);
        multiplications.push(circuit_result);
    }

    #[allow(clippy::disallowed_methods)] // Just for testing purposes.
    let results = join_all(multiplications).await;
    let mut sum = [0u128; N];
    for line in results {
        for (this_sum, this_value) in sum.iter_mut().zip(line.reconstruct_arr()) {
            *this_sum += this_value.as_u128();
        }
    }

    assert_eq!(sum, [u128::from(width); N]);
}

async fn circuit<'a, F, const N: usize>(
    top_ctx: &[SemiHonestContext<'a>; 3],
    record_id: RecordId,
    depth: u16,
) -> [Replicated<F, N>; 3]
where
    F: Field + FieldSimd<N>,
    Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
{
    assert_eq!(
        depth % u16::try_from(N).unwrap(),
        0,
        "depth must be a multiple of vectorization factor"
    );

    let mut a = [F::ONE; N].share_with(&mut thread_rng());

    for stripe in 0..(depth / u16::try_from(N).unwrap()) {
        let b = [F::ONE; N].share_with(&mut thread_rng());
        let stripe_ctx = narrow_contexts(top_ctx, &format!("s{stripe}"));
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in stripe_ctx.iter().enumerate() {
                let mul = a[i].multiply(
                    &b[i],
                    ctx.narrow("mult")
                        .set_total_records(TotalRecords::Indeterminate),
                    record_id,
                );
                coll.push(mul);
            }

            join3v(coll).await
        }
        .await;
    }

    a
}
