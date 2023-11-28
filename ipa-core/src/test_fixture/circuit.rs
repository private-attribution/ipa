use futures_util::future::join_all;

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
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::{narrow_contexts, Reconstruct, TestWorld},
};

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F>(width: u32, depth: u8)
where
    F: Field + IntoShares<Replicated<F>>,
    for<'a> Replicated<F>: SecureMul<SemiHonestContext<'a>>,
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
    let mut sum = 0;
    for line in results {
        sum += line.reconstruct().as_u128();
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit<'a, F>(
    top_ctx: &[SemiHonestContext<'a>; 3],
    record_id: RecordId,
    depth: u8,
) -> [Replicated<F>; 3]
where
    F: Field + IntoShares<Replicated<F>>,
    Replicated<F>: SecureMul<SemiHonestContext<'a>>,
{
    let mut a = F::ONE.share_with(&mut thread_rng());

    for bit in 0..depth {
        let b = F::ONE.share_with(&mut thread_rng());
        let bit_ctx = narrow_contexts(top_ctx, &format!("b{bit}"));
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in bit_ctx.iter().enumerate() {
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
