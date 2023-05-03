use crate::{
    ff::{Field, Fp31},
    helpers::TotalRecords,
    protocol::{basics::SecureMul, context::Context, RecordId},
    rand::thread_rng,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::{narrow_contexts, Reconstruct, TestWorld},
};
use futures_util::future::join_all;

use super::join3v;

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F: Field>(width: u32, depth: u8) {
    let world = TestWorld::default();

    let mut multiplications = Vec::new();
    for record in 0..width {
        let circuit_result = circuit(&world, RecordId::from(record), depth);
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

async fn circuit(world: &TestWorld, record_id: RecordId, depth: u8) -> [Replicated<Fp31>; 3] {
    let top_ctx = world.contexts();
    let mut a = Fp31::ONE.share_with(&mut thread_rng());

    for bit in 0..depth {
        let b = Fp31::ONE.share_with(&mut thread_rng());
        let bit_ctx = narrow_contexts(&top_ctx, &format!("b{bit}"));
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in bit_ctx.iter().enumerate() {
                let mul = a[i].multiply(
                    &b[i],
                    ctx.narrow(&"mult".to_string())
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
