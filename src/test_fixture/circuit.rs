use crate::ff::Field;
use crate::protocol::{QueryId, RecordId};
use crate::secret_sharing::Replicated;
use crate::test_fixture::{
    make_contexts, make_world, narrow_contexts, share, validate_and_reconstruct, Fp31, TestWorld,
};
use futures_util::future::join_all;
use rand::thread_rng;

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F: Field>(width: u32, depth: u8) {
    let world = make_world(QueryId);

    let mut multiplications = Vec::new();
    for record in 0..width {
        let circuit_result = circuit(&world, RecordId::from(record), depth);
        multiplications.push(circuit_result);
    }

    let results = join_all(multiplications).await;
    let mut sum = 0;
    for line in results {
        sum += validate_and_reconstruct((line[0], line[1], line[2])).as_u128();
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit(world: &TestWorld, record_id: RecordId, depth: u8) -> [Replicated<Fp31>; 3] {
    let top_ctx = make_contexts::<Fp31>(world);
    let mut a = share(Fp31::ONE, &mut thread_rng());

    for bit in 0..depth {
        let b = share(Fp31::ONE, &mut thread_rng());
        let bit_ctx = narrow_contexts(&top_ctx, &format!("b{bit}"));
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in bit_ctx.iter().enumerate() {
                let mul = ctx.narrow(&"mult".to_string()).multiply(record_id);
                coll.push(mul.execute(a[i], b[i]));
            }

            join_all(coll)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        }
        .await;
    }

    a
}
