use crate::ff::Field;
use crate::protocol::basics::SecureMul;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::rand::thread_rng;
use crate::secret_sharing::{IntoShares, Replicated};
use crate::test_fixture::{Fp31, Reconstruct, TestWorld, TestWorldConfig};
use futures::future::try_join_all;
use futures_util::future::join_all;

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F: Field>(width: u32, depth: u8) {
    let mut config = TestWorldConfig::default();
    config.gateway_config.send_buffer_config.items_in_batch = 1; // break by setting to 2.
    let world = TestWorld::new_with(config).await;

    let mut multiplications = Vec::new();
    for _ in 0..width {
        let circuit_result = circuit(&world, depth);
        multiplications.push(circuit_result);
    }

    let results = join_all(multiplications).await;
    let mut sum = 0;
    for line in results {
        sum += line.reconstruct().as_u128();
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit(world: &TestWorld, depth: u8) -> [Replicated<Fp31>; 3] {
    let top_ctx = world.contexts();
    let mut a = Fp31::ONE.share_with(&mut thread_rng());

    println!("circuit depth {depth}");
    let contexts = &top_ctx;
    for bit in 0..depth {
        println!("multiply a by b_{bit}");
        let b = Fp31::ONE.share_with(&mut thread_rng());
        a = async move {
            let iter = contexts.iter().enumerate().map(|(i, ctx)| {
                println!("{:?} multiply a by b_{bit}", ctx.role());
                ctx.narrow("mult")
                    .multiply(RecordId::from(u32::from(bit)), &a[i], &b[i])
            });

            try_join_all(iter).await.unwrap().try_into().unwrap()
        }
        .await;
        println!("multiplied a by b_{bit}");
    }

    a
}
