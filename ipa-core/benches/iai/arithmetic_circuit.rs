use iai::black_box;
use ipa_core::{ff::Fp31, test_fixture::circuit};
use tokio::runtime::Builder;

pub fn iai_benchmark() {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .build()
        .expect("Creating runtime failed");

    const CIRCUIT_WIDTH: u32 = 500_000;
    const CIRCUIT_DEPTH: u16 = 1;

    tracing::warn!("test data generation may skew results of this benchmark");
    rt.block_on(async {
        let input = circuit::arithmetic_setup(CIRCUIT_WIDTH, CIRCUIT_DEPTH);
        circuit::arithmetic::<Fp31, 1>(
            black_box(CIRCUIT_WIDTH),
            black_box(CIRCUIT_DEPTH),
            1024,
            input,
        )
        .await;
    })
}

iai::main!(iai_benchmark);
