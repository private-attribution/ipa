use iai::black_box;
use ipa::{ff::Fp31, test_fixture::circuit};
use tokio::runtime::Builder;

pub fn iai_benchmark() {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .build()
        .expect("Creating runtime failed");

    const CIRCUIT_WIDTH: u32 = 500_000;
    const CIRCUIT_DEPTH: u8 = 1;

    rt.block_on(async {
        circuit::arithmetic::<Fp31>(black_box(CIRCUIT_WIDTH), black_box(CIRCUIT_DEPTH)).await;
    })
}

iai::main!(iai_benchmark);
