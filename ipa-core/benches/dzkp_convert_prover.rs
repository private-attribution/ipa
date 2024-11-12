//! Benchmark for the convert_prover function in dzkp_field.rs.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ipa_core::{
    ff::Fp61BitPrime,
    protocol::context::{dzkp_field::DZKPBaseField, dzkp_validator::MultiplicationInputsBlock},
};
use rand::{thread_rng, Rng};

fn convert_prover_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("dzkp_convert_prover");
    group.bench_function("convert", |b| {
        b.iter_batched_ref(
            || {
                // Generate input
                let mut rng = thread_rng();

                MultiplicationInputsBlock {
                    x_left: rng.gen::<[u8; 32]>().into(),
                    x_right: rng.gen::<[u8; 32]>().into(),
                    y_left: rng.gen::<[u8; 32]>().into(),
                    y_right: rng.gen::<[u8; 32]>().into(),
                    prss_left: rng.gen::<[u8; 32]>().into(),
                    prss_right: rng.gen::<[u8; 32]>().into(),
                    z_right: rng.gen::<[u8; 32]>().into(),
                }
            },
            |input| {
                let MultiplicationInputsBlock {
                    x_left,
                    x_right,
                    y_left,
                    y_right,
                    prss_right,
                    ..
                } = input;
                Fp61BitPrime::convert_prover(x_left, x_right, y_left, y_right, prss_right);
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, convert_prover_benchmark);
criterion_main!(benches);
