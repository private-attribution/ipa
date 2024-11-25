//! Benchmark for the table_indices_prover function in dzkp_field.rs.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ipa_core::protocol::context::dzkp_validator::MultiplicationInputsBlock;
use rand::{thread_rng, Rng};

fn convert_prover_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("dzkp_convert_prover");
    group.bench_function("convert", |b| {
        b.iter_batched_ref(
            || thread_rng().gen(),
            |input: &mut MultiplicationInputsBlock| input.table_indices_prover(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, convert_prover_benchmark);
criterion_main!(benches);
