//! Benchmarks for bit matrix transpose operations.
//!
//! Some of these routines run very fast, which doesn't work well with the default Criterion settings.
//! The warm up time and measurement time are reduced, because the defaults will produce a very large
//! number of samples (which in turn will take Criterion a long time to analyze).
//!
//! Some of the benchmark routines are looped so that the running time is long enough for Criterion
//! to measure reliably. When too short, Criterion complains that some measurements take zero time.
//! Presumably, the behavior of the underlying system clock is a contributing factor here.
//!
//! There is also a panic in the `plotters` crate used by Criterion to produce HTML reports that can
//! occur with very fast-running routines. This can be worked around by passing the `-n` option to
//! Criterion to disable HTML reports.

use std::{array, iter::repeat_with, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ipa_core::{
    error::UnwrapInfallible,
    ff::boolean_array::BA64,
    secret_sharing::{
        SharedValue, TransposeFrom,
        vector::{transpose_8x8, transpose_16x16},
    },
};
use rand::{
    Rng,
    distributions::{Distribution, Standard},
    thread_rng,
};

fn random_array<T, const N: usize>() -> [T; N]
where
    Standard: Distribution<T>,
{
    let mut rng = thread_rng();
    array::from_fn(|_| rng.r#gen())
}

struct Params {
    rows: usize,
    cols: usize,
    iters: usize,
}

fn do_benchmark<O, T, const N: usize>(
    c: &mut Criterion,
    Params { rows, cols, iters }: Params,
    routine: fn(&[T; N]) -> O,
) where
    Standard: Distribution<T>,
{
    let mut group = c.benchmark_group(format!("{rows}x{cols}"));
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(200));
    group.throughput(Throughput::Elements((rows * cols * iters) as u64));

    group.bench_with_input(
        BenchmarkId::new("transpose", format!("{iters}x")),
        &(),
        move |b, _| {
            b.iter_batched_ref(
                || repeat_with(random_array).take(iters).collect::<Vec<_>>(),
                |input| input.iter().map(routine).count(),
                BatchSize::SmallInput,
            )
        },
    );
    group.finish();
}

fn bench_8x8(c: &mut Criterion) {
    do_benchmark(
        c,
        Params {
            rows: 8,
            cols: 8,
            iters: 100,
        },
        |m| transpose_8x8(m),
    );
}

fn bench_16x16(c: &mut Criterion) {
    do_benchmark(
        c,
        Params {
            rows: 16,
            cols: 16,
            iters: 50,
        },
        transpose_16x16,
    );
}

fn bench_64x64(c: &mut Criterion) {
    do_benchmark(
        c,
        Params {
            rows: 64,
            cols: 64,
            iters: 1,
        },
        |src| {
            let mut dst = array::from_fn(|_| BA64::ZERO);
            dst.transpose_from(src).unwrap_infallible();
            dst
        },
    );
}

criterion_group!(benches_8x8, bench_8x8);
criterion_group!(benches_16x16, bench_16x16);
criterion_group!(benches_64x64, bench_64x64);
criterion_main!(benches_8x8, benches_16x16, benches_64x64);
