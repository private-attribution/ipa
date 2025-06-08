use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, Throughput, black_box,
    criterion_group, criterion_main, measurement::Measurement,
};
use ipa_core::{
    ff::{Field, Fp31, Fp32BitPrime, U128Conversions},
    protocol::{basics::SecureMul, context::SemiHonestContext},
    secret_sharing::{FieldSimd, IntoShares, replicated::semi_honest::AdditiveShare as Replicated},
    test_fixture::circuit,
};
use rand::distributions::{Distribution, Standard};
use tokio::runtime::{Builder, Runtime};

fn do_benchmark<M, F, const N: usize>(
    rt: &Runtime,
    group: &mut BenchmarkGroup<M>,
    width: u32,
    depth: u16,
    active_work: usize,
) where
    M: Measurement,
    F: Field + FieldSimd<N> + U128Conversions,
    for<'a> Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
    Standard: Distribution<F>,
{
    group.throughput(Throughput::Elements((width * depth as u32) as u64));
    group.bench_with_input(
        BenchmarkId::new(
            "circuit",
            format!("{width}:{depth}:{active_work}:{}x{}", F::NAME, N),
        ),
        &(width, depth),
        |b, &(width, depth)| {
            b.to_async(rt).iter_batched(
                || circuit::arithmetic_setup(width, depth),
                |input| {
                    circuit::arithmetic::<F, N>(
                        black_box(width),
                        black_box(depth),
                        active_work,
                        input,
                    )
                },
                BatchSize::PerIteration,
            );
        },
    );
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .enable_time()
        .build()
        .expect("Creating runtime failed");

    let mut group = c.benchmark_group("arithmetic");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Note that the width parameter (3rd-to-last argument to do_benchmark) must
    // be a multiple of the vectorization width.

    #[cfg(not(coverage))]
    {
        do_benchmark::<_, Fp31, 1>(&rt, &mut group, 4_096, 64, 1024);
        do_benchmark::<_, Fp31, 1>(&rt, &mut group, 1_024, 256, 1024);

        do_benchmark::<_, Fp32BitPrime, 1>(&rt, &mut group, 4_096, 64, 1024);
        do_benchmark::<_, Fp32BitPrime, 1>(&rt, &mut group, 1_024, 256, 1024);
        do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 4_096, 64, 32);
        do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 1_024, 256, 32);
    }

    #[cfg(coverage)]
    {
        do_benchmark::<_, Fp31, 1>(&rt, &mut group, 256, 64, 32);
        do_benchmark::<_, Fp32BitPrime, 1>(&rt, &mut group, 256, 64, 32);
        do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 256, 64, 32);
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
