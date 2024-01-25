use criterion::{
    black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
    BenchmarkId, Criterion, SamplingMode, Throughput,
};
use ipa_core::{
    ff::{Field, Fp31, Fp32BitPrime, U128Conversions},
    protocol::{basics::SecureMul, context::SemiHonestContext},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, IntoShares},
    test_fixture::circuit,
};
use rand::distributions::{Distribution, Standard};
use tokio::runtime::{Builder, Runtime};

fn do_benchmark<M, F, const N: usize>(
    rt: &Runtime,
    group: &mut BenchmarkGroup<M>,
    width: u32,
    depth: u16,
) where
    M: Measurement,
    F: Field + FieldSimd<N> + U128Conversions,
    for<'a> Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
    Standard: Distribution<F>,
{
    group.throughput(Throughput::Elements((width * depth as u32) as u64));
    group.bench_with_input(
        BenchmarkId::new("circuit", format!("{width}:{depth}:{}x{}", F::NAME, N)),
        &(width, depth),
        |b, &(width, depth)| {
            b.to_async(rt)
                .iter(|| circuit::arithmetic::<F, N>(black_box(width), black_box(depth)));
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

    do_benchmark::<_, Fp31, 1>(&rt, &mut group, 512_000, 1);
    do_benchmark::<_, Fp31, 1>(&rt, &mut group, 51_200, 10);
    do_benchmark::<_, Fp31, 1>(&rt, &mut group, 8_000, 64);

    do_benchmark::<_, Fp32BitPrime, 1>(&rt, &mut group, 25_600, 10);
    do_benchmark::<_, Fp32BitPrime, 1>(&rt, &mut group, 2_560, 100);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 4_000, 64);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 250, 1_024);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
