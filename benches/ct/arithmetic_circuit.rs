use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use ipa::{ff::Fp31, test_fixture::circuit};
use tokio::runtime::Builder;

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

    for width in [5_000u32, 50_000, 500_000, 1_000_000] {
        for depth in [1u8, 10, 64] {
            group.throughput(Throughput::Elements((width * depth as u32) as u64));
            group.bench_with_input(
                BenchmarkId::new("circuit", format!("{width}:{depth}")),
                &(width, depth),
                |b, &(width, depth)| {
                    b.to_async(&rt)
                        .iter(|| circuit::arithmetic::<Fp31>(black_box(width), black_box(depth)));
                },
            );
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
