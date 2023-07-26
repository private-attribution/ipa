use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use futures_util::future::{join, try_join};
use std::num::NonZeroUsize;
use tokio_stream::StreamExt;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("spsc-reader-writer")
        .enable_time()
        .build()
        .expect("Creating runtime failed");

    let mut group = c.benchmark_group("spsc");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for capacity in [1_usize, 1 << 8, 1 << 10] {
        group.throughput(Throughput::Elements(10000));
        group.bench_with_input(
            BenchmarkId::new("with_capacity", capacity),
            &capacity,
            |b, &capacity| {
                b.to_async(&rt).iter(|| async {
                    let capacity = NonZeroUsize::new(capacity).unwrap();
                    let (tx, mut rx) = ipa::helpers::spsc::channel(capacity);

                    let writer_handle = rt.spawn(async move {
                        for _ in 1..100 * capacity.get() {
                            tx.push(1).await;
                        }
                    });
                    let reader_handle = rt.spawn(async move {
                        while let Some(item) = rx.next().await {
                            black_box(item);
                        }
                    });

                    try_join(writer_handle, reader_handle).await.unwrap();
                });
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
