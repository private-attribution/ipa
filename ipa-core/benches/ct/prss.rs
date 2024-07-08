use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ipa_core::{
    ff::boolean_array::{BA256, BA64, BA8},
    protocol::{
        prss::{Endpoint, IndexedSharedRandomness, KeyExchange, SharedRandomness},
        Gate,
    },
};
use rand::thread_rng;

fn make_prss() -> Arc<IndexedSharedRandomness> {
    let prss_setup = Endpoint::prepare(&mut thread_rng());
    let left_peer = KeyExchange::new(&mut thread_rng());
    let right_peer = KeyExchange::new(&mut thread_rng());

    let prss = prss_setup
        .setup(&left_peer.public_key(), &right_peer.public_key())
        .indexed(&Gate::default());

    prss
}

fn prss_benchmark(c: &mut Criterion) {
    if cfg!(debug_assertions) {
        panic!(
            "Debug assertions enable PRSS generators to track used indices. This \
                will make this benchmark very slow. Turn them off."
        )
    }

    // Setup PRSS outside measured code.
    let mut group = c.benchmark_group("prss_one_chunk");
    let prss = make_prss();

    // PRSS generates a pair of 16 byte values
    group.throughput(Throughput::Bytes(32));
    let mut index = 0_u32;
    group.bench_function("BA8", |b| {
        b.iter(|| {
            let data = prss.generate::<(BA8, _), _>(index);
            index += 1;
            black_box(data);
        })
    });
    group.bench_function("BA64", |b| {
        b.iter(|| {
            let data = prss.generate::<(BA64, _), _>(index);
            index += 1;
            black_box(data);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("prss_two_chunks");
    group.throughput(Throughput::Bytes(64));
    group.bench_function("BA256", |b| {
        b.iter(|| {
            let data = prss.generate::<(BA256, _), _>(index);
            index += 1;
            black_box(data);
        })
    });
}

criterion_group!(benches, prss_benchmark);
criterion_main!(benches);
