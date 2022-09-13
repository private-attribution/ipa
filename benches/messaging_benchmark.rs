use criterion::{black_box, criterion_group, criterion_main, Criterion};
use raw_ipa::helpers::mock::{make_world};
use raw_ipa::protocol::QueryId;
use raw_ipa::securemul::tests::make_context;


fn messaging_bench() {
    let world = make_world(QueryId);
    let participants = raw_ipa::prss::test::make_three();
    let context = make_context(&world, &participants);
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("mul", |b| b.iter(|| fibonacci(black_box(20))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);