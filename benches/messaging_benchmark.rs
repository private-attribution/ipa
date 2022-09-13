use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode, Throughput, BenchmarkId};
use futures_util::future::join_all;
use rand::rngs::mock::StepRng;
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use tokio::runtime::Builder;
use raw_ipa::field::Fp31;
use raw_ipa::helpers::mock::{make_world, TestHelperGateway};
use raw_ipa::protocol::{QueryId, RecordId, Step};
use raw_ipa::prss::SpaceIndex;
use raw_ipa::replicated_secret_sharing::ReplicatedSecretSharing;
use raw_ipa::securemul::ProtocolContext;
use raw_ipa::securemul::tests::{make_context, share, validate_and_reconstruct};
use raw_ipa::field::Field;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct BenchStep(u8);

impl Step for BenchStep {}

impl SpaceIndex for BenchStep {
    const MAX: usize = 1;

    fn as_usize(&self) -> usize {
        0
    }
}

const CIRCUIT_DEPTH: u8 = 1;


async fn circuit(contexts: &[ProtocolContext<'_, TestHelperGateway<BenchStep>, BenchStep>; 3], record_id: RecordId) -> [ReplicatedSecretSharing<Fp31>; 3] {
    let mut a = share(Fp31::from(1_u128), &mut thread_rng());
    for bit in 0..CIRCUIT_DEPTH {
        let b = share(Fp31::from(1_u128), &mut thread_rng());
        let c = contexts;
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in c.iter().enumerate() {
                let mul = ctx.multiply(record_id, BenchStep(bit)).await;
                coll.push(mul.execute(a[i], b[i]))
            }

            join_all(coll).await.into_iter().collect::<Result<Vec<_>, _>>().unwrap().try_into().unwrap()
        }.await;
    }

    a
}

async fn messaging_bench(record_count: u32) {
    let world = make_world(QueryId);
    let participants = raw_ipa::prss::test::make_three();
    let context = make_context(&world, &participants);

    let mut multiplications = Vec::new();
    for record in 0..record_count {
        let circuit_result = circuit(&context, RecordId::from(record));
        multiplications.push(circuit_result);
    }
    let results = join_all(multiplications).await;
    let mut sum = 0_u128;
    for line in results {
        sum += validate_and_reconstruct((line[0], line[1], line[2])).as_u128();
    }
    // println!("resulting sum for {CIRCUIT_WIDTH}: {sum}");
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .build()
        .expect("Creating runtime failed");

    let mut group = c.benchmark_group("messaging");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for width in [5_000u32, 50_000, 500_000, 1_000_000] {
        group.throughput(Throughput::Elements(width as u64));
        group.bench_with_input(BenchmarkId::from_parameter(width), &width, |b, &record_count| {
            b.to_async(&rt).iter(|| messaging_bench(record_count));
            // b.iter(|| iter::repeat(0u8).take(size).collect::<Vec<_>>());
        });
    }

    // for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].iter() {
    //        group.throughput(Throughput::Bytes(*size as u64));
    //        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
    //            b.iter(|| iter::repeat(0u8).take(size).collect::<Vec<_>>());
    //        });
    //    }
    //    group.finish();
    // group.bench_function("mul", |b| {
    //     b.to_async(&rt).iter(|| messaging_bench());
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);