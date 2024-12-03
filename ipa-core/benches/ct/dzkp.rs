//! Benchmarks for DZKPs.

use std::iter::{repeat_with, zip};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, SamplingMode};
use futures::{stream::iter, TryStreamExt};
use ipa_core::{
    ff::boolean_array::BA256,
    helpers::TotalRecords,
    protocol::{
        basics::BooleanArrayMul,
        context::{
            dzkp_validator::{DZKPValidator, MultiplicationInputsBlock, TARGET_PROOF_SIZE},
            malicious::TEST_DZKP_STEPS,
            Context, DZKPUpgradedMaliciousContext, UpgradableContext,
        },
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
    sharding::NotSharded,
    test_fixture::{Runner, TestWorld},
    utils::non_zero_prev_power_of_two,
};
use rand::{thread_rng, Rng};
use tokio::runtime::Builder;

/// Benchmark for the table_indices_prover function in dzkp_field.rs.
fn benchmark_table_indices_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("benches");
    group.bench_function("table_indices_prover", |b| {
        b.iter_batched_ref(
            || thread_rng().gen(),
            |input: &mut MultiplicationInputsBlock| input.table_indices_prover(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

/// Benchmark for end-to-end proof.
///
/// This benchmark focuses on proof performance by evaluating one of the simplest and
/// most performant MPC circuits possible: 64 million AND gates in parallel.
fn benchmark_proof(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .enable_time()
        .build()
        .expect("Creating runtime failed");

    type BA = BA256;
    const COUNT: usize = 64 * 1024 * 1024 / BA::BITS as usize;

    let mut group = c.benchmark_group("proof");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("proof", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let mut rng = thread_rng();

                let a = repeat_with(|| rng.gen()).take(COUNT).collect::<Vec<BA>>();
                let b = repeat_with(|| rng.gen()).take(COUNT).collect::<Vec<BA>>();

                (a, b)
            },
            |(a, b): (Vec<BA>, Vec<BA>)| async move {
                TestWorld::default()
                    .malicious((a.into_iter(), b.into_iter()), |ctx, (a, b)| async move {
                        let batch_size = non_zero_prev_power_of_two(
                            TARGET_PROOF_SIZE / usize::try_from(BA::BITS).unwrap(),
                        );
                        let v = ctx
                            .set_total_records(TotalRecords::specified(COUNT)?)
                            .dzkp_validator(TEST_DZKP_STEPS, batch_size);
                        let m_ctx = v.context();

                        v.validated_seq_join(iter(zip(a, b).enumerate().map(
                            |(i, (a_malicious, b_malicious))| {
                                let m_ctx = m_ctx.clone();
                                let a_vec = <Replicated<BA> as BooleanArrayMul<
                                    DZKPUpgradedMaliciousContext<NotSharded>,
                                >>::Vectorized::from(
                                    a_malicious
                                );
                                let b_vec = <Replicated<BA> as BooleanArrayMul<
                                    DZKPUpgradedMaliciousContext<NotSharded>,
                                >>::Vectorized::from(
                                    b_malicious
                                );
                                async move {
                                    <Replicated<BA> as BooleanArrayMul<_>>::multiply(
                                        m_ctx,
                                        RecordId::from(i),
                                        &a_vec,
                                        &b_vec,
                                    )
                                    .await
                                    .map(<Replicated<BA>>::from)
                                }
                            },
                        )))
                        .try_collect::<Vec<_>>()
                        .await
                    })
                    .await
                    .map(Result::unwrap);
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

criterion_group!(benches, benchmark_table_indices_prover);
criterion_group!(proof, benchmark_proof);
criterion_main!(benches, proof);
