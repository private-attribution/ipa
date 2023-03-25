use clap::Parser;
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use raw_ipa::{
    error::Error,
    ff::Fp32BitPrime,
    helpers::GatewayConfig,
    test_fixture::{
        generate_random_user_records_in_reverse_chronological_order, test_ipa,
        update_expected_output_for_user, IpaSecurityModel, TestWorld, TestWorldConfig,
    },
};
use std::cmp::min;
use std::time::Instant;

/// A benchmark for the full IPA protocol.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// The total number of records to process.
    #[arg(short = 'n')]
    query_size: usize,
    #[arg(short = 'm')]
    max_records_per_user: usize,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    const MAX_BREAKDOWN_KEY: u32 = 16;
    const MAX_TRIGGER_VALUE: u32 = 5;
    const QUERY_SIZE: usize = 1000;
    const MAX_RECORDS_PER_USER: usize = 10;
    const ATTRIBUTION_WINDOW_SECONDS: u32 = 0;
    const PER_USER_CAP: u32 = 3;
    type BenchField = Fp32BitPrime;

    let prep_time = Instant::now();
    let mut config = TestWorldConfig::default();
    config.gateway_config =
        GatewayConfig::symmetric_buffers::<BenchField>(QUERY_SIZE.clamp(16, 1024));

    let random_seed = thread_rng().gen();
    println!("Using random seed: {random_seed} for {QUERY_SIZE} records");
    let mut rng = StdRng::seed_from_u64(random_seed);

    // for per_user_cap in [1, 3] {
    let mut expected_results = vec![0_u32; MAX_BREAKDOWN_KEY.try_into().unwrap()];
    let mut raw_data = Vec::with_capacity(QUERY_SIZE + MAX_RECORDS_PER_USER);
    while raw_data.len() < QUERY_SIZE {
        let records_for_user = generate_random_user_records_in_reverse_chronological_order(
            &mut rng,
            MAX_RECORDS_PER_USER,
            MAX_BREAKDOWN_KEY,
            MAX_TRIGGER_VALUE,
        );
        let needed = min(
            records_for_user.len(),
            QUERY_SIZE.saturating_sub(raw_data.len()),
        );
        raw_data.extend_from_slice(&records_for_user[..needed]);
        update_expected_output_for_user(
            &records_for_user[..needed],
            &mut expected_results,
            PER_USER_CAP,
            0,
        );
    }
    println!("Running test for {:?} records", raw_data.len());

    // Sort the records in chronological order
    // This is part of the IPA spec. Callers should do this before sending a batch of records in for processing.
    raw_data.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let world = TestWorld::new_with(config.clone());
    println!("Preparation time {:?}", prep_time.elapsed());

    let protocol_time = Instant::now();
    test_ipa::<BenchField>(
        &world,
        &raw_data,
        &expected_results,
        PER_USER_CAP,
        MAX_BREAKDOWN_KEY,
        ATTRIBUTION_WINDOW_SECONDS,
        IpaSecurityModel::Malicious,
    )
    .await;
    println!("IPA for {QUERY_SIZE} records took {:?}", protocol_time.elapsed());
    Ok(())
}
