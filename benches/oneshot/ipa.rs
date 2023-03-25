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
use std::{cmp::min, time::Instant};

/// A benchmark for the full IPA protocol.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// The total number of records to process.
    #[arg(short = 'n', long, default_value = "1000")]
    query_size: usize,
    /// The maximum number of records for each person.
    #[arg(short = 'u', long, default_value = "50")]
    records_per_user: usize,
    /// The contribution cap for each person.
    #[arg(short = 'c', long, default_value = "3")]
    per_user_cap: u32,
    /// The number of breakdown keys.
    #[arg(short = 'b', long, default_value = "16")]
    breakdown_keys: u32,
    /// The maximum trigger value.
    #[arg(short = 't', long, default_value = "5")]
    max_trigger_value: u32,
    /// The size of the attribution window, in seconds.
    #[arg(short = 'w', long, default_value = "0")]
    attribution_window: u32,
    /// The random seed to use.
    #[arg(short = 's', long)]
    random_seed: Option<u64>,
    /// Needed for benches.
    #[arg(long, hide = true)]
    bench: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    type BenchField = Fp32BitPrime;

    let args = Args::parse();

    let prep_time = Instant::now();
    let mut config = TestWorldConfig::default();
    config.gateway_config =
        GatewayConfig::symmetric_buffers::<BenchField>(args.query_size.clamp(16, 1024));

    let seed = args.random_seed.unwrap_or_else(|| thread_rng().gen());
    println!(
        "Using random seed: {seed} for {q} records",
        q = args.query_size
    );
    let mut rng = StdRng::seed_from_u64(seed);

    // for args.per_user_cap in [1, 3] {
    let mut expected_results = vec![0_u32; args.breakdown_keys.try_into().unwrap()];
    let mut raw_data = Vec::with_capacity(args.query_size + args.records_per_user);
    while raw_data.len() < args.query_size {
        let records_for_user = generate_random_user_records_in_reverse_chronological_order(
            &mut rng,
            args.records_per_user,
            args.breakdown_keys,
            args.max_trigger_value,
        );
        let needed = min(
            records_for_user.len(),
            args.query_size.saturating_sub(raw_data.len()),
        );
        raw_data.extend_from_slice(&records_for_user[..needed]);
        update_expected_output_for_user(
            &records_for_user[..needed],
            &mut expected_results,
            args.per_user_cap,
            args.attribution_window,
        );
    }

    // Sort the records in chronological order
    // This is part of the IPA spec. Callers should do this before sending a batch of records in for processing.
    raw_data.sort_unstable_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let world = TestWorld::new_with(config.clone());
    println!("Preparation complete in {:?}", prep_time.elapsed());

    let protocol_time = Instant::now();
    test_ipa::<BenchField>(
        &world,
        &raw_data,
        &expected_results,
        args.per_user_cap,
        args.breakdown_keys,
        args.attribution_window,
        IpaSecurityModel::Malicious,
    )
    .await;
    println!(
        "IPA for {q} records took {t:?}",
        q = args.query_size,
        t = protocol_time.elapsed()
    );
    Ok(())
}
