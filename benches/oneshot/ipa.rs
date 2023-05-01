use clap::Parser;
use ipa::{
    error::Error,
    ff::Fp32BitPrime,
    helpers::{
        query::{DifferentialPrivacy, IpaQueryConfig},
        GatewayConfig,
    },
    test_fixture::{
        ipa::{
            generate_random_user_records_in_reverse_chronological_order, test_ipa,
            update_expected_output_for_user, IpaSecurityModel,
        },
        TestWorld, TestWorldConfig,
    },
};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use std::{num::NonZeroUsize, time::Instant};

#[cfg(all(target_arch = "x86_64", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
    #[arg(short = 'w', long, default_value = "86400")]
    attribution_window: u32,
    /// The number of sequential bits of breakdown key and match key to process in parallel
    /// while doing modulus conversion and attribution
    #[arg(long, default_value = "3")]
    num_multi_bits: u32,
    /// The random seed to use.
    #[arg(short = 's', long)]
    random_seed: Option<u64>,
    /// The amount of active items to concurrently track.
    #[arg(short = 'a', long)]
    active_work: Option<NonZeroUsize>,
    /// Desired security model for IPA protocol
    #[arg(short = 'm', long, value_enum, default_value_t=IpaSecurityModel::Malicious)]
    mode: IpaSecurityModel,
    /// The epsilon value for differential privacy.
    #[arg(short = 'e', long)]
    epsilon: Option<f64>,
    /// The delta value for differential privacy.
    #[arg(short = 'd', long, default_value = "1e-6")]
    delta: f64,
    /// Needed for benches.
    #[arg(long, hide = true)]
    bench: bool,
}

impl Args {
    fn active(&self) -> usize {
        self.active_work
            .map(NonZeroUsize::get)
            .unwrap_or_else(|| self.query_size.clamp(16, 1024))
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Error> {
    type BenchField = Fp32BitPrime;

    let args = Args::parse();

    let prep_time = Instant::now();
    let config = TestWorldConfig {
        gateway_config: GatewayConfig::new(args.active()),
        ..TestWorldConfig::default()
    };

    let seed = args.random_seed.unwrap_or_else(|| thread_rng().gen());
    println!(
        "Using random seed: {seed} for {q} records",
        q = args.query_size
    );
    let mut rng = StdRng::seed_from_u64(seed);

    let mut expected_results = vec![0_u32; args.breakdown_keys.try_into().unwrap()];
    let mut raw_data = Vec::with_capacity(args.query_size + args.records_per_user);
    while raw_data.len() < args.query_size {
        let mut records_for_user = generate_random_user_records_in_reverse_chronological_order(
            &mut rng,
            args.records_per_user,
            args.breakdown_keys,
            args.max_trigger_value,
        );
        records_for_user.truncate(args.query_size - raw_data.len());
        update_expected_output_for_user(
            &records_for_user,
            &mut expected_results,
            args.per_user_cap,
            args.attribution_window,
        );
        raw_data.append(&mut records_for_user);
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
        IpaQueryConfig::new(
            args.per_user_cap,
            args.breakdown_keys,
            args.attribution_window,
            args.num_multi_bits,
            args.epsilon
                .map(|e| DifferentialPrivacy::new(e, args.delta)),
        ),
        args.mode,
    )
    .await;
    println!(
        "{m:?} IPA for {q} records took {t:?}",
        m = args.mode,
        q = args.query_size,
        t = protocol_time.elapsed()
    );
    Ok(())
}
