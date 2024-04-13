use std::{
    env,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Instant,
};

use clap::Parser;
use ipa_core::{
    error::Error,
    ff::Fp32BitPrime,
    helpers::{query::IpaQueryConfig, GatewayConfig},
    test_fixture::{
        ipa::{ipa_in_the_clear, test_oprf_ipa, CappingOrder, IpaSecurityModel},
        EventGenerator, EventGeneratorConfig, TestWorld, TestWorldConfig,
    },
};
use rand::{random, rngs::StdRng, SeedableRng};
use tokio::runtime::Builder;

#[cfg(all(not(target_env = "msvc"), not(feature = "dhat-heap")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// A benchmark for the full IPA protocol.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// The number of threads to use for running IPA.
    #[arg(short = 'j', long, default_value = "3")]
    threads: usize,
    /// The total number of records to process.
    #[arg(short = 'n', long, default_value = "1000")]
    query_size: usize,
    /// The maximum number of records for each person.
    #[arg(short = 'u', long, default_value = "50")]
    records_per_user: u32,
    /// The contribution cap for each person.
    #[arg(short = 'c', long, default_value = "8")]
    per_user_cap: u32,
    /// The number of breakdown keys.
    #[arg(short = 'b', long, default_value = "16")]
    breakdown_keys: u32,
    /// The maximum trigger value.
    #[arg(short = 't', long, default_value = "5")]
    max_trigger_value: u32,
    /// The size of the attribution window, in seconds.
    #[arg(
        short = 'w',
        long,
        default_value = "86400",
        help = "The size of the attribution window, in seconds. Pass 0 for an infinite window."
    )]
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

    fn attribution_window(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.attribution_window)
    }

    fn config(&self) -> IpaQueryConfig {
        IpaQueryConfig {
            per_user_credit_cap: self.per_user_cap,
            max_breakdown_key: self.breakdown_keys,
            attribution_window_seconds: self.attribution_window(),
            num_multi_bits: self.num_multi_bits,
            plaintext_match_keys: true,
        }
    }
}

async fn run(args: Args) -> Result<(), Error> {
    type BenchField = Fp32BitPrime;

    let _prep_time = Instant::now();
    let config = TestWorldConfig {
        gateway_config: GatewayConfig::new(args.active()),
        ..TestWorldConfig::default()
    };
    // Construct TestWorld early to initialize logging.
    let world = TestWorld::new_with(&config);

    let seed = args.random_seed.unwrap_or_else(|| random());
    tracing::info!(
        "Using random seed: {seed} for {q} records",
        q = args.query_size
    );
    let rng = StdRng::seed_from_u64(seed);
    let (user_count, min_events_per_user, max_events_per_user, query_size) =
        if cfg!(feature = "step-trace") {
            // For the steps collection, compact gate requires a single user with the same number
            // of dynamic steps as defined for `UserNthRowStep::Row`.
            (
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(64).unwrap(),
                NonZeroU32::new(64).unwrap(),
                64,
            )
        } else {
            (
                EventGeneratorConfig::default().user_count,
                EventGeneratorConfig::default().min_events_per_user,
                NonZeroU32::new(args.records_per_user).unwrap(),
                args.query_size,
            )
        };
    let mut raw_data = EventGenerator::with_config(
        rng,
        EventGeneratorConfig {
            user_count,
            max_trigger_value: NonZeroU32::try_from(args.max_trigger_value).unwrap(),
            max_breakdown_key: NonZeroU32::try_from(args.breakdown_keys).unwrap(),
            min_events_per_user,
            max_events_per_user,
            ..Default::default()
        },
    )
    .take(query_size)
    .collect::<Vec<_>>();
    // EventGenerator produces events in random order, but IPA requires them to be sorted by
    // timestamp.
    raw_data.sort_by_key(|e| e.timestamp);

    let order = CappingOrder::CapMostRecentFirst;

    let expected_results = ipa_in_the_clear(
        &raw_data,
        args.per_user_cap,
        args.attribution_window(),
        args.breakdown_keys,
        &order,
    );

    tracing::trace!("Preparation complete in {:?}", _prep_time.elapsed());

    let _protocol_time = Instant::now();
    test_oprf_ipa::<BenchField>(&world, raw_data, &expected_results, args.config()).await;
    tracing::info!(
        "{m:?} IPA for {q} records took {t:?}",
        m = args.mode,
        q = args.query_size,
        t = _protocol_time.elapsed()
    );
    Ok(())
}

fn main() -> Result<(), Error> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // The default in test_fixture::logging is to enable logging for ipa-core only. Override that to
    // include logs from the bench as well.
    if env::var_os("RUST_LOG").is_none() {
        env::set_var(
            "RUST_LOG",
            format!(
                "{}=INFO,{}=INFO",
                ipa_core::CRATE_NAME,
                env!("CARGO_CRATE_NAME")
            ),
        );
    }

    let args = Args::parse();
    let rt = Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();
    let task = rt.spawn(run(args));
    rt.block_on(task)?
}
