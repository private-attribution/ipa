use std::{
    borrow::Cow,
    error::Error,
    fmt::Debug,
    fs::{File, OpenOptions},
    io,
    io::{stdout, Write},
    ops::Deref,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use comfy_table::{Cell, Table};
use hyper::http::uri::Scheme;
use ipa_core::{
    cli::{
        noise::{apply, ApplyDpArgs},
        playbook::{make_clients, playbook_oprf_ipa, validate, validate_dp, InputSource},
        CsvSerializer, IpaQueryResult, Verbosity,
    },
    config::{KeyRegistries, NetworkConfig},
    ff::{boolean_array::BA32, FieldType},
    helpers::query::{DpMechanism, IpaQueryConfig, QueryConfig, QuerySize, QueryType},
    net::MpcHelperClient,
    report::DEFAULT_KEY_ID,
    test_fixture::{
        ipa::{ipa_in_the_clear, CappingOrder, IpaQueryStyle, IpaSecurityModel, TestRawDataRecord},
        EventGenerator, EventGeneratorConfig,
    },
};
use rand::{distributions::Alphanumeric, rngs::StdRng, thread_rng, Rng};
use rand_core::SeedableRng;

#[derive(Debug, Parser)]
#[clap(name = "rc", about = "Report Collector CLI")]
#[command(about)]
struct Args {
    #[clap(flatten)]
    logging: Verbosity,

    /// Path to helper network configuration file
    #[arg(long)]
    network: Option<PathBuf>,

    /// Use insecure HTTP
    #[arg(short = 'k', long)]
    disable_https: bool,

    /// Seconds to wait for server to be running
    #[arg(short, long, default_value_t = 0)]
    wait: usize,

    #[clap(flatten)]
    input: CommandInput,

    /// The destination file for output.
    #[arg(long, value_name = "FILE")]
    output_file: Option<PathBuf>,

    #[command(subcommand)]
    action: ReportCollectorCommand,
}

#[derive(Debug, Parser)]
pub struct CommandInput {
    #[arg(
        long,
        help = "Read the input from the provided file, instead of standard input"
    )]
    input_file: Option<PathBuf>,
}

impl From<&CommandInput> for InputSource {
    fn from(source: &CommandInput) -> Self {
        if let Some(ref file_name) = source.input_file {
            InputSource::from_file(file_name)
        } else {
            InputSource::from_stdin()
        }
    }
}

#[derive(Debug, Subcommand)]
enum ReportCollectorCommand {
    /// Generate inputs for IPA
    GenIpaInputs {
        /// Number of records to generate
        #[clap(long, short = 'n')]
        count: u32,

        /// The seed for random generator.
        #[clap(long, short = 's')]
        seed: Option<u64>,

        #[clap(flatten)]
        gen_args: EventGeneratorConfig,
    },
    /// Apply differential privacy noise to IPA inputs
    ApplyDpNoise(ApplyDpArgs),
    /// Execute OPRF IPA in a semi-honest setting
    SemiHonestOprfIpa(IpaQueryConfig),
    /// Execute OPRF IPA in an honest majority (one malicious helper) setting
    MaliciousOprfIpa(IpaQueryConfig),
}

#[derive(Debug, clap::Args)]
struct GenInputArgs {
    /// Maximum records per user
    #[clap(long)]
    max_per_user: u32,
    /// number of breakdowns
    breakdowns: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let scheme = if args.disable_https {
        Scheme::HTTP
    } else {
        Scheme::HTTPS
    };

    let (clients, network) = make_clients(args.network.as_deref(), scheme, args.wait).await;
    match args.action {
        ReportCollectorCommand::GenIpaInputs {
            count,
            seed,
            gen_args,
        } => gen_inputs(count, seed, args.output_file, gen_args)?,
        ReportCollectorCommand::ApplyDpNoise(ref dp_args) => apply_dp_noise(&args, dp_args)?,
        ReportCollectorCommand::SemiHonestOprfIpa(config) => {
            ipa(
                &args,
                &network,
                IpaSecurityModel::SemiHonest,
                config,
                &clients,
                IpaQueryStyle::Oprf,
            )
            .await?
        }
        ReportCollectorCommand::MaliciousOprfIpa(config) => {
            ipa(
                &args,
                &network,
                IpaSecurityModel::Malicious,
                config,
                &clients,
                IpaQueryStyle::Oprf,
            )
            .await?
        }
    };

    Ok(())
}

fn gen_inputs(
    count: u32,
    seed: Option<u64>,
    output_file: Option<PathBuf>,
    args: EventGeneratorConfig,
) -> io::Result<()> {
    let rng = seed
        .map(StdRng::seed_from_u64)
        .unwrap_or_else(StdRng::from_entropy);
    let event_gen = EventGenerator::with_config(rng, args)
        .take(count as usize)
        .collect::<Vec<_>>();
    let mut writer: Box<dyn Write> = if let Some(path) = output_file {
        Box::new(OpenOptions::new().write(true).create_new(true).open(path)?)
    } else {
        Box::new(stdout().lock())
    };

    for event in event_gen {
        event.to_csv(&mut writer)?;
        writer.write_all(b"\n")?;
    }

    Ok(())
}

async fn ipa(
    args: &Args,
    network: &NetworkConfig,
    security_model: IpaSecurityModel,
    ipa_query_config: IpaQueryConfig,
    helper_clients: &[MpcHelperClient; 3],
    query_style: IpaQueryStyle,
) -> Result<(), Box<dyn Error>> {
    let input = InputSource::from(&args.input);
    let query_type = match (security_model, &query_style) {
        (IpaSecurityModel::SemiHonest, IpaQueryStyle::Oprf) => {
            QueryType::OprfIpaRelaxedDpPadding(ipa_query_config)
        }
        (IpaSecurityModel::Malicious, IpaQueryStyle::Oprf) => {
            QueryType::MaliciousOprfIpa(ipa_query_config)
        }
    };

    let input_rows = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();
    let query_config = QueryConfig {
        size: QuerySize::try_from(input_rows.len()).unwrap(),
        field_type: FieldType::Fp32BitPrime,
        query_type,
    };
    let query_id = helper_clients[0]
        .create_query(query_config)
        .await
        .expect("Unable to create query!");

    let expected = {
        let mut r = ipa_in_the_clear(
            &input_rows,
            ipa_query_config.per_user_credit_cap,
            ipa_query_config.attribution_window_seconds,
            ipa_query_config.max_breakdown_key,
            &(match query_style {
                IpaQueryStyle::Oprf => CappingOrder::CapMostRecentFirst,
            }),
        );

        // pad the output vector to the max breakdown key, to make sure it is aligned with the MPC results
        // truncate shouldn't happen unless in_the_clear is badly broken
        r.resize(
            usize::try_from(ipa_query_config.max_breakdown_key).unwrap(),
            0,
        );
        r
    };

    let mut key_registries = KeyRegistries::default();
    let Some(key_registries) = key_registries.init_from(network) else {
        panic!("could not load network file")
    };
    let actual = match query_style {
        IpaQueryStyle::Oprf => {
            // the value for histogram values (BA32) must be kept in sync with the server-side
            // implementation, otherwise a runtime reconstruct error will be generated.
            // see ipa-core/src/query/executor.rs
            playbook_oprf_ipa::<BA32, _>(
                input_rows,
                helper_clients,
                query_id,
                ipa_query_config,
                Some((DEFAULT_KEY_ID, key_registries)),
            )
            .await
        }
    };

    if let Some(ref path) = args.output_file {
        // it will be sad to lose the results if file already exists.
        let path = if Path::is_file(path) {
            let mut new_file_name = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(5)
                .map(char::from)
                .collect::<String>();
            let file_name = path.file_stem().ok_or("not a file")?;

            new_file_name.insert(0, '-');
            new_file_name.insert_str(0, &file_name.to_string_lossy());
            tracing::warn!(
                "{} file exists, renaming to {:?}",
                path.display(),
                new_file_name
            );

            // it will not be 100% accurate until file_prefix API is stabilized
            Cow::Owned(
                path.with_file_name(&new_file_name)
                    .with_extension(path.extension().unwrap_or("".as_ref())),
            )
        } else {
            Cow::Borrowed(path)
        };
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(path.deref())
            .map_err(|e| format!("Failed to create output file {}: {e}", path.display()))?;

        write!(file, "{}", serde_json::to_string_pretty(&actual)?)?;
    }

    tracing::info!("{m:?}", m = ipa_query_config);

    match ipa_query_config.with_dp {
        0 => {
            validate(&expected, &actual.breakdowns);
        }
        _ => {
            validate_dp(
                expected,
                actual.breakdowns,
                ipa_query_config.epsilon,
                ipa_query_config.per_user_credit_cap,
                DpMechanism::DiscreteLaplace {
                    epsilon: ipa_query_config.epsilon,
                },
            );
        }
    }

    Ok(())
}

fn apply_dp_noise(args: &Args, dp_args: &ApplyDpArgs) -> Result<(), Box<dyn Error>> {
    let IpaQueryResult { breakdowns, .. } =
        serde_json::from_slice(&InputSource::from(&args.input).to_vec()?)?;

    let output = apply(&breakdowns, dp_args);
    let mut table = Table::new();
    let header = std::iter::once("Epsilon".to_string())
        .chain(std::iter::once("Variance".to_string()))
        .chain(std::iter::once("Mean".to_string()))
        .chain((0..breakdowns.len()).map(|i| format!("{}", i + 1)))
        .collect::<Vec<_>>();
    table.set_header(header);

    // original values
    table.add_row(
        std::iter::repeat("-".to_string())
            .take(3)
            .chain(breakdowns.iter().map(ToString::to_string)),
    );

    // reverse because smaller epsilon means more noise and I print the original values
    // in the first row.
    for epsilon in output.keys().rev() {
        let noised_values = output.get(epsilon).unwrap();
        let mut row = vec![
            Cell::new(format!("{:.3}", epsilon)),
            Cell::new(format!("{:.3}", noised_values.std)),
            Cell::new(format!("{:.3}", noised_values.mean)),
        ];

        for agg in noised_values.breakdowns.iter() {
            row.push(Cell::new(format!("{}", agg)));
        }

        table.add_row(row);
    }

    println!("{}", table);

    if let Some(file) = &args.output_file {
        let mut file = File::create(file)?;
        serde_json::to_writer_pretty(&mut file, &output)?;
    }

    Ok(())
}
