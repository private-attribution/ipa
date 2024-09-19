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
use hyper::http::uri::Scheme;
use ipa_core::{
    cli::{
        playbook::{
            make_clients, playbook_oprf_ipa, run_query_and_validate, validate, validate_dp,
            InputSource,
        },
        CsvSerializer, IpaQueryResult, Verbosity,
    },
    config::{KeyRegistries, NetworkConfig},
    ff::{boolean_array::BA32, FieldType},
    helpers::query::{DpMechanism, IpaQueryConfig, QueryConfig, QuerySize, QueryType},
    net::MpcHelperClient,
    report::{EncryptedOprfReportStreams, DEFAULT_KEY_ID},
    test_fixture::{
        ipa::{ipa_in_the_clear, CappingOrder, IpaSecurityModel, TestRawDataRecord},
        EventGenerator, EventGeneratorConfig, HybridEventGenerator, HybridGeneratorConfig,
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
    #[arg(long, value_name = "OUTPUT_FILE")]
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
    GenHybridInputs {
        /// Number of records to generate
        #[clap(long, short = 'n')]
        count: u32,

        /// The seed for random generator.
        #[clap(long, short = 's')]
        seed: Option<u64>,

        #[clap(flatten)]
        gen_args: HybridGeneratorConfig,
    },
    /// Execute OPRF IPA in a semi-honest majority setting with known test data
    /// and compare results against expectation
    SemiHonestOprfIpaTest(IpaQueryConfig),
    /// Execute OPRF IPA in an honest majority (one malicious helper) setting
    /// with known test data and compare results against expectation
    MaliciousOprfIpaTest(IpaQueryConfig),
    /// Execute OPRF IPA in a semi-honest majority setting with unknown encrypted data
    #[command(visible_alias = "oprf-ipa")]
    SemiHonestOprfIpa {
        #[clap(flatten)]
        encrypted_inputs: EncryptedInputs,

        #[clap(flatten)]
        ipa_query_config: IpaQueryConfig,
    },
    /// Execute OPRF IPA in an honest majority (one malicious helper) setting
    /// with unknown encrypted data
    MaliciousOprfIpa {
        #[clap(flatten)]
        encrypted_inputs: EncryptedInputs,

        #[clap(flatten)]
        ipa_query_config: IpaQueryConfig,
    },
}

#[derive(Debug, clap::Args)]
struct GenInputArgs {
    /// Maximum records per user
    #[clap(long)]
    max_per_user: u32,
    /// number of breakdowns
    breakdowns: u32,
}

#[derive(Debug, Parser)]
struct EncryptedInputs {
    /// The encrypted input for H1
    #[arg(long, value_name = "H1_ENCRYPTED_INPUT_FILE")]
    enc_input_file1: PathBuf,

    /// The encrypted input for H2
    #[arg(long, value_name = "H2_ENCRYPTED_INPUT_FILE")]
    enc_input_file2: PathBuf,

    /// The encrypted input for H3
    #[arg(long, value_name = "H3_ENCRYPTED_INPUT_FILE")]
    enc_input_file3: PathBuf,
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
        ReportCollectorCommand::GenHybridInputs {
            count,
            seed,
            gen_args,
        } => gen_hybrid_inputs(count, seed, args.output_file, gen_args)?,
        ReportCollectorCommand::SemiHonestOprfIpaTest(config) => {
            ipa_test(
                &args,
                &network,
                IpaSecurityModel::SemiHonest,
                config,
                &clients,
            )
            .await?
        }
        ReportCollectorCommand::MaliciousOprfIpaTest(config) => {
            ipa_test(
                &args,
                &network,
                IpaSecurityModel::Malicious,
                config,
                &clients,
            )
            .await?
        }
        ReportCollectorCommand::MaliciousOprfIpa {
            ref encrypted_inputs,
            ipa_query_config,
        } => {
            ipa(
                &args,
                IpaSecurityModel::Malicious,
                ipa_query_config,
                &clients,
                encrypted_inputs,
            )
            .await?
        }
        ReportCollectorCommand::SemiHonestOprfIpa {
            ref encrypted_inputs,
            ipa_query_config,
        } => {
            ipa(
                &args,
                IpaSecurityModel::SemiHonest,
                ipa_query_config,
                &clients,
                encrypted_inputs,
            )
            .await?
        }
    };

    Ok(())
}

fn gen_hybrid_inputs(
    count: u32,
    seed: Option<u64>,
    output_file: Option<PathBuf>,
    args: HybridGeneratorConfig,
) -> io::Result<()> {
    let rng = seed
        .map(StdRng::seed_from_u64)
        .unwrap_or_else(StdRng::from_entropy);
    let event_gen = HybridEventGenerator::with_config(rng, args).take(count as usize);

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

fn get_query_type(security_model: IpaSecurityModel, ipa_query_config: IpaQueryConfig) -> QueryType {
    match security_model {
        IpaSecurityModel::SemiHonest => QueryType::SemiHonestOprfIpa(ipa_query_config),
        IpaSecurityModel::Malicious => QueryType::MaliciousOprfIpa(ipa_query_config),
    }
}

fn write_ipa_output_file(
    path: &PathBuf,
    query_result: &IpaQueryResult,
) -> Result<(), Box<dyn Error>> {
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

    write!(file, "{}", serde_json::to_string_pretty(query_result)?)?;
    Ok(())
}

async fn ipa(
    args: &Args,
    security_model: IpaSecurityModel,
    ipa_query_config: IpaQueryConfig,
    helper_clients: &[MpcHelperClient; 3],
    encrypted_inputs: &EncryptedInputs,
) -> Result<(), Box<dyn Error>> {
    let query_type = get_query_type(security_model, ipa_query_config);

    let files = [
        &encrypted_inputs.enc_input_file1,
        &encrypted_inputs.enc_input_file2,
        &encrypted_inputs.enc_input_file3,
    ];

    let encrypted_oprf_report_streams = EncryptedOprfReportStreams::from(files);

    let query_config = QueryConfig {
        size: QuerySize::try_from(encrypted_oprf_report_streams.query_size).unwrap(),
        field_type: FieldType::Fp32BitPrime,
        query_type,
    };

    let query_id = helper_clients[0]
        .create_query(query_config)
        .await
        .expect("Unable to create query!");

    tracing::info!("Starting query for OPRF");
    // the value for histogram values (BA32) must be kept in sync with the server-side
    // implementation, otherwise a runtime reconstruct error will be generated.
    // see ipa-core/src/query/executor.rs
    let actual = run_query_and_validate::<BA32>(
        encrypted_oprf_report_streams.streams,
        encrypted_oprf_report_streams.query_size,
        helper_clients,
        query_id,
        ipa_query_config,
    )
    .await;

    if let Some(ref path) = args.output_file {
        write_ipa_output_file(path, &actual)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&actual)?);
    }
    Ok(())
}

async fn ipa_test(
    args: &Args,
    network: &NetworkConfig,
    security_model: IpaSecurityModel,
    ipa_query_config: IpaQueryConfig,
    helper_clients: &[MpcHelperClient; 3],
) -> Result<(), Box<dyn Error>> {
    let input = InputSource::from(&args.input);
    let query_type = get_query_type(security_model, ipa_query_config);

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
            &CappingOrder::CapMostRecentFirst,
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
    // the value for histogram values (BA32) must be kept in sync with the server-side
    // implementation, otherwise a runtime reconstruct error will be generated.
    // see ipa-core/src/query/executor.rs
    let actual = playbook_oprf_ipa::<BA32, _>(
        input_rows,
        helper_clients,
        query_id,
        ipa_query_config,
        Some((DEFAULT_KEY_ID, key_registries)),
    )
    .await;

    if let Some(ref path) = args.output_file {
        write_ipa_output_file(path, &actual)?;
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
