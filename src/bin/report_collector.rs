use clap::{Parser, Subcommand};
use hyper::http::uri::Scheme;
use ipa::{
    cli::{
        playbook::{make_clients, playbook_ipa, validate, InputSource},
        Verbosity,
    },
    config::NetworkConfig,
    ff::{FieldType, Fp32BitPrime},
    helpers::query::{IpaQueryConfig, QueryConfig, QueryType},
    hpke::{KeyRegistry, PublicKeyOnly},
    net::MpcHelperClient,
    protocol::{BreakdownKey, MatchKey},
    report::{KeyIdentifier, DEFAULT_KEY_ID},
    test_fixture::{
        ipa::{ipa_in_the_clear, IpaSecurityModel, TestRawDataRecord},
        EventGenerator, EventGeneratorConfig,
    },
};

use ipa::{cli::CsvSerializer, helpers::query::QuerySize};
use rand::{distributions::Alphanumeric, rngs::StdRng, thread_rng, Rng};
use rand_core::SeedableRng;
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

    /// The destination file for generated records
    #[arg(long)]
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
    /// Execute IPA in semi-honest honest majority setting
    SemiHonestIpa(IpaQueryConfig),
    /// Execute IPA in malicious honest majority setting
    MaliciousIpa(IpaQueryConfig),
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
        ReportCollectorCommand::SemiHonestIpa(config) => {
            ipa(
                &args,
                &network,
                IpaSecurityModel::SemiHonest,
                config,
                &clients,
            )
            .await?
        }
        ReportCollectorCommand::MaliciousIpa(config) => {
            ipa(
                &args,
                &network,
                IpaSecurityModel::Malicious,
                config,
                &clients,
            )
            .await?
        }
        ReportCollectorCommand::GenIpaInputs {
            count,
            seed,
            gen_args,
        } => gen_inputs(count, seed, args.output_file, gen_args).unwrap(),
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
        .unwrap_or_else(|| StdRng::from_entropy());
    let event_gen = EventGenerator::with_config(rng, args).take(count as usize);
    let mut writer: Box<dyn Write> = if let Some(path) = output_file {
        Box::new(OpenOptions::new().write(true).create_new(true).open(path)?)
    } else {
        Box::new(stdout().lock())
    };

    for event in event_gen {
        event.to_csv(&mut writer)?;
        writer.write(&[b'\n'])?;
    }

    Ok(())
}

#[derive(Default)]
struct KeyRegistries(Vec<KeyRegistry<PublicKeyOnly>>);

impl KeyRegistries {
    fn init_from(
        &mut self,
        network: &NetworkConfig,
    ) -> Option<(KeyIdentifier, [&KeyRegistry<PublicKeyOnly>; 3])> {
        // Get the configs, if all three peers have one
        let Some(configs) = network
            .peers()
            .iter()
            .fold(Some(vec![]), |acc, peer| {
                if let (Some(mut vec), Some(hpke_config)) = (acc, peer.hpke_config.as_ref()) {
                    vec.push(hpke_config);
                    Some(vec)
                } else {
                    None
                }
            })
        else {
            return None;
        };

        // Create key registries
        self.0 = configs
            .into_iter()
            .map(|hpke| KeyRegistry::from_keys([PublicKeyOnly(hpke.public_key.clone())]))
            .collect::<Vec<KeyRegistry<PublicKeyOnly>>>();

        Some((
            DEFAULT_KEY_ID,
            self.0.iter().collect::<Vec<_>>().try_into().ok().unwrap(),
        ))
    }
}

async fn ipa(
    args: &Args,
    network: &NetworkConfig,
    security_model: IpaSecurityModel,
    ipa_query_config: IpaQueryConfig,
    helper_clients: &[MpcHelperClient; 3],
) -> Result<(), Box<dyn Error>> {
    let input = InputSource::from(&args.input);
    let query_type: QueryType;
    match security_model {
        IpaSecurityModel::SemiHonest => {
            query_type = QueryType::SemiHonestIpa(ipa_query_config.clone());
        }
        IpaSecurityModel::Malicious => {
            query_type = QueryType::MaliciousIpa(ipa_query_config.clone())
        }
    };

    let input_rows = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();
    let query_config = QueryConfig {
        size: QuerySize::try_from(input_rows.len()).unwrap(),
        field_type: FieldType::Fp32BitPrime,
        query_type,
    };
    let query_id = helper_clients[0].create_query(query_config).await.unwrap();

    let expected = {
        let mut r = ipa_in_the_clear(
            &input_rows,
            ipa_query_config.per_user_credit_cap,
            ipa_query_config.attribution_window_seconds,
            ipa_query_config.max_breakdown_key,
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
    let actual = playbook_ipa::<Fp32BitPrime, MatchKey, BreakdownKey, _>(
        &input_rows,
        &helper_clients,
        query_id,
        ipa_query_config,
        key_registries.init_from(network),
    )
    .await;

    tracing::info!("{m:?}", m = ipa_query_config);

    validate(&expected, &actual.breakdowns);

    if let Some(ref path) = args.output_file {
        // it will be sad to lose the results if file already exists.
        let path = if Path::is_file(&path) {
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

    Ok(())
}
