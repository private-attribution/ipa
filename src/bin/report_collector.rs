use clap::{Parser, Subcommand};
use hyper::http::uri::Scheme;
use ipa::{
    cli::{
        playbook::{playbook_ipa, InputSource},
        Verbosity,
    },
    config::NetworkConfig,
    ff::{FieldType, Fp31, Fp32BitPrime},
    helpers::query::{IpaQueryConfig, QueryConfig, QueryType},
    net::{ClientIdentity, MpcHelperClient},
    protocol::{BreakdownKey, MatchKey},
    test_fixture::ipa::{IpaSecurityModel, TestRawDataRecord},
};
use std::{error::Error, fmt::Debug, fs, path::PathBuf, time::Duration};
use tokio::time::sleep;

#[derive(Debug, Parser)]
#[clap(
    name = "report_collector",
    about = "CLI to execute test scenarios on IPA MPC helpers"
)]
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

    #[command(subcommand)]
    action: TestAction,
}

#[derive(Debug, Parser)]
pub struct CommandInput {
    #[arg(
        long,
        help = "Read the input from the provided file, instead of standard input"
    )]
    input_file: Option<PathBuf>,

    #[arg(value_enum, long, default_value_t = FieldType::Fp32BitPrime, help = "Convert the input into the given field before sending to helpers")]
    field: FieldType,
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
enum TestAction {
    /// Execute IPA in semi-honest honest majority setting
    SemiHonestIpa(IpaQueryConfig),
    /// Execute IPA in malicious honest majority setting
    MaliciousIpa(IpaQueryConfig),
}

async fn clients_ready(clients: &[MpcHelperClient; 3]) -> bool {
    clients[0].echo("").await.is_ok()
        && clients[1].echo("").await.is_ok()
        && clients[2].echo("").await.is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let make_clients = || async {
        let scheme = if args.disable_https {
            Scheme::HTTP
        } else {
            Scheme::HTTPS
        };

        let config_path = args.network.as_deref();
        let mut wait = args.wait;

        let config = if let Some(path) = config_path {
            NetworkConfig::from_toml_str(&fs::read_to_string(path).unwrap()).unwrap()
        } else {
            panic!("network.toml is malformed");
        }
        .override_scheme(&scheme);
        let clients = MpcHelperClient::from_conf(&config, ClientIdentity::None);
        while wait > 0 && !clients_ready(&clients).await {
            tracing::debug!("waiting for servers to come up");
            sleep(Duration::from_secs(1)).await;
            wait -= 1;
        }

        clients
    };

    match args.action {
        TestAction::SemiHonestIpa(config) => {
            ipa(
                &args,
                IpaSecurityModel::SemiHonest,
                &config,
                &make_clients().await,
            )
            .await
        }
        TestAction::MaliciousIpa(config) => {
            ipa(
                &args,
                IpaSecurityModel::Malicious,
                &config,
                &make_clients().await,
            )
            .await
        }
    };

    Ok(())
}

async fn ipa(
    args: &Args,
    security_model: IpaSecurityModel,
    ipa_query_config: &IpaQueryConfig,
    helper_clients: &[MpcHelperClient; 3],
) -> Vec<u32> {
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

    let query_config = QueryConfig {
        field_type: args.input.field,
        query_type,
    };
    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let input_rows = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();

    match args.input.field {
        FieldType::Fp31 => {
            playbook_ipa::<Fp31, MatchKey, BreakdownKey>(&input_rows, &helper_clients, query_id)
                .await
        }
        FieldType::Fp32BitPrime => {
            playbook_ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                &input_rows,
                &helper_clients,
                query_id,
            )
            .await
        }
    }
}
