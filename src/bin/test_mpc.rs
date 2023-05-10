use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::Table;
use hyper::http::uri::Scheme;
use ipa::{
    cli::{
        playbook::{secure_mul, semi_honest, InputSource},
        Verbosity,
    },
    config::NetworkConfig,
    ff::{FieldType, Fp31, Fp32BitPrime},
    helpers::query::{IpaQueryConfig, QueryConfig, QueryType},
    net::MpcHelperClient,
    protocol::{BreakdownKey, MatchKey},
    test_fixture::config::TestConfigBuilder,
};
use std::{error::Error, fmt::Debug, fs, path::PathBuf, time::Duration};
use tokio::time::sleep;

#[derive(Debug, Parser)]
#[clap(
    name = "mpc-client",
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

    #[arg(value_enum, long, default_value_t = InputType::Fp31, help = "Convert the input into the given field before sending to helpers")]
    input_type: InputType,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InputType {
    Fp31,
    Fp32BitPrime,
    Int64,
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Execute end-to-end multiplication.
    Multiply,
    /// Execute IPA in semi-honest majority setting
    SemiHonestIPA,
}

async fn clients_ready(clients: &[MpcHelperClient; 3]) -> bool {
    clients[0].echo("").await.is_ok()
        && clients[1].echo("").await.is_ok()
        && clients[2].echo("").await.is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    fn print_output<O: Debug>(values: &[Vec<O>; 3]) {
        let mut shares_table = Table::new();
        shares_table.set_header(vec!["Row", "H1", "H2", "H3"]);
        for i in 0..values[0].len() {
            shares_table.add_row(vec![
                i.to_string(),
                format!("{:?}", values[0][i]),
                format!("{:?}", values[1][i]),
                format!("{:?}", values[2][i]),
            ]);
        }

        println!("{shares_table}");
    }

    fn make_clients(disable_https: bool, config_path: Option<PathBuf>) -> [MpcHelperClient; 3] {
        let scheme = if disable_https {
            Scheme::HTTP
        } else {
            Scheme::HTTPS
        };
        let config = if let Some(path) = config_path {
            NetworkConfig::from_toml_str(&fs::read_to_string(path).unwrap()).unwrap()
        } else {
            TestConfigBuilder::with_default_test_ports().build().network
        }
        .override_scheme(&scheme);
        MpcHelperClient::from_conf(&config)
    }

    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let input = InputSource::from(&args.input);
    let clients = make_clients(args.disable_https, args.network);

    let mut wait = args.wait;
    while wait > 0 && !clients_ready(&clients).await {
        println!("waiting for servers to come up");
        sleep(Duration::from_secs(1)).await;
        wait -= 1;
    }

    match args.action {
        TestAction::Multiply => match args.input.input_type {
            InputType::Fp31 => {
                let query_config = QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                };
                let query_id = clients[0].create_query(query_config).await.unwrap();
                let output = secure_mul::<Fp31>(input, &clients, query_id).await;
                print_output(&output);
            }
            InputType::Fp32BitPrime => {
                unimplemented!()
            }
            InputType::Int64 => panic!("Only field values are supported"),
        },
        TestAction::SemiHonestIPA => {
            let query_type = QueryType::Ipa(IpaQueryConfig {
                per_user_credit_cap: 3,
                max_breakdown_key: 3,
                num_multi_bits: 3,
                attribution_window_seconds: 0,
            });

            match args.input.input_type {
                InputType::Fp31 => {
                    let query_config = QueryConfig {
                        field_type: FieldType::Fp31,
                        query_type,
                    };
                    let query_id = clients[0].create_query(query_config).await.unwrap();
                    let output =
                        semi_honest::<Fp31, MatchKey, BreakdownKey>(input, &clients, query_id)
                            .await;
                    print_output(&output);
                }
                InputType::Fp32BitPrime => {
                    let query_config = QueryConfig {
                        field_type: FieldType::Fp32BitPrime,
                        query_type,
                    };
                    let query_id = clients[0].create_query(query_config).await.unwrap();
                    let output = semi_honest::<Fp32BitPrime, MatchKey, BreakdownKey>(
                        input, &clients, query_id,
                    )
                    .await;
                    print_output(&output);
                }
                InputType::Int64 => panic!("Only field values are supported"),
            }
        }
    };

    Ok(())
}
