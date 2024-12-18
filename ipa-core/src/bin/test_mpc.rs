use std::{
    error::Error,
    fmt::Debug,
    fs::File,
    io::ErrorKind,
    net::TcpListener,
    ops::Add,
    os::fd::{FromRawFd, RawFd},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use generic_array::ArrayLength;
use hyper::http::uri::Scheme;
use ipa_core::{
    cli::{
        playbook::{
            make_clients, make_sharded_clients, secure_add, secure_mul, secure_shuffle, validate,
            InputSource,
        },
        Verbosity,
    },
    ff::{
        boolean_array::BA64, Field, FieldType, Fp31, Fp32BitPrime, Serializable, U128Conversions,
    },
    helpers::query::{
        QueryConfig,
        QueryType::{TestAddInPrimeField, TestMultiply, TestShardedShuffle},
    },
    net::{Helper, IpaHttpClient},
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
};
use tiny_http::{Response, ResponseBox, Server, StatusCode};
use tracing::{error, info};

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

    #[arg(value_enum, long, default_value_t = FieldType::Fp32BitPrime, help = "Convert the input into the given field before sending to helpers")]
    field: FieldType,

    #[arg(
        long,
        conflicts_with = "input_file",
        help = "Instead of taking input from a file, generate the given number of field values for input"
    )]
    generate: Option<u64>,
}

impl From<&CommandInput> for InputSource {
    fn from(source: &CommandInput) -> Self {
        if let Some(ref file_name) = source.input_file {
            InputSource::from_file(file_name)
        } else if let Some(count) = source.generate {
            InputSource::from_generator(count)
        } else {
            InputSource::from_stdin()
        }
    }
}

#[derive(Debug, Subcommand)]
enum TestAction {
    /// Execute end-to-end multiplication.
    Multiply,
    /// Execute end-to-end simple addition circuit that uses prime fields.
    /// All helpers add their shares locally and set the resulting share to be the
    /// sum. No communication is required to run the circuit.
    AddInPrimeField,
    /// A test protocol for sharded MPCs. The goal here is to use
    /// both shard-to-shard and helper-to-helper communication channels.
    /// This is exactly what shuffle does and that's why it is picked
    /// for this purpose.
    ShardedShuffle,
    ServeInput(ServeInputArgs),
}

#[derive(Debug, clap::Args)]
#[clap(about = "Run a simple HTTP server to serve query input files")]
pub struct ServeInputArgs {
    /// Port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Listen on the supplied prebound socket instead of binding a new socket
    #[arg(long, conflicts_with = "port")]
    fd: Option<RawFd>,

    /// Directory with input files to serve
    #[arg(short, long = "dir")]
    directory: PathBuf,
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

    match args.action {
        TestAction::Multiply => {
            let (clients, _) = make_clients(args.network.as_deref(), scheme, args.wait).await;
            multiply(&args, &clients).await
        }
        TestAction::AddInPrimeField => {
            let (clients, _) = make_clients(args.network.as_deref(), scheme, args.wait).await;
            add(&args, &clients).await
        }
        TestAction::ShardedShuffle => {
            // we need clients to talk to each individual shard
            let (clients, _networks) = make_sharded_clients(
                args.network
                    .as_deref()
                    .expect("network config is required for sharded shuffle"),
                scheme,
                args.wait,
            )
            .await;
            sharded_shuffle(&args, clients).await
        }
        TestAction::ServeInput(options) => serve_input(options),
    };

    Ok(())
}

async fn multiply_in_field<F>(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3])
where
    F: Field + U128Conversions + IntoShares<AdditiveShare<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    let input = InputSource::from(&args.input);
    let input_rows = input.iter::<(F, F)>().collect::<Vec<_>>();
    let query_config = QueryConfig::new(TestMultiply, args.input.field, input_rows.len()).unwrap();

    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let expected = input_rows.iter().map(|(a, b)| *a * *b).collect::<Vec<_>>();
    let actual = secure_mul(input_rows, helper_clients, query_id).await;

    validate(&expected, &actual);
}

async fn multiply(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3]) {
    match args.input.field {
        FieldType::Fp31 => multiply_in_field::<Fp31>(args, helper_clients).await,
        FieldType::Fp32BitPrime => multiply_in_field::<Fp32BitPrime>(args, helper_clients).await,
    };
}

async fn add_in_field<F>(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3])
where
    F: Field + U128Conversions + IntoShares<AdditiveShare<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    let input = InputSource::from(&args.input);
    // compute the sum as we are iterating through the input. That avoid cloning the iterator
    let mut expected = F::ZERO;
    let input_rows = input.known_size_iter().map(F::truncate_from).map(|v| {
        expected += v;
        v
    });
    let query_config =
        QueryConfig::new(TestAddInPrimeField, args.input.field, input_rows.len()).unwrap();

    let query_id = helper_clients[0].create_query(query_config).await.unwrap();
    let actual = secure_add(input_rows, helper_clients, query_id).await;

    validate(&vec![expected], &vec![actual]);
}

async fn add(args: &Args, helper_clients: &[IpaHttpClient<Helper>; 3]) {
    match args.input.field {
        FieldType::Fp31 => add_in_field::<Fp31>(args, helper_clients).await,
        FieldType::Fp32BitPrime => add_in_field::<Fp32BitPrime>(args, helper_clients).await,
    };
}

async fn sharded_shuffle(args: &Args, helper_clients: Vec<[IpaHttpClient<Helper>; 3]>) {
    let input = InputSource::from(&args.input);
    let input_rows = input
        .iter::<u64>()
        .map(BA64::truncate_from)
        .collect::<Vec<_>>();
    let query_config =
        QueryConfig::new(TestShardedShuffle, args.input.field, input_rows.len()).unwrap();
    let query_id = helper_clients[0][0]
        .create_query(query_config)
        .await
        .unwrap();
    let shuffled = secure_shuffle(input_rows.clone(), &helper_clients, query_id).await;

    assert_eq!(shuffled.len(), input_rows.len());
    assert_ne!(shuffled, input_rows);
}

fn not_found() -> ResponseBox {
    Response::from_string("not found")
        .with_status_code(StatusCode(404))
        .boxed()
}

#[tracing::instrument("serve_input", skip_all)]
fn serve_input(args: ServeInputArgs) {
    let server = if let Some(port) = args.port {
        Server::http(("localhost", port)).unwrap()
    } else if let Some(fd) = args.fd {
        Server::from_listener(unsafe { TcpListener::from_raw_fd(fd) }, None).unwrap()
    } else {
        Server::http("localhost:0").unwrap()
    };

    if args.port.is_none() {
        info!(
            "Listening on :{}",
            server.server_addr().to_ip().unwrap().port()
        );
    }

    loop {
        let request = server.recv().unwrap();
        tracing::info!(target: "request_url", "{}", request.url());

        let url = request.url()[1..].to_owned();
        let response = if url.contains('/') {
            error!(target: "error", "Request URL contains a slash");
            not_found()
        } else {
            match File::open(args.directory.join(&url)) {
                Ok(file) => Response::from_file(file).boxed(),
                Err(err) => {
                    if err.kind() != ErrorKind::NotFound {
                        error!(target: "error", "{err}");
                    }
                    not_found()
                }
            }
        };

        let _ = request.respond(response).map_err(|err| {
            error!(target: "error", "{err}");
        });
    }
}
