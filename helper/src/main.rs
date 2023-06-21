use clap::{self, Parser, Subcommand};
use hyper::http::uri::Scheme;
use ipa::{
    cli::{
        client_config_setup, keygen, test_setup, ConfGenArgs, KeygenArgs, TestSetupArgs, Verbosity,
    },
    config::{hpke_registry, HpkeServerConfig, NetworkConfig, ServerConfig, TlsConfig},
    error::BoxError,
    helpers::HelperIdentity,
    net::{ClientIdentity, HttpTransport, MpcHelperClient},
    AppSetup,
};
use std::{
    fs,
    net::TcpListener,
    os::fd::{FromRawFd, RawFd},
    path::{Path, PathBuf},
    process,
};
use tracing::{error, info};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, Parser)]
#[clap(
    name = "helper",
    about = "Interoperable Private Attribution (IPA) MPC helper"
)]
#[command(subcommand_negates_reqs = true)]
struct Args {
    /// Configure logging.
    #[clap(flatten)]
    logging: Verbosity,

    #[clap(flatten, next_help_heading = "Server Options")]
    server: ServerArgs,

    #[command(subcommand)]
    command: Option<HelperCommand>,
}

#[derive(Debug, clap::Args)]
struct ServerArgs {
    /// Identity of this helper in the MPC protocol (1, 2, or 3)
    // This is required when running the server, but the `subcommand_negates_reqs`
    // attribute on `Args` makes it optional when running a utility command.
    #[arg(short, long, required = true)]
    identity: Option<usize>,

    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: Option<u16>,

    /// Use the supplied prebound socket instead of binding a new socket
    ///
    /// This is only intended for avoiding port conflicts in tests.
    #[arg(hide = true, long)]
    server_socket_fd: Option<RawFd>,

    /// Use insecure HTTP
    #[arg(short = 'k', long)]
    disable_https: bool,

    /// File containing helper network configuration
    #[arg(long, required = true)]
    network: Option<PathBuf>,

    /// TLS certificate for helper-to-helper communication
    #[arg(
        long,
        visible_alias("cert"),
        visible_alias("tls-certificate"),
        requires = "tls_key"
    )]
    tls_cert: Option<PathBuf>,

    /// TLS key for helper-to-helper communication
    #[arg(long, visible_alias("key"), requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Public key for encrypting match keys
    #[arg(long, requires = "mk_private_key")]
    mk_public_key: Option<PathBuf>,

    /// Private key for decrypting match keys
    #[arg(long, requires = "mk_public_key")]
    mk_private_key: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum HelperCommand {
    Confgen(ConfGenArgs),
    Keygen(KeygenArgs),
    TestSetup(TestSetupArgs),
}

fn read_utf8_bytes(path: &Path) -> Result<Vec<u8>, BoxError> {
    Ok(fs::read_to_string(path)
        .map_err(|e| format!("failed to open file {}: {e:?}", path.display()))?
        .into_bytes())
}

async fn server(args: ServerArgs) -> Result<(), BoxError> {
    let my_identity = HelperIdentity::try_from(args.identity.expect("enforced by clap")).unwrap();

    let (identity, server_tls) = match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key_file)) => {
            let key = read_utf8_bytes(&key_file)?;
            let certs = read_utf8_bytes(&cert)?;
            (
                ClientIdentity::from_pks8(&certs, &key)?,
                Some(TlsConfig::File {
                    certificate_file: cert,
                    private_key_file: key_file,
                }),
            )
        }
        (None, None) => (ClientIdentity::Helper(my_identity), None),
        _ => panic!("should have been rejected by clap"),
    };

    let mk_encryption = args
        .mk_public_key
        .zip(args.mk_private_key)
        .map(|(pk_path, sk_path)| HpkeServerConfig::File {
            public_key_file: pk_path,
            private_key_file: sk_path,
        });

    let key_registry = hpke_registry(mk_encryption.as_ref()).await?;
    let (setup, callbacks) = AppSetup::with_key_registry(key_registry);

    let server_config = ServerConfig {
        port: args.port,
        disable_https: args.disable_https,
        tls: server_tls,
        hpke_config: mk_encryption,
    };

    let scheme = if args.disable_https {
        Scheme::HTTP
    } else {
        Scheme::HTTPS
    };
    let network_config_path = args.network.as_deref().unwrap();
    let network_config = NetworkConfig::from_toml_str(&fs::read_to_string(network_config_path)?)?
        .override_scheme(&scheme);
    let clients = MpcHelperClient::from_conf(&network_config, identity);

    let (transport, server) = HttpTransport::new(
        my_identity,
        server_config,
        network_config,
        clients,
        callbacks,
    );

    let _app = setup.connect(transport.clone());

    let listener = args.server_socket_fd
        .map(|fd| {
            // SAFETY:
            //  1. The `--server-socket-fd` option is only intended for use in tests, not in production.
            //  2. This must be the only call to from_raw_fd for this file descriptor, to ensure it has
            //     only one owner.
            let listener = unsafe { TcpListener::from_raw_fd(fd) };
            if listener.local_addr().is_ok() {
                info!("adopting fd {fd} as listening socket");
                Ok(listener)
            } else {
                Err(BoxError::from(format!("the server was asked to listen on fd {fd}, but it does not appear to be a valid socket")))
            }
        })
        .transpose()?;

    let (_addr, server_handle) = server
        .start_on(
            listener,
            // TODO, trace based on the content of the query.
            None as Option<()>,
        )
        .await;

    server_handle.await?;

    Ok(())
}

#[tokio::main]
pub async fn main() {
    let args = Args::parse();
    let _handle = args.logging.setup_logging();

    let res = match args.command {
        None => server(args.server).await,
        Some(HelperCommand::Keygen(args)) => keygen(&args),
        Some(HelperCommand::TestSetup(args)) => test_setup(args),
        Some(HelperCommand::Confgen(args)) => client_config_setup(args),
    };

    if let Err(e) = res {
        error!("{e}");
        process::exit(1);
    }
}
