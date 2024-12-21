use std::{
    fs,
    io::BufReader,
    net::TcpListener,
    os::fd::{FromRawFd, RawFd},
    path::{Path, PathBuf},
    process,
};

use clap::{self, Parser, Subcommand};
use futures::future::join;
use hyper::http::uri::Scheme;
use ipa_core::{
    cli::{
        client_config_setup, keygen, sharded_client_config_setup, sharded_server_from_toml_str,
        test_setup, ConfGenArgs, KeygenArgs, LoggingHandle, ShardedConfGenArgs, TestSetupArgs,
        Verbosity,
    },
    config::{hpke_registry, HpkeServerConfig, ServerConfig, TlsConfig},
    error::BoxError,
    executor::IpaRuntime,
    helpers::HelperIdentity,
    net::{
        ClientIdentity, ConnectionFlavor, IpaHttpClient, MpcHttpTransport, Shard,
        ShardHttpTransport,
    },
    sharding::ShardIndex,
    AppConfig, AppSetup, NonZeroU32PowerOfTwo,
};
use tokio::runtime::Runtime;
use tracing::{error, info};

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

    #[arg(long, default_value = "0")]
    shard_index: Option<u32>,

    #[arg(long, default_value = "1")]
    shard_count: Option<u32>,

    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: Option<u16>,

    /// Port to use for shard-to-shard communication, if sharded MPC is used
    #[arg(long, default_value = "6000")]
    shard_port: Option<u16>,

    /// Use the supplied prebound socket instead of binding a new socket for mpc
    ///
    /// This is only intended for avoiding port conflicts in tests.
    #[arg(hide = true, long)]
    server_socket_fd: Option<RawFd>,

    /// Use the supplied prebound socket instead of binding a new socket for shard server
    ///
    /// This is only intended for avoiding port conflicts in tests.
    #[arg(hide = true, long)]
    shard_server_socket_fd: Option<RawFd>,

    /// Use insecure HTTP
    #[arg(short = 'k', long)]
    disable_https: bool,

    /// File containing helper network configuration
    #[arg(long, required = true)]
    network: Option<PathBuf>,

    /// TLS certificate for helper-to-helper and shard-to-shard communication
    #[arg(
        long,
        visible_alias("cert"),
        visible_alias("tls-certificate"),
        requires = "tls_key"
    )]
    tls_cert: Option<PathBuf>,

    /// TLS key for helper-to-helper and shard-to-shard communication
    #[arg(long, visible_alias("key"), requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Public key for encrypting match keys
    #[arg(long, requires = "mk_private_key")]
    mk_public_key: Option<PathBuf>,

    /// Private key for decrypting match keys
    #[arg(long, requires = "mk_public_key")]
    mk_private_key: Option<PathBuf>,

    /// Override the amount of active work processed in parallel
    #[arg(long)]
    active_work: Option<NonZeroU32PowerOfTwo>,
}

#[derive(Debug, Subcommand)]
enum HelperCommand {
    ShardedConfgen(ShardedConfGenArgs),
    Confgen(ConfGenArgs),
    Keygen(KeygenArgs),
    TestSetup(TestSetupArgs),
}

fn read_file(path: &Path) -> Result<BufReader<fs::File>, BoxError> {
    Ok(fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map(BufReader::new)
        .map_err(|e| format!("failed to open file {}: {e:?}", path.display()))?)
}

/// Helper function that creates the client identity; either with certificates if they are provided
/// or just with headers otherwise. This works both for sharded and helper configs.
fn create_client_identity<F: ConnectionFlavor>(
    id: F::Identity,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<(ClientIdentity<F>, Option<TlsConfig>), BoxError> {
    match (tls_cert, tls_key) {
        (Some(cert_file), Some(key_file)) => {
            let mut key = read_file(&key_file)?;
            let mut certs = read_file(&cert_file)?;
            Ok((
                ClientIdentity::<F>::from_pkcs8(&mut certs, &mut key)?,
                Some(TlsConfig::File {
                    certificate_file: cert_file,
                    private_key_file: key_file,
                }),
            ))
        }
        (None, None) => Ok((ClientIdentity::Header(id), None)),
        _ => Err("should have been rejected by clap".into()),
    }
}

/// Creates a [`TcpListener`] from an optional raw file descriptor. Safety notes:
///  1. The `--server-socket-fd` option is only intended for use in tests, not in production.
///  2. This must be the only call to from_raw_fd for this file descriptor, to ensure it has
///     only one owner.
fn create_listener(server_socket_fd: Option<RawFd>) -> Result<Option<TcpListener>, BoxError> {
    server_socket_fd
        .map(|fd| {
            let listener = unsafe { TcpListener::from_raw_fd(fd) };
            if listener.local_addr().is_ok() {
                info!("adopting fd {fd} as listening socket");
                Ok(listener)
            } else {
                Err(BoxError::from(format!("the server was asked to listen on fd {fd}, but it does not appear to be a valid socket")))
            }
        })
        .transpose()
}

async fn server(args: ServerArgs, logging_handle: LoggingHandle) -> Result<(), BoxError> {
    let my_identity = HelperIdentity::try_from(args.identity.expect("enforced by clap")).unwrap();
    let shard_index = ShardIndex::from(args.shard_index.expect("enforced by clap"));
    let shard_count = ShardIndex::from(args.shard_count.expect("enforced by clap"));
    assert!(
        shard_index < shard_count,
        "Shard index should be lower than shard count"
    );
    assert_eq!(
        args.tls_cert.is_some(),
        !args.disable_https,
        "Inconsistent configuration: TLS certs and disable_http"
    );

    let (identity, server_tls) =
        create_client_identity(my_identity, args.tls_cert.clone(), args.tls_key.clone())?;
    let (shard_identity, shard_server_tls) =
        create_client_identity(shard_index, args.tls_cert, args.tls_key)?;

    let mk_encryption = args.mk_private_key.map(|sk_path| HpkeServerConfig::File {
        private_key_file: sk_path,
    });

    let query_runtime = new_query_runtime(&logging_handle);
    let app_config = AppConfig::default()
        .with_key_registry(hpke_registry(mk_encryption.as_ref()).await?)
        .with_active_work(args.active_work)
        .with_runtime(IpaRuntime::from_tokio_runtime(&query_runtime));

    let (setup, handler, shard_handler) = AppSetup::new(app_config);

    let server_config = ServerConfig {
        port: args.port,
        disable_https: args.disable_https,
        tls: server_tls,
        hpke_config: mk_encryption.clone(),
    };

    let shard_server_config = ServerConfig {
        port: args.shard_port,
        disable_https: args.disable_https,
        tls: shard_server_tls,
        hpke_config: mk_encryption,
    };

    let scheme = if args.disable_https {
        Scheme::HTTP
    } else {
        Scheme::HTTPS
    };

    let network_config_path = args.network.as_deref().unwrap();
    let network_config_string = &fs::read_to_string(network_config_path)?;
    let (mut mpc_network, mut shard_network) = sharded_server_from_toml_str(
        network_config_string,
        my_identity,
        shard_index,
        shard_count,
        args.shard_port,
    )?;
    mpc_network = mpc_network.override_scheme(&scheme);
    shard_network = shard_network.override_scheme(&scheme);

    let http_runtime = new_http_runtime(&logging_handle);
    let clients = IpaHttpClient::from_conf(
        &IpaRuntime::from_tokio_runtime(&http_runtime),
        &mpc_network,
        &identity,
    );
    let (transport, server) = MpcHttpTransport::new(
        IpaRuntime::from_tokio_runtime(&http_runtime),
        my_identity,
        server_config,
        mpc_network,
        &clients,
        Some(handler),
    );

    let shard_clients = IpaHttpClient::<Shard>::shards_from_conf(
        &IpaRuntime::from_tokio_runtime(&http_runtime),
        &shard_network,
        &shard_identity,
    );
    let (shard_transport, shard_server) = ShardHttpTransport::new(
        IpaRuntime::from_tokio_runtime(&http_runtime),
        shard_index,
        shard_count,
        shard_server_config,
        shard_network,
        shard_clients,
        Some(shard_handler),
    );

    let _app = setup.connect(transport.clone(), shard_transport.clone(), logging_handle);

    let listener = create_listener(args.server_socket_fd)?;
    let shard_listener = create_listener(args.shard_server_socket_fd)?;

    let (_addr, server_handle) = server
        .start_on(
            &IpaRuntime::from_tokio_runtime(&http_runtime),
            listener,
            // TODO, trace based on the content of the query.
            None as Option<()>,
        )
        .await;
    let (_saddr, shard_server_handle) = shard_server
        .start_on(
            &IpaRuntime::from_tokio_runtime(&http_runtime),
            shard_listener,
            // TODO, trace based on the content of the query.
            None as Option<()>,
        )
        .await;

    join(server_handle, shard_server_handle).await;

    [query_runtime, http_runtime].map(Runtime::shutdown_background);

    Ok(())
}

/// Creates a new runtime for HTTP stack. It is useful to provide a dedicated
/// scheduler to HTTP tasks, to make sure IPA server can respond to requests,
/// if for some reason query runtime becomes overloaded.
/// When multi-threading feature is enabled it creates a runtime with thread-per-core,
/// otherwise a single-threaded runtime is created.
fn new_http_runtime(logging_handle: &LoggingHandle) -> Runtime {
    if cfg!(feature = "multi-threading") {
        logging_handle
            .metrics_handle
            .tokio_bind(
                tokio::runtime::Builder::new_multi_thread()
                    .thread_name("http-worker")
                    .enable_all(),
            )
            .build()
            .unwrap()
    } else {
        logging_handle
            .metrics_handle
            .tokio_bind(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("http-worker")
                    .enable_all(),
            )
            .build()
            .unwrap()
    }
}

/// This function creates a runtime suitable for executing MPC queries.
/// When multi-threading feature is enabled it creates a runtime with thread-per-core,
/// otherwise a single-threaded runtime is created.
fn new_query_runtime(logging_handle: &LoggingHandle) -> Runtime {
    // it is intentional that IO driver is not enabled here (enable_time() call only).
    // query runtime is supposed to use CPU/memory only, no writes to disk and all
    // network communication is handled by HTTP runtime.
    if cfg!(feature = "multi-threading") {
        logging_handle
            .metrics_handle
            .tokio_bind(
                tokio::runtime::Builder::new_multi_thread()
                    .thread_name("query-executor")
                    .enable_time(),
            )
            .build()
            .unwrap()
    } else {
        logging_handle
            .metrics_handle
            .tokio_bind(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("query-executor")
                    .enable_time(),
            )
            .build()
            .unwrap()
    }
}

/// A single thread is enough here, because server spawns additional
/// runtimes to use in MPC queries and HTTP.
#[tokio::main(flavor = "current_thread")]
pub async fn main() {
    #[cfg(jemalloc)]
    ipa_core::use_jemalloc!();

    #[cfg(feature = "dhat-heap")]
    #[global_allocator]
    static ALLOC: dhat::Alloc = dhat::Alloc;

    let args = Args::parse();
    let handle = args.logging.setup_logging();

    let res = match args.command {
        None => server(args.server, handle).await,
        Some(HelperCommand::Keygen(args)) => keygen(&args),
        Some(HelperCommand::TestSetup(args)) => test_setup(&args),
        Some(HelperCommand::Confgen(args)) => client_config_setup(args),
        Some(HelperCommand::ShardedConfgen(args)) => sharded_client_config_setup(args),
    };

    if let Err(e) = res {
        error!("{e}");
        process::exit(1);
    }
}
