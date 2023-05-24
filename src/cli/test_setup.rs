use crate::{
    cli::{keygen, KeygenArgs},
    config::ClientConfig,
};
use clap::Args;
use std::{
    error::Error,
    fs::{self, DirBuilder},
    iter::zip,
    path::PathBuf,
};
use toml::{map::Map, Table, Value};

#[derive(Debug, Args)]
#[clap(
    name = "test_setup",
    about = "Prepare a test network of three helpers",
    next_help_heading = "Test Setup Options"
)]
pub struct TestSetupArgs {
    #[arg(short, long, default_value = "test_data")]
    output_dir: PathBuf,

    /// Ignored. The same configuration can be used for HTTP and HTTPS.
    #[arg(long)]
    disable_https: bool,

    /// Configure helper clients to use HTTP1 instead of default HTTP version (HTTP2 at the moment).
    #[arg(long, default_value_t = false)]
    use_http1: bool,

    #[arg(short, long, num_args = 3, value_name = "PORT", default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,
}

/// Prepare a test network of three helpers.
///
/// # Errors
/// If a problem is encountered.
///
/// # Panics
/// If something that shouldn't happen goes wrong.
pub fn test_setup(args: TestSetupArgs) -> Result<(), Box<dyn Error>> {
    if args.output_dir.exists() {
        if !args.output_dir.is_dir() || args.output_dir.read_dir()?.next().is_some() {
            return Err("output directory already exists and is not empty".into());
        }
    } else {
        DirBuilder::new().create(&args.output_dir)?;
    }

    let peers = zip([1, 2, 3], args.ports)
        .map(|(id, port)| {
            let tls_cert = args.output_dir.join(format!("h{id}.pem"));
            let tls_key = args.output_dir.join(format!("h{id}.key"));

            keygen(KeygenArgs {
                name: String::from("localhost"),
                tls_cert: tls_cert.clone(),
                tls_key,
            })?;

            let certificate = fs::read_to_string(&tls_cert)?;

            // Constructing toml directly because it avoids linking
            // a PEM library to serialize the certificate.
            let mut peer = Map::new();
            peer.insert(
                String::from("url"),
                Value::String(format!("localhost:{port}")),
            );
            peer.insert(String::from("certificate"), Value::String(certificate));
            Ok::<_, Box<dyn Error>>(peer.into())
        })
        .collect::<Result<Vec<Value>, _>>()?
        .into();

    let client_config = if args.use_http1 {
        ClientConfig::use_http1()
    } else {
        ClientConfig::default()
    };
    let mut network_config = Map::new();
    network_config.insert(String::from("peers"), peers);
    network_config.insert(
        String::from("client"),
        Table::try_from(client_config)?.into(),
    );
    let network_config = toml::to_string_pretty(&network_config)?;

    fs::write(args.output_dir.join("network.toml"), network_config)?;

    Ok(())
}
