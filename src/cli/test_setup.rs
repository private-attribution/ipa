use crate::{
    cli::{keygen, KeygenArgs},
    config::{NetworkConfig, PeerConfig},
};
use clap::Args;
use std::{
    error::Error,
    fs::{self, DirBuilder},
    iter::zip,
    path::PathBuf,
};

#[derive(Debug, Args)]
#[clap(
    name = "test_setup",
    about = "Prepare a test network of three helpers",
    next_help_heading = "Test Setup Options"
)]
pub struct TestSetupArgs {
    #[arg(short, long, default_value = "test_data")]
    output_dir: PathBuf,

    /// Write http URLs to the network configuration (certificates will still be generated)
    #[arg(long)]
    disable_https: bool,

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

            let certificate = Some(fs::read_to_string(&tls_cert)?);

            Ok::<_, Box<dyn Error>>(PeerConfig {
                url: format!(
                    "{}://localhost:{}",
                    if args.disable_https { "http" } else { "https" },
                    port
                )
                .parse()
                .unwrap(),
                certificate,
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .unwrap();

    let network_config = toml::to_string_pretty(&NetworkConfig { peers })?;

    fs::write(args.output_dir.join("network.toml"), network_config)?;

    Ok(())
}
