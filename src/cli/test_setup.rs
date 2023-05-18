use crate::{
    cli::{keygen, KeygenArgs},
    config::{ClientConfig, NetworkConfig, PeerConfig},
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

    /// Ignored. The same configuration can be used for HTTP and HTTPS.
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

    let configs: [(PeerConfig, ClientConfig); 3] = zip([1, 2, 3], args.ports)
        .map(|(id, port)| {
            let tls_cert = args.output_dir.join(format!("h{id}.pem"));
            let tls_key = args.output_dir.join(format!("h{id}.key"));
            let matchkey_encryption_file = args
                .output_dir
                .join(format!("h{id}_matchkey_encryption_key"));
            let matchkey_decryption_file = args
                .output_dir
                .join(format!("h{id}_matchkey_decryption_key"));

            keygen(&KeygenArgs {
                name: String::from("localhost"),
                tls_cert: tls_cert.clone(),
                tls_key,
                matchkey_encryption_file: matchkey_encryption_file.clone(),
                matchkey_decryption_file,
            })?;

            let certificate = Some(fs::read_to_string(&tls_cert)?);
            let matchkey_encryption = Some(fs::read_to_string(&matchkey_encryption_file)?);

            Ok::<_, Box<dyn Error>>((
                PeerConfig {
                    url: format!("localhost:{port}").parse().unwrap(),
                    certificate,
                },
                ClientConfig {
                    public_key: matchkey_encryption,
                },
            ))
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .unwrap();

    let network_config = toml::to_string_pretty(&NetworkConfig {
        peers: [
            configs[0].0.clone(),
            configs[1].0.clone(),
            configs[2].0.clone(),
        ],
        client_config: [
            configs[0].1.clone(),
            configs[1].1.clone(),
            configs[2].1.clone(),
        ],
    })?;

    fs::write(args.output_dir.join("network.toml"), network_config)?;

    Ok(())
}
