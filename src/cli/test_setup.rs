use crate::{
    cli::{keygen, KeygenArgs},
    config::{ClientConfig, HpkeClientConfig, NetworkConfig, PeerConfig},
};
use clap::Args;
use std::{
    error::Error,
    fs::{self, DirBuilder},
    iter::zip,
    path::PathBuf,
};
use std::fs::File;
use toml::{map::Map, Table, Value};
use crate::cli::clientconf::{gen_client_config, HelperClientConf};
use crate::cli::paths::PathExt;

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

    let localhost = String::from("localhost");

    let clients_config: [_; 3] = zip([1, 2, 3], args.ports).map(|(id, port)| {
        let keygen_args = KeygenArgs {
            name: localhost.clone(),
            tls_cert: args.output_dir.helper_tls_cert(id),
            tls_key: args.output_dir.helper_tls_key(id),
            mk_public_key: args.output_dir.helper_mk_public_key(id),
            mk_private_key: args.output_dir.helper_mk_private_key(id),
        };

        keygen(&keygen_args)?;

        Ok(HelperClientConf {
            host: &localhost,
            port,
            tls_cert_file: keygen_args.tls_cert.clone(),
            mk_public_key_file: keygen_args.mk_public_key.clone()
        })
    }).collect::<Result<Vec<_>, Box<dyn Error>>>()?.try_into().unwrap();

    let mut conf_file = File::create(args.output_dir.join("network.toml"))?;
    Ok(gen_client_config(clients_config, args.use_http1, &mut conf_file)?)
}
