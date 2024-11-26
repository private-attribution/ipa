use std::{
    fs::{DirBuilder, File},
    iter::zip,
    path::PathBuf,
};

use clap::Args;

use crate::{
    cli::{
        config_parse::{gen_client_config, HelperClientConf},
        keygen,
        paths::PathExt,
        KeygenArgs,
    },
    error::BoxError,
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

    /// Configure helper clients to use HTTP1 instead of default HTTP version (HTTP2 at the moment).
    #[arg(long, default_value_t = false)]
    use_http1: bool,

    #[arg(short, long, value_name = "PORT", default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,

    #[arg(short, long, value_name = "SHARD_PORT", default_values = vec!["6000", "6001", "6002"])]
    shard_ports: Vec<u16>,
}

/// Prepare a test network of three helpers.
///
/// # Errors
/// If a problem is encountered.
///
/// # Panics
/// If something that shouldn't happen goes wrong.
pub fn test_setup(args: TestSetupArgs) -> Result<(), BoxError> {
    assert_eq!(args.ports.len(), args.shard_ports.len(), "number of mpc ports and shard ports don't match");
    assert_eq!(args.ports.len() % 3, 0, "Number of ports must be a multiple of 3");

    if args.output_dir.exists() {
        if !args.output_dir.is_dir() || args.output_dir.read_dir()?.next().is_some() {
            return Err("output directory already exists and is not empty".into());
        }
    } else {
        DirBuilder::new().create(&args.output_dir)?;
    }

    let localhost = String::from("localhost");

    let clients_config: [_; 3] = zip([1, 2, 3], zip(args.ports, args.shard_ports))
        .map(|(id, (port, shard_port))| {
            let keygen_args = KeygenArgs {
                name: localhost.clone(),
                tls_cert: args.output_dir.helper_tls_cert(id),
                tls_key: args.output_dir.helper_tls_key(id),
                tls_expire_after: 365,
                mk_public_key: Some(args.output_dir.helper_mk_public_key(id)),
                mk_private_key: Some(args.output_dir.helper_mk_private_key(id)),
            };

            keygen(&keygen_args)?;

            Ok(HelperClientConf {
                host: localhost.to_string(),
                port,
                shard_port,
                tls_cert_file: keygen_args.tls_cert,
                mk_public_key_file: keygen_args.mk_public_key.unwrap(),
            })
        })
        .collect::<Result<Vec<_>, BoxError>>()?
        .try_into()
        .unwrap();

    let mut conf_file = File::create(args.output_dir.join("network.toml"))?;
    gen_client_config(clients_config.into_iter(), args.use_http1, &mut conf_file)
}
