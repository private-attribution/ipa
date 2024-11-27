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

    /// A list of ALL the MPC ports for all servers. If you have a server with shard count 4, you
    /// will have to provide 12 ports.
    #[arg(short, long, value_name = "PORT", num_args = 1.., default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,

    /// A list of ALL the sharding ports for all servers. If you have a server with shard count 4,
    /// you will have to provide 12 ports.
    #[arg(short, long, value_name = "SHARD_PORT", num_args = 1.., default_values = vec!["6000", "6001", "6002"])]
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
    assert_eq!(
        args.ports.len(),
        args.shard_ports.len(),
        "number of mpc ports and shard ports don't match"
    );
    assert_eq!(
        args.ports.len() % 3,
        0,
        "Number of ports must be a multiple of 3"
    );
    assert!(
        !args.ports.is_empty() && !args.shard_ports.is_empty(),
        "Please provide a list of ports"
    );

    if args.output_dir.exists() {
        if !args.output_dir.is_dir() || args.output_dir.read_dir()?.next().is_some() {
            return Err("output directory already exists and is not empty".into());
        }
    } else {
        DirBuilder::new().create(&args.output_dir)?;
    }

    let localhost = String::from("localhost");

    let keygen_args: Vec<_> = [1, 2, 3]
        .into_iter()
        .cycle()
        .take(args.ports.len())
        .enumerate()
        .map(|(i, id)| {
            //let helper_dir = .join(format!("helper{}", id));
            //DirBuilder::new().create(&helper_dir).unwrap();
            let shard_dir = args.output_dir.join(format!("shard{i}"));
            DirBuilder::new().create(&shard_dir).unwrap();
            if i < 3 {
                // Only leader shards generate MK keys
                KeygenArgs {
                    name: localhost.clone(),
                    tls_cert: shard_dir.helper_tls_cert(id),
                    tls_key: shard_dir.helper_tls_key(id),
                    tls_expire_after: 365,
                    mk_public_key: Some(shard_dir.helper_mk_public_key(id)),
                    mk_private_key: Some(shard_dir.helper_mk_private_key(id)),
                }
            } else {
                KeygenArgs {
                    name: localhost.clone(),
                    tls_cert: shard_dir.helper_tls_cert(id),
                    tls_key: shard_dir.helper_tls_key(id),
                    tls_expire_after: 365,
                    mk_public_key: None,
                    mk_private_key: None,
                }
            }
        })
        .collect();

    for ka in &keygen_args {
        keygen(ka)?;
    }

    let clients_config: Vec<_> = zip(
        keygen_args.iter(),
        zip(
            keygen_args.clone().into_iter().take(3).cycle(),
            zip(args.ports, args.shard_ports),
        ),
    )
    .map(
        |(keygen, (leader_keygen, (port, shard_port)))| HelperClientConf {
            host: localhost.to_string(),
            port,
            shard_port,
            tls_cert_file: keygen.tls_cert.clone(),
            mk_public_key_file: leader_keygen.mk_public_key.clone().unwrap(),
        },
    )
    .collect();

    let mut conf_file = File::create(args.output_dir.join("network.toml"))?;
    gen_client_config(clients_config.into_iter(), args.use_http1, &mut conf_file)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use crate::{
        cli::{sharded_server_from_toml_str, test_setup, TestSetupArgs},
        helpers::HelperIdentity,
        sharding::ShardIndex,
    };

    #[test]
    fn test_happy_case() {
        let temp_dir = TempDir::new().unwrap();
        let outdir = temp_dir.path().to_path_buf();
        let args = TestSetupArgs {
            output_dir: outdir.clone(),
            disable_https: false,
            use_http1: false,
            ports: vec![3000, 3001, 3002, 3003, 3004, 3005],
            shard_ports: vec![6000, 6001, 6002, 6003, 6004, 6005],
        };
        test_setup(args).unwrap();
        let network_config_path = outdir.join("network.toml");
        let network_config_string = &fs::read_to_string(network_config_path).unwrap();
        let _r = sharded_server_from_toml_str(
            network_config_string,
            HelperIdentity::TWO,
            ShardIndex::from(1),
            ShardIndex::from(2),
            None,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Please provide a list of ports")]
    fn test_empty_ports() {
        let temp_dir = TempDir::new().unwrap();
        let outdir = temp_dir.path().to_path_buf();
        let args = TestSetupArgs {
            output_dir: outdir,
            disable_https: false,
            use_http1: false,
            ports: vec![],
            shard_ports: vec![],
        };
        test_setup(args).unwrap();
    }

    #[test]
    #[should_panic(expected = "number of mpc ports and shard ports don't match")]
    fn test_mismatched_ports() {
        let temp_dir = TempDir::new().unwrap();
        let outdir = temp_dir.path().to_path_buf();
        let args = TestSetupArgs {
            output_dir: outdir,
            disable_https: false,
            use_http1: false,
            ports: vec![3000, 3001],
            shard_ports: vec![6000, 6001, 6002],
        };
        test_setup(args).unwrap();
    }
}
