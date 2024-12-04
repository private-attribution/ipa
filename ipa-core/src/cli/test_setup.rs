use std::{
    fs::{self, DirBuilder, File},
    iter::zip,
    path::{Path, PathBuf},
};

use clap::Args;

use super::clientconf::shard_conf_folder;
use crate::{
    cli::{
        config_parse::{gen_client_config, HelperClientConf},
        keygen,
        paths::PathExt,
        KeygenArgs,
    },
    error::BoxError,
    sharding::ShardIndex,
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

impl TestSetupArgs {
    /// Returns number of shards requested for setup.
    fn shard_count(&self) -> usize {
        self.ports.len() / 3
    }

    /// If the number of shards requested is greater than 1
    /// then we configure a sharded environment, otherwise
    /// a fixed 3-host MPC configuration is created
    fn is_sharded(&self) -> bool {
        self.shard_count() > 1
    }
}

/// Prepare a test network of three helpers.
///
/// # Errors
/// If a problem is encountered.
///
/// # Panics
/// If something that shouldn't happen goes wrong.
pub fn test_setup(args: &TestSetupArgs) -> Result<(), BoxError> {
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

    if args.is_sharded() {
        sharded_keygen(args)
    } else {
        non_sharded_keygen(args)
    }
}

fn sharded_keygen(args: &TestSetupArgs) -> Result<(), BoxError> {
    const RING_SIZE: usize = 3;

    // we split all ports into chunks of 3 (for each MPC ring) and go over
    // all of them, creating configuration
    let clients_config: Vec<_> = zip(
        args.ports.chunks(RING_SIZE),
        args.shard_ports.chunks(RING_SIZE),
    )
    .enumerate()
    .flat_map(|(shard_id, (mpc_ports, shard_ports))| {
        let shard_dir = args.output_dir.join(shard_conf_folder(shard_id));
        DirBuilder::new().create(&shard_dir)?;
        make_client_configs(mpc_ports, shard_ports, &shard_dir)
    })
    .flatten()
    .collect::<Vec<_>>();

    // for match key encryption keys we need to do some extra work. All shards
    // must have access to the same set of encryption keys in order to decrypt the
    // reports. So we distribute the leader encryption keys across all shards.
    let first_shard_dir = args.output_dir.join(shard_conf_folder(ShardIndex::FIRST));
    for dest_shard in 1..args.shard_count() {
        let dest_shard_dir = args.output_dir.join(shard_conf_folder(dest_shard));
        for helper_id in 1..=3 {
            fs::copy(
                first_shard_dir.helper_mk_public_key(helper_id),
                dest_shard_dir.helper_mk_public_key(helper_id),
            )?;
            fs::copy(
                first_shard_dir.helper_mk_private_key(helper_id),
                dest_shard_dir.helper_mk_private_key(helper_id),
            )?;
        }
    }

    let mut conf_file = File::create(args.output_dir.join("network.toml"))?;
    gen_client_config(clients_config, args.use_http1, &mut conf_file)
}

/// This generates directories and files needed to run a non-sharded MPC.
/// The directory structure is flattened and does not include per-shard configuration.
fn non_sharded_keygen(args: &TestSetupArgs) -> Result<(), BoxError> {
    let client_configs = make_client_configs(&args.ports, &args.shard_ports, &args.output_dir)?;

    let mut conf_file = File::create(args.output_dir.join("network.toml"))?;
    gen_client_config(client_configs, args.use_http1, &mut conf_file)
}

fn make_client_configs(
    mpc_ports: &[u16],
    shard_ports: &[u16],
    config_dir: &Path,
) -> Result<Vec<HelperClientConf>, BoxError> {
    assert_eq!(shard_ports.len(), mpc_ports.len());
    assert_eq!(3, shard_ports.len());

    let localhost = String::from("localhost");
    zip(mpc_ports.iter(), shard_ports.iter())
        .enumerate()
        .map(|(i, (&mpc_port, &shard_port))| {
            let id = u8::try_from(i + 1).unwrap();

            let keygen_args = KeygenArgs {
                name: localhost.clone(),
                tls_cert: config_dir.helper_tls_cert(id),
                tls_key: config_dir.helper_tls_key(id),
                tls_expire_after: 365,
                mk_public_key: Some(config_dir.helper_mk_public_key(id)),
                mk_private_key: Some(config_dir.helper_mk_private_key(id)),
            };

            keygen(&keygen_args)?;

            Ok(HelperClientConf {
                host: localhost.to_string(),
                port: mpc_port,
                shard_port,
                tls_cert_file: keygen_args.tls_cert,
                mk_public_key_file: keygen_args.mk_public_key.unwrap(),
            })
        })
        .collect::<Result<_, _>>()
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
        test_setup(&args).unwrap();
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
        test_setup(&args).unwrap();
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
        test_setup(&args).unwrap();
    }
}
