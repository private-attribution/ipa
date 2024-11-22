use std::{fs, fs::File, iter::zip, path::PathBuf};

use clap::Args;

use crate::{
    cli::{
        config_parse::{gen_client_config, HelperClientConf},
        paths::PathExt,
    },
    error::BoxError,
    helpers::HelperIdentity,
};

#[derive(Debug, Args)]
#[clap(about = "Generate client config for 3 MPC helper parties")]
pub struct ConfGenArgs {
    #[arg(short, long, num_args = 3, value_name = "PORT", default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,

    #[arg(short, long, num_args = 3, value_name = "SHARD_PORTS", default_values = vec!["6000", "6001", "6002"])]
    shard_ports: Vec<u16>,

    #[arg(long, num_args = 3, default_values = vec!["localhost", "localhost", "localhost"])]
    hosts: Vec<String>,

    /// Path to the folder where certificates and public keys are stored. It must have all 3 helper's
    /// public keys and TLS certificates named according to the naming [`convention`].
    ///
    /// [`convention`]: crate::cli::CliPaths
    #[arg(long)]
    pub(crate) keys_dir: PathBuf,

    /// Destination folder for the config file. If not specified, `keys_folder` will be used.
    #[arg(long)]
    pub(crate) output_dir: Option<PathBuf>,

    /// Overwrite configuration file if it exists at destination.
    #[arg(long, default_value_t = false)]
    pub(crate) overwrite: bool,
}

/// Generate client configuration file that is understood by helper binaries and report collector
/// binary. This configuration describes the public interface to each helper: tls certificate and
/// the public key for HPKE encryption along with the endpoint to talk to.
///
/// It expects certain naming convention for TLS and encryption stuff, see [`Paths`] for more
/// details.
///
/// ## Errors
/// Returns an error if it can't find all three helper's public keys and TLS certs in the folder
/// specified in [`ConfGenArgs`] or if it fails to create the configuration file. Note that if file
/// already exists, without `--overwrite` flag specified, this command will also fail.
///
/// ## Panics
/// It does not panic, but compiler does not know about it.
///
/// [`ConfGenArgs`]: ConfGenArgs
/// [`Paths`]: crate::cli::paths::PathExt
pub fn setup(args: ConfGenArgs) -> Result<(), BoxError> {
    let clients_conf: [_; 3] = zip(args.hosts.iter(), zip(args.ports, args.shard_ports))
        .enumerate()
        .map(|(id, (host, (port, shard_port)))| {
            let id: u8 = u8::try_from(id).unwrap() + 1;
            HelperClientConf {
                host: host.to_string(),
                port,
                shard_port,
                tls_cert_file: args.keys_dir.helper_tls_cert(id),
                mk_public_key_file: args.keys_dir.helper_mk_public_key(id),
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    gen_conf_from_args(
        args.output_dir,
        args.overwrite,
        args.keys_dir,
        clients_conf.into_iter(),
    )
}

#[derive(Debug, Args)]
#[clap(about = "Generate client config for a sharded MPC")]
pub struct ShardedConfGenArgs {
    /// Base directory containing the host keys. `scripts/create-sharded-conf.py` generates the
    /// expected structure. Here's an example:
    /// ```cli
    /// ├── helper1
    /// │   ├── shard0
    /// │   │   ├── helper1.shard0.prod.ipa-helper.dev.key
    /// │   │   ├── helper1.shard0.prod.ipa-helper.dev.pem
    /// │   │   ├── helper1.shard0.prod.ipa-helper.dev_mk.key
    /// │   │   └── helper1.shard0.prod.ipa-helper.dev_mk.pub
    /// │   ├── shard1
    /// │   │   ├── helper1.shard1.prod.ipa-helper.dev.key
    /// │   │   ├── helper1.shard1.prod.ipa-helper.dev.pem
    /// │   │   ├── helper1.shard1.prod.ipa-helper.dev_mk.key
    /// │   │   └── helper1.shard1.prod.ipa-helper.dev_mk.pub
    /// ├── helper2
    /// │   ├── shard0
    /// │   │   ├── helper2.shard0.prod.ipa-helper.dev.key
    /// │   │   ├── helper2.shard0.prod.ipa-helper.dev.pem
    /// │   │   ├── helper2.shard0.prod.ipa-helper.dev_mk.key
    /// ...
    /// ```
    #[arg(long)]
    pub keys_dir: PathBuf,

    /// Number of shards per helper
    #[arg(long)]
    pub shard_count: u32,

    /// Shard port number to be used for all servers.
    #[arg(long)]
    pub shards_port: u16,

    /// MPC port number  to be used for all servers.
    #[arg(long)]
    pub mpc_port: u16,

    /// Destination folder for the config file. If not specified, `keys_folder` will be used.
    #[arg(long)]
    pub(crate) output_dir: Option<PathBuf>,

    /// Overwrite configuration file if it exists at destination.
    #[arg(long, default_value_t = false)]
    pub(crate) overwrite: bool,
}

/// Similar to [`setup`] but for a sharded setup.
pub fn sharded_setup(args: ShardedConfGenArgs) -> Result<(), BoxError> {
    let clients_conf = create_sharded_conf_from_files(
        args.shard_count,
        args.mpc_port,
        args.shards_port,
        args.keys_dir.clone(),
    );
    gen_conf_from_args(args.output_dir, args.overwrite, args.keys_dir, clients_conf)
}

/// this helper function creates [`HelperClientConf`] for a sharded configuration. We go ring by
/// ring as expected by helper binary.
fn create_sharded_conf_from_files(
    shard_count: u32,
    port: u16,
    shard_port: u16,
    keys_dir: PathBuf,
) -> impl Iterator<Item = HelperClientConf> {
    (0..shard_count).flat_map(move |ix| {
        let base_dir = keys_dir.clone();
        HelperIdentity::make_three().into_iter().map(move |id| {
            let mut shard_dir = base_dir.clone();
            let id_nr: u8 = id.into();
            shard_dir.push(format!("helper{id_nr}"));
            shard_dir.push(format!("shard{ix}"));

            let host_name = find_file_with_extension(&shard_dir, "pem").unwrap();
            let tls_cert_file = shard_dir.join(format!("{host_name}.pem"));
            let mk_public_key_file = shard_dir.join(format!("{host_name}_mk.pub"));
            println!("Found {host_name} for helper {id_nr} shard {ix}:");
            println!("\ttls_cert_file: {tls_cert_file:?}");
            println!("\tmk_public_key_file: {mk_public_key_file:?}");
            HelperClientConf {
                host: host_name,
                port,
                shard_port,
                tls_cert_file,
                mk_public_key_file,
            }
        })
    })
}

/// Finds a file with the specified extension in the given directory.
///
/// # Arguments
/// * `path`: The path to the directory to search in.
/// * `extension`: The file extension to search for.
///
/// # Returns
/// An `Option` containing the name of the first file found with the specified extension, or `None`
fn find_file_with_extension(path: &PathBuf, extension: &str) -> Option<String> {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .map_or(false, |ext| ext.to_str().unwrap() == extension)
        {
            return Some(path.file_stem().unwrap().to_str().unwrap().to_string());
        }
    }
    None
}

/// Creates output files depending on the configuration given in args. Calls [`gen_client_config`]
/// to generate and validate the configuration.
fn gen_conf_from_args(
    output_dir: Option<PathBuf>,
    overwrite: bool,
    keys_dir: PathBuf,
    clients_conf: impl Iterator<Item = HelperClientConf>,
) -> Result<(), BoxError> {
    if let Some(ref dir) = output_dir {
        fs::create_dir_all(dir)?;
    }
    let conf_file_path = output_dir.unwrap_or(keys_dir).join("network.toml");
    let mut conf_file = File::options()
        .write(true)
        .create(true)
        .truncate(overwrite)
        .create_new(!overwrite)
        .open(&conf_file_path)
        .map_err(|e| format!("failed to create or open {}: {e}", conf_file_path.display()))?;

    gen_client_config(clients_conf, false, &mut conf_file)?;
    tracing::info!(
        "{} configuration file has been successfully created",
        conf_file_path.display()
    );
    Ok(())
}
