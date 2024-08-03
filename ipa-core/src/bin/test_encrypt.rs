use std::{
    fmt::Debug,
    fs::{read_to_string, OpenOptions},
    io::Write,
    iter::zip,
    path::PathBuf,
};

use clap::Parser;
use ipa_core::{
    cli::playbook::InputSource,
    config::NetworkConfig,
    error::BoxError,
    ff::boolean_array::{BA20, BA3, BA8},
    hpke::{KeyRegistry, PublicKeyOnly},
    report::{KeyIdentifier, OprfReport, DEFAULT_KEY_ID},
    secret_sharing::IntoShares,
    test_fixture::ipa::TestRawDataRecord,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

type BreakdownKey = BA8;
type Timestamp = BA20;
type TriggerValue = BA3;

#[derive(Debug, Parser)]
#[clap(name = "test_encrypt", about = "Test Encrypt")]
#[command(about)]
struct Args {
    /// Path to file to secret share and encrypt
    #[arg(long)]
    input_file: PathBuf,
    // /// The destination dir for encrypted output.
    // /// In that dir, it will create helper1.enc,
    // /// helper2.enc, and helper3.enc
    #[arg(long, value_name = "FILE")]
    output_dir: PathBuf,
    /// Path to helper network configuration file
    #[arg(long)]
    network: PathBuf,
}

#[derive(Default)]
struct KeyRegistries(Vec<KeyRegistry<PublicKeyOnly>>);

impl KeyRegistries {
    fn init_from(
        &mut self,
        network: &NetworkConfig,
    ) -> Option<(KeyIdentifier, [&KeyRegistry<PublicKeyOnly>; 3])> {
        // Get the configs, if all three peers have one
        let configs = network.peers().iter().try_fold(Vec::new(), |acc, peer| {
            if let (mut vec, Some(hpke_config)) = (acc, peer.hpke_config.as_ref()) {
                vec.push(hpke_config);
                Some(vec)
            } else {
                None
            }
        })?;

        // Create key registries
        self.0 = configs
            .into_iter()
            .map(|hpke| KeyRegistry::from_keys([PublicKeyOnly(hpke.public_key.clone())]))
            .collect::<Vec<KeyRegistry<PublicKeyOnly>>>();

        Some((
            DEFAULT_KEY_ID,
            self.0.iter().collect::<Vec<_>>().try_into().ok().unwrap(),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let input = InputSource::from_file(&args.input_file);
    let records = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();

    let mut rng = StdRng::from_entropy();
    let mut key_registries = KeyRegistries::default();
    let network = NetworkConfig::from_toml_str(&read_to_string(&args.network).unwrap()).unwrap();
    let Some((key_id, key_registries)) = key_registries.init_from(&network) else {
        panic!("could not load network file")
    };
    let shares: [Vec<OprfReport<BreakdownKey, TriggerValue, Timestamp>>; 3] =
        records.iter().cloned().share();

    let shares_key_registries = zip(shares, key_registries);

    for (index, (shares, key_registry)) in shares_key_registries.enumerate() {
        let mut writer: Box<dyn Write> = Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(args.output_dir.join(format!("helper{}.enc", index + 1)))?,
        );
        for share in shares {
            let output = share.encrypt(key_id, key_registry, &mut rng).unwrap();
            let hex_output = hex::encode(&output);
            writeln!(writer, "{}", hex_output)?;
        }
    }

    Ok(())
}
