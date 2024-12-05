use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    iter::zip,
    path::{Path, PathBuf},
};

use clap::Parser;
use rand::thread_rng;

use crate::{
    cli::{
        config_parse::HelperNetworkConfigParseExt,
        playbook::{BreakdownKey, InputSource, TriggerValue},
    },
    config::{KeyRegistries, NetworkConfig},
    error::BoxError,
    report::hybrid::{HybridReport, DEFAULT_KEY_ID},
    secret_sharing::IntoShares,
    test_fixture::hybrid::TestHybridRecord,
};

#[derive(Debug, Parser)]
#[clap(name = "test_hybrid_encrypt", about = "Test Hybrid Encrypt")]
#[command(about)]
pub struct HybridEncryptArgs {
    /// Path to file to secret share and encrypt
    #[arg(long)]
    input_file: PathBuf,
    /// The destination dir for encrypted output.
    /// In that dir, it will create helper1.enc,
    /// helper2.enc, and helper3.enc
    #[arg(long, value_name = "FILE")]
    output_dir: PathBuf,
    /// Path to helper network configuration file
    #[arg(long)]
    network: PathBuf,
}

impl HybridEncryptArgs {
    #[must_use]
    pub fn new(input_file: &Path, output_dir: &Path, network: &Path) -> Self {
        Self {
            input_file: input_file.to_path_buf(),
            output_dir: output_dir.to_path_buf(),
            network: network.to_path_buf(),
        }
    }

    /// # Panics
    /// if input file or network file are not correctly formatted
    /// # Errors
    /// if it cannot open the files
    pub fn encrypt(&self) -> Result<(), BoxError> {
        let input = InputSource::from_file(&self.input_file);

        let mut rng = thread_rng();
        let mut key_registries = KeyRegistries::default();

        let network =
            NetworkConfig::from_toml_str_sharded(&read_to_string(&self.network).unwrap_or_else(
                |e| panic!("Failed to open network file: {:?}. {}", &self.network, e),
            ))
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to parse network file into toml: {:?}. {}",
                    &self.network, e
                )
            });
        let Some(key_registries) = key_registries.init_from(&network[0]) else {
            panic!("could not load network file")
        };

        let shares: [Vec<HybridReport<BreakdownKey, TriggerValue>>; 3] =
            input.iter::<TestHybridRecord>().share();

        for (index, (shares, key_registry)) in zip(shares, key_registries).enumerate() {
            let output_filename = format!("helper{}.enc", index + 1);
            let mut writer = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.output_dir.join(&output_filename))
                .unwrap_or_else(|e| panic!("unable write to {}. {}", &output_filename, e));

            for share in shares {
                let output = share
                    .encrypt(DEFAULT_KEY_ID, key_registry, &mut rng)
                    .unwrap();
                let hex_output = hex::encode(&output);
                writeln!(writer, "{hex_output}")?;
            }
        }

        Ok(())
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::io::Write;

    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            crypto::{hybrid_encrypt::HybridEncryptArgs, sample_data},
            CsvSerializer,
        },
        test_fixture::hybrid::TestHybridRecord,
    };

    #[tokio::test]
    async fn try_encrypting_something() {
        let helper_origin = "HELPER_ORIGIN".to_string();
        let conversion_site_domain = "meta.com".to_string();
        let records = vec![
            TestHybridRecord::TestConversion {
                match_key: 12345,
                value: 2,
                key_id: 0,
                helper_origin: helper_origin.clone(),
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 100,
                epsilon: 0.0,
                sensitivity: 0.0,
            },
            TestHybridRecord::TestConversion {
                match_key: 12345,
                value: 5,
                key_id: 0,
                helper_origin: helper_origin.clone(),
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 101,
                epsilon: 0.0,
                sensitivity: 0.0,
            },
            TestHybridRecord::TestImpression {
                match_key: 23456,
                breakdown_key: 4,
                key_id: 0,
                helper_origin: helper_origin.clone(),
            },
        ];
        let mut input_file = NamedTempFile::new().unwrap();

        for event in records {
            event.to_csv(input_file.as_file_mut()).unwrap();
            writeln!(input_file.as_file()).unwrap();
        }
        input_file.flush().unwrap();

        let output_dir = tempdir().unwrap();
        let network_file = sample_data::test_keys().network_config();

        HybridEncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();
    }

    #[test]
    #[should_panic = "Failed to open network file:"]
    fn encrypt_no_network_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_dir = tempdir().unwrap();
        let network_file = network_dir.path().join("does_not_exist");
        HybridEncryptArgs::new(input_file.path(), output_dir.path(), &network_file)
            .encrypt()
            .unwrap();
    }

    #[test]
    #[should_panic = "TOML parse error at"]
    fn encrypt_bad_network_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();
        let output_dir = tempdir().unwrap();
        let network_data = r"
this is not toml!
%^& weird characters
(\deadbeef>?
";
        let mut network_file = NamedTempFile::new().unwrap();
        writeln!(network_file.as_file_mut(), "{network_data}").unwrap();

        HybridEncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Failed to parse network file into toml")]
    fn encrypt_incomplete_network_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_data = r#"
[[peers]]
url = "helper1.test"
[peers.hpke]
public_key = "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a"
[[peers]]
url = "helper2.test"
[peers.hpke]
public_key = "cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e"
"#;
        let mut network_file = NamedTempFile::new().unwrap();
        writeln!(network_file.as_file_mut(), "{network_data}").unwrap();

        HybridEncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();
    }
}
