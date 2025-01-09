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
        playbook::{BreakdownKey, InputSource, Timestamp, TriggerValue},
    },
    config::{KeyRegistries, NetworkConfig},
    error::BoxError,
    report::{OprfReport, DEFAULT_KEY_ID},
    secret_sharing::IntoShares,
    test_fixture::ipa::TestRawDataRecord,
};

#[derive(Debug, Parser)]
#[clap(name = "test_encrypt", about = "Test Encrypt")]
#[command(about)]
pub struct EncryptArgs {
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

impl EncryptArgs {
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
        let key_registries = KeyRegistries::default();

        let network =
            NetworkConfig::from_toml_str(&read_to_string(&self.network).unwrap_or_else(|e| {
                panic!("Failed to open network file: {:?}. {}", &self.network, e)
            }))
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to parse network file into toml: {:?}. {}",
                    &self.network, e
                )
            });
        let Some(key_registries) = key_registries.init_from(&network) else {
            panic!("could not load network file")
        };

        let shares: [Vec<OprfReport<BreakdownKey, TriggerValue, Timestamp>>; 3] =
            input.iter::<TestRawDataRecord>().share();

        for (index, (shares, key_registry)) in zip(shares, key_registries).enumerate() {
            let output_filename = format!("helper{}.enc", index + 1);
            let mut writer = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.output_dir.join(&output_filename))
                .unwrap_or_else(|e| panic!("unable write to {}. {}", &output_filename, e));

            for share in shares {
                let output = share
                    .encrypt(DEFAULT_KEY_ID, &key_registry, &mut rng)
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

    use crate::cli::crypto::{encrypt::EncryptArgs, sample_data};

    #[test]
    #[should_panic = "Failed to open network file:"]
    fn encrypt_no_network_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_dir = tempdir().unwrap();
        let network_file = network_dir.path().join("does_not_exist");
        EncryptArgs::new(input_file.path(), output_dir.path(), &network_file)
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

        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
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

        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();
    }
}
