use std::{
    fs::{read_to_string, OpenOptions},
    io::Write,
    iter::zip,
    path::{Path, PathBuf},
};

use clap::Parser;
use rand::thread_rng;

use crate::{
    cli::playbook::{BreakdownKey, InputSource, Timestamp, TriggerValue},
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
        let mut key_registries = KeyRegistries::default();

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
    use std::{io::Write, sync::Arc};

    use hpke::Deserializable;
    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            crypto::{encrypt::EncryptArgs, sample_data},
            CsvSerializer,
        },
        ff::{boolean_array::BA16, U128Conversions},
        helpers::query::{IpaQueryConfig, QuerySize},
        hpke::{IpaPrivateKey, KeyRegistry, PrivateKeyOnly},
        query::OprfIpaQuery,
        report::EncryptedOprfReportStreams,
        test_fixture::{ipa::TestRawDataRecord, join3v, Reconstruct, TestWorld},
    };

    #[tokio::test]
    async fn encrypt_and_execute_query() {
        const EXPECTED: &[u128] = &[0, 2, 5];

        let records = vec![
            TestRawDataRecord {
                timestamp: 0,
                user_id: 12345,
                is_trigger_report: false,
                breakdown_key: 2,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 4,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 10,
                user_id: 12345,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 5,
            },
            TestRawDataRecord {
                timestamp: 12,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 0,
                trigger_value: 2,
            },
        ];
        let query_size = QuerySize::try_from(records.len()).unwrap();
        let mut input_file = NamedTempFile::new().unwrap();

        for event in records {
            event.to_csv(input_file.as_file_mut()).unwrap();
            writeln!(input_file.as_file()).unwrap();
        }
        input_file.flush().unwrap();

        let output_dir = tempdir().unwrap();
        let network_file = sample_data::test_keys().network_config();

        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();

        let files = [
            &output_dir.path().join("helper1.enc"),
            &output_dir.path().join("helper2.enc"),
            &output_dir.path().join("helper3.enc"),
        ];

        let world = TestWorld::default();

        let mk_private_keys = [
            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff",
            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
        ];

        #[allow(clippy::large_futures)]
        let results = join3v(
            EncryptedOprfReportStreams::from(files)
                .streams
                .into_iter()
                .zip(world.contexts())
                .zip(mk_private_keys.into_iter())
                .map(|((input, ctx), mk_private_key)| {
                    let mk_private_key = hex::decode(mk_private_key)
                        .map(|bytes| IpaPrivateKey::from_bytes(&bytes).unwrap())
                        .unwrap();
                    let query_config = IpaQueryConfig {
                        max_breakdown_key: 3,
                        with_dp: 0,
                        epsilon: 1.0,
                        ..Default::default()
                    };

                    OprfIpaQuery::<_, BA16, _>::new(
                        query_config,
                        Arc::new(KeyRegistry::from_keys([PrivateKeyOnly(mk_private_key)])),
                    )
                    .execute(ctx, query_size, input)
                }),
        )
        .await;

        assert_eq!(
            results.reconstruct()[0..3]
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }

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
    #[should_panic = "invalid length 2, expected an array of length 3"]
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
