use std::{
    fmt::Debug,
    fs::{read_to_string, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    iter::zip,
    path::PathBuf,
};

use clap::Parser;
use rand::thread_rng;

use crate::{
    cli::playbook::{BreakdownKey, InputSource, Timestamp, TriggerValue},
    config::{hpke_registry, HpkeServerConfig, KeyRegistries, NetworkConfig},
    error::BoxError,
    ff::{
        boolean_array::{BA20, BA3, BA8},
        U128Conversions,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    report::{EncryptedOprfReport, EventType, InvalidReportError, OprfReport, DEFAULT_KEY_ID},
    secret_sharing::IntoShares,
    test_fixture::{ipa::TestRawDataRecord, Reconstruct},
};

#[derive(Debug, Parser)]
#[clap(name = "test_encrypt", about = "Test Encrypt")]
#[command(about)]
pub struct EncryptArgs {
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

#[derive(Debug, Parser)]
#[clap(name = "test_decrypt", about = "Test Decrypt")]
#[command(about)]
pub struct DecryptArgs {
    /// Path to helper1 file to decrypt
    #[arg(long)]
    input_file1: PathBuf,

    /// Helper1 Private key for decrypting match keys
    #[arg(long)]
    mk_private_key1: PathBuf,

    /// Path to helper2 file to decrypt
    #[arg(long)]
    input_file2: PathBuf,

    /// Helper2 Private key for decrypting match keys
    #[arg(long)]
    mk_private_key2: PathBuf,

    /// Path to helper3 file to decrypt
    #[arg(long)]
    input_file3: PathBuf,

    /// Helper3 Private key for decrypting match keys
    #[arg(long)]
    mk_private_key3: PathBuf,

    /// The destination file for decrypted output.
    #[arg(long, value_name = "FILE")]
    output_file: PathBuf,
}

/// # Panics
/// if input file or network file are not correctly formatted
/// # Errors
/// if it cannot open the files
pub fn encrypt(args: &EncryptArgs) -> Result<(), BoxError> {
    let input = InputSource::from_file(&args.input_file);

    let mut rng = thread_rng();
    let mut key_registries = KeyRegistries::default();

    let network = NetworkConfig::from_toml_str(
        &read_to_string(&args.network)
            .unwrap_or_else(|e| panic!("Failed to open network file: {:?}. {}", &args.network, e)),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Failed to parse network file into toml: {:?}. {}",
            &args.network, e
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
            .open(args.output_dir.join(&output_filename))
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

async fn build_hpke_registry(
    private_key_file: PathBuf,
) -> Result<KeyRegistry<PrivateKeyOnly>, BoxError> {
    let mk_encryption = Some(HpkeServerConfig::File { private_key_file });
    let key_registry = hpke_registry(mk_encryption.as_ref()).await?;
    Ok(key_registry)
}

struct DecryptedReports {
    reader: BufReader<File>,
    key_registry: KeyRegistry<PrivateKeyOnly>,
}

impl DecryptedReports {
    fn new(filename: &PathBuf, key_registry: KeyRegistry<PrivateKeyOnly>) -> Self {
        let file = File::open(filename)
            .unwrap_or_else(|e| panic!("unable to open file {filename:?}. {e}"));
        let reader = BufReader::new(file);
        Self {
            reader,
            key_registry,
        }
    }
}

impl Iterator for DecryptedReports {
    type Item = Result<OprfReport<BA8, BA3, BA20>, InvalidReportError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).unwrap() > 0 {
            let encrypted_report_bytes = hex::decode(line.trim()).unwrap();
            let enc_report =
                EncryptedOprfReport::from_bytes(encrypted_report_bytes.as_slice()).unwrap();
            let dec_report = enc_report.decrypt(&self.key_registry);
            Some(dec_report)
        } else {
            None
        }
    }
}

/// # Panics
// if input files or private_keys are not correctly formatted
/// # Errors
/// if it cannot open the files
pub async fn decrypt_and_reconstruct(args: DecryptArgs) -> Result<(), BoxError> {
    let key_registry1 = build_hpke_registry(args.mk_private_key1).await?;
    let key_registry2 = build_hpke_registry(args.mk_private_key2).await?;
    let key_registry3 = build_hpke_registry(args.mk_private_key3).await?;
    let decrypted_reports1 = DecryptedReports::new(&args.input_file1, key_registry1);
    let decrypted_reports2 = DecryptedReports::new(&args.input_file2, key_registry2);
    let decrypted_reports3 = DecryptedReports::new(&args.input_file3, key_registry3);

    let mut writer = Box::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.output_file)?,
    );
    let mut first_error = None;
    for (idx, (dec_report1, (dec_report2, dec_report3))) in decrypted_reports1
        .zip(decrypted_reports2.zip(decrypted_reports3))
        .enumerate()
    {
        match (dec_report1, dec_report2, dec_report3) {
            (Ok(dec_report1), Ok(dec_report2), Ok(dec_report3)) => {
                let timestamp = [
                    dec_report1.timestamp,
                    dec_report2.timestamp,
                    dec_report3.timestamp,
                ]
                .reconstruct()
                .as_u128();

                let match_key = [
                    dec_report1.match_key,
                    dec_report2.match_key,
                    dec_report3.match_key,
                ]
                .reconstruct()
                .as_u128();

                // these aren't reconstucted, so we explictly make sure
                // they are consistent across all three files, then set
                // it to the first one (without loss of generality)
                assert_eq!(dec_report1.event_type, dec_report2.event_type);
                assert_eq!(dec_report2.event_type, dec_report3.event_type);
                let is_trigger_report = dec_report1.event_type == EventType::Trigger;

                let breakdown_key = [
                    dec_report1.breakdown_key,
                    dec_report2.breakdown_key,
                    dec_report3.breakdown_key,
                ]
                .reconstruct()
                .as_u128();

                let trigger_value = [
                    dec_report1.trigger_value,
                    dec_report2.trigger_value,
                    dec_report3.trigger_value,
                ]
                .reconstruct()
                .as_u128();

                writeln!(
                    writer,
                    "{},{},{},{},{}",
                    timestamp,
                    match_key,
                    u8::from(is_trigger_report),
                    breakdown_key,
                    trigger_value,
                )?;
            }
            (Err(e1), _, _) => {
                writeln!(writer, "Decryption failed Record: {idx} Reason:{e1}",)?;
                eprintln!("Decryption failed Record: {idx} Reason:{e1}");
                if first_error.is_none() {
                    first_error = Some(e1);
                }
            }
            (Ok(_), Err(e2), _) => {
                writeln!(writer, "Decryption failed Record: {idx} Reason:{e2}",)?;
                eprintln!("Decryption failed Record: {idx} Reason:{e2}");
                if first_error.is_none() {
                    first_error = Some(e2);
                }
            }
            (Ok(_), Ok(_), Err(e3)) => {
                writeln!(writer, "Decryption failed Record: {idx} Reason:{e3}",)?;
                eprintln!("Decryption failed Record: {idx} Reason:{e3}");
                if first_error.is_none() {
                    first_error = Some(e3);
                }
            }
        }
    }
    match first_error {
        None => Ok(()),
        Some(err) => Err(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader, Write},
        path::Path,
        sync::Arc,
    };

    use bytes::BufMut;
    use clap::Parser;
    use hpke::Deserializable;
    use rand::thread_rng;
    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            crypto::{decrypt_and_reconstruct, encrypt, DecryptArgs, EncryptArgs},
            CsvSerializer,
        },
        ff::{boolean_array::BA16, U128Conversions},
        helpers::{
            query::{IpaQueryConfig, QuerySize},
            BodyStream,
        },
        hpke::{IpaPrivateKey, KeyRegistry, PrivateKeyOnly},
        query::OprfIpaQuery,
        test_fixture::{
            ipa::TestRawDataRecord, join3v, EventGenerator, EventGeneratorConfig, Reconstruct,
            TestWorld,
        },
    };

    fn are_files_equal(file1: &Path, file2: &Path) {
        let file1 =
            File::open(file1).unwrap_or_else(|e| panic!("unable to open {}: {e}", file1.display()));
        let file2 =
            File::open(file2).unwrap_or_else(|e| panic!("unable to open {}: {e}", file2.display()));
        let reader1 = BufReader::new(file1).lines();
        let mut reader2 = BufReader::new(file2).lines();
        for line1 in reader1 {
            let line2 = reader2.next().expect("Files have different lengths");
            assert_eq!(line1.unwrap(), line2.unwrap());
        }
        assert!(reader2.next().is_none(), "Files have different lengths");
    }

    fn write_input_file() -> NamedTempFile {
        let count = 10;
        let rng = thread_rng();
        let event_gen_args = EventGeneratorConfig::new(10, 5, 20, 1, 10, 604_800);

        let event_gen = EventGenerator::with_config(rng, event_gen_args)
            .take(count)
            .collect::<Vec<_>>();
        let mut input = NamedTempFile::new().unwrap();

        for event in event_gen {
            let _ = event.to_csv(input.as_file_mut());
            writeln!(input.as_file()).unwrap();
        }
        input.as_file_mut().flush().unwrap();
        input
    }

    fn write_network_file() -> NamedTempFile {
        let network_data = r#"
[[peers]]
url = "helper1.test"
[peers.hpke]
public_key = "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a"
[[peers]]
url = "helper2.test"
[peers.hpke]
public_key = "cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e"
[[peers]]
url = "helper3.test"
[peers.hpke]
public_key = "b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e"
"#;
        let mut network = NamedTempFile::new().unwrap();
        writeln!(network.as_file_mut(), "{network_data}").unwrap();
        network
    }

    fn write_mk_private_key(mk_private_key_data: &str) -> NamedTempFile {
        let mut mk_private_key = NamedTempFile::new().unwrap();
        writeln!(mk_private_key.as_file_mut(), "{mk_private_key_data}").unwrap();
        mk_private_key
    }

    fn build_encrypt_args(
        input_file: &Path,
        output_dir: &Path,
        network_file: &Path,
    ) -> EncryptArgs {
        EncryptArgs::try_parse_from([
            "test_encrypt",
            "--input-file",
            input_file.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network",
            network_file.to_str().unwrap(),
        ])
        .unwrap()
    }

    fn build_decrypt_args(
        enc1: &Path,
        enc2: &Path,
        enc3: &Path,
        mk_private_key1: &Path,
        mk_private_key2: &Path,
        mk_private_key3: &Path,
        decrypt_output: &Path,
    ) -> DecryptArgs {
        DecryptArgs::try_parse_from([
            "test_decrypt",
            "--input-file1",
            enc1.to_str().unwrap(),
            "--input-file2",
            enc2.to_str().unwrap(),
            "--input-file3",
            enc3.to_str().unwrap(),
            "--mk-private-key1",
            mk_private_key1.to_str().unwrap(),
            "--mk-private-key2",
            mk_private_key2.to_str().unwrap(),
            "--mk-private-key3",
            mk_private_key3.to_str().unwrap(),
            "--output-file",
            decrypt_output.to_str().unwrap(),
        ])
        .unwrap()
    }

    #[test]
    #[should_panic = "Failed to open network file:"]
    fn encrypt_no_network_file() {
        let input_file = write_input_file();
        let output_dir = tempdir().unwrap();
        let network_dir = tempdir().unwrap();
        let network_file = network_dir.path().join("does_not_exist");
        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.as_path());
        let _ = encrypt(&encrypt_args);
    }

    #[test]
    #[should_panic = "TOML parse error at"]
    fn encrypt_bad_network_file() {
        let input_file = write_input_file();
        let output_dir = tempdir().unwrap();
        let network_data = r"
this is not toml!
%^& weird characters
(\deadbeef>?
";
        let mut network_file = NamedTempFile::new().unwrap();
        writeln!(network_file.as_file_mut(), "{network_data}").unwrap();

        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);
    }

    #[test]
    #[should_panic = "invalid length 2, expected an array of length 3"]
    fn encrypt_incomplete_network_file() {
        let input_file = write_input_file();
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

        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);
    }

    #[tokio::test]
    #[should_panic = "No such file or directory (os error 2)"]
    async fn decrypt_no_enc_file() {
        let input_file = write_input_file();
        let output_dir = tempdir().unwrap();
        let network_file = write_network_file();
        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("DOES_NOT_EXIST.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        let mk_private_key1 = write_mk_private_key(
            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff",
        );
        let mk_private_key2 = write_mk_private_key(
            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
        );
        let mk_private_key3 = write_mk_private_key(
            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
        );

        let decrypt_args = build_decrypt_args(
            enc1.as_path(),
            enc2.as_path(),
            enc3.as_path(),
            mk_private_key1.path(),
            mk_private_key2.path(),
            mk_private_key3.path(),
            &decrypt_output,
        );
        let _ = decrypt_and_reconstruct(decrypt_args).await;
    }

    #[tokio::test]
    #[should_panic = "called `Result::unwrap()` on an `Err` value: Crypt(Other)"]
    async fn decrypt_bad_private_key() {
        let input_file = write_input_file();
        let output_dir = tempdir().unwrap();
        let network_file = write_network_file();
        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");
        let mk_private_key1 = write_mk_private_key(
            "bad9fdc79d98471cedd07ee6743d3bb43aabbddabc49cd9fae1d5daef3f2b3ba",
        );
        let mk_private_key2 = write_mk_private_key(
            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
        );
        let mk_private_key3 = write_mk_private_key(
            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
        );

        let decrypt_args = build_decrypt_args(
            enc1.as_path(),
            enc2.as_path(),
            enc3.as_path(),
            mk_private_key1.path(),
            mk_private_key2.path(),
            mk_private_key3.path(),
            &decrypt_output,
        );
        let _ = decrypt_and_reconstruct(decrypt_args).await;
    }

    #[tokio::test]
    async fn encrypt_and_decrypt() {
        let input_file = write_input_file();
        let output_dir = tempdir().unwrap();
        let network_file = write_network_file();
        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");
        let mk_private_key1 = write_mk_private_key(
            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff",
        );
        let mk_private_key2 = write_mk_private_key(
            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
        );
        let mk_private_key3 = write_mk_private_key(
            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
        );

        let decrypt_args = build_decrypt_args(
            enc1.as_path(),
            enc2.as_path(),
            enc3.as_path(),
            mk_private_key1.path(),
            mk_private_key2.path(),
            mk_private_key3.path(),
            &decrypt_output,
        );
        let _ = decrypt_and_reconstruct(decrypt_args).await;

        are_files_equal(input_file.path(), &decrypt_output);
    }

    #[tokio::test]
    async fn encrypt_and_execute_query() {
        const EXPECTED: &[u128] = &[0, 8, 5];

        let records: Vec<TestRawDataRecord> = vec![
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
            TestRawDataRecord {
                timestamp: 20,
                user_id: 68362,
                is_trigger_report: false,
                breakdown_key: 1,
                trigger_value: 0,
            },
            TestRawDataRecord {
                timestamp: 30,
                user_id: 68362,
                is_trigger_report: true,
                breakdown_key: 1,
                trigger_value: 7,
            },
        ];
        let query_size = QuerySize::try_from(records.len()).unwrap();
        let mut input_file = NamedTempFile::new().unwrap();

        for event in records {
            let _ = event.to_csv(input_file.as_file_mut());
            writeln!(input_file.as_file()).unwrap();
        }
        input_file.as_file_mut().flush().unwrap();

        let output_dir = tempdir().unwrap();
        let network_file = write_network_file();
        let encrypt_args =
            build_encrypt_args(input_file.path(), output_dir.path(), network_file.path());
        let _ = encrypt(&encrypt_args);

        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());
        for (i, path) in [enc1, enc2, enc3].iter().enumerate() {
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.unwrap();
                let encrypted_report_bytes = hex::decode(line.trim()).unwrap();
                println!("{}", encrypted_report_bytes.len());
                buffers[i].put_u16_le(encrypted_report_bytes.len().try_into().unwrap());
                buffers[i].put_slice(encrypted_report_bytes.as_slice());
            }
        }

        let world = TestWorld::default();
        let contexts = world.contexts();

        let mk_private_keys = vec![
            hex::decode("53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff")
                .expect("manually provided for test"),
            hex::decode("3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569")
                .expect("manually provided for test"),
            hex::decode("1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7")
                .expect("manually provided for test"),
        ];

        #[allow(clippy::large_futures)]
        let results = join3v(buffers.into_iter().zip(contexts).zip(mk_private_keys).map(
            |((buffer, ctx), mk_private_key)| {
                let query_config = IpaQueryConfig {
                    per_user_credit_cap: 8,
                    attribution_window_seconds: None,
                    max_breakdown_key: 3,
                    with_dp: 0,
                    epsilon: 1.0,
                    plaintext_match_keys: false,
                };
                let input = BodyStream::from(buffer);

                let private_registry =
                    Arc::new(KeyRegistry::<PrivateKeyOnly>::from_keys([PrivateKeyOnly(
                        IpaPrivateKey::from_bytes(&mk_private_key)
                            .expect("manually constructed for test"),
                    )]));

                OprfIpaQuery::<BA16, KeyRegistry<PrivateKeyOnly>>::new(
                    query_config,
                    private_registry,
                )
                .execute(ctx, query_size, input)
            },
        ))
        .await;

        assert_eq!(
            results.reconstruct()[0..3]
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<u128>>(),
            EXPECTED
        );
    }
}
