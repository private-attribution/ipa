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
    report::{EncryptedOprfReport, EventType, OprfReport, DEFAULT_KEY_ID},
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
    type Item = OprfReport<BA8, BA3, BA20>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).unwrap() > 0 {
            let encrypted_report_bytes = hex::decode(line.trim()).unwrap();
            let enc_report =
                EncryptedOprfReport::from_bytes(encrypted_report_bytes.as_slice()).unwrap();
            let dec_report: OprfReport<BA8, BA3, BA20> =
                enc_report.decrypt(&self.key_registry).unwrap();
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

    for (dec_report1, (dec_report2, dec_report3)) in
        decrypted_reports1.zip(decrypted_reports2.zip(decrypted_reports3))
    {
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader, Write},
        path::Path,
    };

    use clap::Parser;
    use rand::thread_rng;
    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            crypto::{decrypt_and_reconstruct, encrypt, DecryptArgs, EncryptArgs},
            CsvSerializer,
        },
        test_fixture::{EventGenerator, EventGeneratorConfig},
    };

    fn are_files_equal(file1: &Path, file2: &Path) {
        let file1 = File::open(file1).unwrap();
        let file2 = File::open(file2).unwrap();
        let reader1 = BufReader::new(file1).lines();
        let mut reader2 = BufReader::new(file2).lines();
        for line1 in reader1 {
            let line2 = reader2.next().expect("Files have different lengths");
            assert_eq!(line1.unwrap(), line2.unwrap());
        }
        assert!(reader2.next().is_none(), "Files have different lengths");
    }

    #[tokio::test]
    async fn encrypt_and_decrypt() {
        let count = 10;
        let rng = thread_rng();
        let event_gen_args = EventGeneratorConfig::new(10, 5, 20, 1, 10, 604_800);

        let event_gen = EventGenerator::with_config(rng, event_gen_args)
            .take(count)
            .collect::<Vec<_>>();
        let mut raw_input = NamedTempFile::new().unwrap();

        for event in event_gen {
            let _ = event.to_csv(raw_input.as_file_mut());
            writeln!(raw_input.as_file()).unwrap();
        }
        raw_input.as_file_mut().flush().unwrap();

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
[[peers]]
url = "helper3.test"
[peers.hpke]
public_key = "b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e"
"#;
        let mut network = NamedTempFile::new().unwrap();
        writeln!(network.as_file_mut(), "{network_data}").unwrap();
        let encrypt_args = EncryptArgs::try_parse_from([
            "test_encrypt",
            "--input-file",
            raw_input.path().to_str().unwrap(),
            "--output-dir",
            output_dir.path().to_str().unwrap(),
            "--network",
            network.path().to_str().unwrap(),
        ])
        .unwrap();
        let _ = encrypt(&encrypt_args);

        let mk_private_key1_data =
            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff";
        let mk_private_key2_data =
            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569";
        let mk_private_key3_data =
            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7";
        let mut mk_private_key1 = NamedTempFile::new().unwrap();
        let mut mk_private_key2 = NamedTempFile::new().unwrap();
        let mut mk_private_key3 = NamedTempFile::new().unwrap();
        writeln!(mk_private_key1.as_file_mut(), "{mk_private_key1_data}").unwrap();
        writeln!(mk_private_key2.as_file_mut(), "{mk_private_key2_data}").unwrap();
        writeln!(mk_private_key3.as_file_mut(), "{mk_private_key3_data}").unwrap();

        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        let decrypt_output = output_dir.path().join("output");

        let decrypt_args = DecryptArgs::try_parse_from([
            "test_decrypt",
            "--input-file1",
            enc1.to_str().unwrap(),
            "--input-file2",
            enc2.to_str().unwrap(),
            "--input-file3",
            enc3.to_str().unwrap(),
            "--mk-private-key1",
            mk_private_key1.path().to_str().unwrap(),
            "--mk-private-key2",
            mk_private_key2.path().to_str().unwrap(),
            "--mk-private-key3",
            mk_private_key3.path().to_str().unwrap(),
            "--output-file",
            decrypt_output.to_str().unwrap(),
        ])
        .unwrap();

        let _ = decrypt_and_reconstruct(decrypt_args).await;

        are_files_equal(raw_input.path(), &decrypt_output);
    }
}
