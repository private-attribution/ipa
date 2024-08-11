use std::{
    fmt::Debug,
    fs::{read_to_string, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    iter::zip,
    path::PathBuf,
};

use clap::Parser;
use rand::rngs::StdRng;
use rand_core::SeedableRng;

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
    let records = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();

    let mut rng = StdRng::from_entropy();
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
    let Some((key_id, key_registries)) = key_registries.init_from(&network, DEFAULT_KEY_ID) else {
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

/// # Panics
// if input files or private_keys are not correctly formatted
/// # Errors
/// if it cannot open the files
pub async fn decrypt_and_reconstruct(args: DecryptArgs) -> Result<(), BoxError> {
    let file1 = File::open(args.input_file1)?;
    let file2 = File::open(args.input_file2)?;
    let file3 = File::open(args.input_file3)?;
    let reader1 = BufReader::new(file1);
    let reader2 = BufReader::new(file2);
    let reader3 = BufReader::new(file3);
    let key_registry1 = build_hpke_registry(args.mk_private_key1).await?;
    let key_registry2 = build_hpke_registry(args.mk_private_key2).await?;
    let key_registry3 = build_hpke_registry(args.mk_private_key3).await?;

    let mut writer: Box<dyn Write> = Box::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.output_file)?,
    );

    for (line1, (line2, line3)) in reader1.lines().zip(reader2.lines().zip(reader3.lines())) {
        let line1 = line1?;
        let line2 = line2?;
        let line3 = line3?;
        let encrypted_report_bytes1 = hex::decode(line1.trim()).unwrap();
        let encrypted_report_bytes2 = hex::decode(line2.trim()).unwrap();
        let encrypted_report_bytes3 = hex::decode(line3.trim()).unwrap();

        let enc_report1 =
            EncryptedOprfReport::from_bytes(encrypted_report_bytes1.as_slice()).unwrap();
        let enc_report2 =
            EncryptedOprfReport::from_bytes(encrypted_report_bytes2.as_slice()).unwrap();
        let enc_report3 =
            EncryptedOprfReport::from_bytes(encrypted_report_bytes3.as_slice()).unwrap();

        let dec_report1: OprfReport<BA8, BA3, BA20> = enc_report1.decrypt(&key_registry1).unwrap();
        let dec_report2: OprfReport<BA8, BA3, BA20> = enc_report2.decrypt(&key_registry2).unwrap();
        let dec_report3: OprfReport<BA8, BA3, BA20> = enc_report3.decrypt(&key_registry3).unwrap();

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
            timestamp.try_into().unwrap_or(u64::MAX),
            match_key.try_into().unwrap_or(u64::MAX),
            u8::from(is_trigger_report),
            breakdown_key.try_into().unwrap_or(u32::MAX),
            trigger_value.try_into().unwrap_or(u32::MAX)
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
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;
    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            hpke::{decrypt_and_reconstruct, encrypt, DecryptArgs, EncryptArgs},
            CsvSerializer,
        },
        test_fixture::{ipa::TestRawDataRecord, EventGenerator, EventGeneratorConfig},
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
        let count: u32 = 10;
        let rng = StdRng::from_entropy();
        let event_gen_args = EventGeneratorConfig::new(10, 5, 20, 1, 10, 604_800);

        let event_gen: Vec<TestRawDataRecord> = EventGenerator::with_config(rng, event_gen_args)
            .take(count as usize)
            .collect::<Vec<_>>();
        let mut raw_input = NamedTempFile::new().unwrap();

        for event in event_gen {
            let _ = event.to_csv(raw_input.as_file_mut());
            writeln!(raw_input.as_file_mut()).unwrap();
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
