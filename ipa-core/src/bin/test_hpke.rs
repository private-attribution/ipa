use std::{
    fmt::Debug,
    fs::{read_to_string, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    iter::zip,
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use ipa_core::{
    cli::playbook::InputSource,
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
use rand::rngs::StdRng;
use rand_core::SeedableRng;

type BreakdownKey = BA8;
type Timestamp = BA20;
type TriggerValue = BA3;

#[derive(Debug, Parser)]
#[clap(name = "test_encrypt", about = "Test Encrypt")]
#[command(about)]
struct EncryptArgs {
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
struct DecryptArgs {
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

#[derive(Debug, Parser)]
#[clap(name = "rc", about = "Report Collector CLI")]
#[command(about)]
struct Args {
    #[command(subcommand)]
    action: TestHPKECommand,
}

#[derive(Debug, Subcommand)]
enum TestHPKECommand {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    match args.action {
        TestHPKECommand::Encrypt(encrypt_args) => encrypt(encrypt_args).await?,
        TestHPKECommand::Decrypt(decrypt_args) => decrypt_and_reconstruct(decrypt_args).await?,
    }
    Ok(())
}

async fn encrypt(args: EncryptArgs) -> Result<(), BoxError> {
    let input = InputSource::from_file(&args.input_file);
    let records = input.iter::<TestRawDataRecord>().collect::<Vec<_>>();

    let mut rng = StdRng::from_entropy();
    let mut key_registries = KeyRegistries::default();
    let network = NetworkConfig::from_toml_str(&read_to_string(&args.network).unwrap()).unwrap();
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
            writeln!(writer, "{}", hex_output)?;
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

async fn decrypt_and_reconstruct(args: DecryptArgs) -> Result<(), BoxError> {
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
