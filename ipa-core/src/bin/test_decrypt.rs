use std::{
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};

use clap::Parser;
use ipa_core::{
    config::{hpke_registry, HpkeServerConfig},
    error::BoxError,
    ff::boolean_array::{BA20, BA3, BA8},
    hpke::{KeyRegistry, PrivateKeyOnly},
    report::{EncryptedOprfReport, EventType, OprfReport},
    secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
};

pub trait Serializer {
    /// Converts self into a CSV-encoded byte string
    /// ## Errors
    /// If this conversion fails due to insufficient capacity in `buf` or other reasons.
    fn to_csv<W: Write>(&self, buf: &mut W) -> std::io::Result<()>;
}

#[cfg(any(test, feature = "test-fixture"))]
impl<BK: SharedValue, TV: SharedValue, TS: SharedValue> Serializer for OprfReport<BK, TV, TS> {
    fn to_csv<W: Write>(&self, buf: &mut W) -> std::io::Result<()> {
        let is_trigger_report = self.event_type == EventType::Trigger;

        // fmt::write is cool because it does not allocate when serializing integers
        write!(buf, "{:?},", self.timestamp.left())?;
        write!(buf, "{:?},", self.match_key.left())?;
        write!(buf, "{},", u8::from(is_trigger_report))?;
        write!(buf, "{:?},", self.breakdown_key.left())?;
        write!(buf, "{:?}", self.trigger_value.left())?;

        Ok(())
    }
}

#[derive(Debug, Parser)]
#[clap(name = "test_decrypt", about = "Test Decrypt")]
#[command(about)]
struct Args {
    /// Path to file to decrypt
    #[arg(long)]
    input_file: PathBuf,

    /// The destination file for decrypted output.
    #[arg(long, value_name = "FILE")]
    output_file: PathBuf,

    /// Private key for decrypting match keys
    #[arg(long)]
    mk_private_key: PathBuf,
}

async fn build_hpke_registry(
    private_key_file: PathBuf,
) -> Result<KeyRegistry<PrivateKeyOnly>, BoxError> {
    let mk_encryption = Some(HpkeServerConfig::File { private_key_file });
    let key_registry = hpke_registry(mk_encryption.as_ref()).await?;
    Ok(key_registry)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let file = File::open(args.input_file)?;
    let reader = BufReader::new(file);
    let key_registry = build_hpke_registry(args.mk_private_key).await?;

    let mut writer: Box<dyn Write> = Box::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.output_file)?,
    );

    for line in reader.lines() {
        let line = line?;
        let encrypted_report_bytes = hex::decode(line.trim()).unwrap();

        let enc_report =
            EncryptedOprfReport::from_bytes(encrypted_report_bytes.as_slice()).unwrap();

        let dec_report: OprfReport<BA8, BA3, BA20> = enc_report.decrypt(&key_registry).unwrap();
        println!("{:?}", dec_report);
        dec_report.to_csv(&mut writer)?;
        writer.write_all(&[b'\n'])?;
    }

    Ok(())
}
