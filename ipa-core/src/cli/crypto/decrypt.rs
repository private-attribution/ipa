use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use clap::Parser;

use crate::{
    config::{hpke_registry, HpkeServerConfig},
    error::BoxError,
    ff::{
        boolean_array::{BA20, BA3, BA8},
        U128Conversions,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    report::{EncryptedOprfReport, EventType, InvalidReportError, OprfReport},
    test_fixture::Reconstruct,
};

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

impl DecryptArgs {
    #[must_use]
    pub fn new(
        input_file1: &Path,
        input_file2: &Path,
        input_file3: &Path,
        mk_private_key1: &Path,
        mk_private_key2: &Path,
        mk_private_key3: &Path,
        output_file: &Path,
    ) -> Self {
        Self {
            input_file1: input_file1.to_path_buf(),
            mk_private_key1: mk_private_key1.to_path_buf(),
            input_file2: input_file2.to_path_buf(),
            mk_private_key2: mk_private_key2.to_path_buf(),
            input_file3: input_file3.to_path_buf(),
            mk_private_key3: mk_private_key3.to_path_buf(),
            output_file: output_file.to_path_buf(),
        }
    }

    /// # Panics
    // if input files or private_keys are not correctly formatted
    /// # Errors
    /// if it cannot open the files
    pub async fn decrypt_and_reconstruct(self) -> Result<(), BoxError> {
        let Self {
            input_file1,
            mk_private_key1,
            input_file2,
            mk_private_key2,
            input_file3,
            mk_private_key3,
            output_file,
        } = self;
        let key_registry1 = build_hpke_registry(mk_private_key1).await?;
        let key_registry2 = build_hpke_registry(mk_private_key2).await?;
        let key_registry3 = build_hpke_registry(mk_private_key3).await?;
        let decrypted_reports1 = DecryptedReports::new(&input_file1, key_registry1);
        let decrypted_reports2 = DecryptedReports::new(&input_file2, key_registry2);
        let decrypted_reports3 = DecryptedReports::new(&input_file3, key_registry3);

        let mut writer = Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_file)?,
        );

        for (dec_report1, (dec_report2, dec_report3)) in
            decrypted_reports1.zip(decrypted_reports2.zip(decrypted_reports3))
        {
            if let (Ok(dec_report1), Ok(dec_report2), Ok(dec_report3)) =
                (dec_report1, dec_report2, dec_report3)
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
        }

        Ok(())
    }
}

struct DecryptedReports {
    filename: PathBuf,
    reader: BufReader<File>,
    key_registry: KeyRegistry<PrivateKeyOnly>,
    iter_index: usize,
}

impl Iterator for DecryptedReports {
    type Item = Result<OprfReport<BA8, BA3, BA20>, InvalidReportError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).unwrap() > 0 {
            self.iter_index += 1;
            let encrypted_report_bytes = hex::decode(line.trim()).unwrap();
            let enc_report =
                EncryptedOprfReport::from_bytes(encrypted_report_bytes.as_slice()).unwrap();
            let dec_report = enc_report.decrypt(&self.key_registry);
            match dec_report {
                Ok(dec_report) => Some(Ok(dec_report)),
                Err(e) => {
                    eprintln!(
                        "Decryption failed: File: {0}. Record: {1}. Error: {e}.",
                        self.filename.display(),
                        self.iter_index
                    );
                    Some(Err(e))
                }
            }
        } else {
            None
        }
    }
}

impl DecryptedReports {
    fn new(filename: &PathBuf, key_registry: KeyRegistry<PrivateKeyOnly>) -> Self {
        let file = File::open(filename)
            .unwrap_or_else(|e| panic!("unable to open file {filename:?}. {e}"));
        let reader = BufReader::new(file);
        Self {
            filename: filename.clone(),
            reader,
            key_registry,
            iter_index: 0,
        }
    }
}

async fn build_hpke_registry(
    private_key_file: PathBuf,
) -> Result<KeyRegistry<PrivateKeyOnly>, BoxError> {
    let mk_encryption = Some(HpkeServerConfig::File { private_key_file });
    let key_registry = hpke_registry(mk_encryption.as_ref()).await?;
    Ok(key_registry)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    use tempfile::tempdir;

    use crate::cli::crypto::{decrypt::DecryptArgs, encrypt::EncryptArgs, sample_data};

    #[tokio::test]
    #[should_panic = "No such file or directory (os error 2)"]
    async fn decrypt_no_enc_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_file = sample_data::test_keys().network_config();
        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("DOES_NOT_EXIST.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        let [mk_private_key1, mk_private_key2, mk_private_key3] =
            sample_data::test_keys().sk_files();

        let decrypt_args = DecryptArgs::new(
            enc1.as_path(),
            enc2.as_path(),
            enc3.as_path(),
            mk_private_key1.path(),
            mk_private_key2.path(),
            mk_private_key3.path(),
            &decrypt_output,
        );
        decrypt_args.decrypt_and_reconstruct().await.unwrap();
    }

    #[tokio::test]
    async fn decrypt_bad_private_key() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let network_file = sample_data::test_keys().network_config();
        let output_dir = tempdir().unwrap();
        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        // corrupt the secret key for H1
        let mut keys = sample_data::test_keys().clone();
        let mut sk = keys.get_sk(0);
        sk[0] = !sk[0];
        keys.set_sk(0, sk);
        let [mk_private_key1, mk_private_key2, mk_private_key3] = keys.sk_files();

        DecryptArgs::new(
            enc1.as_path(),
            enc2.as_path(),
            enc3.as_path(),
            mk_private_key1.path(),
            mk_private_key2.path(),
            mk_private_key3.path(),
            &decrypt_output,
        )
        .decrypt_and_reconstruct()
        .await
        .unwrap();

        let file = File::open(decrypt_output).unwrap();
        let reader = BufReader::new(file);
        assert_eq!(reader.lines().count(), 0);
    }
}
