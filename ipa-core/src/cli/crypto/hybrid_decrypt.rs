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
        boolean_array::{BA3, BA8},
        U128Conversions,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    report::hybrid::{EncryptedHybridReport, HybridReport},
    test_fixture::Reconstruct,
};

#[derive(Debug, Parser)]
#[clap(name = "test_hybrid_decrypt", about = "Test Hybrid Decrypt")]
#[command(about)]
pub struct HybridDecryptArgs {
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

impl HybridDecryptArgs {
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
        let decrypted_reports1 = DecryptedHybridReports::new(&input_file1, key_registry1);
        let decrypted_reports2 = DecryptedHybridReports::new(&input_file2, key_registry2);
        let decrypted_reports3 = DecryptedHybridReports::new(&input_file3, key_registry3);

        let mut writer = Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_file)?,
        );

        for (dec_report1, (dec_report2, dec_report3)) in
            decrypted_reports1.zip(decrypted_reports2.zip(decrypted_reports3))
        {
            match (dec_report1, dec_report2, dec_report3) {
                (
                    HybridReport::Impression(impression_report1),
                    HybridReport::Impression(impression_report2),
                    HybridReport::Impression(impression_report3),
                ) => {
                    let match_key = [
                        impression_report1.match_key,
                        impression_report2.match_key,
                        impression_report3.match_key,
                    ]
                    .reconstruct()
                    .as_u128();

                    let breakdown_key = [
                        impression_report1.breakdown_key,
                        impression_report2.breakdown_key,
                        impression_report3.breakdown_key,
                    ]
                    .reconstruct()
                    .as_u128();
                    let key_id = impression_report1.info.key_id;

                    writeln!(writer, "i,{match_key},{breakdown_key},{key_id}")?;
                }
                (
                    HybridReport::Conversion(conversion_report1),
                    HybridReport::Conversion(conversion_report2),
                    HybridReport::Conversion(conversion_report3),
                ) => {
                    let match_key = [
                        conversion_report1.match_key,
                        conversion_report2.match_key,
                        conversion_report3.match_key,
                    ]
                    .reconstruct()
                    .as_u128();

                    let value = [
                        conversion_report1.value,
                        conversion_report2.value,
                        conversion_report3.value,
                    ]
                    .reconstruct()
                    .as_u128();
                    let key_id = conversion_report1.info.key_id;
                    let conversion_site_domain = conversion_report1.info.conversion_site_domain;
                    let timestamp = conversion_report1.info.timestamp;
                    let epsilon = conversion_report1.info.epsilon;
                    let sensitivity = conversion_report1.info.sensitivity;
                    writeln!(writer, "c,{match_key},{value},{key_id},{conversion_site_domain},{timestamp},{epsilon},{sensitivity}")?;
                }
                _ => {
                    panic!("Reports are not all the same type");
                }
            }
        }

        Ok(())
    }
}

struct DecryptedHybridReports {
    reader: BufReader<File>,
    key_registry: KeyRegistry<PrivateKeyOnly>,
}

impl Iterator for DecryptedHybridReports {
    type Item = HybridReport<BA8, BA3>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).unwrap() > 0 {
            let encrypted_report_bytes = hex::decode(line.trim()).unwrap();
            let enc_report =
                EncryptedHybridReport::from_bytes(encrypted_report_bytes.into()).unwrap();
            let dec_report: HybridReport<BA8, BA3> =
                enc_report.decrypt(&self.key_registry).unwrap();
            Some(dec_report)
        } else {
            None
        }
    }
}

impl DecryptedHybridReports {
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

async fn build_hpke_registry(
    private_key_file: PathBuf,
) -> Result<KeyRegistry<PrivateKeyOnly>, BoxError> {
    let mk_encryption = Some(HpkeServerConfig::File { private_key_file });
    let key_registry = hpke_registry(mk_encryption.as_ref()).await?;
    Ok(key_registry)
}

#[cfg(test)]
mod tests {

    use tempfile::tempdir;

    use crate::cli::crypto::{
        hybrid_decrypt::HybridDecryptArgs, hybrid_encrypt::HybridEncryptArgs, hybrid_sample_data,
    };

    #[tokio::test]
    #[should_panic = "No such file or directory (os error 2)"]
    async fn decrypt_no_enc_file() {
        let input_file =
            hybrid_sample_data::write_csv(hybrid_sample_data::test_hybrid_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_file = hybrid_sample_data::test_keys().network_config();
        HybridEncryptArgs::new(
            input_file.path(),
            output_dir.path(),
            network_file.path(),
            false,
        )
        .encrypt()
        .unwrap();

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("DOES_NOT_EXIST.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        let [mk_private_key1, mk_private_key2, mk_private_key3] =
            hybrid_sample_data::test_keys().sk_files();

        let decrypt_args = HybridDecryptArgs::new(
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
    #[should_panic = "called `Result::unwrap()` on an `Err` value: Crypt(Other)"]
    async fn decrypt_bad_private_key() {
        let input_file =
            hybrid_sample_data::write_csv(hybrid_sample_data::test_hybrid_data().take(10)).unwrap();

        let network_file = hybrid_sample_data::test_keys().network_config();
        let output_dir = tempdir().unwrap();
        HybridEncryptArgs::new(
            input_file.path(),
            output_dir.path(),
            network_file.path(),
            false,
        )
        .encrypt()
        .unwrap();

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");

        // corrupt the secret key for H1
        let mut keys = hybrid_sample_data::test_keys().clone();
        let mut sk = keys.get_sk(0);
        sk[0] = !sk[0];
        keys.set_sk(0, sk);
        let [mk_private_key1, mk_private_key2, mk_private_key3] = keys.sk_files();

        HybridDecryptArgs::new(
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
    }
}
