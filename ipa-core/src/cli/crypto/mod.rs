mod decrypt;
mod encrypt;
mod hybrid_decrypt;
mod hybrid_encrypt;

pub use decrypt::DecryptArgs;
pub use encrypt::EncryptArgs;
pub use hybrid_decrypt::HybridDecryptArgs;
pub use hybrid_encrypt::HybridEncryptArgs;

#[cfg(test)]
mod sample_data {
    use std::{io, io::Write, sync::OnceLock};

    use hpke::{Deserializable, Serializable};
    use rand::thread_rng;
    use tempfile::NamedTempFile;

    use crate::{
        cli::CsvSerializer,
        hpke::{IpaPrivateKey, IpaPublicKey},
        test_fixture::{ipa::TestRawDataRecord, EventGenerator, EventGeneratorConfig},
    };

    /// Keys that are used in crypto tests
    #[derive(Clone)]
    pub(super) struct TestKeys {
        key_pairs: [(IpaPublicKey, IpaPrivateKey); 3],
    }

    static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();
    pub fn test_keys() -> &'static TestKeys {
        TEST_KEYS.get_or_init(TestKeys::new)
    }

    impl TestKeys {
        pub fn new() -> Self {
            Self {
                key_pairs: [
                    (
                        decode_key::<_, IpaPublicKey>(
                            "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff",
                        ),
                    ),
                    (
                        decode_key::<_, IpaPublicKey>(
                            "cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
                        ),
                    ),
                    (
                        decode_key::<_, IpaPublicKey>(
                            "b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
                        ),
                    ),
                ],
            }
        }

        pub fn network_config(&self) -> NamedTempFile {
            let mut file = NamedTempFile::new().unwrap();
            let [pk1, pk2, pk3] = self.key_pairs.each_ref().map(|(pk, _)| pk);
            let [pk1, pk2, pk3] = [
                hex::encode(pk1.to_bytes()),
                hex::encode(pk2.to_bytes()),
                hex::encode(pk3.to_bytes()),
            ];
            let network_data = format!(
                r#"
                [[peers]]
                url = "helper1.test"
                [peers.hpke]
                public_key = "{pk1}"
                [[peers]]
                url = "helper2.test"
                [peers.hpke]
                public_key = "{pk2}"
                [[peers]]
                url = "helper3.test"
                [peers.hpke]
                public_key = "{pk3}"
            "#
            );
            file.write_all(network_data.as_bytes()).unwrap();

            file
        }

        pub fn set_sk<I: AsRef<[u8]>>(&mut self, idx: usize, data: I) {
            self.key_pairs[idx].1 = IpaPrivateKey::from_bytes(data.as_ref()).unwrap();
        }

        pub fn get_sk(&self, idx: usize) -> Vec<u8> {
            self.key_pairs[idx].1.to_bytes().to_vec()
        }

        pub fn sk_files(&self) -> [NamedTempFile; 3] {
            self.key_pairs.each_ref().map(|(_, sk)| sk).map(|sk| {
                let mut file = NamedTempFile::new().unwrap();
                file.write_all(hex::encode(sk.to_bytes()).as_bytes())
                    .unwrap();
                file.flush().unwrap();

                file
            })
        }
    }

    fn decode_key<I: AsRef<[u8]>, T: Deserializable>(input: I) -> T {
        let bytes = hex::decode(input).unwrap();
        T::from_bytes(&bytes).unwrap()
    }

    pub fn test_ipa_data() -> impl Iterator<Item = TestRawDataRecord> {
        let rng = thread_rng();
        let event_gen_args = EventGeneratorConfig::new(10, 5, 20, 1, 10, 604_800);

        EventGenerator::with_config(rng, event_gen_args)
    }

    pub fn write_csv<C: CsvSerializer>(
        data: impl Iterator<Item = C>,
    ) -> Result<NamedTempFile, io::Error> {
        let mut file = NamedTempFile::new()?;
        for event in data {
            let () = event.to_csv(&mut file)?;
            writeln!(file)?;
        }

        file.flush()?;

        Ok(file)
    }
}

#[cfg(test)]
mod hybrid_sample_data {
    use std::{io, io::Write, sync::OnceLock};

    use hpke::{Deserializable, Serializable};
    use rand::thread_rng;
    use tempfile::NamedTempFile;

    use crate::{
        cli::CsvSerializer,
        hpke::{IpaPrivateKey, IpaPublicKey},
        test_fixture::{
            hybrid::TestHybridRecord, hybrid_event_gen::ConversionDistribution,
            HybridEventGenerator, HybridGeneratorConfig,
        },
    };

    /// Keys that are used in crypto tests
    #[derive(Clone)]
    pub(super) struct TestKeys {
        key_pairs: [(IpaPublicKey, IpaPrivateKey); 3],
    }

    static TEST_KEYS: OnceLock<TestKeys> = OnceLock::new();
    pub fn test_keys() -> &'static TestKeys {
        TEST_KEYS.get_or_init(TestKeys::new)
    }

    impl TestKeys {
        pub fn new() -> Self {
            Self {
                key_pairs: [
                    (
                        decode_key::<_, IpaPublicKey>(
                            "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff",
                        ),
                    ),
                    (
                        decode_key::<_, IpaPublicKey>(
                            "cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569",
                        ),
                    ),
                    (
                        decode_key::<_, IpaPublicKey>(
                            "b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e",
                        ),
                        decode_key::<_, IpaPrivateKey>(
                            "1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7",
                        ),
                    ),
                ],
            }
        }

        pub fn network_config(&self) -> NamedTempFile {
            let mut file = NamedTempFile::new().unwrap();
            let [pk1, pk2, pk3] = self.key_pairs.each_ref().map(|(pk, _)| pk);
            let [pk1, pk2, pk3] = [
                hex::encode(pk1.to_bytes()),
                hex::encode(pk2.to_bytes()),
                hex::encode(pk3.to_bytes()),
            ];
            let network_data = format!(
                r#"
                [[peers]]
                url = "helper1.test"
                [peers.hpke]
                public_key = "{pk1}"
                [[peers]]
                url = "helper2.test"
                [peers.hpke]
                public_key = "{pk2}"
                [[peers]]
                url = "helper3.test"
                [peers.hpke]
                public_key = "{pk3}"
            "#
            );
            file.write_all(network_data.as_bytes()).unwrap();

            file
        }

        pub fn set_sk<I: AsRef<[u8]>>(&mut self, idx: usize, data: I) {
            self.key_pairs[idx].1 = IpaPrivateKey::from_bytes(data.as_ref()).unwrap();
        }

        pub fn get_sk(&self, idx: usize) -> Vec<u8> {
            self.key_pairs[idx].1.to_bytes().to_vec()
        }

        pub fn sk_files(&self) -> [NamedTempFile; 3] {
            self.key_pairs.each_ref().map(|(_, sk)| sk).map(|sk| {
                let mut file = NamedTempFile::new().unwrap();
                file.write_all(hex::encode(sk.to_bytes()).as_bytes())
                    .unwrap();
                file.flush().unwrap();

                file
            })
        }
    }

    fn decode_key<I: AsRef<[u8]>, T: Deserializable>(input: I) -> T {
        let bytes = hex::decode(input).unwrap();
        T::from_bytes(&bytes).unwrap()
    }

    pub fn test_hybrid_data() -> impl Iterator<Item = TestHybridRecord> {
        let rng = thread_rng();
        let event_gen_args = HybridGeneratorConfig::new(3, 50, ConversionDistribution::Default);

        HybridEventGenerator::with_config(rng, event_gen_args)
    }

    pub fn write_csv<C: CsvSerializer>(
        data: impl Iterator<Item = C>,
    ) -> Result<NamedTempFile, io::Error> {
        let mut file = NamedTempFile::new()?;
        for event in data {
            let () = event.to_csv(&mut file)?;
            writeln!(file)?;
        }

        file.flush()?;

        Ok(file)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    use tempfile::tempdir;

    use crate::cli::crypto::{
        decrypt::DecryptArgs, encrypt::EncryptArgs, hybrid_decrypt::HybridDecryptArgs,
        hybrid_encrypt::HybridEncryptArgs, hybrid_sample_data, sample_data,
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

    #[tokio::test]
    async fn encrypt_and_decrypt() {
        let output_dir = tempdir().unwrap();
        let input = sample_data::test_ipa_data().take(10);
        let input_file = sample_data::write_csv(input).unwrap();
        let network_file = sample_data::test_keys().network_config();
        EncryptArgs::new(input_file.path(), output_dir.path(), network_file.path())
            .encrypt()
            .unwrap();

        let decrypt_output = output_dir.path().join("output");
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");
        let [mk_private_key1, mk_private_key2, mk_private_key3] =
            sample_data::test_keys().sk_files();

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

        are_files_equal(input_file.path(), &decrypt_output);
    }

    #[tokio::test]
    async fn hybrid_encrypt_and_decrypt() {
        let output_dir = tempdir().unwrap();
        let input = hybrid_sample_data::test_hybrid_data().take(10);
        let input_file = hybrid_sample_data::write_csv(input).unwrap();
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
        let enc1 = output_dir.path().join("helper1.enc");
        let enc2 = output_dir.path().join("helper2.enc");
        let enc3 = output_dir.path().join("helper3.enc");
        let [mk_private_key1, mk_private_key2, mk_private_key3] =
            hybrid_sample_data::test_keys().sk_files();

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

        are_files_equal(input_file.path(), &decrypt_output);
    }
}
