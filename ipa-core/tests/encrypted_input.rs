#[cfg(all(
    feature = "test-fixture",
    feature = "web-app",
    feature = "cli",
    feature = "in-memory-infra"
))]
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
    use ipa_core::{
        cli::{
            crypto::{encrypt, EncryptArgs},
            CsvSerializer,
        },
        ff::{boolean_array::BA16, U128Conversions},
        helpers::{
            query::{IpaQueryConfig, QuerySize},
            BodyStream,
        },
        hpke::{IpaPrivateKey, KeyRegistry, PrivateKeyOnly},
        query::OprfIpaQuery,
        test_fixture::{ipa::TestRawDataRecord, join3v, Reconstruct, TestWorld},
    };
    use tempfile::{tempdir, NamedTempFile};

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

                OprfIpaQuery::<_, BA16, KeyRegistry<PrivateKeyOnly>>::new(
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
