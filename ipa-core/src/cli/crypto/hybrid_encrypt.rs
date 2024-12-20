use std::{
    array,
    collections::BTreeMap,
    fs::{read_to_string, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::mpsc::SyncSender,
    thread,
    thread::JoinHandle,
    time::Instant,
};

use clap::Parser;
use rand::thread_rng;

use crate::{
    cli::{
        config_parse::HelperNetworkConfigParseExt,
        playbook::{BreakdownKey, InputSource, TriggerValue},
    },
    config::{KeyRegistries, NetworkConfig},
    error::BoxError,
    hpke::{KeyRegistry, PublicKeyOnly},
    report::hybrid::{HybridReport, DEFAULT_KEY_ID},
    secret_sharing::IntoShares,
    test_fixture::hybrid::TestHybridRecord,
};

/// Encryptor takes 3 arguments: `report_id`, helper that the shares must be encrypted towards
/// and the actual share ([`HybridReport`]) to encrypt.
type EncryptorInput = (usize, usize, HybridReport<BreakdownKey, TriggerValue>);
/// Encryptor sends report id and encrypted bytes down to file worker to write those bytes
/// down
type EncryptorOutput = (usize, Vec<u8>);
type FileWorkerInput = EncryptorOutput;

/// This type is used quite often in this module
type UnitResult = Result<(), BoxError>;

#[derive(Debug, Parser)]
#[clap(name = "test_hybrid_encrypt", about = "Test Hybrid Encrypt")]
#[command(about)]
pub struct HybridEncryptArgs {
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
    /// a flag to produce length delimited binary instead of newline delimited hex
    #[arg(long)]
    length_delimited: bool,
}

#[derive(Copy, Clone)]
enum FileFormat {
    LengthDelimitedBinary,
    NewlineDelimitedHex,
}

impl HybridEncryptArgs {
    #[must_use]
    pub fn new(
        input_file: &Path,
        output_dir: &Path,
        network: &Path,
        length_delimited: bool,
    ) -> Self {
        Self {
            input_file: input_file.to_path_buf(),
            output_dir: output_dir.to_path_buf(),
            network: network.to_path_buf(),
            length_delimited,
        }
    }

    fn file_format(&self) -> FileFormat {
        if self.length_delimited {
            FileFormat::LengthDelimitedBinary
        } else {
            FileFormat::NewlineDelimitedHex
        }
    }

    /// # Panics
    /// if input file or network file are not correctly formatted
    /// # Errors
    /// if it cannot open the files
    pub fn encrypt(&self) -> UnitResult {
        tracing::info!("encrypting input from {:?}", self.input_file);
        let start = Instant::now();
        let input = InputSource::from_file(&self.input_file);

        let key_registries = KeyRegistries::default();

        let network =
            NetworkConfig::from_toml_str_sharded(&read_to_string(&self.network).unwrap_or_else(
                |e| panic!("Failed to open network file: {:?}. {}", &self.network, e),
            ))
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to parse network file into toml: {:?}. {}",
                    &self.network, e
                )
            });
        let Some(key_registries) = key_registries.init_from(&network[0]) else {
            panic!("could not load network file")
        };

        let mut worker_pool =
            ReportWriter::new(key_registries, &self.output_dir, self.file_format());
        for (report_id, record) in input.iter::<TestHybridRecord>().enumerate() {
            worker_pool.submit(report_id, record.share())?;
        }

        worker_pool.join()?;

        let elapsed = start.elapsed();
        tracing::info!(
            "Encryption process is completed. {}s",
            elapsed.as_secs_f64()
        );

        Ok(())
    }
}

/// A thread-per-core pool responsible for encrypting reports in parallel.
/// This pool is shared across all writers to reduce the number of context switches.
struct EncryptorPool {
    pool: Vec<(SyncSender<EncryptorInput>, JoinHandle<UnitResult>)>,
    next_worker: usize,
}

impl EncryptorPool {
    pub fn with_worker_threads(
        thread_count: usize,
        file_writer: [SyncSender<EncryptorOutput>; 3],
        key_registries: [KeyRegistry<PublicKeyOnly>; 3],
        file_format: FileFormat,
    ) -> Self {
        Self {
            pool: (0..thread_count)
                .map(move |i| {
                    let (tx, rx) = std::sync::mpsc::sync_channel::<EncryptorInput>(65535);
                    let key_registries = key_registries.clone();
                    let file_writer = file_writer.clone();
                    (
                        tx,
                        std::thread::Builder::new()
                            .name(format!("encryptor-{i}"))
                            .spawn(move || {
                                for (i, helper_id, report) in rx {
                                    let key_registry = &key_registries[helper_id];
                                    let mut output =
                                        Vec::with_capacity(usize::from(report.encrypted_len() + 2));
                                    match file_format {
                                        FileFormat::NewlineDelimitedHex => report.encrypt_to(
                                            DEFAULT_KEY_ID,
                                            key_registry,
                                            &mut thread_rng(),
                                            &mut output,
                                        )?,
                                        FileFormat::LengthDelimitedBinary => report
                                            .delimited_encrypt_to(
                                                DEFAULT_KEY_ID,
                                                key_registry,
                                                &mut thread_rng(),
                                                &mut output,
                                            )?,
                                    }
                                    file_writer[helper_id].send((i, output))?;
                                }

                                Ok(())
                            })
                            .unwrap(),
                    )
                })
                .collect(),
            next_worker: 0,
        }
    }

    pub fn encrypt_share(&mut self, report: EncryptorInput) -> UnitResult {
        let tx = &self.pool[self.next_worker].0;
        tx.send(report)?;
        self.next_worker = (self.next_worker + 1) % self.pool.len();

        Ok(())
    }

    pub fn stop(self) -> UnitResult {
        for (tx, handle) in self.pool {
            drop(tx);
            handle.join().unwrap()?;
        }

        Ok(())
    }
}

/// Performs end-to-end encryption, taking individual shares as input
/// (see [`ReportWriter::submit`]), encrypting them in parallel and writing
/// encrypted shares into 3 separate files. This optimizes for memory usage,
/// and maximizes CPU utilization.
struct ReportWriter {
    encryptor_pool: EncryptorPool,
    workers: Option<[FileWriteWorker; 3]>,
}

impl ReportWriter {
    pub fn new(
        key_registries: [KeyRegistry<PublicKeyOnly>; 3],
        output_dir: &Path,
        file_format: FileFormat,
    ) -> Self {
        // create 3 worker threads to write data into 3 files
        let workers = array::from_fn(|i| {
            let output_filename = format!("helper{}.enc", i + 1);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output_dir.join(&output_filename))
                .unwrap_or_else(|e| panic!("unable write to {:?}. {}", &output_filename, e));

            FileWriteWorker::new(file, file_format)
        });
        let encryptor_pool = EncryptorPool::with_worker_threads(
            num_cpus::get(),
            workers.each_ref().map(|x| x.sender.clone()),
            key_registries,
            file_format,
        );

        Self {
            encryptor_pool,
            workers: Some(workers),
        }
    }

    pub fn submit(
        &mut self,
        report_id: usize,
        shares: [HybridReport<BreakdownKey, TriggerValue>; 3],
    ) -> UnitResult {
        for (i, share) in shares.into_iter().enumerate() {
            self.encryptor_pool.encrypt_share((report_id, i, share))?;
        }

        Ok(())
    }

    pub fn join(mut self) -> UnitResult {
        self.encryptor_pool.stop()?;
        self.workers
            .take()
            .unwrap()
            .map(|worker| {
                let FileWriteWorker { handle, sender } = worker;
                drop(sender);
                handle.join().unwrap()
            })
            .into_iter()
            .collect()
    }
}

/// This takes a file and writes all encrypted reports to it,
/// ensuring the same total order based on `report_id`. Report id is
/// just the index of file input row that guarantees consistency
/// of shares written across 3 files
struct FileWriteWorker {
    sender: SyncSender<FileWorkerInput>,
    handle: JoinHandle<UnitResult>,
}

impl FileWriteWorker {
    pub fn new(file: File, file_format: FileFormat) -> Self {
        fn write_report<W: Write>(
            writer: &mut W,
            report: &[u8],
            file_format: FileFormat,
        ) -> Result<(), BoxError> {
            match file_format {
                FileFormat::LengthDelimitedBinary => {
                    FileWriteWorker::write_report_length_delimited_binary(writer, report)
                }
                FileFormat::NewlineDelimitedHex => {
                    FileWriteWorker::write_report_newline_delimited_hex(writer, report)
                }
            }
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(65535);
        Self {
            sender: tx,
            handle: thread::spawn(move || {
                // write low watermark. All reports below this line have been written
                let mut lw = 0;
                let mut pending_reports = BTreeMap::new();

                // Buffered writes should improve IO, but it is likely not the bottleneck here.
                let mut writer = BufWriter::new(file);
                for (report_id, report) in rx {
                    // Because reports are encrypted in parallel, it is possible
                    // to receive report_id = X+1 before X. To mitigate that, we keep
                    // a buffer, ordered by report_id and always write from low watermark.
                    // This ensures consistent order of reports written to files. Any misalignment
                    // will result in broken shares and garbage output.
                    assert!(
                        report_id >= lw,
                        "Internal error: received a report {report_id} below low watermark"
                    );
                    assert!(
                        pending_reports.insert(report_id, report).is_none(),
                        "Internal error: received a duplicate report {report_id}"
                    );
                    while let Some(report) = pending_reports.remove(&lw) {
                        write_report(&mut writer, &report, file_format)?;
                        lw += 1;
                        if lw % 1_000_000 == 0 {
                            tracing::info!("Encrypted {}M reports", lw / 1_000_000);
                        }
                    }
                }
                Ok(())
            }),
        }
    }

    fn write_report_newline_delimited_hex<W: Write>(
        writer: &mut W,
        report: &[u8],
    ) -> Result<(), BoxError> {
        let hex_output = hex::encode(report);
        writeln!(writer, "{hex_output}")?;
        Ok(())
    }

    fn write_report_length_delimited_binary<W: Write>(
        writer: &mut W,
        report: &[u8],
    ) -> Result<(), BoxError> {
        writer.write_all(report)?;
        Ok(())
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::io::Write;

    use tempfile::{tempdir, NamedTempFile};

    use crate::{
        cli::{
            crypto::{hybrid_encrypt::HybridEncryptArgs, sample_data},
            CsvSerializer,
        },
        test_fixture::hybrid::TestHybridRecord,
    };

    #[tokio::test]
    async fn try_encrypting_something() {
        let conversion_site_domain = "meta.com".to_string();
        let records = vec![
            TestHybridRecord::TestConversion {
                match_key: 12345,
                value: 2,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 100,
                epsilon: 0.0,
                sensitivity: 0.0,
            },
            TestHybridRecord::TestConversion {
                match_key: 12345,
                value: 5,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 101,
                epsilon: 0.0,
                sensitivity: 0.0,
            },
            TestHybridRecord::TestImpression {
                match_key: 23456,
                breakdown_key: 4,
                key_id: 0,
            },
        ];
        let mut input_file = NamedTempFile::new().unwrap();

        for event in records {
            event.to_csv(input_file.as_file_mut()).unwrap();
            writeln!(input_file.as_file()).unwrap();
        }
        input_file.flush().unwrap();

        let output_dir_1 = tempdir().unwrap();
        let output_dir_2 = tempdir().unwrap();
        let network_file = sample_data::test_keys().network_config();

        HybridEncryptArgs::new(
            input_file.path(),
            output_dir_1.path(),
            network_file.path(),
            false,
        )
        .encrypt()
        .unwrap();
        HybridEncryptArgs::new(
            input_file.path(),
            output_dir_2.path(),
            network_file.path(),
            true,
        )
        .encrypt()
        .unwrap();
    }

    #[test]
    #[should_panic = "Failed to open network file:"]
    fn encrypt_no_network_file() {
        let input_file = sample_data::write_csv(sample_data::test_ipa_data().take(10)).unwrap();

        let output_dir = tempdir().unwrap();
        let network_dir = tempdir().unwrap();
        let network_file = network_dir.path().join("does_not_exist");
        HybridEncryptArgs::new(input_file.path(), output_dir.path(), &network_file, true)
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

        HybridEncryptArgs::new(
            input_file.path(),
            output_dir.path(),
            network_file.path(),
            true,
        )
        .encrypt()
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Failed to parse network file into toml")]
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

        HybridEncryptArgs::new(
            input_file.path(),
            output_dir.path(),
            network_file.path(),
            true,
        )
        .encrypt()
        .unwrap();
    }
}
