// some pub functions in `common` to be compiled, and rust complains about dead code.
#[allow(dead_code)]
mod common;

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    iter::once,
    net::TcpListener,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bytes::Bytes;
use command_fds::CommandFdExt;
use common::{
    spawn_shards, tempdir::TempDir, test_sharded_setup, CommandExt, TerminateOnDropExt,
    UnwrapStatusExt, CRYPTO_UTIL_BIN, TEST_RC_BIN,
};
use futures_util::{StreamExt, TryStreamExt};
use ipa_core::{
    cli::playbook::HybridQueryResult,
    error::BoxError,
    helpers::{query::HybridQueryParams, LengthDelimitedStream},
};
use rand::thread_rng;
use rand_core::RngCore;
use serde_json::from_reader;

use crate::common::TEST_MPC_BIN;

pub const IN_THE_CLEAR_BIN: &str = env!("CARGO_BIN_EXE_in_the_clear");

#[test]
fn test_hybrid() {
    const INPUT_SIZE: usize = 100;
    const SHARDS: usize = 5;
    const MAX_CONVERSION_VALUE: usize = 5;

    let config = HybridQueryParams {
        max_breakdown_key: 5,
        with_dp: 0,
        epsilon: 0.0,
        plaintext_match_keys: false, // this shouldn't be necessary
    };

    let dir = TempDir::new_delete_on_drop();

    // Gen inputs
    let input_file = dir.path().join("ipa_inputs.txt");
    let in_the_clear_output_file = dir.path().join("ipa_output_in_the_clear.json");
    let output_file = dir.path().join("ipa_output.json");

    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--output-file".as_ref(), input_file.as_os_str()])
        .arg("gen-hybrid-inputs")
        .args(["--count", &INPUT_SIZE.to_string()])
        .args(["--max-conversion-value", &MAX_CONVERSION_VALUE.to_string()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()])
        .args(["--seed", &thread_rng().next_u64().to_string()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let mut command = Command::new(IN_THE_CLEAR_BIN);
    command
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args([
            "--output-file".as_ref(),
            in_the_clear_output_file.as_os_str(),
        ])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let config_path = dir.path().join("config");
    let sockets = test_sharded_setup::<SHARDS>(&config_path);
    let _helpers = spawn_shards(&config_path, &sockets, true);

    // encrypt input
    let mut command = Command::new(CRYPTO_UTIL_BIN);
    command
        .arg("hybrid-encrypt")
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args(["--output-dir".as_ref(), dir.path().as_os_str()])
        .args(["--network".into(), config_path.join("network.toml")])
        .stdin(Stdio::piped());
    command.status().unwrap_status();
    let enc1 = dir.path().join("helper1.enc");
    let enc2 = dir.path().join("helper2.enc");
    let enc3 = dir.path().join("helper3.enc");

    // Run Hybrid
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--network".into(), config_path.join("network.toml")])
        .args(["--output-file".as_ref(), output_file.as_os_str()])
        .args(["--shard-count", SHARDS.to_string().as_str()])
        .args(["--wait", "2"])
        .arg("malicious-hybrid")
        .silent()
        .args(["--count", INPUT_SIZE.to_string().as_str()])
        .args(["--enc-input-file1".as_ref(), enc1.as_os_str()])
        .args(["--enc-input-file2".as_ref(), enc2.as_os_str()])
        .args(["--enc-input-file3".as_ref(), enc3.as_os_str()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()]);

    match config.with_dp {
        0 => {
            command.args(["--with-dp", &config.with_dp.to_string()]);
        }
        _ => {
            command
                .args(["--with-dp", &config.with_dp.to_string()])
                .args(["--epsilon", &config.epsilon.to_string()]);
        }
    }
    command.stdin(Stdio::piped());

    let test_mpc = command.spawn().unwrap().terminate_on_drop();
    test_mpc.wait().unwrap_status();

    // basic output checks - output should have the exact size as number of breakdowns
    let output = serde_json::from_str::<HybridQueryResult>(
        &std::fs::read_to_string(&output_file).expect("IPA results file should exist"),
    )
    .expect("IPA results file is valid JSON");

    assert_eq!(
        usize::try_from(config.max_breakdown_key).unwrap(),
        output.breakdowns.len(),
        "Number of breakdowns does not match the expected",
    );
    assert_eq!(INPUT_SIZE, usize::from(output.input_size));

    let expected_result: Vec<u32> = from_reader(
        File::open(in_the_clear_output_file)
            .expect("file should exist as it's created above in the test"),
    )
    .expect("should match hard coded format from in_the_clear");
    assert!(output
        .breakdowns
        .iter()
        .zip(expected_result.iter())
        .all(|(a, b)| a == b));
}

#[test]
fn test_hybrid_poll() {
    const INPUT_SIZE: usize = 100;
    const SHARDS: usize = 5;
    const MAX_CONVERSION_VALUE: usize = 5;

    let config = HybridQueryParams {
        max_breakdown_key: 5,
        with_dp: 0,
        epsilon: 0.0,
        // only encrypted inputs are supported
        plaintext_match_keys: false,
    };

    let dir = TempDir::new_delete_on_drop();

    // Gen inputs
    let input_file = dir.path().join("ipa_inputs.txt");
    let in_the_clear_output_file = dir.path().join("ipa_output_in_the_clear.json");
    let output_file = dir.path().join("ipa_output.json");

    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--output-file".as_ref(), input_file.as_os_str()])
        .arg("gen-hybrid-inputs")
        .args(["--count", &INPUT_SIZE.to_string()])
        .args(["--max-conversion-value", &MAX_CONVERSION_VALUE.to_string()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()])
        .args(["--seed", &thread_rng().next_u64().to_string()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let mut command = Command::new(IN_THE_CLEAR_BIN);
    command
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args([
            "--output-file".as_ref(),
            in_the_clear_output_file.as_os_str(),
        ])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    let config_path = dir.path().join("config");
    let sockets = test_sharded_setup::<SHARDS>(&config_path);
    let _helpers = spawn_shards(&config_path, &sockets, true);

    // encrypt input
    let mut command = Command::new(CRYPTO_UTIL_BIN);
    command
        .arg("hybrid-encrypt")
        .args(["--input-file".as_ref(), input_file.as_os_str()])
        .args(["--output-dir".as_ref(), dir.path().as_os_str()])
        .args(["--length-delimited"])
        .args(["--network".into(), config_path.join("network.toml")])
        .stdin(Stdio::piped());
    command.status().unwrap_status();
    let enc1 = dir.path().join("helper1.enc");
    let enc2 = dir.path().join("helper2.enc");
    let enc3 = dir.path().join("helper3.enc");

    let poll_port = TcpListener::bind("127.0.0.1:0").unwrap();

    // split encryption into N shards and create a metadata file that contains
    // all files
    let upload_metadata = create_upload_files::<SHARDS>(
        &enc1,
        &enc2,
        &enc3,
        poll_port.local_addr().unwrap().port(),
        dir.path(),
    )
    .unwrap();

    // spawn HTTP server to serve the uploaded files
    let mut command = Command::new(TEST_MPC_BIN);
    command
        .arg("serve-input")
        .preserved_fds(vec![poll_port.as_raw_fd()])
        .args(["--fd", &poll_port.as_raw_fd().to_string()])
        .args([
            "--dir".as_ref(),
            upload_metadata.parent().unwrap().as_os_str(),
        ])
        .silent();

    let _server_handle = command.spawn().unwrap().terminate_on_drop();

    // Run Hybrid
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--network".into(), config_path.join("network.toml")])
        .args(["--output-file".as_ref(), output_file.as_os_str()])
        .args(["--shard-count", SHARDS.to_string().as_str()])
        .args(["--wait", "2"])
        .arg("malicious-hybrid")
        .silent()
        .args(["--count", INPUT_SIZE.to_string().as_str()])
        .args(["--url-file-list".into(), upload_metadata])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()]);

    match config.with_dp {
        0 => {
            command.args(["--with-dp", &config.with_dp.to_string()]);
        }
        _ => {
            command
                .args(["--with-dp", &config.with_dp.to_string()])
                .args(["--epsilon", &config.epsilon.to_string()]);
        }
    }
    command.stdin(Stdio::piped());

    let test_mpc = command.spawn().unwrap().terminate_on_drop();
    test_mpc.wait().unwrap_status();

    // basic output checks - output should have the exact size as number of breakdowns
    let output = serde_json::from_str::<HybridQueryResult>(
        &std::fs::read_to_string(&output_file).expect("IPA results file should exist"),
    )
    .expect("IPA results file is valid JSON");

    assert_eq!(
        usize::try_from(config.max_breakdown_key).unwrap(),
        output.breakdowns.len(),
        "Number of breakdowns does not match the expected",
    );
    assert_eq!(INPUT_SIZE, usize::from(output.input_size));

    let expected_result: Vec<u32> = from_reader(
        File::open(in_the_clear_output_file)
            .expect("file should exist as it's created above in the test"),
    )
    .expect("should match hard coded format from in_the_clear");
    assert!(output
        .breakdowns
        .iter()
        .zip(expected_result.iter())
        .all(|(a, b)| a == b));
}

fn create_upload_files<const SHARDS: usize>(
    enc_file1: &Path,
    enc_file2: &Path,
    enc_file3: &Path,
    port: u16,
    dest: &Path,
) -> Result<PathBuf, BoxError> {
    let manifest_path = dest.join("manifest.txt");
    let mut manifest_file = File::create_new(&manifest_path)?;
    create_upload_file::<SHARDS>("h1", enc_file1, port, dest, &mut manifest_file)?;
    create_upload_file::<SHARDS>("h2", enc_file2, port, dest, &mut manifest_file)?;
    create_upload_file::<SHARDS>("h3", enc_file3, port, dest, &mut manifest_file)?;

    manifest_file.flush()?;

    Ok(manifest_path)
}

fn create_upload_file<const SHARDS: usize>(
    prefix: &str,
    enc_file: &Path,
    port: u16,
    dest_dir: &Path,
    metadata_file: &mut File,
) -> Result<(), BoxError> {
    let mut files = (0..SHARDS)
        .map(|i| {
            let path = dest_dir.join(format!("{prefix}_shard_{i}.enc"));
            let file = File::create_new(&path)?;
            Ok((path, file))
        })
        .collect::<std::io::Result<Vec<_>>>()?;

    // we assume files are tiny for the integration tests
    let mut input = BufReader::new(File::open(enc_file)?);
    let mut buf = Vec::new();
    if input.read_to_end(&mut buf)? == 0 {
        panic!("{:?} file is empty", enc_file);
    }

    // read length delimited data and write it to each file
    let stream =
        LengthDelimitedStream::<Bytes, _>::new(futures::stream::iter(once(Ok::<_, BoxError>(
            buf.into(),
        ))))
        .map_ok(|v| futures::stream::iter(v).map(Ok::<_, BoxError>))
        .try_flatten();

    for (i, next_bytes) in futures::executor::block_on_stream(stream).enumerate() {
        let next_bytes = next_bytes?;
        let file = &mut files[i % SHARDS].1;
        let len = u16::try_from(next_bytes.len())
            .map_err(|_| format!("record is too too big: {} > 65535", next_bytes.len()))?;
        file.write(&len.to_le_bytes())?;
        file.write_all(&next_bytes)?;
    }

    // update manifest file
    for (path, mut file) in files {
        file.flush()?;
        let path = path.file_name().and_then(|p| p.to_str()).unwrap();
        writeln!(metadata_file, "http://localhost:{port}/{path}")?;
    }

    Ok(())
}
