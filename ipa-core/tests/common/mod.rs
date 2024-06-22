use std::{
    array,
    error::Error,
    io::{self, Write},
    iter::zip,
    net::TcpListener,
    ops::Deref,
    os::fd::AsRawFd,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
};

use command_fds::CommandFdExt;
use ipa_core::{
    cli::IpaQueryResult,
    helpers::query::{DpParams, IpaQueryConfig},
    test_fixture::ipa::IpaSecurityModel,
};
use rand::thread_rng;
use rand_core::RngCore;
use tempdir::TempDir;

#[cfg(all(test, feature = "cli"))]
pub mod tempdir;

pub const HELPER_BIN: &str = env!("CARGO_BIN_EXE_helper");
pub const TEST_MPC_BIN: &str = env!("CARGO_BIN_EXE_test_mpc");
pub const TEST_RC_BIN: &str = env!("CARGO_BIN_EXE_report_collector");

pub trait UnwrapStatusExt {
    fn unwrap_status(self);
}

impl UnwrapStatusExt for Result<ExitStatus, io::Error> {
    fn unwrap_status(self) {
        self.map_err(Box::<dyn Error>::from)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(status.to_string().into())
                }
            })
            .unwrap()
    }
}

trait TerminateOnDropExt {
    fn terminate_on_drop(self) -> TerminateOnDrop;
}

impl TerminateOnDropExt for Child {
    fn terminate_on_drop(self) -> TerminateOnDrop {
        TerminateOnDrop::from(self)
    }
}

pub struct TerminateOnDrop(Option<Child>);

impl TerminateOnDrop {
    fn into_inner(mut self) -> Child {
        self.0.take().unwrap()
    }

    fn wait(self) -> io::Result<ExitStatus> {
        self.into_inner().wait()
    }
}

impl From<Child> for TerminateOnDrop {
    fn from(child: Child) -> Self {
        Self(Some(child))
    }
}

impl Deref for TerminateOnDrop {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for TerminateOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            eprintln!("killing process {}", child.id());
            let _ = child.kill();
        }
    }
}

pub trait CommandExt {
    fn silent(&mut self) -> &mut Self;
}

impl CommandExt for Command {
    fn silent(&mut self) -> &mut Self {
        if std::env::var("VERBOSE").ok().is_none() {
            self.arg("--quiet")
        } else {
            self.arg("-vv")
        }
        // return self;
    }
}

fn test_setup(config_path: &Path) -> [TcpListener; 3] {
    let sockets: [_; 3] = array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
    let ports: [u16; 3] = sockets
        .each_ref()
        .map(|sock| sock.local_addr().unwrap().port());

    let mut command = Command::new(HELPER_BIN);
    command
        .silent()
        .arg("test-setup")
        .args(["--output-dir".as_ref(), config_path.as_os_str()])
        .arg("--ports")
        .args(ports.map(|p| p.to_string()));

    command.status().unwrap_status();
    sockets
}

pub fn spawn_helpers(
    config_path: &Path,
    sockets: &[TcpListener; 3],
    https: bool,
) -> Vec<TerminateOnDrop> {
    zip([1, 2, 3], sockets)
        .map(|(id, socket)| {
            let mut command = Command::new(HELPER_BIN);
            command
                .args(["-i", &id.to_string()])
                .args(["--network".into(), config_path.join("network.toml")])
                .silent();

            if https {
                command
                    .args(["--tls-cert".into(), config_path.join(format!("h{id}.pem"))])
                    .args(["--tls-key".into(), config_path.join(format!("h{id}.key"))])
                    .args([
                        "--mk-public-key".into(),
                        config_path.join(format!("h{id}_mk.pub")),
                    ])
                    .args([
                        "--mk-private-key".into(),
                        config_path.join(format!("h{id}_mk.key")),
                    ]);
            } else {
                command.arg("--disable-https");
            }

            command.preserved_fds(vec![socket.as_raw_fd()]);
            command.args(["--server-socket-fd", &socket.as_raw_fd().to_string()]);

            // something went wrong if command is terminated at this point.
            let mut child = command.spawn().unwrap();
            if let Ok(Some(status)) = child.try_wait() {
                panic!("Helper binary terminated early with status = {status}");
            }

            child.terminate_on_drop()
        })
        .collect::<Vec<_>>()
}

pub fn test_multiply(config_dir: &Path, https: bool) {
    let mut command = Command::new(TEST_MPC_BIN);
    command
        .args(["--network".into(), config_dir.join("network.toml")])
        .args(["--wait", "2"]);
    if !https {
        command.arg("--disable-https");
    }
    command.silent().arg("multiply").stdin(Stdio::piped());

    let test_mpc = command.spawn().unwrap().terminate_on_drop();

    test_mpc
        .stdin
        .as_ref()
        .unwrap()
        .write_all(b"3,6\n")
        .unwrap();
    test_mpc.wait().unwrap_status();
}

pub fn test_network(https: bool) {
    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    test_multiply(path, https);
}

pub fn test_ipa(mode: IpaSecurityModel, https: bool) {
    test_ipa_with_config(
        mode,
        https,
        IpaQueryConfig {
            // dp_params: DpParams::NoDp,
            ..Default::default()
        },
    );
}

pub fn test_ipa_with_config(mode: IpaSecurityModel, https: bool, config: IpaQueryConfig) {
    const INPUT_SIZE: usize = 100;
    // set to true to always keep the temp dir after test finishes
    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    // Gen inputs
    let inputs_file = dir.path().join("ipa_inputs.txt");
    let output_file = dir.path().join("ipa_output.json");
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--output-file".as_ref(), inputs_file.as_os_str()])
        .arg("gen-ipa-inputs")
        .args(["--count", &INPUT_SIZE.to_string()])
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()])
        .args(["--seed", &thread_rng().next_u64().to_string()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    // Run IPA
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--input-file".as_ref(), inputs_file.as_os_str()])
        .args(["--output-file".as_ref(), output_file.as_os_str()])
        .args(["--wait", "2"])
        .silent();

    if !https {
        command.arg("--disable-https");
    }

    let protocol = match mode {
        IpaSecurityModel::SemiHonest => "oprf-ipa",
        IpaSecurityModel::Malicious => "malicious-ipa",
    };
    command
        .arg(protocol)
        .args(["--max-breakdown-key", &config.max_breakdown_key.to_string()])
        .args([
            "--per-user-credit-cap",
            &config.per_user_credit_cap.to_string(),
        ])
        .args(["--dp-params", &config.dp_params.to_string()])
        .stdin(Stdio::piped());
    if config.attribution_window_seconds.is_some() {
        command.args([
            "--attribution-window-seconds",
            &config.attribution_window_seconds.unwrap().to_string(),
        ]);
    }

    if !https {
        // No reason that match key encryption needs to be coupled with helper-to-helper TLS, but
        // currently it is.
        command.arg("--plaintext-match-keys");
    }

    let test_mpc = command.spawn().unwrap().terminate_on_drop();
    test_mpc.wait().unwrap_status();
    // basic output checks - output should have the exact size as number of breakdowns
    let output = serde_json::from_str::<IpaQueryResult>(
        &std::fs::read_to_string(&output_file).expect("IPA results file exists"),
    )
    .expect("IPA results file is valid JSON");

    assert_eq!(
        usize::try_from(config.max_breakdown_key).unwrap(),
        output.breakdowns.len(),
        "Number of breakdowns does not match the expected",
    );
    assert_eq!(INPUT_SIZE, usize::from(output.input_size));
}
