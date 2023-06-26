use command_fds::CommandFdExt;
use ipa::{cli::CliPaths, helpers::HelperIdentity, test_fixture::ipa::IpaSecurityModel};
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
    str,
};
use tempdir::TempDir;

#[cfg(all(test, feature = "cli"))]
pub mod tempdir;

const HELPER_BIN: &str = env!("CARGO_BIN_EXE_helper");
const TEST_MPC_BIN: &str = env!("CARGO_BIN_EXE_test_mpc");
const TEST_RC_BIN: &str = env!("CARGO_BIN_EXE_report_collector");

trait UnwrapStatusExt {
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

trait CommandExt {
    fn silent(&mut self) -> &mut Self;
}

impl CommandExt for Command {
    fn silent(&mut self) -> &mut Self {
        if std::env::var("VERBOSE").ok().is_none() {
            self.arg("--quiet")
        } else {
            self.arg("-vv")
        }
    }
}

fn test_setup(config_path: &Path) -> [TcpListener; 3] {
    let sockets: [_; 3] = array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
    let ports: [u16; 3] = sockets
        .iter()
        .map(|sock| sock.local_addr().unwrap().port())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

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

fn spawn_helpers(
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

fn test_multiply(config_dir: &Path, https: bool) {
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

fn test_network(https: bool) {
    // set to true to always keep the temp dir after test finishes
    let dir = TempDir::new(false);
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    test_multiply(&path, https);
}

fn test_ipa(mode: IpaSecurityModel, https: bool) {
    // set to true to always keep the temp dir after test finishes
    let dir = TempDir::new(false);
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    // Gen inputs
    let inputs_file = dir.path().join("ipa_inputs.txt");
    let mut command = Command::new(TEST_RC_BIN);
    command
        .arg("gen-ipa-inputs")
        .args(["--count", "10"])
        .args(["--max-breakdown-key", "20"])
        .args(["--output-file".as_ref(), inputs_file.as_os_str()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    // Run IPA
    let mut command = Command::new(TEST_RC_BIN);
    command
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--input-file".as_ref(), inputs_file.as_os_str()])
        .args(["--wait", "2"])
        .silent();

    if !https {
        command.arg("--disable-https");
    }

    let protocol = match mode {
        IpaSecurityModel::SemiHonest => "semi-honest-ipa",
        IpaSecurityModel::Malicious => "malicious-ipa",
    };
    command
        .arg(protocol)
        .args(["--max-breakdown-key", "20"])
        .stdin(Stdio::piped());
    if !https {
        // No reason that match key encryption needs to be coupled with helper-to-helper TLS, but
        // currently it is.
        command.arg("--plaintext-match-keys");
    }

    let test_mpc = command.spawn().unwrap().terminate_on_drop();
    test_mpc.wait().unwrap_status();
}

#[test]
fn http_network() {
    test_network(false);
}

#[test]
fn https_network() {
    test_network(true);
}

#[test]
fn http_semi_honest_ipa() {
    test_ipa(IpaSecurityModel::SemiHonest, false);
}

#[test]
fn https_semi_honest_ipa() {
    test_ipa(IpaSecurityModel::SemiHonest, true);
}

/// Similar to [`network`] tests, but it uses keygen + confgen CLIs to generate helper client config
/// and then just runs test multiply to make sure helpers are up and running
///
/// [`network`]: crate::test_network
#[test]
fn keygen_confgen() {
    let dir = TempDir::new(false);
    let path = dir.path();

    let sockets: [_; 3] = array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
    let ports: [u16; 3] = sockets
        .iter()
        .map(|sock| sock.local_addr().unwrap().port())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // closure that generates the client config file (network.toml)
    let exec_conf_gen = |overwrite| {
        let mut command = Command::new(HELPER_BIN);
        command
            .silent()
            .arg("confgen")
            .args(["--output-dir".as_ref(), path.as_os_str()])
            .args(["--keys-dir".as_ref(), path.as_os_str()])
            .arg("--ports")
            .args(ports.map(|p| p.to_string()))
            .arg("--hosts")
            .args(["localhost", "localhost", "localhost"]);
        if overwrite {
            command.arg("--overwrite");
        }
        command.status().unwrap_status();
    };

    // generate keys for all 3 helpers
    for id in HelperIdentity::make_three() {
        exec_keygen_cmd(id, &path)
    }

    exec_conf_gen(false);
    let helpers = spawn_helpers(path, &sockets, true);
    test_multiply(&path, true);
    drop(helpers);

    // now overwrite the configuration file and try again
    exec_conf_gen(true);
    let helpers = spawn_helpers(path, &sockets, true);
    test_multiply(&path, true);
    drop(helpers);
}

fn exec_keygen_cmd(helper_identity: HelperIdentity, dest_dir: &Path) {
    let mut command = Command::new(HELPER_BIN);
    command
        .silent()
        .arg("keygen")
        .args(["--name", "localhost"])
        .args([
            "--tls-cert".as_ref(),
            dest_dir.helper_tls_cert(helper_identity).as_os_str(),
        ])
        .args([
            "--tls-key".as_ref(),
            dest_dir.helper_tls_key(helper_identity).as_os_str(),
        ])
        .args([
            "--mk-private-key".as_ref(),
            dest_dir.helper_mk_private_key(helper_identity).as_os_str(),
        ])
        .args([
            "--mk-public-key".as_ref(),
            dest_dir.helper_mk_public_key(helper_identity).as_os_str(),
        ]);

    command.status().unwrap_status();
}
