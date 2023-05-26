use command_fds::CommandFdExt;
use ipa::test_fixture::ipa::IpaSecurityModel;
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
use tempfile::tempdir;

const HELPER_BIN: &str = env!("CARGO_BIN_EXE_helper");
const TEST_MPC_BIN: &str = env!("CARGO_BIN_EXE_test_mpc");

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
                        config_path.join(format!("h{id}_mk")),
                    ]);
            } else {
                command.arg("--disable-https");
            }

            command.preserved_fds(vec![socket.as_raw_fd()]);
            command.args(["--server-socket-fd", &socket.as_raw_fd().to_string()]);

            command.spawn().unwrap().terminate_on_drop()
        })
        .collect::<Vec<_>>()
}

fn test_network(https: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    let mut command = Command::new(TEST_MPC_BIN);
    command
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--wait", "2"]);
    if !https {
        command.arg("--disable-https");
    }
    command.silent().arg("multiply").stdin(Stdio::piped());

    let test_mpc = command.spawn().unwrap().terminate_on_drop();

    // Uncomment this to preserve the temporary directory after the test runs.
    // std::mem::forget(dir);

    test_mpc
        .stdin
        .as_ref()
        .unwrap()
        .write_all(b"3,6\n")
        .unwrap();
    test_mpc.wait().unwrap_status();
}

fn test_ipa(mode: IpaSecurityModel, https: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https);

    // Gen inputs
    let inputs_file = dir.path().join("ipa_inputs.txt");
    let mut command = Command::new(TEST_MPC_BIN);
    command
        .arg("gen-ipa-inputs")
        .args(["--count", "10"])
        .args(["--max-breakdown-key", "20"])
        .args(["--output-file".as_ref(), inputs_file.as_os_str()])
        .silent()
        .stdin(Stdio::piped());
    command.status().unwrap_status();

    // Run IPA
    let mut command = Command::new(TEST_MPC_BIN);
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

    // Uncomment this to preserve the temporary directory after the test runs.
    // std::mem::forget(dir);

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
