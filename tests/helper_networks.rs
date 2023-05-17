use std::{
    error::Error,
    io::{self, Write},
    iter::zip,
    ops::Deref,
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

fn test_network(ports: &[u16; 3], https: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path();

    println!("generating configuration in {}", path.display());

    let mut command = Command::new(HELPER_BIN);
    command
        .arg("test-setup")
        .args(["--output-dir".as_ref(), dir.path().as_os_str()])
        .arg("--ports")
        .args(ports.map(|p| p.to_string()));
    command.status().unwrap_status();

    let _helpers = zip([1, 2, 3], ports)
        .map(|(id, port)| {
            let mut command = Command::new(HELPER_BIN);
            command
                .args(["-i", &id.to_string()])
                .args(["--port", &port.to_string()])
                .args(["--network".into(), dir.path().join("network.toml")]);

            if https {
                command
                    .args(["--tls-cert".into(), dir.path().join(format!("h{id}.pem"))])
                    .args(["--tls-key".into(), dir.path().join(format!("h{id}.key"))])
                    .args([
                        "--matchkey-encryption-file".into(),
                        dir.path().join(format!("h{id}_matchkey_encryption")),
                    ])
                    .args([
                        "--matchkey-decryption-file".into(),
                        dir.path().join(format!("h{id}_matchkey_decryption")),
                    ]);
            } else {
                command.arg("--disable-https");
            }

            command.spawn().unwrap().terminate_on_drop()
        })
        .collect::<Vec<_>>();

    let mut command = Command::new(TEST_MPC_BIN);
    command
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--wait", "2"]);
    if !https {
        command.arg("--disable-https");
    }
    command.arg("--quiet").arg("multiply").stdin(Stdio::piped());

    let test_mpc = command.spawn().unwrap().terminate_on_drop();

    test_mpc
        .stdin
        .as_ref()
        .unwrap()
        .write_all(b"3,6\n")
        .unwrap();
    test_mpc.wait().unwrap_status();

    // Uncomment this to preserve the temporary directory after the test runs.
    //std::mem::forget(dir);
}

#[test]
fn http_network() {
    test_network(&[3000, 3001, 3002], false);
}

#[test]
fn https_network() {
    test_network(&[4430, 4431, 4432], true);
}
