use std::{
    error::Error,
    io::{self, Write},
    iter::zip,
    process::{Command, ExitStatus, Stdio},
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
    if !https {
        command.arg("--disable-https");
    }
    command.status().unwrap_status();

    let helpers = zip([1, 2, 3], ports)
        .map(|(id, port)| {
            let mut command = Command::new(HELPER_BIN);
            command
                .args(["-i", &id.to_string()])
                .args(["--port", &port.to_string()])
                .args(["--network".into(), dir.path().join("network.toml")]);

            if https {
                command
                    .args(["--tls-cert".into(), dir.path().join(format!("h{id}.pem"))])
                    .args(["--tls-key".into(), dir.path().join(format!("h{id}.key"))]);
            }

            command.spawn().unwrap()
        })
        .collect::<Vec<_>>();

    let mut test_mpc = Command::new(TEST_MPC_BIN)
        .args(["--network".into(), dir.path().join("network.toml")])
        .args(["--wait", "2"])
        .arg("--quiet")
        .arg("multiply")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    test_mpc
        .stdin
        .as_ref()
        .unwrap()
        .write_all(b"3,6\n")
        .unwrap();
    test_mpc.wait().unwrap_status();

    for mut helper in helpers {
        helper.kill().unwrap();
    }

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
