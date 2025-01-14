use std::{
    array,
    error::Error,
    io::{self, Read, Write},
    net::TcpListener,
    ops::Deref,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, Command, ExitStatus, Stdio},
};

use command_fds::CommandFdExt;
use tempdir::TempDir;

#[cfg(all(test, feature = "cli"))]
pub mod tempdir;

pub const HELPER_BIN: &str = env!("CARGO_BIN_EXE_helper");
pub const TEST_MPC_BIN: &str = env!("CARGO_BIN_EXE_test_mpc");

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

pub trait TerminateOnDropExt {
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

    pub fn wait(self) -> io::Result<ExitStatus> {
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
            if std::thread::panicking() {
                print_stderr(child.stderr.as_mut());
            }
            let _ = child.kill();
        }
    }
}

pub trait CommandExt {
    fn silent(&mut self) -> &mut Self;
}

impl CommandExt for Command {
    // Have the `silent` function return self and comment out the
    // rest of the function to see printing from tests that run all
    // the binaries. e.g. when running: `cargo test --test compact_gate --lib
    // compact_gate_cap_8_no_window_semi_honest -p ipa-core --no-default-features
    // --features "cli web-app real-world-infra test-fixture compact-gate"`
    fn silent(&mut self) -> &mut Self {
        if std::env::var("VERBOSE").ok().is_none() {
            self.arg("--quiet")
        } else {
            self.arg("-vv")
        }
        // return self;
    }
}

fn test_setup(config_path: &Path) -> [ShardTcpListeners; 3] {
    test_sharded_setup::<1>(config_path)
        .into_iter()
        .next()
        .unwrap()
}

pub struct ShardTcpListeners {
    pub mpc: TcpListener,
    pub shard: TcpListener,
}

impl ShardTcpListeners {
    pub fn bind_random() -> Self {
        let mpc = TcpListener::bind("127.0.0.1:0").unwrap();
        let shard = TcpListener::bind("127.0.0.1:0").unwrap();

        Self { mpc, shard }
    }
}

pub fn test_sharded_setup<const SHARDS: usize>(config_path: &Path) -> Vec<[ShardTcpListeners; 3]> {
    let sockets: [_; SHARDS] = array::from_fn(|_| {
        let r: [_; 3] = array::from_fn(|_| ShardTcpListeners::bind_random());

        r
    });

    let (mpc_ports, shard_ports): (Vec<_>, Vec<_>) = sockets
        .each_ref()
        .iter()
        .flat_map(|listeners| {
            listeners
                .each_ref()
                .iter()
                .map(|l| {
                    (
                        l.mpc.local_addr().unwrap().port(),
                        l.shard.local_addr().unwrap().port(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unzip();

    let mut command = Command::new(HELPER_BIN);
    command
        .silent()
        .arg("test-setup")
        .args(["--output-dir".as_ref(), config_path.as_os_str()])
        .arg("--ports")
        .args(mpc_ports.iter().map(|p| p.to_string()))
        .arg("--shard-ports")
        .args(shard_ports.iter().map(|p| p.to_string()));
    command.status().unwrap_status();

    sockets.into_iter().collect()
}

pub fn spawn_shards(
    config_path: &Path,
    sockets: &[[ShardTcpListeners; 3]],
    https: bool,
) -> Vec<TerminateOnDrop> {
    let shard_count = sockets.len();
    sockets
        .iter()
        .enumerate()
        .flat_map(|(shard_index, mpc_sockets)| {
            (1..=3)
                .zip(mpc_sockets.each_ref().iter())
                .map(|(id, ShardTcpListeners { mpc, shard })| {
                    let mut command = Command::new(HELPER_BIN);
                    command
                        .args(["-i", &id.to_string()])
                        .args(["--shard-index", &shard_index.to_string()])
                        .args(["--shard-count", &shard_count.to_string()])
                        .args(["--network".into(), config_path.join("network.toml")]);

                    if https {
                        let config_path = config_path.join(format!("shard{shard_index}"));
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

                    command.preserved_fds(vec![mpc.as_raw_fd(), shard.as_raw_fd()]);
                    command.args(["--server-socket-fd", &mpc.as_raw_fd().to_string()]);
                    command.args(["--shard-server-socket-fd", &shard.as_raw_fd().to_string()]);

                    // something went wrong if command is terminated at this point.
                    let mut child = command.silent().spawn().unwrap();
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            panic!("Helper binary terminated early with status = {status}")
                        }
                        Ok(None) => {}
                        Err(e) => {
                            panic!("Error while waiting for helper binary: {e}");
                        }
                    }

                    child.terminate_on_drop()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn spawn_helpers(
    config_path: &Path,
    // (mpc port + shard port) for 3 helpers
    sockets: &[ShardTcpListeners; 3],
    https: bool,
    log_files: Option<[PathBuf; 3]>,
) -> Vec<TerminateOnDrop> {
    sockets
        .iter()
        .enumerate()
        .zip(
            log_files
                .map(|v| v.map(Some))
                .unwrap_or_else(|| [None, None, None]),
        )
        .map(|((id, ShardTcpListeners { mpc, shard }), log_file)| {
            let id = id + 1;
            let mut command = Command::new(HELPER_BIN);
            command
                .stderr(Stdio::piped())
                .args(["-i", &id.to_string()])
                .args(["--network".into(), config_path.join("network.toml")]);

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

            if let Some(log_file) = log_file {
                command.args(["--log-file".into(), log_file]);
            }

            command.preserved_fds(vec![mpc.as_raw_fd(), shard.as_raw_fd()]);
            command.args(["--server-socket-fd", &mpc.as_raw_fd().to_string()]);
            command.args(["--shard-server-socket-fd", &shard.as_raw_fd().to_string()]);

            // something went wrong if command is terminated at this point.
            let mut child = command.spawn().unwrap();
            if let Ok(Some(status)) = child.try_wait() {
                print_stderr(child.stderr.as_mut());
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

pub fn test_add_in_prime_field(config_dir: &Path, https: bool, count: u32) {
    let mut command = Command::new(TEST_MPC_BIN);
    command
        .args(["--network".into(), config_dir.join("network.toml")])
        .args(["--wait", "2"])
        .args(["--generate", &count.to_string()]);
    if !https {
        command.arg("--disable-https");
    }
    command.silent().arg("add-in-prime-field");

    let test_mpc = command.spawn().unwrap().terminate_on_drop();
    test_mpc.wait().unwrap_status();
}

pub fn test_network<T: NetworkTest>(https: bool) {
    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    println!("generating configuration in {}", path.display());
    let log_files = [
        path.join("h1.log"),
        path.join("h2.log"),
        path.join("h3.log"),
    ];
    let sockets = test_setup(path);
    let _helpers = spawn_helpers(path, &sockets, https, Some(log_files.clone()));

    T::execute(path, https);

    // check that helpers logged something
    for log_file in log_files {
        assert!(log_file.exists(), "log file {log_file:?} does not exist");
        let log = std::fs::read_to_string(&log_file).unwrap();
        assert!(
            log.contains("server listening on"),
            "Logs don't indicate that HTTP server has started: {log}"
        );
    }
}

pub fn test_sharded_network<const SHARDS: usize, T: NetworkTest<SHARDS>>(https: bool) {
    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    println!(
        "generating configuration for {SHARDS} shards in {}",
        path.display()
    );
    let sockets = test_sharded_setup::<SHARDS>(path);
    let _helpers = spawn_shards(path, &sockets, https);

    T::execute(path, https);
}

pub trait NetworkTest<const SHARDS: usize = 1> {
    fn execute(config_path: &Path, https: bool);
}

pub struct Multiply;

impl NetworkTest for Multiply {
    fn execute(config_path: &Path, https: bool) {
        test_multiply(config_path, https)
    }
}

pub struct AddInPrimeField<const N: u32>;

impl<const N: u32> NetworkTest for AddInPrimeField<N> {
    fn execute(config_path: &Path, https: bool) {
        test_add_in_prime_field(config_path, https, N)
    }
}

pub struct ShardedShuffle;

impl<const SHARDS: usize> NetworkTest<SHARDS> for ShardedShuffle {
    fn execute(config_path: &Path, https: bool) {
        let mut command = Command::new(TEST_MPC_BIN);
        command
            .args(["--network".into(), config_path.join("network.toml")])
            .args(["--wait", "2"]);

        if !https {
            command.arg("--disable-https");
        }

        command.arg("sharded-shuffle").stdin(Stdio::piped());

        let test_mpc = command.silent().spawn().unwrap().terminate_on_drop();

        // Shuffle numbers from 1 to 10. `test_mpc` binary will check if they were
        // permuted correctly. Our job here is to submit input large enough to avoid
        // false negatives
        test_mpc
            .stdin
            .as_ref()
            .unwrap()
            .write_all(
                (1..10)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
                    .as_bytes(),
            )
            .unwrap();
        TerminateOnDrop::wait(test_mpc).unwrap_status();
    }
}

fn print_stderr(err_pipe: Option<&mut ChildStderr>) {
    let stderr = err_pipe.unwrap();
    let mut buf = String::new();
    stderr.read_to_string(&mut buf).unwrap();
    println!("stderr output:\n==begin==\n{buf}\n==end==")
}
