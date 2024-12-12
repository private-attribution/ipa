mod common;

use std::{array, path::Path, process::Command};

use common::{
    spawn_helpers, tempdir::TempDir, test_ipa, test_multiply, test_network, CommandExt,
    UnwrapStatusExt, HELPER_BIN,
};
use ipa_core::{cli::CliPaths, helpers::HelperIdentity, test_fixture::ipa::IpaSecurityModel};

use crate::common::{
    test_sharded_network, AddInPrimeField, Multiply, ShardTcpListeners, ShardedShuffle,
};

#[test]
#[cfg(all(test, web_test))]
fn http_network_multiply() {
    test_network::<Multiply>(false);
}

#[test]
#[cfg(all(test, web_test))]
fn https_network_multiply() {
    test_network::<Multiply>(true);
}

#[test]
#[cfg(all(test, web_test))]
fn http_network_add() {
    test_network::<AddInPrimeField<10>>(false);
}

/// This reproduces the faulty behaviour described in #ipa/1141 and should fail
/// if the fix is not in place.
#[test]
#[cfg(all(test, web_test))]
fn http_network_large_input() {
    if std::env::var("EXEC_SLOW_TESTS").is_err() {
        return;
    }

    // 2^31 / (2*sizeof(Fp32BitPrime)) - to exceed the limit for a single chunk on HTTP
    const N: u32 = 268_435_456;
    test_network::<AddInPrimeField<N>>(false);
}

#[test]
#[cfg(all(test, web_test))]
fn http_semi_honest_ipa() {
    test_ipa(IpaSecurityModel::SemiHonest, false, false);
}

#[test]
#[cfg(all(test, web_test))]
fn https_semi_honest_ipa() {
    test_ipa(IpaSecurityModel::SemiHonest, true, true);
}

#[test]
#[cfg(all(test, web_test))]
#[ignore]
fn https_malicious_ipa() {
    test_ipa(IpaSecurityModel::Malicious, true, true);
}

#[test]
#[cfg(all(test, web_test))]
fn http_sharded_shuffle_3_shards() {
    test_sharded_network::<3, ShardedShuffle>(false);
}

#[test]
#[cfg(all(test, web_test))]
fn https_sharded_shuffle_3_shards() {
    test_sharded_network::<3, ShardedShuffle>(true);
}

/// Similar to [`network`] tests, but it uses keygen + confgen CLIs to generate helper client config
/// and then just runs test multiply to make sure helpers are up and running
///
/// [`network`]: crate::test_network
#[test]
#[cfg(all(test, web_test))]
fn keygen_confgen() {
    let dir = TempDir::new_delete_on_drop();
    let path = dir.path();

    let sockets: [_; 3] = array::from_fn(|_| ShardTcpListeners::bind_random());
    let (mpc_ports, shard_ports): (Vec<_>, Vec<_>) = sockets
        .each_ref()
        .iter()
        .map(|ShardTcpListeners { mpc, shard }| {
            (
                mpc.local_addr().unwrap().port(),
                shard.local_addr().unwrap().port(),
            )
        })
        .unzip();

    // closure that generates the client config file (network.toml)
    let exec_conf_gen = |overwrite| {
        let mut command = Command::new(HELPER_BIN);
        command
            .silent()
            .arg("confgen")
            .args(["--output-dir".as_ref(), path.as_os_str()])
            .args(["--keys-dir".as_ref(), path.as_os_str()])
            .arg("--ports")
            .args(mpc_ports.iter().map(|p| p.to_string()))
            .arg("--shard-ports")
            .args(shard_ports.iter().map(|p| p.to_string()))
            .arg("--hosts")
            .args(["localhost", "localhost", "localhost"]);
        if overwrite {
            command.arg("--overwrite");
        }
        command.status().unwrap_status();
    };

    // generate keys for all 3 helpers
    for id in HelperIdentity::make_three() {
        exec_keygen_cmd(id, path)
    }

    exec_conf_gen(false);
    let helpers = spawn_helpers(path, &sockets, true, None);
    test_multiply(path, true);
    drop(helpers);

    // now overwrite the configuration file and try again
    exec_conf_gen(true);
    let helpers = spawn_helpers(path, &sockets, true, None);
    test_multiply(path, true);
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
        .args(["--tls-valid-days", "2"])
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
