use crate::{
    helpers::transport::http::discovery::conf::Conf, net::discovery::conf::Conf as OldConf,
};
use std::fmt::Debug;

/// Creates a new config for helpers configured to run on local machine using unique port.
#[allow(clippy::missing_panics_doc)]
pub fn localhost_config<P: TryInto<u16>>(ports: [P; 3]) -> OldConf
where
    P::Error: Debug,
{
    let ports = ports.map(|v| v.try_into().expect("Failed to parse the value into u16"));
    let config_str = format!(
        r#"
    [[peers]]
        origin = "http://localhost:{}"

        [peers.tls]
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

    [[peers]]
        origin = "http://localhost:{}"

        [peers.tls]
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

    [[peers]]
        origin = "http://localhost:{}"

        [peers.tls]
        public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#,
        ports[0], ports[1], ports[2]
    );

    OldConf::from_toml_str(&config_str).unwrap()
}

/// Creates a new config for helpers configured to run on local machine using unique port.
#[allow(clippy::missing_panics_doc)]
pub fn localhost_config_map<P: TryInto<u16>>(ports: [P; 3]) -> Conf
where
    P::Error: Debug,
{
    let ports = ports.map(|v| v.try_into().expect("Failed to parse the value into u16"));
    let config_str = format!(
        r#"
[1]
origin = "http://localhost:{}"

[1.tls]
public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

[2]
origin = "http://localhost:{}"

[2.tls]
public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

[3]
origin = "http://localhost:{}"

[3.tls]
public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#,
        ports[0], ports[1], ports[2]
    );

    Conf::from_toml_str(&config_str).unwrap()
}
