use crate::net::discovery::{peer, Error, PeerDiscovery};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// All config value necessary to discover other peer helpers of the MPC ring
#[derive(Serialize, Deserialize)]
struct Config {
    peers: [peer::Config; 3],
}

impl Config {
    /// Reads config from `file_location`. Expects file to be json format
    /// # Errors
    /// if the file does not exist, or is in an invalid format
    #[allow(dead_code)] // TODO: will use in upcoming PR
    pub fn new(file_location: PathBuf) -> Result<Self, Error> {
        use std::{fs::File, io::BufReader};

        let contents = File::open(file_location)?;
        let buffered = BufReader::new(contents);
        Ok(serde_json::from_reader(buffered)?)
    }
}

impl PeerDiscovery for Config {
    fn peers(&self) -> [peer::Config; 3] {
        self.peers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{helpers::Role, net::discovery::peer::PublicKey};
    use hyper::Uri;
    use rand::{
        distributions::Alphanumeric,
        {thread_rng, Rng},
    };
    use std::fs::File;
    use std::io::Write;

    const ROLE: Role = Role::H2;
    const H1_PUBLIC_KEY: [u8; 32] = [
        19, 204, 244, 38, 60, 236, 188, 48, 245, 14, 106, 139, 156, 135, 67, 148, 61, 221, 230, 32,
        121, 88, 11, 192, 185, 1, 155, 5, 186, 143, 233, 36,
    ];
    const H2_PUBLIC_KEY: [u8; 32] = [
        146, 91, 249, 130, 67, 207, 112, 183, 41, 222, 29, 117, 191, 79, 230, 190, 152, 169, 134,
        96, 131, 49, 219, 99, 144, 43, 130, 161, 105, 29, 193, 59,
    ];
    const H3_PUBLIC_KEY: [u8; 32] = [
        18, 192, 152, 129, 161, 199, 169, 45, 28, 112, 217, 234, 97, 157, 122, 224, 104, 75, 156,
        180, 94, 204, 32, 123, 152, 239, 48, 236, 33, 96, 160, 116,
    ];
    const H1_URI: &str = "http://localhost:3000";
    const H2_URI: &str = "http://localhost:3001";
    const H3_URI: &str = "http://localhost:3002";
    const EXAMPLE_CONFIG: &str = r#"
{
    "peers": [
        {
            "http": {
                "origin": "http://localhost:3000",
                "public_key": "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"
            },
            "prss": {
                "public_key": "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"
            }
        },
        {
            "http": {
                "origin": "http://localhost:3001",
                "public_key": "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"
            },
            "prss": {
                "public_key": "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"
            }
        },
        {
            "http": {
                "origin":"http://localhost:3002",
                "public_key": "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
            },
            "prss": {
                "public_key": "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
            }
        }
    ]
}"#;

    fn origin_from_uri_str(uri_str: &str) -> peer::Origin {
        let parts = uri_str.parse::<Uri>().unwrap().into_parts();
        peer::Origin::new(parts.scheme.unwrap(), parts.authority.unwrap())
    }

    fn origin_to_string(origin: &peer::Origin) -> String {
        let uri = Uri::from(origin.clone());
        format!("{}://{}", uri.scheme().unwrap(), uri.authority().unwrap())
    }

    #[test]
    fn parse_config() {
        let conf: Config = serde_json::from_str(EXAMPLE_CONFIG).unwrap();
        // H1
        assert_eq!(
            conf.peers[Role::H1].http.origin,
            origin_from_uri_str(H1_URI)
        );
        assert_eq!(
            conf.peers[Role::H1].http.public_key,
            PublicKey::from(H1_PUBLIC_KEY)
        );

        // H2
        assert_eq!(
            conf.peers[Role::H2].http.origin,
            origin_from_uri_str(H2_URI)
        );
        assert_eq!(
            conf.peers[Role::H2].http.public_key,
            PublicKey::from(H2_PUBLIC_KEY)
        );

        // H3
        assert_eq!(
            conf.peers[Role::H3].http.origin,
            origin_from_uri_str(H3_URI)
        );
        assert_eq!(
            conf.peers[Role::H3].http.public_key,
            PublicKey::from(H3_PUBLIC_KEY)
        );
    }

    #[test]
    fn config_from_file() {
        let filename = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect::<String>();
        let mut filepath = std::env::temp_dir();
        filepath.push(format!("{filename}.json"));

        let mut file = File::create(&filepath).unwrap();
        file.write_all(EXAMPLE_CONFIG.as_bytes()).unwrap();

        let conf = Config::new(filepath).expect("config should successfully be parsed");
        let peers = conf.peers();
        // H1
        assert_eq!(origin_to_string(&peers[0].http.origin), H1_URI);
        assert_eq!(peers[0].http.public_key, PublicKey::from(H1_PUBLIC_KEY));
        // H2
        assert_eq!(origin_to_string(&peers[1].http.origin), H2_URI);
        assert_eq!(peers[1].http.public_key, PublicKey::from(H2_PUBLIC_KEY));
        // H3
        assert_eq!(origin_to_string(&peers[2].http.origin), H3_URI);
        assert_eq!(peers[2].http.public_key, PublicKey::from(H3_PUBLIC_KEY));
    }
}
