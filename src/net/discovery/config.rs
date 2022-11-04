use crate::{
    helpers::{Direction, Role},
    net::{
        discovery::{Error, PeerDiscovery},
        MpcHelperClient,
    },
    protocol::prss,
};
use axum::http::uri::{Authority, Scheme, Uri};
use rand::thread_rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;
use std::path::PathBuf;
use x25519_dalek::PublicKey;

/// Describes just the origin of a url, i.e.: "http\[s\]://\[authority\]", minus the path and
/// query parameters
#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin {
    scheme: Scheme,
    authority: Authority,
}

impl From<Origin> for Uri {
    fn from(origin: Origin) -> Self {
        Uri::builder()
            .scheme(origin.scheme)
            .authority(origin.authority)
            .path_and_query("")
            .build()
            .unwrap()
    }
}

impl Serialize for Origin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}://{}", self.scheme, self.authority))
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UrlVisitor;
        impl<'de> serde::de::Visitor<'de> for UrlVisitor {
            type Value = Origin;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a valid format origin made up of http[s]://<authority>")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let uri = v.parse::<Uri>().map_err(|err| E::custom(err.to_string()))?;
                let parts = uri.into_parts();
                let scheme = parts.scheme.ok_or_else(|| E::custom("missing scheme"))?;
                let authority = parts
                    .authority
                    .ok_or_else(|| E::custom("missing authority"))?;
                Ok(Origin { scheme, authority })
            }
        }
        deserializer.deserialize_str(UrlVisitor)
    }
}

/// Configuration values relevant for interacting with other helpers
#[derive(Serialize, Deserialize)]
struct Peer {
    origin: Origin,
    public_key: PublicKey,
}

/// All config value necessary to discover other peer helpers of the MPC ring
#[derive(Serialize, Deserialize)]
struct Config {
    peers: [Peer; 3],
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
    /// TODO: support HTTPS
    fn peers(&self) -> [MpcHelperClient; 3] {
        self.peers
            .iter()
            .map(|peer| MpcHelperClient::new(peer.origin.clone().into()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| panic!("could not convert vec into array"))
    }

    // TODO: do we need different public key for HTTP and PRSS, or can they share?
    fn prss(&self, role: Role) -> prss::Endpoint {
        let mut rng = thread_rng();
        let endpoint = prss::Endpoint::prepare(&mut rng);
        endpoint.setup(
            &self.peers[role.peer(Direction::Left)].public_key,
            &self.peers[role.peer(Direction::Right)].public_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::fs::File;
    use std::io::Write;

    #[allow(unused)] // TODO: how to test prss seed equality?
    const ROLE: Role = Role::H2;
    #[allow(unused)] // TODO: how to test prss seed equality?
    const H1_PUBLIC_KEY: [u8; 32] = [
        19, 204, 244, 38, 60, 236, 188, 48, 245, 14, 106, 139, 156, 135, 67, 148, 61, 221, 230, 32,
        121, 88, 11, 192, 185, 1, 155, 5, 186, 143, 233, 36,
    ];
    #[allow(unused)] // TODO: how to test prss seed equality?
    const H2_PUBLIC_KEY: [u8; 32] = [
        146, 91, 249, 130, 67, 207, 112, 183, 41, 222, 29, 117, 191, 79, 230, 190, 152, 169, 134,
        96, 131, 49, 219, 99, 144, 43, 130, 161, 105, 29, 193, 59,
    ];
    #[allow(unused)] // TODO: how to test prss seed equality?
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
            "origin": "http://localhost:3000",
            "public_key": [19,204,244,38,60,236,188,48,245,14,106,139,156,135,67,148,61,221,230,32,
                121,88,11,192,185,1,155,5,186,143,233,36]
        },
        {
            "origin": "http://localhost:3001",
            "public_key": [146,91,249,130,67,207,112,183,41,222,29,117,191,79,230,190,152,169,134,
                96,131,49,219,99,144,43,130,161,105,29,193,59]
        },
        {
            "origin":"http://localhost:3002",
            "public_key":[18,192,152,129,161,199,169,45,28,112,217,234,97,157,122,224,104,75,156,
                180,94,204,32,123,152,239,48,236,33,96,160,116]
        }
    ]
}"#;

    fn origin_from_uri_str(uri_str: &str) -> Origin {
        let parts = uri_str.parse::<Uri>().unwrap().into_parts();
        Origin {
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    #[test]
    fn parse_config() {
        let conf: Config = serde_json::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(conf.peers[Role::H1].origin, origin_from_uri_str(H1_URI));
        assert_eq!(conf.peers[Role::H2].origin, origin_from_uri_str(H2_URI));
        assert_eq!(conf.peers[Role::H3].origin, origin_from_uri_str(H3_URI));
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
        assert_eq!(peers[0].origin(), H1_URI);
        assert_eq!(peers[1].origin(), H2_URI);
        assert_eq!(peers[2].origin(), H3_URI);
    }
}
