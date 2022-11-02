use crate::net::{
    discovery::{Error, PeerDiscovery},
    MpcHelperClient,
};
use axum::http::uri::{Authority, Scheme, Uri};
use serde::{Deserialize, Deserializer};
use std::fmt::Formatter;
use std::path::PathBuf;

/// Describes just the origin of a url, i.e.: "http\[s\]://\[authority\]", minus the path and
/// query parameters
#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin(Scheme, Authority);

impl From<Origin> for Uri {
    fn from(origin: Origin) -> Self {
        let Origin(scheme, authority) = origin;
        Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query("")
            .build()
            .unwrap()
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
                Ok(Origin(scheme, authority))
            }
        }
        deserializer.deserialize_str(UrlVisitor)
    }
}

/// Configuration values for a single peer helper of the MPC ring
#[derive(Deserialize)]
struct HelperConfig {
    origin: Origin,
}

/// All config value necessary to discover all peer helpers of the MPC ring
#[derive(Deserialize)]
struct Config {
    h1: HelperConfig,
    h2: HelperConfig,
    h3: HelperConfig,
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
    fn peers(&self) -> [MpcHelperClient; 3] {
        let h1 = MpcHelperClient::new(self.h1.origin.clone().into());
        let h2 = MpcHelperClient::new(self.h2.origin.clone().into());
        let h3 = MpcHelperClient::new(self.h3.origin.clone().into());
        [h1, h2, h3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::fs::File;
    use std::io::Write;

    const H1_URI: &str = "http://localhost:3000";
    const H2_URI: &str = "http://localhost:3001";
    const H3_URI: &str = "http://localhost:3002";
    const EXAMPLE_CONFIG: &str = r#"
{
    "h1": {
        "origin": "http://localhost:3000"
    },
    "h2": {
        "origin": "http://localhost:3001"
    },
    "h3": {
        "origin": "http://localhost:3002"
    }
}"#;

    fn origin_from_uri_str(uri_str: &str) -> Origin {
        let parts = uri_str.parse::<Uri>().unwrap().into_parts();
        Origin(parts.scheme.unwrap(), parts.authority.unwrap())
    }

    #[test]
    fn parse_config() {
        let conf: Config = serde_json::from_str(EXAMPLE_CONFIG).unwrap();
        assert_eq!(conf.h1.origin, origin_from_uri_str(H1_URI));
        assert_eq!(conf.h2.origin, origin_from_uri_str(H2_URI));
        assert_eq!(conf.h3.origin, origin_from_uri_str(H3_URI));
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
