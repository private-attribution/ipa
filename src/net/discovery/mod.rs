pub mod config;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] serde_json::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

pub mod peer {
    use axum::http::{
        uri::{Authority, Scheme},
        Uri,
    };
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt::Formatter;
    use std::ops::{Deref, DerefMut};

    /// Describes just the origin of a url, i.e.: "http\[s\]://\[authority\]", minus the path and
    /// query parameters
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Origin {
        scheme: Scheme,
        authority: Authority,
    }

    impl Origin {
        pub fn new(scheme: Scheme, authority: Authority) -> Self {
            Self { scheme, authority }
        }
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

    #[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
    pub struct PublicKey(x25519_dalek::PublicKey);

    impl Serialize for PublicKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let pk_bytes = self.0.to_bytes();
            let hex_str = hex::encode(pk_bytes);
            serializer.serialize_str(&hex_str)
        }
    }

    impl<'de> Deserialize<'de> for PublicKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct PublicKeyVisitor;
            impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                    formatter.write_str("a valid 32 byte hex string")
                }

                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    let hex_bytes = hex::decode(v).map_err(E::custom)?;
                    let hex_bytes_array: [u8; 32] =
                        hex_bytes.try_into().map_err(|v: Vec<u8>| {
                            E::custom(format!("invalid length for public key: {}", v.len()))
                        })?;
                    Ok(PublicKey(hex_bytes_array.into()))
                }
            }
            deserializer.deserialize_str(PublicKeyVisitor)
        }
    }

    impl Deref for PublicKey {
        type Target = x25519_dalek::PublicKey;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for PublicKey {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl From<[u8; 32]> for PublicKey {
        fn from(bytes: [u8; 32]) -> Self {
            PublicKey(x25519_dalek::PublicKey::from(bytes))
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct HttpConfig {
        pub origin: Origin,
        pub public_key: PublicKey,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct PrssConfig {
        pub public_key: PublicKey,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Config {
        pub http: HttpConfig,
        pub prss: PrssConfig,
    }
}

/// Provides a set of peer helpers for an MPC computation. Also includes the client pointing to the
/// running server. Since the running server is aware of which [`Identity`] it is (`H1`, `H2`, or
/// `H3`), it should be able to use only the references to other servers. However, it's possible for
/// a server to send data to itself.
///
/// Any potential failures should be captured in the initialization of the implementer.
#[allow(clippy::module_name_repetitions)] // following standard naming convention
pub trait PeerDiscovery {
    fn peers(&self) -> [peer::Config; 3];
}
