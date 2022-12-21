use hyper::Uri;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

/// # Errors
/// if serializing to string fails
pub fn serialize<S: Serializer>(uri: &Uri, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&uri.to_string())
}

/// # Errors
/// if deserializing from string fails, or if string is not a [`Uri`]
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uri, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse().map_err(D::Error::custom)
}
