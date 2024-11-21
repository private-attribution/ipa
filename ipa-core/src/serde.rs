//! Serialization helpers for Serde

#[cfg(feature = "web-app")]
pub mod uri {
    use hyper::Uri;
    use serde::{de::Error, Deserialize, Deserializer};

    /// # Errors
    /// if deserializing from string fails, or if string is not a [`Uri`]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uri, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;
        s.parse().map_err(D::Error::custom)
    }
}

#[cfg(feature = "web-app")]
pub mod option {
    pub mod uri {
        use hyper::Uri;
        use serde::{de::Error, Deserialize, Deserializer};

        /// # Errors
        /// if deserializing from string fails, or if string is not a [`Uri`]
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Uri>, D::Error> {
            let opt_s: Option<String> = Deserialize::deserialize(deserializer)?;
            if let Some(s) = opt_s {
                s.parse().map(Some).map_err(D::Error::custom)
            } else {
                Ok(None)
            }
        }
    }
}

pub mod duration {
    use std::time::Duration;

    pub fn to_secs<'dur, I, S>(d: I, s: S) -> Result<S::Ok, S::Error>
    where
        I: Into<Option<&'dur Duration>>,
        S: serde::Serializer,
    {
        let d = d.into();
        match d {
            Some(v) => s.serialize_f64(v.as_secs_f64()),
            None => s.serialize_none(),
        }
    }

    pub fn from_secs<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = serde::Deserialize::deserialize(d)?;
        Ok(Duration::from_secs_f64(secs))
    }

    #[cfg(feature = "web-app")]
    pub fn from_secs_optional<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let secs: Option<f64> = serde::Deserialize::deserialize(d)?;
        Ok(secs.map(Duration::from_secs_f64))
    }
}
