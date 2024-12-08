use crate::report::{
    hybrid::{InvalidHybridReportError, NonAsciiStringError, HELPER_ORIGIN},
    KeyIdentifier,
};

const DOMAIN: &str = "private-attribution";

#[derive(Clone, Debug, PartialEq)]
pub struct HybridImpressionInfo {
    pub key_id: KeyIdentifier,
}

impl HybridImpressionInfo {
    /// Creates a new instance.
    #[must_use]
    pub fn new(key_id: KeyIdentifier) -> Self {
        Self { key_id }
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        let out_len = std::mem::size_of_val(&self.key_id);
        debug_assert_eq!(out_len, self.to_bytes().len(), "Serialization length estimation is incorrect and leads to extra allocation or wasted memory");
        out_len
    }

    // Converts this instance into an owned byte slice. DO NOT USE AS INPUT TO HPKE
    // This is only for serialization and deserialization.
    #[must_use]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let info_len = std::mem::size_of_val(&self.key_id);
        let mut r = Vec::with_capacity(info_len);

        r.push(self.key_id);

        debug_assert_eq!(r.len(), info_len, "Serialization length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    #[must_use]
    // Converts this instance into an owned byte slice that can further be used to create HPKE sender or receiver context.
    pub fn to_enc_bytes(&self) -> Box<[u8]> {
        let info_len = DOMAIN.len() + HELPER_ORIGIN.len() + std::mem::size_of_val(&self.key_id);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.extend_from_slice(HELPER_ORIGIN.as_bytes());

        r.push(self.key_id);

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    /// ## Errors
    /// If deserialization fails.
    /// ## Panics
    /// If not enough delimiters are found in the input bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidHybridReportError> {
        let key_id = bytes[0];
        Ok(Self { key_id })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HybridConversionInfo {
    pub key_id: KeyIdentifier,
    pub conversion_site_domain: String,
    pub timestamp: u64,
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl HybridConversionInfo {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if `site_domain` is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        conversion_site_domain: &str,
        timestamp: u64,
        epsilon: f64,
        sensitivity: f64,
    ) -> Result<Self, NonAsciiStringError> {
        if !conversion_site_domain.is_ascii() {
            return Err(conversion_site_domain.into());
        }

        Ok(Self {
            key_id,
            conversion_site_domain: conversion_site_domain.to_string(),
            timestamp,
            epsilon,
            sensitivity,
        })
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        let out_len = std::mem::size_of_val(&self.key_id)
        + 1 // delimiter
        + self.conversion_site_domain.len()
        + std::mem::size_of_val(&self.timestamp)
        + std::mem::size_of_val(&self.epsilon)
        + std::mem::size_of_val(&self.sensitivity);
        debug_assert_eq!(out_len, self.to_bytes().len(), "Serialization length estimation is incorrect and leads to extra allocation or wasted memory");
        out_len
    }

    // Converts this instance into an owned byte slice. DO NOT USE AS INPUT TO HPKE
    // This is only for serialization and deserialization.
    #[must_use]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let info_len = self.conversion_site_domain.len()
            + 1 // delimiter
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.timestamp)
            + std::mem::size_of_val(&self.epsilon)
            + std::mem::size_of_val(&self.sensitivity);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(self.conversion_site_domain.as_bytes());
        r.push(0);

        r.push(self.key_id);
        r.extend_from_slice(&self.timestamp.to_be_bytes());
        r.extend_from_slice(&self.epsilon.to_be_bytes());
        r.extend_from_slice(&self.sensitivity.to_be_bytes());

        debug_assert_eq!(r.len(), info_len, "Serilization length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    // Converts this instance into an owned byte slice that can further be used to create HPKE
    // sender or receiver context.
    #[must_use]
    pub fn to_enc_bytes(&self) -> Box<[u8]> {
        let info_len = DOMAIN.len()
            + HELPER_ORIGIN.len()
            + self.conversion_site_domain.len()
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.timestamp)
            + std::mem::size_of_val(&self.epsilon)
            + std::mem::size_of_val(&self.sensitivity);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.extend_from_slice(HELPER_ORIGIN.as_bytes());
        r.extend_from_slice(self.conversion_site_domain.as_bytes());

        r.push(self.key_id);
        r.extend_from_slice(&self.timestamp.to_be_bytes());
        r.extend_from_slice(&self.epsilon.to_be_bytes());
        r.extend_from_slice(&self.sensitivity.to_be_bytes());

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    /// ## Errors
    /// If deserialization fails.
    /// ## Panics
    /// If not enough delimiters are found in the input bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidHybridReportError> {
        let mut pos = 0;
        let delimiter_pos = bytes[pos..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or_else(|| panic!("not enough delimiters for HybridConversionInfo"));
        let conversion_site_domain = String::from_utf8(bytes[pos..pos + delimiter_pos].to_vec())
            .map_err(|e| {
                InvalidHybridReportError::DeserializationError(
                    "HybridConversionInfo: conversion_site_domain",
                    e.into(),
                )
            })?;
        pos += delimiter_pos + 1;
        debug_assert!(pos + 3*8 + 1 == bytes.len(), "{}", format!("bytes for HybridConversionInfo::from_bytes has incorrect length. Expected: {}, Actual: {}", pos + 3*8 + 1, bytes.len()).to_string());

        let key_id = bytes[pos];
        pos += 1;
        let timestamp = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let epsilon = f64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let sensitivity = f64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());

        Ok(Self {
            key_id,
            conversion_site_domain,
            timestamp,
            epsilon,
            sensitivity,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HybridInfo {
    pub impression: HybridImpressionInfo,
    pub conversion: HybridConversionInfo,
}

impl HybridInfo {
    /// Creates a new instance.
    /// ## Errors
    /// if `site_domain` is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        conversion_site_domain: &str,
        timestamp: u64,
        epsilon: f64,
        sensitivity: f64,
    ) -> Result<Self, NonAsciiStringError> {
        let impression = HybridImpressionInfo::new(key_id);
        let conversion = HybridConversionInfo::new(
            key_id,
            conversion_site_domain,
            timestamp,
            epsilon,
            sensitivity,
        )?;
        Ok(Self {
            impression,
            conversion,
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.conversion.to_bytes()
    }

    /// ## Errors
    /// If deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidHybridReportError> {
        let conversion = HybridConversionInfo::from_bytes(bytes)?;
        let impression = HybridImpressionInfo {
            key_id: conversion.key_id,
        };
        Ok(Self {
            impression,
            conversion,
        })
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use super::*;

    #[test]
    fn test_hybrid_impression_serialization() {
        let info = HybridImpressionInfo::new(0);
        let bytes = info.to_bytes();
        let info2 = HybridImpressionInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_hybrid_conversion_serialization() {
        let info = HybridConversionInfo::new(0, "https://www.example2.com", 1_234_567, 1.151, 0.95)
            .unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridConversionInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info2.key_id, 0);
        assert_eq!(info2.conversion_site_domain, "https://www.example2.com");
        assert_eq!(info2.timestamp, 1_234_567);
        assert_eq!(info2.epsilon, 1.151);
        assert_eq!(info2.sensitivity, 0.95);
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }

    #[test]
    fn test_hybrid_info_serialization() {
        let info = HybridInfo::new(0, "https://www.example2.com", 1_234_567, 1.151, 0.95).unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }
}
