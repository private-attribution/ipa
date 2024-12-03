use crate::report::{hybrid::{NonAsciiStringError, InvalidHybridReportError}, KeyIdentifier};

const DOMAIN: &str = "private-attribution";

#[derive(Clone, Debug, PartialEq)]
pub struct HybridImpressionInfo {
    pub key_id: KeyIdentifier,
    pub helper_origin: String,
}

impl HybridImpressionInfo {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &str,
    ) -> Result<Self, NonAsciiStringError> {
        // If the types of errors returned from this function change, then the validation in
        // `EncryptedReport::from_bytes` may need to change as well.
        if !helper_origin.is_ascii() {
            return Err(helper_origin.into());
        }

        Ok(Self {
            key_id,
            helper_origin: helper_origin.to_string(),
        })
    }

    // Converts this instance into an owned byte slice that can further be used to create HPKE
    // sender or receiver context.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let info_len = DOMAIN.len()
            + self.helper_origin.len()
            + 2 // delimiters(?)
            + std::mem::size_of_val(&self.key_id);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.push(0);
        r.extend_from_slice(self.helper_origin.as_bytes());
        r.push(0);

        r.push(self.key_id);

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &[u8]) ->  Result<Self, InvalidHybridReportError> {
        let mut pos = 0;

        let domain = std::str::from_utf8(&bytes[pos..pos + DOMAIN.len()]).unwrap();
        assert!(domain == DOMAIN, "HPKE Info domain does not match hardcoded domain");
        pos += DOMAIN.len() + 1;

        let delimiter_pos = bytes[pos..].iter().position(|&b| b == 0).unwrap();
        let helper_origin = String::from_utf8(bytes[pos..pos + delimiter_pos].to_vec()).unwrap();

        pos += delimiter_pos + 1;

        let key_id = bytes[pos];

        Ok(Self {
            key_id,
            helper_origin,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HybridConversionInfo{
    pub key_id: KeyIdentifier,
    pub helper_origin: String,
    pub conversion_site_domain: String,
    pub timestamp: u64,
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl HybridConversionInfo{
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &str,
        conversion_site_domain: &str,
        timestamp: u64,
        epsilon: f64,
        sensitivity: f64,
    ) -> Result<Self, NonAsciiStringError> {
        // If the types of errors returned from this function change, then the validation in
        // `EncryptedReport::from_bytes` may need to change as well.
        if !helper_origin.is_ascii() {
            return Err(helper_origin.into());
        }

        if !conversion_site_domain.is_ascii() {
            return Err(conversion_site_domain.into());
        }

        Ok(Self {
            key_id,
            helper_origin: helper_origin.to_string(),
            conversion_site_domain: conversion_site_domain.to_string(),
            timestamp,
            epsilon,
            sensitivity,
        })
    }

    // Converts this instance into an owned byte slice that can further be used to create HPKE
    // sender or receiver context.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let info_len = DOMAIN.len()
            + self.helper_origin.len()
            + self.conversion_site_domain.len()
            + 3 // delimiters
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.timestamp)
            + std::mem::size_of_val(&self.epsilon)
            + std::mem::size_of_val(&self.sensitivity);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.push(0);
        r.extend_from_slice(self.helper_origin.as_bytes());
        r.push(0);
        r.extend_from_slice(self.conversion_site_domain.as_bytes());
        r.push(0);

        r.push(self.key_id);
        r.extend_from_slice(&self.timestamp.to_be_bytes());
        r.extend_from_slice(&self.epsilon.to_be_bytes());
        r.extend_from_slice(&self.sensitivity.to_be_bytes());

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &[u8]) ->  Result<Self, InvalidHybridReportError> {
        let mut pos = 0;

        let domain = std::str::from_utf8(&bytes[pos..pos + DOMAIN.len()]).unwrap();
        assert!(domain == DOMAIN, "HPKE Info domain does not match hardcoded domain");
        pos += DOMAIN.len() + 1;

        let mut delimiter_pos = bytes[pos..].iter().position(|&b| b == 0).unwrap();
        let helper_origin = String::from_utf8(bytes[pos..pos + delimiter_pos].to_vec()).unwrap();
        pos += delimiter_pos + 1;

        delimiter_pos = bytes[pos..].iter().position(|&b| b == 0).unwrap();
        let conversion_site_domain = String::from_utf8(bytes[pos..pos + delimiter_pos].to_vec()).unwrap();
        pos += delimiter_pos + 1;

        let key_id = bytes[pos];
        pos += 1;
        let timestamp = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let epsilon = f64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let sensitivity = f64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());

        Ok(Self {
            key_id,
            helper_origin,
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

impl HybridInfo{
    /// Creates a new instance.
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &str,
        conversion_site_domain: &str,
        timestamp: u64,
        epsilon: f64,
        sensitivity: f64,
    ) -> Result<Self, NonAsciiStringError> {
        let impression = HybridImpressionInfo::new(key_id, helper_origin)?;
        let conversion = HybridConversionInfo::new(
            key_id,
            helper_origin,
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

    pub fn to_bytes(&self) -> Box<[u8]> {
        self.conversion.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidHybridReportError> {
        let conversion = HybridConversionInfo::from_bytes(bytes)?;
        let impression = HybridImpressionInfo{
            key_id: conversion.key_id,
            helper_origin: conversion.helper_origin.clone(),
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
        let info = HybridImpressionInfo::new(0, "https://www.example.com").unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridImpressionInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }

    #[test]
    fn test_hybrid_conversion_serialization() {
        let info = HybridConversionInfo::new(0, "https://www.example.com", "https://www.example2.com", 1234567, 1.151, 0.95).unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridConversionInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }

    #[test]
    fn test_hybrid_info_serialization() {
        let info = HybridInfo::new(0, "https://www.example.com", "https://www.example2.com", 1234567, 1.151, 0.95).unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridInfo::from_bytes(&bytes).unwrap();
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }
}
