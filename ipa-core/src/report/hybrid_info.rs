use crate::report::{hybrid::NonAsciiStringError, KeyIdentifier};

const DOMAIN: &str = "private-attribution";

#[derive(Clone, Debug)]
pub struct HybridImpressionInfo {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'static str,
}

impl HybridImpressionInfo {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &'static str,
    ) -> Result<Self, NonAsciiStringError> {
        // If the types of errors returned from this function change, then the validation in
        // `EncryptedReport::from_bytes` may need to change as well.
        if !helper_origin.is_ascii() {
            return Err(helper_origin.into());
        }

        Ok(Self {
            key_id,
            helper_origin,
        })
    }

    // Converts this instance into an owned byte slice that can further be used to create HPKE
    // sender or receiver context.
    pub(super) fn to_bytes(&self) -> Box<[u8]> {
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

    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        let mut pos = 0;

        let domain = std::str::from_utf8(&bytes[pos..pos + DOMAIN.len()]).unwrap();
        assert!(domain == DOMAIN, "HPKE Info domain does not match hardcoded domain");
        pos += DOMAIN.len() + 1;

        let delimiter_pos = bytes[pos..].iter().position(|&b| b == 0).unwrap();
        let helper_origin_str = String::from_utf8(bytes[pos..pos + delimiter_pos].to_vec()).unwrap();
        let helper_origin = helper_origin_str.as_str();

        pos += delimiter_pos + 1;

        let key_id = bytes[pos];

        Self {
            key_id,
            helper_origin,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HybridConversionInfo<'a> {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'static str,
    pub conversion_site_domain: &'a str,
    pub timestamp: u64,
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl<'a> HybridConversionInfo<'a> {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &'static str,
        conversion_site_domain: &'a str,
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
            helper_origin,
            conversion_site_domain,
            timestamp,
            epsilon,
            sensitivity,
        })
    }

    // Converts this instance into an owned byte slice that can further be used to create HPKE
    // sender or receiver context.
    pub(super) fn to_bytes(&self) -> Box<[u8]> {
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
}

#[derive(Clone, Debug)]
pub struct HybridInfo<'a> {
    pub impression: HybridImpressionInfo,
    pub conversion: HybridConversionInfo<'a>,
}

impl HybridInfo<'_> {
    /// Creates a new instance.
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        helper_origin: &'static str,
        conversion_site_domain: &'static str,
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
}

#[cfg(all(test, unit_test))]
mod test {
    use super::*;

    #[test]
    fn test_hybrid_impression_serialization() {
        let info = HybridImpressionInfo::new(0, "https://www.example.com").unwrap();
        let bytes = info.to_bytes();
        let info2 = HybridImpressionInfo::from_bytes(&bytes);
        assert_eq!(info.to_bytes(), info2.to_bytes());
    }
}
