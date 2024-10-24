use crate::report::{hybrid::NonAsciiStringError, KeyIdentifier};

const DOMAIN: &str = "private-attribution";

#[derive(Debug)]
pub struct HybridImpressionInfo<'a> {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'a str,
}

impl<'a> HybridImpressionInfo<'a> {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(key_id: KeyIdentifier, helper_origin: &'a str) -> Result<Self, NonAsciiStringError> {
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
}

#[derive(Debug)]
pub struct HybridConversionInfo<'a> {
    pub key_id: KeyIdentifier,
    pub helper_origin: &'a str,
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
        helper_origin: &'a str,
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

#[allow(dead_code)]
pub enum HybridInfo<'a> {
    Impression(HybridImpressionInfo<'a>),
    Conversion(HybridConversionInfo<'a>),
}
