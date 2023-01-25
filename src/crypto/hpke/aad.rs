use std::fmt::{Display, Formatter};

use super::{Epoch, KeyIdentifier};

const DOMAIN: &str = "private-attribution";

/// Represents the [`info`] part of the receiver context, that is: application specific data
/// for each encryption.
///
/// IPA uses key identifier, event epoch and both helper and site origins to authenticate match key
/// encryptions. It is not guaranteed that the same receiver can be used for anything else.
///
/// [`info`]: https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con
#[derive(Clone)]
pub struct Info<'a> {
    pub(super) key_id: KeyIdentifier,
    pub(super) epoch: Epoch,
    pub(super) helper_origin: &'a str,
    pub(super) site_origin: &'a str,
}

#[derive(Debug)]
pub struct NonAsciiStringError<'a> {
    input: &'a str,
}

impl Display for NonAsciiStringError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "string contains non-ascii symbols: {}", self.input)
    }
}

impl<'a> From<&'a str> for NonAsciiStringError<'a> {
    fn from(input: &'a str) -> Self {
        Self { input }
    }
}

impl<'a> Info<'a> {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        epoch: Epoch,
        helper_origin: &'a str,
        site_origin: &'a str,
    ) -> Result<Self, NonAsciiStringError<'a>> {
        if !helper_origin.is_ascii() {
            return Err(helper_origin.into());
        }

        if !site_origin.is_ascii() {
            return Err(site_origin.into());
        }

        Ok(Self {
            key_id,
            epoch,
            helper_origin,
            site_origin,
        })
    }

    pub(super) fn key_id(&self) -> KeyIdentifier {
        self.key_id
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Converts this instance into an owned byte slice that can further be used to create HPKE
    /// sender or receiver context.
    pub(super) fn into_bytes(self) -> Box<[u8]> {
        let info_len = DOMAIN.len()
            + 3 // account for 3 delimiters
            + self.helper_origin.len()
            + self.site_origin.len()
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.epoch);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.push(0);
        r.extend_from_slice(self.helper_origin.as_bytes());
        r.push(0);
        r.extend_from_slice(self.site_origin.as_bytes());
        r.push(0);

        r.push(self.key_id);
        // Spec dictates epoch to be encoded in BE
        r.extend_from_slice(&self.epoch.to_be_bytes());

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }
}
