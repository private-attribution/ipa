use std::fmt::{Display, Formatter};

use super::{Epoch, KeyIdentifier};

const SALT: &str = "private-attribution";

#[derive(Debug)]
pub struct HelperOrigin<'a>(pub &'a str);
#[derive(Debug)]
pub struct SiteOrigin<'a>(pub &'a str);

/// Represents the [`info`] part of the receiver context, that is: application specific data
/// for each encryption.
///
/// IPA uses key identifier, event epoch and both helper and site origins to authenticate match key
/// encryptions. It is not guaranteed that the same receiver can be used for anything else.
///
/// [`info`]: https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con
pub struct AssociatedData<'a> {
    key_id: KeyIdentifier,
    epoch: Epoch,
    helper_origin: &'a HelperOrigin<'a>,
    site_origin: &'a SiteOrigin<'a>,
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

impl<'a> AssociatedData<'a> {
    /// Creates new instance
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        epoch: Epoch,
        helper_origin: &'a HelperOrigin<'a>,
        site_origin: &'a SiteOrigin<'a>,
    ) -> Result<Self, NonAsciiStringError<'a>> {
        if !helper_origin.0.is_ascii() {
            return Err(helper_origin.0.into());
        }

        if !site_origin.0.is_ascii() {
            return Err(site_origin.0.into());
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

    pub(super) fn to_bytes(&self) -> Box<[u8]> {
        let info_len = SALT.len()
            + 2 // account for 2 delimiters
            + self.helper_origin.0.len()
            + self.site_origin.0.len()
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.epoch);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(SALT.as_bytes());
        r.extend_from_slice(self.helper_origin.0.as_bytes());
        r.push(b'\0');
        r.extend_from_slice(self.site_origin.0.as_bytes());
        r.push(b'\0');

        r.push(self.key_id);
        // Spec dictates epoch to be encoded in BE
        r.extend_from_slice(&self.epoch.to_be_bytes());

        r.into_boxed_slice()
    }
}
