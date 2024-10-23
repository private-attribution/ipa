use crate::report::{Epoch, EventType, KeyIdentifier, NonAsciiStringError};

const DOMAIN: &str = "private-attribution";

/// Represents the [`info`] part of the receiver context, that is: application specific data
/// for each encryption.
///
/// IPA uses key identifier, key event epoch, helper and match key provider origins, and
/// site registrable domain to authenticate the encryption of a match key.
/// It is not guaranteed that the same receiver can be used for anything else.
///
/// [`info`]: https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con
#[derive(Clone)]
pub struct Info<'a> {
    pub(super) key_id: KeyIdentifier,
    pub(super) epoch: Epoch,
    pub(super) event_type: EventType,
    pub(super) helper_origin: &'a str,
    pub(super) site_domain: &'a str,
}

impl<'a> Info<'a> {
    /// Creates a new instance.
    ///
    /// ## Errors
    /// if helper or site origin is not a valid ASCII string.
    pub fn new(
        key_id: KeyIdentifier,
        epoch: Epoch,
        event_type: EventType,
        helper_origin: &'a str,
        site_domain: &'a str,
    ) -> Result<Self, NonAsciiStringError> {
        // If the types of errors returned from this function change, then the validation in
        // `EncryptedReport::from_bytes` may need to change as well.
        if !helper_origin.is_ascii() {
            return Err(helper_origin.into());
        }

        if !site_domain.is_ascii() {
            return Err(site_domain.into());
        }

        Ok(Self {
            key_id,
            epoch,
            event_type,
            helper_origin,
            site_domain,
        })
    }

    /// Converts this instance into an owned byte slice that can further be used to create HPKE
    /// sender or receiver context.
    pub(crate) fn to_bytes(&self) -> Box<[u8]> {
        let info_len = DOMAIN.len()
            + self.helper_origin.len()
            + self.site_domain.len()
            + 3 // account for 3 delimiters
            + std::mem::size_of_val(&self.key_id)
            + std::mem::size_of_val(&self.epoch)
            + std::mem::size_of_val(&self.event_type);
        let mut r = Vec::with_capacity(info_len);

        r.extend_from_slice(DOMAIN.as_bytes());
        r.push(0);
        r.extend_from_slice(self.helper_origin.as_bytes());
        r.push(0);
        r.extend_from_slice(self.site_domain.as_bytes());
        r.push(0);

        r.push(self.key_id);
        // Spec dictates epoch to be encoded in BE
        r.extend_from_slice(&self.epoch.to_be_bytes());
        r.push((&self.event_type).into());

        debug_assert_eq!(r.len(), info_len, "HPKE Info length estimation is incorrect and leads to extra allocation or wasted memory");

        r.into_boxed_slice()
    }
}
