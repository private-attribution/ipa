use crate::{
    ff::{GaloisField, Serializable},
    hpke::{open_in_place, seal_in_place, CryptError, Info, KeyRegistry, MatchKeyCrypt},
};
use bytes::BufMut;
use generic_array::GenericArray;
use hpke::Serializable as _;
use rand_core::{CryptoRng, RngCore};
use std::{
    fmt::{Display, Formatter},
    marker::PhantomData,
};
use typenum::Unsigned;

static HELPER_ORIGIN: &str = "github.com/private-attribution";

pub type KeyIdentifier = u8;
pub type Timestamp = u32;

/// Event epoch as described [`ipa-spec`]
/// For the purposes of this module, epochs are used to authenticate match key encryption. As
/// report collectors may submit queries with events spread across multiple epochs, decryption context
/// needs to know which epoch to use for each individual event.
///
/// [`ipa-spec`]: https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#other-key-terms
pub type Epoch = u16;

/// Event type as described [`ipa-issue`]
/// Initially we will just support trigger vs source event types but could extend to others in
/// the future.
///
/// ['ipa-issue']: https://github.com/patcg-individual-drafts/ipa/issues/38
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EventType {
    Trigger,
    Source,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEventTypeError(u8);

impl Display for ParseEventTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Illegal trigger bit value: {v}, only 0 and 1 are accepted",
            v = self.0
        )
    }
}

impl std::error::Error for ParseEventTypeError {}

impl TryFrom<u8> for EventType {
    type Error = ParseEventTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Source),
            1 => Ok(Self::Trigger),
            _ => Err(ParseEventTypeError(value)),
        }
    }
}

impl From<&EventType> for u8 {
    fn from(value: &EventType) -> Self {
        match value {
            EventType::Source => 0,
            EventType::Trigger => 1,
        }
    }
}

#[derive(Debug)]
pub struct NonAsciiStringError {
    input: String,
}

impl Display for NonAsciiStringError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "string contains non-ascii symbols: {}", self.input)
    }
}

impl std::error::Error for NonAsciiStringError {}

impl From<&'_ [u8]> for NonAsciiStringError {
    fn from(input: &[u8]) -> Self {
        Self {
            input: String::from_utf8(
                input
                    .iter()
                    .copied()
                    .flat_map(std::ascii::escape_default)
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        }
    }
}

impl From<&'_ str> for NonAsciiStringError {
    fn from(input: &str) -> Self {
        Self::from(input.as_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidReportError {
    #[error("{0}")]
    BadEventType(#[from] ParseEventTypeError),
    #[error("bad site_domain: {0}")]
    NonAsciiString(#[from] NonAsciiStringError),
    #[error("en/decryption failure: {0}")]
    Crypt(#[from] CryptError),
}

/// A binary report as submitted by a report collector, containing encrypted match key shares.
///
/// Contains the following fields:
///  * 0..4: `timestamp`
///  * 4: `breakdown_key`
///  * 5..9: `trigger_value`
///  * 9..a: `encap_key`
///  * a..b: `mk_ciphertext`
///  * b: `event_type`
///  * b+1: `key_id`
///  * b+2..b+4: `epoch`
///  * b+4..: `site_domain`
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EncryptedReport<'a, MK: MatchKeyCrypt, BK: GaloisField> {
    data: &'a [u8],
    phantom_data: PhantomData<(MK, BK)>,
}

// TODO: If we are parsing reports from CSV files, we may also want an owned version of EncryptedReport.

impl<'a, MK: MatchKeyCrypt, BK: GaloisField> EncryptedReport<'a, MK, BK>
where
    MK: MatchKeyCrypt,
{
    // Constants are defined for:
    //  1. Offsets that are calculated from typenum values
    //  2. Offsets that appear in the code in more places than two successive accessors. (Some
    //     offsets are used by validations in the `from_bytes` constructor.)
    const CIPHERTEXT_OFFSET: usize = 9 + <MK as MatchKeyCrypt>::EncapKeySize::USIZE;
    const EVENT_TYPE_OFFSET: usize =
        Self::CIPHERTEXT_OFFSET + <MK as MatchKeyCrypt>::CiphertextSize::USIZE;
    const SITE_DOMAIN_OFFSET: usize = Self::EVENT_TYPE_OFFSET + 4;

    fn timestamp(&self) -> u32 {
        u32::from_le_bytes(self.data[0..4].try_into().unwrap()) // infallible slice-to-array conversion
    }

    fn breakdown_key(&self) -> BK {
        BK::deserialize(GenericArray::from_slice(&[self.data[4]]))
    }

    fn trigger_value(&self) -> u32 {
        u32::from_le_bytes(self.data[5..9].try_into().unwrap()) // infallible slice-to-array conversion
    }

    fn encap_key(&self) -> &[u8] {
        &self.data[9..Self::CIPHERTEXT_OFFSET]
    }

    fn match_key_ciphertext(&self) -> &[u8] {
        &self.data[Self::CIPHERTEXT_OFFSET..Self::EVENT_TYPE_OFFSET]
    }

    fn event_type(&self) -> EventType {
        EventType::try_from(self.data[Self::EVENT_TYPE_OFFSET]).unwrap() // validated on construction
    }

    fn key_id(&self) -> KeyIdentifier {
        self.data[Self::EVENT_TYPE_OFFSET + 1]
    }

    fn epoch(&self) -> Epoch {
        u16::from_le_bytes(
            self.data[Self::EVENT_TYPE_OFFSET + 2..Self::SITE_DOMAIN_OFFSET]
                .try_into()
                .unwrap(), // infallible slice-to-array conversion
        )
    }

    fn site_domain(&self) -> &str {
        std::str::from_utf8(&self.data[Self::SITE_DOMAIN_OFFSET..]).unwrap() // validated on construction
    }

    #[allow(dead_code)] // TODO: temporary
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, InvalidReportError> {
        EventType::try_from(bytes[Self::EVENT_TYPE_OFFSET])?;
        let site_domain = &bytes[Self::SITE_DOMAIN_OFFSET..];
        if !site_domain.is_ascii() {
            return Err(NonAsciiStringError::from(site_domain).into());
        }
        Ok(Self {
            data: bytes,
            phantom_data: PhantomData,
        })
    }

    #[allow(dead_code)] // TODO: temporary
    fn decrypt(&self, key_registry: &KeyRegistry) -> Result<Report<MK, BK>, InvalidReportError> {
        let info = Info::new(
            self.key_id(),
            self.epoch(),
            self.event_type(),
            HELPER_ORIGIN,
            self.site_domain(),
        )
        .unwrap(); // validated on construction

        let mut ciphertext: GenericArray<u8, <MK as MatchKeyCrypt>::CiphertextSize> =
            GenericArray::clone_from_slice(self.match_key_ciphertext());
        let plaintext = open_in_place(key_registry, self.encap_key(), &mut ciphertext, info)?;

        Ok(Report {
            timestamp: self.timestamp(),
            mk_shares: <MK as MatchKeyCrypt>::SemiHonestShares::deserialize(
                GenericArray::from_slice(plaintext),
            ),
            event_type: self.event_type(),
            breakdown_key: self.breakdown_key(),
            trigger_value: self.trigger_value(),
            epoch: self.epoch(),
            site_domain: self.site_domain().to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report<MK: MatchKeyCrypt, BK: GaloisField> {
    pub timestamp: u32,
    pub mk_shares: <MK as MatchKeyCrypt>::SemiHonestShares,
    pub event_type: EventType,
    pub breakdown_key: BK,
    pub trigger_value: u32,
    pub epoch: Epoch,
    pub site_domain: String,
}

impl<MK: MatchKeyCrypt, BK: GaloisField> Report<MK, BK> {
    #[allow(dead_code)] // TODO: temporary
    fn encrypt<R: CryptoRng + RngCore>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &KeyRegistry,
        rng: &mut R,
    ) -> Result<Vec<u8>, InvalidReportError> {
        let mut out = Vec::new();
        self.encrypt_to(key_id, key_registry, rng, &mut out)?;
        Ok(out)
    }

    fn encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &KeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidReportError> {
        let info = Info::new(
            key_id,
            self.epoch,
            self.event_type,
            HELPER_ORIGIN,
            self.site_domain.as_ref(),
        )?;

        let mut plaintext = GenericArray::default();
        self.mk_shares.serialize(&mut plaintext);

        let (encap_key, ciphertext, tag) =
            seal_in_place(key_registry, plaintext.as_mut(), info, rng)?;

        out.put_slice(&self.timestamp.to_le_bytes());

        let mut bk = GenericArray::default();
        self.breakdown_key.serialize(&mut bk);
        out.put_slice(bk.as_slice());

        out.put_slice(&self.trigger_value.to_le_bytes());
        out.put_slice(&encap_key.to_bytes());
        out.put_slice(ciphertext);
        out.put_slice(&tag.to_bytes());
        out.put_slice(&[u8::from(&self.event_type)]);
        out.put_slice(&[key_id]);
        out.put_slice(&self.epoch.to_le_bytes());
        out.put_slice(self.site_domain.as_bytes());

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::ff::{Gf40Bit, Gf8Bit};

    use super::*;

    use rand::{distributions::Alphanumeric, rngs::StdRng, Rng};
    use rand_core::SeedableRng;

    #[test]
    fn enc_dec_roundtrip() {
        let mut rng = StdRng::from_seed([1_u8; 32]);

        let report = Report::<Gf40Bit, Gf8Bit> {
            timestamp: rng.gen(),
            mk_shares: (rng.gen(), rng.gen()).into(),
            event_type: EventType::Trigger,
            breakdown_key: rng.gen(),
            trigger_value: rng.gen(),
            epoch: rng.gen(),
            site_domain: (&mut rng)
                .sample_iter(Alphanumeric)
                .map(char::from)
                .take(10)
                .collect(),
        };

        let key_registry = KeyRegistry::random(1, &mut rng);
        let key_id = 0;

        let enc_report_bytes = report.encrypt(key_id, &key_registry, &mut rng).unwrap();
        let enc_report = EncryptedReport::from_bytes(enc_report_bytes.as_slice()).unwrap();
        let dec_report = enc_report.decrypt(&key_registry).unwrap();

        assert_eq!(dec_report, report);
    }

    #[test]
    fn decrypt() {
        let mut rng = StdRng::from_seed([1_u8; 32]);

        let expected = Report::<Gf40Bit, Gf8Bit> {
            timestamp: rng.gen(),
            mk_shares: (rng.gen(), rng.gen()).into(),
            event_type: EventType::Trigger,
            breakdown_key: rng.gen(),
            trigger_value: rng.gen(),
            epoch: rng.gen(),
            site_domain: (&mut rng)
                .sample_iter(Alphanumeric)
                .map(char::from)
                .take(10)
                .collect(),
        };

        let key_registry = KeyRegistry::random(1, &mut rng);

        let enc_report_bytes = hex::decode(
            "\
            3301e8d7523820f0f88f9b31268b0819b5fafbcd78c27fdbf8841a37a28d\
            8417218da229cb3d55a5228d5939e2181c9da900dadfba0cdf4aa284b9e7\
            af4f6ec90dd4f70100984f536e574d74776c64466e\
        ",
        )
        .unwrap();

        let enc_report = EncryptedReport::from_bytes(enc_report_bytes.as_slice()).unwrap();
        let report = enc_report.decrypt(&key_registry).unwrap();

        assert_eq!(report, expected);
    }

    #[test]
    fn invalid_event_type() {
        let bytes = hex::decode(
            "\
            3301e8d7523820f0f88f9b31268b0819b5fafbcd78c27fdbf8841a37a28d\
            8417218da229cb3d55a5228d5939e2181c9da900dadfba0cdf4aa284b9e7\
            af4f6ec90dd4f7bd00984f536e574d74776c64466e\
        ",
        )
        .unwrap();

        let err = EncryptedReport::<Gf40Bit, Gf8Bit>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::BadEventType(_)));
    }

    #[test]
    fn invalid_site_domain() {
        let bytes = hex::decode(
            "\
            3301e8d7523820f0f88f9b31268b0819b5fafbcd78c27fdbf8841a37a28d\
            8417218da229cb3d55a5228d5939e2181c9da900dadfba0cdf4aa284b9e7\
            af4f6ec90dd4f70100984fff6e574d74776c64466e\
        ",
        )
        .unwrap();

        let err = EncryptedReport::<Gf40Bit, Gf8Bit>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::NonAsciiString(_)));
    }
}
