use std::{
    fmt::{Display, Formatter},
    marker::PhantomData,
    mem::size_of,
    ops::{Add, Deref},
};

use bytes::{BufMut, Bytes};
use generic_array::{ArrayLength, GenericArray};
use hpke::Serializable as _;
use rand_core::{CryptoRng, RngCore};
use typenum::{Unsigned, U1, U11, U8};

use crate::{
    ff::{
        boolean::Boolean, boolean_array::BA64, GaloisField, Gf40Bit, Gf8Bit, PrimeField,
        Serializable,
    },
    hpke::{
        open_in_place, seal_in_place, CryptError, FieldShareCrypt, Info, KeyPair, KeyRegistry,
        PublicKeyRegistry,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, WeakSharedValue},
};

// TODO(679): This needs to come from configuration.
static HELPER_ORIGIN: &str = "github.com/private-attribution";

pub type KeyIdentifier = u8;
pub const DEFAULT_KEY_ID: KeyIdentifier = 0;

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

impl Serializable for EventType {
    type Size = U1;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let raw: &[u8] = match self {
            EventType::Trigger => &[0],
            EventType::Source => &[1],
        };
        buf.copy_from_slice(raw);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mut buf_to = [0u8; 1];
        buf_to[..buf.len()].copy_from_slice(buf);

        match buf[0] {
            0 => EventType::Trigger,
            1 => EventType::Source,
            2_u8..=u8::MAX => panic!("Unreachable code"),
        }
    }
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
    #[error("timestamp {0} out of range")]
    Timestamp(Timestamp),
    #[error("en/decryption failure: {0}")]
    Crypt(#[from] CryptError),
}

/// A binary report as submitted by a report collector, containing encrypted match key shares.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EncryptedReport<F, MK, BK, B>
where
    B: Deref<Target = [u8]>,
    F: PrimeField,
    Replicated<F>: Serializable,
    MK: FieldShareCrypt,
    BK: GaloisField,
{
    data: B,
    phantom_data: PhantomData<(F, MK, BK)>,
}

// TODO: If we are parsing reports from CSV files, we may also want an owned version of EncryptedReport.

// Report structure:
//  * 0..4: `timestamp`
//  * 4: `breakdown_key`
//  * 5..a: `trigger_value`
//  * a..b: `encap_key`
//  * b..c: `mk_ciphertext`
//  * c: `event_type`
//  * c+1: `key_id`
//  * c+2..c+4: `epoch`
//  * c+4..: `site_domain`
impl<F, B> EncryptedReport<F, Gf40Bit, Gf8Bit, B>
where
    F: PrimeField,
    Replicated<F>: Serializable,
    B: Deref<Target = [u8]>,
{
    // Constants are defined for:
    //  1. Offsets that are calculated from typenum values
    //  2. Offsets that appear in the code in more places than two successive accessors. (Some
    //     offsets are used by validations in the `from_bytes` constructor.)
    const ENCAP_KEY_OFFSET: usize = 5 + 2 * <F as Serializable>::Size::USIZE;
    const CIPHERTEXT_OFFSET: usize =
        Self::ENCAP_KEY_OFFSET + <Gf40Bit as FieldShareCrypt>::EncapKeySize::USIZE;
    const EVENT_TYPE_OFFSET: usize =
        Self::CIPHERTEXT_OFFSET + <Gf40Bit as FieldShareCrypt>::CiphertextSize::USIZE;
    const SITE_DOMAIN_OFFSET: usize = Self::EVENT_TYPE_OFFSET + 4;

    /// ## Panics
    /// Never.
    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes(self.data[0..4].try_into().unwrap()) // infallible slice-to-array conversion
    }

    pub fn breakdown_key(&self) -> Gf8Bit {
        Gf8Bit::deserialize(GenericArray::from_slice(&[self.data[4]]))
    }

    pub fn trigger_value(&self) -> Replicated<F> {
        Replicated::<F>::deserialize(GenericArray::from_slice(
            &self.data[5..Self::ENCAP_KEY_OFFSET],
        ))
    }

    pub fn encap_key(&self) -> &[u8] {
        &self.data[Self::ENCAP_KEY_OFFSET..Self::CIPHERTEXT_OFFSET]
    }

    pub fn match_key_ciphertext(&self) -> &[u8] {
        &self.data[Self::CIPHERTEXT_OFFSET..Self::EVENT_TYPE_OFFSET]
    }

    /// ## Panics
    /// Only if a `Report` constructor failed to validate the contents properly, which would be a bug.
    pub fn event_type(&self) -> EventType {
        EventType::try_from(self.data[Self::EVENT_TYPE_OFFSET]).unwrap() // validated on construction
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.data[Self::EVENT_TYPE_OFFSET + 1]
    }

    /// ## Panics
    /// Never.
    pub fn epoch(&self) -> Epoch {
        u16::from_le_bytes(
            self.data[Self::EVENT_TYPE_OFFSET + 2..Self::SITE_DOMAIN_OFFSET]
                .try_into()
                .unwrap(), // infallible slice-to-array conversion
        )
    }

    /// ## Panics
    /// Only if a `Report` constructor failed to validate the contents properly, which would be a bug.
    pub fn site_domain(&self) -> &str {
        std::str::from_utf8(&self.data[Self::SITE_DOMAIN_OFFSET..]).unwrap() // validated on construction
    }

    /// ## Errors
    /// If the report contents are invalid.
    pub fn from_bytes(bytes: B) -> Result<Self, InvalidReportError> {
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

    /// ## Errors
    /// If the match key shares in the report cannot be decrypted (e.g. due to a
    /// failure of the authenticated encryption).
    /// ## Panics
    /// Should not panic. Only panics if a `Report` constructor failed to validate the
    /// contents properly, which would be a bug.
    pub fn decrypt(
        &self,
        key_registry: &KeyRegistry<KeyPair>,
    ) -> Result<Report<F, Gf40Bit, Gf8Bit>, InvalidReportError> {
        let info = Info::new(
            self.key_id(),
            self.epoch(),
            self.event_type(),
            HELPER_ORIGIN,
            self.site_domain(),
        )
        .unwrap(); // validated on construction

        let mut ciphertext: GenericArray<u8, <Gf40Bit as FieldShareCrypt>::CiphertextSize> =
            *GenericArray::from_slice(self.match_key_ciphertext());
        let plaintext = open_in_place(key_registry, self.encap_key(), &mut ciphertext, &info)?;

        Ok(Report {
            timestamp: self.timestamp(),
            mk_shares: <Gf40Bit as FieldShareCrypt>::SemiHonestShares::deserialize(
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

impl<F> TryFrom<Bytes> for EncryptedReport<F, Gf40Bit, Gf8Bit, Bytes>
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    type Error = InvalidReportError;

    fn try_from(bytes: Bytes) -> Result<Self, InvalidReportError> {
        EncryptedReport::from_bytes(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report<F, MK, BK>
where
    F: PrimeField,
    Replicated<F>: Serializable,
    MK: FieldShareCrypt,
    BK: GaloisField,
{
    pub timestamp: u32,
    pub mk_shares: <MK as FieldShareCrypt>::SemiHonestShares,
    pub event_type: EventType,
    pub breakdown_key: BK,
    pub trigger_value: Replicated<F>,
    pub epoch: Epoch,
    pub site_domain: String,
}

impl<F> Report<F, Gf40Bit, Gf8Bit>
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    /// # Panics
    /// If report length does not fit in u16.
    pub fn encrypted_len(&self) -> u16 {
        let len = EncryptedReport::<F, Gf40Bit, Gf8Bit, &[u8]>::SITE_DOMAIN_OFFSET
            + self.site_domain.as_bytes().len();
        len.try_into().unwrap()
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn delimited_encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidReportError> {
        out.put_u16_le(self.encrypted_len());
        self.encrypt_to(key_id, key_registry, rng, out)
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
    ) -> Result<Vec<u8>, InvalidReportError> {
        let mut out = Vec::new();
        self.encrypt_to(key_id, key_registry, rng, &mut out)?;
        debug_assert_eq!(out.len(), usize::from(self.encrypted_len()));
        Ok(out)
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
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
            seal_in_place(key_registry, plaintext.as_mut(), &info, rng)?;

        out.put_slice(&self.timestamp.to_le_bytes());

        let mut bk = GenericArray::default();
        self.breakdown_key.serialize(&mut bk);
        out.put_slice(bk.as_slice());

        let mut trigger_value = GenericArray::default();
        self.trigger_value.serialize(&mut trigger_value);
        out.put_slice(trigger_value.as_slice());
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfReport<BK, TV, TS>
where
    BK: WeakSharedValue,
    TV: WeakSharedValue,
    TS: WeakSharedValue,
{
    pub match_key: Replicated<BA64>,
    pub event_type: Replicated<Boolean>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
}

impl Serializable for u64 {
    type Size = U8;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let raw = &self.to_le_bytes()[..buf.len()];
        buf.copy_from_slice(raw);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mut buf_to = [0u8; 8];
        buf_to[..buf.len()].copy_from_slice(buf);
        u64::from_le_bytes(buf_to)
    }
}

impl<BK: WeakSharedValue, TV: WeakSharedValue, TS: WeakSharedValue> Serializable
    for OprfReport<BK, TV, TS>
where
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U11>,
    <Replicated<TS> as Serializable>::Size:
        Add<<<Replicated<BK> as Serializable>::Size as Add<U11>>::Output>,
    <Replicated<TV> as Serializable>::Size: Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U11>>::Output,
        >>::Output,
    >,
    <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U11>>::Output,
        >>::Output,
    >>::Output: ArrayLength,
{
    type Size = <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U11>>::Output,
        >>::Output,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let sizeof_u64 = size_of::<u64>() * 2;
        let sizeof_eventtype = size_of::<Boolean>() * 2;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;

        self.match_key
            .serialize(GenericArray::from_mut_slice(&mut buf[..sizeof_u64]));

        self.timestamp.serialize(GenericArray::from_mut_slice(
            &mut buf[sizeof_u64..sizeof_u64 + ts_sz],
        ));

        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[sizeof_u64 + ts_sz..sizeof_u64 + ts_sz + bk_sz],
        ));

        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[sizeof_u64 + ts_sz + bk_sz..sizeof_u64 + ts_sz + bk_sz + tv_sz],
        ));

        self.event_type.serialize(GenericArray::from_mut_slice(
            &mut buf[sizeof_u64 + ts_sz + bk_sz + tv_sz
                ..sizeof_u64 + ts_sz + bk_sz + tv_sz + sizeof_eventtype],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let sizeof_u64 = size_of::<u64>() * 2;
        let sizeof_eventtype = size_of::<Boolean>() * 2;

        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;

        let match_key =
            Replicated::<BA64>::deserialize(GenericArray::from_slice(&buf[..sizeof_u64]));
        let timestamp = Replicated::<TS>::deserialize(GenericArray::from_slice(
            &buf[sizeof_u64..sizeof_u64 + ts_sz],
        ));
        let breakdown_key = Replicated::<BK>::deserialize(GenericArray::from_slice(
            &buf[sizeof_u64 + ts_sz..sizeof_u64 + ts_sz + bk_sz],
        ));
        let trigger_value = Replicated::<TV>::deserialize(GenericArray::from_slice(
            &buf[sizeof_u64 + ts_sz + bk_sz..sizeof_u64 + ts_sz + bk_sz + tv_sz],
        ));
        let event_type = Replicated::<Boolean>::deserialize(GenericArray::from_slice(
            &buf[sizeof_u64 + ts_sz + bk_sz + tv_sz
                ..sizeof_u64 + ts_sz + bk_sz + tv_sz + sizeof_eventtype],
        ));
        Self {
            match_key,
            event_type,
            breakdown_key,
            trigger_value,
            timestamp,
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::{distributions::Alphanumeric, rngs::StdRng, Rng};
    use rand_core::SeedableRng;

    use super::*;
    use crate::ff::{Fp32BitPrime, Gf40Bit, Gf8Bit};

    #[test]
    fn enc_dec_roundtrip() {
        let mut rng = StdRng::from_seed([1_u8; 32]);

        let report = Report::<Fp32BitPrime, Gf40Bit, Gf8Bit> {
            timestamp: rng.gen(),
            mk_shares: (rng.gen(), rng.gen()).into(),
            event_type: EventType::Trigger,
            breakdown_key: rng.gen(),
            trigger_value: (rng.gen(), rng.gen()).into(),
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

        let expected = Report::<Fp32BitPrime, Gf40Bit, Gf8Bit> {
            timestamp: rng.gen(),
            mk_shares: (rng.gen(), rng.gen()).into(),
            event_type: EventType::Trigger,
            breakdown_key: rng.gen(),
            trigger_value: (rng.gen(), rng.gen()).into(),
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
            3301e8d7528e08671418d2164dc80a3403e4aadd01be4263b723ba2204638c20\
            830500710b2bdb931f5f429f234abddf09109ecb2f730b368b7fa4fda0acf3db\
            52c5d509681e8a0100783b6c64466e5531386d6c44\
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
            3301e8d7528e08671418d2164dc80a3403e4aadd01be4263b723ba2204638c20\
            830500710b2bdb931f5f429f234abddf09109ecb2f730b368b7fa4fda0acf3db\
            52c5d509681e8abd00783b6c64466e5531386d6c44\
        ",
        )
        .unwrap();

        let err = EncryptedReport::<Fp32BitPrime, Gf40Bit, Gf8Bit, _>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::BadEventType(_)));
    }

    #[test]
    fn invalid_site_domain() {
        let bytes = hex::decode(
            "\
            3301e8d7528e08671418d2164dc80a3403e4aadd01be4263b723ba2204638c20\
            830500710b2bdb931f5f429f234abddf09109ecb2f730b368b7fa4fda0acf3db\
            52c5d509681e8a0100783bff64466e5531386d6c44\
        ",
        )
        .unwrap();

        let err = EncryptedReport::<Fp32BitPrime, Gf40Bit, Gf8Bit, _>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::NonAsciiString(_)));
    }
}
