use std::{
    fmt::{Display, Formatter},
    marker::PhantomData,
    ops::{Add, Deref},
};

use bytes::{BufMut, Bytes};
use generic_array::{ArrayLength, GenericArray};
use hpke::Serializable as _;
use rand_core::{CryptoRng, RngCore};
use typenum::{Sum, Unsigned, U1, U16};

use crate::{
    error::BoxError,
    ff::{boolean_array::BA64, Serializable},
    hpke::{
        open_in_place, seal_in_place, CryptError, EncapsulationSize, Info, KeyPair, KeyRegistry,
        PublicKeyRegistry, TagSize,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
};
mod matchkey;

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

#[derive(thiserror::Error, Debug)]
#[error("{0} is not a valid event type, only 0 and 1 are allowed.")]
pub struct UnknownEventType(u8);

impl Serializable for EventType {
    type Size = U1;
    type DeserializationError = UnknownEventType;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let raw: &[u8] = match self {
            EventType::Trigger => &[1],
            EventType::Source => &[0],
        };
        buf.copy_from_slice(raw);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        match buf[0] {
            1 => Ok(EventType::Trigger),
            0 => Ok(EventType::Source),
            _ => Err(UnknownEventType(buf[0])),
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
    #[error("failed to deserialize field {0}: {1}")]
    DeserializationError(&'static str, #[source] BoxError),
    #[error("report is too short: {0}, expected length at least: {1}")]
    Length(usize, usize),
}

// TODO: If we are parsing reports from CSV files, we may also want an owned version of EncryptedReport.

/// A binary report as submitted by a report collector, containing encrypted `OprfReport`
/// An `EncryptedOprfReport` consists of:
///     `ct_mk`: Enc(`match_key`)
///     `ct_btt`: Enc(`breakdown_key`, `trigger_value`, `timestamp`)
///     associated data of `ct_mk`: `key_id`, `epoch`, `event_type`, `site_domain`,
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EncryptedOprfReport<BK, TV, TS, B>
where
    B: Deref<Target = [u8]>,
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
{
    data: B,
    phantom_data: PhantomData<(BK, TV, TS)>,
}

// follows the outline of the implementation of `EncryptedReport`
// Report structure:
//  * 0..a: `encap_key_1`
//  * a..b: `mk_ciphertext`
//  * b..c: `encap_key_2`
//  * c..d: `btt_ciphertext`
//  * d: `event_type`
//  * d+1: `key_id`
//  * d+2..d+4: `epoch`
//  * d+4..: `site_domain`

// btt ciphertext structure
// * 0..a `timestamp`
// * a..b `breakdown`
// * b..c `trigger value`
impl<B, BK, TV, TS> EncryptedOprfReport<BK, TV, TS, B>
where
    B: Deref<Target = [u8]>,
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<<Replicated<TV> as Serializable>::Size>,
    Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>:
        Add<<Replicated<TS> as Serializable>::Size>,
    Sum<
        Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
        <Replicated<TS> as Serializable>::Size,
    >: Add<U16>,
    Sum<
        Sum<
            Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
            <Replicated<TS> as Serializable>::Size,
        >,
        U16,
    >: ArrayLength,
{
    const ENCAP_KEY_MK_OFFSET: usize = 0;
    const CIPHERTEXT_MK_OFFSET: usize = Self::ENCAP_KEY_MK_OFFSET + EncapsulationSize::USIZE;
    const ENCAP_KEY_BTT_OFFSET: usize = (Self::CIPHERTEXT_MK_OFFSET
        + TagSize::USIZE
        + <Replicated<BA64> as Serializable>::Size::USIZE);
    const CIPHERTEXT_BTT_OFFSET: usize = Self::ENCAP_KEY_BTT_OFFSET + EncapsulationSize::USIZE;

    const EVENT_TYPE_OFFSET: usize = (Self::CIPHERTEXT_BTT_OFFSET
        + TagSize::USIZE
        + <Replicated<BK> as Serializable>::Size::USIZE
        + <Replicated<TV> as Serializable>::Size::USIZE
        + <Replicated<TS> as Serializable>::Size::USIZE);
    const KEY_IDENTIFIER_OFFSET: usize = Self::EVENT_TYPE_OFFSET + 1;
    const EPOCH_OFFSET: usize = Self::KEY_IDENTIFIER_OFFSET + 1;
    const SITE_DOMAIN_OFFSET: usize = Self::EPOCH_OFFSET + 2;

    // offsets within Ciphertext_BTT
    const TS_OFFSET: usize = 0;

    const BK_OFFSET: usize = Self::TS_OFFSET + <Replicated<TS> as Serializable>::Size::USIZE;
    const TV_OFFSET: usize = Self::BK_OFFSET + <Replicated<BK> as Serializable>::Size::USIZE;
    const TV_END: usize = Self::TV_OFFSET + <Replicated<TV> as Serializable>::Size::USIZE;

    pub fn encap_key_mk(&self) -> &[u8] {
        &self.data[Self::ENCAP_KEY_MK_OFFSET..Self::CIPHERTEXT_MK_OFFSET]
    }

    pub fn mk_ciphertext(&self) -> &[u8] {
        &self.data[Self::CIPHERTEXT_MK_OFFSET..Self::ENCAP_KEY_BTT_OFFSET]
    }

    pub fn encap_key_btt(&self) -> &[u8] {
        &self.data[Self::ENCAP_KEY_BTT_OFFSET..Self::CIPHERTEXT_BTT_OFFSET]
    }

    pub fn btt_ciphertext(&self) -> &[u8] {
        &self.data[Self::CIPHERTEXT_BTT_OFFSET..Self::EVENT_TYPE_OFFSET]
    }

    /// ## Panics
    /// Only if a `Report` constructor failed to validate the contents properly, which would be a bug.
    pub fn event_type(&self) -> EventType {
        EventType::try_from(self.data[Self::EVENT_TYPE_OFFSET]).unwrap() // validated on construction
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.data[Self::KEY_IDENTIFIER_OFFSET]
    }

    /// ## Panics
    /// Never.
    pub fn epoch(&self) -> Epoch {
        u16::from_le_bytes(
            self.data[Self::EPOCH_OFFSET..Self::SITE_DOMAIN_OFFSET]
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
        if bytes.len() <= Self::SITE_DOMAIN_OFFSET {
            return Err(InvalidReportError::Length(
                bytes.len(),
                Self::SITE_DOMAIN_OFFSET,
            ));
        }
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
    ) -> Result<OprfReport<BK, TV, TS>, InvalidReportError> {
        type CTMKLength = Sum<<Replicated<BA64> as Serializable>::Size, TagSize>;
        type CTBTTLength<BK, TV, TS> = Sum<
            Sum<
                Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
                <Replicated<TS> as Serializable>::Size,
            >,
            TagSize,
        >;

        let info = Info::new(
            self.key_id(),
            self.epoch(),
            self.event_type(),
            HELPER_ORIGIN,
            self.site_domain(),
        )
        .unwrap(); // validated on construction

        let mut ct_mk: GenericArray<u8, CTMKLength> =
            *GenericArray::from_slice(self.mk_ciphertext());
        let plaintext_mk = open_in_place(key_registry, self.encap_key_mk(), &mut ct_mk, &info)?;
        let mut ct_btt: GenericArray<u8, CTBTTLength<BK, TV, TS>> =
            GenericArray::from_slice(self.btt_ciphertext()).clone();
        let plaintext_btt = open_in_place(key_registry, self.encap_key_btt(), &mut ct_btt, &info)?;

        Ok(OprfReport::<BK, TV, TS> {
            timestamp: Replicated::<TS>::deserialize(GenericArray::from_slice(
                &plaintext_btt[Self::TS_OFFSET..Self::BK_OFFSET],
            ))
            .map_err(|e| InvalidReportError::DeserializationError("timestamp", e.into()))?,
            match_key: Replicated::<BA64>::deserialize(GenericArray::from_slice(plaintext_mk))
                .map_err(|e| InvalidReportError::DeserializationError("matchkey", e.into()))?,
            event_type: self.event_type(),
            breakdown_key: Replicated::<BK>::deserialize(GenericArray::from_slice(
                &plaintext_btt[Self::BK_OFFSET..Self::TV_OFFSET],
            ))
            .map_err(|e| InvalidReportError::DeserializationError("is_trigger", e.into()))?,
            trigger_value: Replicated::<TV>::deserialize(GenericArray::from_slice(
                &plaintext_btt[Self::TV_OFFSET..Self::TV_END],
            ))
            .map_err(|e| InvalidReportError::DeserializationError("trigger_value", e.into()))?,
            epoch: self.epoch(),
            site_domain: self.site_domain().to_owned(),
        })
    }
}

impl<BK, TV, TS> TryFrom<Bytes> for EncryptedOprfReport<BK, TV, TS, Bytes>
where
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<<Replicated<TV> as Serializable>::Size>,
    Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>:
        Add<<Replicated<TS> as Serializable>::Size>,
    Sum<
        Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
        <Replicated<TS> as Serializable>::Size,
    >: Add<U16>,
    Sum<
        Sum<
            Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
            <Replicated<TS> as Serializable>::Size,
        >,
        U16,
    >: ArrayLength,
{
    type Error = InvalidReportError;

    fn try_from(bytes: Bytes) -> Result<Self, InvalidReportError> {
        EncryptedOprfReport::from_bytes(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OprfReport<BK, TV, TS>
where
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
{
    pub match_key: Replicated<BA64>,
    pub event_type: EventType,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
    pub epoch: Epoch,
    pub site_domain: String,
}

impl<BK, TV, TS> OprfReport<BK, TV, TS>
where
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<<Replicated<TV> as Serializable>::Size>,
    Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>:
        Add<<Replicated<TS> as Serializable>::Size>,
    Sum<
        Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
        <Replicated<TS> as Serializable>::Size,
    >: Add<U16>,
    Sum<
        Sum<
            Sum<<Replicated<BK> as Serializable>::Size, <Replicated<TV> as Serializable>::Size>,
            <Replicated<TS> as Serializable>::Size,
        >,
        U16,
    >: ArrayLength,
{
    // offsets for BTT Ciphertext
    const TS_OFFSET: usize = 0;
    const BK_OFFSET: usize = Self::TS_OFFSET + <Replicated<TS> as Serializable>::Size::USIZE;
    const TV_OFFSET: usize = Self::BK_OFFSET + <Replicated<BK> as Serializable>::Size::USIZE;
    const BTT_END: usize = Self::TV_OFFSET + <Replicated<TV> as Serializable>::Size::USIZE;

    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn encrypted_len(&self) -> u16 {
        let len = EncryptedOprfReport::<BK, TV, TS, &[u8]>::SITE_DOMAIN_OFFSET
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
        let mut out = Vec::with_capacity(usize::from(self.encrypted_len()));
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

        let mut plaintext_mk = GenericArray::default();
        self.match_key.serialize(&mut plaintext_mk);

        let mut plaintext_btt = vec![0u8; Self::BTT_END];
        self.timestamp.serialize(GenericArray::from_mut_slice(
            &mut plaintext_btt[Self::TS_OFFSET..Self::BK_OFFSET],
        ));
        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut plaintext_btt[Self::BK_OFFSET..Self::TV_OFFSET],
        ));
        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut plaintext_btt[Self::TV_OFFSET
                ..(Self::TV_OFFSET + <Replicated<TV> as Serializable>::Size::USIZE)],
        ));

        let (encap_key_mk, ciphertext_mk, tag_mk) =
            seal_in_place(key_registry, plaintext_mk.as_mut(), &info, rng)?;

        let (encap_key_btt, ciphertext_btt, tag_btt) =
            seal_in_place(key_registry, plaintext_btt.as_mut(), &info, rng)?;

        out.put_slice(&encap_key_mk.to_bytes());
        out.put_slice(ciphertext_mk);
        out.put_slice(&tag_mk.to_bytes());
        out.put_slice(&encap_key_btt.to_bytes());
        out.put_slice(ciphertext_btt);
        out.put_slice(&tag_btt.to_bytes());
        out.put_slice(&[u8::from(&self.event_type)]);
        out.put_slice(&[key_id]);
        out.put_slice(&self.epoch.to_le_bytes());
        out.put_slice(self.site_domain.as_bytes());

        Ok(())
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use super::*;
    use crate::{
        ff::boolean_array::{BA20, BA3, BA8},
        report,
        report::EventType::{Source, Trigger},
        secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
    };

    #[test]
    fn enc_dec_roundtrip_oprf() {
        let mut rng = thread_rng();

        let b: EventType = if rng.gen::<bool>() { Trigger } else { Source };

        let report = OprfReport::<BA8, BA3, BA20> {
            match_key: AdditiveShare::new(rng.gen(), rng.gen()),
            timestamp: AdditiveShare::new(rng.gen(), rng.gen()),
            breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
            trigger_value: AdditiveShare::new(rng.gen(), rng.gen()),
            event_type: b,
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
        let enc_report = EncryptedOprfReport::from_bytes(enc_report_bytes.as_slice()).unwrap();
        let dec_report: OprfReport<BA8, BA3, BA20> = enc_report.decrypt(&key_registry).unwrap();

        assert_eq!(dec_report, report);
    }

    #[test]
    fn test_decryption_fails() {
        let mut rng = thread_rng();

        let b: EventType = if rng.gen::<bool>() { Trigger } else { Source };

        let report = OprfReport::<BA8, BA3, BA20> {
            match_key: AdditiveShare::new(rng.gen(), rng.gen()),
            timestamp: AdditiveShare::new(rng.gen(), rng.gen()),
            breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
            trigger_value: AdditiveShare::new(rng.gen(), rng.gen()),
            event_type: b,
            epoch: rng.gen(),
            site_domain: (&mut rng)
                .sample_iter(Alphanumeric)
                .map(char::from)
                .take(10)
                .collect(),
        };

        let enc_key_registry = KeyRegistry::random(1, &mut rng);
        let enc_key_id = 0;
        let dec_key_registry = KeyRegistry::random(1, &mut rng);

        let enc_report_bytes = report
            .encrypt(enc_key_id, &enc_key_registry, &mut rng)
            .unwrap();
        let enc_report: report::EncryptedOprfReport<BA8, BA3, BA20, &[u8]> =
            EncryptedOprfReport::from_bytes(enc_report_bytes.as_slice()).unwrap();
        let dec_report = enc_report.decrypt(&dec_key_registry);

        assert!(dec_report.is_err());
    }

    #[test]
    fn invalid_event_type() {
        let bytes = hex::decode(
            "2879655662559e44389efb0cb27675b0571f878623411364c525f8201f94\
            c449df144ed7087b5d628615028b55483a0f675494c4ab0f8ba92625921cf71406\
            2055ab3d676cada0505745e9f8c25a269da20c81019a4db50212090073067b9400\
            28672642880bdc9a4b8eafc9f0a8a0a350f66447aaab563c8a5603007d06626232\
            497732584d5447",
        )
        .unwrap();

        let err = EncryptedOprfReport::<BA8, BA3, BA20, _>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::BadEventType(_)));
    }

    #[test]
    fn invalid_site_domain() {
        let bytes = hex::decode(
            "2879655662559e44389efb0cb27675b0571f878623411364c525f8201f94\
            c449df144ed7087b5d628615028b55483a0f675494c4ab0f8ba92625921cf71406\
            2055ab3d676cada0505745e9f8c25a269da20c81019a4db50212090073067b9400\
            28672642880bdc9a4b8eafc9f0a8a0a350f66447aaab563c8a5601007d06626232\
            497732584d54ff",
        )
        .unwrap();

        let err = EncryptedOprfReport::<BA8, BA3, BA20, _>::from_bytes(bytes.as_slice())
            .err()
            .unwrap();
        assert!(matches!(err, InvalidReportError::NonAsciiString(_)));
    }
}
