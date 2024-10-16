//! Provides report types which are aggregated by the IPA protocol
//!
//! The `OprfReport` is the primary data type which each helpers use to aggreate in the IPA
//! protocol.
//! From each Helper's POV, the Report Collector POSTs a length delimited byte
//! stream, which is then processed as follows:
//!
//! `BodyStream` → `EncryptedOprfReport` → `OprfReport`
//!
//! From the Report Collectors's POV, there are two potential paths:
//! 1. In production, encrypted events are recieved from clients and accumulated out of band
//!    as 3 files of newline delimited hex encoded enrypted events.
//! 2. For testing, simluated plaintext events are provided as a CSV.
//!
//! Path 1 is proccssed as follows:
//!
//! `files: [PathBuf; 3]` → `EncryptedOprfReportsFiles` → `helpers::BodyStream`
//!
//! Path 2 is processed as follows:
//!
//! `cli::playbook::InputSource` (`PathBuf` or `stdin()`) →
//! `test_fixture::ipa::TestRawDataRecord` → `OprfReport` → encrypted bytes
//! (via `Oprf.delmited_encrypt_to`) → `helpers::BodyStream`

use std::{
    fmt::{Display, Formatter},
    fs::File,
    io::{BufRead, BufReader},
    marker::PhantomData,
    ops::{Add, Deref},
    path::PathBuf,
};

use bytes::{BufMut, Bytes};
use generic_array::{ArrayLength, GenericArray};
use hpke::Serializable as _;
use rand_core::{CryptoRng, RngCore};
use typenum::{Sum, Unsigned, U1, U16};

use crate::{
    error::BoxError,
    ff::{boolean_array::BA64, Serializable},
    helpers::BodyStream,
    hpke::{
        open_in_place, seal_in_place, CryptError, EncapsulationSize, Info, PrivateKeyRegistry,
        PublicKeyRegistry, TagSize,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
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

/// A struct intended for the Report Collector to hold the streams of underlying
/// `EncryptedOprfReports` represented as length delmited bytes. Helpers receive an
/// individual stream, which are unpacked into `EncryptedOprfReports` and decrypted
/// into `OprfReports`.
pub struct EncryptedOprfReportStreams {
    pub streams: [BodyStream; 3],
    pub query_size: usize,
}

/// A trait to build an `EncryptedOprfReportStreams` struct from 3 files of
///  `EncryptedOprfReports` formated at newline delimited hex.
impl From<[&PathBuf; 3]> for EncryptedOprfReportStreams {
    fn from(files: [&PathBuf; 3]) -> Self {
        let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());
        let mut query_sizes: [usize; 3] = [0, 0, 0];
        for (i, path) in files.iter().enumerate() {
            let file =
                File::open(path).unwrap_or_else(|e| panic!("unable to open file {path:?}. {e}"));
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let encrypted_report_bytes = hex::decode(
                    line.expect("Unable to read line. {file:?} is likely corrupt")
                        .trim(),
                )
                .expect("Unable to read line. {file:?} is likely corrupt");
                buffers[i].put_u16_le(
                    encrypted_report_bytes
                        .len()
                        .try_into()
                        .expect("Unable to read line. {file:?} is likely corrupt"),
                );
                buffers[i].put_slice(encrypted_report_bytes.as_slice());
                query_sizes[i] += 1;
            }
        }
        // Panic if input sizes are not the same
        // Panic instead of returning an Error as this is non-recoverable
        assert_eq!(query_sizes[0], query_sizes[1]);
        assert_eq!(query_sizes[1], query_sizes[2]);

        Self {
            streams: buffers.map(BodyStream::from),
            // without loss of generality, set query length to length of first input size
            query_size: query_sizes[0],
        }
    }
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
    pub fn decrypt<P: PrivateKeyRegistry>(
        &self,
        key_registry: &P,
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
        let plaintext_mk = open_in_place(
            key_registry,
            self.encap_key_mk(),
            &mut ct_mk,
            self.key_id(),
            &info.to_bytes(),
        )?;
        let mut ct_btt: GenericArray<u8, CTBTTLength<BK, TV, TS>> =
            GenericArray::from_slice(self.btt_ciphertext()).clone();

        let plaintext_btt = open_in_place(
            key_registry,
            self.encap_key_btt(),
            &mut ct_btt,
            self.key_id(),
            &info.to_bytes(),
        )?;

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

        let (encap_key_mk, ciphertext_mk, tag_mk) = seal_in_place(
            key_registry,
            plaintext_mk.as_mut(),
            key_id,
            &info.to_bytes(),
            rng,
        )?;

        let (encap_key_btt, ciphertext_btt, tag_btt) = seal_in_place(
            key_registry,
            plaintext_btt.as_mut(),
            key_id,
            &info.to_bytes(),
            rng,
        )?;

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
        hpke::{Deserializable, IpaPrivateKey, IpaPublicKey, KeyPair, KeyRegistry},
        report,
        report::EventType::{Source, Trigger},
        secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        test_fixture::Reconstruct,
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

        let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
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

        let enc_key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
        let enc_key_id = 0;
        let dec_key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);

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

    struct RawReport {
        event_type: EventType,
        epoch: u16,
        site_domain: String,
        matchkey: u128,
        trigger_value: u128,
        breakdown_key: u128,
        timestamp: u128,
    }

    fn decrypt_report(
        pk: &[u8],
        sk: &[u8],
        encrypted_report_bytes: &[u8],
        expected: &RawReport,
    ) -> OprfReport<BA8, BA3, BA20> {
        let key_registry1 = KeyRegistry::<KeyPair>::from_keys([KeyPair::from((
            IpaPrivateKey::from_bytes(sk).unwrap(),
            IpaPublicKey::from_bytes(pk).unwrap(),
        ))]);

        let enc_report = EncryptedOprfReport::from_bytes(encrypted_report_bytes).unwrap();
        let dec_report: OprfReport<BA8, BA3, BA20> = enc_report.decrypt(&key_registry1).unwrap();

        assert_eq!(dec_report.event_type, expected.event_type);
        assert_eq!(dec_report.epoch, expected.epoch);
        assert_eq!(dec_report.site_domain, expected.site_domain);

        dec_report
    }

    fn validate_blobs(
        enc_report_bytes1: &[u8],
        enc_report_bytes2: &[u8],
        enc_report_bytes3: &[u8],
        expected: &RawReport,
    ) {
        let pk = [
            hex::decode("92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a")
                .unwrap(),
            hex::decode("cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e")
                .unwrap(),
            hex::decode("b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e")
                .unwrap(),
        ];
        let sk = [
            hex::decode("53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff")
                .unwrap(),
            hex::decode("3a0a993a3cfc7e8d381addac586f37de50c2a14b1a6356d71e94ca2afaeb2569")
                .unwrap(),
            hex::decode("1fb5c5274bf85fbe6c7935684ef05499f6cfb89ac21640c28330135cc0e8a0f7")
                .unwrap(),
        ];

        let dec_report1: OprfReport<BA8, BA3, BA20> = decrypt_report(
            pk[0].as_slice(),
            sk[0].as_slice(),
            enc_report_bytes1,
            expected,
        );

        let dec_report2: OprfReport<BA8, BA3, BA20> = decrypt_report(
            pk[1].as_slice(),
            sk[1].as_slice(),
            enc_report_bytes2,
            expected,
        );

        let dec_report3: OprfReport<BA8, BA3, BA20> = decrypt_report(
            pk[2].as_slice(),
            sk[2].as_slice(),
            enc_report_bytes3,
            expected,
        );

        assert_eq!(
            [
                dec_report1.match_key,
                dec_report2.match_key,
                dec_report3.match_key
            ]
            .reconstruct(),
            expected.matchkey
        );
        assert_eq!(
            [
                dec_report1.breakdown_key,
                dec_report2.breakdown_key,
                dec_report3.breakdown_key
            ]
            .reconstruct(),
            expected.breakdown_key
        );
        assert_eq!(
            [
                dec_report1.trigger_value,
                dec_report2.trigger_value,
                dec_report3.trigger_value
            ]
            .reconstruct(),
            expected.trigger_value
        );
        assert_eq!(
            [
                dec_report1.timestamp,
                dec_report2.timestamp,
                dec_report3.timestamp
            ]
            .reconstruct(),
            expected.timestamp
        );
    }

    #[test]
    fn check_compatibility_impressionmk_with_ios_encryption() {
        let enc_report_bytes1 = hex::decode(
            "12854879d86ef277cd70806a7f6bad269877adc95ee107380381caf15b841a7e995e41\
        4c63a9d82f834796cdd6c40529189fca82720714d24200d8a916a1e090b123f27eaf24\
        f047f3930a77e5bcd33eeb823b73b0e9546c59d3d6e69383c74ae72b79645698fe1422\
        f83886bd3cbca9fbb63f7019e2139191dd000000007777772e6d6574612e636f6d",
        )
        .unwrap();
        let enc_report_bytes2 = hex::decode(
            "1d85741b3edf3f49e8ed5824b8ea0ed156301fb6d450fc30ad76785fc3b281775\
            937d0275efc237d3e3ac92e22cf60ebd8dc09a41abaa20c0a7ee9e5e1c736708c0\
            1dd65f592e5683f8ca0e23f8bfcd3a7736335cc5bec95beceb6474abb816b01f9a\
            df7cc12c344c1538bb84c98b089b24733790032e70c7406000000007777772e6d6\
            574612e636f6d",
        )
        .unwrap();
        let enc_report_bytes3 = hex::decode(
            "545f9df229a16c70497dd1f93ac75bef8ad33e836bb20f2ff37297bd814a09138\
            9d85db9007e7b95231a3e5a0055ae59dc56d431849c0aaf5e01e66c8e6b7888bf2\
            99f66907861798097aba96aae193d59b7fcafd5655e745f4b4ae51631c6342e36e\
            e3b6f1682385b46295b7ce0128af02f6828cba562bf0c12000000007777772e6d6\
            574612e636f6d",
        )
        .unwrap();

        assert_eq!(enc_report_bytes1.len(), 138);
        assert_eq!(enc_report_bytes2.len(), 138);
        assert_eq!(enc_report_bytes3.len(), 138);

        let expected = RawReport {
            event_type: EventType::Source,
            epoch: 0,
            site_domain: String::from("www.meta.com"),
            matchkey: 1,
            trigger_value: 0,
            breakdown_key: 45,
            timestamp: 456,
        };

        validate_blobs(
            &enc_report_bytes1,
            &enc_report_bytes2,
            &enc_report_bytes3,
            &expected,
        );
    }

    #[test]
    fn check_compatibility_conversion_with_ios_encryption() {
        let enc_report_bytes1 = hex::decode(
            "741cd5012df1cf8f337258066a55c408d1052297af27a35bdef571773215ad7cb\
            d367eab689145a24ad9666a12731a221ff5548cc7591a5ce50da4dcde203cc6141\
            75759ef230641adac977187143471b512f1c8fd95eafeb53602d90a69a6411f3af\
            9cb44e02417f6f27b7162f08bff009e82b1c2c2aaaf156f010000007777772e616\
            2632e636f6d",
        )
        .unwrap();

        let enc_report_bytes2 = hex::decode(
            "effd53a97a3df4020d717409a9905210510932d894aa70430d324f2048e0b768e7f696\
        60861ff5e73c64d71547c2245f0120957b51925bb9dfbda319ec04b79139467438e647\
        f2b384995af9c66eab0a7943c9ee7a4238c08f5aa52ca460936a89b7ea07a171ff6e3c\
        247ae1d30a43be78b46db7f638050a8fcf010000007777772e6162632e636f6d",
        )
        .unwrap();

        let enc_report_bytes3 = hex::decode(
            "e708bd1d032ea399964e2f1e2dfe3145203cfc079f519f00e8e789db412f297c9d02e0\
        0cc38c3dd3d3cff2771d3811c70b1f37b334402216ca664f224e34900c641edb48469b\
        cf1f09f34fd2a7775d886e5a770e6c6d2089595c87300c87962c3481aec4b4bc1f3f4f\
        3944c3143e590e1e2c87d2cbd91eabe6be010000007777772e6162632e636f6d",
        )
        .unwrap();

        assert_eq!(enc_report_bytes1.len(), 137);
        assert_eq!(enc_report_bytes2.len(), 137);
        assert_eq!(enc_report_bytes3.len(), 137);

        let expected = RawReport {
            event_type: EventType::Trigger,
            epoch: 0,
            site_domain: String::from("www.abc.com"),
            matchkey: 1,
            trigger_value: 5,
            breakdown_key: 0,
            timestamp: 123,
        };

        validate_blobs(
            &enc_report_bytes1,
            &enc_report_bytes2,
            &enc_report_bytes3,
            &expected,
        );
    }
}
