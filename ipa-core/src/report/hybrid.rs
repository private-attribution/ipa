//! Provides report types which are aggregated by the Hybrid protocol
//!
//! The `IndistinguishableHybridReport` is the primary data type which each helpers uses
//! to aggreate in the Hybrid protocol.
//!
//! From each Helper's POV, the Report Collector POSTs a length delimited byte
//! stream, which is then processed as follows:
//!
//! `BodyStream` → `EncryptedHybridReport` → `HybridReport` → `IndistinguishableHybridReport`
//!
//! The difference between a `HybridReport` and a `IndistinguishableHybridReport` is that a
//! a `HybridReport` is an `enum` with two possible options: `Impression` and `Conversion`.
//! These two options are implemented as `HybridImpressionReport` and `HybridConversionReport`.
//! A `IndistinguishableHybridReport` contains the union of the fields across
//! `HybridImpressionReport` and `HybridConversionReport`. Those fields are secret sharings,
//! which allows for building a collection of `IndistinguishableHybridReport` which carry
//! the information of the underlying `HybridImpressionReport` and `HybridConversionReport`
//! (and secret sharings of zero in the fields unique to each report type) without the
//! ability to infer if a given report is a `HybridImpressionReport`
//! or a `HybridConversionReport`.

//! Note: immediately following convertion of a `HybridReport` into a
//! `IndistinguishableHybridReport`, each helper will know which type it was built from,
//! both from the position in the collection as well as the fact that both replicated
//! secret shares for one or more fields are zero. A shuffle is required to delink
//! a `IndistinguishableHybridReport`'s position in a collection, which also rerandomizes
//! all secret sharings (including the sharings of zero), making the collection of reports
//! cryptographically indistinguishable.

use std::{collections::HashSet, convert::Infallible, marker::PhantomData, ops::Add};

use bytes::{Buf, BufMut, Bytes};
use generic_array::{ArrayLength, GenericArray};
use hpke::Serializable as _;
use rand_core::{CryptoRng, RngCore};
use typenum::{Sum, Unsigned, U12, U16};

use crate::{
    const_assert_eq,
    error::{BoxError, Error},
    ff::{
        boolean_array::{
            BooleanArray, BooleanArrayReader, BooleanArrayWriter, BA112, BA3, BA32, BA64, BA8,
        },
        Serializable,
    },
    hpke::{
        open_in_place, seal_in_place, CryptError, EncapsulationSize, PrivateKeyRegistry,
        PublicKeyRegistry, TagSize,
    },
    protocol::ipa_prf::{boolean_ops::expand_shared_array_in_place, shuffle::Shuffleable},
    report::hybrid_info::{HybridConversionInfo, HybridImpressionInfo},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        SharedValue,
    },
    sharding::ShardIndex,
};

// TODO(679): This needs to come from configuration.
#[allow(dead_code)]
static HELPER_ORIGIN: &str = "github.com/private-attribution";

pub type KeyIdentifier = u8;
pub const DEFAULT_KEY_ID: KeyIdentifier = 0;

#[derive(Debug, thiserror::Error)]
#[error("string contains non-ascii symbols: {0}")]
pub struct NonAsciiStringError(String);

impl From<&'_ str> for NonAsciiStringError {
    fn from(input: &str) -> Self {
        Self(input.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHybridReportError {
    #[error("bad site_domain: {0}")]
    NonAsciiString(#[from] NonAsciiStringError),
    #[error("en/decryption failure: {0}")]
    Crypt(#[from] CryptError),
    #[error("failed to deserialize field {0}: {1}")]
    DeserializationError(&'static str, #[source] BoxError),
    #[error("report is too short: {0}, expected length at least: {1}")]
    Length(usize, usize),
    #[error("unknown event type: {0}. Only 0 and 1 are allowed")]
    UnknownEventType(u8),
    #[error("Incorrect hybrid info type: Expected {0}")]
    WrongInfoType(&'static str),
}

/// Event type as described [`ipa-issue`]
/// Initially we will just support trigger vs source event types but could extend to others in
/// the future.
///
/// ['ipa-issue']: https://github.com/patcg-individual-drafts/ipa/issues/38
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HybridEventType {
    Impression,
    Conversion,
}

impl TryFrom<u8> for HybridEventType {
    type Error = InvalidHybridReportError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Impression),
            1 => Ok(Self::Conversion),
            _ => Err(InvalidHybridReportError::UnknownEventType(value)),
        }
    }
}

/// Reports for impression events are represented here.
#[derive(Clone, Debug, PartialEq)]
pub struct HybridImpressionReport<BK>
where
    BK: SharedValue,
{
    pub match_key: Replicated<BA64>,
    pub breakdown_key: Replicated<BK>,
    pub info: HybridImpressionInfo,
}

impl<BK> HybridImpressionReport<BK>
where
    BK: SharedValue,
    Replicated<BK>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
{
    pub fn serialize<B: BufMut>(&self, buf: &mut B) {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        let mut plaintext_mk = vec![0u8; mk_sz];
        self.match_key.serialize(GenericArray::from_mut_slice(&mut plaintext_mk));
        let mut plaintext_bk = vec![0u8; bk_sz];
        self.breakdown_key.serialize(GenericArray::from_mut_slice(&mut plaintext_bk));

        buf.put_slice(&plaintext_mk);
        buf.put_slice(&plaintext_bk);
        buf.put_slice(&self.info.to_bytes());
    }

    /// # Errors
    /// If there is a problem deserializing the report.
    pub fn deserialize(buf: &Bytes) -> Result<Self, InvalidHybridReportError> {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let match_key =
            Replicated::<BA64>::deserialize_infallible(GenericArray::from_slice(&buf[..mk_sz]));
        let breakdown_key =
            Replicated::<BK>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + bk_sz]))
            .map_err(|e| InvalidHybridReportError::DeserializationError("breakdown_key", e.into()))?;
        let info = HybridImpressionInfo::from_bytes(&buf[mk_sz + bk_sz..])?;

        Ok(Self { match_key, breakdown_key, info })
    }

    #[must_use]
    pub fn serialized_len() -> usize {
        Replicated::<BK>::size() + Replicated::<BA64>::size()
    }
}

impl<BK> HybridImpressionReport<BK>
where
    BK: SharedValue,
    Replicated<BK>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
{
    const BTT_END: usize = <Replicated<BK> as Serializable>::Size::USIZE;

    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn ciphertext_len(&self) -> u16 {
        let len = EncryptedHybridImpressionReport::<BK>::INFO_OFFSET;
        len.try_into().unwrap()
    }

    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn encrypted_len(&self) -> u16 {
        // Todo: get this more efficiently
        self.ciphertext_len() + u16::try_from(self.info.to_bytes().len()).unwrap()
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn delimited_encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidHybridReportError> {
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
    ) -> Result<Vec<u8>, InvalidHybridReportError> {
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
    ) -> Result<(), InvalidHybridReportError> {
        let mut plaintext_mk = GenericArray::default();
        self.match_key.serialize(&mut plaintext_mk);

        let mut plaintext_btt = vec![0u8; Self::BTT_END];
        self.breakdown_key
            .serialize(GenericArray::from_mut_slice(&mut plaintext_btt[..]));

        let pk = key_registry.public_key(key_id).ok_or(CryptError::NoSuchKey(key_id))?;
        let info_bytes = self.info.to_bytes();

        let (encap_key_mk, ciphertext_mk, tag_mk) = seal_in_place(
            pk,
            plaintext_mk.as_mut(),
            &info_bytes,
            rng,
        )?;

        let (encap_key_btt, ciphertext_btt, tag_btt) = seal_in_place(
            pk,
            plaintext_btt.as_mut(),
            &info_bytes,
            rng,
        )?;

        out.put_slice(&encap_key_mk.to_bytes());
        out.put_slice(ciphertext_mk);
        out.put_slice(&tag_mk.to_bytes());
        out.put_slice(&encap_key_btt.to_bytes());
        out.put_slice(ciphertext_btt);
        out.put_slice(&tag_btt.to_bytes());
        out.put_slice(&[key_id]);
        out.put_slice(&info_bytes);

        Ok(())
    }
}

/// Reports for conversion events are represented here.
#[derive(Clone, Debug, PartialEq)]
pub struct HybridConversionReport<V>
where
    V: SharedValue,
{
    pub match_key: Replicated<BA64>,
    pub value: Replicated<V>,
    pub info: HybridConversionInfo,
}

impl<V> HybridConversionReport<V>
where
    V: SharedValue,
    Replicated<V>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
{
    pub fn serialize<B: BufMut>(&self, buf: &mut B) {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let v_sz = <Replicated<V> as Serializable>::Size::USIZE;

        let mut plaintext_mk = vec![0u8; mk_sz];
        self.match_key.serialize(GenericArray::from_mut_slice(&mut plaintext_mk));
        let mut plaintext_v = vec![0u8; v_sz];
        self.value.serialize(GenericArray::from_mut_slice(&mut plaintext_v));

        buf.put_slice(&plaintext_mk);
        buf.put_slice(&plaintext_v);
        buf.put_slice(&self.info.to_bytes());
    }

    /// # Errors
    /// If there is a problem deserializing the report.
    pub fn deserialize(buf: &Bytes) -> Result<Self, InvalidHybridReportError> {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let v_sz = <Replicated<V> as Serializable>::Size::USIZE;
        let match_key =
            Replicated::<BA64>::deserialize_infallible(GenericArray::from_slice(&buf[..mk_sz]));
        let value =
            Replicated::<V>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + v_sz]))
            .map_err(|e| InvalidHybridReportError::DeserializationError("breakdown_key", e.into()))?;
        let info = HybridConversionInfo::from_bytes(&buf[mk_sz + v_sz..])?;
        Ok(Self { match_key, value, info })
    }

    #[must_use]
    pub fn serialized_len() -> usize {
        Replicated::<V>::size() + Replicated::<BA64>::size()
    }
}

impl<V> HybridConversionReport<V>
where
    V: SharedValue,
    Replicated<V>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
{
    const BTT_END: usize = <Replicated<V> as Serializable>::Size::USIZE;

    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn ciphertext_len(&self) -> u16 {
        let len = EncryptedHybridConversionReport::<V>::INFO_OFFSET;
        len.try_into().unwrap()
    }

    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn encrypted_len(&self) -> u16 {
        // Todo: get this more efficiently
        self.ciphertext_len() + u16::try_from(self.info.to_bytes().len()).unwrap()
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn delimited_encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidHybridReportError> {
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
    ) -> Result<Vec<u8>, InvalidHybridReportError> {
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
    ) -> Result<(), InvalidHybridReportError> {

        let mut plaintext_mk = GenericArray::default();
        self.match_key.serialize(&mut plaintext_mk);

        let mut plaintext_btt = vec![0u8; Self::BTT_END];
        self.value
            .serialize(GenericArray::from_mut_slice(&mut plaintext_btt[..]));

        let pk = key_registry.public_key(key_id).ok_or(CryptError::NoSuchKey(key_id))?;
        let info_bytes = self.info.to_bytes();

        let (encap_key_mk, ciphertext_mk, tag_mk) = seal_in_place(
            pk,
            plaintext_mk.as_mut(),
            &info_bytes,
            rng,
        )?;

        let (encap_key_btt, ciphertext_btt, tag_btt) = seal_in_place(
            pk,
            plaintext_btt.as_mut(),
            &info_bytes,
            rng,
        )?;

        out.put_slice(&encap_key_mk.to_bytes());
        out.put_slice(ciphertext_mk);
        out.put_slice(&tag_mk.to_bytes());
        out.put_slice(&encap_key_btt.to_bytes());
        out.put_slice(ciphertext_btt);
        out.put_slice(&tag_btt.to_bytes());
        out.put_slice(&[key_id]); //todo: this is also in the info
        out.put_slice(&info_bytes);

        Ok(())
    }
}

/// This enum contains both report types, impression and conversion.
#[derive(Clone, Debug, PartialEq)]
pub enum HybridReport<BK, V>
where
    BK: SharedValue,
    V: SharedValue,
{
    Impression(HybridImpressionReport<BK>),
    Conversion(HybridConversionReport<V>),
}

impl<BK, V> HybridReport<BK, V>
where
    BK: SharedValue,
    V: SharedValue,
    Replicated<BK>: Serializable,
    Replicated<V>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
    <<Replicated<V> as Serializable>::Size as Add<<Replicated<BA64> as Serializable>::Size>>:: Output: ArrayLength,
{
    /// # Panics
    /// If report length does not fit in `u16`.
    pub fn encrypted_len(&self) -> u16 {
        match self {
            HybridReport::Impression(impression_report) => {
                impression_report.encrypted_len() +1
            }
            HybridReport::Conversion(conversion_report) => {
                conversion_report.encrypted_len() +1
            }
        }
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn delimited_encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidHybridReportError> {
        match self {
            HybridReport::Impression(impression_report) => {
                out.put_u16_le(self.encrypted_len());
                out.put_u8(HybridEventType::Impression as u8);
                impression_report.encrypt_to(key_id, key_registry, rng, out)
            },
            HybridReport::Conversion(conversion_report) => {
                out.put_u16_le(self.encrypted_len());
                out.put_u8(HybridEventType::Conversion as u8);
                conversion_report.encrypt_to(key_id, key_registry, rng, out)
            },
        }
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
    ) -> Result<Vec<u8>, InvalidHybridReportError> {
        let mut buf = Vec::new();
        self.encrypt_to(key_id, key_registry, rng, &mut buf)?;
        Ok(buf)
    }

    /// # Errors
    /// If there is a problem encrypting the report.
    pub fn encrypt_to<R: CryptoRng + RngCore, B: BufMut>(
        &self,
        key_id: KeyIdentifier,
        key_registry: &impl PublicKeyRegistry,
        rng: &mut R,
        out: &mut B,
    ) -> Result<(), InvalidHybridReportError> {
        match self {
            HybridReport::Impression(impression_report) =>{
                    out.put_u8(HybridEventType::Impression as u8);
                    impression_report.encrypt_to(key_id, key_registry, rng, out)
            },
            HybridReport::Conversion(conversion_report) => {
                    out.put_u8(HybridEventType::Conversion as u8);
                    conversion_report.encrypt_to(key_id, key_registry, rng, out)
            },
        }
    }
}

/// `HybridImpressionReport`s are encrypted when they arrive to the helpers,
/// which is represented here. A `EncryptedHybridImpressionReport` decrypts
/// into a `HybridImpressionReport`.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedHybridImpressionReport<BK>
where
    BK: SharedValue,
{
    data: Bytes,
    phantom_data: PhantomData<BK>,
}

impl<BK> EncryptedHybridImpressionReport<BK>
where
    BK: SharedValue,
    Replicated<BK>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
{
    const ENCAP_KEY_MK_OFFSET: usize = 0;
    const CIPHERTEXT_MK_OFFSET: usize = Self::ENCAP_KEY_MK_OFFSET + EncapsulationSize::USIZE;
    const ENCAP_KEY_BTT_OFFSET: usize =
        (Self::CIPHERTEXT_MK_OFFSET + TagSize::USIZE + Replicated::<BA64>::size());
    const CIPHERTEXT_BTT_OFFSET: usize = Self::ENCAP_KEY_BTT_OFFSET + EncapsulationSize::USIZE;

    const KEY_IDENTIFIER_OFFSET: usize =
        (Self::CIPHERTEXT_BTT_OFFSET + TagSize::USIZE + Replicated::<BK>::size());
    const INFO_OFFSET: usize = Self::KEY_IDENTIFIER_OFFSET + 1;

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
        &self.data[Self::CIPHERTEXT_BTT_OFFSET..Self::KEY_IDENTIFIER_OFFSET]
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.data[Self::KEY_IDENTIFIER_OFFSET]
    }

    /// ## Errors
    /// If the report contents are invalid.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, InvalidHybridReportError> {
        if bytes.len() < Self::INFO_OFFSET {
            return Err(InvalidHybridReportError::Length(
                bytes.len(),
                Self::INFO_OFFSET,
            ));
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
    ) -> Result<HybridImpressionReport<BK>, InvalidHybridReportError> {
        type CTMKLength = Sum<<Replicated<BA64> as Serializable>::Size, TagSize>;
        type CTBTTLength<BK> = <<Replicated<BK> as Serializable>::Size as Add<TagSize>>::Output;

        let mut ct_mk: GenericArray<u8, CTMKLength> =
            *GenericArray::from_slice(self.mk_ciphertext());
        let sk = key_registry
            .private_key(self.key_id())
            .ok_or(CryptError::NoSuchKey(self.key_id()))?;
        let info =
            HybridImpressionInfo::from_bytes(&self.data[Self::INFO_OFFSET..]).map_err(|e| {
                InvalidHybridReportError::DeserializationError("HybridImpressionInfo", e.into())
            })?;
        let plaintext_mk = open_in_place(sk, self.encap_key_mk(), &mut ct_mk, &info.to_bytes())?;
        let mut ct_btt: GenericArray<u8, CTBTTLength<BK>> =
            GenericArray::from_slice(self.btt_ciphertext()).clone();

        let plaintext_btt = open_in_place(sk, self.encap_key_btt(), &mut ct_btt, &info.to_bytes())?;

        Ok(HybridImpressionReport::<BK> {
            match_key: Replicated::<BA64>::deserialize_infallible(GenericArray::from_slice(
                plaintext_mk,
            )),
            breakdown_key: Replicated::<BK>::deserialize(GenericArray::from_slice(plaintext_btt))
                .map_err(|e| {
                InvalidHybridReportError::DeserializationError("is_trigger", e.into())
            })?,
            info,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedHybridConversionReport<V>
where
    V: SharedValue,
{
    data: Bytes,
    phantom_data: PhantomData<V>,
}

impl<V> EncryptedHybridConversionReport<V>
where
    V: SharedValue,
    Replicated<V>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
{
    const ENCAP_KEY_MK_OFFSET: usize = 0;
    const CIPHERTEXT_MK_OFFSET: usize = Self::ENCAP_KEY_MK_OFFSET + EncapsulationSize::USIZE;
    const ENCAP_KEY_BTT_OFFSET: usize =
        (Self::CIPHERTEXT_MK_OFFSET + TagSize::USIZE + Replicated::<BA64>::size());
    const CIPHERTEXT_BTT_OFFSET: usize = Self::ENCAP_KEY_BTT_OFFSET + EncapsulationSize::USIZE;

    const KEY_IDENTIFIER_OFFSET: usize =
        (Self::CIPHERTEXT_BTT_OFFSET + TagSize::USIZE + Replicated::<V>::size());
    // Todo: determine a minimum size for Info which can be used for debugging
    const INFO_OFFSET: usize = Self::KEY_IDENTIFIER_OFFSET + 1;

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
        &self.data[Self::CIPHERTEXT_BTT_OFFSET..Self::KEY_IDENTIFIER_OFFSET]
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.data[Self::KEY_IDENTIFIER_OFFSET]
    }

    /// ## Errors
    /// If the report contents are invalid.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, InvalidHybridReportError> {
        if bytes.len() < Self::INFO_OFFSET {
            return Err(InvalidHybridReportError::Length(
                bytes.len(),
                Self::INFO_OFFSET,
            ));
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
    ) -> Result<HybridConversionReport<V>, InvalidHybridReportError> {
        type CTMKLength = Sum<<Replicated<BA64> as Serializable>::Size, TagSize>;
        type CTBTTLength<V> = <<Replicated<V> as Serializable>::Size as Add<TagSize>>::Output;

        let mut ct_mk: GenericArray<u8, CTMKLength> =
            *GenericArray::from_slice(self.mk_ciphertext());
        let sk = key_registry
            .private_key(self.key_id())
            .ok_or(CryptError::NoSuchKey(self.key_id()))?;
        let info =
            HybridConversionInfo::from_bytes(&self.data[Self::INFO_OFFSET..]).map_err(|e| {
                InvalidHybridReportError::DeserializationError("HybridConversionInfo", e.into())
            })?;

        let plaintext_mk = open_in_place(sk, self.encap_key_mk(), &mut ct_mk, &info.to_bytes())?;
        let mut ct_btt: GenericArray<u8, CTBTTLength<V>> =
            GenericArray::from_slice(self.btt_ciphertext()).clone();
        let plaintext_btt = open_in_place(sk, self.encap_key_btt(), &mut ct_btt, &info.to_bytes())?;

        Ok(HybridConversionReport::<V> {
            match_key: Replicated::<BA64>::deserialize_infallible(GenericArray::from_slice(
                plaintext_mk,
            )),
            value: Replicated::<V>::deserialize(GenericArray::from_slice(plaintext_btt)).map_err(
                |e| InvalidHybridReportError::DeserializationError("trigger_value", e.into()),
            )?,
            info,
        })
    }
}

/// Converted report where shares of match key are replaced with OPRF value
pub type PrfHybridReport<BK, V> = IndistinguishableHybridReport<BK, V, u64>;

/// After grouping `IndistinguishableHybridReport`s by the OPRF of thier `match_key`,
/// that OPRF value is no longer required.
pub type AggregateableHybridReport<BK, V> = IndistinguishableHybridReport<BK, V, ()>;

impl<BK, V> IndistinguishableHybridReport<BK, V, ()>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    pub const ZERO: Self = Self {
        match_key: (),
        value: Replicated::<V>::ZERO,
        breakdown_key: Replicated::<BK>::ZERO,
    };

    fn join_fields(value: V, breakdown_key: BK) -> <Self as Shuffleable>::Share {
        let mut share = <Self as Shuffleable>::Share::ZERO;

        BooleanArrayWriter::new(&mut share)
            .write(&value)
            .write(&breakdown_key);

        share
    }

    fn split_fields(share: &<Self as Shuffleable>::Share) -> (V, BK) {
        let bits = BooleanArrayReader::new(share);
        let (value, bits) = bits.read();
        let (breakdown_key, _) = bits.read();
        (value, breakdown_key)
    }
}

/// When aggregating reports, we need to lift the value from `V` to `HV`.
impl<BK, V, HV> From<PrfHybridReport<BK, V>> for AggregateableHybridReport<BK, HV>
where
    BK: SharedValue + BooleanArray,
    V: SharedValue + BooleanArray,
    HV: SharedValue + BooleanArray,
{
    fn from(report: PrfHybridReport<BK, V>) -> Self {
        let mut value = Replicated::<HV>::ZERO;
        expand_shared_array_in_place(&mut value, &report.value, 0);
        Self {
            match_key: (),
            breakdown_key: report.breakdown_key,
            value,
        }
    }
}

/// This struct is designed to fit both `HybridConversionReport`s
/// and `HybridImpressionReport`s so that they can be made indistingushable.
/// Note: these need to be shuffled (and secret shares need to be rerandomized)
/// to provide any formal indistinguishability.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IndistinguishableHybridReport<BK, V, MK = Replicated<BA64>>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    pub match_key: MK,
    pub value: Replicated<V>,
    pub breakdown_key: Replicated<BK>,
}

impl<BK, V> IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    pub const ZERO: Self = Self {
        match_key: Replicated::<BA64>::ZERO,
        value: Replicated::<V>::ZERO,
        breakdown_key: Replicated::<BK>::ZERO,
    };

    fn join_fields(match_key: BA64, value: V, breakdown_key: BK) -> <Self as Shuffleable>::Share {
        let mut share = <Self as Shuffleable>::Share::ZERO;

        BooleanArrayWriter::new(&mut share)
            .write(&match_key)
            .write(&value)
            .write(&breakdown_key);

        share
    }

    fn split_fields(share: &<Self as Shuffleable>::Share) -> (BA64, V, BK) {
        let bits = BooleanArrayReader::new(share);
        let (match_key, bits) = bits.read();
        let (value, bits) = bits.read();
        let (breakdown_key, _) = bits.read();
        (match_key, value, breakdown_key)
    }
}

impl<BK, V> From<Replicated<BA64>> for IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    fn from(match_key: Replicated<BA64>) -> Self {
        Self {
            match_key,
            value: Replicated::<V>::ZERO,
            breakdown_key: Replicated::<BK>::ZERO,
        }
    }
}

impl<BK, V> From<HybridReport<BK, V>> for IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    fn from(report: HybridReport<BK, V>) -> Self {
        match report {
            HybridReport::Impression(r) => r.into(),
            HybridReport::Conversion(r) => r.into(),
        }
    }
}

impl<BK, V> From<HybridImpressionReport<BK>> for IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    fn from(impression_report: HybridImpressionReport<BK>) -> Self {
        Self {
            match_key: impression_report.match_key,
            value: Replicated::ZERO,
            breakdown_key: impression_report.breakdown_key,
        }
    }
}

impl<BK, V> From<HybridConversionReport<V>> for IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    fn from(conversion_report: HybridConversionReport<V>) -> Self {
        Self {
            match_key: conversion_report.match_key,
            value: conversion_report.value,
            breakdown_key: Replicated::ZERO,
        }
    }
}

impl<BK, V> Shuffleable for IndistinguishableHybridReport<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    // this requires BK:BAXX + V:BAYY  such that XX + YY <= 48
    // this is checked in a debud_assert call in ::new below
    // PERF OPPORTUNITY
    // note that BA96 would likely be a better fit here. however, that would require a `BA128`
    // in order to use `impl_malicious_shuffle_share!` and `BA128` cannot currently be
    // implemented with `the boolean_array_impl!` macro as the trait `secret_sharing::Block`
    // is not implemented for `bitvec::array::BitArray<[u8; 16]>`
    type Share = BA112;

    fn left(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::left(&self.match_key),
            self.value.left(),
            self.breakdown_key.left(),
        )
    }

    fn right(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::right(&self.match_key),
            self.value.right(),
            self.breakdown_key.right(),
        )
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        debug_assert!(
            BA64::BITS + BK::BITS + V::BITS <= Self::Share::BITS,
            "share type {} is too small",
            std::any::type_name::<Self::Share>(),
        );

        let left = Self::split_fields(&l);
        let right = Self::split_fields(&r);

        Self {
            match_key: ReplicatedSecretSharing::new(left.0, right.0),
            value: ReplicatedSecretSharing::new(left.1, right.1),
            breakdown_key: ReplicatedSecretSharing::new(left.2, right.2),
        }
    }
}

impl<BK, V> Shuffleable for IndistinguishableHybridReport<BK, V, ()>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    // this requires BK:BAXX + V:BAYY  such that XX + YY <= 32
    // this is checked in a debud_assert call in ::new below
    type Share = BA32;

    fn left(&self) -> Self::Share {
        Self::join_fields(self.value.left(), self.breakdown_key.left())
    }

    fn right(&self) -> Self::Share {
        Self::join_fields(self.value.right(), self.breakdown_key.right())
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        debug_assert!(
            BK::BITS + V::BITS <= Self::Share::BITS,
            "share type {} is too small",
            std::any::type_name::<Self::Share>(),
        );

        let left = Self::split_fields(&l);
        let right = Self::split_fields(&r);

        Self {
            match_key: (),
            value: ReplicatedSecretSharing::new(left.0, right.0),
            breakdown_key: ReplicatedSecretSharing::new(left.1, right.1),
        }
    }
}

impl PrfHybridReport<BA8, BA3> {
    const PRF_MK_SZ: usize = 8;
    const V_SZ: usize = <Replicated<BA3> as Serializable>::Size::USIZE;
    const BK_SZ: usize = <Replicated<BA8> as Serializable>::Size::USIZE;
}

impl Serializable for PrfHybridReport<BA8, BA3> {
    type Size = U12;
    type DeserializationError = InvalidHybridReportError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf[..Self::PRF_MK_SZ].copy_from_slice(&self.match_key.to_le_bytes());

        self.value.serialize(GenericArray::from_mut_slice(
            &mut buf[Self::PRF_MK_SZ..Self::PRF_MK_SZ + Self::V_SZ],
        ));

        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[Self::PRF_MK_SZ + Self::V_SZ..Self::PRF_MK_SZ + Self::V_SZ + Self::BK_SZ],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let prf_of_match_key = u64::from_le_bytes(buf[..Self::PRF_MK_SZ].try_into().unwrap());

        let value = Replicated::<BA3>::deserialize(GenericArray::from_slice(
            &buf[Self::PRF_MK_SZ..Self::PRF_MK_SZ + Self::V_SZ],
        ))
        .map_err(|e| InvalidHybridReportError::DeserializationError("value", e.into()))?;

        let breakdown_key = Replicated::<BA8>::deserialize_infallible(GenericArray::from_slice(
            &buf[Self::PRF_MK_SZ + Self::V_SZ..Self::PRF_MK_SZ + Self::V_SZ + Self::BK_SZ],
        ));

        Ok(Self {
            match_key: prf_of_match_key,
            value,
            breakdown_key,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum EncryptedHybridReport<BK, V>
where
    BK: SharedValue,
    V: SharedValue,
{
    Impression(EncryptedHybridImpressionReport<BK>),
    Conversion(EncryptedHybridConversionReport<V>),
}
impl<BK, V> EncryptedHybridReport<BK, V>
where
    V: SharedValue,
    BK: SharedValue,
    Replicated<V>: Serializable,
    Replicated<BK>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
{
    pub fn encap_key_mk(&self) -> &[u8] {
        match self {
            EncryptedHybridReport::Impression(impression_report) => {
                impression_report.encap_key_mk()
            }
            EncryptedHybridReport::Conversion(conversion_report) => {
                conversion_report.encap_key_mk()
            }
        }
    }
    pub fn mk_ciphertext(&self) -> &[u8] {
        match self {
            EncryptedHybridReport::Impression(impression_report) => {
                impression_report.mk_ciphertext()
            }
            EncryptedHybridReport::Conversion(conversion_report) => {
                conversion_report.mk_ciphertext()
            }
        }
    }
    pub fn encap_key_btt(&self) -> &[u8] {
        match self {
            EncryptedHybridReport::Impression(impression_report) => {
                impression_report.encap_key_btt()
            }
            EncryptedHybridReport::Conversion(conversion_report) => {
                conversion_report.encap_key_btt()
            }
        }
    }
    pub fn btt_ciphertext(&self) -> &[u8] {
        match self {
            EncryptedHybridReport::Impression(impression_report) => {
                impression_report.btt_ciphertext()
            }
            EncryptedHybridReport::Conversion(conversion_report) => {
                conversion_report.btt_ciphertext()
            }
        }
    }
    pub fn key_id(&self) -> u8 {
        match self {
            EncryptedHybridReport::Impression(impression_report) => impression_report.key_id(),
            EncryptedHybridReport::Conversion(conversion_report) => conversion_report.key_id(),
        }
    }
    /// ## Errors
    /// If the report contents are invalid.
    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, InvalidHybridReportError> {
        match HybridEventType::try_from(bytes[0])? {
            HybridEventType::Impression => {
                bytes.advance(1);
                let impression_report = EncryptedHybridImpressionReport::<BK>::from_bytes(bytes)?;
                Ok(EncryptedHybridReport::Impression(impression_report))
            }
            HybridEventType::Conversion => {
                bytes.advance(1);
                let conversion_report = EncryptedHybridConversionReport::<V>::from_bytes(bytes)?;
                Ok(EncryptedHybridReport::Conversion(conversion_report))
            }
        }
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
    ) -> Result<HybridReport<BK, V>, InvalidHybridReportError> {
        match self {
            EncryptedHybridReport::Impression(impression_report) => Ok(HybridReport::Impression(
                impression_report.decrypt(key_registry)?,
            )),
            EncryptedHybridReport::Conversion(conversion_report) => Ok(HybridReport::Conversion(
                conversion_report.decrypt(key_registry)?,
            )),
        }
    }
}

impl<BK, V> TryFrom<Bytes> for EncryptedHybridReport<BK, V>
where
    V: SharedValue,
    BK: SharedValue,
    Replicated<V>: Serializable,
    Replicated<BK>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
{
    type Error = InvalidHybridReportError;

    fn try_from(bytes: Bytes) -> Result<Self, InvalidHybridReportError> {
        Self::from_bytes(bytes)
    }
}

const TAG_SIZE: usize = TagSize::USIZE;

#[derive(Clone, Debug)]
pub struct UniqueTag {
    bytes: [u8; TAG_SIZE],
}

pub trait UniqueBytes {
    fn unique_bytes(&self) -> [u8; TAG_SIZE];
}

impl UniqueBytes for UniqueTag {
    fn unique_bytes(&self) -> [u8; TAG_SIZE] {
        self.bytes
    }
}

impl<BK, V> UniqueBytes for EncryptedHybridReport<BK, V>
where
    V: SharedValue,
    BK: SharedValue,
    Replicated<V>: Serializable,
    Replicated<BK>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<U16>,
    <<Replicated<V> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
    <Replicated<BK> as Serializable>::Size: Add<U16>,
    <<Replicated<BK> as Serializable>::Size as Add<U16>>::Output: ArrayLength,
{
    /// We use the `TagSize` (the first 16 bytes of the ciphertext) for collision-detection
    /// See [analysis here for uniqueness](https://eprint.iacr.org/2019/624)
    fn unique_bytes(&self) -> [u8; TAG_SIZE] {
        let slice = &self.mk_ciphertext()[0..TAG_SIZE];
        let mut array = [0u8; TAG_SIZE];
        array.copy_from_slice(slice);
        array
    }
}

impl UniqueTag {
    // Function to attempt to create a UniqueTag from a UniqueBytes implementor
    pub fn from_unique_bytes<T: UniqueBytes>(item: &T) -> Self {
        const_assert_eq!(16, TAG_SIZE);
        UniqueTag {
            bytes: item.unique_bytes(),
        }
    }

    /// Maps the tag into a consistent shard.
    ///
    /// ## Panics
    /// if the `TAG_SIZE != 16`
    /// note: ~10 below this, we have a compile time check that `TAG_SIZE = 16`
    #[must_use]
    pub fn shard_picker(&self, shard_count: ShardIndex) -> ShardIndex {
        let num = u128::from_le_bytes(self.bytes);
        let shard_count = u128::from(shard_count);
        ShardIndex::try_from(num % shard_count).expect("Modulo a u32 will fit in u32")
    }
}

impl Serializable for UniqueTag {
    type Size = U16; // This must match TAG_SIZE
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.bytes);
    }
    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let mut bytes = [0u8; TAG_SIZE];
        bytes.copy_from_slice(buf.as_slice());
        Ok(UniqueTag { bytes })
    }
}

#[derive(Debug)]
pub struct UniqueTagValidator {
    hash_set: HashSet<[u8; TAG_SIZE]>,
    check_counter: usize,
}

impl UniqueTagValidator {
    #[must_use]
    pub fn new(size: usize) -> Self {
        UniqueTagValidator {
            hash_set: HashSet::with_capacity(size),
            check_counter: 0,
        }
    }
    fn insert(&mut self, value: [u8; TAG_SIZE]) -> bool {
        self.hash_set.insert(value)
    }
    /// Checks that item is unique among all checked thus far
    ///
    /// ## Errors
    /// if the item inserted is not unique among all checked thus far
    pub fn check_duplicate<U: UniqueBytes>(&mut self, item: &U) -> Result<(), Error> {
        self.check_counter += 1;
        if self.insert(item.unique_bytes()) {
            Ok(())
        } else {
            Err(Error::DuplicateBytes(self.check_counter))
        }
    }
    /// Checks that an iter of items is unique among the iter and any other items checked thus far
    ///
    /// ## Errors
    /// if the and item inserted is not unique among all in this batch and checked previously
    pub fn check_duplicates<U: UniqueBytes>(&mut self, items: &[U]) -> Result<(), Error> {
        items
            .iter()
            .try_for_each(|item| self.check_duplicate(item))?;
        Ok(())
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use bytes::Bytes;
    use rand::Rng;

    use super::{
        EncryptedHybridImpressionReport, EncryptedHybridReport, GenericArray,
        HybridConversionReport, HybridImpressionReport, HybridReport,
        IndistinguishableHybridReport, PrfHybridReport, UniqueTag, UniqueTagValidator,
        HELPER_ORIGIN,
    };
    use crate::{
        error::Error,
        ff::{
            boolean_array::{BA3, BA8},
            Serializable,
        },
        hpke::{KeyPair, KeyRegistry},
        report::{
            hybrid::{EncryptedHybridConversionReport, HybridEventType, NonAsciiStringError},
            hybrid_info::{HybridConversionInfo, HybridImpressionInfo},
        },
        secret_sharing::replicated::{
            semi_honest::{AdditiveShare as Replicated, AdditiveShare},
            ReplicatedSecretSharing,
        },
        test_executor::run_random,
    };

    fn build_hybrid_report<R>(event_type: HybridEventType, rng: &mut R) -> HybridReport<BA8, BA3>
    where
        R: Rng,
    {
        match event_type {
            HybridEventType::Impression => {
                HybridReport::Impression(HybridImpressionReport::<BA8> {
                    match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                    breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
                    info: HybridImpressionInfo::new(0, "HelperOrigin").unwrap(),
                })
            }
            HybridEventType::Conversion => {
                HybridReport::Conversion(HybridConversionReport::<BA3> {
                    match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                    value: AdditiveShare::new(rng.gen(), rng.gen()),
                    info: HybridConversionInfo::new(
                        0,
                        "HelperOrigin",
                        "https://www.example2.com",
                        rng.gen(),
                        0.0,
                        0.0,
                    )
                    .unwrap(),
                })
            }
        }
    }

    fn generate_random_tag<R>(rng: &mut R) -> UniqueTag
    where
        R: Rng,
    {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes[..]);
        UniqueTag { bytes }
    }

    /// We create a random `HybridConversionReport`, convert it into an
    ///`IndistinguishableHybridReport`, and check that the field values are the same
    /// (or zero, for the breakdown key, which doesn't exist on the conversion report.)
    /// We then build a generic `HybridReport` from the conversion report, convert it
    /// into an `IndistingushableHybridReport`, and validate that it has the same value
    /// as the previous `IndistingushableHybridReport`.
    #[test]
    fn convert_hybrid_conversion_report_to_indistinguishable_report() {
        run_random(|mut rng| async move {
            let conversion_report = HybridConversionReport::<BA3> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                value: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridConversionInfo::new(
                    0,
                    "HelperOrigin",
                    "https://www.example2.com",
                    1_234_567,
                    0.0,
                    0.0,
                )
                .unwrap(),
            };
            let indistinguishable_report: IndistinguishableHybridReport<BA8, BA3> =
                conversion_report.clone().into();
            assert_eq!(
                conversion_report.match_key,
                indistinguishable_report.match_key
            );
            assert_eq!(conversion_report.value, indistinguishable_report.value);
            assert_eq!(AdditiveShare::ZERO, indistinguishable_report.breakdown_key);

            let hybrid_report = HybridReport::Conversion::<BA8, BA3>(conversion_report.clone());
            let indistinguishable_report2: IndistinguishableHybridReport<BA8, BA3> =
                hybrid_report.clone().into();
            assert_eq!(indistinguishable_report, indistinguishable_report2);
        });
    }

    /// We create a random `HybridImpressionReport`, convert it into an
    ///`IndistinguishableHybridReport`, and check that the field values are the same
    /// (or zero, for the value, which doesn't exist on the impression report.)
    /// We then build a generic `HybridReport` from the impression report, convert it
    /// into an `IndistingushableHybridReport`, and validate that it has the same value
    /// as the previous `IndistingushableHybridReport`.
    #[test]
    fn convert_hybrid_impression_report_to_indistinguishable_report() {
        run_random(|mut rng| async move {
            let impression_report = HybridImpressionReport::<BA8> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridImpressionInfo::new(0, "HelperOrigin").unwrap(),
            };
            let indistinguishable_report: IndistinguishableHybridReport<BA8, BA3> =
                impression_report.clone().into();
            assert_eq!(
                impression_report.match_key,
                indistinguishable_report.match_key
            );
            assert_eq!(AdditiveShare::ZERO, indistinguishable_report.value);
            assert_eq!(
                impression_report.breakdown_key,
                indistinguishable_report.breakdown_key
            );

            let hybrid_report = HybridReport::Impression::<BA8, BA3>(impression_report.clone());
            let indistinguishable_report2: IndistinguishableHybridReport<BA8, BA3> =
                hybrid_report.clone().into();
            assert_eq!(indistinguishable_report, indistinguishable_report2);
        });
    }

    #[test]
    fn unique_encrypted_hybrid_reports() {
        run_random(|mut rng| async move {
            let tag1 = generate_random_tag(&mut rng);
            let tag2 = generate_random_tag(&mut rng);
            let tag3 = generate_random_tag(&mut rng);
            let tag4 = generate_random_tag(&mut rng);

            let mut unique_bytes = UniqueTagValidator::new(4);

            unique_bytes.check_duplicate(&tag1).unwrap();

            unique_bytes
                .check_duplicates(&[tag2.clone(), tag3.clone()])
                .unwrap();
            let expected_err = unique_bytes.check_duplicate(&tag2);
            assert!(matches!(expected_err, Err(Error::DuplicateBytes(4))));

            let expected_err = unique_bytes.check_duplicates(&[tag4, tag3]);
            assert!(matches!(expected_err, Err(Error::DuplicateBytes(6))));
        });
    }

    #[test]
    fn serialization_hybrid_impression() {
        run_random(|mut rng| async move {
            let hybrid_impression_report = HybridImpressionReport::<BA8> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridImpressionInfo::new(0, "HelperOrigin").unwrap(),
            };
            let mut hybrid_impression_report_bytes =
                Vec::with_capacity(HybridImpressionReport::<BA8>::serialized_len());
            hybrid_impression_report.serialize(&mut hybrid_impression_report_bytes);
            let hybrid_impression_report2 = HybridImpressionReport::<BA8>::deserialize(
                &Bytes::copy_from_slice(&hybrid_impression_report_bytes[..]),
            )
            .unwrap();
            assert_eq!(hybrid_impression_report, hybrid_impression_report2);
        });
    }

    #[test]
    fn serialization_hybrid_conversion() {
        run_random(|mut rng| async move {
            let hybrid_conversion_report = HybridConversionReport::<BA3> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                value: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridConversionInfo::new(
                    0,
                    "HelperOrigin",
                    "https://www.example2.com",
                    1_234_567,
                    0.0,
                    0.0,
                )
                .unwrap(),
            };
            let mut hybrid_conversion_report_bytes =
                Vec::with_capacity(HybridImpressionReport::<BA8>::serialized_len());
            hybrid_conversion_report.serialize(&mut hybrid_conversion_report_bytes);
            let hybrid_conversion_report2 = HybridConversionReport::<BA3>::deserialize(
                &Bytes::copy_from_slice(&hybrid_conversion_report_bytes[..]),
            )
            .unwrap();
            assert_eq!(hybrid_conversion_report, hybrid_conversion_report2);
        });
    }

    #[test]
    fn enc_dec_roundtrip_hybrid_impression() {
        run_random(|mut rng| async move {
            let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
            let key_id = 0;

            let hybrid_impression_report = HybridImpressionReport::<BA8> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                breakdown_key: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridImpressionInfo::new(key_id, HELPER_ORIGIN).unwrap(),
            };

            let enc_report_bytes = hybrid_impression_report
                .encrypt(key_id, &key_registry, &mut rng)
                .unwrap();

            let enc_report =
                EncryptedHybridImpressionReport::<BA8>::from_bytes(enc_report_bytes.into())
                    .unwrap();
            let dec_report: HybridImpressionReport<BA8> =
                enc_report.decrypt(&key_registry).unwrap();

            assert_eq!(dec_report, hybrid_impression_report);
        });
    }

    #[test]
    fn enc_dec_roundtrip_hybrid_conversion() {
        run_random(|mut rng| async move {
            let hybrid_conversion_report = HybridConversionReport::<BA3> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                value: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridConversionInfo::new(
                    0,
                    HELPER_ORIGIN,
                    "meta.com",
                    1_729_707_432,
                    5.0,
                    1.1,
                )
                .unwrap(),
            };

            let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
            let key_id = 0;

            let enc_report_bytes = hybrid_conversion_report
                .encrypt(key_id, &key_registry, &mut rng)
                .unwrap();

            let enc_report =
                EncryptedHybridConversionReport::<BA3>::from_bytes(enc_report_bytes.into())
                    .unwrap();
            let dec_report: HybridConversionReport<BA3> =
                enc_report.decrypt(&key_registry).unwrap();

            assert_eq!(dec_report, hybrid_conversion_report);
        });
    }

    #[test]
    fn enc_dec_roundtrip_hybrid() {
        run_random(|mut rng| async move {
            let b = HybridEventType::Impression;
            let hybrid_report = build_hybrid_report(b, &mut rng);

            let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
            let key_id = 0;

            let enc_report_bytes = hybrid_report
                .encrypt(key_id, &key_registry, &mut rng)
                .unwrap();

            let enc_report =
                EncryptedHybridReport::<BA8, BA3>::from_bytes(enc_report_bytes.into()).unwrap();
            let dec_report: HybridReport<BA8, BA3> = enc_report.decrypt(&key_registry).unwrap();

            assert_eq!(dec_report, hybrid_report);
        });
    }

    #[test]
    fn enc_report_serialization() {
        run_random(|mut rng| async move {
            let hybrid_conversion_report = HybridConversionReport::<BA3> {
                match_key: AdditiveShare::new(rng.gen(), rng.gen()),
                value: AdditiveShare::new(rng.gen(), rng.gen()),
                info: HybridConversionInfo::new(
                    0,
                    "HELPER_ORIGIN",
                    "meta.com",
                    1_729_707_432,
                    5.0,
                    1.1,
                )
                .unwrap(),
            };

            let key_registry = KeyRegistry::<KeyPair>::random(1, &mut rng);
            let key_id = 0;

            let enc_report_bytes = hybrid_conversion_report
                .encrypt(key_id, &key_registry, &mut rng)
                .unwrap();

            let mut enc_report_bytes2 = enc_report_bytes.clone();

            let enc_report =
                EncryptedHybridConversionReport::<BA3>::from_bytes(enc_report_bytes.into())
                    .unwrap();
            let dec_report: HybridConversionReport<BA3> =
                enc_report.decrypt(&key_registry).unwrap();
            assert_eq!(dec_report, hybrid_conversion_report);

            // Prepend a byte to the ciphertext to mark it as a ConversionReport
            enc_report_bytes2.splice(0..0, [HybridEventType::Conversion as u8]);

            let enc_report2 =
                EncryptedHybridReport::<BA8, BA3>::from_bytes(enc_report_bytes2.into()).unwrap();
            let enc_report3 = enc_report2.clone();

            // Case 1: Match first, then decrypt
            match enc_report2 {
                EncryptedHybridReport::Impression(_) => panic!("Expected conversion report"),
                EncryptedHybridReport::Conversion(enc_report_conv) => {
                    let dec_report2: HybridConversionReport<BA3> =
                        enc_report_conv.decrypt(&key_registry).unwrap();
                    assert_eq!(dec_report2, hybrid_conversion_report);
                }
            }
            // Case 2: Decrypt directly
            let dec_report3 = enc_report3.decrypt(&key_registry).unwrap();
            assert_eq!(
                dec_report3,
                HybridReport::Conversion(hybrid_conversion_report)
            );
        });
    }

    #[test]
    fn non_ascii_string() {
        let non_ascii_string = "☃️☃️☃️";
        let err = HybridImpressionInfo::new(0, non_ascii_string).unwrap_err();
        assert!(matches!(err, NonAsciiStringError(_)));
    }

    #[test]
    fn serde() {
        run_random(|mut rng| async move {
            let report = PrfHybridReport::<BA8, BA3> {
                match_key: rng.gen(),
                breakdown_key: Replicated::new(rng.gen(), rng.gen()),
                value: Replicated::new(rng.gen(), rng.gen()),
            };
            let mut buf = GenericArray::default();
            report.serialize(&mut buf);
            let deserialized_report = PrfHybridReport::<BA8, BA3>::deserialize(&buf);
            assert_eq!(report, deserialized_report.unwrap());
        });
    }
}
