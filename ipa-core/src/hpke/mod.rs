//! Provides HPKE decryption primitives for match key shares according to the [`specification`].
//!
//! [`specification`]: https://github.com/patcg-individual-drafts/ipa/blob/main/details/encryption.md

use std::{fmt::Debug, io, ops::Add};

use generic_array::ArrayLength;
use hpke::{
    OpModeR, OpModeS, aead::AeadTag, single_shot_open_in_place_detached,
    single_shot_seal_in_place_detached,
};
use rand_core::{CryptoRng, RngCore};
use typenum::U16;

mod registry;

pub use registry::{
    KeyPair, KeyRegistry, PrivateKeyOnly, PrivateKeyRegistry, PublicKeyOnly, PublicKeyRegistry,
};

use crate::{
    ff::{GaloisField, Serializable as IpaSerializable},
    secret_sharing::replicated::semi_honest::AdditiveShare,
};

/// IPA ciphersuite
type IpaKem = hpke::kem::X25519HkdfSha256;
type IpaAead = hpke::aead::AesGcm128;
type IpaKdf = hpke::kdf::HkdfSha256;

pub type EncapsulationSize = <<IpaKem as hpke::Kem>::EncappedKey as Serializable>::OutputSize;
pub type TagSize = <AeadTag<IpaAead> as Serializable>::OutputSize;

pub type IpaPublicKey = <IpaKem as hpke::kem::Kem>::PublicKey;
pub type IpaPrivateKey = <IpaKem as hpke::kem::Kem>::PrivateKey;
pub type IpaEncapsulatedKey = <IpaKem as hpke::kem::Kem>::EncappedKey;

pub use hpke::{Deserializable, Serializable};

use crate::report::hybrid::KeyIdentifier;

pub trait FieldShareCrypt: GaloisField + IpaSerializable {
    type EncapKeySize: ArrayLength;
    type CiphertextSize: ArrayLength;
    type SemiHonestShares: IpaSerializable + Clone + Debug + Eq;
}

// Ideally this could generically add the tag size to the size of the share (i.e. remove the
// `OutputSize = U16` constraint and instead of writing `Add<U16>`, write `Add<<AeadTag<IpaAead> as
// hpke::Serializable>::OutputSize>`), but could not figure out how to get the compiler to accept
// that, and it doesn't seem worth a lot of trouble for a value that won't be changing.
impl<F> FieldShareCrypt for F
where
    F: GaloisField + IpaSerializable + Clone + Debug + Eq,
    AdditiveShare<F>: IpaSerializable + Clone + Debug + Eq,
    AeadTag<IpaAead>: Serializable<OutputSize = U16>,
    <AdditiveShare<F> as IpaSerializable>::Size: Add<U16>,
    <<AdditiveShare<F> as IpaSerializable>::Size as Add<U16>>::Output: ArrayLength,
{
    type EncapKeySize = <<IpaKem as hpke::Kem>::EncappedKey as Serializable>::OutputSize;
    type CiphertextSize = <<AdditiveShare<F> as IpaSerializable>::Size as Add<U16>>::Output;
    type SemiHonestShares = AdditiveShare<F>;
}

#[derive(Debug, thiserror::Error)]
pub enum CryptError {
    #[error("Unknown key {0}")]
    NoSuchKey(KeyIdentifier),
    #[error("Failed to open ciphertext")]
    Other,
}

impl From<hpke::HpkeError> for CryptError {
    fn from(_value: hpke::HpkeError) -> Self {
        Self::Other
    }
}

impl From<io::Error> for CryptError {
    fn from(_value: io::Error) -> Self {
        Self::Other
    }
}

/// Opens the given ciphertext in place by first obtaining the secret key from `key_registry`
/// using epoch and key from the `info` parameter and then applying [`HPKE decryption`]
/// to the provided ciphertext.
///
/// This function mutates the provided ciphertext slice and replaces it with the plaintext obtained
/// after opening the ciphertext. The result will contain a pointer to the plaintext slice.
/// Note that if the ciphertext slice does not include authentication tag, decryption
/// will fail.
///
/// ## Errors
/// If ciphertext cannot be opened for any reason.
///
/// [`HPKE decryption`]: https://datatracker.ietf.org/doc/html/rfc9180#name-encryption-and-decryption
pub fn open_in_place<'a>(
    sk: &IpaPrivateKey,
    enc: &[u8],
    ciphertext: &'a mut [u8],
    info: &[u8],
) -> Result<&'a [u8], CryptError> {
    let encap_key = <IpaKem as hpke::Kem>::EncappedKey::from_bytes(enc)?;
    let (ct, tag) = ciphertext.split_at_mut(ciphertext.len() - AeadTag::<IpaAead>::size());
    let tag = AeadTag::<IpaAead>::from_bytes(tag)?;

    single_shot_open_in_place_detached::<_, IpaKdf, IpaKem>(
        &OpModeR::Base,
        sk,
        &encap_key,
        info,
        ct,
        &[],
        &tag,
    )?;

    // at this point ct is no longer a pointer to the ciphertext.
    let pt = ct;
    Ok(pt)
}

// Avoids a clippy "complex type" warning on the return type from `seal_in_place`.
// Not intended to be widely used.
pub(crate) type Ciphertext<'a> = (
    <IpaKem as hpke::Kem>::EncappedKey,
    &'a [u8],
    AeadTag<IpaAead>,
);

/// ## Errors
/// If the match key cannot be sealed for any reason.
pub(crate) fn seal_in_place<'a, R: CryptoRng + RngCore>(
    pk: &IpaPublicKey,
    plaintext: &'a mut [u8],
    info: &[u8],
    rng: &mut R,
) -> Result<Ciphertext<'a>, CryptError> {
    let (encap_key, tag) = single_shot_seal_in_place_detached::<IpaAead, IpaKdf, IpaKem, _>(
        &OpModeS::Base,
        pk,
        info,
        plaintext,
        &[],
        rng,
    )?;

    // at this point `plaintext` is no longer a pointer to the plaintext.
    Ok((encap_key, plaintext, tag))
}
