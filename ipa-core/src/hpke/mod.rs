//! Provides HPKE decryption primitives for match key shares according to the [`specification`].
//!
//! [`specification`]: https://github.com/patcg-individual-drafts/ipa/blob/main/details/encryption.md

use std::{fmt::Debug, io, ops::Add};

use generic_array::ArrayLength;
use hpke::{
    aead::AeadTag, single_shot_open_in_place_detached, single_shot_seal_in_place_detached, OpModeR,
    OpModeS,
};
use rand_core::{CryptoRng, RngCore};
use typenum::U16;

mod info;
mod registry;

pub use info::Info;
pub use registry::{
    KeyPair, KeyRegistry, PrivateKeyOnly, PrivateKeyRegistry, PublicKeyOnly, PublicKeyRegistry,
};

use crate::{
    ff::{GaloisField, Serializable as IpaSerializable},
    report::KeyIdentifier,
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
pub fn open_in_place<'a, R: PrivateKeyRegistry + ?Sized>(
    key_registry: &R,
    enc: &[u8],
    ciphertext: &'a mut [u8],
    info: &Info,
) -> Result<&'a [u8], CryptError> {
    let key_id = info.key_id;
    let info = info.to_bytes();
    let encap_key = <IpaKem as hpke::Kem>::EncappedKey::from_bytes(enc)?;
    let (ct, tag) = ciphertext.split_at_mut(ciphertext.len() - AeadTag::<IpaAead>::size());
    let tag = AeadTag::<IpaAead>::from_bytes(tag)?;
    let sk = key_registry
        .private_key(key_id)
        .ok_or(CryptError::NoSuchKey(key_id))?;

    single_shot_open_in_place_detached::<_, IpaKdf, IpaKem>(
        &OpModeR::Base,
        sk,
        &encap_key,
        &info,
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
pub(crate) fn seal_in_place<'a, R: CryptoRng + RngCore, K: PublicKeyRegistry>(
    key_registry: &K,
    plaintext: &'a mut [u8],
    info: &'a Info,
    rng: &mut R,
) -> Result<Ciphertext<'a>, CryptError> {
    let key_id = info.key_id;
    let info = info.to_bytes();
    let pk_r = key_registry
        .public_key(key_id)
        .ok_or(CryptError::NoSuchKey(key_id))?;

    let (encap_key, tag) = single_shot_seal_in_place_detached::<IpaAead, IpaKdf, IpaKem, _>(
        &OpModeS::Base,
        pk_r,
        &info,
        plaintext,
        &[],
        rng,
    )?;

    // at this point `plaintext` is no longer a pointer to the plaintext.
    Ok((encap_key, plaintext, tag))
}

#[cfg(all(test, unit_test))]
mod tests {
    use generic_array::GenericArray;
    use hpke::{aead::AeadTag, Serializable};
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use typenum::Unsigned;

    use crate::{
        ff::{Gf40Bit, Serializable as IpaSerializable},
        hpke::{open_in_place, seal_in_place, CryptError, Info, IpaAead, KeyPair, KeyRegistry},
        report::{Epoch, EventType, KeyIdentifier},
        secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
    };

    type XorReplicated = AdditiveShare<Gf40Bit>;

    /// match key size, in bytes
    const MATCHKEY_LEN: usize = <XorReplicated as IpaSerializable>::Size::USIZE;

    /// Total len in bytes for an encrypted matchkey including the authentication tag.
    const MATCHKEY_CT_LEN: usize =
        MATCHKEY_LEN + <AeadTag<IpaAead> as Serializable>::OutputSize::USIZE;

    /// Represents an encrypted share of single match key.
    #[derive(Clone)]
    struct MatchKeyEncryption<'a> {
        /// Encapsulated key as defined in [`url`] specification.
        /// Key size depends on the AEAD type used in HPKE, in current setting IPA uses [`aead`] type.
        ///
        /// [`url`]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
        /// [`aead`]: IpaAead
        enc: [u8; 32],

        /// Ciphertext + tag
        ct: [u8; MATCHKEY_CT_LEN],

        /// Info part of the receiver context as defined in [`url`] specification.
        ///
        /// [`url`]: https://datatracker.ietf.org/doc/html/rfc9180#section-5.1
        info: Info<'a>,
    }

    struct EncryptionSuite<R: RngCore + CryptoRng> {
        registry: KeyRegistry<KeyPair>,
        rng: R,
        epoch: Epoch,
    }

    impl<R: RngCore + CryptoRng> EncryptionSuite<R> {
        const HELPER_ORIGIN: &'static str = "foo";
        const SITE_DOMAIN: &'static str = "xn--mozilla.com.xn--example.com";

        pub fn new(keys: usize, mut rng: R) -> Self {
            Self {
                registry: KeyRegistry::<KeyPair>::random(keys, &mut rng),
                rng,
                epoch: 0,
            }
        }

        pub fn seal_with_info<'a>(
            &mut self,
            info: Info<'a>,
            match_key: &XorReplicated,
        ) -> MatchKeyEncryption<'a> {
            let mut plaintext = GenericArray::default();
            match_key.serialize(&mut plaintext);

            let (encap_key, ciphertext, tag) = seal_in_place(
                &self.registry,
                plaintext.as_mut_slice(),
                &info,
                &mut self.rng,
            )
            .unwrap();

            let mut ct_and_tag = [0u8; MATCHKEY_CT_LEN];
            ct_and_tag[..ciphertext.len()].copy_from_slice(ciphertext);
            ct_and_tag[ciphertext.len()..].copy_from_slice(&Serializable::to_bytes(&tag));

            MatchKeyEncryption {
                enc: <[u8; 32]>::from(Serializable::to_bytes(&encap_key)),
                ct: ct_and_tag,
                info,
            }
        }

        #[must_use]
        pub fn seal(
            &mut self,
            key_id: KeyIdentifier,
            event_type: EventType,
            match_key: &XorReplicated,
        ) -> MatchKeyEncryption<'static> {
            let info = Info::new(
                key_id,
                self.epoch,
                event_type,
                Self::HELPER_ORIGIN,
                Self::SITE_DOMAIN,
            )
            .unwrap();

            self.seal_with_info(info, match_key)
        }

        pub fn open(
            &self,
            key_id: KeyIdentifier,
            event_type: EventType,
            mut enc: MatchKeyEncryption<'_>,
        ) -> Result<XorReplicated, CryptError> {
            let info = Info::new(
                key_id,
                self.epoch,
                event_type,
                Self::HELPER_ORIGIN,
                Self::SITE_DOMAIN,
            )
            .unwrap();
            open_in_place(&self.registry, &enc.enc, enc.ct.as_mut(), &info)?;

            // TODO: fix once array split is a thing.
            Ok(XorReplicated::deserialize_infallible(
                GenericArray::from_slice(&enc.ct[..MATCHKEY_LEN]),
            ))
        }

        pub fn advance_epoch(&mut self) {
            self.epoch += 1;
        }
    }

    fn new_share(a: u64, b: u64) -> XorReplicated {
        let left = Gf40Bit::try_from(u128::from(a)).unwrap();
        let right = Gf40Bit::try_from(u128::from(b)).unwrap();

        XorReplicated::new(left, right)
    }

    /// Make sure we obey the spec
    #[test]
    fn ipa_info_serialize() {
        let info = Info::new(255, 32767, EventType::Trigger, "foo", "bar").unwrap();
        assert_eq!(
            b"private-attribution\0foo\0bar\0\xff\x7f\xff\x01",
            info.to_bytes().as_ref()
        );
    }

    #[test]
    fn decrypt_happy_case() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = new_share(1u64 << 39, 1u64 << 20);

        let enc = suite.seal(0, EventType::Source, &match_key);
        let r = suite.open(0, EventType::Source, enc).unwrap();

        assert_eq!(match_key, r);
    }

    #[test]
    fn decrypt_wrong_epoch() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = new_share(1u64 << 39, 1u64 << 20);
        let enc = suite.seal(0, EventType::Source, &match_key);
        suite.advance_epoch();

        let _: CryptError = suite.open(0, EventType::Source, enc).unwrap_err();
    }

    #[test]
    fn decrypt_wrong_key() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(10, rng);
        let match_key = new_share(1u64 << 39, 1u64 << 20);
        let enc = suite.seal(0, EventType::Source, &match_key);
        let _: CryptError = suite.open(1, EventType::Source, enc).unwrap_err();
    }

    #[test]
    fn decrypt_unknown_key() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = new_share(1u64 << 39, 1u64 << 20);
        let enc = suite.seal(0, EventType::Source, &match_key);

        assert!(matches!(
            suite.open(1, EventType::Source, enc),
            Err(CryptError::NoSuchKey(1))
        ));
    }

    mod proptests {
        use proptest::prelude::ProptestConfig;
        use rand::{distributions::Alphanumeric, Rng};

        use super::*;

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_ct_corruption(bad_byte in 0..23_usize, bad_bit in 0..7_usize, seed: [u8; 32]) {
                let rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(1, rng);
                let mut encryption = suite.seal(0, EventType::Source, &new_share(0, 0));

                encryption.ct.as_mut()[bad_byte] ^= 1 << bad_bit;
                suite.open(0, EventType::Source, encryption).unwrap_err();
            }
        }

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
             fn arbitrary_enc_corruption(bad_byte in 0..32_usize, bad_bit in 0..7_usize, seed: [u8; 32]) {
                let rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(1, rng);
                let mut encryption = suite.seal(0, EventType::Source, &new_share(0, 0));

                encryption.enc.as_mut()[bad_byte] ^= 1 << bad_bit;
                suite.open(0, EventType::Source, encryption).unwrap_err();
            }
        }

        fn corrupt_str<R: RngCore>(s: &mut String, rng: &mut R) {
            assert!(s.is_ascii());

            // 0 - add
            // 1 - remove
            // 2 - modify
            let idx = rng.gen_range(0..s.len());
            match rng.gen_range(0..3) {
                0 => {
                    let c = rng.sample(Alphanumeric);
                    s.insert(idx, char::from(c));
                }
                1 => {
                    s.remove(idx);
                }
                2 => {
                    let char_at_idx = s.chars().nth(idx).unwrap();
                    let c = rng
                        .sample_iter(Alphanumeric)
                        .map(char::from)
                        .skip_while(|new_char| new_char == &char_at_idx)
                        .take(1)
                        .next()
                        .unwrap();

                    s.replace_range(idx..=idx, &c.to_string());
                }
                _ => unreachable!(),
            }
        }

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_info_corruption(corrupted_info_field in 1..5,
                                         site_domain in "[a-z]{10}",
                                         helper_origin in "[a-z]{10}",
                                         trigger_bit in 0_u8..=1,
                                         seed: [u8; 32]) {
                let mut rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(10, rng.clone());
                // keep the originals, in case if we need to damage them
                let (mut site_domain_clone, mut helper_clone) = (site_domain.clone(), helper_origin.clone());
                let info = Info::new(0, 0, EventType::try_from(trigger_bit).unwrap(), &site_domain, &helper_origin).unwrap();
                let mut encryption = suite.seal_with_info(info, &new_share(0, 0));

                let info = match corrupted_info_field {
                    1 => Info {
                        key_id: encryption.info.key_id + 1,
                        ..encryption.info
                    },
                    2 => Info {
                        epoch: encryption.info.epoch + 1,
                        ..encryption.info
                    },
                    3 => Info {
                        event_type: EventType::try_from(trigger_bit ^ 1).unwrap(),
                        ..encryption.info
                    },
                    4 => {
                        corrupt_str(&mut site_domain_clone, &mut rng);

                        Info {
                            site_domain: &site_domain_clone,
                            ..encryption.info
                        }
                    },
                    5 => {
                        corrupt_str(&mut helper_clone, &mut rng);

                        Info {
                            helper_origin: &helper_clone,
                            ..encryption.info
                        }
                    }
                    _ => panic!("bad test setup: only 5 fields can be corrupted, asked to corrupt: {corrupted_info_field}")
                };

                open_in_place(&suite.registry, &encryption.enc, &mut encryption.ct, &info).unwrap_err();
            }
        }
    }
}
