//! Provides decryption primitives for HPKE according to the [`specification`].
//!
//! [`specification`]: https://github.com/patcg-individual-drafts/ipa/pull/31

use hpke::aead::AeadTag;
use hpke::generic_array::typenum::Unsigned;
use hpke::{single_shot_open_in_place_detached, OpModeR};
use std::io;

mod aad;
mod registry;

use crate::secret_sharing::XorReplicated;
pub use aad::Info;
pub use registry::KeyRegistry;

/// IPA ciphersuite
type IpaKem = hpke::kem::X25519HkdfSha256;
type IpaAead = hpke::aead::AesGcm128;
type IpaKdf = hpke::kdf::HkdfSha256;

pub type KeyIdentifier = u8;
/// Event epoch as described [`ipa-spec`]
/// For the purposes of this module, epochs are used to authenticate match key encryption. As
/// report collectors may submit queries with events spread across multiple epochs, decryption context
/// needs to know which epoch to use for each individual event.
///
/// [`ipa-spec`]: https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#other-key-terms
pub type Epoch = u16;
type IpaPublicKey = <IpaKem as hpke::kem::Kem>::PublicKey;
type IpaPrivateKey = <IpaKem as hpke::kem::Kem>::PrivateKey;

/// Total len in bytes for an encrypted matchkey including the authentication tag.
pub const MATCHKEY_CT_LEN: usize = <XorReplicated as crate::bits::Serializable>::SIZE_IN_BYTES
    + <AeadTag<IpaAead> as hpke::Serializable>::OutputSize::USIZE;

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("Unknown key {0}")]
    NoSuchKey(KeyIdentifier),
    #[error("Failed to open ciphertext")]
    Other,
}

impl From<hpke::HpkeError> for DecryptionError {
    fn from(_value: hpke::HpkeError) -> Self {
        Self::Other
    }
}

impl From<io::Error> for DecryptionError {
    fn from(_value: io::Error) -> Self {
        Self::Other
    }
}

/// Opens the given ciphertext in place by first obtaining the secret key from [`key_registry`]
/// using epoch and key from [`info`] and then applying [`HPKE decryption`] to the provided ciphertext.
///
/// This function mutates the provided ciphertext slice and replaces it with the plaintext obtained
/// after opening the ciphertext. The result will contain a pointer to the plaintext slice.
/// of the plaintext. Note that if the ciphertext slice does not include authentication tag, decryption
/// will fail.
///
/// ## Errors
/// If ciphertext cannot be opened for any reason.
///
/// [`HPKE decryption`]: https://datatracker.ietf.org/doc/html/rfc9180#name-encryption-and-decryption
pub fn open_in_place<'a>(
    key_registry: &KeyRegistry,
    enc: &[u8],
    ciphertext: &'a mut [u8],
    info: Info,
) -> Result<&'a [u8], DecryptionError> {
    use hpke::{Deserializable, Serializable};

    let key_id = info.key_id;
    let info = info.into_bytes();
    let encap_key = <IpaKem as hpke::Kem>::EncappedKey::from_bytes(enc)?;
    let (ct, tag) = ciphertext.split_at_mut(ciphertext.len() - AeadTag::<IpaAead>::size());
    let tag = AeadTag::<IpaAead>::from_bytes(tag)?;
    let sk = key_registry
        .private_key(key_id)
        .ok_or(DecryptionError::NoSuchKey(key_id))?;

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

/// Represents an encrypted share of single match key.
#[derive(Clone)]
// temporarily to appease clippy while we don't have actual consumers of this struct
#[cfg(all(test, not(feature = "shuttle")))]
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::secret_sharing::XorReplicated;

    use crate::bits::Serializable;
    use hpke::{single_shot_seal_in_place_detached, OpModeS};
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    struct EncryptionSuite<R: RngCore + CryptoRng> {
        registry: KeyRegistry,
        rng: R,
        epoch: Epoch,
    }

    impl<R: RngCore + CryptoRng> EncryptionSuite<R> {
        const HELPER_ORIGIN: &'static str = "foo";
        const SITE_ORIGIN: &'static str = "bar";

        pub fn new(keys: usize, mut rng: R) -> Self {
            Self {
                registry: KeyRegistry::random(keys, &mut rng),
                rng,
                epoch: 0,
            }
        }

        #[must_use]
        pub fn seal(
            &mut self,
            key_id: KeyIdentifier,
            match_key: XorReplicated,
        ) -> MatchKeyEncryption<'static> {
            let info =
                Info::new(key_id, self.epoch, Self::HELPER_ORIGIN, Self::SITE_ORIGIN).unwrap();
            let mut plaintext = [0_u8; 16];

            match_key.serialize(&mut plaintext).unwrap();
            let pk_r = self.registry.public_key(key_id).unwrap();

            let (encap_key, tag) =
                single_shot_seal_in_place_detached::<IpaAead, super::IpaKdf, super::IpaKem, _>(
                    &OpModeS::Base,
                    pk_r,
                    &info.clone().into_bytes(),
                    &mut plaintext,
                    &[],
                    &mut self.rng,
                )
                .unwrap();

            let mut ct = [0u8; MATCHKEY_CT_LEN];
            ct[..16].copy_from_slice(&plaintext);
            ct[16..].copy_from_slice(&hpke::Serializable::to_bytes(&tag));
            MatchKeyEncryption {
                enc: <[u8; 32]>::from(hpke::Serializable::to_bytes(&encap_key)),
                ct,
                info,
            }
        }

        pub fn open(
            &self,
            key_id: KeyIdentifier,
            mut enc: MatchKeyEncryption<'_>,
        ) -> Result<XorReplicated, DecryptionError> {
            let info =
                Info::new(key_id, self.epoch, Self::HELPER_ORIGIN, Self::SITE_ORIGIN).unwrap();
            open_in_place(&self.registry, &enc.enc, enc.ct.as_mut(), info)?;

            Ok(XorReplicated::deserialize(enc.ct.as_ref())?)
        }

        pub fn advance_epoch(&mut self) {
            self.epoch += 1;
        }
    }

    /// Make sure we obey the spec
    #[test]
    fn ipa_info_serialize() {
        let aad = Info::new(255, 32767, "foo", "bar").unwrap();
        assert_eq!(
            b"private-attribution\0foo\0bar\0\xff\x7f\xff",
            aad.into_bytes().as_ref()
        );
    }

    #[test]
    fn decrypt_happy_case() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = XorReplicated::new(u64::MAX, u64::MAX / 2);

        let enc = suite.seal(0, match_key);
        let r = suite.open(0, enc).unwrap();

        assert_eq!(match_key, r);
    }

    #[test]
    fn decrypt_wrong_aad() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = XorReplicated::new(u64::MAX, u64::MAX / 2);
        let enc = suite.seal(0, match_key);
        suite.advance_epoch();

        let _ = suite.open(0, enc).unwrap_err();
    }

    #[test]
    fn decrypt_wrong_key() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(10, rng);
        let match_key = XorReplicated::new(u64::MAX, u64::MAX / 2);
        let enc = suite.seal(0, match_key);
        let _ = suite.open(1, enc).unwrap_err();
    }

    #[test]
    fn decrypt_unknown_key() {
        let rng = StdRng::from_seed([1_u8; 32]);
        let mut suite = EncryptionSuite::new(1, rng);
        let match_key = XorReplicated::new(u64::MAX, u64::MAX / 2);
        let enc = suite.seal(0, match_key);

        assert!(matches!(
            suite.open(1, enc),
            Err(DecryptionError::NoSuchKey(1))
        ));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::ProptestConfig;
        use rand::Rng;

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_ct_corruption(bad_byte in 0..23_usize, bad_bit in 0..7_usize, seed: [u8; 32]) {
                let rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(1, rng);
                let mut encryption = suite.seal(0, XorReplicated::new(0, 0));

                encryption.ct.as_mut()[bad_byte] ^= 1 << bad_bit;
                let _ = suite.open(0, encryption).unwrap_err();
            }
        }

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_enc_corruption(bad_byte in 0..32_usize, bad_bit in 0..7_usize, seed: [u8; 32]) {
                let rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(1, rng);
                let mut encryption = suite.seal(0, XorReplicated::new(0, 0));

                encryption.enc.as_mut()[bad_byte] ^= 1 << bad_bit;
                let _ = suite.open(0, encryption).unwrap_err();
            }
        }

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_info_corruption(corrupted_info_field in 1..4, seed: [u8; 32]) {
                let mut rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(10, rng.clone());
                let mut encryption = suite.seal(0, XorReplicated::new(0, 0));

                let mut site_origin = EncryptionSuite::<StdRng>::SITE_ORIGIN.to_owned();
                let mut helper_origin = EncryptionSuite::<StdRng>::HELPER_ORIGIN.to_owned();

                let info = match corrupted_info_field {
                    1 => Info {
                        key_id: encryption.info.key_id + 1,
                        ..encryption.info
                    },
                    2 => Info {
                        epoch: encryption.info.epoch + 1,
                        ..encryption.info
                    },
                    3 => {
                        let idx = rng.gen_range(0..site_origin.len());
                        site_origin.remove(idx);

                        Info {
                            site_origin: site_origin.as_ref(),
                            ..encryption.info
                        }
                    },
                    4 => {
                        let idx = rng.gen_range(0..helper_origin.len());
                        helper_origin.remove(idx);

                        Info {
                            helper_origin: helper_origin.as_ref(),
                            ..encryption.info
                        }
                    }
                    _ => panic!("bad test setup: only 4 fields can be corrupted, asked to corrupt: {corrupted_info_field}")
                };

                let _ = open_in_place(&suite.registry, &encryption.enc, &mut encryption.ct, info).unwrap_err();
            }
        }
    }
}
