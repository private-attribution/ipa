//! Provides decryption primitives for HPKE according to the [`specification`].
//!
//! [`specification`]: https://github.com/patcg-individual-drafts/ipa/pull/31

use hpke::aead::AeadTag;
use hpke::{single_shot_open_in_place_detached, Deserializable, OpModeR};
use std::{fmt, io};

mod aad;
mod registry;

pub use aad::AssociatedData;
pub use registry::KeyRegistry;

/// IPA ciphersuite
type IpaKem = hpke::kem::X25519HkdfSha256;
type IpaAead = hpke::aead::AesGcm128;
type IpaKdf = hpke::kdf::HkdfSha256;

pub type KeyIdentifier = u8;
pub type Epoch = u16;
type IpaPublicKey = <IpaKem as hpke::kem::Kem>::PublicKey;
type IpaPrivateKey = <IpaKem as hpke::kem::Kem>::PrivateKey;

#[derive(Debug)]
pub struct BottomError;

impl From<hpke::HpkeError> for BottomError {
    fn from(_value: hpke::HpkeError) -> Self {
        Self
    }
}

impl From<io::Error> for BottomError {
    fn from(_value: io::Error) -> Self {
        Self
    }
}

impl fmt::Display for BottomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to open ciphertext")
    }
}

/// Opens ciphertext in place by first obtaining the secret key from [`key_registry`]
/// using epoch and key from [`aad`] and then applying [`HPKE decryption`] to the provided ciphertext.
///
/// ## Errors
/// If ciphertext cannot be opened for any reason.
///
/// [`HPKE decryption`]: https://datatracker.ietf.org/doc/html/rfc9180#name-encryption-and-decryption
pub fn open_in_place(
    key_registry: &KeyRegistry,
    encap_key: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8],
    aad: &AssociatedData,
) -> Result<(), BottomError> {
    //TODO: log errors, but don't return them
    let info = aad.to_bytes();
    let encap_key = <IpaKem as hpke::Kem>::EncappedKey::from_bytes(encap_key)?;
    let tag = AeadTag::<IpaAead>::from_bytes(tag)?;
    let sk = key_registry.private_key(aad.epoch(), aad.key_id());

    Ok(single_shot_open_in_place_detached::<_, IpaKdf, IpaKem>(
        &OpModeR::Base,
        sk,
        &encap_key,
        &info,
        ciphertext,
        &[],
        &tag,
    )?)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::secret_sharing::XorReplicated;

    use hpke::{single_shot_seal_in_place_detached, OpModeS, Serializable};
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    use crate::crypto::hpke::aad::{HelperOrigin, SiteOrigin};

    #[derive(Clone)]
    struct MatchKeyEncryption {
        encap_key: [u8; 32],
        ct: Box<[u8]>,
        tag: [u8; 16],
    }

    struct EncryptionSuite<R: RngCore + CryptoRng> {
        registry: KeyRegistry,
        rng: R,
        epoch: Epoch,
    }

    impl<R: RngCore + CryptoRng> EncryptionSuite<R> {
        const HELPER_ORIGIN: HelperOrigin<'static> = HelperOrigin("foo");
        const SITE_ORIGIN: SiteOrigin<'static> = SiteOrigin("bar");

        pub fn new(keys_per_epoch: usize, mut rng: R) -> Self {
            Self {
                registry: KeyRegistry::random(4, keys_per_epoch, &mut rng),
                rng,
                epoch: 0,
            }
        }

        #[must_use]
        pub fn seal(
            &mut self,
            key_id: KeyIdentifier,
            match_key: XorReplicated,
        ) -> MatchKeyEncryption {
            let aad =
                AssociatedData::new(key_id, self.epoch, &Self::HELPER_ORIGIN, &Self::SITE_ORIGIN)
                    .unwrap();
            let info = aad.to_bytes();
            let mut plaintext = [0_u8; 16];
            match_key.serialize(&mut plaintext).unwrap();
            let pk_r = self.registry.public_key(self.epoch, key_id);

            let (encap_key, tag) =
                single_shot_seal_in_place_detached::<IpaAead, super::IpaKdf, super::IpaKem, _>(
                    &OpModeS::Base,
                    pk_r,
                    &info,
                    &mut plaintext,
                    &[],
                    &mut self.rng,
                )
                .unwrap();

            MatchKeyEncryption {
                encap_key: <[u8; 32]>::from(encap_key.to_bytes()),
                ct: Box::new(plaintext),
                tag: <[u8; 16]>::from(tag.to_bytes()),
            }
        }

        pub fn open(
            &self,
            key_id: KeyIdentifier,
            mut enc: MatchKeyEncryption,
        ) -> Result<XorReplicated, BottomError> {
            let aad =
                AssociatedData::new(key_id, self.epoch, &Self::HELPER_ORIGIN, &Self::SITE_ORIGIN)
                    .unwrap();
            open_in_place(
                &self.registry,
                &enc.encap_key,
                enc.ct.as_mut(),
                &enc.tag,
                &aad,
            )?;

            Ok(XorReplicated::deserialize(enc.ct.as_ref())?)
        }

        pub fn advance_epoch(&mut self) {
            self.epoch += 1;
        }
    }

    /// Make sure we obey the spec
    #[test]
    fn ipa_info_serialize() {
        let aad =
            AssociatedData::new(255, 32767, &HelperOrigin("foo"), &SiteOrigin("bar")).unwrap();
        assert_eq!(
            b"private-attributionfoo\0bar\0\xff\x7f\xff",
            aad.to_bytes().as_ref()
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

    mod proptests {
        use super::*;
        use proptest::prelude::ProptestConfig;

        proptest::proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]
            #[test]
            fn arbitrary_corruption(bad_byte in 0..15_usize, bad_bit in 0..7_usize, seed: [u8; 32]) {
                let rng = StdRng::from_seed(seed);
                let mut suite = EncryptionSuite::new(1, rng);
                let enc = suite.seal(0, XorReplicated::new(0, 0));

                // corrupt the ciphertext
                let mut ct_corruption = enc.clone();
                ct_corruption.ct.as_mut()[bad_byte] ^= 1 << bad_bit;
                let _ = suite.open(0, ct_corruption).unwrap_err();

                // corrupt the tag
                let mut tag_corruption = enc;
                tag_corruption.tag[bad_byte] ^= 1 << bad_bit;
                let _ = suite.open(0, tag_corruption).unwrap_err();
            }
        }
    }
}
