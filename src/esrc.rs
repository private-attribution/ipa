//! Implementation of [Efficient Signatures on Randomizable Ciphertexts](https://eprint.iacr.org/2020/524.pdf).
//!
//! In contrast with typical encryption, randomizable ciphertexts allow one to "randomize a
//! ciphertext so it is distributed like a fresh encryption of the same plaintext." Since the
//! ciphertext changes, any signature of the original ciphertext needs to "adapt" to the
//! randomization. The Esrc struct in this module implements:
//!
//! * encrypt: encryption of plaintext
//! * decrypt: decryption of ciphertext
//! * sign: signing of ciphertext
//! * randomize: randomization of ciphertext
//! * adapt: signature adaptation of randomized ciphertext
//! * verify: confirm ciphertext validity via its signature

#![allow(clippy::must_use_candidate)]

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand::{CryptoRng, RngCore};
use std::ops::Mul;

/// `DecryptionKey` represents a random scalar value
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct DecryptionKey(Scalar);
impl DecryptionKey {
    pub fn new(rng: &mut (impl RngCore + CryptoRng)) -> DecryptionKey {
        DecryptionKey(Scalar::from(rng.next_u64()))
    }
}
impl Mul<DecryptionKey> for &G1Projective {
    type Output = G1Projective;

    fn mul(self, rhs: DecryptionKey) -> Self::Output {
        self * rhs.0
    }
}
impl Mul<DecryptionKey> for G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: DecryptionKey) -> Self::Output {
        self * rhs.0
    }
}

/// `EncryptionKey` represents an elliptic curve point as generated via a decryption key
#[derive(Copy, Clone, Debug)]
struct EncryptionKey(G1Projective);
impl EncryptionKey {
    pub fn new(dec_key: DecryptionKey) -> EncryptionKey {
        let enc_key = G1Affine::generator() * dec_key;
        EncryptionKey(enc_key)
    }
}
impl Mul<Scalar> for EncryptionKey {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        self.0 * rhs
    }
}
impl From<EncryptionKey> for G1Affine {
    fn from(enc_key: EncryptionKey) -> Self {
        G1Affine::from(enc_key.0)
    }
}

/// `SigningKey` represents 2 random scalar values
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SigningKey(Scalar, Scalar);
impl SigningKey {
    fn new(rng: &mut (impl RngCore + CryptoRng)) -> SigningKey {
        let x0 = Scalar::from(rng.next_u64()).double();
        let x1 = Scalar::from(rng.next_u64()).double();
        SigningKey(x0, x1)
    }
}

/// `VerifyKey` represents 2 elliptic curve points on a paired elliptic curve, as generated via a
/// signing key
#[derive(Copy, Clone, Debug)]
struct VerifyKey(G2Projective, G2Projective);
impl VerifyKey {
    fn new(sign_key: SigningKey) -> VerifyKey {
        let SigningKey(x0, x1) = sign_key;
        let x_hat0 = G2Affine::generator() * x0;
        let x_hat1 = G2Affine::generator() * x1;
        VerifyKey(x_hat0, x_hat1)
    }
}

/// `CipherText` represents an encrypted message generated with an encryption key
#[derive(Copy, Clone, Debug)]
pub struct CipherText(G1Projective, G1Projective);

/// `Signature` represents a signature of a `CipherText` that can be used to verify the
/// `CipherText`'s authenticity
#[derive(Copy, Clone, Debug)]
pub struct Signature(G1Projective, G1Projective, G2Projective, G1Projective);

/// `Esrc` implements
/// [Efficient Signatures on Randomizable Ciphertexts](https://eprint.iacr.org/2020/524.pdf)
pub struct Esrc {
    dec_key: DecryptionKey,
    enc_key: EncryptionKey,
    sign_key: SigningKey,
    verify_key: VerifyKey,
}
impl Esrc {
    pub fn new(rng: &mut (impl RngCore + CryptoRng)) -> Esrc {
        let dec_key = DecryptionKey::new(rng);
        let enc_key = EncryptionKey::new(dec_key);

        let sign_key = SigningKey::new(rng);
        let verify_key = VerifyKey::new(sign_key);

        Esrc {
            dec_key,
            enc_key,
            sign_key,
            verify_key,
        }
    }

    /// encrypt a message
    pub fn encrypt(&self, rng: &mut (impl RngCore + CryptoRng), m: G1Affine) -> CipherText {
        let r = Scalar::from(rng.next_u64());
        let c0 = G1Affine::generator() * r;
        let c1 = m + (self.enc_key * r);
        CipherText(c0, c1)
    }

    /// decrypt a message
    pub fn decrypt(&self, cm: &CipherText) -> G1Affine {
        let CipherText(c0, c1) = cm;
        let dec = c1 - (c0 * self.dec_key);
        G1Affine::from(dec)
    }

    /// randomize an encrypted message
    pub fn randomize(&self, cm: &CipherText, r_prime: Scalar) -> CipherText {
        let CipherText(c0, c1) = cm;
        let rc0 = c0 + (G1Affine::generator() * r_prime);
        let rc1 = c1 + (self.enc_key * r_prime);
        CipherText(rc0, rc1)
    }

    fn rand_scalar_and_inverse(rng: &mut (impl RngCore + CryptoRng)) -> (Scalar, Scalar) {
        for _ in 0..10 {
            let s = Scalar::from(rng.next_u64());
            let inverted = s.invert();
            if inverted.is_some().into() {
                return (s, inverted.unwrap());
            }
        }
        panic!("rng was unable to generate a Scalar value that could be inverted")
    }

    /// sign an encrypted message
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), cm: &CipherText) -> Signature {
        let (scalar_s, scalar_s_inverted) = Esrc::rand_scalar_and_inverse(rng);
        let CipherText(c0, c1) = cm;
        let SigningKey(x0, x1) = self.sign_key;
        let z = (G1Affine::generator() + (c0 * x0) + (c1 * x1)) * scalar_s_inverted;
        let s = G1Affine::generator() * scalar_s;
        let s_hat = G2Affine::generator() * scalar_s;
        let t = ((G1Affine::generator() * x0) + (self.enc_key * x1)) * scalar_s_inverted;
        Signature(z, s, s_hat, t)
    }

    /// modify the original signature of an encrypted message to match the randomized encrypted message
    #[allow(clippy::unused_self)] // keep function signatures consistent
    pub fn adapt(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        signature: &Signature,
        r_prime: Scalar,
    ) -> Signature {
        let (scalar_s_prime, scalar_s_prime_inverted) = Esrc::rand_scalar_and_inverse(rng);
        let Signature(z, s, s_hat, t) = signature;

        let z_prime = (z + (t * r_prime)) * scalar_s_prime_inverted;
        let s_prime = s * scalar_s_prime;
        let s_hat_prime = s_hat * scalar_s_prime;
        let t_prime = t * scalar_s_prime_inverted;
        Signature(z_prime, s_prime, s_hat_prime, t_prime)
    }

    /// confirm encrypted message validity via its signature
    #[allow(clippy::similar_names)] // g_g_hat_pair and g_s_hat_pair
    pub fn verify(&self, cm: &CipherText, signature: &Signature) -> bool {
        let Signature(z, s, s_hat, t) = signature;
        let CipherText(c0, c1) = cm;
        let VerifyKey(x_hat0, x_hat1) = self.verify_key;

        let z_s_hat_pair = pairing(&G1Affine::from(z), &G2Affine::from(s_hat));
        let g_g_hat_pair = pairing(&G1Affine::generator(), &G2Affine::generator());
        let c0_x_hat0_pair = pairing(&G1Affine::from(c0), &G2Affine::from(x_hat0));
        let c1_x_hat1_pair = pairing(&G1Affine::from(c1), &G2Affine::from(x_hat1));
        if z_s_hat_pair != g_g_hat_pair + c0_x_hat0_pair + c1_x_hat1_pair {
            return false;
        }

        let t_s_hat_pair = pairing(&G1Affine::from(t), &G2Affine::from(s_hat));
        let g_x_hat0_pair = pairing(&G1Affine::generator(), &G2Affine::from(x_hat0));
        let enc_key_x_hat1_pair = pairing(&G1Affine::from(self.enc_key), &G2Affine::from(x_hat1));
        if t_s_hat_pair != g_x_hat0_pair + enc_key_x_hat1_pair {
            return false;
        }

        let g_s_hat_pair = pairing(&G1Affine::generator(), &G2Affine::from(s_hat));
        let s_g_hat_pair = pairing(&G1Affine::from(s), &G2Affine::generator());
        if g_s_hat_pair != s_g_hat_pair {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_enc_dec() {
        let mut rng = StdRng::from_entropy();
        let esrc = Esrc::new(&mut rng);

        // the message to encrypt
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // encrypt then decrypt
        let enc_m = esrc.encrypt(&mut rng, m);
        let dec_m = esrc.decrypt(&enc_m);
        assert_eq!(m, dec_m);
    }

    #[test]
    fn test_enc_randomize_verify() {
        let mut rng = StdRng::from_entropy();
        let e = Esrc::new(&mut rng);

        // the message to rerandomize
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // initial encryption and signing
        let cm = e.encrypt(&mut rng, m);
        let signature = e.sign(&mut rng, &cm);

        // rerandomize
        let r_prime = Scalar::from(rng.next_u64());
        let r_cm = e.randomize(&cm, r_prime);
        let r_signature = e.adapt(&mut rng, &signature, r_prime);

        // verify
        assert!(e.verify(&r_cm, &r_signature));
        assert!(!e.verify(&r_cm, &signature));
        assert_eq!(e.decrypt(&r_cm), m);
    }
}
