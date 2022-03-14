use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand::{CryptoRng, RngCore, SeedableRng};
use std::ops::Mul;

#[derive(Copy, Clone, Debug)]
struct EncryptionKey(G1Projective);
impl Mul<Scalar> for &EncryptionKey {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> Self::Output {
        self.0 * rhs
    }
}
impl From<&EncryptionKey> for G1Affine {
    fn from(enc_key: &EncryptionKey) -> Self {
        G1Affine::from(enc_key.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct DecryptionKey(Scalar);
impl Mul<&DecryptionKey> for &G1Projective {
    type Output = G1Projective;

    fn mul(self, rhs: &DecryptionKey) -> Self::Output {
        self * rhs.0
    }
}

#[derive(Copy, Clone, Debug)]
struct CipherText(G1Projective, G1Projective);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SigningKey(Scalar, Scalar);
#[derive(Copy, Clone, Debug)]
struct VerifyKey(G2Projective, G2Projective);
#[derive(Copy, Clone, Debug)]
struct Signature(G1Projective, G1Projective, G2Projective, G1Projective);

fn setup_encryption_keys(rng: &mut (impl RngCore + CryptoRng)) -> (EncryptionKey, DecryptionKey) {
    let dec_key = Scalar::from(rng.next_u64());
    let enc_key = G1Affine::generator() * dec_key;
    (EncryptionKey(enc_key), DecryptionKey(dec_key))
}

fn setup_signing_keys(rng: &mut (impl RngCore + CryptoRng)) -> (SigningKey, VerifyKey) {
    let x0 = Scalar::from(rng.next_u64()).double();
    let x1 = Scalar::from(rng.next_u64()).double();
    let x_hat0 = G2Affine::generator() * x0;
    let x_hat1 = G2Affine::generator() * x1;
    (SigningKey(x0, x1), VerifyKey(x_hat0, x_hat1))
}

fn encrypt(
    rng: &mut (impl RngCore + CryptoRng),
    m: G1Affine,
    enc_key: &EncryptionKey,
) -> CipherText {
    let r = Scalar::from(rng.next_u64());
    let c0 = G1Affine::generator() * r;
    let c1 = m + (enc_key * r);
    CipherText(c0, c1)
}

fn decrypt(cm: &CipherText, dec_key: &DecryptionKey) -> G1Affine {
    let CipherText(c0, c1) = cm;
    let dec = c1 - (c0 * dec_key);
    G1Affine::from(dec)
}

fn randomize(cm: &CipherText, enc_key: &EncryptionKey, r_prime: Scalar) -> CipherText {
    let CipherText(c0, c1) = cm;
    let rc0 = c0 + (G1Affine::generator() * r_prime);
    let rc1 = c1 + (enc_key * r_prime);
    CipherText(rc0, rc1)
}

fn sign(
    rng: &mut (impl RngCore + CryptoRng),
    cm: &CipherText,
    enc_key: &EncryptionKey,
    sign_key: SigningKey,
) -> Signature {
    let scalar_s = Scalar::from(rng.next_u64());
    let scalar_s_inverted = scalar_s.invert().unwrap(); // TODO: how to handle?
    let CipherText(c0, c1) = cm;
    let SigningKey(x0, x1) = sign_key;
    let z = (G1Affine::generator() + (c0 * x0) + (c1 * x1)) * scalar_s_inverted;
    let s = G1Affine::generator() * scalar_s;
    let s_hat = G2Affine::generator() * scalar_s;
    let t = ((G1Affine::generator() * x0) + (enc_key * x1)) * scalar_s_inverted;
    Signature(z, s, s_hat, t)
}

fn adapt(
    rng: &mut (impl RngCore + CryptoRng),
    signature: &Signature,
    r_prime: Scalar,
) -> Signature {
    let scalar_s_prime = Scalar::from(rng.next_u64());
    let scalar_s_prime_inverted = scalar_s_prime.invert().unwrap(); // TODO: how to handle?
    let Signature(z, s, s_hat, t) = signature;

    let z_prime = (z + (t * r_prime)) * scalar_s_prime_inverted;
    let s_prime = s * scalar_s_prime;
    let s_hat_prime = s_hat * scalar_s_prime;
    let t_prime = t * scalar_s_prime_inverted;
    Signature(z_prime, s_prime, s_hat_prime, t_prime)
}

fn verify(
    verify_key: &VerifyKey,
    enc_key: &EncryptionKey,
    cm: &CipherText,
    signature: &Signature,
) -> bool {
    let Signature(z, s, s_hat, t) = signature;
    let CipherText(c0, c1) = cm;
    let VerifyKey(x_hat0, x_hat1) = verify_key;

    let z_s_pair = pairing(&G1Affine::from(z), &G2Affine::from(s_hat));
    let g_g_hat_pair = pairing(&G1Affine::generator(), &G2Affine::generator());
    let c0_x_hat0_pair = pairing(&G1Affine::from(c0), &G2Affine::from(x_hat0));
    let c1_x_hat1_pair = pairing(&G1Affine::from(c1), &G2Affine::from(x_hat1));
    if z_s_pair != g_g_hat_pair + c0_x_hat0_pair + c1_x_hat1_pair {
        return false;
    }

    let t_s_hat_pair = pairing(&G1Affine::from(t), &G2Affine::from(s_hat));
    let g_x_hat0_pair = pairing(&G1Affine::generator(), &G2Affine::from(x_hat0));
    let enc_key_x_hat1_pair = pairing(&G1Affine::from(enc_key), &G2Affine::from(x_hat1));
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
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;

    #[test]
    fn test_enc_dec() {
        let mut rng = StdRng::from_entropy();
        let (enc_key, dec_key) = setup_encryption_keys(&mut rng);

        // the message to encrypt
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // encrypt then decrypt
        let enc_m = encrypt(&mut rng, m, &enc_key);
        let dec_m = decrypt(&enc_m, &dec_key);
        assert_eq!(m, dec_m);
    }

    #[test]
    fn test_enc_randomize_verify() {
        let mut rng = StdRng::from_entropy();
        let (enc_key, dec_key) = setup_encryption_keys(&mut rng);
        let (sign_key, verify_key) = setup_signing_keys(&mut rng);

        // the message to transfer
        let m = G1Affine::from(G1Affine::generator() * Scalar::from(rng.next_u64()));

        // initial encryption and signing
        let enc_m = encrypt(&mut rng, m, &enc_key);
        let signature = sign(&mut rng, &enc_m, &enc_key, sign_key);

        // rerandomize
        let r_prime = Scalar::from(rng.next_u64());
        let r_enc_m = randomize(&enc_m, &enc_key, r_prime);
        let r_signature = adapt(&mut rng, &signature, r_prime);

        // verify
        assert!(verify(&verify_key, &enc_key, &r_enc_m, &r_signature));
        assert!(!verify(&verify_key, &enc_key, &r_enc_m, &signature));
        assert_eq!(decrypt(&r_enc_m, &dec_key), m);
    }
}
