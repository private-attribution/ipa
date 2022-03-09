use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rust_elgamal::{DecryptionKey, EncryptionKey, Scalar, Ciphertext, GENERATOR_TABLE, RistrettoPoint};
use bls12_381::{G1Affine, G1Projective};

fn setup_encryption_keys(rng: &mut (impl RngCore + CryptoRng)) -> (DecryptionKey, EncryptionKey) {
    let dec_key = DecryptionKey::new(rng);
    let enc_key = dec_key.encryption_key();
    (dec_key, *enc_key)
}

fn encrypt(m: RistrettoPoint, enc_key: &EncryptionKey, rng: &mut (impl RngCore + CryptoRng)) -> Ciphertext {
    enc_key.encrypt(m, rng)
}

fn decrypt(cm: Ciphertext, dec_key: &DecryptionKey) -> RistrettoPoint {
    dec_key.decrypt(cm)
}

fn randomize(cm: Ciphertext, enc_key: &EncryptionKey, r: Scalar) -> Ciphertext {
    enc_key.rerandomise_with(cm, r)
}

#[derive(Copy, Clone, Hash)]
struct SigningKey {
    x0: Scalar,
    x1: Scalar
}

impl SigningKey {
    fn new(rng: &mut (impl RngCore + CryptoRng)) -> SigningKey {
        SigningKey{
            x0: Scalar::from(rng.next_u32()),
            x1: Scalar::from(rng.next_u32())
        }
    }
}

impl From<(Scalar, Scalar)> for SigningKey {
    fn from((x0, x1): (Scalar, Scalar)) -> Self {
        SigningKey{ x0, x1 }
    }
}

// fn setup_signing_keys() -> (SigningKey) {
// }

fn main() {
    let mut rng = StdRng::from_entropy();
    let (dec_key, enc_key) = setup_encryption_keys(&mut rng);
    let m = &Scalar::random() * &GENERATOR_TABLE;
    let cm = encrypt(m, &enc_key, &mut rng);

    let dec_m = decrypt(cm, &dec_key);
    assert_eq!(m, dec_m);
    println!("message encrypted successfully");


    let affine = G1Affine::generator();
    affine
}