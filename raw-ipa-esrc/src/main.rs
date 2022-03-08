use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rust_elgamal::{DecryptionKey, EncryptionKey, Scalar, Ciphertext, GENERATOR_TABLE, RistrettoPoint};

fn setup(rng: &mut (impl RngCore + CryptoRng)) -> (DecryptionKey, EncryptionKey) {
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

fn main() {
    let mut rng = StdRng::from_entropy();
    let (dec_key, enc_key) = setup(&mut rng);
    let m = &Scalar::from(rng.next_u64()) * &GENERATOR_TABLE;
    let cm = encrypt(m, &enc_key, &mut rng);
    let dec_m = decrypt(cm, &dec_key);
    assert_eq!(m, dec_m);
    println!("message encrypted successfully")
}