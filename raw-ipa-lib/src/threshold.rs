use hex::encode as hex;
use rand_core::{CryptoRng, RngCore};
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, RistrettoPoint};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

pub struct ThresholdEncryptionKey(EncryptionKey);

impl ThresholdEncryptionKey {
    pub fn new(k1: &EncryptionKey, k2: &EncryptionKey) -> Self {
        Self(EncryptionKey::from(k1.as_ref() + k2.as_ref()))
    }
}

impl Deref for ThresholdEncryptionKey {
    type Target = EncryptionKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for ThresholdEncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ThresholdEncryptionKey ")?;
        f.write_str(&hex(self.as_ref().compress().as_bytes()))
    }
}

pub struct ThresholdDecryptionKey(DecryptionKey);

impl ThresholdDecryptionKey {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(DecryptionKey::new(rng))
    }

    pub fn threshold_decrypt(&self, c: Ciphertext) -> Ciphertext {
        let (c0, _) = c.inner();
        let p = self.0.decrypt(c);
        Ciphertext::from((c0, p))
    }

    pub fn decrypt(&self, c: Ciphertext) -> RistrettoPoint {
        self.0.decrypt(c)
    }

    pub fn encryption_key(&self) -> &EncryptionKey {
        self.0.encryption_key()
    }
}

impl From<DecryptionKey> for ThresholdDecryptionKey {
    fn from(k: DecryptionKey) -> Self {
        Self(k)
    }
}

impl Debug for ThresholdDecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("ThresholdDecryptionKey ")?;
        f.write_str(&hex(self.0.as_ref().to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ThresholdDecryptionKey, ThresholdEncryptionKey};
    use hex::encode as hex;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rust_elgamal::{Ciphertext, RistrettoPoint, Scalar};

    fn dump_c(n: &str, c: &Ciphertext) {
        let (c0, c1) = c.inner();
        println!(
            "{}: {} {}",
            n,
            hex(c0.compress().as_bytes()),
            hex(c1.compress().as_bytes()),
        );
    }

    fn dump_p(n: &str, p: &RistrettoPoint) {
        println!("{}: {}", n, hex(p.compress().as_bytes()));
    }

    fn dump_s(n: &str, s: &Scalar) {
        println!("{}: {}", n, hex(s.to_bytes()));
    }

    #[test]
    fn threshold_encrypt() {
        let mut rng = StdRng::from_entropy();
        let k1 = ThresholdDecryptionKey::new(&mut rng);
        dump_s("k1", k1.0.as_ref());
        let k2 = ThresholdDecryptionKey::new(&mut rng);
        dump_s("k2", k2.0.as_ref());

        let m = RistrettoPoint::random(&mut rng);
        dump_p("m", &m);

        let r = Scalar::random(&mut rng);
        dump_s("r", &r);

        let c1 = k1.encryption_key().encrypt_with(m, r);
        dump_c("c1", &c1);
        let c1_m = c1.inner().1 - m;
        dump_p("c1 - m", &c1_m);
        let c2 = k2.0.encryption_key().encrypt_with(m, r);
        dump_c("c2", &c2);
        let c2_m = c2.inner().1 - m;
        dump_p("c2 - m", &c2_m);

        assert_eq!(c1.inner().0, c2.inner().0);

        let c1_2 = c1.inner().1 + r * k2.encryption_key().as_ref();
        dump_p("c1_2", &c1_2);
        let c2_1 = c2.inner().1 + r * k1.encryption_key().as_ref();
        dump_p("c2_1", &c2_1);

        // Now try the threshold encryption.
        let tk = ThresholdEncryptionKey::new(k1.encryption_key(), k2.encryption_key());
        dump_p("tk", tk.as_ref());

        let c = tk.encrypt_with(m, r);
        dump_c("c", &c);

        let p = k1.threshold_decrypt(c);
        dump_c("p", &p);

        let m_out = k2.decrypt(p);
        dump_p("out", &m_out);
        assert_eq!(m.compress(), m_out.compress());
    }
}
