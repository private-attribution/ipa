use hex::encode as hex;
use rand_core::{CryptoRng, RngCore};
pub use rust_elgamal::{Ciphertext, DecryptionKey as DKey, EncryptionKey as EKey, RistrettoPoint};
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct EncryptionKey(EKey);

impl EncryptionKey {
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = impl AsRef<RistrettoPoint>>) -> Self {
        Self(EKey::from(
            keys.into_iter()
                .map(|k| *k.as_ref())
                .sum::<RistrettoPoint>(),
        ))
    }
}

impl Deref for EncryptionKey {
    type Target = EKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncryptionKey ")?;
        f.write_str(&hex(self.as_ref().compress().as_bytes()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct DecryptionKey(DKey);

impl DecryptionKey {
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(DKey::new(rng))
    }

    #[must_use]
    pub fn threshold_decrypt(&self, c: Ciphertext) -> Ciphertext {
        let (c0, _) = c.inner();
        let p = self.0.decrypt(c);
        Ciphertext::from((c0, p))
    }

    #[must_use]
    pub fn decrypt(&self, c: Ciphertext) -> RistrettoPoint {
        self.0.decrypt(c)
    }

    #[must_use]
    pub fn encryption_key(&self) -> EKey {
        *self.0.encryption_key()
    }
}

impl From<DKey> for DecryptionKey {
    fn from(k: DKey) -> Self {
        Self(k)
    }
}

impl Debug for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("DecryptionKey ")?;
        f.write_str(&hex(self.0.as_ref().to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptionKey, EncryptionKey};
    use hex::encode as hex;
    use rand::thread_rng;
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
    fn encrypt_decrypt() {
        let mut rng = thread_rng();
        let k1 = DecryptionKey::new(&mut rng);
        dump_s("k1", k1.0.as_ref());
        let k2 = DecryptionKey::new(&mut rng);
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

        // Now try the  encryption.
        let tk = EncryptionKey::new(&[k1.encryption_key(), k2.encryption_key()]);
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
