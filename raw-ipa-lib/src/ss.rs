use curve25519_dalek_ng::constants;
use rand::thread_rng;
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, RistrettoPoint, Scalar};

#[derive(Clone)]
pub struct GeneratorShare {
    p: RistrettoPoint,
}

#[derive(Clone)]
pub struct EncryptedGeneratorShare {
    c: Ciphertext,
}

impl GeneratorShare {
    #[must_use]
    pub fn share(value: u8) -> (Self, Self) {
        let mut rng = thread_rng();
        let v = Scalar::from(value);
        let mapped_value = &v * &constants::RISTRETTO_BASEPOINT_TABLE;
        let ss1 = RistrettoPoint::random(&mut rng);
        let ss2 = mapped_value - ss1;
        (Self { p: ss1 }, Self { p: ss2 })
    }

    #[must_use]
    pub fn encrypt(&self, ek: &EncryptionKey) -> EncryptedGeneratorShare {
        let mut rng = thread_rng();

        let r = Scalar::random(&mut rng);
        EncryptedGeneratorShare {
            c: ek.encrypt_with(self.p, r),
        }
    }

    #[must_use]
    pub fn pt(&self) -> RistrettoPoint {
        self.p
    }

    /// # Panics
    /// If this point does not correspond to a value between 1 and 1000 (inclusive)
    #[must_use]
    pub fn map_point_to_value(r: &RistrettoPoint) -> u32 {
        let mut i = 1;
        while i <= 1000 {
            let query = &Scalar::from(i) * &constants::RISTRETTO_BASEPOINT_TABLE;
            if query.eq(r) {
                return i;
            }
            i += 1;
        }
        panic!("point does not map to a value between 1 and 1000");
    }
}

impl EncryptedGeneratorShare {
    #[must_use]
    pub fn add_ciphertext(&self, offset: Ciphertext) -> EncryptedGeneratorShare {
        EncryptedGeneratorShare { c: self.c + offset }
    }

    #[must_use]
    pub fn decrypt(&self, dek: &DecryptionKey) -> GeneratorShare {
        GeneratorShare {
            p: dek.decrypt(self.c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptedGeneratorShare, GeneratorShare};
    use rand::thread_rng;
    use rust_elgamal::{DecryptionKey, RistrettoPoint, Scalar};

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn encrypt_scramble_decrypt() {
        let mut rng = thread_rng();

        // Generate random encryption / decryption keys for
        // Helper Nodes 3 and 4
        let helper3_dek = DecryptionKey::new(&mut rng);
        let helper3_ek = helper3_dek.encryption_key();
        let helper4_dek = DecryptionKey::new(&mut rng);
        let helper4_ek = helper4_dek.encryption_key();

        // The original trigger value
        let trigger_value: u8 = 16;

        // First, the client splits it into two secret shares
        let (ss1, ss2) = GeneratorShare::share(trigger_value);

        // Next, the client encrypts the first towards H3
        let enc_ss1 = ss1.encrypt(helper3_ek);
        // ...and the second towards H4
        let enc_ss2 = ss2.encrypt(helper4_ek);

        // The first helper to receive the trigger event is H2
        // It homomorphically adds / subtracts a random value to
        // The two secret shares
        let random_scramble = RistrettoPoint::random(&mut rng);
        let scrambled_enc_ss1 = enc_ss1
            .add_ciphertext(helper3_ek.encrypt_with(random_scramble, Scalar::random(&mut rng)));
        let scrambled_enc_ss2 = enc_ss2
            .add_ciphertext(helper4_ek.encrypt_with(-random_scramble, Scalar::random(&mut rng)));

        // The second helper to receive the trigger event is H1
        // It may need to scramble the shares as well
        let random_scramble_2 = RistrettoPoint::random(&mut rng);
        let double_scrambled_enc_ss1 = scrambled_enc_ss1
            .add_ciphertext(helper3_ek.encrypt_with(random_scramble_2, Scalar::random(&mut rng)));
        let double_scrambled_enc_ss2 = scrambled_enc_ss2
            .add_ciphertext(helper4_ek.encrypt_with(-random_scramble_2, Scalar::random(&mut rng)));

        // Eventually, H3 and H4 receive these events and decrypt them
        let double_scrambled_ss1 = double_scrambled_enc_ss1.decrypt(&helper3_dek);
        let double_scrambled_ss2 = double_scrambled_enc_ss2.decrypt(&helper4_dek);

        // If these points are added together...
        // ...they should be equivalent to the original secret shared value
        let sum = double_scrambled_ss1.pt() + double_scrambled_ss2.pt();
        assert_eq!(
            GeneratorShare::map_point_to_value(&sum),
            u32::from(trigger_value),
        );
    }

    #[allow(clippy::similar_names)] // deal with it.
    #[test]
    fn batch_sum() {
        let mut rng = thread_rng();

        // Generate random encryption / decryption keys for
        // Helper Nodes 3 and 4
        let helper3_dek = DecryptionKey::new(&mut rng);
        let helper3_ek = helper3_dek.encryption_key();
        let helper4_dek = DecryptionKey::new(&mut rng);
        let helper4_ek = helper4_dek.encryption_key();

        // Assume there are 10 trigger events which are attributed to
        // source events. We want to compute the sum of these trigger values
        let trigger_values: [u8; 10] = [1, 4, 9, 3, 7, 9, 1, 10, 14, 7];
        let correct_sum: u32 = trigger_values.iter().map(|x| u32::from(*x)).sum();

        // First, the client splits each trigger value into two secret shares
        // encrypting one towards H3 and one towards H4
        let trigger_events: Vec<(EncryptedGeneratorShare, EncryptedGeneratorShare)> =
            trigger_values
                .iter()
                .map(|x| {
                    let (ss1, ss2) = GeneratorShare::share(*x);
                    (ss1.encrypt(helper3_ek), ss2.encrypt(helper4_ek))
                })
                .collect();

        // H2 receives these events and "scrambles" them, by adding a random
        // Ristretto Point to the first, and subtracting it from the second
        let scrambled_trigger_events: Vec<(EncryptedGeneratorShare, EncryptedGeneratorShare)> =
            trigger_events
                .iter()
                .map(|(ss1, ss2)| {
                    let random_scramble = RistrettoPoint::random(&mut rng);
                    let scrambled_ss1 = ss1.add_ciphertext(
                        helper3_ek.encrypt_with(random_scramble, Scalar::random(&mut rng)),
                    );
                    let scrambled_ss2 = ss2.add_ciphertext(
                        helper4_ek.encrypt_with(-random_scramble, Scalar::random(&mut rng)),
                    );
                    (scrambled_ss1, scrambled_ss2)
                })
                .collect();

        // H1 receives these events and potentially "scrambles" them again
        let double_scrambled_trigger_events: Vec<(
            EncryptedGeneratorShare,
            EncryptedGeneratorShare,
        )> = scrambled_trigger_events
            .iter()
            .map(|(ss1, ss2)| {
                let random_scramble = RistrettoPoint::random(&mut rng);
                let scrambled_ss1 = ss1.add_ciphertext(
                    helper3_ek.encrypt_with(random_scramble, Scalar::random(&mut rng)),
                );
                let scrambled_ss2 = ss2.add_ciphertext(
                    helper4_ek.encrypt_with(-random_scramble, Scalar::random(&mut rng)),
                );
                (scrambled_ss1, scrambled_ss2)
            })
            .collect();

        // Next, the secret shares get split up. Half go to H3, and half go to H4
        let (h3, h4): (Vec<_>, Vec<_>) = double_scrambled_trigger_events.iter().cloned().unzip();

        // Each helper decrypts then sums up the secret shares it has received
        let h3_pts: Vec<RistrettoPoint> = h3.iter().map(|x| x.decrypt(&helper3_dek).pt()).collect();
        let h3_sum: RistrettoPoint = h3_pts.iter().sum();

        let h4_pts: Vec<RistrettoPoint> = h4.iter().map(|x| x.decrypt(&helper4_dek).pt()).collect();
        let h4_sum: RistrettoPoint = h4_pts.iter().sum();

        // The client then just sums up the two sub-totals
        let total = h3_sum + h4_sum;

        // This should be equivalent to the generator point raised to the Nth power,
        // where N is the sum of the trigger values

        assert_eq!(GeneratorShare::map_point_to_value(&total), correct_sum,);
    }
}
