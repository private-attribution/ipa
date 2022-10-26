use std::fmt::Formatter;
use std::ops::AddAssign;
use std::ops::SubAssign;
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use crate::field::Field;
use crate::helpers::Identity;
use crate::secret_sharing::Replicated;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MaliciousReplicated<T>(Replicated<T>, Replicated<T>);

impl<T: Debug> Debug for MaliciousReplicated<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "x: {:?}, rx: {:?}", self.0, self.1)
    }
}

impl<T: Field> Default for MaliciousReplicated<T> {
    fn default() -> Self {
        MaliciousReplicated::new(Replicated::default(), Replicated::default())
    }
}

impl<T: Field> MaliciousReplicated<T> {
    #[must_use]
    pub fn new(x: Replicated<T>, rx: Replicated<T>) -> Self {
        Self(x, rx)
    }

    #[allow(dead_code)]
    pub fn x(&self) -> Replicated<T> {
        self.0
    }

    #[allow(dead_code)]
    pub fn rx(&self) -> Replicated<T> {
        self.1
    }

    /*
    /// Unsure if we need this...
    pub fn as_tuple(&self) -> (T, T) {
        (self.0, self.1)
    }
    */

    /// Returns a pair of replicated secret sharings. One of "one", one of "r"
    #[allow(dead_code)]
    pub fn one(helper_identity: Identity, r_share: Replicated<T>) -> Self {
        Self::new(Replicated::one(helper_identity), r_share)
    }
}

impl<T: Field> Add for MaliciousReplicated<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<T: Field> AddAssign for MaliciousReplicated<T> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl<T: Field> SubAssign for MaliciousReplicated<T> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl<T: Field> Neg for MaliciousReplicated<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0, -self.1)
    }
}

impl<T: Field> Sub for MaliciousReplicated<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<T: Field> Mul<T> for MaliciousReplicated<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self {
        Self(self.0 * rhs, self.1 * rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::MaliciousReplicated;
    use crate::field::Field;
    use crate::field::Fp31;
    use crate::helpers::Identity;
    use crate::test_fixture::{share, validate_and_reconstruct};
    use proptest::prelude::Rng;

    #[test]
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    fn test_local_operations() {
        let mut rng = rand::thread_rng();

        let a = Fp31::from(rng.gen::<u128>());
        let b = Fp31::from(rng.gen::<u128>());
        let c = Fp31::from(rng.gen::<u128>());
        let d = Fp31::from(rng.gen::<u128>());
        let e = Fp31::from(rng.gen::<u128>());
        let f = Fp31::from(rng.gen::<u128>());
        // Randomization constant
        let r = Fp31::from(rng.gen::<u128>());

        let a_shared = share(a, &mut rng);
        let b_shared = share(b, &mut rng);
        let c_shared = share(c, &mut rng);
        let d_shared = share(d, &mut rng);
        let e_shared = share(e, &mut rng);
        let f_shared = share(f, &mut rng);
        // Randomization constant
        let r_shared = share(r, &mut rng);

        let ra = a * r;
        let rb = b * r;
        let rc = c * r;
        let rd = d * r;
        let re = e * r;
        let rf = f * r;

        let ra_shared = share(ra, &mut rng);
        let rb_shared = share(rb, &mut rng);
        let rc_shared = share(rc, &mut rng);
        let rd_shared = share(rd, &mut rng);
        let re_shared = share(re, &mut rng);
        let rf_shared = share(rf, &mut rng);

        let identities = [Identity::H1, Identity::H2, Identity::H3];
        let mut results = Vec::with_capacity(3);

        for i in 0..3 {
            let identity = identities[i];

            let malicious_a = MaliciousReplicated::new(a_shared[i], ra_shared[i]);
            let malicious_b = MaliciousReplicated::new(b_shared[i], rb_shared[i]);
            let malicious_c = MaliciousReplicated::new(c_shared[i], rc_shared[i]);
            let malicious_d = MaliciousReplicated::new(d_shared[i], rd_shared[i]);
            let malicious_e = MaliciousReplicated::new(e_shared[i], re_shared[i]);
            let malicious_f = MaliciousReplicated::new(f_shared[i], rf_shared[i]);

            let malicious_a_plus_b = malicious_a + malicious_b;
            let malicious_c_minus_d = malicious_c - malicious_d;
            let malicious_1_minus_e = MaliciousReplicated::one(identity, r_shared[i]) - malicious_e;
            let malicious_2f = malicious_f * Fp31::from(2_u128);

            let mut temp = -malicious_a_plus_b;
            temp -= malicious_c_minus_d;
            temp -= malicious_1_minus_e;
            temp = temp * Fp31::from(6_u128);
            temp += malicious_2f;
            results.push(temp);
        }

        let correct =
            (-(a + b) - (c - d) - (Fp31::ONE - e)) * Fp31::from(6_u128) + Fp31::from(2_u128) * f;

        assert_eq!(
            validate_and_reconstruct((results[0].x(), results[1].x(), results[2].x())),
            correct,
        );
        assert_eq!(
            validate_and_reconstruct((results[0].rx(), results[1].rx(), results[2].rx())),
            correct * r,
        );
    }
}
