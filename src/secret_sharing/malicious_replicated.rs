use std::fmt::Formatter;
use std::ops::AddAssign;
use std::ops::SubAssign;
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use crate::ff::Field;
use crate::helpers::Role;
use crate::secret_sharing::Replicated;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MaliciousReplicated<F> {
    x: Replicated<F>,
    rx: Replicated<F>,
}

impl<F: Debug> Debug for MaliciousReplicated<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "x: {:?}, rx: {:?}", self.x, self.rx)
    }
}

impl<F: Field> Default for MaliciousReplicated<F> {
    fn default() -> Self {
        MaliciousReplicated::new(Replicated::default(), Replicated::default())
    }
}

impl<F: Field> MaliciousReplicated<F> {
    #[must_use]
    pub fn new(x: Replicated<F>, rx: Replicated<F>) -> Self {
        Self { x, rx }
    }

    pub fn x(&self) -> Replicated<F> {
        self.x
    }

    pub fn rx(&self) -> Replicated<F> {
        self.rx
    }

    /// Returns a pair of replicated secret sharings. One of "one", one of "r"
    #[allow(dead_code)]
    pub fn one(helper_role: Role, r_share: Replicated<F>) -> Self {
        Self::new(Replicated::one(helper_role), r_share)
    }
}

impl<F: Field> Add for MaliciousReplicated<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            x: self.x + rhs.x,
            rx: self.rx + rhs.rx,
        }
    }
}

impl<F: Field> AddAssign for MaliciousReplicated<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl<F: Field> SubAssign for MaliciousReplicated<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl<F: Field> Neg for MaliciousReplicated<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: -self.x,
            rx: -self.rx,
        }
    }
}

impl<F: Field> Sub for MaliciousReplicated<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            x: self.x - rhs.x,
            rx: self.rx - rhs.rx,
        }
    }
}

impl<F: Field> Mul<F> for MaliciousReplicated<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        Self {
            x: self.x * rhs,
            rx: self.rx * rhs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MaliciousReplicated;
    use crate::ff::{Field, Fp31};
    use crate::helpers::Role;
    use crate::test_fixture::{share, validate_and_reconstruct};
    use proptest::prelude::Rng;

    #[test]
    #[allow(clippy::many_single_char_names)]
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

        let roles = [Role::H1, Role::H2, Role::H3];
        let mut results = Vec::with_capacity(3);

        for i in 0..3 {
            let helper_role = roles[i];

            let malicious_a = MaliciousReplicated::new(a_shared[i], ra_shared[i]);
            let malicious_b = MaliciousReplicated::new(b_shared[i], rb_shared[i]);
            let malicious_c = MaliciousReplicated::new(c_shared[i], rc_shared[i]);
            let malicious_d = MaliciousReplicated::new(d_shared[i], rd_shared[i]);
            let malicious_e = MaliciousReplicated::new(e_shared[i], re_shared[i]);
            let malicious_f = MaliciousReplicated::new(f_shared[i], rf_shared[i]);

            let malicious_a_plus_b = malicious_a + malicious_b;
            let malicious_c_minus_d = malicious_c - malicious_d;
            let malicious_1_minus_e =
                MaliciousReplicated::one(helper_role, r_shared[i]) - malicious_e;
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
