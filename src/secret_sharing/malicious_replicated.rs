use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use crate::ff::Field;
use crate::helpers::Role;
use crate::secret_sharing::Replicated;

#[derive(Clone, PartialEq, Eq)]
pub struct MaliciousReplicated<F: Field> {
    x: Replicated<F>,
    rx: Replicated<F>,
}

/// A trait that is implemented for various collections of `MaliciousReplicated`
/// shares.  This allows a protocol to downgrade to ordinary `Replicated` shares
/// when the protocol is done.  This should not be used directly.
pub trait Downgrade {
    type Target;
    fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target>;
}

#[must_use = "You should not be downgrading `MaliciousReplicated` values without calling `MaliciousValidator::validate()`"]
pub struct UnauthorizedDowngradeWrapper<T>(T);

pub trait ThisCodeIsAuthorizedToDowngradeFromMalicious<T> {
    fn access_without_downgrade(self) -> T;
}

impl<F: Field + Debug> Debug for MaliciousReplicated<F> {
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

    pub fn x(&self) -> UnauthorizedDowngradeWrapper<&Replicated<F>> {
        UnauthorizedDowngradeWrapper(&self.x)
    }

    pub fn rx(&self) -> &Replicated<F> {
        &self.rx
    }

    /// Returns a pair of replicated secret sharings. One of "one", one of "r"
    pub fn one(helper_role: Role, r_share: Replicated<F>) -> Self {
        Self::new(Replicated::one(helper_role), r_share)
    }
}

impl<F: Field> Add<Self> for &MaliciousReplicated<F> {
    type Output = MaliciousReplicated<F>;

    fn add(self, rhs: Self) -> Self::Output {
        MaliciousReplicated {
            x: &self.x + &rhs.x,
            rx: &self.rx + &rhs.rx,
        }
    }
}

impl<F: Field> Add<&Self> for MaliciousReplicated<F> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F: Field> AddAssign<&Self> for MaliciousReplicated<F> {
    fn add_assign(&mut self, rhs: &Self) {
        self.x += &rhs.x;
        self.rx += &rhs.rx;
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

impl<F: Field> Sub<Self> for &MaliciousReplicated<F> {
    type Output = MaliciousReplicated<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        MaliciousReplicated {
            x: &self.x - &rhs.x,
            rx: &self.rx - &rhs.rx,
        }
    }
}
impl<F: Field> Sub<&Self> for MaliciousReplicated<F> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<F: Field> SubAssign<&Self> for MaliciousReplicated<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.x -= &rhs.x;
        self.rx -= &rhs.rx;
    }
}

impl<F: Field> Mul<F> for MaliciousReplicated<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Self {
            x: self.x * rhs,
            rx: self.rx * rhs,
        }
    }
}

impl<F: Field> Downgrade for MaliciousReplicated<F> {
    type Target = Replicated<F>;
    fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(self.x)
    }
}

impl<F: Field> Downgrade for (MaliciousReplicated<F>, MaliciousReplicated<F>) {
    type Target = (Replicated<F>, Replicated<F>);
    fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper((
            self.0.downgrade().access_without_downgrade(),
            self.1.downgrade().access_without_downgrade(),
        ))
    }
}

impl<F: Field> Downgrade for Vec<MaliciousReplicated<F>> {
    type Target = Vec<Replicated<F>>;
    fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(
            self.into_iter()
                .map(|v| v.downgrade().access_without_downgrade())
                .collect(),
        )
    }
}

// Stoopid E0119 👎
//   "upstream crates may add a new impl of trait `Iterator` for type
//   `(MaliciousReplicated<_>, MaliciousReplicated<_>)` in future versions"
//
// pub struct DowngradeIter<I> {
//     iter: I,
// }

// impl<I, F> Iterator for DowngradeIter<I>
// where
//     I: Iterator<Item = MaliciousReplicated<F>>,
//     F: Field,
// {
//     type Item = Replicated<F>;
//     fn next(&mut self) -> Option<Self::Item> {
//         self.iter.next().map(|v| v.downgrade().authorized_access())
//     }
// }

// impl<I, F> Downgrade for I
// where
//     I: Iterator<Item = MaliciousReplicated<F>>,
//     F: Field,
// {
//     type Target = DowngradeIter<I>;
//     fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
//         UnauthorizedDowngradeWrapper(DowngradeIter {
//             iter: self.into_iter(),
//         })
//     }
// }

impl<T> ThisCodeIsAuthorizedToDowngradeFromMalicious<T> for UnauthorizedDowngradeWrapper<T> {
    fn access_without_downgrade(self) -> T {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Downgrade, MaliciousReplicated, ThisCodeIsAuthorizedToDowngradeFromMalicious};
    use crate::ff::{Field, Fp31};
    use crate::helpers::Role;
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::{share, validate_and_reconstruct};
    use proptest::prelude::Rng;
    use rand::thread_rng;

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_local_operations() {
        let mut rng = rand::thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let c = rng.gen::<Fp31>();
        let d = rng.gen::<Fp31>();
        let e = rng.gen::<Fp31>();
        let f = rng.gen::<Fp31>();
        // Randomization constant
        let r = rng.gen::<Fp31>();

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

            // Avoiding copies here is a real pain: clone!
            let malicious_a = MaliciousReplicated::new(a_shared[i].clone(), ra_shared[i].clone());
            let malicious_b = MaliciousReplicated::new(b_shared[i].clone(), rb_shared[i].clone());
            let malicious_c = MaliciousReplicated::new(c_shared[i].clone(), rc_shared[i].clone());
            let malicious_d = MaliciousReplicated::new(d_shared[i].clone(), rd_shared[i].clone());
            let malicious_e = MaliciousReplicated::new(e_shared[i].clone(), re_shared[i].clone());
            let malicious_f = MaliciousReplicated::new(f_shared[i].clone(), rf_shared[i].clone());

            let malicious_a_plus_b = malicious_a + &malicious_b;
            let malicious_c_minus_d = malicious_c - &malicious_d;
            let malicious_1_minus_e =
                MaliciousReplicated::one(helper_role, r_shared[i].clone()) - &malicious_e;
            let malicious_2f = malicious_f * Fp31::from(2_u128);

            let mut temp = -malicious_a_plus_b - &malicious_c_minus_d - &malicious_1_minus_e;
            temp = temp * Fp31::from(6_u128);
            results.push(temp + &malicious_2f);
        }

        let correct =
            (-(a + b) - (c - d) - (Fp31::ONE - e)) * Fp31::from(6_u128) + Fp31::from(2_u128) * f;

        assert_eq!(
            validate_and_reconstruct(
                results[0].x().access_without_downgrade(),
                results[1].x().access_without_downgrade(),
                results[2].x().access_without_downgrade(),
            ),
            correct,
        );
        assert_eq!(
            validate_and_reconstruct(results[0].rx(), results[1].rx(), results[2].rx()),
            correct * r,
        );
    }

    #[test]
    fn downgrade() {
        let mut rng = thread_rng();
        let x = Replicated::new(rng.gen::<Fp31>(), rng.gen());
        let y = Replicated::new(rng.gen::<Fp31>(), rng.gen());
        let m = MaliciousReplicated::new(x.clone(), y);
        assert_eq!(x, m.downgrade().access_without_downgrade());
    }
}
