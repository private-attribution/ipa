use crate::ff::Field;
use crate::helpers::Role;
use std::fmt::{Debug, Formatter};
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};


#[derive(Clone, PartialEq, Eq)]
pub struct Replicated<F: Field>(F, F);

impl<F: Field + Debug> Debug for Replicated<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<F: Field> Default for Replicated<F> {
    fn default() -> Self {
        Replicated::new(F::ZERO, F::ZERO)
    }
}

impl<F: Field> Replicated<F> {
    #[must_use]
    pub fn new(a: F, b: F) -> Self {
        Self(a, b)
    }

    pub fn as_tuple(&self) -> (F, F) {
        (self.0, self.1)
    }

    pub fn left(&self) -> F {
        self.0
    }

    pub fn right(&self) -> F {
        self.1
    }

    /// Returns share of value one.
    #[must_use]
    pub fn one(helper_role: Role) -> Self {
        Self::from_scalar(helper_role, F::ONE)
    }

    /// Returns share of a scalar value.
    pub fn from_scalar(helper_role: Role, a: F) -> Self {
        match helper_role {
            Role::H1 => Self::new(a, F::ZERO),
            Role::H2 => Self::new(F::ZERO, F::ZERO),
            Role::H3 => Self::new(F::ZERO, a),
        }
    }

    /// Replicated secret share where both left and right values are `F::ZERO`
    pub const ZERO: Replicated<F> = Self(F::ZERO, F::ZERO);

    pub fn from_iter(from: &[u8]) -> impl Iterator<Item = Self> + '_ {
        from
            .chunks(2 * F::SIZE_IN_BYTES as usize)
            .map(|chunk| {
                assert_eq!(chunk.len(), 2 * F::SIZE_IN_BYTES as usize);
                let left = F::deserialize(chunk).unwrap();
                let right = F::deserialize(&chunk[F::SIZE_IN_BYTES as usize..]).unwrap();
                Self(left, right)
            })
    }
}

impl<F: Field> Add<Self> for &Replicated<F> {
    type Output = Replicated<F>;

    fn add(self, rhs: Self) -> Self::Output {
        Replicated(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<F: Field> Add<&Self> for Replicated<F> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F: Field> AddAssign<&Self> for Replicated<F> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
    }
}

impl<F: Field> Neg for Replicated<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl<F: Field> Sub<Self> for &Replicated<F> {
    type Output = Replicated<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        Replicated(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<F: Field> Sub<&Self> for Replicated<F> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<F: Field> SubAssign<&Self> for Replicated<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
        self.1 -= rhs.1;
    }
}

impl<F: Field> Mul<F> for Replicated<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Self(self.0 * rhs, self.1 * rhs)
    }
}

impl<F: Field> From<(F, F)> for Replicated<F> {
    fn from(s: (F, F)) -> Self {
        Replicated::new(s.0, s.1)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::Replicated;
    use crate::ff::Fp31;

    fn secret_share(a: u8, b: u8, c: u8) -> (Replicated<Fp31>, Replicated<Fp31>, Replicated<Fp31>) {
        (
            Replicated::new(Fp31::from(a), Fp31::from(b)),
            Replicated::new(Fp31::from(b), Fp31::from(c)),
            Replicated::new(Fp31::from(c), Fp31::from(a)),
        )
    }

    fn assert_valid_secret_sharing(
        res1: &Replicated<Fp31>,
        res2: &Replicated<Fp31>,
        res3: &Replicated<Fp31>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: &Replicated<Fp31>,
        a2: &Replicated<Fp31>,
        a3: &Replicated<Fp31>,
        expected_value: u128,
    ) {
        assert_eq!(a1.0 + a2.0 + a3.0, Fp31::from(expected_value));
        assert_eq!(a1.1 + a2.1 + a3.1, Fp31::from(expected_value));
    }

    fn addition_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 + r2
        let res1 = a1 + &b1;
        let res2 = a2 + &b2;
        let res3 = a3 + &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_addition() {
        addition_test_case((1, 0, 0), (1, 0, 0), 2);
        addition_test_case((1, 0, 0), (0, 1, 0), 2);
        addition_test_case((1, 0, 0), (0, 0, 1), 2);

        addition_test_case((0, 1, 0), (1, 0, 0), 2);
        addition_test_case((0, 1, 0), (0, 1, 0), 2);
        addition_test_case((0, 1, 0), (0, 0, 1), 2);

        addition_test_case((0, 0, 1), (1, 0, 0), 2);
        addition_test_case((0, 0, 1), (0, 1, 0), 2);
        addition_test_case((0, 0, 1), (0, 0, 1), 2);

        addition_test_case((0, 0, 0), (1, 0, 0), 1);
        addition_test_case((0, 0, 0), (0, 1, 0), 1);
        addition_test_case((0, 0, 0), (0, 0, 1), 1);

        addition_test_case((1, 0, 0), (0, 0, 0), 1);
        addition_test_case((0, 1, 0), (0, 0, 0), 1);
        addition_test_case((0, 0, 1), (0, 0, 0), 1);

        addition_test_case((0, 0, 0), (0, 0, 0), 0);

        addition_test_case((1, 3, 5), (10, 0, 2), 21);
    }

    fn subtraction_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 - r2
        let res1 = a1 - &b1;
        let res2 = a2 - &b2;
        let res3 = a3 - &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_subtraction() {
        subtraction_test_case((1, 0, 0), (1, 0, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 1, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 1, 0), (1, 0, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 1, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 1), (1, 0, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 1, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 0), (1, 0, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 1, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 0, 1), 30);

        subtraction_test_case((1, 0, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 1, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 0, 1), (0, 0, 0), 1);

        subtraction_test_case((0, 0, 0), (0, 0, 0), 0);

        subtraction_test_case((1, 3, 5), (10, 0, 2), 28);
    }

    fn mult_by_constant_test_case(a: (u8, u8, u8), c: u8, expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);

        let res1 = a1 * Fp31::from(c);
        let res2 = a2 * Fp31::from(c);
        let res3 = a3 * Fp31::from(c);

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_mult_by_constant() {
        mult_by_constant_test_case((1, 0, 0), 2, 2);
        mult_by_constant_test_case((0, 1, 0), 2, 2);
        mult_by_constant_test_case((0, 0, 1), 2, 2);
        mult_by_constant_test_case((0, 0, 0), 2, 0);
    }
}
