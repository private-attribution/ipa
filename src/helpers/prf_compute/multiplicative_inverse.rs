use num_bigint::{BigInt, Sign::Plus};
use num_integer::Integer;
use num_traits::{identities::Zero, Signed};
use rust_elgamal::Scalar;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarType(Scalar);

impl From<&ScalarType> for BigInt {
    fn from(value: &ScalarType) -> Self {
        BigInt::from_bytes_le(Plus, value.0.as_bytes())
    }
}

impl From<&BigInt> for ScalarType {
    fn from(value: &BigInt) -> Self {
        let (_, mut bytes) = (value).to_bytes_le();
        while bytes.len() < 32 {
            bytes.push(0_u8);
        }
        let ans = bytes.try_into().unwrap();
        ScalarType(Scalar::from_bits(ans))
    }
}

/// Implementation of Extended Euclidean Algorithm to compute multiplicative inverse of a number
/// i.e given num and modulus it computes t such that (num * t) % modulus = 1
///
/// How it computes :
/// Finds Bezout Coefficient a and b for coprimes num and modulus i.e.
/// ``bezout_coefficient_a`` * ``num`` + ``bezout_coefficient_b`` * ``modulus`` = 1
/// This deduces to ( ``bezout_coefficient_a`` * ``num`` ) % ``modulus`` = 1 % ``modulus``
/// Hence ``bezout_coefficient_a`` % ``modulus`` is the multiplicative inverse of ``num``
/// In the code, ``bezout_coefficient_a`` is represented by ``t_current``
/// Before returning number is converted into a positive number
///
/// # Panics
/// This will assert in case input numbers are zero or num is not smaller than modulus
/// if the function does not work properly and returns an unexpected bezout coefficient

#[must_use]
pub fn multiplicative_inverse<'a>(num: &'a ScalarType, modulus: &'a ScalarType) -> ScalarType {
    // Assume non zero
    assert!(num.0 != Scalar::zero());
    assert!(modulus.0 != Scalar::zero());
    let (num, modulus) = (BigInt::from(num), BigInt::from(modulus));

    assert!(num < modulus);

    let (mut remainder_current, mut remainder_last) = (num, modulus.clone());
    let (mut t_last, mut t_current) = (BigInt::from(0_i32), BigInt::from(1_i32));

    loop {
        let (quotient, remainder_new) = remainder_last.div_rem(&remainder_current);
        if remainder_new.is_zero() {
            break;
        }
        let t_new = &t_last - quotient * t_current.clone();
        remainder_last = remainder_current;
        remainder_current = remainder_new;
        t_last = t_current;
        t_current = t_new;
    }

    if t_current.is_negative() {
        t_current += modulus.clone();
        assert!(t_current.is_positive());
    }
    ScalarType::from(&(t_current % modulus))
}

#[cfg(test)]
mod tests {
    use crate::helpers::prf_compute::multiplicative_inverse::ScalarType;

    use super::{multiplicative_inverse, BigInt, Scalar};
    use rand::Rng;

    impl From<u32> for ScalarType {
        fn from(value: u32) -> Self {
            ScalarType(Scalar::from(value))
        }
    }

    impl From<u128> for ScalarType {
        fn from(value: u128) -> Self {
            ScalarType(Scalar::from(value))
        }
    }

    #[test]
    fn check_multiplicative_inverse() {
        let num = 638_204_786_u32;
        let modulo = 2_147_483_647_u32;

        let inv = multiplicative_inverse(&ScalarType::from(num), &ScalarType::from(modulo));
        assert_eq!(inv, ScalarType::from(1_237_888_327_u32));

        let result = (num * BigInt::from(&inv)) % modulo;
        assert_eq!(result, BigInt::from(1_i32));
    }

    #[test]
    fn check_multiplicative_inverse_big_primes() {
        let mut rng = rand::thread_rng();
        let primes = [
            999_999_000_001_u128,
            67_280_421_310_721_u128,
            4_125_636_888_562_548_868_221_559_797_461_449_u128,
            170_141_183_460_469_231_731_687_303_715_884_105_727_u128,
        ];

        for prime in primes {
            for _i in [1..10] {
                let num = rng.gen_range(0..prime);
                let inv = multiplicative_inverse(&ScalarType::from(num), &ScalarType::from(prime));
                let result = (num * BigInt::from(&inv)) % prime;
                assert_eq!(result, BigInt::from(1_i32));
            }
        }
    }
}
