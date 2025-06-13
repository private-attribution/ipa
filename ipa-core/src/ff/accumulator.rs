//! Optimized multiply-accumulate for field elements.
//!
//! An add or multiply operation in a prime field can be implemented as the
//! corresponding operation over the integers, followed by a reduction modulo the prime.
//!
//! In the case of several arithmetic operations performed in sequence, it is not
//! necessary to perform the reduction after every operation. As long as an exact
//! integer result is maintained up until reducing, the reduction can be performed once
//! at the end of the sequence.
//!
//! The reduction is usually the most expensive part of a multiplication operation, even
//! when using special primes like Mersenne primes that have an efficient reduction
//! operation.
//!
//! This module implements an optimized multiply-accumulate operation for field elements
//! that defers reduction.
//!
//! To enable this optimized implementation for a field, it is necessary to (1) select
//! an accumulator type, (2) calculate the number of multiply-accumulate operations
//! that can be performed without overflowing the accumulator. Record these values
//! in an implementation of the `MultiplyAccumulate` trait.
//!
//! This module also provides a generic implementation of `MultiplyAccumulate` that
//! reduces after every operation. To use the generic implementation for `MyField`:
//!
//! ```ignore
//! impl MultiplyAccumulate for MyField {
//!     type Accumulator = MyField;
//!     type AccumulatorArray<const N: usize> = [MyField; N];
//! }
//! ```
//!
//! Currently, an optimized implementation is supplied only for `Fp61BitPrime`, which is
//! used _extensively_ in DZKP-based malicious security. All other fields use a naive
//! implementation. (The implementation of DZKPs is also the only place that the traits
//! in this module are used; there is no reason to adopt them if not trying to access
//! the optimized implementation, or at least trying to be easily portable to an
//! optimized implementation.)
//!
//! To perform multiply-accumulate operations using this API:
//! ```
//! use ipa_core::ff::{PrimeField, MultiplyAccumulate, MultiplyAccumulator};
//! fn dot_product<F: PrimeField, const N: usize>(a: &[F; N], b: &[F; N]) -> F {
//!     let mut acc = <F as MultiplyAccumulate>::Accumulator::new();
//!     for i in 0..N {
//!         acc.multiply_accumulate(a[i], b[i]);
//!     }
//!     acc.take()
//! }
//! ```

use std::{
    array,
    marker::PhantomData,
    ops::{AddAssign, Mul},
};

use crate::{
    ff::{Field, U128Conversions},
    secret_sharing::SharedValue,
};

/// Trait for multiply-accumulate operations on.
///
/// See the module-level documentation for usage.
pub trait MultiplyAccumulator<F>: Clone {
    /// Create a new accumulator with a value of zero.
    fn new() -> Self
    where
        Self: Sized;

    /// Performs _accumulator <- accumulator + lhs * rhs_.
    fn multiply_accumulate(&mut self, lhs: F, rhs: F);

    /// Consume the accumulator and return its value.
    fn take(self) -> F;

    #[cfg(test)]
    fn reduce_interval() -> usize;
}

/// Trait for multiply-accumulate operations on vectors.
///
/// See the module-level documentation for usage.
pub trait MultiplyAccumulatorArray<F, const N: usize>: Clone {
    /// Create a new accumulator with a value of zero.
    fn new() -> Self
    where
        Self: Sized;

    /// Performs _accumulator <- accumulator + lhs * rhs_.
    ///
    /// Each of _accumulator_, _lhs_, and _rhs_ is a vector of length `N`, and _lhs *
    /// rhs_ is an element-wise product.
    fn multiply_accumulate(&mut self, lhs: &[F; N], rhs: &[F; N]);

    /// Consume the accumulator and return its value.
    fn take(self) -> [F; N];

    #[cfg(test)]
    fn reduce_interval() -> usize;
}

/// Trait for values (e.g. `Field`s) that support multiply-accumulate operations.
///
/// See the module-level documentation for usage.
pub trait MultiplyAccumulate: Sized {
    type Accumulator: MultiplyAccumulator<Self>;
    type AccumulatorArray<const N: usize>: MultiplyAccumulatorArray<Self, N>;
}

#[derive(Clone, Default)]
pub struct Accumulator<F, A, const REDUCE_INTERVAL: usize> {
    value: A,
    count: usize,
    phantom_data: PhantomData<F>,
}

#[cfg(all(test, unit_test))]
impl<F, A, const REDUCE_INTERVAL: usize> Accumulator<F, A, REDUCE_INTERVAL> {
    /// Return the raw accumulator value, which may not directly correspond to
    /// a valid value for `F`. This is intended for tests.
    fn into_raw(self) -> A {
        self.value
    }
}

/// Create a new accumulator containing the specified value.
///
/// This is currently used only by tests, and for that purpose it is sufficient to
/// access it via the concrete `Accumulator` type. To use it more generally, it would
/// need to be made part of the trait (either by adding a `From` supertrait bound, or by
/// adding a method in the trait to perform the operation).
impl<F, A, const REDUCE_INTERVAL: usize> From<F> for Accumulator<F, A, REDUCE_INTERVAL>
where
    A: Default + From<u128>,
    F: U128Conversions,
{
    fn from(value: F) -> Self {
        Self {
            value: value.as_u128().into(),
            count: 0,
            phantom_data: PhantomData,
        }
    }
}
/// Optimized multiply-accumulate implementation that adds `REDUCE_INTERVAL` products
/// into an accumulator before reducing.
///
/// Note that the accumulator must be large enough to hold `REDUCE_INTERVAL` products,
/// plus one additional field element. The additional field element represents the
/// output of the previous reduction, or an initial value of the accumulator.
impl<F, A, const REDUCE_INTERVAL: usize> MultiplyAccumulator<F>
    for Accumulator<F, A, REDUCE_INTERVAL>
where
    A: AddAssign + Copy + Default + Mul<Output = A> + From<u128> + Into<u128>,
    F: SharedValue + U128Conversions + MultiplyAccumulate<Accumulator = Self>,
{
    #[inline]
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::default()
    }

    #[inline]
    fn multiply_accumulate(&mut self, lhs: F, rhs: F) {
        self.value += A::from(lhs.as_u128()) * A::from(rhs.as_u128());
        self.count += 1;
        if self.count == REDUCE_INTERVAL {
            // Modulo, not really a truncation.
            self.value = A::from(F::truncate_from(self.value).as_u128());
            self.count = 0;
        }
    }

    #[inline]
    fn take(self) -> F {
        // Modulo, not really a truncation.
        F::truncate_from(self.value)
    }

    #[cfg(test)]
    fn reduce_interval() -> usize {
        REDUCE_INTERVAL
    }
}

/// Optimized multiply-accumulate implementation that adds `REDUCE_INTERVAL` products
/// into an accumulator before reducing. This version operates on arrays.
impl<F, A, const N: usize, const REDUCE_INTERVAL: usize> MultiplyAccumulatorArray<F, N>
    for Accumulator<F, [A; N], REDUCE_INTERVAL>
where
    A: AddAssign + Copy + Default + Mul<Output = A> + From<u128> + Into<u128>,
    F: SharedValue + U128Conversions + MultiplyAccumulate<AccumulatorArray<N> = Self>,
{
    #[inline]
    fn new() -> Self
    where
        Self: Sized,
    {
        Accumulator {
            value: [A::default(); N],
            count: 0,
            phantom_data: PhantomData,
        }
    }

    #[inline]
    fn multiply_accumulate(&mut self, lhs: &[F; N], rhs: &[F; N]) {
        for i in 0..N {
            self.value[i] += A::from(lhs[i].as_u128()) * A::from(rhs[i].as_u128());
        }
        self.count += 1;
        if self.count == REDUCE_INTERVAL {
            // Modulo, not really a truncation.
            self.value = array::from_fn(|i| A::from(F::truncate_from(self.value[i]).as_u128()));
            self.count = 0;
        }
    }

    #[inline]
    fn take(self) -> [F; N] {
        // Modulo, not really a truncation.
        array::from_fn(|i| F::truncate_from(self.value[i]))
    }

    #[cfg(test)]
    fn reduce_interval() -> usize {
        REDUCE_INTERVAL
    }
}

// Unoptimized implementation usable for any field.
impl<F: Field> MultiplyAccumulator<F> for F {
    #[inline]
    fn new() -> Self
    where
        Self: Sized,
    {
        F::ZERO
    }

    #[inline]
    fn multiply_accumulate(&mut self, lhs: F, rhs: F) {
        *self += lhs * rhs;
    }

    #[inline]
    fn take(self) -> F {
        self
    }

    #[cfg(test)]
    fn reduce_interval() -> usize {
        1
    }
}

// Unoptimized implementation usable for any field. This version operates on arrays.
impl<F: Field, const N: usize> MultiplyAccumulatorArray<F, N> for [F; N] {
    #[inline]
    fn new() -> Self
    where
        Self: Sized,
    {
        [F::ZERO; N]
    }

    #[inline]
    fn multiply_accumulate(&mut self, lhs: &[F; N], rhs: &[F; N]) {
        for i in 0..N {
            self[i] += lhs[i] * rhs[i];
        }
    }

    #[inline]
    fn take(self) -> [F; N] {
        self
    }

    #[cfg(test)]
    fn reduce_interval() -> usize {
        1
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::ff::{Fp61BitPrime, MultiplyAccumulate, MultiplyAccumulator, U128Conversions};

    // If adding optimized multiply-accumulate for an additional field, it would make
    // sense to convert the freestanding `fp61bit_*` tests here to a macro and replicate
    // them for the new field.

    #[test]
    fn fp61bit_accum_size() {
        // Test that the accumulator does not overflow before reaching REDUCE_INTERVAL.
        type Accumulator = <Fp61BitPrime as MultiplyAccumulate>::Accumulator;
        let max = -Fp61BitPrime::from_bit(true);
        let mut acc = Accumulator::from(max);
        for _ in 0..Accumulator::reduce_interval() - 1 {
            acc.multiply_accumulate(max, max);
        }

        let expected = max.as_u128()
            + u128::try_from(Accumulator::reduce_interval() - 1).unwrap()
                * (max.as_u128() * max.as_u128());
        assert_eq!(acc.clone().into_raw(), expected);

        assert_eq!(acc.take(), Fp61BitPrime::truncate_from(expected));

        // Test that the largest value the accumulator should ever hold (which is not
        // visible through the API, because it will be reduced immediately) does not
        // overflow.
        let _ = max.as_u128()
            + u128::try_from(Accumulator::reduce_interval()).unwrap()
                * (max.as_u128() * max.as_u128());
    }

    #[test]
    fn fp61bit_accum_reduction() {
        // Test that the accumulator reduces after reaching the specified interval.
        // (This test assumes that the implementation (1) sets REDUCE_INTERVAL as large
        // as possible, and (2) fully reduces upon reaching REDUCE_INTERVAL. It is
        // possible for a correct implementation not to have these properties. If
        // adding such an implementation, this test will need to be adjusted.)
        type Accumulator = <Fp61BitPrime as MultiplyAccumulate>::Accumulator;
        let max = -Fp61BitPrime::from_bit(true);
        let mut acc = Accumulator::new();
        for _ in 0..Accumulator::reduce_interval() {
            acc.multiply_accumulate(max, max);
        }

        let expected = Fp61BitPrime::truncate_from(
            u128::try_from(Accumulator::reduce_interval()).unwrap()
                * (max.as_u128() * max.as_u128()),
        );
        assert_eq!(acc.clone().into_raw(), expected.as_u128());
        assert_eq!(acc.take(), expected);
    }

    #[macro_export]
    macro_rules! accum_tests {
        ($field:ty) => {
            mod accum_tests {
                use std::iter::zip;
                use rand::Rng;

                use proptest::prelude::*;

                use $crate::{
                    ff::{MultiplyAccumulate, MultiplyAccumulator, MultiplyAccumulatorArray},
                    test_executor::run_random,
                };
                use super::*;

                const SZ: usize = 2;

                #[test]
                fn accum_simple() {
                    run_random(|mut rng| async move {
                        let a = rng.r#gen();
                        let b = rng.r#gen();
                        let c = rng.r#gen();
                        let d = rng.r#gen();

                        let mut acc = <$field as MultiplyAccumulate>::Accumulator::new();
                        acc.multiply_accumulate(a, b);
                        acc.multiply_accumulate(c, d);

                        assert_eq!(acc.take(), a * b + c * d);
                    });
                }

                prop_compose! {
                    fn arb_inputs(max_len: usize)
                                 (len in 0..max_len)
                                 (
                                     lhs in prop::collection::vec(any::<$field>(), len),
                                     rhs in prop::collection::vec(any::<$field>(), len),
                                 )
                    -> (Vec<$field>, Vec<$field>) {
                        (lhs, rhs)
                    }
                }

                proptest::proptest! {
                    #[test]
                    fn accum_proptest((lhs, rhs) in arb_inputs(
                        10 * <$field as MultiplyAccumulate>::Accumulator::reduce_interval()
                    )) {
                        type Accumulator = <$field as MultiplyAccumulate>::Accumulator;
                        let mut acc = Accumulator::new();
                        let mut expected = <$field>::ZERO;
                        for (lhs_term, rhs_term) in zip(lhs, rhs) {
                            acc.multiply_accumulate(lhs_term, rhs_term);
                            expected += lhs_term * rhs_term;
                        }
                        assert_eq!(acc.take(), expected);
                    }
                }

                prop_compose! {
                    fn arb_array_inputs(max_len: usize)
                                       (len in 0..max_len)
                                       (
                                           lhs in prop::collection::vec(
                                               prop::array::uniform(any::<$field>()),
                                               len,
                                           ),
                                           rhs in prop::collection::vec(
                                               prop::array::uniform(any::<$field>()),
                                               len,
                                           ),
                                       )
                    -> (Vec<[$field; SZ]>, Vec<[$field; SZ]>) {
                        (lhs, rhs)
                    }
                }

                proptest::proptest! {
                    #[test]
                    fn accum_array_proptest((lhs, rhs) in arb_array_inputs(
                        10 * <$field as MultiplyAccumulate>::AccumulatorArray::<SZ>::reduce_interval()
                    )) {
                        type Accumulator = <$field as MultiplyAccumulate>::AccumulatorArray::<SZ>;
                        let mut acc = Accumulator::new();
                        let mut expected = [<$field>::ZERO; SZ];
                        for (lhs_arr, rhs_arr) in zip(lhs, rhs) {
                            acc.multiply_accumulate(&lhs_arr, &rhs_arr);
                            for i in 0..SZ {
                                expected[i] += lhs_arr[i] * rhs_arr[i];
                            }
                        }
                        assert_eq!(acc.take(), expected);
                    }
                }
            }
        }
    }
}
