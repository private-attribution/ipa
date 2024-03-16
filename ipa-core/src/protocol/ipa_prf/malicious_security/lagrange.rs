use std::fmt::Debug;
use std::iter::repeat;

use generic_array::{ArrayLength, GenericArray};
use typenum::{Unsigned, U1};

use crate::ff::{Field, PrimeField, Serializable};

/// A degree `N-1` polynomial is stored as `N` points `(x,y)`
/// where the "x coordinates" of the input points are `x_0` to `x_N` are `F::ZERO` to `(N-1)*F::ONE`
/// Therefore, we only need to store the `y` coordinates.
#[derive(Debug, PartialEq, Clone)]
pub struct Polynomial<F: Field, N: ArrayLength> {
    y_coordinates: GenericArray<F, N>,
}

/// The Canonical Lagrange denominator is defined as the denominator of the Lagrange base polynomials
/// `https://en.wikipedia.org/wiki/Lagrange_polynomial`
/// where the "x coordinates" of the input points are `x_0` to `x_N` are `F::ZERO` to `(N-1)*F::ONE`
/// the degree of the polynomials is `N-1`
pub struct CanonicalLagrangeDenominator<F: Field, N: ArrayLength> {
    denominator: GenericArray<F, N>,
}

impl<F, N> CanonicalLagrangeDenominator<F, N>
where
    F: PrimeField + TryFrom<u128>,
    <F as TryFrom<u128>>::Error: Debug,
    N: ArrayLength,
{
    /// generates canonical Lagrange denominators
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    pub fn new() -> Self {
        // assertion that field is large enough
        // when it is large enough, `F::try_from().unwrap()` below does not panic
        assert!(
            N::U128 < F::PRIME.into(),
            "Field size {} is not large enough to hold {} points",
            F::PRIME.into(),
            N::U128
        );

        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N::USIZE < 2024);

        Self {
            denominator: (0..N::U128)
                .into_iter()
                .map(|i| {
                    (0..N::U128)
                        .into_iter()
                        .filter(|&j| i != j)
                        .map(|j| F::try_from(i).unwrap() - F::try_from(j).unwrap())
                        .fold(F::ONE, |acc, a| acc * a)
                        .invert()
                })
                .collect(),
        }
    }
}

/// `LagrangeTable` is a precomputed table for the Lagrange evaluation.
/// Allows to compute points on the polynomial, i.e. output points,
/// given enough points on the polynomial, i.e. input points,
/// by using the `eval` function.
/// The "x coordinates" are implicit.
/// The "y coordinates" of the input points are inputs to `eval`.
/// The output of `eval` are the "y coordinates" of the output points .
/// The "x coordinates" of the input points `x_0` to `x_(N-1)` are `F::ZERO` to `(N-1)*F::ONE`.
/// The `LagrangeTable` also specifies `M` "x coordinates" for the output points.
/// The "x coordinates" of the output points `x_N` to `x_(N+M-1)` are `N*F::ONE` to `(N+M-1)*F::ONE`
/// when generated using `from(denominator)`
/// unless generated using `new(denominator, x_output)` for a specific output "x coordinate" `x_output`.
pub struct LagrangeTable<F: Field, N: ArrayLength, M: ArrayLength> {
    table: GenericArray<GenericArray<F, N>, M>,
}

impl<F, N> LagrangeTable<F, N, U1>
where
    F: Field + TryFrom<u128>,
    <F as TryFrom<u128>>::Error: Debug,
    N: ArrayLength,
{
    /// generates a `CanonicalLagrangeTable` from `CanoncialLagrangeDenominators` for a single output point
    /// The "x coordinate" of the output point is `x_output`.
    pub fn new(denominator: &CanonicalLagrangeDenominator<F, N>, x_output: &F) -> Self {
        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N::USIZE < 2024);

        let table = Self::compute_table_row(x_output, denominator);
        LagrangeTable::<F, N, U1> {
            table: GenericArray::from_array([table; 1]),
        }
    }
}

impl<F, N, M> LagrangeTable<F, N, M>
where
    F: Field,
    N: ArrayLength,
    M: ArrayLength,
{
    /// This function uses the `LagrangeTable` to evaluate `polynomial` on the specified output "x coordinates"
    /// outputs the "y coordinates" such that `(x,y)` lies on `polynomial`
    pub fn eval(&self, polynomial: &Polynomial<F, N>) -> GenericArray<F, M> {
        self.table
            .iter()
            .map(|table_row| {
                table_row
                    .iter()
                    .zip(polynomial.y_coordinates.iter())
                    .fold(F::ZERO, |acc, (&base, &y)| acc + base * y)
            })
            .collect()
    }

    /// helper function to compute a single row of `LagrangeTable`
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    fn compute_table_row(
        x_output: &F,
        denominator: &CanonicalLagrangeDenominator<F, N>,
    ) -> GenericArray<F, N>
    where
        F: Field + TryFrom<u128>,
        <F as TryFrom<u128>>::Error: Debug,
        N: ArrayLength,
    {
        (0..N::U128)
            .zip(repeat(0..N::U128))
            .map(|(i, range)| {
                range
                    .filter(|&j| j != i)
                    .fold(F::ONE, |acc, j| acc * (*x_output - F::try_from(j).unwrap()))
            })
            .zip(&denominator.denominator)
            .map(|(numerator, denominator)| *denominator * numerator)
            .collect()
    }
}

impl<F, N, M> From<CanonicalLagrangeDenominator<F, N>> for LagrangeTable<F, N, M>
where
    F: PrimeField,
    N: ArrayLength,
    M: ArrayLength,
{
    fn from(value: CanonicalLagrangeDenominator<F, N>) -> Self {
        // assertion that field is large enough
        // when it is large enough, `F::try_from().unwrap()` below does not panic
        assert!(
            N::U128 + M::U128 < F::PRIME.into(),
            "Field size {} is not large enough to hold {} + {} points",
            F::PRIME.into(),
            N::U128,
            M::U128
        );

        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N::USIZE * M::USIZE < 2024);

        LagrangeTable {
            table: (N::U128..(N::U128 + M::U128))
                .map(|i| Self::compute_table_row(&F::try_from(i).unwrap(), &value))
                .collect(),
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::fmt::Debug;

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use proptest::{prelude::*, proptest};
    use typenum::{U1, U32, U7, U8};

    use crate::{
        ff::Field,
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable, Polynomial,
        },
    };

    type TestField = crate::ff::Fp32BitPrime;

    #[derive(Debug, PartialEq, Clone)]
    struct MonomialFormPolynomial<F: Field, N: ArrayLength> {
        coefficients: GenericArray<F, N>,
    }

    impl<F, N> MonomialFormPolynomial<F, N>
    where
        F: Field,
        N: ArrayLength,
    {
        /// test helper function that evaluates a polynomial in monomial form, i.e. `sum_i c_i x^i` on points `x_output`
        /// where `c_0` to `c_N` are stored in `polynomial`
        fn eval<M>(&self, x_output: &GenericArray<F, M>) -> GenericArray<F, M>
        where
            M: ArrayLength,
        {
            x_output
                .iter()
                .map(|&x| {
                    // monomial base, i.e. `x^k`
                    // evaluate p via `sum_k coefficient_k * x^k`
                    let (_, y) = self
                        .coefficients
                        .iter()
                        .fold((F::ONE, F::ZERO), |(base, y), &coef| {
                            (base * x, y + coef * base)
                        });
                    y
                })
                .collect()
        }
    }

    impl<F, N> From<MonomialFormPolynomial<F, N>> for Polynomial<F, N>
    where
        F: Field + TryFrom<u128>,
        <F as TryFrom<u128>>::Error: Debug,
        N: ArrayLength,
    {
        fn from(value: MonomialFormPolynomial<F, N>) -> Self {
            let canonical_points: GenericArray<F, N> =
                GenericArray::generate(|i| F::try_from(u128::try_from(i).unwrap()).unwrap());
            Polynomial {
                y_coordinates: value.eval(&canonical_points),
            }
        }
    }

    fn lagrange_single_output_point_using_new(
        output_point: TestField,
        input_points: [TestField; 32],
    ) {
        let polynomial_monomial_form = MonomialFormPolynomial {
            coefficients: GenericArray::<TestField, U32>::from_array(input_points),
        };
        let output_expected = polynomial_monomial_form.eval(
            &GenericArray::<TestField, U1>::from_array([output_point; 1]),
        );
        let polynomial = Polynomial::from(polynomial_monomial_form.clone());
        let denominator = CanonicalLagrangeDenominator::<TestField, U32>::new();
        // generate table using new
        let lagrange_table = LagrangeTable::<TestField, U32, U1>::new(&denominator, &output_point);
        let output = lagrange_table.eval(&polynomial);
        assert_eq!(output, output_expected);
    }

    proptest! {
    #[test]
    fn proptest_lagrange_single_output_point_using_new(output_point: TestField, input_points in prop::array::uniform32(any::<TestField>())){
        lagrange_single_output_point_using_new(output_point,input_points);
    }
    }

    fn lagrange_canonical_using_from(input_points: [TestField; 8]) {
        let polynomial_monomial_form = MonomialFormPolynomial {
            coefficients: GenericArray::<TestField, U8>::from_array(input_points),
        };
        // the canonical x coordinates are 0..7, the outputs use coordinates 8..15:
        let x_coordinates_output = GenericArray::<_, U7>::generate(|i| {
            TestField::try_from(u128::try_from(i).unwrap() + 8).unwrap()
        });
        let output_expected = polynomial_monomial_form.eval(&x_coordinates_output);
        let polynomial = Polynomial::from(polynomial_monomial_form.clone());
        let denominator = CanonicalLagrangeDenominator::<TestField, U8>::new();
        // generate table using from
        let lagrange_table = LagrangeTable::<TestField, U8, U7>::from(denominator);
        let output = lagrange_table.eval(&polynomial);
        assert_eq!(output, output_expected);
    }

    proptest! {
        #[test]
        fn proptest_lagrange_canonical_using_from(input_points in prop::array::uniform8(any::<TestField>()))
        {
            lagrange_canonical_using_from(input_points);
        }
    }
}
