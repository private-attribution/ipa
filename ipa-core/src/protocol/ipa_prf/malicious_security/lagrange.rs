use std::{borrow::Borrow, fmt::Debug};

use typenum::Unsigned;

use crate::ff::{Field, PrimeField, Serializable};

/// The Canonical Lagrange denominator is defined as the denominator of the Lagrange base polynomials
/// `https://en.wikipedia.org/wiki/Lagrange_polynomial`
/// where the "x coordinates" of the input points are `x_0` to `x_N` are `F::ZERO` to `(N-1)*F::ONE`
/// the degree of the polynomials is `N-1`
pub struct CanonicalLagrangeDenominator<F: Field, const N: usize> {
    denominator: [F; N],
}

impl<F, const N: usize> CanonicalLagrangeDenominator<F, N>
where
    F: PrimeField + TryFrom<u128>,
    <F as TryFrom<u128>>::Error: Debug,
{
    /// generates canonical Lagrange denominators
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    pub fn new() -> Self {
        // assertion that field is large enough
        // when it is large enough, `F::try_from().unwrap()` below does not panic
        assert!(
            u128::try_from(N).unwrap() < u128::try_from(F::PRIME).unwrap(),
            "Field size {} is not large enough to hold {} points",
            F::PRIME.into(),
            N
        );

        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N < 2024);

        Self {
            denominator: (0u128..N.try_into().unwrap())
                .map(|i| {
                    (0u128..N.try_into().unwrap())
                        .filter(|&j| i != j)
                        .map(|j| F::try_from(i).unwrap() - F::try_from(j).unwrap())
                        .fold(F::ONE, |acc, a| acc * a)
                        .invert()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl<F, const N: usize> Default for CanonicalLagrangeDenominator<F, N>
where
    F: PrimeField + TryFrom<u128>,
    <F as TryFrom<u128>>::Error: Debug,
{
    fn default() -> Self {
        Self::new()
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
#[derive(Debug)]
pub struct LagrangeTable<F: Field, const N: usize, const M: usize> {
    table: [[F; N]; M],
}

impl<F, const N: usize> LagrangeTable<F, N, 1>
where
    F: Field + TryFrom<u128>,
    <F as TryFrom<u128>>::Error: Debug,
{
    /// generates a `CanonicalLagrangeTable` from `CanoncialLagrangeDenominators` for a single output point
    /// The "x coordinate" of the output point is `x_output`.
    pub fn new(denominator: &CanonicalLagrangeDenominator<F, N>, x_output: &F) -> Self {
        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N < 2024);

        let table = Self::compute_table_row(x_output, denominator);
        LagrangeTable::<F, N, 1> { table: [table; 1] }
    }
}

impl<F, const N: usize, const M: usize> LagrangeTable<F, N, M>
where
    F: Field,
{
    /// This function uses the `LagrangeTable` to evaluate `polynomial` on the _output_ "x coordinates"
    /// that were used to generate this table.
    /// It is assumed that the `y_coordinates` provided to this function correspond the values of the _input_ "x coordinates"
    /// that were used to generate this table.
    pub fn eval(&self, y_coordinates: &[F; N]) -> [F; M]
    {
        self.table
            .iter()
            .map(|table_row| {
                table_row
                    .iter()
                    .zip(y_coordinates)
                    .fold(F::ZERO, |acc, (&base, y)| acc + base * (*y.borrow()))
            })
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    /// helper function to compute a single row of `LagrangeTable`
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    fn compute_table_row(x_output: &F, denominator: &CanonicalLagrangeDenominator<F, N>) -> [F; N]
    where
        F: Field + TryFrom<u128>,
        <F as TryFrom<u128>>::Error: Debug,
    {
        (0u128..N.try_into().unwrap())
            .map(|i| {
                (0u128..N.try_into().unwrap())
                    .filter(|&j| j != i)
                    .fold(F::ONE, |acc, j| acc * (*x_output - F::try_from(j).unwrap()))
            })
            .zip(&denominator.denominator)
            .map(|(numerator, denominator)| *denominator * numerator)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }
}

impl<F, const N: usize, const M: usize> From<CanonicalLagrangeDenominator<F, N>>
    for LagrangeTable<F, N, M>
where
    F: PrimeField,
{
    fn from(value: CanonicalLagrangeDenominator<F, N>) -> Self {
        // assertion that field is large enough
        // when it is large enough, `F::try_from().unwrap()` below does not panic
        assert!(
            u128::try_from(N + M).unwrap() < u128::try_from(F::PRIME).unwrap(),
            "Field size {} is not large enough to hold {} + {} points",
            F::PRIME.into(),
            N,
            M
        );

        // assertion that table is not too large for the stack
        assert!(<F as Serializable>::Size::USIZE * N * M < 8192);

        LagrangeTable {
            table: (N..(N + M))
                .map(|i| {
                    Self::compute_table_row(&F::try_from(i.try_into().unwrap()).unwrap(), &value)
                })
                .collect::<Vec<[F; N]>>()
                .try_into()
                .unwrap(),
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::{borrow::Borrow, fmt::Debug};

    use proptest::{prelude::*, proptest};

    use crate::{
        ff::PrimeField,
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable,
        },
    };

    type TestField = crate::ff::Fp32BitPrime;

    #[derive(Debug, PartialEq, Clone)]
    struct MonomialFormPolynomial<F: PrimeField, const N: usize> {
        coefficients: [F; N],
    }

    impl<F, const N: usize> MonomialFormPolynomial<F, N>
    where
        F: PrimeField,
    {
        fn gen_y_values_of_canonical_points(self) -> [F; N] {
            // Sadly, we cannot just use the range (0..N::U128) because it does not implement ExactSizeIterator
            let canonical_points = (0..N).map(|i| F::try_from(u128::try_from(i).unwrap()).unwrap());
            self.eval(canonical_points)
        }

        /// test helper function that evaluates a polynomial in monomial form, i.e. `sum_i c_i x^i` on points `x_output`
        /// where `c_0` to `c_N` are stored in `polynomial`
        fn eval<const M: usize, I>(&self, x_output: I) -> [F; M]
        where
            I: IntoIterator,
            I::IntoIter: ExactSizeIterator,
            I::Item: Borrow<F>,
        {
            x_output
                .into_iter()
                .map(|x| {
                    // monomial base, i.e. `x^k`
                    // evaluate p via `sum_k coefficient_k * x^k`
                    let (_, y) = self
                        .coefficients
                        .iter()
                        .fold((F::ONE, F::ZERO), |(base, y), &coef| {
                            (base * (*x.borrow()), y + coef * base)
                        });
                    y
                })
                .collect::<Vec<F>>()
                .try_into()
                .unwrap()
        }
    }

    fn lagrange_single_output_point_using_new(
        output_point: TestField,
        input_points: [TestField; 32],
    ) {
        let polynomial_monomial_form = MonomialFormPolynomial {
            coefficients: input_points,
        };
        let output_expected = polynomial_monomial_form.eval(&[output_point]);
        let denominator = CanonicalLagrangeDenominator::<TestField, 32>::new();
        // generate table using new
        let lagrange_table = LagrangeTable::<TestField, 32, 1>::new(&denominator, &output_point);
        let output =
            lagrange_table.eval(&polynomial_monomial_form.gen_y_values_of_canonical_points());
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
            coefficients: input_points,
        };
        // the canonical x coordinates are 0..7, the outputs use coordinates 8..15:
        let x_coordinates_output =
            (0..7).map(|i| TestField::try_from(u128::try_from(i).unwrap() + 8).unwrap());
        let output_expected = polynomial_monomial_form.eval(x_coordinates_output);
        let denominator = CanonicalLagrangeDenominator::<TestField, 8>::new();
        // generate table using from
        let lagrange_table = LagrangeTable::<TestField, 8, 7>::from(denominator);
        let output =
            lagrange_table.eval(&polynomial_monomial_form.gen_y_values_of_canonical_points());
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
