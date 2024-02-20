use std::iter;

use generic_array::{ArrayLength, GenericArray};
use typenum::U1;

use crate::ff::{Field, PrimeField};

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
    F: PrimeField,
    N: ArrayLength,
{
    /// generates canonical Lagrange denominators
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    pub fn new() -> Self {
        // assertion that field is large enough
        // also checks that `try_from` for conversions from sufficiently small `u128` to `F` do not panic
        debug_assert!(F::BITS > usize::BITS - N::USIZE.leading_zeros());

        let mut denominator = iter::repeat(F::ONE)
            .take(N::USIZE)
            .collect::<GenericArray<_, N>>();
        for (i, d) in denominator.iter_mut().enumerate() {
            for j in (0usize..N::USIZE).filter(|&j| i != j) {
                *d *= F::try_from(i as u128).unwrap() - F::try_from(j as u128).unwrap();
            }
            *d = d.invert();
        }
        Self { denominator }
    }
}

/// `LagrangeTable` is a precomputation table for the Lagrange evaluation.
/// The "x coordinates" of the input points are `x_0` to `x_(N-1)` are `F::ZERO` to `(N-1)*F::ONE`.
/// The `LagrangeTable` also specifies `M` "x coordinates" for the output points
/// The "x coordinates" of the output points are `x_N` to `x_(N+M-1)` are `N*F::ONE` to `(N+M-1)*F::ONE`.
pub struct LagrangeTable<F: Field, N: ArrayLength, M: ArrayLength> {
    table: GenericArray<GenericArray<F, N>, M>,
}

impl<F, N> LagrangeTable<F, N, U1>
where
    F: Field,
    N: ArrayLength,
{
    /// generates a `CanonicalLagrangeTable` from `CanoncialLagrangeDenominators` for a single output point
    /// The "x coordinate" of the output point is `x_output`.
    pub fn new(denominator: CanonicalLagrangeDenominator<F, N>, x_output: &F) -> Self {
        let mut table = denominator.denominator;
        Self::compute_table_row(x_output, &mut table);
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
        let mut result = iter::repeat(F::ONE)
            .take(M::USIZE)
            .collect::<GenericArray<_, _>>();
        self.mult_result_by_evaluation(polynomial, &mut result);
        result
    }

    /// This function uses the `LagrangeTable` to evaluate `polynomial` on the specified output "x coordinates"
    /// the "y coordinates" of the evaluation are multiplied to `result`
    pub fn mult_result_by_evaluation(
        &self,
        polynomial: &Polynomial<F, N>,
        result: &mut GenericArray<F, M>,
    ) {
        for (y, base) in result.iter_mut().zip(self.table.iter()) {
            *y *= base
                .iter()
                .zip(polynomial.y_coordinates.iter())
                .fold(F::ZERO, |acc, (&base, &y)| acc + base * y);
        }
    }

    /// helper function to compute a single row of `CanonicalLagrangeTable`
    ///
    /// ## Panics
    /// When the field size is too small for `N` evaluation points
    fn compute_table_row(x_output: &F, table_row: &mut GenericArray<F, N>)
    where
        F: Field,
        N: ArrayLength,
    {
        for (i, entry) in table_row.iter_mut().enumerate() {
            for j in (0usize..N::USIZE).filter(|&j| j != i) {
                *entry *= *x_output - F::try_from(j as u128).unwrap();
            }
        }
    }
}

impl<F, N, M> From<CanonicalLagrangeDenominator<F, N>> for LagrangeTable<F, N, M>
where
    F: Field,
    N: ArrayLength,
    M: ArrayLength,
{
    fn from(value: CanonicalLagrangeDenominator<F, N>) -> Self {
        // assertion that field is large enough
        // also checks that `try_from` for conversions from sufficiently small `u128` to `F` do not panic
        debug_assert!(F::BITS > usize::BITS - (N::USIZE + M::USIZE).leading_zeros());

        let mut table = iter::repeat(value.denominator.clone())
            .take(M::USIZE)
            .collect::<GenericArray<_, _>>();
        table.iter_mut().enumerate().for_each(|(i, row)| {
            Self::compute_table_row(&F::try_from((i + N::USIZE) as u128).unwrap(), row);
        });
        LagrangeTable { table }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use generic_array::{ArrayLength, GenericArray};
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
            // evaluate polynomial p at evaluation_points and random point using monomial base
            let mut y_values = iter::repeat(F::ZERO)
                .take(M::USIZE)
                .collect::<GenericArray<_, _>>();
            for (x, y) in x_output.iter().zip(y_values.iter_mut()) {
                // monomial base, i.e. `x^k`
                let mut base = F::ONE;
                // evaluate p via `sum_k coefficient_k * x^k`
                for coefficient in &self.coefficients {
                    *y += *coefficient * base;
                    base *= *x;
                }
            }
            y_values
        }
    }

    impl<F, N> From<MonomialFormPolynomial<F, N>> for Polynomial<F, N>
    where
        F: Field,
        N: ArrayLength,
    {
        fn from(value: MonomialFormPolynomial<F, N>) -> Self {
            let canonical_points: GenericArray<F, N> = (0..N::USIZE)
                .map(|i| F::try_from(i as u128).unwrap())
                .collect::<GenericArray<_, _>>();
            Polynomial {
                y_coordinates: value.eval(&canonical_points),
            }
        }
    }

    proptest! {
        #[test]
        fn lagrange_single_output_point_using_new(output_point: TestField, input_points in prop::array::uniform32(any::<TestField>())){
            let polynomial_monomial_form = MonomialFormPolynomial{
                coefficients: GenericArray::<TestField,U32>::from_array(input_points)};
            let output_expected = polynomial_monomial_form.eval(
                &GenericArray::<TestField,U1>::from_array([output_point;1]));
            let polynomial = Polynomial::from(polynomial_monomial_form.clone());
            let denominator = CanonicalLagrangeDenominator::<TestField,U32>::new();
            // generate table using new
            let lagrange_table = LagrangeTable::<TestField,U32,U1>::new(denominator,&output_point);
            let output = lagrange_table.eval(&polynomial);
            assert_eq!(output,output_expected);
        }

        #[test]
        fn lagrange_cannonical_using_from(input_points in prop::array::uniform8(any::<TestField>()))
        {
            let polynomial_monomial_form = MonomialFormPolynomial{
                coefficients: GenericArray::<TestField,U8>::from_array(input_points)};
            // the canonical x coordinates are 0..15, the outputs use coordinates 8..15:
            let x_coordinates_output = (8..15).map(|i|TestField::try_from(i).unwrap()).collect::<GenericArray<_, _>>();
            let output_expected = polynomial_monomial_form.eval(&x_coordinates_output);
            let polynomial = Polynomial::from(polynomial_monomial_form.clone());
            let denominator = CanonicalLagrangeDenominator::<TestField,U8>::new();
            // generate table using from
            let lagrange_table = LagrangeTable::<TestField,U8,U7>::from(denominator);
            let output = lagrange_table.eval(&polynomial);
            assert_eq!(output,output_expected);
        }
    }
}
