use std::{
    iter::zip,
    ops::{Add, Sub},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::{Diff, Sum, U1};

use crate::{
    ff::PrimeField,
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

pub struct ZeroKnowledgeProof<F: PrimeField, N: ArrayLength> {
    g: GenericArray<F, N>,
}

pub struct ProofGenerator<F: PrimeField> {
    u: Vec<F>,
    v: Vec<F>,
}

type TwoNMinusOne<N> = Diff<Sum<N, N>, U1>;

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_camel_case_types)]
impl<F> ProofGenerator<F>
where
    F: PrimeField,
{
    pub fn new(u: Vec<F>, v: Vec<F>) -> Self {
        debug_assert_eq!(u.len(), v.len(), "u and v must be of equal length");
        Self { u, v }
    }

    pub fn compute_proof<λ: ArrayLength>(
        &self,
        r: F,
    ) -> (ZeroKnowledgeProof<F, TwoNMinusOne<λ>>, ProofGenerator<F>)
    where
        λ: ArrayLength + Add + Sub<U1>,
        <λ as Add>::Output: Sub<U1>,
        <<λ as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <λ as Sub<U1>>::Output: ArrayLength,
    {
        debug_assert_eq!(self.u.len() % λ::USIZE, 0); // We should pad with zeroes eventually

        let s = self.u.len() / λ::USIZE;

        assert!(
            s > 1,
            "When the output is this small, you should call `compute_final_proof`"
        );

        let mut next_proof_generator = ProofGenerator {
            u: Vec::<F>::with_capacity(s),
            v: Vec::<F>::with_capacity(s),
        };

        let denominator = CanonicalLagrangeDenominator::<F, λ>::new();
        let lagrange_table_r = LagrangeTable::<F, λ, U1>::new(&denominator, &r);
        let lagrange_table = LagrangeTable::<F, λ, <λ as Sub<U1>>::Output>::from(denominator);
        let extrapolated_points = (0..s).map(|i| {
            let start = i * λ::USIZE;
            let end = start + λ::USIZE;
            let p = &self.u[start..end];
            let q = &self.v[start..end];
            let p_extrapolated = lagrange_table.eval(p);
            let q_extrapolated = lagrange_table.eval(q);
            let p_r = lagrange_table_r.eval(p)[0];
            let q_r = lagrange_table_r.eval(q)[0];
            next_proof_generator.u.push(p_r);
            next_proof_generator.v.push(q_r);
            // p.into_iter() has elements that are &F
            // p_extrapolated.into_iter() has elements that are F
            // So these iterators cannot be chained.
            zip(p, q)
                .map(|(a, b)| *a * *b)
                .chain(zip(p_extrapolated, q_extrapolated).map(|(a, b)| a * b))
                .collect::<GenericArray<F, _>>()
        });
        let proof = ZeroKnowledgeProof {
            g: extrapolated_points
                .reduce(|acc, pts| zip(acc, pts).map(|(a, b)| a + b).collect())
                .unwrap(),
        };
        (proof, next_proof_generator)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use typenum::U4;

    use super::ProofGenerator;
    use crate::ff::{Fp31, U128Conversions};

    #[test]
    fn sample_proof() {
        const U: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const V: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const EXPECTED: [u128; 7] = [0, 30, 29, 30, 5, 28, 13];
        const R1: u128 = 22;
        const EXPECTED_NEXT_U: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const EXPECTED_NEXT_V: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];
        let pg: ProofGenerator<Fp31> = ProofGenerator::new(
            U.into_iter().map(|x| Fp31::try_from(x).unwrap()).collect(),
            V.into_iter().map(|x| Fp31::try_from(x).unwrap()).collect(),
        );
        let (proof, next_proof_generator) = pg.compute_proof::<U4>(Fp31::try_from(R1).unwrap());
        assert_eq!(
            proof.g.into_iter().map(|x| x.as_u128()).collect::<Vec<_>>(),
            EXPECTED,
        );
        assert_eq!(
            next_proof_generator
                .u
                .into_iter()
                .map(|x| x.as_u128())
                .collect::<Vec<_>>(),
            EXPECTED_NEXT_U,
        );
        assert_eq!(
            next_proof_generator
                .v
                .into_iter()
                .map(|x| x.as_u128())
                .collect::<Vec<_>>(),
            EXPECTED_NEXT_V,
        );
    }
}
