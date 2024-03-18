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
type TwoNPlusOne<N> = Sum<Sum<N, N>, U1>;

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

    pub fn compute_final_proof<λ: ArrayLength>(
        &self,
        p_0: F,
        q_0: F,
    ) -> ZeroKnowledgeProof<F, TwoNPlusOne<λ>>
    where
        λ: ArrayLength + Add + Add<U1>,
        <λ as Add>::Output: Add<U1>,
        <<λ as Add>::Output as Add<U1>>::Output: ArrayLength,
        <λ as Add<U1>>::Output: ArrayLength,
    {
        assert_eq!(self.u.len(), λ::USIZE); // We should pad with zeroes eventually

        let denominator = CanonicalLagrangeDenominator::<F, Sum<λ, U1>>::new();
        //let lagrange_table_r = LagrangeTable::<F, λ, U1>::new(&denominator, &r);
        let lagrange_table = LagrangeTable::<F, Sum<λ, U1>, λ>::from(denominator);

        let mut p = vec![p_0];
        p.extend_from_slice(&self.u);
        let mut q = vec![q_0];
        q.extend_from_slice(&self.v);
        let p_extrapolated = lagrange_table.eval(&p);
        let q_extrapolated = lagrange_table.eval(&q);

        // let p_r = lagrange_table_r.eval(&p)[0];
        // let q_r = lagrange_table_r.eval(&q)[0];

        ZeroKnowledgeProof {
            g: zip(p, q)
                .map(|(a, b)| a * b)
                .chain(zip(p_extrapolated, q_extrapolated).map(|(a, b)| a * b))
                .collect(),
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use typenum::{U2, U4};

    use super::ProofGenerator;
    use crate::ff::{Fp31, U128Conversions};

    #[test]
    fn sample_proof() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const EXPECTED_1: [u128; 7] = [0, 30, 29, 30, 5, 28, 13];
        const R_1: u128 = 22;
        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];

        const EXPECTED_2: [u128; 7] = [12, 6, 15, 8, 29, 30, 6];
        const R_2: u128 = 17;
        const U_3: [u128; 2] = [3, 3];
        const V_3: [u128; 2] = [5, 24];

        const EXPECTED_3: [u128; 5] = [12, 15, 10, 14, 17];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let pg: ProofGenerator<Fp31> = ProofGenerator::new(
            U_1.into_iter()
                .map(|x| Fp31::try_from(x).unwrap())
                .collect(),
            V_1.into_iter()
                .map(|x| Fp31::try_from(x).unwrap())
                .collect(),
        );

        // first iteration
        let (proof, pg_2) = pg.compute_proof::<U4>(Fp31::try_from(R_1).unwrap());
        assert_eq!(
            proof.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            EXPECTED_1,
        );
        assert_eq!(pg_2.u.iter().map(Fp31::as_u128).collect::<Vec<_>>(), U_2,);
        assert_eq!(pg_2.v.iter().map(Fp31::as_u128).collect::<Vec<_>>(), V_2,);

        // next iteration
        let (proof_2, pg_3) = pg_2.compute_proof::<U4>(Fp31::try_from(R_2).unwrap());
        assert_eq!(
            proof_2.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            EXPECTED_2,
        );
        assert_eq!(pg_3.u.iter().map(Fp31::as_u128).collect::<Vec<_>>(), U_3,);
        assert_eq!(pg_3.v.iter().map(Fp31::as_u128).collect::<Vec<_>>(), V_3,);

        // final iteration
        let proof_3 = pg_3.compute_final_proof::<U2>(
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
        );
        assert_eq!(
            proof_3.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            EXPECTED_3,
        );
    }
}
