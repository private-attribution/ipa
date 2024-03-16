use std::{
    iter::zip,
    ops::{Add, Sub},
};

use generic_array::{arr, sequence::GenericSequence, ArrayLength, GenericArray};
use typenum::{Diff, Sum, Unsigned, U1};

use crate::{
    ff::PrimeField,
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable, Polynomial,
    },
};

pub struct ProofGenerator<F: PrimeField> {
    u: Vec<F>,
    v: Vec<F>,
}

impl<F> ProofGenerator<F>
where
    F: PrimeField,
{
    pub fn compute_proof<N: ArrayLength>(self) -> GenericArray<F, Diff<Sum<N, N>, U1>>
    where
        N: ArrayLength + Add + Sub<U1>,
        <N as Add>::Output: Sub<U1>,
        <<N as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <N as Sub<U1>>::Output: ArrayLength,
    {
        assert!(self.u.len() % N::USIZE == 0); // We should pad with zeroes eventually

        let strip_len = self.u.len() / N::USIZE;

        let denominator = CanonicalLagrangeDenominator::<F, N>::new();
        let lagrange_table = LagrangeTable::<F, N, <N as Sub<U1>>::Output>::from(denominator);
        let extrapolated_points = (0..strip_len).map(|i| {
            let p: GenericArray<F, N> = (0..N::USIZE).map(|j| self.u[i * N::USIZE + j]).collect();
            let q: GenericArray<F, N> = (0..N::USIZE).map(|j| self.v[i * N::USIZE + j]).collect();
            let p_extrapolated = lagrange_table.eval(&p);
            let q_extrapolated = lagrange_table.eval(&q);
            zip(
                p.into_iter().chain(p_extrapolated),
                q.into_iter().chain(q_extrapolated),
            )
            .map(|(a, b)| a * b)
            .collect::<GenericArray<F, _>>()
        });
        extrapolated_points
            .reduce(|acc, pts| zip(acc, pts).map(|(a, b)| a + b).collect())
            .unwrap()
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::fmt::Debug;

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use proptest::{prelude::*, proptest};
    use typenum::{U1, U32, U4, U7, U8};

    use super::ProofGenerator;
    use crate::{
        ff::{Field, Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable, Polynomial,
        },
    };

    #[test]
    fn sample_proof() {
        const U: [u128; 32] = [
            0, 0, 1, 15, 0, 0, 0, 15, 2, 30, 30, 16, 29, 1, 1, 15, 0, 0, 0, 15, 0, 0, 0, 15, 2, 30,
            30, 16, 0, 0, 1, 15,
        ];
        const V: [u128; 32] = [
            30, 30, 30, 30, 0, 1, 0, 1, 0, 0, 0, 30, 0, 30, 0, 30, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
            30, 0, 0, 30, 30,
        ];
        const EXPECTED: [u128; 7] = [0, 30, 29, 30, 3, 22, 6];
        let pg: ProofGenerator<Fp31> = ProofGenerator {
            u: U.into_iter().map(|x| Fp31::try_from(x).unwrap()).collect(),
            v: V.into_iter().map(|x| Fp31::try_from(x).unwrap()).collect(),
        };
        let proof = pg.compute_proof::<U4>();
        assert_eq!(
            proof.into_iter().map(|x| x.as_u128()).collect::<Vec<_>>(),
            EXPECTED
        );
    }
}
