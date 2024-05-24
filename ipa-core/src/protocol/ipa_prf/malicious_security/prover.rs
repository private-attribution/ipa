use std::{
    borrow::Borrow,
    iter::zip,
    ops::{Add, Sub},
};

use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use typenum::{Diff, Sum, U1};

use crate::{
    ff::PrimeField,
    helpers::hashing::{compute_hash, hash_to_field},
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

pub struct ZeroKnowledgeProof<F: PrimeField, N: ArrayLength> {
    pub g: GenericArray<F, N>,
}

impl<F, N> ZeroKnowledgeProof<F, N>
where
    F: PrimeField,
    N: ArrayLength,
{
    pub fn new<I>(g: I) -> Self
    where
        I: IntoIterator<Item = F>,
    {
        ZeroKnowledgeProof {
            g: g.into_iter().collect(),
        }
    }
}

#[derive(Debug)]
pub struct ProofGenerator<F: PrimeField> {
    u: Vec<F>,
    v: Vec<F>,
}

pub type TwoNMinusOne<N> = Diff<Sum<N, N>, U1>;
pub type TwoNPlusOne<N> = Sum<Sum<N, N>, U1>;

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_camel_case_types, clippy::many_single_char_names)]
impl<F> ProofGenerator<F>
where
    F: PrimeField,
{
    pub fn new(u: Vec<F>, v: Vec<F>) -> Self {
        debug_assert_eq!(u.len(), v.len(), "u and v must be of equal length");
        Self { u, v }
    }

    pub fn compute_proof<λ, J, B>(
        uv_iterator: J,
        lagrange_table: &LagrangeTable<F, λ, <λ as Sub<U1>>::Output>,
    ) -> ZeroKnowledgeProof<F, TwoNMinusOne<λ>>
    where
        λ: ArrayLength + Add + Sub<U1>,
        <λ as Add>::Output: Sub<U1>,
        <<λ as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <λ as Sub<U1>>::Output: ArrayLength,
        J: Iterator<Item = B>,
        B: Borrow<(GenericArray<F, λ>, GenericArray<F, λ>)>,
    {
        let mut proof = GenericArray::<F, TwoNMinusOne<λ>>::generate(|_| F::ZERO);
        for uv_polynomial in uv_iterator {
            for i in 0..λ::USIZE {
                proof[i] += uv_polynomial.borrow().0[i] * uv_polynomial.borrow().1[i];
            }
            let p_extrapolated = lagrange_table.eval(&uv_polynomial.borrow().0);
            let q_extrapolated = lagrange_table.eval(&uv_polynomial.borrow().1);

            for (i, (x, y)) in
                zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate()
            {
                proof[λ::USIZE + i] += x * y;
            }
        }
        ZeroKnowledgeProof::new(proof)
    }

    pub fn gen_challenge_and_recurse<λ, I, J>(
        proof_left: &GenericArray<F, TwoNMinusOne<λ>>,
        proof_right: &GenericArray<F, TwoNMinusOne<λ>>,
        u: I,
        v: J,
    ) -> ProofGenerator<F>
    where
        λ: ArrayLength + Add + Sub<U1>,
        <λ as Add>::Output: Sub<U1>,
        <<λ as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <λ as Sub<U1>>::Output: ArrayLength,
        I: IntoIterator<Item = F>,
        J: IntoIterator<Item = F>,
        I::IntoIter: ExactSizeIterator,
        J::IntoIter: ExactSizeIterator,
    {
        let mut u = u.into_iter();
        let mut v = v.into_iter();

        debug_assert_eq!(u.len() % λ::USIZE, 0); // We should pad with zeroes eventually

        let s = u.len() / λ::USIZE;

        assert!(
            s > 1,
            "When the output is this small, you should validate the proof with a more straightforward reveal"
        );

        let r: F = hash_to_field(
            &compute_hash(proof_left),
            &compute_hash(proof_right),
            λ::U128,
        );
        let mut p = GenericArray::<F, λ>::generate(|_| F::ZERO);
        let mut q = GenericArray::<F, λ>::generate(|_| F::ZERO);
        let denominator = CanonicalLagrangeDenominator::<F, λ>::new();
        let lagrange_table_r = LagrangeTable::<F, λ, U1>::new(&denominator, &r);

        let pairs = (0..s).map(|_| {
            for i in 0..λ::USIZE {
                let x = u.next().unwrap_or(F::ZERO);
                let y = v.next().unwrap_or(F::ZERO);
                p[i] = x;
                q[i] = y;
            }
            let p_r = lagrange_table_r.eval(&p)[0];
            let q_r = lagrange_table_r.eval(&q)[0];
            (p_r, q_r)
        });
        let (u, v) = pairs.unzip();
        ProofGenerator::new(u, v)
    }
}

impl<F> PartialEq<(&[u128], &[u128])> for ProofGenerator<F>
where
    F: PrimeField + std::cmp::PartialEq<u128>,
{
    fn eq(&self, other: &(&[u128], &[u128])) -> bool {
        let (cmp_a, cmp_b) = other;
        for (i, elem) in cmp_a.iter().enumerate() {
            if !self.u[i].eq(elem) {
                return false;
            }
        }
        for (i, elem) in cmp_b.iter().enumerate() {
            if !self.v[i].eq(elem) {
                return false;
            }
        }
        true
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::{sequence::GenericSequence, GenericArray};
    use typenum::{U3, U4, U7};

    use super::ProofGenerator;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable,
        },
        secret_sharing::SharedValue,
    };

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
        const PROOF_1: [u128; 7] = [0, 30, 29, 30, 5, 28, 13];
        const PROOF_LEFT_1: [u128; 7] = [0, 11, 24, 8, 0, 4, 3];
        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];

        const PROOF_2: [u128; 7] = [12, 6, 15, 8, 29, 30, 6];
        const PROOF_LEFT_2: [u128; 7] = [5, 26, 14, 9, 0, 25, 2];
        const U_3: [u128; 2] = [3, 3];
        const V_3: [u128; 2] = [5, 24];

        const PROOF_3: [u128; 7] = [12, 15, 10, 0, 18, 6, 5];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let denominator = CanonicalLagrangeDenominator::<Fp31, U4>::new();
        let lagrange_table = LagrangeTable::<Fp31, U4, U3>::from(denominator);

        // convert to field
        let vec_u_1 = U_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_1 = V_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_u_2 = U_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_2 = V_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_u_3 = U_3
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_3 = V_3
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();

        // uv values in input format
        let uv_1 = (0usize..8)
            .map(|i| {
                (
                    *GenericArray::<Fp31, U4>::from_slice(&vec_u_1[4 * i..4 * i + 4]),
                    *GenericArray::<Fp31, U4>::from_slice(&vec_v_1[4 * i..4 * i + 4]),
                )
            })
            .collect::<Vec<_>>();
        let uv_2 = (0usize..2)
            .map(|i| {
                (
                    *GenericArray::<Fp31, U4>::from_slice(&vec_u_2[4 * i..4 * i + 4]),
                    *GenericArray::<Fp31, U4>::from_slice(&vec_v_2[4 * i..4 * i + 4]),
                )
            })
            .collect::<Vec<_>>();
        let uv_3 = vec![(
            GenericArray::<Fp31, U4>::from([
                Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
                vec_u_3[0],
                vec_u_3[1],
                Fp31::ZERO,
            ]),
            GenericArray::<Fp31, U4>::from([
                Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
                vec_v_3[0],
                vec_v_3[1],
                Fp31::ZERO,
            ]),
        )];

        // first iteration
        let proof_1 =
            ProofGenerator::<Fp31>::compute_proof::<U4, _, _>(uv_1.iter(), &lagrange_table);
        assert_eq!(
            proof_1.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_1,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_1 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_1[i]).unwrap());
        let proof_right_1 = GenericArray::<Fp31, U7>::generate(|i| proof_1.g[i] - proof_left_1[i]);

        // fiat-shamir
        let pg_2 = ProofGenerator::gen_challenge_and_recurse::<U4, _, _>(
            &proof_left_1,
            &proof_right_1,
            U_1.into_iter().map(|x| Fp31::try_from(x).unwrap()),
            V_1.into_iter().map(|x| Fp31::try_from(x).unwrap()),
        );
        assert_eq!(pg_2, (&U_2[..], &V_2[..]));

        // next iteration
        let proof_2 =
            ProofGenerator::<Fp31>::compute_proof::<U4, _, _>(uv_2.iter(), &lagrange_table);
        assert_eq!(
            proof_2.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_2,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_2 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_2[i]).unwrap());
        let proof_right_2 = GenericArray::<Fp31, U7>::generate(|i| proof_2.g[i] - proof_left_2[i]);

        // fiat-shamir
        let pg_3 = ProofGenerator::gen_challenge_and_recurse::<U4, _, _>(
            &proof_left_2,
            &proof_right_2,
            pg_2.u,
            pg_2.v,
        );
        assert_eq!(pg_3, (&U_3[..], &V_3[..]));

        // final iteration
        let proof_3 =
            ProofGenerator::<Fp31>::compute_proof::<U4, _, _>(uv_3.iter(), &lagrange_table);
        assert_eq!(
            proof_3.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }
}
