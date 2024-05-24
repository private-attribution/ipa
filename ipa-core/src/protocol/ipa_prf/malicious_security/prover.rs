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

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct ProofGenerator<F: PrimeField, λ>
where
    λ: ArrayLength,
{
    uv: Vec<(GenericArray<F, λ>, GenericArray<F, λ>)>,
}

pub type TwoNMinusOne<N> = Diff<Sum<N, N>, U1>;
pub type TwoNPlusOne<N> = Sum<Sum<N, N>, U1>;

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_camel_case_types, clippy::many_single_char_names)]
impl<F, λ> ProofGenerator<F, λ>
where
    F: PrimeField,
    λ: ArrayLength,
{
    pub fn compute_proof<J, B>(
        uv_iterator: J,
        lagrange_table: &LagrangeTable<F, λ, <λ as Sub<U1>>::Output>,
    ) -> ZeroKnowledgeProof<F, TwoNMinusOne<λ>>
    where
        λ: Add + Sub<U1>,
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

    pub fn compute_final_proof(
        uv: &(GenericArray<F, λ>, GenericArray<F, λ>),
        p_0: F,
        q_0: F,
        lagrange_table: &LagrangeTable<F, Sum<λ, U1>, λ>,
    ) -> ZeroKnowledgeProof<F, TwoNPlusOne<λ>>
    where
        λ: Add + Add<U1>,
        <λ as Add>::Output: Add<U1>,
        <<λ as Add>::Output as Add<U1>>::Output: ArrayLength,
        <λ as Add<U1>>::Output: ArrayLength,
    {
        let mut p = GenericArray::<F, Sum<λ, U1>>::generate(|_| F::ZERO);
        let mut q = GenericArray::<F, Sum<λ, U1>>::generate(|_| F::ZERO);
        let mut proof: GenericArray<F, TwoNPlusOne<λ>> = GenericArray::generate(|_| F::ZERO);
        p[0] = p_0;
        q[0] = q_0;
        proof[0] = p_0 * q_0;

        for i in 0..λ::USIZE {
            p[i + 1] = uv.0[i];
            q[i + 1] = uv.1[i];
            proof[i + 1] += uv.0[i] * uv.1[i];
        }
        // We need a table of size `λ + 1` since we add a random point at x=0
        let p_extrapolated = lagrange_table.eval(&p);
        let q_extrapolated = lagrange_table.eval(&q);

        for (i, (x, y)) in zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate() {
            proof[λ::USIZE + 1 + i] += x * y;
        }

        ZeroKnowledgeProof::new(proof)
    }

    pub fn gen_challenge_and_recurse<J, B>(
        proof_left: &GenericArray<F, TwoNMinusOne<λ>>,
        proof_right: &GenericArray<F, TwoNMinusOne<λ>>,
        uv_iterator: J,
    ) -> Self
    where
        λ: Add + Sub<U1>,
        <λ as Add>::Output: Sub<U1>,
        <<λ as Add>::Output as Sub<U1>>::Output: ArrayLength,
        <λ as Sub<U1>>::Output: ArrayLength,
        J: Iterator<Item = B>,
        B: Borrow<(GenericArray<F, λ>, GenericArray<F, λ>)>,
    {
        let r: F = hash_to_field(
            &compute_hash(proof_left),
            &compute_hash(proof_right),
            λ::U128,
        );
        let mut output = Vec::<(GenericArray<F, λ>, GenericArray<F, λ>)>::new();
        let denominator = CanonicalLagrangeDenominator::<F, λ>::new();
        let lagrange_table_r = LagrangeTable::<F, λ, U1>::new(&denominator, &r);

        // iter and interpolate at x coordinate r
        let mut index = 0;
        let mut new_u_chunk = GenericArray::<F, λ>::generate(|_| F::ZERO);
        let mut new_v_chunk = GenericArray::<F, λ>::generate(|_| F::ZERO);
        for polynomial in uv_iterator {
            let (u_chunk, v_chunk) = polynomial.borrow();
            let u = lagrange_table_r.eval(u_chunk)[0];
            let v = lagrange_table_r.eval(v_chunk)[0];
            if index >= λ::USIZE {
                output.push((new_u_chunk, new_v_chunk));
                new_u_chunk = GenericArray::<F, λ>::generate(|_| F::ZERO);
                new_v_chunk = GenericArray::<F, λ>::generate(|_| F::ZERO);
                index = 0;
            }
            new_u_chunk[index] = u;
            new_v_chunk[index] = v;
            index += 1;
        }
        if index != 0 {
            output.push((new_u_chunk, new_v_chunk));
        }

        Self { uv: output }
    }
}

#[allow(non_camel_case_types)]
impl<F, λ> PartialEq<(&[u128], &[u128])> for ProofGenerator<F, λ>
where
    F: PrimeField + std::cmp::PartialEq<u128>,
    λ: ArrayLength,
{
    fn eq(&self, other: &(&[u128], &[u128])) -> bool {
        let (cmp_a, cmp_b) = other;
        for (i, uv_polynomial) in self.uv.iter().enumerate() {
            for (j, u) in uv_polynomial.0.iter().enumerate() {
                if !u.eq(&cmp_a[i * λ::USIZE + j]) {
                    return false;
                }
            }
            for (j, v) in uv_polynomial.1.iter().enumerate() {
                if !v.eq(&cmp_b[i * λ::USIZE + j]) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::{sequence::GenericSequence, GenericArray};
    use typenum::{U2, U3, U4, U7};

    use super::ProofGenerator;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable,
        },
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

        const PROOF_3: [u128; 5] = [12, 15, 10, 14, 17];
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

        // first iteration
        let proof_1 = ProofGenerator::<Fp31, U4>::compute_proof(uv_1.iter(), &lagrange_table);
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
        let pg_2 = ProofGenerator::<_, U4>::gen_challenge_and_recurse(
            &proof_left_1,
            &proof_right_1,
            uv_1.iter(),
        );
        assert_eq!(pg_2, (&U_2[..], &V_2[..]));

        // next iteration
        let proof_2 = ProofGenerator::<Fp31, U4>::compute_proof(uv_2.iter(), &lagrange_table);
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
        let pg_3 = ProofGenerator::<_, U4>::gen_challenge_and_recurse(
            &proof_left_2,
            &proof_right_2,
            pg_2.uv.iter(),
        );

        // final proof trim pg_3 from U4 to U2
        let uv = (
            *GenericArray::<Fp31, U2>::from_slice(&pg_3.uv[0].0.as_slice()[0..2]),
            *GenericArray::<Fp31, U2>::from_slice(&pg_3.uv[0].1.as_slice()[0..2]),
        );

        assert_eq!(ProofGenerator { uv: vec![uv; 1] }, (&U_3[..], &V_3[..]));

        // final iteration
        let denominator = CanonicalLagrangeDenominator::<Fp31, U3>::new();
        let lagrange_table = LagrangeTable::<Fp31, U3, U2>::from(denominator);
        let proof_3 = ProofGenerator::<Fp31, U2>::compute_final_proof(
            &uv,
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
            &lagrange_table,
        );
        assert_eq!(
            proof_3.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }
}
