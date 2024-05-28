use std::{borrow::Borrow, iter::zip};

use crate::{
    ff::{Fp31, Fp61BitPrime, PrimeField},
    helpers::hashing::{compute_hash, hash_to_field},
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
#[allow(non_camel_case_types)]
fn compute_proof_generic<F, J, B, const λ: usize, const P: usize, const M: usize>(
    uv_iterator: J,
    lagrange_table: &LagrangeTable<F, λ, M>,
) -> [F; P]
where
    F: PrimeField,
    J: Iterator<Item = B>,
    B: Borrow<([F; λ], [F; λ])>,
{
    let mut proof = [F::ZERO; P];
    for uv_polynomial in uv_iterator {
        for i in 0..λ {
            proof[i] += uv_polynomial.borrow().0[i] * uv_polynomial.borrow().1[i];
        }
        let p_extrapolated = lagrange_table.eval(&uv_polynomial.borrow().0);
        let q_extrapolated = lagrange_table.eval(&uv_polynomial.borrow().1);

        for (i, (x, y)) in zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate() {
            proof[λ + i] += x * y;
        }
    }
    proof
}

#[allow(non_camel_case_types)]
fn gen_challenge_and_recurse_generic<F, J, B, const λ: usize, const P: usize>(
    proof_left: &[F; P],
    proof_right: &[F; P],
    uv_iterator: J,
) -> Vec<([F; λ], [F; λ])>
where
    F: PrimeField,
    J: Iterator<Item = B>,
    B: Borrow<([F; λ], [F; λ])>,
{
    let r: F = hash_to_field(
        &compute_hash(proof_left),
        &compute_hash(proof_right),
        λ.try_into().unwrap(),
    );
    let mut output = Vec::<([F; λ], [F; λ])>::new();
    let denominator = CanonicalLagrangeDenominator::<F, λ>::new();
    let lagrange_table_r = LagrangeTable::<F, λ, 1>::new(&denominator, &r);

    // iter and interpolate at x coordinate r
    let mut index = 0;
    let mut new_u_chunk = [F::ZERO; λ];
    let mut new_v_chunk = [F::ZERO; λ];
    for polynomial in uv_iterator {
        let (u_chunk, v_chunk) = polynomial.borrow();
        let u = lagrange_table_r.eval(u_chunk)[0];
        let v = lagrange_table_r.eval(v_chunk)[0];
        if index >= λ {
            output.push((new_u_chunk, new_v_chunk));
            new_u_chunk = [F::ZERO; λ];
            new_v_chunk = [F::ZERO; λ];
            index = 0;
        }
        new_u_chunk[index] = u;
        new_v_chunk[index] = v;
        index += 1;
    }
    if index != 0 {
        output.push((new_u_chunk, new_v_chunk));
    }

    output
}

pub struct TestProofGenerator {}

impl TestProofGenerator {
    pub fn compute_proof<J, B>(
        uv_iterator: J,
        lagrange_table: &LagrangeTable<Fp31, 4, 3>,
    ) -> [Fp31; 7]
    where
        J: Iterator<Item = B>,
        B: Borrow<([Fp31; 4], [Fp31; 4])>,
    {
        compute_proof_generic::<Fp31, J, B, 4, 7, 3>(uv_iterator, lagrange_table)
    }

    pub fn gen_challenge_and_recurse<J, B>(
        proof_left: &[Fp31; 7],
        proof_right: &[Fp31; 7],
        uv_iterator: J,
    ) -> Vec<([Fp31; 4], [Fp31; 4])>
    where
        J: Iterator<Item = B>,
        B: Borrow<([Fp31; 4], [Fp31; 4])>,
    {
        gen_challenge_and_recurse_generic::<Fp31, J, B, 4, 7>(proof_left, proof_right, uv_iterator)
    }
}

#[allow(dead_code)]
pub struct LegitProofGenerator {}

#[allow(dead_code)]
impl LegitProofGenerator {
    pub fn compute_proof<J, B>(
        uv_iterator: J,
        lagrange_table: &LagrangeTable<Fp61BitPrime, 32, 31>,
    ) -> [Fp61BitPrime; 63]
    where
        J: Iterator<Item = B>,
        B: Borrow<([Fp61BitPrime; 32], [Fp61BitPrime; 32])>,
    {
        compute_proof_generic::<Fp61BitPrime, J, B, 32, 63, 31>(uv_iterator, lagrange_table)
    }

    pub fn gen_challenge_and_recurse<J, B>(
        proof_left: &[Fp61BitPrime; 63],
        proof_right: &[Fp61BitPrime; 63],
        uv_iterator: J,
    ) -> Vec<([Fp61BitPrime; 32], [Fp61BitPrime; 32])>
    where
        J: Iterator<Item = B>,
        B: Borrow<([Fp61BitPrime; 32], [Fp61BitPrime; 32])>,
    {
        gen_challenge_and_recurse_generic::<Fp61BitPrime, J, B, 32, 63>(
            proof_left,
            proof_right,
            uv_iterator,
        )
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter::zip;

    use crate::{
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::ipa_prf::malicious_security::{
            lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            prover::TestProofGenerator,
        },
    };

    fn zip_chunks<F: PrimeField, const U: usize>(a: &[u128], b: &[u128]) -> Vec<([F; U], [F; U])> {
        zip(a.chunks(U), b.chunks(U))
            .map(|(u_chunk, v_chunk)| {
                let mut u_out = [F::ZERO; U];
                let mut v_out = [F::ZERO; U];
                for i in 0..U {
                    u_out[i] = F::truncate_from(u_chunk[i]);
                    v_out[i] = F::truncate_from(v_chunk[i]);
                }
                (u_out, v_out)
            })
            .collect::<Vec<_>>()
    }

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
        const U_3: [u128; 4] = [3, 3, 0, 0]; // padded with zeroes
        const V_3: [u128; 4] = [5, 24, 0, 0]; // padded with zeroes

        const PROOF_3: [u128; 7] = [12, 15, 10, 0, 18, 6, 5];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let denominator = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let lagrange_table = LagrangeTable::<Fp31, 4, 3>::from(denominator);

        // uv values in input format (iterator of tuples of arrays of length 4)
        let uv_1 = zip_chunks(&U_1, &V_1);

        // first iteration
        let proof_1 = TestProofGenerator::compute_proof(uv_1.iter(), &lagrange_table);
        assert_eq!(
            proof_1.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_1,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_1: [Fp31; 7] = PROOF_LEFT_1.map(|x| Fp31::truncate_from(x));
        let proof_right_1: [Fp31; 7] = zip(proof_1, proof_left_1)
            .map(|(x, y)| x - y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // fiat-shamir
        let uv_2 = TestProofGenerator::gen_challenge_and_recurse(
            &proof_left_1,
            &proof_right_1,
            uv_1.iter(),
        );
        assert_eq!(uv_2, zip_chunks(&U_2, &V_2));

        // next iteration
        let proof_2 = TestProofGenerator::compute_proof(uv_2.iter(), &lagrange_table);
        assert_eq!(
            proof_2.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_2,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_2: [Fp31; 7] = PROOF_LEFT_2.map(|x| Fp31::truncate_from(x));
        let proof_right_2 = zip(proof_2, proof_left_2)
            .map(|(x, y)| x - y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // fiat-shamir
        let uv_3 = TestProofGenerator::gen_challenge_and_recurse(
            &proof_left_2,
            &proof_right_2,
            uv_2.iter(),
        );
        assert_eq!(uv_3, zip_chunks(&U_3[..], &V_3[..]));

        let masked_uv_3 = zip_chunks(
            &[P_RANDOM_WEIGHT, U_3[0], U_3[1], U_3[2]],
            &[Q_RANDOM_WEIGHT, V_3[0], V_3[1], V_3[2]],
        );

        // final iteration
        let proof_3 = TestProofGenerator::compute_proof(masked_uv_3.iter(), &lagrange_table);
        assert_eq!(
            proof_3.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }
}
