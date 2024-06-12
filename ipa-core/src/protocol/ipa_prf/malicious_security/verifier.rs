use std::borrow::Borrow;

use crate::{
    ff::PrimeField,
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_upper_case_globals)]
/// This function interprets the zkp as points on a polynomial, and interpolates the
/// value of this polynomial at the provided value of `r`
pub fn interpolate_at_r<F: PrimeField, const λ: usize, const P: usize>(
    zkp: &[F; P],
    r: F,
    lagrange_denominator: &CanonicalLagrangeDenominator<F, P>,
) -> F {
    let lagrange_table_g = LagrangeTable::<F, P, 1>::new(lagrange_denominator, &r);
    lagrange_table_g.eval(zkp)[0]
}

/// This function computes the sum of the first λ elements of the zero-knowledge proof
#[allow(non_upper_case_globals)]
pub fn compute_sum_share<F: PrimeField, const λ: usize, const P: usize>(zkp: &[F; P]) -> F {
    (0..λ).fold(F::ZERO, |acc, i| acc + zkp[i])
}

/// This function compresses the `u_or_v` values.
#[allow(non_upper_case_globals)]
pub fn recurse_u_or_v<F: PrimeField, J, B, const λ: usize>(
    u_or_v_iterator: J,
    r: F,
) -> Vec<[F; λ]>
where
    J: Iterator<Item = B>,
    B: Borrow<[F; λ]>,
{
    let denominator_p_or_q = CanonicalLagrangeDenominator::<F, λ>::new();
    let lagrange_table_p_or_q_r = LagrangeTable::<F, λ, 1>::new(&denominator_p_or_q, &r);

    let mut new_u_or_v_vec = Vec::<[F; λ]>::new();

    // iter and interpolate at x coordinate r
    let mut index = 0;
    let mut new_u_or_v_chunk = [F::ZERO; λ];
    for polynomial in u_or_v_iterator {
        let value_at_r = lagrange_table_p_or_q_r.eval(polynomial.borrow())[0];
        if index >= λ {
            new_u_or_v_vec.push(new_u_or_v_chunk);
            new_u_or_v_chunk = [F::ZERO; λ];
            index = 0;
        }
        new_u_or_v_chunk[index] = value_at_r;
        index += 1;
    }
    if index > 0 {
        new_u_or_v_vec.push(new_u_or_v_chunk);
    }

    new_u_or_v_vec
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use crate::{
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::ipa_prf::malicious_security::{
            lagrange::CanonicalLagrangeDenominator,
            verifier::{compute_sum_share, interpolate_at_r, recurse_u_or_v},
        },
    };

    fn make_chunks<F: PrimeField, const N: usize>(a: &[u128]) -> Vec<[F; N]> {
        a.chunks(N)
            .map(|chunk| <[u128; N]>::try_from(chunk).unwrap().map(F::truncate_from))
            .collect::<Vec<_>>()
    }

    #[test]
    fn sample_proof_u() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const OUT_1: u128 = 27;
        const ZKP_1: [u128; 7] = [0, 0, 13, 17, 11, 25, 7];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 0;
        const EXPECTED_B_1: u128 = 3;

        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const ZKP_2: [u128; 7] = [11, 25, 17, 9, 22, 23, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 13;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [21, 1, 6, 25, 1];
        const U_3: [u128; 2] = [3, 3];
        const R_3: u128 = 30;
        const P_RANDOM_WEIGHT: u128 = 12;

        const EXPECTED_P_FINAL: u128 = 30;
        const EXPECTED_G_R_FINAL: u128 = 0;

        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // uv values in input format
        let u_1 = make_chunks::<_, 4>(&U_1);

        // first iteration
        let zkp_1 = ZKP_1.map(Fp31::truncate_from);

        let g_r_share_1 = interpolate_at_r::<Fp31, 4, 7>(
            &zkp_1,
            Fp31::try_from(R_1).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_1).unwrap();

        assert_eq!(g_r_share_1.as_u128(), EXPECTED_G_R_1);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1);

        let u_or_v_2 = recurse_u_or_v(u_1.iter(), Fp31::try_from(R_1).unwrap());
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&U_2));

        // second iteration
        let zkp_2 = ZKP_2.map(Fp31::truncate_from);

        let g_r_share_2 = interpolate_at_r::<Fp31, 4, 7>(
            &zkp_2,
            Fp31::try_from(R_2).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2);
        assert_eq!(zero_share_2.as_u128(), EXPECTED_B_2);

        let u_or_v_3_temp = recurse_u_or_v(u_or_v_2.iter(), Fp31::try_from(R_2).unwrap());

        // final proof trim from U4 to U2
        let u_or_v_3 = [
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            u_or_v_3_temp[0][0],
            u_or_v_3_temp[0][1],
        ];

        assert_eq!([u_or_v_3[1], u_or_v_3[2]], make_chunks::<Fp31, 2>(&U_3)[0]);

        // final iteration
        let zkp_3 = ZKP_3.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r::<Fp31, 3, 5>(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            &final_lagrange_denominator,
        );

        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL);

        let p_final = recurse_u_or_v(iter::once(u_or_v_3), Fp31::try_from(R_3).unwrap());

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_P_FINAL);
    }

    #[test]
    fn sample_proof_v() {
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const OUT_1: u128 = 0;
        const ZKP_1: [u128; 7] = [0, 30, 16, 13, 25, 3, 6];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 10;
        const EXPECTED_B_1: u128 = 28;

        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];
        const ZKP_2: [u128; 7] = [1, 12, 29, 30, 7, 7, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 12;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [22, 14, 4, 20, 16];
        const V_3: [u128; 2] = [5, 24];
        const R_3: u128 = 30;
        const Q_RANDOM_WEIGHT: u128 = 1;

        const EXPECTED_Q_FINAL: u128 = 12;
        const EXPECTED_G_R_FINAL: u128 = 19;

        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // uv values in input format
        let v_1 = make_chunks::<_, 4>(&V_1);

        // first iteration
        let zkp_1 = ZKP_1.map(Fp31::truncate_from);

        let g_r_share_1 = interpolate_at_r::<Fp31, 4, 7>(
            &zkp_1,
            Fp31::try_from(R_1).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_1).unwrap();

        assert_eq!(g_r_share_1, EXPECTED_G_R_1);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1);

        let u_or_v_2 = recurse_u_or_v(v_1.iter(), Fp31::try_from(R_1).unwrap());
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&V_2));

        // second iteration
        let zkp_2 = ZKP_2.map(Fp31::truncate_from);

        let g_r_share_2 = interpolate_at_r::<Fp31, 4, 7>(
            &zkp_2,
            Fp31::try_from(R_2).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2);
        assert_eq!(zero_share_2, EXPECTED_B_2);

        let u_or_v_3_temp = recurse_u_or_v(u_or_v_2.iter(), Fp31::try_from(R_2).unwrap());

        // final proof trim from U4 to U2
        let u_or_v_3 = [
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
            u_or_v_3_temp[0][0],
            u_or_v_3_temp[0][1],
        ];

        assert_eq!([u_or_v_3[1], u_or_v_3[2]], make_chunks::<Fp31, 2>(&V_3)[0]);

        // final iteration
        let zkp_3 = ZKP_3.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r::<Fp31, 3, 5>(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            &final_lagrange_denominator,
        );
        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL);

        let p_final = recurse_u_or_v(iter::once(u_or_v_3), Fp31::try_from(R_3).unwrap());

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_Q_FINAL);
    }
}
