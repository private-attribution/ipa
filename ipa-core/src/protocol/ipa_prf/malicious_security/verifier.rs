use std::pin::Pin;

use futures::Stream;
use futures_util::StreamExt;

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
/// This function interprets the zkp as points on a polynomial, and interpolates the
/// value of this polynomial at the provided value of `r`
fn interpolate_at_r<F: PrimeField, const P: usize>(
    zkp: &[F; P],
    r: F,
    lagrange_denominator: &CanonicalLagrangeDenominator<F, P>,
) -> F {
    let lagrange_table_g = LagrangeTable::<F, P, 1>::new(lagrange_denominator, &r);
    lagrange_table_g.eval(zkp)[0]
}

/// This function computes the sum of the first λ elements of the zero-knowledge proof
fn compute_sum_share<F: PrimeField, const λ: usize, const P: usize>(zkp: &[F; P]) -> F {
    (0..λ).fold(F::ZERO, |acc, i| acc + zkp[i])
}

/// This function compresses the `u_or_v` values and returns the next `u_or_v` values.
///
/// The function uses streams since stream offers a chunk method.
async fn recurse_u_or_v<'a, F: PrimeField, J, const λ: usize>(
    u_or_v_iterator: J,
    lagrange_table: &'a LagrangeTable<F, λ, 1>,
) -> impl Stream<Item = [F; λ]> + 'a
where
    J: Stream<Item = [F; λ]> + 'a,
{
    u_or_v_iterator
        .map(|polynomial| lagrange_table.eval(polynomial)[0])
        .chunks(λ)
        .map(|chunk| {
            let mut new_u_or_v_vec = [F::ZERO; λ];
            for (i, &x) in chunk.iter().enumerate() {
                new_u_or_v_vec[i] = x;
            }
            new_u_or_v_vec
        })
}

pub async fn compute_p_or_q<F: PrimeField, J, const λ: usize>(
    u_or_v_iterator: J,
    r: Vec<F>,
    p_or_q_0: F,
) -> F
where
    J: Stream<Item = [F; λ]> + Unpin,
{
    let recursions = r.len();

    // compute Lagrange tables
    let denominator_p_or_q = CanonicalLagrangeDenominator::<F, λ>::new();
    let tables = r
        .iter()
        .map(|r| LagrangeTable::<F, λ, 1>::new(&denominator_p_or_q, r))
        .collect::<Vec<_>>();

    // generate & evaluate recursive streams
    // to compute last array
    let mut stream: Pin<Box<dyn Stream<Item = [F; λ]>>> = Box::pin(u_or_v_iterator);
    for lagrange_table in tables.iter().take(recursions - 1) {
        stream = Box::pin(recurse_u_or_v(stream, lagrange_table).await);
    }
    let mut last_u_or_v_array = stream.next().await.unwrap();
    // make sure stream is empty
    assert!(stream.next().await.is_none());

    // set mask
    last_u_or_v_array[λ - 1] = last_u_or_v_array[0];
    last_u_or_v_array[0] = p_or_q_0;

    // compute and output p_or_q
    tables[recursions - 1].eval(last_u_or_v_array)[0]
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use futures_util::{stream, StreamExt};

    use crate::{
        ff::{Fp31, PrimeField, U128Conversions},
        protocol::ipa_prf::malicious_security::{
            lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            verifier::{compute_p_or_q, compute_sum_share, interpolate_at_r, recurse_u_or_v},
        },
    };

    fn make_chunks<F: PrimeField, const N: usize>(a: &[u128]) -> Vec<[F; N]> {
        a.chunks(N)
            .map(|chunk| <[u128; N]>::try_from(chunk).unwrap().map(F::truncate_from))
            .collect::<Vec<_>>()
    }

    #[test]
    fn sample_proof_u() {
        const OUT_1: u128 = 27;
        const ZKP_1: [u128; 7] = [0, 0, 13, 17, 11, 25, 7];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 0;
        const EXPECTED_B_1: u128 = 3;

        const ZKP_2: [u128; 7] = [11, 25, 17, 9, 22, 23, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 13;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [21, 1, 6, 25, 1];

        const R_3: u128 = 30;

        const EXPECTED_G_R_FINAL: u128 = 0;

        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // first iteration
        let zkp_1 = ZKP_1.map(Fp31::truncate_from);

        let g_r_share_1 =
            interpolate_at_r(&zkp_1, Fp31::try_from(R_1).unwrap(), &lagrange_denominator);
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_1).unwrap();

        assert_eq!(g_r_share_1.as_u128(), EXPECTED_G_R_1);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1);

        // second iteration
        let zkp_2 = ZKP_2.map(Fp31::truncate_from);

        let g_r_share_2 =
            interpolate_at_r(&zkp_2, Fp31::try_from(R_2).unwrap(), &lagrange_denominator);
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2);
        assert_eq!(zero_share_2.as_u128(), EXPECTED_B_2);

        // final iteration
        let zkp_3 = ZKP_3.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            &final_lagrange_denominator,
        );

        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL);
    }

    #[tokio::test]
    async fn sample_u_recursion() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];

        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];

        const U_3: [u128; 2] = [3, 3];

        const R: [u128; 3] = [22, 17, 30];

        const P_RANDOM_WEIGHT: u128 = 12;

        const EXPECTED_P_FINAL: u128 = 30;

        // compute Lagrange tables
        let denominator_p_or_q = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let table_1 =
            LagrangeTable::<Fp31, 4, 1>::new(&denominator_p_or_q, &Fp31::try_from(R[0]).unwrap());
        let table_2 =
            LagrangeTable::<Fp31, 4, 1>::new(&denominator_p_or_q, &Fp31::try_from(R[1]).unwrap());
        let denominator_p_or_q_final = CanonicalLagrangeDenominator::<Fp31, 3>::new();
        let table_3 = LagrangeTable::<Fp31, 3, 1>::new(
            &denominator_p_or_q_final,
            &Fp31::try_from(R[2]).unwrap(),
        );

        // uv values in input format
        let u_1 = make_chunks::<_, 4>(&U_1);

        let u_or_v_2 = recurse_u_or_v(stream::iter(u_1), &table_1)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&U_2));

        let u_or_v_3_temp = recurse_u_or_v(stream::iter(u_or_v_2.into_iter()), &table_2)
            .await
            .collect::<Vec<_>>()
            .await;

        // final proof trim from U4 to U2
        let u_or_v_3 = [
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            u_or_v_3_temp[0][0],
            u_or_v_3_temp[0][1],
        ];

        assert_eq!([u_or_v_3[1], u_or_v_3[2]], make_chunks::<Fp31, 2>(&U_3)[0]);

        let p_final = recurse_u_or_v(stream::iter(iter::once(u_or_v_3)), &table_3)
            .await
            .collect::<Vec<_>>()
            .await;

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_P_FINAL);
    }

    #[test]
    fn sample_proof_v() {
        const OUT_1: u128 = 0;
        const ZKP_1: [u128; 7] = [0, 30, 16, 13, 25, 3, 6];
        const R_1: u128 = 22;

        const EXPECTED_G_R_1: u128 = 10;
        const EXPECTED_B_1: u128 = 28;

        const ZKP_2: [u128; 7] = [1, 12, 29, 30, 7, 7, 3];
        const R_2: u128 = 17;

        const EXPECTED_G_R_2: u128 = 12;
        const EXPECTED_B_2: u128 = 0;

        const ZKP_3: [u128; 5] = [22, 14, 4, 20, 16];
        const R_3: u128 = 30;

        const EXPECTED_G_R_FINAL: u128 = 19;

        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // first iteration
        let zkp_1 = ZKP_1.map(Fp31::truncate_from);

        let g_r_share_1 =
            interpolate_at_r(&zkp_1, Fp31::try_from(R_1).unwrap(), &lagrange_denominator);
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_1).unwrap();

        assert_eq!(g_r_share_1, EXPECTED_G_R_1);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1);

        // second iteration
        let zkp_2 = ZKP_2.map(Fp31::truncate_from);

        let g_r_share_2 =
            interpolate_at_r(&zkp_2, Fp31::try_from(R_2).unwrap(), &lagrange_denominator);
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2);
        assert_eq!(zero_share_2, EXPECTED_B_2);

        // final iteration
        let zkp_3 = ZKP_3.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r(
            &zkp_3,
            Fp31::try_from(R_3).unwrap(),
            &final_lagrange_denominator,
        );
        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL);
    }

    #[tokio::test]
    async fn sample_v_recursion() {
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];
        const V_3: [u128; 2] = [5, 24];

        const R: [u128; 3] = [22, 17, 30];

        const Q_RANDOM_WEIGHT: u128 = 1;

        const EXPECTED_Q_FINAL: u128 = 12;

        // compute Lagrange tables
        let denominator_p_or_q = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let table_1 =
            LagrangeTable::<Fp31, 4, 1>::new(&denominator_p_or_q, &Fp31::try_from(R[0]).unwrap());
        let table_2 =
            LagrangeTable::<Fp31, 4, 1>::new(&denominator_p_or_q, &Fp31::try_from(R[1]).unwrap());
        let denominator_p_or_q_final = CanonicalLagrangeDenominator::<Fp31, 3>::new();
        let table_3 = LagrangeTable::<Fp31, 3, 1>::new(
            &denominator_p_or_q_final,
            &Fp31::try_from(R[2]).unwrap(),
        );

        // uv values in input format
        let v_1 = make_chunks::<_, 4>(&V_1);

        let u_or_v_2 = recurse_u_or_v(stream::iter(v_1), &table_1)
            .await
            .collect::<Vec<_>>()
            .await;
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&V_2));
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&V_2));

        let u_or_v_3_temp = recurse_u_or_v(stream::iter(u_or_v_2.into_iter()), &table_2)
            .await
            .collect::<Vec<_>>()
            .await;

        // final proof trim from U4 to U2
        let u_or_v_3 = [
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
            u_or_v_3_temp[0][0],
            u_or_v_3_temp[0][1],
        ];

        assert_eq!([u_or_v_3[1], u_or_v_3[2]], make_chunks::<Fp31, 2>(&V_3)[0]);

        // final iteration

        let p_final = recurse_u_or_v(stream::iter(iter::once(u_or_v_3)), &table_3)
            .await
            .collect::<Vec<_>>()
            .await;

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_Q_FINAL);
    }

    #[tokio::test]
    async fn recursive_compute_p() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];

        const R: [u128; 3] = [22, 17, 30];

        const P_RANDOM_WEIGHT: u128 = 12;

        // uv values in input format
        let u_1 = make_chunks::<_, 4>(&U_1);

        // this approach of computing p is tested in test sample_u_recursion
        let tested_p = {
            // compute Lagrange tables
            let denominator_p_or_q = CanonicalLagrangeDenominator::<Fp31, 4>::new();
            let table_1 = LagrangeTable::<Fp31, 4, 1>::new(
                &denominator_p_or_q,
                &Fp31::try_from(R[0]).unwrap(),
            );
            let table_2 = LagrangeTable::<Fp31, 4, 1>::new(
                &denominator_p_or_q,
                &Fp31::try_from(R[1]).unwrap(),
            );
            let table_3 = LagrangeTable::<Fp31, 4, 1>::new(
                &denominator_p_or_q,
                &Fp31::try_from(R[2]).unwrap(),
            );

            let u_or_v_2 = recurse_u_or_v(stream::iter(u_1.clone()), &table_1).await;

            let mut u_or_v_3 = recurse_u_or_v(u_or_v_2, &table_2)
                .await
                .collect::<Vec<_>>()
                .await[0];

            // set mask
            u_or_v_3[3] = u_or_v_3[0];
            u_or_v_3[0] = Fp31::try_from(P_RANDOM_WEIGHT).unwrap();

            let p_final = recurse_u_or_v(stream::iter(iter::once(u_or_v_3)), &table_3)
                .await
                .collect::<Vec<_>>()
                .await;

            // return tested p
            p_final[0][0]
        };

        let p = compute_p_or_q::<Fp31, _, 4>(
            stream::iter(u_1),
            R.map(|x| Fp31::try_from(x).unwrap())
                .into_iter()
                .collect::<Vec<_>>(),
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
        )
        .await;

        assert_eq!(p, tested_p);
    }
}
