use std::{iter, pin::Pin};

use futures::Stream;
use futures_util::StreamExt;

use crate::{
    ff::PrimeField,
    protocol::ipa_prf::malicious_security::lagrange::{
        CanonicalLagrangeDenominator, LagrangeTable,
    },
};

/// This function computes the shares that sum to zero from the zero-knowledge proofs.
///
/// `out_share` is a share of `x` where the proof proves the statement `sum_i u_i * v_i = x`
pub fn compute_g_differences<F, const P: usize, const λ: usize>(
    zkps: &Vec<[F; P]>,
    challenges: &[F],
    out_share: F,
) -> Vec<F>
where
    F: PrimeField,
{
    // compute denominator
    let lagrange_denominator: CanonicalLagrangeDenominator<F, P> =
        CanonicalLagrangeDenominator::<F, P>::new();

    // compute expected_sum with "out_share" at the first spot
    let expected_sums = iter::once(out_share)
        .chain(
            challenges
                .iter()
                .zip(zkps)
                .map(|(challenge, zkp)| interpolate_at_r(zkp, *challenge, &lagrange_denominator)),
        )
        .collect::<Vec<_>>();

    // compute g_sum)
    let g_sums = zkps
        .iter()
        .map(compute_sum_share::<F, λ, P>)
        // append spot for final sum
        .chain(iter::once(F::ZERO))
        .collect::<Vec<_>>();

    g_sums
        .iter()
        .zip(expected_sums)
        .map(|(g_sum, expected_sum)| *g_sum - expected_sum)
        .collect()
}

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
fn recurse_u_or_v<'a, F: PrimeField, J, const λ: usize>(
    u_or_v_stream: J,
    lagrange_table: &'a LagrangeTable<F, λ, 1>,
) -> impl Stream<Item = [F; λ]> + 'a
where
    J: Stream<Item = [F; λ]> + 'a,
{
    u_or_v_stream
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

pub async fn recursively_compute_final_check<F: PrimeField, J, const λ: usize>(
    u_or_v_stream: J,
    challenges: Vec<F>,
    p_or_q_0: F,
) -> F
where
    J: Stream<Item = [F; λ]> + Unpin,
{
    let recursions = challenges.len();

    // compute Lagrange tables
    let denominator_p_or_q = CanonicalLagrangeDenominator::<F, λ>::new();
    let tables = challenges
        .iter()
        .map(|r| LagrangeTable::<F, λ, 1>::new(&denominator_p_or_q, r))
        .collect::<Vec<_>>();

    // generate & evaluate recursive streams
    // to compute last array
    let mut stream: Pin<Box<dyn Stream<Item = [F; λ]>>> = Box::pin(u_or_v_stream);
    for lagrange_table in tables.iter().take(recursions - 1) {
        stream = Box::pin(recurse_u_or_v(stream, lagrange_table));
    }
    let mut last_u_or_v_array = stream.next().await.unwrap();
    // make sure stream is empty
    assert!(stream.next().await.is_none());

    // In the protocol, the prover is expected to continue recursively compressing the
    // u and v vectors until it has length strictly less than λ.
    // For this reason, we can safely assume that in the final proof, the last value
    // in the ZKP is zero.
    // A debug assert will help catch any errors while in development.
    // set mask
    debug_assert!(
        last_u_or_v_array[λ - 1] == F::ZERO,
        "Should not be overwriting non-zero values"
    );
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
            verifier::{
                compute_g_differences, compute_sum_share, interpolate_at_r, recurse_u_or_v,
                recursively_compute_final_check,
            },
        },
        secret_sharing::SharedValue,
    };

    fn make_chunks<F: PrimeField, const N: usize>(a: &[u128]) -> Vec<[F; N]> {
        a.chunks(N)
            .map(|chunk| <[u128; N]>::try_from(chunk).unwrap().map(F::truncate_from))
            .collect::<Vec<_>>()
    }

    fn chunks_from_vector<F: PrimeField, const N: usize>(a: Vec<&[u128]>) -> Vec<[F; N]> {
        make_chunks(
            &a.into_iter()
                .flat_map(|x| x.iter())
                .map(Clone::clone)
                .collect::<Vec<u128>>(),
        )
    }

    // test proof for Fp31
    // u, v values
    const U_1: [u128; 32] = [
        0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30, 30,
        16, 0, 0, 30, 16,
    ];
    const V_1: [u128; 32] = [
        0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 1,
    ];

    const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
    const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];

    const V_3: [u128; 4] = [5, 24, 0, 0];
    const U_3: [u128; 4] = [3, 3, 0, 0];

    // out shares
    const OUT_LEFT: u128 = 27;
    const OUT_RIGHT: u128 = 0;

    // weights
    const P_RANDOM_WEIGHT: u128 = 12;
    const Q_RANDOM_WEIGHT: u128 = 1;

    // proofs
    const ZKP_1_LEFT: [u128; 7] = [0, 0, 13, 17, 11, 25, 7];
    const ZKP_1_RIGHT: [u128; 7] = [0, 30, 16, 13, 25, 3, 6];

    const ZKP_2_LEFT: [u128; 7] = [11, 25, 17, 9, 22, 23, 3];
    const ZKP_2_RIGHT: [u128; 7] = [1, 12, 29, 30, 7, 7, 3];

    const ZKP_3_LEFT: [u128; 5] = [21, 1, 6, 25, 1];
    const ZKP_3_RIGHT: [u128; 5] = [22, 14, 4, 20, 16];

    // challenges
    const CHALLENGES: [u128; 3] = [22, 17, 30];

    // expected values
    const EXPECTED_G_R_1_LEFT: u128 = 0;
    const EXPECTED_G_R_1_RIGHT: u128 = 10;
    const EXPECTED_B_1_LEFT: u128 = 3;
    const EXPECTED_B_1_RIGHT: u128 = 28;
    const EXPECTED_G_R_2_LEFT: u128 = 13;
    const EXPECTED_G_R_2_RIGHT: u128 = 12;
    const EXPECTED_B_2_LEFT: u128 = 0;
    const EXPECTED_B_2_RIGHT: u128 = 0;

    const EXPECTED_G_R_FINAL_LEFT: u128 = 0;
    const EXPECTED_G_R_FINAL_RIGHT: u128 = 19;
    const EXPECTED_P_FINAL: u128 = 27;
    const EXPECTED_Q_FINAL: u128 = 10;

    #[test]
    fn sample_proof_u() {
        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // first iteration
        let zkp_1 = ZKP_1_LEFT.map(Fp31::truncate_from);

        let g_r_share_1 = interpolate_at_r(
            &zkp_1,
            Fp31::try_from(CHALLENGES[0]).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_LEFT).unwrap();

        assert_eq!(g_r_share_1.as_u128(), EXPECTED_G_R_1_LEFT);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1_LEFT);

        // second iteration
        let zkp_2 = ZKP_2_LEFT.map(Fp31::truncate_from);

        let g_r_share_2 = interpolate_at_r(
            &zkp_2,
            Fp31::try_from(CHALLENGES[1]).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2_LEFT);
        assert_eq!(zero_share_2.as_u128(), EXPECTED_B_2_LEFT);

        // final iteration
        let zkp_3 = ZKP_3_LEFT.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r(
            &zkp_3,
            Fp31::try_from(CHALLENGES[2]).unwrap(),
            &final_lagrange_denominator,
        );

        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL_LEFT);
    }

    #[tokio::test]
    async fn sample_u_recursion() {
        // compute Lagrange tables
        let denominator_p_or_q = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let tables: [LagrangeTable<Fp31, 4, 1>; 3] = CHALLENGES
            .map(|r| LagrangeTable::new(&denominator_p_or_q, &Fp31::try_from(r).unwrap()));

        // uv values in input format
        let u_1 = make_chunks::<_, 4>(&U_1);

        let u_or_v_2 = recurse_u_or_v(stream::iter(u_1), &tables[0])
            .collect::<Vec<_>>()
            .await;
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&U_2));

        let u_or_v_3 = recurse_u_or_v(stream::iter(u_or_v_2.into_iter()), &tables[1])
            .collect::<Vec<_>>()
            .await;

        assert_eq!(u_or_v_3, make_chunks::<Fp31, 4>(&U_3));

        let u_or_v_3_masked = [
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(), // set mask at index 0
            u_or_v_3[0][1],
            Fp31::ZERO,
            u_or_v_3[0][0], // move first element to the end
        ];

        let p_final = recurse_u_or_v(stream::iter(iter::once(u_or_v_3_masked)), &tables[2])
            .collect::<Vec<_>>()
            .await;

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_P_FINAL);

        // uv values in input format
        let u_1 = make_chunks::<_, 4>(&U_1);

        let p_final_another_way = recursively_compute_final_check::<Fp31, _, 4>(
            stream::iter(u_1),
            CHALLENGES
                .map(|x| Fp31::try_from(x).unwrap())
                .into_iter()
                .collect::<Vec<_>>(),
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
        )
        .await;

        assert_eq!(p_final_another_way.as_u128(), EXPECTED_P_FINAL);
    }

    #[test]
    fn sample_proof_v() {
        let lagrange_denominator: CanonicalLagrangeDenominator<Fp31, 7> =
            CanonicalLagrangeDenominator::<Fp31, 7>::new();

        // first iteration
        let zkp_1 = ZKP_1_RIGHT.map(Fp31::truncate_from);

        let g_r_share_1 = interpolate_at_r(
            &zkp_1,
            Fp31::try_from(CHALLENGES[0]).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_1 = compute_sum_share::<Fp31, 4, 7>(&zkp_1);
        let zero_share_1 = sum_share_1 - Fp31::try_from(OUT_RIGHT).unwrap();

        assert_eq!(g_r_share_1, EXPECTED_G_R_1_RIGHT);
        assert_eq!(zero_share_1.as_u128(), EXPECTED_B_1_RIGHT);

        // second iteration
        let zkp_2 = ZKP_2_RIGHT.map(Fp31::truncate_from);

        let g_r_share_2 = interpolate_at_r(
            &zkp_2,
            Fp31::try_from(CHALLENGES[1]).unwrap(),
            &lagrange_denominator,
        );
        let sum_share_2 = compute_sum_share::<Fp31, 4, 7>(&zkp_2);
        let zero_share_2 = sum_share_2 - g_r_share_1;

        assert_eq!(g_r_share_2.as_u128(), EXPECTED_G_R_2_RIGHT);
        assert_eq!(zero_share_2, EXPECTED_B_2_RIGHT);

        // final iteration
        let zkp_3 = ZKP_3_RIGHT.map(Fp31::truncate_from);

        let final_lagrange_denominator = CanonicalLagrangeDenominator::<Fp31, 5>::new();
        let g_r_share_3 = interpolate_at_r(
            &zkp_3,
            Fp31::try_from(CHALLENGES[2]).unwrap(),
            &final_lagrange_denominator,
        );
        assert_eq!(g_r_share_3, EXPECTED_G_R_FINAL_RIGHT);
    }

    #[tokio::test]
    async fn sample_v_recursion() {
        // compute Lagrange tables
        let denominator_p_or_q = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let tables: [LagrangeTable<Fp31, 4, 1>; 3] = CHALLENGES
            .map(|r| LagrangeTable::new(&denominator_p_or_q, &Fp31::try_from(r).unwrap()));

        // uv values in input format
        let v_1 = make_chunks::<_, 4>(&V_1);

        let u_or_v_2 = recurse_u_or_v(stream::iter(v_1), &tables[0])
            .collect::<Vec<_>>()
            .await;
        assert_eq!(u_or_v_2, make_chunks::<Fp31, 4>(&V_2));

        let u_or_v_3 = recurse_u_or_v(stream::iter(u_or_v_2.into_iter()), &tables[1])
            .collect::<Vec<_>>()
            .await;

        assert_eq!(u_or_v_3, make_chunks::<Fp31, 4>(&V_3));

        let u_or_v_3_masked = [
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(), // set mask at index 0
            u_or_v_3[0][1],
            Fp31::ZERO,
            u_or_v_3[0][0], // move first element to the end
        ];

        // final iteration
        let p_final = recurse_u_or_v(stream::iter(iter::once(u_or_v_3_masked)), &tables[2])
            .collect::<Vec<_>>()
            .await;

        assert_eq!(p_final[0][0].as_u128(), EXPECTED_Q_FINAL);

        // uv values in input format
        let v_1 = make_chunks::<_, 4>(&V_1);

        let q_final_another_way = recursively_compute_final_check::<Fp31, _, 4>(
            stream::iter(v_1),
            CHALLENGES
                .map(|x| Fp31::try_from(x).unwrap())
                .into_iter()
                .collect::<Vec<_>>(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
        )
        .await;

        assert_eq!(q_final_another_way.as_u128(), EXPECTED_Q_FINAL);
    }

    #[test]
    fn differences_are_zero() {
        let zkp_left = chunks_from_vector::<Fp31, 7>(vec![&ZKP_1_LEFT, &ZKP_2_LEFT]);
        let zkp_right = chunks_from_vector::<Fp31, 7>(vec![&ZKP_1_RIGHT, &ZKP_2_RIGHT]);
        let challenges = vec![Fp31::truncate_from(22u128), Fp31::truncate_from(17u128)];

        let g_differences_left =
            compute_g_differences::<_, 7, 4>(&zkp_left, &challenges, Fp31::truncate_from(OUT_LEFT));
        let g_differences_right = compute_g_differences::<_, 7, 4>(
            &zkp_right,
            &challenges,
            Fp31::truncate_from(OUT_RIGHT),
        );

        let g_differences = g_differences_left
            .iter()
            .zip(g_differences_right)
            .map(|(left, right)| *left + right)
            .collect::<Vec<_>>();

        assert_eq!(Fp31::ZERO, g_differences[0]);
        assert_eq!(Fp31::ZERO, g_differences[1]);
    }
}
