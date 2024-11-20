use std::{
    array,
    iter::{self},
};

use crate::{
    ff::PrimeField,
    protocol::{
        context::{
            dzkp_field::UVTable,
            dzkp_validator::{MAX_PROOF_RECURSION, MIN_PROOF_RECURSION},
        },
        ipa_prf::malicious_security::{
            CanonicalLagrangeDenominator, LagrangeTable, FIRST_RECURSION_FACTOR as FRF,
        },
    },
    utils::arraychunks::ArrayChunkIterator,
};

/// This function computes the shares that sum to zero from the zero-knowledge proofs.
///
/// `out_share` is a share of `x` where the proof proves the statement `sum_i u_i * v_i = x`
pub fn compute_g_differences<
    F,
    const P: usize,
    const L: usize,
    const P_FIRST: usize,
    const L_FIRST: usize,
>(
    first_zkp: &[F; P_FIRST],
    zkps: &Vec<[F; P]>,
    challenges: &[F],
    sum_of_uv: F,
    p_times_q: F,
) -> Vec<F>
where
    F: PrimeField,
{
    // compute denominator
    let first_lagrange_denominator: CanonicalLagrangeDenominator<F, P_FIRST> =
        CanonicalLagrangeDenominator::<F, P_FIRST>::new();
    let lagrange_denominator: CanonicalLagrangeDenominator<F, P> =
        CanonicalLagrangeDenominator::<F, P>::new();

    // compute expected_sum with "out_share" at the first spot
    let expected_sums = iter::once(sum_of_uv)
        .chain(iter::once(interpolate_at_r(
            first_zkp,
            &challenges[0],
            &first_lagrange_denominator,
        )))
        .chain(
            challenges[1..]
                .iter()
                .zip(zkps)
                .map(|(challenge, zkp)| interpolate_at_r(zkp, challenge, &lagrange_denominator)),
        )
        .collect::<Vec<_>>();

    // compute g_sum)
    let g_sums = iter::once(compute_sum_share::<F, L_FIRST, P_FIRST>(first_zkp))
        .chain(
            zkps.iter()
                .take(zkps.len() - 1)
                .map(compute_sum_share::<F, L, P>),
        )
        // in the final proof, skip the random weights
        .chain(iter::once(compute_final_sum_share::<F, L, P>(
            zkps.last().unwrap(),
        )))
        // append spot for final sum
        .chain(iter::once(p_times_q))
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
pub fn interpolate_at_r<F: PrimeField, const P: usize>(
    zkp: &[F; P],
    r: &F,
    lagrange_denominator: &CanonicalLagrangeDenominator<F, P>,
) -> F {
    let lagrange_table_g = LagrangeTable::<F, P, 1>::new(lagrange_denominator, r);
    lagrange_table_g.eval(zkp)[0]
}

/// This function computes the sum of the first L elements of the zero-knowledge proof
pub fn compute_sum_share<F: PrimeField, const L: usize, const P: usize>(zkp: &[F; P]) -> F {
    (0..L).fold(F::ZERO, |acc, i| acc + zkp[i])
}

/// In the final proof, skip the random weights when computing the sum
pub fn compute_final_sum_share<F: PrimeField, const L: usize, const P: usize>(zkp: &[F; P]) -> F {
    (1..L).fold(F::ZERO, |acc, i| acc + zkp[i])
}

/// This function compresses the `u_or_v` values and returns the next `u_or_v` values.
fn recurse_u_or_v<'a, F: PrimeField, const L: usize>(
    u_or_v: impl Iterator<Item = F> + 'a,
    lagrange_table: &'a LagrangeTable<F, L, 1>,
) -> impl Iterator<Item = F> + 'a {
    VerifierValues(u_or_v.chunk_array::<L>()).eval_at_r(lagrange_table)
}

/// This function recursively compresses the `u_or_v` values.
///
/// The recursion factor (or compression) of the first recursion is fixed at
/// `FIRST_RECURSION_FACTOR` (`FRF`). The recursion factor of all following recursions
/// is `L`.
pub fn recursively_compute_final_check<F: PrimeField, const L: usize>(
    input: impl VerifierLagrangeInput<F, FRF>,
    challenges: &[F],
    p_or_q_0: F,
) -> F {
    // This function requires MIN_PROOF_RECURSION be at least 3.
    assert!(challenges.len() >= MIN_PROOF_RECURSION && challenges.len() <= MAX_PROOF_RECURSION);
    let recursions_after_first = challenges.len() - 1;

    // compute Lagrange tables
    let denominator_p_or_q_first = CanonicalLagrangeDenominator::<F, FRF>::new();
    let table_first = LagrangeTable::<F, FRF, 1>::new(&denominator_p_or_q_first, &challenges[0]);
    let denominator_p_or_q = CanonicalLagrangeDenominator::<F, L>::new();
    let tables = challenges[1..]
        .iter()
        .map(|r| LagrangeTable::<F, L, 1>::new(&denominator_p_or_q, r))
        .collect::<Vec<_>>();

    // generate & evaluate recursive streams
    // to compute last array
    let mut iterator: Box<dyn Iterator<Item = F>> = Box::new(input.eval_at_r(&table_first));
    // all following recursion except last one
    for lagrange_table in tables.iter().take(recursions_after_first - 1) {
        iterator = Box::new(recurse_u_or_v(iterator, lagrange_table));
    }
    let last_u_or_v_values = iterator.collect::<Vec<F>>();
    // Make sure there are less than L last u or v values. The prover is expected to continue
    // recursively compressing the u and v vectors until they have length strictly less than L.
    // The extra spot is needed for the p_0 / q_0 masks.
    assert!(
        last_u_or_v_values.len() < L,
        "Too many u or v values in last recursion. Got {}, max is L = {L}",
        last_u_or_v_values.len(),
    );

    let mut last_array = [F::ZERO; L];

    // array needs to be consistent with what the prover does
    // i.e. set first u or v value to the end
    last_array[L - 1] = last_u_or_v_values[0];
    last_array[0] = p_or_q_0;

    last_array[1..last_u_or_v_values.len()].copy_from_slice(&last_u_or_v_values[1..]);

    // compute and output p_or_q
    tables.last().unwrap().eval(&last_array)[0]
}

/// Trait for inputs to Lagrange interpolation on the verifier.
///
/// Lagrange interpolation is used in the verifier to evaluate polynomials at the
/// randomly chosen challenge point _r_.
///
/// There are two implementations of this trait: `VerifierTableIndices`, and
/// `VerifierValues`. `VerifierTableIndices` is used for the input to the first proof.
/// Each set of 4 _u_ or _v_ values input to the first proof has one of eight possible
/// values, determined by the values of the 3 associated multiplication intermediates.
/// The `VerifierTableIndices` implementation uses a lookup table containing the output
/// of the Lagrange interpolation for each of these eight possible values. The
/// `VerifierValues` implementation, which represents actual _u_ and _v_ values, is used
/// by the remaining recursive proofs.
///
/// There is a similar trait `ProverLagrangeInput` in `prover.rs`. The prover operates
/// on _u_ and _v_ values simultaneously (i.e. iterators of tuples). The verifier
/// operates on only one of _u_ or _v_ at a time.
pub trait VerifierLagrangeInput<F: PrimeField, const L: usize> {
    fn eval_at_r<'a>(
        self,
        lagrange_table: &'a LagrangeTable<F, L, 1>,
    ) -> impl Iterator<Item = F> + 'a
    where
        Self: 'a;
}

/// Implementation of `VerifierLagrangeInput` for table indices, used for the first proof.
pub struct VerifierTableIndices<'a, F: PrimeField, I: Iterator<Item = u8>> {
    pub input: I,
    pub table: &'a UVTable<F>,
}

/// Iterator producted by `VerifierTableIndices::eval_at_r`.
struct TableIndicesIterator<F: PrimeField, I: Iterator<Item = u8>> {
    input: I,
    table: [F; 8],
}

impl<F: PrimeField, I: Iterator<Item = u8>> VerifierLagrangeInput<F, FRF>
    for VerifierTableIndices<'_, F, I>
{
    fn eval_at_r<'a>(
        self,
        lagrange_table: &'a LagrangeTable<F, FRF, 1>,
    ) -> impl Iterator<Item = F> + 'a
    where
        Self: 'a,
    {
        TableIndicesIterator {
            input: self.input,
            table: array::from_fn(|i| lagrange_table.eval(&self.table[i])[0]),
        }
    }
}

impl<F: PrimeField, I: Iterator<Item = u8>> Iterator for TableIndicesIterator<F, I> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        self.input
            .next()
            .map(|index| self.table[usize::from(index)])
    }
}

/// Implementation of `VerifierLagrangeInput` for _u_ and _v_ values, used for
/// subsequent recursive proofs.
pub struct VerifierValues<F: PrimeField, const L: usize, I: Iterator<Item = [F; L]>>(pub I);

/// Iterator returned by `ProverValues::eval_at_r`.
struct ValuesEvalAtRIterator<'a, F: PrimeField, const L: usize, I: Iterator<Item = [F; L]>> {
    input: I,
    lagrange_table: &'a LagrangeTable<F, L, 1>,
}

impl<'a, F: PrimeField, const L: usize, I: Iterator<Item = [F; L]>> Iterator
    for ValuesEvalAtRIterator<'a, F, L, I>
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        self.input
            .next()
            .map(|values| self.lagrange_table.eval(&values)[0])
    }
}

impl<F: PrimeField, const L: usize, I: Iterator<Item = [F; L]>> VerifierLagrangeInput<F, L>
    for VerifierValues<F, L, I>
{
    fn eval_at_r<'a>(
        self,
        lagrange_table: &'a LagrangeTable<F, L, 1>,
    ) -> impl Iterator<Item = F> + 'a
    where
        Self: 'a,
    {
        ValuesEvalAtRIterator {
            input: self.0,
            lagrange_table,
        }
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use super::*;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::{
            context::{
                dzkp_field::{tests::reference_convert, TABLE_U, TABLE_V},
                dzkp_validator::{MultiplicationInputsBlock, BIT_ARRAY_LEN},
            },
            ipa_prf::malicious_security::lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
        },
        secret_sharing::SharedValue,
        test_executor::run_random,
        utils::arraychunks::ArrayChunkIterator,
    };

    fn to_field(a: &[u128]) -> Vec<Fp31> {
        a.iter()
            .map(|x| Fp31::truncate_from(*x))
            .collect::<Vec<_>>()
    }

    fn array_to_field<const N: usize>(a: &[u128; N]) -> [Fp31; N] {
        a.map(Fp31::truncate_from)
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
            &Fp31::try_from(CHALLENGES[0]).unwrap(),
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
            &Fp31::try_from(CHALLENGES[1]).unwrap(),
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
            &Fp31::try_from(CHALLENGES[2]).unwrap(),
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

        let u_or_v_2 =
            recurse_u_or_v::<_, 4>(to_field(&U_1).into_iter(), &tables[0]).collect::<Vec<Fp31>>();
        assert_eq!(u_or_v_2, to_field(&U_2));

        let u_or_v_3 = recurse_u_or_v::<_, 4>(u_or_v_2.into_iter(), &tables[1]).collect::<Vec<_>>();

        assert_eq!(u_or_v_3, to_field(&U_3[..2]));

        let u_or_v_3_masked = [
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(), // set mask at index 0
            u_or_v_3[1],
            Fp31::ZERO,
            u_or_v_3[0], // move first element to the end
        ];

        let p_final =
            recurse_u_or_v::<_, 4>(u_or_v_3_masked.into_iter(), &tables[2]).collect::<Vec<_>>();

        assert_eq!(p_final[0].as_u128(), EXPECTED_P_FINAL);

        let p_final_another_way = recursively_compute_final_check::<_, 4>(
            VerifierValues(to_field(&U_1).into_iter().chunk_array::<4>()),
            &CHALLENGES
                .map(|x| Fp31::try_from(x).unwrap())
                .into_iter()
                .collect::<Vec<_>>(),
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
        );

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
            &Fp31::try_from(CHALLENGES[0]).unwrap(),
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
            &Fp31::try_from(CHALLENGES[1]).unwrap(),
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
            &Fp31::try_from(CHALLENGES[2]).unwrap(),
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
        let v_1 = to_field(&V_1);

        let u_or_v_2 = recurse_u_or_v(v_1.into_iter(), &tables[0]).collect::<Vec<_>>();
        assert_eq!(u_or_v_2, to_field(&V_2));

        let u_or_v_3 = recurse_u_or_v(u_or_v_2.into_iter(), &tables[1]).collect::<Vec<_>>();

        assert_eq!(u_or_v_3, to_field(&V_3[..2]));

        let u_or_v_3_masked = [
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(), // set mask at index 0
            u_or_v_3[1],
            Fp31::ZERO,
            u_or_v_3[0], // move first element to the end
        ];

        // final iteration
        let p_final =
            recurse_u_or_v::<_, 4>(u_or_v_3_masked.into_iter(), &tables[2]).collect::<Vec<_>>();

        assert_eq!(p_final[0].as_u128(), EXPECTED_Q_FINAL);

        // uv values in input format
        let v_1 = to_field(&V_1);

        let q_final_another_way = recursively_compute_final_check::<Fp31, 4>(
            VerifierValues(v_1.into_iter().chunk_array::<4>()),
            &CHALLENGES
                .map(|x| Fp31::try_from(x).unwrap())
                .into_iter()
                .collect::<Vec<_>>(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
        );

        assert_eq!(q_final_another_way.as_u128(), EXPECTED_Q_FINAL);
    }

    #[test]
    fn differences_are_zero() {
        let zkp_left = [array_to_field(&ZKP_1_LEFT), array_to_field(&ZKP_2_LEFT)];
        let zkp_right = [array_to_field(&ZKP_1_RIGHT), array_to_field(&ZKP_2_RIGHT)];
        let challenges = vec![Fp31::truncate_from(22u128), Fp31::truncate_from(17u128)];

        let p_times_q =
            Fp31::truncate_from(EXPECTED_Q_FINAL) * Fp31::truncate_from(EXPECTED_P_FINAL);

        let g_differences_left = compute_g_differences::<_, 7, 4, 7, 4>(
            &zkp_left[0],
            &zkp_left[1..].to_vec(),
            &challenges,
            Fp31::truncate_from(OUT_LEFT),
            Fp31::ZERO,
        );
        let g_differences_right = compute_g_differences::<_, 7, 4, 7, 4>(
            &zkp_right[0],
            &zkp_right[1..].to_vec(),
            &challenges,
            Fp31::truncate_from(OUT_RIGHT),
            p_times_q,
        );

        let g_differences = g_differences_left
            .iter()
            .zip(g_differences_right)
            .map(|(left, right)| *left + right)
            .collect::<Vec<_>>();

        assert_eq!(Fp31::ZERO, g_differences[0]);
    }

    #[test]
    fn verifier_table_indices_equivalence() {
        run_random(|mut rng| async move {
            let block = rng.gen::<MultiplicationInputsBlock>();

            let denominator = CanonicalLagrangeDenominator::new();
            let r = rng.gen();
            let lagrange_table_r = LagrangeTable::new(&denominator, &r);

            // Test equivalence for _u_ values
            assert!(VerifierTableIndices {
                input: block
                    .rotate_right()
                    .table_indices_from_right_prover()
                    .into_iter(),
                table: &TABLE_U,
            }
            .eval_at_r(&lagrange_table_r)
            .eq(VerifierValues((0..BIT_ARRAY_LEN).map(|i| {
                reference_convert(
                    block.x_left[i],
                    block.x_right[i],
                    block.y_left[i],
                    block.y_right[i],
                    block.prss_left[i],
                    block.prss_right[i],
                )
                .0
            }))
            .eval_at_r(&lagrange_table_r)));

            // Test equivalence for _v_ values
            assert!(VerifierTableIndices {
                input: block
                    .rotate_left()
                    .table_indices_from_left_prover()
                    .into_iter(),
                table: &TABLE_V,
            }
            .eval_at_r(&lagrange_table_r)
            .eq(VerifierValues((0..BIT_ARRAY_LEN).map(|i| {
                reference_convert(
                    block.x_left[i],
                    block.x_right[i],
                    block.y_left[i],
                    block.y_right[i],
                    block.prss_left[i],
                    block.prss_right[i],
                )
                .1
            }))
            .eval_at_r(&lagrange_table_r)));
        });
    }
}
