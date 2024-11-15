use std::{borrow::Borrow, iter::zip, marker::PhantomData};

use crate::{
    error::Error::{self, DZKPMasks},
    ff::{Fp61BitPrime, PrimeField},
    helpers::hashing::{compute_hash, hash_to_field},
    protocol::{
        context::Context,
        ipa_prf::{
            malicious_security::lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            CompressedProofGenerator,
        },
        prss::SharedRandomness,
        RecordId, RecordIdRange,
    },
};

/// This struct stores intermediate `uv` values.
/// The storage format is compatible with further processing
/// via a `ProofGenerator` with parameters `L` and `F`.
#[derive(PartialEq, Debug)]
pub struct UVValues<F, const L: usize>
where
    F: PrimeField,
{
    uv_chunks: Vec<([F; L], [F; L])>,
    length: usize,
}

impl<F, const L: usize> FromIterator<(F, F)> for UVValues<F, L>
where
    F: PrimeField,
{
    fn from_iter<T: IntoIterator<Item = (F, F)>>(iter: T) -> Self {
        let mut uv_chunks = Vec::<([F; L], [F; L])>::new();

        let mut length = 0;
        let mut new_u_chunk = [F::ZERO; L];
        let mut new_v_chunk = [F::ZERO; L];
        for (u, v) in iter {
            new_u_chunk[length % L] = u;
            new_v_chunk[length % L] = v;
            if (length + 1) % L == 0 {
                uv_chunks.push((new_u_chunk, new_v_chunk));
                new_u_chunk = [F::ZERO; L];
                new_v_chunk = [F::ZERO; L];
            }
            length += 1;
        }
        if length % L != 0 {
            uv_chunks.push((new_u_chunk, new_v_chunk));
        }

        Self { uv_chunks, length }
    }
}

impl<F, const L: usize> UVValues<F, L>
where
    F: PrimeField,
{
    /// This function returns the amount of field element tuples stored in `UVValues`.
    /// The amount corresponds to the amount of stored `u`
    /// as well as the amount of stored `v` values.
    pub fn len(&self) -> usize {
        self.length
    }

    /// This function returns a tuple
    /// which consists of an array of `u` values and an array of `v` values.
    pub fn iter(&self) -> impl Iterator<Item = &([F; L], [F; L])> + Clone {
        self.uv_chunks.iter()
    }

    /// This function allows to generate and set masks
    ///
    /// It outputs `(p_mask_from_left_prover,q_mask_from_right_prover)`.
    ///
    /// ## Errors
    /// Errors when the length is too long such that masks cannot be set safely.
    pub fn set_masks(&mut self, my_p_mask: F, my_q_mask: F) -> Result<(), Error> {
        if self.len() >= L {
            return Err(DZKPMasks);
        }
        // compute final uv values
        let (u_values, v_values) = &mut self.uv_chunks[0];
        // shift first element to last position
        u_values[CompressedProofGenerator::RECURSION_FACTOR - 1] = u_values[0];
        v_values[CompressedProofGenerator::RECURSION_FACTOR - 1] = v_values[0];
        // set masks in first position
        u_values[0] = my_p_mask;
        v_values[0] = my_q_mask;

        Ok(())
    }
}

/// This struct sets up the parameter for the proof generation
/// and provides several functions to generate zero knowledge proofs.
///
/// The purpose of the constants is the following:
/// `L`: Recursion factor of the proof.
/// `P`: Length of the proof, i.e. `2*L-1`.
/// `M`: Dimension of the Lagrange table, i.e. `L`.
pub struct ProofGenerator<F: PrimeField, const L: usize, const P: usize, const M: usize> {
    phantom_data: PhantomData<F>,
}

// Compression Factor is L
// P, Proof size is 2*L - 1
// M, the number of interpolated points is L - 1
// The reason we need these is that Rust doesn't support basic math operations on const generics
pub type SmallProofGenerator = ProofGenerator<Fp61BitPrime, 4, 7, 3>;

pub const BLOCK_SIZE: usize = 4;

impl<F: PrimeField, const L: usize, const P: usize, const M: usize> ProofGenerator<F, L, P, M> {
    // define constants such that they can be used externally
    // when using the pub types defined above
    pub const RECURSION_FACTOR: usize = L;
    pub const PROOF_LENGTH: usize = P;
    pub const LAGRANGE_LENGTH: usize = M;

    pub fn compute_proof_from_uv<J>(uv: J, lagrange_table: &LagrangeTable<F, L, M>) -> [F; P]
    where
        J: Iterator,
        J::Item: Borrow<([F; L], [F; L])>,
    {
        Self::compute_proof(uv.map(|uv| {
            let (u, v) = uv.borrow();
            let mut u_ex = [F::ZERO; P];
            let mut v_ex = [F::ZERO; P];
            u_ex[0..L].copy_from_slice(u);
            v_ex[0..L].copy_from_slice(v);
            u_ex[L..].copy_from_slice(&lagrange_table.eval(u));
            v_ex[L..].copy_from_slice(&lagrange_table.eval(v));
            (u_ex, v_ex)
        }))
    }

    ///
    /// Distributed Zero Knowledge Proofs algorithm drawn from
    /// `https://eprint.iacr.org/2023/909.pdf`
    pub fn compute_proof<J>(pq_iterator: J) -> [F; P]
    where
        J: Iterator,
        J::Item: Borrow<([F; P], [F; P])>,
    {
        let mut proof = [F::ZERO; P];
        let mut accums = [0u128; P];
        let mut accum_count = 0;
        for pq in pq_iterator {
            for (accum, (p, q)) in zip(accums.iter_mut(), zip(&pq.borrow().0, &pq.borrow().1)) {
                *accum += p.as_u128() * q.as_u128();
            }

            accum_count += 1;
            if accum_count == 63 {
                for (proof_elt, accum) in zip(proof.iter_mut(), accums.iter_mut()) {
                    *proof_elt = F::truncate_from(*accum + proof_elt.as_u128());
                    *accum = 0;
                }
                accum_count = 0;
            }
        }
        for (proof_elt, accum) in zip(proof.iter_mut(), accums.iter_mut()) {
            *proof_elt = F::truncate_from(*accum + proof_elt.as_u128())
        }
        proof
    }

    fn gen_challenge_and_recurse<J, const N: usize>(
        proof_left: &[F; P],
        proof_right: &[F; P],
        uv_iterator: J,
    ) -> UVValues<F, N>
    where
        J: Iterator,
        J::Item: Borrow<([F; L], [F; L])>,
    {
        let r: F = hash_to_field(
            &compute_hash(proof_left),
            &compute_hash(proof_right),
            L.try_into().unwrap(),
        );

        let denominator = CanonicalLagrangeDenominator::<F, L>::new();
        let lagrange_table_r = LagrangeTable::<F, L, 1>::new(&denominator, &r);

        // iter and interpolate at x coordinate r
        uv_iterator
            .map(|polynomial| {
                let (u_chunk, v_chunk) = polynomial.borrow();
                (
                    // new u value
                    lagrange_table_r.eval(u_chunk)[0],
                    // new v value
                    lagrange_table_r.eval(v_chunk)[0],
                )
            })
            .collect::<UVValues<F, N>>()
    }

    fn gen_proof_shares_from_prss<C>(ctx: &C, record_ids: &mut RecordIdRange) -> ([F; P], [F; P])
    where
        C: Context,
    {
        let mut out_left = [F::ZERO; P];
        let mut out_right = [F::ZERO; P];
        // use PRSS
        for i in 0..P {
            let (left, right) = ctx
                .prss()
                .generate_fields::<F, RecordId>(record_ids.expect_next());

            out_left[i] = left;
            out_right[i] = right;
        }
        (out_left, out_right)
    }

    fn gen_other_proof_share(proof: [F; P], proof_prss_share: [F; P]) -> [F; P] {
        let mut proof_other_share = [F::ZERO; P];
        for i in 0..P {
            proof_other_share[i] = proof[i] - proof_prss_share[i];
        }
        proof_other_share
    }

    /// This function is a helper function that computes the next proof
    /// from an iterator over uv values
    /// It also computes the next uv values
    ///
    /// It output `(uv values, share_of_proof_from_prover_left, my_proof_left_share)`
    /// where
    /// `share_of_proof_from_prover_left` from left has type `Vec<[F; P]>`,
    /// `my_proof_left_share` has type `Vec<[F; P]>`,
    pub fn gen_artefacts_from_recursive_step<C, J, const N: usize>(
        ctx: &C,
        record_ids: &mut RecordIdRange,
        my_proof: [F; P],
        uv_iterator: J,
    ) -> (UVValues<F, N>, [F; P], [F; P])
    where
        C: Context,
        J: Iterator,
        J::Item: Borrow<([F; L], [F; L])>,
    {
        // generate next proof
        // from iterator

        // generate proof shares from prss
        let (share_of_proof_from_prover_left, my_proof_right_share) =
            Self::gen_proof_shares_from_prss(ctx, record_ids);

        // generate prover left proof
        let my_proof_left_share = Self::gen_other_proof_share(my_proof, my_proof_right_share);

        // compute next uv values
        // from iterator
        let uv_values = Self::gen_challenge_and_recurse(
            &my_proof_left_share,
            &my_proof_right_share,
            uv_iterator,
        );

        //output uv values, prover left component and component from left
        (
            uv_values,
            share_of_proof_from_prover_left,
            my_proof_left_share,
        )
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::iter::zip;

    use futures::future::try_join;

    use crate::{
        ff::{Fp31, Fp61BitPrime, PrimeField, U128Conversions},
        helpers::{Direction, Role},
        protocol::{
            context::Context,
            ipa_prf::malicious_security::{
                lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
                prover::{ProofGenerator, SmallProofGenerator, UVValues},
            },
            RecordId, RecordIdRange,
        },
        seq_join::SeqJoin,
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    type TestProofGenerator = ProofGenerator<Fp31, 4, 7, 3>;
    type LargeProofGenerator = ProofGenerator<Fp61BitPrime, 32, 63, 31>;

    fn zip_chunks<F: PrimeField, const U: usize, I, J>(a: I, b: J) -> UVValues<F, U>
    where
        I: IntoIterator<Item = u128>,
        J: IntoIterator<Item = u128>,
    {
        a.into_iter()
            .zip(b)
            .map(|(u, v)| (F::truncate_from(u), F::truncate_from(v)))
            .collect::<UVValues<F, U>>()
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
        const U_3: [u128; 2] = [3, 3]; // will later be padded with zeroes
        const V_3: [u128; 2] = [5, 24]; // will later be padded with zeroes

        const PROOF_3: [u128; 7] = [12, 10, 0, 15, 16, 19, 5];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let denominator = CanonicalLagrangeDenominator::<Fp31, 4>::new();
        let lagrange_table = LagrangeTable::<Fp31, 4, 3>::from(denominator);

        // uv values in input format (iterator of tuples of arrays of length 4)
        let uv_1 = zip_chunks(U_1, V_1);

        // first iteration
        let proof_1 = TestProofGenerator::compute_proof_from_uv(uv_1.iter(), &lagrange_table);
        assert_eq!(
            proof_1.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_1,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_1: [Fp31; 7] = PROOF_LEFT_1.map(Fp31::truncate_from);
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
        assert_eq!(uv_2, zip_chunks(U_2, V_2));

        // next iteration
        let proof_2 = TestProofGenerator::compute_proof_from_uv(uv_2.iter(), &lagrange_table);
        assert_eq!(
            proof_2.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_2,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_2: [Fp31; 7] = PROOF_LEFT_2.map(Fp31::truncate_from);
        let proof_right_2 = zip(proof_2, proof_left_2)
            .map(|(x, y)| x - y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // fiat-shamir
        let uv_3 = TestProofGenerator::gen_challenge_and_recurse::<_, 4>(
            &proof_left_2,
            &proof_right_2,
            uv_2.iter(),
        );
        assert_eq!(uv_3, zip_chunks(U_3, V_3));

        let masked_uv_3 = zip_chunks(
            [P_RANDOM_WEIGHT, U_3[1], 0, U_3[0]],
            [Q_RANDOM_WEIGHT, V_3[1], 0, V_3[0]],
        );

        // final iteration
        let proof_3 =
            TestProofGenerator::compute_proof_from_uv(masked_uv_3.iter(), &lagrange_table);
        assert_eq!(
            proof_3.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }

    #[test]
    fn check_uv_length() {
        run(|| async move {
            const U_1: [u128; 27] = [
                0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2,
                30, 30,
            ];
            const V_1: [u128; 27] = [
                0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0,
                0, 1,
            ];

            let denominator = CanonicalLagrangeDenominator::<Fp31, 4>::new();
            let lagrange_table = LagrangeTable::<Fp31, 4, 3>::from(denominator);

            // uv values in input format (iterator of tuples of arrays of length 4)
            let uv_1 = zip_chunks(U_1, V_1);

            // first iteration
            let world = TestWorld::default();
            let mut record_ids = RecordIdRange::ALL;
            let proof = TestProofGenerator::compute_proof_from_uv(uv_1.iter(), &lagrange_table);
            let (uv_values, _, _) = TestProofGenerator::gen_artefacts_from_recursive_step::<_, _, 4>(
                &world.contexts()[0],
                &mut record_ids,
                proof,
                uv_1.iter(),
            );

            assert_eq!(7, uv_values.len());
        });
    }

    /// Simple test that ensures there is no panic when using the small parameter set.
    /// It checks that the small parameter set is set up correctly.
    #[test]
    fn check_for_panic_small_set() {
        const U: [u128; 64] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16, 0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1,
            15, 0, 0, 1, 15, 2, 30, 30, 16, 0, 0, 30, 16,
        ];
        const V: [u128; 64] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1, 0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30,
            0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1,
        ];

        let uv_before = zip_chunks(U, V);

        let denominator = CanonicalLagrangeDenominator::<
            Fp61BitPrime,
            { SmallProofGenerator::RECURSION_FACTOR },
        >::new();
        let lagrange_table = LagrangeTable::<
            Fp61BitPrime,
            { SmallProofGenerator::RECURSION_FACTOR },
            { SmallProofGenerator::LAGRANGE_LENGTH },
        >::from(denominator);

        // compute proof
        let proof = SmallProofGenerator::compute_proof_from_uv(uv_before.iter(), &lagrange_table);

        assert_eq!(proof.len(), SmallProofGenerator::PROOF_LENGTH);

        let uv_after = SmallProofGenerator::gen_challenge_and_recurse::<_, 8>(
            &proof,
            &proof,
            uv_before.iter(),
        );

        assert_eq!(
            uv_before.len(),
            uv_after.len() * SmallProofGenerator::RECURSION_FACTOR
        );
    }

    /// Simple test that ensures there is no panic when using the large parameter set.
    /// It checks that the small parameter set is set up correctly.
    #[test]
    fn check_for_panic_large_set() {
        const U: [u128; 1024] = [1u128; 1024];
        const V: [u128; 1024] = [2u128; 1024];

        let uv_before = zip_chunks(U, V);

        let denominator = CanonicalLagrangeDenominator::<
            Fp61BitPrime,
            { LargeProofGenerator::RECURSION_FACTOR },
        >::new();
        let lagrange_table = LagrangeTable::<
            Fp61BitPrime,
            { LargeProofGenerator::RECURSION_FACTOR },
            { LargeProofGenerator::LAGRANGE_LENGTH },
        >::from(denominator);

        // compute proof
        let proof = LargeProofGenerator::compute_proof_from_uv(uv_before.iter(), &lagrange_table);

        assert_eq!(proof.len(), LargeProofGenerator::PROOF_LENGTH);

        let uv_after = LargeProofGenerator::gen_challenge_and_recurse::<_, 8>(
            &proof,
            &proof,
            uv_before.iter(),
        );

        assert_eq!(
            uv_before.len(),
            uv_after.len() * LargeProofGenerator::RECURSION_FACTOR
        );
    }

    #[tokio::test]
    pub async fn test_prss_consistency() {
        const NUM_PROOFS: usize = 10;

        let world = TestWorld::default();
        let [helper_1_proofs, helper_2_proofs, helper_3_proofs] = world
            .semi_honest((), |ctx, ()| async move {
                let mut record_ids = RecordIdRange::ALL;
                (0..NUM_PROOFS)
                    .map(|i| {
                        assert_eq!(i * 7, usize::from(record_ids.peek_first()));
                        TestProofGenerator::gen_proof_shares_from_prss(&ctx, &mut record_ids)
                    })
                    .collect::<Vec<_>>()
            })
            .await;

        for i in 0..NUM_PROOFS {
            // Destructure
            let (h1_proof_left, h1_proof_right) = helper_1_proofs[i];
            let (h2_proof_left, h2_proof_right) = helper_2_proofs[i];
            let (h3_proof_left, h3_proof_right) = helper_3_proofs[i];

            // Check share consistency
            assert_eq!(h1_proof_right, h2_proof_left);
            assert_eq!(h2_proof_right, h3_proof_left);
            assert_eq!(h3_proof_right, h1_proof_left);

            // Since the shares are randomly distributed, there is an extremely low chance that they will be the same.
            assert_ne!(h1_proof_right, h2_proof_right);
            assert_ne!(h2_proof_right, h3_proof_right);
            assert_ne!(h3_proof_right, h1_proof_right);

            if i > 0 {
                // The record ID should be incremented, ensuring each proof is unique
                assert_ne!(helper_1_proofs[i - 1].1, h1_proof_right);
                assert_ne!(helper_2_proofs[i - 1].1, h2_proof_right);
                assert_ne!(helper_3_proofs[i - 1].1, h3_proof_right);
            }
        }
    }

    fn assert_two_part_secret_sharing(
        expected_proof: [u128; 7],
        left_share: [Fp31; 7],
        right_share: [Fp31; 7],
    ) {
        for (expected_value, (left, right)) in zip(expected_proof, zip(left_share, right_share)) {
            assert_eq!(expected_value, (left + right).as_u128());
        }
    }

    #[tokio::test]
    pub async fn test_proof_secret_sharing() {
        const PROOF_1: [u128; 7] = [7, 12, 30, 22, 16, 14, 8];
        const PROOF_2: [u128; 7] = [18, 13, 26, 29, 1, 0, 4];
        const PROOF_3: [u128; 7] = [19, 25, 20, 9, 2, 15, 5];
        let world = TestWorld::default();
        let [(h1_proof_left, h1_proof_right), (h2_proof_left, h2_proof_right), (h3_proof_left, h3_proof_right)] =
            world
                .semi_honest((), |ctx, ()| async move {
                    let mut record_ids = RecordIdRange::ALL;
                    let (proof_share_left, my_share_of_right) =
                        TestProofGenerator::gen_proof_shares_from_prss(&ctx, &mut record_ids);
                    let proof_u128 = match ctx.role() {
                        Role::H1 => PROOF_1,
                        Role::H2 => PROOF_2,
                        Role::H3 => PROOF_3,
                    };
                    let proof = proof_u128.map(Fp31::truncate_from);
                    let proof_share_right =
                        TestProofGenerator::gen_other_proof_share(proof, proof_share_left);

                    // set up context
                    let c = ctx
                        .narrow("send_proof_share")
                        .set_total_records(proof_share_right.len());

                    // set up channels
                    let send_channel_right =
                        &c.send_channel::<Fp31>(ctx.role().peer(Direction::Right));
                    let recv_channel_left =
                        &c.recv_channel::<Fp31>(ctx.role().peer(Direction::Left));

                    // send share
                    let (my_share_of_left_vec, _) = try_join(
                        c.parallel_join((0..proof_share_right.len()).map(|i| async move {
                            recv_channel_left.receive(RecordId::from(i)).await
                        })),
                        c.parallel_join(proof_share_right.iter().enumerate().map(
                            |(i, elem)| async move {
                                send_channel_right.send(RecordId::from(i), elem).await
                            },
                        )),
                    )
                    .await
                    .unwrap();

                    (my_share_of_left_vec.try_into().unwrap(), my_share_of_right)
                })
                .await;

        assert_two_part_secret_sharing(PROOF_1, h3_proof_right, h2_proof_left);
        assert_two_part_secret_sharing(PROOF_2, h1_proof_right, h3_proof_left);
        assert_two_part_secret_sharing(PROOF_3, h2_proof_right, h1_proof_left);
    }
}
