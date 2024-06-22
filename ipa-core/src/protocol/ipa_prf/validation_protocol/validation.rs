use std::iter::{once, repeat};

use futures_util::{
    future::{try_join, try_join4},
    stream,
};

use crate::{
    error::Error,
    ff::Fp61BitPrime,
    helpers::{
        hashing::{compute_hash, hash_to_field, Hash},
        Direction, TotalRecords,
    },
    protocol::{
        context::{dzkp_field::UVTupleBlock, Context},
        ipa_prf::{
            malicious_security::{
                lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
                prover::{LargeProofGenerator, SmallProofGenerator},
                verifier::recursively_compute_final_check,
            },
            validation_protocol::proof_generation::ProofBatch,
        },
        prss::SharedRandomness,
        RecordId,
    },
};

/// This is a tuple of `ZeroKnowledgeProofs` owned by a verifier.
/// It consists of a proof from the prover on the left
/// and a proof from the prover on the right.
///
/// The first proof has a different length, i.e. length `P`.
/// It is therefore not stored in the vector with the other proofs.
///
/// `ProofsToVerify` also contains two masks `p_0` and `q_0` in `masks` stored as `(p_0,q_0)`
/// These masks are used as additional `u,v` values for the final proof.
/// These masks mask sensitive information when verifying the final proof.
/// `sum_of_uv` is `sum u*v`.
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct BatchToVerify {
    first_proof_from_left_prover: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    first_proof_from_right_prover: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    proofs_from_left_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    proofs_from_right_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    p_mask_from_right_prover: Fp61BitPrime,
    q_mask_from_left_prover: Fp61BitPrime,
    // remove dead_code once we use size_m
    #[allow(dead_code)]
    sum_of_uv: usize,
}

impl BatchToVerify {
    /// This function generates the `BatchToVerify`.
    /// Each helper party generates a set of proofs, which are secret-shared.
    /// The "left" shares of these proofs are sent to the helper on the left.
    /// The "right" shares of these proofs need not be transmitted over the wire, as they
    /// are generated via `PRSS`, so the helper on the right can independently generate them.
    /// Finally, each helper receives a batch of secret-shares from the helper to its right.
    /// The final proof must be "masked" with random values drawn from PRSS.
    /// These values will be needed at verification time.
    pub async fn generate_batch_to_verify<C, I>(
        ctx: C,
        uv_tuple_inputs: I,
        sum_of_uv: usize,
    ) -> Self
    where
        C: Context,
        I: Iterator<Item = UVTupleBlock<Fp61BitPrime>> + Clone,
    {
        const LRF: usize = LargeProofGenerator::RECURSION_FACTOR;
        const LLL: usize = LargeProofGenerator::LAGRANGE_LENGTH;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;
        const SLL: usize = SmallProofGenerator::LAGRANGE_LENGTH;
        const SPL: usize = SmallProofGenerator::PROOF_LENGTH;

        // set up record counter
        let mut record_counter = RecordId::from(0);

        // precomputation for first proof
        let first_denominator = CanonicalLagrangeDenominator::<Fp61BitPrime, LRF>::new();
        let first_lagrange_table = LagrangeTable::<Fp61BitPrime, LRF, LLL>::from(first_denominator);

        // generate first proof from input iterator
        let (mut uv_values, first_proof_from_left, my_first_proof_left_share) =
            LargeProofGenerator::gen_artefacts_from_recursive_step(
                &ctx,
                &mut record_counter,
                &first_lagrange_table,
                ProofBatch::polynomials_from_inputs(uv_tuple_inputs),
            );

        // approximate length of proof vector (rounded up)
        let uv_len_bits: u32 = usize::BITS - uv_values.len().leading_zeros();
        let small_recursion_factor_bits: u32 = usize::BITS - SRF.leading_zeros();
        let expected_len = 1 << (uv_len_bits - small_recursion_factor_bits);

        // storage for other proofs
        let mut my_proofs_left_shares = Vec::<[Fp61BitPrime; SPL]>::with_capacity(expected_len);
        let mut shares_of_proofs_from_prover_left =
            Vec::<[Fp61BitPrime; SPL]>::with_capacity(expected_len);

        // generate masks
        // verifier on the left has p,
        // therefore the left share is "implicitly sent" to the left ("communicated" via PRSS)
        let (my_p_mask, p_mask_from_right_prover) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;
        // and verifier on the right has q
        // therefore the right share is "implicitly sent" to the right (communication via PRSS)
        let (q_mask_from_left_prover, my_q_mask) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;

        let denominator = CanonicalLagrangeDenominator::<Fp61BitPrime, SRF>::new();
        let lagrange_table = LagrangeTable::<Fp61BitPrime, SRF, SLL>::from(denominator);

        // recursively generate proofs via SmallProofGenerator
        while uv_values.len() > 1 {
            if uv_values.len() < SRF {
                uv_values.set_masks(my_p_mask, my_q_mask).unwrap();
            }
            let (uv_values_new, share_of_proof_from_prover_left, my_proof_left_share) =
                SmallProofGenerator::gen_artefacts_from_recursive_step(
                    &ctx,
                    &mut record_counter,
                    &lagrange_table,
                    uv_values.iter(),
                );
            shares_of_proofs_from_prover_left.push(share_of_proof_from_prover_left);
            my_proofs_left_shares.push(my_proof_left_share);

            uv_values = uv_values_new;
        }

        let my_batch_left_shares = ProofBatch {
            first_proof: my_first_proof_left_share,
            proofs: my_proofs_left_shares,
        };
        let shares_of_batch_from_left_prover = ProofBatch {
            first_proof: first_proof_from_left,
            proofs: shares_of_proofs_from_prover_left,
        };

        // send one batch left and receive one batch from the right
        let length = my_batch_left_shares.len();
        let ((), shares_of_batch_from_right_prover) = try_join(
            my_batch_left_shares.send_to_left(&ctx),
            ProofBatch::receive_from_right(&ctx, length),
        )
        .await
        .unwrap();

        BatchToVerify {
            first_proof_from_left_prover: shares_of_batch_from_left_prover.first_proof,
            first_proof_from_right_prover: shares_of_batch_from_right_prover.first_proof,
            proofs_from_left_prover: shares_of_batch_from_left_prover.proofs,
            proofs_from_right_prover: shares_of_batch_from_right_prover.proofs,
            p_mask_from_right_prover,
            q_mask_from_left_prover,
            sum_of_uv,
        }
    }

    /// This function computes a tuple of vector of challenges from a `BatchToVerify`
    /// It outputs (`challenges_for_left_prover`, `challenges_for_right_prover`)
    ///
    /// ## Panics
    /// Panics when recursion factor constant cannot be converted to `u128`
    /// or when sending and receiving hashes over the network fails.
    async fn generate_challenges<C: Context>(
        &self,
        ctx: &C,
    ) -> (Vec<Fp61BitPrime>, Vec<Fp61BitPrime>) {
        const LRF: usize = LargeProofGenerator::RECURSION_FACTOR;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;

        // exclude for first proof
        let exclude_large = u128::try_from(LRF).unwrap();
        // exclude for other proofs
        let exclude_small = u128::try_from(SRF).unwrap();

        // generate hashes
        let my_hashes_prover_left = ProofHashes::generate_hashes(self, Side::Left);
        let my_hashes_prover_right = ProofHashes::generate_hashes(self, Side::Right);

        // receive hashes from the other verifier
        let ((), (), other_hashes_prover_left, other_hashes_prover_right) = try_join4(
            my_hashes_prover_left.send_hashes(ctx, Side::Left),
            my_hashes_prover_right.send_hashes(ctx, Side::Right),
            ProofHashes::receive_hashes(ctx, my_hashes_prover_left.hashes.len(), Side::Left),
            ProofHashes::receive_hashes(ctx, my_hashes_prover_right.hashes.len(), Side::Right),
        )
        .await
        .unwrap();

        // From the perspective of the *prover_left*, _left_ is the other helper and _right_ is this verifier
        let challenges_for_prover_left = other_hashes_prover_left
            .hashes
            .iter()
            .zip(my_hashes_prover_left.hashes.iter())
            .zip(once(exclude_large).chain(repeat(exclude_small)))
            .map(|((hash_left, hash_right), exclude)| {
                hash_to_field(hash_left, hash_right, exclude)
            });

        // From the perspective of the *prover_right*, _left_ is this helper and _right_ is the other verifier
        let challenges_for_prover_right = my_hashes_prover_right
            .hashes
            .iter()
            .zip(other_hashes_prover_right.hashes.iter())
            .zip(once(exclude_large).chain(repeat(exclude_small)))
            .map(|((hash_left, hash_right), exclude)| {
                hash_to_field(hash_left, hash_right, exclude)
            });

        (
            challenges_for_prover_left.collect(),
            challenges_for_prover_right.collect(),
        )
    }

    /// This function computes and outputs the final `p_r_from_left_prover * q_r_from_left_prover` value.
    async fn p_and_q_r_check<C, U, V>(
        &self,
        ctx: &C,
        challenges_for_left_prover: &[Fp61BitPrime],
        challenges_for_right_prover: &[Fp61BitPrime],
        u_from_right_prover: U,
        v_from_left_prover: V,
    ) -> Result<Fp61BitPrime, Error>
    where
        C: Context,
        U: Iterator<Item = Fp61BitPrime> + Send,
        V: Iterator<Item = Fp61BitPrime> + Send,
    {
        const LRF: usize = LargeProofGenerator::RECURSION_FACTOR;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;

        // compute p_r
        let p_r_right_prover = recursively_compute_final_check::<_, _, LRF, SRF>(
            stream::iter(u_from_right_prover),
            challenges_for_right_prover,
            self.p_mask_from_right_prover,
        )
        .await;
        // compute q_r
        let q_r_left_prover = recursively_compute_final_check::<_, _, LRF, SRF>(
            stream::iter(v_from_left_prover),
            challenges_for_left_prover,
            self.q_mask_from_left_prover,
        )
        .await;

        // send to the left
        let communication_ctx = ctx.set_total_records(1);

        let send_channel =
            communication_ctx.send_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Right));
        let receive_channel =
            communication_ctx.recv_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Left));

        let ((), q_r_right_prover) = try_join(
            send_channel.send(RecordId::FIRST, q_r_left_prover),
            receive_channel.receive(RecordId::FIRST),
        )
        .await?;

        Ok(p_r_right_prover * q_r_right_prover)
    }
}

struct ProofHashes {
    hashes: Vec<Hash>,
}

#[derive(Clone, Copy, Debug)]
enum Side {
    Left,
    Right,
}

impl ProofHashes {
    // Generates hashes for proofs received from prover indicated by `side`
    fn generate_hashes(batch_to_verify: &BatchToVerify, side: Side) -> Self {
        let (first_proof, other_proofs) = match side {
            Side::Left => (
                &batch_to_verify.first_proof_from_left_prover,
                &batch_to_verify.proofs_from_left_prover,
            ),
            Side::Right => (
                &batch_to_verify.first_proof_from_right_prover,
                &batch_to_verify.proofs_from_right_prover,
            ),
        };

        Self {
            hashes: once(compute_hash(first_proof))
                .chain(
                    other_proofs
                        .iter()
                        //.take(length - 1) // we don't need to hash last proof
                        .map(|proof| compute_hash(proof.iter())),
                )
                .collect::<Vec<_>>(),
        }
    }

    /// Sends the one verifier's hashes to the other verifier
    /// `side` indicates the direction of the prover.
    async fn send_hashes<C: Context>(&self, ctx: &C, side: Side) -> Result<(), Error> {
        let communication_ctx = ctx.set_total_records(TotalRecords::specified(self.hashes.len())?);

        let send_channel = match side {
            // send left hashes to the right
            Side::Left => communication_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Right)),
            // send right hashes to the left
            Side::Right => communication_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Left)),
        };
        let send_channel_ref = &send_channel;

        communication_ctx
            .parallel_join(self.hashes.iter().enumerate().map(|(i, hash)| async move {
                send_channel_ref.send(RecordId::from(i), hash).await
            }))
            .await?;

        Ok(())
    }

    /// This function receives hashes from the other verifier
    /// `side` indicates the direction of the prover.
    async fn receive_hashes<C: Context>(ctx: &C, length: usize, side: Side) -> Result<Self, Error> {
        // set up context for the communication over the network
        let communication_ctx = ctx.set_total_records(TotalRecords::specified(length)?);

        let recv_channel = match side {
            // receive left hashes from the right helper
            Side::Left => communication_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Right)),
            // reeive right hashes from the left helper
            Side::Right => communication_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Left)),
        };
        let recv_channel_ref = &recv_channel;

        let hashes_received = communication_ctx
            .parallel_join(
                (0..length)
                    .map(|i| async move { recv_channel_ref.receive(RecordId::from(i)).await }),
            )
            .await?;

        Ok(Self {
            hashes: hashes_received,
        })
    }
}

#[cfg(all(test, unit_test))]
pub mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Fp61BitPrime, U128Conversions},
        protocol::{
            context::{
                dzkp_field::{UVTupleBlock, BLOCK_SIZE},
                Context,
            },
            ipa_prf::{
                malicious_security::{
                    lagrange::CanonicalLagrangeDenominator,
                    prover::{LargeProofGenerator, SmallProofGenerator},
                    verifier::{compute_sum_share, interpolate_at_r},
                },
                validation_protocol::validation::BatchToVerify,
            },
            prss::SharedRandomness,
            RecordId,
        },
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    // todo: deprecate once validation protocol is implemented
    pub fn simple_proof_check(
        h: Fp61BitPrime,
        left_verifier: &BatchToVerify,
        right_verifier: &BatchToVerify,
    ) {
        // check lengths:
        // first proof has correct length
        assert_eq!(
            left_verifier.first_proof_from_left_prover.len(),
            LargeProofGenerator::PROOF_LENGTH
        );
        assert_eq!(
            left_verifier.first_proof_from_left_prover.len(),
            left_verifier.first_proof_from_right_prover.len()
        );
        // other proofs has correct length
        for i in 0..left_verifier.proofs_from_left_prover.len() {
            assert_eq!(
                (i, left_verifier.proofs_from_left_prover[i].len()),
                (i, SmallProofGenerator::PROOF_LENGTH)
            );
            assert_eq!(
                (i, left_verifier.proofs_from_left_prover[i].len()),
                (i, left_verifier.proofs_from_right_prover[i].len())
            );
        }
        // check that masks are not 0
        assert_ne!(
            (
                left_verifier.q_mask_from_left_prover,
                right_verifier.p_mask_from_right_prover
            ),
            (Fp61BitPrime::ZERO, Fp61BitPrime::ZERO)
        );

        // check first proof,
        // compute simple proof without lagrange interpolated points
        let simple_proof = {
            let block_to_polynomial = BLOCK_SIZE / LargeProofGenerator::RECURSION_FACTOR;
            let simple_proof_uv = (0usize..100 * block_to_polynomial)
                .map(|i| {
                    (
                        (LargeProofGenerator::RECURSION_FACTOR * i
                            ..LargeProofGenerator::RECURSION_FACTOR * (i + 1))
                            .map(|j| Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h)
                            .collect::<[Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR]>(),
                        (LargeProofGenerator::RECURSION_FACTOR * i
                            ..LargeProofGenerator::RECURSION_FACTOR * (i + 1))
                            .map(|j| Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h)
                            .collect::<[Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR]>(),
                    )
                })
                .collect::<Vec<(
                    [Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR],
                    [Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR],
                )>>();

            simple_proof_uv.iter().fold(
                [Fp61BitPrime::ZERO; LargeProofGenerator::RECURSION_FACTOR],
                |mut acc, (left, right)| {
                    for i in 0..LargeProofGenerator::RECURSION_FACTOR {
                        acc[i] += left[i] * right[i];
                    }
                    acc
                },
            )
        };

        // reconstruct computed proof
        // by adding shares left and right
        let proof_computed = left_verifier
            .first_proof_from_right_prover
            .iter()
            .zip(right_verifier.first_proof_from_left_prover.iter())
            .map(|(&left, &right)| left + right)
            .collect::<Vec<Fp61BitPrime>>();

        // check for consistency
        // only check first R::USIZE field elements
        assert_eq!(
            (h.as_u128(), simple_proof.to_vec()),
            (
                h.as_u128(),
                proof_computed[0..LargeProofGenerator::RECURSION_FACTOR].to_vec()
            )
        );
    }

    #[test]
    fn check_challenge_consistency_across_verifier() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            // each helper samples a random value h
            // which is later used to generate distinct values across helpers
            let h = Fp61BitPrime::truncate_from(rng.gen_range(0u128..100));

            let [(helper_1_left, helper_1_right), (helper_2_left, helper_2_right), (helper_3_left, helper_3_right)] =
                world
                    .semi_honest(h, |ctx, h| async move {
                        let h = Fp61BitPrime::truncate_from(h.left().as_u128() % 100);
                        // generate blocks of UV values
                        // generate u values as (1h,2h,3h,....,10h*BlockSize) split into Blocksize chunks
                        // where BlockSize = 32
                        // v values are identical to u
                        let uv_tuple_vec = (0usize..100)
                            .map(|i| {
                                (
                                    (BLOCK_SIZE * i..BLOCK_SIZE * (i + 1))
                                        .map(|j| {
                                            Fp61BitPrime::truncate_from(u128::try_from(j).unwrap())
                                                * h
                                        })
                                        .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                                    (BLOCK_SIZE * i..BLOCK_SIZE * (i + 1))
                                        .map(|j| {
                                            Fp61BitPrime::truncate_from(u128::try_from(j).unwrap())
                                                * h
                                        })
                                        .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // generate and output VerifierBatch together with h value
                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            uv_tuple_vec.into_iter(),
                            // sum is not asserted in this test
                            0,
                        )
                        .await;

                        // generate and output challenges
                        batch_to_verify.generate_challenges(&ctx).await
                    })
                    .await;

            // verifier when H1 is prover
            assert_eq!(helper_2_left, helper_3_right);
            // verifier when H2 is prover
            assert_eq!(helper_3_left, helper_1_right);
            // verifier when H3 is prover
            assert_eq!(helper_1_left, helper_2_right);
        });
    }

    /// This is a helper function to generate `u`, `v` values.
    ///
    /// outputs `(my_u_and_v, u_from_right_prover, v_from_left_prover)`
    #[allow(clippy::type_complexity)]
    fn generate_u_v<C: Context>(
        ctx: &C,
    ) -> (
        Vec<UVTupleBlock<Fp61BitPrime>>,
        Vec<Fp61BitPrime>,
        Vec<Fp61BitPrime>,
    ) {
        const SIZE: usize = 100;

        // outputs
        let mut vec_u_from_right_prover = Vec::<Fp61BitPrime>::with_capacity(BLOCK_SIZE * SIZE);
        let mut vec_v_from_left_prover = Vec::<Fp61BitPrime>::with_capacity(BLOCK_SIZE * SIZE);

        let mut vec_my_u_and_v =
            Vec::<([Fp61BitPrime; BLOCK_SIZE], [Fp61BitPrime; BLOCK_SIZE])>::with_capacity(SIZE);

        // generate random u, v values using PRSS
        let mut counter = RecordId::FIRST;

        for _ in 0..SIZE {
            let mut my_u_array = [Fp61BitPrime::ZERO; BLOCK_SIZE];
            let mut my_v_array = [Fp61BitPrime::ZERO; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                let (my_u, u_from_right_prover) = ctx.prss().generate_fields(counter);
                counter += 1;
                let (v_from_left_prover, my_v) = ctx.prss().generate_fields(counter);
                counter += 1;
                my_u_array[i] = my_u;
                my_v_array[i] = my_v;
                vec_u_from_right_prover.push(u_from_right_prover);
                vec_v_from_left_prover.push(v_from_left_prover);
            }
            vec_my_u_and_v.push((my_u_array, my_v_array));
        }

        (
            vec_my_u_and_v,
            vec_u_from_right_prover,
            vec_v_from_left_prover,
        )
    }

    fn recombine<const P: usize>(
        left: &[Fp61BitPrime; P],
        right: &[Fp61BitPrime; P],
    ) -> [Fp61BitPrime; P] {
        left.iter()
            .zip(right.iter())
            .map(|(left, right)| *left + *right)
            .collect()
    }

    /// This test checks the batches to verify by running a partial verification
    /// The verification checks whether the zero shares of intermediate proofs
    /// are indeed zero by recombining the shares (without sending them over the "network")
    #[test]
    fn check_batch_to_verify_consistency() {
        run(|| async move {
            let world = TestWorld::default();

            let [(h1_c_left, h1_c_right, h1_batch), (h2_c_left, h2_c_right, h2_batch), (h3_c_left, h3_c_right, h3_batch)] =
                world
                    .semi_honest((), |ctx, ()| async move {
                        // generate u, v values
                        let (vec_my_u_and_v, _, _) = generate_u_v(&ctx);

                        // generate and output VerifierBatch together with h value
                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            vec_my_u_and_v.clone().into_iter(),
                            // sum is not asserted in this test
                            0,
                        )
                        .await;

                        // generate challenges
                        let (challenges_for_left_prover, challenges_for_right_prover) =
                            batch_to_verify
                                .generate_challenges(&ctx.narrow("generate_hash"))
                                .await;

                        assert_eq!(
                            challenges_for_right_prover.len(),
                            batch_to_verify.proofs_from_right_prover.len() + 1
                        );

                        // output challenges and batches to verify
                        (
                            challenges_for_left_prover,
                            challenges_for_right_prover,
                            batch_to_verify,
                        )
                    })
                    .await;

            // check challenges
            // h1 prover
            assert_eq!(h2_c_left, h3_c_right);
            // h2 prover
            assert_eq!(h3_c_left, h1_c_right);
            // h3 prover
            assert_eq!(h1_c_left, h2_c_right);

            // assert batches
            // h1
            assert_batch(&h2_batch, &h3_batch, &h3_c_right);
            // h2
            assert_batch(&h3_batch, &h1_batch, &h1_c_right);
            // h3
            assert_batch(&h1_batch, &h2_batch, &h2_c_right);
        });
    }

    fn assert_batch(left: &BatchToVerify, right: &BatchToVerify, challenges: &[Fp61BitPrime]) {
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;
        const SPL: usize = SmallProofGenerator::PROOF_LENGTH;
        const LPL: usize = LargeProofGenerator::PROOF_LENGTH;

        let first = recombine(
            &left.first_proof_from_left_prover,
            &right.first_proof_from_right_prover,
        );
        let others = left
            .proofs_from_left_prover
            .iter()
            .zip(right.proofs_from_right_prover.iter())
            .map(|(left, right)| recombine(left, right))
            .collect::<Vec<_>>();
        let denominator_first = CanonicalLagrangeDenominator::<_, LPL>::new();
        let denominator = CanonicalLagrangeDenominator::<_, SPL>::new();

        let length = others.len();

        let mut out = interpolate_at_r(&first, &challenges[0], &denominator_first);
        for (i, proof) in others.iter().take(length - 1).enumerate() {
            assert_eq!((i, out), (i, compute_sum_share::<_, SRF, SPL>(proof)));
            out = interpolate_at_r(proof, &challenges[i + 1], &denominator);
        }
        // last sum without masks
        let masks = others[length - 1][0];
        let last_sum = compute_sum_share::<_, SRF, SPL>(&others[length - 1]);
        assert_eq!(out, last_sum - masks);
    }

    /// This test checks that `p_r*q_r` is consistent with the last proof
    #[test]
    fn p_times_q() {
        run(|| async move {
            let world = TestWorld::default();

            let [(pq_h1, h1_left, h1_right), (pq_h2, h2_left, h2_right), (pq_h3, h3_left, h3_right)] =
                world
                    .semi_honest((), |ctx, ()| async move {
                        // generate u, v values
                        let (vec_my_u_and_v, vec_u_from_right_prover, vec_v_from_left_prover) =
                            generate_u_v(&ctx);

                        // generate and output VerifierBatch together with h value
                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            vec_my_u_and_v.clone().into_iter(),
                            // sum is not asserted in this test
                            0,
                        )
                        .await;

                        // generate challenges
                        let (challenges_for_left_prover, challenges_for_right_prover) =
                            batch_to_verify
                                .generate_challenges(&ctx.narrow("generate_hash"))
                                .await;

                        assert_eq!(
                            challenges_for_right_prover.len(),
                            batch_to_verify.proofs_from_right_prover.len() + 1
                        );

                        let p_times_q = batch_to_verify
                            .p_and_q_r_check(
                                &ctx,
                                &challenges_for_left_prover,
                                &challenges_for_right_prover,
                                vec_u_from_right_prover.into_iter(),
                                vec_v_from_left_prover.into_iter(),
                            )
                            .await
                            .unwrap();

                        let denominator = CanonicalLagrangeDenominator::<
                            Fp61BitPrime,
                            { SmallProofGenerator::PROOF_LENGTH },
                        >::new();

                        let g_r_left = interpolate_at_r(
                            batch_to_verify.proofs_from_left_prover.last().unwrap(),
                            challenges_for_left_prover.last().unwrap(),
                            &denominator,
                        );
                        let g_r_right = interpolate_at_r(
                            batch_to_verify.proofs_from_right_prover.last().unwrap(),
                            challenges_for_right_prover.last().unwrap(),
                            &denominator,
                        );
                        (p_times_q, g_r_left, g_r_right)
                    })
                    .await;

            // check h1's proof
            assert_eq!(pq_h3, h2_left + h3_right);

            // check h2's proof
            assert_eq!(pq_h1, h3_left + h1_right);

            // check h3's proof
            assert_eq!(pq_h2, h1_left + h2_right);
        });
    }
}
