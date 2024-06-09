use futures_util::future::try_join;

use crate::{
    error::Error,
    ff::Fp61BitPrime,
    helpers::{
        hashing::{compute_hash, hash_to_field, Hash},
        Direction,
    },
    protocol::{
        context::{dzkp_field::UVTupleBlock, Context},
        ipa_prf::{
            malicious_security::{
                lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
                prover::{LargeProofGenerator, SmallProofGenerator},
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
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct BatchToVerify {
    first_proof_from_left_prover: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    first_proof_from_right_prover: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    proofs_from_left_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    proofs_from_right_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    p_mask_from_left_prover: Fp61BitPrime,
    q_mask_from_right_prover: Fp61BitPrime,
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
    pub async fn generate_batch_to_verify<C, I>(ctx: C, uv_tuple_inputs: I) -> Self
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
        // verifier on the right has p,
        // therefore the right share is "implicitly sent" to the right ("communicated" via PRSS)
        let (p_mask_from_left_prover, my_p_mask) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;
        // and verifier on the left has q
        // therefore the left share is "implicitly sent" to the left (communication via PRSS)
        let (my_q_mask, q_mask_from_right_prover) = ctx.prss().generate_fields(record_counter);
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
            p_mask_from_left_prover,
            q_mask_from_right_prover,
        }
    }

    /// This function computes a tuple of vector of challenges from a `BatchToVerify`
    /// It outputs (`challenges_from_proof_of_left_prover`, `challenges_from_proof_of_right_prover`)
    ///
    /// ## Panics
    /// Panics when recursion factor constant cannot be converted to `u128`
    /// or when sending and receiving hashes over the network fails.
    async fn generate_challenge<C: Context>(
        &self,
        ctx: &C,
    ) -> (Vec<Fp61BitPrime>, Vec<Fp61BitPrime>) {
        // exclude for first proof
        let exclude_large = u128::try_from(LargeProofGenerator::RECURSION_FACTOR).unwrap();
        // exclude for other proofs
        let exclude_small = u128::try_from(SmallProofGenerator::RECURSION_FACTOR).unwrap();

        // generate hashes
        let hashes = ProofHash::generate_hash(self);

        // send hashes
        let send_future = hashes.send_hash(ctx);
        let receive_future = ProofHash::receive_hash(ctx, hashes.len());

        // receive other hashes
        let ((), other_hashes) = try_join(send_future, receive_future).await.unwrap();

        // compute challenges_from_proof_of_left_prover
        // the prover computes hash_to_field(left,right)
        // this is the right verifier of the party to the left,
        // i.e. it has the right share, other is the left share
        let mut challenges_from_proof_of_left_prover =
            Vec::<Fp61BitPrime>::with_capacity(hashes.len());
        challenges_from_proof_of_left_prover.push(hash_to_field(
            &other_hashes.proof_from_prover_left_hash[0],
            &hashes.proof_from_prover_left_hash[0],
            exclude_large,
        ));
        for (left, right) in other_hashes
            .proof_from_prover_left_hash
            .iter()
            .zip(hashes.proof_from_prover_left_hash.iter())
        {
            challenges_from_proof_of_left_prover.push(hash_to_field(left, right, exclude_small));
        }

        // compute challenges_from_proof_of_right_prover
        // the prover computes hash_to_field(left,right)
        // this is the left verifier of the party to the right,
        // i.e. it has the left share, other is the right share
        let mut challenges_from_proof_of_right_prover =
            Vec::<Fp61BitPrime>::with_capacity(hashes.len());
        challenges_from_proof_of_right_prover.push(hash_to_field(
            &hashes.proof_from_prover_right_hash[0],
            &other_hashes.proof_from_prover_right_hash[0],
            exclude_large,
        ));
        for (left, right) in hashes
            .proof_from_prover_right_hash
            .iter()
            .zip(other_hashes.proof_from_prover_right_hash.iter())
        {
            challenges_from_proof_of_right_prover.push(hash_to_field(left, right, exclude_small));
        }

        (
            challenges_from_proof_of_left_prover,
            challenges_from_proof_of_right_prover,
        )
    }
}

struct ProofHash {
    proof_from_prover_left_hash: Vec<Hash>,
    proof_from_prover_right_hash: Vec<Hash>,
}

impl ProofHash {
    fn len(&self) -> usize {
        assert_eq!(
            self.proof_from_prover_left_hash.len(),
            self.proof_from_prover_right_hash.len()
        );
        self.proof_from_prover_left_hash.len()
    }
    fn generate_hash(batch_to_verify: &BatchToVerify) -> Self {
        let length = batch_to_verify.proofs_from_left_prover.len();
        let mut proof_from_prover_left_hash = Vec::<Hash>::with_capacity(length);
        let mut proof_from_prover_right_hash = Vec::<Hash>::with_capacity(length);

        // compute first hash
        proof_from_prover_left_hash.push(compute_hash(
            batch_to_verify.first_proof_from_left_prover.iter(),
        ));
        proof_from_prover_right_hash.push(compute_hash(
            batch_to_verify.first_proof_from_right_prover.iter(),
        ));

        // compute other hashes
        // we don't need to hash last proof
        for i in 0..(length - 1) {
            proof_from_prover_left_hash.push(compute_hash(
                batch_to_verify.proofs_from_left_prover[i].iter(),
            ));
            proof_from_prover_right_hash.push(compute_hash(
                batch_to_verify.proofs_from_right_prover[i].iter(),
            ));
        }

        Self {
            proof_from_prover_left_hash,
            proof_from_prover_right_hash,
        }
    }

    /// This function sends the `ProofHash` over the network.
    /// It sends `proof_from_prover_left_hash` to the other verifier which is on the right
    /// (for the proof generated by the party on the left).
    /// It sends `proof_from_prover_right_hash` to the other verifier which is on the left
    /// (for the proof generated by the party on the right).
    async fn send_hash<C: Context>(&self, ctx: &C) -> Result<(), Error> {
        // set up context for the communication over the network
        let communication_ctx = ctx.set_total_records(self.len());

        // set up channels
        let send_channel_left =
            &communication_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Left));
        let send_channel_right =
            &communication_ctx.send_channel::<Hash>(ctx.role().peer(Direction::Right));

        // send left hashes to the right
        let send_to_right = communication_ctx.parallel_join(
            self.proof_from_prover_left_hash
                .iter()
                .enumerate()
                .map(|(i, hash)| async move {
                    // send hash
                    send_channel_right.send(RecordId::from(i), hash).await
                }),
        );
        // send left hashes to the left
        let send_to_left = communication_ctx.parallel_join(
            self.proof_from_prover_right_hash
                .iter()
                .enumerate()
                .map(|(i, hash)| async move {
                    // send hash
                    send_channel_left.send(RecordId::from(i), hash).await
                }),
        );

        let _ = try_join(send_to_right, send_to_left).await?;

        Ok(())
    }

    /// This function receives the hashes of the proof from the other verifier.
    async fn receive_hash<C: Context>(ctx: &C, length: usize) -> Result<Self, Error> {
        // set up context
        let communication_ctx = ctx.set_total_records(length);

        // set up channels
        let receive_channel_left =
            &communication_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Left));
        let receive_channel_right =
            &communication_ctx.recv_channel::<Hash>(ctx.role().peer(Direction::Right));

        // receive hashes
        // receive from the right helper
        let future_right =
            communication_ctx
                .parallel_join((0..length).map(|i| async move {
                    receive_channel_right.receive(RecordId::from(i)).await
                }));
        // receive from the left helper
        let future_left = communication_ctx.parallel_join(
            (0..length)
                .map(|i| async move { receive_channel_left.receive(RecordId::from(i)).await }),
        );

        // we receive hash of proof from prover left from the right helper,
        // i.e. the other verifier for that proof
        // and hash of proof from prover right from the left helper,
        // i.e. the other verifier for that proof
        let (other_hash_of_proof_from_prover_left, other_hash_of_proof_from_prover_right) =
            try_join(future_right, future_left).await?;

        Ok(Self {
            proof_from_prover_left_hash: other_hash_of_proof_from_prover_left,
            proof_from_prover_right_hash: other_hash_of_proof_from_prover_right,
        })
    }
}

#[cfg(all(test, unit_test))]
pub mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Fp61BitPrime, U128Conversions},
        protocol::{
            context::{dzkp_field::BLOCK_SIZE, Context},
            ipa_prf::{
                malicious_security::prover::{LargeProofGenerator, SmallProofGenerator},
                validation_protocol::validation::BatchToVerify,
            },
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
                left_verifier.q_mask_from_right_prover,
                right_verifier.p_mask_from_left_prover
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

            let result = world
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
                                        Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h
                                    })
                                    .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                                (BLOCK_SIZE * i..BLOCK_SIZE * (i + 1))
                                    .map(|j| {
                                        Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h
                                    })
                                    .collect::<[Fp61BitPrime; BLOCK_SIZE]>(),
                            )
                        })
                        .collect::<Vec<_>>();

                    // generate and output VerifierBatch together with h value
                    let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                        ctx.narrow("generate_batch"),
                        uv_tuple_vec.into_iter(),
                    )
                    .await;

                    // generate and output challenges
                    batch_to_verify.generate_challenge(&ctx).await
                })
                .await;

            // check consistency of result
            let (helper_1_left, helper_1_right) = result[0].clone();
            let (helper_2_left, helper_2_right) = result[1].clone();
            let (helper_3_left, helper_3_right) = result[2].clone();
            // verifier when H1 is prover
            assert_eq!(helper_2_left, helper_3_right);
            // verifier when H2 is prover
            assert_eq!(helper_3_left, helper_1_right);
            // verifier when H3 is prover
            assert_eq!(helper_1_left, helper_2_right);
        });
    }
}
