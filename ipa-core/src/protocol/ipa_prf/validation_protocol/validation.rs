use std::{
    array,
    iter::{once, repeat, zip},
};

use futures_util::future::{try_join, try_join4};
use typenum::{Unsigned, U288, U80};

use crate::{
    const_assert_eq,
    error::{Error, UnwrapInfallible},
    ff::{Fp61BitPrime, Serializable},
    helpers::{
        hashing::{compute_hash, hash_to_field, Hash},
        Direction, MpcMessage, TotalRecords,
    },
    protocol::{
        context::{
            dzkp_validator::MAX_PROOF_RECURSION, step::DzkpProofVerifyStep as Step, Context,
        },
        ipa_prf::{
            malicious_security::{
                prover::{FirstProofGenerator, SmallProofGenerator},
                verifier::{compute_g_differences, recursively_compute_final_check},
            },
            validation_protocol::proof_generation::ProofBatch,
        },
        RecordId,
    },
    secret_sharing::SharedValue,
};

/// This is a tuple of `ZeroKnowledgeProofs` owned by a verifier.
/// It consists of a proof from the prover on the left
/// and a proof from the prover on the right.
///
/// The first proof has a different length, i.e. length `P`.
/// It is therefore not stored in the vector with the other proofs.
///
/// `ProofsToVerify` also contains two masks, `p` and `q`
/// These masks are used as additional `u,v` values for the final proof.
/// These masks mask sensitive information when verifying the final proof.
/// `sum_of_uv` is `sum u*v`.
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct BatchToVerify {
    first_proof_from_left_prover: [Fp61BitPrime; FirstProofGenerator::PROOF_LENGTH],
    first_proof_from_right_prover: [Fp61BitPrime; FirstProofGenerator::PROOF_LENGTH],
    proofs_from_left_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    proofs_from_right_prover: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
    p_mask_from_right_prover: Fp61BitPrime,
    q_mask_from_left_prover: Fp61BitPrime,
}

impl BatchToVerify {
    /// This function generates the `BatchToVerify`
    /// from `my_batch_left_shares` and `shares_of_batch_from_left_prover`.
    /// The `BatchToVerify` is generated by sending `my_batch_left_shares` to the left
    /// and receiving `shares_of_batch_from_right_prover` from the right.
    ///
    /// ## Panics
    /// Panics when send and receive over the network channels fail.
    pub async fn generate_batch_to_verify<C>(
        ctx: C,
        record_id: RecordId,
        my_batch_left_shares: ProofBatch,
        shares_of_batch_from_left_prover: ProofBatch,
        p_mask_from_right_prover: Fp61BitPrime,
        q_mask_from_left_prover: Fp61BitPrime,
    ) -> Self
    where
        C: Context,
    {
        // send one batch left and receive one batch from the right
        let length = my_batch_left_shares.len();
        let ((), shares_of_batch_from_right_prover) = try_join(
            my_batch_left_shares.send_to_left(&ctx, record_id),
            ProofBatch::receive_from_right(&ctx, record_id, length),
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
        }
    }

    /// This function computes a tuple of vector of challenges from a `BatchToVerify`
    /// It outputs (`challenges_for_left_prover`, `challenges_for_right_prover`)
    ///
    /// ## Panics
    /// Panics when recursion factor constant cannot be converted to `u128`
    /// or when sending and receiving hashes over the network fails.
    pub async fn generate_challenges<C>(
        &self,
        ctx: C,
        record_id: RecordId,
    ) -> (Vec<Fp61BitPrime>, Vec<Fp61BitPrime>)
    where
        C: Context,
    {
        const LRF: usize = FirstProofGenerator::RECURSION_FACTOR;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;

        // exclude for first proof
        let exclude_large = u128::try_from(LRF).unwrap();
        // exclude for other proofs
        let exclude_small = u128::try_from(SRF).unwrap();

        // generate hashes
        let my_hashes_prover_left = ProofHashes::generate_hashes(self, Direction::Left);
        let my_hashes_prover_right = ProofHashes::generate_hashes(self, Direction::Right);

        // receive hashes from the other verifier
        let ((), (), other_hashes_prover_left, other_hashes_prover_right) = try_join4(
            my_hashes_prover_left.send_hashes(&ctx, record_id, Direction::Left),
            my_hashes_prover_right.send_hashes(&ctx, record_id, Direction::Right),
            ProofHashes::receive_hashes(
                &ctx,
                record_id,
                my_hashes_prover_left.hashes.len(),
                Direction::Left,
            ),
            ProofHashes::receive_hashes(
                &ctx,
                record_id,
                my_hashes_prover_right.hashes.len(),
                Direction::Right,
            ),
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

    /// This function computes and outputs `p_r_right_prover`, `q_r_left_prover`.
    pub fn compute_p_and_q_r<U, V>(
        &self,
        challenges_for_left_prover: &[Fp61BitPrime],
        challenges_for_right_prover: &[Fp61BitPrime],
        u_from_right_prover: U, // Prover P_i and verifier P_{i-1} both compute `u` and `p(x)`
        v_from_left_prover: V,  // Prover P_i and verifier P_{i+1} both compute `v` and `q(x)`
    ) -> (Fp61BitPrime, Fp61BitPrime)
    where
        U: Iterator<Item = Fp61BitPrime> + Send,
        V: Iterator<Item = Fp61BitPrime> + Send,
    {
        const LRF: usize = FirstProofGenerator::RECURSION_FACTOR;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;

        // compute p_r
        let p_r_right_prover = recursively_compute_final_check::<_, _, LRF, SRF>(
            u_from_right_prover.into_iter(),
            challenges_for_right_prover,
            self.p_mask_from_right_prover,
        );
        // compute q_r
        let q_r_left_prover = recursively_compute_final_check::<_, _, LRF, SRF>(
            v_from_left_prover.into_iter(),
            challenges_for_left_prover,
            self.q_mask_from_left_prover,
        );

        (p_r_right_prover, q_r_left_prover)
    }

    /// This function computes and outputs the final `p_r_right_prover * q_r_right_prover` value.
    async fn compute_p_times_q<C>(
        ctx: C,
        record_id: RecordId,
        p_r_right_prover: Fp61BitPrime,
        q_r_left_prover: Fp61BitPrime,
    ) -> Result<Fp61BitPrime, Error>
    where
        C: Context,
    {
        // send to the left
        let communication_ctx = ctx.set_total_records(TotalRecords::Indeterminate);

        let send_right =
            communication_ctx.send_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Right));
        let receive_left =
            communication_ctx.recv_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Left));

        let ((), q_r_right_prover) = try_join(
            send_right.send(record_id, q_r_left_prover),
            receive_left.receive(record_id),
        )
        .await?;

        Ok(p_r_right_prover * q_r_right_prover)
    }

    /// This function verifies a `BatchToVerify`.
    ///
    /// ## Errors
    /// Propagates network errors or when the proof fails to verify.
    ///
    /// ## Panics
    /// If the proof exceeds `MAX_PROOF_RECURSION`.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        sum_of_uv_right: Fp61BitPrime,
        p_r_right_prover: Fp61BitPrime,
        q_r_left_prover: Fp61BitPrime,
        challenges_for_left_prover: &[Fp61BitPrime],
        challenges_for_right_prover: &[Fp61BitPrime],
    ) -> Result<(), Error>
    where
        C: Context,
    {
        const LRF: usize = FirstProofGenerator::RECURSION_FACTOR;
        const SRF: usize = SmallProofGenerator::RECURSION_FACTOR;

        const LPL: usize = FirstProofGenerator::PROOF_LENGTH;
        const SPL: usize = SmallProofGenerator::PROOF_LENGTH;

        let p_times_q_right = Self::compute_p_times_q(
            ctx.narrow(&Step::PTimesQ),
            record_id,
            p_r_right_prover,
            q_r_left_prover,
        )
        .await?;

        // add Zero for p_times_q and sum since they are not secret shared
        let diff_left = compute_g_differences::<_, SPL, SRF, LPL, LRF>(
            &self.first_proof_from_left_prover,
            &self.proofs_from_left_prover,
            challenges_for_left_prover,
            Fp61BitPrime::ZERO,
            Fp61BitPrime::ZERO,
        );

        let diff_right = compute_g_differences::<_, SPL, SRF, LPL, LRF>(
            &self.first_proof_from_right_prover,
            &self.proofs_from_right_prover,
            challenges_for_right_prover,
            sum_of_uv_right,
            p_times_q_right,
        );

        // send diff_left to the right
        let length = diff_left.len();
        assert!(length <= MAX_PROOF_RECURSION + 1);

        let communication_ctx = ctx
            .narrow(&Step::Diff)
            .set_total_records(TotalRecords::Indeterminate);

        let send_data = array::from_fn(|i| *diff_left.get(i).unwrap_or(&Fp61BitPrime::ZERO));

        let ((), receive_data) = try_join(
            communication_ctx
                .send_channel::<ProofDiff>(ctx.role().peer(Direction::Right))
                .send(record_id, send_data),
            communication_ctx
                .recv_channel::<ProofDiff>(ctx.role().peer(Direction::Left))
                .receive(record_id),
        )
        .await?;
        let diff_right_from_other_verifier = receive_data[0..length].to_vec();

        // compare recombined dif to zero
        for i in 0..length {
            if diff_right[i] + diff_right_from_other_verifier[i] != Fp61BitPrime::ZERO {
                return Err(Error::DZKPValidationFailed);
            }
        }

        Ok(())
    }
}

struct ProofHashes {
    hashes: Vec<Hash>,
}

impl ProofHashes {
    // Generates hashes for proofs received from prover indicated by `direction`
    fn generate_hashes(batch_to_verify: &BatchToVerify, direction: Direction) -> Self {
        let (first_proof, other_proofs) = match direction {
            Direction::Left => (
                &batch_to_verify.first_proof_from_left_prover,
                &batch_to_verify.proofs_from_left_prover,
            ),
            Direction::Right => (
                &batch_to_verify.first_proof_from_right_prover,
                &batch_to_verify.proofs_from_right_prover,
            ),
        };

        Self {
            hashes: once(compute_hash(first_proof))
                .chain(other_proofs.iter().map(|proof| compute_hash(proof.iter())))
                .collect::<Vec<_>>(),
        }
    }

    /// Sends the one verifier's hashes to the other verifier
    /// `direction` indicates the direction of the prover.
    async fn send_hashes<C: Context>(
        &self,
        ctx: &C,
        record_id: RecordId,
        direction: Direction,
    ) -> Result<(), Error> {
        assert!(self.hashes.len() <= MAX_PROOF_RECURSION);
        let hashes_send =
            array::from_fn(|i| self.hashes.get(i).unwrap_or(&Hash::default()).clone());
        let verifier_direction = !direction;
        ctx.set_total_records(TotalRecords::Indeterminate)
            .send_channel::<[Hash; MAX_PROOF_RECURSION]>(ctx.role().peer(verifier_direction))
            .send(record_id, hashes_send)
            .await?;

        Ok(())
    }

    /// This function receives hashes from the other verifier
    /// `direction` indicates the direction of the prover.
    async fn receive_hashes<C: Context>(
        ctx: &C,
        record_id: RecordId,
        length: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        assert!(length <= MAX_PROOF_RECURSION);
        let verifier_direction = !direction;
        let hashes_received = ctx
            .set_total_records(TotalRecords::Indeterminate)
            .recv_channel::<[Hash; MAX_PROOF_RECURSION]>(ctx.role().peer(verifier_direction))
            .receive(record_id)
            .await?;
        Ok(Self {
            hashes: hashes_received[0..length].to_vec(),
        })
    }
}

const_assert_eq!(
    MAX_PROOF_RECURSION,
    9,
    "following impl valid only for MAX_PROOF_RECURSION = 9"
);

impl Serializable for [Hash; MAX_PROOF_RECURSION] {
    type Size = U288;

    type DeserializationError = <Hash as Serializable>::DeserializationError;

    fn serialize(&self, buf: &mut generic_array::GenericArray<u8, Self::Size>) {
        for (hash, buf) in zip(
            self,
            buf.chunks_mut(<<Hash as Serializable>::Size as Unsigned>::to_usize()),
        ) {
            hash.serialize(buf.try_into().unwrap());
        }
    }

    fn deserialize(
        buf: &generic_array::GenericArray<u8, Self::Size>,
    ) -> Result<Self, Self::DeserializationError> {
        Ok(buf
            .chunks(<<Hash as Serializable>::Size as Unsigned>::to_usize())
            .map(|buf| Hash::deserialize(buf.try_into().unwrap()).unwrap_infallible())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap())
    }
}

impl MpcMessage for [Hash; MAX_PROOF_RECURSION] {}

const_assert_eq!(
    MAX_PROOF_RECURSION,
    9,
    "following impl valid only for MAX_PROOF_RECURSION = 9"
);

type ProofDiff = [Fp61BitPrime; MAX_PROOF_RECURSION + 1];

impl Serializable for ProofDiff {
    type Size = U80;

    type DeserializationError = <Fp61BitPrime as Serializable>::DeserializationError;

    fn serialize(&self, buf: &mut generic_array::GenericArray<u8, Self::Size>) {
        for (hash, buf) in zip(
            self,
            buf.chunks_mut(<<Fp61BitPrime as Serializable>::Size as Unsigned>::to_usize()),
        ) {
            hash.serialize(buf.try_into().unwrap());
        }
    }

    fn deserialize(
        buf: &generic_array::GenericArray<u8, Self::Size>,
    ) -> Result<Self, Self::DeserializationError> {
        Ok(buf
            .chunks(<<Fp61BitPrime as Serializable>::Size as Unsigned>::to_usize())
            .map(|buf| Fp61BitPrime::deserialize(buf.try_into().unwrap()))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap())
    }
}

impl MpcMessage for ProofDiff {}

#[cfg(all(test, unit_test))]
pub mod test {
    use futures_util::future::try_join;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Fp61BitPrime, U128Conversions},
        helpers::Direction,
        protocol::{
            context::{
                dzkp_field::{UVTupleBlock, BLOCK_SIZE},
                Context,
            },
            ipa_prf::{
                malicious_security::{
                    lagrange::CanonicalLagrangeDenominator,
                    prover::{FirstProofGenerator, LargeProofGenerator, SmallProofGenerator},
                    verifier::{compute_sum_share, interpolate_at_r},
                },
                validation_protocol::{proof_generation::ProofBatch, validation::BatchToVerify},
            },
            prss::SharedRandomness,
            RecordId, RecordIdRange,
        },
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    /// ## Panics
    /// When proof is not generated correctly.
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
            FirstProofGenerator::PROOF_LENGTH
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
            let block_to_polynomial = BLOCK_SIZE / FirstProofGenerator::RECURSION_FACTOR;
            let simple_proof_uv = (0usize..100 * block_to_polynomial)
                .map(|i| {
                    (
                        (FirstProofGenerator::RECURSION_FACTOR * i
                            ..FirstProofGenerator::RECURSION_FACTOR * (i + 1))
                            .map(|j| Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h)
                            .collect::<[Fp61BitPrime; FirstProofGenerator::RECURSION_FACTOR]>(),
                        (FirstProofGenerator::RECURSION_FACTOR * i
                            ..FirstProofGenerator::RECURSION_FACTOR * (i + 1))
                            .map(|j| Fp61BitPrime::truncate_from(u128::try_from(j).unwrap()) * h)
                            .collect::<[Fp61BitPrime; FirstProofGenerator::RECURSION_FACTOR]>(),
                    )
                })
                .collect::<Vec<(
                    [Fp61BitPrime; FirstProofGenerator::RECURSION_FACTOR],
                    [Fp61BitPrime; FirstProofGenerator::RECURSION_FACTOR],
                )>>();

            simple_proof_uv.iter().fold(
                [Fp61BitPrime::ZERO; FirstProofGenerator::RECURSION_FACTOR],
                |mut acc, (left, right)| {
                    for i in 0..FirstProofGenerator::RECURSION_FACTOR {
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
                proof_computed[0..FirstProofGenerator::RECURSION_FACTOR].to_vec()
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
                        let (
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        ) = ProofBatch::generate(
                            &ctx.narrow("generate_batch"),
                            RecordIdRange::ALL,
                            uv_tuple_vec.into_iter(),
                        );

                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            RecordId::FIRST,
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        )
                        .await;

                        // generate and output challenges
                        batch_to_verify
                            .generate_challenges(ctx, RecordId::FIRST)
                            .await
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
    /// Prover `P_i` and verifier `P_{i+1}` both generate `u`
    /// Prover `P_i` and verifier `P_{i-1}` both generate `v`
    ///
    /// outputs `(my_u_and_v, u_from_right_prover, v_from_left_prover)`
    fn generate_u_v<C: Context>(
        ctx: &C,
        len: usize,
    ) -> (
        Vec<UVTupleBlock<Fp61BitPrime>>,
        Fp61BitPrime,
        Vec<Fp61BitPrime>,
        Vec<Fp61BitPrime>,
    ) {
        // outputs
        let mut vec_u_from_right_prover = Vec::<Fp61BitPrime>::with_capacity(BLOCK_SIZE * len);
        let mut vec_v_from_left_prover = Vec::<Fp61BitPrime>::with_capacity(BLOCK_SIZE * len);

        let mut vec_my_u_and_v =
            Vec::<([Fp61BitPrime; BLOCK_SIZE], [Fp61BitPrime; BLOCK_SIZE])>::with_capacity(len);
        let mut sum_of_uv = Fp61BitPrime::ZERO;

        // generate random u, v values using PRSS
        let mut counter = RecordId::FIRST;

        for _ in 0..len {
            let mut my_u_array = [Fp61BitPrime::ZERO; BLOCK_SIZE];
            let mut my_v_array = [Fp61BitPrime::ZERO; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                let (my_u, u_from_right_prover) = ctx.prss().generate_fields(counter);
                counter += 1;
                let (v_from_left_prover, my_v) = ctx.prss().generate_fields(counter);
                counter += 1;
                my_u_array[i] = my_u;
                my_v_array[i] = my_v;
                sum_of_uv += my_u * my_v;
                vec_u_from_right_prover.push(u_from_right_prover);
                vec_v_from_left_prover.push(v_from_left_prover);
            }
            vec_my_u_and_v.push((my_u_array, my_v_array));
        }

        (
            vec_my_u_and_v,
            sum_of_uv,
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
        const LEN: usize = 100;

        run(|| async move {
            let world = TestWorld::default();

            let [(h1_c_left, h1_c_right, h1_batch), (h2_c_left, h2_c_right, h2_batch), (h3_c_left, h3_c_right, h3_batch)] =
                world
                    .semi_honest((), |ctx, ()| async move {
                        // generate u, v values
                        let (vec_my_u_and_v, _, _, _) = generate_u_v(&ctx, LEN);

                        // generate and output VerifierBatch together with h value
                        let (
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        ) = ProofBatch::generate(
                            &ctx.narrow("generate_batch"),
                            RecordIdRange::ALL,
                            vec_my_u_and_v.into_iter(),
                        );

                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            RecordId::FIRST,
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        )
                        .await;

                        // generate challenges
                        let (challenges_for_left_prover, challenges_for_right_prover) =
                            batch_to_verify
                                .generate_challenges(ctx.narrow("generate_hash"), RecordId::FIRST)
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
        const LPL: usize = FirstProofGenerator::PROOF_LENGTH;

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
        const LEN: usize = 100;

        run(|| async move {
            let world = TestWorld::default();

            let [(pq_h1, h1_left, h1_right), (pq_h2, h2_left, h2_right), (pq_h3, h3_left, h3_right)] =
                world
                    .semi_honest((), |ctx, ()| async move {
                        // generate u, v values
                        let (vec_my_u_and_v, _, vec_u_from_right_prover, vec_v_from_left_prover) =
                            generate_u_v(&ctx, LEN);

                        // generate and output VerifierBatch together with h value
                        let (
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        ) = ProofBatch::generate(
                            &ctx.narrow("generate_batch"),
                            RecordIdRange::ALL,
                            vec_my_u_and_v.into_iter(),
                        );

                        let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                            ctx.narrow("generate_batch"),
                            RecordId::FIRST,
                            my_batch_left_shares,
                            shares_of_batch_from_left_prover,
                            p_mask_from_right_prover,
                            q_mask_from_left_prover,
                        )
                        .await;

                        // generate challenges
                        let (challenges_for_left_prover, challenges_for_right_prover) =
                            batch_to_verify
                                .generate_challenges(ctx.narrow("generate_hash"), RecordId::FIRST)
                                .await;

                        assert_eq!(
                            challenges_for_right_prover.len(),
                            batch_to_verify.proofs_from_right_prover.len() + 1
                        );

                        let (p, q) = batch_to_verify.compute_p_and_q_r(
                            &challenges_for_left_prover,
                            &challenges_for_right_prover,
                            vec_u_from_right_prover.into_iter(),
                            vec_v_from_left_prover.into_iter(),
                        );

                        let p_times_q =
                            BatchToVerify::compute_p_times_q(ctx, RecordId::FIRST, p, q)
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

    /// This test checks that a `BatchToVerify` verifies
    fn verify_batch(len: usize) {
        run(move || async move {
            let world = TestWorld::default();

            let _ = world
                .semi_honest((), |ctx, ()| async move {
                    // generate u, v values
                    let (
                        vec_my_u_and_v,
                        sum_of_uv,
                        vec_u_from_right_prover,
                        vec_v_from_left_prover,
                    ) = generate_u_v(&ctx, len);

                    // generate and output VerifierBatch together with h value
                    let (
                        my_batch_left_shares,
                        shares_of_batch_from_left_prover,
                        p_mask_from_right_prover,
                        q_mask_from_left_prover,
                    ) = ProofBatch::generate(
                        &ctx.narrow("generate_batch"),
                        RecordIdRange::ALL,
                        vec_my_u_and_v.into_iter(),
                    );

                    let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                        ctx.narrow("generate_batch"),
                        RecordId::FIRST,
                        my_batch_left_shares,
                        shares_of_batch_from_left_prover,
                        p_mask_from_right_prover,
                        q_mask_from_left_prover,
                    )
                    .await;

                    // context for verification
                    let v_ctx = ctx.narrow("verify");

                    // send sum to the left
                    // and receive from the right
                    let communication_ctx = ctx.set_total_records(1);

                    let send_channel = communication_ctx
                        .send_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Left));
                    let receive_channel = communication_ctx
                        .recv_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Right));

                    let ((), sum_of_uv_right) = try_join(
                        send_channel.send(RecordId::FIRST, sum_of_uv),
                        receive_channel.receive(RecordId::FIRST),
                    )
                    .await
                    .unwrap();

                    // generate challenges
                    let (challenges_for_left_prover, challenges_for_right_prover) = batch_to_verify
                        .generate_challenges(ctx.narrow("generate_hash"), RecordId::FIRST)
                        .await;

                    let (p, q) = batch_to_verify.compute_p_and_q_r(
                        &challenges_for_left_prover,
                        &challenges_for_right_prover,
                        vec_u_from_right_prover.into_iter(),
                        vec_v_from_left_prover.into_iter(),
                    );

                    batch_to_verify
                        .verify(
                            v_ctx,
                            RecordId::FIRST,
                            sum_of_uv_right,
                            p,
                            q,
                            &challenges_for_left_prover,
                            &challenges_for_right_prover,
                        )
                        .await
                        .unwrap();
                })
                .await;
        });
    }

    #[test]
    fn verify_batches() {
        verify_batch(100);

        // Test a batch that exercises the case where `uv_values.len() == 1` but `did_set_masks =
        // false` in `ProofBatch::generate`.
        verify_batch(
            LargeProofGenerator::RECURSION_FACTOR * SmallProofGenerator::RECURSION_FACTOR
                / BLOCK_SIZE,
        );
    }
}
