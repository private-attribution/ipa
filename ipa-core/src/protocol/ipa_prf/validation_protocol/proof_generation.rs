use futures_util::future::try_join;

use crate::{
    error::Error,
    ff::Fp61BitPrime,
    helpers::Direction,
    protocol::{
        context::{
            dzkp_field::{UVTupleBlock, BLOCK_SIZE},
            Context,
        },
        ipa_prf::malicious_security::{
            lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            prover::{LargeProofGenerator, SmallProofGenerator},
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
}

/// This a `ProofBatch` generated by a prover.
struct ProofBatch {
    first_proof: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    proofs: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
}

impl FromIterator<Fp61BitPrime> for ProofBatch {
    fn from_iter<T: IntoIterator<Item = Fp61BitPrime>>(iter: T) -> Self {
        let mut iterator = iter.into_iter();
        // consume the first P elements
        let first_proof = iterator
            .by_ref()
            .take(LargeProofGenerator::PROOF_LENGTH)
            .collect::<[Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH]>();
        // consume the rest
        let proofs = iterator.collect::<Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>>();
        ProofBatch {
            first_proof,
            proofs,
        }
    }
}

impl ProofBatch {
    /// This function returns the length in field elements.
    fn len(&self) -> usize {
        self.proofs.len() * SmallProofGenerator::PROOF_LENGTH + LargeProofGenerator::PROOF_LENGTH
    }

    /// This function returns an iterator over the field elements of all proofs.
    fn iter(&self) -> impl Iterator<Item = &Fp61BitPrime> {
        self.first_proof
            .iter()
            .chain(self.proofs.iter().flat_map(|x| x.iter()))
    }

    /// This function sends a `Proof` to the party on the left
    async fn send_to_left<C>(&self, ctx: &C) -> Result<(), Error>
    where
        C: Context,
    {
        // set up context for the communication over the network
        let communication_ctx = ctx.set_total_records(self.len());

        // set up channel
        let send_channel_left =
            &communication_ctx.send_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Left));

        // send to left
        // we send the proof batch via sending the individual field elements
        communication_ctx
            .parallel_join(
                self.iter().enumerate().map(|(i, x)| async move {
                    send_channel_left.send(RecordId::from(i), x).await
                }),
            )
            .await?;
        Ok(())
    }

    /// This function receives a `Proof` from the party on the right.
    async fn receive_from_right<C>(ctx: &C, length: usize) -> Result<Self, Error>
    where
        C: Context,
    {
        // set up context
        let communication_ctx = ctx.set_total_records(length);

        // set up channel
        let receive_channel_right =
            &communication_ctx.recv_channel::<Fp61BitPrime>(ctx.role().peer(Direction::Right));

        // receive from the right
        Ok(ctx
            .parallel_join(
                (0..length)
                    .map(|i| async move { receive_channel_right.receive(RecordId::from(i)).await }),
            )
            .await?
            .into_iter()
            .collect())
    }

    /// This is a helper function that allows to split a `UVTupleInputs`
    /// which consists of arrays of size `BLOCK_SIZE`
    /// into an iterator over arrays of size `LargeProofGenerator::RECURSION_FACTOR`.
    ///
    /// ## Panic
    /// Panics when `unwrap` panics, i.e. `try_from` fails to convert a slice to an array.
    fn polynomials_from_inputs<I>(
        inputs: I,
    ) -> impl Iterator<
        Item = (
            [Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR],
            [Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR],
        ),
    > + Clone
    where
        I: Iterator<Item = UVTupleBlock<Fp61BitPrime>> + Clone,
    {
        assert_eq!(BLOCK_SIZE % LargeProofGenerator::RECURSION_FACTOR, 0);
        inputs.flat_map(|(u_block, v_block)| {
            (0usize..(BLOCK_SIZE / LargeProofGenerator::RECURSION_FACTOR)).map(move |i| {
                (
                    <[Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR]>::try_from(
                        &u_block[i * LargeProofGenerator::RECURSION_FACTOR
                            ..(i + 1) * LargeProofGenerator::RECURSION_FACTOR],
                    )
                    .unwrap(),
                    <[Fp61BitPrime; LargeProofGenerator::RECURSION_FACTOR]>::try_from(
                        &v_block[i * LargeProofGenerator::RECURSION_FACTOR
                            ..(i + 1) * LargeProofGenerator::RECURSION_FACTOR],
                    )
                    .unwrap(),
                )
            })
        })
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        ff::{Fp61BitPrime, U128Conversions},
        protocol::{
            context::dzkp_field::BLOCK_SIZE,
            ipa_prf::{
                malicious_security::prover::{LargeProofGenerator, SmallProofGenerator},
                validation_protocol::proof_generation::BatchToVerify,
            },
        },
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    impl Default for Fp61BitPrime {
        fn default() -> Self {
            Fp61BitPrime::ZERO
        }
    }

    #[test]
    fn generate_verifier_batch() {
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
                    (
                        h,
                        BatchToVerify::generate_batch_to_verify(ctx, uv_tuple_vec.into_iter())
                            .await,
                    )
                })
                .await;

            // proof from first party
            simple_proof_check(result[0].0, &result[2].1, &result[1].1);

            // proof from second party
            simple_proof_check(result[1].0, &result[0].1, &result[2].1);

            // proof from third party
            simple_proof_check(result[2].0, &result[1].1, &result[0].1);
        });
    }

    fn simple_proof_check(
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
}
