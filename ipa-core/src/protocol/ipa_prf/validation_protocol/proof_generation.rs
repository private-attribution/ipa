use crate::{
    error::Error,
    ff::Fp61BitPrime,
    helpers::{Direction, TotalRecords},
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

/// This a `ProofBatch` generated by a prover.
pub struct ProofBatch {
    pub first_proof: [Fp61BitPrime; LargeProofGenerator::PROOF_LENGTH],
    pub proofs: Vec<[Fp61BitPrime; SmallProofGenerator::PROOF_LENGTH]>,
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
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.proofs.len() * SmallProofGenerator::PROOF_LENGTH + LargeProofGenerator::PROOF_LENGTH
    }

    /// This function returns an iterator over the field elements of all proofs.
    fn iter(&self) -> impl Iterator<Item = &Fp61BitPrime> {
        self.first_proof
            .iter()
            .chain(self.proofs.iter().flat_map(|x| x.iter()))
    }

    /// Each helper party generates a set of proofs, which are secret-shared.
    /// The "left" shares of these proofs are for the helper on the left.
    /// The "right" shares of these proofs need not be transmitted over the wire, as they
    /// are generated via `PRSS`, so the helper on the right can independently generate them.
    /// The final proof must be "masked" with random values drawn from PRSS.
    /// These values will be needed at verification time.
    /// The function outputs `my_proofs_left_shares`, `shares_of_proofs_from_prover_left`,
    /// `p_mask_from_right_prover`, `q_mask_from_left_prover`
    ///
    /// ## Panics
    /// Panics when the function fails to set the masks without overwritting `u` and `v` values.
    /// This only happens when there is an issue in the recursion.
    pub fn generate<C, I>(ctx: &C, uv_tuple_inputs: I) -> (Self, Self, Fp61BitPrime, Fp61BitPrime)
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
        let mut record_counter = RecordId::FIRST;

        // precomputation for first proof
        let first_denominator = CanonicalLagrangeDenominator::<Fp61BitPrime, LRF>::new();
        let first_lagrange_table = LagrangeTable::<Fp61BitPrime, LRF, LLL>::from(first_denominator);

        // generate first proof from input iterator
        let (mut uv_values, first_proof_from_left, my_first_proof_left_share) =
            LargeProofGenerator::gen_artefacts_from_recursive_step(
                ctx,
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
        // Prover `P_i` and verifier `P_{i-1}` both compute p(x)
        // therefore the "right" share computed by this verifier corresponds to that which
        // was used by the prover to the right.
        let (my_p_mask, p_mask_from_right_prover) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;
        // Prover `P_i` and verifier `P_{i+1}` both compute q(x)
        // therefore the "left" share computed by this verifier corresponds to that which
        // was used by the prover to the left.
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
                    ctx,
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
        (
            my_batch_left_shares,
            shares_of_batch_from_left_prover,
            p_mask_from_right_prover,
            q_mask_from_left_prover,
        )
    }

    /// This function sends a `Proof` to the party on the left
    ///
    /// ## Errors
    /// Propagates error from sending values over the network channel.
    pub async fn send_to_left<C>(&self, ctx: &C) -> Result<(), Error>
    where
        C: Context,
    {
        // set up context for the communication over the network
        let communication_ctx = ctx.set_total_records(TotalRecords::specified(self.len())?);

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
    ///
    /// ## Errors
    /// Propagates errors from receiving values over the network channel.
    pub async fn receive_from_right<C>(ctx: &C, length: usize) -> Result<Self, Error>
    where
        C: Context,
    {
        // set up context
        let communication_ctx = ctx.set_total_records(TotalRecords::specified(length)?);

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
    /// ## Panics
    /// Panics when `unwrap` panics, i.e. `try_from` fails to convert a slice to an array.
    pub fn polynomials_from_inputs<I>(
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
            context::{dzkp_field::BLOCK_SIZE, Context},
            ipa_prf::validation_protocol::{
                proof_generation::ProofBatch,
                validation::{test::simple_proof_check, BatchToVerify},
            },
        },
        secret_sharing::replicated::ReplicatedSecretSharing,
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

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
                    let (
                        my_batch_left_shares,
                        shares_of_batch_from_left_prover,
                        p_mask_from_right_prover,
                        q_mask_from_left_prover,
                    ) = ProofBatch::generate(
                        &ctx.narrow("generate_batch"),
                        uv_tuple_vec.into_iter(),
                    );

                    let batch_to_verify = BatchToVerify::generate_batch_to_verify(
                        ctx.narrow("generate_batch"),
                        my_batch_left_shares,
                        shares_of_batch_from_left_prover,
                        p_mask_from_right_prover,
                        q_mask_from_left_prover,
                    )
                    .await;

                    // generate and output VerifierBatch together with h value
                    (h, batch_to_verify)
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
}
