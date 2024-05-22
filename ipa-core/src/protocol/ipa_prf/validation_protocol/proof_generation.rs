use std::{borrow::Borrow, ops::Sub};

use futures_util::{stream, StreamExt};
use generic_array::{ArrayLength, GenericArray};
use typenum::{Unsigned, U1};

use crate::{
    ff::PrimeField,
    helpers::Direction,
    protocol::{
        context::{
            dzkp_field::{BlockSize, UVTupleBlock},
            Context,
        },
        ipa_prf::malicious_security::{
            lagrange::{CanonicalLagrangeDenominator, LagrangeTable},
            prover::{ProofArray, UVPolynomial, UVStore, ZeroKnowledgeProof},
        },
        prss::SharedRandomness,
        RecordId,
    },
    seq_join::seq_join,
};

/// This is a batch of `ZeroKnowledgeProofs` owned by a verifier.
/// It consists of a `ProofBatch` from the prover on the left
/// and a `ProofBatch` from the prover on the right.
///
/// It uses parameter `R` which is the recursion factor of the zero-knowledge proofs
/// A zero-knowledge proof with recursion factor `R` has length `2*R::USIZE-1`
///
/// The `VerifierBatch` also contains two masks `p_0` and `q_0` in `left_masks` stored as `(p_0,q_0)`
/// These masks are used as additional `u,v` values for the final proof
/// of the `left` batch of `ZeroKnowledgeProofs`.
/// On the `right` batch of `ZeroKnowledgeProofs` these values are set to `F::ZERO`.
/// These masks mask sensitive information when the right verifier sends a field value to the left verifier,
/// i.e. using a channel with `Direction:Right`, who does not have access to these masks.
#[derive(Debug)]
pub struct VerifierBatch<F, R>
where
    F: PrimeField,
    ZeroKnowledgeProof<F, R>: ProofArray,
{
    left: Vec<ZeroKnowledgeProof<F, R>>,
    right: Vec<ZeroKnowledgeProof<F, R>>,
    left_masks: (F, F),
}

impl<F, R> VerifierBatch<F, R>
where
    F: PrimeField + Default,
    ZeroKnowledgeProof<F, R>: ProofArray,
{
    /// This function generates a `ProofBatch` where this helper is the prover. It then distributes
    /// shares of the `ProofBatch` to the helper on the left. The shares for the helper on the right
    /// are generated using `PRSS`. Further, this helper
    /// receives a `ProofBatch` from the right helper, i.e. `verifier_right_batch`,
    /// and generates a `ProofBatch` using `PRSS`, i.e. `verifier_left_batch`.
    pub async fn generate_and_distribute_proofs<C, I>(ctx: C, uv_tuple_block: I) -> Self
    where
        C: Context,
        I: Iterator<Item = UVTupleBlock<F>> + Clone,
        R: ArrayLength + Sub<U1>,
        <R as Sub<U1>>::Output: ArrayLength,
    {
        // generate ProofBatch
        let (prover_left_batch, verifier_left_batch, (p, q)) =
            ProofBatch::<F, R>::compute_proof_batch(&ctx, uv_tuple_block);

        // send left_prover_batch and receive right_verifier_batch
        let verifier_right_batch = prover_left_batch.send_and_receive(ctx).await;

        // output
        VerifierBatch {
            left: verifier_left_batch.proofs,
            right: verifier_right_batch.proofs,
            left_masks: (p, q),
        }
    }
}

/// This is a batch of `ZeroKnowledgeProofs` owned by a prover.
///
/// It uses parameter `R` which is the recursion factor of the zero-knowledge proofs
/// A zero-knowledge proof with recursion factor `R` has length `2*R::USIZE-1`
struct ProofBatch<F, R>
where
    F: PrimeField,
    ZeroKnowledgeProof<F, R>: ProofArray,
{
    proofs: Vec<ZeroKnowledgeProof<F, R>>,
}

impl<F, R> ProofBatch<F, R>
where
    F: PrimeField + Default,
    ZeroKnowledgeProof<F, R>: ProofArray,
{
    fn len(&self) -> usize {
        self.proofs.len() * <ZeroKnowledgeProof<F, R> as ProofArray>::Length::USIZE
    }

    fn new() -> Self {
        ProofBatch { proofs: Vec::new() }
    }

    /// This function sends a `ProofBatch` to the party on the left
    /// and receives a `ProofBatch` from the party on the right.
    ///
    /// It sets `total_records` in the input context to the `ProofBatch` length,
    /// i.e. it expects to receive a `ProofBatch` of the same length as being sent.
    async fn send_and_receive<C>(&self, ctx: C) -> Self
    where
        C: Context,
    {
        // set up context
        let ctx_left = ctx.set_total_records(self.len());

        // set up channels
        let send_channel_left = &ctx_left.send_channel::<F>(ctx.role().peer(Direction::Left));
        let receive_channel_right = &ctx_left.recv_channel::<F>(ctx.role().peer(Direction::Right));

        // prepare variable for received messages
        let mut receive_right = ProofBatch::new();

        // send to left, receive on the right
        // we send the proof batch via sending the individual field elements
        seq_join(
            ctx_left.active_work(),
            stream::iter(self.proofs.iter().flat_map(|x| x.g.iter()).enumerate().map(
                |(i, &x)| async move {
                    send_channel_left.send(RecordId::from(i), x).await.unwrap();
                    receive_channel_right
                        .receive(RecordId::from(i))
                        .await
                        .unwrap()
                },
            )),
        )
        //.collect::<Vec<GenericArray<F, N>>>()
        .collect::<Vec<F>>()
        .await
        .chunks(<ZeroKnowledgeProof<F, R> as ProofArray>::Length::USIZE)
        .for_each(|x| {
            receive_right.proofs.push(ZeroKnowledgeProof {
                g: GenericArray::<F, <ZeroKnowledgeProof<F, R> as ProofArray>::Length>::from_slice(
                    x,
                )
                .clone(),
            });
        });

        // output
        receive_right
    }

    /// This function generates a batch of quadratic proofs
    /// it iteratively generates `ZeroKnowledgeProofs` and collects them in a batch
    ///
    /// It generates `prover_left_batch` as its left output
    /// and `verifier_left_batch` as its right output.
    /// Further, it outputs the generated masks included in the last proof of the batch.
    ///
    /// `PRSS` is invoked since `PRSS` right is used to generate `prover_left_batch`.
    /// Since `PRSS` cannot be invoked later again on the same `Gate` and `Index`,
    /// we use `PRSS` left to generate `verifier_left_batch` and output it as well.
    ///
    /// Outputs `(prover_left_batch, verifier_left_batch, (p_mask, q_mask))`
    ///
    /// ## Panics
    /// Panics when there is an issue with the implementation of this function
    /// and masks cannot be set safely (which should not happen).
    fn compute_proof_batch<C, I>(ctx: &C, uv_tuple_block: I) -> (Self, Self, (F, F))
    where
        C: Context,
        I: Iterator<Item = UVTupleBlock<F>> + Clone,
        R: ArrayLength + Sub<U1>,
        <R as Sub<U1>>::Output: ArrayLength,
    {
        let mut prover_left_batch = Vec::<ZeroKnowledgeProof<F, R>>::new();
        let mut verifier_left_batch = Vec::<ZeroKnowledgeProof<F, R>>::new();

        // precomputation
        // N is the proof length,
        // i.e. polynomial of degree 2*R-1
        // where R is the recursion factor
        // the denominator takes as parameter R
        let denominator = CanonicalLagrangeDenominator::<F, R>::new();
        // the lagrange table takes as parameter R, and R-1
        let lagrange_table = LagrangeTable::<F, R, <R as Sub<U1>>::Output>::from(denominator);

        // set up record counter
        let mut record_counter = RecordId::from(0);

        // generate first proof from input
        let mut uv_store = Self::compute_next_proof(
            &mut prover_left_batch,
            &mut verifier_left_batch,
            &mut record_counter,
            ctx,
            &lagrange_table,
            Self::polynomials_from_blocks::<R, _>(uv_tuple_block),
        );

        // recursively generate proofs
        // until there are less than `R::USIZE * (R::USIZE-1)` many (u,v) field elements
        // and then do one more iteration
        // This ensures that after the last iteration,
        // there are at most R::USIZE-1 many real (u,v) field elements
        // Therefore at least the last field element is a `F:ZERO` filler that can be replaced
        // Therefore we have space to include the masks during the final proof
        //
        // notice that uv_store.len() will always be at least 1
        // further, polynomial uv_store.uv[0].0 and .1 will always have
        // R::USIZE many points since they are filled with `F::ZERO`.
        assert!(R::USIZE > 1usize);
        let two_r_minus_one = R::USIZE * (R::USIZE - 1);
        uv_store = loop {
            let stop = uv_store.len() < two_r_minus_one;

            // generate next proof
            uv_store = Self::compute_next_proof(
                &mut prover_left_batch,
                &mut verifier_left_batch,
                &mut record_counter,
                ctx,
                &lagrange_table,
                uv_store.iter(),
            );

            if stop {
                break uv_store;
            }
        };

        // generate masks
        // The right masks are used during the proof generation.
        // The left masks are later used during the verification.
        //
        // Notice that this helper party's left masks are the helper party on the left's right masks
        // which it uses for its proof generation
        // Therefore, when this helper party plays the role of a verifier
        // (for the proof from the party on the left)
        // it will need to use the masks.
        let (left_p_mask, right_p_mask): (F, F) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;
        let (left_q_mask, right_q_mask): (F, F) = ctx.prss().generate_fields(record_counter);
        record_counter += 1;

        // set masks & panic when setting masks is unsafe
        // which only happens when there are issues with the implementation
        // (i.e. input independent panic)
        uv_store.set_masks(right_p_mask, right_q_mask).unwrap();

        // generate last proof
        _ = Self::compute_next_proof(
            &mut prover_left_batch,
            &mut verifier_left_batch,
            &mut record_counter,
            ctx,
            &lagrange_table,
            uv_store.iter(),
        );

        // output proofs
        // as well as the left masks
        // which are later needed during the verification
        (
            ProofBatch {
                proofs: prover_left_batch,
            },
            ProofBatch {
                proofs: verifier_left_batch,
            },
            (left_p_mask, left_q_mask),
        )
    }

    /// This function is a helper function that computes the next proof from an iterator
    /// It also computes the next `UVStore`
    /// that can be used for the `compute_next_proof` call that follows this call.
    fn compute_next_proof<C, J, B>(
        prover_left_batch: &mut Vec<ZeroKnowledgeProof<F, R>>,
        verifier_left_batch: &mut Vec<ZeroKnowledgeProof<F, R>>,
        record_counter: &mut RecordId,
        ctx: &C,
        lagrange_table: &LagrangeTable<F, R, <R as Sub<U1>>::Output>,
        uv: J,
    ) -> UVStore<F, R>
    where
        C: Context,
        R: ArrayLength + Sub<U1>,
        <R as Sub<U1>>::Output: ArrayLength,
        J: Iterator<Item = B> + Clone,
        B: Borrow<UVPolynomial<F, R>>,
    {
        // generate next proof
        // from iterator
        let mut prover_left_proof =
            ZeroKnowledgeProof::<F, R>::compute_proof(uv.clone(), lagrange_table);

        // generate proof shares
        let (verifier_left_proof, prover_right_proof) =
            Self::share_via_prss(&mut prover_left_proof, ctx, record_counter);

        // compute next uv values
        // from iterator
        let uv_store =
            UVStore::<F, R>::gen_challenge_and_recurse(&prover_left_proof, &prover_right_proof, uv);

        // store proofs
        prover_left_batch.push(prover_left_proof);
        verifier_left_batch.push(verifier_left_proof);

        //output UVStore
        uv_store
    }

    /// This is a helper function that allows to split a `UVTupleBlock`
    /// into `UVPolynomials` of the correct size.
    fn polynomials_from_blocks<M, I>(blocks: I) -> impl Iterator<Item = UVPolynomial<F, M>> + Clone
    where
        I: Iterator<Item = UVTupleBlock<F>> + Clone,
        M: ArrayLength,
    {
        assert_eq!(BlockSize::USIZE % M::USIZE, 0);
        blocks.flat_map(|x| {
            (0usize..(BlockSize::USIZE / M::USIZE)).map(move |i| {
                (
                    GenericArray::<F, M>::from_slice(&x.0[i * M::USIZE..(i + 1) * M::USIZE])
                        .clone(),
                    GenericArray::<F, M>::from_slice(&x.1[i * M::USIZE..(i + 1) * M::USIZE])
                        .clone(),
                )
            })
        })
    }

    /// This function is a helper function that secret shares a `ZeroKnowledgeProof` using `PRSS`.
    ///
    /// It takes as input the prover's proof and a context where the latter allows us to use `PRSS`.
    /// `record_counter` is used to generate the `RecordId` input for `PRSS`
    ///
    /// The goal of this function is to generate three proof shares.
    /// First, it replaces the input proof with the left share of the proof
    /// for which this helper party is the prover, i.e. `prover_left_proof`.
    /// Second, it outputs the other share, i.e. `prover_right_proof`.
    /// Third, the `PRSS` is also used to generate the left share of the proof for which this helper party
    /// is the verifier, i.e. `verifier_left_proof`. This share is part of the output.
    ///
    /// Outputs `(verifier_left_proof, prover_right_proof)`
    fn share_via_prss<C>(
        prover_left_proof: &mut ZeroKnowledgeProof<F, R>,
        ctx: &C,
        record_counter: &mut RecordId,
    ) -> (ZeroKnowledgeProof<F, R>, ZeroKnowledgeProof<F, R>)
    where
        C: Context,
    {
        // variables for outputs
        let mut prover_right_proof = <ZeroKnowledgeProof<F, R>>::default();
        let mut verifier_left_proof = <ZeroKnowledgeProof<F, R>>::default();

        // use PRSS
        for i in 0..<ZeroKnowledgeProof<F, R> as ProofArray>::Length::USIZE {
            let (left, right) = ctx.prss().generate_fields::<F, RecordId>(*record_counter);

            *record_counter += 1;

            // mask proof such that party on the left does not know mask
            // i.e. use PRSS right
            // subtract the shares from `prover_left_proof`
            // such that `right` cancels out with `prover_right_proof`
            // which is set to `right` below
            prover_left_proof.g[i] -= right;

            // set prover_right_proof
            // such that party on the right can compute it himself
            // i.e. use PRSS right
            prover_right_proof.g[i] = right;

            // set verifier_left
            // by using prss left
            // which has been used by the prover on the right to generate `prover_right_proof`
            verifier_left_proof.g[i] = left;
        }

        //output
        (verifier_left_proof, prover_right_proof)
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use rand::{thread_rng, Rng};
    use typenum::{Unsigned, U8};

    use crate::{
        ff::{Fp61BitPrime, U128Conversions},
        protocol::{
            context::dzkp_field::BlockSize,
            ipa_prf::{
                malicious_security::prover::{ProofArray, ZeroKnowledgeProof},
                validation_protocol::proof_generation::VerifierBatch,
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
                                GenericArray::<Fp61BitPrime, BlockSize>::generate(|j| {
                                    Fp61BitPrime::truncate_from(
                                        u128::try_from(BlockSize::USIZE * i + j).unwrap(),
                                    ) * h
                                }),
                                GenericArray::<Fp61BitPrime, BlockSize>::generate(|j| {
                                    Fp61BitPrime::truncate_from(
                                        u128::try_from(BlockSize::USIZE * i + j).unwrap(),
                                    ) * h
                                }),
                            )
                        })
                        .collect::<Vec<_>>();

                    // generate and output VerifierBatch together with h value
                    (
                        h,
                        VerifierBatch::<Fp61BitPrime, U8>::generate_and_distribute_proofs(
                            ctx,
                            uv_tuple_vec.into_iter(),
                        )
                        .await,
                    )
                })
                .await;

            // proof from first party
            simple_proof_check::<U8>(result[0].0, &result[2].1, &result[1].1);

            // proof from second party
            simple_proof_check::<U8>(result[1].0, &result[0].1, &result[2].1);

            // proof from third party
            simple_proof_check::<U8>(result[2].0, &result[1].1, &result[0].1);
        });
    }

    fn simple_proof_check<R>(
        h: Fp61BitPrime,
        left_verifier: &VerifierBatch<Fp61BitPrime, R>,
        right_verifier: &VerifierBatch<Fp61BitPrime, R>,
    ) where
        R: ArrayLength,
        ZeroKnowledgeProof<Fp61BitPrime, R>: ProofArray,
    {
        // check lengths
        // i.e. each proof has length 2*R::SIZE -1
        for i in 0..left_verifier.right.len() {
            assert_eq!((i, left_verifier.right[i].g.len()), (i, 2 * R::USIZE - 1));
        }

        // check that masks are not 0
        assert_ne!(
            right_verifier.left_masks,
            (Fp61BitPrime::ZERO, Fp61BitPrime::ZERO)
        );

        // check first proof,
        // compute simple proof without lagrange interpolated points
        let block_to_polynomial = BlockSize::USIZE / R::USIZE;
        let simple_proof_uv = (0usize..100 * block_to_polynomial)
            .map(|i| {
                (
                    GenericArray::<Fp61BitPrime, R>::generate(|j| {
                        Fp61BitPrime::truncate_from(u128::try_from(R::USIZE * i + j).unwrap()) * h
                    }),
                    GenericArray::<Fp61BitPrime, R>::generate(|j| {
                        Fp61BitPrime::truncate_from(u128::try_from(R::USIZE * i + j).unwrap()) * h
                    }),
                )
            })
            .collect::<Vec<(GenericArray<Fp61BitPrime, R>, GenericArray<Fp61BitPrime, R>)>>();

        let simple_proof = simple_proof_uv.iter().fold(
            GenericArray::<Fp61BitPrime, R>::default(),
            |mut acc, (left, right)| {
                for i in 0..R::USIZE {
                    acc[i] += left[i] * right[i];
                }
                acc
            },
        );

        // reconstruct computed proof
        // by adding shares left and right
        let proof_computed = left_verifier.right[0]
            .g
            .iter()
            .zip(right_verifier.left[0].g.iter())
            .map(|(&left, &right)| left + right)
            .collect::<Vec<Fp61BitPrime>>();

        // check for consistency
        // only check first R::USIZE field elements
        assert_eq!(
            (h.as_u128(), simple_proof.to_vec()),
            (h.as_u128(), proof_computed[0..R::USIZE].to_vec())
        );
    }
}
