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
/// The `VerifierBatch` also contains two masks `p_0` and `q_0` in `masks` stored as `(p_0,q_0)`
/// These masks are used as additional `u,v` values for the final proof
/// of the `left` batch of `ZeroKnowledgeProofs`.
/// On the `right` batch of `ZeroKnowledgeProofs` these values are set to `F::ZERO`.
/// These masks mask sensitive information when the right verifier sends a field value to the left verifier,
/// i.e. using a channel with `Direction:Right`, who does not have access to these masks.
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
pub struct ProofBatch<F, R>
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
    fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

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
    /// `PRSS` is invoked since `PRSS` left is used to generate `prover_left_batch`.
    /// Since it cannot be invoked later again on the same `Gate` and `Index`,
    /// we use `PRSS` right to generate `verifier_left_batch` and output it as well.
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
        // i.e. polynomial of degree 2*λ-1
        // where λ is the recursion factor
        // the denominator takes as parameter λ = (N+1)/2
        let denominator = CanonicalLagrangeDenominator::<F, R>::new();
        // the lagrange table takes as parameter λ, and λ-1
        // i.e. (N+1)/2 and (N+1)/2-1
        let lagrange_table = LagrangeTable::<F, R, <R as Sub<U1>>::Output>::from(denominator);

        // set up record counter
        let mut record_counter = 0usize;

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
        // until there are less than `R::USIZE` many (u,v) field elements
        // and then do one more iteration
        //
        // notice that uv_store.len() will always be at least 1
        // further, polynomial uv_store.uv[0].0 and .1 will always have
        // R::USIZE many points since they are filled with `F::ZERO`.
        loop {
            let stop = uv_store.len() < R::USIZE;

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
                break;
            }
        }

        // generate masks
        // the right mask are used during the proof generation
        // and the verifier on the right generate the same masks
        // as his left_mask which are then used during the verification
        // this prover stores its left masks
        // which he uses once he plays the role of the verifier to the left
        let (left_p_mask, right_p_mask): (F, F) =
            ctx.prss().generate_fields(RecordId::from(record_counter));
        record_counter += 1;
        let (left_q_mask, right_q_mask): (F, F) =
            ctx.prss().generate_fields(RecordId::from(record_counter));
        record_counter += 1;

        // set masks
        uv_store.set_masks(right_p_mask, right_q_mask);

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
        record_counter: &mut usize,
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
        let mut proof = ZeroKnowledgeProof::<F, R>::compute_proof(uv.clone(), &lagrange_table);

        // generate proof shares
        let (prover_left_proof, verifier_left_proof) =
            Self::share_via_prss(&mut proof, ctx, record_counter);

        // compute next uv values
        // from iterator
        let uv_store = UVStore::<F, R>::gen_challenge_and_recurse(&prover_left_proof, &proof, uv);

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
                    GenericArray::<F, M>::from_slice(
                        &x.0[i * (BlockSize::USIZE / M::USIZE)
                            ..i * (BlockSize::USIZE / M::USIZE) + M::USIZE],
                    )
                    .clone(),
                    GenericArray::<F, M>::from_slice(
                        &x.1[i * (BlockSize::USIZE / M::USIZE)
                            ..i * (BlockSize::USIZE / M::USIZE) + M::USIZE],
                    )
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
    /// First, it replaces the input `proof` with the right share of the proof
    /// for which this helper party is the prover, i.e. `prover_right_proof`.
    /// Second, it outputs the other share, i.e. `prover_left_proof`.
    /// Third, the `PRSS` is also used to generate the right share of the proof for which this helper party
    /// is the verifier, i.e. `verifier_right_proof`. This share is part of the output.
    fn share_via_prss<C>(
        proof: &mut ZeroKnowledgeProof<F, R>,
        ctx: &C,
        record_counter: &mut usize,
    ) -> (ZeroKnowledgeProof<F, R>, ZeroKnowledgeProof<F, R>)
    where
        C: Context,
    {
        // variables for outputs
        let mut prover_left_proof = <ZeroKnowledgeProof<F, R>>::default();
        let mut verifier_right_proof = <ZeroKnowledgeProof<F, R>>::default();

        // use PRSS
        for i in 0..<ZeroKnowledgeProof<F, R> as ProofArray>::Length::USIZE {
            let (left, right) = ctx
                .prss()
                .generate_fields::<F, RecordId>(RecordId::from(i + *record_counter));

            // mask proof such that party on the right does not know mask
            // i.e. use PRSS left
            proof.g[i] += left;

            // set prover_left_proof
            // such that party on the left can compute it himself
            // i.e. use PRSS left
            prover_left_proof.g[i] = left;

            // set verifier_right
            // by using prss right
            // which has been used by the prover on the right to generate `prover_left_proof`
            verifier_right_proof.g[i] = right;
        }

        // update record_counter
        *record_counter += <ZeroKnowledgeProof<F, R> as ProofArray>::Length::USIZE;

        //output
        (prover_left_proof, verifier_right_proof)
    }
}
