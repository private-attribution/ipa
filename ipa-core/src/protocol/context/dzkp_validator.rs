use std::{collections::BTreeMap, fmt::Debug, future::ready};

use async_trait::async_trait;
use bitvec::prelude::{BitArray, BitSlice, Lsb0};
use futures::{stream, Future, FutureExt, Stream, StreamExt};
use ipa_step::StepNarrow;

use crate::{
    error::{BoxError, Error},
    ff::{Fp61BitPrime, U128Conversions},
    helpers::TotalRecords,
    protocol::{
        context::{
            batcher::Batcher,
            dzkp_field::{DZKPBaseField, UVTupleBlock},
            dzkp_malicious::DZKPUpgraded as MaliciousDZKPUpgraded,
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded,
            step::DzkpValidationProtocolStep as Step,
            Base, Context, DZKPContext, MaliciousContext, MaliciousProtocolSteps,
        },
        ipa_prf::{
            validation_protocol::{proof_generation::ProofBatch, validation::BatchToVerify},
            LargeProofGenerator, SmallProofGenerator,
        },
        Gate, RecordId, RecordIdRange,
    },
    seq_join::{seq_join, SeqJoin},
    sharding::ShardBinding,
    sync::{Arc, Mutex},
};

pub type Array256Bit = BitArray<[u8; 32], Lsb0>;

type BitSliceType = BitSlice<u8, Lsb0>;

const BIT_ARRAY_LEN: usize = 256;
const BIT_ARRAY_MASK: usize = BIT_ARRAY_LEN - 1;
const BIT_ARRAY_SHIFT: usize = BIT_ARRAY_LEN.ilog2() as usize;

// The target size of a zero-knowledge proof, in GF(2) multiplies.  Seven intermediate
// values are stored for each multiply, so the amount memory required is 7 times this
// value.
//
// To enable computing a read size for `OrdereringSender` that achieves good network
// utilization, the number of records in a proof must be a power of two. Protocols
// typically compute the size of a proof batch by dividing TARGET_PROOF_SIZE by
// an approximate number of multiplies per record, and then rounding up to a power
// of two. Thus, it is not necessary for TARGET_PROOF_SIZE to be a power of two.
//
// A smaller value is used for tests, to enable covering some corner cases with a
// reasonable runtime. Some of these tests use TARGET_PROOF_SIZE directly, so for tests
// it does need to be a power of two.
#[cfg(test)]
pub const TARGET_PROOF_SIZE: usize = 8192;
#[cfg(not(test))]
pub const TARGET_PROOF_SIZE: usize = 50_000_000;

/// Maximum proof recursion depth.
//
// This is a hard limit. Each GF(2) multiply generates four G values and four H values,
// so the restriction is:
// $$ large_recursion_factor * small_recursion_factor ^ (depth - 1) >= 4 * target_proof_size $$
// With large_recursion_factor = 32 and small_recursion_factor = 8, this means:
// $$ depth >= log_8 target_proof_size $$
// Because multiplication intermediate storage gets rounded up to blocks of 256, leaving
// some margin is advised.
pub const MAX_PROOF_RECURSION: usize = 9;

/// `MultiplicationInputsBlock` is a block of fixed size of intermediate values
/// that occur duringa multiplication.
/// These values need to be verified since there might have been malicious behavior.
/// For a multiplication, let `(x1, x2), (x2, x3), (x3,x1)`, `(y1, y2), (y2, y3), (y3,y1)` be the shares of `x` and `y`
/// and let the goal of the multiplication be to compute `x*y`.
/// `(pi, p(i+1)` is the randomness from `PRSS` used for the multiplication by helper `i`.
/// `z(i+1)` is the result of the multiplication received from the helper on the right.
/// We do not need to store `zi` since it can be computed from the other stored values.
#[derive(Clone, Debug)]
struct MultiplicationInputsBlock {
    x_left: Array256Bit,
    x_right: Array256Bit,
    y_left: Array256Bit,
    y_right: Array256Bit,
    prss_left: Array256Bit,
    prss_right: Array256Bit,
    z_right: Array256Bit,
}

impl Default for MultiplicationInputsBlock {
    fn default() -> Self {
        MultiplicationInputsBlock {
            x_left: BitArray::ZERO,
            x_right: BitArray::ZERO,
            y_left: BitArray::ZERO,
            y_right: BitArray::ZERO,
            prss_left: BitArray::ZERO,
            prss_right: BitArray::ZERO,
            z_right: BitArray::ZERO,
        }
    }
}

impl MultiplicationInputsBlock {
    /// set using bitslices
    /// ## Errors
    /// Errors when length of slices is not 256 bit
    fn clone_from(
        x_left: &BitSliceType,
        x_right: &BitSliceType,
        y_left: &BitSliceType,
        y_right: &BitSliceType,
        prss_left: &BitSliceType,
        prss_right: &BitSliceType,
        z_right: &BitSliceType,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            x_left: BitArray::try_from(x_left)?,
            x_right: BitArray::try_from(x_right)?,
            y_left: BitArray::try_from(y_left)?,
            y_right: BitArray::try_from(y_right)?,
            prss_left: BitArray::try_from(prss_left)?,
            prss_right: BitArray::try_from(prss_right)?,
            z_right: BitArray::try_from(z_right)?,
        })
    }

    /// set using bitslices
    /// ## Errors
    /// Errors when length of slices is not 256 bit
    #[allow(clippy::too_many_arguments)]
    fn set(
        &mut self,
        x_left: &BitSliceType,
        x_right: &BitSliceType,
        y_left: &BitSliceType,
        y_right: &BitSliceType,
        prss_left: &BitSliceType,
        prss_right: &BitSliceType,
        z_right: &BitSliceType,
    ) -> Result<(), BoxError> {
        self.x_left = BitArray::try_from(x_left)?;
        self.x_right = BitArray::try_from(x_right)?;
        self.y_left = BitArray::try_from(y_left)?;
        self.y_right = BitArray::try_from(y_right)?;
        self.prss_left = BitArray::try_from(prss_left)?;
        self.prss_right = BitArray::try_from(prss_right)?;
        self.z_right = BitArray::try_from(z_right)?;

        Ok(())
    }

    /// `Convert` allows to convert `MultiplicationInputs` into a format compatible with DZKPs
    /// This is the convert function called by the prover.
    fn convert_prover<DF: DZKPBaseField>(&self) -> Vec<UVTupleBlock<DF>> {
        DF::convert_prover(
            &self.x_left,
            &self.x_right,
            &self.y_left,
            &self.y_right,
            &self.prss_right,
        )
    }

    /// `convert_values_from_right_prover` allows to convert `MultiplicationInputs` into a format compatible with DZKPs
    /// This is the convert function called by the verifier on the left.
    fn convert_values_from_right_prover<DF: DZKPBaseField>(&self) -> Vec<DF> {
        DF::convert_value_from_right_prover(
            &self.x_right,
            &self.y_right,
            &self.prss_right,
            &self.z_right,
        )
    }

    /// `convert_values_from_left_prover` allows to convert `MultiplicationInputs` into a format compatible with DZKPs
    /// This is the convert function called by the verifier on the right.
    fn convert_values_from_left_prover<DF: DZKPBaseField>(&self) -> Vec<DF> {
        DF::convert_value_from_left_prover(&self.x_left, &self.y_left, &self.prss_left)
    }
}

/// `Segment` is a variable size set or subset of `MultiplicationInputs` using a `BitSlice`
/// For efficiency reasons we constrain the segments size in bits to be a divisor of 256
/// when less than 256 or a multiple of 256 when more than 256.
/// Therefore, segments eventually need to be filled with `0` to be a multiple of 256
#[derive(Clone, Debug)]
pub struct Segment<'a> {
    x_left: SegmentEntry<'a>,
    x_right: SegmentEntry<'a>,
    y_left: SegmentEntry<'a>,
    y_right: SegmentEntry<'a>,
    prss_left: SegmentEntry<'a>,
    prss_right: SegmentEntry<'a>,
    z_right: SegmentEntry<'a>,
}

impl<'a> Segment<'a> {
    #[must_use]
    pub fn from_entries(
        x_left: SegmentEntry<'a>,
        x_right: SegmentEntry<'a>,
        y_left: SegmentEntry<'a>,
        y_right: SegmentEntry<'a>,
        prss_left: SegmentEntry<'a>,
        prss_right: SegmentEntry<'a>,
        z_right: SegmentEntry<'a>,
    ) -> Self {
        // check for consistent length
        // using debug assert for efficiency
        // debug assert is sufficient since len only depends on the implementation,
        // i.e. choice of vectorization dimension and Boolean Array type,
        // user inputs are not a concern as long as it works for all vectorization options
        debug_assert_eq!(x_left.len(), x_right.len());
        debug_assert_eq!(x_left.len(), y_left.len());
        debug_assert_eq!(x_left.len(), y_right.len());
        debug_assert_eq!(x_left.len(), prss_left.len());
        debug_assert_eq!(x_left.len(), prss_right.len());
        debug_assert_eq!(x_left.len(), z_right.len());
        // check that length is either smaller or a multiple of 256
        debug_assert!(
            x_left.len() <= 256 || x_left.len() % 256 == 0,
            "length {} needs to be smaller or a multiple of 256",
            x_left.len()
        );
        // asserts passed, create struct
        Self {
            x_left,
            x_right,
            y_left,
            y_right,
            prss_left,
            prss_right,
            z_right,
        }
    }

    /// This function returns the length of the segment in bits. More specifically it returns the length of
    /// the first entry, i.e. `x_left` which is consistent with the length of all other entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.x_left.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.x_left.is_empty()
    }
}

/// `SegmentEntry` is a simple wrapper to represent one entry of a `Segment`
/// currently, we only support `BitSlices`
#[derive(Clone, Debug)]
pub struct SegmentEntry<'a>(&'a BitSliceType);

impl<'a> SegmentEntry<'a> {
    #[must_use]
    pub fn from_bitslice(entry: &'a BitSliceType) -> Self {
        SegmentEntry(entry)
    }

    #[must_use]
    pub fn as_bitslice(&self) -> &'a BitSliceType {
        self.0
    }

    /// This function returns the size in bits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `MultiplicationInputsBatch` stores a batch of multiplication inputs in a vector of `MultiplicationInputsBlock`.
/// `first_record` is the first `RecordId` for the current batch.
/// `max_multiplications` is the maximum amount of multiplications performed within a this batch.
/// It is used to determine the vector length during the allocation.
/// If there are more multiplications, it will cause a panic!
/// `multiplication_bit_size` is the bit size of a single multiplication. The size will be consistent
/// across all multiplications of a gate.
#[derive(Clone, Debug)]
struct MultiplicationInputsBatch {
    first_record: Option<RecordId>,
    max_multiplications: usize,
    multiplication_bit_size: usize,
    vec: Vec<MultiplicationInputsBlock>,
}

impl MultiplicationInputsBatch {
    /// Creates a new store for multiplication intermediates. The first record is
    /// specified by `first_record`, or if that is `None`, is set automatically the
    /// first time a segment is added to the batch. Once the first record is set,
    /// attempting to add a segment before the first record will panic.
    ///
    /// The size of the allocated vector is
    /// `ceil((max_multiplications * multiplication_bit_size) / BIT_ARRAY_LEN)`.
    fn new(
        first_record: Option<RecordId>,
        max_multiplications: usize,
        multiplication_bit_size: usize,
    ) -> Self {
        // We should probably check that max_multiplications * multiplication_bit_size does
        // not exceed TARGET_PROOF_SIZE, or at least does not exceed it by much. But for now,
        // it is actually convenient that we don't -- we use TARGET_PROOF_SIZE as the limit
        // for preallocation of the storage, which is important to limit because the allocation
        // will occur regardless of the input size (i.e. even if we run IPA on two records).
        // The actual max_multiplications * multiplication_bit_size can be larger, for
        // subprotocols that don't yet know how to verify at granularity less than all input
        // records.
        let capacity_bits = usize::min(
            TARGET_PROOF_SIZE,
            max_multiplications.saturating_mul(multiplication_bit_size),
        );
        Self {
            first_record,
            max_multiplications,
            multiplication_bit_size,
            vec: Vec::with_capacity((capacity_bits + BIT_ARRAY_MASK) >> BIT_ARRAY_SHIFT),
        }
    }

    /// This function returns the amount of multiplications in one bit multiplications
    /// that are currently stored in the `MultiplicationInputsBatch`.
    fn get_number_of_multiplications(&self) -> usize {
        self.vec.len() * 256
    }

    /// returns whether the store is empty
    fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    /// `insert_segment` allows to include a new segment in `MultiplicationInputsBatch`.
    /// It supports `segments` that are either smaller than 256 bits or multiple of 256 bits.
    ///
    /// ## Panics
    /// Panics when segments have different lengths across records.
    /// It also Panics when the `record_id` is smaller
    /// than the first record of the batch, i.e. `first_record`
    /// or too large, i.e. `first_record+max_multiplications`
    fn insert_segment(&mut self, record_id: RecordId, segment: Segment) {
        // check segment size
        debug_assert_eq!(segment.len(), self.multiplication_bit_size);

        let first_record = *self.first_record.get_or_insert(record_id);

        // panics when record_id is out of bounds
        assert!(
            record_id >= first_record,
            "record_id out of range in insert_segment. record {record_id} is before \
             first record {first_record}",
        );
        assert!(
            usize::from(record_id)
                < self
                    .max_multiplications
                    .saturating_add(usize::from(first_record)),
            "record_id out of range in insert_segment. record {record_id} is beyond \
             segment of length {} starting at {}",
            self.max_multiplications,
            first_record,
        );

        // panics when record_id is too large to fit in, i.e. when it is out of bounds
        if segment.len() < 256 {
            self.insert_segment_small(record_id, segment);
        } else {
            self.insert_segment_large(record_id, &segment);
        }
    }

    /// insert `segments` that are smaller than or equal to 256
    ///
    /// ## Panics
    /// Panics when `bit_length` and `block_id` are out of bounds.
    /// It also Panics when the `record_id` is smaller
    /// than the first record of the batch, i.e. `first_record`
    /// or too large, i.e. `first_record+max_multiplications`
    fn insert_segment_small(&mut self, record_id: RecordId, segment: Segment) {
        // panics when record_id is less than first_record
        let id_within_batch = usize::from(record_id) - usize::from(self.first_record.unwrap());
        // round up segment length to a power of two since we want to have divisors of 256
        let length = segment.len().next_power_of_two();

        let block_id = (length * id_within_batch) >> BIT_ARRAY_SHIFT;
        // segments are small, pack one or more in each entry of `vec`
        let position_within_block_start = (length * id_within_batch) % 256;
        let position_within_block_end = position_within_block_start + segment.len();

        if self.vec.len() <= block_id {
            self.vec
                .resize_with(block_id + 1, MultiplicationInputsBlock::default);
        }
        let block = &mut self.vec[block_id];

        // copy segment value into entry
        for (segment_value, array_value) in [
            (segment.x_left, &mut block.x_left),
            (segment.x_right, &mut block.x_right),
            (segment.y_left, &mut block.y_left),
            (segment.y_right, &mut block.y_right),
            (segment.prss_left, &mut block.prss_left),
            (segment.prss_right, &mut block.prss_right),
            (segment.z_right, &mut block.z_right),
        ] {
            // panics when out of bounds
            let values_in_array = array_value
                .get_mut(position_within_block_start..position_within_block_end)
                .unwrap();
            values_in_array.clone_from_bitslice(segment_value.0);
        }
    }

    /// insert `segments` that are multiples of 256
    ///
    /// ## Panics
    /// Panics when segment is not a multiple of 256 or is out of bounds.
    /// It also Panics when the `record_id` is smaller
    /// than the first record of the batch, i.e. `first_record`
    /// or too large, i.e. `first_record+max_multiplications`
    fn insert_segment_large(&mut self, record_id: RecordId, segment: &Segment) {
        let id_within_batch = usize::from(record_id) - usize::from(self.first_record.unwrap());
        let block_id = (segment.len() * id_within_batch) >> BIT_ARRAY_SHIFT;
        let length_in_blocks = segment.len() >> BIT_ARRAY_SHIFT;
        if self.vec.len() < block_id {
            self.vec
                .resize_with(block_id, MultiplicationInputsBlock::default);
        }

        for i in 0..length_in_blocks {
            if self.vec.len() > block_id + i {
                MultiplicationInputsBlock::set(
                    &mut self.vec[block_id + i],
                    &segment.x_left.0[256 * i..256 * (i + 1)],
                    &segment.x_right.0[256 * i..256 * (i + 1)],
                    &segment.y_left.0[256 * i..256 * (i + 1)],
                    &segment.y_right.0[256 * i..256 * (i + 1)],
                    &segment.prss_left.0[256 * i..256 * (i + 1)],
                    &segment.prss_right.0[256 * i..256 * (i + 1)],
                    &segment.z_right.0[256 * i..256 * (i + 1)],
                )
                .unwrap();
            } else {
                self.vec.push(
                    MultiplicationInputsBlock::clone_from(
                        &segment.x_left.0[256 * i..256 * (i + 1)],
                        &segment.x_right.0[256 * i..256 * (i + 1)],
                        &segment.y_left.0[256 * i..256 * (i + 1)],
                        &segment.y_right.0[256 * i..256 * (i + 1)],
                        &segment.prss_left.0[256 * i..256 * (i + 1)],
                        &segment.prss_right.0[256 * i..256 * (i + 1)],
                        &segment.z_right.0[256 * i..256 * (i + 1)],
                    )
                    .unwrap(),
                );
            }
        }
    }

    /// `get_field_values_prover` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the prover of the DZKPs
    fn get_field_values_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = UVTupleBlock<DF>> + Clone + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_prover::<DF>)
    }

    /// `get_field_values_from_right_prover` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the verifier of the DZKPs on the left side of the prover, i.e. the `u` values.
    fn get_field_values_from_right_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF> + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_values_from_right_prover::<DF>)
    }

    /// `get_field_values_from_left_prover` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the verifier of the DZKPs on the right side of the prover, i.e. the `v` values.
    fn get_field_values_from_left_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF> + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_values_from_left_prover::<DF>)
    }
}

/// `Batch` collects a batch of `MultiplicationInputsBatch` in an ordered map.
/// Binary tree map gives the consistent ordering of multiplications per batch across
/// all helpers, so it is important to preserve.
/// The size of the batch is limited due to the memory costs and verifier specific constraints.
///
/// Corresponds to `AccumulatorState` of the MAC based malicious validator.
#[derive(Debug)]
pub(super) struct Batch {
    max_multiplications_per_gate: usize,
    first_record: Option<RecordId>,
    inner: BTreeMap<Gate, MultiplicationInputsBatch>,
}

impl Batch {
    /// Creates a new `Batch` for multiplication intermediates from multiple gates. The
    /// first record is specified by `first_record`, or if that is `None`, is set
    /// automatically for each gate the first time a segment from that gate is added.
    fn new(first_record: Option<RecordId>, max_multiplications_per_gate: usize) -> Self {
        Self {
            max_multiplications_per_gate,
            first_record,
            inner: BTreeMap::<Gate, MultiplicationInputsBatch>::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty() || self.inner.values().all(MultiplicationInputsBatch::is_empty)
    }

    pub(super) fn push(&mut self, gate: Gate, record_id: RecordId, segment: Segment) {
        // get value_store & create new one when necessary
        // insert segment
        self.inner
            .entry(gate)
            .or_insert_with(|| {
                MultiplicationInputsBatch::new(
                    self.first_record,
                    self.max_multiplications_per_gate,
                    segment.len(),
                )
            })
            .insert_segment(record_id, segment);
    }

    /// This function returns the amount of multiplications in one bit multiplications
    /// that are currently stored in the `batch`.
    fn get_number_of_multiplications(&self) -> usize {
        self.inner
            .values()
            .map(MultiplicationInputsBatch::get_number_of_multiplications)
            .sum()
    }

    /// `get_field_values_prover` converts a `Batch` into an iterator over field values
    /// which is used by the prover of the DZKP
    fn get_field_values_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = UVTupleBlock<DF>> + Clone + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_prover::<DF>)
    }

    /// `get_field_values_from_right_prover` converts a `Batch` into an iterator over field values
    /// which is used by the verifier of the DZKP on the left side of the prover.
    /// This produces the `u` values.
    fn get_field_values_from_right_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF> + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_from_right_prover::<DF>)
    }

    /// `get_field_values_from_left_prover` converts a `Batch` into an iterator over field values
    /// which is used by the verifier of the DZKP on the right side of the prover.
    /// This produces the `v` values.
    fn get_field_values_from_left_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF> + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_from_left_prover::<DF>)
    }

    /// ## Panics
    /// If `usize` to `u128` conversion fails.
    pub(super) async fn validate<B: ShardBinding>(
        self,
        ctx: Base<'_, B>,
        batch_index: usize,
    ) -> Result<(), Error> {
        const PRSS_RECORDS_PER_BATCH: usize = LargeProofGenerator::PROOF_LENGTH
            + (MAX_PROOF_RECURSION - 1) * SmallProofGenerator::PROOF_LENGTH
            + 2; // P and Q masks

        let proof_ctx = ctx.narrow(&Step::GenerateProof);

        let record_id = RecordId::from(batch_index);
        let prss_record_id_start = RecordId::from(batch_index * PRSS_RECORDS_PER_BATCH);
        let prss_record_id_end = RecordId::from((batch_index + 1) * PRSS_RECORDS_PER_BATCH);
        let prss_record_ids = RecordIdRange::from(prss_record_id_start..prss_record_id_end);

        if self.is_empty() {
            return Ok(());
        }

        let (
            my_batch_left_shares,
            shares_of_batch_from_left_prover,
            p_mask_from_right_prover,
            q_mask_from_left_prover,
        ) = {
            // generate BatchToVerify
            ProofBatch::generate(&proof_ctx, prss_record_ids, self.get_field_values_prover())
        };

        let chunk_batch = BatchToVerify::generate_batch_to_verify(
            proof_ctx,
            record_id,
            my_batch_left_shares,
            shares_of_batch_from_left_prover,
            p_mask_from_right_prover,
            q_mask_from_left_prover,
        )
        .await;

        // generate challenges
        let (challenges_for_left_prover, challenges_for_right_prover) = chunk_batch
            .generate_challenges(ctx.narrow(&Step::Challenge), record_id)
            .await;

        let (sum_of_uv, p_r_right_prover, q_r_left_prover) = {
            // get number of multiplications
            let m = self.get_number_of_multiplications();
            tracing::info!("validating {m} multiplications");
            debug_assert_eq!(
                m,
                self.get_field_values_prover::<Fp61BitPrime>()
                    .flat_map(|(u_array, v_array)| {
                        u_array.into_iter().zip(v_array).map(|(u, v)| u * v)
                    })
                    .count()
                    / 4,
                "Number of multiplications is counted incorrectly"
            );
            let sum_of_uv = Fp61BitPrime::truncate_from(u128::try_from(m).unwrap())
                * Fp61BitPrime::MINUS_ONE_HALF;

            let (p_r_right_prover, q_r_left_prover) = chunk_batch.compute_p_and_q_r(
                &challenges_for_left_prover,
                &challenges_for_right_prover,
                self.get_field_values_from_right_prover(),
                self.get_field_values_from_left_prover(),
            );

            (sum_of_uv, p_r_right_prover, q_r_left_prover)
        };

        // verify BatchToVerify, return result
        chunk_batch
            .verify(
                ctx.narrow(&Step::VerifyProof),
                record_id,
                sum_of_uv,
                p_r_right_prover,
                q_r_left_prover,
                &challenges_for_left_prover,
                &challenges_for_right_prover,
            )
            .await
    }
}

/// Validator Trait for DZKPs
/// It is different from the validator trait since context outputs a `DZKPUpgradedContext`
/// that is tied to a `DZKPBatch` rather than an `accumulator`.
/// Function signature of `validate` is also different, it does not downgrade shares anymore
#[async_trait]
pub trait DZKPValidator: Send + Sync {
    type Context: DZKPContext;

    fn context(&self) -> Self::Context;

    /// Sets the validator's total number of records field. This is required when using
    /// the validate_record API, if it wasn't already set on the context used to create
    /// the validator.
    fn set_total_records<T: Into<TotalRecords>>(&mut self, total_records: T);

    /// Validates all of the multiplies associated with this validator.
    ///
    /// Only one of the `DZKPValidator::validate` or the `DZKPContext::validate_record`
    /// APIs may be used with each validator. Since the `DZKPValidator::validate` API
    /// consumes the validator, using it means that all of the multiplies associated
    /// with the validator must be validated in a single proof, and
    /// `max_multiplications_per_gate` must be set accordingly.
    ///
    /// # Panics
    /// May panic if the above restrictions on validator usage are not followed.
    async fn validate(self) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.validate_indexed(0).await
    }

    /// Validates all of the multiplies associated with this validator, specifying
    /// an explicit batch index.
    ///
    /// This should be used when the protocol is explicitly managing batches.
    async fn validate_indexed(self, batch_index: usize) -> Result<(), Error>;

    /// `is_verified` checks that there are no `MultiplicationInputs` that have not been verified
    /// within the associated `DZKPBatch`
    ///
    /// ## Errors
    /// Errors when there are `MultiplicationInputs` that have not been verified.
    fn is_verified(&self) -> Result<(), Error>;

    /// `validated_seq_join` in this trait is a validated version of `seq_join`. Like `seq_join`,
    /// it performs a sequential join of futures from the provided iterable, but each future is
    /// augmented to additionally call `validate_record`.
    ///
    /// Unlike `seq_join`, the futures being joined are required to return a `Result`, which is
    /// used to report validation failures.
    ///
    fn validated_seq_join<'st, S, F, O>(
        self,
        source: S,
    ) -> impl Stream<Item = Result<O, Error>> + Send + 'st
    where
        Self: Sized + 'st,
        S: Stream<Item = F> + Send + 'st,
        F: Future<Output = Result<O, Error>> + Send + 'st,
        O: Send + Sync + 'static,
    {
        let ctx = self.context();
        seq_join(
            ctx.active_work(),
            source.enumerate().map(move |(index, fut)| {
                let ctx = ctx.clone();
                fut.then(move |res| async move {
                    let item = res?;
                    ctx.validate_record(RecordId::from(index)).await?;
                    Ok(item)
                })
            }),
        )
        .chain(stream::unfold(Some(self), move |mut validator| {
            // This keeps the validator alive until the stream has finished.
            drop(validator.take());
            ready(None)
        }))
    }
}

// Wrapper to avoid https://github.com/rust-lang/rust/issues/100013.
pub fn validated_seq_join<'st, V, S, F, O>(
    validator: V,
    source: S,
) -> impl Stream<Item = Result<O, Error>> + Send + 'st
where
    V: DZKPValidator + 'st,
    S: Stream<Item = F> + Send + 'st,
    F: Future<Output = Result<O, Error>> + Send + 'st,
    O: Send + Sync + 'static,
{
    validator.validated_seq_join(source)
}

#[derive(Clone)]
pub struct SemiHonestDZKPValidator<'a, B: ShardBinding> {
    context: SemiHonestDZKPUpgraded<'a, B>,
}

impl<'a, B: ShardBinding> SemiHonestDZKPValidator<'a, B> {
    pub(super) fn new(inner: Base<'a, B>) -> Self {
        Self {
            context: SemiHonestDZKPUpgraded::new(inner),
        }
    }
}

#[async_trait]
impl<'a, B: ShardBinding> DZKPValidator for SemiHonestDZKPValidator<'a, B> {
    type Context = SemiHonestDZKPUpgraded<'a, B>;

    fn context(&self) -> SemiHonestDZKPUpgraded<'a, B> {
        self.context.clone()
    }

    fn set_total_records<T: Into<TotalRecords>>(&mut self, _total_records: T) {
        // Semi-honest validator doesn't do anything, so doesn't care.
    }

    async fn validate_indexed(self, _batch_index: usize) -> Result<(), Error> {
        Ok(())
    }

    fn is_verified(&self) -> Result<(), Error> {
        Ok(())
    }
}

type DzkpBatcher<'a> = Batcher<'a, Batch>;

/// The DZKP validator, and all associated contexts, each hold a reference to a single
/// instance of `MaliciousDZKPValidatorInner`.
pub(super) struct MaliciousDZKPValidatorInner<'a, B: ShardBinding> {
    pub(super) batcher: Mutex<DzkpBatcher<'a>>,
    pub(super) validate_ctx: Base<'a, B>,
}

/// `MaliciousDZKPValidator` corresponds to pub struct `Malicious` and implements the trait `DZKPValidator`
/// The implementation of `validate` of the `DZKPValidator` trait depends on generic `DF`
pub struct MaliciousDZKPValidator<'a, B: ShardBinding> {
    // This is an `Option` because we want to consume it in `DZKPValidator::validate`,
    // but we also want to implement `Drop`. Note that the `is_verified` check in `Drop`
    // does nothing when `batcher_ref` is already `None`.
    inner_ref: Option<Arc<MaliciousDZKPValidatorInner<'a, B>>>,
    protocol_ctx: MaliciousDZKPUpgraded<'a, B>,
}

#[async_trait]
impl<'a, B: ShardBinding> DZKPValidator for MaliciousDZKPValidator<'a, B> {
    type Context = MaliciousDZKPUpgraded<'a, B>;

    fn context(&self) -> MaliciousDZKPUpgraded<'a, B> {
        self.protocol_ctx.clone()
    }

    fn set_total_records<T: Into<TotalRecords>>(&mut self, total_records: T) {
        self.inner_ref
            .as_ref()
            .expect("validator should be active")
            .batcher
            .lock()
            .unwrap()
            .set_total_records(total_records);
    }

    async fn validate_indexed(mut self, batch_index: usize) -> Result<(), Error> {
        let arc = self
            .inner_ref
            .take()
            .expect("nothing else should be consuming the batcher");
        let MaliciousDZKPValidatorInner {
            batcher: batcher_mutex,
            validate_ctx,
        } = Arc::into_inner(arc)
            .expect("validator should hold the only strong reference to batcher");

        let batcher = batcher_mutex.into_inner().unwrap();

        batcher
            .into_single_batch()
            .validate(validate_ctx, batch_index)
            .await
    }

    /// `is_verified` checks that there are no `MultiplicationInputs` that have not been verified.
    /// This function is called by drop() to ensure that the validator is safe to be dropped.
    ///
    /// ## Errors
    /// Errors when there are `MultiplicationInputs` that have not been verified.
    fn is_verified(&self) -> Result<(), Error> {
        let batcher = self
            .inner_ref
            .as_ref()
            .expect("validator should be active")
            .batcher
            .lock()
            .unwrap();
        if batcher.is_empty() {
            Ok(())
        } else {
            Err(Error::ContextUnsafe(format!("{:?}", self.protocol_ctx)))
        }
    }
}

impl<'a, B: ShardBinding> MaliciousDZKPValidator<'a, B> {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new<S>(
        ctx: MaliciousContext<'a, B>,
        steps: MaliciousProtocolSteps<S>,
        max_multiplications_per_gate: usize,
    ) -> Self
    where
        Gate: StepNarrow<S>,
        S: ipa_step::Step + ?Sized,
    {
        let batcher = Batcher::new(
            max_multiplications_per_gate,
            ctx.total_records(),
            Box::new(move |batch_index| {
                let first_record = (max_multiplications_per_gate != usize::MAX)
                    .then(|| RecordId::from(batch_index * max_multiplications_per_gate));
                Batch::new(first_record, max_multiplications_per_gate)
            }),
        );
        let inner = Arc::new(MaliciousDZKPValidatorInner {
            batcher,
            validate_ctx: ctx.narrow(steps.validate).validator_context(),
        });
        let protocol_ctx = MaliciousDZKPUpgraded::new(&inner, ctx.narrow(steps.protocol));
        Self {
            inner_ref: Some(inner),
            protocol_ctx,
        }
    }
}

impl<'a, B: ShardBinding> Drop for MaliciousDZKPValidator<'a, B> {
    fn drop(&mut self) {
        // If `validate` has not been called, and we are not unwinding, check that the
        // validator is not holding unverified multiplies.
        //  * If `validate` has been called (i.e. the validator was used in the
        //    non-`validate_record` mode of operation), then `self.inner_ref` is `None`,
        //    because validation consumed the batcher via `self.inner_ref`.
        //  * Unwinding can happen at any time, so complaining about incomplete
        //    validation is likely just extra noise, and the additional panic
        //    during unwinding could be confusing.
        if self.inner_ref.is_some() && !std::thread::panicking() {
            self.is_verified().unwrap();
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        iter::{repeat, repeat_with, zip},
        num::NonZeroUsize,
        sync::Arc,
    };

    use bitvec::{order::Lsb0, prelude::BitArray, vec::BitVec};
    use futures::{stream, StreamExt, TryStreamExt};
    use futures_util::stream::iter;
    use proptest::{
        prelude::{Just, Strategy},
        prop_compose, prop_oneof, proptest,
        test_runner::Config as ProptestConfig,
    };
    use rand::{distributions::Standard, prelude::Distribution};

    use crate::{
        error::Error,
        ff::{
            boolean::Boolean,
            boolean_array::{BooleanArray, BA16, BA20, BA256, BA3, BA32, BA64, BA8},
            Fp61BitPrime,
        },
        protocol::{
            basics::{select, BooleanArrayMul, SecureMul},
            context::{
                dzkp_field::{DZKPCompatibleField, BLOCK_SIZE},
                dzkp_validator::{
                    Batch, DZKPValidator, Segment, SegmentEntry, BIT_ARRAY_LEN, TARGET_PROOF_SIZE,
                },
                Context, DZKPUpgradedMaliciousContext, DZKPUpgradedSemiHonestContext,
                UpgradableContext, TEST_DZKP_STEPS,
            },
            Gate, RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SharedValue,
            Vectorizable,
        },
        seq_join::{seq_join, SeqJoin},
        sharding::NotSharded,
        test_fixture::{join3v, Reconstruct, Runner, TestWorld},
    };

    async fn test_select_semi_honest<V>()
    where
        V: BooleanArray,
        for<'a> Replicated<V>: BooleanArrayMul<DZKPUpgradedSemiHonestContext<'a, NotSharded>>,
        Standard: Distribution<V>,
    {
        let world = TestWorld::default();
        let context = world.contexts();
        let mut rng = thread_rng();

        let bit = rng.gen::<Boolean>();
        let a = rng.gen::<V>();
        let b = rng.gen::<V>();

        let bit_shares = bit.share_with(&mut rng);
        let a_shares = a.share_with(&mut rng);
        let b_shares = b.share_with(&mut rng);

        let futures = zip(context.iter(), zip(bit_shares, zip(a_shares, b_shares))).map(
            |(ctx, (bit_share, (a_share, b_share)))| async move {
                let v = ctx.clone().dzkp_validator(TEST_DZKP_STEPS, 1);
                let sh_ctx = v.context();

                let result = select(
                    sh_ctx.set_total_records(1),
                    RecordId::from(0),
                    &bit_share,
                    &a_share,
                    &b_share,
                )
                .await?;

                v.validate().await?;

                Ok::<_, Error>(result)
            },
        );

        let [ab0, ab1, ab2] = join3v(futures).await;

        let ab = [ab0, ab1, ab2].reconstruct();

        assert_eq!(ab, if bit.into() { a } else { b });
    }

    #[tokio::test]
    async fn select_semi_honest() {
        test_select_semi_honest::<BA3>().await;
        test_select_semi_honest::<BA8>().await;
        test_select_semi_honest::<BA16>().await;
        test_select_semi_honest::<BA20>().await;
        test_select_semi_honest::<BA32>().await;
        test_select_semi_honest::<BA64>().await;
        test_select_semi_honest::<BA256>().await;
    }

    async fn test_select_malicious<V>()
    where
        V: BooleanArray,
        for<'a> Replicated<V>: BooleanArrayMul<DZKPUpgradedMaliciousContext<'a, NotSharded>>,
        Standard: Distribution<V>,
    {
        let world = TestWorld::default();
        let context = world.malicious_contexts();
        let mut rng = thread_rng();

        let bit = rng.gen::<Boolean>();
        let a = rng.gen::<V>();
        let b = rng.gen::<V>();

        let bit_shares = bit.share_with(&mut rng);
        let a_shares = a.share_with(&mut rng);
        let b_shares = b.share_with(&mut rng);

        let futures = zip(context.iter(), zip(bit_shares, zip(a_shares, b_shares))).map(
            |(ctx, (bit_share, (a_share, b_share)))| async move {
                let v = ctx.clone().dzkp_validator(TEST_DZKP_STEPS, 1);
                let m_ctx = v.context();

                let result = select(
                    m_ctx.set_total_records(1),
                    RecordId::from(0),
                    &bit_share,
                    &a_share,
                    &b_share,
                )
                .await?;

                v.validate().await?;

                Ok::<_, Error>(result)
            },
        );

        let [ab0, ab1, ab2] = join3v(futures).await;

        let ab = [ab0, ab1, ab2].reconstruct();

        assert_eq!(ab, if bit.into() { a } else { b });
    }

    #[tokio::test]
    async fn select_malicious() {
        test_select_malicious::<BA3>().await;
        test_select_malicious::<BA8>().await;
        test_select_malicious::<BA16>().await;
        test_select_malicious::<BA20>().await;
        test_select_malicious::<BA32>().await;
        test_select_malicious::<BA64>().await;
        test_select_malicious::<BA256>().await;
    }

    #[tokio::test]
    async fn two_multiplies_malicious() {
        const COUNT: usize = 32;
        let mut rng = thread_rng();

        let original_inputs = repeat_with(|| rng.gen())
            .take(COUNT)
            .collect::<Vec<Boolean>>();

        let [res0, res1, res2] = TestWorld::default()
            .malicious(
                original_inputs.clone().into_iter(),
                |ctx, input_shares| async move {
                    let v = ctx.dzkp_validator(TEST_DZKP_STEPS, COUNT);
                    let m_ctx = v.context().set_total_records(COUNT - 1);

                    let m_results = seq_join(
                        NonZeroUsize::new(COUNT).unwrap(),
                        iter(
                            zip(input_shares.clone(), input_shares.into_iter().skip(1))
                                .enumerate()
                                .map(|(i, (a_malicious, b_malicious))| {
                                    let m_ctx = m_ctx.clone();
                                    async move {
                                        let tmp = a_malicious
                                            .multiply(
                                                &b_malicious,
                                                m_ctx.narrow("a"),
                                                RecordId::from(i),
                                            )
                                            .await
                                            .unwrap();
                                        // This multiplication is redundant with the previous, but
                                        // means we test a circuit with more than one gate.
                                        tmp.multiply(
                                            &b_malicious,
                                            m_ctx.narrow("b"),
                                            RecordId::from(i),
                                        )
                                        .await
                                        .unwrap()
                                    }
                                }),
                        ),
                    )
                    .collect::<Vec<_>>()
                    .await;
                    v.validate().await.unwrap();
                    Ok::<_, Error>(m_results)
                },
            )
            .await
            .map(Result::unwrap);

        for i in 0..COUNT - 1 {
            let expected = original_inputs[i] * original_inputs[i + 1];
            let actual = [res0[i].clone(), res1[i].clone(), res2[i].clone()].reconstruct();
            assert_eq!(expected, actual);
        }
    }

    /// Similar to `test_select_malicious`, but operating on vectors
    async fn multi_select_malicious<V>(count: usize, max_multiplications_per_gate: usize)
    where
        V: BooleanArray,
        for<'a> Replicated<V>: BooleanArrayMul<DZKPUpgradedMaliciousContext<'a, NotSharded>>,
        Standard: Distribution<V>,
    {
        let mut rng = thread_rng();

        let bit: Vec<Boolean> = repeat_with(|| rng.gen::<Boolean>()).take(count).collect();
        let a: Vec<V> = repeat_with(|| rng.gen()).take(count).collect();
        let b: Vec<V> = repeat_with(|| rng.gen()).take(count).collect();

        let [ab0, ab1, ab2]: [Vec<Replicated<V>>; 3] = TestWorld::default()
            .malicious(
                zip(bit.clone(), zip(a.clone(), b.clone())),
                |ctx, inputs| async move {
                    let v = ctx
                        .set_total_records(count)
                        .dzkp_validator(TEST_DZKP_STEPS, max_multiplications_per_gate);
                    let m_ctx = v.context();

                    v.validated_seq_join(stream::iter(inputs).enumerate().map(
                        |(i, (bit_share, (a_share, b_share)))| {
                            let m_ctx = m_ctx.clone();
                            async move {
                                select(m_ctx, RecordId::from(i), &bit_share, &a_share, &b_share)
                                    .await
                            }
                        },
                    ))
                    .try_collect()
                    .await
                },
            )
            .await
            .map(Result::unwrap);

        let ab: Vec<V> = [ab0, ab1, ab2].reconstruct();

        for i in 0..count {
            assert_eq!(ab[i], if bit[i].into() { a[i] } else { b[i] });
        }
    }

    /// test for testing `validated_seq_join`
    /// similar to `complex_circuit` in `validator.rs` (which has a more detailed comment)
    async fn chained_multiplies_dzkp(
        count: usize,
        max_multiplications_per_gate: usize,
    ) -> Result<(), Error> {
        let world = TestWorld::default();

        let mut rng = thread_rng();

        let original_inputs = (0..count)
            .map(|_| rng.gen::<Boolean>())
            .collect::<Vec<Boolean>>();

        let shared_inputs: Vec<[Replicated<Boolean>; 3]> = original_inputs
            .iter()
            .map(|x| x.share_with(&mut rng))
            .collect();
        let h1_shares: Vec<Replicated<Boolean>> =
            shared_inputs.iter().map(|x| x[0].clone()).collect();
        let h2_shares: Vec<Replicated<Boolean>> =
            shared_inputs.iter().map(|x| x[1].clone()).collect();
        let h3_shares: Vec<Replicated<Boolean>> =
            shared_inputs.iter().map(|x| x[2].clone()).collect();

        let futures = world
            .malicious_contexts()
            .into_iter()
            .zip([h1_shares.clone(), h2_shares.clone(), h3_shares.clone()])
            .map(|(ctx, input_shares)| async move {
                let v = ctx
                    .set_total_records(count - 1)
                    .dzkp_validator(TEST_DZKP_STEPS, max_multiplications_per_gate);
                let m_ctx = v.context();

                let m_results = v
                    .validated_seq_join(iter(
                        zip(
                            repeat(m_ctx.clone()).enumerate(),
                            zip(input_shares.iter(), input_shares.iter().skip(1)),
                        )
                        .map(
                            |((i, ctx), (a_malicious, b_malicious))| async move {
                                a_malicious
                                    .multiply(b_malicious, ctx, RecordId::from(i))
                                    .await
                            },
                        ),
                    ))
                    .try_collect::<Vec<_>>()
                    .await?;
                Ok::<_, Error>(m_results)
            });

        let processed_outputs_malicious = join3v(futures).await;

        let futures = world
            .contexts()
            .into_iter()
            .zip([h1_shares, h2_shares, h3_shares])
            .map(|(ctx, input_shares)| async move {
                let v = ctx.dzkp_validator(TEST_DZKP_STEPS, max_multiplications_per_gate);
                let m_ctx = v.context();

                let m_results = v
                    .validated_seq_join(iter(
                        zip(
                            repeat(m_ctx.set_total_records(count - 1)).enumerate(),
                            zip(input_shares.iter(), input_shares.iter().skip(1)),
                        )
                        .map(
                            |((i, ctx), (a_malicious, b_malicious))| async move {
                                a_malicious
                                    .multiply(b_malicious, ctx, RecordId::from(i))
                                    .await
                            },
                        ),
                    ))
                    .try_collect::<Vec<_>>()
                    .await?;
                Ok::<_, Error>(m_results)
            });

        let processed_outputs_semi_honest = join3v(futures).await;

        for i in 0..count - 1 {
            let x1 = original_inputs[i];
            let x2 = original_inputs[i + 1];
            let x1_times_x2_malicious = [
                processed_outputs_malicious[0][i].clone(),
                processed_outputs_malicious[1][i].clone(),
                processed_outputs_malicious[2][i].clone(),
            ]
            .reconstruct();
            let x1_times_x2_semi_honest = [
                processed_outputs_semi_honest[0][i].clone(),
                processed_outputs_semi_honest[1][i].clone(),
                processed_outputs_semi_honest[2][i].clone(),
            ]
            .reconstruct();

            assert_eq!((x1, x2, x1 * x2), (x1, x2, x1_times_x2_malicious));
            assert_eq!((x1, x2, x1 * x2), (x1, x2, x1_times_x2_semi_honest));
        }

        Ok(())
    }

    fn record_count_strategy() -> impl Strategy<Value = usize> {
        // The chained_multiplies test has count - 1 records, so 1 is not a valid input size.
        // It is for multi_select though.
        prop_oneof![2usize..=512, (1u32..=9).prop_map(|i| 1usize << i)]
    }

    fn max_multiplications_per_gate_strategy(record_count: usize) -> impl Strategy<Value = usize> {
        let max_max_mults = record_count.min(128);
        (0u32..=max_max_mults.ilog2()).prop_map(|i| 1usize << i)
    }

    prop_compose! {
        fn batching()
                   (record_count in record_count_strategy())
                   (record_count in Just(record_count), max_mults in max_multiplications_per_gate_strategy(record_count))
        -> (usize, usize)
        {
            (record_count, max_mults)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn batching_proptest((record_count, max_multiplications_per_gate) in batching()) {
            println!("record_count {record_count} batch {max_multiplications_per_gate}");
            // This condition is correct only for active_work = 16 and record size of 1 byte.
            if max_multiplications_per_gate != 1 && max_multiplications_per_gate % 16 != 0 {
                // TODO: #1300, read_size | batch_size.
                // Note: for active work < 2048, read size matches active work.

                // Besides read_size | batch_size, there is also a constraint
                // something like active_work > read_size + batch_size - 1.
                println!("skipping config due to read_size vs. batch_size constraints");
            } else {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    chained_multiplies_dzkp(record_count, max_multiplications_per_gate).await.unwrap();
                    /*
                    multi_select_malicious::<BA3>(record_count, max_multiplications_per_gate).await;
                    multi_select_malicious::<BA8>(record_count, max_multiplications_per_gate).await;
                    multi_select_malicious::<BA16>(record_count, max_multiplications_per_gate).await;
                    */
                    multi_select_malicious::<BA20>(record_count, max_multiplications_per_gate).await;
                    /*
                    multi_select_malicious::<BA32>(record_count, max_multiplications_per_gate).await;
                    multi_select_malicious::<BA64>(record_count, max_multiplications_per_gate).await;
                    multi_select_malicious::<BA256>(record_count, max_multiplications_per_gate).await;
                    */
                });
            }
        }
    }

    #[tokio::test]
    async fn large_batch() {
        multi_select_malicious::<BA8>(2 * TARGET_PROOF_SIZE, 2 * TARGET_PROOF_SIZE).await;
    }

    // Similar to multi_select_malicious, but instead of using `validated_seq_join`, passes
    // `usize::MAX` as the batch size and does a single `v.validate()`.
    #[tokio::test]
    async fn large_single_batch() {
        let count: usize = TARGET_PROOF_SIZE + 1;
        let mut rng = thread_rng();

        let bit: Vec<Boolean> = repeat_with(|| rng.gen::<Boolean>()).take(count).collect();
        let a: Vec<BA8> = repeat_with(|| rng.gen()).take(count).collect();
        let b: Vec<BA8> = repeat_with(|| rng.gen()).take(count).collect();

        let [ab0, ab1, ab2]: [Vec<Replicated<BA8>>; 3] = TestWorld::default()
            .malicious(
                zip(bit.clone(), zip(a.clone(), b.clone())),
                |ctx, inputs| async move {
                    let v = ctx
                        .set_total_records(count)
                        .dzkp_validator(TEST_DZKP_STEPS, usize::MAX);
                    let m_ctx = v.context();

                    let result = seq_join(
                        m_ctx.active_work(),
                        stream::iter(inputs).enumerate().map(
                            |(i, (bit_share, (a_share, b_share)))| {
                                let m_ctx = m_ctx.clone();
                                async move {
                                    select(m_ctx, RecordId::from(i), &bit_share, &a_share, &b_share)
                                        .await
                                }
                            },
                        ),
                    )
                    .try_collect()
                    .await
                    .unwrap();

                    v.validate().await.unwrap();

                    result
                },
            )
            .await;

        let ab: Vec<BA8> = [ab0, ab1, ab2].reconstruct();

        for i in 0..count {
            assert_eq!(ab[i], if bit[i].into() { a[i] } else { b[i] });
        }
    }

    #[tokio::test]
    #[should_panic(expected = "ContextUnsafe(\"DZKPMaliciousContext\")")]
    async fn missing_validate() {
        let mut rng = thread_rng();

        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();

        TestWorld::default()
            .malicious((a, b), |ctx, (a, b)| async move {
                let v = ctx.dzkp_validator(TEST_DZKP_STEPS, 1);
                let m_ctx = v.context().set_total_records(1);

                a.multiply(&b, m_ctx, RecordId::FIRST).await.unwrap()

                // `validate` should appear here.
            })
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "panicking before validate")]
    #[allow(unreachable_code)]
    async fn missing_validate_panic() {
        let mut rng = thread_rng();

        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();

        TestWorld::default()
            .malicious((a, b), |ctx, (a, b)| async move {
                let v = ctx.dzkp_validator(TEST_DZKP_STEPS, 1);
                let m_ctx = v.context().set_total_records(1);

                let _result = a.multiply(&b, m_ctx, RecordId::FIRST).await.unwrap();

                panic!("panicking before validate");
            })
            .await;
    }

    fn segment_from_entry(entry: SegmentEntry) -> Segment {
        Segment::from_entries(
            entry.clone(),
            entry.clone(),
            entry.clone(),
            entry.clone(),
            entry.clone(),
            entry.clone(),
            entry,
        )
    }

    #[test]
    fn batch_allocation_small() {
        const SIZE: usize = 1;
        let mut batch = Batch::new(None, SIZE);
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        batch.push(Gate::default(), RecordId::FIRST, segment);
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 1);
        assert!(batch.inner.get(&Gate::default()).unwrap().vec.capacity() >= SIZE);
        assert!(batch.inner.get(&Gate::default()).unwrap().vec.capacity() <= 2 * SIZE);
    }

    #[test]
    fn batch_allocation_big() {
        const SIZE: usize = 2 * TARGET_PROOF_SIZE;
        let mut batch = Batch::new(None, SIZE);
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        batch.push(Gate::default(), RecordId::FIRST, segment);
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 1);
        assert!(
            batch.inner.get(&Gate::default()).unwrap().vec.capacity()
                >= TARGET_PROOF_SIZE / BIT_ARRAY_LEN
        );
        assert!(
            batch.inner.get(&Gate::default()).unwrap().vec.capacity()
                <= 11 * TARGET_PROOF_SIZE / 10 / BIT_ARRAY_LEN
        );
    }

    #[test]
    fn batch_fill() {
        const SIZE: usize = 10;
        let mut batch = Batch::new(None, SIZE);
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        for i in 0..SIZE {
            batch.push(Gate::default(), RecordId::from(i), segment.clone());
        }
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 1);
        assert!(batch.inner.get(&Gate::default()).unwrap().vec.capacity() >= 1);
        assert!(batch.inner.get(&Gate::default()).unwrap().vec.capacity() <= 2);
    }

    #[test]
    fn batch_fill_out_of_order() {
        let mut batch = Batch::new(None, 3);
        let ba0 = BA256::from((0, 0));
        let ba1 = BA256::from((0, 1));
        let ba2 = BA256::from((0, 2));
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba0,
        ));
        batch.push(Gate::default(), RecordId::from(0), segment.clone());
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba2,
        ));
        batch.push(Gate::default(), RecordId::from(2), segment.clone());
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba1,
        ));
        batch.push(Gate::default(), RecordId::from(1), segment.clone());
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 3);
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[0].x_left,
            ba0.as_bitslice()
        );
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[1].x_left,
            ba1.as_bitslice()
        );
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[2].x_left,
            ba2.as_bitslice()
        );
    }

    #[test]
    fn batch_fill_at_offset() {
        let mut batch = Batch::new(None, 3);
        let ba0 = BA256::from((0, 0));
        let ba1 = BA256::from((0, 1));
        let ba2 = BA256::from((0, 2));
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba0,
        ));
        batch.push(Gate::default(), RecordId::from(4), segment.clone());
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba1,
        ));
        batch.push(Gate::default(), RecordId::from(5), segment.clone());
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba2,
        ));
        batch.push(Gate::default(), RecordId::from(6), segment.clone());
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 3);
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[0].x_left,
            ba0.as_bitslice()
        );
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[1].x_left,
            ba1.as_bitslice()
        );
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[2].x_left,
            ba2.as_bitslice()
        );
    }

    #[test]
    fn batch_explicit_first_record() {
        let mut batch = Batch::new(Some(RecordId::from(4)), 3);
        let ba6 = BA256::from((0, 6));
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<256>>::as_segment_entry(
            &ba6,
        ));
        batch.push(Gate::default(), RecordId::from(6), segment.clone());
        assert_eq!(batch.inner.get(&Gate::default()).unwrap().vec.len(), 3);
        assert_eq!(
            batch.inner.get(&Gate::default()).unwrap().vec[2].x_left,
            ba6.as_bitslice()
        );
    }

    #[test]
    fn batch_is_empty() {
        const SIZE: usize = 10;
        let mut batch = Batch::new(None, SIZE);
        assert!(batch.is_empty());
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        batch.push(Gate::default(), RecordId::FIRST, segment);
        assert!(!batch.is_empty());
    }

    #[test]
    #[should_panic(
        expected = "record_id out of range in insert_segment. record 0 is before first record 10"
    )]
    fn batch_underflow() {
        const SIZE: usize = 10;
        let mut batch = Batch::new(None, SIZE);
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        batch.push(Gate::default(), RecordId::from(10), segment.clone());
        batch.push(Gate::default(), RecordId::from(0), segment.clone());
    }

    #[test]
    #[should_panic(
        expected = "record_id out of range in insert_segment. record 10 is beyond segment of length 10 starting at 0"
    )]
    fn batch_overflow() {
        const SIZE: usize = 10;
        let mut batch = Batch::new(None, SIZE);
        let zero = Boolean::ZERO;
        let zero_vec: <Boolean as Vectorizable<1>>::Array = zero.into_array();
        let segment = segment_from_entry(<Boolean as DZKPCompatibleField<1>>::as_segment_entry(
            &zero_vec,
        ));
        for i in 0..=SIZE {
            batch.push(Gate::default(), RecordId::from(i), segment.clone());
        }
    }

    fn populate_batch(
        segment_size: usize,
        batch_prover: &mut Batch,
        batch_left: &mut Batch,
        batch_right: &mut Batch,
    ) {
        let mut rng = thread_rng();

        // vec for segments
        let vec_x_left = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_x_right = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_y_left = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_y_right = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_prss_left = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_prss_right = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();

        // compute z
        let vec_z_left = vec_x_left.clone() & vec_y_left.clone()
            ^ (vec_x_left.clone() & vec_y_right.clone())
            ^ (vec_x_right.clone() & vec_y_left.clone())
            ^ vec_prss_left.clone()
            ^ vec_prss_right.clone();

        // vector for unchecked elements
        // i.e. these are used to fill the segments of the verifier and prover that are not part
        // of this povers proof
        let vec_x_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_y_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_z_right = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_prss_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_z_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();

        // generate and push segments
        for i in 0..1024 / segment_size {
            // prover
            // generate segments
            let segment_prover = Segment::from_entries(
                SegmentEntry::from_bitslice(
                    &vec_x_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_x_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_z_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
            );
            // push segment into batch
            batch_prover.push(Gate::default(), RecordId::from(i), segment_prover);

            // verifier to the left
            // generate segments
            let segment_left = Segment::from_entries(
                SegmentEntry::from_bitslice(
                    &vec_x_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_x_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_z_left[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
            );
            // push segment into batch
            batch_left.push(Gate::default(), RecordId::from(i), segment_left);

            // verifier to the right
            // generate segments
            let segment_right = Segment::from_entries(
                SegmentEntry::from_bitslice(
                    &vec_x_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_x_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_y_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_right[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_prss_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
                SegmentEntry::from_bitslice(
                    &vec_z_3rd_share[i * 8 * segment_size..(i + 1) * 8 * segment_size],
                ),
            );
            // push segment into batch
            batch_right.push(Gate::default(), RecordId::from(i), segment_right);
        }
    }

    #[test]
    fn batch_convert() {
        // test for small and large segments, i.e. 8bit and 512 bit
        for segment_size in [8usize, 512usize] {
            // generate batch for the prover
            let mut batch_prover = Batch::new(None, 1024 / segment_size);

            // generate batch for the verifier on the left of the prover
            let mut batch_left = Batch::new(None, 1024 / segment_size);

            // generate batch for the verifier on the right of the prover
            let mut batch_right = Batch::new(None, 1024 / segment_size);

            // fill the batches with random values
            populate_batch(
                segment_size,
                &mut batch_prover,
                &mut batch_left,
                &mut batch_right,
            );

            // check correctness of batch
            assert_batch(&batch_prover, &batch_left, &batch_right);
            assert_batch_convert(&batch_prover, &batch_left, &batch_right);
        }
    }

    fn assert_batch_convert(batch_prover: &Batch, batch_left: &Batch, batch_right: &Batch) {
        batch_prover
            .get_field_values_prover::<Fp61BitPrime>()
            .zip(
                batch_left
                    .get_field_values_from_right_prover::<Fp61BitPrime>()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .zip(
                batch_right
                    .get_field_values_from_left_prover::<Fp61BitPrime>()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .for_each(|((prover, verifier_left), verifier_right)| {
                assert_eq!(prover.0, verifier_left);
                assert_eq!(prover.1, verifier_right);
            });
    }

    fn assert_batch(batch_prover: &Batch, batch_left: &Batch, batch_right: &Batch) {
        batch_prover
            .inner
            .values()
            .flat_map(|x| x.vec.iter())
            .zip(batch_left.inner.values().flat_map(|x| x.vec.iter()))
            .zip(batch_right.inner.values().flat_map(|x| x.vec.iter()))
            .for_each(|((prover, verifier_left), verifier_right)| {
                assert_eq!(prover.x_left, verifier_left.x_right, "x_left");
                assert_eq!(prover.x_right, verifier_right.x_left, "x_right");
                assert_eq!(prover.y_left, verifier_left.y_right, "y_left");
                assert_eq!(prover.y_right, verifier_right.y_left, "y_right");
                assert_eq!(prover.prss_left, verifier_left.prss_right, "prss_left");
                assert_eq!(prover.prss_right, verifier_right.prss_left, "x_right");
                let z_left = prover.x_left & prover.y_left
                    ^ prover.x_right & prover.y_left
                    ^ prover.x_left & prover.y_right
                    ^ prover.prss_left
                    ^ prover.prss_right;
                assert_eq!(verifier_left.z_right, z_left, "z_left");
            });
    }

    #[tokio::test]
    async fn simple_multiply_conversion() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();

        let [h1_batch, h2_batch, h3_batch] = world
            .malicious((a, b), |ctx, (a, b)| async move {
                let mut validator = ctx.dzkp_validator(TEST_DZKP_STEPS, 8);
                let mctx = validator.context();
                let _ = a
                    .multiply(&b, mctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap();

                let batcher_mutex = Arc::into_inner(validator.inner_ref.take().unwrap())
                    .unwrap()
                    .batcher;
                batcher_mutex.into_inner().unwrap().into_single_batch()
            })
            .await;

        // H1
        assert_batch(&h1_batch, &h3_batch, &h2_batch);
        assert_batch_convert(&h1_batch, &h3_batch, &h2_batch);

        // H2
        assert_batch(&h2_batch, &h1_batch, &h3_batch);
        assert_batch_convert(&h2_batch, &h1_batch, &h3_batch);

        // H3
        assert_batch(&h3_batch, &h2_batch, &h1_batch);
        assert_batch_convert(&h3_batch, &h2_batch, &h1_batch);
    }

    #[test]
    fn powers_of_two() {
        let bits = BitArray::<[u8; 32], Lsb0>::new([255u8; 32]);

        // Boolean
        assert_eq!(
            1usize,
            SegmentEntry::from_bitslice(bits.get(0..1).unwrap())
                .len()
                .next_power_of_two()
        );

        // BA3
        assert_eq!(
            4usize,
            SegmentEntry::from_bitslice(bits.get(0..3).unwrap())
                .len()
                .next_power_of_two()
        );

        // BA8
        assert_eq!(
            8usize,
            SegmentEntry::from_bitslice(bits.get(0..8).unwrap())
                .len()
                .next_power_of_two()
        );

        // BA20
        assert_eq!(
            32usize,
            SegmentEntry::from_bitslice(bits.get(0..20).unwrap())
                .len()
                .next_power_of_two()
        );

        // BA64
        assert_eq!(
            64usize,
            SegmentEntry::from_bitslice(bits.get(0..64).unwrap())
                .len()
                .next_power_of_two()
        );

        // BA256
        assert_eq!(
            256usize,
            SegmentEntry::from_bitslice(bits.get(0..256).unwrap())
                .len()
                .next_power_of_two()
        );
    }
}
