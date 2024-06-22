use std::{cmp, collections::HashMap, fmt::Debug};

use async_trait::async_trait;
use bitvec::{array::BitArray, prelude::Lsb0, slice::BitSlice};
use futures::{Future, Stream};
use futures_util::{StreamExt, TryFutureExt};

use super::step::ZeroKnowledgeProofValidateStep as Step;
#[cfg(all(test, unit_test))]
use crate::protocol::context::dzkp_field::{DZKPBaseField, UVTupleBlock};
use crate::{
    error::{BoxError, Error},
    helpers::stream::TryFlattenItersExt,
    protocol::{
        context::{
            dzkp_malicious::DZKPUpgraded as MaliciousDZKPUpgraded,
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded, Base, Context,
            MaliciousContext, SemiHonestContext, UpgradableContext,
        },
        Gate, RecordId,
    },
    seq_join::{seq_join, SeqJoin},
    sharding::ShardBinding,
    sync::{Arc, Mutex, Weak},
    telemetry::metrics::DZKP_BATCH_INCREMENTS,
};

// constants for metrics::increment_counter!
const ALLOCATED_AMOUNT: &str = "allocated amount of multiplications";
const ACTUAL_AMOUNT: &str = "actual amount of multiplications";
const UNIT_SIZE: &str = "bit size of a multiplication";

pub type Array256Bit = BitArray<[u8; 32], Lsb0>;

type BitSliceType = BitSlice<u8, Lsb0>;

const BIT_ARRAY_SHIFT: usize = 8;

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
    #[cfg(all(test, unit_test))]
    fn convert_prover<DF: DZKPBaseField>(&self) -> Vec<UVTupleBlock<DF>> {
        DF::convert_prover(
            &self.x_left,
            &self.x_right,
            &self.y_left,
            &self.y_right,
            &self.prss_right,
        )
    }

    /// `Convert` allows to convert `MultiplicationInputs` into a format compatible with DZKPs
    /// This is the convert function called by the verifier on the left.
    #[cfg(all(test, unit_test))]
    fn convert_verifier_left<DF: DZKPBaseField>(&self) -> Vec<DF> {
        DF::convert_verifier_left(
            &self.x_right,
            &self.y_right,
            &self.prss_right,
            &self.z_right,
        )
    }

    /// `Convert` allows to convert `MultiplicationInputs` into a format compatible with DZKPs
    /// This is the convert function called by the verifier on the right.
    #[cfg(all(test, unit_test))]
    fn convert_verifier_right<DF: DZKPBaseField>(&self) -> Vec<DF> {
        DF::convert_verifier_right(&self.x_left, &self.y_left, &self.prss_left)
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
/// `last_record` keeps track of the highest record that has been added to the batch.
/// `max_multiplications` is the maximum amount of multiplications performed within a this batch.
/// It is used to determine the vector length during the allocation.
/// If there are more multiplications, it will cause a panic!
/// `multiplication_bit_size` is the bit size of a single multiplication. The size will be consistent
/// across all multiplications of a gate.
/// `is_empty` keeps track of whether any value has been added
#[derive(Clone, Debug)]
struct MultiplicationInputsBatch {
    first_record: RecordId,
    last_record: RecordId,
    max_multiplications: usize,
    multiplication_bit_size: usize,
    is_empty: bool,
    vec: Vec<MultiplicationInputsBlock>,
}

impl MultiplicationInputsBatch {
    /// Creates a new store.
    /// `first_record` and `last_record` is initialized to `0`.
    /// The size of the allocated vector is `(max_multiplications * multiplication_bit_size + 255) / 256`
    fn new(max_multiplications: usize, multiplication_bit_size: usize) -> Self {
        Self {
            first_record: RecordId::FIRST,
            last_record: RecordId::FIRST,
            max_multiplications,
            multiplication_bit_size,
            is_empty: false,
            vec: vec![
                MultiplicationInputsBlock::default();
                (max_multiplications * multiplication_bit_size + 255) >> BIT_ARRAY_SHIFT
            ],
        }
    }

    /// `increment_record_ids` increments the current batch to the next set of records.
    /// it maintains all the allocated memory and increments the `RecordIds` as follows:
    /// It sets `last_record` and `first_record` to the record that follows `last_record`.
    fn increment_record_ids(&mut self) {
        // measure the amount of records stored using metrics
        // currently, MultiplicationInputsBatch does not store the Gate information, maybe we should store it here
        // such that we can add it to the metrics counter
        metrics::increment_counter!(DZKP_BATCH_INCREMENTS,
            ALLOCATED_AMOUNT => self.max_multiplications.to_string(),
            ACTUAL_AMOUNT => (usize::from(self.last_record)-usize::from(self.first_record)+1usize).to_string(),
            UNIT_SIZE => self.multiplication_bit_size.to_string(),
        );

        self.last_record += 1;
        self.first_record = self.last_record;

        // set it to empty
        self.is_empty = true;
    }

    /// returns whether the store is empty
    fn is_empty(&self) -> bool {
        self.is_empty
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

        // panics when record_id is out of bounds
        assert!(record_id >= self.first_record);
        assert!(
            record_id < RecordId::from(self.max_multiplications + usize::from(self.first_record))
        );

        // update last record
        self.last_record = cmp::max(self.last_record, record_id);

        // panics when record_id is too large to fit in, i.e. when it is out of bounds
        if segment.len() <= 256 {
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
        // check length
        debug_assert!(segment.len() <= 256);

        // panics when record_id is out of bounds
        assert!(record_id >= self.first_record);
        assert!(
            record_id < RecordId::from(self.max_multiplications + usize::from(self.first_record))
        );

        // panics when record_id is less than first_record
        let id_within_batch = usize::from(record_id) - usize::from(self.first_record);
        // round up segment length to a power of two since we want to have divisors of 256
        let length = segment.len().next_power_of_two();

        let block_id = (length * id_within_batch) >> BIT_ARRAY_SHIFT;
        // segments are small, pack one or more in each entry of `vec`
        let position_within_block_start = (length * id_within_batch) % 256;
        let position_within_block_end = position_within_block_start + segment.len();

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
        // check length
        debug_assert_eq!(segment.len() % 256, 0);

        // panics when record_id is out of bounds
        assert!(record_id >= self.first_record);
        assert!(
            record_id < RecordId::from(self.max_multiplications + usize::from(self.first_record))
        );

        let id_within_batch = usize::from(record_id) - usize::from(self.first_record);
        let block_id = (segment.len() * id_within_batch) >> BIT_ARRAY_SHIFT;

        let length_in_blocks = segment.len() >> BIT_ARRAY_SHIFT;
        for i in 0..length_in_blocks {
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
        }
    }

    /// `get_field_values_prover` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the prover of the DZKPs
    #[cfg(all(test, unit_test))]
    fn get_field_values_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = UVTupleBlock<DF>> + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_prover::<DF>)
    }

    /// `get_field_values_verifier_left` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the verifier of the DZKPs on the left side of the prover
    #[cfg(all(test, unit_test))]
    fn get_field_values_verifier_left<DF: DZKPBaseField>(&self) -> impl Iterator<Item = DF> + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_verifier_left::<DF>)
    }

    /// `get_field_values_verifier_right` converts a `MultiplicationInputsBatch` into an iterator over `field`
    /// values used by the verifier of the DZKPs on the right side of the prover
    #[cfg(all(test, unit_test))]
    fn get_field_values_verifier_right<DF: DZKPBaseField>(&self) -> impl Iterator<Item = DF> + '_ {
        self.vec
            .iter()
            .flat_map(MultiplicationInputsBlock::convert_verifier_right::<DF>)
    }
}

/// `Batch` collects a batch of `MultiplicationInputsBatch` in a hashmap.
/// The size of the batch is limited due to the memory costs and verifier specific constraints.
///
/// Corresponds to `AccumulatorState` of the MAC based malicious validator.
#[derive(Clone, Debug)]
struct Batch {
    max_multiplications_per_gate: usize,
    inner: HashMap<Gate, MultiplicationInputsBatch>,
}

impl Batch {
    fn new(max_multiplications_per_gate: usize) -> Self {
        Self {
            max_multiplications_per_gate,
            inner: HashMap::<Gate, MultiplicationInputsBatch>::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty() || self.inner.values().all(MultiplicationInputsBatch::is_empty)
    }

    fn push(&mut self, gate: Gate, record_id: RecordId, segment: Segment) {
        // get value_store & create new one when necessary
        // insert segment
        self.inner
            .entry(gate)
            .or_insert_with(|| {
                MultiplicationInputsBatch::new(self.max_multiplications_per_gate, segment.len())
            })
            .insert_segment(record_id, segment);
    }

    /// This function should only be called by `validate`!
    ///
    /// Updates all `MultiplicationInputsBatch` in hashmap by incrementing the record ids to next chunk
    ///
    /// ## Panics
    /// Panics when `MultiplicationInputsBatch` panics, i.e. when `segment_size` is `None`
    fn increment_record_ids(&mut self) {
        self.inner
            .values_mut()
            .for_each(MultiplicationInputsBatch::increment_record_ids);
    }

    /// `get_field_values_prover` converts a `Batch` into an iterator over field values
    /// which is used by the prover of the DZKP
    #[cfg(all(test, unit_test))]
    fn get_field_values_prover<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = UVTupleBlock<DF>> + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_prover::<DF>)
    }

    /// `get_field_values_verifier_left` converts a `Batch` into an iterator over field values
    /// which is used by the verifier of the DZKP on the left side of the prover
    #[cfg(all(test, unit_test))]
    fn get_field_values_verifier_left<DF: DZKPBaseField>(&self) -> impl Iterator<Item = DF> + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_verifier_left::<DF>)
    }

    /// `get_field_values_verifier_right` converts a `Batch` into an iterator over field values
    /// which is used by the verifier of the DZKP on the right side of the prover
    #[cfg(all(test, unit_test))]
    fn get_field_values_verifier_right<DF: DZKPBaseField>(&self) -> impl Iterator<Item = DF> + '_ {
        self.inner
            .values()
            .flat_map(MultiplicationInputsBatch::get_field_values_verifier_right::<DF>)
    }
}

/// Corresponds to `MaliciousAccumulator` of the MAC based malicious validator.
#[derive(Clone, Debug)]
pub struct DZKPBatch {
    inner: Weak<Mutex<Batch>>,
}

impl DZKPBatch {
    /// pushes values of a record, i.e. segment, to a `Batch`
    ///
    /// ## Panics
    /// Panics when mutex is poisoned or `segments` have different lengths within `gate`
    pub fn push(&self, gate: Gate, record_id: RecordId, segment: Segment) {
        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut batch = arc_mutex.lock().unwrap();
        batch.push(gate, record_id, segment);
        // LOCK END
    }

    /// ## Panics
    /// Panics when mutex is poisoned
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // return true if there is either no value (upgrade returns none) or there is a value but is_empty() is true
        !self
            .inner
            .upgrade()
            .is_some_and(|x| !x.lock().unwrap().is_empty())
    }
}

/// Validator Trait for DZKPs
/// It is different from the validator trait since context outputs a `DZKPUpgradedContext`
/// that is tied to a `DZKPBatch` rather than an `accumulator`.
/// Function signature of `validate` is also different, it does not downgrade shares anymore
#[async_trait]
pub trait DZKPValidator<B: UpgradableContext> {
    fn context(&self) -> B::DZKPUpgradedContext;

    /// Allows to validate the current `DZKPBatch` and empties it. The associated context is then
    /// considered safe until another multiplication is performed and thus new values are added
    /// to `DZKPBatch`.
    /// Currently only allows `Fp61BitPrime` and is not generic over `DZKPBaseFields`.
    ///
    /// `context_counter` allows to create distinct contexts
    /// when calling validate multiple times for the same base context.
    async fn validate(&self, chunk_counter: usize) -> Result<(), Error>;

    /// `is_verified` checks that there are no `MultiplicationInputs` that have not been verified
    /// within the associated `DZKPBatch`
    ///
    /// ## Errors
    /// Errors when there are `MultiplicationInputs` that have not been verified.
    fn is_verified(&self) -> Result<(), Error>;

    /// `validated_seq_join` in this trait is a validated version of `seq_join`. It splits the input stream into `chunks` where
    /// the `chunk_size` is specified as part of the input. Each `chunk` is a vector that is independently
    /// verified using `validator.validate()`, which uses DZKPs. Once the validation fails,
    /// the output stream will return an error.
    ///
    fn validated_seq_join<'st, S, F, O>(
        &'st self,
        chunk_size: usize,
        source: S,
    ) -> impl Stream<Item = Result<O, Error>> + 'st
    where
        S: Stream<Item = F> + Send + 'st,
        F: Future<Output = O> + Send + 'st,
        O: Send + Sync + Clone + 'static,
    {
        // chunk_size is undefined in the semi-honest setting, set it to 10, ideally it would be 1
        // but there is some overhead
        seq_join::<'st, S, F, O>(self.context().active_work(), source)
            .chunks(chunk_size)
            .enumerate()
            .then(move |(context_counter, chunk)| self.validate(context_counter).map_ok(|()| chunk))
            .try_flatten_iters()
    }
}

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
impl<'a, B: ShardBinding> DZKPValidator<SemiHonestContext<'a, B>>
    for SemiHonestDZKPValidator<'a, B>
{
    fn context(&self) -> SemiHonestDZKPUpgraded<'a, B> {
        self.context.clone()
    }

    async fn validate(&self, _context_counter: usize) -> Result<(), Error> {
        Ok(())
    }

    fn is_verified(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// `MaliciousDZKPValidator` corresponds to pub struct `Malicious` and implements the trait `DZKPValidator`
/// The implementation of `validate` of the `DZKPValidator` trait depends on generic `DF`
#[allow(dead_code)]
// dead code: validate_ctx is not used yet
pub struct MaliciousDZKPValidator<'a> {
    batch_ref: Arc<Mutex<Batch>>,
    protocol_ctx: MaliciousDZKPUpgraded<'a>,
    validate_ctx: Base<'a>,
}

#[async_trait]
impl<'a> DZKPValidator<MaliciousContext<'a>> for MaliciousDZKPValidator<'a> {
    fn context(&self) -> MaliciousDZKPUpgraded<'a> {
        self.protocol_ctx.clone()
    }

    /// ## Panics
    /// Panics when `context_counter` exceeds 256.
    async fn validate(&self, context_counter: usize) -> Result<(), Error> {
        assert!(context_counter <= 256);
        // LOCK BEGIN
        let mut batch = self.batch_ref.lock().unwrap();
        if batch.is_empty() {
            Ok(())
        } else {
            // todo: generate proofs and validate them using `batch_list`
            // use context_counter to generate a distinct context for each chunk
            // use get_values to get iterator over field elements for dzkp
            // update which empties batch_list and increments offsets to next chunk
            batch.increment_record_ids();
            Ok(())
        }
        // LOCK END
    }

    /// `is_verified` checks that there are no `MultiplicationInputs` that have not been verified.
    /// This function is called by drop() to ensure that the validator is safe to be dropped.
    ///
    /// ## Errors
    /// Errors when there are `MultiplicationInputs` that have not been verified.
    fn is_verified(&self) -> Result<(), Error> {
        if self.batch_ref.lock().unwrap().is_empty() {
            Ok(())
        } else {
            Err(Error::ContextUnsafe(format!("{:?}", self.protocol_ctx)))
        }
    }
}

impl<'a> MaliciousDZKPValidator<'a> {
    #[must_use]
    pub fn new(ctx: MaliciousContext<'a>, max_multiplications_per_gate: usize) -> Self {
        let list = Batch::new(max_multiplications_per_gate);
        let batch_list = Arc::new(Mutex::new(list));
        let dzkp_batch = DZKPBatch {
            inner: Arc::downgrade(&batch_list),
        };
        let validate_ctx = ctx.narrow(&Step::DZKPValidate).base_context();
        let protocol_ctx = ctx.dzkp_upgrade(&Step::DZKPMaliciousProtocol, dzkp_batch);
        Self {
            batch_ref: batch_list,
            protocol_ctx,
            validate_ctx,
        }
    }
}

impl<'a> Drop for MaliciousDZKPValidator<'a> {
    fn drop(&mut self) {
        self.is_verified().unwrap();
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{repeat, zip};

    use bitvec::{order::Lsb0, prelude::BitArray, vec::BitVec};
    use futures::TryStreamExt;
    use futures_util::stream::iter;
    use proptest::{prop_compose, proptest, sample::select};
    use rand::{thread_rng, Rng};

    use crate::{
        error::Error,
        ff::Fp61BitPrime,
        protocol::{
            basics::SecureMul,
            context::{
                dzkp_field::BLOCK_SIZE,
                dzkp_validator::{Batch, DZKPValidator, Segment, SegmentEntry, Step},
                Context, DZKPContext, UpgradableContext,
            },
            Gate, RecordId,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
        test_fixture::{join3v, Reconstruct, TestWorld},
    };

    /// test for testing `validated_seq_join`
    /// similar to `complex_circuit` in `validator.rs`
    async fn complex_circuit_dzkp(
        count: usize,
        chunk_size: usize,
        max_multiplications_per_gate: usize,
    ) -> Result<(), Error> {
        let world = TestWorld::default();

        let mut rng = thread_rng();

        let original_inputs = (0..count)
            .map(|_| rng.gen::<Fp61BitPrime>())
            .collect::<Vec<Fp61BitPrime>>();

        let shared_inputs: Vec<[Replicated<Fp61BitPrime>; 3]> = original_inputs
            .iter()
            .map(|x| x.share_with(&mut rng))
            .collect();
        let h1_shares: Vec<Replicated<Fp61BitPrime>> =
            shared_inputs.iter().map(|x| x[0].clone()).collect();
        let h2_shares: Vec<Replicated<Fp61BitPrime>> =
            shared_inputs.iter().map(|x| x[1].clone()).collect();
        let h3_shares: Vec<Replicated<Fp61BitPrime>> =
            shared_inputs.iter().map(|x| x[2].clone()).collect();

        // todo(DM): change to malicious once we can run the dzkps
        let futures = world
            .contexts()
            .into_iter()
            .zip([h1_shares.clone(), h2_shares.clone(), h3_shares.clone()])
            .map(|(ctx, input_shares)| async move {
                let v = ctx.dzkp_validator(max_multiplications_per_gate);
                // test whether narrow works
                let m_ctx = v.context().narrow(&Step::DZKPMaliciousProtocol);

                let m_results = v
                    .validated_seq_join(
                        chunk_size,
                        iter(
                            zip(
                                repeat(m_ctx.set_total_records(count - 1)).enumerate(),
                                zip(input_shares.iter(), input_shares.iter().skip(1)),
                            )
                            .map(
                                |((i, ctx), (a_malicious, b_malicious))| async move {
                                    a_malicious
                                        .multiply(b_malicious, ctx, RecordId::from(i))
                                        .await
                                        .unwrap()
                                },
                            ),
                        ),
                    )
                    .try_collect::<Vec<_>>()
                    .await?;
                // check whether verification was successful
                v.is_verified().unwrap();
                m_ctx.is_verified().unwrap();
                Ok::<_, Error>(m_results)
            });

        let processed_outputs_malicious = join3v(futures).await;

        let futures = world
            .contexts()
            .into_iter()
            .zip([h1_shares, h2_shares, h3_shares])
            .map(|(ctx, input_shares)| async move {
                let v = ctx.dzkp_validator(max_multiplications_per_gate);
                // test whether narrow works
                let m_ctx = v.context().narrow(&Step::DZKPMaliciousProtocol);

                let m_results = v
                    .validated_seq_join(
                        chunk_size,
                        iter(
                            zip(
                                repeat(m_ctx.set_total_records(count - 1)).enumerate(),
                                zip(input_shares.iter(), input_shares.iter().skip(1)),
                            )
                            .map(
                                |((i, ctx), (a_malicious, b_malicious))| async move {
                                    a_malicious
                                        .multiply(b_malicious, ctx, RecordId::from(i))
                                        .await
                                        .unwrap()
                                },
                            ),
                        ),
                    )
                    .try_collect::<Vec<_>>()
                    .await?;
                v.is_verified().unwrap();
                m_ctx.is_verified().unwrap();
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

    prop_compose! {
        fn arb_count_and_chunk()((log_count, log_chunk_size, log_multiplication_amount) in select(&[(5,5,5),(7,5,5),(5,7,8)])) -> (usize, usize, usize) {
            (1usize<<log_count, 1usize<<log_chunk_size, 1usize<<log_multiplication_amount)
        }
    }

    proptest! {
        #[test]
        fn test_complex_circuit_dzkp((count, chunk_size, multiplication_amount) in arb_count_and_chunk()){
            let future = async {
            let _ = complex_circuit_dzkp(count, chunk_size, multiplication_amount).await;
        };
        tokio::runtime::Runtime::new().unwrap().block_on(future);
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
        let vec_z_right = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_x_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
        let vec_y_3rd_share = (0..1024).map(|_| rng.gen::<u8>()).collect::<BitVec<u8>>();
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
            let mut batch_prover = Batch::new(1024 / segment_size);

            // generate batch for the verifier on the left of the prover
            let mut batch_left = Batch::new(1024 / segment_size);

            // generate batch for the verifier on the right of the prover
            let mut batch_right = Batch::new(1024 / segment_size);

            // fill the batches with random values
            populate_batch(
                segment_size,
                &mut batch_prover,
                &mut batch_left,
                &mut batch_right,
            );

            // check correctness of batch
            assert_batch_convert(&batch_prover, &batch_left, &batch_right);
        }
    }

    fn assert_batch_convert(batch_prover: &Batch, batch_left: &Batch, batch_right: &Batch) {
        batch_prover
            .get_field_values_prover::<Fp61BitPrime>()
            .zip(
                batch_left
                    .get_field_values_verifier_left::<Fp61BitPrime>()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .zip(
                batch_right
                    .get_field_values_verifier_right::<Fp61BitPrime>()
                    .collect::<Vec<[Fp61BitPrime; BLOCK_SIZE]>>(),
            )
            .for_each(|((prover, verifier_left), verifier_right)| {
                assert_eq!(prover.0, verifier_left);
                assert_eq!(prover.1, verifier_right);
            });
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
