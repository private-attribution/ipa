use std::{
    collections::HashMap,
    fmt::Debug,
    iter::repeat,
    sync::{Arc, Mutex, Weak},
};

use async_trait::async_trait;
use bitvec::{array::BitArray, prelude::Lsb0, slice::BitSlice};
use futures::{Future, Stream};
use futures_util::{StreamExt, TryFutureExt};

use crate::{
    error::Error,
    ff::Field,
    helpers::stream::TryFlattenItersExt,
    protocol::{
        context::{
            dzkp_malicious::DZKPUpgraded as MaliciousDZKPUpgraded,
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded, Base, Context,
            MaliciousContext, SemiHonestContext, UpgradableContext,
        },
        step::Gate,
        RecordId,
    },
    seq_join::{seq_join, SeqJoin},
    sharding::ShardBinding,
    telemetry::metrics::{DZKP_BATCH_REALLOCATION_BACK, DZKP_BATCH_REALLOCATION_FRONT},
};
// constants for metrics::increment_counter!
const RECORD: &str = "record";
const OFFSET: &str = "offset";

/// `UnverifiedValues` are intermediate values that occur during a multiplication.
/// These values need to be verified since there might have been malicious behavior.
/// For a multiplication, let `(x1, x2), (x2, x3), (x3,x1)`, `(y1, y2), (y2, y3), (y3,y1)` be the shares of `x` and `y`
/// and let the goal of the multiplication be to compute `x*y`.
/// `(pi, p(i+1)` is the randomness from `PRSS` used for the multiplication by helper `i`.
/// `z(i+1)` is the result of the multiplication received from the helper on the right.
/// We do not need to store `zi` since it can be computed from the other stored values.
#[derive(Clone, Debug)]
struct UnverifiedValues {
    x_left: BitArray<[u8; 32], Lsb0>,
    x_right: BitArray<[u8; 32], Lsb0>,
    y_left: BitArray<[u8; 32], Lsb0>,
    y_right: BitArray<[u8; 32], Lsb0>,
    prss_left: BitArray<[u8; 32], Lsb0>,
    prss_right: BitArray<[u8; 32], Lsb0>,
    z_right: BitArray<[u8; 32], Lsb0>,
}

impl UnverifiedValues {
    fn new() -> Self {
        Self {
            x_left: BitArray::ZERO,
            x_right: BitArray::ZERO,
            y_left: BitArray::ZERO,
            y_right: BitArray::ZERO,
            prss_left: BitArray::ZERO,
            prss_right: BitArray::ZERO,
            z_right: BitArray::ZERO,
        }
    }

    /// new from bitslices
    /// ## Panics
    /// Panics when length of slices is not 256
    fn new_from_bitslices(
        x_left: &BitSlice<u8, Lsb0>,
        x_right: &BitSlice<u8, Lsb0>,
        y_left: &BitSlice<u8, Lsb0>,
        y_right: &BitSlice<u8, Lsb0>,
        prss_left: &BitSlice<u8, Lsb0>,
        prss_right: &BitSlice<u8, Lsb0>,
        z_right: &BitSlice<u8, Lsb0>,
    ) -> Self {
        Self {
            x_left: BitArray::try_from(x_left).unwrap(),
            x_right: BitArray::try_from(x_right).unwrap(),
            y_left: BitArray::try_from(y_left).unwrap(),
            y_right: BitArray::try_from(y_right).unwrap(),
            prss_left: BitArray::try_from(prss_left).unwrap(),
            prss_right: BitArray::try_from(prss_right).unwrap(),
            z_right: BitArray::try_from(z_right).unwrap(),
        }
    }

    /// `Convert` allows to convert `UnverifiedValues` into a format compatible with DZKPs
    /// Converted values will take more space in memory.
    #[allow(dead_code)]
    fn convert<DF: DZKPBaseField>(&self) -> DF::UnverifiedFieldValues {
        DF::convert(
            &self.x_left,
            &self.x_right,
            &self.y_left,
            &self.y_right,
            &self.prss_left,
            &self.prss_right,
            &self.z_right,
        )
    }
}

/// `Segment` is a variable size set or subset of `UnverifiedValues` using a `BitSlice`
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
    pub fn new(
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
        // check that length is either multiple of 256 or 256 is multiple of length
        debug_assert!(x_left.len() % 256 == 0 || 256 % x_left.len() == 0);
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
pub struct SegmentEntry<'a>(&'a BitSlice<u8, Lsb0>);

impl<'a> SegmentEntry<'a> {
    #[must_use]
    pub fn new(entry: &'a BitSlice<u8, Lsb0>) -> Self {
        SegmentEntry(entry)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `UnverifiedValuesStore` stores a vector of `UnverifiedValues` together with an `offset`.
/// `offset` is the minimum `RecordId` for the current batch.
/// `chunk_size` is the amount of records within a single batch. It is used to estimate the vector length
/// during the allocation.
/// `segment_size` is an option and set to `Some` once we receive the first segment and thus know the size.
///
/// `vec` is a `Vec<Option>` such that we can initialize the whole vector with `None` and access any
/// location out of order. This is important since we do not now the order in which different records
/// are added to the `UnverifiedValueStore`.
/// It is not to keep track whether all relevant records have been added. The verification will fail
/// when a helper party forgets to include one of the records. We could add a check separate from the proof
/// such that this does not count as malicious behavior.
#[derive(Clone, Debug)]
struct UnverifiedValuesStore {
    offset: RecordId,
    chunk_size: usize,
    segment_size: Option<usize>,
    vec: Vec<Option<UnverifiedValues>>,
}

impl UnverifiedValuesStore {
    /// Creates a new store for given `chunk_size`. `offset` is initialized to `0`.
    /// Lazy allocation of the vector. It is allocated once the first segment is added.
    /// `segment_size` is set to `None` since it may not be known yet
    fn new(chunk_size: usize) -> Self {
        Self {
            offset: RecordId::from(0usize),
            chunk_size,
            segment_size: None,
            vec: Vec::<Option<UnverifiedValues>>::new(),
        }
    }

    /// `update` updates the current store to the next offset which is the previous offset plus `vec.actual_len()`.
    /// It deallocates `vec`. `chunk_size` remains the same.
    /// `update` does nothing when `self` is empty, i.e. `vec` is empty.
    ///
    /// ## Panics
    /// Panics when `segment_size` is `None`
    fn update(&mut self) {
        if !self.is_unallocated() {
            // compute how many records have been added
            // since `actual_length` is imprecise (i.e. rounded up) for segments smaller than 256,
            // subtract `1` to make sure that offset is set sufficiently small
            self.offset += ((self.actual_len() - 1) << 8) / self.segment_size.unwrap();
            self.vec = Vec::<Option<UnverifiedValues>>::new();
        }
    }

    /// `actual_len` computes the index of the last actual element plus `1`
    fn actual_len(&self) -> usize {
        self.vec
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |pos| pos + 1)
    }

    /// `is_empty` returns `true` when no segment has been added
    fn is_empty(&self) -> bool {
        self.vec.iter().all(Option::is_none)
    }

    /// `is_unallocated` returns `true` when the associated vector has not been allocated
    fn is_unallocated(&self) -> bool {
        self.vec.is_empty()
    }

    fn initialize_segment_size(&mut self, segment_size: usize) {
        self.segment_size = Some(segment_size);
    }

    /// `allocate_vec` allocates `vec`. The length is determined by the amount
    /// of records, i.e. `chunk_size` and the size of a record, i.e. `segment_size`.
    /// ## Panics
    /// Panics when `segment_size` is `None`.
    fn allocate_vec(&mut self) {
        // add 255 to round up
        self.vec = vec![None; (self.chunk_size * self.segment_size.unwrap() + 255) >> 8];
    }

    /// `reset_offset` reallocates vector such that a smaller `RecordId` than `offset` can be stored
    /// `new_offset` will be the new `offset` and the store and store elements with `RecordId` `new_offset` and larger
    /// when `new_offset` is larger that the current `offset`, the function does nothing
    fn reset_offset(&mut self, new_offset: RecordId, segment_length: usize) {
        if new_offset < self.offset {
            // metrics to count reallocations, disable-metrics flag will disable it globally
            // right now, I don't pass the gate/step information which would be useful
            // it would require to change the function signature and potentially clone gate even when feature is not enabled
            metrics::increment_counter!(DZKP_BATCH_REALLOCATION_FRONT, RECORD => new_offset.to_string(), OFFSET => self.offset.to_string());

            let mut new_offset = usize::from(new_offset);
            // if segment_length is less than 256, redefine new offset such that we don't need to rearrange the existing segments
            if 256 % segment_length == 0 {
                // distance between new_offset and old offset is rounded up to a multiple of 256
                new_offset = ((usize::from(self.offset) - new_offset + 255) >> 8) << 8;
            }
            let extension_length = ((usize::from(self.offset) - new_offset) >> 8) * segment_length;
            // use existing vec and add enough space in front
            self.vec.splice(0..0, repeat(None).take(extension_length));
            self.offset = RecordId::from(new_offset);
        }
    }

    /// `insert_segment` allows to include a new segment in `UnverifiedValuesStore`
    ///
    /// ## Panics
    /// Panics when segments have different lengths across records
    fn insert_segment(&mut self, record_id: RecordId, segment: Segment) {
        // initialize `segment_size` when necessary
        if self.segment_size.is_none() {
            self.initialize_segment_size(segment.len());
        }
        // check segment size
        debug_assert_eq!(segment.len(), self.segment_size.unwrap());
        // allocate if vec is not allocated yet
        if self.is_unallocated() {
            self.allocate_vec();
        }
        // check offset
        if record_id < self.offset {
            // recover from wrong offset, expensive
            self.reset_offset(record_id, segment.len());
        }
        let position_raw = usize::from(record_id) - usize::from(self.offset);
        let length = segment.len();
        let position_vec = (length * position_raw) >> 8;
        // check size of store
        if self.vec.len() < position_vec + (length >> 8) {
            // recover from wrong size
            // increase size of store to twice the size + position of end of the segment to be included
            // expensive, ideally use initialize with correct length
            self.vec
                .resize(self.vec.len() + position_vec + (length >> 8), None);
            // metrics to count reallocations, disable-metrics flag will disable it globally
            // right now, I don't pass the gate/step information which would be useful
            // it would require to change the function signature and potentially clone gate even when feature is not enabled
            metrics::increment_counter!(DZKP_BATCH_REALLOCATION_BACK, RECORD => record_id.to_string(), OFFSET => self.offset.to_string());
        }

        if 256 % length == 0 {
            // segments are small, pack one or more in each entry of `vec`
            let position_bit_array = (length * position_raw) % 256;

            // get entry
            let entry = self.vec[position_vec].get_or_insert_with(UnverifiedValues::new);

            // copy segment value into entry
            for (segment_value, mut array_value) in [
                (segment.x_left, entry.x_left),
                (segment.x_right, entry.x_right),
                (segment.y_left, entry.y_left),
                (segment.y_right, entry.y_right),
                (segment.prss_left, entry.prss_left),
                (segment.prss_right, entry.prss_right),
                (segment.z_right, entry.z_right),
            ] {
                // unwrap safe since index are guaranteed to be within bounds
                let values_in_array = array_value.get_mut(position_bit_array..length).unwrap();
                values_in_array.clone_from_bitslice(segment_value.0);
            }
        } else {
            // segments are multiples of 256
            let length_in_entries = length >> 8;
            for i in 0..length_in_entries {
                let entry_option = &mut self.vec[position_vec + i];
                // make sure we don't overwrite values
                debug_assert!(entry_option.is_none());
                *entry_option = Some(UnverifiedValues::new_from_bitslices(
                    &segment.x_left.0[256 * i..256 * (i + 1)],
                    &segment.x_right.0[256 * i..256 * (i + 1)],
                    &segment.y_left.0[256 * i..256 * (i + 1)],
                    &segment.y_right.0[256 * i..256 * (i + 1)],
                    &segment.prss_left.0[256 * i..256 * (i + 1)],
                    &segment.prss_right.0[256 * i..256 * (i + 1)],
                    &segment.z_right.0[256 * i..256 * (i + 1)],
                ));
            }
        }
    }

    /// `get_unverified_field_value` converts a `UnverifiedValuesStore` into an iterator over `UnverifiedFieldValues`
    /// compatible with DZKPs
    #[allow(dead_code)]
    fn get_unverified_field_values<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF::UnverifiedFieldValues> + '_ {
        self.vec
            .iter()
            .flatten()
            .map(UnverifiedValues::convert::<DF>)
    }
}

/// `Batch` collects a batch of `UnverifiedValuesStore` in a hashmap.
/// The size of the batch is limited due to the memory costs and verifier specific constraints.
///
/// Corresponds to `AccumulatorState` of the MAC based malicious validator.
#[derive(Clone, Debug)]
struct Batch {
    chunk_size: usize,
    inner: HashMap<Gate, UnverifiedValuesStore>,
}

impl Batch {
    fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            inner: HashMap::<Gate, UnverifiedValuesStore>::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty() || self.inner.values().all(UnverifiedValuesStore::is_empty)
    }

    fn push(&mut self, gate: Gate, record_id: RecordId, segment: Segment) {
        // get value_store & create new when necessary
        // insert segment
        self.inner
            .entry(gate)
            .or_insert_with(|| UnverifiedValuesStore::new(self.chunk_size))
            .insert_segment(record_id, segment);
    }

    /// This function should only be called by `validate`!
    ///
    /// Updates all `UnverifiedValueStores` in hashmap by incrementing the offset to next chunk
    /// and deallocating `vec`.
    ///
    /// ## Panics
    /// Panics when `UnverifiedValuesStore` panics, i.e. when `segment_size` is `None`
    fn update(&mut self) {
        self.inner
            .values_mut()
            .for_each(UnverifiedValuesStore::update);
    }

    /// `get_unverified_field_value` converts a `Batch` into an iterator over `UnverifiedFieldValues`
    /// compatible with DZKPs
    #[allow(dead_code)]
    fn get_unverified_field_values<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF::UnverifiedFieldValues> + '_ {
        self.inner
            .values()
            .flat_map(UnverifiedValuesStore::get_unverified_field_values::<DF>)
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

/// Steps used by the validation component of the DZKP
#[cfg_attr(feature = "descriptive-gate", derive(ipa_macros::Step))]
pub(crate) enum Step {
    /// For the execution of the malicious protocol.
    DZKPMaliciousProtocol,
    /// Step for validating the DZK proof.
    DZKPValidate,
}

/// Marker Trait `DZKPBaseField` for fields that can be used as base for DZKP proofs and their verification
/// This is different from trait `DZKPCompatibleField` which is the base for the MPC protocol
pub trait DZKPBaseField: Field {
    type UnverifiedFieldValues;
    fn convert(
        x_left: &BitArray<[u8; 32], Lsb0>,
        x_right: &BitArray<[u8; 32], Lsb0>,
        y_left: &BitArray<[u8; 32], Lsb0>,
        y_right: &BitArray<[u8; 32], Lsb0>,
        prss_left: &BitArray<[u8; 32], Lsb0>,
        prss_right: &BitArray<[u8; 32], Lsb0>,
        z_right: &BitArray<[u8; 32], Lsb0>,
    ) -> Self::UnverifiedFieldValues;
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
    /// Is generic over `DZKPBaseFields`. Please specify a sufficiently large field for the current `DZKPBatch`.
    async fn validate<DF: DZKPBaseField>(&self) -> Result<(), Error>;

    /// `is_safe` checks that there are no remaining `UnverifiedValues` within the associated `DZKPBatch`
    ///
    /// ## Errors
    /// Errors when there are `UnverifiedValues` left.
    fn is_safe(&self) -> Result<(), Error>;

    /// `get_chunk_size` returns the chunk size of the validator
    fn get_chunk_size(&self) -> Option<usize>;

    /// `seq_join` in this trait is a validated version of `seq_join`. It splits the input stream into `chunks` where
    /// the `chunk_size` is defined within `validator`. Each `chunk` is a vector that is independently
    /// verified using `validator.validate()`, which uses DZKPs. Once the validation fails,
    /// the output stream will return that the stream is done.
    ///
    fn seq_join<'st, S, F, O, DF>(
        &'st self,
        source: S,
    ) -> impl Stream<Item = Result<O, Error>> + 'st
    where
        S: Stream<Item = F> + Send + 'st,
        F: Future<Output = O> + Send + 'st,
        O: Send + Sync + Clone + 'static,
        DF: DZKPBaseField,
    {
        // chunk_size is undefined in the semi-honest setting, set it to 10, ideally it would be 1
        // but there is some overhead
        let chunk_size = self.get_chunk_size().unwrap_or(10usize);
        seq_join::<'st, S, F, O>(self.context().active_work(), source)
            .chunks(chunk_size)
            .then(move |chunk| self.validate::<DF>().map_ok(|()| chunk))
            .try_flatten_iters()
    }
}

pub struct SemiHonestDZKPValidator<'a, B: ShardBinding> {
    context: SemiHonestDZKPUpgraded<'a, B>,
}

impl<'a, B: ShardBinding> SemiHonestDZKPValidator<'a, B> {
    pub(super) fn new(inner: Base<'a, B>) -> Self {
        // This is inconsistent with the malicious new() which calls dzkp_upgrade
        // following previous semi honest validator
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

    async fn validate<DF: DZKPBaseField>(&self) -> Result<(), Error> {
        Ok(())
    }

    fn is_safe(&self) -> Result<(), Error> {
        Ok(())
    }

    fn get_chunk_size(&self) -> Option<usize> {
        None
    }
}

/// `MaliciousDZKPValidator` corresponds to pub struct `Malicious` and implements the trait `DZKPValidator`
/// The implementation of `validate` of the `DZKPValidator` trait depends on generic `DF`
#[allow(dead_code)]
#[cfg(feature = "descriptive-gate")]
// dead code: validate_ctx is not used yet
pub struct MaliciousDZKPValidator<'a> {
    batch_ref: Arc<Mutex<Batch>>,
    protocol_ctx: MaliciousDZKPUpgraded<'a>,
    validate_ctx: Base<'a>,
}

#[cfg(feature = "descriptive-gate")]
#[async_trait]
impl<'a> DZKPValidator<MaliciousContext<'a>> for MaliciousDZKPValidator<'a> {
    fn context(&self) -> MaliciousDZKPUpgraded<'a> {
        self.protocol_ctx.clone()
    }

    async fn validate<DF: DZKPBaseField>(&self) -> Result<(), Error> {
        // LOCK BEGIN
        let mut batch = self.batch_ref.lock().unwrap();
        if batch.is_empty() {
            Ok(())
        } else {
            // todo: generate proofs and validate them using `batch_list`
            // use get_values to get iterator over `UnverifiedFieldValues`
            //batch.get_unverified_field_values::<DF>()
            // update which empties batch_list and increments offsets to next chunk
            batch.update();
            Ok(())
        }
        // LOCK END
    }

    /// `is_safe` checks that there are no `UnverifiedValues`.
    /// This function is called by drop() to ensure that the validator is safe to be dropped.
    ///
    /// ## Errors
    /// Errors when there are `UnverifiedValues` left.
    fn is_safe(&self) -> Result<(), Error> {
        if self.batch_ref.lock().unwrap().is_empty() {
            Ok(())
        } else {
            Err(Error::ContextUnsafe(format!("{:?}", self.protocol_ctx)))
        }
    }

    fn get_chunk_size(&self) -> Option<usize> {
        Some(self.batch_ref.lock().unwrap().chunk_size)
    }
}

#[cfg(feature = "descriptive-gate")]
impl<'a> MaliciousDZKPValidator<'a> {
    #[must_use]
    pub fn new(ctx: MaliciousContext<'a>, chunk_size: usize) -> Self {
        let list = Batch::new(chunk_size);
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

#[cfg(feature = "descriptive-gate")]
impl<'a> Drop for MaliciousDZKPValidator<'a> {
    fn drop(&mut self) {
        self.is_safe().unwrap();
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{repeat, zip};

    use bitvec::{array::BitArray, order::Lsb0};
    use futures::TryStreamExt;
    use futures_util::stream::iter;
    use rand::{thread_rng, Rng};

    use crate::{
        error::Error,
        ff::Fp31,
        protocol::{
            basics::SecureMul,
            context::{
                dzkp_validator::{DZKPBaseField, DZKPValidator},
                Context, UpgradableContext,
            },
            RecordId,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
        test_fixture::{join3v, Reconstruct, TestWorld},
    };

    // todo: remove impl and add support for BooleanTypes
    impl DZKPBaseField for Fp31 {
        type UnverifiedFieldValues = ();

        fn convert(
            _x_left: &BitArray<[u8; 32], Lsb0>,
            _x_right: &BitArray<[u8; 32], Lsb0>,
            _y_left: &BitArray<[u8; 32], Lsb0>,
            _y_right: &BitArray<[u8; 32], Lsb0>,
            _prss_left: &BitArray<[u8; 32], Lsb0>,
            _prss_right: &BitArray<[u8; 32], Lsb0>,
            _z_right: &BitArray<[u8; 32], Lsb0>,
        ) {
        }
    }

    /// test for testing `validated_seq_join`
    /// similar to `complex_circuit` in `validator.rs`
    #[tokio::test]
    async fn complex_circuit_dzkp() -> Result<(), Error> {
        const COUNT: usize = 100;
        let world = TestWorld::default();
        let context = world.malicious_contexts();
        let mut rng = thread_rng();
        let chunk_size: usize = 1 << rng.gen_range(1..10);

        let mut original_inputs = Vec::with_capacity(COUNT);
        for _ in 0..COUNT {
            let x = rng.gen::<Fp31>();
            original_inputs.push(x);
        }
        let shared_inputs: Vec<[Replicated<Fp31>; 3]> = original_inputs
            .iter()
            .map(|x| x.share_with(&mut rng))
            .collect();
        let h1_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[0].clone()).collect();
        let h2_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[1].clone()).collect();
        let h3_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[2].clone()).collect();

        let futures = context
            .into_iter()
            .zip([h1_shares, h2_shares, h3_shares])
            .map(|(ctx, input_shares)| async move {
                let v = ctx.dzkp_validator(chunk_size);
                let m_ctx = v.context();

                let m_results = v
                    .seq_join::<_, _, _, Fp31>(iter(
                        zip(
                            repeat(m_ctx.set_total_records(COUNT - 1)).enumerate(),
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
                    ))
                    .try_collect::<Vec<_>>()
                    .await?;
                Ok::<_, Error>(m_results)
            });

        let processed_outputs = join3v(futures).await;

        for i in 0..99 {
            let x1 = original_inputs[i];
            let x2 = original_inputs[i + 1];
            let x1_times_x2 = [
                processed_outputs[0][i].clone(),
                processed_outputs[1][i].clone(),
                processed_outputs[2][i].clone(),
            ]
            .reconstruct();

            assert_eq!((x1, x2, x1 * x2), (x1, x2, x1_times_x2));
        }

        Ok(())
    }
}
