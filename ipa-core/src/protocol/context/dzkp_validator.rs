#[cfg(feature = "descriptive-gate")]
use std::sync::Arc;
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Mutex, Weak},
};

use async_trait::async_trait;
use bitvec::{array::BitArray, prelude::Lsb0, slice::BitSlice};
use futures::{Future, Stream};
use futures_util::{StreamExt, TryFutureExt};

#[cfg(feature = "descriptive-gate")]
use crate::protocol::context::{
    dzkp_malicious::DZKPUpgraded as MaliciousDZKPUpgraded, Context, MaliciousContext,
};
use crate::{
    error::{BoxError, Error},
    helpers::stream::TryFlattenItersExt,
    protocol::{
        context::{
            dzkp_field::DZKPBaseField, dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded,
            Base, SemiHonestContext, UpgradableContext,
        },
        step::Gate,
        RecordId,
    },
    seq_join::{seq_join, SeqJoin},
    sharding::ShardBinding,
    telemetry::metrics::DZKP_BATCH_UPDATE,
};

// constants for metrics::increment_counter!
const ALLOCATED_AMOUNT: &str = "allocated amount of multiplications";
const ACTUAL_AMOUNT: &str = "actual amount of multiplications";
const UNIT_SIZE: &str = "bit size of a multiplication";

pub type Array256Bit = BitArray<[u8; 32], Lsb0>;

type BitSliceType = BitSlice<u8, Lsb0>;

const BIT_ARRAY_SHIFT: usize = 8;

/// `UnverifiedValues` are intermediate values that occur during a multiplication.
/// These values need to be verified since there might have been malicious behavior.
/// For a multiplication, let `(x1, x2), (x2, x3), (x3,x1)`, `(y1, y2), (y2, y3), (y3,y1)` be the shares of `x` and `y`
/// and let the goal of the multiplication be to compute `x*y`.
/// `(pi, p(i+1)` is the randomness from `PRSS` used for the multiplication by helper `i`.
/// `z(i+1)` is the result of the multiplication received from the helper on the right.
/// We do not need to store `zi` since it can be computed from the other stored values.
#[derive(Clone, Debug)]
struct UnverifiedValues {
    x_left: Array256Bit,
    x_right: Array256Bit,
    y_left: Array256Bit,
    y_right: Array256Bit,
    prss_left: Array256Bit,
    prss_right: Array256Bit,
    z_right: Array256Bit,
}

impl Default for UnverifiedValues {
    fn default() -> Self {
        UnverifiedValues {
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

impl UnverifiedValues {
    /// new from bitslices
    /// ## Errors
    /// Errors when length of slices is not 256
    fn new(
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

/// `UnverifiedValuesStore` stores a vector of `UnverifiedValues` together with an `offset`.
/// `first_record_of_batch` is the first `RecordId` for the current batch.
/// `last_record_of_batch` keeps track of the highest record that has been added to the batch.
/// `multiplication_amount` is the maximum amount of multiplications performed within a single batch.
/// It is used to determine the vector length during the allocation.
/// If there are more multiplications, it will cause a panic!
/// `multiplication_bit_size` is an option and set to `Some` once we receive the first segment and thus know the size.
/// `is_empty` keeps track of whether any value has been added
///
/// `vec` is a `Vec<Option>` such that we can initialize the whole vector with `None` and access any
/// location out of order. This is important since we do not now the order in which different records
/// are added to the `UnverifiedValueStore`.
/// It is not to keep track whether all relevant records have been added. The verification will fail
/// when a helper party forgets to include one of the records. We could add a check separate from the proof
/// such that this does not count as malicious behavior.
#[derive(Clone, Debug)]
struct UnverifiedValuesStore {
    first_record_of_batch: RecordId,
    last_record_of_batch: RecordId,
    multiplication_amount: usize,
    multiplication_bit_size: usize,
    is_empty: bool,
    vec: Vec<UnverifiedValues>,
}

impl UnverifiedValuesStore {
    /// Creates a new store.
    /// `first_record_id_of_batch` and `last_record_of_batch` is initialized to `0`.
    /// The size of the allocated vector is `(amount_of_multiplications * multiplication_bit_size + 255) / 256`
    fn new(amount_of_multiplications: usize, multiplication_bit_size: usize) -> Self {
        Self {
            first_record_of_batch: RecordId::FIRST,
            last_record_of_batch: RecordId::FIRST,
            multiplication_amount: amount_of_multiplications,
            multiplication_bit_size,
            is_empty: false,
            vec: vec![
                UnverifiedValues::default();
                (amount_of_multiplications * multiplication_bit_size + 255) >> BIT_ARRAY_SHIFT
            ],
        }
    }

    /// `update` updates the current store to the next chunk of records.
    /// It sets `last_record_of_batch` and `first_record_of_batch` to the record that follows `last_record_of_batch`.
    fn update(&mut self) {
        // measure the amount of records stored using metrics
        // currently, UnverifiedValueStore does not store the Gate information, maybe we should store it here
        // such that we can add it to the metrics counter
        metrics::increment_counter!(DZKP_BATCH_UPDATE,
            ALLOCATED_AMOUNT => self.multiplication_amount.to_string(),
            ACTUAL_AMOUNT => (usize::from(self.last_record_of_batch)-usize::from(self.first_record_of_batch)+1usize).to_string(),
            UNIT_SIZE => self.multiplication_bit_size.to_string(),
        );

        self.last_record_of_batch += 1;
        self.first_record_of_batch = self.last_record_of_batch;

        // set it to empty
        self.is_empty = true;
    }

    /// returns whether the store is empty
    fn is_empty(&self) -> bool {
        self.is_empty
    }

    /// `insert_segment` allows to include a new segment in `UnverifiedValuesStore`
    ///
    /// ## Panics
    /// Panics when segments have different lengths across records, the `record_id` is less than
    /// `first_record_of_batch` or when `record_id` is more than `first_record_of_batch + multiplication_amount`,
    /// i.e. not enough space has been allocated.
    fn insert_segment(&mut self, record_id: RecordId, segment: Segment) {
        // check segment size
        debug_assert_eq!(segment.len(), self.multiplication_bit_size);

        // update last record
        if self.last_record_of_batch < record_id {
            self.last_record_of_batch = record_id;
        }

        // panics when record_id is less than first_record_of_batch
        let position_raw = usize::from(record_id) - usize::from(self.first_record_of_batch);
        let length = segment.len();
        let position_vec = (length * position_raw) >> BIT_ARRAY_SHIFT;

        // panics when record_id is too large to fit in, i.e. when it is out of bounds
        if 256 % length == 0 {
            self.insert_segment_small(length, position_raw, position_vec, segment);
        } else {
            self.insert_segment_large(length, position_vec, &segment);
        }
    }

    /// insert `segments` for `segments` that divide 256
    ///
    /// ## Panics
    /// Panics when `length` and `positions` are out of bounds.
    fn insert_segment_small(
        &mut self,
        length: usize,
        position_raw: usize,
        position_vec: usize,
        segment: Segment,
    ) {
        // segments are small, pack one or more in each entry of `vec`
        let position_bit_array = (length * position_raw) % 256;

        let unverified_values = &mut self.vec[position_vec];

        // copy segment value into entry
        for (segment_value, array_value) in [
            (segment.x_left, &mut unverified_values.x_left),
            (segment.x_right, &mut unverified_values.x_right),
            (segment.y_left, &mut unverified_values.y_left),
            (segment.y_right, &mut unverified_values.y_right),
            (segment.prss_left, &mut unverified_values.prss_left),
            (segment.prss_right, &mut unverified_values.prss_right),
            (segment.z_right, &mut unverified_values.z_right),
        ] {
            // panics when out of bounds
            let values_in_array = array_value
                .get_mut(position_bit_array..position_bit_array + length)
                .unwrap();
            values_in_array.clone_from_bitslice(segment_value.0);
        }
    }

    /// insert `segments` for `segments` that are multiples of 256
    ///
    /// ## Panics
    /// Panics when segment is not a multiple of 256 or is out of bounds.
    fn insert_segment_large(&mut self, length: usize, position_vec: usize, segment: &Segment) {
        let length_in_entries = length >> BIT_ARRAY_SHIFT;
        for i in 0..length_in_entries {
            self.vec[position_vec + i] = UnverifiedValues::new(
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

    /// `get_unverified_field_value` converts a `UnverifiedValuesStore` into an iterator over `UnverifiedFieldValues`
    /// compatible with DZKPs
    #[allow(dead_code)]
    fn get_unverified_field_values<DF: DZKPBaseField>(
        &self,
    ) -> impl Iterator<Item = DF::UnverifiedFieldValues> + '_ {
        self.vec.iter().map(UnverifiedValues::convert::<DF>)
    }
}

/// `Batch` collects a batch of `UnverifiedValuesStore` in a hashmap.
/// The size of the batch is limited due to the memory costs and verifier specific constraints.
///
/// Corresponds to `AccumulatorState` of the MAC based malicious validator.
#[derive(Clone, Debug)]
struct Batch {
    multiplication_amount: usize,
    inner: HashMap<Gate, UnverifiedValuesStore>,
}

impl Batch {
    fn new(multiplication_amount: usize) -> Self {
        Self {
            multiplication_amount,
            inner: HashMap::<Gate, UnverifiedValuesStore>::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty() || self.inner.values().all(UnverifiedValuesStore::is_empty)
    }

    fn push(&mut self, gate: Gate, record_id: RecordId, segment: Segment) {
        // get value_store & create new one when necessary
        // insert segment
        self.inner
            .entry(gate)
            .or_insert_with(|| {
                UnverifiedValuesStore::new(self.multiplication_amount, segment.len())
            })
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

    /// `is_verified` checks that there are no remaining `UnverifiedValues` within the associated `DZKPBatch`
    ///
    /// ## Errors
    /// Errors when there are `UnverifiedValues` left.
    fn is_verified(&self) -> Result<(), Error>;

    /// `validated_seq_join` in this trait is a validated version of `seq_join`. It splits the input stream into `chunks` where
    /// the `chunk_size` is specified as part of the input. Each `chunk` is a vector that is independently
    /// verified using `validator.validate()`, which uses DZKPs. Once the validation fails,
    /// the output stream will return an error.
    ///
    fn validated_seq_join<'st, S, F, O, DF>(
        &'st self,
        chunk_size: usize,
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

    fn is_verified(&self) -> Result<(), Error> {
        Ok(())
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

    /// `is_verified` checks that there are no `UnverifiedValues`.
    /// This function is called by drop() to ensure that the validator is safe to be dropped.
    ///
    /// ## Errors
    /// Errors when there are `UnverifiedValues` left.
    fn is_verified(&self) -> Result<(), Error> {
        if self.batch_ref.lock().unwrap().is_empty() {
            Ok(())
        } else {
            Err(Error::ContextUnsafe(format!("{:?}", self.protocol_ctx)))
        }
    }
}

#[cfg(feature = "descriptive-gate")]
impl<'a> MaliciousDZKPValidator<'a> {
    #[must_use]
    pub fn new(ctx: MaliciousContext<'a>, multiplication_amount: usize) -> Self {
        let list = Batch::new(multiplication_amount);
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
        self.is_verified().unwrap();
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{repeat, zip};

    use bitvec::{field::BitField, vec::BitVec};
    use futures::TryStreamExt;
    use futures_util::stream::iter;
    use proptest::{prop_compose, proptest, sample::select};
    use rand::{thread_rng, Rng};

    use crate::{
        error::Error,
        ff::{Fp31, U128Conversions},
        protocol::{
            basics::SecureMul,
            context::{
                dzkp_field::DZKPBaseField,
                dzkp_validator::{Array256Bit, Batch, DZKPValidator, Segment, SegmentEntry, Step},
                Context, DZKPContext, UpgradableContext,
            },
            step::Gate,
            RecordId,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
        test_fixture::{join3v, Reconstruct, TestWorld},
    };

    /// test for testing `validated_seq_join`
    /// similar to `complex_circuit` in `validator.rs`
    async fn complex_circuit_dzkp(
        count: usize,
        chunk_size: usize,
        multiplication_amount: usize,
    ) -> Result<(), Error> {
        let world = TestWorld::default();

        let mut rng = thread_rng();

        let mut original_inputs = Vec::with_capacity(count);
        for _ in 0..count {
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

        // todo(DM): change to malicious once we can run the dzkps
        let futures = world
            .contexts()
            .into_iter()
            .zip([h1_shares.clone(), h2_shares.clone(), h3_shares.clone()])
            .map(|(ctx, input_shares)| async move {
                let v = ctx.dzkp_validator(multiplication_amount);
                // test whether narrow works
                let m_ctx = v.context().narrow(&Step::DZKPMaliciousProtocol);

                let m_results = v
                    .validated_seq_join::<_, _, _, Fp31>(
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
                let v = ctx.dzkp_validator(chunk_size);
                // test whether narrow works
                let m_ctx = v.context().narrow(&Step::DZKPMaliciousProtocol);

                let m_results = v
                    .validated_seq_join::<_, _, _, Fp31>(
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

    pub struct UnverifiedFp31Values {
        x_left: Vec<Fp31>,
        x_right: Vec<Fp31>,
        y_left: Vec<Fp31>,
        y_right: Vec<Fp31>,
        prss_left: Vec<Fp31>,
        prss_right: Vec<Fp31>,
        z_right: Vec<Fp31>,
    }

    impl DZKPBaseField for Fp31 {
        type UnverifiedFieldValues = UnverifiedFp31Values;

        fn convert(
            x_left: &Array256Bit,
            x_right: &Array256Bit,
            y_left: &Array256Bit,
            y_right: &Array256Bit,
            prss_left: &Array256Bit,
            prss_right: &Array256Bit,
            z_right: &Array256Bit,
        ) -> Self::UnverifiedFieldValues {
            UnverifiedFp31Values {
                x_left: x_left
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                x_right: x_right
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                y_left: y_left
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                y_right: y_right
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                prss_left: prss_left
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                prss_right: prss_right
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
                z_right: z_right
                    .chunks(8)
                    .map(|x| Fp31::truncate_from(x.load_le::<u8>()))
                    .collect(),
            }
        }
    }

    #[test]
    fn batch_and_convert() {
        let mut rng = thread_rng();

        // test for small and large segments, i.e. 8bit and 512 bit
        for segment_size in [8usize, 512usize] {
            // chunk size is equal to amount of segments which is 1024/segment_size
            let mut batch = Batch::new(1024 / segment_size);

            // vec to collect expected
            let mut expected_x_left = Vec::<Fp31>::new();
            let mut expected_x_right = Vec::<Fp31>::new();
            let mut expected_y_left = Vec::<Fp31>::new();
            let mut expected_y_right = Vec::<Fp31>::new();
            let mut expected_prss_left = Vec::<Fp31>::new();
            let mut expected_prss_right = Vec::<Fp31>::new();
            let mut expected_z_right = Vec::<Fp31>::new();

            // vec for segments
            let mut vec_x_left = Vec::<u8>::new();
            let mut vec_x_right = Vec::<u8>::new();
            let mut vec_y_left = Vec::<u8>::new();
            let mut vec_y_right = Vec::<u8>::new();
            let mut vec_prss_left = Vec::<u8>::new();
            let mut vec_prss_right = Vec::<u8>::new();
            let mut vec_z_right = Vec::<u8>::new();

            // gen 1024 random values
            for _i in 0..1024 {
                let x_left: u8 = rng.gen();
                let x_right: u8 = rng.gen();
                let y_left: u8 = rng.gen();
                let y_right: u8 = rng.gen();
                let prss_left: u8 = rng.gen();
                let prss_right: u8 = rng.gen();
                let z_right: u8 = rng.gen();

                // fill expected
                expected_x_left.push(Fp31::truncate_from(x_left));
                expected_x_right.push(Fp31::truncate_from(x_right));
                expected_y_left.push(Fp31::truncate_from(y_left));
                expected_y_right.push(Fp31::truncate_from(y_right));
                expected_prss_left.push(Fp31::truncate_from(prss_left));
                expected_prss_right.push(Fp31::truncate_from(prss_right));
                expected_z_right.push(Fp31::truncate_from(z_right));

                // fill segment vec
                vec_x_left.push(x_left);
                vec_x_right.push(x_right);
                vec_y_left.push(y_left);
                vec_y_right.push(y_right);
                vec_prss_left.push(prss_left);
                vec_prss_right.push(prss_right);
                vec_z_right.push(z_right);
            }

            // generate and push segments
            for i in 0..1024 / segment_size {
                // conv to BitVec
                let x_left =
                    BitVec::<u8>::from_slice(&vec_x_left[i * segment_size..(i + 1) * segment_size]);
                let x_right = BitVec::<u8>::from_slice(
                    &vec_x_right[i * segment_size..(i + 1) * segment_size],
                );
                let y_left =
                    BitVec::<u8>::from_slice(&vec_y_left[i * segment_size..(i + 1) * segment_size]);
                let y_right = BitVec::<u8>::from_slice(
                    &vec_y_right[i * segment_size..(i + 1) * segment_size],
                );
                let prss_left = BitVec::<u8>::from_slice(
                    &vec_prss_left[i * segment_size..(i + 1) * segment_size],
                );
                let prss_right = BitVec::<u8>::from_slice(
                    &vec_prss_right[i * segment_size..(i + 1) * segment_size],
                );
                let z_right = BitVec::<u8>::from_slice(
                    &vec_z_right[i * segment_size..(i + 1) * segment_size],
                );

                // define segment
                let segment = Segment::from_entries(
                    SegmentEntry::from_bitslice(&x_left),
                    SegmentEntry::from_bitslice(&x_right),
                    SegmentEntry::from_bitslice(&y_left),
                    SegmentEntry::from_bitslice(&y_right),
                    SegmentEntry::from_bitslice(&prss_left),
                    SegmentEntry::from_bitslice(&prss_right),
                    SegmentEntry::from_bitslice(&z_right),
                );

                // push segment into batch
                batch.push(Gate::default(), RecordId::from(i), segment);
            }

            // check correctness of batch
            assert_batch(
                &batch,
                &expected_x_left,
                &expected_x_right,
                &expected_y_left,
                &expected_y_right,
                &expected_prss_left,
                &expected_prss_right,
                &expected_z_right,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_batch(
        batch: &Batch,
        expected_x_left: &[Fp31],
        expected_x_right: &[Fp31],
        expected_y_left: &[Fp31],
        expected_y_right: &[Fp31],
        expected_prss_left: &[Fp31],
        expected_prss_right: &[Fp31],
        expected_z_right: &[Fp31],
    ) {
        // assert that it is not empty
        assert!(!batch.is_empty());

        // check that length in bits matches, i.e. offset and allocation are correct and minimal
        assert_eq!(
            1024usize * 8usize,
            batch
                .inner
                .values()
                .map(|x| x.multiplication_bit_size
                    * (usize::from(x.last_record_of_batch) - usize::from(x.first_record_of_batch)
                        + 1usize))
                .sum::<usize>()
        );

        // check that batch is filled with non-trivial values
        for x in batch.inner.values() {
            for uv in &x.vec {
                assert_ne!(uv.x_left, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.x_right, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.y_left, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.y_right, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.prss_left, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.prss_right, BitVec::<u8>::from_vec(vec![0u8; 32]));
                assert_ne!(uv.z_right, BitVec::<u8>::from_vec(vec![0u8; 32]));
            }
        }

        // compare converted values from batch iter to expected
        for (i, x) in batch.get_unverified_field_values::<Fp31>().enumerate() {
            for j in 0..32 {
                assert_eq!((i, x.x_left[j]), (i, expected_x_left[32 * i + j]));
                assert_eq!((i, x.x_right[j]), (i, expected_x_right[32 * i + j]));
                assert_eq!((i, x.y_left[j]), (i, expected_y_left[32 * i + j]));
                assert_eq!((i, x.y_right[j]), (i, expected_y_right[32 * i + j]));
                assert_eq!((i, x.prss_left[j]), (i, expected_prss_left[32 * i + j]));
                assert_eq!((i, x.prss_right[j]), (i, expected_prss_right[32 * i + j]));
                assert_eq!((i, x.z_right[j]), (i, expected_z_right[32 * i + j]));
            }
        }
    }
}
