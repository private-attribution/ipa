use std::{
    collections::HashMap,
    fmt::Debug,
    marker::PhantomData,
    sync::{Arc, Mutex, Weak},
};

use async_trait::async_trait;
use bitvec::{array::BitArray, prelude::Lsb0, slice::BitSlice};

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{
            dzkp_malicious::DZKPUpgraded as MaliciousDZKPUpgraded,
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded, Base, Context,
            DZKPUpgradableContext, MaliciousContext, SemiHonestContext,
        },
        step::Gate,
        RecordId,
    },
};

/// `UnverifiedValues` are intermediate values that occur during a multiplication.
/// These values need to be verified since there might have been malicious behavior.
/// For a multiplication, let `(x1, x2), (x2, x3), (x3,x1)`, `(y1, y2), (y2, y3), (y3,y1)` be the shares of `x` and `y`
/// and let the goal of the multiplication be to compute `x*y`.
/// `(pi, p(i+1)` is the randomness from `PRSS` used for the multiplication by helper `i`.
/// `z(i+1)` is the result of the multiplication received from the helper on the right.
/// We do not need to store `zi` since it can be computed from the other stored values.
#[derive(Clone, Debug)]
struct UnverifiedValues {
    x_left: BitArray<[u8; 256], Lsb0>,
    x_right: BitArray<[u8; 256], Lsb0>,
    y_left: BitArray<[u8; 256], Lsb0>,
    y_right: BitArray<[u8; 256], Lsb0>,
    prss_left: BitArray<[u8; 256], Lsb0>,
    prss_right: BitArray<[u8; 256], Lsb0>,
    z_right: BitArray<[u8; 256], Lsb0>,
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

/// `SegmentEntry` is a simple wrapper to represent one entry of a Segment
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

/// `UnverifiedValuesStore` stores a vector of `UnverifiedValues` together with an `offset`
/// `offset` is the minimum `RecordId` for the current batch within the gate
#[derive(Clone, Debug)]
struct UnverifiedValuesStore {
    offset: RecordId,
    vec: Vec<Option<UnverifiedValues>>,
}

impl UnverifiedValuesStore {
    /// creates a new store for given length and offset
    fn initialize(offset: RecordId, length: usize) -> Self {
        Self {
            offset,
            vec: vec![None; length],
        }
    }

    /// `reset_offset` reallocates vector such that a smaller `RecordId` than `offset` can be stored
    /// `new_offset` will be the new `offset` and the store and store elements with `RecordId` `new_offset` and larger
    /// when `new_offset` is larger that the current `offset`, the function does nothing
    fn reset_offset(&mut self, new_offset: RecordId, segment_length: usize) {
        if new_offset < self.offset {
            let mut new_offset = usize::from(new_offset);
            // if segment_length is less than 256, redefine new offset such that we don't need to rearrange the existing segments
            if 256 % segment_length == 0 {
                // distance between new_offset and old offset is rounded up to a multiple of 256
                new_offset = ((usize::from(self.offset) - new_offset + 255) >> 8) << 8;
            }
            let extension_length = ((usize::from(self.offset) - new_offset) >> 8) * segment_length;
            // use existing vec and add enough space in front
            let vec_previous = &mut self.vec;
            let mut vec: Vec<Option<UnverifiedValues>> =
                Vec::with_capacity(vec_previous.len() + extension_length);
            vec.resize(extension_length, None);
            vec.append(vec_previous);
            self.offset = RecordId::from(new_offset);
        }
    }

    /// `extend_vec` allows to extend a store to be able to hold a larger `RecordId`
    fn extend_vec(&mut self, extension_length: usize) {
        let vec_previous = &mut self.vec;
        let new_length = vec_previous.len() + extension_length;
        let mut vec: Vec<Option<UnverifiedValues>> = Vec::with_capacity(new_length);
        vec.append(vec_previous);
        vec.resize(new_length, None);
    }

    /// `insert_segment` allows to include a new segment in `UnverifiedValuesStore`
    fn insert_segment(&mut self, record_id: RecordId, segment: Segment) {
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
            self.extend_vec(2 * self.vec.len() - (position_vec + (length >> 8)));
        }

        if 256 % length == 0 {
            // segments are small, pack one or more in each entry of `vec`
            let position_bit_array = (length * position_raw) % 256;
            if self.vec[position_vec].is_none() {
                let entry = UnverifiedValues::new();
                self.vec[position_vec] = Some(entry);
            }
            // get entry
            let entry = self.vec[position_vec].as_ref().unwrap();
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
}

/// `Batch` collects a batch of `UnverifiedValuesStore` in a hashmap.
/// The size of the batch is limited due to the memory costs and verifier specific constraints.
///
/// Corresponds to `AccumulatorState` of the MAC based malicious validator.
#[derive(Clone, Debug)]
struct Batch {
    inner: HashMap<Gate, UnverifiedValuesStore>,
}

impl Batch {
    fn new() -> Self {
        Self {
            inner: HashMap::<Gate, UnverifiedValuesStore>::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Corresponds to `MaliciousAccumulator` of the MAC based malicious validator.
#[derive(Clone, Debug)]
pub struct DZKPBatch {
    inner: Weak<Mutex<Batch>>,
}

impl DZKPBatch {
    /// allocates enough memory for a given `Gate` and `offset`
    /// `size` is the length of the vector which is computed as `(segment.len()/256)*records within batch for the gate`
    /// `offset` is the minimum `RecordId` of the current `Gate` within the `Batch`
    ///
    /// ## Errors
    /// Returns error when initializing `gate` when already existing
    ///
    /// ## Panics
    /// Panics when mutex is poisoned
    pub fn initialize(&self, gate: Gate, offset: RecordId, size: usize) -> Result<(), Error> {
        let arc_mutex = self.inner.upgrade().unwrap();

        // LOCK BEGIN
        let mut batch = arc_mutex.lock().unwrap();

        // initialize
        let previous = batch
            .inner
            .insert(gate, UnverifiedValuesStore::initialize(offset, size));

        // output error if already initialized
        if previous.is_some() {
            Err(Error::DZKPBatchDoubleInitialization(format!(
                "{previous:?}"
            )))
        } else {
            Ok(())
        }
        // LOCK END
    }

    /// pushes values of a record, i.e. segment, to a `Batch`
    ///
    /// ## Panics
    /// Panics when mutex is poisoned
    pub fn push(&self, gate: &Gate, record_id: RecordId, segment: Segment) {
        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut batch = arc_mutex.lock().unwrap();

        // get value_store & add it if no offset is there yet
        // not ideal, ideally initialized by calling `initialize`
        if batch.inner.get(gate).is_none() {
            let value_store =
                UnverifiedValuesStore::initialize(record_id, (segment.len() + 255) >> 8);
            batch.inner.insert(gate.clone(), value_store);
        }

        let value_store = batch.inner.get_mut(gate).unwrap();

        value_store.insert_segment(record_id, segment);
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
pub trait DZKPBaseField: Field {}

/// Validator Trait for DZKPs
// Cannot use existing validator trait since context output a `UpgradedContext`
// that is tied to an accumulator rather than a `DZKPBatch`
// Function signature of validate is different, it does not downgrade shares anymore
#[async_trait]
pub trait DZKPValidator<DF: DZKPBaseField, B: DZKPUpgradableContext<DF>> {
    fn context(&self) -> B::UpgradedContext;
    async fn validate(self) -> Result<(), Error>;
}

pub struct SemiHonestDZKPValidator<'a, DF> {
    context: SemiHonestDZKPUpgraded<'a>,
    _f: PhantomData<DF>,
}

impl<'a, DF> SemiHonestDZKPValidator<'a, DF> {
    pub(super) fn new(inner: Base<'a>) -> Self {
        // This is inconsistent with the malicious new() which calls dzkp_upgrade
        // following previous semi honest validator
        Self {
            context: SemiHonestDZKPUpgraded::new(inner),
            _f: PhantomData,
        }
    }
}

#[async_trait]
impl<'a, DF: DZKPBaseField> DZKPValidator<DF, SemiHonestContext<'a>>
    for SemiHonestDZKPValidator<'a, DF>
{
    fn context(&self) -> SemiHonestDZKPUpgraded<'a> {
        self.context.clone()
    }

    async fn validate(self) -> Result<(), Error> {
        Ok(())
    }
}

/// `MaliciousDZKPValidator` corresponds to pub struct `Malicious` and implements the trait `DZKPValidator`
/// The implementation of `validate` of the `DZKPValidator` trait depends on generic `DF`
#[allow(dead_code)]
pub struct MaliciousDZKPValidator<'a, DF: DZKPBaseField> {
    batch_list: Arc<Mutex<Batch>>,
    protocol_ctx: MaliciousDZKPUpgraded<'a>,
    validate_ctx: Base<'a>,
    _f: PhantomData<DF>,
}

#[async_trait]
impl<'a, DF: DZKPBaseField> DZKPValidator<DF, MaliciousContext<'a>>
    for MaliciousDZKPValidator<'a, DF>
{
    fn context(&self) -> MaliciousDZKPUpgraded<'a> {
        self.protocol_ctx.clone()
    }

    async fn validate(self) -> Result<(), Error> {
        // todo: generate proofs and validate them using `batch_list`

        // empty batch_list
        // LOCK BEGIN
        let mut batch = self.batch_list.lock().unwrap();
        *batch = Batch::new();
        Ok(())
        // LOCK END
    }
}

impl<'a, DF: DZKPBaseField> MaliciousDZKPValidator<'a, DF> {
    #[must_use]
    pub fn new(ctx: MaliciousContext<'a>) -> Self {
        let list = Batch::new();
        let batch_list = Arc::new(Mutex::new(list));
        let dzkp_batch = DZKPBatch {
            inner: Arc::downgrade(&batch_list),
        };
        let validate_ctx = ctx.narrow(&Step::DZKPValidate).base_context();
        let protocol_ctx = ctx.dzkp_upgrade(&Step::DZKPMaliciousProtocol, dzkp_batch);
        Self {
            batch_list,
            protocol_ctx,
            validate_ctx,
            _f: PhantomData,
        }
    }
}
