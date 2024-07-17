mod crypto;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, ops::AddAssign};

pub use crypto::{
    FromPrss, FromRandom, FromRandomU128, Generator, GeneratorFactory, KeyExchange,
    SharedRandomness,
};
use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
pub(super) use internal::PrssIndex128;
use x25519_dalek::PublicKey;

use crate::{
    helpers::Direction,
    protocol::{Gate, RecordId},
    rand::{CryptoRng, RngCore},
    sync::{Arc, Mutex},
};

/// This module restricts access to internal PRSS index's private fields
/// and enforces constructing it via `new` even for impl blocks
/// defined in this module.
///
/// This helps to make sure an invalid [`PrssIndex128`] cannot be created
/// and all instantiations occur via `From` calls.
mod internal {
    use std::{
        fmt::{Debug, Display, Formatter},
        num::TryFromIntError,
    };

    use crate::protocol::prss::PrssIndex;

    /// Internal PRSS index.
    ///
    /// `PrssIndex128` values are directly input to the block cipher used for pseudo-random generation.
    /// Each invocation must use a distinct `PrssIndex128` value. Most code should use the `PrssIndex`
    /// type instead, which often corresponds to record IDs. `PrssIndex128` values are produced by
    /// the `PrssIndex::offset` function and include the primary `PrssIndex` plus a possible offset
    /// when more than 128 bits of randomness are required to generate the requested value.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PrssIndex128 {
        index: PrssIndex,
        offset: u32,
    }

    impl Display for PrssIndex128 {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}:{}", self.index.0, self.offset)
        }
    }

    impl Debug for PrssIndex128 {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self}")
        }
    }

    #[cfg(debug_assertions)]
    impl From<u64> for PrssIndex128 {
        fn from(value: u64) -> Self {
            Self::try_from(u128::from(value)).unwrap()
        }
    }

    impl From<PrssIndex128> for u128 {
        fn from(value: PrssIndex128) -> Self {
            u128::from(u64::from(value))
        }
    }

    impl From<PrssIndex128> for u64 {
        fn from(value: PrssIndex128) -> Self {
            (u64::from(value.index.0) << 32) + u64::from(value.offset)
        }
    }

    impl TryFrom<u128> for PrssIndex128 {
        type Error = PrssIndexError;

        fn try_from(value: u128) -> Result<Self, Self::Error> {
            let value64 = u64::try_from(value)?;
            let index = PrssIndex::from(u32::try_from(value64 >> 32).unwrap());
            let offset = usize::try_from(value64 & u64::from(u32::MAX)).unwrap();

            Self::new(index, offset)
        }
    }

    impl PrssIndex128 {
        /// The absolute maximum number of times we can encrypt
        /// using the same AES key inside PRSS is 2^43.  We reserve
        /// 32 bits for index, leaving the remaining 11 for the offset.
        /// That puts a limit to 32k maximum entropy generated
        /// from PRSS using the same record id.
        /// [`proof`]: <https://github.com/private-attribution/i-d/blob/main/draft-thomson-ppm-prss.md>
        pub(super) const MAX_OFFSET: u32 = 1 << 11;

        pub fn new(index: PrssIndex, offset: usize) -> Result<Self, PrssIndexError> {
            let this = Self {
                index,
                offset: offset.try_into()?,
            };

            if this.offset <= Self::MAX_OFFSET {
                Ok(this)
            } else {
                Err(PrssIndexError::OutOfRange(this.into()))
            }
        }

        pub fn index(self) -> PrssIndex {
            self.index
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum PrssIndexError {
        #[error("Type conversion failed")]
        ConversionError(#[from] TryFromIntError),
        #[error("PRSS index is out of range: {0}")]
        OutOfRange(u128),
    }
}

/// PRSS index.
///
/// PRSS indexes are used to ensure that distinct pseudo-randomness is generated for every value
/// output by PRSS. It is often sufficient to use record IDs as PRSS indexes, and
/// `impl From<RecordId> for PrssIndex` is provided for that purpose.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct PrssIndex(u32);

impl From<u32> for PrssIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

// It would be nice for this to be TryFrom, but there's a lot of places where we use u128s as PRSS indexes.
impl From<u128> for PrssIndex {
    fn from(value: u128) -> Self {
        let Ok(v) = u32::try_from(value) else {
            panic!("PRSS indices need to be smaller: {value} > u32::MAX");
        };
        Self(v)
    }
}

impl From<RecordId> for PrssIndex {
    fn from(value: RecordId) -> Self {
        Self(u32::from(value))
    }
}

impl AddAssign<u32> for PrssIndex {
    fn add_assign(&mut self, rhs: u32) {
        if let Some(v) = self.0.checked_add(rhs) {
            self.0 = v;
        } else {
            panic!("PrssIndex {} overflowed after adding {rhs}", self.0)
        }
    }
}

impl PrssIndex {
    fn offset(self, offset: usize) -> PrssIndex128 {
        PrssIndex128::new(self, offset).expect("PRSS offset must not be out of range")
    }
}

/// A participant in a 2-of-N replicated secret sharing.
/// Pseudorandom Secret-Sharing has many applications to the 3-party, replicated secret sharing scheme
/// You can read about it in the seminal paper:
/// "Share Conversion, Pseudorandom Secret-Sharing and Applications to Secure Computation"
/// by Ronald Cramer, Ivan Damgård, and Yuval Ishai - 2005
/// <https://link.springer.com/content/pdf/10.1007/978-3-540-30576-7_19.pdf>
#[derive(Debug)] // TODO(mt) custom debug implementation
pub struct IndexedSharedRandomness {
    left: Generator,
    right: Generator,
}

impl SharedRandomness for IndexedSharedRandomness {
    type ChunkIter<'a, Z: ArrayLength> = ChunkIter<'a, Z>;

    fn generate_chunks_one_side<I: Into<PrssIndex>, Z: ArrayLength>(
        &self,
        index: I,
        direction: Direction,
    ) -> Self::ChunkIter<'_, Z> {
        Self::ChunkIter::new(self, index, direction)
    }

    /// Override the generic implementation for performance reasons.
    /// We need to hint the compiler that calls to `left.generate` and `right.generate` can be
    /// interleaved. See [`ChunksIter`] documentation for more details
    fn generate_chunks_iter<I: Into<PrssIndex>, Z: ArrayLength>(
        &self,
        index: I,
    ) -> impl Iterator<Item = (GenericArray<u128, Z>, GenericArray<u128, Z>)> {
        let index = index.into();
        ChunksIter {
            left: Self::ChunkIter::new(self, index, Direction::Left),
            right: Self::ChunkIter::new(self, index, Direction::Right),
        }
    }
}

/// Specialized implementation for chunks that are generated using both left and right
/// randomness. The functionality is the same as [`std::iter::zip`], but it does not use
/// `Iterator` trait to call `left` and `right` next. It uses inlined method calls to
/// allow rustc to interleave these calls and improve performance.
///
/// Comparing this implementation vs [`std::iter::zip`] showed that this one is
/// 15% faster in benchmarks generating [`crate::ff::BA256`] values.
struct ChunksIter<'a, Z: ArrayLength> {
    left: ChunkIter<'a, Z>,
    right: ChunkIter<'a, Z>,
}

impl<'a, Z: ArrayLength> Iterator for ChunksIter<'a, Z> {
    type Item = (GenericArray<u128, Z>, GenericArray<u128, Z>);

    fn next(&mut self) -> Option<Self::Item> {
        let l = self.left.next()?;
        let r = self.right.next()?;
        Some((l, r))
    }
}

pub struct ChunkIter<'a, Z: ArrayLength> {
    inner: &'a Generator,
    index: PrssIndex,
    offset: usize,
    phantom_data: PhantomData<Z>,
}

impl<'a, Z: ArrayLength> Iterator for ChunkIter<'a, Z> {
    type Item = GenericArray<u128, Z>;

    /// Rustc 1.79 and below does not inline this call without an explicit hint, and it hurts
    /// performance - see ipa/1187.
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let chunk =
            GenericArray::generate(|i| self.inner.generate(self.index.offset(self.offset + i)));

        self.offset += Z::USIZE;
        Some(chunk)
    }
}

impl<'a, Z: ArrayLength> ChunkIter<'a, Z> {
    pub fn new<I: Into<PrssIndex>>(
        prss: &'a IndexedSharedRandomness,
        index: I,
        direction: Direction,
    ) -> Self {
        Self {
            inner: match direction {
                Direction::Left => &prss.left,
                Direction::Right => &prss.right,
            },
            index: index.into(),
            offset: 0,
            phantom_data: PhantomData,
        }
    }
}

/// An implementation of `RngCore` that uses the same underlying `Generator`.
/// For use in place of `PrssSpace` where indexing cannot be used, such as
/// in APIs that expect `Rng`.
///
/// There is a limit of 4B unique values that can be obtained from this.
pub struct SequentialSharedRandomness {
    generator: Generator,
    counter: PrssIndex,
}

impl SequentialSharedRandomness {
    /// Private constructor.
    fn new(generator: Generator) -> Self {
        Self {
            generator,
            counter: PrssIndex::default(),
        }
    }
}

impl RngCore for SequentialSharedRandomness {
    #[allow(clippy::cast_possible_truncation)]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    // This implementation wastes half of the bits that are generated.
    // That is OK for the same reason that we use in converting a `u128` to a small `Field`.
    #[allow(clippy::cast_possible_truncation)]
    fn next_u64(&mut self) -> u64 {
        let v = self.generator.generate(self.counter.offset(0));
        self.counter += 1;
        v as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        rand_core::impls::fill_bytes_via_next(self, dest);
        Ok(())
    }
}

impl CryptoRng for SequentialSharedRandomness {}

/// A single participant in the protocol.
/// This holds multiple streams of correlated (pseudo)randomness.
pub struct Endpoint {
    inner: Mutex<EndpointInner>,
}

impl Endpoint {
    /// Construct a new, unconfigured participant.  This can be configured by
    /// providing public keys for the left and right participants to `setup()`.
    pub fn prepare<R: RngCore + CryptoRng>(r: &mut R) -> EndpointSetup {
        EndpointSetup {
            left: KeyExchange::new(r),
            right: KeyExchange::new(r),
        }
    }

    /// Get the identified PRSS instance.
    ///
    /// # Panics
    /// When used incorrectly.  For instance, if you ask for an RNG and then ask
    /// for a PRSS using the same key.
    pub fn indexed(&self, key: &Gate) -> Arc<IndexedSharedRandomness> {
        self.inner.lock().unwrap().indexed(key)
    }

    /// Get a sequential shared randomness.
    ///
    /// # Panics
    /// This can only be called once.  After that, calls to this function or `indexed` will panic.
    pub fn sequential(
        &self,
        key: &Gate,
    ) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.lock().unwrap().sequential(key)
    }
}

impl Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Participant")
    }
}

enum EndpointItem {
    Indexed(Arc<IndexedSharedRandomness>),
    Sequential,
}

struct EndpointInner {
    left: GeneratorFactory,
    right: GeneratorFactory,
    items: HashMap<Gate, EndpointItem>,
}

impl EndpointInner {
    pub fn indexed(&mut self, key: &Gate) -> Arc<IndexedSharedRandomness> {
        // The second arm of this statement would be fine, except that `HashMap::entry()`
        // only takes an owned value as an argument.
        // This makes the lookup perform an allocation, which is very much suboptimal.
        let item = if let Some(item) = self.items.get(key) {
            item
        } else {
            self.items.entry(key.clone()).or_insert_with_key(|k| {
                EndpointItem::Indexed(Arc::new(IndexedSharedRandomness {
                    left: self.left.generator(k.as_ref().as_bytes()),
                    right: self.right.generator(k.as_ref().as_bytes()),
                }))
            })
        };
        if let EndpointItem::Indexed(idxd) = item {
            Arc::clone(idxd)
        } else {
            panic!("Attempt to get an indexed PRSS for {key} after retrieving a sequential PRSS");
        }
    }

    pub fn sequential(
        &mut self,
        key: &Gate,
    ) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        let prev = self.items.insert(key.clone(), EndpointItem::Sequential);
        assert!(
            prev.is_none(),
            "Attempt access a sequential PRSS for {key} after another access"
        );
        (
            SequentialSharedRandomness::new(self.left.generator(key.as_ref().as_bytes())),
            SequentialSharedRandomness::new(self.right.generator(key.as_ref().as_bytes())),
        )
    }
}

/// Use this to setup a three-party PRSS configuration.
pub struct EndpointSetup {
    left: KeyExchange,
    right: KeyExchange,
}

impl EndpointSetup {
    /// Get the public keys that this setup instance intends to use.
    /// The public key that applies to the left participant is at `.0`,
    /// with the key for the right participant in `.1`.
    #[must_use]
    pub fn public_keys(&self) -> (PublicKey, PublicKey) {
        (self.left.public_key(), self.right.public_key())
    }

    /// Provide the left and right public keys to construct a functioning
    /// participant instance.
    #[must_use]
    pub fn setup(self, left_pk: &PublicKey, right_pk: &PublicKey) -> Endpoint {
        let fl = self.left.key_exchange(left_pk);
        let fr = self.right.key_exchange(right_pk);
        Endpoint {
            inner: Mutex::new(EndpointInner {
                left: fl,
                right: fr,
                items: HashMap::new(),
            }),
        }
    }
}

#[cfg(all(test, unit_test))]
pub mod test {
    use ipa_step::StepNarrow;
    use proptest::proptest;
    use rand::{prelude::SliceRandom, rngs::StdRng};
    use rand_core::{RngCore, SeedableRng};

    use super::{Generator, KeyExchange, PrssIndex128, SequentialSharedRandomness};
    use crate::{
        ff::{Field, Fp31, U128Conversions},
        protocol::{
            prss::{Endpoint, PrssIndex, SharedRandomness},
            Gate,
        },
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::make_participants,
    };

    fn make(seed: u64) -> (Generator, Generator) {
        const CONTEXT: &[u8] = b"test generator";
        let mut r = StdRng::seed_from_u64(seed);

        let (x1, x2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (x1.public_key(), x2.public_key());
        let (f1, f2) = (x1.key_exchange(&pk2), x2.key_exchange(&pk1));
        (f1.generator(CONTEXT), f2.generator(CONTEXT))
    }

    fn participants() -> [Endpoint; 3] {
        make_participants(&mut thread_rng())
    }

    /// Generate an additive share of zero.
    /// Each party generates two values, one that is shared with the party to their left,
    /// one with the party to their right.  If all entities add their left share
    /// and subtract their right value, each share will be added once (as a left share)
    /// and subtracted once (as a right share), resulting in values that sum to zero.
    #[must_use]
    fn zero_u128<P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(prss: &P, index: I) -> u128 {
        let (l, r) = prss.generate_values(index);
        l.wrapping_sub(r)
    }

    /// Generate an XOR share of zero.
    #[must_use]
    fn zero_xor<P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(prss: &P, index: I) -> u128 {
        let (l, r) = prss.generate_values(index);
        l ^ r
    }

    /// Generate an additive shares of a random value.
    /// This is like `zero_u128`, except that the values are added.
    /// The result is that each random value is added twice.  Note that thanks to
    /// using a wrapping add, the result won't be even because the high bit will
    /// wrap around and populate the low bit.
    #[must_use]
    fn random_u128<P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(prss: &P, index: I) -> u128 {
        let (l, r) = prss.generate_values(index);
        l.wrapping_add(r)
    }

    /// Generate additive shares of a random field value.
    #[must_use]
    fn random<F: Field, P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(prss: &P, index: I) -> F {
        let (l, r): (F, F) = prss.generate_fields(index);
        l + r
    }

    /// When inputs are the same, outputs are the same.
    #[test]
    fn generate_equal() {
        const SEED: u64 = 0;
        let (g1, g2) = make(SEED);
        assert_eq!(g1.generate(0), g2.generate(0));
        assert_eq!(g1.generate(1), g2.generate(1));
        assert_eq!(g1.generate(1 << 32), g2.generate(1 << 32));

        // Calling generators seeded with the same key produce the same output
        assert_eq!(g1.generate(12), make(SEED).0.generate(12));
        // Now that g1 has been invoked more times than g2, we can check
        // that it isn't cheating by using an internal counter.
        assert_eq!(g1.generate(100), g2.generate(100));
        assert_eq!(g1.generate(13), g2.generate(13));
    }

    /// It is *highly* unlikely that two different inputs will produce
    /// equal outputs.
    #[test]
    fn generate_unlikely() {
        let (g1, g2) = make(thread_rng().next_u64());
        // An equal output is *unlikely*.
        assert_ne!(g1.generate(0), g2.generate(1));
        // As is a zero output.
        assert_ne!(0, g1.generate(1));
    }

    /// Creating generators with different contexts means different output.
    #[test]
    fn mismatched_context() {
        let mut r = thread_rng();

        let (e1, e2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (e1.public_key(), e2.public_key());
        let (f1, f2) = (e1.key_exchange(&pk2), e2.key_exchange(&pk1));
        let (g1, g2) = (f1.generator(b"one"), f2.generator(b"two"));
        assert_ne!(g1.generate(1), g2.generate(1));
    }

    #[test]
    fn three_party_values() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let (r1_l, r1_r) = p1.indexed(&step).generate_values(IDX);
        assert_ne!(r1_l, r1_r);
        let (r2_l, r2_r) = p2.indexed(&step).generate_values(IDX);
        assert_ne!(r2_l, r2_r);
        let (r3_l, r3_r) = p3.indexed(&step).generate_values(IDX);
        assert_ne!(r3_l, r3_r);

        assert_eq!(r1_l, r3_r);
        assert_eq!(r2_l, r1_r);
        assert_eq!(r3_l, r2_r);
    }

    #[test]
    fn three_party_zero_u128() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let z1 = zero_u128(&*p1.indexed(&step), IDX);
        let z2 = zero_u128(&*p2.indexed(&step), IDX);
        let z3 = zero_u128(&*p3.indexed(&step), IDX);

        assert_eq!(0, z1.wrapping_add(z2).wrapping_add(z3));
    }

    #[test]
    fn three_party_xor_zero() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let z1 = zero_xor(&*p1.indexed(&step), IDX);
        let z2 = zero_xor(&*p2.indexed(&step), IDX);
        let z3 = zero_xor(&*p3.indexed(&step), IDX);

        assert_eq!(0, z1 ^ z2 ^ z3);
    }

    #[test]
    fn three_party_random_u128() {
        const IDX1: u128 = 7;
        const IDX2: u128 = 21362;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let r1 = random_u128(&*p1.indexed(&step), IDX1);
        let r2 = random_u128(&*p2.indexed(&step), IDX1);
        let r3 = random_u128(&*p3.indexed(&step), IDX1);

        let v1 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(0, v1);

        let r1 = random_u128(&*p1.indexed(&step), IDX2);
        let r2 = random_u128(&*p2.indexed(&step), IDX2);
        let r3 = random_u128(&*p3.indexed(&step), IDX2);

        let v2 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(v1, v2);
    }

    #[test]
    fn three_party_fields() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = participants();

        // These tests do not check that left != right because
        // the field might not be large enough.
        let step = Gate::default();
        let (r1_l, r1_r): (Fp31, Fp31) = p1.indexed(&step).generate_fields(IDX);
        let (r2_l, r2_r): (Fp31, Fp31) = p2.indexed(&step).generate_fields(IDX);
        let (r3_l, r3_r): (Fp31, Fp31) = p3.indexed(&step).generate_fields(IDX);

        assert_eq!(r1_l, r3_r);
        assert_eq!(r2_l, r1_r);
        assert_eq!(r3_l, r2_r);
    }

    #[test]
    fn three_party_zero() {
        const IDX: u128 = 72;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let z1: Fp31 = p1.indexed(&step).zero(IDX);
        let z2: Fp31 = p2.indexed(&step).zero(IDX);
        let z3: Fp31 = p3.indexed(&step).zero(IDX);

        assert_eq!(<Fp31 as SharedValue>::ZERO, z1 + z2 + z3);
    }

    #[test]
    fn three_party_random() {
        const IDX1: u128 = 74;
        const IDX2: u128 = 12634;
        let [p1, p2, p3] = participants();

        let step = Gate::default();
        let s1 = p1.indexed(&step);
        let s2 = p2.indexed(&step);
        let s3 = p3.indexed(&step);

        let r1: Fp31 = random(&*s1, IDX1);
        let r2 = random(&*s2, IDX1);
        let r3 = random(&*s3, IDX1);
        let v1 = r1 + r2 + r3;

        // There isn't enough entropy in this field (~5 bits) to be sure that the test will pass.
        // So run a few rounds (~21 -> ~100 bits) looking for a mismatch.
        let mut v2 = Fp31::truncate_from(0_u8);
        for i in IDX2..(IDX2 + 21) {
            let r1: Fp31 = random(&*s1, i);
            let r2 = random(&*s2, i);
            let r3 = random(&*s3, i);

            v2 = r1 + r2 + r3;
            if v1 != v2 {
                break;
            }
        }
        assert_ne!(v1, v2);
    }

    #[test]
    fn prss_rng() {
        fn same_rng(mut a: SequentialSharedRandomness, mut b: SequentialSharedRandomness) {
            assert_eq!(a.gen::<u32>(), b.gen::<u32>());
            assert_eq!(a.gen::<[u8; 20]>(), b.gen::<[u8; 20]>());
            assert_eq!(a.gen_range(7..99), b.gen_range(7..99));
            assert_eq!(a.gen_bool(0.3), b.gen_bool(0.3));
        }

        let [p1, p2, p3] = participants();
        let step = Gate::default();
        let (rng1_l, rng1_r) = p1.sequential(&step);
        let (rng2_l, rng2_r) = p2.sequential(&step);
        let (rng3_l, rng3_r) = p3.sequential(&step);

        same_rng(rng1_l, rng3_r);
        same_rng(rng2_l, rng1_r);
        same_rng(rng3_l, rng2_r);
    }

    #[test]
    fn indexed_and_sequential() {
        let [p1, _p2, _p3] = participants();

        let base = Gate::default();
        let idx = p1.indexed(&base.narrow("indexed"));
        let (mut s_left, mut s_right) = p1.sequential(&base.narrow("sequential"));
        let (i_left, i_right) = idx.generate_values(0_u128);
        assert_ne!(
            i_left & u128::from(u64::MAX),
            u128::from(s_left.gen::<u64>())
        );
        assert_ne!(
            i_right & u128::from(u64::MAX),
            u128::from(s_right.gen::<u64>())
        );
    }

    #[test]
    #[should_panic(
        expected = "Attempt access a sequential PRSS for protocol/test after another access"
    )]
    fn indexed_then_sequential() {
        let [p1, _p2, _p3] = participants();

        let step = Gate::default().narrow("test");
        drop(p1.indexed(&step));
        let _: (_, _) = p1.sequential(&step);
    }

    #[test]
    #[should_panic(
        expected = "Attempt to get an indexed PRSS for protocol/test after retrieving a sequential PRSS"
    )]
    fn sequential_then_indexed() {
        let [p1, _p2, _p3] = participants();

        let step = Gate::default().narrow("test");
        let _: (_, _) = p1.sequential(&step);
        drop(p1.indexed(&step));
    }

    #[test]
    fn indexed_accepts_unique_index() {
        let [_, p2, _p3] = participants();
        let step = Gate::default().narrow("test");
        let mut indices = (1..100_u128).collect::<Vec<_>>();
        indices.shuffle(&mut thread_rng());
        let indexed_prss = p2.indexed(&step);

        for index in indices {
            let _: u128 = random_u128(&*indexed_prss, index);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(
        expected = "Generated randomness for index '100:0' twice using the same key 'protocol/test'"
    )]
    fn indexed_rejects_the_same_index() {
        let [p1, _p2, _p3] = participants();
        let step = Gate::default().narrow("test");

        let _: u128 = random_u128(&*p1.indexed(&step), 100_u128);
        let _: u128 = random_u128(&*p1.indexed(&step), 100_u128);
    }

    #[test]
    fn one_prss_index_u128_conversion() {
        assert_8_byte_index_is_valid(65535, 42);
    }

    #[test]
    #[should_panic(expected = "PrssIndex 4294967295 overflowed after adding 1")]
    fn prss_index_catches_overflow() {
        let mut base = PrssIndex(u32::MAX);
        base += 1;
    }

    #[test]
    fn index_upper_bound() {
        let bad_index = (u128::from(u32::MAX) << 32) + u128::from(PrssIndex128::MAX_OFFSET + 1);
        let good_index = (u128::from(u32::MAX) << 32) + u128::from(PrssIndex128::MAX_OFFSET);

        assert!(PrssIndex128::try_from(bad_index).is_err());
        assert!(PrssIndex128::try_from(good_index).is_ok());
    }

    fn assert_8_byte_index_is_valid(index: u32, offset: usize) {
        let index = PrssIndex(index);
        let index128 = u128::from(index.offset(offset));
        assert_eq!(
            index128,
            u128::from(PrssIndex128::try_from(index128).unwrap())
        );
    }

    proptest! {
        #[test]
        fn prss_index_128_conversions(index in 0..u32::MAX, offset in 0..PrssIndex128::MAX_OFFSET) {
            assert_8_byte_index_is_valid(index, usize::try_from(offset).unwrap());
        }
    }
}
