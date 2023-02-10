#[cfg(not(feature = "no-prss"))]
mod crypto;
#[cfg(feature = "no-prss")]
mod no_op;

#[cfg(not(feature = "no-prss"))]
pub use crypto::{Generator, GeneratorFactory, KeyExchange, SharedRandomness};
#[cfg(feature = "no-prss")]
pub use no_op::{Generator, GeneratorFactory, KeyExchange, SharedRandomness};

use super::Step;
use crate::rand::{CryptoRng, RngCore};
use crate::sync::{Arc, Mutex};

use std::{collections::HashMap, fmt::Debug};
#[cfg(debug_assertions)]
use std::{collections::HashSet, fmt::Formatter};

use x25519_dalek::PublicKey;

/// Keeps track of all indices used to generate shared randomness inside `IndexedSharedRandomness`.
/// Any two indices provided to `IndexesSharedRandomness::generate_values` must be unique.
/// As PRSS instance is unique per step, this only constrains randomness generated within
/// a given step.
#[cfg(debug_assertions)]
struct UsedSet {
    key: String,
    used: Arc<Mutex<HashSet<usize>>>,
}

#[cfg(debug_assertions)]
impl UsedSet {
    fn new(key: String) -> Self {
        Self {
            key,
            used: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Adds a given index to the list of used indices.
    ///
    /// ## Panics
    /// Panic if this index has been used before.
    fn insert(&self, index: u128) {
        if index > usize::MAX as u128 {
            tracing::warn!(
                "PRSS verification can validate values not exceeding {}, index {index} is greater.",
                usize::MAX
            );
        } else {
            assert!(
                self.used.lock().unwrap().insert(index as usize),
                "Generated randomness for index '{index}' twice using the same key '{}'",
                self.key
            );
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for UsedSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IndicesSet(key={})", self.key)
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
    #[cfg(debug_assertions)]
    used: UsedSet,
}

impl SharedRandomness for IndexedSharedRandomness {
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128) {
        let index = index.into();
        #[cfg(debug_assertions)]
        {
            self.used.insert(index);
        }

        (self.left.generate(index), self.right.generate(index))
    }
}

/// An implementation of `RngCore` that uses the same underlying `Generator`.
/// For use in place of `PrssSpace` where indexing cannot be used, such as
/// in APIs that expect `Rng`.
pub struct SequentialSharedRandomness {
    generator: Generator,
    counter: u128,
}

impl SequentialSharedRandomness {
    /// Private constructor.
    fn new(generator: Generator) -> Self {
        Self {
            generator,
            counter: 0,
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
        let v = self.generator.generate(self.counter);
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
    pub fn indexed(&self, key: &Step) -> Arc<IndexedSharedRandomness> {
        self.inner.lock().unwrap().indexed(key.as_ref())
    }

    /// Get a sequential shared randomness.
    ///
    /// # Panics
    /// This can only be called once.  After that, calls to this function or `indexed` will panic.
    pub fn sequential(
        &self,
        key: &Step,
    ) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.lock().unwrap().sequential(key.as_ref())
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
    items: HashMap<String, EndpointItem>,
}

impl EndpointInner {
    pub fn indexed(&mut self, key: &str) -> Arc<IndexedSharedRandomness> {
        // The second arm of this statement would be fine, except that `HashMap::entry()`
        // only takes an owned value as an argument.
        // This makes the lookup perform an allocation, which is very much suboptimal.
        let item = if let Some(item) = self.items.get(key) {
            item
        } else {
            self.items.entry(key.to_owned()).or_insert_with_key(|k| {
                EndpointItem::Indexed(Arc::new(IndexedSharedRandomness {
                    left: self.left.generator(k.as_bytes()),
                    right: self.right.generator(k.as_bytes()),
                    #[cfg(debug_assertions)]
                    used: UsedSet::new(key.to_owned()),
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
        key: &str,
    ) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        let prev = self.items.insert(key.to_owned(), EndpointItem::Sequential);
        assert!(
            prev.is_none(),
            "Attempt access a sequential PRSS for {key} after another access"
        );
        (
            SequentialSharedRandomness::new(self.left.generator(key.as_bytes())),
            SequentialSharedRandomness::new(self.right.generator(key.as_bytes())),
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

#[cfg(all(test, not(feature = "shuttle")))]
pub mod test {
    use super::{Generator, KeyExchange, SequentialSharedRandomness};
    use crate::protocol::prss::SharedRandomness;
    use crate::rand::{thread_rng, Rng};
    use crate::{ff::Fp31, protocol::Step, test_fixture::make_participants};
    use rand::prelude::SliceRandom;
    use std::mem::drop;

    fn make() -> (Generator, Generator) {
        const CONTEXT: &[u8] = b"test generator";
        let mut r = thread_rng();

        let (x1, x2) = (KeyExchange::new(&mut r), KeyExchange::new(&mut r));
        let (pk1, pk2) = (x1.public_key(), x2.public_key());
        let (f1, f2) = (x1.key_exchange(&pk2), x2.key_exchange(&pk1));
        (f1.generator(CONTEXT), f2.generator(CONTEXT))
    }

    /// When inputs are the same, outputs are the same.
    #[test]
    fn generate_equal() {
        let (g1, g2) = make();
        assert_eq!(g1.generate(0), g2.generate(0));
        assert_eq!(g1.generate(1), g2.generate(1));
        assert_eq!(g1.generate(u128::MAX), g2.generate(u128::MAX));

        // Calling g1 twice with the same input produces the same output.
        assert_eq!(g1.generate(12), g1.generate(12));
        // Now that g1 has been invoked more times than g2, we can check
        // that it isn't cheating by using an internal counter.
        assert_eq!(g1.generate(100), g2.generate(100));
        assert_eq!(g2.generate(13), g2.generate(13));
    }

    /// It is *highly* unlikely that two different inputs will produce
    /// equal outputs.
    #[test]
    fn generate_unlikely() {
        let (g1, g2) = make();
        // An equal output is *unlikely*.
        assert_ne!(g1.generate(0), g2.generate(1));
        // As is a zero output.
        assert_ne!(0, g1.generate(0));
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
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
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
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
        let z1 = p1.indexed(&step).zero_u128(IDX);
        let z2 = p2.indexed(&step).zero_u128(IDX);
        let z3 = p3.indexed(&step).zero_u128(IDX);

        assert_eq!(0, z1.wrapping_add(z2).wrapping_add(z3));
    }

    #[test]
    fn three_party_xor_zero() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
        let z1 = p1.indexed(&step).zero_xor(IDX);
        let z2 = p2.indexed(&step).zero_xor(IDX);
        let z3 = p3.indexed(&step).zero_xor(IDX);

        assert_eq!(0, z1 ^ z2 ^ z3);
    }

    #[test]
    fn three_party_random_u128() {
        const IDX1: u128 = 7;
        const IDX2: u128 = 21362;
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
        let r1 = p1.indexed(&step).random_u128(IDX1);
        let r2 = p2.indexed(&step).random_u128(IDX1);
        let r3 = p3.indexed(&step).random_u128(IDX1);

        let v1 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(0, v1);

        let r1 = p1.indexed(&step).random_u128(IDX2);
        let r2 = p2.indexed(&step).random_u128(IDX2);
        let r3 = p3.indexed(&step).random_u128(IDX2);

        let v2 = r1.wrapping_add(r2).wrapping_add(r3);
        assert_ne!(v1, v2);
    }

    #[test]
    fn three_party_fields() {
        const IDX: u128 = 7;
        let [p1, p2, p3] = make_participants();

        // These tests do not check that left != right because
        // the field might not be large enough.
        let step = Step::default();
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
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
        let z1: Fp31 = p1.indexed(&step).zero(IDX);
        let z2: Fp31 = p2.indexed(&step).zero(IDX);
        let z3: Fp31 = p3.indexed(&step).zero(IDX);

        assert_eq!(Fp31::from(0_u8), z1 + z2 + z3);
    }

    #[test]
    fn three_party_random() {
        const IDX1: u128 = 74;
        const IDX2: u128 = 12634;
        let [p1, p2, p3] = make_participants();

        let step = Step::default();
        let s1 = p1.indexed(&step);
        let s2 = p2.indexed(&step);
        let s3 = p3.indexed(&step);

        let r1: Fp31 = s1.random(IDX1);
        let r2 = s2.random(IDX1);
        let r3 = s3.random(IDX1);
        let v1 = r1 + r2 + r3;

        // There isn't enough entropy in this field (~5 bits) to be sure that the test will pass.
        // So run a few rounds (~21 -> ~100 bits) looking for a mismatch.
        let mut v2 = Fp31::from(0_u8);
        for i in IDX2..(IDX2 + 21) {
            let r1: Fp31 = s1.random(i);
            let r2 = s2.random(i);
            let r3 = s3.random(i);

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

        let [p1, p2, p3] = make_participants();
        let step = Step::default();
        let (rng1_l, rng1_r) = p1.sequential(&step);
        let (rng2_l, rng2_r) = p2.sequential(&step);
        let (rng3_l, rng3_r) = p3.sequential(&step);

        same_rng(rng1_l, rng3_r);
        same_rng(rng2_l, rng1_r);
        same_rng(rng3_l, rng2_r);
    }

    #[test]
    fn indexed_and_sequential() {
        let [p1, _p2, _p3] = make_participants();

        let base = Step::default();
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
    #[should_panic]
    fn indexed_then_sequential() {
        let [p1, _p2, _p3] = make_participants();

        let step = Step::default().narrow("test");
        drop(p1.indexed(&step));
        let _ = p1.sequential(&step);
    }

    #[test]
    #[should_panic]
    fn sequential_then_indexed() {
        let [p1, _p2, _p3] = make_participants();

        let step = Step::default().narrow("test");
        let _ = p1.sequential(&step);
        drop(p1.indexed(&step));
    }

    #[test]
    fn indexed_accepts_unique_index() {
        let [_, p2, _p3] = make_participants();
        let step = Step::default().narrow("test");
        let mut indices = (1..100_u128).collect::<Vec<_>>();
        indices.shuffle(&mut thread_rng());
        let indexed_prss = p2.indexed(&step);

        for index in indices {
            let _ = indexed_prss.random_u128(index);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn indexed_rejects_the_same_index() {
        let [p1, _p2, _p3] = make_participants();
        let step = Step::default().narrow("test");

        let _ = p1.indexed(&step).random_u128(100_u128);
        let _ = p1.indexed(&step).random_u128(100_u128);
    }
}
