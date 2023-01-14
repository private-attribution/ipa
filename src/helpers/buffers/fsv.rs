use bitvec::bitvec;
use bitvec::prelude::BitVec;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::{AcqRel, Acquire};

/// A store of bytes that allows for random access inserts, but contiguous removal.
///
/// Fixed-sized elements can be added to this vector with [`insert`] in random order as long as
/// the total number of elements does not exceed the overall capacity.
///
/// Values are taken with [`take`] from the start of the buffer.  Taking values increases the
/// maximum index that is permitted.
///
/// [`insert`]: Self::insert
/// [`take`]: Self::take
#[derive(Debug)]
pub struct FixedSizeByteVec<const N: usize> {
    data: Vec<u8>,
    added: BitVec,
    capacity: NonZeroUsize,
    end: AtomicUsize,
}

impl<const N: usize> FixedSizeByteVec<N> {
    pub const ELEMENT_SIZE_BYTES: usize = N;

    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            data: vec![0_u8; N * capacity.get()],
            added: bitvec![0; capacity.get()],
            capacity,
            end: AtomicUsize::new(capacity.get()),
        }
    }

    /// Inserts a new element to the specified position.
    ///
    /// When inserting, `index` needs to be in range.  Values that are in range are within `capacity`
    /// (as provided to [`new`]) of the last value that was taken with [`take`].
    ///
    /// ## Panics
    /// Panics if `index` is out of bounds or if something was previously inserted at `index`.
    /// Panics only occur in debug builds; otherwise, a bad index will overwrite that location;
    /// expect bad things to happen in that case.
    ///
    /// [`new`]: Self::new
    /// [`take`]: Self::take
    pub fn insert<D: Debug>(&mut self, channel: D, index: usize, elem: &[u8; N]) {
        if cfg!(debug_assertions) {
            let end = self.end.load(Acquire);
            assert!(
                ((end - self.capacity.get())..end).contains(&index),
                "Attempt to insert out of range at index {index} (allowed={:?})",
                (end - self.capacity.get())..end
            );
        }
        // Translate from an absolute index into a relative one.
        let i = index % self.capacity.get();
        let start = i * N;
        let offset = start..start + N;

        let overwritten = self.added.replace(i, true);
        debug_assert!(
            !overwritten,
            "Duplicate send for index {index} on channel {channel:?}"
        );
        self.data[offset].copy_from_slice(elem);
    }

    /// Return any gap ahead of the first missing value.
    #[cfg(any(test, debug_assertions))]
    pub fn missing(&self) -> std::ops::Range<usize> {
        let end = self.end.load(Acquire);
        let start = end - self.capacity.get();
        let i = end % self.capacity.get();
        let mut absent = self.added[i..].leading_zeros();
        if i + absent == self.capacity.get() {
            absent += self.added[..i].leading_zeros();
        }
        if absent == self.capacity.get() {
            start..start
        } else {
            start..(start + absent)
        }
    }

    /// Takes a block of elements from the beginning of the vector, or `None` if
    /// fewer than `min_count` elements have been inserted at the start of the buffer.
    pub fn take(&mut self, min_count: usize) -> Option<Vec<u8>> {
        // Find the relative index we're starting at.
        let i = self.end.load(Acquire) % self.capacity.get();

        // Find how many elements we can return (`tail + wrap`).
        let tail = self.added[i..].leading_ones();
        let wrap = if tail + i == self.capacity.get() {
            self.added[..i].leading_ones()
        } else {
            0
        };

        if tail + wrap < min_count {
            return None;
        }

        // Move `self.end` marker, clear the values in `self.added`, and
        // return a copy of that part of `self.data` that matters.
        self.end.fetch_add(tail + wrap, AcqRel);
        self.added[i..(i + tail)].fill(false);
        if wrap > 0 {
            self.added[..wrap].fill(false);
            let mut buf = Vec::with_capacity((tail + wrap) * N);
            buf.extend_from_slice(&self.data[(i * N)..]);
            buf.extend_from_slice(&self.data[..(wrap * N)]);
            Some(buf)
        } else {
            Some(self.data[(i * N)..((i + tail) * N)].to_owned())
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::num::NonZeroUsize;

    use crate::helpers::buffers::fsv::FixedSizeByteVec;

    const ELEMENT_SIZE: usize = 8;
    fn test_data_at(mut index: usize) -> [u8; ELEMENT_SIZE] {
        if index == 0 {
            // zeros are bad as test data
            index = 255;
        }
        #[allow(clippy::cast_possible_truncation)]
        [index as u8; ELEMENT_SIZE]
    }

    trait FSBTestExt {
        fn insert_test_data(&mut self, index: usize);
    }

    impl FSBTestExt for FixedSizeByteVec<ELEMENT_SIZE> {
        fn insert_test_data(&mut self, index: usize) {
            self.insert("test", index, &test_data_at(index));
        }
    }

    #[test]
    fn insert() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3).unwrap());
        v.insert_test_data(0);
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));
    }

    #[test]
    fn gap() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3).unwrap());
        assert!(v.missing().is_empty());
        v.insert_test_data(1);
        assert_eq!(0..1_usize, v.missing());
    }

    #[test]
    #[cfg(debug_assertions)] // This only asserts in debug builds.
    #[should_panic(expected = "Duplicate send for index 0 on channel \"duplicate\"")]
    fn duplicate_insert() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3).unwrap());
        v.insert_test_data(0);
        v.insert("duplicate", 0, &[10; ELEMENT_SIZE]);
    }

    #[test]
    #[cfg(debug_assertions)] // This only asserts in debug builds.
    #[should_panic(expected = "Attempt to insert out of range at index 0 (allowed=1..4)")]
    fn insert_taken() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3).unwrap());
        v.insert_test_data(0);
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));
        v.insert("taken", 0, &[10; ELEMENT_SIZE]);
    }

    #[test]
    #[cfg(debug_assertions)] // This only asserts in debug builds.
    #[should_panic(expected = "Attempt to insert out of range at index 10 (allowed=0..1)")]
    fn index_out_of_bounds() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(1).unwrap());
        v.insert("oob", 10, &[1; ELEMENT_SIZE]);
    }

    #[test]
    fn take() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3).unwrap());
        v.insert_test_data(0);

        // drain the first region
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));

        // second region became first because of shift but it is not ready to drain
        assert_eq!(v.take(1), None);

        // However there should be no elements in the second region because of the shift
        v.insert_test_data(2);
        assert_eq!(1..2_usize, v.missing());
    }

    #[test]
    fn take_is_greedy() {
        // Insert elements X,X,X,_,X,_,_
        // first take should remove first 3 elements leaving the element at index 4 intact
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(3 * 3).unwrap());

        v.insert_test_data(2);
        v.insert_test_data(4);

        assert_eq!(v.take(2), None);

        v.insert_test_data(1);

        // still not ready (element at 0 is missing)
        assert_eq!(v.take(2), None);

        v.insert_test_data(0);

        // now it is ready
        assert_eq!(
            v.take(2),
            Some([test_data_at(0), test_data_at(1), test_data_at(2)].concat())
        );
        assert_eq!(3..4_usize, v.missing());

        v.insert_test_data(3);

        assert_eq!(v.take(2), Some([test_data_at(3), test_data_at(4)].concat()));

        // buffer should be empty by now
        assert_eq!(v.take(1), None);
    }

    proptest::prop_compose! {
        fn arb_shuffle()(cap in 2..1000_usize) -> Vec<usize> {
            use rand::seq::SliceRandom;

            let mut indices = (0..cap).collect::<Vec<_>>();
            indices.shuffle(&mut crate::rand::thread_rng());
            indices
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_size_seq(cap in 2..1000_usize) {
            let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(NonZeroUsize::new(cap).unwrap());
            assert!(v.missing().is_empty());
            for j in 0..2 {
                for i in 0..cap {
                    v.insert_test_data(j * cap + i);
                }
                assert_eq!(v.take(1).unwrap().len(), cap * ELEMENT_SIZE);
            }
        }

        #[test]
        fn arbitrary_size_shuffle(indices in arb_shuffle(), excess in 0..10_usize) {
            let cap = indices.len();
            let size = NonZeroUsize::new(cap + excess).unwrap();
            let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(size);
            assert!(v.missing().is_empty());
            for j in 0..2 {
                for &i in &indices {
                    v.insert_test_data(j * cap + i);
                }
                assert_eq!(v.take(1).unwrap().len(), cap * ELEMENT_SIZE);
            }
        }
    }
}
