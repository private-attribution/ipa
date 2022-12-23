use bitvec::bitvec;
use bitvec::prelude::BitVec;
use std::fmt::Debug;
use std::ops::Range;

/// A vector of bytes that never grows over a certain size or shrinks below that size.
/// Vector is segmented into regions and `max_size` is a factor of number of regions.
/// For example, if number of regions is `2`, then `max_size` must be a multiple of two.
///
/// Elements can be added to this vector in random order as long as the total number of elements
/// does not exceed the overall capacity of the vector. An attempt to do so, will lead to a panic.
/// Every element is stored by a specific offset and it is assumed that all elements are of the same
/// size.
///
/// The layout of the vector with some elements added to it is presented below. In this example,
/// vector has 3 regions and `X` indicates that space at that element is occupied.
///
///  region1  region2  region3
/// `[X,_,_,_][X,_,X,_][_,X,_,X]`
///
/// Once `region1` is completely filled up, it is possible to drain the vector. Draining will cause
/// **all** elements from the head of the queue to be removed
///
/// `[X,X,X,X][X,_,X,_][_,X,_,X] -> `take` -> [_,X,_,_][X,_,X,_][_,_,_,_]`
///
/// This vector is used inside the send buffer to keep track of messages added to it. Once first
/// batch of messages is ready (region1 is full), it drains this vector and send those messages
/// down to the network layer
#[derive(Debug)]
pub struct FixedSizeByteVec<const N: usize> {
    data: Vec<u8>,
    added: BitVec,
    capacity: usize,
    end: usize,
}

impl<const N: usize> FixedSizeByteVec<N> {
    pub const ELEMENT_SIZE_BYTES: usize = N;

    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0_u8; N * capacity],
            added: bitvec![0; capacity],
            capacity,
            end: capacity,
        }
    }

    /// Inserts a new element to the specified position, returning the previous element at this `index`.
    /// ## Panics
    /// Panics if `index` is out of bounds or if something was previously inserted at `index`.
    pub fn insert<D: Debug>(&mut self, channel: D, index: usize, elem: &[u8; N]) {
        // Translate from an absolute index into a relative one.
        let index = index
            .checked_sub(self.end - self.capacity)
            .unwrap_or_else(|| panic!("Duplicate send for index {index} on channel {channel:?}"));
        let start = index * N;
        let offset = start..start + N;

        assert!(
            !self.added.replace(index, true),
            "Duplicate send for index {index} on channel {channel:?}"
        );
        self.data[offset].copy_from_slice(elem);
    }

    /// Return any gap ahead of the first missing value.
    #[cfg(any(test, debug_assertions))]
    pub fn missing(&self) -> Range<usize> {
        let start = self.end - self.capacity;
        let absent = self.added.leading_zeros();
        if absent == self.capacity {
            start..start
        } else {
            start..(start + absent)
        }
    }

    /// Takes a block of elements from the beginning of the vector, or `None` if
    /// fewer than `min_count` elements have been inserted at the start of the buffer.
    pub fn take(&mut self, min_count: usize) -> Option<Vec<u8>> {
        let contiguous = self.added.leading_ones();

        if contiguous < min_count {
            return None;
        }
        self.added.drain(..contiguous).for_each(drop);
        let r = self.data.drain(..contiguous * N).collect();
        self.end += contiguous;

        // clear out last `contiguous` elements in the buffer
        self.added.resize(self.added.len() + contiguous, false);
        self.data.resize(self.data.len() + contiguous * N, 0);

        Some(r)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::helpers::buffers::fsv::FixedSizeByteVec;
    use proptest::num::usize;

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
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3);
        v.insert_test_data(0);
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));
    }

    #[test]
    fn gap() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3);
        assert!(v.missing().is_empty());
        v.insert_test_data(1);
        assert_eq!(0..1_usize, v.missing());
    }

    #[test]
    #[should_panic(expected = "Duplicate send for index 0 on channel \"duplicate\"")]
    fn duplicate_insert() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3);
        v.insert_test_data(0);
        v.insert("duplicate", 0, &[10; ELEMENT_SIZE]);
    }

    #[test]
    #[should_panic(expected = "Duplicate send for index 0 on channel \"taken\"")]
    fn insert_taken() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3);
        v.insert_test_data(0);
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));
        v.insert("taken", 0, &[10; ELEMENT_SIZE]);
    }

    #[test]
    #[should_panic(expected = "index 10 out of range")]
    fn index_out_of_bounds() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(1);
        v.insert("oob", 10, &[1; ELEMENT_SIZE]);
    }

    #[test]
    fn take() {
        const CAPACITY: usize = 2;
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(CAPACITY);
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
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3 * 2);
        assert_eq!(6, v.capacity);

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
}
