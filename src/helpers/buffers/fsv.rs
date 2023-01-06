use bitvec::bitvec;
use bitvec::prelude::BitVec;

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
    taken: usize,
}

impl<const N: usize> FixedSizeByteVec<N> {
    pub const ELEMENT_SIZE_BYTES: usize = N;

    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0_u8; N * capacity],
            added: bitvec![0; capacity],
            taken: 0,
        }
    }

    /// Inserts a new element to the specified position, returning the previous element at this `index`.
    /// ## Panics
    /// Panics if `index` is out of bounds or if something was previously inserted at `index`.
    pub fn insert(&mut self, index: usize, elem: &[u8; N]) {
        // if index is out of bounds, this line will panic, there is no need for additional check
        // TODO: save runtime cost with `debug_assert!()`, though that would affects panic tests
        assert!(!self.added[index]);
        let start = index * N;
        let offset = start..start + N;

        println!("FSV {self:p} {:?}", self.added);
        self.added.set(index, true);
        println!("FSV {self:p} added {index} -> {:?}", self.added);
        self.data[offset].copy_from_slice(elem);
    }

    /// Returns `true` if record at the given index exists.
    pub fn added(&self, index: usize) -> bool {
        self.added[index]
    }

    /// Takes a block of elements from the beginning of the vector, or `None` if
    /// fewer than `min_count` elements have been inserted at the start of the buffer.
    pub fn take(&mut self, min_count: usize) -> Option<Vec<u8>> {
        let contiguous = self.added.leading_ones();
        println!("FSV {self:p} available {contiguous}");
        if contiguous < min_count {
            return None;
        }
        self.added.drain(..contiguous).for_each(drop);
        let r = self.data.drain(..contiguous * N).collect();
        self.taken += contiguous;

        // clear out last `contiguous` elements in the buffer
        self.added.resize(self.added.len() + contiguous, false);
        self.data.resize(self.data.len() + contiguous * N, 0);

        Some(r)
    }

    /// Returns total number of elements evicted from this buffer since the creation.
    pub fn taken(&self) -> usize {
        self.taken
    }

    /// returns the maximum number of elements this vector can hold.
    pub fn capacity(&self) -> usize {
        self.data.capacity() / N
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
            self.insert(index, &test_data_at(index));
        }
    }

    #[test]
    #[should_panic]
    fn insert() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3);
        v.insert_test_data(0);
        assert!(v.added(0));
        v.insert_test_data(2);
        assert!(v.added(2));
        assert!(!v.added(1));

        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));

        v.insert(1, &[10; ELEMENT_SIZE]);
    }

    #[test]
    fn take() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(2);
        v.insert_test_data(0);

        // drain the first region
        assert_eq!(v.take(1), Some(test_data_at(0).to_vec()));

        // second region became first because of shift but it is not ready to drain
        assert_eq!(v.take(1), None);

        // However there should be no elements in the second region because of the shift
        v.insert_test_data(1);
        assert_eq!(1, v.taken());
    }

    #[test]
    fn take_is_greedy() {
        // Insert elements X,X,X,_,X,_,_
        // first take should remove first 3 elements leaving the element at index 4 intact
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(3 * 2);
        assert_eq!(6, v.capacity());

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
        assert_eq!(3, v.taken());

        v.insert_test_data(0);

        assert_eq!(v.take(2), Some([test_data_at(0), test_data_at(4)].concat()));
        assert_eq!(5, v.taken());

        // buffer should be empty by now
        assert_eq!(v.take(1), None);
    }

    #[test]
    #[should_panic]
    fn index_out_of_bounds() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(1);
        v.insert(10, &[1; ELEMENT_SIZE]);
    }
}
