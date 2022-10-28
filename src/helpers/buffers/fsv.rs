use std::ops::{Range};

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
/// [X,_,_,_][_,_,X,_][_,X,_,X]
///
/// Once `region1` is completely filled up, it is possible to drain the vector
///
/// [X,X,X,X][_,_,X,_][_,X,_,X] -> `drain` -> [_,_,X,_][_,X,_,X][_,_,_,_]
///
///
/// This vector is used inside the send buffer to keep track of messages added to it. Once first
/// batch of messages is ready (region1 is full), it drains this vector and send those messages
/// down to the network layer
pub struct FixedSizeByteVec<const N: usize> {
    data: Vec<u8>,
    region_size: usize,
    // TODO replace with bitvec
    added: Vec<bool>,
}

impl <const N: usize> FixedSizeByteVec<N> {
    pub fn new(region_count: usize, region_size: usize) -> Self {
        // assert_eq!(region_size % N, 0);
        Self {
            data: vec![0_u8; region_size * N * region_count],
            added: vec![false; region_size * region_count],
            region_size,
        }
    }

    pub fn insert(&mut self, index: usize, elem: [u8; N]) -> Option<[u8; N]> {
        let offset = Self::offset(index);

        // if index is out of bounds, this line will panic, there is no need for additional check
        if self.added[index] {
            // this is not supposed to be on the hot path, this branch is executed when there is
            // an error and message with the same record id is received more than once, so
            // copying here is fine.
            let r = self.data[offset.clone()].try_into().unwrap();
            self.data[offset].copy_from_slice(&elem);

            Some(r)
        } else {
            self.added[index] = true;
            self.data[offset].copy_from_slice(&elem);

            None
        }
    }

    pub fn ready(&self) -> bool {
        self.added[..self.region_size].iter().all(|v| *v)
    }

    pub fn drain(&mut self) -> Option<Vec<u8>> {
        if self.ready() {
            self.added.drain(..self.region_size).for_each(drop);
            let r = self.data.drain(..self.region_size*N).collect();

            // restore the elements at the end of the buffer
            self.data.resize(self.data.len() + self.region_size * N, 0);
            self.added.resize(self.added.len() + self.region_size, false);

            Some(r)
        } else {
            None
        }
    }

    fn offset(index: usize) -> Range<usize> {
        let start = index * N;
        start..start + N
    }
}

#[cfg(test)]
mod tests {
    
    use proptest::num::usize;
    use crate::helpers::buffers::fsv::FixedSizeByteVec;

    const ELEMENT_SIZE: usize = 8;
    fn test_data_at(mut index: usize) -> [u8; ELEMENT_SIZE] {
        if index == 0 {
            // zeroes are bad as test data
            index = 255;
        }
        #[allow(clippy::cast_possible_truncation)]
        [index as u8; ELEMENT_SIZE]
    }

    trait FSBTestExt {
        fn insert_test_data(&mut self, index: usize) -> Option<[u8; ELEMENT_SIZE]>;
    }

    impl FSBTestExt for FixedSizeByteVec<ELEMENT_SIZE> {
        fn insert_test_data(&mut self, index: usize) -> Option<[u8; ELEMENT_SIZE]> {
            self.insert(index, test_data_at(index))
        }
    }


    #[test]
    fn insert() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(2, 1);
        v.insert_test_data(0);
        v.insert_test_data(1);

        assert!(v.ready());
        assert_eq!(v.drain(), Some(test_data_at(0).to_vec()));

        // element already present should be returned
        assert_eq!(v.insert(0, [10; ELEMENT_SIZE]), Some(test_data_at(1)));

        assert!(v.ready());
        assert_eq!(v.drain(), Some(vec![10; ELEMENT_SIZE]));
    }

    #[test]
    fn drain() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(2, 1);
        v.insert_test_data(0);

        // drain the first region
        assert!(v.ready());
        assert_eq!(v.drain(), Some(test_data_at(0).to_vec()));

        // second region became first because of shift but it is not ready to drain
        assert!(!v.ready());
        assert_eq!(v.drain(), None);

        // However there should be no elements in the second region because of the shift
        assert_eq!(v.insert_test_data(1), None);
    }

    #[test]
    fn drain_touches_first_region_only() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(2, 2);
        v.insert_test_data(2);
        v.insert_test_data(3);

        assert!(!v.ready());
        assert_eq!(v.drain(), None);

        v.insert_test_data(1);

        // still not ready (element at 0 is missing)
        assert!(!v.ready());
        assert_eq!(v.drain(), None);

        v.insert_test_data(0);

        // now it is ready
        assert!(v.ready());
        assert_eq!(
            v.drain(),
            Some(vec![test_data_at(0), test_data_at(1)].into_iter().flatten().collect())
        );

        // next region should be ready too as it was at capacity even earlier
        assert!(v.ready());
        assert_eq!(
            v.drain(),
            Some(vec![test_data_at(2), test_data_at(3)].into_iter().flatten().collect())
        );

        // buffer should be empty by now
        assert!(!v.ready());
        assert_eq!(v.drain(), None);
    }

    #[test]
    #[should_panic]
    fn index_out_of_bounds() {
        let mut v = FixedSizeByteVec::<ELEMENT_SIZE>::new(1, 1);
        v.insert(10, [1; ELEMENT_SIZE]);
    }
}