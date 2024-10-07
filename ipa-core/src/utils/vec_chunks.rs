use std::{cmp::min, mem};

pub struct VecChunks<T> {
    vec: Vec<T>,
    chunk_size: usize,
}

impl<T> Iterator for VecChunks<T> {
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = min(self.vec.len(), self.chunk_size);
        (pos != 0).then(|| {
            let rest = self.vec.split_off(pos);
            mem::replace(&mut self.vec, rest)
        })
    }
}

pub fn vec_chunks<T>(vec: Vec<T>, chunk_size: usize) -> impl Iterator<Item = Vec<T>> {
    assert!(chunk_size != 0);
    VecChunks { vec, chunk_size }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::vec_chunks;
    use crate::ff::{Field, Fp61BitPrime};

    #[test]
    fn vec_chunk_iter() {
        let elements = vec![Fp61BitPrime::ONE; 4];

        let mut vec_chunk_iterator = vec_chunks(elements, 3);

        assert_eq!(
            vec_chunk_iterator.next().unwrap(),
            vec![Fp61BitPrime::ONE; 3]
        );
        assert_eq!(
            vec_chunk_iterator.next().unwrap(),
            vec![Fp61BitPrime::ONE; 1]
        );
        assert!(vec_chunk_iterator.next().is_none());
    }

    #[test]
    fn vec_chunk_empty() {
        let vec = Vec::<Fp61BitPrime>::new();
        assert!(vec_chunks(vec, 1).next().is_none());
    }
}
