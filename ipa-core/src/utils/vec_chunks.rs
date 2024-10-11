use std::cmp::min;

pub struct VecChunks<T: Clone> {
    vec: Vec<T>,
    pos: usize,
    chunk_size: usize,
}

impl<T: Clone> Iterator for VecChunks<T> {
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.pos;
        let len = min(self.vec.len() - start, self.chunk_size);
        (len != 0).then(|| {
            self.pos += len;
            self.vec[start..start + len].to_vec()
        })
    }
}

pub fn vec_chunks<T: Clone>(vec: Vec<T>, chunk_size: usize) -> impl Iterator<Item = Vec<T>> {
    assert!(chunk_size != 0);
    VecChunks {
        vec,
        pos: 0,
        chunk_size,
    }
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
