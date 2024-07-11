pub trait ArrayChunkIterator: Iterator {
    /// This function returns an iterator that yields arrays of size `L`.
    /// When the amount of items in the iterator is not a multiple of `L`
    /// the iterator fills the last array with zero elements.
    fn chunk_array<const L: usize>(self) -> ArrayChunk<Self, L>
    where
        Self: Sized,
    {
        ArrayChunk { iter: self }
    }
}

pub struct ArrayChunk<I, const L: usize> {
    iter: I,
}

impl<F: Default + Copy, I: Iterator<Item = F>> ArrayChunkIterator for I {}

impl<F, I, const L: usize> Iterator for ArrayChunk<I, L>
where
    F: Default + Copy,
    I: Iterator<Item = F>,
{
    type Item = [I::Item; L];

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(v) = self.iter.next() {
            let mut array = [F::default(); L];
            array[0] = v;
            for element in array.iter_mut().skip(1) {
                *element = self.iter.next().unwrap_or_default();
            }
            Some(array)
        } else {
            None
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Field, Fp61BitPrime},
        secret_sharing::SharedValue,
        utils::arraychunks::ArrayChunkIterator,
    };

    #[test]
    fn array_chunk_iter() {
        let elements = vec![Fp61BitPrime::ONE; 4];

        let mut array_chunk_iterator = elements.into_iter().chunk_array::<3>();

        assert_eq!(array_chunk_iterator.next().unwrap(), [Fp61BitPrime::ONE; 3]);
        assert_eq!(
            array_chunk_iterator.next().unwrap(),
            [Fp61BitPrime::ONE, Fp61BitPrime::ZERO, Fp61BitPrime::ZERO]
        );
    }

    #[test]
    fn array_chunk_empty() {
        let elements = Vec::<Fp61BitPrime>::new();
        assert!(elements.into_iter().chunk_array::<1>().next().is_none());
    }
}
