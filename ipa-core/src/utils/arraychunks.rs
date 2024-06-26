use crate::ff::PrimeField;

#[allow(dead_code)]
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

impl<F: PrimeField, I: Iterator<Item = F>> ArrayChunkIterator for I {}

#[allow(clippy::while_let_on_iterator)]
impl<F, I, const L: usize> Iterator for ArrayChunk<I, L>
where
    F: PrimeField,
    I: Iterator<Item = F>,
{
    type Item = [I::Item; L];

    fn next(&mut self) -> Option<Self::Item> {
        let mut array = [F::ZERO; L];
        let mut counter = 0usize;
        while let Some(element) = self.iter.next() {
            array[counter] = element;
            counter += 1;
            if counter == L {
                break;
            }
        }
        if counter == 0 {
            None
        } else {
            Some(array)
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
