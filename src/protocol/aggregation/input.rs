use std::ops::Add;

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{GaloisField, Gf2, Serializable},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed,
        Linear as LinearSecretSharing,
    },
};

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct AggregateInputRow<V: GaloisField, BK: GaloisField> {
    pub value: Replicated<V>,
    pub breakdown_key: Replicated<BK>,
}

impl<V: GaloisField, BK: GaloisField> Serializable for AggregateInputRow<V, BK>
where
    Replicated<V>: Serializable,
    Replicated<BK>: Serializable,
    <Replicated<V> as Serializable>::Size: Add<<Replicated<BK> as Serializable>::Size>,
    <<Replicated<V> as Serializable>::Size as Add<<Replicated<BK> as Serializable>::Size>>::Output:
        ArrayLength<u8>,
{
    type Size = <<Replicated<V> as Serializable>::Size as Add<
        <Replicated<BK> as Serializable>::Size,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let v_sz = <Replicated<V> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        self.value
            .serialize(GenericArray::from_mut_slice(&mut buf[..v_sz]));
        self.breakdown_key
            .serialize(GenericArray::from_mut_slice(&mut buf[v_sz..v_sz + bk_sz]));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let v_sz = <Replicated<V> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        let value = Replicated::<V>::deserialize(GenericArray::from_slice(&buf[..v_sz]));
        let breakdown_key =
            Replicated::<BK>::deserialize(GenericArray::from_slice(&buf[v_sz..v_sz + bk_sz]));
        Self {
            value,
            breakdown_key,
        }
    }
}

impl<V: GaloisField, BK: GaloisField> AggregateInputRow<V, BK>
where
    AggregateInputRow<V, BK>: Serializable,
{
    /// Splits the given slice into chunks aligned with the size of this struct and returns an
    /// iterator that produces deserialized instances.
    ///
    /// ## Panics
    /// Panics if the slice buffer is not aligned with the size of this struct.
    pub fn from_byte_slice(input: &[u8]) -> impl Iterator<Item = Self> + '_ {
        assert_eq!(
            0,
            input.len() % <AggregateInputRow<V, BK> as Serializable>::Size::USIZE,
            "input is not aligned"
        );
        input
            .chunks(<AggregateInputRow<V, BK> as Serializable>::Size::USIZE)
            .map(|chunk| AggregateInputRow::<V, BK>::deserialize(GenericArray::from_slice(chunk)))
    }
}

pub struct BinarySharedAggregateInputs<T: LinearSecretSharing<Gf2>> {
    pub value: BitDecomposed<T>,
    pub breakdown_key: BitDecomposed<T>,
}

impl<T: LinearSecretSharing<Gf2>> BinarySharedAggregateInputs<T> {
    #[must_use]
    pub fn new(value: BitDecomposed<T>, breakdown_key: BitDecomposed<T>) -> Self {
        Self {
            value,
            breakdown_key,
        }
    }
}
