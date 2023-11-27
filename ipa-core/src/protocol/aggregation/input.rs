use std::ops::Add;

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{GaloisField, Serializable},
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct SparseAggregateInputRow<CV: GaloisField, BK: GaloisField> {
    pub contribution_value: Replicated<CV>,
    pub breakdown_key: Replicated<BK>,
}

impl<CV: GaloisField, BK: GaloisField> Serializable for SparseAggregateInputRow<CV, BK>
where
    Replicated<CV>: Serializable,
    Replicated<BK>: Serializable,
    <Replicated<CV> as Serializable>::Size: Add<<Replicated<BK> as Serializable>::Size>,
    <<Replicated<CV> as Serializable>::Size as Add<<Replicated<BK> as Serializable>::Size>>::Output:
        ArrayLength,
{
    type Size = <<Replicated<CV> as Serializable>::Size as Add<
        <Replicated<BK> as Serializable>::Size,
    >>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let cv_sz = <Replicated<CV> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        self.contribution_value
            .serialize(GenericArray::from_mut_slice(&mut buf[..cv_sz]));
        self.breakdown_key
            .serialize(GenericArray::from_mut_slice(&mut buf[cv_sz..cv_sz + bk_sz]));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let cv_sz = <Replicated<CV> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        let value = Replicated::<CV>::deserialize(GenericArray::from_slice(&buf[..cv_sz]));
        let breakdown_key =
            Replicated::<BK>::deserialize(GenericArray::from_slice(&buf[cv_sz..cv_sz + bk_sz]));
        Self {
            contribution_value: value,
            breakdown_key,
        }
    }
}

impl<CV: GaloisField, BK: GaloisField> SparseAggregateInputRow<CV, BK>
where
    SparseAggregateInputRow<CV, BK>: Serializable,
{
    /// Splits the given slice into chunks aligned with the size of this struct and returns an
    /// iterator that produces deserialized instances.
    ///
    /// ## Panics
    /// Panics if the slice buffer is not aligned with the size of this struct.
    pub fn from_byte_slice(input: &[u8]) -> impl Iterator<Item = Self> + '_ {
        assert_eq!(
            0,
            input.len() % <SparseAggregateInputRow<CV, BK> as Serializable>::Size::USIZE,
            "input is not aligned"
        );
        input
            .chunks(<SparseAggregateInputRow<CV, BK> as Serializable>::Size::USIZE)
            .map(|chunk| {
                SparseAggregateInputRow::<CV, BK>::deserialize(GenericArray::from_slice(chunk))
            })
    }
}
