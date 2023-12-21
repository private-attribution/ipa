use std::ops::Add;

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    error::Error,
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
    type DeserError = Error;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let cv_sz = <Replicated<CV> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        self.contribution_value
            .serialize(GenericArray::from_mut_slice(&mut buf[..cv_sz]));
        self.breakdown_key
            .serialize(GenericArray::from_mut_slice(&mut buf[cv_sz..cv_sz + bk_sz]));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserError> {
        let cv_sz = <Replicated<CV> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;

        let value = Replicated::<CV>::deserialize(GenericArray::from_slice(&buf[..cv_sz]))
            .map_err(|e| Error::ParseError(e.into()))?;
        let breakdown_key =
            Replicated::<BK>::deserialize(GenericArray::from_slice(&buf[cv_sz..cv_sz + bk_sz]))
                .map_err(|e| Error::ParseError(e.into()))?;
        Ok(Self {
            contribution_value: value,
            breakdown_key,
        })
    }
}
