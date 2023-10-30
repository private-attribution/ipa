use crate::{
    error::Error,
    ff::{Field, ArrayAccess},
    secret_sharing::WeakSharedValue,
    protocol::{RecordId, context::Context, basics::SecureMul, step::BitOpStep},
    secret_sharing::replicated::{semi_honest::AdditiveShare},
};

pub async fn multiply_array_with_element<C,S,T>(ctx: C, record_id: RecordId, x: &AdditiveShare<S>, e: &AdditiveShare<T>) -> Result<AdditiveShare<S>,Error>
where
    C: Context,
    S: ArrayAccess<usize, Element=T> + WeakSharedValue,
    T: Field,
{
    Ok((*x).clone())
}