use std::iter::zip;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        context::Context,
        RecordId,
        ipa_prf::boolean_ops::{
            addition_sequential::integer_add,
        },
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};


pub async fn integer_mul<C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
    y: &BitDecomposed<AdditiveShare<Boolean, N>>,
) -> Result<
    (
        BitDecomposed<AdditiveShare<Boolean, N>>,
        AdditiveShare<Boolean, N>,
    ),
    Error,
>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
    Gate: StepNarrow<S>,
{
    //TODO: To be implemented
}