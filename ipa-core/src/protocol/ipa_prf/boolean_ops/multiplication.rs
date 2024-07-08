use ipa_step::StepNarrow;

use crate::{
    error::Error,
    ff::boolean::Boolean,
    protocol::{
        basics::{BooleanProtocols},
        boolean::NBitStep,
        context::Context, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd},
};

pub async fn integer_mul<C, S, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &BitDecomposed<AdditiveShare<Boolean, N>>,
    y: &BitDecomposed<AdditiveShare<Boolean, N>>,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    S: NBitStep,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, N>,
{
    //TODO: To be implemented
    Err(Error::Unsupported("still not implemented".to_owned()))
}
