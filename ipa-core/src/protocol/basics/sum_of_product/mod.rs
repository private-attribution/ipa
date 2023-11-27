use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, UpgradedMaliciousContext},
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
    },
};

pub(crate) mod malicious;
mod semi_honest;

#[async_trait]
pub trait SumOfProducts<C: Context>: Sized {
    async fn sum_of_products<'fut>(
        ctx: C,
        record_id: RecordId,
        a: &[Self],
        b: &[Self],
    ) -> Result<Self, Error>
    where
        C: 'fut;
}

#[async_trait]
impl<C: Context, F: Field> SumOfProducts<C> for Replicated<F> {
    async fn sum_of_products<'fut>(
        ctx: C,
        record_id: RecordId,
        a: &[Self],
        b: &[Self],
    ) -> Result<Self, Error>
    where
        C: 'fut,
    {
        semi_honest::sum_of_products(ctx, record_id, a, b).await
    }
}

#[async_trait]
impl<'a, F: ExtendableField> SumOfProducts<UpgradedMaliciousContext<'a, F>>
    for MaliciousReplicated<F>
{
    async fn sum_of_products<'fut>(
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
        a: &[Self],
        b: &[Self],
    ) -> Result<Self, Error>
    where
        'a: 'fut,
    {
        malicious::sum_of_products(ctx, record_id, a, b).await
    }
}
