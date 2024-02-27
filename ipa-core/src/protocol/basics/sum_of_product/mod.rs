use async_trait::async_trait;

use crate::{
    error::Error,
    protocol::{context::Context, RecordId},
};

#[cfg(feature = "descriptive-gate")]
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
