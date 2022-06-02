pub mod comms;
pub mod error;
pub mod hashmap_thread;

use async_trait::async_trait;
use comms::Comms;
use error::Res;
use std::sync::Arc;

/// The only difference from `PStep` is the `async fn compute`
#[async_trait]
pub trait Step {
    type Input;
    type Output;
    async fn compute(
        &self,
        inp: Self::Input,
        helper: Arc<impl Comms + Send + Sync + 'static>,
    ) -> Res<Self::Output>;
}

/// the only difference from `build_pipeline` is the `async move` block, and the `.await` on
/// `.compute`.
#[macro_export]
macro_rules! build_pipeline {
    ($comms:expr, $($step:expr)=>+) => {{
        move |res| async move {
            $(
                let res = $step.compute(res, $comms).await?;
            )*
            Ok(res)
        }
    }};
}

/// The only difference from `Pipeline` is the `async fn pipeline`
#[async_trait]
pub trait Pipeline<Input, Output> {
    async fn pipeline(&self, inp: Input) -> Res<Output>;
}
