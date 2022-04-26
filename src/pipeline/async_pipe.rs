/// this module mirrors the synchronous pipeline, but with async/await via tokio.
/// requires a workaround `async_trait` to use async functions inside traits
use crate::error::Res;
use async_trait::async_trait;

/// The only difference from `PStep` is the `async fn compute`
#[async_trait]
pub trait AStep {
    type Input;
    type Output;
    async fn compute(&self, inp: Self::Input) -> Res<Self::Output>;
}

/// the only difference from `build_pipeline` is the `async move` block, and the `.await` on
/// `.compute`.
#[macro_export]
macro_rules! build_async_pipeline {
    ($($step:expr)=>+) => {{
        move |res| async move {
            $(
                let res = $step.compute(res).await?;
            )*
            Ok(res)
        }
    }};
}

/// The only difference from `Pipeline` is the `async fn pipeline`
#[async_trait]
pub trait APipeline<Input, Output> {
    async fn pipeline(&self, inp: Input) -> Res<Output>;
}
