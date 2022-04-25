use crate::error::Res;
use async_trait::async_trait;

#[async_trait]
pub trait AStep {
    type Input;
    type Output;
    async fn compute(&self, inp: Self::Input) -> Res<Self::Output>;
}

#[macro_export]
macro_rules! build_async_pipeline {
    ($($step:expr),+) => {{
        move |res| async move {
            $(
                let res = $step.compute(res).await?;
            )*
            Ok(res)
        }
    }};
}

#[async_trait]
pub trait APipeline<Input, Output> {
    async fn pipeline(&self, inp: Input) -> Res<Output>;
}
