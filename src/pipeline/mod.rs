pub mod error;

pub use error::Result;

use async_trait::async_trait;
use futures::stream::Stream;
use futures::{SinkExt, StreamExt};

#[async_trait]
pub trait Step {
    type Input: Send + Sync;
    type Output: Send + Sync;
    async fn compute(&self, inp: Self::Input) -> Result<Self::Output>;
}

pub struct StreamStep<
    Input: Send + Sync,
    Output: Send + Sync,
    S: Step<Input = Input, Output = Output> + Send + Sync,
>(S);
// TODO: any way to have this impl `Step`?
impl<
        Input: Send + Sync,
        Output: Send + Sync + 'static,
        S: Step<Input = Input, Output = Output> + Send + Sync + 'static,
    > StreamStep<Input, Output, S>
{
    pub async fn compute(
        self,
        inps: impl Stream<Item = Input> + Send + 'static,
    ) -> impl Stream<Item = Result<Output>> {
        let (mut tx, rx) = futures::channel::mpsc::channel(32);
        tokio::spawn(async move {
            let mut pinned = Box::pin(inps);
            while let Some(inp) = pinned.next().await {
                let _ = tx.send(self.0.compute(inp).await).await;
            }
        });
        rx
        // TODO: below does not compile
        // inps.then(|inp| self.0.compute(inp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[tokio::test]
    async fn async_example() {
        struct AsyncStep {}

        #[async_trait]
        impl Step for AsyncStep {
            type Input = (i32, i32);
            type Output = i32;

            async fn compute(&self, inp: Self::Input) -> Result<Self::Output> {
                Ok(inp.0 + inp.1)
            }
        }

        let iter = vec![(1, 1), (2, 2), (3, 3), (4, 4)];
        let expected_iter = iter
            .clone()
            .into_iter()
            .map(|(x, y)| x + y)
            .collect::<Vec<_>>();

        let iter_stream = futures::stream::iter(iter);
        let step = AsyncStep {};
        let stream_step = StreamStep(step);

        let res_stream = stream_step.compute(iter_stream).await;
        let res = res_stream.collect::<Vec<_>>().await;
        let res = res.into_iter().collect::<Result<Vec<_>>>().unwrap();

        assert_eq!(expected_iter, res);
    }
}
