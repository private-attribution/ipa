use async_trait::async_trait;
use raw_ipa::build_async_pipeline;
use raw_ipa::error::{Error, Res};
use raw_ipa::pipeline::async_pipe::{APipeline, AStep};
use std::time::Duration;

/// unchanged from regular pipeline
struct Start {
    x: i32,
    y: i32,
}
#[async_trait]
impl AStep for Start {
    type Input = ();
    type Output = (i32, i32);

    async fn compute(&self, _: Self::Input) -> Res<Self::Output> {
        Ok((self.x, self.y))
    }
}

/// unchanged from regular pipeline
struct Add {}
#[async_trait]
impl AStep for Add {
    type Input = (i32, i32);
    type Output = i32;

    async fn compute(&self, inp: Self::Input) -> Res<Self::Output> {
        Ok(inp.0 + inp.1)
    }
}

/// arbitrary async work done (literally a `time::sleep`) to prove that it can occur
struct PairWith3 {}
#[async_trait]
impl AStep for PairWith3 {
    type Input = i32;
    type Output = (i32, i32);

    async fn compute(&self, inp: Self::Input) -> Res<Self::Output> {
        let res = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            3
        });
        res.await
            .map_or(Err(Error::Internal), |three| Ok((inp, three)))
    }
}

struct ExampleAPipeline {}
#[async_trait]
impl APipeline<(), i32> for ExampleAPipeline {
    async fn pipeline(&self, _: ()) -> Res<i32> {
        let pipe = build_async_pipeline!(Start { x: 1, y: 2 } => Add {} => PairWith3 {} => Add {});
        pipe(()).await
    }
}

#[tokio::main]
async fn main() -> Res<()> {
    let pipe = ExampleAPipeline {};
    pipe.pipeline(()).await.map(|res| println!("{}", res))
}
