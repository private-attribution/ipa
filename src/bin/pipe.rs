use async_trait::async_trait;
use log::info;
use raw_ipa::build_pipeline;
use raw_ipa::cli::Verbosity;
use raw_ipa::error::Result;
use raw_ipa::pipeline::comms::{Comms, Target};
use raw_ipa::pipeline::util::intra_process_comms;
use raw_ipa::pipeline::{self, Pipeline, Step};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::try_join;

/// unchanged from regular pipeline
struct Start {
    x: i32,
    y: i32,
}
#[async_trait]
impl Step for Start {
    type Input = ();
    type Output = (i32, i32);

    async fn compute(&self, _: Self::Input, _: Arc<impl Comms>) -> pipeline::Result<Self::Output> {
        Ok((self.x, self.y))
    }
}

/// unchanged from regular pipeline
struct Add {}
#[async_trait]
impl Step for Add {
    type Input = (i32, i32);
    type Output = i32;

    async fn compute(
        &self,
        inp: Self::Input,
        _: Arc<impl Comms>,
    ) -> pipeline::Result<Self::Output> {
        Ok(inp.0 + inp.1)
    }
}

/// arbitrary async work done (literally a `time::sleep`) to prove that it can occur
struct PairWith3 {}
#[async_trait]
impl Step for PairWith3 {
    type Input = i32;
    type Output = (i32, i32);

    async fn compute(
        &self,
        inp: Self::Input,
        _: Arc<impl Comms>,
    ) -> pipeline::Result<Self::Output> {
        let res = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            3
        });
        let three = res.await?;
        Ok((inp, three))
    }
}

struct Stringify {}
#[async_trait]
impl Step for Stringify {
    type Input = i32;
    type Output = String;

    async fn compute(
        &self,
        inp: Self::Input,
        _: Arc<impl Comms>,
    ) -> pipeline::Result<Self::Output> {
        Ok(inp.to_string())
    }
}
struct ForwardData {}

#[derive(Debug, Serialize, Deserialize)]
struct ExampleRequest {
    message: String,
}

#[async_trait]
impl Step for ForwardData {
    type Input = String;
    type Output = String;

    async fn compute(
        &self,
        inp: Self::Input,
        helper: Arc<impl Comms + Send + Sync + 'static>,
    ) -> pipeline::Result<Self::Output> {
        let sent = helper.send_to(
            Target::Next,
            ExampleRequest {
                message: inp.clone(),
            },
        );
        // let sent = helper.send_to_next(self.unique_id(), SendStr(inp.clone()));
        let received = helper.receive_from::<ExampleRequest>(Target::Prev);
        let (_, res) = try_join!(sent, received)?;
        Ok(res.message)
    }
}

struct ExampleAPipeline<C: Comms> {
    comms: Arc<C>,
}
#[async_trait]
impl<C: Comms> Pipeline<(), i32> for ExampleAPipeline<C> {
    async fn pipeline(&self, _: ()) -> pipeline::Result<i32> {
        let pipe = build_pipeline!(self.comms.clone(),
            Start { x: 1, y: 2 } =>
            Add {} =>
            PairWith3 {} =>
            Add {}
        );
        pipe(()).await
    }
}

struct ForwardingPipeline<C: Comms> {
    comms: Arc<C>,
}
#[async_trait]
impl<C: Comms> Pipeline<(), String> for ForwardingPipeline<C> {
    async fn pipeline(&self, _: ()) -> pipeline::Result<String> {
        let pipe = build_pipeline!(self.comms.clone(),
            Start { x: 1, y: 2 } =>
            Add {} =>
            Stringify {} =>
            ForwardData {}
        );
        pipe(()).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let logging = Verbosity::from_args();
    logging.setup_logging();

    let (c1, c2, c3, c_run) = intra_process_comms();
    tokio::spawn(c_run);
    let pipe1 = Arc::new(ForwardingPipeline { comms: c1.clone() });
    let run_pipe1 = {
        let pipe = pipe1.clone();
        tokio::spawn(async move {
            let res = pipe.pipeline(()).await;
            info!("pipeline 1 completed");
            res
        })
    };
    let pipe2 = Arc::new(ForwardingPipeline { comms: c2.clone() });
    let run_pipe2 = {
        let pipe = pipe2.clone();
        tokio::spawn(async move {
            let res = pipe.pipeline(()).await;
            info!("pipeline 2 completed");
            res
        })
    };
    let pipe3 = Arc::new(ForwardingPipeline { comms: c3.clone() });
    let run_pipe3 = {
        let pipe = pipe3.clone();
        tokio::spawn(async move {
            let res = pipe.pipeline(()).await;
            info!("pipeline 3 completed");
            res
        })
    };
    let (pipe1_res, pipe2_res, pipe3_res) = try_join!(run_pipe1, run_pipe2, run_pipe3)?;
    info!(
        "result: 1: {}, 2: {}, 3: {}",
        pipe1_res?, pipe2_res?, pipe3_res?
    );
    Ok(())
}
