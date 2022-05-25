use async_trait::async_trait;
use raw_ipa::build_async_pipeline;
use raw_ipa::error::Res;
use raw_ipa::pipeline::comms::channel::{Channel, SendStr};
use raw_ipa::pipeline::comms::Comms;
use raw_ipa::pipeline::error::Res as PipelineRes;
use raw_ipa::pipeline::{Pipeline, Step};
use std::sync::Arc;
use std::time::Duration;
use tokio::try_join;
use uuid::Uuid;

/// unchanged from regular pipeline
struct Start {
    uuid: Uuid,
    x: i32,
    y: i32,
}
#[async_trait]
impl Step for Start {
    type Input = ();
    type Output = (i32, i32);

    async fn compute(&self, _: Self::Input, _: Arc<impl Comms>) -> PipelineRes<Self::Output> {
        Ok((self.x, self.y))
    }

    fn unique_id(&self) -> Uuid {
        self.uuid
    }
}

/// unchanged from regular pipeline
struct Add {
    uuid: Uuid,
}
#[async_trait]
impl Step for Add {
    type Input = (i32, i32);
    type Output = i32;

    async fn compute(&self, inp: Self::Input, _: Arc<impl Comms>) -> PipelineRes<Self::Output> {
        Ok(inp.0 + inp.1)
    }

    fn unique_id(&self) -> Uuid {
        self.uuid
    }
}

/// arbitrary async work done (literally a `time::sleep`) to prove that it can occur
struct PairWith3 {
    uuid: Uuid,
}
#[async_trait]
impl Step for PairWith3 {
    type Input = i32;
    type Output = (i32, i32);

    async fn compute(&self, inp: Self::Input, _: Arc<impl Comms>) -> PipelineRes<Self::Output> {
        let res = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            3
        });
        let three = res.await?;
        Ok((inp, three))
    }

    fn unique_id(&self) -> Uuid {
        self.uuid
    }
}

struct Stringify {
    uuid: Uuid,
}
#[async_trait]
impl Step for Stringify {
    type Input = i32;
    type Output = String;

    async fn compute(&self, inp: Self::Input, _: Arc<impl Comms>) -> PipelineRes<Self::Output> {
        Ok(inp.to_string())
    }

    fn unique_id(&self) -> Uuid {
        self.uuid
    }
}
struct ForwardData {
    uuid: Uuid,
    receive_uuid: Uuid,
}
#[async_trait]
impl Step for ForwardData {
    type Input = String;
    type Output = String;

    async fn compute(
        &self,
        inp: Self::Input,
        helper: Arc<impl Comms + Send + Sync + 'static>,
    ) -> PipelineRes<Self::Output> {
        let sent = helper.send_to_next(self.unique_id(), SendStr(inp.clone()));
        let received = helper.receive_from::<SendStr>(self.receive_uuid);
        let (_, res) = try_join!(sent, received)?;
        Ok(res.to_string())
    }

    fn unique_id(&self) -> Uuid {
        self.uuid
    }
}

struct ExampleAPipeline<H: Comms> {
    comms: Arc<H>,
}
#[async_trait]
impl<C: Comms + Send + Sync + 'static> Pipeline<(), i32> for ExampleAPipeline<C> {
    async fn pipeline(&self, _: ()) -> PipelineRes<i32> {
        let pipe = build_async_pipeline!(self.comms.clone(),
            Start { x: 1, y: 2, uuid: Uuid::new_v4() } =>
            Add { uuid: Uuid::new_v4() } =>
            PairWith3 { uuid: Uuid::new_v4() } =>
            Add { uuid: Uuid::new_v4() }
        );
        pipe(()).await
    }
}

struct ForwardingPipeline<H: Comms> {
    comms: Arc<H>,
    root_uuid: Uuid,
}
#[async_trait]
impl<C: Comms + Send + Sync + 'static> Pipeline<(), String> for ForwardingPipeline<C> {
    async fn pipeline(&self, _: ()) -> PipelineRes<String> {
        let pipe = build_async_pipeline!(self.comms.clone(),
            Start { x: 1, y: 2, uuid: Uuid::new_v5(&self.root_uuid, &[1]) } =>
            Add { uuid: Uuid::new_v5(&self.root_uuid, &[2]) } =>
            Stringify { uuid: Uuid::new_v5(&self.root_uuid, &[3]) } =>
            ForwardData { uuid: Uuid::new_v5(&self.root_uuid, &[4]), receive_uuid: Uuid::new_v5(&self.root_uuid, &[4])}
        );
        pipe(()).await
    }
}

#[tokio::main]
async fn main() -> Res<()> {
    let (c1, c2, c3, c_run) = Channel::all_comms();
    let run_comms = tokio::spawn(c_run);
    let root_uuid = Uuid::new_v4();
    let run_pipe1 = tokio::spawn(async move {
        let pipe = ForwardingPipeline {
            comms: c1,
            root_uuid,
        };
        let res = pipe.pipeline(()).await;
        println!("pipeline 1 completed");
        pipe.comms.close().await?;
        res
    });
    let run_pipe2 = tokio::spawn(async move {
        let pipe = ForwardingPipeline {
            comms: c2,
            root_uuid,
        };
        let res = pipe.pipeline(()).await;
        println!("pipeline 2 completed");
        pipe.comms.close().await?;
        res
    });
    let run_pipe3 = tokio::spawn(async move {
        let pipe = ForwardingPipeline {
            comms: c3,
            root_uuid,
        };
        let res = pipe.pipeline(()).await;
        println!("pipeline 3 completed");
        pipe.comms.close().await?;
        res
    });
    let (_, pipe1_res, pipe2_res, pipe3_res) =
        try_join!(run_comms, run_pipe1, run_pipe2, run_pipe3)?;
    println!("1: {}, 2: {}, 3: {}", pipe1_res?, pipe2_res?, pipe3_res?);
    Ok(())
}
