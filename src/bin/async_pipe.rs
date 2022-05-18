use async_trait::async_trait;
use prost::Message;
use raw_ipa::build_async_pipeline;
use raw_ipa::error::Res;
use raw_ipa::pipeline::async_pipe::{APipeline, AStep, ChannelHelper, SendStr, THelper};
use raw_ipa::pipeline::error::Res as PipelineRes;
use raw_ipa::pipeline::hashmap_thread::HashMapHandler;
use raw_ipa::proto::pipe::ForwardRequest;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::task::JoinHandle;
use tokio::try_join;
use uuid::Uuid;

/// unchanged from regular pipeline
struct Start {
    uuid: Uuid,
    x: i32,
    y: i32,
}
#[async_trait]
impl AStep for Start {
    type Input = ();
    type Output = (i32, i32);

    async fn compute(&self, _: Self::Input, _: Arc<impl THelper>) -> PipelineRes<Self::Output> {
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
impl AStep for Add {
    type Input = (i32, i32);
    type Output = i32;

    async fn compute(&self, inp: Self::Input, _: Arc<impl THelper>) -> PipelineRes<Self::Output> {
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
impl AStep for PairWith3 {
    type Input = i32;
    type Output = (i32, i32);

    async fn compute(&self, inp: Self::Input, _: Arc<impl THelper>) -> PipelineRes<Self::Output> {
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
impl AStep for Stringify {
    type Input = i32;
    type Output = String;

    async fn compute(&self, inp: Self::Input, _: Arc<impl THelper>) -> PipelineRes<Self::Output> {
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
impl AStep for ForwardData {
    type Input = String;
    type Output = String;

    async fn compute(
        &self,
        inp: Self::Input,
        helper: Arc<impl THelper + Send + Sync + 'static>,
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

struct ExampleAPipeline<H: THelper> {
    helper: Arc<H>,
}
#[async_trait]
impl<H: THelper + Send + Sync + 'static> APipeline<(), i32> for ExampleAPipeline<H> {
    async fn pipeline(&self, _: ()) -> PipelineRes<i32> {
        let pipe = build_async_pipeline!(self.helper.clone(),
            Start { x: 1, y: 2, uuid: Uuid::new_v4() } =>
            Add { uuid: Uuid::new_v4() } =>
            PairWith3 { uuid: Uuid::new_v4() } =>
            Add { uuid: Uuid::new_v4() }
        );
        pipe(()).await
    }
}

struct ForwardingPipeline<H: THelper> {
    helper: Arc<H>,
    send_uuid: Uuid,
    receive_uuid: Uuid,
}
#[async_trait]
impl<H: THelper + Send + Sync + 'static> APipeline<(), String> for ForwardingPipeline<H> {
    async fn pipeline(&self, _: ()) -> PipelineRes<String> {
        let pipe = build_async_pipeline!(self.helper.clone(),
            Start { x: 1, y: 2, uuid: Uuid::new_v4() } =>
            Add { uuid: Uuid::new_v4() } =>
            Stringify { uuid: Uuid::new_v4() } =>
            ForwardData { uuid: self.send_uuid, receive_uuid: self.receive_uuid }
        );
        pipe(()).await
    }
}

#[tokio::main]
async fn main() -> Res<()> {
    let (h1_send, h1_recv) = channel(32);
    let (h2_send, mut h2_recv) = channel(32);
    let (h3_send, _) = channel(32);
    let (hashmap_send, hashmap_recv) = channel(32);
    let h1_recv_uuid = Uuid::new_v4();
    let h2_recv_uuid = Uuid::new_v4();
    let h1_helper = Arc::new(ChannelHelper::new(h2_send, h3_send, hashmap_send));
    let helper_runner = h1_helper.clone();

    let run_hashmap = tokio::spawn(HashMapHandler::new(hashmap_recv).run());
    let run_helper = tokio::spawn(async move { helper_runner.receive_data(h1_recv).await });
    let run_pipe = tokio::spawn(async move {
        let pipe = ForwardingPipeline {
            helper: h1_helper,
            send_uuid: h1_recv_uuid,
            receive_uuid: h2_recv_uuid,
        };
        pipe.pipeline(()).await
    });

    let run_h2_mock: JoinHandle<Res<String>> = tokio::spawn(async move {
        let message = "mocked_h2_data".as_bytes().to_vec();
        let mocked_data = ForwardRequest {
            id: h2_recv_uuid.to_string(),
            num: message,
        };
        let mut buf = Vec::new();
        buf.reserve(mocked_data.encoded_len());
        mocked_data.encode(&mut buf).unwrap();
        println!("sending mock data from h2: {h2_recv_uuid}");
        h1_send.send(buf).await?;
        let received_data = h2_recv.recv().await.unwrap();
        let req = ForwardRequest::decode(&mut Cursor::new(received_data.as_slice()))?;
        let str: SendStr = req.num.try_into()?;
        Ok(str.0)
    });
    let (_, _, pipe_res, h2_mock_res) = try_join!(run_hashmap, run_helper, run_pipe, run_h2_mock)?;
    println!(
        "pipe output: {}; h2 mocked output: {}",
        pipe_res.unwrap(),
        h2_mock_res.unwrap()
    );
    Ok(())
}
