use crate::helpers::error::Error;
use crate::helpers::Identity;
use crate::helpers::ring::Message;
use async_trait::async_trait;
use crate::protocol::{RecordId, Step};

#[async_trait]
trait Mesh {
    async fn send<T: Message>(&mut self, target: Identity, record: RecordId, msg: T) -> Result<(), Error>;
    async fn receive<T: Message>(&mut self, source: Identity, record: RecordId) -> Result<T, Error>;
}

trait Gateway<M: Mesh, S: Step> {
    fn get_channel(&self, step: S) -> M;
}

pub mod mocks {
    use std::collections::btree_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use crate::helpers::error::Error;
    use crate::helpers::Identity;
    use crate::helpers::mesh::{Gateway, Mesh};
    use crate::protocol::{QueryId, RecordId, Step};
    use async_trait::async_trait;
    use tokio::sync::mpsc::{Receiver, Sender};
    use tokio::task::JoinHandle;
    use crate::helpers::ring::Message;

    #[derive(Clone)]
    struct TestGateway<S> {
        identity: Identity,
        sink: MessageSink<S>,
    }

    struct TestMesh<S> {
        step: S,
        gateway: TestGateway<S>,
    }


    struct QueryWorld<S> {
        query_id: QueryId,
        gateways: [TestGateway<S>; 3]
    }

    struct StepChannel {}

    #[derive(Debug)]
    struct MessageEnvelope {
        record_id: RecordId,
        payload: Box<[u8]>,
    }

    #[derive(Clone)]
    struct MessageSink<S> {
        buf: Arc<Mutex<HashMap<(S, Identity), Vec<MessageEnvelope>>>>,
    }

    impl<S: Step> MessageSink<S> {
        fn connect(&self, peer: Identity, step: S, mut rx: Receiver<MessageEnvelope>) {
            let buf = self.buf.clone();
            {
                let mut buf = buf.lock().unwrap();
                assert!(!buf.contains_key(&(step, peer)));
                buf.insert((step, peer), Vec::new());
            }

            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    let mut buf = buf.lock().unwrap();
                    buf.get_mut(&(step, peer)).unwrap().push(msg);
                }
            });
        }

        async fn get_message<T: Message>(&self, peer: Identity, record_id: RecordId, step: S) -> T {
            loop {
                {
                    let mut buf = self.buf.lock().unwrap();
                    if let Some(msgs) = buf.get_mut(&(step, peer)) {
                        let l = msgs.len();
                        for i in 0..l {
                            if msgs[i].record_id == record_id {
                                msgs.swap(i, l - 1);
                                let envelope = msgs.pop().unwrap();
                                let obj: T = serde_json::from_slice(&envelope.payload).unwrap();

                                return obj
                            }
                        }
                    }
                }

                tokio::task::yield_now().await;
            }
        }
    }

    impl <S: Step> TestMesh<S> {
        pub fn new(gateway: &TestGateway<S>, step: S) -> TestMesh<S> {
            Self {
                step,
                gateway: gateway.clone(),
            }
        }

        fn get_target_sender(&self, target: Identity) -> Sender<MessageEnvelope> {
            todo!()
        }
    }

    impl <S: Step> Gateway<TestMesh<S>, S> for TestGateway<S> {
        fn get_channel<'a>(&self, step: S) -> TestMesh<S> {
            TestMesh::new(self, step)
        }
    }

    #[async_trait]
    impl <S: Step> Mesh for TestMesh<S> {
        async fn send<T: Message>(&mut self, target: Identity, record_id: RecordId, msg: T) -> Result<(), Error> {
            let sender = self.get_target_sender(target);

            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                record_id,
                payload: bytes,
            };

            sender.send(envelope).await.map_err(|e| Error::SendError {
                dest: target,
                inner: format!("Failed to send {:?}", e.0).into(),
            })?;

            Ok(())
        }

        async fn receive<T: Message>(&mut self, source: Identity, record: RecordId) -> Result<T, Error> {
            Ok(self.gateway.sink.get_message(source, record, self.step).await)
        }
    }
}