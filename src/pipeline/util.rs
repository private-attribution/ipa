use crate::pipeline::buffer;
use crate::pipeline::comms::{self, Comms};
use crate::pipeline::Result;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::try_join;
use uuid::Uuid;

pub fn intra_process_comms() -> (
    Arc<comms::Channel>,
    Arc<comms::Channel>,
    Arc<comms::Channel>,
    impl Future<Output = Result<()>>,
) {
    let shared_id = Uuid::new_v4();
    let (h1_send, h1_recv) = mpsc::channel(32);
    let (h2_send, h2_recv) = mpsc::channel(32);
    let (h3_send, h3_recv) = mpsc::channel(32);

    let (h1_buffer_tx, h1_buffer_rx) = mpsc::channel(32);
    let (h2_buffer_tx, h2_buffer_rx) = mpsc::channel(32);
    let (h3_buffer_tx, h3_buffer_rx) = mpsc::channel(32);
    let mut h1_buffer = buffer::Mem::new("hm1");
    let mut h2_buffer = buffer::Mem::new("hm2");
    let mut h3_buffer = buffer::Mem::new("hm3");

    let h1 = Arc::new(comms::Channel::new(
        "helper_1",
        h2_send.clone(),
        h3_send.clone(),
        h1_buffer_tx,
        shared_id,
    ));
    let h2 = Arc::new(comms::Channel::new(
        "helper_2",
        h3_send,
        h1_send.clone(),
        h2_buffer_tx,
        shared_id,
    ));
    let h3 = Arc::new(comms::Channel::new(
        "helper_3",
        h1_send,
        h2_send,
        h3_buffer_tx,
        shared_id,
    ));

    let run = {
        let chan1 = Arc::clone(&h1);
        let chan2 = Arc::clone(&h2);
        let chan3 = Arc::clone(&h3);
        async move {
            try_join!(
                tokio::spawn(async move { chan1.receive_data(h1_recv).await }),
                tokio::spawn(async move { chan2.receive_data(h2_recv).await }),
                tokio::spawn(async move { chan3.receive_data(h3_recv).await }),
                tokio::spawn(async move { h1_buffer.run(h1_buffer_rx).await }),
                tokio::spawn(async move { h2_buffer.run(h2_buffer_rx).await }),
                tokio::spawn(async move { h3_buffer.run(h3_buffer_rx).await }),
            )?;
            Ok(())
        }
    };
    (h1, h2, h3, run)
}
