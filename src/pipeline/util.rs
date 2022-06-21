use crate::pipeline::comms;
use crate::pipeline::comms::buffer;
use crate::pipeline::Result;
use rand::{thread_rng, Rng};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::try_join;

#[allow(clippy::type_complexity)]
pub fn intra_process_comms() -> (
    Arc<comms::Channel<buffer::Mem>>,
    Arc<comms::Channel<buffer::Mem>>,
    Arc<comms::Channel<buffer::Mem>>,
    impl Future<Output = Result<()>>,
) {
    let shared_id = thread_rng().gen();
    let (h1_send, h1_recv) = mpsc::channel(32);
    let (h2_send, h2_recv) = mpsc::channel(32);
    let (h3_send, h3_recv) = mpsc::channel(32);

    let h1_buffer = buffer::Mem::new("mem_buffer1");
    let h2_buffer = buffer::Mem::new("mem_buffer2");
    let h3_buffer = buffer::Mem::new("mem_buffer3");

    let h1 = Arc::new(comms::Channel::new(
        "helper_1",
        h2_send.clone(),
        h3_send.clone(),
        h1_buffer,
        shared_id,
    ));
    let h2 = Arc::new(comms::Channel::new(
        "helper_2",
        h3_send.clone(),
        h1_send.clone(),
        h2_buffer,
        shared_id,
    ));
    let h3 = Arc::new(comms::Channel::new(
        "helper_3",
        h1_send.clone(),
        h2_send.clone(),
        h3_buffer,
        shared_id,
    ));
    drop(h1_send);
    drop(h2_send);
    drop(h3_send);

    let run = {
        let chan1 = Arc::clone(&h1);
        let chan2 = Arc::clone(&h2);
        let chan3 = Arc::clone(&h3);
        async move {
            try_join!(
                tokio::spawn(async move { chan1.receive_data(h1_recv).await }),
                tokio::spawn(async move { chan2.receive_data(h2_recv).await }),
                tokio::spawn(async move { chan3.receive_data(h3_recv).await }),
            )?;
            Ok(())
        }
    };
    (h1, h2, h3, run)
}
