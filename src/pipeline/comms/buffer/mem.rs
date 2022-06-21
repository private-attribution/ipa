//! [`Mem`] is an in-memory buffer for network communication and running pipelines. When a pipeline
//! needs to send data to another pipeline, this buffer acts as the place to write the incoming
//! message from one pipeline, and read that message from the other.
//!
//! It is a wrapper around a hashmap with reads/writes gated by a channel. This allows for multiple
//! threads to access the same hashmap safely.
//!
//! # Examples
//!
//! ```
//! use raw_ipa::pipeline::comms::buffer::{Buffer, Mem};
//! use raw_ipa::pipeline::comms::Target;
//! use rand::{thread_rng, Rng};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mem = Mem::new("example_handler");
//!
//! // write data into HashMap
//! let id = thread_rng().gen();
//! let data = Vec::from("example_data");
//! mem.write(id, Target::Prev, data.clone()).await?;
//!
//! // read data from HashMap; this also removes the data from the map
//! let removed = mem.get_and_remove(id, Target::Prev).await?;
//!
//! assert_eq!(Some(data), removed);
//! # Ok(())
//! # }
//! ```

use super::{Buffer, Command};
use crate::pipeline::comms::Target;
use crate::pipeline::Result;
use async_trait::async_trait;
use log::{debug, error, info};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

#[derive(Hash, Eq, PartialEq)]
struct Key(u128, Target);

pub struct Mem {
    name: &'static str,
    tx: mpsc::Sender<Command>,
}
impl Mem {
    #[must_use]
    pub fn new(name: &'static str) -> Mem {
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(Mem::background_task(name, rx));
        Mem { name, tx }
    }

    async fn background_task(name: &'static str, mut rx: mpsc::Receiver<Command>) {
        let mut m = HashMap::new();
        while let Some(command) = rx.recv().await {
            let res: Result<()> = match command {
                Command::Write(key, source, value) => {
                    debug!(
                        "{} writing data with key {key} from target {:?}",
                        name, source
                    );
                    m.insert(Key(key, source), value);
                    Ok(())
                }
                Command::GetAndRemove(key, source, ack) => {
                    debug!(
                        "{} removing data with key {key} from target {:?}",
                        name, source
                    );
                    let removed = m.remove(&Key(key, source));
                    ack.send(removed)
                        .map_err(|_| mpsc::error::SendError::<Vec<u8>>(vec![]).into())
                }
            };
            if res.is_err() {
                error!(
                    "{} could not complete operation on buffer: {}",
                    name,
                    res.unwrap_err()
                );
            }
        }
    }
}

#[async_trait]
impl Buffer for Mem {
    async fn write(&self, key: u128, source: Target, value: Vec<u8>) -> Result<()> {
        self.tx.send(Command::Write(key, source, value)).await?;
        Ok(())
    }
    async fn get_and_remove(&self, key: u128, source: Target) -> Result<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Command::GetAndRemove(key, source, tx)).await?;
        let resp = rx.await?;
        Ok(resp)
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        info!("{} closing", self.name);
    }
}
