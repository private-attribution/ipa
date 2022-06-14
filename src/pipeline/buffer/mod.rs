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
//! use tokio::sync::{mpsc, oneshot};
//! use uuid::Uuid;
//! use raw_ipa::pipeline::buffer::{Command, Mem};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (tx, rx) = mpsc::channel(32);
//! let mut mem = Mem::new("example_handler");
//! tokio::spawn(async move { mem.run(rx).await }); // watch for incoming messages on `rx`
//!
//! // write data into HashMap
//! let id = Uuid::new_v4();
//! let data = Vec::from("example_data");
//! tx.send(Command::Write(id, data.clone())).await?;
//!
//! // read data from HashMap; this also removes the data from the map
//! let (one_tx, one_rx) = oneshot::channel();
//! tx.send(Command::Remove(id, one_tx)).await?;
//! let removed = one_rx.await?;
//!
//! assert_eq!(Some(data), removed);
//! # Ok(())
//! # }
//! ```

use crate::pipeline::Result;
use log::{debug, error, info};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Debug)]
pub enum Command {
    Write(Uuid, Vec<u8>),
    /// Removes and returns the value in the oneshot receiver
    Remove(Uuid, oneshot::Sender<Option<Vec<u8>>>),
}

pub struct Mem {
    name: &'static str,
    m: HashMap<Uuid, Vec<u8>>,
}
impl Mem {
    #[must_use]
    pub fn new(name: &'static str) -> Mem {
        Mem {
            name,
            m: HashMap::new(),
        }
    }

    pub async fn run(&mut self, mut receiver: mpsc::Receiver<Command>) {
        while let Some(command) = receiver.recv().await {
            let res = match command {
                Command::Write(key, value) => {
                    self.write(key, value);
                    Ok(())
                }
                Command::Remove(key, ack) => self.remove(key, ack).await,
            };
            if res.is_err() {
                error!(
                    "{} could not complete operation on buffer: {}",
                    self.name,
                    res.unwrap_err()
                );
            }
        }
    }
    fn write(&mut self, key: Uuid, value: Vec<u8>) {
        debug!("{} writing data with key {key}", self.name);
        self.m.insert(key, value);
    }
    async fn remove(&mut self, key: Uuid, ack: oneshot::Sender<Option<Vec<u8>>>) -> Result<()> {
        debug!("{} removing data with key {key}", self.name);
        let removed = self.m.remove(&key);
        ack.send(removed)
            .map_err(|_| mpsc::error::SendError::<Vec<u8>>(vec![]).into())
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        info!("{} closing", self.name);
    }
}
