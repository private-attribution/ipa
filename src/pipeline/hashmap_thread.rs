//! [HashMapHandler] is a wrapper around a hashmap with reads/writes gated by a channel. This allows
//! for multiple threads to access the same hashmap safely.
//!
//! To use, must pass in the channel receiver.
//!
//! # Examples
//!
//! ```
//! use tokio::sync::{mpsc, oneshot};
//! use uuid::Uuid;
//! use raw_ipa::pipeline::hashmap_thread::{HashMapCommand, HashMapHandler};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (tx, rx) = mpsc::channel(32);
//! let hmh = HashMapHandler::new("example_handler", rx);
//! tokio::spawn(async move { hmh.run() }); // watch for incoming messages on `rx`
//!
//! // write data into HashMap
//! let id = Uuid::new_v4();
//! let data: Vec<u8> = "example_data".into();
//! tx.send(HashMapCommand::Write(id, data)).await?;
//!
//! // read data from HashMap; this also removes the data from the map
//! let (one_tx, one_rx) = oneshot::channel();
//! tx.send(HashMapCommand::Remove(id, one_tx)).await?;
//! let removed = one_rx.await?;
//!
//! assert_eq!(data, removed);
//! # Ok(())
//! # }
//! ```

use crate::pipeline::Result;
use log::{debug, error, info};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/// Possible commands to act on the [HashMapHandler]
#[derive(Debug)]
pub enum HashMapCommand {
    Write(Uuid, Vec<u8>),
    /// Removes and returns the value in the oneshot receiver
    Remove(Uuid, oneshot::Sender<Option<Vec<u8>>>),
}

pub struct HashMapHandler {
    name: &'static str,
    m: HashMap<Uuid, Vec<u8>>,
    receiver: mpsc::Receiver<HashMapCommand>,
}
impl HashMapHandler {
    #[must_use]
    pub fn new(name: &'static str, receiver: mpsc::Receiver<HashMapCommand>) -> HashMapHandler {
        HashMapHandler {
            name,
            m: HashMap::new(),
            receiver,
        }
    }

    pub async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            let res = match command {
                HashMapCommand::Write(key, value) => {
                    self.write(key, value);
                    Ok(())
                }
                HashMapCommand::Remove(key, ack) => self.remove(key, ack).await,
            };
            if res.is_err() {
                error!(
                    "{} could not complete operation on HashMap: {}",
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

impl Drop for HashMapHandler {
    fn drop(&mut self) {
        info!("{} closing", self.name);
    }
}
