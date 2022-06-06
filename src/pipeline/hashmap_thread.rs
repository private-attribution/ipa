use crate::pipeline::Result;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Debug)]
pub enum HashMapCommand {
    Write(Uuid, Vec<u8>),
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
                println!(
                    "{} could not complete operation on HashMap: {}",
                    self.name,
                    res.unwrap_err()
                );
            }
        }
    }
    fn write(&mut self, key: Uuid, value: Vec<u8>) {
        println!("{} writing data with key {key}", self.name);
        self.m.insert(key, value);
    }
    async fn remove(&mut self, key: Uuid, ack: oneshot::Sender<Option<Vec<u8>>>) -> Result<()> {
        println!("{} removing data with key {key}", self.name);
        let removed = self.m.remove(&key);
        ack.send(removed)
            .map_err(|_| mpsc::error::SendError::<Vec<u8>>(vec![]).into())
    }
}

impl Drop for HashMapHandler {
    fn drop(&mut self) {
        println!("{} closing", self.name);
    }
}
