use crate::error::{Error, Res};
use prost::alloc::vec::Vec as ProstVec;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Debug)]
pub enum HashMapCommand {
    Write(Uuid, ProstVec<u8>, oneshot::Sender<Option<ProstVec<u8>>>),
    Remove(Uuid, oneshot::Sender<Option<ProstVec<u8>>>),
}
pub struct HashMapHandler {
    m: HashMap<Uuid, ProstVec<u8>>,
    receiver: mpsc::Receiver<HashMapCommand>,
}
impl HashMapHandler {
    #[must_use]
    pub fn new(receiver: mpsc::Receiver<HashMapCommand>) -> HashMapHandler {
        HashMapHandler {
            m: HashMap::new(),
            receiver,
        }
    }
    pub async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            let res = match command {
                HashMapCommand::Write(key, value, ack) => self.write(key, value, ack).await,
                HashMapCommand::Remove(key, ack) => self.remove(key, ack).await,
            };
            if res.is_err() {
                println!(
                    "could not complete operation on HashMap: {}",
                    res.unwrap_err()
                );
            }
        }
    }
    async fn write(
        &mut self,
        key: Uuid,
        value: Vec<u8>,
        ack: oneshot::Sender<Option<ProstVec<u8>>>,
    ) -> Res<()> {
        println!("writing data with key {key}");
        let ousted = self.m.insert(key, value);
        ack.send(ousted).map_or(
            Err(Error::AsyncDeadThread(mpsc::error::SendError(vec![]))),
            |_| Ok(()),
        )
    }
    async fn remove(&mut self, key: Uuid, ack: oneshot::Sender<Option<ProstVec<u8>>>) -> Res<()> {
        println!("removing data with key {key}");
        let removed = self.m.remove(&key);
        ack.send(removed).map_or(
            Err(Error::AsyncDeadThread(mpsc::error::SendError(vec![]))),
            |_| Ok(()),
        )
    }
}
