use crate::field::Field;
use crate::helpers::Identity;
use crate::helpers::{mesh, mesh::Message, Error, Result};
use crate::net::Client;
use crate::protocol::{QueryId, RecordId, Step};
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use async_trait::async_trait;
use futures::Stream;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type ConnectionKey<S> = (Identity, S);

pub struct World<S, St> {
    pub query_id: QueryId,
    pub gateways: [HelperGateway<S, St>],
}

pub struct Controller<S, St> {
    identity: Identity,
    peers: HashMap<Identity, Client>,
    incoming_data: Arc<Mutex<HashMap<ConnectionKey<S>, St>>>,
}

impl<S, F, St> Controller<S, St>
where
    S: Step,
    F: Field,
    St: Stream<Item = Result<ReplicatedSecretSharing<F>>>,
{
    async fn get_client(&self, peer: Identity, step: S) -> Result<Client> {
        (self.identity == peer)
            .then_some(&self.peers)
            .ok_or(Error::SelfAsPeer)
            .and_then(|peers| {
                peers
                    .get(&peer)
                    .map_or(Err(Error::InvalidPeer(peer)), |client| Ok(client.clone()))
            })
    }

    pub fn add_incoming(&self, identity: Identity, step: S, st: St) {
        self.incoming_data
            .clone()
            .lock()
            .unwrap()
            .insert((identity, step), st);
    }

    /// TODO: better solution than hot-loop + yield_now
    pub async fn receive(&self, identity: Identity, step: S) -> St {
        loop {
            let val = self
                .incoming_data
                .clone()
                .lock()
                .unwrap()
                .remove(&(identity, step));
            if val.is_some() {
                return val.unwrap();
            }
            tokio::task::yield_now().await;
        }
    }
}

impl<S, St> Clone for Controller<S, St> {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity,
            peers: self.peers.clone(),
            incoming_data: self.incoming_data.clone(),
        }
    }
}

pub struct HelperGateway<S, St> {
    controller: Controller<S, St>,
}

impl<S, St> HelperGateway<S, St> {
    fn new(controller: Controller<S, St>) -> Self {
        Self { controller }
    }
}

impl<S: Step, F: Field, St: Stream<Item = Result<ReplicatedSecretSharing<F>>> + Send + 'static>
    mesh::Gateway<Mesh<S, St>, S> for HelperGateway<S, St>
{
    fn get_channel(&self, step: S) -> Mesh<S, St> {
        Mesh {
            step,
            controller: self.controller.clone(),
        }
    }
}

pub struct Mesh<S, St> {
    step: S,
    controller: Controller<S, St>,
}

#[async_trait]
impl<S: Step, F: Field, St: Stream<Item = Result<ReplicatedSecretSharing<F>>> + Send + 'static>
    mesh::Mesh for Mesh<S, St>
{
    async fn send<T: Message>(&mut self, dest: Identity, record: RecordId, msg: T) -> Result<()> {
        //let client = self.controller.get_client(dest, self.step).await?;

        //let payload = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
        // client.execute()
        todo!()
    }

    async fn receive<T: Message>(&mut self, source: Identity, record: RecordId) -> Result<T> {
        todo!()
    }

    fn identity(&self) -> Identity {
        todo!()
    }
}

#[derive(Debug)]
enum ControlMessage<S> {
    ConnectionRequest(Identity, S),
}
