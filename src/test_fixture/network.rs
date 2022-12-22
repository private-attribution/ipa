use crate::sync::{Arc, Mutex, Weak};
use crate::{
    helpers::{
        self,
        network::{ChannelId, MessageChunks},
        old_network::{Network, NetworkSink},
        Error, Role,
    },
    protocol::Step,
};
use ::tokio::sync::mpsc::{self, Receiver, Sender};
use async_trait::async_trait;
use futures::StreamExt;
use futures_util::stream::{FuturesUnordered, SelectAll};
use std::collections::{hash_map::Entry, HashMap};
use std::fmt::{Debug, Formatter};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use crate::helpers::{HelperIdentity, NetworkEventData, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::helpers::TransportCommand::NetworkEvent;
use crate::protocol::QueryId;
use crate::test_fixture::transport::InMemoryTransport;

/// Container for all active transports
#[derive(Debug)]
pub struct InMemoryNetwork {
    pub transports: [Arc<InMemoryTransport>; 3]
}

impl InMemoryNetwork {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new_cyclic(|weak_ptr| {
            let [mut first, mut second, mut third]: [InMemoryTransport; 3] = (0..3).map(|v| {
                InMemoryTransport::new(HelperIdentity::from(v))
            }).collect::<Vec<_>>().try_into().unwrap();

            // it is a bit tedious, is there a better way?
            first.connect(&mut second);
            first.connect(&mut third);
            second.connect(&mut first);
            second.connect(&mut third);
            third.connect(&mut first);
            third.connect(&mut second);

            first.listen();
            second.listen();
            third.listen();

            Self { transports: [Arc::new(first), Arc::new(second), Arc::new(third)] }
        })
    }

    pub fn helper_identities(&self) -> [HelperIdentity; 3] {
        self.transports.iter()
            .map(|t| t.identity().clone())
            .collect::<Vec<_>>().try_into().unwrap()
    }
}
