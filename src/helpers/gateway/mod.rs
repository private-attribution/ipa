mod receive;
mod send;
mod transport;

pub use receive::ReceivingEnd;
pub use send::SendingEnd;

use std::{fmt::Debug, num::NonZeroUsize};

use crate::{
    helpers::{transport::TransportImpl, ChannelId, Message, Role, RoleAssignment, TotalRecords},
    protocol::QueryId,
};

use crate::helpers::gateway::{
    receive::GatewayReceivers, send::GatewaySenders, transport::RoleResolvingTransport,
};
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

/// Gateway into IPA Infrastructure systems. This object allows sending and receiving messages
pub struct Gateway {
    config: GatewayConfig,
    transport: RoleResolvingTransport<TransportImpl>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<TransportImpl>,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// The maximum number of items that can be outstanding for sending.
    pub send_outstanding: NonZeroUsize,
    /// The maximum number of items that can be outstanding for receiving.
    pub recv_outstanding: NonZeroUsize,
}

impl Gateway {
    #[must_use]
    pub fn new(
        query_id: QueryId,
        config: GatewayConfig,
        roles: RoleAssignment,
        transport: TransportImpl,
    ) -> Self {
        Self {
            config,
            transport: RoleResolvingTransport {
                query_id,
                roles,
                inner: transport,
                config,
            },
            senders: GatewaySenders::default(),
            receivers: GatewayReceivers::default(),
        }
    }

    #[must_use]
    pub fn role(&self) -> Role {
        self.transport.role()
    }

    #[must_use]
    pub fn get_sender<M: Message>(
        &self,
        channel_id: &ChannelId,
        total_records: TotalRecords,
    ) -> SendingEnd<M> {
        let (tx, maybe_stream) = self.senders.get_or_create::<M>(
            channel_id,
            self.config.send_outstanding,
            total_records,
        );
        if let Some(stream) = maybe_stream {
            tokio::spawn({
                let channel_id = channel_id.clone();
                let transport = self.transport.clone();
                async move {
                    transport
                        .send(&channel_id, stream)
                        .await
                        .expect("{channel_id:?} receiving end should be accepted by transport");
                }
            });
        }

        SendingEnd::new(tx, self.role(), channel_id)
    }

    #[must_use]
    pub fn get_receiver<M: Message>(&self, channel_id: &ChannelId) -> ReceivingEnd<M> {
        ReceivingEnd::new(
            self.receivers
                .get_or_create::<M, _>(channel_id, || self.transport.receive(channel_id)),
        )
    }
}

impl GatewayConfig {
    /// Config for symmetric send and receive buffers. Capacity must not be zero.
    ///
    /// ## Panics
    /// if capacity is set to be 0.
    #[must_use]
    pub fn symmetric_buffers(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap();
        Self {
            send_outstanding: capacity,
            recv_outstanding: capacity,
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::Fp31,
        helpers::Role,
        protocol::{context::Context, RecordId},
        test_fixture::{TestWorld, TestWorldConfig},
    };

    use futures_util::future::try_join;

    #[tokio::test]
    pub async fn handles_reordering() {
        let mut config = TestWorldConfig::default();
        config.gateway_config.send_outstanding = 2.try_into().unwrap();

        let world = Box::leak(Box::new(TestWorld::new_with(config)));
        let contexts = world.contexts();
        let sender_ctx = contexts[0].narrow("reordering-test").set_total_records(2);
        let recv_ctx = contexts[1].narrow("reordering-test").set_total_records(2);

        // send record 1 first and wait for confirmation before sending record 0.
        // when gateway received record 0 it triggers flush so it must make sure record 1 is also
        // sent (same batch or different does not matter here)
        tokio::spawn(async move {
            let channel = sender_ctx.send_channel(Role::H2);
            try_join(
                channel.send(RecordId::from(1), Fp31::from(1_u128)),
                channel.send(RecordId::from(0), Fp31::from(0_u128)),
            )
            .await
            .unwrap();
        });

        let recv_channel = recv_ctx.recv_channel::<Fp31>(Role::H1);
        let result = try_join(
            recv_channel.receive(RecordId::from(1)),
            recv_channel.receive(RecordId::from(0)),
        )
        .await
        .unwrap();

        assert_eq!((Fp31::from(1u128), Fp31::from(0u128)), result);
    }
}
