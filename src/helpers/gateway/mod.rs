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
use typenum::Unsigned;

/// Gateway into IPA Infrastructure systems. This object allows sending and receiving messages
pub struct Gateway {
    config: GatewayConfig,
    transport: RoleResolvingTransport<TransportImpl>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<TransportImpl>,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// The number of items that can be active at the one time.  
    /// This is used to determine the size of sending and receiving buffers.
    active: NonZeroUsize,
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
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    #[must_use]
    pub fn get_sender<M: Message>(
        &self,
        channel_id: &ChannelId,
        total_records: TotalRecords,
    ) -> SendingEnd<M> {
        let (tx, maybe_stream) = self.senders.get_or_create::<M>(
            channel_id,
            self.config.send_outstanding_bytes::<M>(),
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
                .get_or_create::<M, _>(channel_id, || self.transport.receive::<M>(channel_id)),
        )
    }
}

impl GatewayConfig {
    /// Generate a new configuration with the given active limit.
    ///
    /// ## Panics
    /// If `active` is 0.
    #[must_use]
    pub fn new(active: usize) -> Self {
        Self {
            active: NonZeroUsize::new(active).unwrap(),
        }
    }

    /// The configured amount of active work.
    pub fn active_work(&self) -> NonZeroUsize {
        self.active
    }

    /// Get the size of the send buffer to use.
    ///
    /// ## Panics
    /// Never.
    #[must_use]
    pub fn send_outstanding_bytes<M: Message>(&self) -> NonZeroUsize {
        self.active
            .saturating_mul(NonZeroUsize::new(M::Size::USIZE).unwrap())
    }

    /// Get the size of the receive buffer to use.
    ///
    /// ## Panics
    /// Never.
    #[must_use]
    pub fn recv_outstanding<M: Message>(&self) -> NonZeroUsize {
        self.active
            .saturating_mul(NonZeroUsize::new(M::Size::USIZE).unwrap())
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::GatewayConfig;
    use crate::{
        ff::{Field, Fp31},
        helpers::Role,
        protocol::{context::Context, RecordId},
        test_fixture::{TestWorld, TestWorldConfig},
    };
    use futures_util::future::try_join;

    #[tokio::test]
    pub async fn handles_reordering() {
        let config = TestWorldConfig {
            gateway_config: GatewayConfig::new(2),
            ..TestWorldConfig::default()
        };
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
                channel.send(RecordId::from(1), Fp31::truncate_from(1_u128)),
                channel.send(RecordId::from(0), Fp31::truncate_from(0_u128)),
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

        assert_eq!(
            (Fp31::truncate_from(1u128), Fp31::truncate_from(0u128)),
            result
        );
    }
}
