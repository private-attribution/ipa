mod receive;
mod send;
mod transport;

use std::{fmt::Debug, num::NonZeroUsize};

pub use send::SendingEnd;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

use crate::{
    helpers::{
        gateway::{
            receive::{GatewayReceivers, ReceivingEnd as ReceivingEndBase},
            send::GatewaySenders,
            transport::RoleResolvingTransport,
        },
        ChannelId, Message, Role, RoleAssignment, TotalRecords, Transport,
    },
    protocol::QueryId,
};

/// Alias for the currently configured transport.
///
/// To avoid proliferation of type parameters, most code references this concrete type alias, rather
/// than a type parameter `T: Transport`.
#[cfg(feature = "in-memory-infra")]
pub type TransportImpl = super::transport::InMemoryTransport;

#[cfg(feature = "real-world-infra")]
pub type TransportImpl = crate::sync::Arc<crate::net::HttpTransport>;

pub type TransportError = <TransportImpl as Transport>::Error;
pub type ReceivingEnd<M> = ReceivingEndBase<TransportImpl, M>;

/// Gateway into IPA Infrastructure systems. This object allows sending and receiving messages.
/// As it is generic over network/transport layer implementation, type alias [`Gateway`] should be
/// used to avoid carrying `T` over.
///
/// [`Gateway`]: crate::helpers::Gateway
pub struct Gateway<T: Transport = TransportImpl> {
    config: GatewayConfig,
    transport: RoleResolvingTransport<T>,
    senders: GatewaySenders,
    receivers: GatewayReceivers<T>,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// The number of items that can be active at the one time.
    /// This is used to determine the size of sending and receiving buffers.
    active: NonZeroUsize,
}

impl<T: Transport> Gateway<T> {
    #[must_use]
    pub fn new(
        query_id: QueryId,
        config: GatewayConfig,
        roles: RoleAssignment,
        transport: T,
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

    ///
    /// ## Panics
    /// If there is a failure connecting via HTTP
    #[must_use]
    pub fn get_sender<M: Message>(
        &self,
        channel_id: &ChannelId,
        total_records: TotalRecords,
    ) -> SendingEnd<M> {
        let (tx, maybe_stream) =
            self.senders
                .get_or_create::<M>(channel_id, self.config.active_work(), total_records);
        if let Some(stream) = maybe_stream {
            tokio::spawn({
                let channel_id = channel_id.clone();
                let transport = self.transport.clone();
                async move {
                    // TODO(651): In the HTTP case we probably need more robust error handling here.
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
    pub fn get_receiver<M: Message>(&self, channel_id: &ChannelId) -> ReceivingEndBase<T, M> {
        ReceivingEndBase::new(
            channel_id.clone(),
            self.receivers
                .get_or_create(channel_id, || self.transport.receive(channel_id)),
        )
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self::new(1024)
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
    #[must_use]
    pub fn active_work(&self) -> NonZeroUsize {
        self.active
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use futures_util::future::{join, try_join};

    use super::*;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, Gf2},
        helpers::{Direction, GatewayConfig, SendingEnd},
        protocol::{context::Context, RecordId},
        test_fixture::{Runner, TestWorld, TestWorldConfig},
    };

    /// Verifies that [`Gateway`] send buffer capacity is adjusted to the message size.
    /// IPA protocol opens many channels to send values from different fields, while message size
    /// is set per channel, it does not have to be the same across multiple send channels.
    ///
    /// Gateway must be able to deal with it.
    #[tokio::test]
    async fn can_handle_heterogeneous_channels() {
        async fn send<F: Field>(channel: &SendingEnd<F>, i: usize) {
            channel
                .send(i.into(), F::truncate_from(u128::try_from(i).unwrap()))
                .await
                .unwrap();
        }

        let config = TestWorldConfig {
            gateway_config: GatewayConfig::new(2),
            ..Default::default()
        };

        let world = TestWorld::new_with(config);
        world
            .semi_honest((), |ctx, ()| async move {
                let fp2_ctx = ctx.narrow("fp2").set_total_records(100);
                let fp32_ctx = ctx.narrow("fp32").set_total_records(100);
                let role = ctx.role();

                let fp2_channel = fp2_ctx.send_channel::<Gf2>(role.peer(Direction::Right));
                let fp32_channel =
                    fp32_ctx.send_channel::<Fp32BitPrime>(role.peer(Direction::Right));

                // joins must complete, despite us not closing the send channel.
                // fp2 channel byte capacity must be set to 2 bytes, fp32 channel can store 8 bytes.
                join(send(&fp2_channel, 0), send(&fp2_channel, 1)).await;
                join(send(&fp32_channel, 0), send(&fp32_channel, 1)).await;
            })
            .await;
    }

    #[tokio::test]
    pub async fn handles_reordering() {
        let config = TestWorldConfig {
            gateway_config: GatewayConfig::new(2),
            ..TestWorldConfig::default()
        };
        let world = Box::leak(Box::new(TestWorld::new_with(config)));
        let world_ptr = world as *mut _;
        let contexts = world.contexts();
        let sender_ctx = contexts[0].narrow("reordering-test").set_total_records(2);
        let recv_ctx = contexts[1].narrow("reordering-test").set_total_records(2);

        // send record 1 first and wait for confirmation before sending record 0.
        // when gateway received record 0 it triggers flush so it must make sure record 1 is also
        // sent (same batch or different does not matter here)
        let spawned = tokio::spawn(async move {
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
        spawned.await.unwrap();
        let _world = unsafe { Box::from_raw(world_ptr) };
    }
}
