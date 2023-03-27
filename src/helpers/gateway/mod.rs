mod receive;
mod send;
mod transport;

pub use receive::ReceivingEnd;
pub use send::SendingEnd;

use std::{fmt::Debug, num::NonZeroUsize};

use crate::{
    helpers::{
        gateway::{
            receive::GatewayReceivers, send::GatewaySenders, transport::RoleResolvingTransport,
        },
        transport::TransportImpl,
        ChannelId, Message, Role, RoleAssignment, TotalRecords,
    },
    protocol::QueryId,
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
    pub fn new<T: Into<TransportImpl>>(
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
                inner: transport.into(),
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

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            /// send buffer capacity, in bytes
            send_outstanding: NonZeroUsize::new(4096).unwrap(),
            // receive buffer capacity in total messages it can hold.
            /// set to match send buffer capacity / [`Fp32`] size
            ///
            /// [`Fp32`]: crate::ff::Fp32BitPrime
            recv_outstanding: NonZeroUsize::new(1024).unwrap(),
        }
    }
}

impl GatewayConfig {
    /// Config for symmetric send and receive buffers. Capacity must not be zero.
    /// ## Panics
    /// if capacity is set to be 0.
    #[must_use]
    pub fn symmetric_buffers(capacity: usize) -> Self {
        Self {
            send_outstanding: NonZeroUsize::new(capacity).unwrap(),
            recv_outstanding: NonZeroUsize::new(capacity).unwrap(),
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, Gf2},
        helpers::{Direction, GatewayConfig, SendingEnd},
        protocol::{context::Context, RecordId},
        test_fixture::{Runner, TestWorld, TestWorldConfig},
    };
    use futures_util::future::{join, try_join};

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
            gateway_config: GatewayConfig::symmetric_buffers(2),
            ..Default::default()
        };

        let world = TestWorld::new_with(config);
        world
            .semi_honest((), |ctx, _| async move {
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
        let mut config = TestWorldConfig::default();
        config.gateway_config.send_outstanding = 2.try_into().unwrap();

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
