use crate::{
    helpers::{
        buffers::{OrderingMpscReceiver, UnorderedReceiver},
        gateway::{receive::UR, wrapper::Wrapper},
        ChannelId, GatewayConfig, Role, RoleAssignment, RouteId, Transport,
    },
    protocol::QueryId,
};
use std::io;

/// Transport adapter that resolves [`Role`] -> [`HelperIdentity`] mapping. As gateways created
/// per query, it is not ambiguous.
#[derive(Clone)]
pub(super) struct RoleResolvingTransport<T> {
    pub query_id: QueryId,
    pub roles: RoleAssignment,
    pub config: GatewayConfig,
    pub inner: T,
}

impl<T: Transport> RoleResolvingTransport<T> {
    pub(crate) async fn send(
        &self,
        channel_id: &ChannelId,
        data: OrderingMpscReceiver<Wrapper>,
    ) -> Result<(), io::Error> {
        let dest_identity = self.roles.identity(channel_id.role);
        assert_ne!(
            dest_identity,
            self.inner.identity(),
            "can't send message to itself"
        );

        self.inner
            .send(
                dest_identity,
                (RouteId::Records, self.query_id, channel_id.step.clone()),
                data,
            )
            .await
    }

    pub(crate) fn receive(&self, channel_id: &ChannelId) -> UR<T> {
        let peer = self.roles.identity(channel_id.role);
        assert_ne!(
            peer,
            self.inner.identity(),
            "can't receive message from itself"
        );

        UnorderedReceiver::new(
            Box::pin(
                self.inner
                    .receive(peer, (self.query_id, channel_id.step.clone())),
            ),
            self.config.recv_outstanding,
        )
    }

    pub(crate) fn role(&self) -> Role {
        self.roles.role(self.inner.identity())
    }
}
