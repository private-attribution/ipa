use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::Stream;

use crate::{
    helpers::{
        NoResourceIdentifier, QueryIdBinding, Role, RoleAssignment, RouteId, RouteParams,
        StepBinding, Transport, TransportImpl,
    },
    protocol::{step::Gate, QueryId},
};

#[derive(Debug, thiserror::Error)]
#[error("Failed to send to {0:?}: {1:?}")]
pub struct SendToRoleError(Role, <TransportImpl as Transport>::Error);

/// This struct exists to hide the generic type used to index streams internally.
#[pin_project::pin_project]
pub struct RoleRecordsStream(#[pin] <TransportImpl as Transport>::RecordsStream);

/// Transport adapter that resolves [`Role`] -> [`HelperIdentity`] mapping. As gateways created
/// per query, it is not ambiguous.
///
/// [`HelperIdentity`]: crate::helpers::HelperIdentity
#[derive(Clone)]
pub struct RoleResolvingTransport {
    pub(super) roles: RoleAssignment,
    pub(super) inner: TransportImpl,
}

impl Stream for RoleRecordsStream {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}

#[async_trait]
impl Transport for RoleResolvingTransport {
    type Identity = Role;
    type RecordsStream = RoleRecordsStream;
    type Error = SendToRoleError;

    fn identity(&self) -> Role {
        let helper_identity = self.inner.identity();
        self.roles.role(helper_identity)
    }

    async fn send<
        D: Stream<Item = Vec<u8>> + Send + 'static,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
    >(
        &self,
        dest: Role,
        route: R,
        data: D,
    ) -> Result<(), Self::Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        let dest_helper = self.roles.identity(dest);
        assert_ne!(
            dest_helper,
            self.inner.identity(),
            "can't send message to itself"
        );
        self.inner
            .send(dest_helper, route, data)
            .await
            .map_err(|e| SendToRoleError(dest, e))
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: Role,
        route: R,
    ) -> Self::RecordsStream {
        let origin_helper = self.roles.identity(from);
        assert_ne!(
            origin_helper,
            self.inner.identity(),
            "can't receive message from itself"
        );

        RoleRecordsStream(self.inner.receive(origin_helper, route))
    }
}
