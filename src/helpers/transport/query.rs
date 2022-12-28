use std::any::type_name;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::pin::Pin;
use futures::Stream;
use tokio::sync::oneshot;
use crate::error::BoxError;
use crate::ff::FieldType;
use crate::helpers::{RoleAssignment, TransportCommand};
use crate::protocol::QueryId;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct QueryConfig {
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PrepareQuery {
    pub query_id: QueryId,
    pub config: QueryConfig,
    pub roles: RoleAssignment,
}

pub struct QueryInput {
    pub query_id: QueryId,
    pub input_stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "query_inputs[{:?}]", self.query_id)
    }
}

#[derive(Debug)]
pub enum QueryCommand {
    Create(QueryConfig, oneshot::Sender<PrepareQuery>),
    Prepare(PrepareQuery),
    Input(QueryInput)
}

impl From<QueryCommand> for TransportCommand {
    fn from(value: QueryCommand) -> Self {
        TransportCommand::Query(value)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture"))]
    TestMultiply,
    IPA,
}

