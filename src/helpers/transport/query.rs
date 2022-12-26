use crate::ff::FieldType;
use crate::helpers::{RoleAssignment, TransportCommand};
use crate::protocol::QueryId;

#[derive(Clone, Debug)]
pub struct CreateQuery {
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PrepareQuery {
    pub query_id: QueryId,
    #[allow(dead_code)]
    pub field_type: FieldType,
    #[allow(dead_code)]
    pub query_type: QueryType,
    pub roles: RoleAssignment,
}

#[derive(Debug)]
pub enum QueryCommand {
    Create(CreateQuery),
    Prepare(PrepareQuery),
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
