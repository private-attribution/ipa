use crate::ff::FieldType;
use crate::helpers::RoleAssignment;
use crate::protocol::QueryId;


#[derive(Debug)]
pub struct CreateQuery {
    pub field_type: FieldType,
    pub query_type: QueryType
}

#[derive(Debug)]
pub struct PrepareQuery {
    query_id: QueryId,
    field_type: FieldType,
    query_type: QueryType,
    roles: RoleAssignment
}

#[derive(Debug)]
pub enum QueryCommand {
    Create(CreateQuery),
    Prepare(PrepareQuery)
}


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture"))]
    TestMultiply,
    IPA,
}

