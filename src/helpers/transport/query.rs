use crate::ff::FieldType;
use crate::helpers::RoleAssignment;
use crate::protocol::QueryId;


#[derive(Debug)]
pub struct CreateQuery {
    pub field_type: FieldType,
    pub query_type: QueryType
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PrepareQuery {
    pub(crate) query_id: QueryId,
    pub(crate) field_type: FieldType,
    pub(crate) query_type: QueryType,
    pub(crate) roles: RoleAssignment
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

