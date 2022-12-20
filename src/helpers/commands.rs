use crate::ff::FieldType;
use crate::helpers::{HelperIdentity, Role};
use crate::protocol::QueryId;
use std::collections::HashMap;

pub struct Command<'a> {
    pub dest: &'a HelperIdentity,
    pub command_type: CommandType<'a>,
}

impl<'a> Command<'a> {
    #[must_use]
    pub fn prepare(dest: &'a HelperIdentity, qc: &'a QueryConfiguration) -> Self {
        Self {
            dest,
            command_type: CommandType::Prepare(qc),
        }
    }
}

pub enum CommandType<'a> {
    /// Prepare this helper to start processing a new query
    Prepare(&'a QueryConfiguration<'a>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture"))]
    TestMultiply,
    IPA,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingConfiguration<'a> {
    assignment: HashMap<&'a HelperIdentity, Role>,
}

impl<'a> RingConfiguration<'a> {
    #[must_use]
    pub fn new(assignment: [(&'a HelperIdentity, Role); 3]) -> Self {
        Self {
            assignment: assignment.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryConfiguration<'a> {
    query_id: QueryId,
    field_type: FieldType,
    query_type: QueryType,
    ring: RingConfiguration<'a>,
}

impl<'a> QueryConfiguration<'a> {
    #[must_use]
    pub fn new(
        query_id: QueryId,
        field_type: FieldType,
        query_type: QueryType,
        ring: RingConfiguration<'a>,
    ) -> Self {
        Self {
            query_id,
            field_type,
            query_type,
            ring,
        }
    }
}
