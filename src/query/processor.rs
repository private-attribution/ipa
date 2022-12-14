use std::collections::HashMap;
use hyper::Uri;
use crate::helpers::Role;
use crate::protocol::QueryId;

#[derive(Default)]
struct Processor {
    running_queries: HashMap<QueryId, QueryState>,
}

enum FieldType {
    Fp31,
    Fp32BitPrime
}

enum QueryType {
    #[cfg(test)]
    TestMultiply,
    IPA
}

struct NewQueryRequest {
    field_type: FieldType,
    query_type: QueryType,
}

struct HelperIdentity {
    endpoint: Uri
}

struct RingConfiguration {
    map: HashMap<HelperIdentity, Role>,
}

struct QueryConfiguration {
    field_type: FieldType,
    query_type: QueryType,
    ring: RingConfiguration,
}


impl Processor {

    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka leader)
    /// and is free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers).
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    async fn new_query(&self, req: NewQueryRequest) ->  {
        todo!()
    }
}


#[cfg(all(test, not(feature = "shuttle")))]
mod tests {

}