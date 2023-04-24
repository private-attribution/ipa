mod executor;
mod processor;
mod state;

pub use executor::Result as ProtocolResult;

pub use processor::{
    NewQueryError, PrepareQueryError, Processor as QueryProcessor, QueryCompletionError,
    QueryInputError,
};
