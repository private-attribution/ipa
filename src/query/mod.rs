mod executor;
mod processor;
mod state;

pub use executor::Result as ProtocolResult;

pub use processor::{NewQueryError, QueryInputError, QueryCompletionError, Processor as QueryProcessor};
