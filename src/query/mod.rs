mod completion;
mod executor;
mod processor;
mod runner;
mod state;

pub use executor::Result as ProtocolResult;

pub use processor::{
    NewQueryError, PrepareQueryError, Processor as QueryProcessor, QueryCompletionError,
    QueryInputError,
};

pub use runner::KEY_REGISTRY;

use completion::Handle as CompletionHandle;
