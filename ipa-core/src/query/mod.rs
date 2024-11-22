mod completion;
mod executor;
mod processor;
mod runner;
mod state;

use completion::Handle as CompletionHandle;
pub use executor::Result as ProtocolResult;
pub use processor::{
    NewQueryError, PrepareQueryError, Processor as QueryProcessor, QueryCompletionError,
    QueryInputError, QueryKillStatus, QueryKilled, QueryStatusError,
};
pub use runner::OprfIpaQuery;
pub use state::{min_status, QueryStatus};
