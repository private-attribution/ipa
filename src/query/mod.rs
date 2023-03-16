mod executor;
mod processor;
mod state;

pub use executor::Result as ProtocolResult;

#[cfg(never)]
pub use processor::{NewQueryError, Processor};
