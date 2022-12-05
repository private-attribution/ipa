mod fsv;
mod receive;
mod send;

#[cfg(debug_assertions)]
use crate::helpers::network::ChannelId;

#[cfg(debug_assertions)]
use std::collections::HashMap;

pub use receive::ReceiveBuffer;
pub use {send::Config as SendBufferConfig, send::SendBuffer};

#[cfg(debug_assertions)]
pub(in crate::helpers) struct WaitingTasks<'a> {
    tasks: HashMap<&'a ChannelId, Vec<u32>>,
}

#[cfg(debug_assertions)]
impl WaitingTasks<'_> {
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for WaitingTasks<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (channel, records) in &self.tasks {
            write!(f, "\n{:?}: {:?}", channel, records)?;
        }
        write!(f, "\n]")?;

        Ok(())
    }
}
