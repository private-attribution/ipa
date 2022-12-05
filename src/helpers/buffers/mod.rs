mod fsv;
mod receive;
mod send;

use crate::helpers::network::ChannelId;

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

pub use receive::ReceiveBuffer;
pub use {send::Config as SendBufferConfig, send::SendBuffer};

pub(in crate::helpers) struct WaitingTasks<'a> {
    tasks: HashMap<&'a ChannelId, Vec<u32>>,
}

impl WaitingTasks<'_> {
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

impl Debug for WaitingTasks<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (channel, records) in &self.tasks {
            write!(f, "\n{:?}: {:?}", channel, records)?;
        }
        write!(f, "\n]")?;

        Ok(())
    }
}
