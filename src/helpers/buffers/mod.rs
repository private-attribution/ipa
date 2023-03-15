mod fsv;
mod ordering_mpsc;
mod ordering_sender;
mod receive;
mod send;
mod unordered_receiver;

pub use ordering_mpsc::ordering_mpsc;
pub use receive::ReceiveBuffer;
pub use send::{Config as SendBufferConfig, SendBuffer};

#[cfg(debug_assertions)]
mod waiting {
    use crate::helpers::network::ChannelId;
    use std::collections::HashMap;

    pub(in crate::helpers) struct WaitingTasks<'a> {
        tasks: HashMap<&'a ChannelId, Vec<u32>>,
    }

    impl<'a> WaitingTasks<'a> {
        pub fn new(tasks: HashMap<&'a ChannelId, Vec<u32>>) -> Self {
            Self { tasks }
        }

        pub fn is_empty(&self) -> bool {
            self.tasks.is_empty()
        }
    }

    impl std::fmt::Debug for WaitingTasks<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[")?;
            for (channel, records) in &self.tasks {
                write!(f, "\n    {channel:?}: {records:?}")?;
            }
            write!(f, "\n]")?;

            Ok(())
        }
    }
}
