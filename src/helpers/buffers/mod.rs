mod ordering_mpsc;
pub(crate) mod ordering_sender;
mod unordered_receiver;

pub use ordering_mpsc::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender};
pub use ordering_sender::{OrderedStream, OrderingSender, SenderStatus};
pub use unordered_receiver::UnorderedReceiver;

#[cfg(debug_assertions)]
#[allow(unused)] // todo(alex): make test world print the state again
mod waiting {
    use crate::helpers::ChannelId;
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

pub trait GatherWaitingMessage {
    fn compress_numbers(&self, numbers: &[usize]) -> String {
        let mut result = String::new();

        if numbers.is_empty() {
            return result;
        }

        let mut start = numbers[0];
        let mut prev = numbers[0];

        result.push_str(&start.to_string());

        for &num in numbers.iter().skip(1) {
            if num == prev + 1 {
                prev = num;
                continue;
            }

            if prev - start >= 2 {
                result.push_str(" .. ");
                result.push_str(&prev.to_string());
            } else if prev != start {
                result.push_str(", ");
                result.push_str(&prev.to_string());
            }

            result.push_str(", ");
            result.push_str(&num.to_string());

            start = num;
            prev = num;
        }

        if prev - start >= 2 {
            result.push_str(" .. ");
            result.push_str(&prev.to_string());
        } else if prev != start {
            result.push_str(", ");
            result.push_str(&prev.to_string());
        }

        result
    }
}
