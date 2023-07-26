mod ordering_mpsc;
pub(crate) mod ordering_sender;
mod unordered_receiver;

#[cfg(debug_assertions)]
use std::{fmt, ops::RangeInclusive};

pub use ordering_mpsc::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender};
pub use ordering_sender::{IdleTrackOrderingSender, OrderedStream, OrderingSender};
pub use unordered_receiver::{IdleTrackUnorderedReceiver, UnorderedReceiver};

#[cfg(debug_assertions)]
use itertools::Itertools;

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

#[cfg(debug_assertions)]
pub struct LoggingRanges(Vec<RangeInclusive<usize>>);

#[cfg(debug_assertions)]
impl LoggingRanges {
    pub fn from(numbers: &[usize]) -> Self {
        if numbers.is_empty() {
            return Self(Vec::new());
        }
        #[cfg(not(debug_assertions))]
        return Self(Vec::new());

        #[cfg(debug_assertions)]
        Self(
            numbers
                .iter()
                .enumerate()
                .group_by(|&(i, &num)| num - i)
                .into_iter()
                .map(|(_, group)| {
                    let range: Vec<usize> = group.map(|(_, &num)| num).collect();
                    range[0]..=range[range.len() - 1]
                })
                .collect::<Vec<RangeInclusive<usize>>>(),
        )
    }

    #[cfg(debug_assertions)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(debug_assertions)]
impl fmt::Debug for LoggingRanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Collect the formatted ranges into a vector of strings
        let formatted_ranges: Vec<String> = self
            .0
            .iter()
            .map(|range| match (range.end() - range.start()).cmp(&1) {
                std::cmp::Ordering::Less => format!("{}", range.start()),
                std::cmp::Ordering::Equal => format!("[{}, {}] ", range.start(), range.end()),
                std::cmp::Ordering::Greater => {
                    format!("[{}, ..., {}] ", range.start(), range.end())
                }
            })
            .collect();
        write!(f, "[{}]", formatted_ranges.join(", "))
    }
}
