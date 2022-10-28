use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::mem;

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
pub(in crate::helpers) struct SendBuffer {
    max_capacity: usize,
    inner: HashMap<ChannelId, Vec<MessageEnvelope>>,
}

impl SendBuffer {
    pub fn new(max_channel_capacity: u32) -> Self {
        Self {
            max_capacity: max_channel_capacity as usize,
            inner: HashMap::default(),
        }
    }

    pub fn push(
        &mut self,
        channel_id: ChannelId,
        msg: MessageEnvelope,
    ) -> Option<Vec<MessageEnvelope>> {
        let vec = match self.inner.entry(channel_id) {
            Entry::Occupied(entry) => {
                let vec = entry.into_mut();
                vec.push(msg);

                vec
            }
            Entry::Vacant(entry) => {
                let vec = entry.insert(Vec::with_capacity(self.max_capacity));
                vec.push(msg);

                vec
            }
        };

        if vec.len() >= self.max_capacity {
            let data = mem::replace(vec, Vec::with_capacity(self.max_capacity));
            Some(data)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn remove_random(&mut self) -> (ChannelId, Vec<MessageEnvelope>) {
        assert!(self.len() > 0);

        let channel_id = self.inner.keys().next().unwrap().clone();
        let data = self.inner.remove(&channel_id).unwrap();

        (channel_id, data)
    }
}
