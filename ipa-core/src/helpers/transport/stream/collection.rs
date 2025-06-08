use std::{
    collections::{HashMap, hash_map::Entry},
    fmt::{Debug, Formatter},
    task::Waker,
};

use futures::Stream;

use crate::{
    helpers::TransportIdentity,
    protocol::{Gate, QueryId},
    sync::{Arc, Mutex},
};

/// Each stream is indexed by query id, the identity of helper where stream is originated from
/// and step.
pub type StreamKey<I> = (QueryId, I, Gate);

/// Thread-safe append-only collection of homogeneous record streams.
/// Streams are indexed by [`StreamKey`] and the lifecycle of each stream is described by the
/// [`StreamState`] struct.
///
/// Each stream can be inserted and taken away exactly once, any deviation from this behaviour will
/// result in panic.
pub struct StreamCollection<I, S> {
    inner: Arc<Mutex<HashMap<StreamKey<I>, StreamState<S>>>>,
}

impl<I, S> Default for StreamCollection<I, S> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

impl<I, S> Clone for StreamCollection<I, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<I: TransportIdentity, S: Stream> StreamCollection<I, S> {
    /// Adds a new stream associated with the given key.
    ///
    /// ## Panics
    /// If there was another stream associated with the same key some time in the past.
    pub fn add_stream(&self, key: StreamKey<I>, stream: S) {
        let mut streams = self.inner.lock().unwrap();
        match streams.entry(key) {
            Entry::Occupied(mut entry) => match entry.get_mut() {
                rs @ StreamState::Waiting(_) => {
                    let StreamState::Waiting(waker) =
                        std::mem::replace(rs, StreamState::Ready(stream))
                    else {
                        unreachable!()
                    };
                    waker.wake();
                }
                rs @ (StreamState::Ready(_) | StreamState::Completed) => {
                    let state = format!("{rs:?}");
                    let key = entry.key().clone();
                    drop(streams);
                    panic!("{key:?} entry state expected to be waiting, got {state:?}");
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(StreamState::Ready(stream));
            }
        }
    }

    /// Adds a new waker to notify when the stream is ready. If stream is ready, this method takes
    /// it out, leaving a tombstone in its place, and returns it.
    ///
    /// ## Panics
    /// If [`Waker`] that exists already inside this collection will not wake the given one.
    pub fn add_waker(&self, key: &StreamKey<I>, waker: &Waker) -> Option<S> {
        let mut streams = self.inner.lock().unwrap();

        match streams.entry(key.clone()) {
            Entry::Occupied(mut entry) => match entry.get_mut() {
                StreamState::Waiting(old_waker) => {
                    old_waker.clone_from(waker);
                    None
                }
                rs @ StreamState::Ready(_) => {
                    let StreamState::Ready(stream) = std::mem::replace(rs, StreamState::Completed)
                    else {
                        unreachable!();
                    };

                    Some(stream)
                }
                StreamState::Completed => {
                    drop(streams);
                    panic!("{key:?} stream has been consumed already")
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(StreamState::Waiting(waker.clone()));
                None
            }
        }
    }

    /// Clears up this collection, leaving no streams inside it.
    ///
    /// ## Panics
    /// if mutex is poisoned.
    pub fn clear(&self) {
        let mut streams = self.inner.lock().unwrap();
        streams.clear();
    }

    /// Returns the number of streams inside this collection.
    ///
    /// ## Panics
    /// if mutex is poisoned.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Returns `true` if this collection is empty.
    ///
    /// ## Panics
    /// if mutex is poisoned.
    #[must_use]
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Describes the lifecycle of records stream inside [`StreamCollection`]
enum StreamState<S> {
    /// There was a request to receive this stream, but it hasn't arrived yet
    Waiting(Waker),
    /// Stream is ready to be consumed
    Ready(S),
    /// Stream was successfully received and taken away from [`StreamCollection`].
    /// It may not be requested or received again.
    Completed,
}

impl<S> Debug for StreamState<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamState::Waiting(_) => {
                write!(f, "Waiting")
            }
            StreamState::Ready(_) => {
                write!(f, "Ready")
            }
            StreamState::Completed => {
                write!(f, "Completed")
            }
        }
    }
}
