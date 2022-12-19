use super::solved_bits::{solved_bits, RandomBitsShare};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::SecretSharing;
use futures::{future::try_join_all, TryFutureExt};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::Mutex;

/// An implementation of simple ring buffer that stores `u8::MAX` items.
///
/// Internally, it uses two pointers. `read_pointer` keeps track of the next
/// item to return, and `write_pointer` points to the least recent empty slot.
/// The pointers are `u8`. Incrementing them cause wrap around at the boundary,
/// which makes the hash map a ring buffer.
#[derive(Debug)]
struct RingBuffer<T> {
    entries: HashMap<u8, T>,
    read_pointer: u8,
    write_pointer: u8,
}

impl<T> RingBuffer<T> {
    const MAX_SIZE: usize = 256;

    pub fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(Self::MAX_SIZE),
            read_pointer: 0,
            write_pointer: 0,
        }
    }

    /// Returns the number of items in the buffer.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of available slots in the buffer.
    pub fn available_space(&self) -> usize {
        Self::MAX_SIZE - self.len()
    }

    /// Inserts a value into the buffer at the next available slot.
    pub fn insert(&mut self, v: T) {
        self.entries.insert(self.write_pointer, v);
        self.write_pointer = self.write_pointer.wrapping_add(1);
    }

    /// Takes the least recent value from the buffer and removes it.
    pub fn take(&mut self) -> T {
        let x = self.entries.remove(&self.read_pointer);
        self.read_pointer = self.read_pointer.wrapping_add(1);
        x.expect("unexpected buffer depletion")
    }
}

#[derive(Debug)]
struct State<F, S, C>
where
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
{
    buffer: RingBuffer<RandomBitsShare<F, S>>,
    next_index: u32,
    abort_count: u32,
    context: C,
    _marker: PhantomData<F>,
}

impl<F, S, C> State<F, S, C>
where
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
{
    const REFILL_THRESHOLD: usize = 16;

    pub fn new(context: C) -> Self {
        Self {
            buffer: RingBuffer::new(),
            next_index: 0,
            abort_count: 0,
            context,
            _marker: PhantomData::default(),
        }
    }

    /// Returns a `RandomBitsShare` instance out of the buffer. If the number
    /// of buffered items fall below a threshold, it'll replenish.
    pub async fn get(&mut self) -> Result<RandomBitsShare<F, S>, Error> {
        // If we have enough shares, take one immediately return
        if self.buffer.len() > Self::REFILL_THRESHOLD {
            return Ok(self.buffer.take());
        }

        // call `SolvedBits` to refill the empty slots in the buffer, and returns
        // one `RandomBitsShare` instance.
        let available_space = self.buffer.available_space();
        try_join_all((0..available_space).map(|_| {
            let c = self.context.clone();
            let record_id = RecordId::from(self.next_index);

            // Current implementation will cause the context to panic once u32
            // wraps around. It's probably safe to reuse the same index again
            // after so many records being processed.
            self.next_index = self.next_index.wrapping_add(1);

            async move { solved_bits(c, record_id).await }
        }))
        .and_then(|new_stock| async move {
            for x in new_stock {
                if let Some(r) = x {
                    self.buffer.insert(r);
                } else {
                    // Keep track of how many times `SolvedBits` aborted. This stat
                    // is for testing and telemetry purposes only.
                    self.abort_count += 1;
                }
            }
            Ok(self.buffer.take())
        })
        .await
    }
}

/// A struct that pre-generates and buffers random sharings of bits from the
/// `SolvedBits` protocol. Any protocol who wish to use a random-bits can draw
/// one by calling `take_one()`. It will call `SolvedBits` once the stock falls
/// below `REFILL_THRESHOLD` until it fills up the empty slots.
#[derive(Debug)]
pub struct RandomBitsGenerator<F, S, C>
where
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
{
    state: Arc<Mutex<State<F, S, C>>>,
}

impl<F, S, C> RandomBitsGenerator<F, S, C>
where
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
{
    #[must_use]
    pub fn new(context: C) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new(context))),
        }
    }

    /// Generates a `RandomBitsShare` instance.
    ///
    /// # Errors
    /// This method mail fail for number of reasons. Errors include locking the
    /// inner members multiple times, I/O errors while executing MPC protocols,
    /// read from an empty buffer, etc.
    pub async fn take_one(&self) -> Result<RandomBitsShare<F, S>, Error> {
        let mut state = self.state.lock().await;
        state.get().await
    }

    // Used for unit tests only. Takes a lock and returns the internal counters
    // in the ring buffer.
    #[allow(dead_code)]
    async fn stats(&self) -> (usize, u32, u32, u8, u8) {
        let state = self.state.lock().await;
        (
            state.buffer.len(),
            state.next_index,
            state.abort_count,
            state.buffer.read_pointer,
            state.buffer.write_pointer,
        )
    }
}

impl<F, S, C> Clone for RandomBitsGenerator<F, S, C>
where
    F: Field,
    S: SecretSharing<F>,
    C: Context<F, Share = S>,
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::RandomBitsGenerator;
    use crate::{
        ff::Fp31,
        test_fixture::{join3, TestWorld},
    };

    // Currently, this test runs for about 6 seconds. It needs mocking or similar
    // to be able to have SolvedBits return fake values without communications.
    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)]
    pub async fn basic() {
        let world = TestWorld::new();
        let [c0, c1, c2] = world.contexts::<Fp31>();

        let rbg0 = RandomBitsGenerator::new(c0);
        let rbg1 = RandomBitsGenerator::new(c1);
        let rbg2 = RandomBitsGenerator::new(c2);

        let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

        // From the initial pointer positions r=0, w=0, the buffer is replenished
        // until we fill `MAX_SIZE` items. We called `take_one()` once, so the
        // `counter` should have been incremented to `MAX_SIZE`, and the buffer
        // size `counter - abort_count - 1` (-1 because we took one).
        // The pointers should be at `r=1` (took one) and `w=success_count`
        // (points to the next empty slot).
        let (size, counter, abort_count, rp, wp) = rbg0.stats().await;
        let success_count = counter - abort_count;
        assert_eq!((success_count - 1) as usize, size);
        assert_eq!(256, counter);
        assert_eq!(1, rp);
        assert_eq!(success_count as u8, wp);
        let (last_size, last_rp, last_wp) = (size, rp, wp);
        let take_n = last_size - 16;

        // Now we `take_one()` until 16 items left in the buffer
        for _ in 0..take_n {
            let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;
        }

        // There should be 16 items left in the buffer. It hasn't triggered a
        // refill yet, because RBG checks the buffer size before removing the
        // item from the buffer.
        let (size, counter, abort_count, rp, wp) = rbg0.stats().await;
        assert_eq!(16, size);
        assert_eq!(256, counter);
        assert_eq!(last_rp + take_n as u8, rp);
        assert_eq!(last_wp, wp);
        let last_rp = last_rp + take_n as u8;
        let last_abort_count = abort_count;

        // One more `take_one()` will trigger the replenishment
        let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

        // Now, RBG tried to fill the remaining empty slots (`256 - 16`),
        // aborted N times in this round (last_about_count - abort_count),
        // and we had 15 items in the buffer from the last round (took one
        // from 16).
        let (size, counter, abort_count, rp, wp) = rbg0.stats().await;
        let new_abort_count = abort_count - last_abort_count;
        let success_count = counter - new_abort_count;
        assert_eq!((256 - 16 - new_abort_count + 15) as usize, size);
        assert_eq!(496, counter);
        assert_eq!(last_rp + 1, rp);
        assert_eq!(last_wp.wrapping_add(success_count as u8), wp);
    }
}
