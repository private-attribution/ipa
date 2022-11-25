use super::solved_bits::{RandomBitsShare, SolvedBits};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::RecordId;
use futures::{future::try_join_all, TryFutureExt};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

/// An implementation of simple ring buffer that stores `u8::MAX` items.
///
/// Internally, it uses two pointers. `read_pointer` keeps track of the next
/// item to return, and `write_pointer` points to the least recent empty slot.
/// The pointers are `u8`. Incrementing them cause wrap around at the boundary,
/// which makes the hash map a ring buffer.
struct RingBuffer<F: Field> {
    buffer: HashMap<u8, RandomBitsShare<F>>,
    read_pointer: u8,
    write_pointer: u8,
}

impl<F: Field> RingBuffer<F> {
    const MAX_SIZE: usize = 256;

    pub fn new() -> Self {
        Self {
            buffer: HashMap::with_capacity(Self::MAX_SIZE),
            read_pointer: 0,
            write_pointer: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn available_len(&self) -> usize {
        Self::MAX_SIZE - self.len()
    }

    pub fn insert(&mut self, v: RandomBitsShare<F>) -> Option<RandomBitsShare<F>> {
        let x = self.buffer.insert(self.write_pointer, v);
        self.write_pointer = self.write_pointer.wrapping_add(1);
        x
    }

    pub fn remove(&mut self) -> Option<RandomBitsShare<F>> {
        let x = self.buffer.remove(&self.read_pointer);
        self.read_pointer = self.read_pointer.wrapping_add(1);
        x
    }
}

/// A struct that pre-generates and buffers random sharings of bits from the
/// `SolvedBits` protocol. Any protocol who wish to use a random-bits can draw
/// one by calling `take_one()`. It will call `SolvedBits` once the stock falls
/// below `REFILL_THRESHOLD` until it fills up the empty slots.
#[allow(dead_code)]
pub struct RandomBitsGenerator<'a, F: Field> {
    context: SemiHonestContext<'a, F>,
    buffer: Mutex<RingBuffer<F>>,
    counter: Cell<u32>,
    abort_count: Cell<u32>,
}

#[allow(dead_code)]
impl<'a, F: Field> RandomBitsGenerator<'a, F> {
    const REFILL_THRESHOLD: usize = 16;

    pub fn new(context: SemiHonestContext<'a, F>) -> Self {
        Self {
            context,
            buffer: Mutex::new(RingBuffer::new()),
            counter: Cell::new(0),
            abort_count: Cell::new(0),
        }
    }

    /// Takes one `RandomBitsShare` instance out of the buffer. If the number
    /// of buffered items fall below a threshold, it'll replenish.
    pub async fn take_one(&self) -> Result<RandomBitsShare<F>, Error> {
        let mut buffer = self.buffer.lock().unwrap();

        if buffer.len() > Self::REFILL_THRESHOLD {
            return Ok(self.take_one_from_buffer(&mut buffer));
        }

        self.refill_and_take_one(&mut buffer).await
    }

    /// Takes one `RandomBitsShare`, and advances the read pointer by one.
    fn take_one_from_buffer(&self, buf: &mut RingBuffer<F>) -> RandomBitsShare<F> {
        buf.remove().expect("unexpected buffer depletion")
    }

    /// Calls `SolvedBits` to refill the empty slots in the buffer, and returns
    /// one `RandomBitsShare` instance.
    async fn refill_and_take_one(
        &self,
        buf: &mut RingBuffer<F>,
    ) -> Result<RandomBitsShare<F>, Error> {
        let empty_count = buf.available_len();
        try_join_all((0..empty_count).map(|_| {
            let c = self.context.clone();
            let counter = self.counter.get();
            let record_id = RecordId::from(counter);

            // Current implementation will cause the context to panic once u32
            // wraps around. It's probably safe to reuse the same index again
            // after so many records being processed.
            self.counter.set(counter.wrapping_add(1));

            async move { SolvedBits::execute(c, record_id).await }
        }))
        .and_then(|new_stock| async move {
            new_stock.into_iter().for_each(|x| {
                if let Some(r) = x {
                    buf.insert(r);
                } else {
                    // Keep track of how many times `SolvedBits` aborted. This stat
                    // is for testing and telemetry purposes only.
                    self.abort_count.set(self.abort_count.get() + 1);
                }
            });
            Ok(self.take_one_from_buffer(buf))
        })
        .await
    }

    // Used for unit tests only. Takes a lock and returns the internal counters
    // of the ring buffer.
    fn stats(&self) -> (usize, u32, u32, u8, u8) {
        let buf = self.buffer.lock().unwrap();
        (
            buf.len(),
            self.counter.get(),
            self.abort_count.get(),
            buf.read_pointer,
            buf.write_pointer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::RandomBitsGenerator;
    use crate::{
        error::Error,
        ff::Fp31,
        protocol::QueryId,
        test_fixture::{join3, TestWorld},
    };

    // Currently, this test runs for about 6 seconds. It needs mocking or similar
    // to be able to have SolvedBits return fake values without communications.
    // #[tokio::test]
    // pub async fn basic() -> Result<(), Error> {
    //     let world = TestWorld::new(QueryId);
    //     // let ctx = make_contexts::<Fp31>(&world);
    //     // let [c0, c1, c2] = ctx;

    //     let rbg0 = RandomBitsGenerator::new(c0);
    //     let rbg1 = RandomBitsGenerator::new(c1);
    //     let rbg2 = RandomBitsGenerator::new(c2);

    //     let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

    //     // From the initial pointer positions r=0, w=0, the buffer is replenished
    //     // until we fill `MAX_SIZE` items. We called `take_one()` once, so the
    //     // `counter` should have been incremented to `MAX_SIZE`, and the buffer
    //     // size `counter - abort_count - 1` (-1 because we took one).
    //     // The pointers should be at `r=1` (took one) and `w=success_count`
    //     // (points to the next empty slot).
    //     let (size, counter, abort_count, rp, wp) = rbg0.stats();
    //     let success_count = counter - abort_count;
    //     assert_eq!((success_count - 1) as usize, size);
    //     assert_eq!(256, counter);
    //     assert_eq!(1, rp);
    //     assert_eq!(success_count as u8, wp);
    //     let (last_size, last_rp, last_wp) = (size, rp, wp);
    //     let take_n = last_size - 16;

    //     // Now we `take_one()` until 16 items left in the buffer
    //     for _ in 0..take_n {
    //         let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;
    //     }

    //     // There should be 16 items left in the buffer. It hasn't triggered a
    //     // refill yet, because RBG checks the buffer size before removing the
    //     // item from the buffer.
    //     let (size, counter, abort_count, rp, wp) = rbg0.stats();
    //     assert_eq!(16, size);
    //     assert_eq!(256, counter);
    //     assert_eq!(last_rp + take_n as u8, rp);
    //     assert_eq!(last_wp, wp);
    //     let last_rp = last_rp + take_n as u8;
    //     let last_abort_count = abort_count;

    //     // One more `take_one()` will trigger the replenishment
    //     let _ = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

    //     // Now, RBG tried to fill the remaining empty slots (`256 - 16`),
    //     // aborted N times in this round (last_about_count - abort_count),
    //     // and we had 15 items in the buffer from the last round (took one
    //     // from 16).
    //     let (size, counter, abort_count, rp, wp) = rbg0.stats();
    //     let new_abort_count = abort_count - last_abort_count;
    //     let success_count = counter - new_abort_count;
    //     assert_eq!((256 - 16 - new_abort_count + 15) as usize, size);
    //     assert_eq!(496, counter);
    //     assert_eq!(last_rp + 1, rp);
    //     assert_eq!(last_wp.wrapping_add(success_count as u8), wp);

    //     Ok(())
    // }
}
