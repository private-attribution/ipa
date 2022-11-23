use super::solved_bits::{RandomBitsShare, SolvedBits};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::RecordId;
use std::collections::HashMap;

/// A struct that pre-generates and buffers random sharings of bits from the
/// `SolvedBits` protocol. Any protocol who wish to use a random-bits can draw
/// one by calling `take_one()`. It will call `SolvedBits` once the stock falls
/// below `REFILL_THRESHOLD` until it fills up the empty slots.
///
/// Internally, it uses two pointers. `read_pointer` keeps track of the next
/// item to return, and `write_pointer` points to the least recent empty slot.
/// The pointers are `i8`. Incrementing them cause wrap around at the boundary,
/// which makes the `buffer` hash map a ring buffer.
#[allow(dead_code)]
pub struct RandomBitsGenerator<'a, F: Field> {
    context: SemiHonestContext<'a, F>,
    buffer: HashMap<i8, RandomBitsShare<F>>,
    counter: u32,
    read_pointer: i8,
    write_pointer: i8,
    abort_count: u32,
}

#[allow(dead_code)]
impl<'a, F: Field> RandomBitsGenerator<'a, F> {
    const REFILL_THRESHOLD: u8 = 16;

    pub fn new(context: SemiHonestContext<'a, F>) -> Self {
        Self {
            context,
            buffer: HashMap::with_capacity(u8::MAX.into()),
            counter: 0,
            read_pointer: 0,
            write_pointer: 0,
            abort_count: 0,
        }
    }

    /// Takes one `RandomBitsShare` instance out of the buffer. If the number
    /// of buffered items fall below a threshold, it'll replenish.
    pub async fn take_one(&mut self) -> Result<RandomBitsShare<F>, Error> {
        self.refill_if_needed().await?;
        let r = self
            .buffer
            .remove(&self.read_pointer)
            .expect("unexpected buffer depletion");
        self.read_pointer = self.read_pointer.wrapping_add(1);
        Ok(r)
    }

    /// Checks if the stock is short, and replenish as needed. Specifically, it
    /// will call `SolvedBits` once the stock falls below `REFILL_THRESHOLD`,
    /// until the `write_pointer` is one place behind the `read_pointer`.
    async fn refill_if_needed(&mut self) -> Result<(), Error> {
        // intentional type coercing `i8` -> `u8`
        #[allow(clippy::cast_sign_loss)]
        if self.write_pointer.wrapping_sub(self.read_pointer) as u8 > Self::REFILL_THRESHOLD {
            return Ok(());
        }

        while self.read_pointer.wrapping_sub(self.write_pointer) != 1 {
            let record_id = RecordId::from(self.counter);
            let r = SolvedBits::execute(self.context.clone(), record_id).await?;
            if let Some(x) = r {
                self.buffer.insert(self.write_pointer, x);
                self.write_pointer = self.write_pointer.wrapping_add(1);
            } else {
                // Keep track of how many times `SolvedBits` aborted. This stat
                // is for testing and telemetry purposes only.
                self.abort_count += 1;
            }
            // Current implementation will cause the context to panic once u32
            // wraps around. It's probably safe to reuse the same index again
            // after so many records being processed.
            self.counter = self.counter.wrapping_add(1);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RandomBitsGenerator;
    use crate::{
        error::Error,
        ff::Fp31,
        protocol::QueryId,
        test_fixture::{join3, logging, make_contexts, make_world, TestWorld},
    };

    #[tokio::test]
    pub async fn basic() -> Result<(), Error> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;

        let mut rbg0 = RandomBitsGenerator::new(c0);
        let mut rbg1 = RandomBitsGenerator::new(c1);
        let mut rbg2 = RandomBitsGenerator::new(c2);

        let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

        // From the initial pointer positions r=0, w=0, the buffer is replenished until
        // the r.wrapping_sub(w) == 1. We called `take_one()` once, so the pointers are
        // at r=1 and w=-1. The `counter` should have been incremented to 255 (max buffer
        // size) + `abort_count`.
        assert_eq!(254, rbg0.buffer.len());
        assert_eq!(255 + rbg0.abort_count, rbg0.counter);
        assert_eq!(1, rbg0.read_pointer);
        assert_eq!(-1, rbg0.write_pointer);

        // Now we `take_one()` 238 times
        for _ in 0..238 {
            let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;
        }

        // There should be 16 items left in the buffer
        assert_eq!(16, rbg0.buffer.len());
        assert_eq!(255 + rbg0.abort_count, rbg0.counter);
        assert_eq!(-17, rbg0.read_pointer);
        assert_eq!(-1, rbg0.write_pointer);

        // One more `take_one()` will trigger the replenishment
        let _result = join3(rbg0.take_one(), rbg1.take_one(), rbg2.take_one()).await;

        assert_eq!(254, rbg0.buffer.len());
        assert_eq!(255 + 239 + rbg0.abort_count, rbg0.counter);
        assert_eq!(-16, rbg0.read_pointer);
        assert_eq!(-18, rbg0.write_pointer);

        Ok(())
    }
}
