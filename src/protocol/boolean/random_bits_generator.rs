use super::solved_bits::{solved_bits, RandomBitsShare};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::TotalRecords;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;
use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

/// A struct that pre-generates and buffers random sharings of bits from the
/// `SolvedBits` protocol. Any protocol who wish to use a random-bits can draw
/// one by calling `generate()`.
///
/// This object is safe to share with multiple threads.  It uses an atomic counter
/// to manage concurrent accesses.
#[derive(Debug)]
pub struct RandomBitsGenerator<F, S, C> {
    ctx: C,
    record_id: AtomicU32,
    abort_count: AtomicUsize,
    _marker: PhantomData<(F, S)>,
}

impl<F, S, C> RandomBitsGenerator<F, S, C>
where
    F: Field,
    S: ArithmeticSecretSharing<F>,
    C: Context<F, Share = S>,
{
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // TODO: pending resolution of TotalRecords::Indeterminate
    pub fn new(ctx: C) -> Self {
        debug_assert!(ctx.is_total_records_unspecified());
        Self {
            ctx: ctx.set_total_records(TotalRecords::Indeterminate),
            record_id: AtomicU32::new(0),
            abort_count: AtomicUsize::new(0),
            _marker: PhantomData,
        }
    }

    /// Takes the next `RandomBitsShare` that is available.  As the underlying
    /// generator can fail, this will draw from that repeatedly until a value is produced.
    ///
    /// # Errors
    /// This method may fail for number of reasons. Errors include locking the
    /// inner members multiple times, I/O errors while executing MPC protocols,
    /// read from an empty buffer, etc.
    pub async fn generate(&self) -> Result<RandomBitsShare<F, S>, Error> {
        loop {
            let i = self.record_id.fetch_add(1, Ordering::Relaxed);
            if let Some(v) = solved_bits(self.ctx.clone(), RecordId::from(i)).await? {
                return Ok(v);
            }
            self.abort_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Get the number of aborts for this instance.
    #[allow(dead_code)]
    pub fn aborts(&self) -> usize {
        self.abort_count.load(Ordering::Acquire)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::zip;

    use futures::future::try_join_all;

    use super::RandomBitsGenerator;
    use crate::{
        ff::Fp31,
        protocol::malicious::MaliciousValidator,
        test_fixture::{join3, Reconstruct, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::new().await;
        let [c0, c1, c2] = world.contexts::<Fp31>();

        let rbg0 = RandomBitsGenerator::new(c0);
        let rbg1 = RandomBitsGenerator::new(c1);
        let rbg2 = RandomBitsGenerator::new(c2);

        let result = join3(rbg0.generate(), rbg1.generate(), rbg2.generate()).await;
        assert_eq!(rbg0.aborts(), rbg1.aborts());
        assert_eq!(rbg0.aborts(), rbg2.aborts());
        let _ = result.reconstruct(); // reconstruct() will validate the value.
    }

    #[tokio::test]
    pub async fn malicious() {
        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();

        let validators = contexts.map(MaliciousValidator::new);
        let rbg = validators
            .iter()
            .map(|v| RandomBitsGenerator::new(v.context()))
            .collect::<Vec<_>>();

        let m_result = join3(rbg[0].generate(), rbg[1].generate(), rbg[2].generate()).await;
        assert_eq!(rbg[0].aborts(), rbg[1].aborts());
        assert_eq!(rbg[0].aborts(), rbg[2].aborts());

        let result = <[_; 3]>::try_from(
            try_join_all(zip(validators, m_result).map(|(v, m)| v.validate(m)))
                .await
                .unwrap(),
        )
        .unwrap();
        let _ = result.reconstruct(); // reconstruct() will validate the value.
    }
}
