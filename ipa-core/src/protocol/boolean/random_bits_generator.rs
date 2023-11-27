use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::PrimeField,
    helpers::TotalRecords,
    protocol::{
        boolean::solved_bits::{solved_bits, RandomBitsShare},
        context::UpgradedContext,
        BasicProtocols, RecordId,
    },
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

/// A struct that generates random sharings of bits from the
/// `SolvedBits` protocol. Any protocol who wish to use a random-bits can draw
/// one by calling `generate()`.
///
/// This object is safe to share with multiple threads.  It uses an atomic counter
/// to manage concurrent accesses.
#[derive(Debug)]
pub struct RandomBitsGenerator<F, C, S> {
    ctx: C,
    fallback_ctx: C,
    fallback_count: AtomicU32,
    _marker: PhantomData<(F, S)>,
}

/// Special context that is used when values generated using the standard method are larger
/// than the prime for the field. It is grossly inefficient to use, because communications
/// are unbuffered, but a prime that is close to a power of 2 helps reduce how often we need it.
#[derive(Step)]
pub(crate) enum FallbackStep {
    Fallback,
}

impl<F, C, S> RandomBitsGenerator<F, C, S>
where
    F: PrimeField,
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
{
    #[must_use]
    pub fn new(ctx: C) -> Self {
        let fallback_ctx = ctx
            .narrow(&FallbackStep::Fallback)
            .set_total_records(TotalRecords::Indeterminate);
        Self {
            ctx,
            fallback_ctx,
            fallback_count: AtomicU32::new(0),
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
    pub async fn generate(&self, record_id: RecordId) -> Result<RandomBitsShare<F, S>, Error> {
        let share = if let Some(v) = solved_bits(self.ctx.clone(), record_id).await? {
            v
        } else {
            loop {
                let i = self.fallback_count.fetch_add(1, Ordering::AcqRel);
                if let Some(v) = solved_bits(self.fallback_ctx.clone(), RecordId::from(i)).await? {
                    break v;
                }
            }
        };

        if self.ctx.total_records().is_last(record_id) {
            // TODO: close indeterminate channels
        }

        Ok(share)
    }

    /// Get the number of aborts for this instance.
    #[allow(dead_code)]
    pub fn fallbacks(&self) -> u32 {
        self.fallback_count.load(Ordering::Acquire)
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::zip;

    use futures::future::try_join_all;

    use super::RandomBitsGenerator;
    use crate::{
        ff::{Field, Fp31},
        protocol::{
            context::{Context, UpgradableContext, Validator},
            RecordId,
        },
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            SharedValue,
        },
        test_fixture::{join3, join3v, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn semi_honest() {
        let world = TestWorld::default();
        let contexts = world.contexts().map(|ctx| ctx.set_total_records(1));
        let validators = contexts.map(UpgradableContext::validator);
        let [c0, c1, c2] = validators.map(|v| v.context());
        let record_id = RecordId::from(0);

        let rbg0 = RandomBitsGenerator::new(c0);
        let rbg1 = RandomBitsGenerator::new(c1);
        let rbg2 = RandomBitsGenerator::new(c2);

        let result = join3(
            rbg0.generate(record_id),
            rbg1.generate(record_id),
            rbg2.generate(record_id),
        )
        .await;
        assert_eq!(rbg0.fallbacks(), rbg1.fallbacks());
        assert_eq!(rbg0.fallbacks(), rbg2.fallbacks());
        let _: Fp31 = result.reconstruct(); // reconstruct() will validate the value.
    }

    #[tokio::test]
    pub async fn uses_fallback_channel() {
        /// The odds of needing a fallback on a field of size 31 is 1/32.
        /// 100 iterations will have a fallback with probability of 1-(1-31/32)^100.
        /// Repeating that 20 times should make the odds of failure negligible.
        const OUTER: u32 = 20;
        const INNER: u32 = 100;

        let world = TestWorld::default();

        for _ in 0..OUTER {
            let v = world
                .semi_honest((), |ctx, ()| async move {
                    let validator = ctx.validator();
                    let ctx = validator
                        .context()
                        .set_total_records(usize::try_from(INNER).unwrap());
                    let rbg = RandomBitsGenerator::<Fp31, _, _>::new(ctx);
                    drop(
                        // This can't use `seq_try_join_all` because this isn't sequential.
                        try_join_all((0..INNER).map(|i| rbg.generate(RecordId::from(i))))
                            .await
                            .unwrap(),
                    );
                    // Pass the number of fallbacks out as a share in Fp31.
                    // It will reconstruct as Fp31(3) or Fp31(0), which will let the outer
                    // code to know when to stop.  Reconstruction also ensures that helpers agree.
                    let f = Fp31::truncate_from(rbg.fallbacks() > 0);
                    AdditiveShare::new(f, f)
                })
                .await
                .reconstruct();
            if v != Fp31::ZERO {
                return;
            }
        }
        panic!(
            "{i} iterations failed to result in a fallback",
            i = OUTER * INNER
        );
    }

    #[tokio::test]
    pub async fn malicious() {
        let world = TestWorld::default();
        let contexts = world.malicious_contexts();

        let validators = contexts.map(UpgradableContext::validator::<Fp31>);
        let rbg = validators
            .iter()
            .map(|v| RandomBitsGenerator::new(v.context().set_total_records(1)))
            .collect::<Vec<_>>();
        let record_id = RecordId::from(0);

        let m_result = join3(
            rbg[0].generate(record_id),
            rbg[1].generate(record_id),
            rbg[2].generate(record_id),
        )
        .await;
        assert_eq!(rbg[0].fallbacks(), rbg[1].fallbacks());
        assert_eq!(rbg[0].fallbacks(), rbg[2].fallbacks());

        let result = join3v(zip(validators, m_result).map(|(v, m)| v.validate(m))).await;
        let _: Fp31 = result.reconstruct(); // reconstruct() will validate the value.
    }
}
