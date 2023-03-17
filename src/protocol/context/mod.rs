use crate::{
    helpers::{Role, TotalRecords},
    protocol::{Step, Substep},
};

pub mod malicious;
mod prss;
mod semi_honest;

use crate::helpers::{Message, ReceivingEnd, SendingEnd};
pub(super) use malicious::SpecialAccessToMaliciousContext;
pub use malicious::{MaliciousContext, UpgradeContext, UpgradeToMalicious};
pub use prss::{InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness};
pub use semi_honest::SemiHonestContext;

/// Context used by each helper to perform secure computation. Provides access to shared randomness
/// generator and communication channel.
pub trait Context: Clone + Send + Sync {
    /// The role of this context.
    fn role(&self) -> Role;

    /// A unique identifier for this stage of the protocol execution.
    #[must_use]
    fn step(&self) -> &Step;

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    #[must_use]
    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self;

    /// Returns true if the context does not have a total record count set (regardless
    /// of whether that total is known or indeterminate).
    fn is_total_records_unspecified(&self) -> bool;

    /// Sets the context's total number of records field. Communication channels are
    /// closed based on sending the expected total number of records.
    #[must_use]
    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self;

    /// Get the indexed PRSS instance for this step.  It is safe to call this function
    /// multiple times.
    ///
    /// # Panics
    /// If `prss_rng()` is invoked for the same context, this will panic.  Use of
    /// these two functions are mutually exclusive.
    #[must_use]
    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_>;

    /// Get a pair of PRSS-based RNGs.  The first is shared with the helper to the "left",
    /// the second is shared with the helper to the "right".
    ///
    /// # Panics
    /// This method can only be called once.  This is also mutually exclusive with `prss()`.
    /// This will panic if you have previously invoked `prss()`.
    #[must_use]
    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness,
        InstrumentedSequentialSharedRandomness,
    );

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M>;
    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M>;
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        helpers::Direction,
        protocol::{
            malicious::{MaliciousValidator, Step::MaliciousProtocol},
            prss::SharedRandomness,
            RecordId,
        },
        secret_sharing::replicated::{
            malicious::AdditiveShare as MaliciousReplicated,
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
        telemetry::metrics::{INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED},
    };
    use futures_util::{future::join_all, try_join};
    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use std::iter::repeat;

    use super::*;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig};

    trait AsReplicatedTestOnly<F: Field> {
        fn l(&self) -> F;
        fn r(&self) -> F;
    }

    impl<F: Field> AsReplicatedTestOnly<F> for Replicated<F> {
        fn l(&self) -> F {
            (self as &Replicated<F>).left()
        }

        fn r(&self) -> F {
            (self as &Replicated<F>).right()
        }
    }

    /// This looks weird because it uses `MaliciousReplicated::rx()` value instead of `x`.
    /// Malicious context intentionally disallows access to `x` without validating first and
    /// here it does not matter at all. It needs just some value to send (any value would do just
    /// fine)
    impl<F: Field> AsReplicatedTestOnly<F> for MaliciousReplicated<F> {
        fn l(&self) -> F {
            (self as &MaliciousReplicated<F>).rx().left()
        }

        fn r(&self) -> F {
            (self as &MaliciousReplicated<F>).rx().right()
        }
    }

    /// Toy protocol to execute PRSS generation and send/receive logic
    async fn toy_protocol<F, S, C>(ctx: C, index: usize, share: &S) -> Replicated<F>
    where
        F: Field,
        Standard: Distribution<F>,
        C: Context,
        S: AsReplicatedTestOnly<F>,
    {
        let ctx = ctx.narrow("metrics");
        let (left_peer, right_peer) = (
            ctx.role().peer(Direction::Left),
            ctx.role().peer(Direction::Right),
        );
        let record_id = RecordId::from(index);
        let (l, r) = ctx.prss().generate_fields(record_id);

        let (seq_l, seq_r) = {
            let ctx = ctx.narrow(&format!("seq-prss-{index}"));
            let (mut left_rng, mut right_rng) = ctx.prss_rng();
            (left_rng.gen::<F>(), right_rng.gen::<F>())
        };

        let send_channel = ctx.send_channel(left_peer);
        let recv_channel = ctx.recv_channel::<F>(right_peer);
        let (_, right_share) = try_join!(
            send_channel.send(record_id, share.l() - l - seq_l),
            recv_channel.receive(record_id),
        )
        .unwrap();

        Replicated::new(share.l(), right_share + r + seq_r)
    }

    #[tokio::test]
    async fn semi_honest_metrics() {
        let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());
        let input = (0..10u128).map(Fp31::from).collect::<Vec<_>>();
        let input_len = input.len();

        let result = world
            .semi_honest(input.clone(), |ctx, shares| async move {
                join_all(
                    shares
                        .iter()
                        .enumerate()
                        .zip(repeat(ctx.set_total_records(input_len)))
                        .map(|((i, share), ctx)| toy_protocol(ctx, i, share)),
                )
                .await
            })
            .await
            .reconstruct();

        // just in case, validate that each helper holds valid shares
        assert_eq!(input, result);

        let input_size = input.len();
        let snapshot = world.metrics_snapshot();
        let metrics_step = Step::default()
            .narrow(&TestWorld::execution_step(0))
            .narrow("metrics");

        // for semi-honest protocols, amplification factor per helper is 1.
        // that is, for every communication, there is exactly one send and receive of the same data
        let records_sent_assert = snapshot
            .assert_metric(RECORDS_SENT)
            .total(3 * input_size)
            .per_step(&metrics_step, 3 * input_size);

        let indexed_prss_assert = snapshot
            .assert_metric(INDEXED_PRSS_GENERATED)
            .total(3 * input_size)
            .per_step(&metrics_step, 3 * input_size);

        // each helper generates 2 128 bit values resuling in 4 calls to rng::<gen>() per input row
        let seq_prss_assert = snapshot
            .assert_metric(SEQUENTIAL_PRSS_GENERATED)
            .total(4 * 3 * input_size)
            .per_step(&metrics_step.narrow("seq-prss-0"), 4 * 3);

        for role in Role::all() {
            records_sent_assert.per_helper(role, input_size);
            indexed_prss_assert.per_helper(role, input_size);
            seq_prss_assert.per_helper(role, 4 * input_size);
        }
    }

    #[tokio::test]
    async fn malicious_metrics() {
        let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());
        let input = vec![Fp31::from(0u128), Fp31::from(1u128)];
        let input_len = input.len();

        let _result = world
            .malicious(input.clone(), |ctx, a| async move {
                let ctx = ctx.set_total_records(input_len);
                join_all(
                    a.iter()
                        .enumerate()
                        .map(|(i, share)| toy_protocol(ctx.clone(), i, share)),
                )
                .await;

                a
            })
            .await;

        let metrics_step = Step::default()
            .narrow(&TestWorld::execution_step(0))
            // TODO: leaky abstraction, test world should tell us the exact step
            .narrow(&MaliciousProtocol)
            .narrow("metrics");

        let input_size = input.len();
        let snapshot = world.metrics_snapshot();

        // Malicious protocol has an amplification factor of 3 and constant overhead of 3. For each input row it
        // (input size) upgrades input to malicious
        // (input size) executes toy protocol
        // (input size) propagates u and w
        // (1) multiply r * share of zero
        // (2) reveals r (1 for check_zero, 1 for validate)
        let comm_factor = |input_size| 3 * input_size + 3;
        let records_sent_assert = snapshot
            .assert_metric(RECORDS_SENT)
            .total(3 * comm_factor(input_size))
            .per_step(&metrics_step, 3 * input_size);

        // PRSS amplification factor is 3 and constant overhead is 5
        // (1) to generate r
        // (1) to generate u
        // (1) to generate w
        // (input_size) to generate random constant later used for validation
        // (input_size) to multiply input by r
        // (input_size) to execute toy protocol
        // (1) to generate randomness for check_zero
        // (1) to multiply output with r
        let prss_factor = |input_size| 3 * input_size + 3 + 1 + 1;
        let indexed_prss_assert = snapshot
            .assert_metric(INDEXED_PRSS_GENERATED)
            .total(3 * prss_factor(input_size))
            .per_step(&metrics_step, 3 * input_size);

        // see semi-honest test for explanation
        let seq_prss_assert = snapshot
            .assert_metric(SEQUENTIAL_PRSS_GENERATED)
            .total(4 * 3 * input_size)
            .per_step(&metrics_step.narrow("seq-prss-0"), 4 * 3);

        for role in Role::all() {
            records_sent_assert.per_helper(role, comm_factor(input_size));
            indexed_prss_assert.per_helper(role, prss_factor(input_size));
            seq_prss_assert.per_helper(role, 4 * input_size);
        }
    }

    /// validates that malicious upgrade can be called more than once on contexts narrowed down
    /// to unique steps
    #[tokio::test]
    async fn malicious_upgrade() {
        let input = vec![Fp31::from(0u128), Fp31::from(1u128)];
        let world = TestWorld::default();

        world
            .semi_honest(input, |ctx, shares| async move {
                // upgrade shares two times using different contexts
                let v = MaliciousValidator::new(ctx);
                let ctx = v.context().narrow("step1");
                ctx.upgrade(shares.clone()).await.unwrap();
                let ctx = v.context().narrow("step2");
                ctx.upgrade(shares).await.unwrap();
            })
            .await;
    }
}
