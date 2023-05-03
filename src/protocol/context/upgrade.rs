use crate::{
    error::Error,
    ff::Field,
    protocol::{
        attribution::input::MCCappedCreditsWithAggregationBit, basics::ZeroPositions,
        context::UpgradedContext, modulus_conversion::BitConversionTriple, BitOpStep, NoRecord,
        RecordBinding, RecordId, Substep,
    },
    repeat64str,
    secret_sharing::{
        replicated::{malicious::ExtendableField, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing,
    },
};
use async_trait::async_trait;
use futures::future::{try_join, try_join3};
use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};

/// Special context type used for malicious upgrades.
///
/// The `B: RecordBinding` type parameter is used to prevent using the record ID multiple times to
/// implement an upgrade. For example, trying to use the record ID to iterate over both the inner
/// and outer vectors in a `Vec<Vec<T>>` is an error. Instead, one level of iteration can use the
/// record ID and the other can use something like a `BitOpStep`.
///
/// ```no_run
/// use ipa::protocol::{context::{UpgradeContext, UpgradeToMalicious, UpgradedMaliciousContext as C}, NoRecord, RecordId};
/// use ipa::ff::Fp32BitPrime as F;
/// use ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// // Note: Unbound upgrades only work when testing.
/// #[cfg(test)]
/// let _ = <UpgradeContext<C<'_, F>, F, NoRecord> as UpgradeToMalicious<Replicated<F>, _>>::upgrade;
/// let _ = <UpgradeContext<C<'_, F>, F, RecordId> as UpgradeToMalicious<Replicated<F>, _>>::upgrade;
/// #[cfg(test)]
/// let _ = <UpgradeContext<C<'_, F>, F, NoRecord> as UpgradeToMalicious<(Replicated<F>, Replicated<F>), _>>::upgrade;
/// let _ = <UpgradeContext<C<'_, F>, F, NoRecord> as UpgradeToMalicious<Vec<Replicated<F>>, _>>::upgrade;
/// let _ = <UpgradeContext<C<'_, F>, F, NoRecord> as UpgradeToMalicious<(Vec<Replicated<F>>, Vec<Replicated<F>>), _>>::upgrade;
/// ```
///
/// ```compile_fail
/// use ipa::protocol::{context::{UpgradeContext, UpgradeToMalicious, UpgradedMaliciousContext as C}, NoRecord, RecordId};
/// use ipa::ff::Fp32BitPrime as F;
/// use ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// // This can't be upgraded with a record-bound context because the record ID
/// // is used internally for vector indexing.
/// let _ = <UpgradeContext<C<'_, F>, F, RecordId> as UpgradeToMalicious<Vec<Replicated<F>>, _>>::upgrade;
/// ```
pub struct UpgradeContext<
    'a,
    C: UpgradedContext<F>,
    F: ExtendableField,
    B: RecordBinding = NoRecord,
> {
    ctx: C,
    record_binding: B,
    _lifetime: PhantomData<&'a F>,
}

impl<'a, C, F, B> UpgradeContext<'a, C, F, B>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    B: RecordBinding,
{
    pub fn new(ctx: C, record_binding: B) -> Self {
        Self {
            ctx,
            record_binding,
            _lifetime: PhantomData,
        }
    }

    fn narrow<SS: Substep>(&self, step: &SS) -> Self {
        Self::new(self.ctx.narrow(step), self.record_binding)
    }
}

#[async_trait]
pub trait UpgradeToMalicious<'a, T, M>
where
    T: Send,
{
    async fn upgrade(self, input: T) -> Result<M, Error>;
}

enum UpgradeTripleStep {
    V0,
    V1,
    V2,
}

impl crate::protocol::Substep for UpgradeTripleStep {}

impl AsRef<str> for UpgradeTripleStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::V0 => "upgrade_bit_triple0",
            Self::V1 => "upgrade_bit_triple1",
            Self::V2 => "upgrade_bit_triple2",
        }
    }
}

#[async_trait]
impl<'a, C, F>
    UpgradeToMalicious<'a, BitConversionTriple<Replicated<F>>, BitConversionTriple<C::Share>>
    for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
{
    async fn upgrade(
        self,
        input: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<C::Share>, Error> {
        let [v0, v1, v2] = input.0;
        let (t0, t1, t2) = try_join3(
            self.ctx.narrow(&UpgradeTripleStep::V0).upgrade_one(
                self.record_binding,
                v0,
                ZeroPositions::Pvzz,
            ),
            self.ctx.narrow(&UpgradeTripleStep::V1).upgrade_one(
                self.record_binding,
                v1,
                ZeroPositions::Pzvz,
            ),
            self.ctx.narrow(&UpgradeTripleStep::V2).upgrade_one(
                self.record_binding,
                v2,
                ZeroPositions::Pzzv,
            ),
        )
        .await?;
        Ok(BitConversionTriple([t0, t1, t2]))
    }
}

#[async_trait]
impl<'a, C, F> UpgradeToMalicious<'a, (), ()> for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
{
    async fn upgrade(self, _input: ()) -> Result<(), Error> {
        Ok(())
    }
}

#[async_trait]
impl<'a, C, F, T, TM, U, UM> UpgradeToMalicious<'a, (T, U), (TM, UM)>
    for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    T: Send + 'static,
    U: Send + 'static,
    TM: Send + Sized + 'static,
    UM: Send + Sized + 'static,
    for<'u> UpgradeContext<'u, C, F, NoRecord>:
        UpgradeToMalicious<'u, T, TM> + UpgradeToMalicious<'u, U, UM>,
{
    async fn upgrade(self, input: (T, U)) -> Result<(TM, UM), Error> {
        try_join(
            self.narrow(&BitOpStep::from(0)).upgrade(input.0),
            self.narrow(&BitOpStep::from(1)).upgrade(input.1),
        )
        .await
    }
}

enum Upgrade2DVectors {
    V(usize),
}
impl crate::protocol::Substep for Upgrade2DVectors {}

impl AsRef<str> for Upgrade2DVectors {
    fn as_ref(&self) -> &str {
        const COLUMN: [&str; 64] = repeat64str!["upgrade_2d"];

        match self {
            Self::V(i) => COLUMN[*i],
        }
    }
}

#[async_trait]
impl<'a, C, F, T, M> UpgradeToMalicious<'a, Vec<T>, Vec<M>> for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, T, M>,
{
    async fn upgrade(self, input: Vec<T>) -> Result<Vec<M>, Error> {
        let ctx = self.ctx.set_total_records(input.len());
        let ctx_ref = &ctx;
        ctx.try_join(input.into_iter().enumerate().map(|(i, share)| async move {
            // TODO: make it a bit more ergonomic to call with record id bound
            UpgradeContext::new(ctx_ref.clone(), RecordId::from(i))
                .upgrade(share)
                .await
        }))
        .await
    }
}

/// This function is not a generic implementation of 2D vector upgrade.
/// It assumes the inner vector is much smaller (e.g. multiple bits per record) than the outer vector (e.g. records)
/// Each inner vector element uses a different context and outer vector shares a context for the same inner vector index
#[async_trait]
impl<'a, C, F, T, M> UpgradeToMalicious<'a, Vec<Vec<T>>, Vec<Vec<M>>>
    for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, T, M>,
{
    /// # Panics
    /// Panics if input is empty
    async fn upgrade(self, input: Vec<Vec<T>>) -> Result<Vec<Vec<M>>, Error> {
        let num_records = input.len();
        let num_columns = input.first().map_or(1, Vec::len);
        assert_ne!(num_columns, 0);
        let ctx = self.ctx.set_total_records(num_records);
        let ctx_ref = &self.ctx;
        let all_ctx = (0..num_columns).map(|idx| ctx.narrow(&Upgrade2DVectors::V(idx)));

        ctx_ref
            .try_join(zip(repeat(all_ctx), input.into_iter()).enumerate().map(
                |(record_idx, (all_ctx, one_input))| async move {
                    // This inner join is truly concurrent.
                    ctx_ref
                        .parallel_join(zip(all_ctx, one_input).map(|(ctx, share)| async move {
                            UpgradeContext::new(ctx, RecordId::from(record_idx))
                                .upgrade(share)
                                .await
                        }))
                        .await
                },
            ))
            .await
    }
}

#[async_trait]
impl<'a, C, F> UpgradeToMalicious<'a, Replicated<F>, C::Share>
    for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
{
    async fn upgrade(self, input: Replicated<F>) -> Result<C::Share, Error> {
        self.ctx
            .upgrade_one(self.record_binding, input, ZeroPositions::Pvvv)
            .await
    }
}
pub struct IPAModulusConvertedInputRowWrapper<F: Field, T: LinearSecretSharing<F>> {
    pub timestamp: T,
    pub is_trigger_bit: T,
    pub trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: LinearSecretSharing<F>> IPAModulusConvertedInputRowWrapper<F, T> {
    pub fn new(timestamp: T, is_trigger_bit: T, trigger_value: T) -> Self {
        Self {
            timestamp,
            is_trigger_bit,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

enum UpgradeModConvStep {
    V1,
    V2,
    V3,
}

impl crate::protocol::Substep for UpgradeModConvStep {}

impl AsRef<str> for UpgradeModConvStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::V1 => "upgrade_mod_conv1",
            Self::V2 => "upgrade_mod_conv2",
            Self::V3 => "upgrade_mod_conv3",
        }
    }
}

#[async_trait]
impl<'a, C, F>
    UpgradeToMalicious<
        'a,
        IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
        IPAModulusConvertedInputRowWrapper<F, C::Share>,
    > for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F>,
    F: ExtendableField,
{
    async fn upgrade(
        self,
        input: IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
    ) -> Result<IPAModulusConvertedInputRowWrapper<F, C::Share>, Error> {
        let (is_trigger_bit, trigger_value, timestamp) = try_join3(
            self.ctx.narrow(&UpgradeModConvStep::V1).upgrade_one(
                self.record_binding,
                input.is_trigger_bit,
                ZeroPositions::Pvvv,
            ),
            self.ctx.narrow(&UpgradeModConvStep::V2).upgrade_one(
                self.record_binding,
                input.trigger_value,
                ZeroPositions::Pvvv,
            ),
            self.ctx.narrow(&UpgradeModConvStep::V3).upgrade_one(
                self.record_binding,
                input.timestamp,
                ZeroPositions::Pvvv,
            ),
        )
        .await?;

        Ok(IPAModulusConvertedInputRowWrapper::new(
            timestamp,
            is_trigger_bit,
            trigger_value,
        ))
    }
}
enum UpgradeMCCappedCreditsWithAggregationBit {
    V0(usize),
    V1,
    V2,
    V3,
}

impl crate::protocol::Substep for UpgradeMCCappedCreditsWithAggregationBit {}

impl AsRef<str> for UpgradeMCCappedCreditsWithAggregationBit {
    fn as_ref(&self) -> &str {
        const UPGRADE_AGGREGATION_BIT0: [&str; 64] = repeat64str!["upgrade_aggregation_bit0"];

        match self {
            Self::V0(i) => UPGRADE_AGGREGATION_BIT0[*i],
            Self::V1 => "upgrade_aggregation_bit1",
            Self::V2 => "upgrade_aggregation_bit2",
            Self::V3 => "upgrade_aggregation_bit3",
        }
    }
}

#[async_trait]
impl<'a, C, F>
    UpgradeToMalicious<
        'a,
        MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
        MCCappedCreditsWithAggregationBit<F, C::Share>,
    > for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F>,
    F: ExtendableField,
{
    async fn upgrade(
        self,
        input: MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
    ) -> Result<MCCappedCreditsWithAggregationBit<F, C::Share>, Error> {
        let ctx_ref = &self.ctx;
        let breakdown_key = ctx_ref
            .parallel_join(input.breakdown_key.into_iter().enumerate().map(
                |(idx, bit)| async move {
                    ctx_ref
                        .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V0(idx))
                        .upgrade_one(self.record_binding, bit, ZeroPositions::Pvvv)
                        .await
                },
            ))
            .await?;

        let helper_bit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V1)
            .upgrade_one(self.record_binding, input.helper_bit, ZeroPositions::Pvvv)
            .await?;

        let aggregation_bit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V2)
            .upgrade_one(
                self.record_binding,
                input.aggregation_bit,
                ZeroPositions::Pvvv,
            )
            .await?;

        let credit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V3)
            .upgrade_one(self.record_binding, input.credit, ZeroPositions::Pvvv)
            .await?;
        Ok(MCCappedCreditsWithAggregationBit::new(
            helper_bit,
            aggregation_bit,
            breakdown_key,
            credit,
        ))
    }
}

// Impl for upgrading things that can be upgraded using a single record ID using a non-record-bound
// context. This is only used for tests where the protocol takes a single `Replicated<F>` input.
#[cfg(test)]
#[async_trait]
impl<'a, C, F, T, M> UpgradeToMalicious<'a, T, M> for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    T: Send + 'static,
    M: 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, T, M>,
{
    async fn upgrade(self, input: T) -> Result<M, Error> {
        let ctx = if self.ctx.total_records().is_unspecified() {
            self.ctx.set_total_records(1)
        } else {
            self.ctx
        };
        UpgradeContext::new(ctx, RecordId::FIRST)
            .upgrade(input)
            .await
    }
}

// This could also work on a record-bound context, but it's only used in one place for tests where
// that's not currently required.
#[cfg(test)]
impl<'a, C: UpgradedContext<F>, F: ExtendableField> UpgradeContext<'a, C, F, NoRecord> {
    pub(super) async fn upgrade_sparse(
        self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<C::Share, Error> {
        self.ctx
            .upgrade_one(RecordId::from(0u32), input, zeros_at)
            .await
    }
}
