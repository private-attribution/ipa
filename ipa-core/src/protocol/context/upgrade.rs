use std::marker::PhantomData;

use async_trait::async_trait;
use futures::future::{try_join, try_join3};
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::ZeroPositions,
        context::UpgradedContext,
        ipa::ArithmeticallySharedIPAInputs,
        modulus_conversion::BitConversionTriple,
        step::{BitOpStep, Gate, Step, StepNarrow},
        NoRecord, RecordBinding, RecordId,
    },
    secret_sharing::{
        replicated::{malicious::ExtendableField, semi_honest::AdditiveShare as Replicated},
        BitDecomposed, Linear as LinearSecretSharing,
    },
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

    fn narrow<SS: Step>(&self, step: &SS) -> Self
    where
        Gate: StepNarrow<SS>,
    {
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

#[derive(Step)]
pub(crate) enum UpgradeTripleStep {
    UpgradeBitTriple0,
    UpgradeBitTriple1,
    UpgradeBitTriple2,
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
            self.ctx
                .narrow(&UpgradeTripleStep::UpgradeBitTriple0)
                .upgrade_one(self.record_binding, v0, ZeroPositions::Pvzz),
            self.ctx
                .narrow(&UpgradeTripleStep::UpgradeBitTriple1)
                .upgrade_one(self.record_binding, v1, ZeroPositions::Pzvz),
            self.ctx
                .narrow(&UpgradeTripleStep::UpgradeBitTriple2)
                .upgrade_one(self.record_binding, v2, ZeroPositions::Pzzv),
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

#[derive(Step)]
pub(crate) enum Upgrade2DVectors {
    #[dynamic(64)]
    Upgrade2d(usize),
}

#[async_trait]
impl<'a, C, F, I, M> UpgradeToMalicious<'a, I, Vec<M>> for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    I: IntoIterator + Send + 'static,
    I::IntoIter: ExactSizeIterator + Send,
    I::Item: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, I::Item, M>,
{
    async fn upgrade(self, input: I) -> Result<Vec<M>, Error> {
        let iter = input.into_iter();
        let ctx = self.ctx.set_total_records(iter.len());
        let ctx_ref = &ctx;
        ctx.try_join(iter.enumerate().map(|(i, share)| async move {
            // TODO: make it a bit more ergonomic to call with record id bound
            UpgradeContext::new(ctx_ref.clone(), RecordId::from(i))
                .upgrade(share)
                .await
        }))
        .await
    }
}

#[async_trait]
impl<'a, C, F, T, M> UpgradeToMalicious<'a, BitDecomposed<T>, BitDecomposed<M>>
    for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, T, M>,
{
    async fn upgrade(self, input: BitDecomposed<T>) -> Result<BitDecomposed<M>, Error> {
        let ctx_ref = &self.ctx;
        let record_id = self.record_binding;
        BitDecomposed::try_from(
            self.ctx
                .parallel_join(input.into_iter().enumerate().map(|(i, share)| async move {
                    UpgradeContext::new(ctx_ref.narrow(&Upgrade2DVectors::Upgrade2d(i)), record_id)
                        .upgrade(share)
                        .await
                }))
                .await?,
        )
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

#[derive(Step)]
pub(crate) enum UpgradeModConvStep {
    UpgradeModConv1,
    UpgradeModConv2,
    UpgradeModConv3,
}

#[async_trait]
impl<'a, C, F>
    UpgradeToMalicious<
        'a,
        ArithmeticallySharedIPAInputs<F, Replicated<F>>,
        ArithmeticallySharedIPAInputs<F, C::Share>,
    > for UpgradeContext<'a, C, F, RecordId>
where
    C: UpgradedContext<F>,
    C::Share: LinearSecretSharing<F>,
    F: ExtendableField,
{
    async fn upgrade(
        self,
        input: ArithmeticallySharedIPAInputs<F, Replicated<F>>,
    ) -> Result<ArithmeticallySharedIPAInputs<F, C::Share>, Error> {
        let (is_trigger_bit, trigger_value, timestamp) = try_join3(
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv1)
                .upgrade_one(
                    self.record_binding,
                    input.is_trigger_bit,
                    ZeroPositions::Pvvv,
                ),
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv2)
                .upgrade_one(
                    self.record_binding,
                    input.trigger_value,
                    ZeroPositions::Pvvv,
                ),
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv3)
                .upgrade_one(self.record_binding, input.timestamp, ZeroPositions::Pvvv),
        )
        .await?;

        Ok(ArithmeticallySharedIPAInputs::new(
            timestamp,
            is_trigger_bit,
            trigger_value,
        ))
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
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv1)
                .upgrade_one(
                    self.record_binding,
                    input.is_trigger_bit,
                    ZeroPositions::Pvvv,
                ),
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv2)
                .upgrade_one(
                    self.record_binding,
                    input.trigger_value,
                    ZeroPositions::Pvvv,
                ),
            self.ctx
                .narrow(&UpgradeModConvStep::UpgradeModConv3)
                .upgrade_one(self.record_binding, input.timestamp, ZeroPositions::Pvvv),
        )
        .await?;

        Ok(IPAModulusConvertedInputRowWrapper::new(
            timestamp,
            is_trigger_bit,
            trigger_value,
        ))
    }
}

// Impl to upgrade a single `Replicated<F>` using a non-record-bound context. Used for tests.
#[cfg(test)]
#[async_trait]
impl<'a, C, F, M> UpgradeToMalicious<'a, Replicated<F>, M> for UpgradeContext<'a, C, F, NoRecord>
where
    C: UpgradedContext<F>,
    F: ExtendableField,
    M: 'static,
    for<'u> UpgradeContext<'u, C, F, RecordId>: UpgradeToMalicious<'u, Replicated<F>, M>,
{
    async fn upgrade(self, input: Replicated<F>) -> Result<M, Error> {
        let ctx = if self.ctx.total_records().is_specified() {
            self.ctx
        } else {
            self.ctx.set_total_records(1)
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
