use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, Serializable},
    helpers::Role,
    protocol::{basics::Reshare, context::Context, RecordId},
    secret_sharing::{
        replicated::{
            malicious::{
                AdditiveShare as MaliciousReplicated, DowngradeMalicious, ExtendableField,
                ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
            },
            semi_honest::{AdditiveShare as Replicated, AdditiveShare},
        },
        BitDecomposed, Linear as LinearSecretSharing,
    },
};
use async_trait::async_trait;
use futures::future::{try_join, try_join4};
use generic_array::GenericArray;
use ipa_macros::step;
use std::marker::PhantomData;
use strum::AsRefStr;
use typenum::Unsigned;

//
// `apply_attribution_window` protocol
//
#[derive(Debug)]
pub struct ApplyAttributionWindowInputRow<F: Field, BK: GaloisField> {
    pub timestamp: AdditiveShare<F>,
    pub is_trigger_report: AdditiveShare<F>,
    pub helper_bit: AdditiveShare<F>,
    pub breakdown_key: AdditiveShare<BK>,
    pub trigger_value: AdditiveShare<F>,
}

#[derive(Debug)]
pub struct MCApplyAttributionWindowInputRow<F: Field, S: LinearSecretSharing<F>> {
    pub timestamp: S,
    pub is_trigger_report: S,
    pub helper_bit: S,
    pub breakdown_key: BitDecomposed<Replicated<Gf2>>,
    pub trigger_value: S,
    _marker: PhantomData<F>,
}

impl<F: Field, S: LinearSecretSharing<F>> MCApplyAttributionWindowInputRow<F, S> {
    pub fn new(
        timestamp: S,
        is_trigger_report: S,
        helper_bit: S,
        breakdown_key: BitDecomposed<Replicated<Gf2>>,
        trigger_value: S,
    ) -> Self {
        Self {
            timestamp,
            is_trigger_report,
            helper_bit,
            breakdown_key,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

pub type MCApplyAttributionWindowOutputRow<F, S> = MCAccumulateCreditInputRow<F, S>;

//
// `accumulate_credit` protocol
//

pub struct AccumulateCreditInputRow<F: Field, BK: GaloisField> {
    pub is_trigger_report: AdditiveShare<F>,
    pub helper_bit: AdditiveShare<F>,
    pub active_bit: AdditiveShare<F>,
    pub breakdown_key: AdditiveShare<BK>,
    pub trigger_value: AdditiveShare<F>,
}

#[derive(Debug)]
pub struct MCAccumulateCreditInputRow<F: Field, S: LinearSecretSharing<F>> {
    pub is_trigger_report: S,
    pub helper_bit: S,
    pub active_bit: S,
    pub breakdown_key: BitDecomposed<Replicated<Gf2>>,
    pub trigger_value: S,
    _marker: PhantomData<F>,
}

impl<F: Field, S: LinearSecretSharing<F>> MCAccumulateCreditInputRow<F, S> {
    pub fn new(
        is_trigger_report: S,
        helper_bit: S,
        active_bit: S,
        breakdown_key: BitDecomposed<Replicated<Gf2>>,
        trigger_value: S,
    ) -> Self {
        Self {
            is_trigger_report,
            helper_bit,
            active_bit,
            breakdown_key,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

pub type AccumulateCreditOutputRow<F, BK> = CreditCappingInputRow<F, BK>;
pub type MCAccumulateCreditOutputRow<F, T> = MCCreditCappingInputRow<F, T>;

//
// `credit_capping` protocol
//
pub struct CreditCappingInputRow<F: Field, BK: GaloisField> {
    pub is_trigger_report: AdditiveShare<F>,
    pub helper_bit: AdditiveShare<F>,
    pub breakdown_key: AdditiveShare<BK>,
    pub trigger_value: AdditiveShare<F>,
}

#[derive(Debug)]
pub struct MCCreditCappingInputRow<F: Field, T: LinearSecretSharing<F>> {
    pub is_trigger_report: T,
    pub helper_bit: T,
    pub breakdown_key: BitDecomposed<Replicated<Gf2>>,
    pub trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: LinearSecretSharing<F>> MCCreditCappingInputRow<F, T> {
    pub fn new(
        is_trigger_report: T,
        helper_bit: T,
        breakdown_key: BitDecomposed<Replicated<Gf2>>,
        trigger_value: T,
    ) -> Self {
        Self {
            is_trigger_report,
            helper_bit,
            breakdown_key,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct MCCreditCappingOutputRow<F: Field, T: LinearSecretSharing<F>> {
    pub breakdown_key: BitDecomposed<Replicated<Gf2>>,
    pub credit: T,
    _marker: PhantomData<F>,
}
impl<F: Field, T: LinearSecretSharing<F>> MCCreditCappingOutputRow<F, T> {
    pub fn new(breakdown_key: BitDecomposed<Replicated<Gf2>>, credit: T) -> Self {
        Self {
            breakdown_key,
            credit,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<F: ExtendableField, BK: GaloisField> DowngradeMalicious
    for MCAggregateCreditOutputRow<F, MaliciousReplicated<F>, BK>
where
    Replicated<F>: Serializable,
{
    type Target = MCAggregateCreditOutputRow<F, Replicated<F>, BK>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let Self {
            breakdown_key,
            credit,
            ..
        } = self;
        UnauthorizedDowngradeWrapper::new(Self::Target::new(
            breakdown_key.map(|bk| bk.downgrade().access_without_downgrade()),
            credit.downgrade().access_without_downgrade(),
        ))
    }
}

#[async_trait]
impl<F: ExtendableField, BK: GaloisField> DowngradeMalicious
    for MCAggregateCreditOutputRow<F, Replicated<F>, BK>
{
    type Target = MCAggregateCreditOutputRow<F, Replicated<F>, BK>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper::new(self)
    }
}

//
// `aggregate_credit` protocol
//

#[derive(Debug)]
pub struct AggregateCreditInputRow<F: Field, BK: GaloisField> {
    pub breakdown_key: AdditiveShare<BK>,
    pub credit: AdditiveShare<F>,
}

pub type MCAggregateCreditInputRow<F, T> = MCCreditCappingOutputRow<F, T>;

#[derive(Debug)]
// TODO: `breakdown_key`'s length == `<BK as BitArray>::BITS`.
//       instead of having a `Vec`, we can probably use an array since the length is known at compile time
pub struct MCAggregateCreditOutputRow<F, T, BK> {
    pub breakdown_key: BitDecomposed<T>,
    pub credit: T,
    _marker: PhantomData<(F, BK)>,
}

impl<F, T, BK> MCAggregateCreditOutputRow<F, T, BK>
where
    F: Field,
    T: LinearSecretSharing<F> + Serializable,
    BK: GaloisField,
{
    /// We know there will be exactly `BK::BITS` number of `breakdown_key` parts
    pub const SIZE: usize = (BK::BITS as usize + 1) * <T as Serializable>::Size::USIZE;

    pub fn new(breakdown_key: BitDecomposed<T>, credit: T) -> Self {
        Self {
            breakdown_key,
            credit,
            _marker: PhantomData,
        }
    }

    /// writes the bytes of `MCAggregateCreditOutputRow` into the `buf`.
    /// # Panics
    /// if `breakdown_key` has unexpected length.
    /// if `buf` is not the right length
    pub fn serialize(self, buf: &mut [u8]) {
        assert_eq!(self.breakdown_key.len(), BK::BITS as usize);
        assert_eq!(buf.len(), Self::SIZE);

        let breakdown_key_size = self.breakdown_key.len() * <T as Serializable>::Size::USIZE;

        for (i, key_part) in self.breakdown_key.into_iter().enumerate() {
            key_part.serialize(GenericArray::from_mut_slice(
                &mut buf[<T as Serializable>::Size::USIZE * i
                    ..<T as Serializable>::Size::USIZE * (i + 1)],
            ));
        }
        self.credit.serialize(GenericArray::from_mut_slice(
            &mut buf[breakdown_key_size..breakdown_key_size + <T as Serializable>::Size::USIZE],
        ));
    }

    /// reads the bytes from `buf` into a `MCAggregateCreditOutputRow`
    /// # Panics
    /// if the `buf` is not exactly the right size
    #[must_use]
    pub fn deserialize(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), Self::SIZE);
        let breakdown_key = BitDecomposed::decompose(BK::BITS, |i| {
            let i = i as usize;
            <T as Serializable>::deserialize(GenericArray::from_slice(
                &buf[<T as Serializable>::Size::USIZE * i
                    ..<T as Serializable>::Size::USIZE * (i + 1)],
            ))
        });
        let credit = <T as Serializable>::deserialize(GenericArray::from_slice(
            &buf[<T as Serializable>::Size::USIZE * BK::BITS as usize..],
        ));
        Self::new(breakdown_key, credit)
    }

    pub fn from_byte_slice(from: &[u8]) -> impl Iterator<Item = Self> + '_ {
        debug_assert!(from.len() % Self::SIZE == 0);

        from.chunks((BK::BITS as usize + 1) * <T as Serializable>::Size::USIZE)
            .map(|chunk| Self::deserialize(chunk))
    }
}

#[async_trait]
impl<F, T, C> Reshare<C, RecordId> for MCAccumulateCreditInputRow<F, T>
where
    F: Field,
    T: LinearSecretSharing<F> + Reshare<C, RecordId>,
    C: Context,
{
    async fn reshare<'fut>(
        &self,
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
    where
        C: 'fut,
    {
        let f_trigger_bit = self.is_trigger_report.reshare(
            ctx.narrow(&AttributionResharableStep::IsTriggerReport),
            record_id,
            to_helper,
        );
        let f_helper_bit = self.helper_bit.reshare(
            ctx.narrow(&AttributionResharableStep::HelperBit),
            record_id,
            to_helper,
        );
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&AttributionResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_value = self.trigger_value.reshare(
            ctx.narrow(&AttributionResharableStep::TriggerValue),
            record_id,
            to_helper,
        );
        let f_active_bit = self.active_bit.reshare(
            ctx.narrow(&AttributionResharableStep::ActiveBit),
            record_id,
            to_helper,
        );

        let (breakdown_key, (is_trigger_report, helper_bit, trigger_value, active_bit)) = try_join(
            f_breakdown_key,
            try_join4(f_trigger_bit, f_helper_bit, f_value, f_active_bit),
        )
        .await?;

        Ok(MCAccumulateCreditInputRow::new(
            is_trigger_report,
            helper_bit,
            active_bit,
            breakdown_key,
            trigger_value,
        ))
    }
}

#[step]
pub(crate) enum AttributionResharableStep {
    IsTriggerReport,
    HelperBit,
    BreakdownKey,
    TriggerValue,
    ActiveBit,
}
