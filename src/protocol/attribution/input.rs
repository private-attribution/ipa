use std::marker::PhantomData;

use crate::bits::BitArray;
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::context::Context;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::replicated::malicious::{
    AdditiveShare as MaliciousReplicated, DowngradeMalicious,
    ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
};
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
use crate::secret_sharing::replicated::semi_honest::{AdditiveShare, XorShare};
use crate::secret_sharing::Arithmetic;
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};

//
// `accumulate_credit` protocol
//
#[derive(Debug)]
pub struct AccumulateCreditInputRow<F: Field, BK: BitArray> {
    pub is_trigger_report: AdditiveShare<F>,
    pub helper_bit: AdditiveShare<F>,
    pub breakdown_key: XorShare<BK>,
    pub trigger_value: AdditiveShare<F>,
}

#[derive(Debug)]
pub struct MCAccumulateCreditInputRow<F: Field, T: Arithmetic<F>> {
    pub is_trigger_report: T,
    pub helper_bit: T,
    pub breakdown_key: Vec<T>,
    pub trigger_value: T,
    pub _marker: PhantomData<F>,
}

pub type MCAccumulateCreditOutputRow<F, T> = MCAccumulateCreditInputRow<F, T>;

//
// `credit_capping` protocol
//
pub type CreditCappingInputRow<F, BK> = AccumulateCreditInputRow<F, BK>;
pub type MCCreditCappingInputRow<F, T> = MCAccumulateCreditInputRow<F, T>;

#[derive(Debug)]
pub struct MCCreditCappingOutputRow<F: Field, T: Arithmetic<F>> {
    pub breakdown_key: Vec<T>,
    pub credit: T,
    pub _marker: PhantomData<F>,
}

#[async_trait]
impl<F: Field> DowngradeMalicious for MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>> {
    type Target = MCCappedCreditsWithAggregationBit<F, Replicated<F>>;
    /// For ShuffledPermutationWrapper on downgrading, we return revealed permutation. This runs reveal on the malicious context
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        // Note that this clones the values rather than moving them.
        // This code is only used in test code, so that's probably OK.
        UnauthorizedDowngradeWrapper::new(Self::Target {
            helper_bit: self.helper_bit.x().access_without_downgrade().clone(),
            aggregation_bit: self.aggregation_bit.x().access_without_downgrade().clone(),
            breakdown_key: self
                .breakdown_key
                .into_iter()
                .map(|bk| bk.x().access_without_downgrade().clone())
                .collect::<Vec<_>>(),
            credit: self.credit.x().access_without_downgrade().clone(),
            _marker: PhantomData::default(),
        })
    }
}
// }
//
// `aggregate_credit` protocol
//

#[derive(Debug)]
pub struct AggregateCreditInputRow<F: Field, BK: BitArray> {
    pub breakdown_key: XorShare<BK>,
    pub credit: AdditiveShare<F>,
}

pub type MCAggregateCreditInputRow<F, T> = MCCreditCappingOutputRow<F, T>;

#[derive(Debug)]
pub struct MCCappedCreditsWithAggregationBit<F: Field, T: Arithmetic<F>> {
    pub helper_bit: T,
    pub aggregation_bit: T,
    pub breakdown_key: Vec<T>,
    pub credit: T,
    pub _marker: PhantomData<F>,
}

#[derive(Debug)]
pub struct MCAggregateCreditOutputRow<F: Field, T: Arithmetic<F>> {
    pub breakdown_key: Vec<T>,
    pub credit: T,
    pub _marker: PhantomData<F>,
}

#[async_trait]
impl<F: Field, T: Arithmetic<F>> Resharable<F> for MCAccumulateCreditInputRow<F, T> {
    type Share = T;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_trigger_bit = ctx
            .narrow(&AttributionResharableStep::IsTriggerReport)
            .reshare(&self.is_trigger_report, record_id, to_helper);
        let f_helper_bit = ctx.narrow(&AttributionResharableStep::HelperBit).reshare(
            &self.helper_bit,
            record_id,
            to_helper,
        );
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&AttributionResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_value = ctx
            .narrow(&AttributionResharableStep::TriggerValue)
            .reshare(&self.trigger_value, record_id, to_helper);

        let (breakdown_key, mut fields) = try_join(
            f_breakdown_key,
            try_join_all([f_trigger_bit, f_helper_bit, f_value]),
        )
        .await?;

        Ok(MCAccumulateCreditInputRow {
            breakdown_key,
            is_trigger_report: fields.remove(0),
            helper_bit: fields.remove(0),
            trigger_value: fields.remove(0),
            _marker: PhantomData::default(),
        })
    }
}

#[async_trait]
impl<F: Field + Sized, T: Arithmetic<F>> Resharable<F> for MCCappedCreditsWithAggregationBit<F, T> {
    type Share = T;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_helper_bit = ctx.narrow(&AttributionResharableStep::HelperBit).reshare(
            &self.helper_bit,
            record_id,
            to_helper,
        );
        let f_aggregation_bit = ctx
            .narrow(&AttributionResharableStep::AggregationBit)
            .reshare(&self.aggregation_bit, record_id, to_helper);
        let f_breakdown_key = self.breakdown_key.reshare(
            ctx.narrow(&AttributionResharableStep::BreakdownKey),
            record_id,
            to_helper,
        );
        let f_value = ctx
            .narrow(&AttributionResharableStep::TriggerValue)
            .reshare(&self.credit, record_id, to_helper);

        let (breakdown_key, mut fields) = try_join(
            f_breakdown_key,
            try_join_all([f_aggregation_bit, f_helper_bit, f_value]),
        )
        .await?;

        Ok(MCCappedCreditsWithAggregationBit {
            breakdown_key,
            helper_bit: fields.remove(0),
            aggregation_bit: fields.remove(0),
            credit: fields.remove(0),
            _marker: PhantomData::default(),
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttributionResharableStep {
    IsTriggerReport,
    HelperBit,
    BreakdownKey,
    TriggerValue,
    AggregationBit,
}

impl Substep for AttributionResharableStep {}

impl AsRef<str> for AttributionResharableStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::IsTriggerReport => "is_trigger_report",
            Self::HelperBit => "helper_bit",
            Self::BreakdownKey => "breakdown_key",
            Self::TriggerValue => "trigger_value",
            Self::AggregationBit => "aggregation_bit",
        }
    }
}
