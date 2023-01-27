use crate::bits::BitArray;
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::context::Context;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::replicated::semi_honest::{AdditiveShare, XorShare};
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
pub struct MCAccumulateCreditInputRow<F: Field> {
    pub is_trigger_report: AdditiveShare<F>,
    pub helper_bit: AdditiveShare<F>,
    pub breakdown_key: Vec<AdditiveShare<F>>,
    pub trigger_value: AdditiveShare<F>,
}

pub type MCAccumulateCreditOutputRow<F> = MCAccumulateCreditInputRow<F>;

//
// `credit_capping` protocol
//
pub type CreditCappingInputRow<F, BK> = AccumulateCreditInputRow<F, BK>;
pub type MCCreditCappingInputRow<F> = MCAccumulateCreditInputRow<F>;

#[derive(Debug)]
pub struct MCCreditCappingOutputRow<F: Field> {
    pub breakdown_key: Vec<AdditiveShare<F>>,
    pub credit: AdditiveShare<F>,
}

//
// `aggregate_credit` protocol
//

#[derive(Debug)]
pub struct AggregateCreditInputRow<F: Field, BK: BitArray> {
    pub breakdown_key: XorShare<BK>,
    pub credit: AdditiveShare<F>,
}

pub type MCAggregateCreditInputRow<F> = MCCreditCappingOutputRow<F>;

#[derive(Debug)]
pub struct MCCappedCreditsWithAggregationBit<F: Field> {
    pub helper_bit: AdditiveShare<F>,
    pub aggregation_bit: AdditiveShare<F>,
    pub breakdown_key: Vec<AdditiveShare<F>>,
    pub credit: AdditiveShare<F>,
}

#[derive(Debug)]
pub struct MCAggregateCreditOutputRow<F: Field> {
    pub breakdown_key: Vec<AdditiveShare<F>>,
    pub credit: AdditiveShare<F>,
}

#[async_trait]
impl<F: Field> Resharable<F> for MCAccumulateCreditInputRow<F> {
    type Share = AdditiveShare<F>;

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
        })
    }
}

#[async_trait]
impl<F: Field + Sized> Resharable<F> for MCCappedCreditsWithAggregationBit<F> {
    type Share = AdditiveShare<F>;

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
