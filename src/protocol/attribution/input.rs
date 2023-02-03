use crate::bits::{BitArray, Serializable};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::context::Context;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::replicated::semi_honest::{AdditiveShare, XorShare};
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use generic_array::GenericArray;
use std::marker::PhantomData;
use typenum::Unsigned;

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
// TODO: `breakdown_key`'s length == `<BK as BitArray>::BITS`.
//       instead of having a `Vec`, we can probably use an array since the length is known at compile time
pub struct MCAggregateCreditOutputRow<F: Field, BK: BitArray> {
    pub breakdown_key: Vec<AdditiveShare<F>>,
    pub credit: AdditiveShare<F>,
    _phantom: PhantomData<BK>,
}

impl<F: Field, BK: BitArray> MCAggregateCreditOutputRow<F, BK>
where
    AdditiveShare<F>: Serializable,
{
    pub const SIZE: usize =
        (BK::BITS as usize + 1) * <AdditiveShare<F> as Serializable>::Size::USIZE;

    pub fn new(breakdown_key: Vec<AdditiveShare<F>>, credit: AdditiveShare<F>) -> Self {
        Self {
            breakdown_key,
            credit,
            _phantom: Default::default(),
        }
    }

    pub fn serialize(self) -> Vec<u8> {
        assert_eq!(self.breakdown_key.len(), BK::BITS as usize);

        let breakdown_key_len =
            self.breakdown_key.len() * <AdditiveShare<F> as Serializable>::Size::USIZE;
        let mut buf =
            vec![0u8; breakdown_key_len + <AdditiveShare<F> as Serializable>::Size::USIZE];
        for (i, key_part) in self.breakdown_key.into_iter().enumerate() {
            key_part.serialize(GenericArray::from_mut_slice(
                &mut buf[<AdditiveShare<F> as Serializable>::Size::USIZE * i
                    ..<AdditiveShare<F> as Serializable>::Size::USIZE * (i + 1)],
            ));
        }
        self.credit.serialize(GenericArray::from_mut_slice(
            &mut buf[breakdown_key_len
                ..breakdown_key_len + <AdditiveShare<F> as Serializable>::Size::USIZE],
        ));
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), Self::SIZE);
        let mut breakdown_key = Vec::with_capacity(BK::BITS as usize);
        for i in 0..BK::BITS as usize {
            breakdown_key.push(<AdditiveShare<F> as Serializable>::deserialize(
                GenericArray::clone_from_slice(
                    &buf[<AdditiveShare<F> as Serializable>::Size::USIZE * i
                        ..<AdditiveShare<F> as Serializable>::Size::USIZE * (i + 1)],
                ),
            ));
        }
        let credit =
            <AdditiveShare<F> as Serializable>::deserialize(GenericArray::clone_from_slice(
                &buf[<AdditiveShare<F> as Serializable>::Size::USIZE * BK::BITS as usize..],
            ));
        Self::new(breakdown_key, credit)
    }

    pub fn from_byte_slice(from: &[u8]) -> impl Iterator<Item = Self> + '_ {
        debug_assert!(from.len() % Self::SIZE == 0);

        from.chunks((BK::BITS as usize + 1) * <AdditiveShare<F> as Serializable>::Size::USIZE)
            .map(|chunk| Self::deserialize(chunk))
    }
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
