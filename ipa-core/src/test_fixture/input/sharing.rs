use super::{GenericReportShare, GenericReportTestInput};
use crate::{
    ff::{Field, GaloisField, PrimeField, Serializable},
    protocol::{
        attribution::input::{
            AccumulateCreditInputRow, AggregateCreditInputRow, ApplyAttributionWindowInputRow,
            CreditCappingInputRow, MCAccumulateCreditInputRow, MCAggregateCreditOutputRow,
        },
        ipa::IPAInputRow,
        BreakdownKey, MatchKey,
    },
    rand::Rng,
    report::{EventType, Report},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::{ipa::TestRawDataRecord, Reconstruct},
};
use rand::{distributions::Standard, prelude::Distribution};
use std::iter::zip;

impl<F, MK, BK> IntoShares<GenericReportShare<F, MK, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [GenericReportShare<F, MK, BK>; 3] {
        let optional_field_values = [
            self.attribution_constraint_id,
            self.timestamp,
            self.is_trigger_report,
            self.helper_bit,
            self.aggregation_bit,
            self.active_bit,
        ];
        let optional_field_shares = optional_field_values.map(|v| match v {
            Some(x) => x.share_with(rng).map(Some),
            None => [None, None, None],
        });

        let [mk0, mk1, mk2] = match self.match_key {
            Some(mk) => MK::truncate_from(mk.as_u128()).share_with(rng).map(Some),
            None => [None, None, None],
        };
        let [bk0, bk1, bk2] = BK::truncate_from(self.breakdown_key.as_u128()).share_with(rng);
        let [tv0, tv1, tv2] = self.trigger_value.share_with(rng);

        [
            GenericReportShare {
                match_key: mk0,
                breakdown_key: bk0,
                trigger_value: tv0,
                attribution_constraint_id: optional_field_shares[0][0].clone(),
                timestamp: optional_field_shares[1][0].clone(),
                is_trigger_report: optional_field_shares[2][0].clone(),
                helper_bit: optional_field_shares[3][0].clone(),
                aggregation_bit: optional_field_shares[4][0].clone(),
                active_bit: optional_field_shares[5][0].clone(),
            },
            GenericReportShare {
                match_key: mk1,
                breakdown_key: bk1,
                trigger_value: tv1,
                attribution_constraint_id: optional_field_shares[0][1].clone(),
                timestamp: optional_field_shares[1][1].clone(),
                is_trigger_report: optional_field_shares[2][1].clone(),
                helper_bit: optional_field_shares[3][1].clone(),
                aggregation_bit: optional_field_shares[4][1].clone(),
                active_bit: optional_field_shares[5][1].clone(),
            },
            GenericReportShare {
                match_key: mk2,
                breakdown_key: bk2,
                trigger_value: tv2,
                attribution_constraint_id: optional_field_shares[0][2].clone(),
                timestamp: optional_field_shares[1][2].clone(),
                is_trigger_report: optional_field_shares[2][2].clone(),
                helper_bit: optional_field_shares[3][2].clone(),
                aggregation_bit: optional_field_shares[4][2].clone(),
                active_bit: optional_field_shares[5][2].clone(),
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<ApplyAttributionWindowInputRow<F, BK>>
    for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [ApplyAttributionWindowInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            ApplyAttributionWindowInputRow {
                timestamp: s0.timestamp.unwrap(),
                is_trigger_report: s0.is_trigger_report.unwrap(),
                helper_bit: s0.helper_bit.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            ApplyAttributionWindowInputRow {
                timestamp: s1.timestamp.unwrap(),
                is_trigger_report: s1.is_trigger_report.unwrap(),
                helper_bit: s1.helper_bit.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            ApplyAttributionWindowInputRow {
                timestamp: s2.timestamp.unwrap(),
                is_trigger_report: s2.is_trigger_report.unwrap(),
                helper_bit: s2.helper_bit.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<AccumulateCreditInputRow<F, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AccumulateCreditInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            AccumulateCreditInputRow {
                is_trigger_report: s0.is_trigger_report.unwrap(),
                helper_bit: s0.helper_bit.unwrap(),
                active_bit: s0.active_bit.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            AccumulateCreditInputRow {
                is_trigger_report: s1.is_trigger_report.unwrap(),
                helper_bit: s1.helper_bit.unwrap(),
                active_bit: s1.active_bit.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            AccumulateCreditInputRow {
                is_trigger_report: s2.is_trigger_report.unwrap(),
                helper_bit: s2.helper_bit.unwrap(),
                active_bit: s2.active_bit.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<CreditCappingInputRow<F, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [CreditCappingInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            CreditCappingInputRow {
                is_trigger_report: s0.is_trigger_report.unwrap(),
                helper_bit: s0.helper_bit.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            CreditCappingInputRow {
                is_trigger_report: s1.is_trigger_report.unwrap(),
                helper_bit: s1.helper_bit.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            CreditCappingInputRow {
                is_trigger_report: s2.is_trigger_report.unwrap(),
                helper_bit: s2.helper_bit.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<AggregateCreditInputRow<F, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AggregateCreditInputRow<F, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            AggregateCreditInputRow {
                breakdown_key: s0.breakdown_key,
                credit: s0.trigger_value,
            },
            AggregateCreditInputRow {
                breakdown_key: s1.breakdown_key,
                credit: s1.trigger_value,
            },
            AggregateCreditInputRow {
                breakdown_key: s2.breakdown_key,
                credit: s2.trigger_value,
            },
        ]
    }
}

impl<F, MK, BK> IntoShares<IPAInputRow<F, MK, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [IPAInputRow<F, MK, BK>; 3] {
        let [s0, s1, s2]: [GenericReportShare<F, MK, BK>; 3] = self.share_with(rng);

        [
            IPAInputRow {
                timestamp: s0.timestamp.unwrap(),
                mk_shares: s0.match_key.unwrap(),
                is_trigger_bit: s0.is_trigger_report.unwrap(),
                breakdown_key: s0.breakdown_key,
                trigger_value: s0.trigger_value,
            },
            IPAInputRow {
                timestamp: s1.timestamp.unwrap(),
                mk_shares: s1.match_key.unwrap(),
                is_trigger_bit: s1.is_trigger_report.unwrap(),
                breakdown_key: s1.breakdown_key,
                trigger_value: s1.trigger_value,
            },
            IPAInputRow {
                timestamp: s2.timestamp.unwrap(),
                mk_shares: s2.match_key.unwrap(),
                is_trigger_bit: s2.is_trigger_report.unwrap(),
                breakdown_key: s2.breakdown_key,
                trigger_value: s2.trigger_value,
            },
        ]
    }
}

const DOMAINS: &[&str] = &[
    "mozilla.com",
    "facebook.com",
    "example.com",
    "subdomain.long-domain.example.com",
];

// TODO: this mostly duplicates the impl for GenericReportTestInput, can we avoid that?
impl<F> IntoShares<Report<F, MatchKey, BreakdownKey>> for TestRawDataRecord
where
    F: PrimeField + IntoShares<Replicated<F>>,
    Replicated<F>: Serializable,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Report<F, MatchKey, BreakdownKey>; 3] {
        let mk_shares = MatchKey::try_from(u128::from(self.user_id))
            .unwrap()
            .share_with(rng);
        let event_type = if self.is_trigger_report {
            EventType::Trigger
        } else {
            EventType::Source
        };
        let breakdown_key = BreakdownKey::try_from(u128::from(self.breakdown_key)).unwrap();
        let trigger_value = F::try_from(u128::from(self.trigger_value))
            .unwrap()
            .share_with(rng);
        let epoch = 1;
        let site_domain = DOMAINS[rng.gen_range(0..DOMAINS.len())].to_owned();

        zip(mk_shares.into_iter(), trigger_value.into_iter())
            .map(|(mk_shares, trigger_value)| Report {
                timestamp: self.timestamp.try_into().unwrap(),
                mk_shares,
                event_type,
                breakdown_key,
                trigger_value,
                epoch,
                site_domain: site_domain.clone(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<F> IntoShares<Report<F, MatchKey, BreakdownKey>>
    for GenericReportTestInput<F, MatchKey, BreakdownKey>
where
    F: PrimeField + IntoShares<Replicated<F>>,
    Replicated<F>: Serializable,
{
    #[allow(clippy::if_not_else)] // clippy doesn't like `is_trigger_report != ZERO`, but I stand by it
    fn share_with<R: Rng>(self, rng: &mut R) -> [Report<F, MatchKey, BreakdownKey>; 3] {
        let mk_shares = self.match_key.unwrap().share_with(rng);
        let event_type = if self.is_trigger_report.unwrap() != F::ZERO {
            EventType::Trigger
        } else {
            EventType::Source
        };
        let trigger_value = self.trigger_value.share_with(rng);
        let epoch = 1;
        let site_domain = DOMAINS[rng.gen_range(0..DOMAINS.len())].to_owned();

        zip(mk_shares.into_iter(), trigger_value.into_iter())
            .map(|(mk_shares, trigger_value)| Report {
                timestamp: self.timestamp.unwrap().as_u128().try_into().unwrap(),
                mk_shares,
                event_type,
                breakdown_key: self.breakdown_key,
                trigger_value,
                epoch,
                site_domain: site_domain.clone(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

fn reconstruct_mod_converted_bits<F: Field, B: GaloisField>(input: [&[Replicated<F>]; 3]) -> B {
    debug_assert!(
        B::BITS as usize == input[0].len()
            && input[0].len() == input[1].len()
            && input[1].len() == input[2].len()
    );
    let mut result = 0;
    for i in 0..B::BITS {
        let bit = [
            &input[0][i as usize],
            &input[1][i as usize],
            &input[2][i as usize],
        ]
        .reconstruct();
        result += bit.as_u128() * (1 << i);
    }
    B::truncate_from(result)
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [MCAccumulateCreditInputRow<F, Replicated<F>>; 3]
where
    F: Field,
    MK: GaloisField,
    BK: GaloisField,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [&MCAccumulateCreditInputRow<F, Replicated<F>>; 3]
where
    F: Field,
    MK: GaloisField,
    BK: GaloisField,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        let [s0, s1, s2] = self;

        let breakdown_key = reconstruct_mod_converted_bits([
            &s0.breakdown_key,
            &s1.breakdown_key,
            &s2.breakdown_key,
        ]);
        let trigger_value = [&s0.trigger_value, &s1.trigger_value, &s2.trigger_value].reconstruct();
        let is_trigger_report = [
            &s0.is_trigger_report,
            &s1.is_trigger_report,
            &s2.is_trigger_report,
        ]
        .reconstruct();
        let helper_bit = [&s0.helper_bit, &s1.helper_bit, &s2.helper_bit].reconstruct();
        let active_bit = [&s0.active_bit, &s1.active_bit, &s2.active_bit].reconstruct();

        GenericReportTestInput {
            breakdown_key,
            trigger_value,
            is_trigger_report: Some(is_trigger_report),
            helper_bit: Some(helper_bit),
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            aggregation_bit: None,
            active_bit: Some(active_bit),
        }
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [MCAggregateCreditOutputRow<F, Replicated<F>, BK>; 3]
where
    F: Field,
    MK: GaloisField,
    BK: GaloisField,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F, MK, BK> Reconstruct<GenericReportTestInput<F, MK, BK>>
    for [&MCAggregateCreditOutputRow<F, Replicated<F>, BK>; 3]
where
    F: Field,
    MK: GaloisField,
    BK: GaloisField,
{
    fn reconstruct(&self) -> GenericReportTestInput<F, MK, BK> {
        let [s0, s1, s2] = self;

        let breakdown_key = reconstruct_mod_converted_bits([
            &s0.breakdown_key,
            &s1.breakdown_key,
            &s2.breakdown_key,
        ]);
        let trigger_value = [&s0.credit, &s1.credit, &s2.credit].reconstruct();

        GenericReportTestInput {
            breakdown_key,
            trigger_value,
            is_trigger_report: None,
            helper_bit: None,
            match_key: None,
            attribution_constraint_id: None,
            timestamp: None,
            aggregation_bit: None,
            active_bit: None,
        }
    }
}
