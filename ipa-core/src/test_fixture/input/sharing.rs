use std::iter::{repeat, zip};

use rand::{distributions::Standard, prelude::Distribution};

// #[cfg(feature = "descriptive-gate")]
use crate::{ff::boolean::Boolean, ff::boolean_array::BA64};
use crate::{
    ff::{Field, GaloisField, PrimeField, Serializable},
    protocol::{
        BreakdownKey, MatchKey,
    },
    rand::Rng,
    report::{EventType, OprfReport, Report},
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        IntoShares, SharedValue,
    },
    test_fixture::{
        input::{GenericReportShare, GenericReportTestInput},
        ipa::TestRawDataRecord,
        Reconstruct,
    },
};

impl<F, MK, BK> IntoShares<GenericReportShare<F, MK, BK>> for GenericReportTestInput<F, MK, BK>
where
    F: Field + IntoShares<Replicated<F>>,
    MK: GaloisField + IntoShares<Replicated<MK>>,
    BK: GaloisField + IntoShares<Replicated<BK>>,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [GenericReportShare<F, MK, BK>; 3] {
        let GenericReportTestInput {
            match_key,
            attribution_constraint_id,
            timestamp,
            is_trigger_report,
            breakdown_key,
            trigger_value,
            helper_bit,
            aggregation_bit,
            active_bit,
        } = self;

        let [match_key0, match_key1, match_key2] = match_key.share_with(rng);
        let [attribution_constraint_id0, attribution_constraint_id1, attribution_constraint_id2] =
            attribution_constraint_id.share_with(rng);
        let [timestamp0, timestamp1, timestamp2] = timestamp.share_with(rng);
        let [is_trigger_report0, is_trigger_report1, is_trigger_report2] =
            is_trigger_report.share_with(rng);
        let [breakdown_key0, breakdown_key1, breakdown_key2] = breakdown_key.share_with(rng);
        let [trigger_value0, trigger_value1, trigger_value2] = trigger_value.share_with(rng);
        let [helper_bit0, helper_bit1, helper_bit2] = helper_bit.share_with(rng);
        let [aggregation_bit0, aggregation_bit1, aggregation_bit2] =
            aggregation_bit.share_with(rng);
        let [active_bit0, active_bit1, active_bit2] = active_bit.share_with(rng);

        [
            GenericReportShare {
                match_key: match_key0,
                breakdown_key: breakdown_key0,
                trigger_value: trigger_value0,
                attribution_constraint_id: attribution_constraint_id0,
                timestamp: timestamp0,
                is_trigger_report: is_trigger_report0,
                helper_bit: helper_bit0,
                aggregation_bit: aggregation_bit0,
                active_bit: active_bit0,
            },
            GenericReportShare {
                match_key: match_key1,
                breakdown_key: breakdown_key1,
                trigger_value: trigger_value1,
                attribution_constraint_id: attribution_constraint_id1,
                timestamp: timestamp1,
                is_trigger_report: is_trigger_report1,
                helper_bit: helper_bit1,
                aggregation_bit: aggregation_bit1,
                active_bit: active_bit1,
            },
            GenericReportShare {
                match_key: match_key2,
                breakdown_key: breakdown_key2,
                trigger_value: trigger_value2,
                attribution_constraint_id: attribution_constraint_id2,
                timestamp: timestamp2,
                is_trigger_report: is_trigger_report2,
                helper_bit: helper_bit2,
                aggregation_bit: aggregation_bit2,
                active_bit: active_bit2,
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

        zip(mk_shares, trigger_value)
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

        zip(mk_shares, trigger_value)
            .map(|(mk_shares, trigger_value)| Report {
                timestamp: self.timestamp.unwrap().as_u128().try_into().unwrap(),
                mk_shares,
                event_type,
                breakdown_key: self.breakdown_key.unwrap(),
                trigger_value,
                epoch,
                site_domain: site_domain.clone(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<BK, TV, TS> IntoShares<OprfReport<BK, TV, TS>> for TestRawDataRecord
where
    BK: SharedValue + Field + IntoShares<Replicated<BK>>,
    TV: SharedValue + Field + IntoShares<Replicated<TV>>,
    TS: SharedValue + Field + IntoShares<Replicated<TS>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [OprfReport<BK, TV, TS>; 3] {
        let is_trigger = Replicated::new(
            Boolean::from(self.is_trigger_report),
            Boolean::from(self.is_trigger_report),
        );
        let match_key = BA64::try_from(u128::from(self.user_id))
            .unwrap()
            .share_with(rng);
        let timestamp: [Replicated<TS>; 3] = TS::try_from(u128::from(self.timestamp))
            .unwrap()
            .share_with(rng);
        let breakdown_key = BK::try_from(self.breakdown_key.into())
            .unwrap()
            .share_with(rng);
        let trigger_value = TV::try_from(self.trigger_value.into())
            .unwrap()
            .share_with(rng);

        zip(
            zip(zip(match_key, zip(timestamp, breakdown_key)), trigger_value),
            repeat(is_trigger),
        )
        .map(
            |(((match_key_share, (ts_share, bk_share)), tv_share), is_trigger_share)| OprfReport {
                timestamp: ts_share,
                match_key: match_key_share,
                is_trigger: is_trigger_share,
                breakdown_key: bk_share,
                trigger_value: tv_share,
            },
        )
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }
}

impl<BK, TV, TS> Reconstruct<TestRawDataRecord> for [&OprfReport<BK, TV, TS>; 3]
where
    BK: SharedValue + Field,
    TV: SharedValue + Field,
    TS: SharedValue + Field,
{
    fn reconstruct(&self) -> TestRawDataRecord {
        let [s0, s1, s2] = self;

        let is_trigger_report = [&s0.is_trigger, &s1.is_trigger, &s2.is_trigger].reconstruct();

        let user_id = [&s0.match_key, &s1.match_key, &s2.match_key]
            .reconstruct()
            .as_u128();

        let breakdown_key = [&s0.breakdown_key, &s1.breakdown_key, &s2.breakdown_key]
            .reconstruct()
            .as_u128();

        let trigger_value = [&s0.trigger_value, &s1.trigger_value, &s2.trigger_value]
            .reconstruct()
            .as_u128();
        let timestamp = [&s0.timestamp, &s1.timestamp, &s2.timestamp]
            .reconstruct()
            .as_u128();

        TestRawDataRecord {
            user_id: user_id.try_into().unwrap(),
            is_trigger_report: is_trigger_report.into(),
            breakdown_key: breakdown_key.try_into().unwrap(),
            trigger_value: trigger_value.try_into().unwrap(),
            timestamp: timestamp.try_into().unwrap(),
        }
    }
}
