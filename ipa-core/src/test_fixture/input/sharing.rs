use std::iter::{repeat, zip};

use crate::{
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA64},
        U128Conversions,
    },
    protocol::ipa_prf::OPRFIPAInputRow,
    rand::Rng,
    report::{
        hybrid::{HybridConversionReport, HybridImpressionReport, HybridReport},
        EventType, OprfReport,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        IntoShares,
    },
    test_fixture::{ipa::TestRawDataRecord, Reconstruct},
};

const DOMAINS: &[&str] = &[
    "mozilla.com",
    "facebook.com",
    "example.com",
    "subdomain.long-domain.example.com",
];

// TODO: this mostly duplicates the impl for GenericReportTestInput, can we avoid that?
impl<BK, TV, TS> IntoShares<OprfReport<BK, TV, TS>> for TestRawDataRecord
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    TV: BooleanArray + U128Conversions + IntoShares<Replicated<TV>>,
    TS: BooleanArray + U128Conversions + IntoShares<Replicated<TS>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [OprfReport<BK, TV, TS>; 3] {
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
        let event_type = if self.is_trigger_report {
            EventType::Trigger
        } else {
            EventType::Source
        };
        let epoch = 1;
        let site_domain = DOMAINS[rng.gen_range(0..DOMAINS.len())].to_owned();

        zip(zip(match_key, zip(timestamp, breakdown_key)), trigger_value)
            .map(
                |((match_key_share, (ts_share, bk_share)), tv_share)| OprfReport {
                    timestamp: ts_share,
                    match_key: match_key_share,
                    event_type,
                    breakdown_key: bk_share,
                    trigger_value: tv_share,
                    epoch,
                    site_domain: site_domain.clone(),
                },
            )
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<BK, V> IntoShares<HybridReport<BK, V>> for TestRawDataRecord
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    V: BooleanArray + U128Conversions + IntoShares<Replicated<V>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [HybridReport<BK, V>; 3] {
        let match_key = BA64::try_from(u128::from(self.user_id))
            .unwrap()
            .share_with(rng);
        let breakdown_key = BK::try_from(self.breakdown_key.into())
            .unwrap()
            .share_with(rng);
        let trigger_value = V::try_from(self.trigger_value.into())
            .unwrap()
            .share_with(rng);
        if self.is_trigger_report {
            zip(match_key, trigger_value)
                .map(|(match_key_share, trigger_value_share)| {
                    HybridReport::Conversion::<BK, V>(HybridConversionReport {
                        match_key: match_key_share,
                        value: trigger_value_share,
                    })
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        } else {
            zip(match_key, breakdown_key)
                .map(|(match_key_share, breakdown_key_share)| {
                    HybridReport::Impression::<BK, V>(HybridImpressionReport {
                        match_key: match_key_share,
                        breakdown_key: breakdown_key_share,
                    })
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }
    }
}

impl<BK, TV, TS> IntoShares<OPRFIPAInputRow<BK, TV, TS>> for TestRawDataRecord
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    TV: BooleanArray + U128Conversions + IntoShares<Replicated<TV>>,
    TS: BooleanArray + U128Conversions + IntoShares<Replicated<TS>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [OPRFIPAInputRow<BK, TV, TS>; 3] {
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
        let breakdown_key = BK::try_from(u128::from(self.breakdown_key))
            .unwrap()
            .share_with(rng);
        let trigger_value = TV::try_from(u128::from(self.trigger_value))
            .unwrap()
            .share_with(rng);

        zip(
            zip(zip(match_key, zip(timestamp, breakdown_key)), trigger_value),
            repeat(is_trigger),
        )
        .map(
            |(((match_key_share, (ts_share, bk_share)), tv_share), is_trigger_share)| {
                OPRFIPAInputRow {
                    timestamp: ts_share,
                    match_key: match_key_share,
                    is_trigger: is_trigger_share,
                    breakdown_key: bk_share,
                    trigger_value: tv_share,
                }
            },
        )
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }
}

impl<BK, TV, TS> Reconstruct<TestRawDataRecord> for [&OPRFIPAInputRow<BK, TV, TS>; 3]
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    TV: BooleanArray + U128Conversions + IntoShares<Replicated<TV>>,
    TS: BooleanArray + U128Conversions + IntoShares<Replicated<TS>>,
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
