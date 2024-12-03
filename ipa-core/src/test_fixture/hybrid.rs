use std::{collections::HashMap, iter::zip};

use crate::{
    ff::{
        boolean_array::{BooleanArray, BA64},
        U128Conversions,
    },
    rand::Rng,
    report::{
        hybrid::{
            AggregateableHybridReport, HybridConversionReport, HybridImpressionReport,
            HybridReport, IndistinguishableHybridReport, KeyIdentifier,
        },
        hybrid_info::{HybridConversionInfo, HybridImpressionInfo},
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::sharing::Reconstruct,
};

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum TestHybridRecord {
    TestImpression {
        match_key: u64,
        breakdown_key: u32,
        key_id: KeyIdentifier,
        helper_origin: String,
    },
    TestConversion {
        match_key: u64,
        value: u32,
        key_id: KeyIdentifier,
        helper_origin: String,
        conversion_site_domain: String,
        timestamp: u64,
        epsilon: f64,
        sensitivity: f64,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestIndistinguishableHybridReport<MK = u64> {
    pub match_key: MK,
    pub value: u32,
    pub breakdown_key: u32,
}

pub type TestAggregateableHybridReport = TestIndistinguishableHybridReport<()>;

impl<BK, V> Reconstruct<TestIndistinguishableHybridReport>
    for [&IndistinguishableHybridReport<BK, V>; 3]
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    V: BooleanArray + U128Conversions + IntoShares<Replicated<V>>,
{
    fn reconstruct(&self) -> TestIndistinguishableHybridReport {
        let match_key = self
            .each_ref()
            .map(|v| v.match_key.clone())
            .reconstruct()
            .as_u128();
        let breakdown_key = self
            .each_ref()
            .map(|v| v.breakdown_key.clone())
            .reconstruct()
            .as_u128();
        let value = self
            .each_ref()
            .map(|v| v.value.clone())
            .reconstruct()
            .as_u128();

        TestIndistinguishableHybridReport {
            match_key: match_key.try_into().unwrap(),
            breakdown_key: breakdown_key.try_into().unwrap(),
            value: value.try_into().unwrap(),
        }
    }
}

impl<BK, V> Reconstruct<TestAggregateableHybridReport>
    for [&IndistinguishableHybridReport<BK, V, ()>; 3]
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    V: BooleanArray + U128Conversions + IntoShares<Replicated<V>>,
{
    fn reconstruct(&self) -> TestAggregateableHybridReport {
        let breakdown_key = self
            .each_ref()
            .map(|v| v.breakdown_key.clone())
            .reconstruct()
            .as_u128();
        let value = self
            .each_ref()
            .map(|v| v.value.clone())
            .reconstruct()
            .as_u128();

        TestAggregateableHybridReport {
            match_key: (),
            breakdown_key: breakdown_key.try_into().unwrap(),
            value: value.try_into().unwrap(),
        }
    }
}

impl<BK, V> IntoShares<AggregateableHybridReport<BK, V>> for TestAggregateableHybridReport
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    V: BooleanArray + U128Conversions + IntoShares<Replicated<V>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AggregateableHybridReport<BK, V>; 3] {
        let ba_breakdown_key = BK::try_from(u128::from(self.breakdown_key))
            .unwrap()
            .share_with(rng);
        let ba_value = V::try_from(u128::from(self.value)).unwrap().share_with(rng);
        zip(ba_breakdown_key, ba_value)
            .map(|(breakdown_key, value)| AggregateableHybridReport {
                match_key: (),
                breakdown_key,
                value,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl<BK, V> IntoShares<HybridReport<BK, V>> for TestHybridRecord
where
    BK: BooleanArray + U128Conversions + IntoShares<Replicated<BK>>,
    V: BooleanArray + U128Conversions + IntoShares<Replicated<V>>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [HybridReport<BK, V>; 3] {
        match self {
            TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
                key_id,
                helper_origin,
            } => {
                let ba_match_key = BA64::try_from(u128::from(match_key))
                    .unwrap()
                    .share_with(rng);
                let ba_breakdown_key = BK::try_from(u128::from(breakdown_key))
                    .unwrap()
                    .share_with(rng);
                zip(ba_match_key, ba_breakdown_key)
                    .map(|(match_key_share, breakdown_key_share)| {
                        HybridReport::Impression::<BK, V>(HybridImpressionReport {
                            match_key: match_key_share,
                            breakdown_key: breakdown_key_share,
                            info: HybridImpressionInfo::new(key_id, &helper_origin).unwrap(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            }
            TestHybridRecord::TestConversion {
                match_key,
                value,
                key_id,
                helper_origin,
                conversion_site_domain,
                timestamp,
                epsilon,
                sensitivity,
            } => {
                let ba_match_key = BA64::try_from(u128::from(match_key))
                    .unwrap()
                    .share_with(rng);
                let ba_value = V::try_from(u128::from(value)).unwrap().share_with(rng);
                zip(ba_match_key, ba_value)
                    .map(|(match_key_share, value_share)| {
                        HybridReport::Conversion::<BK, V>(HybridConversionReport {
                            match_key: match_key_share,
                            value: value_share,
                            info: HybridConversionInfo::new(
                                key_id,
                                &helper_origin,
                                &conversion_site_domain,
                                timestamp,
                                epsilon,
                                sensitivity,
                            )
                            .unwrap(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            }
        }
    }
}

enum MatchEntry {
    Single(TestHybridRecord),
    Pair(TestHybridRecord, TestHybridRecord),
    MoreThanTwo,
}

impl MatchEntry {
    pub fn add_record(&mut self, new_record: TestHybridRecord) {
        match self {
            Self::Single(old_record) => {
                *self = Self::Pair(old_record.clone(), new_record);
            }
            Self::Pair { .. } | Self::MoreThanTwo => *self = Self::MoreThanTwo,
        }
    }

    pub fn into_breakdown_key_and_value_tuple(self) -> Option<(u32, u32)> {
        match self {
            Self::Pair(imp, conv) => match (imp, conv) {
                (
                    TestHybridRecord::TestImpression { breakdown_key, .. },
                    TestHybridRecord::TestConversion { value, .. },
                )
                | (
                    TestHybridRecord::TestConversion { value, .. },
                    TestHybridRecord::TestImpression { breakdown_key, .. },
                ) => Some((breakdown_key, value)),
                (
                    TestHybridRecord::TestConversion { value: value1, .. },
                    TestHybridRecord::TestConversion { value: value2, .. },
                ) => Some((0, value1 + value2)),
                _ => None,
            },
            _ => None,
        }
    }
}

/// # Panics
/// It won't, so long as you can convert a u32 to a usize
#[must_use]
pub fn hybrid_in_the_clear(input_rows: &[TestHybridRecord], max_breakdown: usize) -> Vec<u32> {
    let mut attributed_conversions = HashMap::<u64, MatchEntry>::new();
    for input in input_rows {
        match input {
            TestHybridRecord::TestConversion { match_key, .. }
            | TestHybridRecord::TestImpression { match_key, .. } => {
                attributed_conversions
                    .entry(*match_key)
                    .and_modify(|e| e.add_record(input.clone()))
                    .or_insert(MatchEntry::Single(input.clone()));
            }
        }
    }

/*<<<<<<< hybrid_info
    // The key is the "match key" and the value stores both the breakdown and total attributed value
    let mut attributed_conversions = HashMap::new();

    for input in input_rows {
        match input {
            TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
                ..
            } => {
                if conversion_match_keys.contains(match_key) {
                    let v = attributed_conversions
                        .entry(*match_key)
                        .or_insert(HashmapEntry::new(*breakdown_key, 0));
                    v.breakdown_key = *breakdown_key;
                }
            }
            TestHybridRecord::TestConversion {
                match_key, value, ..
            } => {
                if impression_match_keys.contains(match_key) {
                    attributed_conversions
                        .entry(*match_key)
                        .and_modify(|e| e.total_value += value)
                        .or_insert(HashmapEntry::new(0, *value));
                }
            }
        }
    }
=======*/
    let pairs = attributed_conversions
        .into_values()
        .filter_map(MatchEntry::into_breakdown_key_and_value_tuple)
        .collect::<Vec<_>>();

    let mut output = vec![0; max_breakdown];
    for (breakdown_key, value) in pairs {
        output[usize::try_from(breakdown_key).unwrap()] += value;
    }

    output
}

#[must_use]
pub fn build_hybrid_records_and_expectation() -> (Vec<TestHybridRecord>, Vec<u32>) {
    let test_hybrid_records = vec![
        TestHybridRecord::TestConversion {
            match_key: 12345,
            value: 2,
        }, // malicious client attributed to breakdown 0
        TestHybridRecord::TestConversion {
            match_key: 12345,
            value: 5,
        }, // malicious client attributed to breakdown 0
        TestHybridRecord::TestImpression {
            match_key: 23456,
            breakdown_key: 4,
        }, // attributed
        TestHybridRecord::TestConversion {
            match_key: 23456,
            value: 7,
        }, // attributed
        TestHybridRecord::TestImpression {
            match_key: 34567,
            breakdown_key: 1,
        }, // no conversion
        TestHybridRecord::TestImpression {
            match_key: 45678,
            breakdown_key: 3,
        }, // attributed
        TestHybridRecord::TestConversion {
            match_key: 45678,
            value: 5,
        }, // attributed
        TestHybridRecord::TestImpression {
            match_key: 56789,
            breakdown_key: 5,
        }, // no conversion
        TestHybridRecord::TestConversion {
            match_key: 67890,
            value: 2,
        }, // NOT attributed
        TestHybridRecord::TestImpression {
            match_key: 78901,
            breakdown_key: 2,
        }, // too many reports
        TestHybridRecord::TestConversion {
            match_key: 78901,
            value: 3,
        }, // not attributed, too many reports
        TestHybridRecord::TestConversion {
            match_key: 78901,
            value: 4,
        }, // not attributed, too many reports
        TestHybridRecord::TestImpression {
            match_key: 89012,
            breakdown_key: 4,
        }, // attributed
        TestHybridRecord::TestConversion {
            match_key: 89012,
            value: 6,
        }, // attributed
    ];

    let expected = vec![
        7, // two conversions goes to bucket 0: 2 + 5
        0, 0, 5, 13, // 4: 7 + 6
        0,
    ];

    (test_hybrid_records, expected)
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{seq::SliceRandom, thread_rng};

    use crate::test_fixture::hybrid::{build_hybrid_records_and_expectation, hybrid_in_the_clear};

    #[test]
/*<<<<<<< hybrid_info
    #[allow(clippy::too_many_lines)]
    fn basic() {
        let mut test_data = vec![
            TestHybridRecord::TestImpression {
                match_key: 12345,
                breakdown_key: 2,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestImpression {
                match_key: 23456,
                breakdown_key: 4,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestConversion {
                match_key: 23456,
                value: 25,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 102,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 34567,
                breakdown_key: 1,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestImpression {
                match_key: 45678,
                breakdown_key: 3,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestConversion {
                match_key: 45678,
                value: 13,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 103,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 56789,
                breakdown_key: 5,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestConversion {
                match_key: 67890,
                value: 14,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 104,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // NOT attributed
            TestHybridRecord::TestImpression {
                match_key: 78901,
                breakdown_key: 2,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestConversion {
                match_key: 78901,
                value: 12,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 100,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestConversion {
                match_key: 78901,
                value: 31,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 102,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 89012,
                breakdown_key: 4,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
            },
            TestHybridRecord::TestConversion {
                match_key: 89012,
                value: 8,
                key_id: 0,
                helper_origin: "HELPER_ORIGIN".to_string(),
                conversion_site_domain: "meta.com".to_string(),
                timestamp: 1234,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
        ];

=======*/
    fn hybrid_basic() {
        let (mut test_hybrid_records, expected) = build_hybrid_records_and_expectation();
        let mut rng = thread_rng();
        test_hybrid_records.shuffle(&mut rng);
        let result = hybrid_in_the_clear(&test_hybrid_records, 6);
        assert_eq!(result, expected);
    }
}
