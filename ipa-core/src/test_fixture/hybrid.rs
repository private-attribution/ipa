use std::collections::{HashMap, HashSet};

use crate::{
    ff::{boolean_array::BooleanArray, U128Conversions},
    report::hybrid::IndistinguishableHybridReport,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::sharing::Reconstruct,
};

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq)]
pub enum TestHybridRecord {
    TestImpression { match_key: u64, breakdown_key: u32 },
    TestConversion { match_key: u64, value: u32 },
}

#[derive(PartialEq, Eq)]
pub struct TestIndistinguishableHybridReport {
    pub match_key: u64,
    pub value: u32,
    pub breakdown_key: u32,
}

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

struct HashmapEntry {
    breakdown_key: u32,
    total_value: u32,
}

impl HashmapEntry {
    pub fn new(breakdown_key: u32, value: u32) -> Self {
        Self {
            breakdown_key,
            total_value: value,
        }
    }
}

/// # Panics
/// It won't, so long as you can convert a u32 to a usize
#[must_use]
pub fn hybrid_in_the_clear(input_rows: &[TestHybridRecord], max_breakdown: usize) -> Vec<u32> {
    let mut conversion_match_keys = HashSet::new();
    let mut impression_match_keys = HashSet::new();

    for input in input_rows {
        match input {
            TestHybridRecord::TestImpression { match_key, .. } => {
                impression_match_keys.insert(*match_key);
            }
            TestHybridRecord::TestConversion { match_key, .. } => {
                conversion_match_keys.insert(*match_key);
            }
        }
    }

    // The key is the "match key" and the value stores both the breakdown and total attributed value
    let mut attributed_conversions = HashMap::new();

    for input in input_rows {
        match input {
            TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
            } => {
                if conversion_match_keys.contains(match_key) {
                    let v = attributed_conversions
                        .entry(*match_key)
                        .or_insert(HashmapEntry::new(*breakdown_key, 0));
                    v.breakdown_key = *breakdown_key;
                }
            }
            TestHybridRecord::TestConversion { match_key, value } => {
                if impression_match_keys.contains(match_key) {
                    attributed_conversions
                        .entry(*match_key)
                        .and_modify(|e| e.total_value += value)
                        .or_insert(HashmapEntry::new(0, *value));
                }
            }
        }
    }

    let mut output = vec![0; max_breakdown];
    for (_, entry) in attributed_conversions {
        output[usize::try_from(entry.breakdown_key).unwrap()] += entry.total_value;
    }

    output
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::{seq::SliceRandom, thread_rng};

    use super::TestHybridRecord;
    use crate::test_fixture::hybrid::hybrid_in_the_clear;

    #[test]
    fn basic() {
        let mut test_data = vec![
            TestHybridRecord::TestImpression {
                match_key: 12345,
                breakdown_key: 2,
            },
            TestHybridRecord::TestImpression {
                match_key: 23456,
                breakdown_key: 4,
            },
            TestHybridRecord::TestConversion {
                match_key: 23456,
                value: 25,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 34567,
                breakdown_key: 1,
            },
            TestHybridRecord::TestImpression {
                match_key: 45678,
                breakdown_key: 3,
            },
            TestHybridRecord::TestConversion {
                match_key: 45678,
                value: 13,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 56789,
                breakdown_key: 5,
            },
            TestHybridRecord::TestConversion {
                match_key: 67890,
                value: 14,
            }, // NOT attributed
            TestHybridRecord::TestImpression {
                match_key: 78901,
                breakdown_key: 2,
            },
            TestHybridRecord::TestConversion {
                match_key: 78901,
                value: 12,
            }, // attributed
            TestHybridRecord::TestConversion {
                match_key: 78901,
                value: 31,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: 89012,
                breakdown_key: 4,
            },
            TestHybridRecord::TestConversion {
                match_key: 89012,
                value: 8,
            }, // attributed
        ];

        let mut rng = thread_rng();
        test_data.shuffle(&mut rng);
        let expected = vec![
            0, 0, 43, // 12 + 31
            13, 33, // 25 + 8
            0,
        ];
        let result = hybrid_in_the_clear(&test_data, 6);
        assert_eq!(result, expected);
    }
}
