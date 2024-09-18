use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq)]
pub enum TestHybridRecord {
    TestImpression { match_key: u64, breakdown_key: u32 },
    TestConversion { match_key: u64, value: u32 },
}

pub fn hybrid_in_the_clear(input_rows: &[TestHybridRecord], max_breakdown: usize) -> Vec<u32> {
    let mut conversion_match_keys = HashSet::<u64>::new();
    let mut impression_match_keys = HashSet::<u64>::new();

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

    let mut attributed_conversions = HashMap::<u64, (u32, u32), _>::new();

    for input in input_rows {
        match input {
            TestHybridRecord::TestImpression {
                match_key,
                breakdown_key,
            } => {
                if let Some(_) = conversion_match_keys.get(match_key) {
                    attributed_conversions
                        .entry(*match_key)
                        .and_modify(|e| e.0 = *breakdown_key)
                        .or_insert((*breakdown_key, 0));
                }
            }
            TestHybridRecord::TestConversion { match_key, value } => {
                if let Some(_) = impression_match_keys.get(match_key) {
                    attributed_conversions
                        .entry(*match_key)
                        .and_modify(|e| e.1 += value)
                        .or_insert((0, *value));
                }
            }
        }
    }

    let mut output = vec![0; max_breakdown];
    for (_, (breakdown_key, value)) in attributed_conversions {
        output[usize::try_from(breakdown_key).unwrap()] += value;
    }

    return output;
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::TestHybridRecord;
    use crate::test_fixture::hybrid::hybrid_in_the_clear;

    #[test]
    fn basic() {
        let test_data = vec![
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
        let expected = vec![
            0, 0, 43, // 12 + 31
            13, 33, // 25 + 8
            0,
        ];
        let result = hybrid_in_the_clear(&test_data, 6);
        assert_eq!(result, expected);
    }
}
