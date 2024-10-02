use std::{convert::Infallible, mem, ops::Range};

use bitvec::prelude::{BitVec, Lsb0};
use futures::stream::{self, repeat, StreamExt, TryStreamExt};
use typenum::Const;

use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{boolean::Boolean, boolean_array::BooleanArray, Expand},
    helpers::{
        stream::{div_round_up, process_stream_by_chunks, ChunkBuffer, TryFlattenItersExt},
        TotalRecords,
    },
    protocol::{
        basics::reveal,
        boolean::{step::ThirtyTwoBitStep, NBitStep},
        context::{
            dzkp_validator::DZKPValidator, Context, DZKPUpgraded, MaliciousProtocolSteps,
            UpgradableContext,
        },
        ipa_prf::{
            boolean_ops::comparison_and_subtraction_sequential::compare_gt,
            step::{QuicksortPassStep, QuicksortStep as Step},
            SORT_CHUNK,
        },
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, BitDecomposed, SharedValue, TransposeFrom,
        Vectorizable,
    },
    seq_join::seq_join,
};

impl<K> ChunkBuffer<SORT_CHUNK> for (Vec<AdditiveShare<K>>, Vec<AdditiveShare<K>>)
where
    K: SharedValue,
    BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<K>; SORT_CHUNK], Error = Infallible>,
    BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<K>; SORT_CHUNK], Error = Infallible>,
{
    type Item = (AdditiveShare<K>, AdditiveShare<K>);
    type Chunk = (
        BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>,
        BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>,
    );

    fn push(&mut self, item: Self::Item) {
        self.0.push(item.0);
        self.1.push(item.1);
    }

    fn len(&self) -> usize {
        assert_eq!(self.0.len(), self.1.len());
        self.0.len()
    }

    fn resize_with<F: Fn() -> Self::Item>(&mut self, len: usize, f: F) {
        while self.0.len() < len {
            <Self as ChunkBuffer<SORT_CHUNK>>::push(self, f());
        }
    }

    fn take(&mut self) -> Result<Self::Chunk, LengthError> {
        let buffered = mem::replace(
            self,
            (
                Vec::with_capacity(SORT_CHUNK),
                Vec::with_capacity(SORT_CHUNK),
            ),
        );
        let a: Box<[AdditiveShare<K>; SORT_CHUNK]> = match buffered.0.try_into() {
            Ok(boxed) => boxed,
            Err(vec) => {
                *self = (vec, buffered.1);
                return Err(LengthError {
                    expected: SORT_CHUNK,
                    actual: self.0.len(),
                });
            }
        };
        let b: Box<[AdditiveShare<K>; SORT_CHUNK]> = match buffered.1.try_into() {
            Ok(boxed) => boxed,
            Err(vec) => {
                *self = (<Vec<_> as From<Box<[_]>>>::from(a), vec);
                return Err(LengthError {
                    expected: SORT_CHUNK,
                    actual: self.1.len(),
                });
            }
        };

        let a_t = BitDecomposed::transposed_from(&*a).unwrap_infallible();
        let b_t = BitDecomposed::transposed_from(&*b).unwrap_infallible();
        Ok((a_t, b_t))
    }
}

/// Insecure quicksort using MPC comparisons and a key extraction function `get_key`.
///
/// `get_key` takes as input an element in the slice and outputs the key by which we sort by
/// follows partially the function signature of `sort_by_key`,
/// see `https://doc.rust-lang.org/src/alloc/slice.rs.html#305-308`.
///
/// Set `desc` to `true` for descending ordering.
///
/// This version of quicksort is insecure because it does not enforce the uniqueness of the sorted elements.
/// To see why this leaks information: take a list with all elements having equal values.
/// Quicksort for that list runs in time `O(n^2)` while for unique elements, where
/// it is only expected to run in time `O(n log n)`.
///
/// The leakage can be fixed by appending a counter on each element that is unique to the element.
/// This adds another `log_2(N)` bits, where `N` is the amount of elements
///
/// This implementation of quicksort is in place and uses a stack instead of recursion.
/// It terminates once the stack is empty.
/// # Errors
/// Will propagate errors from transport and a few typecasts
///
/// # Panics
/// If any of the input ranges are empty
pub async fn quicksort_ranges_by_key_insecure<C, K, F, S>(
    ctx: C,
    list: &mut [S],
    desc: bool,
    get_key: F,
    mut ranges_to_sort: Vec<Range<usize>>,
) -> Result<(), Error>
where
    C: UpgradableContext,
    S: Send + Sync,
    F: Fn(&S) -> &AdditiveShare<K> + Sync + Send + Copy,
    K: BooleanArray,
    AdditiveShare<Boolean, SORT_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, SORT_CHUNK>,
    BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<K>; SORT_CHUNK], Error = Infallible>,
    BitDecomposed<AdditiveShare<Boolean, SORT_CHUNK>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<K>; SORT_CHUNK], Error = Infallible>,
{
    // Panic on any empty ranges in the input. Check if all the input ranges have length 1;
    // if so, there's nothing to do.
    if ranges_to_sort.iter().fold(true, |trivial, range| {
        assert!(!range.is_empty());
        trivial && range.len() == 1
    }) {
        return Ok(());
    }

    let desc = <Boolean as Vectorizable<SORT_CHUNK>>::Array::expand(&Boolean::from(desc));
    let mut ranges_for_next_pass = Vec::with_capacity(ranges_to_sort.len() * 2);
    let mut quicksort_pass = 1;

    // iterate through all of the potentially incorrectly ordered ranges
    // make one pass, comparing each element to the pivot and splitting into two more
    // potentially incorrectly ordered ranges
    while !ranges_to_sort.is_empty() {
        // The total number of comparisons in each range is one fewer than the
        // number of items in that range.  And we don't accept empty range.
        let num_comparisons_needed = ranges_to_sort
            .iter()
            .map(ExactSizeIterator::len)
            .sum::<usize>()
            - ranges_to_sort.len();

        // num_comparisons_needed can only be zero if all of the ranges have length 1. We handled
        // this explicitly for the input; for subsequent passes, we shouldn't be generating trivial
        // ranges.
        let total_records_usize = div_round_up(num_comparisons_needed, Const::<SORT_CHUNK>);
        let total_records = TotalRecords::specified(total_records_usize)
            .expect("num_comparisons_needed should not be zero");
        let v = ctx.set_total_records(total_records).dzkp_validator(
            MaliciousProtocolSteps {
                protocol: &Step::quicksort_pass(quicksort_pass),
                validate: &Step::quicksort_pass_validate(quicksort_pass),
            },
            // TODO: use something like this when validating in chunks
            // `TARGET_PROOF_SIZE / usize::try_from(K::BITS).unwrap() / SORT_CHUNK``
            total_records_usize.next_power_of_two(),
        );
        let c = v.context();
        let cmp_ctx = c.narrow(&QuicksortPassStep::Compare);
        let rvl_ctx = c.narrow(&QuicksortPassStep::Reveal);

        let compare_index_pairs =
            stream::iter(ranges_to_sort.clone().into_iter().filter(|r| r.len() > 1))
                .flat_map(|range| {
                    // set up iterator
                    let mut iterator = list[range.clone()].iter().map(get_key).cloned();
                    // first element is pivot, apply key extraction function f
                    let pivot = iterator.next().unwrap();
                    repeat(pivot).zip(stream::iter(iterator))
                })
                .map(Ok);

        assert!(
            K::BITS <= ThirtyTwoBitStep::BITS,
            "ThirtyTwoBitStep is not large enough to accommodate this sort"
        );
        let compare_results = seq_join(
            ctx.active_work(),
            process_stream_by_chunks::<_, _, _, _, _, _, SORT_CHUNK>(
                compare_index_pairs,
                (Vec::new(), Vec::new()),
                move |idx, (pivot, k)| {
                    let cmp_ctx = cmp_ctx.clone();
                    let record_id = RecordId::from(idx);
                    async move {
                        // Compare elements against pivot
                        compare_gt::<_, ThirtyTwoBitStep, SORT_CHUNK>(
                            cmp_ctx, record_id, &k, &pivot,
                        )
                        .await
                    }
                },
            ),
        )
        .try_collect::<Vec<_>>()
        .await?;

        // TODO: validate in chunks rather than for the entire input
        v.validate().await?;

        let revealed: BitVec<usize, Lsb0> = seq_join(
            ctx.active_work(),
            stream::iter(compare_results).enumerate().map(|(i, chunk)| {
                let rvl_ctx = rvl_ctx.clone();
                chunk.then(move |results| async move {
                    // Reveal the comparison result
                    let revealed_comp = reveal(rvl_ctx, RecordId::from(i), &results).await?;

                    // desc = true will flip the order of the sort
                    Ok::<_, Error>(revealed_comp + !desc)
                })
            }),
        )
        .try_flatten_iters()
        .map_ok(bool::from)
        .try_collect()
        .await?;

        let mut comp_it = revealed.into_iter();
        for mut range in ranges_to_sort.into_iter().filter(|r| r.len() >= 2) {
            let pivot_index = range.next().unwrap();
            let mut i = pivot_index + 1;
            for n in range.by_ref() {
                let comparison = comp_it.next().unwrap();
                if comparison {
                    list.swap(i, n);
                    i += 1;
                }
            }

            // swap the pivot element with the last of the elements meant to be left of it
            list.swap(i - 1, pivot_index);

            // mark which ranges need to be sorted in the next pass
            if i > pivot_index + 2 {
                ranges_for_next_pass.push(pivot_index..(i - 1));
            }
            if i + 1 < range.end {
                ranges_for_next_pass.push(i..range.end);
            }
        }

        quicksort_pass += 1;
        ranges_to_sort = ranges_for_next_pass;
        ranges_for_next_pass = Vec::with_capacity(ranges_to_sort.len() * 2);
    }

    // no error happened, sorted successfully
    Ok(())
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::{
        cmp::Ordering,
        iter::{repeat, repeat_with},
    };

    use ipa_step_derive::CompactStep;
    use rand::Rng;

    use crate::{
        ff::{boolean_array::BA32, U128Conversions},
        protocol::{context::Context, ipa_prf::quicksort::quicksort_ranges_by_key_insecure},
        rand::thread_rng,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    type TestSortKey = BA32;

    #[derive(CompactStep)]
    pub(crate) enum Step {
        TestReverse,
    }

    #[test]
    fn test_quicksort_insecure_semi_honest() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of random values
                let records: Vec<TestSortKey> = repeat_with(|| rng.gen()).take(20).collect();

                // convert expected into more readable format
                let mut expected: Vec<u128> =
                    records.clone().into_iter().map(|x| x.as_u128()).collect();
                // sort expected
                expected.sort_unstable();

                if desc {
                    expected.reverse();
                }

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, mut r| async move {
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(ctx, &mut r, desc, |x| x, vec![0..20])
                            .await
                            .unwrap();
                        r
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| x.as_u128())
                        .collect::<Vec<u128>>(),
                    expected
                );
            }
        });
    }

    #[test]
    fn test_quicksort_insecure_malicious() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of random values
                let records: Vec<TestSortKey> = repeat_with(|| rng.gen()).take(20).collect();

                // convert expected into more readable format
                let mut expected: Vec<u128> =
                    records.clone().into_iter().map(|x| x.as_u128()).collect();
                // sort expected
                expected.sort_unstable();

                if desc {
                    expected.reverse();
                }

                // compute mpc sort
                let result: Vec<_> = world
                    .malicious(records.into_iter(), |ctx, mut r| async move {
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(ctx, &mut r, desc, |x| x, vec![0..20])
                            .await
                            .unwrap();
                        r
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| x.as_u128())
                        .collect::<Vec<u128>>(),
                    expected
                );
            }
        });
    }

    #[test]
    fn test_quicksort_insecure_semi_honest_trivial() {
        run(|| async move {
            let expected: Vec<u128> = vec![1, 2];
            let records: Vec<TestSortKey> =
                expected.iter().copied().map(BA32::truncate_from).collect();

            // compute mpc sort
            let result: Vec<_> = TestWorld::default()
                .semi_honest(records.into_iter(), |ctx, mut r| async move {
                    quicksort_ranges_by_key_insecure(ctx, &mut r, false, |x| x, vec![0..1, 1..2])
                        .await
                        .unwrap();
                    r
                })
                .await
                .reconstruct();

            assert_eq!(
                // convert into more readable format
                result
                    .into_iter()
                    .map(|x| x.as_u128())
                    .collect::<Vec<u128>>(),
                expected
            );
        });
    }

    // test for identical elements
    #[test]
    fn test_quicksort_insecure_semi_honest_identical() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of 20 copies of same random value
                let records: Vec<TestSortKey> = repeat(rng.gen()).take(20).collect();

                // convert expected into more readable format
                let mut expected: Vec<u128> =
                    records.clone().into_iter().map(|x| x.as_u128()).collect();
                // sort expected
                expected.sort_unstable();

                if desc {
                    expected.reverse();
                }

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, mut r| async move {
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(ctx, &mut r, desc, |x| x, vec![0..20])
                            .await
                            .unwrap();
                        r
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| x.as_u128())
                        .collect::<Vec<u128>>(),
                    expected
                );
            }
        });
    }

    // test for empty list
    #[test]
    fn test_quicksort_insecure_semi_honest_empty() {
        run(|| async move {
            let world = TestWorld::default();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of random values
                let records: Vec<TestSortKey> = vec![];

                // convert expected into more readable format
                let mut expected: Vec<u128> =
                    records.clone().into_iter().map(|x| x.as_u128()).collect();
                // sort expected
                expected.sort_unstable();

                if desc {
                    expected.reverse();
                }

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, mut r| async move {
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(ctx, &mut r, desc, |x| x, vec![0..1])
                            .await
                            .unwrap();
                        r
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| x.as_u128())
                        .collect::<Vec<u128>>(),
                    expected
                );
            }
        });
    }

    // test for reversely sorted list
    #[test]
    fn test_quicksort_insecure_semi_honest_reverse() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of random values
                let records: Vec<TestSortKey> = repeat_with(|| rng.gen()).take(20).collect();

                // convert expected into more readable format
                let mut expected: Vec<u128> =
                    records.clone().into_iter().map(|x| x.as_u128()).collect();
                // sort expected
                expected.sort_unstable();

                if desc {
                    expected.reverse();
                }

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, mut r| async move {
                        let c = ctx.clone();
                        // Sort one direction
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(c, &mut r, !desc, |x| x, vec![0..20])
                            .await
                            .unwrap();

                        let c = ctx.narrow(&Step::TestReverse);
                        // Then sort the other direction
                        #[allow(clippy::single_range_in_vec_init)]
                        quicksort_ranges_by_key_insecure(c, &mut r, desc, |x| x, vec![0..20])
                            .await
                            .unwrap();

                        r
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| x.as_u128())
                        .collect::<Vec<u128>>(),
                    expected
                );
            }
        });
    }

    #[derive(Clone, Copy, Debug)]
    struct SillyStruct {
        timestamp: TestSortKey,
        user_id: usize,
    }

    impl SillyStruct {
        fn timestamp(x: &SillyStructShare) -> &AdditiveShare<TestSortKey> {
            &x.timestamp
        }
    }

    #[derive(Clone, Debug)]
    struct SillyStructShare {
        timestamp: AdditiveShare<TestSortKey>,
        user_id: usize,
    }

    impl IntoShares<SillyStructShare> for SillyStruct {
        fn share_with<R: Rng>(self, rng: &mut R) -> [SillyStructShare; 3] {
            let [t0, t1, t2] = self.timestamp.share_with(rng);
            [
                SillyStructShare {
                    timestamp: t0,
                    user_id: self.user_id,
                },
                SillyStructShare {
                    timestamp: t1,
                    user_id: self.user_id,
                },
                SillyStructShare {
                    timestamp: t2,
                    user_id: self.user_id,
                },
            ]
        }
    }

    impl Reconstruct<SillyStruct> for [SillyStructShare; 3] {
        fn reconstruct(&self) -> SillyStruct {
            SillyStruct {
                user_id: self[0].user_id,
                timestamp: [
                    self[0].timestamp.clone(),
                    self[1].timestamp.clone(),
                    self[2].timestamp.clone(),
                ]
                .reconstruct(),
            }
        }
    }

    impl Reconstruct<Vec<SillyStruct>> for [Vec<SillyStructShare>; 3] {
        fn reconstruct(&self) -> Vec<SillyStruct> {
            let mut res = Vec::with_capacity(self[0].len());
            for i in 0..self[0].len() {
                let elem = [self[0][i].clone(), self[1][i].clone(), self[2][i].clone()];
                res.push(elem.reconstruct());
            }
            res
        }
    }

    const TEST_USER_IDS: [usize; 8] = [1, 2, 3, 5, 8, 13, 21, 34];

    // test for sorting multiple ranges in a longer list
    #[test]
    fn test_multiple_ranges() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of structs corresponding to 8 users.
                // Each user will have a different number of records
                // Each struct will have a random timestamps
                let mut records: Vec<SillyStruct> = Vec::with_capacity(TEST_USER_IDS.iter().sum());
                for user_id in TEST_USER_IDS {
                    for _ in 0..user_id {
                        records.push(SillyStruct {
                            timestamp: rng.gen(),
                            user_id,
                        });
                    }
                }

                // convert expected into more readable format
                let mut expected: Vec<(usize, u128)> = records
                    .clone()
                    .into_iter()
                    .map(|x| (x.user_id, x.timestamp.as_u128()))
                    .collect();
                // sort expected
                expected.sort_unstable_by(|a, b| match a.0.cmp(&b.0) {
                    Ordering::Less => Ordering::Less,
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Equal => {
                        if desc {
                            b.1.cmp(&a.1)
                        } else {
                            a.1.cmp(&b.1)
                        }
                    }
                });

                let (_, ranges_to_sort) = TEST_USER_IDS.iter().fold(
                    (0, Vec::with_capacity(TEST_USER_IDS.len())),
                    |acc, x| {
                        let (start, mut ranges) = acc;
                        let end = start + x;
                        ranges.push(start..end);
                        (end, ranges)
                    },
                );

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, mut r| {
                        let ranges_clone = ranges_to_sort.clone();
                        async move {
                            quicksort_ranges_by_key_insecure(
                                ctx,
                                &mut r[..],
                                desc,
                                SillyStruct::timestamp,
                                ranges_clone,
                            )
                            .await
                            .unwrap();
                            r
                        }
                    })
                    .await
                    .reconstruct();

                assert_eq!(
                    // convert into more readable format
                    result
                        .into_iter()
                        .map(|x| (x.user_id, x.timestamp.as_u128()))
                        .collect::<Vec<_>>(),
                    expected
                );
            }
        });
    }
}
