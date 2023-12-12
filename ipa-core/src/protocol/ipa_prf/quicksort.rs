use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{boolean::Boolean, CustomArray, Field},
    protocol::{
        basics::Reveal, context::Context,
        ipa_prf::boolean_ops::comparison_and_subtraction_sequential::compare_gt, step::BitOpStep,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
};

#[derive(Step)]
pub(crate) enum Step {
    Compare,
    Reveal,
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
pub async fn quicksort_ranges_by_key_insecure<C, K, F, S>(
    ctx: C,
    list: &mut [S],
    desc: bool,
    get_key: F,
    mut ranges_to_sort: Vec<(usize, usize)>,
) -> Result<(), Error>
where
    C: Context,
    S: Send + Sync,
    F: Fn(&S) -> &AdditiveShare<K> + Sync + Send + Copy,
    for<'a> &'a AdditiveShare<K>: IntoIterator<Item = AdditiveShare<K::Element>> + Send,
    K: SharedValue + Field + CustomArray<Element = Boolean> + Send,
    K::Element: Send,
{
    let mut ranges_for_next_pass = Vec::with_capacity(ranges_to_sort.len() * 2);
    let mut quicksort_pass = 1;

    // iterate through all of the potentially incorrectly ordered ranges
    // make one pass, comparing each element to the pivot and splitting into two more
    // potentially incorrectly ordered ranges
    while ranges_to_sort.len() > 0 {
        // compute the total number of comparisons that will be needed
        let mut num_comparisons_needed = 0;
        for range in ranges_to_sort.iter() {
            if range.0 + 1 < range.1 {
                num_comparisons_needed += range.1 - (range.0 + 1);
            }
        }

        let c = ctx
            .narrow(&BitOpStep::from(quicksort_pass))
            .set_total_records(num_comparisons_needed);
        let mut futures = Vec::with_capacity(ranges_to_sort.len());
        let mut counter = 0;

        // check whether sort is needed
        for range in ranges_to_sort.iter() {
            let b_l = range.0;
            let b_r = range.1;
            if b_l + 1 >= b_r {
                continue;
            }
            // first element is pivot, apply key extraction function f
            let pivot = get_key(&list[b_l]);

            // precompute comparison against pivot and reveal result in parallel
            for idx in (b_l + 1)..b_r {
                futures.push({
                    let k = get_key(&list[idx]);
                    let record_id = RecordId::from(counter);
                    let cmp_ctx = c.narrow(&Step::Compare);
                    let rvl_ctx = c.narrow(&Step::Reveal);

                    async move {
                        // Compare the current element against pivot and reveal the result.
                        let comparison = compare_gt(cmp_ctx, record_id, k, pivot)
                            .await?
                            .reveal(rvl_ctx, record_id)
                            .await?;

                        // reveal outcome of comparison
                        // desc = true will flip the order of the sort
                        Ok::<_, Error>(Boolean::from(false ^ desc) == comparison)
                    }
                });
                counter += 1;
            }
        }

        let comp = c.parallel_join(futures).await?;

        let mut offset = 0;
        for range in ranges_to_sort.iter() {
            let b_l = range.0;
            let b_r = range.1;
            if b_l + 1 >= b_r {
                continue;
            }

            // swap elements based on comparisons
            // i is index of first element larger than pivot
            let num_comparisons_in_range = b_r - (b_l + 1);
            let mut i = b_l + 1;
            for (j, idx) in (offset..(offset + num_comparisons_in_range)).enumerate() {
                let b = comp[idx];
                if b {
                    list.swap(i, j + b_l + 1);
                    i += 1;
                }
            }
            offset += num_comparisons_in_range;

            // put pivot to index i-1
            list.swap(i - 1, b_l);

            // push recursively calls to quicksort function on stack
            if i > b_l + 1 {
                ranges_for_next_pass.push((b_l, i - 1));
            }
            if i + 1 < b_r {
                ranges_for_next_pass.push((i, b_r));
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
    use std::cmp::Ordering;

    use ipa_macros::Step;
    use rand::Rng;

    use crate::{
        error::Error,
        ff::{
            boolean_array::{BA20, BA64},
            Field,
        },
        protocol::{context::Context, ipa_prf::quicksort::quicksort_ranges_by_key_insecure},
        rand::thread_rng,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[derive(Step)]
    pub(crate) enum Step {
        TestReverse,
    }

    pub async fn quicksort_insecure_test<C>(
        ctx: C,
        list: &[AdditiveShare<BA64>],
        desc: bool,
    ) -> Result<Vec<AdditiveShare<BA64>>, Error>
    where
        C: Context,
    {
        let mut list_mut = list.to_vec();
        quicksort_ranges_by_key_insecure(
            ctx,
            &mut list_mut[..],
            desc,
            |x| x,
            vec![(0, list.len())],
        )
        .await?;
        let mut result: Vec<AdditiveShare<BA64>> = vec![];
        list_mut.iter().for_each(|x| result.push(x.clone()));
        Ok(result)
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
                let mut records: Vec<BA64> = vec![<BA64>::ONE; 20];
                records.iter_mut().for_each(|x| *x = rng.gen::<BA64>());

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
                    .semi_honest(records.into_iter(), |ctx, records| async move {
                        quicksort_insecure_test::<_>(ctx, &records, desc)
                            .await
                            .unwrap()
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

    // test for identical elements
    #[test]
    fn test_quicksort_insecure_semi_honest_identical() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            // test cases for both, ascending and descending
            let bools = vec![false, true];

            for desc in bools {
                // generate vector of random values
                let element = rng.gen::<BA64>();
                let mut records: Vec<BA64> = vec![<BA64>::ONE; 20];
                records.iter_mut().for_each(|x| *x = element);

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
                    .semi_honest(records.into_iter(), |ctx, records| async move {
                        quicksort_insecure_test::<_>(ctx, &records, desc)
                            .await
                            .unwrap()
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
                let records: Vec<BA64> = vec![];

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
                    .semi_honest(records.into_iter(), |ctx, records| async move {
                        quicksort_insecure_test::<_>(ctx, &records, desc)
                            .await
                            .unwrap()
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
                let mut records: Vec<BA64> = vec![<BA64>::ONE; 20];
                records.iter_mut().for_each(|x| *x = rng.gen::<BA64>());

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
                    .semi_honest(records.into_iter(), |ctx, records| async move {
                        quicksort_insecure_test::<_>(
                            ctx.narrow(&Step::TestReverse),
                            &quicksort_insecure_test::<_>(ctx, &records, !desc)
                                .await
                                .unwrap(),
                            desc,
                        )
                        .await
                        .unwrap()
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
        timestamp: BA20,
        user_id: usize,
    }

    #[derive(Clone, Debug)]
    struct SillyStructShare {
        timestamp: AdditiveShare<BA20>,
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
                user_id: self[0].user_id.clone(),
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

    // test for reversely sorted list
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
                let mut records: Vec<SillyStruct> =
                    Vec::with_capacity(1 + 2 + 3 + 5 + 8 + 13 + 21 + 34);
                for user_id in [1, 2, 3, 5, 8, 13, 21, 34] {
                    for _ in 0..user_id {
                        records.push(SillyStruct {
                            timestamp: rng.gen::<BA20>(),
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

                // compute mpc sort
                let result: Vec<_> = world
                    .semi_honest(records.into_iter(), |ctx, records| async move {
                        let mut list_mut = records.to_vec();
                        quicksort_ranges_by_key_insecure(
                            ctx,
                            &mut list_mut[..],
                            desc,
                            |x| &x.timestamp,
                            vec![
                                (0, 1),
                                (1, 3),
                                (3, 6),
                                (6, 11),
                                (11, 19),
                                (19, 32),
                                (32, 53),
                                (53, 87),
                            ],
                        )
                        .await
                        .unwrap();

                        let mut result = vec![];
                        list_mut.iter().for_each(|x| result.push(x.clone()));
                        result
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
