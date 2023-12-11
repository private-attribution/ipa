use bitvec::prelude::{BitVec, Lsb0};
use futures::{
    future,
    stream::{iter as stream_iter, TryStreamExt},
};
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{boolean::Boolean, CustomArray, Field},
    protocol::{
        basics::Reveal, context::Context,
        ipa_prf::boolean_ops::comparison_and_subtraction_sequential::compare_gt, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
    seq_join::seq_join,
};

#[derive(Step)]
pub(crate) enum Step {
    Left,
    Right,
    Compare,
    Reveal,
}

/// insecure quicksort using MPC comparisons and a key extraction function f
///
/// f takes as input an element in the slice and outputs the key by which we sort by
/// follows partially the function signature of `sort_by_key`, see `https://doc.rust-lang.org/src/alloc/slice.rs.html#305-308`
///
/// set desc = true for descending ordering
///
/// This version of quicksort is insecure because it does not enforce the uniqueness of the sorted elements
/// To see why this leaks information: assume that all elements are equal,
/// then quicksort runs in time O(n^2) while for unique elements, it is only expected to run in time O(n log n)
///
/// The leakage can be fixed by appending a counter on each element that is unique to the element
/// This adds another >= log N bits, where N is the amount of elements
///
/// This implementation of quicksort is in place and uses a stack instead of recursion
/// It terminates once the stack is empty
/// # Errors
/// Will propagate errors from transport and a few typecasts
#[tracing::instrument(name = "quicksort_by_key_insecure", skip_all)]
pub async fn quicksort_by_key_insecure<C, K, F, S>(
    ctx: C,
    list: &mut [S],
    desc: bool,
    f: F,
) -> Result<(), Error>
where
    C: Context,
    S: Send + Sync,
    F: Fn(&S) -> &AdditiveShare<K> + Sync,
    for<'a> &'a AdditiveShare<K>: IntoIterator<Item = AdditiveShare<K::Element>>,
    K: SharedValue + Field + CustomArray<Element = Boolean>,
{
    // expected amount of recursion: compute ceil(log_2(list.len()))
    let expected_depth = std::mem::size_of::<usize>() * 8 - list.len().leading_zeros() as usize;
    // create stack
    let mut stack: Vec<(C, usize, usize)> = Vec::with_capacity(expected_depth);
    // vector for comparison (against pivot) outcomes
    let mut comp: BitVec<usize, Lsb0> = BitVec::with_capacity(list.len());

    // initialize stack
    stack.push((ctx, 0usize, list.len()));

    // iterate through quicksort recursions
    while let Some((ctx, b_l, b_r)) = stack.pop() {
        // start of quicksort function
        // check whether sort is needed
        if b_l + 1 < b_r {
            // set up iterator
            let mut iterator = list[b_l..b_r].iter();
            // first element is pivot, apply key extraction function f
            let pivot = f(iterator.next().unwrap());
            // create pointer to context for moving into closure
            let pctx = &(ctx.set_total_records(b_r - (b_l + 1)));
            let pf = &f;
            // precompute comparison against pivot and reveal result in parallel
            comp.clear();
            seq_join(
                ctx.active_work(),
                stream_iter(iterator.enumerate().map(|(n, x)| {
                    async move {
                        // compare current element against pivot
                        let sh_comp = compare_gt(
                            pctx.narrow(&Step::Compare),
                            RecordId::from(n),
                            // apply key extraction function f to element x
                            pf(x),
                            pivot,
                        )
                        .await?;

                        // reveal outcome of comparison
                        Ok::<bool, Error>(
                            // desc = true will flip the order of the sort
                            Boolean::from(false ^ desc)
                                == sh_comp
                                    .reveal(pctx.narrow(&Step::Reveal), RecordId::from(n))
                                    .await?,
                        )
                    }
                })),
            )
            .try_for_each(|x| {
                comp.push(x);
                future::ready(Ok(()))
            })
            .await?;

            // swap elements based on comparisons
            // i is index of first element larger than pivot
            let mut i = b_l + 1;
            for (j, b) in comp.iter().enumerate() {
                if *b {
                    list.swap(i, j + b_l + 1);
                    i += 1;
                }
            }

            // put pivot to index i-1
            list.swap(i - 1, b_l);

            // push recursively calls to quicksort function on stack
            if i > b_l + 1 {
                stack.push((ctx.narrow(&Step::Left), b_l, i - 1));
            }
            if i + 1 < b_r {
                stack.push((ctx.narrow(&Step::Right), i, b_r));
            }
        }
    }

    // no error happened, sorted successfully
    Ok(())
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use ipa_macros::Step;
    use rand::Rng;

    use crate::{
        error::Error,
        ff::{boolean_array::BA64, Field},
        protocol::{context::Context, ipa_prf::quicksort::quicksort_by_key_insecure},
        rand::thread_rng,
        secret_sharing::replicated::semi_honest::AdditiveShare,
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
        quicksort_by_key_insecure(ctx, &mut list_mut[..], desc, |x| x).await?;
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
}
