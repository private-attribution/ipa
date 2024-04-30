//! Bitwise subtraction and comparison protocols
//!
//! Implementations in this module require that if the bit-width of the second (y) operand exceeds
//! the bit-width of the first (x) operand, then the excess bits of y must be zero. This condition
//! is abbreviated below as `length(x) >= log2(y)`.

use std::{borrow::Borrow, iter::repeat};

#[cfg(all(test, unit_test))]
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{ArrayAccessRef, ArrayBuild, ArrayBuilder, Field},
    protocol::{
        basics::{BooleanProtocols, SecureMul, ShareKnownValue},
        context::Context,
        step::BitOpStep,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, FieldSimd},
};
#[cfg(all(test, unit_test))]
use crate::{
    ff::{boolean::Boolean, CustomArray},
    protocol::{
        basics::{select, BooleanArrayMul},
        context::SemiHonestContext,
    },
    secret_sharing::SharedValue,
};

/// Comparison operation
///
/// Outputs x>=y for length(x) >= log2(y).
/// # Errors
/// Propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn compare_geq<C, F, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &XS,
    y: &YS,
) -> Result<AdditiveShare<F>, Error>
where
    C: Context,
    F: Field,
    XS: ArrayAccessRef<Element = AdditiveShare<F>> + ArrayBuild<Input = AdditiveShare<F>>,
    YS: ArrayAccessRef<Element = AdditiveShare<F>>,
    AdditiveShare<F>: BooleanProtocols<C, F>,
{
    // we need to initialize carry to 1 for x>=y,
    let mut carry = AdditiveShare::<F>::share_known_value(&ctx, F::ONE);
    // We don't care about the subtraction, we just want the carry
    subtraction_circuit(ctx, record_id, x, y, &mut carry).await?;
    Ok(carry)
}

/// Comparison operation

/// Outputs x>y for length(x) >= log2(y).
/// # Errors
/// propagates errors from multiply
pub async fn compare_gt<C, F, XS, YS, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &XS,
    y: &YS,
) -> Result<AdditiveShare<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    XS: ArrayAccessRef<Element = AdditiveShare<F, N>> + ArrayBuild<Input = AdditiveShare<F, N>>,
    YS: ArrayAccessRef<Element = AdditiveShare<F, N>>,
    AdditiveShare<F, N>: BooleanProtocols<C, F, N>,
{
    // we need to initialize carry to 0 for x>y
    let mut carry = AdditiveShare::<F, N>::ZERO;
    subtraction_circuit(ctx, record_id, x, y, &mut carry).await?;
    Ok(carry)
}

/// non-saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored).
/// When y>x, it computes `(x+"XS::MaxValue"+1)-y`, considering only the least-significant
/// length(x) bits of y.
/// # Errors
/// propagates errors from multiply
pub async fn integer_sub<C, F, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &XS,
    y: &YS,
) -> Result<XS, Error>
where
    C: Context,
    F: Field,
    XS: ArrayAccessRef<Element = AdditiveShare<F>> + ArrayBuild<Input = AdditiveShare<F>>,
    YS: ArrayAccessRef<Element = AdditiveShare<F>>,
    AdditiveShare<F>: BooleanProtocols<C, F>,
{
    // we need to initialize carry to 1 for a subtraction
    let mut carry = AdditiveShare::<F>::share_known_value(&ctx, F::ONE);
    subtraction_circuit(ctx, record_id, x, y, &mut carry).await
}

/// saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (we dont seem to need support for different length).
/// when y>x, it outputs 0. Only correct when length(x) >= log2(y).
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn integer_sat_sub<S>(
    ctx: SemiHonestContext<'_>,
    record_id: RecordId,
    x: &AdditiveShare<S>,
    y: &AdditiveShare<S>,
) -> Result<AdditiveShare<S>, Error>
where
    S: SharedValue + CustomArray<Element = Boolean>,
    AdditiveShare<S>: BooleanArrayMul,
{
    #[derive(Step)]
    enum Step {
        Subtract,
        Select,
    }

    let mut carry = !AdditiveShare::<Boolean>::ZERO;
    let result =
        subtraction_circuit(ctx.narrow(&Step::Subtract), record_id, x, y, &mut carry).await?;

    // carry computes carry=(x>=y)
    // if carry==0 then {zero} else {result}
    select(
        ctx.narrow(&Step::Select),
        record_id,
        &carry,
        &result,
        &AdditiveShare::<S>::ZERO,
    )
    .await
}

/// subtraction using bit subtractor
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored,
/// so only correct when length(x) >= log2(y)).
/// Implements `https://encrypto.de/papers/KSS09.pdf` from Section 3.1/3.2
///
/// # Errors
/// propagates errors from multiply
async fn subtraction_circuit<C, F, XS, YS, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &XS,
    y: &YS,
    carry: &mut AdditiveShare<F, N>,
) -> Result<XS, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    XS: ArrayAccessRef<Element = AdditiveShare<F, N>> + ArrayBuild<Input = AdditiveShare<F, N>>,
    YS: ArrayAccessRef<Element = AdditiveShare<F, N>>,
    AdditiveShare<F, N>: BooleanProtocols<C, F, N>,
{
    let x = x.iter();
    let y = y.iter();

    let mut result = XS::builder().with_capacity(x.len());

    for (i, (xb, yb)) in x
        .zip(y.chain(repeat(YS::make_ref(&AdditiveShare::<F, N>::ZERO))))
        .enumerate()
    {
        result.push(
            bit_subtractor(
                ctx.narrow(&BitOpStep::from(i)),
                record_id,
                xb.borrow(),
                yb.borrow(),
                carry,
            )
            .await?,
        );
    }

    Ok(result.build())
}

/// This improved one-bit subtractor that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `difference_bit` denoted with `result` can be efficiently computed as:
/// `d_i = x_i ⊕ !y_i ⊕ c_i` i.e. `result = x + !(c + y)`
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) ∧ !(y_i ⊕ c_i))`
/// i.e. update `carry` to `carry = ( x + carry)(!(y + carry)) + carry`
///
/// # Errors
/// propagates errors from multiply
async fn bit_subtractor<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<F, N>,
    y: &AdditiveShare<F, N>,
    carry: &mut AdditiveShare<F, N>,
) -> Result<AdditiveShare<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    AdditiveShare<F, N>: BooleanProtocols<C, F, N>,
{
    let output = x + !(y + &*carry);

    *carry = &*carry
        + (x + &*carry)
            .multiply(&(!(y + &*carry)), ctx, record_id)
            .await?;

    Ok(output)
}

#[cfg(all(test, unit_test))]
#[cfg_attr(coverage, allow(unused_imports))]
mod test {
    use std::{
        array,
        iter::{repeat, repeat_with, zip},
    };

    use futures::stream::iter as stream_iter;
    use futures_util::TryStreamExt;
    use rand::Rng;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA3, BA32, BA5, BA64},
            Expand, Field, U128Conversions,
        },
        protocol,
        protocol::{
            context::Context,
            ipa_prf::boolean_ops::comparison_and_subtraction_sequential::{
                compare_geq, compare_gt, integer_sat_sub, integer_sub,
            },
            RecordId,
        },
        rand::thread_rng,
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            BitDecomposed, SharedValue,
        },
        seq_join::{seq_join, SeqJoin},
        test_executor::run,
        test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld},
    };

    /// testing correctness of Not
    /// just because we need it for subtractions
    #[test]
    fn test_not() {
        assert_eq!(<Boolean>::ONE, !(<Boolean>::ZERO));
        assert_eq!(<Boolean>::ZERO, !(<Boolean>::ONE));
        assert_eq!(
            AdditiveShare::new(<Boolean>::ZERO, <Boolean>::ZERO),
            !AdditiveShare::new(<Boolean>::ONE, <Boolean>::ONE)
        );
        assert_eq!(
            AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            !AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ONE),
                <BA64>::expand(&<Boolean>::ONE)
            )
        );
        assert_eq!(
            !AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ONE),
                <BA64>::expand(&<Boolean>::ONE)
            )
        );
    }

    /// testing comparisons geq
    #[test]
    fn semi_honest_compare_geq() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();

            let expected = x >= y;

            let result = world
                .semi_honest(records.clone().into_iter(), |ctx, x_y| async move {
                    compare_geq(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            assert_eq!(result, <Boolean>::from(expected));

            let result2 = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    compare_geq(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[0],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result2, <Boolean>::from(true));
        });
    }

    /// testing comparisons gt
    #[test]
    fn semi_honest_compare_gt() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();

            let expected = x > y;

            let result = world
                .semi_honest(records.clone().into_iter(), |ctx, x_y| async move {
                    compare_gt::<_, _, AdditiveShare<BA64>, AdditiveShare<BA64>, 1>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            assert_eq!(result, <Boolean>::from(expected));

            // check that x is not greater than itself
            let result2 = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    compare_gt::<_, _, AdditiveShare<BA64>, AdditiveShare<BA64>, 1>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[0],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result2, <Boolean>::from(false));
        });
    }

    #[cfg(not(coverage))]
    const BENCH_COUNT: usize = 131_072;

    #[test]
    #[ignore] // benchmark
    #[cfg(not(coverage))]
    fn semi_honest_compare_gt_novec() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x = repeat_with(|| rng.gen())
                .take(BENCH_COUNT)
                .collect::<Vec<BA64>>();
            let x_int = x.iter().map(U128Conversions::as_u128).collect::<Vec<_>>();
            let y: BA64 = rng.gen::<BA64>();
            let y_int = y.as_u128();

            let expected = x_int.iter().map(|x| *x > y_int).collect::<Vec<_>>();

            let result = world
                .semi_honest((x.clone().into_iter(), y), |ctx, (x, y)| async move {
                    #[cfg(not(debug_assertions))]
                    let begin = std::time::Instant::now();
                    let ctx = ctx.set_total_records(x.len());
                    let res: Vec<AdditiveShare<Boolean>> = seq_join(
                        ctx.active_work(),
                        stream_iter(x.into_iter().zip(repeat((ctx, y))).enumerate().map(
                            |(i, (x, (ctx, y)))| async move {
                                compare_gt(ctx, RecordId::from(i), &x, &y).await
                            },
                        )),
                    )
                    .try_collect()
                    .await
                    .unwrap();
                    #[cfg(not(debug_assertions))]
                    tracing::info!("Execution time: {:?}", begin.elapsed());
                    res
                })
                .await
                .reconstruct();

            let results_iter = zip(result, expected);
            assert_eq!(results_iter.len(), BENCH_COUNT);
            for (observed, expected) in results_iter {
                assert_eq!(observed, <Boolean>::from(expected));
            }
        });
    }

    #[test]
    #[ignore] // benchmark
    #[cfg(not(coverage))]
    fn semi_honest_compare_gt_vec() {
        run(|| async move {
            const N: usize = 256;
            const CMP_BITS: usize = 64;

            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x = repeat_with(|| rng.gen())
                .take(BENCH_COUNT)
                .collect::<Vec<BA64>>();
            let x_int: Vec<u64> = x
                .iter()
                .map(|x| x.as_u128().try_into().unwrap())
                .collect::<Vec<_>>();
            let y: BA64 = rng.gen::<BA64>();
            let y_int: u64 = y.as_u128().try_into().unwrap();
            let xa: Vec<BitDecomposed<[Boolean; N]>> = x_int
                .chunks(N)
                .map(|x| {
                    BitDecomposed::decompose(CMP_BITS, move |bit| {
                        array::from_fn(|rec| {
                            if (x[rec] >> bit) & 1 == 1 {
                                Boolean::TRUE
                            } else {
                                Boolean::FALSE
                            }
                        })
                    })
                })
                .collect::<Vec<_>>();
            let ya: BitDecomposed<[Boolean; N]> = BitDecomposed::decompose(CMP_BITS, |i| {
                if (y_int >> i) & 1 == 1 {
                    [Boolean::TRUE; N]
                } else {
                    [Boolean::FALSE; N]
                }
            });

            let expected = x_int.iter().map(|x| *x > y_int).collect::<Vec<_>>();

            let xa_iter = xa.clone().into_iter();
            let result = world
                .semi_honest((xa_iter, ya.clone()), |ctx, (x, y)| async move {
                    #[cfg(not(debug_assertions))]
                    let begin = std::time::Instant::now();
                    let ctx = ctx.set_total_records(x.len());
                    let res: Vec<AdditiveShare<Boolean, N>> = seq_join(
                        ctx.active_work(),
                        stream_iter(x.into_iter().zip(repeat((ctx, y))).enumerate().map(
                            |(i, (x, (ctx, y)))| async move {
                                compare_gt(ctx, RecordId::from(i), &x, &y).await
                            },
                        )),
                    )
                    .try_collect()
                    .await
                    .unwrap();
                    #[cfg(not(debug_assertions))]
                    tracing::info!("Execution time: {:?}", begin.elapsed());
                    res
                })
                .await;

            let [r0, r1, r2] = result;
            let observed = (0..r0.len())
                .flat_map(|i| [r0[i].clone(), r1[i].clone(), r2[i].clone()].reconstruct_arr())
                .collect::<Vec<_>>();

            let results_iter = zip(observed, expected);
            assert_eq!(results_iter.len(), BENCH_COUNT);
            for (observed, expected) in results_iter {
                assert_eq!(observed, <Boolean>::from(expected));
            }
        });
    }

    /// testing correctness of subtraction
    #[test]
    fn semi_honest_sub() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();
            let z = 1_u128 << 64;

            let expected = ((x + z) - y) % z;

            let result = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    integer_sub(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn semi_honest_sat_sub() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();

            let expected = if y > x { 0u128 } else { x - y };

            let result = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    integer_sat_sub::<_>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn test_overflow_behavior() {
        run(|| async move {
            let world = TestWorld::default();

            let x = BA3::truncate_from(0_u128);
            let y = BA5::truncate_from(28_u128);
            let expected = 4_u128;

            let result = world
                .semi_honest((x, y), |ctx, x_y| async move {
                    integer_sub(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn semi_honest_sub_differing_lengths() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records = (rng.gen::<BA64>(), rng.gen::<BA32>());
            let x = records.0.as_u128();
            let y = records.1.as_u128();
            let z = 1_u128 << 64;

            let expected = ((x + z) - y) % z;

            let result = world
                .semi_honest(records, |ctx, x_y| async move {
                    integer_sub(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }
}
