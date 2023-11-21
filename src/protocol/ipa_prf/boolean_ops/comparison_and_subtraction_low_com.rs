#[cfg(all(test, unit_test))]
use ipa_macros::Step;

#[cfg(all(test, unit_test))]
use crate::{
    error::Error,
    ff::{ArrayAccess, CustomArray, Expand, Field},
    protocol::{basics::SecureMul, context::Context, step::BitOpStep, RecordId},
    secret_sharing::{replicated::semi_honest::AdditiveShare, WeakSharedValue},
};

#[cfg(all(test, unit_test))]
#[derive(Step)]
pub(crate) enum Step {
    SaturatedSubtraction,
    MultiplyWithCarry,
}

/// Comparison operation
/// outputs x>=y
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn compare_geq<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
) -> Result<AdditiveShare<XS::Element>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    YS: WeakSharedValue + CustomArray<Element = XS::Element>,
    XS: WeakSharedValue + CustomArray + Field,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
{
    // we need to initialize carry to 1 for x>=y,
    // since there are three shares 1+1+1 = 1 mod 2, so setting left = 1 and right = 1 works
    let mut carry = AdditiveShare(XS::Element::ONE, XS::Element::ONE);
    // we don't care about the subtraction, we just want the carry
    let _ = subtraction_circuit(ctx, record_id, x, y, &mut carry).await;
    Ok(carry)
}

/// Comparison operation
/// outputs x>y
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn compare_gt<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
) -> Result<AdditiveShare<XS::Element>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    YS: WeakSharedValue + CustomArray<Element = XS::Element>,
    XS: WeakSharedValue + CustomArray + Field,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
{
    // we need to initialize carry to 0 for x>y
    let mut carry = AdditiveShare::<XS::Element>::ZERO;
    // we don't care about the subtraction, we just want the carry
    let _ = subtraction_circuit(ctx, record_id, x, y, &mut carry).await;
    Ok(carry)
}

/// non-saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored)
/// when y>x, it computes `(x+"XS::MaxValue")-y`
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn integer_sub<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
) -> Result<AdditiveShare<XS>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    YS: WeakSharedValue + CustomArray<Element = XS::Element>,
    XS: WeakSharedValue + CustomArray + Field,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
{
    // we need to initialize carry to 1 for a subtraction
    let mut carry = AdditiveShare(XS::Element::ONE, XS::Element::ONE);
    subtraction_circuit(ctx, record_id, x, y, &mut carry).await
}

/// saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (we dont seem to need support for different length)
/// when y>x, it outputs 0
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn integer_sat_sub<C, S>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<S>,
    y: &AdditiveShare<S>,
) -> Result<AdditiveShare<S>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<S>: IntoIterator<Item = AdditiveShare<S::Element>>,
    S: CustomArray + Field,
    S::Element: Field + std::ops::Not<Output = S::Element>,
{
    let mut carry = AdditiveShare(S::Element::ONE, S::Element::ONE);
    let result = subtraction_circuit(
        ctx.narrow(&Step::SaturatedSubtraction),
        record_id,
        x,
        y,
        &mut carry,
    )
    .await?;

    // carry computes carry=(x>=y)
    // if carry==0 {all 0 array, i.e. Array[carry]} else {result}:
    // compute (1-carry)*Array[carry]+carry*result =carry*result
    AdditiveShare::<S>::expand(&carry)
        .multiply(&result, ctx.narrow(&Step::MultiplyWithCarry), record_id)
        .await
}

/// subtraction using bit subtractor
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored)
/// implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1/3.2
///
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
async fn subtraction_circuit<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
    carry: &mut AdditiveShare<XS::Element>,
) -> Result<AdditiveShare<XS>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    XS: WeakSharedValue + CustomArray,
    YS: WeakSharedValue + CustomArray<Element = XS::Element>,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
{
    let mut result = AdditiveShare::<XS>::ZERO;
    for (i, v) in x.into_iter().enumerate() {
        result.set(
            i,
            bit_subtractor(
                ctx.narrow(&BitOpStep::from(i)),
                record_id,
                &v,
                y.get(i).as_ref(),
                carry,
            )
            .await?,
        );
    }

    Ok(result)
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
#[cfg(all(test, unit_test))]
async fn bit_subtractor<C, S>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<S>,
    y: Option<&AdditiveShare<S>>,
    carry: &mut AdditiveShare<S>,
) -> Result<AdditiveShare<S>, Error>
where
    C: Context,
    S: Field + std::ops::Not<Output = S>,
{
    let output = x + !(y.unwrap_or(&AdditiveShare::<S>::ZERO) + &*carry);

    *carry = &*carry
        + (x + &*carry)
            .multiply(
                &(!(y.unwrap_or(&AdditiveShare::<S>::ZERO) + &*carry)),
                ctx,
                record_id,
            )
            .await?;

    Ok(output)
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA32, BA64},
            Expand, Field,
        },
        protocol,
        protocol::{
            context::Context,
            ipa_prf::boolean_ops::comparison_and_subtraction_low_com::{
                compare_geq, compare_gt, integer_sat_sub, integer_sub,
            },
        },
        rand::thread_rng,
        secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    /// testing correctness of Not
    /// just because we need it for subtractions
    #[test]
    fn test_not() {
        assert_eq!(<Boolean>::ONE, !(<Boolean>::ZERO));
        assert_eq!(<Boolean>::ZERO, !(<Boolean>::ONE));
        assert_eq!(
            AdditiveShare(<Boolean>::ZERO, <Boolean>::ZERO),
            !AdditiveShare(<Boolean>::ONE, <Boolean>::ONE)
        );
        assert_eq!(
            AdditiveShare(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            !AdditiveShare(
                <BA64>::expand(&<Boolean>::ONE),
                <BA64>::expand(&<Boolean>::ONE)
            )
        );
        assert_eq!(
            !AdditiveShare(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            AdditiveShare(
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
                    compare_geq::<_, BA64, BA64>(
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
                    compare_geq::<_, BA64, BA64>(
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
                    compare_gt::<_, BA64, BA64>(
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
                    compare_gt::<_, BA64, BA64>(
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
                    integer_sub::<_, BA64, BA64>(
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
                    integer_sat_sub::<_, BA64>(
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
                    integer_sub::<_, BA64, BA32>(
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
