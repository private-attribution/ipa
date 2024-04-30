use std::{borrow::Borrow, iter::repeat};

#[cfg(all(test, unit_test))]
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{ArrayAccessRef, ArrayBuild, ArrayBuilder, Field},
    protocol::{
        basics::{BooleanProtocols, SecureMul},
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

/// Non-saturated unsigned integer addition
/// This function adds y to x.
/// The output has same length as x.
/// Indices of y beyond the length of x are ignored, but
/// the final carry is returned
///
/// # Errors
/// propagates errors from multiply
pub async fn integer_add<C, F, XS, YS, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &XS,
    y: &YS,
) -> Result<(XS, AdditiveShare<F, N>), Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    XS: ArrayAccessRef<Element = AdditiveShare<F, N>> + ArrayBuild<Input = AdditiveShare<F, N>>,
    YS: ArrayAccessRef<Element = AdditiveShare<F, N>>,
    AdditiveShare<F, N>: BooleanProtocols<C, F, N>,
{
    let mut carry = AdditiveShare::<F, N>::ZERO;
    let sum = addition_circuit(ctx, record_id, x, y, &mut carry).await?;
    Ok((sum, carry))
}

/// saturated unsigned integer addition
/// currently not used, but it is tested
/// adds y to x, Output has same length as x (we dont seem to need support for different length)
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn integer_sat_add<S>(
    ctx: SemiHonestContext<'_>,
    record_id: RecordId,
    x: &AdditiveShare<S>,
    y: &AdditiveShare<S>,
) -> Result<AdditiveShare<S>, Error>
where
    S: SharedValue + CustomArray<Element = Boolean>,
    AdditiveShare<S>: BooleanArrayMul + std::ops::Not<Output = AdditiveShare<S>>,
{
    #[derive(Step)]
    enum Step {
        Add,
        Select,
    }

    let mut carry = AdditiveShare::<Boolean>::ZERO;
    let result = addition_circuit(ctx.narrow(&Step::Add), record_id, x, y, &mut carry).await?;

    // if carry==1 then {all ones} else {result}
    select(
        ctx.narrow(&Step::Select),
        record_id,
        &carry,
        &!AdditiveShare::<S>::ZERO,
        &result,
    )
    .await
}

/// addition using bit adder
/// adds y to x, Output has same length as x (carries and indices of y too large for x are ignored)
/// implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1
/// for all i: output[i] = x[i] + (c[i-1] + y[i])
/// # Errors
/// propagates errors from multiply
///
///
async fn addition_circuit<C, F, XS, YS, const N: usize>(
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
            bit_adder(
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

///
/// This one-bit adder that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
///
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `sum_bit` can be efficiently computed as just `s_i = x_i ⊕ y_i ⊕ c_i`
/// This can be computed "for free" in Gf2
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) & (y_i ⊕ c_i))`
///
/// Returns `sum_bit`
///
/// The mutable refernce to `carry` is mutated to take on the value of the `carry_out` bit
///
/// # Errors
/// propagates errors from multiply
async fn bit_adder<C, F, const N: usize>(
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
    let output = x + y + &*carry;

    *carry = &*carry
        + (x + &*carry)
            .multiply(&(y + &*carry), ctx, record_id)
            .await?;

    Ok(output)
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use crate::{
        ff::{
            boolean_array::{BA32, BA64},
            U128Conversions,
        },
        protocol,
        protocol::{
            context::Context,
            ipa_prf::boolean_ops::addition_sequential::{integer_add, integer_sat_add},
        },
        rand::thread_rng,
        secret_sharing::replicated::semi_honest::AdditiveShare,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    /// testing correctness of addition
    #[test]
    fn semi_honest_add() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba64 = rng.gen::<BA64>();
            let y_ba64 = rng.gen::<BA64>();
            let x = x_ba64.as_u128();
            let y = y_ba64.as_u128();

            let expected = (x + y) % (1 << 64);
            let expected_carry = (x + y) >> 64 & 1;

            let (result, carry) = world
                .semi_honest((x_ba64, y_ba64), |ctx, x_y| async move {
                    integer_add::<_, _, AdditiveShare<BA64>, AdditiveShare<BA64>, 1>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );
        });
    }

    #[test]
    fn semi_honest_sat_add() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba64 = rng.gen::<BA64>();
            let y_ba64 = rng.gen::<BA64>();
            let x = x_ba64.as_u128();
            let y = y_ba64.as_u128();
            let z = 1_u128 << 64;

            let expected = if x + y > z { z - 1 } else { (x + y) % z };

            let result = world
                .semi_honest((x_ba64, y_ba64), |ctx, x_y| async move {
                    integer_sat_add::<_>(
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
            assert_eq!((x, y, z, result), (x, y, z, expected));
        });
    }

    #[test]
    fn semi_honest_add_differing_lengths() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let x_ba64 = rng.gen::<BA64>();
            let y_ba32 = rng.gen::<BA32>();
            let x = x_ba64.as_u128();
            let y = y_ba32.as_u128();

            let expected = (x + y) % (1 << 64);
            let expected_carry = (x + y) >> 64 & 1;

            let (result, carry) = world
                .semi_honest((x_ba64, y_ba32), |ctx, x_y| async move {
                    integer_add::<_, _, AdditiveShare<BA64>, AdditiveShare<BA32>, 1>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );

            let x = x & ((1 << 32) - 1);
            let expected = (x + y) % (1 << 32);
            let expected_carry = (x + y) >> 32 & 1;
            let (result, carry) = world
                .semi_honest((y_ba32, x_ba64), |ctx, x_y| async move {
                    integer_add::<_, _, AdditiveShare<BA32>, AdditiveShare<BA64>, 1>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(
                (x, y, result.as_u128(), carry.as_u128()),
                (x, y, expected, expected_carry)
            );
        });
    }
}
