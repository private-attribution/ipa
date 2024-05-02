use std::{borrow::Borrow, convert::Infallible, ops::Neg};

use ipa_macros::Step;

use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean, boolean_array::BA256, ec_prime_field::Fp25519, ArrayAccess,
        ArrayAccessRef, ArrayBuild, ArrayBuilder, CustomArray, Expand,
    },
    helpers::Role,
    protocol::{
        basics::{partial_reveal, BooleanProtocols},
        context::Context,
        ipa_prf::boolean_ops::addition_sequential::integer_add,
        prss::{FromPrss, SharedRandomness},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        FieldSimd, SharedValue, SharedValueArray, TransposeFrom, Vectorizable,
    },
};

#[derive(Step)]
pub(crate) enum Step {
    GenerateSecretSharing,
    IntegerAddBetweenMasks,
    IntegerAddMaskToX,
    #[dynamic(256)]
    RevealY(usize),
}

/// share conversion
/// from Boolean array of size n to integer mod p, where p is modulus of elliptic curve field `Fp25519`
/// We follow the ABY3 (`https://eprint.iacr.org/2018/403.pdf`)
/// however ABY does not directly allow to convert into integers `mod p` for a prime `p` only to integers `mod 2^n`
///
/// We first explain standard ABY:
/// We convert a Boolean Sharing of `x` to an Arithmetic Sharing of `x` in `Fp25519` as follows:
/// sample random Boolean Sharing `sh_r` of `r`, set share `r_1`, `r_2` to `0` (i.e. `H1` will not know `r = r3`)
/// sample random Boolean Sharing `sh_s` of `s`, set share `r_2`, `r_3` to `0` (i.e. `H2` will not know `s = r1`)
/// compute integer addition of `x`,`r`,`s`: `y = x + (r + s)` in MPC using the Boolean shares
/// reveal `y` to `H1`, `H2`
/// new shares are `H1`: `(-s, y)`, `H2`: `(y, -r)`, `H3`: `(-r,-s)`
/// this is correct since:
/// `r + s + y = r + s + x - r - s = x`
///
///
/// We now adjust the ABY strategy to work for conversion into `Fp25519`
/// This can only be used securely to convert `BAt` to `Fp25519`,
/// where t < 256 - statistical security parameter due to leakage
///
/// leakage free alternative needs secure mod p operation after each addition
/// (which can be performed using secure subtraction)
///
/// The high level idea is to use small enough masks `r` and `s`
/// such that when adding them to a small enough `x` it holds that `x + r + s = (x + r + s mod 2^256)`.
/// once we have computed shares of `y = (x + r + s mod 2^256)`
/// we can compute `y mod p = (x + r + s mod 2^256) mod p = x + r + s mod p` to get shares in `Fp25519`.
/// Since the masks are small, it causes leakage.
///
/// we use a `BA256` for masks `r`, `s` and set the two most significant bits to `0`.
/// this allows us to compute Boolean shares of `r + s` such that `r + s = (r + s mod 2^256)`
/// further it allows us to compute `x + r + s` such that `x + r + s = (x + r + s mod 2^256)`
///
/// We can then reveal `y = x+r+s` via `partial_reveal` and then compute `y mod p`.
///
/// In the process, we need to make sure that highest order `PRSS` masks added by `multiply`
/// are set to zero since otherwise `rs = r + s` would be large and thus
/// `x + rs = (x + r + s mod 2^256)` would not hold anymore when `x + rs > 2^256`.
///
/// Using small masks `r`, `s` leaks information about `x`.
/// This is ok because of the following analysis:
/// assuming `x` has `m` bits,
/// revealing `y = x + rs` (where `rs = r + s`) leaks the following information
///
/// (see `bit_adder` in `protocol::ipa_prf::boolean_ops::addition_low_com::integer_add`):
/// `y_{m} := rs_{m} xor x_{m} xor carry_x`
/// where `x_{m}` is `0` and `carry_x` is `carry_{m-1}` which contains information about `x`
/// The goal is to hide `carry_x` sufficiently using the higher order bits of mask `rs`.
/// Recap that the carries are defined as
/// `carry_{i} = carry_{i-1} xor (x_{i-1} xor carry_{i-1})(y_{i-1} xor carry_{i-1})`
/// Further it holds that:
/// for all `i` where `x_{i-1}=0`: `carry{i} = carry{i-1}y{i-1}`
///
/// Notice that for `j>=0` mask `rs_{m+j}` hides `carry_x`:
/// `y_{m+j} := rs_{m+j} xor (carry_x * product_(k=m)^(m+j-1)rs{k})`
///
/// Thus, the only leakage about `carry_x` happens in bits `255` and `254` where `rs{255}=0` and `rs{254}=0`:
/// `y_{255} := carry_x * product_(k=m)^(255)rs{k})`
/// `y_{254} := carry_x * product_(k=m)^(254)rs{k})`
///
/// However, these terms are only non-zero when all `rs_{k}` terms are non-zero
/// this happens with probability `1/(2^(256-m))` which is negligible for a sufficiently small `m`
///
/// The implementation uses two type parameters to support vectorization. The type `XS` holds match
/// keys. In the unvectorized case, `XS` is `AdditiveShare<BA64>`. In the vectorized case, `XS` is
/// `BitDecomposed<AdditiveShare<BA{N}>>`. The type `YS` holds bitwise Fp25519 intermediates. In the
/// unvectorized case, `YS` is `AdditiveShare<BA256>`. In the vectorized case, `YS` is
/// `BitDecomposed<AdditiveShare<BA{n}>>`.
///
/// # Errors
/// Propagates Errors from Integer Subtraction and Partial Reveal
pub async fn convert_to_fp25519<C, XS, YS, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: XS,
) -> Result<AdditiveShare<Fp25519, N>, Error>
where
    C: Context,
    Fp25519: Vectorizable<N>,
    Boolean: FieldSimd<N>,
    XS: ArrayAccessRef<Element = AdditiveShare<Boolean, N>>,
    YS: ArrayAccessRef<Element = AdditiveShare<Boolean, N>>
        + ArrayBuild<Input = AdditiveShare<Boolean, N>>
        + FromPrss<usize>,
    AdditiveShare<Boolean, N>: BooleanProtocols<C, Boolean, N>,
    Vec<AdditiveShare<BA256>>: for<'a> TransposeFrom<&'a YS>,
    Vec<BA256>:
        for<'a> TransposeFrom<&'a [<Boolean as Vectorizable<N>>::Array; 256], Error = Infallible>,
{
    // `BITS` is the number of bits in the memory representation of Fp25519 field elements. It does
    // not vary with vectorization. Where the type `BA256` appears literally in the source of this
    // function, it is referring to this constant. (It is also possible for `BA256` to be used to
    // hold width-256 vectorizations, but when it serves that purpose, it does not appear literally
    // in the source of this function -- it is behind the XS and YS parameters.)
    const BITS: usize = 256;

    // Ensure that the probability of leaking information is less than 1/(2^128).
    debug_assert!(x.iter().count() < (BITS - 128));

    // generate sh_r = (0, 0, sh_r) and sh_s = (sh_s, 0, 0)
    // the two highest bits are set to 0 to allow carries for two additions
    let (sh_r, sh_s) =
        gen_sh_r_and_sh_s::<_, _, BITS, N>(&ctx.narrow(&Step::GenerateSecretSharing), record_id);

    // addition r+s might cause carry,
    // this is no problem since we have set bit 254 of sh_r and sh_s to 0
    let sh_rs = {
        let (mut rs_with_higherorderbits, _) = integer_add::<_, _, YS, YS, N>(
            ctx.narrow(&Step::IntegerAddBetweenMasks),
            record_id,
            &sh_r,
            &sh_s,
        )
        .await?;

        // PRSS/Multiply masks added random highest order bit,
        // remove them to not cause overflow in second addition (which is mod 256):
        rs_with_higherorderbits.set(BITS - 1, YS::make_ref(&AdditiveShare::<Boolean, N>::ZERO));

        // return rs
        rs_with_higherorderbits
    };

    // addition x+rs, where rs=r+s might cause carry
    // this is not a problem since bit 255 of rs is set to 0
    let (sh_y, _) =
        integer_add::<_, _, YS, XS, N>(ctx.narrow(&Step::IntegerAddMaskToX), record_id, &sh_rs, &x)
            .await?;

    // this leaks information, but with negligible probability
    let mut y = (ctx.role() != Role::H3).then(|| Vec::with_capacity(N));
    for i in 0..BITS {
        let y_bit = partial_reveal(
            ctx.narrow(&Step::RevealY(i)),
            record_id,
            Role::H3,
            sh_y.get(i).unwrap().borrow(),
        )
        .await?;
        match (&mut y, y_bit) {
            (Some(y), Some(y_bit)) => y.push(y_bit),
            (None, None) => (),
            _ => unreachable!("inconsistent partial_reveal behavior"),
        }
    }

    let y = y.map(|y| {
        Vec::<BA256>::transposed_from(y.as_slice().try_into().unwrap()).unwrap_infallible()
    });

    let sh_r = Vec::<AdditiveShare<BA256>>::transposed_from(&sh_r)
        .ok()
        .expect("sh_r was constructed with the correct number of bits");
    let sh_s = Vec::<AdditiveShare<BA256>>::transposed_from(&sh_s)
        .ok()
        .expect("sh_s was constructed with the correct number of bits");

    match ctx.role() {
        Role::H1 => Ok(AdditiveShare::<Fp25519, N>::new_arr(
            <Fp25519 as Vectorizable<N>>::Array::from_fn(|i| {
                Fp25519::from(sh_s.get(i).unwrap().left()).neg()
            }),
            y.unwrap().into_iter().map(Fp25519::from).collect(),
        )),
        Role::H2 => Ok(AdditiveShare::<Fp25519, N>::new_arr(
            y.unwrap().into_iter().map(Fp25519::from).collect(),
            <Fp25519 as Vectorizable<N>>::Array::from_fn(|i| {
                Fp25519::from(sh_r.get(i).unwrap().right()).neg()
            }),
        )),
        Role::H3 => Ok(AdditiveShare::<Fp25519, N>::new_arr(
            <Fp25519 as Vectorizable<N>>::Array::from_fn(|i| {
                Fp25519::from(sh_r.get(i).unwrap().left()).neg()
            }),
            <Fp25519 as Vectorizable<N>>::Array::from_fn(|i| {
                Fp25519::from(sh_s.get(i).unwrap().right()).neg()
            }),
        )),
    }
}

/// Generates `sh_r` and `sh_s` from PRSS randomness (`r`).
fn gen_sh_r_and_sh_s<C, YS, const BITS: usize, const N: usize>(
    ctx: &C,
    record_id: RecordId,
) -> (YS, YS)
where
    C: Context,
    Boolean: FieldSimd<N>,
    YS: ArrayAccessRef<Element = AdditiveShare<Boolean, N>>
        + ArrayBuild<Input = AdditiveShare<Boolean, N>>
        + FromPrss<usize>,
{
    // we generate random values r = (r1,r2,r3) using PRSS
    // r: H1: (r1,r2), H2: (r2,r3), H3: (r3, r1)
    let mut r: YS = ctx.prss().generate_with(record_id, BITS);

    // set 2 highest order bits of r1, r2, r3 to 0
    r.set(BITS - 1, YS::make_ref(&AdditiveShare::<Boolean, N>::ZERO));
    r.set(BITS - 2, YS::make_ref(&AdditiveShare::<Boolean, N>::ZERO));

    let mut sh_r_builder = YS::builder().with_capacity(BITS);
    let mut sh_s_builder = YS::builder().with_capacity(BITS);
    // generate sh_r, sh_s
    // sh_r: H1: (0,0), H2: (0,r3), H3: (r3, 0)
    // sh_s: H1: (r1,0), H2: (0,0), H3: (0, r1)
    match ctx.role() {
        Role::H1 => {
            for i in 0..BITS {
                sh_r_builder.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
                sh_s_builder.push(AdditiveShare::new_arr(
                    r.get(i).unwrap().borrow().left_arr().clone(),
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
            }
        }
        Role::H2 => {
            for i in 0..BITS {
                sh_r_builder.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    r.get(i).unwrap().borrow().right_arr().clone(),
                ));
                sh_s_builder.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
            }
        }
        Role::H3 => {
            for i in 0..BITS {
                sh_r_builder.push(AdditiveShare::new_arr(
                    r.get(i).unwrap().borrow().left_arr().clone(),
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
                sh_s_builder.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    r.get(i).unwrap().borrow().right_arr().clone(),
                ));
            }
        }
    }
    (sh_r_builder.build(), sh_s_builder.build())
}

/// inserts smaller array in the larger array starting from location offset
pub fn expand_shared_array_in_place<YS, XS>(
    y: &mut AdditiveShare<YS>,
    x: &AdditiveShare<XS>,
    offset: usize,
) where
    YS: CustomArray<Element = Boolean> + SharedValue,
    XS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    for i in 0..XS::BITS as usize {
        ArrayAccess::set(
            y,
            i + offset,
            ArrayAccess::get(x, i).unwrap_or(AdditiveShare::<Boolean>::ZERO),
        );
    }
}

// This function extracts shares of a small array from the larger array
pub fn extract_from_shared_array<YS, XS>(y: &AdditiveShare<YS>, offset: usize) -> AdditiveShare<XS>
where
    YS: CustomArray<Element = Boolean> + SharedValue,
    XS: SharedValue + ArrayAccess<Output = Boolean> + Expand<Input = Boolean>,
{
    let mut x = AdditiveShare::<XS>::ZERO;
    for i in 0..XS::BITS as usize {
        ArrayAccess::set(
            &mut x,
            i,
            ArrayAccess::get(y, i + offset).unwrap_or(AdditiveShare::<Boolean>::ZERO),
        );
    }
    x
}

/// inserts a smaller array into a larger
/// allows conversion between Boolean Array types like 'BA64' and 'BA256'
/// we don't use it right except for testing purposes
#[cfg(all(test, unit_test))]
pub fn expand_array<XS, YS>(x: &XS, offset: Option<usize>) -> YS
where
    XS: CustomArray,
    YS: CustomArray<Element = XS::Element> + SharedValue,
    XS::Element: SharedValue,
{
    let mut y = YS::ZERO;
    for i in 0..<YS>::BITS as usize {
        y.set(
            i,
            x.get(i - (offset.unwrap_or(0usize)))
                .unwrap_or(XS::Element::ZERO),
        );
    }
    y
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::repeat_with;

    use curve25519_dalek::Scalar;
    use futures::stream::TryStreamExt;
    use generic_array::GenericArray;
    use rand::Rng;
    use typenum::U32;

    use super::*;
    use crate::{
        ff::{boolean_array::BA64, Serializable},
        helpers::stream::{process_slice_by_chunks, TryFlattenItersExt},
        protocol::{context::SemiHonestContext, ipa_prf::MK_BITS},
        rand::thread_rng,
        seq_join::{seq_join, SeqJoin},
        test_executor::run,
        test_fixture::{ReconstructArr, Runner, TestWorld},
        BoolVector,
    };

    fn test_semi_honest_convert_into_fp25519<XS, YS, const COUNT: usize, const CHUNK: usize>()
    where
        Fp25519: Vectorizable<CHUNK>,
        Boolean: FieldSimd<CHUNK>,
        XS: ArrayAccessRef<Element = AdditiveShare<Boolean, CHUNK>>
            + ArrayBuild<Input = AdditiveShare<Boolean, CHUNK>>
            + for<'a> TransposeFrom<&'a [AdditiveShare<BA64>; CHUNK], Error = Infallible>
            + Send
            + Sync
            + 'static,
        YS: ArrayAccessRef<Element = AdditiveShare<Boolean, CHUNK>>
            + ArrayBuild<Input = AdditiveShare<Boolean, CHUNK>>
            + FromPrss<usize>
            + Send
            + Sync
            + 'static,
        for<'a> <XS as ArrayAccessRef>::Ref<'a>: Send,
        for<'a> <YS as ArrayAccessRef>::Ref<'a>: Send,
        AdditiveShare<Boolean, CHUNK>:
            for<'a> BooleanProtocols<SemiHonestContext<'a>, Boolean, CHUNK>,
        Vec<AdditiveShare<BA256>>: for<'a> TransposeFrom<&'a YS>,
        Vec<BA256>: for<'a> TransposeFrom<
            &'a [<Boolean as Vectorizable<CHUNK>>::Array; 256],
            Error = Infallible,
        >,
        [AdditiveShare<Fp25519, CHUNK>; 3]: ReconstructArr<<Fp25519 as Vectorizable<CHUNK>>::Array>,
    {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records = repeat_with(|| rng.gen::<BA64>())
                .take(COUNT)
                .collect::<Vec<_>>();

            let expected = records
                .iter()
                .map(|record| {
                    let mut buf: GenericArray<u8, U32> = [0u8; 32].into();
                    expand_array::<BA64, BA256>(record, None).serialize(&mut buf);
                    Fp25519::from(<Scalar>::from_bytes_mod_order(<[u8; 32]>::from(buf)))
                })
                .collect::<Vec<_>>();

            let [res0, res1, res2] = world
                .semi_honest(records.into_iter(), |ctx, records| async move {
                    #[cfg(not(debug_assertions))]
                    let begin = std::time::Instant::now();
                    let res: Result<Vec<AdditiveShare<Fp25519>>, Error> = seq_join(
                        ctx.active_work(),
                        process_slice_by_chunks(
                            &records,
                            |idx, chunk| {
                                let ctx = ctx.clone();
                                async move {
                                    let mut match_keys_builder = XS::builder();
                                    for _ in 0..MK_BITS {
                                        match_keys_builder
                                            .push(AdditiveShare::<Boolean, CHUNK>::ZERO);
                                    }
                                    let mut match_keys = match_keys_builder.build();
                                    match_keys.transpose_from(&chunk).unwrap_infallible();
                                    convert_to_fp25519::<_, XS, YS, CHUNK>(
                                        ctx.set_total_records((COUNT + CHUNK - 1) / CHUNK),
                                        RecordId::from(idx),
                                        match_keys,
                                    )
                                    .await
                                    .map(|shares| {
                                        shares
                                            .into_unpacking_iter()
                                            .collect::<Vec<_>>()
                                            .try_into()
                                            .unwrap()
                                    })
                                }
                            },
                            || AdditiveShare::<BA64>::ZERO,
                        ),
                    )
                    .try_flatten_iters()
                    .try_collect()
                    .await;
                    #[cfg(not(debug_assertions))]
                    tracing::info!("Execution time: {:?}", begin.elapsed());
                    res
                })
                .await
                .map(Result::unwrap);
            let mut result = Vec::with_capacity(COUNT);
            for line in res0.into_iter().zip(res1).zip(res2) {
                let ((s0, s1), s2) = line;
                result.extend([s0, s1, s2].reconstruct_arr().into_iter());
            }
            assert_eq!(result, expected);
        });
    }

    // The third generic parameter in these calls is the number of conversions. It is set to give
    // reasonable runtime for debug builds. These can also be used for benchmarking, in which case
    // a size of 4096 is reasonable.

    #[test]
    fn semi_honest_convert_into_fp25519_novec() {
        test_semi_honest_convert_into_fp25519::<BoolVector!(64, 1), BoolVector!(256, 1), 2, 1>();
    }

    #[test]
    fn semi_honest_convert_into_fp25519_vec64() {
        test_semi_honest_convert_into_fp25519::<BoolVector!(64, 64), BoolVector!(256, 64), 65, 64>(
        );
    }

    #[test]
    fn test_expand() {
        let mut rng = thread_rng();

        let a = rng.gen::<BA64>();

        let b = expand_array::<_, BA256>(&a, None);

        for i in 0..BA256::BITS as usize {
            assert_eq!(
                (i, b.get(i).unwrap_or(Boolean::ZERO)),
                (i, a.get(i).unwrap_or(Boolean::ZERO))
            );
        }
    }
}
