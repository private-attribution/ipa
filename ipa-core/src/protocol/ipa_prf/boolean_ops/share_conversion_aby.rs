use std::{convert::Infallible, iter::zip, ops::Neg};

use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA256},
        ec_prime_field::Fp25519,
        ArrayAccess,
    },
    helpers::Role,
    protocol::{
        basics::{validated_partial_reveal, BooleanProtocols},
        boolean::step::TwoHundredFiftySixBitOpStep,
        context::{Context, DZKPContext},
        ipa_prf::boolean_ops::{
            addition_sequential::integer_add, step::Fp25519ConversionStep as Step,
        },
        prss::{FromPrss, SharedRandomness},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, SharedValueArray, TransposeFrom, Vectorizable,
    },
};

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
/// `NC` is the share conversion vectorization dimension, and `NP` is the PRF vectorization
/// dimension. Most of this routine works at `NC`. The final packing in `output_shares` converts to
/// a vector of (NC / NP) shares, each with dimension `NP`.
///
/// # Errors
/// Propagates Errors from Integer Subtraction, Partial Reveal and Validate
/// # Panics
/// If values processed by this function is smaller than 256 bits.
/// If vectorization is too large, i.e. `NC>=100k`.
pub async fn convert_to_fp25519<C, const NC: usize, const NP: usize>(
    ctx: C,
    record_id: RecordId,
    input_shares: BitDecomposed<AdditiveShare<Boolean, NC>>,
) -> Result<Vec<AdditiveShare<Fp25519, NP>>, Error>
where
    C: DZKPContext,
    Fp25519: Vectorizable<NP>,
    Boolean: FieldSimd<NC>,
    BitDecomposed<AdditiveShare<Boolean, NC>>: FromPrss<usize>,
    AdditiveShare<Boolean, NC>: BooleanProtocols<C, NC>,
    Vec<AdditiveShare<BA256>>: for<'a> TransposeFrom<&'a BitDecomposed<AdditiveShare<Boolean, NC>>>,
    Vec<BA256>:
        for<'a> TransposeFrom<&'a [<Boolean as Vectorizable<NC>>::Array; 256], Error = Infallible>,
{
    // `BITS` is the number of bits in the memory representation of Fp25519 field elements. It does
    // not vary with vectorization. Where the type `BA256` appears literally in the source of this
    // function, it is referring to this constant. (It is also possible for `BA256` to be used to
    // hold width-256 vectorizations, but when it serves that purpose, it does not appear literally
    // in the source of this function -- it is behind the NC parameter.)
    const BITS: usize = 256;

    assert!(
        NC % NP == 0,
        "conversion chunk should be a multiple of PRF chunk"
    );

    // Ensure that the probability of leaking information is less than 1/(2^128).
    debug_assert!(input_shares.iter().count() < (BITS - 128));

    // generate sh_r = (0, 0, sh_r) and sh_s = (sh_s, 0, 0)
    // the two highest bits are set to 0 to allow carries for two additions
    let (sh_r, sh_s) =
        gen_sh_r_and_sh_s::<_, BITS, NC>(&ctx.narrow(&Step::GenerateSecretSharing), record_id);

    // addition r+s might cause carry,
    // this is no problem since we have set bit 254 of sh_r and sh_s to 0
    let sh_rs = {
        let (mut rs_with_higherorderbits, _) = integer_add::<_, TwoHundredFiftySixBitOpStep, NC>(
            ctx.narrow(&Step::IntegerAddBetweenMasks),
            record_id,
            &sh_r,
            &sh_s,
        )
        .await?;

        // PRSS/Multiply masks added random highest order bit,
        // remove them to not cause overflow in second addition (which is mod 256):
        rs_with_higherorderbits[BITS - 1] = AdditiveShare::<Boolean, NC>::ZERO;

        // return rs
        rs_with_higherorderbits
    };

    // addition x+rs, where rs=r+s might cause carry
    // this is not a problem since bit 255 of rs is set to 0
    let (sh_y, _) = integer_add::<_, TwoHundredFiftySixBitOpStep, NC>(
        ctx.narrow(&Step::IntegerAddMaskToX),
        record_id,
        &sh_rs,
        &input_shares,
    )
    .await?;

    // validate and reveal
    // this leaks information, but with negligible probability
    let y =
        validated_partial_reveal(ctx.narrow(&Step::RevealY), record_id, Role::H3, &sh_y).await?;

    let y = y.map(|y| {
        Vec::<BA256>::transposed_from(y.as_slice().try_into().unwrap()).unwrap_infallible()
    });

    let sh_r = Vec::<AdditiveShare<BA256>>::transposed_from(&sh_r)
        .ok()
        .expect("sh_r was constructed with the correct number of bits");
    let sh_s = Vec::<AdditiveShare<BA256>>::transposed_from(&sh_s)
        .ok()
        .expect("sh_s was constructed with the correct number of bits");

    output_shares::<_, NC, NP>(&ctx, &sh_r, &sh_s, y)
}

/// Generates `sh_r` and `sh_s` from PRSS randomness (`r`).
fn gen_sh_r_and_sh_s<C, const BITS: usize, const N: usize>(
    ctx: &C,
    record_id: RecordId,
) -> (
    BitDecomposed<AdditiveShare<Boolean, N>>,
    BitDecomposed<AdditiveShare<Boolean, N>>,
)
where
    C: Context,
    Boolean: FieldSimd<N>,
    BitDecomposed<AdditiveShare<Boolean, N>>: FromPrss<usize>,
{
    // we generate random values r = (r1,r2,r3) using PRSS
    // r: H1: (r1,r2), H2: (r2,r3), H3: (r3, r1)
    let mut r: BitDecomposed<AdditiveShare<Boolean, N>> = ctx.prss().generate_with(record_id, BITS);

    // set 2 highest order bits of r1, r2, r3 to 0
    r[BITS - 1] = AdditiveShare::<Boolean, N>::ZERO;
    r[BITS - 2] = AdditiveShare::<Boolean, N>::ZERO;

    let mut sh_r = BitDecomposed::<AdditiveShare<Boolean, N>>::with_capacity(BITS);
    let mut sh_s = BitDecomposed::<AdditiveShare<Boolean, N>>::with_capacity(BITS);
    // generate sh_r, sh_s
    // sh_r: H1: (0,0), H2: (0,r3), H3: (r3, 0)
    // sh_s: H1: (r1,0), H2: (0,0), H3: (0, r1)
    match ctx.role() {
        Role::H1 => {
            for i in 0..BITS {
                sh_r.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
                sh_s.push(AdditiveShare::new_arr(
                    r.get(i).unwrap().left_arr().clone(),
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
            }
        }
        Role::H2 => {
            for i in 0..BITS {
                sh_r.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    r.get(i).unwrap().right_arr().clone(),
                ));
                sh_s.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
            }
        }
        Role::H3 => {
            for i in 0..BITS {
                sh_r.push(AdditiveShare::new_arr(
                    r.get(i).unwrap().left_arr().clone(),
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                ));
                sh_s.push(AdditiveShare::new_arr(
                    <Boolean as Vectorizable<N>>::Array::ZERO_ARRAY,
                    r.get(i).unwrap().right_arr().clone(),
                ));
            }
        }
    }
    (sh_r, sh_s)
}

/// Select output share values from `sh_r`, `sh_s`, and `y`, depending on which helper we are.
///
/// Because the PRF vectorization dimension (NP) may be smaller than the share conversion
/// vectorization dimension (NC), this routine also re-chunks the outputs into (NC / NP) chunks of
/// NP records.
fn output_shares<C, const NC: usize, const NP: usize>(
    ctx: &C,
    sh_r: &[AdditiveShare<BA256>],
    sh_s: &[AdditiveShare<BA256>],
    y: Option<Vec<BA256>>,
) -> Result<Vec<AdditiveShare<Fp25519, NP>>, Error>
where
    C: Context,
    Fp25519: Vectorizable<NP>,
{
    let (left, right): (Vec<Vec<Fp25519>>, Vec<Vec<Fp25519>>) = match ctx.role() {
        Role::H1 => sh_s
            .chunks(NP)
            .zip(y.expect("y was revealed to H1").chunks(NP))
            .map(|(sh_s, y)| {
                (
                    sh_s.iter()
                        .map(|sh_s| Fp25519::from(sh_s.left()).neg())
                        .collect(),
                    y.iter().map(|&y| Fp25519::from(y)).collect(),
                )
            })
            .unzip(),
        Role::H2 => y
            .expect("y was revealed to H1")
            .chunks(NP)
            .zip(sh_r.chunks(NP))
            .map(|(y, sh_r)| {
                (
                    y.iter().map(|&y| Fp25519::from(y)).collect(),
                    sh_r.iter()
                        .map(|sh_r| Fp25519::from(sh_r.right()).neg())
                        .collect(),
                )
            })
            .unzip(),
        Role::H3 => sh_r
            .chunks(NP)
            .zip(sh_s.chunks(NP))
            .map(|(sh_r, sh_s)| {
                (
                    sh_r.iter()
                        .map(|sh_r| Fp25519::from(sh_r.left()).neg())
                        .collect(),
                    sh_s.iter()
                        .map(|sh_s| Fp25519::from(sh_s.right()).neg())
                        .collect(),
                )
            })
            .unzip(),
    };

    let mut results = Vec::with_capacity(NC / NP);
    for (left, right) in zip(left, right) {
        results.push(AdditiveShare::<Fp25519, NP>::new_arr(
            <Fp25519 as Vectorizable<NP>>::Array::try_from(left)?,
            <Fp25519 as Vectorizable<NP>>::Array::try_from(right)?,
        ));
    }
    Ok(results)
}

/// inserts smaller array in the larger array starting from location offset
pub fn expand_shared_array_in_place<YS: BooleanArray, XS: BooleanArray>(
    y: &mut AdditiveShare<YS>,
    x: &AdditiveShare<XS>,
    offset: usize,
) {
    for i in 0..XS::BITS as usize {
        ArrayAccess::set(
            y,
            i + offset,
            ArrayAccess::get(x, i).unwrap_or(AdditiveShare::<Boolean>::ZERO),
        );
    }
}

// This function extracts shares of a small array from the larger array
pub fn extract_from_shared_array<YS: BooleanArray, XS: BooleanArray>(
    y: &AdditiveShare<YS>,
    offset: usize,
) -> AdditiveShare<XS> {
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
    XS: BooleanArray,
    YS: BooleanArray,
{
    let mut y = YS::ZERO;
    for i in 0..<YS>::BITS as usize {
        y.set(
            i,
            x.get(i - (offset.unwrap_or(0usize)))
                .unwrap_or(Boolean::FALSE),
        );
    }
    y
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{self, repeat_n, repeat_with};

    use curve25519_dalek::Scalar;
    use futures::stream::TryStreamExt;
    use generic_array::GenericArray;
    use rand::Rng;
    use typenum::U32;

    use super::*;
    use crate::{
        ff::{boolean_array::BA64, Serializable},
        helpers::stream::process_slice_by_chunks,
        protocol::{
            context::{dzkp_validator::DZKPValidator, UpgradableContext, TEST_DZKP_STEPS},
            ipa_prf::{conv_proof_chunk, CONV_CHUNK, PRF_CHUNK},
        },
        rand::thread_rng,
        secret_sharing::SharedValue,
        seq_join::{seq_join, SeqJoin},
        test_executor::run,
        test_fixture::{ReconstructArr, Runner, TestWorld},
    };

    #[test]
    fn test_semi_honest_convert_to_fp25519() {
        run(|| async move {
            const COUNT: usize = CONV_CHUNK + 1;

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
                    let c_ctx = ctx.set_total_records((COUNT + CONV_CHUNK - 1) / CONV_CHUNK);
                    let validator = &c_ctx.dzkp_validator(TEST_DZKP_STEPS, conv_proof_chunk());
                    let m_ctx = validator.context();
                    seq_join(
                        m_ctx.active_work(),
                        process_slice_by_chunks(&records, |idx, chunk| {
                            let match_keys =
                                BitDecomposed::transposed_from(&*chunk).unwrap_infallible();
                            convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(
                                m_ctx.clone(),
                                RecordId::from(idx),
                                match_keys,
                            )
                        }),
                    )
                    .try_collect::<Vec<_>>()
                    .await
                })
                .await
                .map(|res| {
                    res.unwrap()
                        .into_iter()
                        .flat_map(|chunk| chunk.unpack::<PRF_CHUNK>().into_iter())
                        .flat_map(|chunk| chunk.map(AdditiveShare::into_unpacking_iter))
                        .collect::<Vec<_>>()
                });
            let mut result = Vec::with_capacity(COUNT);
            for line in res0.into_iter().zip(res1).zip(res2) {
                let ((s0, s1), s2) = line;
                result.extend([s0, s1, s2].reconstruct_arr().into_iter());
            }
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn test_malicious_convert_to_fp25519() {
        run(|| async move {
            // Ideally PROOF_CHUNK could be more than 1, but the test is pretty slow.
            const PROOF_CHUNK: usize = 1;
            const COUNT: usize = CONV_CHUNK * PROOF_CHUNK * 2 + 1;
            const TOTAL_RECORDS: usize = (COUNT + CONV_CHUNK - 1) / CONV_CHUNK;

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
                .malicious(records.into_iter(), |ctx, records| async move {
                    let c_ctx = ctx.set_total_records(TOTAL_RECORDS);
                    let validator = &c_ctx.dzkp_validator(TEST_DZKP_STEPS, PROOF_CHUNK);
                    let m_ctx = validator.context();
                    seq_join(
                        m_ctx.active_work(),
                        process_slice_by_chunks(&records, |idx, chunk| {
                            let match_keys =
                                BitDecomposed::transposed_from(&*chunk).unwrap_infallible();
                            convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(
                                m_ctx.clone(),
                                RecordId::from(idx),
                                match_keys,
                            )
                        }),
                    )
                    .try_collect::<Vec<_>>()
                    .await
                })
                .await
                .map(|res| {
                    res.unwrap()
                        .into_iter()
                        .flat_map(|chunk| chunk.unpack::<PRF_CHUNK>().into_iter())
                        .flat_map(|chunk| chunk.map(AdditiveShare::into_unpacking_iter))
                        .collect::<Vec<_>>()
                });
            let mut result = Vec::with_capacity(COUNT);
            for line in res0.into_iter().zip(res1).zip(res2) {
                let ((s0, s1), s2) = line;
                result.extend([s0, s1, s2].reconstruct_arr().into_iter());
            }
            assert_eq!(result, expected);
        });
    }

    #[test]
    #[should_panic(expected = "< (BITS - 128)")]
    fn convert_to_fp25519_rejects_large_match_keys() {
        run(|| async move {
            TestWorld::default()
                .semi_honest(iter::empty::<BA256>(), |ctx, _records| async move {
                    let c_ctx = ctx.set_total_records(1);
                    let validator = &c_ctx.dzkp_validator(TEST_DZKP_STEPS, 1);
                    let m_ctx = validator.context();
                    let match_keys = BitDecomposed::new(repeat_n(
                        AdditiveShare::<Boolean, CONV_CHUNK>::ZERO,
                        128,
                    ));
                    convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(
                        m_ctx.clone(),
                        RecordId::FIRST,
                        match_keys,
                    )
                    .await
                    .unwrap()
                })
                .await;
        });
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
