use std::ops::Neg;

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean, boolean_array::BA256, ec_prime_field::Fp25519, ArrayAccess, CustomArray,
        Field,
    },
    helpers::Role,
    protocol::{
        basics::PartialReveal, context::Context,
        ipa_prf::boolean_ops::addition_sequential::integer_add, prss::SharedRandomness, RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
        WeakSharedValue,
    },
};

#[derive(Step)]
pub(crate) enum Step {
    GenerateSecretSharing,
    IntegerAddBetweenMasks,
    IntegerAddMaskToX,
    RevealY,
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
/// # Errors
/// Propagates Errors from Integer Subtraction and Partial Reveal
pub async fn convert_to_fp25519<C, B>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<B>,
) -> Result<AdditiveShare<Fp25519>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<B>: IntoIterator<Item = AdditiveShare<B::Element>>,
    B: WeakSharedValue + CustomArray<Element = Boolean> + Field,
{
    // generate sh_r = (0, 0, sh_r) and sh_s = (sh_s, 0, 0)
    // the two highest bits are set to 0 to allow carries for two additions
    let (sh_r, sh_s) = {
        // this closure generates sh_r, sh_r from PRSS randomness r

        // we generate random values r = (r1,r2,r3) using PRSS
        // r: H1: (r1,r2), H2: (r2,r3), H3: (r3, r1)
        let mut r: AdditiveShare<BA256> = ctx
            .narrow(&Step::GenerateSecretSharing)
            .prss()
            .generate_replicated(record_id);

        // set 2 highest order bits of r1, r2, r3 to 0
        r.set(255, AdditiveShare::<Boolean>::ZERO);
        r.set(254, AdditiveShare::<Boolean>::ZERO);

        // generate sh_r, sh_s
        // sh_r: H1: (0,0), H2: (0,r3), H3: (r3, 0)
        // sh_s: H1: (r1,0), H2: (0,0), H3: (0, r1)
        match ctx.role() {
            Role::H1 => (
                AdditiveShare(
                    <BA256 as WeakSharedValue>::ZERO,
                    <BA256 as WeakSharedValue>::ZERO,
                ),
                AdditiveShare(r.0, <BA256 as WeakSharedValue>::ZERO),
            ),
            Role::H2 => (
                AdditiveShare(<BA256 as WeakSharedValue>::ZERO, r.1),
                AdditiveShare(
                    <BA256 as WeakSharedValue>::ZERO,
                    <BA256 as WeakSharedValue>::ZERO,
                ),
            ),
            Role::H3 => (
                AdditiveShare(r.0, <BA256 as WeakSharedValue>::ZERO),
                AdditiveShare(<BA256 as WeakSharedValue>::ZERO, r.1),
            ),
        }
    };

    // addition r+s might cause carry,
    // this is no problem since we have set bit 254 of sh_r and sh_s to 0
    let sh_rs = {
        let mut rs_with_higherorderbits = integer_add::<_, BA256, BA256>(
            ctx.narrow(&Step::IntegerAddBetweenMasks),
            record_id,
            &sh_r,
            &sh_s,
        )
        .await?;

        // PRSS/Multiply masks added random highest order bit,
        // remove them to not cause overflow in second addition (which is mod 256):
        rs_with_higherorderbits.set(255, AdditiveShare::<Boolean>::ZERO);

        // return rs
        rs_with_higherorderbits
    };

    // addition x+rs, where rs=r+s might cause carry
    // this is not a problem since bit 255 of rs is set to 0
    let sh_y =
        integer_add::<_, BA256, B>(ctx.narrow(&Step::IntegerAddMaskToX), record_id, &sh_rs, x)
            .await?;

    // this leaks information, but with negligible probability
    let y = AdditiveShare::<BA256>(sh_y.left(), sh_y.right())
        .partial_reveal(ctx.narrow(&Step::RevealY), record_id, Role::H3)
        .await?;

    match ctx.role() {
        Role::H1 => Ok(AdditiveShare::<Fp25519>(
            Fp25519::from(sh_s.0).neg(),
            Fp25519::from(y.unwrap()),
        )),
        Role::H2 => Ok(AdditiveShare::<Fp25519>(
            Fp25519::from(y.unwrap()),
            Fp25519::from(sh_r.1).neg(),
        )),
        Role::H3 => Ok(AdditiveShare::<Fp25519>(
            Fp25519::from(sh_r.0).neg(),
            Fp25519::from(sh_s.1).neg(),
        )),
    }
}

/// inserts a smaller array into a larger
/// allows conversion between Boolean Array types like 'BA64' and 'BA256'
/// we don't use it right except for testing purposes
#[cfg(all(test, unit_test))]
pub fn expand_array<XS, YS>(x: &XS, offset: Option<usize>) -> YS
where
    for<'a> &'a YS: IntoIterator<Item = XS::Element>,
    XS: CustomArray,
    YS: CustomArray<Element = XS::Element> + WeakSharedValue,
    XS::Element: WeakSharedValue,
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

/// inserts a smaller array into a larger
/// allows share conversion between secret shared Boolean Array types like 'BA64' and 'BA256'
/// only used for testing purposes
#[cfg(all(test, unit_test))]
pub fn expand_shared_array<XS, YS>(
    x: &AdditiveShare<XS>,
    offset: Option<usize>,
) -> AdditiveShare<YS>
where
    for<'a> &'a AdditiveShare<YS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    for<'a> &'a YS: IntoIterator<Item = XS::Element>,
    XS: CustomArray + WeakSharedValue,
    YS: CustomArray<Element = XS::Element> + WeakSharedValue,
    XS::Element: WeakSharedValue,
{
    AdditiveShare::<YS>(
        expand_array(&x.left(), offset),
        expand_array(&x.right(), offset),
    )
}

#[cfg(all(test, unit_test))]
mod tests {
    use curve25519_dalek::Scalar;
    use generic_array::GenericArray;
    use rand::Rng;
    use typenum::U32;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA256, BA64},
            ec_prime_field::Fp25519,
            ArrayAccess, Serializable,
        },
        protocol,
        protocol::{
            context::Context,
            ipa_prf::boolean_ops::share_conversion_aby::{
                convert_to_fp25519, expand_array, expand_shared_array,
            },
        },
        rand::thread_rng,
        secret_sharing::{replicated::semi_honest::AdditiveShare, WeakSharedValue},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[test]
    fn semi_honest_convert_into_fp25519() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records = rng.gen::<BA64>();

            let mut buf: GenericArray<u8, U32> = [0u8; 32].into();

            expand_array::<BA64, BA256>(&records, None).serialize(&mut buf);

            let expected = Fp25519::from(<Scalar>::from_bytes_mod_order(<[u8; 32]>::from(buf)));

            let result = world
                .semi_honest(records, |ctx, x| async move {
                    convert_to_fp25519::<_, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn test_expand() {
        let mut rng = thread_rng();

        let a = rng.gen::<BA64>();

        let shared_a = AdditiveShare::<BA64>(rng.gen::<BA64>(), rng.gen::<BA64>());

        let b = expand_array::<_, BA256>(&a, None);

        let shared_b = expand_shared_array::<_, BA256>(&shared_a, None);

        for i in 0..BA256::BITS as usize {
            assert_eq!(
                (i, b.get(i).unwrap_or(Boolean::ZERO)),
                (i, a.get(i).unwrap_or(Boolean::ZERO))
            );
            assert_eq!(
                (i, shared_b.get(i).unwrap_or(AdditiveShare::<Boolean>::ZERO)),
                (i, shared_a.get(i).unwrap_or(AdditiveShare::<Boolean>::ZERO))
            );
        }
    }
}
