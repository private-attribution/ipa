#[cfg(all(test, unit_test))]
use std::ops::Neg;

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{CustomArray, Field},
    helpers::Role,
    protocol::{
        basics::PartialReveal, context::Context,
        ipa_prf::boolean_ops::addition_low_com::integer_add, prss::SharedRandomness, RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, WeakSharedValue},
};
#[cfg(all(test, unit_test))]
use crate::{
    ff::{boolean::Boolean, boolean_array::BA256, ec_prime_field::Fp25519, ArrayAccess},
    secret_sharing::replicated::ReplicatedSecretSharing,
};

#[derive(Step)]
pub(crate) enum Step {
    GenerateSecretSharing,
    IntegerAddBetweenMasks,
    IntegerAddMaskToX,
    RevealY,
}

/// share conversion from Boolean array of size n to integer mod 2^n
/// See ABY3 (`https://eprint.iacr.org/2018/403.pdf`):
///
/// currently not used and also not tested
///
/// We convert a Boolean Sharing of x to an Arithmetic Sharing of x as follows:
/// sample random Boolean Sharing of r, set share `r_1`, `r_2` to 0 (i.e. H1 will not know r)
/// sample random Boolean Sharing of s, set share `s_2`, `s_3` to 0 (i.e. H2 will not know s)
/// compute integer addition of x,r,s: y = x+(r+s) in MPC using the Boolean shares
/// reveal y to H1, H2
/// new shares are H1: (-s, y), H2: (y, -r), H3: (-r,-s)
/// r+s+y = r+s+x-r-s = x
///
/// unfortunately, we cannot exploit that x might have much lower bit length than the Arithmetic share
/// by sampling masks r+s from the same bit length (and setting higher order bits to 0)
/// this is due to the fact that y needs to be revealed (which requires to reveal at least 2 bits more
/// than the bit length of x even when r+s has 0 as higher order bits, due to carries)
/// r+s needs to mask these additional bits which cause additional carries that need to be masked as well
/// # Errors
/// Propagates Errors from Interger Subtraction and Partial Reveal
#[allow(dead_code)]
async fn convert<C, B, A>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<B>,
) -> Result<AdditiveShare<A>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<B>: IntoIterator<Item = AdditiveShare<B::Element>>,
    B: WeakSharedValue + CustomArray + Field,
    B::Element: Field + std::ops::Not<Output = B::Element>,
    A: WeakSharedValue,
    A: From<B>,
{
    // we generate r <- (r1,r2,r3) and redefine r = (0,0,r3), and s = (r1,0,0)
    let mut sh_r: AdditiveShare<B> = ctx
        .narrow(&Step::GenerateSecretSharing)
        .prss()
        .generate_replicated(record_id);

    // set r2=0
    match ctx.role() {
        Role::H1 => sh_r.1 = <B as WeakSharedValue>::ZERO,
        Role::H2 => sh_r.0 = <B as WeakSharedValue>::ZERO,
        Role::H3 => (),
    }

    //generate s from r
    let mut sh_s = sh_r.clone();

    //redefine (r, s): H1: ((0,0),(r1,0)), H2: ((0,r3),(0,0)), H3: ((r3,0),(0,r1))
    match ctx.role() {
        Role::H1 => {
            sh_r.0 = <B as WeakSharedValue>::ZERO;
        }
        Role::H2 => {
            sh_s.1 = <B as WeakSharedValue>::ZERO;
        }
        Role::H3 => {
            sh_r.1 = <B as WeakSharedValue>::ZERO;
            sh_s.0 = <B as WeakSharedValue>::ZERO;
        }
    }

    let sh_rs = integer_add(
        ctx.narrow(&Step::IntegerAddBetweenMasks),
        record_id,
        &sh_r,
        &sh_s,
    )
    .await?;

    let sh_y = integer_add(ctx.narrow(&Step::IntegerAddMaskToX), record_id, &sh_rs, x).await?;

    let y = sh_y
        .partial_reveal(ctx.narrow(&Step::RevealY), record_id, Role::H3)
        .await?;

    match ctx.role() {
        Role::H1 => Ok(AdditiveShare::<A>(
            A::from(sh_s.0).neg(),
            A::from(y.unwrap()),
        )),
        Role::H2 => Ok(AdditiveShare::<A>(
            A::from(y.unwrap()),
            A::from(sh_r.1).neg(),
        )),
        Role::H3 => Ok(AdditiveShare::<A>(
            A::from(sh_r.0).neg(),
            A::from(sh_s.1).neg(),
        )),
    }
}

/// similar to convert however converting Boolean arrays to `Fp25519` takes special treatment
/// requires `BA256` (to handle carries),
/// can only be used securely to convert `BAt` to `Fp25519`,
/// where t < 256 - statistical security parameter due to leakage
///
/// leakage free alternative needs secure mod p operation after each addition
/// (which can be performed using secure subtraction)
///
/// we use a `BA256` for masks r, s and set the 2 most significant bits to 0.
/// this allows us to compute Boolean shares of r + s without reducing it mod 256
/// further it allows us to compute x + r + s without reducing it mod 256
///
/// We can then reveal x+r+s via `partial_reveal` and reduce it with mod p, where p is the prime of `Fp25519`
///
/// in the process, we need to make sure that highest order `PRSS` masks added by `multiply`
/// are set to zero since they would also cause carries in the integer addition
///
/// Setting the most significant bits to 0 leaks information about x:
/// assuming x has m bits, revealing y = x + rs (where rs = r + s) leaks the following information
/// (see `bit_adder` in `protocol::ipa_prf::boolean_ops::addition_low_com::integer_add`):
/// y{m} := rs{m} xor x{m} xor `carry_x`
/// where x{m} is 0 and `carry_x` is carry{m-1} which contains information about x
/// carry is defined as carry{i} = carry{i-1} xor (x{i-1} xor carry{i-1})(y{i-1} xor carry{i-1})
/// for all i where x{i-1}=0: carry{i} = carry{i-1}y{i-1}
/// therefore for j>=0,
/// y{m+j} := rs{m+j} xor (`carry_x` * product_(k=m)^(m+j-1)rs{k})
/// this will result in leakage (rs{255}=0, rs{254}=0)
/// y{255} := `carry_x` * product_(k=m)^(255)rs{k})
/// y{254} := `carry_x` * product_(k=m)^(254)rs{k})
/// however, these terms are only non-zero when all rs{k} terms are non-zero
/// this happens with probability 1/(2^(256-m)) which is negligible for small m
/// # Errors
/// Propagates Errors from Interger Subtraction and Partial Reveal
#[cfg(all(test, unit_test))]
async fn convert_to_fp25519<C, B>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<B>,
) -> Result<AdditiveShare<Fp25519>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<B>: IntoIterator<Item = AdditiveShare<B::Element>>,
    B: WeakSharedValue + CustomArray<Element = Boolean> + Field,
{
    // we generate r <- (r1,r2,r3) and redefine r = (0,0,r3), and s = (r1,0,0)
    let mut sh_r: AdditiveShare<BA256> = ctx
        .narrow(&Step::GenerateSecretSharing)
        .prss()
        .generate_replicated(record_id);

    // set 2 highest order bits to 0 to allow carries for two additions
    sh_r.set(255, AdditiveShare::<Boolean>::ZERO);
    sh_r.set(254, AdditiveShare::<Boolean>::ZERO);

    // set r2=0
    match ctx.role() {
        Role::H1 => sh_r.1 = <BA256 as WeakSharedValue>::ZERO,
        Role::H2 => sh_r.0 = <BA256 as WeakSharedValue>::ZERO,
        Role::H3 => (),
    }

    //generate s from r
    let mut sh_s = AdditiveShare::<BA256>::ZERO;

    //redefine (r, s): H1: ((0,0),(r1,0)), H2: ((0,r3),(0,0)), H3: ((r3,0),(0,r1))
    match ctx.role() {
        Role::H1 => sh_r.0 = <BA256 as WeakSharedValue>::ZERO,
        Role::H2 => sh_s.1 = <BA256 as WeakSharedValue>::ZERO,
        Role::H3 => {
            sh_r.1 = <BA256 as WeakSharedValue>::ZERO;
            sh_s.0 = <BA256 as WeakSharedValue>::ZERO;
        }
    }

    // addition r+s might cause carry, so we need 253 bits
    let mut sh_rs = integer_add::<_, BA256, BA256>(
        ctx.narrow(&Step::IntegerAddBetweenMasks),
        record_id,
        &sh_r,
        &sh_s,
    )
    .await?;

    //PRSS/Multiply masks added random highest order bit,
    // remove them to not cause overflow in second addition (which is mod 256):
    sh_rs.set(255, AdditiveShare::<Boolean>::ZERO);

    //addition x+rs, where rs=r+s might cause carry
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
/// we don't use it right except for testing purposes
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
