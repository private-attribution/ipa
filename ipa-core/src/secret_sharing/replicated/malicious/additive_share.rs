use std::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use async_trait::async_trait;
use futures::{
    future::{join, join_all},
    stream::{iter as stream_iter, StreamExt},
};
use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{Field, Gf2, Gf32Bit, PrimeField, Serializable, U128Conversions},
    protocol::prss::FromRandom,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare, BitDecomposed,
        FieldSimd, Linear as LinearSecretSharing, SecretSharing, SharedValue,
    },
    seq_join::seq_join,
};

///
/// This code is an optimization to our malicious compiler that is drawn from:
/// "Field Extension in Secret-Shared Form and Its Applications to Efficient Secure Computation"
/// R. Kikuchi, N. Attrapadung, K. Hamada, D. Ikarashi, A. Ishida, T. Matsuda, Y. Sakai, and J. C. N. Schuldt
/// <https://eprint.iacr.org/2019/386.pdf>
///
/// The general idea here is that each "wire" in the circuit carries both the orginal value `x` as well as another value `rx`
/// This paper demonstrates a mechanism by which a very small field (even a binary field) can be used for the `x` value,
/// while a larger extension field is used for `rx`.
///
/// This makes it possible to minimize communication overhead required to reach a desired level of statistical security.
///
#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: SharedValue + ExtendableFieldSimd<N>, const N: usize = 1> {
    x: SemiHonestAdditiveShare<V, N>,
    rx: SemiHonestAdditiveShare<V::ExtendedField, N>,
}

pub trait ExtendableField: Field {
    type ExtendedField: Field + FromRandom;
    fn to_extended(&self) -> Self::ExtendedField;
}

/// Trait for extendable vectorized fields
pub trait ExtendableFieldSimd<const N: usize>:
    ExtendableField<ExtendedField: FieldSimd<N>> + FieldSimd<N>
{
}

/// Blanket implementation for all fields that implement [`ExtendableField`] and [`FieldSimd`].
impl<F: ExtendableField<ExtendedField: FieldSimd<N>> + FieldSimd<N>, const N: usize>
    ExtendableFieldSimd<N> for F
{
}

impl<F: PrimeField> ExtendableField for F {
    type ExtendedField = F;

    fn to_extended(&self) -> Self::ExtendedField {
        *self
    }
}

// A binary field (just 2 elements, 0 and 1) is way too small.
// As such, we need to define a 32-bit extension field (Gf32Bit) if we want to achieve an acceptable level of statistical security.
// Computing the "induced share" is super easy,
// all of the bits are zero except the least significant one - which is taken from the share you're converting.
//
// `f(1) = (0, 0, 0, 0, ..., 0, 1)`
impl ExtendableField for Gf2 {
    type ExtendedField = Gf32Bit;

    fn to_extended(&self) -> Self::ExtendedField {
        Gf32Bit::try_from(self.as_u128()).unwrap()
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> SecretSharing<V> for AdditiveShare<V, N> {
    const ZERO: Self = AdditiveShare::ZERO;
}

impl<V: ExtendableFieldSimd<N>, const N: usize> LinearSecretSharing<V> for AdditiveShare<V, N> {}

/// A trait that is implemented for various collections of `replicated::malicious::AdditiveShare`.
/// This allows a protocol to downgrade to ordinary `replicated::semi_honest::AdditiveShare`
/// when the protocol is done.  This should not be used directly.
#[async_trait]
pub trait Downgrade: Send {
    type Target: Send + 'static;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target>;
}

#[must_use = "You should not be downgrading `replicated::malicious::AdditiveShare` values without calling `MaliciousValidator::validate()`"]
pub struct UnauthorizedDowngradeWrapper<T>(T);
impl<T> UnauthorizedDowngradeWrapper<T> {}

pub trait ThisCodeIsAuthorizedToDowngradeFromMalicious<T> {
    fn access_without_downgrade(self) -> T;
}

impl<V: SharedValue + ExtendableField>
    ThisCodeIsAuthorizedToDowngradeFromMalicious<SemiHonestAdditiveShare<V>> for AdditiveShare<V>
{
    fn access_without_downgrade(self) -> SemiHonestAdditiveShare<V> {
        self.x
    }
}

impl<V: Debug + ExtendableFieldSimd<N>, const N: usize> Debug for AdditiveShare<V, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "x: {:?}, rx: {:?}", self.x, self.rx)
    }
}

impl<V: SharedValue + ExtendableField> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(
            SemiHonestAdditiveShare::default(),
            SemiHonestAdditiveShare::default(),
        )
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> AdditiveShare<V, N> {
    #[must_use]
    pub fn new(
        x: SemiHonestAdditiveShare<V, N>,
        rx: SemiHonestAdditiveShare<V::ExtendedField, N>,
    ) -> Self {
        Self { x, rx }
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> SemiHonestAdditiveShare<V, N> {
    /// Returns a secret sharing over [`V::ExtendedField`] by converting `V` into
    /// the extended field.
    pub fn induced(&self) -> SemiHonestAdditiveShare<V::ExtendedField, N> {
        self.clone().transform(|v| v.to_extended())
    }
}

impl<V: ExtendableField> AdditiveShare<V> {
    pub fn downgrade(self) -> UnauthorizedDowngradeWrapper<SemiHonestAdditiveShare<V>> {
        UnauthorizedDowngradeWrapper(self.x)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> AdditiveShare<V, N> {
    pub fn x(&self) -> UnauthorizedDowngradeWrapper<&SemiHonestAdditiveShare<V, N>> {
        UnauthorizedDowngradeWrapper(&self.x)
    }

    pub fn rx(&self) -> &SemiHonestAdditiveShare<V::ExtendedField, N> {
        &self.rx
    }

    pub const ZERO: Self = Self {
        x: SemiHonestAdditiveShare::ZERO,
        rx: SemiHonestAdditiveShare::ZERO,
    };
}

impl<'a, 'b, V: ExtendableFieldSimd<N>, const N: usize> Add<&'b AdditiveShare<V, N>>
    for &'a AdditiveShare<V, N>
{
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: &'b AdditiveShare<V, N>) -> Self::Output {
        AdditiveShare {
            x: &self.x + &rhs.x,
            rx: &self.rx + &rhs.rx,
        }
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Add<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Add<AdditiveShare<V, N>> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Add<&AdditiveShare<V, N>> for AdditiveShare<V, N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> AddAssign<&Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: &Self) {
        self.x += &rhs.x;
        self.rx += &rhs.rx;
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> AddAssign<Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Neg for AdditiveShare<V, N> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: -self.x,
            rx: -self.rx,
        }
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Sub<Self> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare {
            x: &self.x - &rhs.x,
            rx: &self.rx - &rhs.rx,
        }
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Sub<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Sub<&Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Sub<AdditiveShare<V, N>> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> SubAssign<&Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.x -= &rhs.x;
        self.rx -= &rhs.rx;
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> SubAssign<Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, V: ExtendableFieldSimd<N>, const N: usize> Mul<&'b V> for &'a AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn mul(self, rhs: &'b V) -> Self::Output {
        AdditiveShare {
            x: &self.x * rhs,
            rx: &self.rx * rhs.to_extended(),
        }
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Mul<V> for AdditiveShare<V, N> {
    type Output = Self;

    fn mul(self, rhs: V) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Mul<&V> for AdditiveShare<V, N> {
    type Output = Self;

    fn mul(self, rhs: &V) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<V: ExtendableFieldSimd<N>, const N: usize> Mul<V> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn mul(self, rhs: V) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ExtendableFieldDeserializationError<F: Serializable, EF: Serializable> {
    #[error(
        "error deserializing field value when creating a maliciously secure replicated share: {0}"
    )]
    FieldError(F::DeserializationError),
    #[error("error deserializing extended field value when creating a maliciously secure replicated share: {0}")]
    ExtendedFieldError(EF::DeserializationError),
}

/// todo serde macro for these collections so we can hide the crazy size calculations
impl<V: SharedValue + ExtendableField> Serializable for AdditiveShare<V>
where
    SemiHonestAdditiveShare<V>: Serializable,
    SemiHonestAdditiveShare<V::ExtendedField>: Serializable,
    <SemiHonestAdditiveShare<V> as Serializable>::Size:
        Add<<SemiHonestAdditiveShare<V::ExtendedField> as Serializable>::Size>,
    <<SemiHonestAdditiveShare<V> as Serializable>::Size as Add<
        <SemiHonestAdditiveShare<V::ExtendedField> as Serializable>::Size,
    >>::Output: ArrayLength,
{
    type Size = <<SemiHonestAdditiveShare<V> as Serializable>::Size as Add<
        <SemiHonestAdditiveShare<V::ExtendedField> as Serializable>::Size,
    >>::Output;
    type DeserializationError = ExtendableFieldDeserializationError<
        SemiHonestAdditiveShare<V>,
        SemiHonestAdditiveShare<V::ExtendedField>,
    >;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) =
            buf.split_at_mut(<SemiHonestAdditiveShare<V> as Serializable>::Size::USIZE);
        self.x.serialize(GenericArray::from_mut_slice(left));
        self.rx.serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let x =
            <SemiHonestAdditiveShare<V> as Serializable>::deserialize(GenericArray::from_slice(
                &buf[..<SemiHonestAdditiveShare<V> as Serializable>::Size::USIZE],
            ))
            .map_err(ExtendableFieldDeserializationError::FieldError)?;
        let rx = <SemiHonestAdditiveShare<V::ExtendedField> as Serializable>::deserialize(
            GenericArray::from_slice(
                &buf[<SemiHonestAdditiveShare<V::ExtendedField> as Serializable>::Size::USIZE..],
            ),
        )
        .map_err(ExtendableFieldDeserializationError::ExtendedFieldError)?;
        Ok(Self { x, rx })
    }
}

#[async_trait]
impl<F: ExtendableField> Downgrade for AdditiveShare<F> {
    type Target = SemiHonestAdditiveShare<F>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(self.x)
    }
}

#[async_trait]
impl<F: ExtendableField> Downgrade for SemiHonestAdditiveShare<F> {
    type Target = SemiHonestAdditiveShare<F>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(self)
    }
}

#[async_trait]
impl Downgrade for () {
    type Target = ();
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(())
    }
}

#[async_trait]
impl<T, U> Downgrade for (T, U)
where
    T: Downgrade,
    U: Downgrade,
{
    type Target = (<T>::Target, <U>::Target);
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let output = join(self.0.downgrade(), self.1.downgrade()).await;
        UnauthorizedDowngradeWrapper((
            output.0.access_without_downgrade(),
            output.1.access_without_downgrade(),
        ))
    }
}

#[async_trait]
impl<T> Downgrade for BitDecomposed<T>
where
    T: Downgrade,
{
    type Target = BitDecomposed<<T as Downgrade>::Target>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        #[allow(clippy::disallowed_methods)]
        let result = join_all(
            self.into_iter()
                .map(|v| async move { v.downgrade().await.access_without_downgrade() }),
        );
        UnauthorizedDowngradeWrapper(BitDecomposed::new(result.await))
    }
}

#[async_trait]
impl<T> Downgrade for Vec<T>
where
    T: Downgrade,
{
    type Target = Vec<<T as Downgrade>::Target>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        // TODO: connect this number to something.
        let result = seq_join(
            NonZeroUsize::new(4096).unwrap(),
            stream_iter(
                self.into_iter()
                    .map(|v| async move { v.downgrade().await.access_without_downgrade() }),
            ),
        );
        UnauthorizedDowngradeWrapper(result.collect::<Self::Target>().await)
    }
}

impl<T> ThisCodeIsAuthorizedToDowngradeFromMalicious<T> for UnauthorizedDowngradeWrapper<T> {
    fn access_without_downgrade(self) -> T {
        self.0
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::{AdditiveShare, Downgrade, ThisCodeIsAuthorizedToDowngradeFromMalicious};
    use crate::{
        ff::{Field, Fp31, U128Conversions},
        helpers::Role,
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::{
                semi_honest::AdditiveShare as SemiHonestAdditiveShare, ReplicatedSecretSharing,
            },
            IntoShares,
        },
        test_fixture::Reconstruct,
    };

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_local_operations() {
        let mut rng = rand::thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let c = rng.gen::<Fp31>();
        let d = rng.gen::<Fp31>();
        let e = rng.gen::<Fp31>();
        let f = rng.gen::<Fp31>();
        // Randomization constant
        let r = rng.gen::<Fp31>();

        let one_shared = Fp31::ONE.share_with(&mut rng);
        let a_shared = a.share_with(&mut rng);
        let b_shared = b.share_with(&mut rng);
        let c_shared = c.share_with(&mut rng);
        let d_shared = d.share_with(&mut rng);
        let e_shared = e.share_with(&mut rng);
        let f_shared = f.share_with(&mut rng);
        // Randomization constant
        let r_shared = r.share_with(&mut rng);

        let ra = a * r;
        let rb = b * r;
        let rc = c * r;
        let rd = d * r;
        let re = e * r;
        let rf = f * r;

        let ra_shared = ra.share_with(&mut rng);
        let rb_shared = rb.share_with(&mut rng);
        let rc_shared = rc.share_with(&mut rng);
        let rd_shared = rd.share_with(&mut rng);
        let re_shared = re.share_with(&mut rng);
        let rf_shared = rf.share_with(&mut rng);

        let mut results = Vec::with_capacity(3);

        for &i in Role::all() {
            // Avoiding copies here is a real pain: clone!
            let malicious_one = AdditiveShare::new(one_shared[i].clone(), r_shared[i].clone());
            let malicious_a = AdditiveShare::new(a_shared[i].clone(), ra_shared[i].clone());
            let malicious_b = AdditiveShare::new(b_shared[i].clone(), rb_shared[i].clone());
            let malicious_c = AdditiveShare::new(c_shared[i].clone(), rc_shared[i].clone());
            let malicious_d = AdditiveShare::new(d_shared[i].clone(), rd_shared[i].clone());
            let malicious_e = AdditiveShare::new(e_shared[i].clone(), re_shared[i].clone());
            let malicious_f = AdditiveShare::new(f_shared[i].clone(), rf_shared[i].clone());

            let malicious_a_plus_b = malicious_a + &malicious_b;
            let malicious_c_minus_d = malicious_c - &malicious_d;
            let malicious_1_minus_e = malicious_one - &malicious_e;
            let malicious_2f = malicious_f * Fp31::truncate_from(2_u128);

            let mut temp = -malicious_a_plus_b - &malicious_c_minus_d - &malicious_1_minus_e;
            temp = temp * Fp31::truncate_from(6_u128);
            results.push(temp + &malicious_2f);
        }

        let correct = (-(a + b) - (c - d) - (Fp31::ONE - e)) * Fp31::truncate_from(6_u128)
            + Fp31::truncate_from(2_u128) * f;

        assert_eq!(
            [
                results[0].x().access_without_downgrade(),
                results[1].x().access_without_downgrade(),
                results[2].x().access_without_downgrade(),
            ]
            .reconstruct(),
            correct,
        );
        assert_eq!(
            [results[0].rx(), results[1].rx(), results[2].rx()].reconstruct(),
            correct * r,
        );
    }

    #[tokio::test]
    async fn downgrade() {
        let mut rng = thread_rng();
        let x = SemiHonestAdditiveShare::new(rng.gen::<Fp31>(), rng.gen());
        let y = SemiHonestAdditiveShare::new(rng.gen::<Fp31>(), rng.gen());
        let m = AdditiveShare::new(x.clone(), y);
        assert_eq!(x, Downgrade::downgrade(m).await.access_without_downgrade());
    }
}
