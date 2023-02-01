use crate::helpers::Role;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare;
use crate::secret_sharing::{
    Arithmetic as ArithmeticSecretSharing, ArithmeticShare, SecretSharing,
};
use crate::{
    ff::Field,
    protocol::{
        basics::reveal_permutation,
        context::Context,
        sort::{
            generate_permutation::ShuffledPermutationWrapper, ShuffleRevealStep::RevealPermutation,
        },
    },
};
use async_trait::async_trait;
use futures::future::{join, join_all};
use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: ArithmeticShare> {
    x: SemiHonestAdditiveShare<V>,
    rx: SemiHonestAdditiveShare<V>,
}

impl<V: ArithmeticShare> SecretSharing<V> for AdditiveShare<V> {
    const ZERO: Self = AdditiveShare::ZERO;
}

impl<V: ArithmeticShare> ArithmeticSecretSharing<V> for AdditiveShare<V> {}

/// A trait that is implemented for various collections of `replicated::malicious::AdditiveShare`.
/// This allows a protocol to downgrade to ordinary `replicated::semi_honest::AdditiveShare`
/// when the protocol is done.  This should not be used directly.
#[async_trait]
pub trait Downgrade: Send {
    type Target: Send;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target>;
}

#[must_use = "You should not be downgrading `replicated::malicious::AdditiveShare` values without calling `MaliciousValidator::validate()`"]
pub struct UnauthorizedDowngradeWrapper<T>(T);
impl<T> UnauthorizedDowngradeWrapper<T> {
    pub(crate) fn new(v: T) -> Self {
        Self(v)
    }
}

pub trait ThisCodeIsAuthorizedToDowngradeFromMalicious<T> {
    fn access_without_downgrade(self) -> T;
}

impl<V: ArithmeticShare + Debug> Debug for AdditiveShare<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "x: {:?}, rx: {:?}", self.x, self.rx)
    }
}

impl<V: ArithmeticShare> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(
            SemiHonestAdditiveShare::default(),
            SemiHonestAdditiveShare::default(),
        )
    }
}

impl<V: ArithmeticShare> AdditiveShare<V> {
    #[must_use]
    pub fn new(x: SemiHonestAdditiveShare<V>, rx: SemiHonestAdditiveShare<V>) -> Self {
        Self { x, rx }
    }

    pub fn x(&self) -> UnauthorizedDowngradeWrapper<&SemiHonestAdditiveShare<V>> {
        UnauthorizedDowngradeWrapper(&self.x)
    }

    pub fn rx(&self) -> &SemiHonestAdditiveShare<V> {
        &self.rx
    }

    pub const ZERO: Self = Self {
        x: SemiHonestAdditiveShare::ZERO,
        rx: SemiHonestAdditiveShare::ZERO,
    };
}

impl<F: Field> AdditiveShare<F> {
    /// Returns a pair of replicated secret sharings. One of "one", one of "r"
    pub fn one(helper_role: Role, r_share: SemiHonestAdditiveShare<F>) -> Self {
        Self::new(SemiHonestAdditiveShare::one(helper_role), r_share)
    }
}

impl<V: ArithmeticShare> Add<Self> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn add(self, rhs: Self) -> Self::Output {
        AdditiveShare {
            x: &self.x + &rhs.x,
            rx: &self.rx + &rhs.rx,
        }
    }
}

impl<V: ArithmeticShare> Add<&Self> for AdditiveShare<V> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<V: ArithmeticShare> AddAssign<&Self> for AdditiveShare<V> {
    fn add_assign(&mut self, rhs: &Self) {
        self.x += &rhs.x;
        self.rx += &rhs.rx;
    }
}

impl<V: ArithmeticShare> Neg for AdditiveShare<V> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: -self.x,
            rx: -self.rx,
        }
    }
}

impl<V: ArithmeticShare> Sub<Self> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare {
            x: &self.x - &rhs.x,
            rx: &self.rx - &rhs.rx,
        }
    }
}
impl<V: ArithmeticShare> Sub<&Self> for AdditiveShare<V> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<V: ArithmeticShare> SubAssign<&Self> for AdditiveShare<V> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.x -= &rhs.x;
        self.rx -= &rhs.rx;
    }
}

impl<V: ArithmeticShare> Mul<V> for AdditiveShare<V> {
    type Output = Self;

    fn mul(self, rhs: V) -> Self::Output {
        Self {
            x: self.x * rhs,
            rx: self.rx * rhs,
        }
    }
}

#[async_trait]
impl<F: Field> Downgrade for AdditiveShare<F> {
    type Target = SemiHonestAdditiveShare<F>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(self.x)
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
impl<'a, F: Field> Downgrade for ShuffledPermutationWrapper<'a, F> {
    type Target = Vec<u32>;
    /// For ShuffledPermutationWrapper on downgrading, we return revealed permutation. This runs reveal on the malicious context
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let output = reveal_permutation(self.m_ctx.narrow(&RevealPermutation), &self.perm)
            .await
            .unwrap();
        UnauthorizedDowngradeWrapper(output)
    }
}

#[async_trait]
impl<T> Downgrade for Vec<T>
where
    T: Downgrade,
{
    type Target = Vec<<T as Downgrade>::Target>;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let result = join_all(
            self.into_iter()
                .map(|v| async move { v.downgrade().await.access_without_downgrade() }),
        );
        UnauthorizedDowngradeWrapper(result.await)
    }
}

impl<T> ThisCodeIsAuthorizedToDowngradeFromMalicious<T> for UnauthorizedDowngradeWrapper<T> {
    fn access_without_downgrade(self) -> T {
        self.0
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::{AdditiveShare, Downgrade, ThisCodeIsAuthorizedToDowngradeFromMalicious};
    use crate::ff::{Field, Fp31};
    use crate::helpers::Role;
    use crate::rand::thread_rng;
    use crate::secret_sharing::{
        replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare, IntoShares,
    };
    use crate::test_fixture::Reconstruct;
    use proptest::prelude::Rng;

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

        let roles = [Role::H1, Role::H2, Role::H3];
        let mut results = Vec::with_capacity(3);

        for i in 0..3 {
            let helper_role = roles[i];

            // Avoiding copies here is a real pain: clone!
            let malicious_a = AdditiveShare::new(a_shared[i].clone(), ra_shared[i].clone());
            let malicious_b = AdditiveShare::new(b_shared[i].clone(), rb_shared[i].clone());
            let malicious_c = AdditiveShare::new(c_shared[i].clone(), rc_shared[i].clone());
            let malicious_d = AdditiveShare::new(d_shared[i].clone(), rd_shared[i].clone());
            let malicious_e = AdditiveShare::new(e_shared[i].clone(), re_shared[i].clone());
            let malicious_f = AdditiveShare::new(f_shared[i].clone(), rf_shared[i].clone());

            let malicious_a_plus_b = malicious_a + &malicious_b;
            let malicious_c_minus_d = malicious_c - &malicious_d;
            let malicious_1_minus_e =
                AdditiveShare::one(helper_role, r_shared[i].clone()) - &malicious_e;
            let malicious_2f = malicious_f * Fp31::from(2_u128);

            let mut temp = -malicious_a_plus_b - &malicious_c_minus_d - &malicious_1_minus_e;
            temp = temp * Fp31::from(6_u128);
            results.push(temp + &malicious_2f);
        }

        let correct =
            (-(a + b) - (c - d) - (Fp31::ONE - e)) * Fp31::from(6_u128) + Fp31::from(2_u128) * f;

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
        assert_eq!(x, m.downgrade().await.access_without_downgrade());
    }
}
