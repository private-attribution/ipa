#[cfg_attr(not(debug_assertions), allow(unused_variables))]
use crate::secret_sharing::Vectorizable;
use crate::{
    helpers::Role,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
};

/// A description of a replicated secret sharing, with zero values at known positions.
/// Convention here is to refer to the "left" share available at each helper, with
/// helpers taken in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroPositions {
    /// No zeros
    Pvvv,
    /// Value at H3 left, H2 right
    Pzzv,
    /// Value at H2 left, H1 right
    Pzvz,
    /// Value at H1 left, H2 right
    Pvzz,
    /// Zero at H3 left, H2 right
    Pvvz,
    /// Zero at H2 left, H1 right
    Pvzv,
    /// Zero at H1 left, H2 right
    Pzvv,
    // Note: all zero values are invalid (you don't need to multiply these)
}

pub type MultiplyZeroPositions = (ZeroPositions, ZeroPositions);

impl ZeroPositions {
    /// Both arguments have values in all positions.  This should be the default.
    pub const NONE: (Self, Self) = (Self::Pvvv, Self::Pvvv);
    /// The second argument has two zero-valued positions.
    pub const AVVV_BZZV: (Self, Self) = (Self::Pvvv, Self::Pzzv);
    /// Both arguments have two zero-valued positions arranged for minimal work.
    pub const AVZZ_BZVZ: (Self, Self) = (Self::Pvzz, Self::Pzvz);
    /// Both arguments have zero-valued positions, but not optimally arranged.
    pub const AVVZ_BZZV: (Self, Self) = (Self::Pvvz, Self::Pzzv);

    /// Get the work that `Role::H1` would perform given two values with known zero values
    /// in the identified positions.  Work is who sends: `[left, self, right]`, which for
    /// the current role is interpreted as `[recv, send, add_random_rhs]`.
    #[must_use]
    fn work(zeros_at: MultiplyZeroPositions) -> [bool; 3] {
        // This match looks scary, but it is the output of a test function,
        // formatted with clippy's help.  See `print_mappings` below.
        match zeros_at {
            (Self::Pvzz, Self::Pvzz) | (Self::Pzvz, Self::Pzvz) | (Self::Pzzv, Self::Pzzv) => {
                if cfg!(debug_assertions) {
                    panic!("attempting to do a multiplication that can be performed locally");
                } else {
                    [false, false, false]
                }
            }
            (Self::Pzvv | Self::Pzvz | Self::Pzzv, Self::Pzvv)
            | (Self::Pzvv | Self::Pzzv, Self::Pzvz)
            | (Self::Pzvv | Self::Pzvz, Self::Pzzv) => [false, false, true],
            (Self::Pvvz | Self::Pvzz | Self::Pzvz, Self::Pvvz)
            | (Self::Pvvz | Self::Pzvz, Self::Pvzz)
            | (Self::Pvvz | Self::Pvzz, Self::Pzvz) => [false, true, false],
            (Self::Pvvv | Self::Pvzv, Self::Pzvz) | (Self::Pzvz, Self::Pvvv | Self::Pvzv) => {
                [false, true, true]
            }
            (Self::Pvzv | Self::Pvzz | Self::Pzzv, Self::Pvzv)
            | (Self::Pvzv | Self::Pzzv, Self::Pvzz)
            | (Self::Pvzv | Self::Pvzz, Self::Pzzv) => [true, false, false],
            (Self::Pvvv | Self::Pvvz, Self::Pzzv) | (Self::Pzzv, Self::Pvvv | Self::Pvvz) => {
                [true, false, true]
            }
            (Self::Pvvv | Self::Pzvv, Self::Pvzz) | (Self::Pvzz, Self::Pvvv | Self::Pzvv) => {
                [true, true, false]
            }
            (Self::Pvvv | Self::Pvvz | Self::Pvzv | Self::Pzvv, Self::Pvvv)
            | (Self::Pvvv | Self::Pvzv | Self::Pzvv, Self::Pvvz)
            | (Self::Pvvv | Self::Pvvz | Self::Pzvv, Self::Pvzv)
            | (Self::Pvvv | Self::Pvvz | Self::Pvzv, Self::Pzvv) => [true, true, true],
        }
    }

    /// Determine if the identified work is pointless.
    /// That is, if the work could be done locally.
    #[must_use]
    pub fn is_pointless(zeros_at: MultiplyZeroPositions) -> bool {
        zeros_at.0 == zeros_at.1
            && matches!(
                zeros_at.0,
                ZeroPositions::Pvzz | ZeroPositions::Pzvz | ZeroPositions::Pzzv
            )
    }

    /// Determine where the zero positions are in the output of a multiplication.
    #[must_use]
    pub fn mul_output(zeros_at: MultiplyZeroPositions) -> Self {
        // A zero only appears on the lhs of the output if the helper is neither
        // sending nor receiving.
        match Self::work(zeros_at) {
            [false, false, true] => Self::Pzvv,
            [false, true, false] => Self::Pvvz,
            [true, false, false] => Self::Pvzv,
            _ => Self::Pvvv,
        }
    }

    /// Sanity check a value at a given helper.
    /// Debug code only as this is unnecessary work.
    /// # Panics
    /// When the input value includes a non-zero value in a position marked as having a zero.
    #[cfg_attr(not(debug_assertions), allow(unused_variables))]
    pub fn check<V: SharedValue + Vectorizable<N>, const N: usize>(
        self,
        role: Role,
        which: &str,
        v: &Replicated<V, N>,
    ) {
        #[cfg(debug_assertions)]
        {
            use crate::{helpers::Direction::Right, secret_sharing::SharedValueArray};

            let flags = <[bool; 3]>::from(self);
            if flags[role as usize] {
                assert_eq!(
                    &<V as Vectorizable<N>>::Array::ZERO_ARRAY,
                    v.left_arr(),
                    "expected a zero on the left for input {which}"
                );
            }
            if flags[role.peer(Right) as usize] {
                assert_eq!(
                    &<V as Vectorizable<N>>::Array::ZERO_ARRAY,
                    v.right_arr(),
                    "expected a zero on the right for input {which}"
                );
            }
        }
    }

    #[must_use]
    pub fn all() -> &'static [ZeroPositions] {
        const ALL: &[ZeroPositions] = &[
            ZeroPositions::Pzvv,
            ZeroPositions::Pvzv,
            ZeroPositions::Pvvz,
            ZeroPositions::Pvzz,
            ZeroPositions::Pzvz,
            ZeroPositions::Pzzv,
            ZeroPositions::Pvvv,
        ];
        ALL
    }
}

// Code for testing and debugging only.
impl From<ZeroPositions> for [bool; 3] {
    fn from(zp: ZeroPositions) -> Self {
        match zp {
            ZeroPositions::Pvvv => [false, false, false],
            ZeroPositions::Pzzv => [true, true, false],
            ZeroPositions::Pzvz => [true, false, true],
            ZeroPositions::Pvzz => [false, true, true],
            ZeroPositions::Pvvz => [false, false, true],
            ZeroPositions::Pvzv => [false, true, false],
            ZeroPositions::Pzvv => [true, false, false],
        }
    }
}

/// This struct includes public constants for different arrangements of known zeros in shares.
/// The value of this can be used to determine which of the three helpers sends during a multiplication.
pub(super) trait MultiplyWork {
    /// Determine the work that is required for the identified role.
    /// Return value is who is sending relative to the given role [self, left, right].
    fn work_for(self, role: Role) -> [bool; 3];

    #[cfg(all(test, unit_test))]
    /// Determines where there are known zeros in the output of a multiplication.
    fn output(self) -> ZeroPositions;
}

impl MultiplyWork for MultiplyZeroPositions {
    fn work_for(self, role: Role) -> [bool; 3] {
        let work = ZeroPositions::work(self);
        let i = role as usize;
        let need_to_recv = work[i % 3];
        let need_to_send = work[(i + 1) % 3];
        let need_random_right = work[(i + 2) % 3];
        [need_to_recv, need_to_send, need_random_right]
    }

    #[cfg(all(test, unit_test))]
    fn output(self) -> ZeroPositions {
        ZeroPositions::mul_output(self)
    }
}

#[cfg(all(test, unit_test))]
pub(in crate::protocol) mod test {
    use std::{borrow::Borrow, iter::zip};

    use futures::future::try_join;
    use rand::distributions::{Distribution, Standard};

    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::{
            Direction::{Left, Right},
            Role,
        },
        protocol::{
            basics::{mul::sparse::MultiplyWork, MultiplyZeroPositions, SecureMul, ZeroPositions},
            context::{Context, UpgradableContext, UpgradedContext, Validator},
            step::BitOpStep,
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
            IntoShares,
        },
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[derive(Clone, Copy)]
    pub struct SparseField<F> {
        v: F,
        z: ZeroPositions,
    }

    impl<F> SparseField<F> {
        #[must_use]
        pub fn new(v: F, z: ZeroPositions) -> Self {
            Self { v, z }
        }

        #[must_use]
        pub fn value(self) -> F {
            self.v
        }
    }

    impl<F> IntoShares<Replicated<F>> for SparseField<F>
    where
        F: Field,
        Standard: Distribution<F>,
    {
        // Create a sharing of `self.v` with zeros in positions determined by `self.z`.
        // This is a little inefficient, but it shouldn't be so bad in tests.
        fn share_with<R: rand::Rng>(self, rng: &mut R) -> [Replicated<F>; 3] {
            let zeros = <[bool; 3]>::from(self.z);
            // Generate one fewer random value than there are values.
            let mut randoms = zeros.iter().filter(|&x| !x).skip(1).map(|_| rng.gen::<F>());
            let mut remainder = self.v;
            let values = zeros
                .into_iter()
                .map(|z| {
                    if z {
                        F::ZERO
                    } else if let Some(r) = randoms.next() {
                        remainder -= r;
                        r
                    } else {
                        remainder
                    }
                })
                .collect::<Vec<_>>();

            [
                Replicated::new(values[0], values[1]),
                Replicated::new(values[1], values[2]),
                Replicated::new(values[2], values[0]),
            ]
        }
    }

    #[test]
    fn sparse_sharing() {
        let mut rng = thread_rng();
        for &zp in ZeroPositions::all() {
            let v = rng.gen::<Fp32BitPrime>();
            let shares = SparseField::new(v, zp).share_with(&mut rng);
            for (&role, share) in zip(Role::all(), shares.iter()) {
                zp.check(role, &format!("{role:?}-{zp:?}"), share);
            }
            assert_eq!(v, shares.reconstruct());
        }
    }

    /// Determine whether multiplication for helper X requires sending or receiving.
    /// Argument is a description of which items are zero for shares at each helper.
    /// This indicates whether the left share is zero at each.
    /// Setting a = [true, false, true] means that for the first input:
    ///    H1 has (0, ?), H2 has (?, 0), and H3 has (0, 0)
    /// Return value is (self, left, right)
    fn calculate_work(role: Role, a: [bool; 3], b: [bool; 3]) -> [bool; 3] {
        let a_left_left = a[role.peer(Left) as usize];
        let b_left_left = b[role.peer(Left) as usize];
        let a_left = a[role as usize];
        let b_left = b[role as usize];
        let a_right = a[role.peer(Right) as usize];
        let b_right = b[role.peer(Right) as usize];
        let skip_recv = (a_left_left || b_left) && (a_left || b_left_left);
        let skip_send = (a_left || b_right) && (a_right || b_left);
        let skip_rand = (a_right || b_left_left) && (a_left_left || b_right);
        [!skip_recv, !skip_send, !skip_rand]
    }

    #[test]
    fn check_all_work() {
        for &a in ZeroPositions::all() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in ZeroPositions::all() {
                let b_flags = <[bool; 3]>::from(b);
                for &role in Role::all() {
                    let expected = calculate_work(role, a_flags, b_flags);
                    if expected.iter().any(|&x| x) {
                        assert_eq!(
                            (a, b).work_for(role),
                            expected,
                            "{role:?}: {a:?}={a_flags:?}, {b:?}={b_flags:?}"
                        );
                    } else {
                        assert!(ZeroPositions::is_pointless((a, b)));
                    }
                }
            }
        }
    }

    // These multiplications can be done locally, so don't allow them.

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "attempting to do a multiplication that can be performed locally")]
    fn no_work_vzz() {
        (ZeroPositions::Pvzz, ZeroPositions::Pvzz).work_for(Role::H1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "attempting to do a multiplication that can be performed locally")]
    fn no_work_vzv() {
        (ZeroPositions::Pzvz, ZeroPositions::Pzvz).work_for(Role::H2);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "attempting to do a multiplication that can be performed locally")]
    fn no_work_zzv() {
        (ZeroPositions::Pzzv, ZeroPositions::Pzzv).work_for(Role::H3);
    }

    /// Use this test to get mappings for `ZeroPositions`.
    /// `cargo test -- print_mappings --nocapture --include-ignored | grep 'Self::' | sort -t '>' -k 2`
    /// Then do a little cleanup by taking suggestions from `cargo clippy --tests`.
    #[test]
    #[ignore]
    fn print_mappings() {
        for &a in ZeroPositions::all() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in ZeroPositions::all() {
                let b_flags = <[bool; 3]>::from(b);
                println!(
                    "(Self::{a:?}, Self::{b:?}) => {:?},",
                    calculate_work(Role::H1, a_flags, b_flags)
                );
            }
        }
    }

    fn check_output_zeros<F, T>(v: &[T; 3], work: MultiplyZeroPositions)
    where
        F: Field,
        T: Borrow<Replicated<F>>,
    {
        for (&role, expect_zero) in zip(Role::all(), <[bool; 3]>::from(work.output())) {
            if expect_zero {
                assert_eq!(F::ZERO, v[role as usize].borrow().left());
                assert_eq!(F::ZERO, v[role.peer(Left) as usize].borrow().right());
            }
        }
    }

    #[tokio::test]
    async fn check_output() {
        let world = TestWorld::default();
        let mut rng = thread_rng();

        for &a in ZeroPositions::all() {
            for &b in ZeroPositions::all() {
                if ZeroPositions::is_pointless((a, b)) {
                    continue;
                }

                let v1 = SparseField::new(rng.gen::<Fp31>(), a);
                let v2 = SparseField::new(rng.gen::<Fp31>(), b);
                let result = world
                    .semi_honest((v1, v2), |ctx, (v_a, v_b)| async move {
                        v_a.multiply_sparse(&v_b, ctx.set_total_records(1), RecordId::FIRST, (a, b))
                            .await
                            .unwrap()
                    })
                    .await;
                check_output_zeros(&result, (a, b));
                assert_eq!(v1.value() * v2.value(), result.reconstruct());
            }
        }
    }

    #[tokio::test]
    async fn check_output_malicious() {
        let world = TestWorld::default();
        let mut rng = thread_rng();

        for &a in ZeroPositions::all() {
            for &b in ZeroPositions::all() {
                if ZeroPositions::is_pointless((a, b)) {
                    continue;
                }

                let v1 = SparseField::new(rng.gen::<Fp31>(), a);
                let v2 = SparseField::new(rng.gen::<Fp31>(), b);
                let result = world
                    .malicious((v1, v2), |ctx, (v_a, v_b)| async move {
                        let v = ctx.validator();
                        let m_ctx = v.context().set_total_records(1);
                        let (m_a, m_b) = try_join(
                            m_ctx.narrow(&BitOpStep::from(0)).upgrade_sparse(v_a, a),
                            m_ctx.narrow(&BitOpStep::from(1)).upgrade_sparse(v_b, b),
                        )
                        .await
                        .unwrap();

                        let m_ab = m_a
                            .multiply_sparse(&m_b, m_ctx, RecordId::FIRST, (a, b))
                            .await
                            .unwrap();

                        v.validate(m_ab).await.unwrap()
                    })
                    .await;
                check_output_zeros(&result, (a, b));
                assert_eq!(v1.value() * v2.value(), result.reconstruct());
            }
        }
    }
}
