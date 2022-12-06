use crate::{ff::Field, helpers::Role, secret_sharing::Replicated};

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
                panic!("this multiplication always produces zero");
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
    pub fn check<F: Field>(self, role: Role, which: &str, v: &Replicated<F>) {
        #[cfg(debug_assertions)]
        {
            use crate::helpers::Direction::Right;
            let flags = <[bool; 3]>::from(self);
            if flags[role as usize] {
                assert_eq!(
                    F::ZERO,
                    v.left(),
                    "expected a zero on the left for input {which}"
                );
            }
            if flags[role.peer(Right) as usize] {
                assert_eq!(
                    F::ZERO,
                    v.right(),
                    "expected a zero on the right for input {which}"
                );
            }
        }
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

    fn output(self) -> ZeroPositions {
        ZeroPositions::mul_output(self)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        ff::{Field, Fp31},
        helpers::{
            Direction::{Left, Right},
            Role,
        },
        protocol::{
            context::Context,
            malicious::MaliciousValidator,
            mul::{sparse::MultiplyWork, MultiplyZeroPositions, SecureMul, ZeroPositions},
            reveal::Reveal,
            BitOpStep, QueryId, RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::Replicated,
        test_fixture::{Runner, TestWorld},
    };
    use futures::future::try_join;
    use std::{borrow::Borrow, iter::zip};

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

    fn all_zps() -> &'static [ZeroPositions] {
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

    #[test]
    fn check_all_work() {
        for &a in all_zps() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in all_zps() {
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
                        println!("skip value with no work");
                    }
                }
            }
        }
    }

    // Asking for work with these combinations is pointless.  The answer is always zero.

    #[test]
    #[should_panic]
    fn no_work1() {
        (ZeroPositions::Pvzz, ZeroPositions::Pvzz).work_for(Role::H1);
    }

    #[test]
    #[should_panic]
    fn no_work2() {
        (ZeroPositions::Pzvz, ZeroPositions::Pzvz).work_for(Role::H2);
    }

    #[test]
    #[should_panic]
    fn no_work3() {
        (ZeroPositions::Pzzv, ZeroPositions::Pzzv).work_for(Role::H3);
    }

    /// Use this test to get mappings for `ZeroPositions`.
    /// `cargo test -- print_mappings --nocapture --include-ignored | grep 'Self::' | sort -t '>' -k 2`
    /// Then do a little cleanup.
    #[test]
    #[ignore]
    fn print_mappings() {
        for &a in all_zps() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in all_zps() {
                let b_flags = <[bool; 3]>::from(b);
                println!(
                    "(Self::{a:?}, Self::{b:?}) => {:?},",
                    calculate_work(Role::H1, a_flags, b_flags)
                );
            }
        }
    }

    /// For the role and the zero positions provided, put holes in this replicated share
    /// as necessary so that the value has zeros in those places.
    fn puncture<F: Field>(role: Role, zp: ZeroPositions, v: &Replicated<F>) -> Replicated<F> {
        let zero_slots = <[bool; 3]>::from(zp);
        let v_left = if zero_slots[role as usize] {
            F::ZERO
        } else {
            v.left()
        };
        let v_right = if zero_slots[role.peer(Right) as usize] {
            F::ZERO
        } else {
            v.right()
        };
        Replicated::new(v_left, v_right)
    }

    fn check_punctured_output<F, T>(v: &[T; 3], work: MultiplyZeroPositions)
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
        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();

        for &a in all_zps() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in all_zps() {
                let b_flags = <[bool; 3]>::from(b);
                println!("{a:?}={:?}; {b:?}={:?}", a_flags, b_flags);

                if calculate_work(Role::H1, a_flags, b_flags)
                    .iter()
                    .all(|&x| !x)
                {
                    continue; // This combination produces zero, always.
                }

                let v1 = rng.gen::<Fp31>();
                let v2 = rng.gen::<Fp31>();
                let result = world
                    .semi_honest((v1, v2), |ctx, (v_a, v_b)| async move {
                        let v_a = puncture(ctx.role(), a, &v_a);
                        let v_b = puncture(ctx.role(), b, &v_b);

                        ctx.multiply_sparse(RecordId::from(0), &v_a, &v_b, (a, b))
                            .await
                            .unwrap()
                    })
                    .await;
                check_punctured_output(&result, (a, b));
            }
        }
    }

    #[tokio::test]
    async fn check_output_malicious() {
        let world = TestWorld::new(QueryId);
        let mut rng = thread_rng();

        for &a in all_zps() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in all_zps() {
                let b_flags = <[bool; 3]>::from(b);

                if calculate_work(Role::H1, a_flags, b_flags)
                    .iter()
                    .all(|&x| !x)
                {
                    continue; // This combination produces zero, always.
                }

                let v1 = rng.gen::<Fp31>();
                let v2 = rng.gen::<Fp31>();
                let result = world
                    .semi_honest((v1, v2), |ctx, (v_a, v_b)| async move {
                        let v_a = puncture(ctx.role(), a, &v_a);
                        let v_b = puncture(ctx.role(), b, &v_b);

                        let (revealed_a, revealed_b) = try_join(
                            ctx.narrow("reveal_a").reveal(RecordId::from(0), &v_a),
                            ctx.narrow("reveal_b").reveal(RecordId::from(0), &v_b),
                        )
                        .await
                        .unwrap();
                        let reveal_ab_ctx = ctx.narrow("reveal_ab");

                        let v = MaliciousValidator::new(ctx);
                        let m_ctx = v.context();
                        let m_a = m_ctx
                            .upgrade_with_sparse(&BitOpStep::from(0), RecordId::from(0), v_a, a)
                            .await
                            .unwrap();
                        let m_b = m_ctx
                            .upgrade_with_sparse(&BitOpStep::from(1), RecordId::from(0), v_b, b)
                            .await
                            .unwrap();

                        let m_ab = m_ctx
                            .multiply_sparse(RecordId::from(0), &m_a, &m_b, (a, b))
                            .await
                            .unwrap();

                        let ab = v.validate(m_ab).await.unwrap();
                        let revealed_ab =
                            reveal_ab_ctx.reveal(RecordId::from(0), &ab).await.unwrap();
                        assert_eq!(revealed_a * revealed_b, revealed_ab);
                        ab
                    })
                    .await;
                check_punctured_output(&result, (a, b));
            }
        }
    }
}
