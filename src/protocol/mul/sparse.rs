use crate::helpers::Role;

#[derive(Clone, Copy, Debug)]
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
    pub const ALL: (Self, Self) = (Self::Pvvv, Self::Pvvv);
    pub const AVVV_BZZV: (Self, Self) = (Self::Pvvv, Self::Pzzv);
    pub const AVZZ_BZVZ: (Self, Self) = (Self::Pvzz, Self::Pzvz);

    /// Get the work that `Role::H1` would perform given two values with known zero values
    /// in the identified positions.  Work is who sends: `[left, self, right]`, which for
    /// the current role is interpreted as `[recv, send, add_random_rhs]`.
    fn work(a: Self, b: Self) -> [bool; 3] {
        match (a, b) {
            (Self::Pvzz, Self::Pvzz) | (Self::Pzvz, Self::Pzvz) | (Self::Pzzv, Self::Pzzv) => {
                panic!("this multiplication always produces zero");
            }
            (Self::Pzvv, Self::Pzvv | Self::Pzvz | Self::Pzzv)
            | (Self::Pzvz, Self::Pzvv | Self::Pzzv)
            | (Self::Pzzv, Self::Pzvv | Self::Pzvz) => [false, false, true],
            (Self::Pvvz, Self::Pvvz | Self::Pvzz | Self::Pzvz)
            | (Self::Pvzz, Self::Pvvz | Self::Pzvz)
            | (Self::Pzvz, Self::Pvvz | Self::Pvzz) => [false, true, false],
            (Self::Pvvv | Self::Pvzv, Self::Pzvz) | (Self::Pzvz, Self::Pvvv | Self::Pvzv) => {
                [false, true, true]
            }
            (Self::Pvzv, Self::Pvzv | Self::Pvzz | Self::Pzzv)
            | (Self::Pvzz, Self::Pvzv | Self::Pzzv)
            | (Self::Pzzv, Self::Pvzv | Self::Pvzz) => [true, false, false],
            (Self::Pvvv | Self::Pvvz, Self::Pzzv) | (Self::Pzzv, Self::Pvvv | Self::Pvvz) => {
                [true, false, true]
            }
            (Self::Pvzz, Self::Pvvv | Self::Pzvv) | (Self::Pvvv | Self::Pzvv, Self::Pvzz) => {
                [true, true, false]
            }
            (Self::Pvvv, Self::Pvvv | Self::Pvvz | Self::Pvzv | Self::Pzvv)
            | (Self::Pvvz | Self::Pvzv | Self::Pzvv, Self::Pvvv)
            | (Self::Pvvz, Self::Pvzv | Self::Pzvv)
            | (Self::Pvzv, Self::Pvvz | Self::Pzvv)
            | (Self::Pzvv, Self::Pvvz | Self::Pvzv) => [true, true, true],
        }
    }

    fn output(a: Self, b: Self) -> Self {
        // A zero only appears on the lhs of the output if the helper is neither
        // sending nor receiving.
        match Self::work(a, b) {
            [false, false, true] => Self::Pzvv,
            [false, true, false] => Self::Pvvz,
            [true, false, false] => Self::Pvzv,
            _ => Self::Pvvv,
        }
    }
}

/// This struct includes public constants for different arrangements of known zeros in shares.
/// The value of this can be used to determine which of the three helpers sends during a multiplication.
pub(super) trait MultiplyWork {
    /// Determine the work that is required for the identified role.
    /// Return value is who is sending relative to the given role [self, left, right].
    fn work_for(&self, role: Role) -> [bool; 3];
    /// Determines where there are known zeros in the output of a multiplication.
    fn output(&self) -> ZeroPositions;
    /// Determines what an upgraded multiply (as used by the malicious code) would need to use.
    fn upgraded(&self) -> MultiplyZeroPositions;
}

impl MultiplyWork for MultiplyZeroPositions {
    fn work_for(&self, role: Role) -> [bool; 3] {
        let work = ZeroPositions::work(self.0, self.1);
        let i = role as usize;
        let need_to_recv = work[i];
        let need_to_send = work[(i + 1) % 3];
        let need_random_right = work[(i + 2) % 3];
        [need_to_recv, need_to_send, need_random_right]
    }

    fn output(&self) -> ZeroPositions {
        ZeroPositions::output(self.0, self.1)
    }

    fn upgraded(&self) -> MultiplyZeroPositions {
        ((self.0, ZeroPositions::Pvvv).output(), self.1)
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
            mul::{sparse::MultiplyWork, SecureMul, ZeroPositions},
            QueryId, RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::Replicated,
        test_fixture::{Runner, TestWorld},
    };
    use std::iter::zip;

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
        let can_skip_recv = (a_left_left || b_left) && (a_left || b_left_left);
        let can_skip_send = (a_left || b_right) && (a_right || b_left);
        let can_skip_rand = (a_right || b_left_left) && (a_left_left || b_right);
        [!can_skip_recv, !can_skip_send, !can_skip_rand]
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

    #[tokio::test]
    async fn check_output() {
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

        let world = TestWorld::new(QueryId);
        for &a in all_zps() {
            let a_flags = <[bool; 3]>::from(a);
            for &b in all_zps() {
                let b_flags = <[bool; 3]>::from(b);

                if calculate_work(Role::H1, a_flags, b_flags)
                    .iter()
                    .all(|&x| !x)
                {
                    // This combination produces zero, always.
                    continue;
                }

                let mut rng = thread_rng();
                let v1 = rng.gen::<Fp31>();
                let v2 = rng.gen::<Fp31>();
                let result = world
                    .semi_honest((v1, v2), |ctx, (v_a, v_b)| async move {
                        let v_a = puncture(ctx.role(), a, &v_a);
                        let v_b = puncture(ctx.role(), b, &v_b);
                        ctx.multiply_sparse(RecordId::from(0), &v_a, &v_b, &(a, b))
                            .await
                            .unwrap()
                    })
                    .await;
                for (&role, expect_zero) in zip(Role::all(), <[bool; 3]>::from((a, b).output())) {
                    if expect_zero {
                        assert_eq!(Fp31::ZERO, result[role as usize].left());
                        assert_eq!(Fp31::ZERO, result[role.peer(Left) as usize].right());
                    }
                }
            }
        }
    }
}
