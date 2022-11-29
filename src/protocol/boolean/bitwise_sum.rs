use super::align_bit_lengths;
use super::carries::Carries;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::RecordId;
use crate::secret_sharing::Replicated;

/// This is an implementation of Bitwise Sum on bitwise-shared numbers.
///
/// `BitwiseSum` takes inputs `[a]_B = ([a_0]_p,...,[a_(l-1)]_p)` where
/// `a_0,...,a_(l-1) ∈ {0,1} ⊆ F_p` and `[b]_B = ([b_0]_p,...,[b_(l-1)]_p)` where
/// `b_0,...,b_(l-1) ∈ {0,1} ⊆ F_p`, then computes `[d]_B = ([d_0]_p,...,[d_l]_p)`
/// of `a + b`.
///
/// Note that the index notation of the inputs is `0..l-1`, whereas the output
/// index notation is `0..l`. This means that the output of this protocol will be
/// "`l+1`"-bit long bitwise secret shares, where `l = |[a]_B|`.
///
/// This protocol calls `Carries` as its sub-protocol to get `c_i ∈ {0, 1}`
/// where `c_i = 1` iff `Σ (2^j * (a_j + b_j)) > 2_i` where `j=0..i-1`. We can
/// then use `[c_i]` to compute a bitwise sharing of sum `[a]_B` and `[b]_b`.
///
/// All computations other than `Carries` are done locally, so the cost of this
/// protocol equals `Carries`' cost.
///
/// 6.2 Bitwise Sum
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct BitwiseSum {}

impl BitwiseSum {
    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, Error> {
        let (a, b) = align_bit_lengths(a, b);
        let l = a.len();

        // Step 1. Get a bitwise sharing of the carries
        let c = Carries::execute(ctx.narrow(&Step::Carries), record_id, &a, &b).await?;

        // Step 2. `[d_0] = [a_0] + [b_0] - 2[c_1]`
        // The paper refers `[c]_b` as `([c_1],...[c_l])`; the starting index is 1;
        // therefore, `[c_1]` is the first element, `c[0]`, in the code.
        let mut d = Vec::with_capacity(l);
        d.push(a[0].clone() + &b[0] - &(c[0].clone() * F::from(2)));

        // Step 3. `[d_l] = [c_l]`
        // Step 4. for `i=1..l-1`, `[d_i] = [a_i] + [b_i] + [c_i] - 2[c_(i+1)]`
        //
        // In the paper, the output of BIT-ADD is `l + 1` long, where `l` is
        // the length of the inputs `a` and `b`. So, if we are working with a
        // 32-bit long field, the output of this protocol will be 33-bit long
        // bitwise shares.
        for i in 1..l {
            d.push(a[i].clone() + &b[i] + &c[i - 1] - &(c[i].clone() * F::from(2)));
        }
        d.push(c[l - 1].clone());

        Ok(d)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    Carries,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::Carries => "carries",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    //use super::BitwiseSum;
    use crate::protocol::boolean::dumb_bitwise_sum::bitwise_sum;
    use crate::rand::thread_rng;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{QueryId, RecordId},
        test_fixture::{bits_to_value, into_bits, Reconstruct, Runner, TestWorld},
    };
    use rand::Rng;
    use rand::{distributions::Standard, prelude::Distribution};

    /// This protocol requires a number of inputs that are equal to a power of 2.
    /// This functions pads those inputs.
    fn pad<F: Field>(mut values: Vec<F>) -> Vec<F> {
        let target_len = 1 << (usize::BITS - (values.len() - 1).leading_zeros());
        values.resize(target_len, F::ZERO);
        values
    }

    async fn sum<F: Field>(a: F, b: F) -> Vec<F>
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let world = TestWorld::new(QueryId);
        let input = (into_bits(a), into_bits(b));
        let n_bits = input.0.len();
        let sum = world
            .semi_honest(input.clone(), |ctx, (a_share, b_share)| async move {
                bitwise_sum(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let m_sum = world
            .malicious(input, |ctx, (a_share, b_share)| async move {
                bitwise_sum(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(sum, m_sum);

        // Output's bit length should be `input.len() + 1`
        assert_eq!(n_bits + 1, sum.len());
        sum
    }

    #[tokio::test]
    pub async fn fp31_basic() {
        let c = Fp31::from;

        assert_eq!(0, bits_to_value(&sum(c(0_u32), c(0)).await));
        assert_eq!(1, bits_to_value(&sum(c(0), c(1)).await));
        assert_eq!(1, bits_to_value(&sum(c(1), c(0)).await));
        assert_eq!(2, bits_to_value(&sum(c(1), c(1)).await));
        assert_eq!(32, bits_to_value(&sum(c(16), c(16)).await));
        assert_eq!(60, bits_to_value(&sum(c(30), c(30)).await));
    }

    #[tokio::test]
    pub async fn fp_32bit_prime_basic() {
        let c = Fp32BitPrime::from;

        assert_eq!(0, bits_to_value(&sum(c(0_u32), c(0)).await));
        assert_eq!(1, bits_to_value(&sum(c(0), c(1)).await));
        assert_eq!(1, bits_to_value(&sum(c(1), c(0)).await));
        assert_eq!(2, bits_to_value(&sum(c(1), c(1)).await));
        assert_eq!(
            2_147_483_648,
            bits_to_value(&sum(c(2_147_483_647), c(1)).await)
        );
        assert_eq!(
            4_294_967_290,
            bits_to_value(&sum(c(2_147_483_645), c(2_147_483_645)).await)
        );
        assert_eq!(
            4_294_967_291,
            bits_to_value(&sum(c(2_147_483_645), c(2_147_483_646)).await)
        );
    }

    #[tokio::test]
    pub async fn cmp_different_bit_lengths() {
        let world = TestWorld::new(QueryId);

        let input = (
            pad(into_bits(Fp31::from(3_u32))), // 8-bit
            into_bits(Fp31::from(5_u32)),      // 5-bit
        );
        let l = input.0.len();
        let sum = world
            .semi_honest(input, |ctx, (a_share, b_share)| async move {
                bitwise_sum(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        // Output's bit length should be `input.len() + 1`
        assert_eq!(l + 1, sum.len());
        assert_eq!(8, bits_to_value(&sum));
    }

    #[tokio::test]
    pub async fn fp_32bit_prime_random() {
        let c = Fp32BitPrime::from;
        let mut rng = thread_rng();

        for _ in 0..10 {
            let a = c(rng.gen::<u128>());
            let b = c(rng.gen());
            assert_eq!(a.as_u128() + b.as_u128(), bits_to_value(&sum(a, b).await));
        }
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn cmp_all_fp31() {
        for a in 0..Fp31::PRIME {
            for b in 0..Fp31::PRIME {
                assert_eq!(
                    u128::from(a + b),
                    bits_to_value(&sum(Fp31::from(a), Fp31::from(b)).await)
                );
            }
        }
    }
}
