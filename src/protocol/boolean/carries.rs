use super::BitOpStep;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{context::Context, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

#[derive(Clone, Debug)]
/// This struct represents set/propagate/kill bits used to compute the carries.
struct CarryPropagationShares<F: Field> {
    s: Replicated<F>,
    p: Replicated<F>,
    k: Replicated<F>,
}

/// This is an implementation of Carries on bitwise-shared numbers.
///
/// `Carries` takes inputs `[a]_B = ([a_1]_p,...,[a_l]_p)` where
/// `a_1,...,a_l ∈ {0,1} ⊆ F_p`, and `[b]_B = ([b_1]_p,...,[b_l]_p)` where
/// `b_1,...,b_l ∈ {0,1} ⊆ F_p`, then computes `[c]_B = ([c_1]_p,...,[c_l]_p)`
/// where `c_1,...,c_l ∈ {0,1} ⊆ F_p`, and `c_i = 1` iff `i`'th carry bit is
/// set.
///
/// In order to compute the carries, we use set (s) / propagate (p) / kill (k)
/// algorithm. `s_i = 1` iff a carry is set at position `i` (i.e., `a_i + b_i = 2`);
/// `p_i = 1` iff a carry would be propagated at position `i`
/// (i.e., `a_i + b_i = 1`); and `k_i = 1` iff a carry would be killed at
/// position `i` (i.e., `a_i + b_i = 0`).
///
/// 6.3 Computing the carry bits
/// 6.4 Unbounded fan-in carry propagation
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct Carries {}

impl Carries {
    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, Error> {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");
        let s = Self::step1(a, b, ctx.narrow(&Step::AMultB), record_id).await?;
        let e = Self::step2(a, b, &s, &Replicated::one(ctx.role()));
        let f = Self::step3(&e, ctx.narrow(&Step::CarryPropagation), record_id).await?;
        let s = f.into_iter().map(|x| x.s).collect::<Vec<_>>();
        Ok(s)
    }

    /// Step 1. for `i=0..l=1`, `[s_i] = MULT([a_i], [b_i])`
    ///
    /// The interpretation is, `s_i` = 1 iff i'th bit of a and b are 1.
    ///
    /// # Example
    /// ```ignore
    ///   // Input
    ///   [a] = 1 1 0 1 0 1 1 0   // 214 in LE
    ///   [b] = 0 0 0 1 1 1 0 0   // 28 in LE
    ///   // Output
    ///   [s] = 0 0 0 1 0 1 0 0
    /// ```
    async fn step1<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let mul = zip(repeat(ctx), zip(a, b))
            .enumerate()
            .map(|(i, (ctx, (a_bit, b_bit)))| {
                let c = ctx.narrow(&BitOpStep::Step(i));
                async move { c.multiply(record_id, a_bit, b_bit).await }
            });
        try_join_all(mul).await
    }

    /// Step 2. for `i=0..l=1`, generate a vector of tuples `([s], [p], [k])` where
    /// `[p_i] = [a_i] + [b_i] - 2*[s_i]`, and `[k_i] = 1 - [s_i] - [p_i]`
    ///
    /// The interpretations is:
    ///   * `s_i = 1` iff carry is set at position `i` (i.e. `a_i + b_i = 2`)
    ///   * `p_i = 1` iff carry would be propagated at position `i` (i.e. `a_i + b_i = 1`)
    ///   * `k_i = 1` iff a carry would be killed at position `i` (i.e. `a_i + b_i = 0`)
    ///
    /// # Example
    /// ```ignore
    /// // Input
    ///   [a] = 1 1 0 1 0 1 1 0   // 214 in LE
    ///   [b] = 0 0 0 1 1 1 0 0   // 28 in LE
    ///   [s] = 0 0 0 1 0 1 0 0
    /// // Output
    ///   [s] = 0 0 0 1 0 1 0 0   // `a_i & b_i`
    ///   [p] = 1 1 0 0 1 0 1 0   // `a_i ^ b_i`
    ///   [k] = 0 0 1 0 0 0 0 1   // `!(a_i | b_i)`
    /// ```
    #[allow(clippy::many_single_char_names)]
    fn step2<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        s: &[Replicated<F>],
        one: &Replicated<F>,
    ) -> Vec<CarryPropagationShares<F>> {
        zip(a, b)
            .zip(s)
            .map(|((a_bit, b_bit), s_bit)| {
                let p_bit = a_bit + b_bit - &(s_bit.clone() * F::from(2));
                CarryPropagationShares {
                    s: s_bit.clone(),
                    p: p_bit.clone(),
                    k: one - s_bit - &p_bit,
                }
            })
            .collect::<Vec<_>>()
    }

    /// Step 3. Prefix Carry-Propagation
    ///
    /// Let `e_i = (s_i, p_i, k_i)`, and `○` be the carry-propagation operator, it
    /// computes `([f_0],...,[f_l]) ← PRE○([e_0],...,[e_l])`.
    async fn step3<F: Field>(
        e: &[CarryPropagationShares<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<CarryPropagationShares<F>>, Error> {
        let l = e.len();
        let futures = (0..l).map(|i| {
            let c = ctx.narrow(&BitOpStep::Step(i));
            async move { Self::fan_in_carry_propagation(&e[0..=i], c, record_id).await }
        });
        try_join_all(futures).await
    }

    /// 6.4 Unbounded Fan-In Carry Propagation
    ///
    /// Step 1. `for i=1..l, [b] ← ∧ [p_i] i=1..l`
    /// Step 2. `for i=l..1, [q] = PRE∧ [p_j]`
    /// Step 3. `for i=1..l-1, [c_i] = [k_i] ^ [q_(i+1)]`, and `[c_l] = [k_l]`
    /// Step 4. `for i=1..l, [c] = Σ [c_i]`
    /// Step 5. `[a] = 1 - [b] - [c]`
    ///
    /// Output: ([a], [b], [c])
    /// `[a]` => carry set flag
    /// `[b]` => propagate flag
    /// `[c]` => kill flag
    #[allow(clippy::many_single_char_names)]
    async fn fan_in_carry_propagation<F: Field>(
        e: &[CarryPropagationShares<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<CarryPropagationShares<F>, Error> {
        let l = e.len();

        // TODO(taikiy): Optimization: Could run the following 2 blocks in parallel

        // Step 1. fan-in AND. for `i=1..l, ∧ [p_i]`
        let c = ctx.narrow(&Step::FanInAndP);
        let mut b = e[0].p.clone();
        for (i, x) in e.iter().enumerate().skip(1) {
            let c = c.narrow(&BitOpStep::Step(i));
            b = c.multiply(record_id, &b, &x.p).await?;
        }

        // Step 2. prefix AND. for `i=l..1, ∧ [p_j]` where `j=l..i`
        // Note the `i=l..1`. The output bits are in the reverse order.
        let c = ctx.narrow(&Step::PrefixAndP);
        let mut q = Vec::with_capacity(l);
        q.push(e[l - 1].p.clone());
        for (i, x) in e.iter().rev().enumerate().skip(1) {
            let c = c.narrow(&BitOpStep::Step(i));
            // TODO(taikiy): Optimization. Use the symmetric function `PrefixAnd`?
            let result = c.multiply(record_id, &q[i - 1], &x.p).await?;
            q.push(result);
        }
        // Change the order back to LE (LSB first). The next step traverses [q] in i=1..l
        q.reverse();

        // Step 3. for `i=1..l-1, [c_i] = [k_i] ^ [q_(i+1)]`, and `[c_l] = [k_l]`
        let c = ctx.narrow(&Step::KAndQ);
        let futures = e
            .iter()
            .enumerate()
            .take_while(|(i, _)| *i < l - 1)
            .map(|(i, x)| {
                let c = c.narrow(&BitOpStep::Step(i));
                c.multiply(record_id, &x.k, &q[i + 1])
            })
            .collect::<Vec<_>>();
        let mut c = try_join_all(futures).await?;
        c.push(e[l - 1].k.clone());

        // Step 4. `[c] = Σ [c_i]`
        // There's at most one c_i = 1. [c] will be a secret sharing of 0 or 1.
        let c = c.iter().fold(Replicated::ZERO, |acc, x| acc + x);

        // Step 5. `[a] = 1 - [b] - [c]`
        let a = Replicated::one(ctx.role()) - &b - &c;

        Ok(CarryPropagationShares { s: a, p: b, k: c })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    AMultB,
    CarryPropagation,
    FanInAndP,
    PrefixAndP,
    KAndQ,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::AMultB => "a_mult_b",
            Self::CarryPropagation => "carry_propagation",
            Self::FanInAndP => "fan_in_and_p",
            Self::PrefixAndP => "prefix_and_p",
            Self::KAndQ => "k_and_q",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::Carries;
    use crate::ff::{Field, Fp31, Fp32BitPrime};
    use crate::protocol::{QueryId, RecordId};
    use crate::test_fixture::{into_bits, Reconstruct, Runner, TestWorld};
    use rand::{distributions::Standard, prelude::Distribution};

    async fn carries<F: Field>(a: F, b: F) -> Vec<F>
    where
        Standard: Distribution<F>,
    {
        let world = TestWorld::new(QueryId);

        let input = (into_bits(a), into_bits(b));
        let result = world
            .semi_honest(input, |ctx, (a_shares, b_shares)| async move {
                Carries::execute(ctx, RecordId::from(0), &a_shares, &b_shares)
                    .await
                    .unwrap()
            })
            .await;
        result.reconstruct()
    }

    #[tokio::test]
    pub async fn fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;

        // 0 + 0 -> no carry
        assert_eq!(
            vec![zero, zero, zero, zero, zero],
            carries(c(0_u8), c(0)).await
        );
        // 0 + 0 -> no carry
        assert_eq!(
            vec![zero, zero, zero, zero, zero],
            carries(c(1), c(0)).await
        );
        // 01 + 01 -> carry at i=0
        assert_eq!(vec![one, zero, zero, zero, zero], carries(c(1), c(1)).await);
        // 10 + 01 -> no carry
        assert_eq!(
            vec![zero, zero, zero, zero, zero],
            carries(c(2), c(1)).await
        );
        // 10 + 10 -> carry at i=1
        assert_eq!(vec![zero, one, zero, zero, zero], carries(c(2), c(2)).await);
        // 11 + 01 -> carries at i=0,1
        assert_eq!(vec![one, one, zero, zero, zero], carries(c(3), c(1)).await);
        // 0101 + 0101 -> carries at i=0,2
        assert_eq!(vec![one, zero, one, zero, zero], carries(c(5), c(5)).await);
        // 1111 + 0001 -> carries at i=0,1,2,3,
        assert_eq!(vec![one, one, one, one, zero], carries(c(15), c(1)).await);
        // 0001 1110 + 0000 0011 -> carries at i=2,3,4,5
        assert_eq!(vec![zero, one, one, one, one], carries(c(30), c(3)).await);
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() {
        let c = Fp32BitPrime::from;
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;

        assert_eq!(
            vec![
                zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
                zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
                zero, zero, zero, zero,
            ],
            carries(c(0_u32), c(1)).await
        );
        assert_eq!(
            vec![
                one, zero, one, one, one, one, one, one, one, one, one, one, one, one, one, one,
                one, one, one, one, one, one, one, one, one, one, one, one, one, one, one, zero,
            ],
            carries(c(2_147_483_645), c(2_147_483_645)).await
        );
        assert_eq!(
            vec![
                one, one, one, one, one, one, one, one, one, one, one, one, one, one, one, one,
                one, one, one, one, one, one, one, one, one, one, one, one, one, one, one, zero,
            ],
            carries(c(2_147_483_647), c(1)).await
        );
        assert_eq!(
            vec![
                zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
                zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
                zero, zero, zero, one,
            ],
            carries(c(2_147_483_648), c(2_147_483_648)).await
        );
        assert_eq!(
            vec![
                zero, zero, zero, one, one, one, one, one, one, one, one, one, one, one, one, one,
                one, one, one, one, one, one, one, one, one, one, one, one, one, one, one, one,
            ],
            carries(c(4_294_967_290), c(8)).await
        );
    }
}
