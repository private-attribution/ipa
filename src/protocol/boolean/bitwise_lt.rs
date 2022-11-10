use super::prefix_or::PrefixOr;
use super::BitOpStep;
use crate::error::BoxError;
use crate::ff::BinaryField;
use crate::protocol::{context::ProtocolContext, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

/// This is an implementation of Bitwise Less-Than on bitwise-shared numbers.
///
/// `BitwiseLessThan` takes inputs `[a]_B = ([a_1]_p,...,[a_l]_p)` where
/// `a1,...,a_l ∈ {0,1} ⊆ F_p` and `[b]_B = ([b_1]_p,...,[b_l]_p)` where
/// `b1,...,b_l ∈ {0,1} ⊆ F_p`, then computes `h ∈ {0, 1} <- a <? b` where
/// `h = 1` iff `a` is less than `b`.
///
/// Note that `[a]_B` can be converted to `[a]_p` by `Σ (2^i * a_i), i=0..l`. In
/// other words, if comparing two integers, the protocol expects inputs to be in
/// the little-endian; the least-significant byte at the smallest address (0'th
/// element).
///
/// 5.3 Bitwise Less-Than
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct BitwiseLessThan<'a, B: BinaryField> {
    a: &'a [Replicated<B>],
    b: &'a [Replicated<B>],
}

impl<'a, B: BinaryField> BitwiseLessThan<'a, B> {
    #[allow(dead_code)]
    pub fn new(a: &'a [Replicated<B>], b: &'a [Replicated<B>]) -> Self {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");
        Self { a, b }
    }

    /// Step 1. `for i=0..l-1, [e_i] = XOR([a_i], [b_i])`
    ///
    /// We can compute `[a] ⊕ [b], a,b ∈ Z_2` as `[a + b]` locally.
    ///
    /// # Example
    /// ```ignore
    ///   //  bit-0         bit-7
    ///   //    v             v
    ///   [a] = 1 0 1 0 1 0 0 0   // 21 in little-endian
    ///   [b] = 0 1 1 1 1 0 0 0   // 30 in little-endian
    ///   [e] = 1 1 0 1 0 0 0 0
    /// ```
    fn step1(a: &[Replicated<B>], b: &[Replicated<B>]) -> Vec<Replicated<B>> {
        zip(a, b)
            .map(|(&a_bit, &b_bit)| a_bit + b_bit)
            .collect::<Vec<_>>()
    }

    /// Step 2. `([f_(l-1)]..[f_0]) = PrefixOr([e_(l-1)]..[e_0])`
    ///
    /// We compute `PrefixOr` of [e] in the reverse order. Remember that the
    /// inputs are in little-endian format. In this step, we try to find the
    /// smallest `i` (or MSB since `e` is reversed) where `a_i != b_i`. The
    /// output is in big-endian, note that the ordering of `[f]` in the notation
    /// above is also reversed as in `([f_(l-1)]..[f_0])`, hence we reverse the
    /// vector once again before returning.
    ///
    /// # Example
    /// ```ignore
    ///   //  bit-0         bit-7
    ///   //    v             v
    ///   [e] = 1 1 0 1 0 0 0 0
    ///   [f] = 0 0 0 0 1 1 1 1
    /// ```
    async fn step2(
        e: &mut [Replicated<B>],
        ctx: ProtocolContext<'_, Replicated<B>, B>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        e.reverse();
        let mut f = PrefixOr::new(e).execute(ctx, record_id).await?;
        f.reverse();
        Ok(f)
    }

    /// Step 3. `[g_(l-1)] = [f_(l-1)]`
    /// Step 4. `for i=0..l-2, [g_i] = [f_i] - [f_(i+1)]`
    ///
    /// The interpretation is, `g_i` is 1 where the first MSB `a_i != b_i` occurs.
    ///
    /// # Example
    /// ```ignore
    ///   [f] = 0 0 0 0 1 1 1 1
    ///   [g] = 0 0 0 1 0 0 0 0
    /// ```
    fn step3_4(f: &[Replicated<B>]) -> Vec<Replicated<B>> {
        let l = f.len();
        (0..l - 1)
            .map(|i| f[i] - f[i + 1])
            .chain([f[l - 1]])
            .collect()
    }

    /// Step 5. `for i=0..l-1, [h_i] = MULT([g_i], [b_i])`
    ///
    /// The interpretation is, `h_i` is 1 iff `a_i != b_i` and `b_i = 1`.
    ///
    /// # Example
    /// ```ignore
    ///   [g] = 0 0 0 1 0 0 0 0
    ///   [b] = 0 1 1 1 1 0 0 0
    ///   [h] = 0 0 0 1 0 0 0 0
    /// ```
    async fn step5(
        g: &[Replicated<B>],
        b: &[Replicated<B>],
        ctx: ProtocolContext<'_, Replicated<B>, B>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let mul = zip(repeat(ctx), zip(g, b))
            .enumerate()
            .map(|(i, (ctx, (&g_bit, &b_bit)))| {
                let c = ctx.narrow(&BitOpStep::Step(i));
                async move { c.multiply(record_id, g_bit, b_bit).await }
            });
        try_join_all(mul).await
    }

    /// Step 6. `[h] = Σ [h_i] where i=0..l-1`
    ///
    /// The interpretations is, `h` is 1 iff `a < b`
    fn step6(h: &[Replicated<B>]) -> Replicated<B> {
        h.iter()
            .fold(Replicated::new(B::ZERO, B::ZERO), |acc, &x| acc + x)
    }

    #[allow(dead_code)]
    pub async fn execute(
        &self,
        ctx: ProtocolContext<'_, Replicated<B>, B>,
        record_id: RecordId,
    ) -> Result<Replicated<B>, BoxError> {
        let mut e = Self::step1(self.a, self.b);
        let f = Self::step2(&mut e, ctx.narrow(&Step::PrefixOr), record_id).await?;
        let g = Self::step3_4(&f);
        let h = Self::step5(&g, self.b, ctx.narrow(&Step::MaskLessThanBit), record_id).await?;
        let result = Self::step6(&h);
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    PrefixOr,
    MaskLessThanBit,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::PrefixOr => "prefix_or",
            Self::MaskLessThanBit => "mask_less_than_bit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitwiseLessThan;
    use crate::{
        error::BoxError,
        ff::{Field, Fp2, Fp31},
        protocol::{QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::rngs::mock::StepRng;
    use std::iter::zip;

    type BitwiseShares = (
        Vec<Replicated<Fp2>>,
        (Vec<Replicated<Fp2>>, Vec<Replicated<Fp2>>),
    );

    fn fp31_to_bits(x: Fp31) -> Vec<Fp2> {
        let x = u8::from(x);
        (0..u8::BITS).map(|i| Fp2::from(x >> i & 1)).collect()
    }

    async fn bitwise_lt(a: Fp31, b: Fp31) -> Result<Fp2, BoxError> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp2>(&world);
        let mut rand = StepRng::new(1, 1);

        let a_bits = fp31_to_bits(a);
        let b_bits = fp31_to_bits(b);

        // Generate secret shares
        #[allow(clippy::type_complexity)]
        let ((a0, (a1, a2)), (b0, (b1, b2))): (BitwiseShares, BitwiseShares) = zip(a_bits, b_bits)
            .map(|(a_i, b_i)| {
                let x = share(a_i, &mut rand);
                let y = share(b_i, &mut rand);
                ((x[0], (x[1], x[2])), (y[0], (y[1], y[2])))
            })
            .unzip();

        // Execute
        let pre0 = BitwiseLessThan::new(&a0, &b0);
        let pre1 = BitwiseLessThan::new(&a1, &b1);
        let pre2 = BitwiseLessThan::new(&a2, &b2);
        let step = "BitwiseLT_Test";
        let result = try_join_all(vec![
            pre0.execute(ctx[0].narrow(step), RecordId::from(0_u32)),
            pre1.execute(ctx[1].narrow(step), RecordId::from(0_u32)),
            pre2.execute(ctx[2].narrow(step), RecordId::from(0_u32)),
        ])
        .await
        .unwrap();

        Ok(validate_and_reconstruct((result[0], result[1], result[2])))
    }

    #[tokio::test]
    pub async fn basic() -> Result<(), BoxError> {
        let fp31 = Fp31::from;

        assert_eq!(Fp2::ONE, bitwise_lt(Fp31::ZERO, Fp31::ONE).await?);
        assert_eq!(Fp2::ZERO, bitwise_lt(Fp31::ONE, Fp31::ZERO).await?);
        assert_eq!(Fp2::ZERO, bitwise_lt(Fp31::ZERO, Fp31::ZERO).await?);
        assert_eq!(Fp2::ZERO, bitwise_lt(Fp31::ONE, Fp31::ONE).await?);

        assert_eq!(Fp2::ONE, bitwise_lt(fp31(3_u32), fp31(7)).await?);
        assert_eq!(Fp2::ZERO, bitwise_lt(fp31(21), fp31(20)).await?);
        assert_eq!(Fp2::ZERO, bitwise_lt(fp31(9), fp31(9)).await?);

        assert_eq!(
            Fp2::ZERO,
            bitwise_lt(Fp31::ZERO, Fp31::from(Fp31::PRIME)).await?
        );

        Ok(())
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn cmp_all_fp31() -> Result<(), BoxError> {
        for a in 0..Fp31::PRIME {
            for b in 0..Fp31::PRIME {
                assert_eq!(
                    Fp2::from(a < b),
                    bitwise_lt(Fp31::from(a), Fp31::from(b)).await?
                );
            }
        }
        Ok(())
    }
}
