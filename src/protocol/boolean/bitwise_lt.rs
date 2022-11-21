use super::prefix_or::PrefixOr;
use super::xor::xor;
use super::BitOpStep;
use crate::error::Error;
use crate::ff::Field;
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
pub struct BitwiseLessThan {}

impl BitwiseLessThan {
    /// Step 1. `for i=0..l-1, [e_i] = XOR([a_i], [b_i])`
    ///
    /// # Example
    /// ```ignore
    ///   //  bit-0         bit-7
    ///   //    v             v
    ///   [a] = 1 0 1 0 1 0 0 0   // 21 in little-endian
    ///   [b] = 0 1 1 1 1 0 0 0   // 30 in little-endian
    ///   [e] = 1 1 0 1 0 0 0 0
    /// ```
    async fn step1<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let xor = zip(a, b).enumerate().map(|(i, (a_bit, b_bit))| {
            let c = ctx.narrow(&BitOpStep::Step(i));
            async move { xor(c, record_id, a_bit, b_bit).await }
        });
        try_join_all(xor).await
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
    async fn step2<F: Field>(
        e: &mut [Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        e.reverse();
        let mut f = PrefixOr::execute(ctx, record_id, e).await?;
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
    fn step3_4<F: Field>(f: &[Replicated<F>]) -> Vec<Replicated<F>> {
        let l = f.len();
        (0..l - 1)
            .map(|i| &f[i] - &f[i + 1])
            .chain([f[l - 1].clone()])
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
    async fn step5<F: Field>(
        g: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let mul = zip(repeat(ctx), zip(g, b))
            .enumerate()
            .map(|(i, (ctx, (g_bit, b_bit)))| {
                let c = ctx.narrow(&BitOpStep::Step(i));
                async move { c.multiply(record_id, g_bit, b_bit).await }
            });
        try_join_all(mul).await
    }

    /// Step 6. `[h] = Σ [h_i] where i=0..l-1`
    ///
    /// The interpretations is, `h` is 1 iff `a < b`
    fn step6<F: Field>(h: &[Replicated<F>]) -> Replicated<F> {
        h.iter()
            .fold(Replicated::new(F::ZERO, F::ZERO), |acc, x| acc + x)
    }

    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Replicated<F>, Error> {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");
        let mut e = Self::step1(a, b, ctx.narrow(&Step::AXorB), record_id).await?;
        let f = Self::step2(&mut e, ctx.narrow(&Step::PrefixOr), record_id).await?;
        let g = Self::step3_4(&f);
        let h = Self::step5(&g, b, ctx.narrow(&Step::MaskLessThanBit), record_id).await?;
        let result = Self::step6(&h);
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    AXorB,
    PrefixOr,
    MaskLessThanBit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::AXorB => "a_xor_b",
            Self::PrefixOr => "prefix_or",
            Self::MaskLessThanBit => "mask_less_than_bit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitwiseLessThan;
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{
            make_contexts, make_world, shared_bits, transpose, validate_and_reconstruct, TestWorld,
        },
    };
    use futures::future::try_join_all;
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng, Rng};

    // `fp_32bit_prime()` takes about 1sec with 30 tries
    const TEST_TRIES: u32 = 30;

    async fn bitwise_lt<F: Field>(
        ctx: [ProtocolContext<'_, Replicated<F>, F>; 3],
        record_id: RecordId,
        a: F,
        b: F,
    ) -> Result<F, Error>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;
        let mut rand = StepRng::new(1, 1);

        // Generate secret shares
        let a_bits = shared_bits(a, &mut rand);
        let b_bits = shared_bits(b, &mut rand);

        // Execute
        let result = try_join_all([
            BitwiseLessThan::execute(
                c0.bind(record_id),
                record_id,
                &transpose(&a_bits, 0),
                &transpose(&b_bits, 0),
            ),
            BitwiseLessThan::execute(
                c1.bind(record_id),
                record_id,
                &transpose(&a_bits, 1),
                &transpose(&b_bits, 1),
            ),
            BitwiseLessThan::execute(
                c2.bind(record_id),
                record_id,
                &transpose(&a_bits, 2),
                &transpose(&b_bits, 2),
            ),
        ])
        .await
        .unwrap();

        Ok(validate_and_reconstruct(&result[0], &result[1], &result[2]))
    }

    #[tokio::test]
    pub async fn fp31() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..TEST_TRIES {
            let (a, b): (Fp31, Fp31) = (rng.gen::<Fp31>(), rng.gen::<Fp31>());
            let expected = if a.as_u128() < b.as_u128() {
                Fp31::ONE
            } else {
                Fp31::ZERO
            };

            assert_eq!(
                expected,
                bitwise_lt(
                    [c0.clone(), c1.clone(), c2.clone()],
                    RecordId::from(i),
                    a,
                    b
                )
                .await?
            );
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp32BitPrime>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..TEST_TRIES {
            let (a, b): (Fp32BitPrime, Fp32BitPrime) =
                (rng.gen::<Fp32BitPrime>(), rng.gen::<Fp32BitPrime>());
            let expected = if a.as_u128() < b.as_u128() {
                Fp32BitPrime::ONE
            } else {
                Fp32BitPrime::ZERO
            };

            assert_eq!(
                expected,
                bitwise_lt(
                    [c0.clone(), c1.clone(), c2.clone()],
                    RecordId::from(i),
                    a,
                    b
                )
                .await?
            );
        }
        Ok(())
    }
}
