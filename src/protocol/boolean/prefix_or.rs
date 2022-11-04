use crate::error::BoxError;
use crate::ff::BinaryField;
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

/// This is an implementation of Prefix-Or on bitwise-shared numbers.
///
/// `PrefixOr` takes inputs `[a_1]_p,...,[a_l]_p where a1,...,a_l ∈ {0,1} ⊆ F_p`,
/// and computes `[b_1]_p,...,[b_l]_p where b_i = ∨ a_j where j=1..i`.
///
/// In other words, `b_B <- PrefixOr(a_B)` will output `b_B` where b's i'th bit is
/// 1 iff a's i'th bit is the first bit to have 1.
///
/// This is a sub-protocol used by Bitwise Less-Than protocol for an inequality check
/// operation.
///
/// 5.2 Prefix-Or
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct PrefixOr<'a, B: BinaryField> {
    input: &'a [Replicated<B>],
}

impl<'a, B: BinaryField> PrefixOr<'a, B> {
    #[allow(dead_code)]
    pub fn new(input: &'a [Replicated<B>]) -> Self {
        Self { input }
    }

    /// Securely computes `[a] | [b] where a, b ∈ {0, 1}`
    /// OR can be computed as: `[a] ^ [b] ^ ([a] & [b])`
    async fn bit_or(
        a: Replicated<B>,
        b: Replicated<B>,
        ctx: ProtocolContext<'_, B>,
        record_id: RecordId,
    ) -> Result<Replicated<B>, BoxError> {
        let a_and_b = ctx.multiply(record_id).execute(a, b).await?;
        Ok(a + b + a_and_b)
    }

    /// Securely computes `∨ [a_1],...[a_n]`
    async fn block_or(
        a: &[Replicated<B>],
        k: usize,
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Replicated<B>, BoxError> {
        let mut v = Replicated::new(B::ZERO, B::ZERO);
        for (i, &bit) in a.iter().enumerate() {
            let c = ctx.clone();
            v = Self::bit_or(v, bit, c, RecordId::from(i + k)).await?;
        }
        Ok(v)
    }

    /// Step 1. `for i=1..λ, [x_i] = ∨ [a_(i,j)] where j=1..λ`
    ///
    /// We write `a_k` as `a_(i,j) where k = λ(i - 1) + j, and i,j = 1..λ`
    ///
    /// The interpretation is, `x_i` = 1 iff the i'th block contains 1.
    ///
    /// # Example
    /// ```ignore
    ///   l = 16, λ = 4
    ///   [a] = 0 0 0 0  0 0 1 0  0 1 0 1  0 0 0 0
    ///   [x] = 0 1 1 0
    /// ```
    async fn step1(
        a: &[Replicated<B>],
        lambda: usize,
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let mut block_or = Vec::with_capacity(lambda);
        (0..a.len())
            .step_by(lambda)
            .for_each(|i| block_or.push(Self::block_or(&a[i..i + lambda], i, ctx.clone())));
        try_join_all(block_or).await
    }

    /// Step 2. `for i=1..λ, [y_i] = ∨ [x_k] where k=1..i`
    ///
    /// The interpretation is, `y_i` = 1 iff there is a 1 in one of the i first blocks.
    ///
    /// # Example
    /// ```ignore
    ///   [x] = 0 1 1 0
    ///   [y] = 0 1 1 1
    /// ```
    async fn step2(
        x: &[Replicated<B>],
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let lambda = x.len();
        let mut block_or = Vec::with_capacity(lambda);
        (0..lambda).for_each(|i| block_or.push(Self::block_or(&x[0..=i], i, ctx.clone())));
        try_join_all(block_or).await
    }

    /// Step 3. `[f_1] = [x_1]`
    /// Step 4. `for i=2..λ, [f_i] = [y_i] - [y_(i-1)]`
    ///
    /// The interpretation is, `f_i` is 1 iff the i'th block is the first block to contain a 1.
    ///
    /// # Example
    /// ```ignore
    ///   [x] = 0 1 1 0, [y] = 0 1 1 1
    ///   [f] = 0 1 0 0
    /// ```
    fn step3_4(x: &[Replicated<B>], y: &[Replicated<B>]) -> Vec<Replicated<B>> {
        [x[0]]
            .into_iter()
            .chain((1..x.len()).map(|i| y[i] - y[i - 1]))
            .collect()
    }

    /// Step 5. `for i,j=1..λ, [g_(i,j)] = MULT([f_i], [a_(i,j)])`
    ///
    /// The interpretation is, `g_(i,j) = a_(i,j)` iff `f_i` = 1.
    ///
    /// # Example
    /// ```ignore
    ///   [a] = 0 0 0 0  0 0 1 0  0 1 0 1  0 0 0 0,   [f] = 0 1 0 0
    ///   [g] = 0 0 0 0  0 0 1 0  0 0 0 0  0 0 0 0
    /// ```
    async fn step5(
        f: &[Replicated<B>],
        a: &[Replicated<B>],
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let lambda = f.len();
        let mul = zip(repeat(ctx), a).enumerate().map(|(i, (ctx, &a_bit))| {
            let f_bit = f[i / lambda];
            async move { ctx.multiply(RecordId::from(i)).execute(f_bit, a_bit).await }
        });
        try_join_all(mul).await
    }

    /// Step 6. `for j=1..λ, [c_j] = Σ [g_(i,j)] where i=1..λ`
    ///
    /// The interpretation is, `c` is formed by taking the "inner product" of `f` and `a`.
    ///
    /// # Example
    /// ```ignore
    ///   [g] = 0 0 0 0  0 0 1 0  0 0 0 0  0 0 0 0
    ///   [c] = 0 0 1 0
    /// ```
    fn step6(g: &[Replicated<B>], lambda: usize) -> Vec<Replicated<B>> {
        (0..lambda)
            .map(|j| {
                let mut v = Replicated::new(B::ZERO, B::ZERO);
                (0..g.len()).step_by(lambda).for_each(|i| {
                    v += g[i + j];
                });
                v
            })
            .collect()
    }

    /// Step 7. `for j=1..λ, [b_(,j)] = ∨ [c_k] where k=1..j`
    ///
    /// The interpretation is, `b_(,1)..b_(,λ)` are the prefix-or bits of `c`.
    ///
    /// # Example
    /// ```ignore
    ///   [c] = 0 0 1 0
    ///   [b] = 0 0 1 1
    /// ```
    async fn step7(
        c: &[Replicated<B>],
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let lambda = c.len();
        let mut block_or = Vec::with_capacity(lambda);
        (0..lambda).for_each(|j| block_or.push(Self::block_or(&c[0..=j], j, ctx.clone())));
        try_join_all(block_or).await
    }

    /// Step 8. `for i,j=1..λ, [s_(i,j)] = MULT([f_i], [b_(,j)])`
    ///
    /// The interpretation is, `s_(i,j)` forms an all-0 vector, except that the i'th block equals `c` iff `f_i` = 1.
    ///
    /// # Example
    /// ```ignore
    ///   [f] = 0 1 0 0
    ///   [b] = 0 0 1 1
    ///   [s] = 0 0 0 0  0 0 1 1  0 0 0 0  0 0 0 0
    /// ```
    async fn step8(
        f: &[Replicated<B>],
        b: &[Replicated<B>],
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        let lambda = f.len();
        let mut mul = Vec::new();
        for (i, &f_bit) in f.iter().enumerate().take(lambda) {
            for (j, &b_bit) in b.iter().enumerate().take(lambda) {
                let c = ctx.clone();
                mul.push(
                    c.multiply(RecordId::from(lambda * i + j))
                        .execute(f_bit, b_bit),
                );
            }
        }
        try_join_all(mul).await
    }

    /// Step 9. `for i,j=1..λ, [b_(i,j)] = [s_(i,j)] + [y_i] - [f_i]`
    ///
    /// # Example
    /// ```ignore
    ///   [s] = 0 0 0 0  0 0 1 1  0 0 0 0  0 0 0 0
    ///   [y] = 0 1 1 1
    ///   [f] = 0 1 0 0
    ///   [b] = 0 0 0 0  0 0 1 1  1 1 1 1  1 1 1 1   // <- PrefixOr([a])
    /// ```
    fn step9(s: &[Replicated<B>], y: &[Replicated<B>], f: &[Replicated<B>]) -> Vec<Replicated<B>> {
        let lambda = f.len();
        (0..lambda)
            .flat_map(|i| {
                (0..lambda)
                    .map(|j| s[lambda * i + j] + y[i] - f[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    /// Execute `PrefixOr`
    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute(
        &self,
        ctx: ProtocolContext<'_, B>,
    ) -> Result<Vec<Replicated<B>>, BoxError> {
        // The paper assumes `l = λ^2`, where `l` is the bit length of the input
        // share. Then the input is split into `λ` blocks each holding `λ` bits.
        // Or operations are executed in parallel by running the blocks in
        // parallel.
        //
        // The paper doesn't mention about cases where `l != λ^2`. For now, we
        // pad the input with dummy bits at the end, and will be stripped off
        // before returning the output to the caller. The output is correct
        // regardless of the dummy bits, but may affect the performance if
        // `λ^2 - l` becomes large. We should revisit this protocol once the
        // prototype is complete, and optimize if necessary.
        // TODO(taikiy): Prefix-Or optimization

        // It should be safe to cast from `usize` to `u32` and back cast since
        // the input we expect to operate on are 40-bit < `u8` << `u32`.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let lambda = f64::from(self.input.len() as u32).sqrt().ceil() as usize;
        let dummy = vec![Replicated::new(B::ZERO, B::ZERO); lambda * lambda - self.input.len()];

        let a = [self.input, &dummy].concat();
        let x = Self::step1(&a, lambda, ctx.narrow(&Step::BlockOr1)).await?;
        let y = Self::step2(&x, ctx.narrow(&Step::BlockOr2)).await?;
        let f = Self::step3_4(&x, &y);
        let g = Self::step5(&f, &a, ctx.narrow(&Step::Mult1)).await?;
        let c = Self::step6(&g, lambda);
        let b = Self::step7(&c, ctx.narrow(&Step::BlockOr3)).await?;
        let s = Self::step8(&f, &b, ctx.narrow(&Step::Mult2)).await?;
        let b = Self::step9(&s, &y, &f);

        Ok(b[0..self.input.len()].to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BlockOr1,
    BlockOr2,
    BlockOr3,
    Mult1,
    Mult2,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BlockOr1 => "block_or_1",
            Self::BlockOr2 => "block_or_2",
            Self::BlockOr3 => "block_or_3",
            Self::Mult1 => "mult_1",
            Self::Mult2 => "mult_2",
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::future::try_join_all;
    use rand::{rngs::mock::StepRng, Rng};

    use crate::{
        ff::{Field, Fp2},
        protocol::QueryId,
        secret_sharing::Replicated,
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };

    use super::PrefixOr;

    #[tokio::test]
    pub async fn prefix_or() {
        const BITS: usize = 10;
        const TEST_TRIES: usize = 100;
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp2>(&world);
        let mut rand = StepRng::new(1, 1);
        let mut rng = rand::thread_rng();

        // Test 10-bit bitwise shares with randomly distributed bits, for 100 times.
        // The probability of i'th bit being 0 is 1/2^i, so this test covers inputs
        // that have all 0's in 6-7 first bits.
        for i in 0..TEST_TRIES {
            let len = BITS;
            let input: Vec<Fp2> = (0..len).map(|_| Fp2::from(rng.gen::<bool>())).collect();
            let mut expected: Vec<Fp2> = Vec::with_capacity(len);

            // Calculate Prefix-Or of the secret number
            input.iter().fold(Fp2::ZERO, |acc, &x| {
                expected.push(acc | x);
                acc | x
            });

            // Generate secret shares
            #[allow(clippy::type_complexity)]
            let (s0, (s1, s2)): (
                Vec<Replicated<Fp2>>,
                (Vec<Replicated<Fp2>>, Vec<Replicated<Fp2>>),
            ) = input
                .iter()
                .map(|&x| {
                    let y = share(x, &mut rand);
                    (y[0], (y[1], y[2]))
                })
                .unzip();

            // Execute
            let pre0 = PrefixOr::new(&s0);
            let pre1 = PrefixOr::new(&s1);
            let pre2 = PrefixOr::new(&s2);
            let iteration = format!("{}", i);
            let result = try_join_all(vec![
                pre0.execute(ctx[0].narrow(&iteration)),
                pre1.execute(ctx[1].narrow(&iteration)),
                pre2.execute(ctx[2].narrow(&iteration)),
            ])
            .await
            .unwrap();

            // Verify
            assert_eq!(input.len(), result[0].len());
            for (j, &e) in expected.iter().enumerate().take(input.len()) {
                assert_eq!(
                    e,
                    validate_and_reconstruct((result[0][j], result[1][j], result[2][j])),
                );
            }
        }
    }
}
