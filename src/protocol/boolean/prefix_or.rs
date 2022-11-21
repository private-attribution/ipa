use super::{or::or, BitOpStep};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::ProtocolContext, mul::SecureMul, RecordId};
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
pub struct PrefixOr {}

impl PrefixOr {
    /// Securely computes `∨ [a_1],...[a_n]`
    async fn block_or<F: Field>(
        a: &[Replicated<F>],
        k: usize,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Replicated<F>, Error> {
        #[allow(clippy::cast_possible_truncation)]
        let mut v = a[0].clone();
        for (i, bit) in a[1..].iter().enumerate() {
            v = or(ctx.narrow(&BitOpStep::Step(k + i)), record_id, &v, bit).await?;
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
    async fn step1<F: Field>(
        a: &[Replicated<F>],
        lambda: usize,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let mut futures = Vec::with_capacity(lambda);
        (0..a.len()).step_by(lambda).for_each(|i| {
            futures.push(Self::block_or(&a[i..i + lambda], i, ctx.clone(), record_id));
        });
        try_join_all(futures).await
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
    async fn step2<F: Field>(
        x: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let lambda = x.len();
        let mut y = Vec::with_capacity(lambda);
        y.push(x[0].clone());
        for i in 1..lambda {
            let result = or(ctx.narrow(&BitOpStep::Step(i)), record_id, &y[i - 1], &x[i]).await?;
            y.push(result);
        }
        Ok(y)
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
    fn step3_4<F: Field>(x: &[Replicated<F>], y: &[Replicated<F>]) -> Vec<Replicated<F>> {
        [x[0].clone()]
            .into_iter()
            .chain((1..x.len()).map(|i| &y[i] - &y[i - 1]))
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
    async fn step5<F: Field>(
        f: &[Replicated<F>],
        a: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let lambda = f.len();
        let mul = zip(repeat(ctx), a).enumerate().map(|(i, (ctx, a_bit))| {
            let f_bit = &f[i / lambda];
            let c = ctx.narrow(&BitOpStep::Step(i));
            async move { c.multiply(record_id, f_bit, a_bit).await }
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
    fn step6<F: Field>(g: &[Replicated<F>], lambda: usize) -> Vec<Replicated<F>> {
        (0..lambda)
            .map(|j| {
                let mut v = Replicated::new(F::ZERO, F::ZERO);
                (0..g.len()).step_by(lambda).for_each(|i| {
                    v += &g[i + j];
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
    async fn step7<F: Field>(
        c: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let lambda = c.len();
        let mut b = Vec::with_capacity(lambda);
        b.push(c[0].clone());
        for j in 1..lambda {
            let result = or(ctx.narrow(&BitOpStep::Step(j)), record_id, &b[j - 1], &c[j]).await?;
            b.push(result);
        }
        Ok(b)
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
    async fn step8<F: Field>(
        f: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let lambda = f.len();
        let mut mul = Vec::new();
        for (i, f_bit) in f.iter().enumerate() {
            for (j, b_bit) in b.iter().enumerate() {
                let c = ctx.narrow(&BitOpStep::Step(lambda * i + j));
                mul.push(c.multiply(record_id, f_bit, b_bit));
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
    fn step9<F: Field>(
        s: &[Replicated<F>],
        y: &[Replicated<F>],
        f: &[Replicated<F>],
    ) -> Vec<Replicated<F>> {
        let lambda = f.len();
        (0..lambda)
            .flat_map(|i| {
                (0..lambda)
                    .map(|j| &s[lambda * i + j] + &y[i] - &f[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
        input: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, Error> {
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
        // TODO(taikiy): Prefix-Or dummy-bits optimization

        let (a, lambda) = Self::add_dummy_bits(input);
        let x = Self::step1(&a, lambda, ctx.narrow(&Step::BitwiseOrPerBlock), record_id).await?;
        let y = Self::step2(&x, ctx.narrow(&Step::BlockWisePrefixOr), record_id).await?;
        let f = Self::step3_4(&x, &y);
        let g = Self::step5(&f, &a, ctx.narrow(&Step::GetFirstBlockWithOne), record_id).await?;
        let c = Self::step6(&g, lambda);
        let b = Self::step7(&c, ctx.narrow(&Step::InnerProduct), record_id).await?;
        let s = Self::step8(&f, &b, ctx.narrow(&Step::SetFirstBlockWithOne), record_id).await?;
        let b = Self::step9(&s, &y, &f);

        Ok(b[0..input.len()].to_vec())
    }

    /// This method takes a slice of bits of the length `l`, add `m` dummy
    /// bits to the end of the slice, and returns it as a new vector. The
    /// output vector's length is `λ^2` where `λ = sqrt(l + m) ∈ Z`.
    fn add_dummy_bits<F: Field>(a: &[Replicated<F>]) -> (Vec<Replicated<F>>, usize) {
        // We plan to use u32, which we'll add 4 dummy bits to get λ = 6.
        // Since we don't want to compute sqrt() each time this protocol
        // is called, we'll assume that the input is 32-bit long.
        // We can modify this function if we need to support other lengths.
        let l = a.len();
        let lambda: usize = match l {
            8 => 3,
            16 => 4,
            32 => 6,
            _ => panic!("bit length must 8, 16 or 32"),
        };
        let dummy = vec![Replicated::new(F::ZERO, F::ZERO); lambda * lambda - l];
        ([a, &dummy].concat(), lambda)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BitwiseOrPerBlock,
    BlockWisePrefixOr,
    InnerProduct,
    GetFirstBlockWithOne,
    SetFirstBlockWithOne,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BitwiseOrPerBlock => "bitwise_or_per_block",
            Self::BlockWisePrefixOr => "block_wise_prefix_or",
            Self::InnerProduct => "inner_product",
            Self::GetFirstBlockWithOne => "get_first_block_with_one",
            Self::SetFirstBlockWithOne => "set_first_block_with_one",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixOr;
    use crate::{
        error::Error,
        ff::{Field, Fp2, Fp31},
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{
            logging, make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
        },
    };
    use futures::future::try_join_all;
    use rand::distributions::{Distribution, Standard};
    use rand::{rngs::mock::StepRng, Rng};
    use std::iter::zip;

    const BITS: [usize; 2] = [16, 32];
    const TEST_TRIES: usize = 32;

    async fn prefix_or<F: Field>(
        ctx: [ProtocolContext<'_, Replicated<F>, F>; 3],
        record_id: RecordId,
        input: &[F],
    ) -> Result<Vec<F>, Error>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;
        let mut rand = StepRng::new(1, 1);

        // Generate secret shares
        #[allow(clippy::type_complexity)]
        let (s0, (s1, s2)): (Vec<Replicated<F>>, (Vec<Replicated<F>>, Vec<Replicated<F>>)) = input
            .iter()
            .map(|&x| {
                let [y0, y1, y2] = share(x, &mut rand);
                (y0, (y1, y2))
            })
            .unzip();

        // Execute
        let result = try_join_all([
            PrefixOr::execute(c0.bind(record_id), record_id, &s0),
            PrefixOr::execute(c1.bind(record_id), record_id, &s1),
            PrefixOr::execute(c2.bind(record_id), record_id, &s2),
        ])
        .await
        .unwrap();

        // Verify
        assert_eq!(input.len(), result[0].len());
        let [r0, r1, r2] = <[_; 3]>::try_from(result).unwrap();
        let reconstructed = zip(r0, zip(r1, r2))
            .map(|(x0, (x1, x2))| validate_and_reconstruct(&x0, &x1, &x2))
            .collect::<Vec<_>>();
        Ok(reconstructed)
    }

    #[tokio::test]
    /// Test PrefixOr with the input ⊆ F_2
    pub async fn fp2() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp2>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        // Test n-bit (n = BITS[i]) bitwise shares with randomly distributed
        // bits, for 16 times. The probability of i'th bit being 0 is 1/2^i,
        // so this test covers inputs that have all 0's in 5 first bits.
        for len in BITS {
            let step = format!("test_{}bit", len);
            let [c0, c1, c2] = [c0.narrow(&step), c1.narrow(&step), c2.narrow(&step)];

            for i in 0..TEST_TRIES {
                let input: Vec<Fp2> = (0..len).map(|_| Fp2::from(rng.gen::<bool>())).collect();
                let mut expected: Vec<Fp2> = Vec::with_capacity(len);

                // Calculate Prefix-Or of the secret number
                input.iter().fold(Fp2::ZERO, |acc, &x| {
                    expected.push(acc | x);
                    acc | x
                });

                // Execute the protocol
                let result = prefix_or(
                    [c0.clone(), c1.clone(), c2.clone()],
                    RecordId::from(i),
                    &input,
                )
                .await?;

                // Verify
                assert_eq!(expected.len(), result.len());
                zip(expected, result).for_each(|(e, r)| assert_eq!(e, r));
            }
        }

        Ok(())
    }

    #[tokio::test]
    /// Test PrefixOr with the input ⊆ F_p (i.e. Fp31)
    pub async fn fp31() -> Result<(), Error> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        // Test n-bit (n = BITS[i]) bitwise shares with randomly distributed
        // bits, for 16 times. The probability of i'th bit being 0 is 1/2^i,
        // so this test covers inputs that have all 0's in 5 first bits.
        for len in BITS {
            let step = format!("test_{}bit", len);
            let [c0, c1, c2] = [c0.narrow(&step), c1.narrow(&step), c2.narrow(&step)];

            for i in 0..TEST_TRIES {
                // Generate a vector of Fp31::ZERO or Fp31::ONE from randomly picked bool values
                let input: Vec<Fp31> = (0..len)
                    .map(|_| Fp31::from(u128::from(rng.gen::<bool>())))
                    .collect();
                let mut expected: Vec<Fp31> = Vec::with_capacity(len);

                // Calculate Prefix-Or of the secret number
                input.iter().fold(0, |acc, &x| {
                    let sum = acc + x.as_u128();
                    expected.push(Fp31::from(sum > 0));
                    sum
                });

                // Execute the protocol
                let result = prefix_or(
                    [c0.clone(), c1.clone(), c2.clone()],
                    RecordId::from(i),
                    &input,
                )
                .await?;

                // Verify
                assert_eq!(expected.len(), result.len());
                zip(expected, result).for_each(|(e, r)| assert_eq!(e, r));
            }
        }

        Ok(())
    }
}
