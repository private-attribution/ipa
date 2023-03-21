use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        boolean::{multiply_all_shares, random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};

// Compare two arithmetic-shared values `a` and `b` to compute `[a == b]` without revealing `(a == b)` itself.
//
// This is an implementation of 6.4 Equality Test Protocol in "Multiparty Computation for Interval, Equality, and
// Comparison Without Bit-Decomposition Protocol", Nishide & Ohta, PKC 2007.
// <https://doi.org/10.1007/978-3-540-71677-8_23>
//
// Observation: `[a == b]` is equivalent to `[a - b == 0]`
// So we compute `[d] = [a - b]` and focus on computing `[d == 0]`
//
// Strategy:
//  1. Generate random r
//  2. Reveal c = d + r
//  3. Observe that if d == 0, then c == r
//
// Protocol:
//  1. generate a bitwise and arithmetically shared random value r
//  2. compute [c]_p = [d]_p + [r]_p
//  3. Reveal c
//  4. Compute whether all the bits of c are the same as [r]_B
//
/// # Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
#[allow(clippy::many_single_char_names)]
pub async fn equality_test<F, C, S>(
    ctx: C,
    record_id: RecordId,
    rbg: &RandomBitsGenerator<F, S, C>,
    a: &S,
    b: &S,
) -> Result<S, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    use EqualityTestStep as Step;

    let d = a.clone() - b;

    let r = rbg.generate().await?;

    // Mask `d` with random `r` and reveal.
    let c: u128 = (d + &r.b_p)
        .reveal(ctx.narrow(&Step::Reveal), record_id)
        .await?
        .as_u128();

    let one = S::share_known_value(&ctx, F::ONE);

    let transformed_bits = r
        .b_b
        .iter()
        .enumerate()
        .map(|(i, r_bit)| {
            let c_i = (c >> i) & 1;
            if c_i == 1 {
                r_bit.clone()
            } else {
                one.clone() - r_bit
            }
        })
        .collect::<Vec<_>>();

    multiply_all_shares(
        ctx.narrow(&Step::And),
        record_id,
        transformed_bits.as_slice(),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EqualityTestStep {
    Reveal,
    And,
}

impl crate::protocol::Substep for EqualityTestStep {}

impl AsRef<str> for EqualityTestStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::Reveal => "reveal",
            Self::And => "and",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::equality_test;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, PrimeField},
        protocol::{
            boolean::random_bits_generator::RandomBitsGenerator, context::Context, RecordId,
        },
        rand::thread_rng,
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    async fn eq<F: PrimeField>(world: &TestWorld, a: F, b: F) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                equality_test(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &RandomBitsGenerator::new(ctx),
                    &a_share,
                    &b_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                equality_test(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &RandomBitsGenerator::new(ctx),
                    &a_share,
                    &b_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);

        result
    }

    #[tokio::test]
    pub async fn eq_fp31() {
        let c = Fp31::truncate_from::<u8>;
        const ZERO: Fp31 = Fp31::ZERO;
        const ONE: Fp31 = Fp31::ONE;
        let world = TestWorld::default();

        assert_eq!(ONE, eq(&world, ZERO, ZERO).await);
        assert_eq!(ZERO, eq(&world, ZERO, ONE).await);
        assert_eq!(ZERO, eq(&world, ONE, ZERO).await);
        assert_eq!(ONE, eq(&world, ONE, ONE).await);

        assert_eq!(ZERO, eq(&world, c(3), c(7)).await);
        assert_eq!(ONE, eq(&world, c(7), c(7)).await);
        assert_eq!(ZERO, eq(&world, c(21), c(20)).await);
        assert_eq!(ONE, eq(&world, c(21), c(21)).await);

        assert_eq!(ZERO, eq(&world, ZERO, c(Fp31::PRIME - 1)).await);
        assert_eq!(
            ONE,
            eq(&world, c(Fp31::PRIME - 1), c(Fp31::PRIME - 1)).await
        );
        assert_eq!(
            ZERO,
            eq(&world, c(Fp31::PRIME - 2), c(Fp31::PRIME - 1)).await
        );
        assert_eq!(
            ZERO,
            eq(&world, c(Fp31::PRIME - 1), c(Fp31::PRIME - 2)).await
        );
    }

    #[tokio::test]
    pub async fn eq_fp32bit_prime() {
        let c = Fp32BitPrime::truncate_from::<u32>;
        const ZERO: Fp32BitPrime = Fp32BitPrime::ZERO;
        const ONE: Fp32BitPrime = Fp32BitPrime::ONE;
        let u16_max: u32 = u16::MAX.into();
        let world = TestWorld::default();

        assert_eq!(ONE, eq(&world, ZERO, ZERO).await);
        assert_eq!(ZERO, eq(&world, ZERO, ONE).await);
        assert_eq!(ZERO, eq(&world, ONE, ZERO).await);
        assert_eq!(ONE, eq(&world, ONE, ONE).await);

        assert_eq!(ZERO, eq(&world, c(3), c(7)).await);
        assert_eq!(ONE, eq(&world, c(7), c(7)).await);
        assert_eq!(ZERO, eq(&world, c(21), c(20)).await);
        assert_eq!(ONE, eq(&world, c(21), c(21)).await);

        assert_eq!(ONE, eq(&world, c(u16_max - 1), c(u16_max - 1)).await);
        assert_eq!(ZERO, eq(&world, c(u16_max - 1), c(u16_max)).await);
        assert_eq!(ZERO, eq(&world, c(u16_max), c(u16_max - 1)).await);
        assert_eq!(ONE, eq(&world, c(u16_max), c(u16_max)).await);
        assert_eq!(ZERO, eq(&world, c(u16_max + 1), c(u16_max)).await);
        assert_eq!(ZERO, eq(&world, c(u16_max), c(u16_max + 1)).await);
        assert_eq!(ONE, eq(&world, c(u16_max + 1), c(u16_max + 1)).await);

        assert_eq!(ZERO, eq(&world, ZERO, c(Fp32BitPrime::PRIME - 1)).await);
        assert_eq!(
            ONE,
            eq(
                &world,
                c(Fp32BitPrime::PRIME - 1),
                c(Fp32BitPrime::PRIME - 1)
            )
            .await
        );
        assert_eq!(
            ZERO,
            eq(
                &world,
                c(Fp32BitPrime::PRIME - 2),
                c(Fp32BitPrime::PRIME - 1)
            )
            .await
        );
        assert_eq!(
            ZERO,
            eq(
                &world,
                c(Fp32BitPrime::PRIME - 1),
                c(Fp32BitPrime::PRIME - 2)
            )
            .await
        );
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn cmp_random_32_bit_prime_field_elements() {
        let world = TestWorld::default();
        let mut rand = thread_rng();
        for _ in 0..1000 {
            let a = rand.gen::<Fp32BitPrime>();
            let b = rand.gen::<Fp32BitPrime>();
            assert_eq!(
                Fp32BitPrime::truncate_from(a.as_u128() == b.as_u128()),
                eq(&world, a, b).await
            );
        }
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn bw_cmp_all_fp31() {
        let world = TestWorld::default();
        for a in 0..Fp31::PRIME {
            for b in 0..Fp31::PRIME {
                assert_eq!(
                    Fp31::truncate_from(a == b),
                    eq(&world, Fp31::truncate_from(a), Fp31::truncate_from(b)).await
                );
            }
        }
    }
}
