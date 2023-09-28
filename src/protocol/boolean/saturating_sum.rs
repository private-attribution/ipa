use crate::{
    error::Error,
    ff::{Field, Gf2},
    protocol::{boolean::or::or, context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::{BitDecomposed, Linear as LinearSecretSharing, LinearRefOps},
};

#[derive(Debug)]
pub struct SaturatingSum<S: LinearSecretSharing<Gf2>> {
    pub sum: BitDecomposed<S>,
    pub is_saturated: S,
}

impl<S: LinearSecretSharing<Gf2>> SaturatingSum<S> {
    pub fn new(value: BitDecomposed<S>, is_saturated: S) -> SaturatingSum<S> {
        SaturatingSum {
            sum: value,
            is_saturated,
        }
    }

    ///
    /// # Errors
    /// If one of the multiplications errors
    ///
    /// # Panics
    /// If something try to add a bit decomposed value larger than this `SaturatingSum` can accomodate
    pub async fn add<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        value: &BitDecomposed<S>,
    ) -> Result<SaturatingSum<S>, Error>
    where
        C: Context,
        S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
        for<'a> &'a S: LinearRefOps<'a, S, Gf2>,
    {
        assert!(self.sum.len() >= value.len());

        let mut output_sum = Vec::with_capacity(self.sum.len());
        let mut carry_in = S::ZERO;
        let zero = S::ZERO;
        for i in 0..self.sum.len() {
            let c = ctx.narrow(&BitOpStep::from(i));
            // When adding a value with fewer bits than the saturating sum can express
            // we still must compute the carries, which still requires a single multiplication
            // so there is no savings
            let x = value.get(i).unwrap_or(&zero);
            let sum_bit = one_bit_adder(c, record_id, x, &self.sum[i], &mut carry_in).await?;

            output_sum.push(sum_bit);
        }
        let is_saturated = or(
            ctx.narrow(&BitOpStep::from(self.sum.len())),
            record_id,
            &carry_in,
            &self.is_saturated,
        )
        .await?;

        Ok(SaturatingSum::new(
            BitDecomposed::new(output_sum),
            is_saturated,
        ))
    }

    ///
    /// NOTE: ignores the `is_saturated` flag. The return value is non-sensical if `is_saturated` is true
    ///
    /// Only returns the least significant `num_bits` of the delta.
    ///
    /// # Errors
    /// If one of the multiplications errors
    ///
    /// # Panics
    /// If you ask for more bits than the `SaturatingSum` is using
    ///
    pub async fn truncated_delta_to_saturation_point<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        num_bits: u32,
    ) -> Result<BitDecomposed<S>, Error>
    where
        C: Context,
        S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
        for<'a> &'a S: LinearRefOps<'a, S, Gf2>,
    {
        assert!(num_bits as usize <= self.sum.len());

        let mut carry_in = S::share_known_value(&ctx, Gf2::ONE);
        let mut output = vec![];
        for (i, bit) in self.sum.iter().enumerate().take(num_bits as usize) {
            let c = ctx.narrow(&BitOpStep::from(i));

            let compute_carry_out = i < (num_bits as usize) - 1;
            let difference_bit = one_bit_subtractor(
                c,
                record_id,
                &S::ZERO,
                bit,
                &mut carry_in,
                compute_carry_out,
            )
            .await?;

            output.push(difference_bit);
        }
        Ok(BitDecomposed::new(output))
    }
}

///
/// This improved one-bit adder that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
///
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `sum_bit` can be efficiently computed as just `s_i = x_i ⊕ y_i ⊕ c_i`
/// This can be computed "for free" in Gf2
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) & (y_i ⊕ c_i))`
///
/// Returns `sum_bit`
///
/// The mutable refernce to `carry_in` is mutated to take on the value of the `carry_out` bit
///
async fn one_bit_adder<C, SB>(
    ctx: C,
    record_id: RecordId,
    x: &SB,
    y: &SB,
    carry_in: &mut SB,
) -> Result<SB, Error>
where
    C: Context,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
    for<'a> &'a SB: LinearRefOps<'a, SB, Gf2>,
{
    // compute sum bit as x XOR y XOR carry_in
    let sum_bit = x + y + &*carry_in;

    let x_xor_carry_in = x + &*carry_in;
    let y_xor_carry_in = y + &*carry_in;

    // There are two cases when the `carry_out` bit is different from the `carry_in` bit
    // (1) When the `carry_in` bit is 0 and both `x` and `y` are 1
    // (2) When the `carry_in` bit is 1 and both `x` and `y` are 0
    // So by computing `(x ⊕ c) ∧ (y ⊕ c)` we isolate those cases with a single multiplication
    *carry_in = x_xor_carry_in
        .multiply(&y_xor_carry_in, ctx, record_id)
        .await?
        + &*carry_in;

    Ok(sum_bit)
}

///
/// This improved one-bit subtractor that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
///
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `difference_bit` can be efficiently computed as just `d_i = x_i ⊕ !y_i ⊕ c_i`
/// This can be computed "for free" in Gf2
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) ∧ !(y_i ⊕ c_i))`
///
/// Returns `difference_bit`
///
/// If `compute_carry_out` is set to `true`, then the mutable refernce to `carry_in` is mutated to take on the value of the `carry_out` bit
///
async fn one_bit_subtractor<C, SB>(
    ctx: C,
    record_id: RecordId,
    x: &SB,
    y: &SB,
    carry_in: &mut SB,
    compute_carry_out: bool,
) -> Result<SB, Error>
where
    C: Context,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
    for<'a> &'a SB: LinearRefOps<'a, SB, Gf2>,
{
    // compute difference bit as not_y XOR x XOR carry_in
    let difference_bit = SB::share_known_value(&ctx, Gf2::ONE) + y + x + &*carry_in;
    if compute_carry_out {
        let x_xor_carry_in = x + &*carry_in;
        let y_xor_carry_in = y + &*carry_in;
        let not_y_xor_carry_in = SB::share_known_value(&ctx, Gf2::ONE) + &y_xor_carry_in;

        *carry_in = x_xor_carry_in
            .multiply(&not_y_xor_carry_in, ctx, record_id)
            .await?
            + &*carry_in;
    }
    Ok(difference_bit)
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::SaturatingSum;
    use crate::{
        ff::{Field, Gf2},
        protocol::{context::Context, RecordId},
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, SharedValue,
        },
        test_fixture::{get_bits, Reconstruct, Runner, TestWorld},
    };

    impl Reconstruct<u128> for [SaturatingSum<Replicated<Gf2>>; 3] {
        fn reconstruct(&self) -> u128 {
            let [s0, s1, s2] = self;

            let sum_bits: BitDecomposed<Gf2> = BitDecomposed::new(
                s0.sum
                    .iter()
                    .zip(s1.sum.iter())
                    .zip(s2.sum.iter())
                    .map(|((a, b), c)| [a, b, c].reconstruct()),
            );

            let is_saturated = [&s0.is_saturated, &s1.is_saturated, &s2.is_saturated].reconstruct();

            if is_saturated == Gf2::ZERO {
                sum_bits
                    .iter()
                    .map(Field::as_u128)
                    .enumerate()
                    .fold(0_u128, |acc, (i, x)| acc + (x << i))
            } else {
                2_u128.pow(u32::try_from(s0.sum.len()).unwrap())
            }
        }
    }

    impl Reconstruct<u128> for [BitDecomposed<Replicated<Gf2>>; 3] {
        fn reconstruct(&self) -> u128 {
            let [s0, s1, s2] = self;

            let bits: BitDecomposed<Gf2> = BitDecomposed::new(
                s0.iter()
                    .zip(s1.iter())
                    .zip(s2.iter())
                    .map(|((a, b), c)| [a, b, c].reconstruct()),
            );

            bits.iter()
                .map(Field::as_u128)
                .enumerate()
                .fold(0_u128, |acc, (i, x)| acc + (x << i))
        }
    }

    #[tokio::test]
    pub async fn addition() {
        assert_eq!(2, saturating_add(1, 2, 1, 2).await);
        assert_eq!(3, saturating_add(2, 2, 1, 2).await);
        assert_eq!(4, saturating_add(3, 2, 1, 2).await);
        assert_eq!(4, saturating_add(3, 2, 2, 2).await);
        assert_eq!(4, saturating_add(3, 2, 3, 2).await);
        assert_eq!(6, saturating_add(3, 5, 3, 3).await);
        assert_eq!(6, saturating_add(3, 5, 3, 5).await);
        assert_eq!(14, saturating_add(7, 5, 7, 3).await);
        assert_eq!(14, saturating_add(7, 5, 7, 5).await);
        assert_eq!(31, saturating_add(26, 5, 5, 3).await);
        assert_eq!(32, saturating_add(26, 5, 6, 3).await);
        assert_eq!(32, saturating_add(26, 5, 7, 3).await);
        assert_eq!(32, saturating_add(31, 5, 7, 3).await);
        assert_eq!(63, saturating_add(60, 6, 3, 3).await);
        assert_eq!(64, saturating_add(60, 6, 4, 3).await);
        assert_eq!(64, saturating_add(60, 6, 5, 3).await);
    }

    #[tokio::test]
    pub async fn truncated_delta() {
        assert_eq!(2, truncated_delta_to_saturation_point(30, 5, 3).await);
        assert_eq!(2, truncated_delta_to_saturation_point(30, 5, 2).await);
        assert_eq!(0, truncated_delta_to_saturation_point(30, 5, 1).await);
        assert_eq!(1, truncated_delta_to_saturation_point(31, 5, 1).await);
        assert_eq!(0, truncated_delta_to_saturation_point(32, 5, 1).await);
        assert_eq!(7, truncated_delta_to_saturation_point(25, 5, 3).await);
        assert_eq!(3, truncated_delta_to_saturation_point(61, 6, 3).await);
        assert_eq!(1, truncated_delta_to_saturation_point(15, 4, 1).await);
        assert_eq!(1, truncated_delta_to_saturation_point(15, 4, 2).await);
        assert_eq!(1, truncated_delta_to_saturation_point(15, 4, 2).await);
        assert_eq!(1, truncated_delta_to_saturation_point(15, 4, 4).await);
    }

    async fn saturating_add(a: u32, num_a_bits: u32, b: u32, num_b_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_bits = get_bits::<Gf2>(a, num_a_bits);
        let b_bits = get_bits::<Gf2>(b, num_b_bits);

        let foo = world
            .semi_honest(
                (a_bits, b_bits),
                |ctx, (a_bits, b_bits): (BitDecomposed<_>, BitDecomposed<_>)| async move {
                    let a = SaturatingSum::new(a_bits, Replicated::ZERO);
                    a.add(ctx.set_total_records(1), RecordId(0), &b_bits)
                        .await
                        .unwrap()
                },
            )
            .await;

        foo.reconstruct()
    }

    async fn truncated_delta_to_saturation_point(a: u32, num_a_bits: u32, num_b_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_bits = get_bits::<Gf2>(a, num_a_bits);

        let foo = world
            .semi_honest(a_bits, |ctx, a_bits: BitDecomposed<_>| async move {
                let a = SaturatingSum::new(a_bits, Replicated::ZERO);
                a.truncated_delta_to_saturation_point(
                    ctx.set_total_records(1),
                    RecordId(0),
                    num_b_bits,
                )
                .await
                .unwrap()
            })
            .await;

        foo.reconstruct()
    }
}
