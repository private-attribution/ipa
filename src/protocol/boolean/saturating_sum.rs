use crate::{
    error::Error,
    ff::Gf2,
    protocol::{context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::{BitDecomposed, Linear as LinearSecretSharing},
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

    pub async fn add<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        value: &BitDecomposed<S>,
    ) -> Result<SaturatingSum<S>, Error>
    where
        C: Context,
        S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
    {
        assert!(self.sum.len() >= value.len());

        let mut output_sum = Vec::with_capacity(self.sum.len());
        let mut carry_in = S::ZERO;
        let zero = S::ZERO;
        for i in 0..self.sum.len() {
            let c = ctx.narrow(&BitOpStep::from(i));
            let x = if i < value.len() { &value[i] } else { &zero };
            let (sum_bit, carry_out) =
                one_bit_adder(c, record_id, x, &self.sum[i], &carry_in).await?;

            output_sum.push(sum_bit);
            carry_in = carry_out;
        }
        let is_saturated = -carry_in
            .clone()
            .multiply(
                &self.is_saturated,
                ctx.narrow(&BitOpStep::from(self.sum.len())),
                record_id,
            )
            .await?
            + &carry_in
            + &self.is_saturated;

        Ok(SaturatingSum::new(
            BitDecomposed::new(output_sum),
            is_saturated,
        ))
    }
}

///
/// Returns (`sum_bit`, `carry_out`)
///
async fn one_bit_adder<C, SB>(
    ctx: C,
    record_id: RecordId,
    x: &SB,
    y: &SB,
    carry_in: &SB,
) -> Result<(SB, SB), Error>
where
    C: Context,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    // compute sum bit as x XOR y XOR carry_in
    let sum_bit = x.clone() + y + carry_in;

    let x_xor_carry_in = x.clone() + carry_in;
    let y_xor_carry_in = y.clone() + carry_in;
    let carry_out = x_xor_carry_in
        .multiply(&y_xor_carry_in, ctx, record_id)
        .await?
        + carry_in;

    Ok((sum_bit, carry_out))
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
                2_u128.pow(s0.sum.len() as u32)
            }
        }
    }

    #[tokio::test]
    pub async fn simple() {
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

    async fn saturating_add(a: u32, num_a_bits: u32, b: u32, num_b_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_bits = get_bits::<Gf2>(a, num_a_bits);
        //let a_saturated = Gf2::ZERO;
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
}
