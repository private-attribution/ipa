use std::{fmt::Debug, ops::Deref};

use crate::{
    error::Error,
    ff::{Field, Gf2, PrimeField},
    protocol::{
        boolean::saturating_sum::one_bit_subtractor, context::Context, step::BitOpStep,
        BasicProtocols, RecordId,
    },
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

#[derive(Clone, Debug, PartialEq)]
pub struct BitDecomposed<S> {
    bits: Vec<S>,
}

impl<S> BitDecomposed<S> {
    const MAX: usize = 64;

    /// Create a new value from an iterator.
    /// # Panics
    /// If the iterator produces more than `Self::MAX` items.
    pub fn new<I: IntoIterator<Item = S>>(bits: I) -> Self {
        let bits = bits.into_iter().collect::<Vec<_>>();
        assert!(bits.len() <= Self::MAX);
        Self { bits }
    }

    /// Decompose `count` values from context, using a counter from `[0, count)`.
    /// # Panics
    /// If `count` is greater than `Self::MAX`.
    pub fn decompose<I, F>(count: I, f: F) -> Self
    where
        I: From<u8> + Copy,
        u8: TryFrom<I>,
        <u8 as TryFrom<I>>::Error: Debug,
        F: Fn(I) -> S,
    {
        let max = u8::try_from(count).unwrap();
        assert!(usize::from(max) <= Self::MAX);

        Self::try_from((0..max).map(I::from).map(f).collect::<Vec<_>>()).unwrap()
    }

    /// Translate this into a different form.
    pub fn map<F: Fn(S) -> T, T>(self, f: F) -> BitDecomposed<T> {
        BitDecomposed::new(self.bits.into_iter().map(f))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// The inner vector of this type is a list any field type (e.g. Z2, Zp) and
    /// each element is (should be) a share of 1 or 0. This function iterates
    /// over the shares of bits and computes `Σ(2^i * b_i)`.
    pub fn to_additive_sharing_in_large_field<F>(&self) -> S
    where
        S: LinearSecretSharing<F>,
        for<'a> &'a S: LinearRefOps<'a, S, F>,
        F: PrimeField,
    {
        self.iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }

    // Same as above, but without the need to HRTB, as this doesn't used references
    // but rather takes ownership over the BitDecomposed
    pub fn to_additive_sharing_in_large_field_consuming<F>(bits: BitDecomposed<S>) -> S
    where
        S: LinearSecretSharing<F>,
        F: PrimeField,
    {
        bits.into_iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }

    /// Subtraction of two bit-wise secret shares, `self - rhs`, in two's complement.
    /// Subtracting a value larger than `self` value will cause the result to overflow.
    /// Be especially careful as the overflow is not checked and could lead to a privacy
    /// violation (e.g., invalid capping).
    ///
    /// # Errors
    /// If one of the multiplications errors
    /// # Panics
    /// If something try to subtract a bit decomposed value larger than this `BitDecomposed` can accommodate
    pub async fn sub<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        rhs: &BitDecomposed<S>,
    ) -> Result<BitDecomposed<S>, Error>
    where
        C: Context,
        S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
        for<'a> &'a S: LinearRefOps<'a, S, Gf2>,
    {
        assert!(self.len() >= rhs.len());

        let mut output = vec![];
        let mut carry_in = S::share_known_value(&ctx, Gf2::ONE);
        let zero = S::ZERO;
        for i in 0..self.len() {
            let c = ctx.narrow(&BitOpStep::from(i));
            let compute_carry_out = i < self.len() - 1;
            let difference_bit = one_bit_subtractor(
                c,
                record_id,
                &self[i],
                rhs.get(i).unwrap_or(&zero),
                &mut carry_in,
                compute_carry_out,
            )
            .await?;

            output.push(difference_bit);
        }

        Ok(BitDecomposed::new(output))
    }

    #[must_use]
    ///
    /// # Panics
    /// If you provide an index that can't be casted to a usize
    pub fn split_at(self, idx: u32) -> (BitDecomposed<S>, BitDecomposed<S>) {
        let idx: usize = idx.try_into().unwrap();
        let mut left = Vec::with_capacity(idx);
        let mut right = Vec::with_capacity(self.len() - idx);
        for (i, bit) in self.bits.into_iter().enumerate() {
            if i < idx {
                left.push(bit);
            } else {
                right.push(bit);
            }
        }
        (BitDecomposed::new(left), BitDecomposed::new(right))
    }
}

impl<S> TryFrom<Vec<S>> for BitDecomposed<S> {
    type Error = Error;
    fn try_from(bits: Vec<S>) -> Result<Self, Self::Error> {
        if bits.len() <= Self::MAX {
            Ok(Self { bits })
        } else {
            Err(Error::Internal)
        }
    }
}

impl<S> Deref for BitDecomposed<S> {
    type Target = [S];
    fn deref(&self) -> &Self::Target {
        &self.bits
    }
}

impl<S> IntoIterator for BitDecomposed<S> {
    type Item = S;
    type IntoIter = <Vec<S> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.bits.into_iter()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::Gf2,
        protocol::{context::Context, RecordId},
        secret_sharing::BitDecomposed,
        test_fixture::{get_bits, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn subtraction() {
        // `lhs >= rhs`
        assert_eq!(0, subtract(1, 2, 1, 2).await);
        assert_eq!(1, subtract(2, 2, 1, 2).await);
        assert_eq!(1, subtract(3, 2, 2, 2).await);
        assert_eq!(2, subtract(3, 2, 1, 2).await);
        assert_eq!(3, subtract(3, 2, 0, 2).await);
        assert_eq!(2, subtract(3, 5, 1, 5).await);
        assert_eq!(6, subtract(7, 5, 1, 2).await);
        assert_eq!(6, subtract(7, 5, 1, 5).await);

        // `lhs < rhs` so the result is an unsigned integer in two's complement
        // representation in whatever many bits of the `lhs`
        assert_eq!(3, subtract(0, 2, 1, 2).await);
        assert_eq!(31, subtract(1, 5, 2, 2).await);
        assert_eq!(30, subtract(1, 5, 3, 2).await);
        assert_eq!(26, subtract(1, 5, 7, 5).await);
    }

    async fn subtract(a: u32, num_a_bits: u32, b: u32, num_b_bits: u32) -> u128 {
        let world = TestWorld::default();

        let a_bits = get_bits::<Gf2>(a, num_a_bits);
        let b_bits = get_bits::<Gf2>(b, num_b_bits);

        let foo = world
            .semi_honest(
                (a_bits, b_bits),
                |ctx, (a_bits, b_bits): (BitDecomposed<_>, BitDecomposed<_>)| async move {
                    a_bits
                        .sub(ctx.set_total_records(1), RecordId::from(0), &b_bits)
                        .await
                        .unwrap()
                },
            )
            .await;

        foo.reconstruct()
    }
}
