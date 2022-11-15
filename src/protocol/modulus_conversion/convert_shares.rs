use crate::{
    error::BoxError,
    ff::{Field, Fp2},
    protocol::{
        context::ProtocolContext, modulus_conversion::double_random::DoubleRandom, RecordId,
    },
    secret_sharing::{Replicated, SecretSharing},
};

use crate::protocol::reveal::Reveal;
use futures::future::{try_join, try_join_all};
use std::iter::{repeat, zip};

pub struct XorShares {
    num_bits: u8,
    packed_bits_left: u64,
    packed_bits_right: u64,
}

pub struct ConvertShares {
    input: XorShares,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    DoubleRandom,
    BinaryReveal,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::DoubleRandom => "double_random",
            Self::BinaryReveal => "binary_reveal",
        }
    }
}

///
/// This is an implementation of
/// Protocol 5.2 Modulus-conversion protocol from `Z_2^u` to `Z_p`
/// from the paper <https://eprint.iacr.org/2018/387.pdf>
///
/// It works by generating two secret-sharings of a random number `r`,
/// one in `Z_2`, the other in `Z_p`. The sharing in `Z_2` is subtracted
/// from the input and the result is revealed.
///
/// If the revealed result is `0`, that indicates that `r` had the same value
/// as the secret input, so the sharing in `Z_p` is returned.
/// If the revealed result is a `1`, that indicates that `r` was different than
/// the secret input, so a sharing of `1 - r` is returned.
impl ConvertShares {
    pub fn new(input: XorShares) -> Self {
        Self { input }
    }

    pub async fn execute_one_bit<F: Field>(
        &self,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
        bit_index: u8,
    ) -> Result<Replicated<F>, BoxError> {
        assert!(bit_index < self.input.num_bits);

        let prss = &ctx.prss();
        let (left, right) = prss.generate_values(record_id);

        let r_binary = Replicated::new(
            Fp2::from(left & (1 << bit_index) != 0),
            Fp2::from(right & (1 << bit_index) != 0),
        );
        let input = Replicated::new(
            Fp2::from(self.input.packed_bits_left & (1 << bit_index) != 0),
            Fp2::from(self.input.packed_bits_right & (1 << bit_index) != 0),
        );
        let input_xor_r = input + r_binary;
        let (r_big_field, revealed_output) = try_join(
            DoubleRandom::execute(ctx.narrow(&Step::DoubleRandom), record_id, r_binary),
            ctx.narrow(&Step::BinaryReveal)
                .reveal(record_id, input_xor_r),
        )
        .await?;

        if revealed_output == Fp2::ONE {
            Ok(Replicated::<F>::one(ctx.role(), Replicated::default()) - r_big_field)
        } else {
            Ok(r_big_field)
        }
    }
}

#[allow(clippy::module_name_repetitions)]
/// For a given vector of input shares, this returns a vector of modulus converted replicated shares of
/// `bit_index` of each input.
pub async fn convert_shares_for_a_bit<F: Field>(
    ctx: ProtocolContext<'_, Replicated<F>, F>,
    input: &[(u64, u64)],
    num_bits: u8,
    bit_index: u8,
) -> Result<Vec<Replicated<F>>, BoxError> {
    let converted_shares = try_join_all(zip(repeat(ctx), input).enumerate().map(
        |(record_id, (ctx, row))| async move {
            let record_id = RecordId::from(record_id);
            ConvertShares::new(XorShares {
                num_bits,
                packed_bits_left: row.0,
                packed_bits_right: row.1,
            })
            .execute_one_bit(ctx.bind(record_id), record_id, bit_index)
            .await
        },
    ))
    .await?;
    Ok(converted_shares)
}

#[cfg(test)]
mod tests {

    use crate::{
        error::BoxError,
        ff::{Field, Fp31},
        protocol::{
            modulus_conversion::convert_shares::{ConvertShares, XorShares},
            QueryId, RecordId,
        },
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use std::iter::{repeat, zip};

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        prss_space_number: u8,
    }

    #[tokio::test]
    pub async fn convert_one_bit_of_many_match_keys() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = context;

        let mask = (1_u64 << 41) - 1; // in binary, a sequence of 40 ones
        let mut match_keys = Vec::with_capacity(1000);
        let mut shared_match_keys = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let match_key: u64 = rng.gen::<u64>() & mask;
            let share_0 = rng.gen::<u64>() & mask;
            let share_1 = rng.gen::<u64>() & mask;
            let share_2 = match_key ^ share_0 ^ share_1;

            match_keys.push(match_key);
            shared_match_keys.push((share_0, share_1, share_2));
        }

        let results = try_join_all(
            zip(
                repeat(c0),
                zip(repeat(c1), zip(repeat(c2), shared_match_keys)),
            )
            .enumerate()
            .map(|(i, (c0, (c1, (c2, shared_match_key))))| async move {
                let (share_0, share_1, share_2) = shared_match_key;
                let record_id = RecordId::from(0_u32);
                let hack = format!("hack_{}", i);
                try_join_all(vec![
                    ConvertShares::new(XorShares {
                        num_bits: 40,
                        packed_bits_left: share_0,
                        packed_bits_right: share_1,
                    })
                    .execute_one_bit(c0.narrow(&hack), record_id, 4),
                    ConvertShares::new(XorShares {
                        num_bits: 40,
                        packed_bits_left: share_1,
                        packed_bits_right: share_2,
                    })
                    .execute_one_bit(c1.narrow(&hack), record_id, 4),
                    ConvertShares::new(XorShares {
                        num_bits: 40,
                        packed_bits_left: share_2,
                        packed_bits_right: share_0,
                    })
                    .execute_one_bit(c2.narrow(&hack), record_id, 4),
                ])
                .await
            }),
        )
        .await?;

        for i in 0..1000 {
            let match_key = match_keys[i];
            let bit_of_match_key = match_key & (1 << 4) != 0;

            let sh0 = results[i][0];
            let sh1 = results[i][1];
            let sh2 = results[i][2];

            let share_of_bit: Fp31 = validate_and_reconstruct((sh0, sh1, sh2));
            if bit_of_match_key {
                assert_eq!(share_of_bit, Fp31::ONE);
            } else {
                assert_eq!(share_of_bit, Fp31::ZERO);
            }
        }
        Ok(())
    }
}
