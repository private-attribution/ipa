use std::iter::zip;

use futures::{
    future::try_join,
    stream,
    stream::{StreamExt, TryStreamExt},
};

use crate::{
    error::Error,
    ff::{curve_points::RP25519, ec_prime_field::Fp25519, Expand},
    helpers::stream::{Chunk, TryFlattenItersExt},
    protocol::{
        basics::{Reveal, SecureMul},
        context::Context,
        ipa_prf::step::PrfStep as Step,
        prss::{FromPrss, SharedRandomness},
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, Sendable, StdArray, Vectorizable},
    seq_join::seq_join,
};

impl<const N: usize> From<AdditiveShare<Fp25519, N>> for AdditiveShare<RP25519, N>
where
    Fp25519: Vectorizable<N>,
    RP25519: Vectorizable<N, Array = StdArray<RP25519, N>>,
    StdArray<RP25519, N>: Sendable,
{
    fn from(value: AdditiveShare<Fp25519, N>) -> Self {
        let (left_arr, right_arr) =
            StdArray::<RP25519, N>::from_tuple_iter(value.into_unpacking_iter().map(|sh| {
                let (l, r) = sh.as_tuple();
                (RP25519::from(l), RP25519::from(r))
            }));
        Self::new_arr(left_arr, right_arr)
    }
}

/// Evaluates the Dodis-Yampolski PRF g^(1/(k+x)) on every element of the input.
/// Generates a random key using PRSS and then calls [`eval_dy_prf_with_key`].
/// See the documentation
///
/// # Errors
/// Propagates errors from multiplications, reveal and scalar multiplication
pub async fn eval_dy_prf<C, const N: usize>(
    ctx: C,
    curve_points: Vec<Chunk<AdditiveShare<Fp25519, N>, N>>,
) -> Result<Vec<u64>, Error>
where
    C: Context,
    Fp25519: Vectorizable<N> + Send,
    RP25519: Vectorizable<N, Array = StdArray<RP25519, N>> + Send,
    AdditiveShare<Fp25519, N>: SecureMul<C> + FromPrss + Send,
    StdArray<RP25519, N>: Sendable,
{
    let prf_key = &ctx
        .narrow(&Step::PRFKeyGen)
        .prss()
        .generate(RecordId::FIRST);
    eval_dy_prf_with_key(ctx, prf_key, curve_points).await
}

/// evaluates the Dodis-Yampolski PRF g^(1/(k+x)) on every element of the input
/// using the provided key `k`.
/// outputs an 8 byte value as specified in `protocol/prf_sharding/mod.rs` per curve point,
/// all parties learn the output.
///
/// # Errors
/// Propagates errors from multiplications, reveal and scalar multiplication
async fn eval_dy_prf_with_key<C, const N: usize>(
    ctx: C,
    prf_key: &AdditiveShare<Fp25519>,
    curve_points: Vec<Chunk<AdditiveShare<Fp25519, N>, N>>,
) -> Result<Vec<u64>, Error>
where
    C: Context,
    Fp25519: Vectorizable<N> + Send,
    RP25519: Vectorizable<N, Array = StdArray<RP25519, N>> + Send,
    AdditiveShare<Fp25519, N>: SecureMul<C> + FromPrss + Send,
    StdArray<RP25519, N>: Sendable,
{
    let z_and_r_values = seq_join(
        ctx.active_work(),
        stream::iter(curve_points)
            .enumerate()
            .map(|(i, curve_pts)| {
                let record_id = RecordId::from(i);
                let eval_ctx = ctx.clone();
                curve_pts.then(move |pts| ZR::compute(eval_ctx, record_id, prf_key, pts))
            }),
    )
    .try_collect::<Vec<_>>()
    .await?;

    // TODO: validate

    //reconstruct (z,R)
    let values = seq_join(
        ctx.active_work(),
        stream::iter(z_and_r_values).enumerate().map(|(i, chunk)| {
            let record_id = RecordId::from(i);
            let ctx = ctx.clone();
            chunk.then(move |z_r| z_r.reveal(ctx, record_id))
        }),
    )
    .try_flatten_iters()
    .try_collect::<Vec<_>>()
    .await?;

    Ok(values)
}

/// Container for vectorized `z` and `r` values. Revealing it produces the PRF values
/// for each pair of elements.
struct ZR<const N: usize>
where
    Fp25519: Vectorizable<N>,
    RP25519: Vectorizable<N>,
{
    z: AdditiveShare<Fp25519, N>,
    r: AdditiveShare<RP25519, N>,
}

impl<const N: usize> ZR<N>
where
    Fp25519: Vectorizable<N>,
    RP25519: Vectorizable<N>,
{
    /// [`Reveal`] trait does not work here because we move the value of `self`. That allows
    /// `seq_join` to work properly.
    async fn reveal<C: Context>(self, ctx: C, record_id: RecordId) -> Result<[u64; N], Error> {
        let r_ctx = ctx.narrow(&Step::RevealR);
        let z_ctx = ctx.narrow(&Step::Revealz);

        let (r, z) = try_join(
            self.r.reveal(r_ctx, record_id),
            self.z.reveal(z_ctx, record_id),
        )
        .await?;
        let mut prf_values: [_; N] = [0_u64; N];

        zip(&mut prf_values, zip(r, z)).for_each(|(prf, (r, z))| *prf = u64::from(r * z.invert()));

        Ok(prf_values)
    }

    async fn compute<C>(
        ctx: C,
        record_id: RecordId,
        k: &AdditiveShare<Fp25519>,
        x: AdditiveShare<Fp25519, N>,
    ) -> Result<Self, Error>
    where
        C: Context,
        AdditiveShare<Fp25519, N>: SecureMul<C> + FromPrss,
        Fp25519: Vectorizable<N>,
        RP25519: Vectorizable<N, Array = StdArray<RP25519, N>>,
        StdArray<RP25519, N>: Sendable,
    {
        let sh_r: AdditiveShare<Fp25519, N> =
            ctx.narrow(&Step::GenRandomMask).prss().generate(record_id);

        //compute x+k
        let mut y = x + AdditiveShare::<Fp25519, N>::expand(k);

        //compute y <- r*y
        y = y
            .multiply(&sh_r, ctx.narrow(&Step::MultMaskWithPRFInput), record_id)
            .await?;

        Ok(Self {
            z: y,
            // compute (g^left, g^right)
            r: sh_r.into(),
        })
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use crate::{
        error::Error,
        ff::{boolean::Boolean, curve_points::RP25519, ec_prime_field::Fp25519},
        helpers::{
            stream::{Chunk, ChunkType},
            TotalRecords,
        },
        protocol::{basics::SecureMul, context::Context, ipa_prf::prf_eval::eval_dy_prf_with_key},
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    ///defining test input struct
    #[derive(Copy, Clone)]
    struct ShuffledTestInput {
        match_key: Fp25519,
    }

    ///defining test output struct
    #[derive(Debug, PartialEq)]
    struct TestOutput {
        match_key_pseudonym: u64,
    }

    fn test_input(mk: u64) -> ShuffledTestInput {
        ShuffledTestInput {
            match_key: Fp25519::from(mk),
        }
    }

    impl IntoShares<AdditiveShare<Fp25519>> for ShuffledTestInput {
        fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<Fp25519>; 3] {
            self.match_key.share_with(rng)
        }
    }

    impl Reconstruct<TestOutput> for [&u64; 3] {
        fn reconstruct(&self) -> TestOutput {
            TestOutput {
                match_key_pseudonym: if *self[0] == *self[1] && *self[0] == *self[2] {
                    *self[0]
                } else {
                    0u64
                },
            }
        }
    }

    /// generates match key pseudonyms from match keys (in Fp25519 format) and PRF key
    /// PRF key needs to be generated separately using `gen_prf_key`
    ///
    /// `gen_prf_key` is not included such that `compute_match_key_pseudonym` can be tested for correctness
    /// # Errors
    /// Propagates errors from multiplications
    pub async fn compute_match_key_pseudonym<C>(
        sh_ctx: C,
        prf_key: AdditiveShare<Fp25519>,
        input_match_keys: Vec<AdditiveShare<Fp25519>>,
    ) -> Result<Vec<u64>, Error>
    where
        C: Context,
        AdditiveShare<Boolean, 1>: SecureMul<C>,
        AdditiveShare<Fp25519>: SecureMul<C>,
    {
        let ctx = sh_ctx.set_total_records(TotalRecords::specified(input_match_keys.len())?);

        eval_dy_prf_with_key::<_, 1>(
            ctx,
            &prf_key,
            input_match_keys
                .into_iter()
                .map(|mk| Chunk::new(ChunkType::Full, mk))
                .collect(),
        )
        .await
    }

    ///testing correctness of DY PRF evaluation
    /// by checking MPC generated pseudonym with pseudonym generated in the clear
    #[test]
    fn semi_honest() {
        run(|| async move {
            let world = TestWorld::default();

            //first two need to be identical for test to succeed
            let records: Vec<ShuffledTestInput> = vec![
                test_input(3),
                test_input(3),
                test_input(23_443_524_523),
                test_input(56),
                test_input(895_764_542),
                test_input(456_764_576),
                test_input(56),
                test_input(3),
                test_input(56),
                test_input(23_443_524_523),
            ];

            //PRF Key Gen
            let u = 3_216_412_445u64;
            let k: Fp25519 = Fp25519::from(u);

            let expected: Vec<TestOutput> = records
                .iter()
                .map(|&x| TestOutput {
                    match_key_pseudonym: (RP25519::from((x.match_key + k).invert())).into(),
                })
                .collect();

            let result: Vec<_> = world
                .semi_honest(
                    (records.into_iter(), k),
                    |ctx, (input_match_keys, prf_key)| async move {
                        compute_match_key_pseudonym::<_>(ctx, prf_key, input_match_keys)
                            .await
                            .unwrap()
                    },
                )
                .await
                .reconstruct();
            assert_eq!(result, expected);
            assert_eq!(result[0], result[1]);
        });
    }
}
