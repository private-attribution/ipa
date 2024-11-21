use std::iter::zip;

use futures::future::try_join;

use crate::{
    error::Error,
    ff::{curve_points::RP25519, ec_prime_field::Fp25519},
    protocol::{
        basics::{reveal, Reveal, SecureMul},
        context::{
            upgrade::Upgradable, UpgradableContext, UpgradedContext, UpgradedMaliciousContext,
            UpgradedSemiHonestContext,
        },
        ipa_prf::step::PrfStep as Step,
        prss::{FromPrss, SharedRandomness},
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{malicious, semi_honest::AdditiveShare},
        FieldSimd, Vectorizable,
    },
    sharding::{NotSharded, Sharded},
};

/// This trait defines the requirements to the sharing types and the underlying fields
/// used to generate PRF values.
pub trait PrfSharing<C: UpgradedContext, const N: usize>:
    Upgradable<C, Output = Self::UpgradedSharing> + FromPrss
{
    /// The type of field used to compute `z`
    type Field: FieldSimd<N>;

    /// Upgraded sharing type. For semi-honest shares, depending on the context,
    /// it could be either `Self` or malicious sharings.
    type UpgradedSharing: BasicProtocols<C, Self::Field, N>;
}

/// Allow semi-honest shares to be used for PRF generation
impl<'a, const N: usize> PrfSharing<UpgradedSemiHonestContext<'a, NotSharded, Fp25519>, N>
    for AdditiveShare<Fp25519, N>
where
    Fp25519: FieldSimd<N>,
    RP25519: Vectorizable<N>,
    AdditiveShare<Fp25519, N>:
        BasicProtocols<UpgradedSemiHonestContext<'a, NotSharded, Fp25519>, Fp25519, N> + FromPrss,
{
    type Field = Fp25519;
    type UpgradedSharing = AdditiveShare<Fp25519, N>;
}

/// Allow semi-honest shares to be used for PRF generation with shards
impl<'a, const N: usize> PrfSharing<UpgradedSemiHonestContext<'a, Sharded, Fp25519>, N>
    for AdditiveShare<Fp25519, N>
where
    Fp25519: FieldSimd<N>,
    RP25519: Vectorizable<N>,
    AdditiveShare<Fp25519, N>:
        BasicProtocols<UpgradedSemiHonestContext<'a, Sharded, Fp25519>, Fp25519, N> + FromPrss,
{
    type Field = Fp25519;
    type UpgradedSharing = AdditiveShare<Fp25519, N>;
}

/// Allow MAC-malicious shares to be used for PRF generation
impl<'a, const N: usize> PrfSharing<UpgradedMaliciousContext<'a, Fp25519>, N>
    for AdditiveShare<Fp25519, N>
where
    Fp25519: FieldSimd<N>,
    RP25519: Vectorizable<N>,
    malicious::AdditiveShare<Fp25519, N>:
        BasicProtocols<UpgradedMaliciousContext<'a, Fp25519>, Fp25519, N>,
    AdditiveShare<Fp25519, N>: FromPrss,
{
    type Field = Fp25519;
    type UpgradedSharing = malicious::AdditiveShare<Fp25519, N>;
}

impl<const N: usize> From<AdditiveShare<Fp25519, N>> for AdditiveShare<RP25519, N>
where
    Fp25519: Vectorizable<N>,
    RP25519: Vectorizable<N>,
{
    fn from(value: AdditiveShare<Fp25519, N>) -> Self {
        value.transform(RP25519::from)
    }
}

/// generates PRF key k as secret sharing over Fp25519
pub fn gen_prf_key<C, const N: usize>(ctx: &C) -> AdditiveShare<Fp25519, N>
where
    C: UpgradableContext,
    Fp25519: Vectorizable<N>,
{
    let v: AdditiveShare<Fp25519, 1> = ctx.prss().generate(RecordId::FIRST);

    v.expand()
}

/// evaluates the Dodis-Yampolski PRF g^(1/(k+x))
/// the input x and k are secret shared over finite field Fp25519, i.e. the scalar field of curve 25519
/// PRF key k needs to be generated using `gen_prf_key`
///  x is the match key in Fp25519 format
/// outputs a u64 as specified in `protocol/prf_sharding/mod.rs`, all parties learn the output
/// # Errors
/// Propagates errors from multiplications, reveal and scalar multiplication
/// # Panics
/// Never as of when this comment was written, but the compiler didn't know that.
pub async fn eval_dy_prf<C, const N: usize>(
    ctx: C,
    record_id: RecordId,
    key: &AdditiveShare<Fp25519>,
    x: AdditiveShare<Fp25519, N>,
) -> Result<[u64; N], Error>
where
    C: UpgradedContext<Field = Fp25519>,
    AdditiveShare<Fp25519, N>: PrfSharing<C, N, Field = Fp25519>,
    AdditiveShare<RP25519, N>: Reveal<C, Output = <RP25519 as Vectorizable<N>>::Array>,
    Fp25519: FieldSimd<N>,
    RP25519: Vectorizable<N>,
{
    // compute x+k (and upgrade the share)
    let y = (x + key.expand())
        .upgrade(ctx.narrow(&Step::UpgradeY), record_id)
        .await?;

    let r: AdditiveShare<Fp25519, N> = ctx.narrow(&Step::GenRandomMask).prss().generate(record_id);
    // compute (g^left, g^right).
    // Note that it does not get upgraded because this
    // value is revealed immediately without any multiplications
    let sh_gr = AdditiveShare::<RP25519, N>::from(r.clone());

    // upgrade r and compute y <- r*y
    let r = r.upgrade(ctx.narrow(&Step::UpgradeMask), record_id).await?;
    let y = y
        .multiply(&r, ctx.narrow(&Step::MultMaskWithPRFInput), record_id)
        .await?;

    // validate everything before reveal
    ctx.validate_record(record_id).await?;
    let (gr, mut z): (
        <RP25519 as Vectorizable<N>>::Array,
        <Fp25519 as Vectorizable<N>>::Array,
    ) = try_join(
        reveal(ctx.narrow(&Step::RevealR), record_id, &sh_gr),
        reveal(ctx.narrow(&Step::Revealz), record_id, &y),
    )
    .await?;

     //compute R^(1/z) to u64
     let inv_z = crate::ff::ec_prime_field::batch_invert::<N>(&mut z);
     Ok(zip(gr, inv_z)
         .map(|(gr, inv_z)| u64::from(gr * inv_z))
         .collect::<Vec<_>>()
         .try_into()
         .expect("iteration over arrays"))
}

#[cfg(all(test, unit_test))]
mod test {
    use futures_util::future::try_join_all;
    use rand::Rng;

    use crate::{
        error::Error,
        ff::{curve_points::RP25519, ec_prime_field::Fp25519},
        helpers::{in_memory_config::MaliciousHelper, Role},
        protocol::{
            basics::Reveal,
            context::{Context, MacUpgraded, UpgradableContext, Validator},
            ipa_prf::{
                prf_eval::{eval_dy_prf, PrfSharing},
                step::PrfStep,
            },
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares, Vectorizable},
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    /// generates match key pseudonyms from match keys (in Fp25519 format) and PRF key
    /// PRF key needs to be generated separately using `gen_prf_key`
    ///
    /// `gen_prf_key` is not included such that `compute_match_key_pseudonym` can be tested for correctness
    /// # Errors
    /// Propagates errors from multiplications
    pub async fn compute_match_key_pseudonym<C>(
        ctx: C,
        prf_key: AdditiveShare<Fp25519>,
        input_match_keys: Vec<AdditiveShare<Fp25519>>,
    ) -> Result<Vec<u64>, Error>
    where
        C: UpgradableContext,
        AdditiveShare<Fp25519>: PrfSharing<MacUpgraded<C, Fp25519>, 1, Field = Fp25519>,
        AdditiveShare<RP25519>:
            Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<1>>::Array>,
    {
        let ctx = ctx.set_total_records(input_match_keys.len());
        let validator = ctx.validator::<Fp25519>();
        let ctx = validator.context();
        let futures = input_match_keys
            .into_iter()
            .enumerate()
            .map(|(i, x)| eval_dy_prf(ctx.clone(), i.into(), &prf_key, x));

        Ok(try_join_all(futures).await?.into_iter().flatten().collect())
    }

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

    /// Generates a sample to test both semi-honest and malicious implementation
    fn test_case() -> (Vec<ShuffledTestInput>, Vec<TestOutput>, Fp25519) {
        let u = 3_216_412_445u64;
        let k: Fp25519 = Fp25519::from(u);
        let input = vec![
            //first two need to be identical for tests to succeed
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

        let output: Vec<_> = input
            .iter()
            .map(|&x| TestOutput {
                match_key_pseudonym: (RP25519::from((x.match_key + k).invert())).into(),
            })
            .collect();

        (input, output, k)
    }

    ///testing correctness of DY PRF evaluation
    /// by checking MPC generated pseudonym with pseudonym generated in the clear
    #[test]
    fn semi_honest() {
        run(|| async move {
            let world = TestWorld::default();

            //first two need to be identical for test to succeed
            let (records, expected, k) = test_case();

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

    #[test]
    fn malicious() {
        run(|| async move {
            let world = TestWorld::default();
            let (records, expected, key) = test_case();

            let result = world
                .malicious(
                    (records.into_iter(), key),
                    |ctx, (match_key_shares, prf_key)| async move {
                        compute_match_key_pseudonym(ctx, prf_key, match_key_shares)
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

    #[test]
    fn malicious_attack_resistant() {
        const STEPS: [&PrfStep; 3] = [
            &PrfStep::UpgradeY,
            &PrfStep::UpgradeMask,
            &PrfStep::MultMaskWithPRFInput,
            // TODO errors during malicious reveal does not terminate the execution, some helpers
            // make progress and get stuck waiting for messages.
            // &PrfStep::RevealR,
            // &PrfStep::Revealz,
        ];
        run(|| async move {
            for attacker_role in Role::all() {
                for step in STEPS {
                    let mut config = TestWorldConfig::default();
                    config.stream_interceptor = MaliciousHelper::new(
                        *attacker_role,
                        config.role_assignment(),
                        |ctx, data| {
                            if ctx.gate.as_ref().contains(step.as_ref()) {
                                data[0] = !data[0];
                            }
                        },
                    );
                    let world = TestWorld::new_with(&config);
                    let (records, _, key) = test_case();
                    world
                        .malicious(
                            (records.into_iter(), key),
                            |ctx, (match_key_shares, prf_key)| async move {
                                let my_role = ctx.role();

                                match compute_match_key_pseudonym(ctx, prf_key, match_key_shares).await {
                                    Ok(_) if my_role == *attacker_role => {}
                                    Err(Error::MaliciousSecurityCheckFailed | Error::MaliciousRevealFailed) => {}
                                    Ok(_) | Err(_) => {
                                        panic!(
                                            "Malicious validation check passed when it shouldn't have"
                                        )
                                    }
                                }
                            },
                        )
                        .await;
                }
            }
        });
    }
}
