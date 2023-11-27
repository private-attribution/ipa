use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{curve_points::RP25519, ec_prime_field::Fp25519},
    protocol::{
        basics::{Reveal, SecureMul},
        context::Context,
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
};

#[derive(Step)]
pub(crate) enum Step {
    PRFKeyGen,
    GenRandomMask,
    MultMaskWithPRFInput,
    RevealR,
    Revealz,
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
{
    let ctx = sh_ctx.set_total_records(input_match_keys.len());
    let futures = input_match_keys
        .iter()
        .enumerate()
        .map(|(i, x)| eval_dy_prf(ctx.clone(), i.into(), &prf_key, x));
    ctx.try_join(futures).await
}

impl From<AdditiveShare<Fp25519>> for AdditiveShare<RP25519> {
    fn from(s: AdditiveShare<Fp25519>) -> Self {
        AdditiveShare::new(RP25519::from(s.left()), RP25519::from(s.right()))
    }
}

/// generates PRF key k as secret sharing over Fp25519
pub fn gen_prf_key<C>(ctx: &C) -> AdditiveShare<Fp25519>
where
    C: Context,
{
    ctx.narrow(&Step::PRFKeyGen)
        .prss()
        .generate_replicated(RecordId(0))
}

/// evaluates the Dodis-Yampolski PRF g^(1/(k+x))
/// the input x and k are secret shared over finite field Fp25519, i.e. the scalar field of curve 25519
/// PRF key k needs to be generated using `gen_prf_key`
///  x is the match key in Fp25519 format
/// outputs a u64 as specified in `protocol/prf_sharding/mod.rs`, all parties learn the output
/// # Errors
/// Propagates errors from multiplications, reveal and scalar multiplication

pub async fn eval_dy_prf<C>(
    ctx: C,
    record_id: RecordId,
    k: &AdditiveShare<Fp25519>,
    x: &AdditiveShare<Fp25519>,
) -> Result<u64, Error>
where
    C: Context,
{
    let sh_r: AdditiveShare<Fp25519> = ctx
        .narrow(&Step::GenRandomMask)
        .prss()
        .generate_replicated(record_id);

    //compute (g^left, g^right)
    let sh_gr = AdditiveShare::<RP25519>::from(sh_r.clone());

    //compute x+k
    let mut y = x + k;

    //compute y <- r*y
    y = y
        .multiply(&sh_r, ctx.narrow(&Step::MultMaskWithPRFInput), record_id)
        .await?;

    //reconstruct (z,R)
    let gr: RP25519 = sh_gr.reveal(ctx.narrow(&Step::RevealR), record_id).await?;
    let z = y.reveal(ctx.narrow(&Step::Revealz), record_id).await?;

    //compute R^(1/z) to u64
    Ok(u64::from(gr * (z.invert())))
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::Rng;

    use crate::{
        ff::{curve_points::RP25519, ec_prime_field::Fp25519},
        protocol::ipa_prf::prf_eval::compute_match_key_pseudonym,
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
