use futures_util::{stream, TryStreamExt};
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use typenum::Unsigned;

use crate::{
    error::Error,
    ff::{Field, Serializable},
    helpers::{Direction, ReceivingEnd, SendingEnd},
    protocol::{context::Context, ipa_prf::malicious_security::quadratic_proofs::NIDZKP, RecordId},
    seq_join::seq_join,
};

/// computes random challenge `r` from `proof_direction`
/// since the verifier has only access to one side of the proof,
/// he needs to receive `fiat_shamir(proof_direction.neg())` from the other verifier
/// `r` is computed has `fiat_shamir(proof_left)+fiat_shamir(proof_right)`
/// further, he computes all `r` at once
/// `compute_r_prover` takes as input `r` and adds the generated `r` to input `r`
// todo: make it async
pub async fn compute_r_verifier<C, F>(
    ctx: C,
    proof: &NIDZKP<F>,
    direction: Direction,
    r_d: &mut [F],
    r_nd: &mut [F],
) -> Result<(), Error>
where
    C: Context,
    F: Field,
{
    debug_assert_eq!(proof.proofs.len(), r_d.len());

    // set up context
    let ctx_new = &(ctx.set_total_records(r_d.len()));
    // set up channels
    let send_channel: &SendingEnd<F> = &ctx_new.send_channel(ctx.role().peer(!direction));
    let receive_channel: &ReceivingEnd<F> = &ctx_new.recv_channel(ctx.role().peer(direction));

    let _ = seq_join(
        ctx_new.active_work(),
        stream::iter(r_d.iter_mut().zip(proof.proofs.iter()).enumerate().map(
            |(i, (x, proof))| async move {
                // hash
                let temp = fiat_shamir(proof);
                // keep hash
                *x += temp;
                // send hash
                send_channel.send(RecordId::from(i), temp).await?;
                receive_channel.receive(RecordId::from(i)).await
            },
        )),
    )
    .try_collect::<Vec<_>>()
    .await?
    .iter()
    // add received hashes to the `r` of the other direction, i.e. `r_nd`
    .zip(r_nd.iter_mut())
    .for_each(|(x, y)| *y += *x);

    Ok(())
}

/// computes random challenge `r` from `proof_part_left` and `proof_part_right`
/// since only the prover has access to both parts, only he can compute `r` this way
/// further, the prover computes `r` one by one rather than all `r` at once
/// `r` is computed has `fiat_shamir(proof_part_left)+fiat_shamir(proof_part_right)`
/// `compute_r_prover` takes as input `r` and adds the generated `r` to input `r`
pub fn compute_r_prover<F>(proof_left: &[F], proof_right: &[F]) -> F
where
    F: Field,
{
    fiat_shamir(proof_left) + fiat_shamir(proof_right)
}

/// the Fiat-Shamir core function
/// it takes a commitment, which is for `NIDZKP` the actual proof
/// and computes a vector of random points by hashing the individual proofs parts
/// this function only computes `r` for a single proof part
fn fiat_shamir<F>(proof: &[F]) -> F
where
    F: Field,
{
    // serialize proof const SIZE: usize = <F as Serializable>::Size::USIZE;
    let mut ikm = Vec::<u8>::with_capacity(proof.len() * <F as Serializable>::Size::USIZE);
    proof.iter().for_each(|f| {
        let mut buf = vec![0u8; <F as Serializable>::Size::USIZE];
        f.serialize(GenericArray::from_mut_slice(&mut buf));
        ikm.extend(buf)
    });

    // compute `r` from `hash` of the proof
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    // ideally we would generate `hash` as a `[u8;F::Size]` and `deserialize` it to generate `r`
    // however, deserialize might fail for some fields so we use `from_random_128` instead
    // therefore fields beyond `F::Size()>16` don't further reduce the cheating probability of the prover
    let mut hash = [0u8; 16];
    // hash length is a valid length so expand does not fail
    hk.expand(&[], &mut hash).unwrap();
    F::from_random_u128(u128::from_le_bytes(hash))
}

#[cfg(all(test, unit_test))]
mod test {
    use ipa_macros::Step;
    use rand::{thread_rng, Rng};

    use crate::{
        ff::ec_prime_field::Fp25519,
        helpers::Direction,
        protocol::{
            context::Context,
            ipa_prf::malicious_security::{
                fiat_shamir::{compute_r_prover, compute_r_verifier},
                quadratic_proofs::NIDZKP,
            },
        },
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    #[derive(Step)]
    pub(crate) enum Step {
        TestHashFromLeft,
        TestHashFromRight,
    }

    #[test]
    fn proof_verification_test() {
        run(move || async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let r_len: usize = rng.gen::<usize>() % 99usize + 1;
            let r_f: usize = rng.gen::<usize>() % 19usize + 1;

            let mut r = vec![Fp25519::ZERO; r_len];
            r.iter_mut().for_each(|x| *x = rng.gen());

            let result = world
                .semi_honest(r.into_iter(), |ctx, input| async move {
                    let r_right = input.iter().map(|x| x.right()).collect::<Vec<_>>();
                    let r_left = input.iter().map(|x| x.left()).collect::<Vec<_>>();
                    let proof_right = NIDZKP::<Fp25519> {
                        proofs: r_right.chunks(r_f).map(|x| x.to_vec()).collect::<Vec<_>>(),
                        mask_p: Fp25519::ZERO,
                        mask_q: Fp25519::ZERO,
                    };
                    let proof_left = NIDZKP::<Fp25519> {
                        proofs: r_left.chunks(r_f).map(|x| x.to_vec()).collect::<Vec<_>>(),
                        mask_p: Fp25519::ONE,
                        mask_q: Fp25519::ONE,
                    };
                    let mut fs_verifier_left = vec![Fp25519::ZERO; proof_left.proofs.len()];
                    let mut fs_verifier_right = vec![Fp25519::ZERO; proof_left.proofs.len()];
                    let mut fs_prover = vec![Fp25519::ZERO; proof_left.proofs.len()];
                    // compute hashes verifier
                    compute_r_verifier(
                        ctx.narrow(&Step::TestHashFromRight),
                        &proof_right,
                        Direction::Right,
                        &mut fs_verifier_right,
                        &mut fs_verifier_left,
                    )
                    .await
                    .unwrap();
                    compute_r_verifier(
                        ctx.narrow(&Step::TestHashFromLeft),
                        &proof_left,
                        Direction::Left,
                        &mut fs_verifier_left,
                        &mut fs_verifier_right,
                    )
                    .await
                    .unwrap();
                    // compute hashes prover
                    fs_prover
                        .iter_mut()
                        .zip(proof_left.proofs.iter().zip(proof_right.proofs.iter()))
                        .for_each(|(r_prover, (p_left, p_right))| {
                            *r_prover = compute_r_prover(&p_left, &p_right)
                        });

                    (fs_prover, fs_verifier_left, fs_verifier_right)
                })
                .await;

            let len = result[0].0.len();
            for i in 0..len {
                // check "fs" hashes of prover one
                assert_eq!(
                    (i, result[0].0[i], result[0].0[i]),
                    (i, result[1].1[i], result[2].2[i])
                );
                // check "fs" hashes of prover two
                assert_eq!(
                    (i, result[1].0[i], result[1].0[i]),
                    (i, result[0].2[i], result[2].1[i])
                );
                // check "fs" hashes of prover three
                assert_eq!(
                    (i, result[2].0[i], result[2].0[i]),
                    (i, result[0].1[i], result[1].2[i])
                );
            }
        });
    }
}
