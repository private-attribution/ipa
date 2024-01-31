use futures_util::{stream, TryStreamExt};
use generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::Sha256;
use typenum::Unsigned;

use crate::{
    error::Error,
    ff::Serializable,
    helpers::{Direction, Hash, ReceivingEnd, SendingEnd},
    protocol::{context::Context, RecordId},
    secret_sharing::SharedValue,
    seq_join::seq_join,
};

/// two out of two zero check
/// each of the helpers has two vectors, left and right
/// this check verifies that for each position in the vector
/// the element of left helper right and right helper left sum to zero
/// without revealing the vectors
///
/// We use a hash based approach that is secure in the random oracle model
/// further, only one of left and right helper check that it is zero
/// this is sufficient for Distributed Zero Knowledge Proofs
/// but might not be sufficient for other applications
///
/// The left helper simply hashes the vector and sends it to the right,
/// the right helper hashes his vector and compares it to the received hash
pub async fn two_out_of_two_zero_check<C, S>(
    ctx: C,
    input_left: &Vec<S>,
    input_right: &Vec<S>,
) -> Result<bool, Error>
where
    C: Context,
    S: SharedValue,
{
    // compute hash of `left.neg` and `right`
    let hash_left = Hash::deserialize(GenericArray::from_slice(&compute_hash(
        &input_left
            .iter()
            .map(|x| {
                let mut buf = vec![0u8; <S as Serializable>::Size::USIZE];
                x.serialize(GenericArray::from_mut_slice(&mut buf));
                buf
            })
            .flatten()
            .collect::<Vec<u8>>(),
    )))
    .unwrap();
    let hash_right = Hash::deserialize(GenericArray::from_slice(&compute_hash(
        &input_right
            .iter()
            .map(|x| {
                let mut buf = vec![0u8; <S as Serializable>::Size::USIZE];
                x.serialize(GenericArray::from_mut_slice(&mut buf));
                buf
            })
            .flatten()
            .collect::<Vec<u8>>(),
    )))
    .unwrap();

    // set up context
    let ctx_new = &(ctx.set_total_records(1usize));
    // set up channels
    let send_channel: &SendingEnd<Hash> = &ctx_new.send_channel(ctx.role().peer(Direction::Right));
    let receive_channel: &ReceivingEnd<Hash> =
        &ctx_new.recv_channel(ctx.role().peer(Direction::Left));

    let hash_received = seq_join(
        ctx_new.active_work(),
        stream::iter(
            std::iter::once(hash_right)
                .enumerate()
                .map(|(i, hash)| async move {
                    // send hash
                    send_channel.send(RecordId::from(i), hash).await?;
                    receive_channel.receive(RecordId::from(i)).await
                }),
        ),
    )
    .try_collect::<Vec<_>>()
    .await?[0];

    debug_assert_eq!(hash_left, hash_received);

    Ok(hash_left == hash_received)
}

fn compute_hash(input: &[u8]) -> [u8; 32] {
    // set up hash
    let hk = Hkdf::<Sha256>::new(None, input);
    let mut hash = [0u8; 32];
    // compute hash
    hk.expand(&[], &mut hash).unwrap();
    hash
}

#[cfg(all(test, unit_test))]
mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        ff::ec_prime_field::Fp25519,
        protocol::basics::two_out_of_two_zero_check::two_out_of_two_zero_check,
        secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
        test_executor::run,
        test_fixture::{Runner, TestWorld},
    };

    #[test]
    fn two_out_of_two_zero_check_test() {
        run(|| async move {
            let world = TestWorld::default();
            let mut rng = thread_rng();

            let len: usize = rng.gen::<usize>() % 99usize + 1;

            let mut r = vec![Fp25519::ZERO; len];
            r.iter_mut().for_each(|x| *x = rng.gen());

            let result = world
                .semi_honest(r.into_iter(), |ctx, input| async move {
                    let r_right = input.iter().map(|x| x.right()).collect::<Vec<_>>();
                    let r_left = input.iter().map(|x| x.left()).collect::<Vec<_>>();

                    two_out_of_two_zero_check(ctx, &r_left, &r_right)
                        .await
                        .unwrap()
                })
                .await;

            assert!(result[0]);
            assert!(result[1]);
            assert!(result[2]);
        });
    }
}
