use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        basics::{mul::sparse::MultiplyWork, MultiplyZeroPositions, SecureMul},
        context::{
            dzkp_field::DZKPCompatibleField, dzkp_validator::Segment, Context, DZKPContext,
            DZKPUpgradedMaliciousContext,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, SharedValueArray, Vectorizable,
    },
};

/// This function implements an MPC multiply using the standard strategy, i.e. via computing the
/// cross terms. It mirrors the semi-honest multiply but supports malicious contexts.
///
/// Different to the semi-honest multiply is that it collects intermediate terms in the `dzkp batch`.
/// These intermediate terms are then verified using a validator that has to be called either explicitly
/// or implicitly by using `ctx.seq_join`
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// Panics if the mutex is found to be poisoned
pub async fn multiply<'a, F, const N: usize>(
    ctx: DZKPUpgradedMaliciousContext<'a>,
    record_id: RecordId,
    a: &Replicated<F, N>,
    b: &Replicated<F, N>,
    zeros: MultiplyZeroPositions,
) -> Result<Replicated<F, N>, Error>
where
    F: Field + DZKPCompatibleField<N>,
{
    let role = ctx.role();
    let [need_to_recv, need_to_send, need_random_right] = zeros.work_for(role);
    // dzkp segment that is going to be added to the batch
    let mut segment = Segment::default();

    // include x in the segment
    segment.set_x(
        F::as_segment_entry(a.left_arr()),
        F::as_segment_entry(a.right_arr()),
    );

    // include y in the segment
    segment.set_y(
        F::as_segment_entry(b.left_arr()),
        F::as_segment_entry(b.right_arr()),
    );

    zeros.0.check(role, "a", a);
    zeros.1.check(role, "b", b);

    // Shared randomness used to mask the values that are sent.
    let (s0, s1) = ctx
        .prss()
        .generate::<(<F as Vectorizable<N>>::Array, _), _>(record_id);

    // include prss in the segment
    segment.set_prss(F::as_segment_entry(&s0), F::as_segment_entry(&s1));

    let mut rhs = a.right_arr().clone() * b.right_arr();

    if need_to_send {
        // Compute the value (d_i) we want to send to the right helper (i+1).
        let right_d =
            a.left_arr().clone() * b.right_arr() + a.right_arr().clone() * b.left_arr() - &s0;

        ctx.send_channel::<<F as Vectorizable<N>>::Array>(role.peer(Direction::Right))
            .send(record_id, &right_d)
            .await?;
        rhs += right_d;
    } else {
        debug_assert_eq!(
            a.left_arr().clone() * b.right_arr() + a.right_arr().clone() * b.left_arr(),
            <<F as Vectorizable<N>>::Array as SharedValueArray<F>>::ZERO_ARRAY
        );
    }
    // Add randomness to this value whether we sent or not, depending on whether the
    // peer to the right needed to send.  If they send, they subtract randomness,
    // and we need to add to our share to compensate.
    if need_random_right {
        rhs += s1.clone();
    }

    // Sleep until helper on the left sends us their (d_i-1) value.
    let mut lhs = a.left_arr().clone() * b.left_arr();
    if need_to_recv {
        let left_d: <F as Vectorizable<N>>::Array = ctx
            .recv_channel(role.peer(Direction::Left))
            .receive(record_id)
            .await?;
        lhs += left_d;
    }
    // If we send, we subtract randomness, so we need to add to our share.
    if need_to_send {
        lhs += s0.clone();
    }

    // add z_right to the segment
    segment.set_z(F::as_segment_entry(&lhs));

    // check that the segment is not empty
    debug_assert!(!segment.is_empty());
    // check the consistency of the entry lengths of the segment
    debug_assert!(segment.assert_len());
    // add segment to the batch that needs to be verified by the dzkp prover and verifiers
    ctx.push(record_id, segment);

    Ok(Replicated::new_arr(lhs, rhs))
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: Field + DZKPCompatibleField<N>, const N: usize>
    SecureMul<DZKPUpgradedMaliciousContext<'a>> for Replicated<F, N>
{
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: DZKPUpgradedMaliciousContext<'a>,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        DZKPUpgradedMaliciousContext<'a>: 'fut,
    {
        multiply(ctx, record_id, self, rhs, zeros_at).await
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::{boolean::Boolean, Fp31},
        protocol::{
            basics::SecureMul,
            context::{dzkp_validator::DZKPValidator, Context, DZKPContext, UpgradableContext},
            RecordId,
        },
        rand::{thread_rng, Rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();

        let res = world
            .malicious((a, b), |ctx, (a, b)| async move {
                let validator = ctx.dzkp_validator(10);
                let mctx = validator.context();
                let result = a
                    .multiply(&b, mctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap();

                // batch contains elements
                assert!(mctx.is_verified().is_err());

                // validate all elements in the batch
                validator.validate::<Fp31>().await.unwrap();

                // batch is empty now
                assert!(mctx.is_verified().is_ok());

                result
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }
}
