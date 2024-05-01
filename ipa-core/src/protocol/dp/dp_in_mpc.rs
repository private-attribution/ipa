// DP in MPC


use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        context::Context,
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, SharedValueArray,
        Vectorizable,
    },
};


pub async fn my_new_function<C, F, const N: usize>(
    ctx: C,
    a: &Vec<Replicated<F, N>>,
)-> Result<Vec<Replicated<F, N>>, Error>
where
    C: Context,
    F: Field  + FieldSimd<N>,
{
    let role = ctx.role();
    Ok(a.to_vec())
}




#[cfg(all(test, unit_test))]
mod test {
    use std::{
        array,
        iter::{repeat, zip},
        time::Instant,
    };

    use rand::distributions::{Distribution, Standard};

    // use super::multiply;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, U128Conversions},
        helpers::TotalRecords,
        protocol::{
            basics::{SecureMul, ZeroPositions},
            context::Context,
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::replicated::semi_honest::AdditiveShare,
        seq_join::SeqJoin,
        test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld},
    };

    use crate::protocol::dp::dp_in_mpc::my_new_function;

    #[tokio::test]
    pub async fn test_new_my_function(){
        let world = TestWorld::default();

        // create input
        const COUNT: usize = 10;
        let mut rng = thread_rng();
        let a = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>(); // like semi_honest line 181

        let result = world.semi_honest(
            a.into_iter(),
            | ctx , a | async move {
                my_new_function(ctx,&a).await.unwrap()
            }).await;
    }
}
