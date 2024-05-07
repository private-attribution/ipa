// DP in MPC



use crate::{error::Error, ff::{Field, boolean_array::BA4}, protocol::{
    context::Context,
    prss::SharedRandomness,
},  secret_sharing::{
    replicated::semi_honest::AdditiveShare as Replicated, FieldSimd,
    Vectorizable,
}};
// use crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;
// use crate::secret_sharing::replicated::malicious::AdditiveShare;
// crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;

pub async fn my_new_function<C, F, const N: usize>(
    ctx: C,
    a: &Vec<Replicated<F, N>>,
)-> Result<Vec<Replicated<F, N>>, Error>
where
    C: Context,
    F: Field  + FieldSimd<N>,
{
    let role = ctx.role();
    let mut counter : u32 = 0;
    let (l,r) = ctx
        .prss()
        .generate::<(<F as Vectorizable<N>>::Array,_),_>(counter);
    counter += 1;
    let (left,right) = ctx
        .prss()
        .generate::<(u128,u128),_>(counter);

    let share = ctx
        .prss()
        .generate::<Replicated<F>,_>(counter);

    // let share = ctx
    //     .prss()
    //     .generate::<Replicated<F,N>,_>(counter);
    let x_shared = ctx.prss().generate::<Replicated<BA4>,_>(counter);
    let y_shared = ctx.prss().generate::<Replicated<BA4>,_>(counter);

    // let (sum, carry) = world.semi_honest((x_shared,y_shared),|ctx, x_y|async move {
    //     integer_add::<_,_,AdditiveShare<BA4>,AdditiveShare<BA4>,1>(
    //         ctx.set_total_records(1),
    //         protocol::RecordId(0),
    //         &x_y.0,
    //         &x_y.1,
    //     ).await.unwrap()
    // }).await.reconstruct();
    // let (sum,carry) = integer_add(ctx, counter, x_shared,y_shared);


    Ok(a.to_vec())
}
// BA and

#[cfg(all(test, unit_test))]
mod test {
    // use std::{
    //     array,
    //     iter::{repeat, zip},
    //     time::Instant,
    // };

    use rand::distributions::{Distribution};
    use crate::{ff::{Field, Fp31, Fp32BitPrime, U128Conversions, boolean_array::BA4}, helpers::TotalRecords, protocol::{
        basics::{SecureMul, ZeroPositions},
        context::Context,
        RecordId,
    }, protocol, rand::{thread_rng, Rng}, secret_sharing::replicated::semi_honest::AdditiveShare as Replicated, seq_join::SeqJoin, test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld}};
    use async_trait::async_trait;
    use crate::secret_sharing::replicated::malicious::AdditiveShare;

    // use crate::{error::Error, ff::{Field, boolean_array::BA4}, helpers::Direction, protocol::{
    //     context::Context,
    //     prss::SharedRandomness,
    //     RecordId,
    // }, protocol, secret_sharing::{
    //     replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, SharedValueArray,
    //     Vectorizable,
    // }};
    // use crate::secret_sharing::replicated::malicious::AdditiveShare;

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

    pub async fn test_integer_add(){
        let world = TestWorld::default();
        let counter = 0;
        let x_shared = world.ctx.prss().generate::<Replicated<BA4>,_>(counter);
        let y_shared = world.ctx.prss().generate::<Replicated<BA4>,_>(counter);

        let (sum, carry) = world.semi_honest((x_shared,y_shared),|ctx, x_y|async move {
            integer_add::<_,_,AdditiveShare<BA4>,AdditiveShare<BA4>,1>(
                ctx.set_total_records(1),
                protocol::RecordId(0),
                &x_y.0,
                &x_y.1,
            ).await.unwrap()
        }).await.reconstruct();
    }
}
