// DP in MPC

use crate::{error::Error, ff::{Field, boolean_array::BA4}, protocol::{
    context::Context,
    prss::SharedRandomness,
}, protocol, secret_sharing::{
    replicated::semi_honest::AdditiveShare as Replicated, FieldSimd,
    Vectorizable,
}};
use crate::ff::boolean::Boolean;
use crate::ff::boolean_array::BA8;
use crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;
use crate::protocol::prss::PrssIndex;
use crate::secret_sharing::BitDecomposed;
// use crate::secret_sharing::replicated::malicious::AdditiveShare;
// use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
use crate::protocol::RecordId;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;


#[cfg(test)]
pub async fn my_new_function<C, F>(
    ctx: C,
    a: &Vec<Replicated<F>>,
)-> Result<Vec<Replicated<F>>, Error>
    where
        C: Context,
        F: Field,
        // crate::secret_sharing::replicated::semi_honest::additive_share::AdditiveShare<crate::ff::boolean::Boolean>: crate::protocol::basics::BooleanProtocols<C, crate::ff::boolean::Boolean>
        // Replicated<Boolean> : crate::protocol::basics::BooleanProtocols<C, { Boolean }>,
{
    let role = ctx.role();
    let mut counter : u32 = 0;
    // let (l,r) = ctx
    //     .prss()
    //     .generate::<(<F as Vectorizable<N>>::Array,_),_>(counter);
    // counter += 1;
    let (left,right) = ctx
        .prss()
        .generate::<(u128,u128),_>(counter);

    // let share = ctx
    //     .prss()
    //     .generate::<Replicated<F>,_>(counter);


    //  Generate Bernoulli's with PRSS as BitDecomposed type
    let BITS:  usize = 100;
    // Calls to PRSS which are not working
    // let ss_bits : BitDecomposed<Replicated<Boolean>> = ctx.prss().generate_with(RecordId::from(0_u32),BITS ); // like Andy's example https://github.com/andyleiserson/ipa/commit/a5093b51b6338b701f9d90274eee81f88bc14b99

    // Approach 1) using the below line for BitDecomposed.
    let ss_bits : BitDecomposed<Replicated<Boolean>> = ctx.prss().generate_with(RecordId::from(0_u32),BITS ); // like Andy's example https://github.com/andyleiserson/ipa/commit/a5093b51b6338b701f9d90274eee81f88bc14b99
    // let (sum, carry) = integer_add::<_,Boolean,Replicated<Boolean>,_,_>(ctx,protocol::RecordId(counter), ss_bits[0], ss_bits[1]);
    let (sum, carry) = integer_add(ctx,protocol::RecordId(counter), ss_bits[0], ss_bits[1]);

    // Approach 2) concrete types
    // let ss_ba8s : AdditiveShare<BA8> = ctx.prss().generate_with(RecordId::from(0_u32), )
    // let mut x_shared : Replicated<BA4> = ctx.prss().generate::<Replicated<BA4>,_>(counter);
    // let mut y_shared : Replicated<BA4> = ctx.prss().generate::<Replicated<BA4>,_>(counter);
    //
    // let (sum,carry) = integer_add::<_,BA4,Replicated<BA4>,_,_>(ctx, RecordId::from(0_u32), x_shared,y_shared);

    // let ss_bits : Vec<BitDecomposed<Replicated<Boolean>>> = ctx.prss().generate_with(RecordId::from(0_u32),BITS);
    // let share = ctx
    //     .prss()
    //     .generate::<Vec<Replicated<Boolean>>,_>(counter);


    // let share = ctx
    //     .prss()
    //     .generate::<Replicated<F,N>,_>(counter);



    Ok(a.to_vec())
}
// BA and

#[cfg(all(test, unit_test))]
mod test {

    use crate::protocol::ipa_prf::dp_in_mpc::dp_in_mpc::my_new_function;
    use rand::distributions::{Distribution};
    use crate::{ff::{Field, Fp31, Fp32BitPrime, U128Conversions, boolean_array::BA4}, helpers::TotalRecords, protocol::{
        basics::{SecureMul},
        context::Context,
        RecordId,
    }, protocol, rand::{thread_rng, Rng}, secret_sharing::replicated::semi_honest::AdditiveShare as Replicated, seq_join::SeqJoin, test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld}};
    use async_trait::async_trait;
    use crate::secret_sharing::replicated::malicious::AdditiveShare;
    use crate::protocol::ipa_prf::boolean_ops::addition_sequential::integer_add;
    use crate::protocol::ipa_prf::dp_in_mpc;

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
                my_new_function(ctx, &a).await.unwrap()
            }).await;
    }

    // #[tokio::test]
    // pub async fn test_integer_add(){
    //     let world = TestWorld::default();
    //     let counter = 0;
    //     let x_shared = world.ctx.prss().generate::<Replicated<BA4>,_>(counter);
    //     let y_shared = world.ctx.prss().generate::<Replicated<BA4>,_>(counter);
    //
    //     let (sum, carry) = world.semi_honest((x_shared,y_shared),|ctx, x_y|async move {
    //         integer_add::<_,_,AdditiveShare<BA4>,AdditiveShare<BA4>,1>(
    //             ctx.set_total_records(1),
    //             protocol::RecordId(0),
    //             &x_y.0,
    //             &x_y.1,
    //         ).await.unwrap()
    //     }).await.reconstruct();
    // }
}
