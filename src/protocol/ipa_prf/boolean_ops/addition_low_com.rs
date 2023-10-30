use crate::{
    error::Error,
    ff::{Field, ArrayAccess},
    secret_sharing::WeakSharedValue,
    protocol::{RecordId, context::Context, basics::SecureMul, step::BitOpStep},
    secret_sharing::replicated::{semi_honest::AdditiveShare},
};


///non-saturated unsigned integer addition
pub async fn integer_add<C,XS, YS,T>(ctx: C, record_id: RecordId, x: &AdditiveShare<XS>, y: &AdditiveShare<YS>,) -> Result<AdditiveShare<XS>,Error>
where
    C: Context,
    XS: ArrayAccess<usize, Element=T> + WeakSharedValue,
    YS: ArrayAccess<usize, Element=T> + WeakSharedValue,
    T: Field,
{
    let mut carry = AdditiveShare::<T>::ZERO;
    addition_circuit(ctx,record_id,x,y,&mut carry).await
}

///saturated unsigned integer addition
pub async fn integer_sat_add<C,XS, YS,T>(ctx: C, record_id: RecordId, x: &AdditiveShare<XS>, y: &AdditiveShare<YS>,) -> Result<AdditiveShare<XS>,Error>
    where
        C: Context,
        XS: ArrayAccess<usize, Element=T> + WeakSharedValue,
        YS: ArrayAccess<usize, Element=T> + WeakSharedValue,
        T: Field,
{
    let mut carry = AdditiveShare::<T>::ZERO;
    let result = addition_circuit(ctx,record_id,x,y,&mut carry).await?;

    Ok(result)
}

///addition using bit adder
/// adds Y to X, Output has same length as X (carries and indices of Y too large for X are ignored)
///implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1
///for all i: output[i] = x[i] + (c[i-1] + y[i])
async fn addition_circuit<C,XS, YS,T>(ctx: C, record_id: RecordId, x: &AdditiveShare<XS>, y: &AdditiveShare<YS>, carry: &mut AdditiveShare<T>) -> Result<AdditiveShare<XS>,Error>
    where
        C: Context,
        XS: ArrayAccess<usize, Element=T> + WeakSharedValue,
        YS: ArrayAccess<usize, Element=T> + WeakSharedValue,
        T: Field,
{

    let mut result = AdditiveShare::<XS>::ZERO;
    for i in 0..XS::BITS as usize {
        result.set(i,
                   bit_adder(
                       ctx.narrow(&BitOpStep::from(i)),
                       record_id,
                       &x.get(i),
                       &y.get(i),
                       carry
                   ).await?
        )
    }

    Ok(result)
}

///bit adder
///implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1
///output = x + (c + y)
///update carry to carry = ( x + carry)(y + carry) + carry
async fn bit_adder<C,S>(ctx: C, record_id: RecordId, x: &AdditiveShare<S>, y: &AdditiveShare<S>, carry: &mut AdditiveShare<S>) -> Result<AdditiveShare<S>,Error>
where
    C: Context,
    S: Field,
{
    let output = x + y + &*carry;

    *carry = &*carry + (x+&*carry).multiply(&(y+&*carry), ctx, record_id).await?;

    Ok(output)
}

