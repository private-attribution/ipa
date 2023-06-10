mod normal_distribution;

use num_traits::{Float,NumCast};
use minimal_lexical::Float as FloatP;
use rand::distributions::Distribution;
use std::ops::AddAssign;
use std::convert::From;
use rand::{Rng,CryptoRng};
use crate::protocol::dp::normal_distribution::NormalDistribution;

//super trait for Distribution, requires sample method when implementing apply
//F: type for eps and delta parameter, S: type for samples, C for cap
// T is type of input that we want to make differentially private
trait DPMechanism<F,S,C,T>: Distribution<S>
    where F:Float+From<C>, for<'a> T: AddAssign+From<S>+'a
{
    //generate distribution from privacy parameters eps, delta and cap
    fn new(epsilon: F, delta: F, cap: C) -> Self
        where F: Float;

    //Additive DP Mechanism: we add the noise to get DP
    //there are three ways we want to apply DP but DPGen would be the same:
    // 1. generate DP noise as floats and add it to floats in the clear for testing purposes
    // 2. simple DP: generate DP noise as floats but add them to secret shares
    // 3. complex DP: generate DP noise in MPC as secret shared values and add them to secret shared values
    fn additive<'a, I,R>(&self, input: I, rng: &mut R)
        where I: IntoIterator<Item=&'a mut T>, R:?Sized+Rng+CryptoRng
    {
        input.into_iter().for_each(|x:&'a mut T| *x+=T::from(self.sample(rng)));
    }

}

//Implements 1 and 2, but not complex DP
//for (eps, delta) DP, the variance needs to be sensitivity^2/(eps^2) * 2ln(1.25/delta) see https://arxiv.org/pdf/1702.07476.pdf page 2
//sensitivity=L2(max(output_(with user x) - output_(without user x)))=sqrt(breakdown_count * user_contribution_per_breakdown^2)<cap
//minimum eps, delta is 1/u64_max, max for delta is 1-min
impl<F,S,C,T> DPMechanism<F,S,C,T> for NormalDistribution<F>
    where F:Float+From<C>, S: Float+FloatP, for<'a> T: AddAssign+From<S>+'a
{
    fn new(epsilon: F, delta: F, cap: C) -> Self
    {
        //make sure delta and epsilon are in range, i.e. >min and delta<1-min
        let min =<F as NumCast>::from(1i8).unwrap()/<F as NumCast>::from(u64::MAX).unwrap();
        let epsilon = if epsilon <= <F as NumCast>::from(0f64).unwrap() {min} else {epsilon};
        let delta = if delta <= <F as NumCast>::from(0f64).unwrap() {min} else {
            if delta>= <F as NumCast>::from(1i8).unwrap(){<F as NumCast>::from(1i8).unwrap()-min} else {delta}
        };

        let s= (<F as From<C>>::from(cap) / epsilon) * (((<F as NumCast>::from(2i8).unwrap())*((<F as NumCast>::from(1.25_f64).unwrap()).ln() - delta.ln())).sqrt());
        Self {
            mean: <F as NumCast>::from(0f64).unwrap(),
            std: s,
        }
    }
}


#[cfg(test)]
mod test {
    use rand::thread_rng;
    use crate::protocol::dp::DPMechanism;
    use crate::protocol::dp::normal_distribution::NormalDistribution;

    //approximate equality
    fn aeq(a: f64, b: f64) -> bool
    {
        (a - b).abs() < (2f64.powi((a.abs() + 1f64).log2().ceil() as i32) / 10000f64)
    }

    #[test]
    fn dp_normal_distribution_generation_standard() {
        //set N(0,1)
        let delta = 1.25f64 * ((1f64 / std::f64::consts::E).sqrt());
        let dp:NormalDistribution<f64> = DPMechanism::<f64,f64,u32,f64>::new(1f64, delta, 1);
        assert!(aeq(dp.mean, 0f64) && aeq(dp.std, 1f64));
    }

    #[test]
    fn dp_normal_distribution_generation_random() {
        let cap: u32 = rand::random();
        let delta: f64 = (rand::random::<u32>() as f64) / (u32::MAX as f64);
        let epsilon: f64 = rand::random::<u8>() as f64;
        let sensitivity = cap as f64;
        let dp:NormalDistribution<f64> = DPMechanism::<f64,f64,u32,f64>::new(epsilon, delta, cap);
        let s = (sensitivity) / (epsilon) * ((2_f64 * (1.25_f64.ln() - delta.ln())).sqrt());
        //assert!(aeq(dp.mean, 0f64) && aeq(dp.std, s));
        assert_eq!([dp.mean,dp.std],[0f64,s]);
    }

    #[test]
    fn dp_normal_distribution_generation_bad_inputs() {
        let mut _dp:NormalDistribution<f64> = DPMechanism::<f64,f64,u32,f64>::new(-1f64, -1f64, 1);
        _dp = DPMechanism::<f64,f64,u32,f64>::new(0f64, 100f64, 1);
    }

    #[test]
    fn dp_normal_distribution_apply() {
        //init input + rng
        let mut v: Vec<f64> = vec!(0f64;2);
        let mut rng = thread_rng();

        //init DP Mechanism
        let cap: u32 = rand::random();
        let delta: f64 = (rand::random::<u32>() as f64) / (u32::MAX as f64);
        let epsilon: f64 = rand::random::<u8>() as f64;
        let mut dp: NormalDistribution<f64> = DPMechanism::<f64,f64,u32,f64>::new(epsilon, delta, cap);
        <NormalDistribution<f64> as DPMechanism<f64, f64, u32, f64>>::additive(&dp, &mut v,&mut rng);
        // dp.additive(&mut v, &mut rng); doesn't work, I dont know why, it seems that it doesn't recognize S=f64, C=u32bkdrvhdjngbkglgctvunvvgrvbbbdhnttcvggkruidhdidgelenbrfivbuicrbcj
        assert_ne!((v[0],v[1]),(0f64,0f64));
        dp.std=1f64;
        v=vec!(0f64;2);
        <NormalDistribution<f64> as DPMechanism<f64, f64, u32, f64>>::additive(&dp, &mut v,&mut rng);
        assert_ne!((v[0],v[1]),(0f64,0f64));
    }
}

