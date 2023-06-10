use rand::distributions::Distribution;
use rand::Rng;
use std::f64::consts::PI;
use minimal_lexical::Float as FloatP;
use num_traits::{Float};

pub struct NormalDistribution<F>
    where F: Float
{
    pub mean: F,
    pub std: F,
}
///*
impl<S,F> Distribution<S> for NormalDistribution<F>
    where S: Float+FloatP, F: Float
{
    //compute Box Muller transform: https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
    fn sample<R>(&self, rng: &mut R) -> S
        where R:?Sized+Rng {
        //get shift to generate Mantissa size many bits
        let shift = 64u32-(S::MANTISSA_SIZE as u32);
        let max = S::from(u64::MAX>>shift).unwrap();
        let u = S::from(rng.next_u64()>>shift).unwrap()/max;
        let v = S::from(rng.next_u64()>>shift).unwrap()/max;
        // sample from N(0,1): n = \sqrt{-2 \ln U} \cos(2 \pi V)\,
        let n = ((S::from(-2i8).unwrap())*(u.ln())).sqrt()*(((S::from(2f64*PI).unwrap())* v).cos());
        // map sample to N(mean,variance)=sqrt(variance)*sample+mean
        (n*(S::from(self.std.clone()).unwrap()))+S::from(self.mean.clone()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use rand::rngs::ThreadRng;
    use crate::protocol::dp::normal_distribution::NormalDistribution;
    use rand::distributions::Distribution;

    //rough approximate equality (checks 2-3 digits)
    fn raeq(a: f64, b: f64) -> bool
    {
        (a - b).abs() < (2f64.powi((a.abs() + 1f64).log2().ceil() as i32) / 10f64)
    }


    fn compute_mean_and_std(samples: &mut Vec<f64>) -> (f64, f64) {
        let l = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / l;
        let std = (samples.iter().map(|x| (x - mean as f64).powi(2)).sum::<f64>() / l).sqrt();
        (mean, std)
    }

    #[test]
    fn dp_normal_distribution_sample_standard() {
        let mut rng = thread_rng();
        let nd = NormalDistribution::<f64> { mean: 0f64, std: 1f64 };
        let amount = 100000usize;
        let mut samples = vec!(0f64; amount);
        samples.iter_mut().for_each(|x|*x=nd.sample::<ThreadRng>(&mut rng));
        let (mean, std) = compute_mean_and_std(&mut samples);
        assert!(raeq(mean, 0f64) && raeq(std, 1f64));
        //assert_eq!([mean,std],[0f64,1f64]);
    }

    #[test]
    fn dp_normal_distribution_sample_random() {
        let m=rand::random::<f32>() as f64;
        let s=(rand::random::<f32>().abs() as f64).sqrt();
        let mut rng = thread_rng();
        let nd = NormalDistribution::<f64> { mean: m, std: s };
        let amount = 100000usize;
        let mut samples = vec!(0f64; amount);
        samples.iter_mut().for_each(|x|*x=nd.sample::<ThreadRng>(&mut rng));
        let (mean, std) = compute_mean_and_std(&mut samples);
        assert!(raeq(mean, m) && raeq(std, s));
        //assert_eq!([mean,std],[m,s]);
    }

    #[test]
    fn dp_normal_distribution_sample_random_f32() {
        let m=rand::random::<f32>() as f32;
        let s=(rand::random::<f32>().abs() as f32).sqrt();
        let mut rng = thread_rng();
        let nd = NormalDistribution::<f32> { mean: m, std: s };
        let amount = 100000usize;
        let mut samples = vec!(0f64; amount);
        samples.iter_mut().for_each(|x|*x=(<NormalDistribution<f32> as Distribution<f32>>::sample::<ThreadRng>(&nd, &mut rng)) as f64);
        let (mean, std) = compute_mean_and_std(&mut samples);
        assert!(raeq(mean, m as f64) && raeq(std, s as f64));
        //assert_eq!([mean,std],[m,s]);
    }



}
