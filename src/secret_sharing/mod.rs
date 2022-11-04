mod malicious_replicated;
mod replicated;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
pub use malicious_replicated::MaliciousReplicated;
pub use replicated::Replicated;
use crate::ff::Field;
use crate::helpers::Identity;


pub trait SecretShare<F> : Add
    + AddAssign
    + Neg
    + Sub
    + SubAssign
    + Mul<F>
    + Debug
    + Sized
{
}

impl <F: Field> SecretShare<F> for Replicated<F> {}
impl <F: Field> SecretShare<F> for MaliciousReplicated<F> {}


