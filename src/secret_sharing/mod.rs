mod malicious_replicated;
mod replicated;

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
pub use malicious_replicated::MaliciousReplicated;
pub use replicated::Replicated;
use crate::ff::Field;
use crate::helpers::Identity;


pub trait ReplicatedShare<F: Field> : Add
    + AddAssign
    + Neg
    + Sub
    + SubAssign
    + Mul
    + Sized
{
    // fn left(&self) -> F;
    // fn right(&self) -> F;
    //
    // fn one(helper_role: Identity) -> Self;
}


