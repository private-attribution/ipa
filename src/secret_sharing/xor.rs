use crate::ff::Fp2;

use super::Replicated;

#[derive(Clone, Copy, Debug)]
pub struct XorReplicated {
    left: u64,
    right: u64,
}

impl XorReplicated {
    #[must_use]
    pub fn new(left: u64, right: u64) -> Self {
        Self { left, right }
    }

    #[must_use]
    pub fn left(&self) -> u64 {
        self.left
    }

    #[must_use]
    pub fn right(&self) -> u64 {
        self.right
    }

    /// Get the identified bit as a replicated share in `Fp2`.
    /// For use only by modulus conversion as this produces
    /// shares that might add to 2 rather than just 0 or 1.
    #[must_use]
    pub(crate) fn bit(self, bit_index: u32) -> Replicated<Fp2> {
        debug_assert!(bit_index < 64);
        Replicated::new(
            Fp2::from(self.left & (1 << bit_index) != 0),
            Fp2::from(self.right & (1 << bit_index) != 0),
        )
    }
}
