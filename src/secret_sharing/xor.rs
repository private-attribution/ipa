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
}
