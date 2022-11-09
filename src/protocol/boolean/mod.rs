mod prefix_or;

/// A step generator for bitwise secure operations.
///
/// For each record, we decompose a value into bits (i.e. credits in the
/// Attribution protocol), and execute some binary operations like OR'ing each
/// bit. For each bitwise secure computation, we need to "narrow" the context
/// with a new step to make sure we are using an unique PRSS.
///
/// This is a temporary solution for narrowing contexts until the infra is
/// updated with a new step scheme.
struct BitOpStep {
    count: u8,
    id: String,
}

impl BitOpStep {
    const NAME: &str = "bitop";

    pub fn new(start: u8) -> Self {
        Self {
            count: start,
            id: String::from(Self::NAME),
        }
    }

    fn next(&mut self) -> &Self {
        self.count += 1;
        self.id = format!("{}_{}", Self::NAME, self.count);
        self
    }
}

impl crate::protocol::Step for BitOpStep {}

impl AsRef<str> for BitOpStep {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}
