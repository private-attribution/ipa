#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct HelperIdentity {
    #[cfg(not(test))]
    endpoint: hyper::Uri,
    #[cfg(test)]
    id: u8,
}

impl HelperIdentity {
    #[cfg(test)]
    #[must_use]
    pub fn new(id: u8) -> Self {
        HelperIdentity { id }
    }
}
