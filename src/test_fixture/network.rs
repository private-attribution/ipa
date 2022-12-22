use crate::helpers::HelperIdentity;
use crate::sync::Arc;
use crate::test_fixture::transport::InMemoryTransport;
use std::fmt::Debug;

/// Container for all active transports
#[derive(Debug)]
pub struct InMemoryNetwork {
    pub transports: [InMemoryTransport; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        let [mut first, mut second, mut third]: [InMemoryTransport; 3] = (1..=3)
            .map(|v| InMemoryTransport::new(HelperIdentity::from(v)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // it is a bit tedious, is there a better way?
        first.connect(&mut second);
        first.connect(&mut third);
        second.connect(&mut first);
        second.connect(&mut third);
        third.connect(&mut first);
        third.connect(&mut second);

        first.listen();
        second.listen();
        third.listen();

        let s = Self {
            transports: [first, second, third]
        };
        // println!("created memory network: {}", Arc::strong_count(&s.transports[0]));

        s
    }
}

impl InMemoryNetwork {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn helper_identities(&self) -> [HelperIdentity; 3] {
        self.transports
            .iter()
            .map(|t| t.identity().clone())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

// impl Drop for InMemoryNetwork {
//     fn drop(&mut self) {
//         println!("dropping in memory network: {}", Arc::strong_count(&self.transports[0]));
//     }
// }
