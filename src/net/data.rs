use crate::protocol::QueryId;
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[cfg_attr(feature = "debug", derive(Debug))]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum Command<F, S> {
    Echo(String),
    Mul(ReplicatedSecretSharing<F>, QueryId, S),
}

// #[cfg(feature = "debug")]
// impl<S: Step> Debug for Command<S> {
//     fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
//         f.write_str("Command::")?;
//         match self {
//             Self::Echo(_) => f.write_str("Echo"),
//             Self::Mul(ss, query_id, step) => {
//                 f.write_str("Mul(")?;
//                 ss.fmt(f)?;
//                 f.write_str(")")
//             }
//         }
//     }
// }
