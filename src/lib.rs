#![deny(clippy::clone_on_ref_ptr)]

#[cfg(feature = "cli")]
pub mod cli;
pub mod common;
pub mod error;
pub mod helpers;
pub mod protocol;
pub mod secret_sharing;
