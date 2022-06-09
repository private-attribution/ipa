#![deny(clippy::clone_on_ref_ptr)]

#[cfg(feature = "cli")]
pub mod cli;
pub mod error;
pub mod helpers;
pub mod net;
pub mod pipeline;
pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::pedantic)]
    #[allow(clippy::clone_on_ref_ptr)]
    pub mod pipe {
        include!(concat!(env!("OUT_DIR"), "/pipe.rs"));
    }
}
pub mod report;
pub mod threshold;
pub mod user;
