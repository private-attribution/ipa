pub use data::Command;

mod client;
mod data;
mod server;

pub use server::{bind as bind_mpc_helper_server, router as mpc_helper_router, BindTarget};

#[cfg(feature = "self-signed-certs")]
pub use server::tls_config_from_self_signed_cert;

pub use client::{MpcHandle, MpcHttpConnection as Client};
