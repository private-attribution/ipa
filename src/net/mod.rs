pub use data::Command;
pub use thread::{Message, Pool};

mod client;
mod data;
mod server;
mod thread;

pub use server::{
    bind as bind_mpc_helper_server, router as mpc_helper_router, BindTarget, MpcServerError,
};

#[cfg(feature = "self-signed-certs")]
pub use server::tls_config_from_self_signed_cert;

pub use client::{MpcHandle, MpcHttpConnection as Client};
