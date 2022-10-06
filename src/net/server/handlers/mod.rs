mod echo;
mod mul;

pub use echo::{handler as echo_handler, Payload as EchoData};
pub use mul::{gateway_middleware_fn, handler as mul_handler, GatewayMap};
