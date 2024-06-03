use axum_server::HttpConfig;

use crate::net::MAX_HTTP2_WINDOW_SIZE;

pub(super) struct HttpServerConfig(HttpConfig);

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self(
            HttpConfig::default()
                // This turns off the flow control at the connection level. We ran into issues
                // (see #1085) while having it in place. IPA protocol tend to open many concurrent
                // streams and push data simultaneously through them without having any explicit
                // ordering defined. The execution order however relies on steps that appear early
                // in the execution phase to be scheduled before the later ones. Any mechanism that
                // prevents progress in these scenarios may lead to a deadlock. Connection level
                // flow control is one of these mechanisms, therefore it must be disabled.
                //
                // Because HTTP2 streams are bidirectional, it is important that it is turned off
                // on the receiver (server) side, because we don't push a lot of data
                // from server to client. It should be possible to disable it on the client,
                // if needed
                .http2_initial_connection_window_size(MAX_HTTP2_WINDOW_SIZE)
                .build(),
        )
    }
}

impl From<HttpServerConfig> for HttpConfig {
    fn from(value: HttpServerConfig) -> Self {
        value.0
    }
}
