use hyper_util::server::conn::auto::Http2Builder;

use crate::net::{MAX_HTTP2_CONCURRENT_STREAMS, MAX_HTTP2_WINDOW_SIZE};

pub(super) struct HttpServerConfig;

impl HttpServerConfig {
    pub fn apply<'a, E>(http_builder: &'a mut Http2Builder<'a, E>) -> &'a mut Http2Builder<'a, E> {
        http_builder
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
            .initial_connection_window_size(MAX_HTTP2_WINDOW_SIZE)
            // Sets the SETTINGS_MAX_CONCURRENT_STREAMS option for HTTP2 connections.
            // This number is correlated to the maximum number of stepts that can be executed
            // in parallel.
            // A low value can lead to HTTP step ([`crate::net::client::MpcHelperClient::step`])
            // not responding.
            //
            // See:
            // [`hyper_util::server::conn::auto::Http2Builder::max_concurrent_streams`]
            .max_concurrent_streams(MAX_HTTP2_CONCURRENT_STREAMS)
    }
}
