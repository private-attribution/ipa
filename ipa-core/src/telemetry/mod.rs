pub mod memory;
pub mod stats;
mod step_stats;

pub use step_stats::CsvExporter as StepStatsCsvExporter;

pub mod labels {
    pub use ::ipa_step::descriptive::labels::STEP;
    pub const ROLE: &str = "role";
}

pub mod metrics {

    pub const REQUESTS_RECEIVED: &str = "requests.received";
    pub const RECORDS_SENT: &str = "records.sent";
    pub const BYTES_SENT: &str = "bytes.sent";
    pub const INDEXED_PRSS_GENERATED: &str = "i.prss.gen";
    pub const SEQUENTIAL_PRSS_GENERATED: &str = "s.prss.gen";
    pub use ::ipa_step::descriptive::labels::STEP_NARROWED;
    pub const DZKP_BATCH_INCREMENTS: &str = "batch.realloc.front";

    #[cfg(feature = "web-app")]
    pub mod web {
        use axum::http::Version;

        /// Metric that records the version of HTTP protocol used for a particular request.
        pub struct RequestProtocolVersion(Version);

        impl From<Version> for RequestProtocolVersion {
            fn from(v: Version) -> Self {
                RequestProtocolVersion(v)
            }
        }

        impl RequestProtocolVersion {
            #[must_use]
            pub fn as_str(&self) -> &'static str {
                const HTTP11: &str = "request.protocol.HTTP/1.1";
                const HTTP2: &str = "request.protocol.HTTP/2";
                const HTTP3: &str = "request.protocol.HTTP/3";
                const UNKNOWN: &str = "request.protocol.HTTP/UNKNOWN";

                match self.0 {
                    Version::HTTP_11 => HTTP11,
                    Version::HTTP_2 => HTTP2,
                    Version::HTTP_3 => HTTP3,
                    _ => UNKNOWN,
                }
            }
        }
    }
}
