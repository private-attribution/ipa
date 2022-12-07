pub mod stats;
mod step_stats;

pub use step_stats::CsvExporter as StepStatsCsvExporter;

pub mod labels {
    pub const STEP: &str = "step";
    pub const ROLE: &str = "role";
}

pub mod metrics {
    use axum::http::Version;
    use metrics::Unit;
    use metrics::{describe_counter, KeyName};

    pub const REQUESTS_RECEIVED: &str = "requests.received";
    pub const RECORDS_SENT: &str = "records.sent";
    pub const INDEXED_PRSS_GENERATED: &str = "i.prss.gen";
    pub const SEQUENTIAL_PRSS_GENERATED: &str = "s.prss.gen";

    /// Metric that records the version of HTTP protocol used for a particular request.
    #[cfg(feature = "web-app")]
    pub struct RequestProtocolVersion(Version);

    #[cfg(feature = "web-app")]
    impl From<Version> for RequestProtocolVersion {
        fn from(v: Version) -> Self {
            RequestProtocolVersion(v)
        }
    }

    #[cfg(feature = "web-app")]
    impl From<RequestProtocolVersion> for KeyName {
        fn from(v: RequestProtocolVersion) -> Self {
            const HTTP11: &str = "request.protocol.HTTP/1.1";
            const HTTP2: &str = "request.protocol.HTTP/2";
            const HTTP3: &str = "request.protocol.HTTP/3";
            const UNKNOWN: &str = "request.protocol.HTTP/UNKNOWN";

            KeyName::from_const_str(match v.0 {
                Version::HTTP_11 => HTTP11,
                Version::HTTP_2 => HTTP2,
                Version::HTTP_3 => HTTP3,
                _ => UNKNOWN,
            })
        }
    }

    /// Registers metrics used in the system with the metrics recorder.
    ///
    /// ## Panics
    /// Panic if there is no recorder installed
    pub fn register() {
        assert!(
            matches!(metrics::try_recorder(), Some(_)),
            "metrics recorder must be installed before metrics can be described"
        );

        describe_counter!(
            REQUESTS_RECEIVED,
            Unit::Count,
            "Total number of requests received by the web server"
        );

        describe_counter!(
            RequestProtocolVersion::from(Version::HTTP_11),
            Unit::Count,
            "Total number of HTTP/1.1 requests received"
        );

        describe_counter!(
            RequestProtocolVersion::from(Version::HTTP_2),
            Unit::Count,
            "Total number of HTTP/2 requests received"
        );

        describe_counter!(
            RECORDS_SENT,
            Unit::Count,
            "Number of unique records sent from the infrastructure layer to the network"
        );

        describe_counter!(
            INDEXED_PRSS_GENERATED,
            Unit::Count,
            "Number of times shared randomness is requested by the protocols"
        );

        describe_counter!(
            SEQUENTIAL_PRSS_GENERATED,
            Unit::Count,
            "Number of times PRSS is used as CPRNG to generate a random value"
        );
    }
}
