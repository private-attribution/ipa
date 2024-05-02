pub mod stats;
mod step_stats;

pub use step_stats::CsvExporter as StepStatsCsvExporter;

pub mod labels {
    pub const STEP: &str = "step";
    pub const ROLE: &str = "role";
}

pub mod metrics {
    use metrics::{describe_counter, Unit};

    pub const REQUESTS_RECEIVED: &str = "requests.received";
    pub const RECORDS_SENT: &str = "records.sent";
    pub const BYTES_SENT: &str = "bytes.sent";
    pub const INDEXED_PRSS_GENERATED: &str = "i.prss.gen";
    pub const SEQUENTIAL_PRSS_GENERATED: &str = "s.prss.gen";
    pub const STEP_NARROWED: &str = "step.narrowed";
    pub const DZKP_BATCH_REALLOCATION_FRONT: &str = "batch.realloc.front";
    pub const DZKP_BATCH_REALLOCATION_BACK: &str = "batch.realloc.back";

    #[cfg(feature = "web-app")]
    pub mod web {
        use axum::http::Version;
        use metrics::KeyName;

        /// Metric that records the version of HTTP protocol used for a particular request.
        pub struct RequestProtocolVersion(Version);

        impl From<Version> for RequestProtocolVersion {
            fn from(v: Version) -> Self {
                RequestProtocolVersion(v)
            }
        }

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
    }

    /// Registers metrics used in the system with the metrics recorder.
    ///
    /// ## Panics
    /// Panic if there is no recorder installed
    pub fn register() {
        describe_counter!(
            REQUESTS_RECEIVED,
            Unit::Count,
            "Total number of requests received by the web server"
        );

        #[cfg(feature = "web-app")]
        {
            use axum::http::Version;
            describe_counter!(
                web::RequestProtocolVersion::from(Version::HTTP_11),
                Unit::Count,
                "Total number of HTTP/1.1 requests received"
            );

            describe_counter!(
                web::RequestProtocolVersion::from(Version::HTTP_2),
                Unit::Count,
                "Total number of HTTP/2 requests received"
            );
        }

        describe_counter!(
            RECORDS_SENT,
            Unit::Count,
            "Number of unique records sent from the infrastructure layer to the network"
        );

        describe_counter!(
            BYTES_SENT,
            Unit::Count,
            "Bytes sent from the infrastructure layer to the network"
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

        describe_counter!(
            STEP_NARROWED,
            Unit::Count,
            "Number of times the step is narrowed"
        );

        describe_counter!(
            DZKP_BATCH_REALLOCATION_FRONT,
            Unit::Count,
            "Number of DZKP reallocations due to records smaller than the offset"
        );

        describe_counter!(
            DZKP_BATCH_REALLOCATION_BACK,
            Unit::Count,
            "Number of DZKP reallocations due to insufficient length"
        );
    }
}
