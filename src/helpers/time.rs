use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Simple timer that only works in the presence of tokio runtime. Any other runtime will
/// make it a no-op.
#[cfg(not(feature = "shuttle"))]
#[pin_project::pin_project]
pub(crate) struct Timer {
    interval: Duration,
    #[pin]
    timer: tokio::time::Sleep,
}

#[cfg(feature = "shuttle")]
struct GatewayTimer {}

#[cfg(not(feature = "shuttle"))]
impl Timer {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            timer: tokio::time::sleep(interval),
        }
    }

    pub fn reset(self: Pin<&mut Self>) {
        let this = self.project();
        this.timer
            .reset(tokio::time::Instant::now() + *this.interval);
    }
}

#[cfg(feature = "shuttle")]
impl Timer {
    pub fn new(_: Duration) -> Self {
        Self {}
    }

    pub fn reset(&mut self) {}
}

impl Future for Timer {
    type Output = ();

    #[cfg(feature = "shuttle")]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }

    #[cfg(not(feature = "shuttle"))]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.timer.poll(cx)
    }
}
