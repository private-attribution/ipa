use std::{
    future::Future,
    io, iter, mem,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

use dashmap::DashMap;
use hyper_util::client::legacy::connect::dns::{GaiFuture, GaiResolver, Name};
use pin_project::pin_project;
use tower::Service;

use crate::sync::Arc;

/// Wrapper around Hyper's [`GaiResolver`] to cache the DNS response.
/// The nature of IPA dictates clients talking to a very limited set of services.
/// Assuming there are M shards in the system:
/// - Report collector talks to each shard on every helper (3*M)
/// - Shard talks to each other shard and to the shard with the same index on two other helpers (M+2)
///   So the memory usage is proportional to the number of shards. We need to cache the response,
///   because there is no other caching layer in the system:
/// - Hyper uses [`GaiResolver`] that is basically just a call to libc `getaddrinfo`
/// - Linux by default does not have any OS-level DNS caching enabled. There is [`nscd`], but
///   it is disabled by default and is claimed to be broken on some distributions [`issue`].
///
/// Given these constraints, it is probably much simpler to cache the DNS response in application
/// layer. With the model where each instance just runs a single query it should simplify things
/// by a lot.
///
/// This struct does exactly that.
///
/// [`nscd`]: https://linux.die.net/man/8/nscd
/// [`issue`]: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=335476
#[derive(Clone)]
pub(super) struct CachingGaiResolver {
    cache: Arc<DashMap<Name, Vec<SocketAddr>>>,
    resolver: GaiResolver,
}

impl CachingGaiResolver {
    pub fn new() -> Self {
        Self::seeded(iter::empty())
    }

    pub fn seeded<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(items: I) -> Self {
        let cache = DashMap::default();
        for (name, addr) in items {
            cache.insert(
                Name::from_str(name)
                    .unwrap_or_else(|_| panic!("{name} is not a valid domain name")),
                vec![addr.parse().unwrap()],
            );
        }
        Self {
            cache: Arc::new(cache),
            resolver: GaiResolver::new(),
        }
    }
}

#[derive(Default)]
pub struct IpAddresses {
    iter: std::vec::IntoIter<SocketAddr>,
}

impl Iterator for IpAddresses {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

#[pin_project(project = ResolvingFutureEnumProj)]
pub enum ResolvingFuture {
    Ready(IpAddresses),
    Pending(#[pin] GaiFuture, Name, Arc<DashMap<Name, Vec<SocketAddr>>>),
}

impl Future for ResolvingFuture {
    type Output = Result<IpAddresses, io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResolvingFutureEnumProj::Ready(addr) => Poll::Ready(Ok(mem::take(addr))),
            ResolvingFutureEnumProj::Pending(fut, name, cache) => {
                let res = match fut.poll(cx) {
                    Poll::Ready(Ok(addr)) => addr,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                };
                let addrs = res.collect::<Vec<_>>();
                // This should probably be a trace span, once we have full confidence
                // that this module works fine
                tracing::info!("caching IP addresses for {name}: {addrs:?}");
                assert!(
                    cache.insert(name.clone(), addrs.clone()).is_none(),
                    "{name} is in the cache already"
                );
                Poll::Ready(Ok(IpAddresses {
                    iter: addrs.into_iter(),
                }))
            }
        }
    }
}

impl Service<Name> for CachingGaiResolver {
    type Response = IpAddresses;
    type Error = io::Error;
    type Future = ResolvingFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Name) -> Self::Future {
        if let Some(addr) = self.cache.get(&req) {
            ResolvingFuture::Ready(IpAddresses {
                iter: addr.clone().into_iter(),
            })
        } else {
            let fut = self.resolver.call(req.clone());
            ResolvingFuture::Pending(fut, req, Arc::clone(&self.cache))
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::str::FromStr;

    use hyper_util::client::legacy::connect::dns::Name;
    use tower::Service;

    use crate::{
        net::client::dns::{IpAddresses, ResolvingFuture},
        test_executor::run,
    };

    #[test]
    fn cache_data() {
        let name = Name::from_str("www.notadomain.com").unwrap();
        let mut resolver =
            super::CachingGaiResolver::seeded([(name.as_str(), "172.20.0.254:8000")]);
        let fut = resolver.call(name);
        let res = futures::executor::block_on(fut)
            .unwrap()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        assert_eq!(vec!["172.20.0.254:8000"], res);
    }

    #[test]
    fn calls_real_resolver() {
        fn assert_localhost_present(input: IpAddresses) {
            let input = input.into_iter().map(|v| v.to_string()).collect::<Vec<_>>();
            assert!(
                input.contains(&"127.0.0.1:0".to_string()),
                "{input:?} does not include localhost"
            );
        }

        run(|| async move {
            let name = Name::from_str("localhost").unwrap();
            let mut resolver = super::CachingGaiResolver::new();
            let res = resolver.call(name.clone()).await.unwrap();
            assert_localhost_present(res);

            // call again and make sure it is ready
            let fut = resolver.call(name.clone());
            if let ResolvingFuture::Ready(ip_addrs) = fut {
                assert_localhost_present(ip_addrs);
            } else {
                panic!("{name} hasn't been cached");
            }
        });
    }
}
