#![allow(dead_code)]
use crate::bits::Serializable;
use crate::helpers::{messaging::Message, Error};
use bitvec::{bitvec, vec::BitVec};
use futures::FutureExt;
use generic_array::GenericArray;
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{
            AtomicUsize,
            Ordering::{AcqRel, Acquire},
        },
        Arc,
    },
};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Notify,
};
use typenum::Unsigned;

pub struct OrderingMpscReceiver<M: Message> {
    rx: Receiver<(usize, M)>,
    buf: Vec<u8>,
    added: BitVec,
    capacity: NonZeroUsize,
    end: Arc<OrderingMpscEnd>,
    #[cfg(debug_assertions)]
    name: String,
}

#[derive(Clone)]
pub struct OrderingMpscSender<M: Message> {
    tx: Sender<(usize, M)>,
    end: Arc<OrderingMpscEnd>,
}

struct OrderingMpscEnd {
    end: AtomicUsize,
    notify: Notify,
}

/// A multi-producer, single-consumer channel that performs buffered reordering
/// of inputs, with back pressure if the insertion is beyond the end of its buffer.
/// This requires that each item be serializable and fixed size.
#[cfg_attr(not(debug_assertions), allow(unused_variables))] // For name.
pub fn ordering_mpsc<M: Message, S: AsRef<str>>(
    name: S,
    capacity: NonZeroUsize,
) -> (OrderingMpscSender<M>, OrderingMpscReceiver<M>) {
    let (tx, rx) = mpsc::channel((capacity.get() / 4).clamp(4, 256)); // TODO configure, tune
    let end = Arc::new(OrderingMpscEnd::new(capacity));
    (
        OrderingMpscSender {
            tx,
            end: Arc::clone(&end),
        },
        OrderingMpscReceiver {
            rx,
            buf: vec![0_u8; capacity.get() * <M as Serializable>::Size::USIZE],
            added: bitvec![0; capacity.get()],
            capacity,
            end,
            #[cfg(debug_assertions)]
            name: name.as_ref().to_string(),
        },
    )
}

impl<M: Message> OrderingMpscReceiver<M> {
    /// Inserts a new element to the specified position.
    ///
    /// When inserting, `index` needs to be in range.  Values that are in range are within `capacity`
    /// (as provided to [`new`]) of the last value that was taken with [`take`].
    ///
    /// ## Panics
    /// Panics if `index` is out of bounds or if something was previously inserted at `index`.
    /// Panics only occur in debug builds; otherwise, a bad index will overwrite that location;
    /// expect bad things to happen in that case.
    /// In all builds, this panics if `msg` fails to serialize properly, which shouldn't happen.
    ///
    /// [`new`]: Self::new
    /// [`take`]: Self::take
    fn insert(&mut self, index: usize, msg: M) {
        #[cfg(debug_assertions)]
        {
            let end = self.end.get();
            assert!(
                ((end - self.capacity.get())..end).contains(&index),
                "Out of range at index {index} on channel \"{}\" (allowed={:?})",
                self.name,
                (end - self.capacity.get())..end,
            );
        }
        // Translate from an absolute index into a relative one.
        let i = index % self.capacity.get();
        let start = i * M::Size::USIZE;
        let offset = start..start + M::Size::USIZE;

        #[cfg_attr(not(debug_assertions), allow(unused_variables))]
        let overwritten = self.added.replace(i, true);
        #[cfg(debug_assertions)]
        assert!(
            !overwritten,
            "Duplicate send for index {index} on channel \"{}\"",
            self.name,
        );
        msg.serialize(GenericArray::from_mut_slice(&mut self.buf[offset]));
    }

    /// Takes a block of elements from the beginning of the vector, or `None` if
    /// fewer than `min_count` elements have been inserted at the start of the buffer.
    fn take(&mut self, min_count: usize) -> Option<Vec<u8>> {
        // Find the relative index we're starting at.
        let i = self.end.get() % self.capacity.get();

        // Find how many elements we can return, at the tail
        let tail = self.added[i..].leading_ones();
        // ... and if we need to wrap to the start of the buffer.
        let wrap = if tail + i == self.capacity.get() {
            self.added[..i].leading_ones()
        } else {
            0
        };

        if tail + wrap < min_count {
            return None;
        }

        // Move `self.end` marker, clear the values in `self.added`, and
        // return a copy of that part of `self.data` that matters.
        self.end.incr(tail + wrap);
        self.added[i..(i + tail)].fill(false);
        if wrap > 0 {
            self.added[..wrap].fill(false);
            let mut buf = Vec::with_capacity((tail + wrap) * M::Size::USIZE);
            buf.extend_from_slice(&self.buf[(i * M::Size::USIZE)..]);
            buf.extend_from_slice(&self.buf[..(wrap * M::Size::USIZE)]);
            Some(buf)
        } else {
            Some(self.buf[(i * M::Size::USIZE)..((i + tail) * M::Size::USIZE)].to_owned())
        }
    }

    /// Take the next set of values.  This will not resolve until `min_count` values are available.
    pub async fn next(&mut self, min_count: usize) -> Option<Vec<u8>> {
        // Read all values that are available before trying to return anything.
        while let Some(read) = self.rx.recv().now_or_never() {
            if let Some((index, msg)) = read {
                self.insert(index, msg);
            } else {
                return None;
            }
        }
        loop {
            let output = self.take(min_count);
            if output.is_some() {
                return output;
            }
            if let Some((index, msg)) = self.rx.recv().await {
                self.insert(index, msg);
            } else {
                return None;
            }
        }
    }

    /// Return any gap ahead of the first missing value.
    #[cfg(any(test, debug_assertions))]
    pub fn missing(&self) -> std::ops::Range<usize> {
        let end = self.end.get();
        let start = end - self.capacity.get();
        let i = end % self.capacity.get();
        let mut absent = self.added[i..].leading_zeros();
        if i + absent == self.capacity.get() {
            absent += self.added[..i].leading_zeros();
        }
        if absent == self.capacity.get() {
            start..start
        } else {
            start..(start + absent)
        }
    }
}

impl<M: Message> OrderingMpscSender<M> {
    pub async fn send(&self, index: usize, msg: M) -> Result<(), Error> {
        self.end.block(index).await;
        self.tx.send((index, msg)).await?;
        Ok(())
    }
}

impl OrderingMpscEnd {
    /// Create a new instance, starting at `end`.
    fn new(end: NonZeroUsize) -> Self {
        Self {
            end: AtomicUsize::new(end.get()),
            notify: Notify::new(),
        }
    }
    /// Move the marker forwards.
    fn incr(&self, amount: usize) {
        self.end.fetch_add(amount, AcqRel);
        self.notify.notify_waiters();
    }

    /// Peek at the active value.
    fn get(&self) -> usize {
        self.end.load(Acquire)
    }

    /// Block asynchronously until the end reaches `until`.
    async fn block(&self, until: usize) {
        while until >= self.get() {
            self.notify.notified().await;
        }
    }
}

#[cfg(test)]
mod fixture {
    use crate::{
        bits::Serializable,
        ff::Fp32BitPrime,
        helpers::buffers::ordering_mpsc::{
            ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender,
        },
        rand::thread_rng,
    };
    use async_trait::async_trait;
    use futures::future::join_all;
    use std::num::NonZeroUsize;
    use tokio::sync::mpsc::{channel, Receiver};
    use typenum::Unsigned;

    pub const FP32BIT_SIZE: usize = <Fp32BitPrime as Serializable>::Size::USIZE;

    #[async_trait]
    pub trait TestSender {
        async fn send_test(&self, i: usize);
    }

    #[async_trait]
    impl TestSender for OrderingMpscSender<Fp32BitPrime> {
        async fn send_test(&self, i: usize) {
            self.send(i, Fp32BitPrime::from(u128::try_from(i).unwrap()))
                .await
                .unwrap();
        }
    }

    /// Shuffle `count` indices.
    pub fn shuffle_indices(count: usize) -> Vec<usize> {
        use rand::seq::SliceRandom;
        let mut indices = (0..count).collect::<Vec<_>>();
        indices.shuffle(&mut thread_rng());
        indices
    }

    /// For the provided receiver, read from it and report out when
    /// the number of bytes produced hits a multiple of `report_multiple`.
    ///
    /// Unlike other tests, which only send in a few values, a separate
    /// spawned task is necessary here so that the mpsc buffer
    /// internal to the `ordering_mpsc` channel doesn't fill up.
    fn read_and_report(
        mut rx: OrderingMpscReceiver<Fp32BitPrime>,
        report_multiple: usize,
    ) -> Receiver<usize> {
        #[cfg(feature = "shuttle")]
        use shuttle::future::spawn;
        #[cfg(not(feature = "shuttle"))]
        use tokio::spawn;

        let (tx, report) = channel::<usize>(1);
        spawn(async move {
            let mut bytes = 0;
            while let Some(buf) = rx.next(1).await {
                bytes += buf.len();
                if bytes % report_multiple == 0 {
                    tx.send(bytes).await.unwrap();
                }
            }
        });
        report
    }

    /// A test that validates that reading and writing `cap` items works,
    /// if the items are sent in the specified order.
    pub async fn shuffled_send_recv(indices: &[usize], excess: usize) {
        let cap = indices.len();
        let (tx, rx) = ordering_mpsc("test", NonZeroUsize::new(cap + excess).unwrap());
        assert!(rx.missing().is_empty());

        let output_size = cap * FP32BIT_SIZE;
        let mut recvd = read_and_report(rx, output_size);
        for j in 0..2 {
            join_all(indices.iter().map(|&i| tx.send_test(j * cap + i))).await;
            assert_eq!(recvd.recv().await.unwrap(), output_size * (j + 1));
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod unit {
    use crate::{
        bits::Serializable,
        ff::Fp31,
        helpers::buffers::ordering_mpsc::{
            fixture::{TestSender, FP32BIT_SIZE},
            ordering_mpsc,
        },
    };
    use futures::{future::join, FutureExt};
    use generic_array::GenericArray;
    use std::{mem, num::NonZeroUsize};

    /// Test that a single value can be sent and received successfully.
    #[tokio::test]
    async fn in_and_out() {
        let input = Fp31::from(7_u128);
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        let tx_a = tx.clone();
        let send = async move {
            tx_a.send(0, input).await.unwrap();
        };
        let (_, output) = join(send, rx.next(1)).await;
        assert_eq!(
            input,
            Fp31::deserialize(GenericArray::from_slice(output.as_ref().unwrap()))
        );
    }

    /// If the sender is dropped, then the receiver will report that it is done.
    #[tokio::test]
    async fn drop_tx() {
        let (tx, mut rx) = ordering_mpsc::<Fp31, _>("test", NonZeroUsize::new(3).unwrap());
        mem::drop(tx);
        assert!(rx.next(1).now_or_never().unwrap().is_none());
    }

    /// ... even if there are things in the pipe ahead of the close.
    #[tokio::test]
    async fn drop_flush() {
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        tx.send_test(2).await;
        mem::drop(tx);
        assert!(rx.next(1).now_or_never().unwrap().is_none());
    }

    #[tokio::test]
    async fn gap() {
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        tx.send_test(1).await;

        assert!(rx.missing().is_empty());
        assert!(rx.next(1).now_or_never().is_none());
        assert_eq!(rx.missing(), 0..1);
        assert!(rx.next(1).now_or_never().is_none());
    }

    #[tokio::test]
    #[should_panic(expected = "Duplicate send for index 1 on channel \"test\"")]
    async fn duplicate() {
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        tx.send_test(1).await;
        tx.send_test(1).await;
        mem::drop(rx.next(1).await);
    }

    #[tokio::test]
    #[should_panic(expected = "Out of range at index 0 on channel \"test\" (allowed=1..4)")]
    async fn insert_taken() {
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        tx.send_test(0).await;
        assert!(rx.next(1).await.is_some());
        tx.send_test(0).await;
        mem::drop(rx.next(1).await);
    }

    /// When the index is too far into the future, sending does not resolve.
    #[tokio::test]
    async fn send_blocked() {
        let (tx, mut rx) = ordering_mpsc("test", NonZeroUsize::new(3).unwrap());
        let send3 = tx.send_test(3);
        assert!(send3.now_or_never().is_none());
        assert!(rx.missing().is_empty());

        // Poking at the receiver receiving doesn't allow the send to complete.
        let recv = rx.next(1);
        assert!(recv.now_or_never().is_none());
        let send3 = tx.send_test(3);
        assert!(send3.now_or_never().is_none());

        // Filling in the gap doesn't either.
        for i in 0..3 {
            tx.send_test(i).await;
        }
        let send3 = tx.send_test(3);
        assert!(send3.now_or_never().is_none());

        // You have to fill the gap AND receive.
        let buf = rx.next(1).now_or_never().unwrap().unwrap();
        assert_eq!(buf.len(), 3 * FP32BIT_SIZE);
        let send3 = tx.send_test(3);
        assert!(send3.now_or_never().is_some());
    }
}

#[cfg(all(test, feature = "shuttle"))]
mod concurrency {
    use crate::helpers::buffers::ordering_mpsc::fixture::{shuffle_indices, shuffled_send_recv};
    use shuttle::{check_random, future::block_on};

    #[test]
    fn shuffle() {
        check_random(
            || {
                block_on(async {
                    shuffled_send_recv(&shuffle_indices(100), 0).await;
                });
            },
            1000,
        );
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod proptests {
    use crate::helpers::buffers::ordering_mpsc::fixture::{shuffle_indices, shuffled_send_recv};

    proptest::prop_compose! {
        fn shuffled()(cap in 2..1000_usize) -> Vec<usize> {
            shuffle_indices(cap)
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_size_seq(cap in 2..1000_usize) {
            let indices = (0..cap).collect::<Vec<_>>();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move { shuffled_send_recv(&indices, 0).await });
        }

        #[test]
        fn arbitrary_size_shuffle(indices in shuffled(), excess in 0..10_usize) {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async { shuffled_send_recv(&indices, excess).await });
        }
    }
}
