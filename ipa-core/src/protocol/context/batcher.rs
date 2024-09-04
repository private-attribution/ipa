use std::{cmp::min, collections::VecDeque, future::Future};

use bitvec::{bitvec, prelude::BitVec};
use tokio::sync::watch;

use crate::{
    error::Error,
    protocol::RecordId,
    sync::{Arc, Mutex},
};

/// Manages validation of batches of records for malicious protocols.
///
/// `Batcher` is utilized as follows:
/// 1. Construct with `Batcher::new`.
/// 2. Record information in the batch via `Batcher::get_batch` and
///    some protocol-defined mechanism.
/// 3. Either:
///    a. Call `Batcher::validate_record` for each record.
///    b. Call `Batcher::into_single_batch` once.
pub(super) struct Batcher<'a, B> {
    batches: VecDeque<BatchState<B>>,
    first_batch: usize,
    records_per_batch: usize,
    total_records: Option<usize>,
    batch_constructor: Box<dyn Fn(usize) -> B + Send + 'a>,
}

/// State associated with a batch.
///
/// `batch` holds state defined by a particular malicious protocol. The other fields
/// hold state that is defined and used by the `Batcher` implementation for all
/// protocols.
#[derive(Debug)]
pub(super) struct BatchState<B> {
    pub(super) batch: B,
    validation_result: watch::Sender<bool>,
    pending_count: usize,
    pending_records: BitVec,
}

// Helper for `Batcher::validate_record` and `Batcher::is_ready_for_validation`.
enum Ready<B> {
    No(watch::Receiver<bool>),
    Yes {
        batch_index: usize,
        batch: BatchState<B>,
    },
}

impl<'a, B> Batcher<'a, B> {
    pub fn new(
        records_per_batch: usize,
        total_records: Option<usize>,
        batch_constructor: Box<dyn Fn(usize) -> B + Send + 'a>,
    ) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            batches: VecDeque::new(),
            first_batch: 0,
            records_per_batch,
            total_records,
            batch_constructor,
        }))
    }

    fn batch_offset(&self, record_id: RecordId) -> usize {
        let batch_index = usize::from(record_id) / self.records_per_batch;
        let Some(batch_offset) = batch_index.checked_sub(self.first_batch) else {
            panic!(
                "Batches should be processed in order. Attempting to retrieve batch {batch_index}. \
                 The oldest active batch is batch {}.",
                self.first_batch,
            )
        };
        batch_offset
    }

    fn get_batch_by_offset(&mut self, batch_offset: usize) -> &mut BatchState<B> {
        if self.batches.len() <= batch_offset {
            self.batches.reserve(batch_offset - self.batches.len() + 1);
            while self.batches.len() <= batch_offset {
                let (validation_result, _) = watch::channel::<bool>(false);
                let state = BatchState {
                    batch: (self.batch_constructor)(self.first_batch + batch_offset),
                    validation_result,
                    pending_count: 0,
                    pending_records: bitvec![0; self.records_per_batch],
                };
                self.batches.push_back(state);
            }
        }

        &mut self.batches[batch_offset]
    }

    pub fn get_batch(&mut self, record_id: RecordId) -> &mut BatchState<B> {
        self.get_batch_by_offset(self.batch_offset(record_id))
    }

    fn is_ready_for_validation(&mut self, record_id: RecordId) -> Result<Ready<B>, Error> {
        let Some(total_records) = self.total_records else {
            return Err(Error::MissingTotalRecords(String::from("validate_record")));
        };

        let batch_offset = self.batch_offset(record_id);
        let batch_index = self.first_batch + batch_offset;
        let first_record_in_batch = batch_index * self.records_per_batch;
        let remaining_records =
            total_records
                .checked_sub(first_record_in_batch)
                .ok_or(Error::RecordIdOutOfRange {
                    record_id,
                    total_records,
                })?;
        let total_count = min(self.records_per_batch, remaining_records);
        let record_offset_in_batch = usize::from(record_id) - first_record_in_batch;
        let batch = self.get_batch_by_offset(batch_offset);
        batch.pending_records.set(record_offset_in_batch, true);
        batch.pending_count += 1;
        if batch.pending_count == total_count {
            // I am not sure if this is okay, or if we need to tolerate batch validation requests
            // arriving out of order. (If we do, I think we would still want to actually fulfill
            // the validations in order.)
            assert_eq!(
                batch_offset,
                0,
                "Batches should be processed in order. \
                Batch {batch_index} is ready for validation, but the first batch is {first}.",
                first = self.first_batch,
            );
            assert!(batch.pending_records[0..total_count].all());
            tracing::info!("batch {batch_index} is ready for validation");
            let batch = self.batches.pop_front().unwrap();
            self.first_batch += 1;
            Ok(Ready::Yes { batch_index, batch })
        } else {
            Ok(Ready::No(batch.validation_result.subscribe()))
        }
    }

    pub fn validate_record<VF, Fut>(
        &mut self,
        record_id: RecordId,
        validate_batch: VF,
    ) -> impl Future<Output = Result<(), Error>>
    where
        VF: FnOnce(usize, B) -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        tracing::trace!("validate record {record_id}");

        let ready = self.is_ready_for_validation(record_id);

        // At this point we are done with `self`. Capturing `self` in the future is
        // problematic when it is inside a mutex.

        async move {
            match ready? {
                Ready::No(mut validation_result_rx) => {
                    validation_result_rx
                        .changed()
                        .await
                        .expect("sender should not be dropped");
                    if *validation_result_rx.borrow() {
                        Ok(())
                    } else {
                        // Because errors are not `Clone`, only the validate_record call that actually
                        // did the validation returns the actual error (of type
                        // `Error::DZKPValidationFailed`, possibly with additional detail in the
                        // future). The rest get this error.
                        Err(Error::ParallelDZKPValidationFailed)
                    }
                }
                Ready::Yes {
                    batch_index,
                    batch: state,
                } => {
                    tracing::debug!("validating batch {batch_index}");
                    let result = validate_batch(batch_index, state.batch).await;
                    state.validation_result.send_replace(result.is_ok());
                    result
                }
            }
        }
    }

    /// Consumes the batcher and returns a single batch, if possible.
    ///
    /// It is possible to do so if either:
    /// 1. The batcher was never used at all (returns a new, empty batch), or
    /// 2. The batcher was only ever used for a single batch (i.e. if the batcher was
    ///    used for at most `min(records_per_batch, total_records)` records, and that
    ///    batch was not validated via the `validate_record` API.
    ///
    /// This is used by the non-batched `DZKPValidator::validate` API.
    ///
    /// # Panics
    /// If the batcher contains more than one batch.
    #[allow(dead_code)]
    pub fn into_single_batch(mut self) -> B {
        assert!(self.first_batch == 0);
        assert!(self.batches.len() <= 1);
        match self.batches.pop_back() {
            Some(state) => state.batch,
            None => (self.batch_constructor)(0),
        }
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = &BatchState<B>> {
        self.batches.iter()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{future::ready, pin::pin};

    use futures::future::{poll_immediate, try_join, try_join3, try_join4};

    use super::*;

    #[test]
    fn makes_batches() {
        let batcher = Batcher::new(2, Some(4), Box::new(|_| Vec::new()));
        let mut batcher = batcher.lock().unwrap();

        for i in 0..4 {
            batcher.get_batch(RecordId::from(i)).batch.push(i);
        }

        assert_eq!(
            batcher.get_batch(RecordId::from(0)).batch.as_slice(),
            [0, 1]
        );
        assert_eq!(
            batcher.get_batch(RecordId::from(2)).batch.as_slice(),
            [2, 3]
        );
    }

    #[tokio::test]
    async fn validates_batches() {
        let batcher = Batcher::new(2, Some(4), Box::new(|_| Vec::new()));
        let results = {
            let mut batcher = batcher.lock().unwrap();

            for i in 0..4 {
                batcher.get_batch(RecordId::from(i)).batch.push(i);
            }

            try_join4(
                batcher.validate_record(RecordId::from(0), |_i, _b| async { unreachable!() }),
                batcher.validate_record(RecordId::from(1), |i, b| {
                    assert!(i == 0 && b.as_slice() == [0, 1]);
                    ready(Ok(()))
                }),
                batcher.validate_record(RecordId::from(2), |_i, _b| async { unreachable!() }),
                batcher.validate_record(RecordId::from(3), |i, b| {
                    assert!(i == 1 && b.as_slice() == [2, 3]);
                    ready(Ok(()))
                }),
            )
        };

        assert_eq!(results.await.unwrap(), ((), (), (), ()));
    }

    #[tokio::test]
    async fn validates_batches_async() {
        let batcher = Batcher::new(2, Some(4), Box::new(|_| Vec::new()));

        for i in 0..4 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let mut fut0 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(0), |_i, _b| async { unreachable!() }));
        let fut1 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(1), |i, b| {
                assert!(i == 0 && b.as_slice() == [0, 1]);
                ready(Ok(()))
            }));
        let mut fut2 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(2), |_i, _b| async { unreachable!() }));
        let fut3 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(3), |i, b| {
                assert!(i == 1 && b.as_slice() == [2, 3]);
                ready(Ok(()))
            }));

        assert!(poll_immediate(&mut fut0).await.is_none());
        assert!(poll_immediate(&mut fut2).await.is_none());

        assert!(matches!(fut1.await, Ok(())));
        assert!(matches!(poll_immediate(&mut fut0).await, Some(Ok(()))));
        assert!(poll_immediate(&mut fut2).await.is_none());

        assert!(matches!(fut3.await, Ok(())));
        assert!(matches!(poll_immediate(&mut fut2).await, Some(Ok(()))));
    }

    #[tokio::test]
    async fn validation_failure() {
        let batcher = Batcher::new(2, Some(4), Box::new(|_| Vec::new()));

        for i in 0..4 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let mut fut0 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(0), |_i, _b| async { unreachable!() }));
        let fut1 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(1), |i, b| {
                assert!(i == 0 && b.as_slice() == [0, 1]);
                ready(Err(Error::DZKPValidationFailed))
            }));
        let mut fut2 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(2), |_i, _b| async { unreachable!() }));
        let fut3 = pin!(batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(3), |i, b| {
                assert!(i == 1 && b.as_slice() == [2, 3]);
                ready(Ok(()))
            }));

        assert!(poll_immediate(&mut fut0).await.is_none());
        assert!(poll_immediate(&mut fut2).await.is_none());

        assert!(matches!(fut1.await, Err(Error::DZKPValidationFailed)));
        assert!(matches!(
            poll_immediate(&mut fut0).await,
            Some(Err(Error::ParallelDZKPValidationFailed))
        ));
        assert!(poll_immediate(&mut fut2).await.is_none());

        assert!(matches!(fut3.await, Ok(())));
        assert!(matches!(poll_immediate(&mut fut2).await, Some(Ok(()))));
    }

    #[tokio::test]
    async fn handles_partial_final_batch() {
        let batcher = Batcher::new(2, Some(3), Box::new(|_| Vec::new()));
        let results = {
            let mut batcher = batcher.lock().unwrap();

            for i in 0..3 {
                batcher.get_batch(RecordId::from(i)).batch.push(i);
            }

            try_join3(
                batcher.validate_record(RecordId::from(0), |i, b| {
                    assert!(i == 0 && b.as_slice() == [0, 1]);
                    ready(Ok(()))
                }),
                batcher.validate_record(RecordId::from(1), |i, b| {
                    assert!(i == 0 && b.as_slice() == [0, 1]);
                    ready(Ok(()))
                }),
                batcher.validate_record(RecordId::from(2), |i, b| {
                    assert!(i == 1 && b.as_slice() == [2]);
                    ready(Ok(()))
                }),
            )
        };

        assert_eq!(results.await.unwrap(), ((), (), ()));
    }

    #[tokio::test]
    async fn requires_total_records_in_validate_record() {
        let batcher = Batcher::new(2, None, Box::new(|_| Vec::new()));
        let result = {
            let mut batcher = batcher.lock().unwrap();
            batcher.get_batch(RecordId::FIRST).batch.push(0);

            batcher.validate_record(RecordId::FIRST, |_i, _b| async { unreachable!() })
        };

        assert!(matches!(result.await, Err(Error::MissingTotalRecords(_)),));
    }

    #[tokio::test]
    async fn record_id_out_of_range() {
        let batcher = Batcher::new(2, Some(1), Box::new(|_| Vec::new()));

        for i in 0..2 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let result = batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(2), |_i, _b| async { unreachable!() });

        assert!(matches!(
            result.await,
            Err(Error::RecordIdOutOfRange { .. })
        ));
    }

    #[test]
    fn into_single_batch() {
        let batcher = Batcher::new(2, None, Box::new(|_| Vec::new()));

        for i in 0..2 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let batcher = Arc::into_inner(batcher).unwrap().into_inner().unwrap();
        assert_eq!(batcher.into_single_batch(), vec![0, 1]);
    }

    #[test]
    #[should_panic(expected = "assertion failed: self.batches.len() <= 1")]
    fn into_single_batch_fails_with_multiple_batches() {
        let batcher = Batcher::new(2, None, Box::new(|_| Vec::new()));

        for i in 0..4 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let batcher = Arc::into_inner(batcher).unwrap().into_inner().unwrap();
        batcher.into_single_batch();
    }

    #[tokio::test]
    #[should_panic(expected = "assertion failed: self.first_batch == 0")]
    async fn into_single_batch_fails_after_first_batch() {
        let batcher = Batcher::new(2, Some(4), Box::new(|_| Vec::new()));

        for i in 0..4 {
            batcher
                .lock()
                .unwrap()
                .get_batch(RecordId::from(i))
                .batch
                .push(i);
        }

        let fut1 = batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(0), |i, b| {
                assert!(i == 0 && b.as_slice() == [0, 1]);
                ready(Ok(()))
            });
        let fut2 = batcher
            .lock()
            .unwrap()
            .validate_record(RecordId::from(1), |i, b| {
                assert!(i == 0 && b.as_slice() == [0, 1]);
                ready(Ok(()))
            });
        assert_eq!(try_join(fut1, fut2).await.unwrap(), ((), ()));

        let batcher = Arc::into_inner(batcher).unwrap().into_inner().unwrap();
        batcher.into_single_batch();
    }
}
