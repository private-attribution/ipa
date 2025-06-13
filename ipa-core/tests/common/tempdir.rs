use std::{path::Path, thread};

use tempfile::tempdir;

/// Wrapper around [`TempDir`] that prevents the temp directory from being deleted
/// if a panic occurs or if it was told not to.
///
/// [`TempDir`]: tempfile::TempDir
pub struct TempDir {
    inner: Option<tempfile::TempDir>,
    delete: bool,
}

impl TempDir {
    /// Creates a new temporary directory that will be deleted when this instance is dropped.
    /// There is an exception if thread is panicking, then it won't be.
    ///
    /// ## Panics
    /// Panics if a new temp dir cannot be created.
    #[must_use]
    pub fn new_delete_on_drop() -> Self {
        Self {
            inner: Some(tempdir().expect("Can create temp directory")),
            delete: true,
        }
    }

    /// Returns the path to the temp dir.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn path(&self) -> &Path {
        self.inner.as_ref().unwrap().path()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.delete || thread::panicking() {
            let td = self.inner.take().unwrap();
            let _ = td.keep();
        }
    }
}
