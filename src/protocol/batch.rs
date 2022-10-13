use std::ops::{Deref, DerefMut, Index, IndexMut};

pub type RecordIndex = u32;

/// A wrapper around Vec<T> ensuring that the wrapped vector has max length <= `RecordIndex::MAX`
#[derive(Debug, Clone)]
pub struct Batch<T>(Vec<T>);

impl<T> From<Vec<T>> for Batch<T> {
    fn from(v: Vec<T>) -> Self {
        let _: RecordIndex = v
            .len()
            .try_into()
            .expect("usize doesn't fit into RecordIndex");
        Self(v)
    }
}

impl<T> From<Batch<T>> for Vec<T> {
    fn from(v: Batch<T>) -> Self {
        v.0
    }
}

/// lets you access Vec<T> methods
impl<T> Deref for Batch<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Batch<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Index<RecordIndex> for Batch<T> {
    type Output = T;
    fn index(&self, index: RecordIndex) -> &Self::Output {
        let i: usize = index
            .try_into()
            .expect("RecordIndex doesn't fit into usize");
        &self.0[i]
    }
}

impl<T> Index<usize> for Batch<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        let _: RecordIndex = index
            .try_into()
            .expect("usize doesn't fit into RecordIndex");
        &self.0[index]
    }
}

impl<T> IndexMut<RecordIndex> for Batch<T> {
    fn index_mut(&mut self, index: RecordIndex) -> &mut Self::Output {
        let i: usize = index
            .try_into()
            .expect("RecordIndex doesn't fit into usize");
        &mut self.0[i]
    }
}

impl<T> IndexMut<usize> for Batch<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let _: RecordIndex = index
            .try_into()
            .expect("usize doesn't fit into RecordIndex");
        &mut self.0[index]
    }
}
