use std::ops::{Index, IndexMut};

pub type RecordIndex = u32;

/// A wrapper around Vec<T> ensuring that the wrapped vector has max length <= `RecordIndex::MAX`.
/// `Batch` offers access to inner vector items through `Index`/`IndexMut`/`iter()`. Once a `Batch`
/// is created, however, adding new items to it is not allowed.
#[derive(Debug, Clone)]
pub struct Batch<T>(Vec<T>);

impl<T> Batch<T> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T> TryFrom<Vec<T>> for Batch<T> {
    type Error = &'static str;

    fn try_from(v: Vec<T>) -> Result<Self, Self::Error> {
        let len = RecordIndex::try_from(v.len());
        if len.is_err() {
            Err("usize doesn't fit into RecordIndex")
        } else {
            Ok(Self(v))
        }
    }
}

impl<T> From<Batch<T>> for Vec<T> {
    fn from(v: Batch<T>) -> Self {
        v.0
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
        &mut self.0[index]
    }
}

#[cfg(test)]
mod tests {
    use super::Batch;

    #[test]
    fn batch_index() {
        let v = vec![1, 2, 3, 4, 5];
        let b = Batch::try_from(v.clone()).unwrap();

        for i in 0..v.len() {
            assert_eq!(v[i], b[i]);
        }
    }

    #[test]
    fn batch_index_mut() {
        let v = vec![1, 2, 3, 4, 5];
        let mut b = Batch::try_from(v.clone()).unwrap();

        b[2u32] = 0;
        for i in 0..v.len() {
            if i == 2 {
                assert_ne!(v[i], b[i]);
                assert_eq!(v[i], 3);
                assert_eq!(b[i], 0);
            } else {
                assert_eq!(v[i], b[i]);
            }
        }
    }

    #[test]
    fn batch_iter() {
        let v = vec![1, 2, 3, 4, 5];
        let b = Batch::try_from(v.clone()).unwrap();

        b.iter().zip(v).for_each(|(x, y)| assert_eq!(*x, y));
    }
}
