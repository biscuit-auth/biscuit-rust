use std::collections::BTreeSet;
use std::hash::Hash;
use std::iter::FromIterator;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origin {
    inner: BTreeSet<usize>,
}

impl Origin {
    pub fn insert(&mut self, i: usize) {
        self.inner.insert(i);
    }

    pub fn union(&self, other: &Self) -> Self {
        Origin {
            inner: self.inner.union(&other.inner).cloned().collect(),
        }
    }

    pub fn is_superset(&self, other: &Self) -> bool {
        self.inner.is_superset(&other.inner)
    }
}

impl<'a> Extend<&'a usize> for Origin {
    fn extend<T: IntoIterator<Item = &'a usize>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl Extend<usize> for Origin {
    fn extend<T: IntoIterator<Item = usize>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl<'a> FromIterator<&'a usize> for Origin {
    fn from_iter<T: IntoIterator<Item = &'a usize>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().cloned().collect(),
        }
    }
}

impl FromIterator<usize> for Origin {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}
