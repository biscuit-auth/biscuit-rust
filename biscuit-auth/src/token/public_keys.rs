use std::collections::HashSet;

use crate::{crypto::PublicKey, error};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct PublicKeys {
    pub(crate) keys: Vec<PublicKey>,
}

impl PublicKeys {
    pub fn new() -> Self {
        PublicKeys { keys: vec![] }
    }

    pub fn from(keys: Vec<PublicKey>) -> Self {
        PublicKeys { keys }
    }

    pub fn extend(&mut self, other: &PublicKeys) -> Result<(), error::Format> {
        if !self.is_disjoint(&other) {
            return Err(error::Format::PublicKeyTableOverlap);
        }
        self.keys.extend(other.keys.iter().cloned());
        Ok(())
    }

    pub fn insert(&mut self, k: &PublicKey) -> u64 {
        match self.keys.iter().position(|key| key == k) {
            Some(index) => index as u64,
            None => {
                self.keys.push(*k);
                (self.keys.len() - 1) as u64
            }
        }
    }

    pub fn get(&self, k: &PublicKey) -> Option<u64> {
        self.keys.iter().position(|key| key == k).map(|i| i as u64)
    }

    pub fn current_offset(&self) -> usize {
        self.keys.len()
    }

    pub fn split_at(&mut self, offset: usize) -> PublicKeys {
        let mut table = PublicKeys::new();
        table.keys = self.keys.split_off(offset);
        table
    }

    pub fn is_disjoint(&self, other: &PublicKeys) -> bool {
        let h1 = self.keys.iter().collect::<HashSet<_>>();
        let h2 = other.keys.iter().collect::<HashSet<_>>();

        h1.is_disjoint(&h2)
    }

    pub fn get_key(&self, i: u64) -> Option<&PublicKey> {
        self.keys.get(i as usize)
    }

    pub fn into_inner(self) -> Vec<PublicKey> {
        self.keys
    }
}
