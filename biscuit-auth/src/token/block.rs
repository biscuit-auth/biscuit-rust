use std::collections::HashMap;

use crate::{
    crypto::PublicKey,
    datalog::{Check, Fact, Origin, Rule, SymbolTable, Term},
};

use super::{public_keys::PublicKeys, Scope};

/// a block contained in a token
#[derive(Clone, Debug)]
pub struct Block {
    /// list of symbols introduced by this block
    pub symbols: SymbolTable,
    /// list of facts provided by this block
    pub facts: Vec<Fact>,
    /// list of rules provided by this block
    pub rules: Vec<Rule>,
    /// checks that the token and ambient data must validate
    pub checks: Vec<Check>,
    /// contextual information that can be looked up before the verification
    /// (as an example, a user id to query rights into a database)
    pub context: Option<String>,
    /// format version used to generate this block
    pub version: u32,
    /// key used in optional external signature
    pub external_key: Option<PublicKey>,
    /// list of public keys referenced by this block
    pub public_keys: PublicKeys,
    /// list of scopes defining which blocks are trusted by this block
    pub scopes: Vec<Scope>,
}

impl Block {
    pub fn symbol_add(&mut self, s: &str) -> Term {
        self.symbols.add(s)
    }

    pub fn symbol_insert(&mut self, s: &str) -> u64 {
        self.symbols.insert(s)
    }

    pub(crate) fn print_source(&self, symbols: &SymbolTable) -> String {
        let facts: Vec<_> = self.facts.iter().map(|f| symbols.print_fact(f)).collect();
        let rules: Vec<_> = self
            .rules
            .iter()
            .map(|rule| symbols.print_rule(rule))
            .collect();
        let checks: Vec<_> = self
            .checks
            .iter()
            .map(|check| symbols.print_check(check))
            .collect();

        let mut res = facts.join(";\n");
        if !facts.is_empty() {
            res.push_str(";\n");
        }
        res.push_str(&rules.join(";\n"));
        if !rules.is_empty() {
            res.push_str(";\n");
        }
        res.push_str(&checks.join(";\n"));
        if !checks.is_empty() {
            res.push_str(";\n");
        }

        res
    }

    pub(crate) fn origins(
        &self,
        current_block: usize,
        public_key_to_block_id: Option<&HashMap<usize, Vec<usize>>>,
    ) -> Origin {
        let mut origins = Origin::default();
        // we always trust the authorizer
        origins.insert(usize::MAX);
        // we always trust the current block
        origins.insert(current_block);

        // in the default case, we trust the authority block
        if self.scopes.is_empty() {
            origins.insert(0);
        } else {
            for scope in &self.scopes {
                match scope {
                    Scope::Authority => {
                        origins.insert(0);
                    }
                    Scope::Previous => {
                        if current_block != usize::MAX {
                            origins.extend(0..current_block + 1)
                        }
                    }
                    Scope::PublicKey(key_id) => {
                        if let Some(map) = public_key_to_block_id {
                            if let Some(block_ids) = map.get(&(*key_id as usize)) {
                                origins.extend(block_ids.iter())
                            }
                        }
                    }
                }
            }
        }
        origins
    }
}
