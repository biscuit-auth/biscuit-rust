use super::{BlockBuilder, Check, Fact, Rule, Scope, Term};
use crate::builder_ext::BuilderExt;
use crate::crypto::PublicKey;
use crate::datalog::SymbolTable;
use crate::token::default_symbol_table;
use crate::{error, Biscuit, KeyPair};
use rand::{CryptoRng, RngCore};

use std::fmt;
use std::time::SystemTime;
use std::{collections::HashMap, convert::TryInto, fmt::Write};

/// creates a Biscuit
#[derive(Clone, Default)]
pub struct BiscuitBuilder {
    inner: BlockBuilder,
    root_key_id: Option<u32>,
}

impl BiscuitBuilder {
    pub fn new() -> BiscuitBuilder {
        BiscuitBuilder {
            inner: BlockBuilder::new(),
            root_key_id: None,
        }
    }

    pub fn merge(&mut self, other: BlockBuilder) {
        self.inner.merge(other)
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        self.inner.add_fact(fact)
    }

    pub fn add_rule<Ru: TryInto<Rule>>(&mut self, rule: Ru) -> Result<(), error::Token>
    where
        error::Token: From<<Ru as TryInto<Rule>>::Error>,
    {
        self.inner.add_rule(rule)
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.inner.add_check(check)
    }

    pub fn add_code<T: AsRef<str>>(&mut self, source: T) -> Result<(), error::Token> {
        self.inner
            .add_code_with_params(source, HashMap::new(), HashMap::new())
    }

    pub fn add_code_with_params<T: AsRef<str>>(
        &mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<(), error::Token> {
        self.inner
            .add_code_with_params(source, params, scope_params)
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.inner.add_scope(scope);
    }

    #[cfg(test)]
    pub(crate) fn add_right(&mut self, resource: &str, right: &str) {
        use crate::builder::fact;

        use super::string;

        let _ = self.add_fact(fact("right", &[string(resource), string(right)]));
    }

    pub fn set_context(&mut self, context: String) {
        self.inner.set_context(context);
    }

    pub fn set_root_key_id(&mut self, root_key_id: u32) {
        self.root_key_id = Some(root_key_id);
    }

    /// returns all of the datalog loaded in the biscuit builder
    pub fn dump(&self) -> (Vec<Fact>, Vec<Rule>, Vec<Check>) {
        (
            self.inner.facts.clone(),
            self.inner.rules.clone(),
            self.inner.checks.clone(),
        )
    }

    pub fn dump_code(&self) -> String {
        let (facts, rules, checks) = self.dump();
        let mut f = String::new();
        for fact in facts {
            let _ = writeln!(f, "{};", fact);
        }
        for rule in rules {
            let _ = writeln!(f, "{};", rule);
        }
        for check in checks {
            let _ = writeln!(f, "{};", check);
        }
        f
    }

    pub fn build(self, root_key: &KeyPair) -> Result<Biscuit, error::Token> {
        self.build_with_symbols(root_key, default_symbol_table())
    }

    pub fn build_with_symbols(
        self,
        root_key: &KeyPair,
        symbols: SymbolTable,
    ) -> Result<Biscuit, error::Token> {
        self.build_with_rng(root_key, symbols, &mut rand::rngs::OsRng)
    }

    pub fn build_with_rng<R: RngCore + CryptoRng>(
        self,
        root: &KeyPair,
        symbols: SymbolTable,
        rng: &mut R,
    ) -> Result<Biscuit, error::Token> {
        let authority_block = self.inner.build(symbols.clone());
        Biscuit::new_with_rng(rng, self.root_key_id, root, symbols, authority_block)
    }

    pub fn build_with_key_pair(
        self,
        root: &KeyPair,
        symbols: SymbolTable,
        next: &KeyPair,
    ) -> Result<Biscuit, error::Token> {
        let authority_block = self.inner.build(symbols.clone());
        Biscuit::new_with_key_pair(self.root_key_id, root, next, symbols, authority_block)
    }
}

impl fmt::Display for BiscuitBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.root_key_id {
            None => writeln!(f, "// no root key id set")?,
            Some(id) => writeln!(f, "// root key id: {}", id)?,
        }
        self.inner.fmt(f)
    }
}

impl BuilderExt for BiscuitBuilder {
    fn add_resource(&mut self, name: &str) {
        self.inner.add_resource(name);
    }
    fn check_resource(&mut self, name: &str) {
        self.inner.check_resource(name);
    }
    fn check_resource_prefix(&mut self, prefix: &str) {
        self.inner.check_resource_prefix(prefix);
    }
    fn check_resource_suffix(&mut self, suffix: &str) {
        self.inner.check_resource_suffix(suffix);
    }
    fn add_operation(&mut self, name: &str) {
        self.inner.add_operation(name);
    }
    fn check_operation(&mut self, name: &str) {
        self.inner.check_operation(name);
    }
    fn check_expiration_date(&mut self, date: SystemTime) {
        self.inner.check_expiration_date(date);
    }
}
