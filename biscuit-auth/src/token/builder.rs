//! helper functions and structure to create tokens and blocks
use super::{default_symbol_table, Biscuit, Block};
use crate::crypto::{KeyPair, PublicKey};
use crate::datalog::{self, SymbolTable};
use crate::error;
use crate::parser::parse_block_source;
use rand_core::{CryptoRng, RngCore};
use std::{
    collections::{BTreeSet, HashMap},
    convert::{TryFrom, TryInto},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// reexport those because the builder uses the same definitions
pub use crate::datalog::{Binary, Unary};

#[cfg(feature = "datalog-macro")]
use quote::{quote, ToTokens};

/// creates a Block content to append to an existing token
#[derive(Clone, Debug, Default)]
pub struct BlockBuilder {
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub scopes: Vec<Scope>,
    pub context: Option<String>,
}

impl BlockBuilder {
    pub fn new() -> BlockBuilder {
        BlockBuilder::default()
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        let fact = fact.try_into()?;
        fact.validate()?;

        self.facts.push(fact);
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let rule = rule.try_into()?;
        rule.validate_parameters()?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        let check = check.try_into()?;
        check.validate_parameters()?;
        self.checks.push(check);
        Ok(())
    }

    pub fn add_code<T: AsRef<str>>(&mut self, source: T) -> Result<(), error::Token> {
        self.add_code_with_params(source, HashMap::new(), HashMap::new())
    }

    /// Add datalog code to the builder, performing parameter subsitution as required
    /// Unknown parameters are ignored
    pub fn add_code_with_params<T: AsRef<str>>(
        &mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<(), error::Token> {
        let input = source.as_ref();

        let source_result = parse_block_source(input)?;

        for (_, mut fact) in source_result.facts.into_iter() {
            for (name, value) in &params {
                let res = match fact.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::Parameters {
                        missing_parameters,
                        ..
                    })) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            fact.validate()?;
            self.facts.push(fact);
        }

        for (_, mut rule) in source_result.rules.into_iter() {
            for (name, value) in &params {
                let res = match rule.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::Parameters {
                        missing_parameters,
                        ..
                    })) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match rule.set_scope(&name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::Parameters {
                        missing_parameters,
                        ..
                    })) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            rule.validate_parameters()?;
            self.rules.push(rule);
        }

        for (_, mut check) in source_result.checks.into_iter() {
            for (name, value) in &params {
                let res = match check.set(&name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(error::LanguageError::Parameters {
                        missing_parameters,
                        ..
                    })) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            check.validate_parameters()?;
            self.checks.push(check);
        }

        Ok(())
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.push(scope);
    }

    pub fn set_context(&mut self, context: String) {
        self.context = Some(context);
    }

    pub(crate) fn build(self, mut symbols: SymbolTable) -> Block {
        let symbols_start = symbols.current_offset();
        let public_keys_start = symbols.public_keys.current_offset();

        let mut facts = Vec::new();
        for fact in self.facts {
            facts.push(fact.convert(&mut symbols));
        }

        let mut rules = Vec::new();
        for rule in self.rules {
            rules.push(rule.convert(&mut symbols));
        }

        let mut checks = Vec::new();
        for check in self.checks {
            checks.push(check.convert(&mut symbols));
        }
        let new_syms = symbols.split_at(symbols_start);
        let public_keys = symbols.public_keys.split_at(public_keys_start);

        Block {
            symbols: new_syms,
            facts,
            rules,
            checks,
            context: self.context,
            version: super::MAX_SCHEMA_VERSION,
            external_key: None,
            public_keys,
            scopes: self
                .scopes
                .into_iter()
                .map(|scope| scope.convert(&mut symbols))
                .collect(),
        }
    }

    // still used in tests but does not make sense for the public API
    #[cfg(test)]
    pub(crate) fn check_right(&mut self, right: &str) {
        let check = rule(
            "check_right",
            &[string(right)],
            &[
                pred("resource", &[var("resource_name")]),
                pred("operation", &[string(right)]),
                pred("right", &[var("resource_name"), string(right)]),
            ],
        );

        let _ = self.add_check(check);
    }

    /// checks the presence of a fact `resource($resource)`
    pub fn check_resource(&mut self, resource: &str) {
        let check = rule(
            "resource_check",
            &[string("resource_check")],
            &[pred("resource", &[string(resource)])],
        );

        let _ = self.add_check(check);
    }

    /// checks the presence of a fact `operation($operation)`
    pub fn check_operation(&mut self, operation: &str) {
        let check = rule(
            "operation_check",
            &[string("operation_check")],
            &[pred("operation", &[string(operation)])],
        );

        let _ = self.add_check(check);
    }

    pub fn resource_prefix(&mut self, prefix: &str) {
        let check = constrained_rule(
            "prefix",
            &[var("resource")],
            &[pred("resource", &[var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(prefix)),
                    Op::Binary(Binary::Prefix),
                ],
            }],
        );

        let _ = self.add_check(check);
    }

    pub fn resource_suffix(&mut self, suffix: &str) {
        let check = constrained_rule(
            "suffix",
            &[var("resource")],
            &[pred("resource", &[var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(suffix)),
                    Op::Binary(Binary::Suffix),
                ],
            }],
        );

        let _ = self.add_check(check);
    }

    pub fn expiration_date(&mut self, exp: SystemTime) {
        let check = constrained_rule(
            "expiration",
            &[var("date")],
            &[pred("time", &[var("date")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("date")),
                    Op::Value(date(&exp)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            }],
        );

        let _ = self.add_check(check);
    }
}

impl fmt::Display for BlockBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for mut fact in self.facts.clone().into_iter() {
            fact.apply_parameters();
            write!(f, "{};\n", &fact)?;
        }
        for mut rule in self.rules.clone().into_iter() {
            rule.apply_parameters();
            write!(f, "{};\n", &rule)?;
        }
        for mut check in self.checks.clone().into_iter() {
            check.apply_parameters();
            write!(f, "{};\n", &check)?;
        }
        Ok(())
    }
}

/// creates a Biscuit
#[derive(Clone)]
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
            f.push_str(&format!("{};\n", &fact));
        }
        for rule in rules {
            f.push_str(&format!("{};\n", &rule));
        }
        for check in checks {
            f.push_str(&format!("{};\n", &check));
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
}

/// Builder for a Datalog value
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    Variable(String),
    Integer(i64),
    Str(String),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<Term>),
    Parameter(String),
}

impl Term {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Term {
        match self {
            Term::Variable(s) => datalog::Term::Variable(symbols.insert(s) as u32),
            Term::Integer(i) => datalog::Term::Integer(*i),
            Term::Str(s) => datalog::Term::Str(symbols.insert(s)),
            Term::Date(d) => datalog::Term::Date(*d),
            Term::Bytes(s) => datalog::Term::Bytes(s.clone()),
            Term::Bool(b) => datalog::Term::Bool(*b),
            Term::Set(s) => datalog::Term::Set(s.iter().map(|i| i.convert(symbols)).collect()),
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Term::Parameter(s) => panic!("Remaining parameter {}", &s),
        }
    }

    pub fn convert_from(f: &datalog::Term, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(match f {
            datalog::Term::Variable(s) => Term::Variable(symbols.print_symbol(*s as u64)?),
            datalog::Term::Integer(i) => Term::Integer(*i),
            datalog::Term::Str(s) => Term::Str(symbols.print_symbol(*s)?),
            datalog::Term::Date(d) => Term::Date(*d),
            datalog::Term::Bytes(s) => Term::Bytes(s.clone()),
            datalog::Term::Bool(b) => Term::Bool(*b),
            datalog::Term::Set(s) => Term::Set(
                s.iter()
                    .map(|i| Term::convert_from(i, symbols))
                    .collect::<Result<BTreeSet<_>, error::Format>>()?,
            ),
        })
    }
}

impl From<&Term> for Term {
    fn from(i: &Term) -> Self {
        match i {
            Term::Variable(ref v) => Term::Variable(v.clone()),
            Term::Integer(ref i) => Term::Integer(*i),
            Term::Str(ref s) => Term::Str(s.clone()),
            Term::Date(ref d) => Term::Date(*d),
            Term::Bytes(ref s) => Term::Bytes(s.clone()),
            Term::Bool(b) => Term::Bool(*b),
            Term::Set(ref s) => Term::Set(s.clone()),
            Term::Parameter(ref p) => Term::Parameter(p.clone()),
        }
    }
}

impl AsRef<Term> for Term {
    fn as_ref(&self) -> &Term {
        self
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Variable(i) => write!(f, "${}", i),
            Term::Integer(i) => write!(f, "{}", i),
            Term::Str(s) => write!(f, "\"{}\"", s),
            Term::Date(d) => {
                let date = time::OffsetDateTime::from_unix_timestamp(*d as i64)
                    .ok()
                    .and_then(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    })
                    .unwrap_or_else(|| "<invalid date>".to_string());

                write!(f, "{}", date)
            }
            Term::Bytes(s) => write!(f, "hex:{}", hex::encode(s)),
            Term::Bool(b) => {
                if *b {
                    write!(f, "true")
                } else {
                    write!(f, "false")
                }
            }
            Term::Set(s) => {
                let terms = s.iter().map(|term| term.to_string()).collect::<Vec<_>>();
                write!(f, "[ {}]", terms.join(", "))
            }
            Term::Parameter(s) => {
                write!(f, "{{{}}}", s)
            }
        }
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Term {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            Term::Variable(v) => quote! { ::biscuit_auth::builder::Term::Variable(#v.to_string()) },
            Term::Integer(v) => quote! { ::biscuit_auth::builder::Term::Integer(#v) },
            Term::Str(v) => quote! { ::biscuit_auth::builder::Term::Str(#v.to_string()) },
            Term::Date(v) => quote! { ::biscuit_auth::builder::Term::Date(#v) },
            Term::Bool(v) => quote! { ::biscuit_auth::builder::Term::Bool(#v) },
            Term::Parameter(v) => quote! { ::biscuit_auth::builder::Term::Parameter(#v.to_string()) },
            Term::Bytes(v) => quote! { ::biscuit_auth::builder::Term::Bytes(<[u8]>::into_vec(Box::new([ #(#v),*]))) },
            Term::Set(v) => {
                quote! { ::biscuit_auth::builder::Term::Set(::std::collections::BTreeSet::from_iter(<[::biscuit_auth::builder::Term]>::into_vec(Box::new([ #(#v),*])))) }
            }
        })
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    Authority,
    Previous,
    PublicKey(PublicKey),
    Parameter(String),
}

impl Scope {
    pub fn convert(&self, symbols: &mut SymbolTable) -> super::Scope {
        match self {
            Scope::Authority => crate::token::Scope::Authority,
            Scope::Previous => crate::token::Scope::Previous,
            Scope::PublicKey(key) => {
                crate::token::Scope::PublicKey(symbols.public_keys.insert(&key))
            }
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Scope::Parameter(s) => panic!("Remaining parameter {}", &s),
        }
    }

    pub fn convert_from(
        scope: &super::Scope,
        symbols: &SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(match scope {
            super::Scope::Authority => Scope::Authority,
            super::Scope::Previous => Scope::Previous,
            super::Scope::PublicKey(key_id) => Scope::PublicKey(
                *symbols
                    .public_keys
                    .get_key(*key_id)
                    .ok_or(error::Format::UnknownExternalKey)?,
            ),
        })
    }
}

impl ToTokens for Scope {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            Scope::Authority => quote! { ::biscuit_auth::builder::Scope::Authority},
            Scope::Previous => quote! { ::biscuit_auth::builder::Scope::Previous},
            Scope::PublicKey(_pk) => {
                // rustc complains about `pk` not being used (I guess because of the quote! macro)
                // so it's named _pk to silence the warning.
                quote! { ::biscuit_auth::builder::Scope::PublicKey(
                  ::biscuit_auth::crypto::PublicKey.from_bytes(#(_pk.to_bytes())).unwrap()
                )}
            }
            Scope::Parameter(v) => {
                quote! { ::biscuit_auth::builder::Scope::Parameter(#v.to_string())}
            }
        })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Authority => write!(f, "authority"),
            Scope::Previous => write!(f, "previous"),
            Scope::PublicKey(pk) => write!(f, "ed25519/{}", hex::encode(pk.to_bytes())),
            Scope::Parameter(s) => {
                write!(f, "{{{}}}", s)
            }
        }
    }
}

/// Builder for a Datalog dicate, used in facts and rules
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: String,
    pub terms: Vec<Term>,
}

impl Predicate {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Predicate {
        let name = symbols.insert(&self.name);
        let mut terms = vec![];

        for term in self.terms.iter() {
            terms.push(term.convert(symbols));
        }

        datalog::Predicate { name, terms }
    }

    pub fn convert_from(
        p: &datalog::Predicate,
        symbols: &SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(Predicate {
            name: symbols.print_symbol(p.name)?,
            terms: p
                .terms
                .iter()
                .map(|term| Term::convert_from(term, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
        })
    }

    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Predicate {
        Predicate {
            name,
            terms: terms.into(),
        }
    }
}

impl AsRef<Predicate> for Predicate {
    fn as_ref(&self) -> &Predicate {
        self
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.name)?;

        if !self.terms.is_empty() {
            write!(f, "{}", self.terms[0])?;

            if self.terms.len() > 1 {
                for i in 1..self.terms.len() {
                    write!(f, ", {}", self.terms[i])?;
                }
            }
        }
        write!(f, ")")
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Predicate {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let name = &self.name;
        let terms = self.terms.iter();
        tokens.extend(quote! {
            ::biscuit_auth::builder::Predicate::new(
              #name.to_string(),
              <[::biscuit_auth::builder::Term]>::into_vec(Box::new([#(#terms),*]))
            )
        })
    }
}

/// Builder for a Datalog fact
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub predicate: Predicate,
    pub parameters: Option<HashMap<String, Option<Term>>>,
}

impl Fact {
    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Fact {
        let mut parameters = HashMap::new();
        let terms: Vec<Term> = terms.into();

        for term in &terms {
            if let Term::Parameter(name) = &term {
                parameters.insert(name.to_string(), None);
            }
        }
        Fact {
            predicate: Predicate::new(name, terms),
            parameters: Some(parameters),
        }
    }

    pub fn validate(&self) -> Result<(), error::Token> {
        match &self.parameters {
            None => Ok(()),
            Some(parameters) => {
                let invalid_parameters = parameters
                    .iter()
                    .filter_map(
                        |(name, opt_term)| {
                            if opt_term.is_none() {
                                Some(name)
                            } else {
                                None
                            }
                        },
                    )
                    .map(|name| name.to_string())
                    .collect::<Vec<_>>();

                if invalid_parameters.is_empty() {
                    Ok(())
                } else {
                    Err(error::Token::Language(error::LanguageError::Parameters {
                        missing_parameters: invalid_parameters,
                        unused_parameters: vec![],
                    }))
                }
            }
        }
    }
}

impl Fact {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        let mut fact = self.clone();
        fact.apply_parameters();

        datalog::Fact {
            predicate: fact.predicate.convert(symbols),
        }
    }

    pub fn convert_from(f: &datalog::Fact, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Fact {
            predicate: Predicate::convert_from(&f.predicate, symbols)?,
            parameters: None,
        })
    }

    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                })),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a parameter with the term argument, without raising an error
    /// if the parameter is not present in the fact description
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Ok(()),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: ToAnyParam>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        match param.to_any_param() {
            AnyParam::Term(t) => self.set_lenient(name, t),
            AnyParam::PublicKey(_) => Ok(()),
        }
    }

    fn apply_parameters(&mut self) {
        if let Some(parameters) = self.parameters.clone() {
            self.predicate.terms = self
                .predicate
                .terms
                .drain(..)
                .map(|t| {
                    if let Term::Parameter(name) = &t {
                        if let Some(Some(term)) = parameters.get(name) {
                            return term.clone();
                        }
                    }
                    t
                })
                .collect();
        }
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fact = self.clone();
        fact.apply_parameters();

        fact.predicate.fmt(f)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Fact {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let name = &self.predicate.name;
        let terms = self.predicate.terms.iter();
        tokens.extend(quote! {
            ::biscuit_auth::builder::Fact::new(
              #name.to_string(),
              <[::biscuit_auth::builder::Term]>::into_vec(Box::new([#(#terms),*]))
            )
        })
    }
}

/// Builder for a Datalog expression
#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub ops: Vec<Op>,
}
// todo track parameters

impl Expression {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Expression {
        datalog::Expression {
            ops: self.ops.iter().map(|op| op.convert(symbols)).collect(),
        }
    }

    pub fn convert_from(
        e: &datalog::Expression,
        symbols: &SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(Expression {
            ops: e
                .ops
                .iter()
                .map(|op| Op::convert_from(op, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
        })
    }
}

impl AsRef<Expression> for Expression {
    fn as_ref(&self) -> &Expression {
        self
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut syms = super::default_symbol_table();
        let expr = self.convert(&mut syms);
        let s = expr.print(&syms).unwrap();
        write!(f, "{}", s)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Expression {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let ops = self.ops.iter();
        tokens.extend(quote! {
          ::biscuit_auth::builder::Expression {
            ops: <[::biscuit_auth::builder::Op]>::into_vec(Box::new([#(#ops),*]))
          }
        });
    }
}

/// Builder for an expression operation
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Value(Term),
    Unary(Unary),
    Binary(Binary),
}

impl Op {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Op {
        match self {
            Op::Value(t) => datalog::Op::Value(t.convert(symbols)),
            Op::Unary(u) => datalog::Op::Unary(u.clone()),
            Op::Binary(b) => datalog::Op::Binary(b.clone()),
        }
    }

    pub fn convert_from(op: &datalog::Op, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(match op {
            datalog::Op::Value(t) => Op::Value(Term::convert_from(t, symbols)?),
            datalog::Op::Unary(u) => Op::Unary(u.clone()),
            datalog::Op::Binary(b) => Op::Binary(b.clone()),
        })
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Op {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            Op::Value(t) => quote! { ::biscuit_auth::builder::Op::Value(#t) },
            Op::Unary(u) => quote! { ::biscuit_auth::builder::Op::Unary(#u) },
            Op::Binary(b) => quote! { ::biscuit_auth::builder::Op::Binary(#b) },
        });
    }
}

/// Builder for a Datalog rule
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub head: Predicate,
    pub body: Vec<Predicate>,
    pub expressions: Vec<Expression>,
    pub parameters: Option<HashMap<String, Option<Term>>>,
    pub scopes: Vec<Scope>,
    pub scope_parameters: Option<HashMap<String, Option<PublicKey>>>,
}

impl Rule {
    pub fn new(
        head: Predicate,
        body: Vec<Predicate>,
        expressions: Vec<Expression>,
        scopes: Vec<Scope>,
    ) -> Rule {
        let mut parameters = HashMap::new();
        let mut scope_parameters = HashMap::new();
        for term in &head.terms {
            if let Term::Parameter(name) = &term {
                parameters.insert(name.to_string(), None);
            }
        }

        for predicate in &body {
            for term in &predicate.terms {
                if let Term::Parameter(name) = &term {
                    parameters.insert(name.to_string(), None);
                }
            }
        }

        for expression in &expressions {
            for op in &expression.ops {
                if let Op::Value(Term::Parameter(name)) = &op {
                    parameters.insert(name.to_string(), None);
                }
            }
        }

        for scope in &scopes {
            if let Scope::Parameter(name) = &scope {
                scope_parameters.insert(name.to_string(), None);
            }
        }

        Rule {
            head,
            body,
            expressions,
            parameters: Some(parameters),
            scopes,
            scope_parameters: Some(scope_parameters),
        }
    }

    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
        let mut r = self.clone();
        r.apply_parameters();

        let head = r.head.convert(symbols);
        let mut body = vec![];
        let mut expressions = vec![];
        let mut scopes = vec![];

        for p in r.body.iter() {
            body.push(p.convert(symbols));
        }

        for c in r.expressions.iter() {
            expressions.push(c.convert(symbols));
        }

        for scope in r.scopes.iter() {
            scopes.push(match scope {
                Scope::Authority => crate::token::Scope::Authority,
                Scope::Previous => crate::token::Scope::Previous,
                Scope::PublicKey(key) => {
                    crate::token::Scope::PublicKey(symbols.public_keys.insert(&key))
                }
                // The error is caught in the `add_xxx` functions, so this should
                // not happen™
                Scope::Parameter(s) => panic!("Remaining parameter {}", &s),
            })
        }
        datalog::Rule {
            head,
            body,
            expressions,
            scopes,
        }
    }

    pub fn convert_from(r: &datalog::Rule, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Rule {
            head: Predicate::convert_from(&r.head, symbols)?,
            body: r
                .body
                .iter()
                .map(|p| Predicate::convert_from(p, symbols))
                .collect::<Result<Vec<Predicate>, error::Format>>()?,
            expressions: r
                .expressions
                .iter()
                .map(|c| Expression::convert_from(c, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
            parameters: None,
            scopes: r
                .scopes
                .iter()
                .map(|scope| Scope::convert_from(scope, symbols))
                .collect::<Result<Vec<Scope>, error::Format>>()?,
            scope_parameters: None,
        })
    }

    pub fn validate_parameters(&self) -> Result<(), error::Token> {
        let mut invalid_parameters = match &self.parameters {
            None => vec![],
            Some(parameters) => parameters
                .iter()
                .filter_map(
                    |(name, opt_term)| {
                        if opt_term.is_none() {
                            Some(name)
                        } else {
                            None
                        }
                    },
                )
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        };
        let mut invalid_scope_parameters = match &self.scope_parameters {
            None => vec![],
            Some(parameters) => parameters
                .iter()
                .filter_map(
                    |(name, opt_key)| {
                        if opt_key.is_none() {
                            Some(name)
                        } else {
                            None
                        }
                    },
                )
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        };
        let mut all_invalid_parameters = vec![];
        all_invalid_parameters.append(&mut invalid_parameters);
        all_invalid_parameters.append(&mut invalid_scope_parameters);

        if all_invalid_parameters.is_empty() {
            Ok(())
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: all_invalid_parameters,
                unused_parameters: vec![],
            }))
        }
    }

    pub fn validate_variables(&self) -> Result<(), String> {
        let mut head_variables: std::collections::HashSet<String> = self
            .head
            .terms
            .iter()
            .filter_map(|term| match term {
                Term::Variable(s) => Some(s.to_string()),
                _ => None,
            })
            .collect();

        for predicate in self.body.iter() {
            for term in predicate.terms.iter() {
                if let Term::Variable(v) = term {
                    head_variables.remove(v);
                    if head_variables.is_empty() {
                        return Ok(());
                    }
                }
            }
        }

        if head_variables.is_empty() {
            Ok(())
        } else {
            Err(format!(
                    "rule head contains variables that are not used in predicates of the rule's body: {}",
                    head_variables
                    .iter()
                    .map(|s| format!("${}", s))
                    .collect::<Vec<_>>()
                    .join(", ")
                    ))
        }
    }

    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                })),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a parameter with the term argument, without raising an error if the
    /// parameter is not present in the rule
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Ok(()),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a scope parameter with the pubkey argument
    pub fn set_scope(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        if let Some(parameters) = self.scope_parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                })),
                Some(v) => {
                    *v = Some(pubkey);
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a scope parameter with the public key argument, without raising an error if the
    /// parameter is not present in the rule scope
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        if let Some(parameters) = self.scope_parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Ok(()),
                Some(v) => {
                    *v = Some(pubkey);
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: ToAnyParam>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        match param.to_any_param() {
            AnyParam::Term(t) => self.set_lenient(name, t),
            AnyParam::PublicKey(pubkey) => self.set_scope_lenient(name, pubkey),
        }
    }

    fn apply_parameters(&mut self) {
        if let Some(parameters) = self.parameters.clone() {
            self.head.terms = self
                .head
                .terms
                .drain(..)
                .map(|t| {
                    if let Term::Parameter(name) = &t {
                        if let Some(Some(term)) = parameters.get(name) {
                            return term.clone();
                        }
                    }
                    t
                })
                .collect();

            for predicate in &mut self.body {
                predicate.terms = predicate
                    .terms
                    .drain(..)
                    .map(|t| {
                        if let Term::Parameter(name) = &t {
                            if let Some(Some(term)) = parameters.get(name) {
                                return term.clone();
                            }
                        }
                        t
                    })
                    .collect();
            }

            for expression in &mut self.expressions {
                expression.ops = expression
                    .ops
                    .drain(..)
                    .map(|op| {
                        if let Op::Value(Term::Parameter(name)) = &op {
                            if let Some(Some(term)) = parameters.get(name) {
                                return Op::Value(term.clone());
                            }
                        }
                        op
                    })
                    .collect();
            }
        }

        if let Some(parameters) = self.scope_parameters.clone() {
            self.scopes = self
                .scopes
                .drain(..)
                .map(|scope| {
                    if let Scope::Parameter(name) = &scope {
                        if let Some(Some(pubkey)) = parameters.get(name) {
                            return Scope::PublicKey(pubkey.clone());
                        }
                    }
                    scope
                })
                .collect();
        }
    }
}

fn display_rule_body(r: &Rule, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut rule = r.clone();
    rule.apply_parameters();
    if !rule.body.is_empty() {
        write!(f, "{}", rule.body[0])?;

        if rule.body.len() > 1 {
            for i in 1..rule.body.len() {
                write!(f, ", {}", rule.body[i])?;
            }
        }
    }

    if !rule.expressions.is_empty() {
        if !rule.body.is_empty() {
            write!(f, ", ")?;
        }

        write!(f, "{}", rule.expressions[0])?;

        if rule.expressions.len() > 1 {
            for i in 1..rule.expressions.len() {
                write!(f, ", {}", rule.expressions[i])?;
            }
        }
    }

    if !rule.scopes.is_empty() {
        write!(f, " trusting {}", rule.scopes[0])?;
        if rule.scopes.len() > 1 {
            for i in 1..rule.scopes.len() {
                write!(f, ", {}", rule.scopes[i])?;
            }
        }
    }

    Ok(())
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = self.clone();
        r.apply_parameters();

        write!(f, "{} <- ", r.head)?;

        display_rule_body(&r, f)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Rule {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let head = &self.head;
        let body = self.body.iter();
        let expressions = self.expressions.iter();
        let scopes = self.scopes.iter();
        tokens.extend(quote! {
          ::biscuit_auth::builder::Rule::new(
            #head,
            <[::biscuit_auth::builder::Predicate]>::into_vec(Box::new([#(#body),*])),
            <[::biscuit_auth::builder::Expression]>::into_vec(Box::new([#(#expressions),*])),
            <[::biscuit_auth::builder::Scope]>::into_vec(Box::new([#(#scopes),*]))
          )
        });
    }
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub queries: Vec<Rule>,
}

impl Check {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Check {
        let mut queries = vec![];
        for q in self.queries.iter() {
            queries.push(q.convert(symbols));
        }

        datalog::Check { queries }
    }

    pub fn convert_from(r: &datalog::Check, symbols: &SymbolTable) -> Result<Self, error::Format> {
        let mut queries = vec![];
        for q in r.queries.iter() {
            queries.push(Rule::convert_from(q, symbols)?);
        }

        Ok(Check { queries })
    }

    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        self.set_inner(name, term)
    }

    fn set_inner(&mut self, name: &str, term: Term) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set(name, term.clone()).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a scope parameter with the pubkey argument
    pub fn set_scope(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set_scope(name, pubkey).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a parameter with the term argument, without raising an error if the
    /// parameter is not present in the check
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        for query in &mut self.queries {
            query.set_lenient(name, term.clone())?;
        }
        Ok(())
    }

    /// replace a scope parameter with the term argument, without raising an error if the
    /// parameter is not present in the check
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        for query in &mut self.queries {
            query.set_scope_lenient(name, pubkey)?;
        }
        Ok(())
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: ToAnyParam>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        match param.to_any_param() {
            AnyParam::Term(t) => self.set_lenient(name, t),
            AnyParam::PublicKey(p) => self.set_scope_lenient(name, p),
        }
    }

    pub fn validate_parameters(&self) -> Result<(), error::Token> {
        for rule in &self.queries {
            rule.validate_parameters()?;
        }

        Ok(())
    }

    fn apply_parameters(&mut self) {
        for rule in self.queries.iter_mut() {
            rule.apply_parameters();
        }
    }
}

impl TryFrom<Rule> for Check {
    type Error = error::Token;

    fn try_from(value: Rule) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: vec![value],
        })
    }
}

impl TryFrom<&[Rule]> for Check {
    type Error = error::Token;

    fn try_from(values: &[Rule]) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: values.to_vec(),
        })
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check if ")?;

        if !self.queries.is_empty() {
            let mut q0 = self.queries[0].clone();
            q0.apply_parameters();
            display_rule_body(&q0, f)?;

            if self.queries.len() > 1 {
                for i in 1..self.queries.len() {
                    write!(f, " or ")?;
                    let mut qn = self.queries[i].clone();
                    qn.apply_parameters();
                    display_rule_body(&qn, f)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Check {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let queries = self.queries.iter();
        tokens.extend(quote! {
          ::biscuit_auth::builder::Check {
            queries: <[::biscuit_auth::builder::Rule]>::into_vec(Box::new([#(#queries),*])),
          }
        });
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyKind {
    Allow,
    Deny,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for PolicyKind {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            PolicyKind::Allow => quote! {
              ::biscuit_auth::builder::PolicyKind::Allow
            },
            PolicyKind::Deny => quote! {
              ::biscuit_auth::builder::PolicyKind::Deny
            },
        });
    }
}

/// Builder for a Biscuit policy
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub queries: Vec<Rule>,
    pub kind: PolicyKind,
}

impl Policy {
    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        self.set_inner(name, term)
    }

    pub fn set_inner(&mut self, name: &str, term: Term) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set(name, term.clone()).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a scope parameter with the pubkey argument
    pub fn set_scope(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set_scope(name, pubkey).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec![],
                unused_parameters: vec![name.to_string()],
            }))
        }
    }

    /// replace a parameter with the term argument, ignoring unknown parameters
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        for query in &mut self.queries {
            query.set_lenient(name, term.clone())?;
        }
        Ok(())
    }

    /// replace a scope parameter with the pubkey argument, ignoring unknown parameters
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        for query in &mut self.queries {
            query.set_scope_lenient(name, pubkey)?;
        }
        Ok(())
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: ToAnyParam>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        match param.to_any_param() {
            AnyParam::Term(t) => self.set_lenient(name, t),
            AnyParam::PublicKey(p) => self.set_scope_lenient(name, p),
        }
    }

    pub fn validate_parameters(&self) -> Result<(), error::Token> {
        for query in &self.queries {
            query.validate_parameters()?;
        }

        Ok(())
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.queries.is_empty() {
            match self.kind {
                PolicyKind::Allow => write!(f, "allow if ")?,
                PolicyKind::Deny => write!(f, "deny if ")?,
            }

            if !self.queries.is_empty() {
                display_rule_body(&self.queries[0], f)?;

                if self.queries.len() > 1 {
                    for i in 1..self.queries.len() {
                        write!(f, " or ")?;
                        display_rule_body(&self.queries[i], f)?;
                    }
                }
            }
        } else {
            match self.kind {
                PolicyKind::Allow => write!(f, "allow")?,
                PolicyKind::Deny => write!(f, "deny")?,
            }
        }

        Ok(())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Policy {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        let queries = self.queries.iter();
        let kind = &self.kind;
        tokens.extend(quote! {
          ::biscuit_auth::builder::Policy{
            kind: #kind,
            queries: <[::biscuit_auth::builder::Rule]>::into_vec(Box::new([#(#queries),*])),
          }
        });
    }
}

/// creates a new fact
pub fn fact<I: AsRef<Term>>(name: &str, terms: &[I]) -> Fact {
    let pred = pred(name, terms);
    Fact::new(pred.name, pred.terms)
}

/// creates a predicate
pub fn pred<I: AsRef<Term>>(name: &str, terms: &[I]) -> Predicate {
    Predicate {
        name: name.to_string(),
        terms: terms.iter().map(|term| term.as_ref().clone()).collect(),
    }
}

/// creates a rule
pub fn rule<T: AsRef<Term>, P: AsRef<Predicate>>(
    head_name: &str,
    head_terms: &[T],
    predicates: &[P],
) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        Vec::new(),
        vec![],
    )
}

/// creates a rule with constraints
pub fn constrained_rule<T: AsRef<Term>, P: AsRef<Predicate>, E: AsRef<Expression>>(
    head_name: &str,
    head_terms: &[T],
    predicates: &[P],
    expressions: &[E],
) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions.iter().map(|c| c.as_ref().clone()).collect(),
        vec![],
    )
}

/// creates a check
pub fn check<P: AsRef<Predicate>>(predicates: &[P]) -> Check {
    let empty_terms: &[Term] = &[];
    Check {
        queries: vec![Rule::new(
            pred("query", empty_terms),
            predicates.iter().map(|p| p.as_ref().clone()).collect(),
            vec![],
            vec![],
        )],
    }
}

/// creates an integer value
pub fn int(i: i64) -> Term {
    Term::Integer(i)
}

/// creates a string
pub fn string(s: &str) -> Term {
    Term::Str(s.to_string())
}

/// creates a date
///
/// internally the date will be stored as seconds since UNIX_EPOCH
pub fn date(t: &SystemTime) -> Term {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    Term::Date(dur.as_secs())
}

/// creates a variable for a rule
pub fn var(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a variable for a rule
pub fn variable(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a byte array
pub fn bytes(s: &[u8]) -> Term {
    Term::Bytes(s.to_vec())
}

/// creates a boolean
pub fn boolean(b: bool) -> Term {
    Term::Bool(b)
}

/// creates a set
pub fn set(s: BTreeSet<Term>) -> Term {
    Term::Set(s)
}

/// creates a parameter
pub fn parameter(p: &str) -> Term {
    Term::Parameter(p.to_string())
}

#[cfg(feature = "datalog-macro")]
pub enum AnyParam {
    Term(Term),
    PublicKey(PublicKey),
}

#[cfg(feature = "datalog-macro")]
pub trait ToAnyParam {
    fn to_any_param(&self) -> AnyParam;
}

impl From<i64> for Term {
    fn from(i: i64) -> Self {
        Term::Integer(i)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for i64 {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self as i64).into())
    }
}

impl TryFrom<Term> for i64 {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Integer(i) => Ok(i),
            _ => Err(error::Token::ConversionError(format!(
                "expected integer, got {:?}",
                value
            ))),
        }
    }
}

impl From<bool> for Term {
    fn from(b: bool) -> Self {
        Term::Bool(b)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for bool {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self as bool).into())
    }
}

impl TryFrom<Term> for bool {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Bool(b) => Ok(b),
            _ => Err(error::Token::ConversionError(format!(
                "expected boolean, got {:?}",
                value
            ))),
        }
    }
}

impl From<String> for Term {
    fn from(s: String) -> Self {
        Term::Str(s)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for String {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl From<&str> for Term {
    fn from(s: &str) -> Self {
        Term::Str(s.into())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for &str {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.to_string().into())
    }
}

impl TryFrom<Term> for String {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Str(s) => Ok(s),
            _ => Err(error::Token::ConversionError(format!(
                "expected string or symbol, got {:?}",
                value
            ))),
        }
    }
}

impl From<Vec<u8>> for Term {
    fn from(v: Vec<u8>) -> Self {
        Term::Bytes(v)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for Vec<u8> {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl TryFrom<Term> for Vec<u8> {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Bytes(b) => Ok(b),
            _ => Err(error::Token::ConversionError(format!(
                "expected byte array, got {:?}",
                value
            ))),
        }
    }
}

impl From<&[u8]> for Term {
    fn from(v: &[u8]) -> Self {
        Term::Bytes(v.into())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for &[u8] {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl From<SystemTime> for Term {
    fn from(t: SystemTime) -> Self {
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        Term::Date(dur.as_secs())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for SystemTime {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl TryFrom<Term> for SystemTime {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Date(d) => Ok(UNIX_EPOCH + Duration::from_secs(d)),
            _ => Err(error::Token::ConversionError(format!(
                "expected date, got {:?}",
                value
            ))),
        }
    }
}

impl<T: Ord + TryFrom<Term, Error = error::Token>> TryFrom<Term> for BTreeSet<T> {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Set(d) => d.iter().cloned().map(TryFrom::try_from).collect(),
            _ => Err(error::Token::ConversionError(format!(
                "expected set, got {:?}",
                value
            ))),
        }
    }
}

macro_rules! tuple_try_from(
    ($ty1:ident, $ty2:ident, $($ty:ident),*) => (
        tuple_try_from!(__impl $ty1, $ty2; $($ty),*);
        );
    (__impl $($ty: ident),+; $ty1:ident, $($ty2:ident),*) => (
        tuple_try_from_impl!($($ty),+);
        tuple_try_from!(__impl $($ty),+ , $ty1; $($ty2),*);
        );
    (__impl $($ty: ident),+; $ty1:ident) => (
        tuple_try_from_impl!($($ty),+);
        tuple_try_from_impl!($($ty),+, $ty1);
        );
    );

impl<A: TryFrom<Term, Error = error::Token>> TryFrom<Fact> for (A,) {
    type Error = error::Token;
    fn try_from(fact: Fact) -> Result<Self, Self::Error> {
        let mut terms = fact.predicate.terms;
        let mut it = terms.drain(..);

        Ok((it
            .next()
            .ok_or_else(|| error::Token::ConversionError("not enough terms in fact".to_string()))
            .and_then(A::try_from)?,))
    }
}

macro_rules! tuple_try_from_impl(
    ($($ty: ident),+) => (
        impl<$($ty: TryFrom<Term, Error = error::Token>),+> TryFrom<Fact> for ($($ty),+) {
            type Error = error::Token;
            fn try_from(fact: Fact) -> Result<Self, Self::Error> {
                let mut terms = fact.predicate.terms;
                let mut it = terms.drain(..);

                Ok((
                        $(
                            it.next().ok_or(error::Token::ConversionError("not enough terms in fact".to_string())).and_then($ty::try_from)?
                         ),+
                   ))

            }
        }
        );
    );

tuple_try_from!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U);

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for PublicKey {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::PublicKey(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_rule_parameters() {
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        rule.set("p4", 0i64).unwrap();
        rule.set("p4", 1i64).unwrap();

        let s = rule.to_string();
        assert_eq!(s, "fact($var1, \"hello\") <- f1($var1, $var3), f2(\"hello\", $var3, 1), $var3.starts_with(\"hello\")");
    }

    #[test]
    fn set_rule_scope_parameters() {
        let pubkey = PublicKey::from_bytes(
            &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                .unwrap(),
        )
        .unwrap();
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2}) trusting {pk}",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        rule.set("p4", 0i64).unwrap();
        rule.set("p4", 1i64).unwrap();
        rule.set_scope("pk", pubkey).unwrap();

        let s = rule.to_string();
        assert_eq!(s, "fact($var1, \"hello\") <- f1($var1, $var3), f2(\"hello\", $var3, 1), $var3.starts_with(\"hello\") trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db");
    }

    #[test]
    fn set_code_parameters() {
        let mut builder = BlockBuilder::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p3".to_string(), true.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        builder
            .add_code_with_params(
                r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0;
             check if {p3};
            "#,
                params,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(
            format!("{}", &builder),
            r#"fact("hello", "value");
rule($head_var) <- f1($head_var), 1 > 0;
check if true;
"#
        );
    }

    #[test]
    fn forbid_unbound_parameters() {
        let mut builder = BlockBuilder::new();

        let mut fact = Fact::try_from("fact({p1}, {p4})").unwrap();
        fact.set("p1", "hello").unwrap();
        let res = builder.add_fact(fact);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            }))
        );
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        let res = builder.add_rule(rule);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            }))
        );
        let mut check = Check::try_from("check if {p4}, {p3}").unwrap();
        check.set("p3", true).unwrap();
        let res = builder.add_check(check);
        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            }))
        );
    }

    #[test]
    fn forbid_unbound_parameters_in_set_code() {
        let mut builder = BlockBuilder::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        let res = builder.add_code_with_params(
            r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0;
             check if {p3};
            "#,
            params,
            HashMap::new(),
        );

        assert_eq!(
            res,
            Err(error::Token::Language(error::LanguageError::Parameters {
                missing_parameters: vec!["p3".to_string()],
                unused_parameters: vec![],
            }))
        )
    }
}
