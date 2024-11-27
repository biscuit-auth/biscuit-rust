//! helper functions and structure to create tokens and blocks
use super::Block;
use crate::crypto::PublicKey;
use crate::datalog::{self, SymbolTable};
use crate::error;
use crate::token::builder_ext::BuilderExt;
use nom::Finish;
use std::str::FromStr;
use std::{
    collections::{BTreeSet, HashMap},
    convert::{TryFrom, TryInto},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// reexport those because the builder uses the same definitions
pub use crate::datalog::{
    Binary as DatalogBinary, Expression as DatalogExpression, Op as DatalogOp,
    Unary as DatalogUnary,
};

mod biscuit;
mod block;
mod term;

pub use biscuit::*;
pub use block::*;
pub use term::*;

pub trait Convert<T>: Sized {
    fn convert(&self, symbols: &mut SymbolTable) -> T;
    fn convert_from(f: &T, symbols: &SymbolTable) -> Result<Self, error::Format>;
    fn translate(
        f: &T,
        from_symbols: &SymbolTable,
        to_symbols: &mut SymbolTable,
    ) -> Result<T, error::Format> {
        Ok(Self::convert_from(f, from_symbols)?.convert(to_symbols))
    }
}

/// Builder for a unary operation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unary {
    Negate,
    Parens,
    Length,
    TypeOf,
    Ffi(String),
}

/// Builder for a binary operation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binary {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    Contains,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    NotEqual,
    HeterogeneousEqual,
    HeterogeneousNotEqual,
    LazyAnd,
    LazyOr,
    All,
    Any,
    Get,
    Ffi(String),
}

/// Builder for a block or rule scope
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    /// Trusts the first block, current block and the authorizer
    Authority,
    /// Trusts the current block and all previous ones
    Previous,
    /// Trusts the current block and any block signed by the public key
    PublicKey(PublicKey),
    /// Used for parameter substitution
    Parameter(String),
}

impl Convert<super::Scope> for Scope {
    fn convert(&self, symbols: &mut SymbolTable) -> super::Scope {
        match self {
            Scope::Authority => crate::token::Scope::Authority,
            Scope::Previous => crate::token::Scope::Previous,
            Scope::PublicKey(key) => {
                crate::token::Scope::PublicKey(symbols.public_keys.insert(key))
            }
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Scope::Parameter(s) => panic!("Remaining parameter {}", &s),
        }
    }

    fn convert_from(scope: &super::Scope, symbols: &SymbolTable) -> Result<Self, error::Format> {
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

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Authority => write!(f, "authority"),
            Scope::Previous => write!(f, "previous"),
            Scope::PublicKey(pk) => pk.write(f),
            Scope::Parameter(s) => {
                write!(f, "{{{}}}", s)
            }
        }
    }
}

impl From<biscuit_parser::builder::Scope> for Scope {
    fn from(scope: biscuit_parser::builder::Scope) -> Self {
        match scope {
            biscuit_parser::builder::Scope::Authority => Scope::Authority,
            biscuit_parser::builder::Scope::Previous => Scope::Previous,
            biscuit_parser::builder::Scope::PublicKey(pk) => Scope::PublicKey(
                PublicKey::from_bytes(&pk.key, pk.algorithm.into()).expect("invalid public key"),
            ),
            biscuit_parser::builder::Scope::Parameter(s) => Scope::Parameter(s),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub enum Algorithm {
    Ed25519,
    Secp256r1,
}

impl TryFrom<&str> for Algorithm {
    type Error = error::Format;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ed25519" => Ok(Algorithm::Ed25519),
            "secp256r1" => Ok(Algorithm::Secp256r1),
            _ => Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                value
            ))),
        }
    }
}

impl From<biscuit_parser::builder::Algorithm> for Algorithm {
    fn from(value: biscuit_parser::builder::Algorithm) -> Algorithm {
        match value {
            biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
            biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for biscuit_parser::builder::Algorithm {
    fn from(value: Algorithm) -> biscuit_parser::builder::Algorithm {
        match value {
            Algorithm::Ed25519 => biscuit_parser::builder::Algorithm::Ed25519,
            Algorithm::Secp256r1 => biscuit_parser::builder::Algorithm::Secp256r1,
        }
    }
}

impl From<crate::format::schema::public_key::Algorithm> for Algorithm {
    fn from(value: crate::format::schema::public_key::Algorithm) -> Algorithm {
        match value {
            crate::format::schema::public_key::Algorithm::Ed25519 => Algorithm::Ed25519,
            crate::format::schema::public_key::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for crate::format::schema::public_key::Algorithm {
    fn from(value: Algorithm) -> crate::format::schema::public_key::Algorithm {
        match value {
            Algorithm::Ed25519 => crate::format::schema::public_key::Algorithm::Ed25519,
            Algorithm::Secp256r1 => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

/// Builder for a Datalog predicate, used in facts and rules
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: String,
    pub terms: Vec<Term>,
}

impl Predicate {
    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Predicate {
        Predicate {
            name,
            terms: terms.into(),
        }
    }
}

impl Convert<datalog::Predicate> for Predicate {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Predicate {
        let name = symbols.insert(&self.name);
        let mut terms = vec![];

        for term in self.terms.iter() {
            terms.push(term.convert(symbols));
        }

        datalog::Predicate { name, terms }
    }

    fn convert_from(p: &datalog::Predicate, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Predicate {
            name: symbols.print_symbol(p.name)?,
            terms: p
                .terms
                .iter()
                .map(|term| Term::convert_from(term, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
        })
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

impl From<biscuit_parser::builder::Predicate> for Predicate {
    fn from(p: biscuit_parser::builder::Predicate) -> Self {
        Predicate {
            name: p.name,
            terms: p.terms.into_iter().map(|t| t.into()).collect(),
        }
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
            term.extract_parameters(&mut parameters);
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
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters: invalid_parameters,
                            unused_parameters: vec![],
                        },
                    ))
                }
            }
        }
    }

    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(
                    biscuit_parser::error::LanguageError::Parameters {
                        missing_parameters: vec![],
                        unused_parameters: vec![name.to_string()],
                    },
                )),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
                .map(|t| t.apply_parameters(&parameters))
                .collect();
        }
    }
}

impl Convert<datalog::Fact> for Fact {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        let mut fact = self.clone();
        fact.apply_parameters();

        datalog::Fact {
            predicate: fact.predicate.convert(symbols),
        }
    }

    fn convert_from(f: &datalog::Fact, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Fact {
            predicate: Predicate::convert_from(&f.predicate, symbols)?,
            parameters: None,
        })
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fact = self.clone();
        fact.apply_parameters();

        fact.predicate.fmt(f)
    }
}

impl From<biscuit_parser::builder::Fact> for Fact {
    fn from(f: biscuit_parser::builder::Fact) -> Self {
        Fact {
            predicate: f.predicate.into(),
            //    pub parameters: Option<HashMap<String, Option<Term>>>,
            parameters: f.parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| (k, v.map(|term| term.into())))
                    .collect()
            }),
        }
    }
}

/// Builder for a Datalog expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expression {
    pub ops: Vec<Op>,
}
// todo track parameters

impl Convert<datalog::Expression> for Expression {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Expression {
        datalog::Expression {
            ops: self.ops.iter().map(|op| op.convert(symbols)).collect(),
        }
    }

    fn convert_from(e: &datalog::Expression, symbols: &SymbolTable) -> Result<Self, error::Format> {
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

impl From<biscuit_parser::builder::Expression> for Expression {
    fn from(e: biscuit_parser::builder::Expression) -> Self {
        Expression {
            ops: e.ops.into_iter().map(|op| op.into()).collect(),
        }
    }
}

/// Builder for an expression operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Value(Term),
    Unary(Unary),
    Binary(Binary),
    Closure(Vec<String>, Vec<Op>),
}

impl Op {
    fn collect_parameters(&self, parameters: &mut HashMap<String, Option<Term>>) {
        match self {
            Op::Value(Term::Parameter(ref name)) => {
                parameters.insert(name.to_owned(), None);
            }
            Op::Closure(_, ops) => {
                for op in ops {
                    op.collect_parameters(parameters);
                }
            }
            _ => {}
        }
    }

    fn apply_parameters(self, parameters: &HashMap<String, Option<Term>>) -> Self {
        match self {
            Op::Value(Term::Parameter(ref name)) => {
                if let Some(Some(t)) = parameters.get(name) {
                    Op::Value(t.clone())
                } else {
                    self
                }
            }
            Op::Value(_) => self,
            Op::Unary(_) => self,
            Op::Binary(_) => self,
            Op::Closure(args, mut ops) => Op::Closure(
                args,
                ops.drain(..)
                    .map(|op| op.apply_parameters(parameters))
                    .collect(),
            ),
        }
    }
}

impl Convert<datalog::Op> for Op {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Op {
        match self {
            Op::Value(t) => datalog::Op::Value(t.convert(symbols)),
            Op::Unary(u) => datalog::Op::Unary(u.convert(symbols)),
            Op::Binary(b) => datalog::Op::Binary(b.convert(symbols)),
            Op::Closure(ps, os) => datalog::Op::Closure(
                ps.iter().map(|p| symbols.insert(p) as u32).collect(),
                os.iter().map(|o| o.convert(symbols)).collect(),
            ),
        }
    }

    fn convert_from(op: &datalog::Op, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(match op {
            datalog::Op::Value(t) => Op::Value(Term::convert_from(t, symbols)?),
            datalog::Op::Unary(u) => Op::Unary(Unary::convert_from(u, symbols)?),
            datalog::Op::Binary(b) => Op::Binary(Binary::convert_from(b, symbols)?),
            datalog::Op::Closure(ps, os) => Op::Closure(
                ps.iter()
                    .map(|p| symbols.print_symbol(*p as u64))
                    .collect::<Result<_, _>>()?,
                os.iter()
                    .map(|o| Op::convert_from(o, symbols))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

impl From<biscuit_parser::builder::Op> for Op {
    fn from(op: biscuit_parser::builder::Op) -> Self {
        match op {
            biscuit_parser::builder::Op::Value(t) => Op::Value(t.into()),
            biscuit_parser::builder::Op::Unary(u) => Op::Unary(u.into()),
            biscuit_parser::builder::Op::Binary(b) => Op::Binary(b.into()),
            biscuit_parser::builder::Op::Closure(ps, os) => {
                Op::Closure(ps, os.into_iter().map(|o| o.into()).collect())
            }
        }
    }
}

impl Convert<datalog::Unary> for Unary {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Unary {
        match self {
            Unary::Negate => datalog::Unary::Negate,
            Unary::Parens => datalog::Unary::Parens,
            Unary::Length => datalog::Unary::Length,
            Unary::TypeOf => datalog::Unary::TypeOf,
            Unary::Ffi(n) => datalog::Unary::Ffi(symbols.insert(n)),
        }
    }

    fn convert_from(f: &datalog::Unary, symbols: &SymbolTable) -> Result<Self, error::Format> {
        match f {
            datalog::Unary::Negate => Ok(Unary::Negate),
            datalog::Unary::Parens => Ok(Unary::Parens),
            datalog::Unary::Length => Ok(Unary::Length),
            datalog::Unary::TypeOf => Ok(Unary::TypeOf),
            datalog::Unary::Ffi(i) => Ok(Unary::Ffi(symbols.print_symbol(*i)?)),
        }
    }
}

impl From<biscuit_parser::builder::Unary> for Unary {
    fn from(unary: biscuit_parser::builder::Unary) -> Self {
        match unary {
            biscuit_parser::builder::Unary::Negate => Unary::Negate,
            biscuit_parser::builder::Unary::Parens => Unary::Parens,
            biscuit_parser::builder::Unary::Length => Unary::Length,
            biscuit_parser::builder::Unary::TypeOf => Unary::TypeOf,
            biscuit_parser::builder::Unary::Ffi(name) => Unary::Ffi(name),
        }
    }
}

impl Convert<datalog::Binary> for Binary {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Binary {
        match self {
            Binary::LessThan => datalog::Binary::LessThan,
            Binary::GreaterThan => datalog::Binary::GreaterThan,
            Binary::LessOrEqual => datalog::Binary::LessOrEqual,
            Binary::GreaterOrEqual => datalog::Binary::GreaterOrEqual,
            Binary::Equal => datalog::Binary::Equal,
            Binary::Contains => datalog::Binary::Contains,
            Binary::Prefix => datalog::Binary::Prefix,
            Binary::Suffix => datalog::Binary::Suffix,
            Binary::Regex => datalog::Binary::Regex,
            Binary::Add => datalog::Binary::Add,
            Binary::Sub => datalog::Binary::Sub,
            Binary::Mul => datalog::Binary::Mul,
            Binary::Div => datalog::Binary::Div,
            Binary::And => datalog::Binary::And,
            Binary::Or => datalog::Binary::Or,
            Binary::Intersection => datalog::Binary::Intersection,
            Binary::Union => datalog::Binary::Union,
            Binary::BitwiseAnd => datalog::Binary::BitwiseAnd,
            Binary::BitwiseOr => datalog::Binary::BitwiseOr,
            Binary::BitwiseXor => datalog::Binary::BitwiseXor,
            Binary::NotEqual => datalog::Binary::NotEqual,
            Binary::HeterogeneousEqual => datalog::Binary::HeterogeneousEqual,
            Binary::HeterogeneousNotEqual => datalog::Binary::HeterogeneousNotEqual,
            Binary::LazyAnd => datalog::Binary::LazyAnd,
            Binary::LazyOr => datalog::Binary::LazyOr,
            Binary::All => datalog::Binary::All,
            Binary::Any => datalog::Binary::Any,
            Binary::Get => datalog::Binary::Get,
            Binary::Ffi(n) => datalog::Binary::Ffi(symbols.insert(n)),
        }
    }

    fn convert_from(f: &datalog::Binary, symbols: &SymbolTable) -> Result<Self, error::Format> {
        match f {
            datalog::Binary::LessThan => Ok(Binary::LessThan),
            datalog::Binary::GreaterThan => Ok(Binary::GreaterThan),
            datalog::Binary::LessOrEqual => Ok(Binary::LessOrEqual),
            datalog::Binary::GreaterOrEqual => Ok(Binary::GreaterOrEqual),
            datalog::Binary::Equal => Ok(Binary::Equal),
            datalog::Binary::Contains => Ok(Binary::Contains),
            datalog::Binary::Prefix => Ok(Binary::Prefix),
            datalog::Binary::Suffix => Ok(Binary::Suffix),
            datalog::Binary::Regex => Ok(Binary::Regex),
            datalog::Binary::Add => Ok(Binary::Add),
            datalog::Binary::Sub => Ok(Binary::Sub),
            datalog::Binary::Mul => Ok(Binary::Mul),
            datalog::Binary::Div => Ok(Binary::Div),
            datalog::Binary::And => Ok(Binary::And),
            datalog::Binary::Or => Ok(Binary::Or),
            datalog::Binary::Intersection => Ok(Binary::Intersection),
            datalog::Binary::Union => Ok(Binary::Union),
            datalog::Binary::BitwiseAnd => Ok(Binary::BitwiseAnd),
            datalog::Binary::BitwiseOr => Ok(Binary::BitwiseOr),
            datalog::Binary::BitwiseXor => Ok(Binary::BitwiseXor),
            datalog::Binary::NotEqual => Ok(Binary::NotEqual),
            datalog::Binary::HeterogeneousEqual => Ok(Binary::HeterogeneousEqual),
            datalog::Binary::HeterogeneousNotEqual => Ok(Binary::HeterogeneousNotEqual),
            datalog::Binary::LazyAnd => Ok(Binary::LazyAnd),
            datalog::Binary::LazyOr => Ok(Binary::LazyOr),
            datalog::Binary::All => Ok(Binary::All),
            datalog::Binary::Any => Ok(Binary::Any),
            datalog::Binary::Get => Ok(Binary::Get),
            datalog::Binary::Ffi(i) => Ok(Binary::Ffi(symbols.print_symbol(*i)?)),
        }
    }
}

impl From<biscuit_parser::builder::Binary> for Binary {
    fn from(binary: biscuit_parser::builder::Binary) -> Self {
        match binary {
            biscuit_parser::builder::Binary::LessThan => Binary::LessThan,
            biscuit_parser::builder::Binary::GreaterThan => Binary::GreaterThan,
            biscuit_parser::builder::Binary::LessOrEqual => Binary::LessOrEqual,
            biscuit_parser::builder::Binary::GreaterOrEqual => Binary::GreaterOrEqual,
            biscuit_parser::builder::Binary::Equal => Binary::Equal,
            biscuit_parser::builder::Binary::Contains => Binary::Contains,
            biscuit_parser::builder::Binary::Prefix => Binary::Prefix,
            biscuit_parser::builder::Binary::Suffix => Binary::Suffix,
            biscuit_parser::builder::Binary::Regex => Binary::Regex,
            biscuit_parser::builder::Binary::Add => Binary::Add,
            biscuit_parser::builder::Binary::Sub => Binary::Sub,
            biscuit_parser::builder::Binary::Mul => Binary::Mul,
            biscuit_parser::builder::Binary::Div => Binary::Div,
            biscuit_parser::builder::Binary::And => Binary::And,
            biscuit_parser::builder::Binary::Or => Binary::Or,
            biscuit_parser::builder::Binary::Intersection => Binary::Intersection,
            biscuit_parser::builder::Binary::Union => Binary::Union,
            biscuit_parser::builder::Binary::BitwiseAnd => Binary::BitwiseAnd,
            biscuit_parser::builder::Binary::BitwiseOr => Binary::BitwiseOr,
            biscuit_parser::builder::Binary::BitwiseXor => Binary::BitwiseXor,
            biscuit_parser::builder::Binary::NotEqual => Binary::NotEqual,
            biscuit_parser::builder::Binary::HeterogeneousEqual => Binary::HeterogeneousEqual,
            biscuit_parser::builder::Binary::HeterogeneousNotEqual => Binary::HeterogeneousNotEqual,
            biscuit_parser::builder::Binary::LazyAnd => Binary::LazyAnd,
            biscuit_parser::builder::Binary::LazyOr => Binary::LazyOr,
            biscuit_parser::builder::Binary::All => Binary::All,
            biscuit_parser::builder::Binary::Any => Binary::Any,
            biscuit_parser::builder::Binary::Get => Binary::Get,
            biscuit_parser::builder::Binary::Ffi(name) => Binary::Ffi(name),
        }
    }
}

/// Builder for a Datalog rule
#[derive(Debug, Clone, PartialEq, Eq)]
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
            term.extract_parameters(&mut parameters);
        }

        for predicate in &body {
            for term in &predicate.terms {
                term.extract_parameters(&mut parameters);
            }
        }

        for expression in &expressions {
            for op in &expression.ops {
                op.collect_parameters(&mut parameters);
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: all_invalid_parameters,
                    unused_parameters: vec![],
                },
            ))
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
                None => Err(error::Token::Language(
                    biscuit_parser::error::LanguageError::Parameters {
                        missing_parameters: vec![],
                        unused_parameters: vec![name.to_string()],
                    },
                )),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
        }
    }

    /// replace a scope parameter with the pubkey argument
    pub fn set_scope(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        if let Some(parameters) = self.scope_parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(
                    biscuit_parser::error::LanguageError::Parameters {
                        missing_parameters: vec![],
                        unused_parameters: vec![name.to_string()],
                    },
                )),
                Some(v) => {
                    *v = Some(pubkey);
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
                    .map(|op| op.apply_parameters(&parameters))
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
                            return Scope::PublicKey(*pubkey);
                        }
                    }
                    scope
                })
                .collect();
        }
    }
}

impl Convert<datalog::Rule> for Rule {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
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
                    crate::token::Scope::PublicKey(symbols.public_keys.insert(key))
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

    fn convert_from(r: &datalog::Rule, symbols: &SymbolTable) -> Result<Self, error::Format> {
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

impl From<biscuit_parser::builder::Rule> for Rule {
    fn from(r: biscuit_parser::builder::Rule) -> Self {
        Rule {
            head: r.head.into(),
            body: r.body.into_iter().map(|p| p.into()).collect(),
            expressions: r.expressions.into_iter().map(|e| e.into()).collect(),
            parameters: r.parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| (k, v.map(|term| term.into())))
                    .collect()
            }),
            scopes: r.scopes.into_iter().map(|s| s.into()).collect(),
            scope_parameters: r.scope_parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.map(|pk| {
                                PublicKey::from_bytes(&pk.key, pk.algorithm.into())
                                    .expect("invalid public key")
                            }),
                        )
                    })
                    .collect()
            }),
        }
    }
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub queries: Vec<Rule>,
    pub kind: CheckKind,
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    One,
    All,
    Reject,
}

impl Check {
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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

impl Convert<datalog::Check> for Check {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Check {
        let mut queries = vec![];
        for q in self.queries.iter() {
            queries.push(q.convert(symbols));
        }

        datalog::Check {
            queries,
            kind: self.kind.clone(),
        }
    }

    fn convert_from(r: &datalog::Check, symbols: &SymbolTable) -> Result<Self, error::Format> {
        let mut queries = vec![];
        for q in r.queries.iter() {
            queries.push(Rule::convert_from(q, symbols)?);
        }

        Ok(Check {
            queries,
            kind: r.kind.clone(),
        })
    }
}

impl TryFrom<Rule> for Check {
    type Error = error::Token;

    fn try_from(value: Rule) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: vec![value],
            kind: CheckKind::One,
        })
    }
}

impl TryFrom<&[Rule]> for Check {
    type Error = error::Token;

    fn try_from(values: &[Rule]) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: values.to_vec(),
            kind: CheckKind::One,
        })
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            CheckKind::One => write!(f, "check if ")?,
            CheckKind::All => write!(f, "check all ")?,
            CheckKind::Reject => write!(f, "reject if ")?,
        };

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

impl From<biscuit_parser::builder::Check> for Check {
    fn from(c: biscuit_parser::builder::Check) -> Self {
        Check {
            queries: c.queries.into_iter().map(|q| q.into()).collect(),
            kind: match c.kind {
                biscuit_parser::builder::CheckKind::One => CheckKind::One,
                biscuit_parser::builder::CheckKind::All => CheckKind::All,
                biscuit_parser::builder::CheckKind::Reject => CheckKind::Reject,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyKind {
    Allow,
    Deny,
}

/// Builder for a Biscuit policy
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
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

impl From<biscuit_parser::builder::Policy> for Policy {
    fn from(p: biscuit_parser::builder::Policy) -> Self {
        Policy {
            queries: p.queries.into_iter().map(|q| q.into()).collect(),
            kind: match p.kind {
                biscuit_parser::builder::PolicyKind::Allow => PolicyKind::Allow,
                biscuit_parser::builder::PolicyKind::Deny => PolicyKind::Deny,
            },
        }
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
pub fn check<P: AsRef<Predicate>>(predicates: &[P], kind: CheckKind) -> Check {
    let empty_terms: &[Term] = &[];
    Check {
        queries: vec![Rule::new(
            pred("query", empty_terms),
            predicates.iter().map(|p| p.as_ref().clone()).collect(),
            vec![],
            vec![],
        )],
        kind,
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

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for Term {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.clone())
    }
}

impl From<i64> for Term {
    fn from(i: i64) -> Self {
        Term::Integer(i)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for i64 {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self).into())
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
        AnyParam::Term((*self).into())
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
impl ToAnyParam for [u8] {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.into())
    }
}

#[cfg(feature = "uuid")]
impl ToAnyParam for uuid::Uuid {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(Term::Bytes(self.as_bytes().to_vec()))
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
        AnyParam::Term((*self).into())
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

impl From<BTreeSet<Term>> for Term {
    fn from(value: BTreeSet<Term>) -> Term {
        set(value)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for BTreeSet<Term> {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
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

// TODO: From and ToAnyParam for arrays and maps
impl TryFrom<serde_json::Value> for Term {
    type Error = &'static str;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(Term::Null),
            serde_json::Value::Bool(b) => Ok(Term::Bool(b)),
            serde_json::Value::Number(i) => match i.as_i64() {
                Some(i) => Ok(Term::Integer(i)),
                None => Err("Biscuit values do not support floating point numbers"),
            },
            serde_json::Value::String(s) => Ok(Term::Str(s)),
            serde_json::Value::Array(array) => Ok(Term::Array(
                array
                    .into_iter()
                    .map(|v| v.try_into())
                    .collect::<Result<_, _>>()?,
            )),
            serde_json::Value::Object(o) => Ok(Term::Map(
                o.into_iter()
                    .map(|(key, value)| {
                        let value: Term = value.try_into()?;
                        Ok::<_, &'static str>((MapKey::Str(key), value))
                    })
                    .collect::<Result<_, _>>()?,
            )),
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
        AnyParam::PublicKey(*self)
    }
}

impl TryFrom<&str> for Fact {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::fact(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl TryFrom<&str> for Rule {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::rule(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Fact {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::fact(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Rule {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::rule(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl TryFrom<&str> for Check {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::check(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Check {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::check(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl TryFrom<&str> for Policy {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::policy(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Policy {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::policy(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl BuilderExt for BlockBuilder {
    fn add_resource(&mut self, name: &str) {
        self.facts.push(fact("resource", &[string(name)]));
    }
    fn check_resource(&mut self, name: &str) {
        self.checks.push(Check {
            queries: vec![rule(
                "resource_check",
                &[string("resource_check")],
                &[pred("resource", &[string(name)])],
            )],
            kind: CheckKind::One,
        });
    }
    fn add_operation(&mut self, name: &str) {
        self.facts.push(fact("operation", &[string(name)]));
    }
    fn check_operation(&mut self, name: &str) {
        self.checks.push(Check {
            queries: vec![rule(
                "operation_check",
                &[string("operation_check")],
                &[pred("operation", &[string(name)])],
            )],
            kind: CheckKind::One,
        });
    }
    fn check_resource_prefix(&mut self, prefix: &str) {
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

        self.checks.push(Check {
            queries: vec![check],
            kind: CheckKind::One,
        });
    }

    fn check_resource_suffix(&mut self, suffix: &str) {
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

        self.checks.push(Check {
            queries: vec![check],
            kind: CheckKind::One,
        });
    }

    fn check_expiration_date(&mut self, exp: SystemTime) {
        let empty: Vec<Term> = Vec::new();
        let check = constrained_rule(
            "query",
            &empty,
            &[pred("time", &[var("time")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("time")),
                    Op::Value(date(&exp)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            }],
        );

        self.checks.push(Check {
            queries: vec![check],
            kind: CheckKind::One,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_rule_parameters() {
        let mut rule = Rule::try_from(
            "fact($var1, {p2}, {p5}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        rule.set("p4", 0i64).unwrap();
        rule.set("p4", 1i64).unwrap();

        let mut term_set = BTreeSet::new();
        term_set.insert(int(0i64));
        rule.set("p5", term_set).unwrap();

        let s = rule.to_string();
        assert_eq!(s, "fact($var1, \"hello\", {0}) <- f1($var1, $var3), f2(\"hello\", $var3, 1), $var3.starts_with(\"hello\")");
    }

    #[test]
    fn set_closure_parameters() {
        let mut rule = Rule::try_from("fact(true) <- false || {p1}").unwrap();
        rule.set_lenient("p1", true).unwrap();
        println!("{rule:?}");
        let s = rule.to_string();
        assert_eq!(s, "fact(true) <- false || true");

        let mut rule = Rule::try_from("fact(true) <- false || {p1}").unwrap();
        rule.set("p1", true).unwrap();
        let s = rule.to_string();
        assert_eq!(s, "fact(true) <- false || true");
    }

    #[test]
    fn set_rule_scope_parameters() {
        let pubkey = PublicKey::from_bytes(
            &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                .unwrap(),
            Algorithm::Ed25519,
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
        let pubkey = PublicKey::from_bytes(
            &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                .unwrap(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut scope_params = HashMap::new();
        scope_params.insert("pk".to_string(), pubkey);
        builder
            .add_code_with_params(
                r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0 trusting {pk};
             check if {p3} trusting {pk};
            "#,
                params,
                scope_params,
            )
            .unwrap();
        assert_eq!(
            format!("{}", &builder),
            r#"fact("hello", "value");
rule($head_var) <- f1($head_var), 1 > 0 trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        let res = builder.add_rule(rule);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
        );
        let mut check = Check::try_from("check if {p4}, {p3}").unwrap();
        check.set("p3", true).unwrap();
        let res = builder.add_check(check);
        assert_eq!(
            res,
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p4".to_string()],
                    unused_parameters: vec![],
                }
            ))
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
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec!["p3".to_string()],
                    unused_parameters: vec![],
                }
            ))
        )
    }
}
