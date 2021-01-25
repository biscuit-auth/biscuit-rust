//! helper functions and structure to create tokens and blocks
use super::{Biscuit, Block};
use crate::crypto::KeyPair;
use crate::datalog::{
    self, SymbolTable, ID,
};
use crate::error;
use rand_core::{CryptoRng, RngCore};
use std::{fmt, convert::{TryInto, TryFrom}, time::{SystemTime, Duration, UNIX_EPOCH},
  collections::BTreeSet};

// reexport those because the builder uses the same definitions
pub use crate::datalog::{Unary, Binary};

#[derive(Clone, Debug)]
pub struct BlockBuilder {
    pub index: u32,
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub context: Option<String>,
}

impl BlockBuilder {
    pub fn new(index: u32) -> BlockBuilder {
        BlockBuilder {
            index,
            facts: vec![],
            rules: vec![],
            checks: vec![],
            context: None,
        }
    }

    pub fn add_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token> {
        let fact = fact.try_into().map_err(|_| error::Token::ParseError)?;
        self.facts.push(fact);
        Ok(())
    }

    pub fn add_rule<R: TryInto<Rule>>(&mut self, rule: R) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;
        self.rules.push(rule);
        Ok(())
    }

    pub fn add_check<C: TryInto<Check>>(&mut self, check: C) -> Result<(), error::Token> {
        let check = check.try_into().map_err(|_| error::Token::ParseError)?;
        self.checks.push(check);
        Ok(())
    }

    pub fn set_context(&mut self, context: String) {
        self.context = Some(context);
    }

    pub fn build(self, mut symbols: SymbolTable) -> Block {
        let symbols_start = symbols.symbols.len();

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
        let new_syms = SymbolTable {
            symbols: symbols.symbols.split_off(symbols_start),
        };

        Block {
            index: self.index,
            symbols: new_syms,
            facts,
            rules,
            checks,
            context: self.context,
            version: super::MAX_SCHEMA_VERSION,
        }
    }

    pub fn check_right(&mut self, right: &str) {
        let check = rule(
            "check_right",
            &[s(right)],
            &[
                pred("resource", &[s("ambient"), var("resource_name")]),
                pred("operation", &[s("ambient"), s(right)]),
                pred("right", &[s("authority"), var("resource_name"), s(right)]),
            ],
        );

        let _ = self.add_check(check);
    }

    pub fn check_resource(&mut self, resource: &str) {
        let check = rule(
            "resource_check",
            &[s("resource_check")],
            &[pred("resource", &[s("ambient"), string(resource)])],
        );

        let _ = self.add_check(check);
    }

    pub fn check_operation(&mut self, operation: &str) {
        let check = rule(
            "operation_check",
            &[s("operation_check")],
            &[pred("operation", &[s("ambient"), s(operation)])],
        );

        let _ = self.add_check(check);
    }

    pub fn resource_prefix(&mut self, prefix: &str) {
        let check = constrained_rule(
            "prefix",
            &[var("resource")],
            &[pred("resource", &[s("ambient"), var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(prefix)),
                    Op::Binary(Binary::Prefix),
                ]
            }],
        );

        let _ = self.add_check(check);
    }

    pub fn resource_suffix(&mut self, suffix: &str) {
        let check = constrained_rule(
            "suffix",
            &[var("resource")],
            &[pred("resource", &[s("ambient"), var("resource")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("resource")),
                    Op::Value(string(suffix)),
                    Op::Binary(Binary::Suffix),
                ]
            }],
        );

        let _ = self.add_check(check);
    }

    pub fn expiration_date(&mut self, exp: SystemTime) {
        let check = constrained_rule(
            "expiration",
            &[var("date")],
            &[pred("time", &[s("ambient"), var("date")])],
            &[Expression {
                ops: vec![
                    Op::Value(var("date")),
                    Op::Value(date(&exp)),
                    Op::Binary(Binary::LessOrEqual),
                ]
            }],
        );

        let _ = self.add_check(check);
    }

    pub fn revocation_id(&mut self, id: i64) {
        let _ = self.add_fact(fact("revocation_id", &[int(id)]));
    }
}

#[derive(Clone)]
pub struct BiscuitBuilder<'a> {
    root: &'a KeyPair,
    pub symbols_start: usize,
    pub symbols: SymbolTable,
    pub facts: Vec<datalog::Fact>,
    pub rules: Vec<datalog::Rule>,
    pub checks: Vec<datalog::Check>,
    pub context: Option<String>,
}

impl<'a> BiscuitBuilder<'a> {
    pub fn new(
        root: &'a KeyPair,
        base_symbols: SymbolTable,
    ) -> BiscuitBuilder<'a> {
        BiscuitBuilder {
            root,
            symbols_start: base_symbols.symbols.len(),
            symbols: base_symbols,
            facts: vec![],
            rules: vec![],
            checks: vec![],
            context: None,
        }
    }

    pub fn add_authority_fact<F: TryInto<Fact>>(&mut self, fact: F) -> Result<(), error::Token> {
        let fact = fact.try_into().map_err(|_| error::Token::ParseError)?;

        let f = fact.convert(&mut self.symbols);
        self.facts.push(f);
        Ok(())
    }

    pub fn add_authority_rule<Ru: TryInto<Rule>>(&mut self, rule: Ru) -> Result<(), error::Token> {
        let rule = rule.try_into().map_err(|_| error::Token::ParseError)?;

        let r = rule.convert(&mut self.symbols);
        self.rules.push(r);
        Ok(())
    }

    pub fn add_authority_check<Ru: TryInto<Rule>>(&mut self, rule: Ru) -> Result<(), error::Token> {
        let check = rule.try_into().map_err(|_| error::Token::ParseError)?;
        let r = check.convert(&mut self.symbols);
        self.checks.push(datalog::Check { queries: vec![r]});
        Ok(())
    }

    pub fn add_right(&mut self, resource: &str, right: &str) {
        let _ = self.add_authority_fact(fact(
            "right",
            &[s("authority"), string(resource), s(right)],
        ));
    }

    pub fn set_context(&mut self, context: String) {
        self.context = Some(context);
    }

    pub fn build(self) -> Result<Biscuit, error::Token> {
        self.build_with_rng(&mut rand::rngs::OsRng)
    }

    pub fn build_with_rng<R: RngCore + CryptoRng>(mut self, rng: &'a mut R) -> Result<Biscuit, error::Token> {
        let new_syms = SymbolTable { symbols: self.symbols.symbols.split_off(self.symbols_start) };

        let authority_block = Block {
            index: 0,
            symbols: new_syms,
            facts: self.facts,
            rules: self.rules,
            checks: self.checks,
            context: self.context,
            version: super::MAX_SCHEMA_VERSION,
        };

        Biscuit::new_with_rng(rng, self.root, self.symbols, authority_block)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    Symbol(String),
    Variable(String),
    Integer(i64),
    Str(String),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<Term>),
}

impl Term {
    pub fn convert(&self, symbols: &mut SymbolTable) -> ID {
        match self {
            Term::Symbol(s) => ID::Symbol(symbols.insert(s)),
            Term::Variable(s) => ID::Variable(symbols.insert(s) as u32),
            Term::Integer(i) => ID::Integer(*i),
            Term::Str(s) => ID::Str(s.clone()),
            Term::Date(d) => ID::Date(*d),
            Term::Bytes(s) => ID::Bytes(s.clone()),
            Term::Bool(b) => ID::Bool(*b),
            Term::Set(s) => ID::Set(s.iter().map(|i| i.convert(symbols)).collect()),
        }
    }

    pub fn convert_from(f: &datalog::ID, symbols: &SymbolTable) -> Self {
      match f {
        ID::Symbol(s) => Term::Symbol(symbols.print_symbol(*s)),
        ID::Variable(s) => Term::Variable(symbols.print_symbol(*s as u64)),
        ID::Integer(i) => Term::Integer(*i),
        ID::Str(s) => Term::Str(s.clone()),
        ID::Date(d) => Term::Date(*d),
        ID::Bytes(s) => Term::Bytes(s.clone()),
        ID::Bool(b) => Term::Bool(*b),
        ID::Set(s) => Term::Set(s.iter().map(|i| Term::convert_from(i, symbols)).collect()),
      }
    }
}

impl From<&Term> for Term {
    fn from(i: &Term) -> Self {
        match i {
            Term::Symbol(ref s) => Term::Symbol(s.clone()),
            Term::Variable(ref v) => Term::Variable(v.clone()),
            Term::Integer(ref i) => Term::Integer(*i),
            Term::Str(ref s) => Term::Str(s.clone()),
            Term::Date(ref d) => Term::Date(*d),
            Term::Bytes(ref s) => Term::Bytes(s.clone()),
            Term::Bool(b) => Term::Bool(*b),
            Term::Set(ref s) => Term::Set(s.clone()),
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
            Term::Symbol(s) => write!(f, "#{}", s),
            Term::Date(d) => {
                let t = UNIX_EPOCH + Duration::from_secs(*d);
                write!(f, "{:?}", t)
            }
            Term::Bytes(s) => write!(f, "hex:{}", hex::encode(s)),
            Term::Bool(b) => if *b {
                write!(f, "true")
            } else {
                write!(f, "false")
            },
            Term::Set(s) => {
                let terms =  s.iter().map(|term| term.to_string()).collect::<Vec<_>>();
                write!(f, "[ {}]", terms.join(", "))
            }
        }

    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: String,
    pub ids: Vec<Term>,
}

impl Predicate {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Predicate {
        let name = symbols.insert(&self.name);
        let mut ids = vec![];

        for id in self.ids.iter() {
            ids.push(id.convert(symbols));
        }

        datalog::Predicate { name, ids }
    }

    pub fn convert_from(p: &datalog::Predicate, symbols: &SymbolTable) -> Self {
        Predicate {
          name: symbols.print_symbol(p.name),
          ids: p.ids.iter().map(|id| Term::convert_from(&id, symbols)).collect(),
        }
    }

    pub fn new(name: String, ids: &[Term]) -> Predicate {
        Predicate {
            name,
            ids: ids.to_vec(),
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

        if self.ids.len() > 0 {
            write!(f, "{}", self.ids[0])?;

            if self.ids.len() > 1 {
                for i in 1..self.ids.len() {
                    write!(f, ", {}", self.ids[i])?;
                }
            }
        }
        write!(f, ")")
    }
}


#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Fact(pub Predicate);

impl Fact {
    pub fn new(name: String, ids: &[Term]) -> Fact {
        Fact(Predicate::new(name, ids))
    }
}

impl Fact {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        datalog::Fact {
            predicate: self.0.convert(symbols),
        }
    }

    pub fn convert_from(f: &datalog::Fact, symbols: &SymbolTable) -> Self {
        Fact(Predicate::convert_from(&f.predicate, symbols))
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub ops: Vec<Op>,
}

impl Expression {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Expression {
        datalog::Expression {
            ops: self.ops.iter().map(|op| op.convert(symbols)).collect()
        }
    }

    pub fn convert_from(e: &datalog::Expression, symbols: &SymbolTable) -> Self {
        Expression {
            ops: e.ops.iter().map(|op| Op::convert_from(op, symbols)).collect()
        }
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

    pub fn convert_from(op: &datalog::Op, symbols: &SymbolTable) -> Self {
        match op {
            datalog::Op::Value(t) => Op::Value(Term::convert_from(t, symbols)),
            datalog::Op::Unary(u) => Op::Unary(u.clone()),
            datalog::Op::Binary(b) => Op::Binary(b.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule(
    pub Predicate,
    pub Vec<Predicate>,
    pub Vec<Expression>,
);

impl Rule {
    pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
        let head = self.0.convert(symbols);
        let mut body = vec![];
        let mut expressions = vec![];

        for p in self.1.iter() {
            body.push(p.convert(symbols));
        }

        for c in self.2.iter() {
            expressions.push(c.convert(symbols));
        }

        datalog::Rule {
            head,
            body,
            expressions,
        }
    }

    pub fn convert_from(r: &datalog::Rule, symbols: &SymbolTable) -> Self {
        Rule(
            Predicate::convert_from(&r.head, symbols),
            r.body.iter().map(|p| Predicate::convert_from(p, symbols)).collect(),
            r.expressions.iter().map(|c| Expression::convert_from(c, symbols)).collect(),
        )
    }
}

fn display_rule_body(r: &Rule, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if r.1.len() > 0 {
        write!(f, "{}", r.1[0])?;

        if r.1.len() > 1 {
            for i in 1..r.1.len() {
                write!(f, ", {}", r.1[i])?;
            }
        }
    }

    if r.2.len() > 0 {
        if r.1.len() > 0 {
            write!(f, ", ")?;
        }

        write!(f, "{}", r.2[0])?;

        if r.2.len() > 1 {
            for i in 1..r.2.len() {
                write!(f, ", {}", r.2[i])?;
            }
        }

    }

    Ok(())
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <- ", self.0)?;

        display_rule_body(self, f)
    }
}

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

    pub fn convert_from(r: &datalog::Check, symbols: &SymbolTable) -> Self {
        let mut queries = vec![];
        for q in r.queries.iter() {
            queries.push(Rule::convert_from(q, symbols));
        }

        Check { queries }
    }
}

impl TryFrom<Rule> for Check {
    type Error = error::Token;

    fn try_from(value: Rule) -> Result<Self, Self::Error> {
        Ok(Check { queries: vec![value] })
    }
}

impl TryFrom<&[Rule]> for Check {
    type Error = error::Token;

    fn try_from(values: &[Rule]) -> Result<Self, Self::Error> {
        Ok(Check { queries: values.to_vec() })
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check if ")?;

        if self.queries.len() > 0 {
            display_rule_body(&self.queries[0], f)?;

            if self.queries.len() > 1 {
                for i in 1..self.queries.len() {
                    write!(f, " or ")?;
                    display_rule_body(&self.queries[i], f)?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyKind {
    Allow,
    Deny,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub queries: Vec<Rule>,
    pub kind: PolicyKind,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.queries.len() > 0 {
            match self.kind {
                PolicyKind::Allow => write!(f, "allow if ")?,
                PolicyKind::Deny => write!(f, "deny if ")?,
            }

            if self.queries.len() > 0 {
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

/// creates a new fact
pub fn fact<I: AsRef<Term>>(name: &str, ids: &[I]) -> Fact {
    Fact(pred(name, ids))
}

/// creates a predicate
pub fn pred<I: AsRef<Term>>(name: &str, ids: &[I]) -> Predicate {
    Predicate {
        name: name.to_string(),
        ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
    }
}

/// creates a rule
pub fn rule<I: AsRef<Term>, P: AsRef<Predicate>>(
    head_name: &str,
    head_ids: &[I],
    predicates: &[P],
) -> Rule {
    Rule(
        pred(head_name, head_ids),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        Vec::new(),
    )
}

/// creates a rule with constraints
pub fn constrained_rule<I: AsRef<Term>, P: AsRef<Predicate>, E: AsRef<Expression>>(
    head_name: &str,
    head_ids: &[I],
    predicates: &[P],
    expressions: &[E],
) -> Rule {
    Rule(
        pred(head_name, head_ids),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions.iter().map(|c| c.as_ref().clone()).collect(),
    )
}

/// creates an integer value
pub fn int(i: i64) -> Term {
    Term::Integer(i)
}

/// creates a string
pub fn string(s: &str) -> Term {
    Term::Str(s.to_string())
}

/// creates a symbol
///
/// once the block is generated, this symbol will be added to the symbol table if needed
pub fn s(s: &str) -> Term {
    Term::Symbol(s.to_string())
}

/// creates a symbol
///
/// once the block is generated, this symbol will be added to the symbol table if needed
pub fn symbol(s: &str) -> Term {
    Term::Symbol(s.to_string())
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
