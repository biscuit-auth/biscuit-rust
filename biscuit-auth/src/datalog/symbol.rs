//! Symbol table implementation
use std::collections::HashSet;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub type SymbolIndex = u64;
use super::{Check, Fact, Predicate, Rule, Term, World};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SymbolTable {
    symbols: Vec<String>,
}

const DEFAULT_SYMBOLS: [&str; 28] = [
    "read",
    "write",
    "resource",
    "operation",
    "right",
    "time",
    "role",
    "owner",
    "tenant",
    "namespace",
    "user",
    "team",
    "service",
    "admin",
    "email",
    "group",
    "member",
    "ip_address",
    "client",
    "client_ip",
    "domain",
    "path",
    "version",
    "cluster",
    "node",
    "hostname",
    "nonce",
    "query",
];

const OFFSET: usize = 1024;

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable { symbols: vec![] }
    }

    //FIXME: should check if symbols are already in default
    pub fn from(symbols: Vec<String>) -> Self {
        SymbolTable { symbols }
    }

    pub fn extend(&mut self, other: &SymbolTable) {
        self.symbols.extend(other.symbols.iter().cloned());
    }

    pub fn insert(&mut self, s: &str) -> SymbolIndex {
        if let Some(index) = DEFAULT_SYMBOLS.iter().position(|sym| *sym == s) {
            return index as u64;
        }

        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => (OFFSET + index) as u64,
            None => {
                self.symbols.push(s.to_string());
                (OFFSET + (self.symbols.len() - 1)) as u64
            }
        }
    }

    pub fn add(&mut self, s: &str) -> Term {
        let term = self.insert(s);
        Term::Str(term)
    }

    pub fn get(&self, s: &str) -> Option<SymbolIndex> {
        if let Some(index) = DEFAULT_SYMBOLS.iter().position(|sym| *sym == s) {
            return Some(index as u64);
        }

        self.symbols
            .iter()
            .position(|sym| sym.as_str() == s)
            .map(|i| (OFFSET + i) as SymbolIndex)
    }

    pub fn strings(&self) -> Vec<String> {
        self.symbols.clone()
    }

    pub fn current_offset(&self) -> usize {
        self.symbols.len()
    }

    pub fn split_at(&mut self, offset: usize) -> SymbolTable {
        let mut table = SymbolTable::new();
        table.symbols = self.symbols.split_off(offset);
        table
    }

    pub fn is_disjoint(&self, other: &SymbolTable) -> bool {
        let h1 = self.symbols.iter().collect::<HashSet<_>>();
        let h2 = other.symbols.iter().collect::<HashSet<_>>();

        h1.is_disjoint(&h2)
    }

    pub fn get_symbol(&self, i: SymbolIndex) -> Option<&str> {
        if i >= 1024 {
            self.symbols.get((i - 1024) as usize).map(|s| s.as_str())
        } else {
            DEFAULT_SYMBOLS.get(i as usize).map(|s| *s)
        }
    }

    pub fn print_symbol(&self, i: SymbolIndex) -> String {
        self.get_symbol(i)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("<{}?>", i))
    }

    pub fn print_world(&self, w: &World) -> String {
        let facts = w
            .facts
            .inner
            .iter()
            .map(|facts| facts.1.iter())
            .flatten()
            .map(|f| self.print_fact(f))
            .collect::<Vec<_>>();
        let rules = w
            .rules
            .inner
            .iter()
            .map(|rules| rules.1.iter())
            .flatten()
            .map(|r| self.print_rule(r))
            .collect::<Vec<_>>();
        format!("World {{\n  facts: {:#?}\n  rules: {:#?}\n}}", facts, rules)
    }

    pub fn print_term(&self, term: &Term) -> String {
        match term {
            Term::Variable(i) => format!("${}", self.print_symbol(*i as u64)),
            Term::Integer(i) => i.to_string(),
            Term::Str(index) => format!("\"{}\"", self.print_symbol(*index as u64)),
            Term::Date(d) => OffsetDateTime::from_unix_timestamp(*d as i64)
                .ok()
                .and_then(|t| t.format(&Rfc3339).ok())
                .unwrap_or_else(|| "<invalid date>".to_string()),
            Term::Bytes(s) => format!("hex:{}", hex::encode(s)),
            Term::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            Term::Set(s) => {
                let terms = s
                    .iter()
                    .map(|term| self.print_term(term))
                    .collect::<Vec<_>>();
                format!("[{}]", terms.join(", "))
            }
        }
    }
    pub fn print_fact(&self, f: &Fact) -> String {
        self.print_predicate(&f.predicate)
    }

    pub fn print_predicate(&self, p: &Predicate) -> String {
        let strings = p
            .terms
            .iter()
            .map(|term| self.print_term(term))
            .collect::<Vec<_>>();
        format!(
            "{}({})",
            self.get_symbol(p.name).unwrap_or("<?>"),
            strings.join(", ")
        )
    }

    pub fn print_expression(&self, e: &super::expression::Expression) -> String {
        e.print(self)
            .unwrap_or_else(|| format!("<invalid expression: {:?}>", e.ops))
    }

    pub fn print_rule_body(&self, r: &Rule) -> String {
        let preds: Vec<_> = r.body.iter().map(|p| self.print_predicate(p)).collect();

        let expressions: Vec<_> = r
            .expressions
            .iter()
            .map(|c| self.print_expression(c))
            .collect();

        let e = if expressions.is_empty() {
            String::new()
        } else if preds.is_empty() {
            expressions.join(", ")
        } else {
            format!(", {}", expressions.join(", "))
        };

        format!("{}{}", preds.join(", "), e)
    }

    pub fn print_rule(&self, r: &Rule) -> String {
        let res = self.print_predicate(&r.head);

        format!("{} <- {}", res, self.print_rule_body(r))
    }

    pub fn print_check(&self, c: &Check) -> String {
        let queries = c
            .queries
            .iter()
            .map(|r| self.print_rule_body(r))
            .collect::<Vec<_>>();

        format!("check if {}", queries.join(" or "))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TemporarySymbolTable<'a> {
    base: &'a SymbolTable,
    offset: usize,
    symbols: Vec<String>,
}

impl<'a> TemporarySymbolTable<'a> {
    pub fn new(base: &'a SymbolTable) -> Self {
        let offset = OFFSET + base.current_offset();

        TemporarySymbolTable {
            base,
            offset,
            symbols: vec![],
        }
    }

    pub fn get_symbol(&self, i: SymbolIndex) -> Option<&str> {
        if i as usize >= self.offset {
            self.symbols
                .get(i as usize - self.offset)
                .map(|s| s.as_str())
        } else {
            self.base.get_symbol(i)
        }
    }

    pub fn insert(&mut self, s: &str) -> SymbolIndex {
        if let Some(index) = self.base.get(s) {
            return index as u64;
        }

        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => (self.offset + index) as u64,
            None => {
                self.symbols.push(s.to_string());
                (self.offset + (self.symbols.len() - 1)) as u64
            }
        }
    }
}
