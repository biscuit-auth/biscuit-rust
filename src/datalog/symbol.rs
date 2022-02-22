//! Symbol table implementation
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
pub type SymbolIndex = u64;
use super::{Check, Fact, Predicate, Rule, Term, World};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SymbolTable {
    pub symbols: Vec<String>,
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable::default()
    }

    pub fn insert(&mut self, s: &str) -> SymbolIndex {
        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => index as u64,
            None => {
                self.symbols.push(s.to_string());
                (self.symbols.len() - 1) as u64
            }
        }
    }

    pub fn add(&mut self, s: &str) -> Term {
        let term = self.insert(s);
        Term::Str(term)
    }

    pub fn get(&self, s: &str) -> Option<SymbolIndex> {
        self.symbols
            .iter()
            .position(|sym| sym.as_str() == s)
            .map(|i| i as SymbolIndex)
    }

    pub fn get_symbol(&self, i: SymbolIndex) -> Option<&str> {
        self.symbols.get(i as usize).map(|s| s.as_str())
    }

    pub fn print_symbol(&self, i: SymbolIndex) -> String {
        self.symbols
            .get(i as usize)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("<{}?>", i))
    }

    pub fn print_world(&self, w: &World) -> String {
        let facts = w
            .facts
            .iter()
            .map(|f| self.print_fact(f))
            .collect::<Vec<_>>();
        let rules = w
            .rules
            .iter()
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
            self.symbols
                .get(p.name as usize)
                .map(|s| s.as_str())
                .unwrap_or("<?>"),
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
