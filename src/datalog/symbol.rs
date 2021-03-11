//! Symbol table implementation
use chrono::{DateTime, NaiveDateTime, Utc};

pub type Symbol = u64;
use super::{ID, World, Fact, Rule, Check, Predicate};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SymbolTable {
    pub symbols: Vec<String>,
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable::default()
    }

    pub fn insert(&mut self, s: &str) -> Symbol {
        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => index as u64,
            None => {
                self.symbols.push(s.to_string());
                (self.symbols.len() - 1) as u64
            }
        }
    }

    pub fn add(&mut self, s: &str) -> ID {
        let id = self.insert(s);
        ID::Symbol(id)
    }

    pub fn get(&self, s: &str) -> Option<Symbol> {
        self.symbols
            .iter()
            .position(|sym| sym.as_str() == s)
            .map(|i| i as u64)
    }

    pub fn print_symbol(&self, s: Symbol) -> String {
      self.symbols.get(s as usize).map(|s| s.to_string()).unwrap_or_else(|| format!("<{}?>", s))
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

    pub fn print_id(&self, id: &ID) -> String {
        match id {
            ID::Variable(i) => format!("${}", self.print_symbol(*i as u64)),
            ID::Integer(i) => i.to_string(),
            ID::Str(s) => format!("\"{}\"", s),
            ID::Symbol(index) => format!("#{}", self.print_symbol(*index as u64)),
            ID::Date(d) => {
                let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(*d as i64, 0), Utc);
                date.to_rfc3339()
            },
            ID::Bytes(s) => format!("hex:{}", hex::encode(s)),
            ID::Bool(b) => if *b {
                "true".to_string()
            } else {
                "false".to_string()
            },
            ID::Set(s) => {
                let ids = s.iter().map(|id| self.print_id(id)).collect::<Vec<_>>();
                format!("[{}]", ids.join(", "))
            }
        }
    }
    pub fn print_fact(&self, f: &Fact) -> String {
        self.print_predicate(&f.predicate)
    }

    pub fn print_predicate(&self, p: &Predicate) -> String {
        let strings = p
            .ids
            .iter()
            .map(|id| self.print_id(id))
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
        e.print(self).unwrap_or_else(|| format!("<invalid expression: {:?}>", e.ops))
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
        } else {
            if preds.is_empty() {
                expressions.join(", ")
            } else {
                format!(", {}", expressions.join(", "))
            }
        };

        format!(
            "{}{}",
            preds.join(", "),
            e
        )
    }

    pub fn print_rule(&self, r: &Rule) -> String {
        let res = self.print_predicate(&r.head);

        format!(
            "{} <- {}",
            res,
            self.print_rule_body(r)
        )
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
