//! Logic language implementation for caveats
use std::collections::HashSet;
use std::time::{Duration, UNIX_EPOCH};
use chrono::{DateTime, NaiveDateTime, Utc};

pub type Symbol = u64;
use super::{ID, World, Fact, Rule, Constraint, ConstraintKind, Caveat,
  IntConstraint, StrConstraint, SymbolConstraint, BytesConstraint,
  DateConstraint, Predicate};

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

    pub fn print_fact(&self, f: &Fact) -> String {
        self.print_predicate(&f.predicate)
    }

    pub fn print_predicate(&self, p: &Predicate) -> String {
        let strings = p
            .ids
            .iter()
            .map(|id| match id {
                ID::Variable(i) => format!("${}", self.print_symbol(*i as u64)),
                ID::Integer(i) => i.to_string(),
                ID::Str(s) => format!("\"{}\"", s),
                ID::Symbol(index) => format!("#{}", self.print_symbol(*index as u64)),
                ID::Date(d) => {
                    let t = UNIX_EPOCH + Duration::from_secs(*d);
                    format!("{:?}", t)
                },
                ID::Bytes(s) => format!("hex:{}", hex::encode(s)),
            })
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

    pub fn print_constraint(&self, c: &Constraint) -> String {
        match &c.kind {
            ConstraintKind::Int(IntConstraint::LessThan(i)) => format!("${} < {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::GreaterThan(i)) => format!("${} > {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::LessOrEqual(i)) => format!("${} <= {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::GreaterOrEqual(i)) => format!("${} >= {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::Equal(i)) => format!("${} == {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::In(i)) => format!("${} in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::NotIn(i)) => format!("${} not in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Prefix(i)) => format!("${} matches {}*", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Suffix(i)) => format!("${} matches *{}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Equal(i)) => format!("${} == {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Regex(i)) => format!("${} matches /{}/", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::In(i)) => format!("${} in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::NotIn(i)) => format!("${} not in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Date(DateConstraint::Before(i)) => {
              let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(*i as i64, 0), Utc);
              format!("${} <= {}", self.print_symbol(c.id as u64), date.to_rfc3339())
            },
            ConstraintKind::Date(DateConstraint::After(i)) => {
              let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(*i as i64, 0), Utc);
              format!("${} >= {}", self.print_symbol(c.id as u64), date.to_rfc3339())
            },
            ConstraintKind::Symbol(SymbolConstraint::In(i)) => format!("${} in {:?}", c.id, i),
            ConstraintKind::Symbol(SymbolConstraint::NotIn(i)) => {
                format!("${} not in {:?}", self.print_symbol(c.id as u64), i)
            }
            ConstraintKind::Bytes(BytesConstraint::Equal(i)) => format!("${} == hex:{}", c.id, hex::encode(i)),
            ConstraintKind::Bytes(BytesConstraint::In(i)) => {
                format!("${} in {:?}", self.print_symbol(c.id as u64), i.iter()
                        .map(|s| format!("hex:{}", hex::encode(s))).collect::<HashSet<_>>())
            },
            ConstraintKind::Bytes(BytesConstraint::NotIn(i)) => {
                format!("${} not in {:?}", self.print_symbol(c.id as u64), i.iter()
                        .map(|s| format!("hex:{}", hex::encode(s))).collect::<HashSet<_>>())
            },
        }
    }

    pub fn print_rule(&self, r: &Rule) -> String {
        let res = self.print_predicate(&r.head);
        let preds: Vec<_> = r.body.iter().map(|p| self.print_predicate(p)).collect();
        let constraints: Vec<_> = r
            .constraints
            .iter()
            .map(|c| self.print_constraint(c))
            .collect();

        let c = if constraints.is_empty() {
          String::new()
        } else {
          format!(" @ {}", constraints.join(", "))
        };

        format!(
            "{} <- {}{}",
            res,
            preds.join(", "),
            c
        )
    }

    pub fn print_caveat(&self, c: &Caveat) -> String {
        let queries = c
            .queries
            .iter()
            .map(|r| self.print_rule(r))
            .collect::<Vec<_>>();

        queries.join(" || ")
    }
}
