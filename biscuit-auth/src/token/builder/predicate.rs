use std::fmt;

use crate::{
    datalog::{self, SymbolTable},
    error,
};

use super::{Convert, Term};

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
