//! helper functions and structure to create tokens and blocks
//use crate::error;
use crate::parser::parse_block_source;
use std::{
    collections::{BTreeSet, HashMap},
    convert::{TryFrom, TryInto},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "datalog-macro")]
use quote::{quote, ToTokens};

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
        panic!()
        /*match self {
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
        }*/
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

/// Builder for a Datalog dicate, used in facts and rules
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
}
impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fact = self.clone();

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

/*impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut syms = super::default_symbol_table();
        let expr = self.convert(&mut syms);
        let s = expr.print(&syms).unwrap();
        write!(f, "{}", s)
    }
}*/

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

#[derive(Debug, Clone, PartialEq)]
pub enum Unary {
    Negate,
    Parens,
    Length,
}

#[derive(Debug, Clone, PartialEq)]
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

#[cfg(feature = "datalog-macro")]
impl ToTokens for Unary {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            Unary::Negate => quote! {::biscuit_auth::datalog::Unary::Negate },
            Unary::Parens => quote! {::biscuit_auth::datalog::Unary::Parens },
            Unary::Length => quote! {::biscuit_auth::datalog::Unary::Length },
        });
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Binary {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            Binary::LessThan => quote! { ::biscuit_auth::datalog::Binary::LessThan  },
            Binary::GreaterThan => quote! { ::biscuit_auth::datalog::Binary::GreaterThan  },
            Binary::LessOrEqual => quote! { ::biscuit_auth::datalog::Binary::LessOrEqual  },
            Binary::GreaterOrEqual => quote! { ::biscuit_auth::datalog::Binary::GreaterOrEqual  },
            Binary::Equal => quote! { ::biscuit_auth::datalog::Binary::Equal  },
            Binary::Contains => quote! { ::biscuit_auth::datalog::Binary::Contains  },
            Binary::Prefix => quote! { ::biscuit_auth::datalog::Binary::Prefix  },
            Binary::Suffix => quote! { ::biscuit_auth::datalog::Binary::Suffix  },
            Binary::Regex => quote! { ::biscuit_auth::datalog::Binary::Regex  },
            Binary::Add => quote! { ::biscuit_auth::datalog::Binary::Add  },
            Binary::Sub => quote! { ::biscuit_auth::datalog::Binary::Sub  },
            Binary::Mul => quote! { ::biscuit_auth::datalog::Binary::Mul  },
            Binary::Div => quote! { ::biscuit_auth::datalog::Binary::Div  },
            Binary::And => quote! { ::biscuit_auth::datalog::Binary::And  },
            Binary::Or => quote! { ::biscuit_auth::datalog::Binary::Or  },
            Binary::Intersection => quote! { ::biscuit_auth::datalog::Binary::Intersection  },
            Binary::Union => quote! { ::biscuit_auth::datalog::Binary::Union  },
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
}

impl Rule {
    pub fn new(head: Predicate, body: Vec<Predicate>, expressions: Vec<Expression>) -> Rule {
        let mut parameters = HashMap::new();
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

        Rule {
            head,
            body,
            expressions,
            parameters: Some(parameters),
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
}

fn display_rule_body(r: &Rule, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut rule = r.clone();
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

        panic!()
        /*write!(f, "{}", rule.expressions[0])?;

        if rule.expressions.len() > 1 {
            for i in 1..rule.expressions.len() {
                write!(f, ", {}", rule.expressions[i])?;
            }
        }*/
    }

    Ok(())
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.clone();

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
        tokens.extend(quote! {
          ::biscuit_auth::builder::Rule::new(
            #head,
            <[::biscuit_auth::builder::Predicate]>::into_vec(Box::new([#(#body),*])),
            <[::biscuit_auth::builder::Expression]>::into_vec(Box::new([#(#expressions),*]))
          )
        });
    }
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub queries: Vec<Rule>,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check if ")?;

        if !self.queries.is_empty() {
            let q0 = self.queries[0].clone();
            display_rule_body(&q0, f)?;

            if self.queries.len() > 1 {
                for i in 1..self.queries.len() {
                    write!(f, " or ")?;
                    let qn = self.queries[i].clone();
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
    )
}

/// creates a check
pub fn check<P: AsRef<Predicate>>(predicates: &[P]) -> Check {
    let empty_terms: &[Term] = &[];
    Check {
        queries: vec![Rule::new(
            pred("query", empty_terms),
            predicates.iter().map(|p| p.as_ref().clone()).collect(),
            Vec::new(),
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
