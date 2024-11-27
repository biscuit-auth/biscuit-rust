//! helper functions and structure to create tokens and blocks
use super::Block;
use crate::crypto::PublicKey;
use crate::datalog::SymbolTable;
use crate::error;
use crate::token::builder_ext::BuilderExt;
use nom::Finish;
use std::str::FromStr;
use std::{
    collections::BTreeSet,
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
mod check;
mod expression;
mod fact;
mod policy;
mod predicate;
mod rule;
mod scope;
mod term;

pub use biscuit::*;
pub use block::*;
pub use check::*;
pub use expression::*;
pub use fact::*;
pub use policy::*;
pub use predicate::*;
pub use rule::*;
pub use scope::*;
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
    use std::collections::HashMap;

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
