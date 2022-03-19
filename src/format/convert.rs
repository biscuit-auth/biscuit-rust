//! helper functions for conversion between internal structures and Protobuf

use super::schema;
use crate::datalog::*;
use crate::error;
use crate::token::{authorizer::AuthorizerPolicies, Block};

pub fn token_block_to_proto_block(input: &Block) -> schema::Block {
    schema::Block {
        symbols: input.symbols.symbols.clone(),
        context: input.context.clone(),
        version: Some(input.version),
        facts_v2: input
            .facts
            .iter()
            .map(v2::token_fact_to_proto_fact)
            .collect(),
        rules_v2: input
            .rules
            .iter()
            .map(v2::token_rule_to_proto_rule)
            .collect(),
        checks_v2: input
            .checks
            .iter()
            .map(v2::token_check_to_proto_check)
            .collect(),
    }
}

pub fn proto_block_to_token_block(input: &schema::Block) -> Result<Block, error::Format> {
    let version = input.version.unwrap_or(0);
    if version > crate::token::MAX_SCHEMA_VERSION {
        return Err(error::Format::Version {
            maximum: crate::token::MAX_SCHEMA_VERSION,
            actual: version,
        });
    }

    let mut facts = vec![];
    let mut rules = vec![];
    let mut checks = vec![];
    if version == 2 {
        for fact in input.facts_v2.iter() {
            facts.push(v2::proto_fact_to_token_fact(fact)?);
        }

        for rule in input.rules_v2.iter() {
            rules.push(v2::proto_rule_to_token_rule(rule)?);
        }

        for check in input.checks_v2.iter() {
            checks.push(v2::proto_check_to_token_check(check)?);
        }
    }

    let context = input.context.clone();

    let mut symbols = SymbolTable::new();
    symbols.symbols = input.symbols.clone();

    Ok(Block {
        symbols,
        facts,
        rules,
        checks,
        context,
        version,
    })
}

pub fn authorizer_to_proto_authorizer(input: &AuthorizerPolicies) -> schema::AuthorizerPolicies {
    let mut symbols = input.symbols.clone();
    let policies = input
        .policies
        .iter()
        .map(|p| v2::policy_to_proto_policy(p, &mut symbols))
        .collect();

    schema::AuthorizerPolicies {
        symbols: symbols.symbols,
        version: Some(input.version),
        facts: input
            .facts
            .iter()
            .map(v2::token_fact_to_proto_fact)
            .collect(),
        rules: input
            .rules
            .iter()
            .map(v2::token_rule_to_proto_rule)
            .collect(),
        checks: input
            .checks
            .iter()
            .map(v2::token_check_to_proto_check)
            .collect(),
        policies,
    }
}

pub fn proto_authorizer_to_authorizer(
    input: &schema::AuthorizerPolicies,
) -> Result<AuthorizerPolicies, error::Format> {
    let version = input.version.unwrap_or(0);
    if version == 0 || version > crate::token::MAX_SCHEMA_VERSION {
        return Err(error::Format::Version {
            maximum: crate::token::MAX_SCHEMA_VERSION,
            actual: version,
        });
    }


    let mut symbols = SymbolTable::new();
    symbols.symbols = input.symbols.clone();

    let mut facts = vec![];
    let mut rules = vec![];
    let mut checks = vec![];
    let mut policies = vec![];

    for fact in input.facts.iter() {
        facts.push(v2::proto_fact_to_token_fact(fact)?);
    }

    for rule in input.rules.iter() {
        rules.push(v2::proto_rule_to_token_rule(rule)?);
    }

    for check in input.checks.iter() {
        checks.push(v2::proto_check_to_token_check(check)?);
    }

    for policy in input.policies.iter() {
        policies.push(v2::proto_policy_to_policy(policy, &symbols)?);
    }

    Ok(AuthorizerPolicies {
        version,
        symbols,
        facts,
        rules,
        checks,
        policies,
    })
}

pub mod v2 {
    use super::schema;
    use crate::datalog::*;
    use crate::error;
    use std::collections::BTreeSet;

    pub fn token_fact_to_proto_fact(input: &Fact) -> schema::FactV2 {
        schema::FactV2 {
            predicate: token_predicate_to_proto_predicate(&input.predicate),
        }
    }

    pub fn proto_fact_to_token_fact(input: &schema::FactV2) -> Result<Fact, error::Format> {
        Ok(Fact {
            predicate: proto_predicate_to_token_predicate(&input.predicate)?,
        })
    }

    pub fn token_check_to_proto_check(input: &Check) -> schema::CheckV2 {
        schema::CheckV2 {
            queries: input.queries.iter().map(token_rule_to_proto_rule).collect(),
        }
    }

    pub fn proto_check_to_token_check(input: &schema::CheckV2) -> Result<Check, error::Format> {
        let mut queries = vec![];

        for q in input.queries.iter() {
            queries.push(proto_rule_to_token_rule(q)?);
        }

        Ok(Check { queries })
    }

    pub fn policy_to_proto_policy(
        input: &crate::token::builder::Policy,
        symbols: &mut SymbolTable,
    ) -> schema::Policy {
        schema::Policy {
            queries: input
                .queries
                .iter()
                .map(|q| q.convert(symbols))
                .map(|r| token_rule_to_proto_rule(&r))
                .collect(),
            kind: match input.kind {
                crate::token::builder::PolicyKind::Allow => schema::policy::Kind::Allow as i32,
                crate::token::builder::PolicyKind::Deny => schema::policy::Kind::Deny as i32,
            },
        }
    }

    pub fn proto_policy_to_policy(
        input: &schema::Policy,
        symbols: &SymbolTable,
    ) -> Result<crate::token::builder::Policy, error::Format> {
        use schema::policy::Kind;
        let mut queries = vec![];

        for q in input.queries.iter() {
            let c = proto_rule_to_token_rule(q)?;
            let c = crate::token::builder::Rule::convert_from(&c, symbols);
            queries.push(c);
        }

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid policy kind".to_string(),
            ));
        };

        let kind = match kind {
            Kind::Allow => crate::token::builder::PolicyKind::Allow,
            Kind::Deny => crate::token::builder::PolicyKind::Deny,
        };

        Ok(crate::token::builder::Policy { queries, kind })
    }

    pub fn token_rule_to_proto_rule(input: &Rule) -> schema::RuleV2 {
        schema::RuleV2 {
            head: token_predicate_to_proto_predicate(&input.head),
            body: input
                .body
                .iter()
                .map(token_predicate_to_proto_predicate)
                .collect(),
            expressions: input
                .expressions
                .iter()
                .map(token_expression_to_proto_expression)
                .collect(),
        }
    }

    pub fn proto_rule_to_token_rule(input: &schema::RuleV2) -> Result<Rule, error::Format> {
        let mut body = vec![];

        for p in input.body.iter() {
            body.push(proto_predicate_to_token_predicate(p)?);
        }

        let mut expressions = vec![];

        for c in input.expressions.iter() {
            expressions.push(proto_expression_to_token_expression(c)?);
        }

        Ok(Rule {
            head: proto_predicate_to_token_predicate(&input.head)?,
            body,
            expressions,
        })
    }

    pub fn token_predicate_to_proto_predicate(input: &Predicate) -> schema::PredicateV2 {
        schema::PredicateV2 {
            name: input.name,
            terms: input.terms.iter().map(token_term_to_proto_id).collect(),
        }
    }

    pub fn proto_predicate_to_token_predicate(
        input: &schema::PredicateV2,
    ) -> Result<Predicate, error::Format> {
        let mut terms = vec![];

        for term in input.terms.iter() {
            terms.push(proto_id_to_token_term(term)?);
        }

        Ok(Predicate {
            name: input.name,
            terms,
        })
    }

    pub fn token_term_to_proto_id(input: &Term) -> schema::TermV2 {
        use schema::term_v2::Content;

        match input {
            Term::Variable(v) => schema::TermV2 {
                content: Some(Content::Variable(*v)),
            },
            Term::Integer(i) => schema::TermV2 {
                content: Some(Content::Integer(*i)),
            },
            Term::Str(s) => schema::TermV2 {
                content: Some(Content::String(*s)),
            },
            Term::Date(d) => schema::TermV2 {
                content: Some(Content::Date(*d)),
            },
            Term::Bytes(s) => schema::TermV2 {
                content: Some(Content::Bytes(s.clone())),
            },
            Term::Bool(b) => schema::TermV2 {
                content: Some(Content::Bool(*b)),
            },
            Term::Set(s) => schema::TermV2 {
                content: Some(Content::Set(schema::TermSet {
                    set: s.iter().map(token_term_to_proto_id).collect(),
                })),
            },
        }
    }

    pub fn proto_id_to_token_term(input: &schema::TermV2) -> Result<Term, error::Format> {
        use schema::term_v2::Content;

        match &input.content {
            None => Err(error::Format::DeserializationError(
                "deserialization error: ID content enum is empty".to_string(),
            )),
            Some(Content::Variable(i)) => Ok(Term::Variable(*i)),
            Some(Content::Integer(i)) => Ok(Term::Integer(*i)),
            Some(Content::String(s)) => Ok(Term::Str(*s)),
            Some(Content::Date(i)) => Ok(Term::Date(*i)),
            Some(Content::Bytes(s)) => Ok(Term::Bytes(s.clone())),
            Some(Content::Bool(b)) => Ok(Term::Bool(*b)),
            Some(Content::Set(s)) => {
                let mut kind: Option<u8> = None;
                let mut set = BTreeSet::new();

                for i in s.set.iter() {
                    let index = match i.content {
                        Some(Content::Variable(_)) => {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets cannot contain variables".to_string(),
                            ));
                        }
                        Some(Content::Integer(_)) => 2,
                        Some(Content::String(_)) => 3,
                        Some(Content::Date(_)) => 4,
                        Some(Content::Bytes(_)) => 5,
                        Some(Content::Bool(_)) => 6,
                        Some(Content::Set(_)) => {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets cannot contain other sets".to_string(),
                            ));
                        }
                        None => {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: ID content enum is empty".to_string(),
                            ))
                        }
                    };

                    if let Some(k) = kind.as_ref() {
                        if *k != index {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets elements must have the same type"
                                    .to_string(),
                            ));
                        }
                    } else {
                        kind = Some(index);
                    }

                    set.insert(proto_id_to_token_term(i)?);
                }

                Ok(Term::Set(set))
            }
        }
    }

    pub fn token_expression_to_proto_expression(input: &Expression) -> schema::ExpressionV2 {
        schema::ExpressionV2 {
            ops: input
                .ops
                .iter()
                .map(|op| {
                    let content = match op {
                        Op::Value(i) => schema::op::Content::Value(token_term_to_proto_id(i)),
                        Op::Unary(u) => {
                            use schema::op_unary::Kind;

                            schema::op::Content::Unary(schema::OpUnary {
                                kind: match u {
                                    Unary::Negate => Kind::Negate,
                                    Unary::Parens => Kind::Parens,
                                    Unary::Length => Kind::Length,
                                } as i32,
                            })
                        }
                        Op::Binary(b) => {
                            use schema::op_binary::Kind;

                            schema::op::Content::Binary(schema::OpBinary {
                                kind: match b {
                                    Binary::LessThan => Kind::LessThan,
                                    Binary::GreaterThan => Kind::GreaterThan,
                                    Binary::LessOrEqual => Kind::LessOrEqual,
                                    Binary::GreaterOrEqual => Kind::GreaterOrEqual,
                                    Binary::Equal => Kind::Equal,
                                    Binary::Contains => Kind::Contains,
                                    Binary::Prefix => Kind::Prefix,
                                    Binary::Suffix => Kind::Suffix,
                                    Binary::Regex => Kind::Regex,
                                    Binary::Add => Kind::Add,
                                    Binary::Sub => Kind::Sub,
                                    Binary::Mul => Kind::Mul,
                                    Binary::Div => Kind::Div,
                                    Binary::And => Kind::And,
                                    Binary::Or => Kind::Or,
                                    Binary::Intersection => Kind::Intersection,
                                    Binary::Union => Kind::Union,
                                } as i32,
                            })
                        }
                    };

                    schema::Op {
                        content: Some(content),
                    }
                })
                .collect(),
        }
    }

    pub fn proto_expression_to_token_expression(
        input: &schema::ExpressionV2,
    ) -> Result<Expression, error::Format> {
        use schema::{op, op_binary, op_unary};
        let mut ops = Vec::new();

        for op in input.ops.iter() {
            let translated = match op.content.as_ref() {
                Some(op::Content::Value(id)) => Op::Value(proto_id_to_token_term(id)?),
                Some(op::Content::Unary(u)) => match op_unary::Kind::from_i32(u.kind) {
                    Some(op_unary::Kind::Negate) => Op::Unary(Unary::Negate),
                    Some(op_unary::Kind::Parens) => Op::Unary(Unary::Parens),
                    Some(op_unary::Kind::Length) => Op::Unary(Unary::Length),
                    None => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: unary operation is empty".to_string(),
                        ))
                    }
                },
                Some(op::Content::Binary(b)) => match op_binary::Kind::from_i32(b.kind) {
                    Some(op_binary::Kind::LessThan) => Op::Binary(Binary::LessThan),
                    Some(op_binary::Kind::GreaterThan) => Op::Binary(Binary::GreaterThan),
                    Some(op_binary::Kind::LessOrEqual) => Op::Binary(Binary::LessOrEqual),
                    Some(op_binary::Kind::GreaterOrEqual) => Op::Binary(Binary::GreaterOrEqual),
                    Some(op_binary::Kind::Equal) => Op::Binary(Binary::Equal),
                    Some(op_binary::Kind::Contains) => Op::Binary(Binary::Contains),
                    Some(op_binary::Kind::Prefix) => Op::Binary(Binary::Prefix),
                    Some(op_binary::Kind::Suffix) => Op::Binary(Binary::Suffix),
                    Some(op_binary::Kind::Regex) => Op::Binary(Binary::Regex),
                    Some(op_binary::Kind::Add) => Op::Binary(Binary::Add),
                    Some(op_binary::Kind::Sub) => Op::Binary(Binary::Sub),
                    Some(op_binary::Kind::Mul) => Op::Binary(Binary::Mul),
                    Some(op_binary::Kind::Div) => Op::Binary(Binary::Div),
                    Some(op_binary::Kind::And) => Op::Binary(Binary::And),
                    Some(op_binary::Kind::Or) => Op::Binary(Binary::Or),
                    Some(op_binary::Kind::Intersection) => Op::Binary(Binary::Intersection),
                    Some(op_binary::Kind::Union) => Op::Binary(Binary::Union),
                    None => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: binary operation is empty".to_string(),
                        ))
                    }
                },
                None => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: operation is empty".to_string(),
                    ))
                }
            };
            ops.push(translated);
        }

        Ok(Expression { ops })
    }
}
