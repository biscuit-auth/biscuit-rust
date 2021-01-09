//! helper functions for conversion between internal structures and Protobuf
use crate::crypto::TokenSignature;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};

use super::schema;
use crate::datalog::*;
use crate::error;
use crate::token::Block;

pub fn token_sig_to_proto_sig(input: &TokenSignature) -> schema::Signature {
    schema::Signature {
        parameters: input
            .parameters
            .iter()
            .map(|g| Vec::from(&g.compress().to_bytes()[..]))
            .collect(),
        z: Vec::from(&input.z.as_bytes()[..]),
    }
}

pub fn proto_sig_to_token_sig(input: schema::Signature) -> Result<TokenSignature, error::Format> {
    let mut parameters = vec![];

    for data in input.parameters {
        if data.len() == 32 {
            if let Some(d) = CompressedRistretto::from_slice(&data[..]).decompress() {
                parameters.push(d);
            } else {
                return Err(error::Format::DeserializationError(
                    "deserialization error: cannot decompress parameters point".to_string(),
                ));
            }
        } else {
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: invalid size for parameters = {}",
                data.len()
            )));
        }
    }

    let z = if input.z.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&input.z[..]);
        if let Some(d) = Scalar::from_canonical_bytes(bytes) {
            d
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: non canonical z scalar".to_string(),
            ));
        }
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid size for z = {} bytes",
            input.z.len()
        )));
    };

    Ok(TokenSignature { parameters, z })
}

pub fn token_block_to_proto_block(input: &Block) -> schema::Block {
    schema::Block {
        index: input.index,
        symbols: input.symbols.symbols.clone(),
        facts_v0: Vec::new(),
        rules_v0: Vec::new(),
        caveats_v0: Vec::new(),
        context: input.context.clone(),
        version: Some(input.version),
        facts_v1: input
            .facts
            .iter()
            .map(v1::token_fact_to_proto_fact)
            .collect(),
        rules_v1: input
            .rules
            .iter()
            .map(v1::token_rule_to_proto_rule)
            .collect(),
        caveats_v1: input
            .caveats
            .iter()
            .map(v1::token_caveat_to_proto_caveat)
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
    let mut caveats = vec![];
    if version == 0 {
        for fact in input.facts_v0.iter() {
            facts.push(v0::proto_fact_to_token_fact(fact)?);
        }

        for rule in input.rules_v0.iter() {
            rules.push(v0::proto_rule_to_token_rule(rule)?);
        }

        for caveat in input.caveats_v0.iter() {
            caveats.push(v0::proto_caveat_to_token_caveat(caveat)?);
        }
    } else {
        for fact in input.facts_v1.iter() {
            facts.push(v1::proto_fact_to_token_fact(fact)?);
        }

        for rule in input.rules_v1.iter() {
            rules.push(v1::proto_rule_to_token_rule(rule)?);
        }

        for caveat in input.caveats_v1.iter() {
            caveats.push(v1::proto_caveat_to_token_caveat(caveat)?);
        }
    }

    let context = input.context.clone();

    Ok(Block {
        index: input.index,
        symbols: SymbolTable {
            symbols: input.symbols.clone(),
        },
        facts,
        rules,
        caveats,
        context,
        version,
    })
}

pub mod v0 {
    use super::schema;
    use crate::datalog::*;
    use crate::error;

    pub fn proto_fact_to_token_fact(input: &schema::FactV0) -> Result<Fact, error::Format> {
        Ok(Fact {
            predicate: proto_predicate_to_token_predicate(&input.predicate)?,
        })
    }

    pub fn proto_caveat_to_token_caveat(input: &schema::CaveatV0) -> Result<Caveat, error::Format> {
        let mut queries = vec![];

        for q in input.queries.iter() {
            queries.push(proto_rule_to_token_rule(q)?);
        }

        Ok(Caveat { queries })
    }

    pub fn proto_rule_to_token_rule(input: &schema::RuleV0) -> Result<Rule, error::Format> {
        let mut body = vec![];

        for p in input.body.iter() {
            body.push(proto_predicate_to_token_predicate(p)?);
        }

        let mut expressions = vec![];

        for c in input.constraints.iter() {
            expressions.push(proto_constraint_to_token_constraint(c)?);
        }

        Ok(Rule {
            head: proto_predicate_to_token_predicate(&input.head)?,
            body,
            expressions,
        })
    }

    pub fn proto_predicate_to_token_predicate(
        input: &schema::PredicateV0,
    ) -> Result<Predicate, error::Format> {
        let mut ids = vec![];

        for id in input.ids.iter() {
            ids.push(proto_id_to_token_id(id)?);
        }

        Ok(Predicate {
            name: input.name,
            ids,
        })
    }

    pub fn proto_id_to_token_id(input: &schema::Idv0) -> Result<ID, error::Format> {
        use schema::idv0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid id kind".to_string(),
            ));
        };

        match kind {
            Kind::Symbol => {
                if let Some(s) = input.symbol {
                    return Ok(ID::Symbol(s));
                }
            }
            Kind::Variable => {
                if let Some(v) = input.variable {
                    return Ok(ID::Variable(v));
                }
            }
            Kind::Integer => {
                if let Some(i) = input.integer {
                    return Ok(ID::Integer(i));
                }
            }
            Kind::Str => {
                if let Some(ref s) = input.str {
                    return Ok(ID::Str(s.clone()));
                }
            }
            Kind::Date => {
                if let Some(d) = input.date {
                    return Ok(ID::Date(d));
                }
            }
            Kind::Bytes => {
                if let Some(ref s) = input.bytes {
                    return Ok(ID::Bytes(s.clone()));
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid id".to_string(),
        ))
    }

    pub fn proto_constraint_to_token_constraint(
        input: &schema::ConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::Int => {
                if let Some(ref i) = input.int {
                    return proto_int_constraint_to_token_int_expression(ID::Variable(input.id), i);
                }
            }
            Kind::String => {
                if let Some(ref i) = input.str {
                    return proto_str_constraint_to_token_str_expression(ID::Variable(input.id), i);
                }
            }
            Kind::Date => {
                if let Some(ref i) = input.date {
                    return proto_date_constraint_to_token_date_expression(ID::Variable(input.id), i);
                }
            }
            Kind::Symbol => {
                if let Some(ref i) = input.symbol {
                    return proto_symbol_constraint_to_token_symbol_expression(ID::Variable(input.id), i);
                }
            }
            Kind::Bytes => {
                if let Some(ref i) = input.bytes {
                    return proto_bytes_constraint_to_token_bytes_expression(ID::Variable(input.id), i);
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid constraint".to_string(),
        ))
    }

    pub fn proto_int_constraint_to_token_int_expression(
        id: ID,
        input: &schema::IntConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::int_constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid int constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::Lower => {
                if let Some(i) = input.lower {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Integer(i)), Op::Binary(Binary::LessThan)] });
                }
            }
            Kind::Larger => {
                if let Some(i) = input.larger {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Integer(i)), Op::Binary(Binary::GreaterThan)] });
                }
            }
            Kind::LowerOrEqual => {
                if let Some(i) = input.lower_or_equal {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Integer(i)), Op::Binary(Binary::LessOrEqual)] });
                }
            }
            Kind::LargerOrEqual => {
                if let Some(i) = input.larger_or_equal {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Integer(i)), Op::Binary(Binary::GreaterOrEqual)] });
                }
            }
            Kind::Equal => {
                if let Some(i) = input.equal {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Integer(i)), Op::Binary(Binary::Equal)] });
                }
            }
            Kind::In => {
                if !input.in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|i| ID::Integer(*i)).collect())),
                        Op::Binary(Binary::In)
                    ] });
                }
            }
            Kind::NotIn => {
                if !input.not_in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|i| ID::Integer(*i)).collect())),
                        Op::Binary(Binary::NotIn)
                    ] });
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid id".to_string(),
        ))
    }

    pub fn proto_str_constraint_to_token_str_expression(
        id: ID,
        input: &schema::StringConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::string_constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid string constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::Prefix => {
                if let Some(ref s) = input.prefix {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Str(s.clone())), Op::Binary(Binary::Prefix)] });
                }
            }
            Kind::Suffix => {
                if let Some(ref s) = input.suffix {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Str(s.clone())), Op::Binary(Binary::Suffix)] });
                }
            }
            Kind::Equal => {
                if let Some(ref s) = input.equal {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Str(s.clone())), Op::Binary(Binary::Equal)] });
                }
            }
            Kind::Regex => {
                if let Some(ref r) = input.regex {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Str(r.clone())), Op::Binary(Binary::Regex)] });
                }
            }
            Kind::In => {
                if !input.in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|s| ID::Str(s.clone())).collect())),
                        Op::Binary(Binary::In)
                    ] });
                }
            }
            Kind::NotIn => {
                if !input.not_in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|s| ID::Str(s.clone())).collect())),
                        Op::Binary(Binary::NotIn)
                    ] });
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid string constraint".to_string(),
        ))
    }

    pub fn proto_date_constraint_to_token_date_expression(
        id: ID,
        input: &schema::DateConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::date_constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid date constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::Before => {
                if let Some(i) = input.before {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Date(i)), Op::Binary(Binary::LessOrEqual)] });
                }
            }
            Kind::After => {
                if let Some(i) = input.after {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Date(i)), Op::Binary(Binary::GreaterOrEqual)] });
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid date constraint".to_string(),
        ))
    }

    pub fn proto_symbol_constraint_to_token_symbol_expression(
        id: ID,
        input: &schema::SymbolConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::symbol_constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid symbol constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::In => {
                if !input.in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|s| ID::Symbol(*s)).collect())),
                        Op::Binary(Binary::In)
                    ] });
                }
            }
            Kind::NotIn => {
                if !input.not_in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|s| ID::Symbol(*s)).collect())),
                        Op::Binary(Binary::NotIn)
                    ] });
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid symbol constraint".to_string(),
        ))
    }

    pub fn proto_bytes_constraint_to_token_bytes_expression(
        id: ID,
        input: &schema::BytesConstraintV0,
    ) -> Result<Expression, error::Format> {
        use schema::bytes_constraint_v0::Kind;

        let kind = if let Some(i) = Kind::from_i32(input.kind) {
            i
        } else {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid bytes constraint kind".to_string(),
            ));
        };

        match kind {
            Kind::Equal => {
                if let Some(ref s) = input.equal {
                    return Ok(Expression { ops: vec![Op::Value(id), Op::Value(ID::Bytes(s.clone())), Op::Binary(Binary::Equal)] });
                }
            }
            Kind::In => {
                if !input.in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|b| ID::Bytes(b.clone())).collect())),
                        Op::Binary(Binary::In)
                    ] });
                }
            }
            Kind::NotIn => {
                if !input.not_in_set.is_empty() {
                    return Ok(Expression { ops: vec![
                        Op::Value(id),
                        Op::Value(ID::Set(input.in_set.iter().map(|b| ID::Bytes(b.clone())).collect())),
                        Op::Binary(Binary::NotIn)
                    ] });
                }
            }
        }

        Err(error::Format::DeserializationError(
            "deserialization error: invalid string constraint".to_string(),
        ))
    }
}

pub mod v1 {
    use super::schema;
    use crate::datalog::*;
    use crate::error;
    use std::collections::BTreeSet;

    pub fn token_fact_to_proto_fact(input: &Fact) -> schema::FactV1 {
        schema::FactV1 {
            predicate: token_predicate_to_proto_predicate(&input.predicate),
        }
    }

    pub fn proto_fact_to_token_fact(input: &schema::FactV1) -> Result<Fact, error::Format> {
        Ok(Fact {
            predicate: proto_predicate_to_token_predicate(&input.predicate)?,
        })
    }

    pub fn token_caveat_to_proto_caveat(input: &Caveat) -> schema::CaveatV1 {
        schema::CaveatV1 {
            queries: input.queries.iter().map(token_rule_to_proto_rule).collect(),
        }
    }

    pub fn proto_caveat_to_token_caveat(input: &schema::CaveatV1) -> Result<Caveat, error::Format> {
        let mut queries = vec![];

        for q in input.queries.iter() {
            queries.push(proto_rule_to_token_rule(q)?);
        }

        Ok(Caveat { queries })
    }

    pub fn token_rule_to_proto_rule(input: &Rule) -> schema::RuleV1 {
        schema::RuleV1 {
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

    pub fn proto_rule_to_token_rule(input: &schema::RuleV1) -> Result<Rule, error::Format> {
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

    pub fn token_predicate_to_proto_predicate(input: &Predicate) -> schema::PredicateV1 {
        schema::PredicateV1 {
            name: input.name,
            ids: input.ids.iter().map(token_id_to_proto_id).collect(),
        }
    }

    pub fn proto_predicate_to_token_predicate(
        input: &schema::PredicateV1,
    ) -> Result<Predicate, error::Format> {
        let mut ids = vec![];

        for id in input.ids.iter() {
            ids.push(proto_id_to_token_id(id)?);
        }

        Ok(Predicate {
            name: input.name,
            ids,
        })
    }

    pub fn token_id_to_proto_id(input: &ID) -> schema::Idv1 {
        use schema::idv1::Content;

        match input {
            ID::Symbol(s) => schema::Idv1 {
                content: Some(Content::Symbol(*s)),
            },
            ID::Variable(v) => schema::Idv1 {
                content: Some(Content::Variable(*v)),
            },
            ID::Integer(i) => schema::Idv1 {
                content: Some(Content::Integer(*i)),
            },
            ID::Str(s) => schema::Idv1 {
                content: Some(Content::String(s.clone())),
            },
            ID::Date(d) => schema::Idv1 {
                content: Some(Content::Date(*d)),
            },
            ID::Bytes(s) => schema::Idv1 {
                content: Some(Content::Bytes(s.clone())),
            },
            ID::Bool(b) => schema::Idv1 {
                content: Some(Content::Bool(*b)),
            },
            ID::Set(s) => schema::Idv1 {
                content: Some(Content::Set(schema::IdSet {
                    set: s.iter().map(token_id_to_proto_id).collect()
                }))
            },
        }
    }

    pub fn proto_id_to_token_id(input: &schema::Idv1) -> Result<ID, error::Format> {
        use schema::idv1::Content;

        match &input.content {
            None => Err(error::Format::DeserializationError(
                "deserialization error: ID content enum is empty".to_string(),
            )),
            Some(Content::Symbol(i)) => Ok(ID::Symbol(*i)),
            Some(Content::Variable(i)) => Ok(ID::Variable(*i)),
            Some(Content::Integer(i)) => Ok(ID::Integer(*i)),
            Some(Content::String(s)) => Ok(ID::Str(s.clone())),
            Some(Content::Date(i)) => Ok(ID::Date(*i)),
            Some(Content::Bytes(s)) => Ok(ID::Bytes(s.clone())),
            Some(Content::Bool(b)) => Ok(ID::Bool(*b)),
            Some(Content::Set(s)) => {
                let mut kind: Option<u8> = None;
                let mut set = BTreeSet::new();

                for i in s.set.iter() {
                    let index = match i.content {
                        Some(Content::Symbol(_)) => 0,
                        Some(Content::Variable(_)) => {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets cannot contain variables".to_string(),
                            ));
                        },
                        Some(Content::Integer(_)) => 2,
                        Some(Content::String(_)) => 3,
                        Some(Content::Date(_)) => 4,
                        Some(Content::Bytes(_)) => 5,
                        Some(Content::Bool(_)) => 6,
                        Some(Content::Set(_)) => {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets cannot contain other sets".to_string(),
                            ));
                        },
                        None => return Err(error::Format::DeserializationError(
                            "deserialization error: ID content enum is empty".to_string(),
                        )),
                    };

                    if let Some(k) = kind.as_ref() {
                        if *k != index {
                            return Err(error::Format::DeserializationError(
                                "deserialization error: sets elements must have the same type".to_string(),
                            ));
                        }
                    } else {
                        kind = Some(index);
                    }

                    set.insert(proto_id_to_token_id(i)?);
                }

                Ok(ID::Set(set))
            }
        }
    }

    pub fn token_expression_to_proto_expression(input: &Expression) -> schema::ExpressionV1 {
        schema::ExpressionV1 {
            ops: input.ops.iter().map(|op| {
                let content = match op {
                    Op::Value(i) => schema::op::Content::Value(token_id_to_proto_id(i)),
                    Op::Unary(u) => {
                        use schema::op_unary::Kind;

                        schema::op::Content::Unary(schema::OpUnary {
                            kind: match u {
                                Unary::Negate => Kind::Negate,
                            } as i32,
                        })
                    },
                    Op::Binary(b) => {
                        use schema::op_binary::Kind;

                        schema::op::Content::Binary(schema::OpBinary {
                            kind: match b {
                                Binary::LessThan => Kind::LessThan,
                                Binary::GreaterThan => Kind::GreaterThan,
                                Binary::LessOrEqual => Kind::LessOrEqual,
                                Binary::GreaterOrEqual => Kind::GreaterOrEqual,
                                Binary::Equal => Kind::Equal,
                                Binary::In => Kind::In,
                                Binary::NotIn => Kind::NotIn,
                                Binary::Prefix => Kind::Prefix,
                                Binary::Suffix => Kind::Suffix,
                                Binary::Regex => Kind::Regex,
                                Binary::Add => Kind::Add,
                                Binary::Sub => Kind::Sub,
                                Binary::Mul => Kind::Mul,
                                Binary::Div => Kind::Div,
                                Binary::And => Kind::And,
                                Binary::Or => Kind::Or,
                            } as i32,
                        })
                    },
                };

                schema::Op { content: Some(content) }
            }).collect(),
        }
    }

    pub fn proto_expression_to_token_expression(
        input: &schema::ExpressionV1,
    ) -> Result<Expression, error::Format> {
        use schema::{op, op_unary, op_binary};
        let mut ops = Vec::new();

        for op in input.ops.iter() {
            let translated = match op.content.as_ref() {
                Some(op::Content::Value(id)) => Op::Value(proto_id_to_token_id(&id)?),
                Some(op::Content::Unary(u)) => match op_unary::Kind::from_i32(u.kind) {
                    Some(op_unary::Kind::Negate) => Op::Unary(Unary::Negate),
                    None => return Err(error::Format::DeserializationError(
                        "deserialization error: unary operation is empty".to_string(),
                    )),
                }
                Some(op::Content::Binary(b)) => match op_binary::Kind::from_i32(b.kind) {
                    Some(op_binary::Kind::LessThan) => Op::Binary(Binary::LessThan),
                    Some(op_binary::Kind::GreaterThan) => Op::Binary(Binary::GreaterThan),
                    Some(op_binary::Kind::LessOrEqual) => Op::Binary(Binary::LessOrEqual),
                    Some(op_binary::Kind::GreaterOrEqual) => Op::Binary(Binary::GreaterOrEqual),
                    Some(op_binary::Kind::Equal) => Op::Binary(Binary::Equal),
                    Some(op_binary::Kind::In) => Op::Binary(Binary::In),
                    Some(op_binary::Kind::NotIn) => Op::Binary(Binary::NotIn),
                    Some(op_binary::Kind::Prefix) => Op::Binary(Binary::Prefix),
                    Some(op_binary::Kind::Suffix) => Op::Binary(Binary::Suffix),
                    Some(op_binary::Kind::Regex) => Op::Binary(Binary::Regex),
                    Some(op_binary::Kind::Add) => Op::Binary(Binary::Add),
                    Some(op_binary::Kind::Sub) => Op::Binary(Binary::Sub),
                    Some(op_binary::Kind::Mul) => Op::Binary(Binary::Mul),
                    Some(op_binary::Kind::Div) => Op::Binary(Binary::Div),
                    Some(op_binary::Kind::And) => Op::Binary(Binary::And),
                    Some(op_binary::Kind::Or) => Op::Binary(Binary::Or),
                    None => return Err(error::Format::DeserializationError(
                        "deserialization error: binary operation is empty".to_string(),
                    )),
                }
                None => return Err(error::Format::DeserializationError(
                    "deserialization error: operation is empty".to_string(),
                    )),
            };
            ops.push(translated);
        }

        Ok(Expression { ops })
        /*
        use schema::constraint_v1;

        match &input.constraint {
            None => Err(error::Format::DeserializationError(
                "deserialization error: constraint enum is empty".to_string(),
            )),
            Some(constraint_v1::Constraint::Int(i)) => {
                proto_int_constraint_to_token_int_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Int(c),
                })
            }
            Some(constraint_v1::Constraint::String(i)) => {
                proto_str_constraint_to_token_str_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Str(c),
                })
            }
            Some(constraint_v1::Constraint::Date(i)) => {
                proto_date_constraint_to_token_date_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Date(c),
                })
            }
            Some(constraint_v1::Constraint::Symbol(i)) => {
                proto_symbol_constraint_to_token_symbol_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Symbol(c),
                })
            }
            Some(constraint_v1::Constraint::Bytes(i)) => {
                proto_bytes_constraint_to_token_bytes_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Bytes(c),
                })
            }
        }*/
    }
}
