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
                return Err(error::Format::DeserializationError(format!(
                    "deserialization error: cannot decompress parameters point"
                )));
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
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: non canonical z scalar"
            )));
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
        facts: input.facts.iter().map(token_fact_to_proto_fact).collect(),
        caveats: input.caveats.iter().map(token_rule_to_proto_rule).collect(),
    }
}

pub fn proto_block_to_token_block(input: &schema::Block) -> Result<Block, error::Format> {
    let mut facts = vec![];
    for fact in input.facts.iter() {
        facts.push(proto_fact_to_token_fact(fact)?);
    }

    let mut caveats = vec![];
    for caveat in input.caveats.iter() {
        caveats.push(proto_rule_to_token_rule(caveat)?);
    }

    Ok(Block {
        index: input.index,
        symbols: SymbolTable {
            symbols: input.symbols.clone(),
        },
        facts,
        caveats,
    })
}

pub fn token_fact_to_proto_fact(input: &Fact) -> schema::Fact {
    schema::Fact {
        predicate: token_predicate_to_proto_predicate(&input.predicate),
    }
}

pub fn proto_fact_to_token_fact(input: &schema::Fact) -> Result<Fact, error::Format> {
    Ok(Fact {
        predicate: proto_predicate_to_token_predicate(&input.predicate)?,
    })
}

pub fn token_rule_to_proto_rule(input: &Rule) -> schema::Rule {
    schema::Rule {
        head: token_predicate_to_proto_predicate(&input.head),
        body: input
            .body
            .iter()
            .map(token_predicate_to_proto_predicate)
            .collect(),
        constraints: input
            .constraints
            .iter()
            .map(token_constraint_to_proto_constraint)
            .collect(),
    }
}

pub fn proto_rule_to_token_rule(input: &schema::Rule) -> Result<Rule, error::Format> {
    let mut body = vec![];

    for p in input.body.iter() {
        body.push(proto_predicate_to_token_predicate(p)?);
    }

    let mut constraints = vec![];

    for c in input.constraints.iter() {
        constraints.push(proto_constraint_to_token_constraint(c)?);
    }

    Ok(Rule {
        head: proto_predicate_to_token_predicate(&input.head)?,
        body,
        constraints,
    })
}

pub fn token_predicate_to_proto_predicate(input: &Predicate) -> schema::Predicate {
    schema::Predicate {
        name: input.name,
        ids: input.ids.iter().map(token_id_to_proto_id).collect(),
    }
}

pub fn proto_predicate_to_token_predicate(
    input: &schema::Predicate,
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

pub fn token_id_to_proto_id(input: &ID) -> schema::Id {
    use schema::id::Kind;

    match input {
        ID::Symbol(s) => schema::Id {
            kind: Kind::Symbol as i32,
            symbol: Some(*s),
            variable: None,
            integer: None,
            str: None,
            date: None,
        },
        ID::Variable(v) => schema::Id {
            kind: Kind::Variable as i32,
            symbol: None,
            variable: Some(*v),
            integer: None,
            str: None,
            date: None,
        },
        ID::Integer(i) => schema::Id {
            kind: Kind::Integer as i32,
            symbol: None,
            variable: None,
            integer: Some(*i),
            str: None,
            date: None,
        },
        ID::Str(s) => schema::Id {
            kind: Kind::Str as i32,
            symbol: None,
            variable: None,
            integer: None,
            str: Some(s.clone()),
            date: None,
        },
        ID::Date(d) => schema::Id {
            kind: Kind::Date as i32,
            symbol: None,
            variable: None,
            integer: None,
            str: None,
            date: Some(*d),
        },
    }
}

pub fn proto_id_to_token_id(input: &schema::Id) -> Result<ID, error::Format> {
    use schema::id::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid id kind"
        )));
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
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid id"
    )))
}

pub fn token_constraint_to_proto_constraint(input: &Constraint) -> schema::Constraint {
    use schema::constraint::Kind;

    match input.kind {
        ConstraintKind::Int(ref c) => schema::Constraint {
            id: input.id,
            kind: Kind::Int as i32,
            int: Some(token_int_constraint_to_proto_int_constraint(c)),
            str: None,
            date: None,
            symbol: None,
        },
        ConstraintKind::Str(ref c) => schema::Constraint {
            id: input.id,
            kind: Kind::String as i32,
            int: None,
            str: Some(token_str_constraint_to_proto_str_constraint(c)),
            date: None,
            symbol: None,
        },
        ConstraintKind::Date(ref c) => schema::Constraint {
            id: input.id,
            kind: Kind::Date as i32,
            int: None,
            str: None,
            date: Some(token_date_constraint_to_proto_date_constraint(c)),
            symbol: None,
        },
        ConstraintKind::Symbol(ref c) => schema::Constraint {
            id: input.id,
            kind: Kind::Date as i32,
            int: None,
            str: None,
            date: None,
            symbol: Some(token_symbol_constraint_to_proto_symbol_constraint(c)),
        },
    }
}

pub fn proto_constraint_to_token_constraint(
    input: &schema::Constraint,
) -> Result<Constraint, error::Format> {
    use schema::constraint::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid constraint kind"
        )));
    };

    match kind {
        Kind::Int => {
            if let Some(ref i) = input.int {
                return proto_int_constraint_to_token_int_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Int(c),
                });
            }
        }
        Kind::String => {
            if let Some(ref i) = input.str {
                return proto_str_constraint_to_token_str_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Str(c),
                });
            }
        }
        Kind::Date => {
            if let Some(ref i) = input.date {
                return proto_date_constraint_to_token_date_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Date(c),
                });
            }
        }
        Kind::Symbol => {
            if let Some(ref i) = input.symbol {
                return proto_symbol_constraint_to_token_symbol_constraint(i).map(|c| Constraint {
                    id: input.id,
                    kind: ConstraintKind::Symbol(c),
                });
            }
        }
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid constraint"
    )))
}

pub fn token_int_constraint_to_proto_int_constraint(
    input: &IntConstraint,
) -> schema::IntConstraint {
    use schema::int_constraint::Kind;

    match input {
        IntConstraint::Lower(i) => schema::IntConstraint {
            kind: Kind::Lower as i32,
            lower: Some(*i),
            larger: None,
            lower_or_equal: None,
            larger_or_equal: None,
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        IntConstraint::Larger(i) => schema::IntConstraint {
            kind: Kind::Larger as i32,
            lower: None,
            larger: Some(*i),
            lower_or_equal: None,
            larger_or_equal: None,
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        IntConstraint::LowerOrEqual(i) => schema::IntConstraint {
            kind: Kind::LowerOrEqual as i32,
            lower: None,
            larger: None,
            lower_or_equal: Some(*i),
            larger_or_equal: None,
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        IntConstraint::LargerOrEqual(i) => schema::IntConstraint {
            kind: Kind::LargerOrEqual as i32,
            lower: None,
            larger: None,
            lower_or_equal: None,
            larger_or_equal: Some(*i),
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        IntConstraint::Equal(i) => schema::IntConstraint {
            kind: Kind::Equal as i32,
            lower: None,
            larger: None,
            lower_or_equal: None,
            larger_or_equal: None,
            equal: Some(*i),
            in_set: vec![],
            not_in_set: vec![],
        },
        IntConstraint::In(s) => schema::IntConstraint {
            kind: Kind::In as i32,
            lower: None,
            larger: None,
            lower_or_equal: None,
            larger_or_equal: None,
            equal: None,
            in_set: s.iter().cloned().collect(),
            not_in_set: vec![],
        },
        IntConstraint::NotIn(s) => schema::IntConstraint {
            kind: Kind::NotIn as i32,
            lower: None,
            larger: None,
            lower_or_equal: None,
            larger_or_equal: None,
            equal: None,
            in_set: vec![],
            not_in_set: s.iter().cloned().collect(),
        },
    }
}

pub fn proto_int_constraint_to_token_int_constraint(
    input: &schema::IntConstraint,
) -> Result<IntConstraint, error::Format> {
    use schema::int_constraint::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid int constraint kind"
        )));
    };

    match kind {
        Kind::Lower => {
            if let Some(i) = input.lower {
                return Ok(IntConstraint::Lower(i));
            }
        }
        Kind::Larger => {
            if let Some(i) = input.larger {
                return Ok(IntConstraint::Larger(i));
            }
        }
        Kind::LowerOrEqual => {
            if let Some(i) = input.lower_or_equal {
                return Ok(IntConstraint::LowerOrEqual(i));
            }
        }
        Kind::LargerOrEqual => {
            if let Some(i) = input.larger_or_equal {
                return Ok(IntConstraint::LargerOrEqual(i));
            }
        }
        Kind::Equal => {
            if let Some(i) = input.equal {
                return Ok(IntConstraint::Equal(i));
            }
        }
        Kind::In => {
            if !input.in_set.is_empty() {
                return Ok(IntConstraint::In(input.in_set.iter().cloned().collect()));
            }
        }
        Kind::NotIn => {
            if !input.not_in_set.is_empty() {
                return Ok(IntConstraint::NotIn(
                    input.not_in_set.iter().cloned().collect(),
                ));
            }
        }
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid id"
    )))
}

pub fn token_str_constraint_to_proto_str_constraint(
    input: &StrConstraint,
) -> schema::StringConstraint {
    use schema::string_constraint::Kind;

    match input {
        StrConstraint::Prefix(s) => schema::StringConstraint {
            kind: Kind::Prefix as i32,
            prefix: Some(s.clone()),
            suffix: None,
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        StrConstraint::Suffix(s) => schema::StringConstraint {
            kind: Kind::Suffix as i32,
            prefix: None,
            suffix: Some(s.clone()),
            equal: None,
            in_set: vec![],
            not_in_set: vec![],
        },
        StrConstraint::Equal(s) => schema::StringConstraint {
            kind: Kind::Equal as i32,
            prefix: None,
            suffix: None,
            equal: Some(s.clone()),
            in_set: vec![],
            not_in_set: vec![],
        },
        StrConstraint::In(s) => schema::StringConstraint {
            kind: Kind::In as i32,
            prefix: None,
            suffix: None,
            equal: None,
            in_set: s.iter().cloned().collect(),
            not_in_set: vec![],
        },
        StrConstraint::NotIn(s) => schema::StringConstraint {
            kind: Kind::NotIn as i32,
            prefix: None,
            suffix: None,
            equal: None,
            in_set: vec![],
            not_in_set: s.iter().cloned().collect(),
        },
    }
}

pub fn proto_str_constraint_to_token_str_constraint(
    input: &schema::StringConstraint,
) -> Result<StrConstraint, error::Format> {
    use schema::string_constraint::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid string constraint kind"
        )));
    };

    match kind {
        Kind::Prefix => {
            if let Some(ref s) = input.prefix {
                return Ok(StrConstraint::Prefix(s.clone()));
            }
        }
        Kind::Suffix => {
            if let Some(ref s) = input.suffix {
                return Ok(StrConstraint::Suffix(s.clone()));
            }
        }
        Kind::Equal => {
            if let Some(ref s) = input.equal {
                return Ok(StrConstraint::Equal(s.clone()));
            }
        }
        Kind::In => {
            if !input.in_set.is_empty() {
                return Ok(StrConstraint::In(input.in_set.iter().cloned().collect()));
            }
        }
        Kind::NotIn => {
            if !input.not_in_set.is_empty() {
                return Ok(StrConstraint::NotIn(
                    input.not_in_set.iter().cloned().collect(),
                ));
            }
        }
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid string constraint"
    )))
}

pub fn token_date_constraint_to_proto_date_constraint(
    input: &DateConstraint,
) -> schema::DateConstraint {
    use schema::date_constraint::Kind;

    match input {
        DateConstraint::Before(i) => schema::DateConstraint {
            kind: Kind::Before as i32,
            before: Some(*i),
            after: None,
        },
        DateConstraint::After(i) => schema::DateConstraint {
            kind: Kind::After as i32,
            before: None,
            after: Some(*i),
        },
    }
}

pub fn proto_date_constraint_to_token_date_constraint(
    input: &schema::DateConstraint,
) -> Result<DateConstraint, error::Format> {
    use schema::date_constraint::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid date constraint kind"
        )));
    };

    match kind {
        Kind::Before => {
            if let Some(i) = input.before {
                return Ok(DateConstraint::Before(i));
            }
        }
        Kind::After => {
            if let Some(i) = input.after {
                return Ok(DateConstraint::After(i));
            }
        }
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid date constraint"
    )))
}

pub fn token_symbol_constraint_to_proto_symbol_constraint(
    input: &SymbolConstraint,
) -> schema::SymbolConstraint {
    use schema::symbol_constraint::Kind;

    match input {
        SymbolConstraint::In(s) => schema::SymbolConstraint {
            kind: Kind::In as i32,
            in_set: s.iter().cloned().collect(),
            not_in_set: vec![],
        },
        SymbolConstraint::NotIn(s) => schema::SymbolConstraint {
            kind: Kind::NotIn as i32,
            in_set: vec![],
            not_in_set: s.iter().cloned().collect(),
        },
    }
}

pub fn proto_symbol_constraint_to_token_symbol_constraint(
    input: &schema::SymbolConstraint,
) -> Result<SymbolConstraint, error::Format> {
    use schema::symbol_constraint::Kind;

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(format!(
            "deserialization error: invalid symbol constraint kind"
        )));
    };

    match kind {
        Kind::In => {
            if !input.in_set.is_empty() {
                return Ok(SymbolConstraint::In(input.in_set.iter().cloned().collect()));
            }
        }
        Kind::NotIn => {
            if !input.not_in_set.is_empty() {
                return Ok(SymbolConstraint::NotIn(
                    input.not_in_set.iter().cloned().collect(),
                ));
            }
        }
    }

    Err(error::Format::DeserializationError(format!(
        "deserialization error: invalid symbol constraint"
    )))
}
