use std::collections::{BTreeMap, HashMap};

use crate::{
    builder::{Check, Convert, Fact, Rule},
    datalog::{Origin, SymbolTable},
    error,
    format::{
        convert::v2::{
            policy_to_proto_policy, proto_check_to_token_check, proto_fact_to_token_fact,
            proto_policy_to_policy, proto_rule_to_token_rule, token_check_to_proto_check,
            token_fact_to_proto_fact, token_rule_to_proto_rule,
        },
        schema::{self, SnapshotChecks, SnapshotFacts, SnapshotRules},
    },
    token::{MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION},
    PublicKey,
};

impl super::Authorizer {
    pub fn from_snapshot(input: schema::AuthorizerSnapshot) -> Result<Self, error::Format> {
        let version = input.version.unwrap_or(0);
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
            return Err(error::Format::Version {
                minimum: crate::token::MIN_SCHEMA_VERSION,
                maximum: crate::token::MAX_SCHEMA_VERSION,
                actual: version,
            });
        }

        let input_symbols = SymbolTable::from(input.symbols.clone())?;
        let mut authorizer = super::Authorizer::new();
        authorizer.symbols = input_symbols;

        /*
        for (key_id, block_ids) in &token.public_key_to_block_id {
            let key = token
                .symbols
                .public_keys
                .get_key(*key_id as u64)
                .ok_or(error::Format::UnknownExternalKey)?;
            let new_key_id = self.symbols.public_keys.insert(key);

            self.public_key_to_block_id
                .insert(new_key_id as usize, block_ids.clone());
        }
        */
        for schema::KeyMap { key, block_ids } in input.public_key_map {
            let new_key_id = authorizer
                .symbols
                .public_keys
                .insert(&PublicKey::from_proto(&key)?);
            authorizer.public_key_to_block_id.insert(
                new_key_id as usize,
                block_ids.into_iter().map(|id| id as usize).collect(),
            );
        }

        for SnapshotFacts { origins, facts } in input.facts {
            let origin = proto_origin_to_authorizer_origin(&origins)?;

            for fact in &facts {
                authorizer
                    .world
                    .facts
                    .insert(&origin, proto_fact_to_token_fact(fact)?);
            }
        }

        for SnapshotRules { origin, rules } in input.rules {
            //let origin = proto_origin_to_authorizer_origin(&origins)?;

            for rule in rules {
                let (rule, scopes) = proto_rule_to_token_rule(&rule, version)?;
                let rule = Rule::convert_from(&rule, &input_symbols)?;
            }
        }

        for SnapshotChecks { origin, checks } in input.checks {
            //let origin = proto_origin_to_authorizer_origin(&origins)?;

            for check in checks {
                let check = proto_check_to_token_check(&check, version)?;
                let check = Rule::convert_from(&check, &input_symbols)?;
            }
        }

        for policy in input.policies {
            authorizer
                .policies
                .push(proto_policy_to_policy(&policy, &input_symbols, version)?);
        }

        Ok(authorizer)
    }

    pub fn snapshot(&self) -> schema::AuthorizerSnapshot {
        let mut symbols = self.symbols.clone();
        let facts: Vec<schema::SnapshotFacts> = self
            .world
            .facts
            .inner
            .iter()
            .map(|(origin, facts)| SnapshotFacts {
                origins: authorizer_origin_to_proto_origin(origin),
                facts: facts.iter().map(token_fact_to_proto_fact).collect(),
            })
            .collect();

        let mut rules_map: BTreeMap<usize, Vec<_>> = BTreeMap::new();
        for (trusted_origins, ruleset) in self.world.rules.iter_all() {
            for (origin, rule) in ruleset {
                rules_map.entry(*origin).or_default().push(rule);
            }
        }

        let rules: Vec<schema::SnapshotRules> = rules_map
            .iter()
            .map(|(origin, rules)| SnapshotRules {
                origin: if *origin == usize::MAX {
                    schema::Origin {
                        authorizer: Some(true),
                        origin: None,
                    }
                } else {
                    schema::Origin {
                        authorizer: None,
                        origin: Some(*origin as u32),
                    }
                },
                rules: rules.iter().map(|r| token_rule_to_proto_rule(*r)).collect(),
            })
            .collect();

        let mut checks: Vec<schema::SnapshotChecks> = Vec::new();

        if !self.authorizer_block_builder.checks.is_empty() {
            let origin = schema::Origin {
                authorizer: Some(true),
                origin: None,
            };

            checks.push(SnapshotChecks {
                origin,
                checks: self
                    .authorizer_block_builder
                    .checks
                    .iter()
                    .map(|c| c.convert(&mut symbols))
                    .map(|c| token_check_to_proto_check(&c))
                    .collect(),
            });
        }

        if let Some(blocks) = &self.blocks {
            for (i, block) in blocks.iter().enumerate() {
                if !block.checks.is_empty() {
                    let origin = schema::Origin {
                        authorizer: None,
                        origin: Some(i as u32),
                    };

                    checks.push(SnapshotChecks {
                        origin,
                        checks: block
                            .checks
                            .iter()
                            .map(|c| token_check_to_proto_check(&c))
                            .collect(),
                    });
                }
            }
        }

        let policies = self
            .policies
            .iter()
            .map(|policy| policy_to_proto_policy(policy, &mut symbols))
            .collect();
        schema::AuthorizerSnapshot {
            symbols: symbols.strings(),
            version: Some(MAX_SCHEMA_VERSION),
            facts,
            rules,
            checks,
            policies,
        }
    }
}

fn authorizer_origin_to_proto_origin(origin: &Origin) -> Vec<schema::Origin> {
    origin
        .inner
        .iter()
        .map(|o| {
            if *o == usize::MAX {
                schema::Origin {
                    authorizer: Some(true),
                    origin: None,
                }
            } else {
                schema::Origin {
                    authorizer: None,
                    origin: Some(*o as u32),
                }
            }
        })
        .collect()
}

fn proto_origin_to_authorizer_origin(origins: &[schema::Origin]) -> Result<Origin, error::Format> {
    let mut new_origin = Origin::default();

    for schema::Origin { authorizer, origin } in origins {
        match (authorizer, origin) {
            (Some(true), None) => new_origin.insert(usize::MAX),
            (_, Some(o)) => new_origin.insert(*o as usize),
            _ => {
                return Err(error::Format::DeserializationError(
                    "invalid origin".to_string(),
                ))
            }
        }
    }

    Ok(new_origin)
}
