use std::collections::{BTreeMap, HashMap};

use crate::{
    builder::{Check, Convert, Fact, Rule},
    datalog::Origin,
    error,
    format::{
        convert::v2::{
            policy_to_proto_policy, token_check_to_proto_check, token_fact_to_proto_fact,
            token_rule_to_proto_rule,
        },
        schema::{self, SnapshotChecks, SnapshotFacts, SnapshotRules},
    },
    token::MAX_SCHEMA_VERSION,
};

impl super::Authorizer {
    pub fn from_snapshot(data: schema::AuthorizerSnapshot) -> Result<Self, error::Format> {
        todo!()
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
        for ruleset in self.world.rules.inner.values() {
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
