use std::collections::HashMap;

use crate::{
    builder::{BlockBuilder, Convert, Policy},
    datalog::{Origin, TrustedOrigins},
    error,
    format::{
        convert::{
            proto_snapshot_block_to_token_block, token_block_to_proto_snapshot_block,
            v2::{
                policy_to_proto_policy, proto_fact_to_token_fact, proto_policy_to_policy,
                token_fact_to_proto_fact,
            },
        },
        schema::{self, GeneratedFacts},
    },
    token::{default_symbol_table, MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION},
    PublicKey,
};

impl super::Authorizer {
    pub fn from_snapshot(input: schema::AuthorizerSnapshot) -> Result<Self, error::Token> {
        let version = input.version.unwrap_or(0);
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
            return Err(error::Format::Version {
                minimum: crate::token::MIN_SCHEMA_VERSION,
                maximum: crate::token::MAX_SCHEMA_VERSION,
                actual: version,
            }
            .into());
        }

        let mut symbols = default_symbol_table();
        for symbol in input.symbols {
            symbols.insert(&symbol);
        }

        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut external_keys: HashMap<usize, PublicKey> = HashMap::new();
        for schema::KeyMap { key, block_ids } in input.public_key_map {
            let public_key = PublicKey::from_proto(&key)?;
            let new_key_id = symbols.public_keys.insert(&public_key);

            for id in &block_ids {
                external_keys.insert(*id as usize, public_key);
            }

            public_key_to_block_id.insert(
                new_key_id as usize,
                block_ids.into_iter().map(|id| id as usize).collect(),
            );
        }

        let authorizer_block = proto_snapshot_block_to_token_block(&input.authorizer_block, None)?;

        let authorizer_block_builder = BlockBuilder::convert_from(&authorizer_block, &symbols)?;
        let policies = input
            .policies
            .iter()
            .map(|policy| proto_policy_to_policy(&policy, &symbols, version))
            .collect::<Result<Vec<Policy>, error::Format>>()?;

        let mut authorizer = super::Authorizer::new();
        authorizer.symbols = symbols;
        authorizer.authorizer_block_builder = authorizer_block_builder;
        authorizer.policies = policies;
        authorizer.public_key_to_block_id = public_key_to_block_id;

        let mut blocks = Vec::new();
        for (i, block) in input.blocks.iter().enumerate() {
            let token_symbols = if external_keys.get(&i).is_none() {
                authorizer.symbols.clone()
            } else {
                let mut token_symbols = authorizer.symbols.clone();
                token_symbols.public_keys = authorizer.symbols.public_keys.clone();
                token_symbols
            };

            let mut block =
                proto_snapshot_block_to_token_block(block, external_keys.get(&i).cloned())?;

            authorizer.add_block(&mut block, i, &token_symbols)?;

            blocks.push(block);
        }

        if !blocks.is_empty() {
            authorizer.token_origins = TrustedOrigins::from_scopes(
                &[crate::token::Scope::Previous],
                &TrustedOrigins::default(),
                blocks.len(),
                &authorizer.public_key_to_block_id,
            );
            authorizer.blocks = Some(blocks);
        }

        for GeneratedFacts { origins, facts } in input.generated_facts {
            let origin = proto_origin_to_authorizer_origin(&origins)?;

            for fact in &facts {
                let fact = proto_fact_to_token_fact(fact)?;
                //let fact = Fact::convert_from(&fact, &symbols)?.convert(&mut authorizer.symbols);
                authorizer.world.facts.insert(&origin, fact);
            }
        }

        Ok(authorizer)
    }

    pub fn snapshot(&self) -> Result<schema::AuthorizerSnapshot, error::Format> {
        let mut symbols = default_symbol_table();

        let policies = self
            .policies
            .iter()
            .map(|policy| policy_to_proto_policy(policy, &mut symbols))
            .collect();

        let authorizer_block = self.authorizer_block_builder.clone().build(symbols.clone());
        symbols.extend(&authorizer_block.symbols)?;
        symbols.public_keys.extend(&authorizer_block.public_keys)?;

        println!("will serialize authorizer block: {:?}", authorizer_block);
        let authorizer_block = token_block_to_proto_snapshot_block(&authorizer_block);

        let blocks = match self.blocks.as_ref() {
            None => Vec::new(),
            Some(blocks) => blocks
                .iter()
                .map(|block| {
                    block
                        .translate(&self.symbols, &mut symbols)
                        .map(|block| token_block_to_proto_snapshot_block(&block))
                })
                .collect::<Result<Vec<_>, error::Format>>()?,
        };

        let generated_facts = self
            .world
            .facts
            .inner
            .iter()
            .map(|(origin, facts)| {
                Ok(GeneratedFacts {
                    origins: authorizer_origin_to_proto_origin(origin),
                    facts: facts
                        .iter()
                        .map(|fact| {
                            Ok(token_fact_to_proto_fact(
                                &crate::builder::Fact::convert_from(fact, &self.symbols)?
                                    .convert(&mut symbols),
                            ))
                        })
                        .collect::<Result<Vec<_>, error::Format>>()?,
                })
            })
            .collect::<Result<Vec<GeneratedFacts>, error::Format>>()?;

        let mut public_key_map = Vec::new();
        for (key_id, key) in self.symbols.public_keys.keys.iter().enumerate() {
            let block_ids = self
                .public_key_to_block_id
                .get(&key_id)
                .map(|ids| ids.iter().map(|id| *id as u32).collect())
                .unwrap_or_default();

            public_key_map.push(schema::KeyMap {
                key: key.to_proto(),
                block_ids,
            });
        }

        Ok(schema::AuthorizerSnapshot {
            version: Some(MAX_SCHEMA_VERSION),
            symbols: symbols.strings(),
            blocks,
            authorizer_block,
            generated_facts,
            policies,
            public_key_map,
        })
    }
}

fn authorizer_origin_to_proto_origin(origin: &Origin) -> Vec<schema::Origin> {
    origin
        .inner
        .iter()
        .map(|o| {
            if *o == usize::MAX {
                schema::Origin {
                    content: Some(schema::origin::Content::Authorizer(true)),
                }
            } else {
                schema::Origin {
                    content: Some(schema::origin::Content::Origin(*o as u32)),
                }
            }
        })
        .collect()
}

fn proto_origin_to_authorizer_origin(origins: &[schema::Origin]) -> Result<Origin, error::Format> {
    let mut new_origin = Origin::default();

    for origin in origins {
        match origin.content {
            Some(schema::origin::Content::Authorizer(true)) => new_origin.insert(usize::MAX),
            Some(schema::origin::Content::Origin(o)) => new_origin.insert(o as usize),
            _ => {
                return Err(error::Format::DeserializationError(
                    "invalid origin".to_string(),
                ))
            }
        }
    }

    Ok(new_origin)
}
