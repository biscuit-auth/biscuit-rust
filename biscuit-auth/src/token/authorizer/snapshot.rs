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
        for public_key in input.public_keys {
            symbols
                .public_keys
                .insert(&PublicKey::from_proto(&public_key)?);
        }

        let authorizer_block = proto_snapshot_block_to_token_block(&input.authorizer_block)?;

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

        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut blocks = Vec::new();
        for (i, block) in input.blocks.iter().enumerate() {
            let token_symbols = if block.external_key.is_none() {
                authorizer.symbols.clone()
            } else {
                let mut token_symbols = authorizer.symbols.clone();
                token_symbols.public_keys = authorizer.symbols.public_keys.clone();
                token_symbols
            };

            let mut block = proto_snapshot_block_to_token_block(block)?;

            if let Some(key) = block.external_key.as_ref() {
                public_key_to_block_id
                    .entry(authorizer.symbols.public_keys.insert(key) as usize)
                    .or_default()
                    .push(i);
            }

            authorizer.add_block(&mut block, i, &token_symbols)?;
            blocks.push(block);
        }

        authorizer.public_key_to_block_id = public_key_to_block_id;

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

        Ok(schema::AuthorizerSnapshot {
            version: Some(MAX_SCHEMA_VERSION),
            symbols: symbols.strings(),
            public_keys: symbols
                .public_keys
                .into_inner()
                .into_iter()
                .map(|key| key.to_proto())
                .collect(),
            blocks,
            authorizer_block,
            generated_facts,
            policies,
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
