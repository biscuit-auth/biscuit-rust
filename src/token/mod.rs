//! main structures to interact with Biscuit tokens
use super::crypto::{KeyPair, PublicKey};
use super::datalog::{Fact, Rule, SymbolTable, World, ID};
use super::error;
use super::format::SerializedBiscuit;
use builder::{BiscuitBuilder, BlockBuilder};
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use std::collections::{HashMap, HashSet};

use crate::format::{convert::proto_block_to_token_block, schema};
use verifier::Verifier;

pub mod builder;
pub mod sealed;
pub mod verifier;

/// some symbols are predefined and available in every implementation, to avoid
/// transmitting them with every token
pub fn default_symbol_table() -> SymbolTable {
    let mut syms = SymbolTable::new();
    syms.insert("authority");
    syms.insert("ambient");
    syms.insert("resource");
    syms.insert("operation");
    syms.insert("right");
    syms.insert("current_time");
    syms.insert("revocation_id");

    syms
}

/// This structure represents a valid Biscuit token
///
/// It contains multiple `Block` elements, the associated symbol table,
/// and a serialized version of this data
///
/// ```rust
/// extern crate rand;
/// extern crate biscuit;
///
/// use biscuit::{crypto::KeyPair, token::{Biscuit, builder::*}};
///
/// fn main() {
///   let mut rng = rand::thread_rng();
///
///   let root = KeyPair::new(&mut rng);
///
///   // first we define the authority block for global data,
///   // like access rights
///   // data from the authority block cannot be created in any other block
///   let mut builder = Biscuit::builder(&mut rng, &root);
///   builder.add_authority_fact(&fact("right", &[s("authority"), string("/a/file1.txt"), s("read")]));
///
///   let token1 = builder.build().unwrap();
///
///   // we can create a new block builder from that token
///   let mut builder2 = token1.create_block();
///   builder2.check_operation("read");
///
///   let keypair2 = KeyPair::new(&mut rng);
///   let token2 = token1.append(&mut rng, &keypair2, builder2.build()).unwrap();
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Biscuit {
    authority: Block,
    blocks: Vec<Block>,
    symbols: SymbolTable,
    container: Option<SerializedBiscuit>,
}

impl Biscuit {
    /// creates a new token
    ///
    /// the public part of the root keypair must be used for verification
    ///
    /// The block is an authority block: its index must be 0 and all of its facts must have the authority tag
    pub fn new<T: RngCore + CryptoRng>(
        rng: &mut T,
        root: &KeyPair,
        mut symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit, error::Token> {
        let h1 = symbols.symbols.iter().collect::<HashSet<_>>();
        let h2 = authority.symbols.symbols.iter().collect::<HashSet<_>>();

        if !h1.is_disjoint(&h2) {
            return Err(error::Token::SymbolTableOverlap);
        }

        if authority.index as usize != 0 {
            return Err(error::Token::InvalidAuthorityIndex(authority.index));
        }

        symbols
            .symbols
            .extend(authority.symbols.symbols.iter().cloned());

        let blocks = vec![];

        let container =
            SerializedBiscuit::new(rng, root, &authority).map_err(error::Token::Format)?;

        Ok(Biscuit {
            authority,
            blocks,
            symbols,
            container: Some(container),
        })
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from(slice: &[u8]) -> Result<Self, error::Token> {
      Biscuit::from_with_symbols(slice, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    pub fn from_with_symbols(slice: &[u8], mut symbols: SymbolTable) -> Result<Self, error::Token> {
        let container = SerializedBiscuit::from_slice(slice).map_err(error::Token::Format)?;

        let authority: Block = schema::Block::decode(&container.authority)
            .map_err(|e| {
                error::Token::Format(error::Format::BlockDeserializationError(format!(
                    "error deserializing authority block: {:?}",
                    e
                )))
            })
            .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

        if authority.index != 0 {
            return Err(error::Token::InvalidAuthorityIndex(authority.index));
        }

        let mut blocks = vec![];

        let mut index = 1;
        for block in container.blocks.iter() {
            let deser: Block = schema::Block::decode(block)
                .map_err(|e| {
                    error::Token::Format(error::Format::BlockDeserializationError(format!(
                        "error deserializing block: {:?}",
                        e
                    )))
                })
                .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

            if deser.index != index {
                return Err(error::Token::InvalidBlockIndex(error::InvalidBlockIndex {
                    expected: index,
                    found: deser.index,
                }));
            }
            blocks.push(deser);

            index += 1;
        }

        symbols
            .symbols
            .extend(authority.symbols.symbols.iter().cloned());

        for block in blocks.iter() {
            symbols
                .symbols
                .extend(block.symbols.symbols.iter().cloned());
        }

        let container = Some(container);

        Ok(Biscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a sealed token and checks its signature with the secret, using a custom symbol table
    pub fn from_sealed(slice: &[u8], secret: &[u8]) -> Result<Self, error::Token> {
      Biscuit::from_sealed_with_symbols(slice, secret, default_symbol_table())
    }

    /// deserializes a sealed token and checks its signature with the secret
    pub fn from_sealed_with_symbols(slice: &[u8], secret: &[u8], mut symbols: SymbolTable) -> Result<Self, error::Token> {
        let container =
            sealed::SealedBiscuit::from_slice(slice, secret).map_err(error::Token::Format)?;

        let authority: Block = schema::Block::decode(container.authority)
            .map_err(|e| {
                error::Token::Format(error::Format::BlockDeserializationError(format!(
                    "error deserializing authority block: {:?}",
                    e
                )))
            })
            .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

        if authority.index != 0 {
            return Err(error::Token::InvalidAuthorityIndex(authority.index));
        }

        let mut blocks = vec![];

        let mut index = 1;
        for block in container.blocks.iter() {
            let deser: Block = schema::Block::decode(block)
                .map_err(|e| {
                    error::Token::Format(error::Format::BlockDeserializationError(format!(
                        "error deserializing block: {:?}",
                        e
                    )))
                })
                .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

            if deser.index != index {
                return Err(error::Token::InvalidBlockIndex(error::InvalidBlockIndex {
                    expected: index,
                    found: deser.index,
                }));
            }
            blocks.push(deser);

            index += 1;
        }

        symbols
            .symbols
            .extend(authority.symbols.symbols.iter().cloned());

        for block in blocks.iter() {
            symbols
                .symbols
                .extend(block.symbols.symbols.iter().cloned());
        }

        let container = None;

        Ok(Biscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        match self.container.as_ref() {
            None => Err(error::Token::InternalError),
            Some(c) => c.to_vec().map_err(error::Token::Format),
        }
    }

    /// serializes a sealed version of the token
    pub fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, error::Token> {
        let sealed =
            sealed::SealedBiscuit::from_token(self, secret).map_err(error::Token::Format)?;
        sealed.to_vec().map_err(error::Token::Format)
    }

    /// returns the internal representation of the token
    pub fn container(&self) -> Option<&SerializedBiscuit> {
        self.container.as_ref()
    }

    pub fn check_root_key(&self, root: PublicKey) -> Result<(), error::Token> {
        self.container
            .as_ref()
            .map(|c| c.check_root_key(root).map_err(error::Token::Format))
            .unwrap_or(Err(error::Token::Sealed))?;
        Ok(())
    }

    pub fn verify(&self, root: PublicKey) -> Result<Verifier, error::Token> {
        self.check_root_key(root)?;

        Ok(Verifier::new(self))
    }

    pub fn verify_sealed(&self) -> Result<Verifier, error::Token> {
        if self.container.is_some() {
            Err(error::Token::InternalError)
        } else {
            Ok(Verifier::new(self))
        }
    }

    /// checks the caveats of a token, in the context of the request it comes with
    ///
    /// the verifier provides ambient facts (that must carry the "ambient" tag) like
    /// which resource is requested, which operation, the current time, etc
    ///
    /// those ambient facts can also be generated by the provided ambient rules
    ///
    /// the verifier can also provide its own caveats to validate the content of the token.
    /// Verifier caveats can either apply on the "authority" part (they will be tested once
    /// in the entire token), while block level caveast will be tested once per block.
    ///
    /// the symbol table argument is generated from the token's symbol table, adding
    /// new symbols as needed from ambient facts and rules
    ///
    /// if successful, it returns answers to the verifier queries as a HashMap indexed
    /// by the query name. Each query result contains a HashMap of block id -> Vec of Facts
    pub(crate) fn check(
        &self,
        symbols: &SymbolTable,
        mut ambient_facts: Vec<Fact>,
        ambient_rules: Vec<Rule>,
        authority_caveats: Vec<Rule>,
        block_caveats: Vec<Rule>,
        queries: HashMap<String, Rule>,
    ) -> Result<HashMap<String, HashMap<u32, Vec<Fact>>>, error::Logic> {
        let mut world = World::new();

        let authority_index = symbols.get("authority").unwrap();
        let ambient_index = symbols.get("ambient").unwrap();

        for fact in self.authority.facts.iter().cloned() {
            if fact.predicate.ids[0] != ID::Symbol(authority_index) {
                return Err(error::Logic::InvalidAuthorityFact(
                    symbols.print_fact(&fact),
                ));
            }

            world.facts.insert(fact);
        }

        for rule in self.authority.rules.iter().cloned() {
            world.rules.push(rule);
        }

        world.run();

        for fact in world.facts.iter() {
            // FIXME: check that facts have at least one element in the predicate
            if fact.predicate.ids[0] != ID::Symbol(authority_index) {
                return Err(error::Logic::InvalidAuthorityFact(
                    symbols.print_fact(&fact),
                ));
            }
        }

        //remove authority rules: we cannot create facts anymore in authority scope
        //w.rules.clear();

        for fact in ambient_facts.drain(..) {
            if fact.predicate.ids[0] != ID::Symbol(ambient_index) {
                return Err(error::Logic::InvalidAmbientFact(symbols.print_fact(&fact)));
            }

            world.facts.insert(fact);
        }

        for rule in ambient_rules.iter().cloned() {
            world.rules.push(rule);
        }

        world.run();

        // we only keep the verifier rules
        world.rules = ambient_rules;

        let mut errors = vec![];

        // authority caveats provided by the authority block
        for (i, caveat) in self.authority.caveats.iter().enumerate() {
            let res = world.query_rule(caveat.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Block(error::FailedBlockCaveat {
                    block_id: 0,
                    caveat_id: i as u32,
                    rule: symbols.print_rule(caveat),
                }));
            }
        }

        // authority level caveats provided by the verifier
        for (i, caveat) in authority_caveats.iter().enumerate() {
            let res = world.query_rule(caveat.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    block_id: 0,
                    caveat_id: i as u32,
                    rule: symbols.print_rule(caveat),
                }));
            }
        }

        let mut query_results = HashMap::new();
        for (name, rule) in queries.iter() {
          let res = world.query_rule(rule.clone());
          if !res.is_empty() {
            let entry = query_results.entry(name.clone()).or_insert_with(HashMap::new);
            (*entry).insert(0, res);
          }
        }

        for (i, block) in self.blocks.iter().enumerate() {
            let w = world.clone();

            if let Err(e) = block.check(i, w, symbols, &block_caveats, &queries, &mut query_results) {
                match e {
                    error::Logic::FailedCaveats(mut e) => errors.extend(e.drain(..)),
                    e => return Err(e),
                }
            }
        }

        if errors.is_empty() {
            Ok(query_results)
        } else {
            Err(error::Logic::FailedCaveats(errors))
        }
    }

    pub fn builder<'a, 'b, R: RngCore + CryptoRng>(
        rng: &'a mut R,
        root: &'b KeyPair,
    ) -> BiscuitBuilder<'a, 'b, R> {
        Biscuit::builder_with_symbols(rng, root, default_symbol_table())
    }

    pub fn builder_with_symbols<'a, 'b, R: RngCore + CryptoRng>(
        rng: &'a mut R,
        root: &'b KeyPair,
        symbols: SymbolTable,
    ) -> BiscuitBuilder<'a, 'b, R> {
        BiscuitBuilder::new(rng, root, symbols)
    }

    /// creates a new block builder
    pub fn create_block(&self) -> BlockBuilder {
        BlockBuilder::new((1 + self.blocks.len()) as u32, self.symbols.clone())
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        keypair: &KeyPair,
        block: Block,
    ) -> Result<Self, error::Token> {
        if self.container.is_none() {
            return Err(error::Token::Sealed);
        }

        let h1 = self.symbols.symbols.iter().collect::<HashSet<_>>();
        let h2 = block.symbols.symbols.iter().collect::<HashSet<_>>();

        if !h1.is_disjoint(&h2) {
            return Err(error::Token::SymbolTableOverlap);
        }

        if block.index as usize != 1 + self.blocks.len() {
            return Err(error::Token::InvalidBlockIndex(error::InvalidBlockIndex {
                expected: 1 + self.blocks.len() as u32,
                found: block.index,
            }));
        }

        let authority = self.authority.clone();
        let mut blocks = self.blocks.clone();
        let mut symbols = self.symbols.clone();

        let container = match self.container.as_ref() {
            None => return Err(error::Token::Sealed),
            Some(c) => c
                .append(rng, keypair, &block)
                .map_err(error::Token::Format)?,
        };

        symbols
            .symbols
            .extend(block.symbols.symbols.iter().cloned());
        blocks.push(block);

        Ok(Biscuit {
            authority,
            blocks,
            symbols,
            container: Some(container),
        })
    }

    /// pretty printer for this token
    pub fn print(&self) -> String {
        let authority = print_block(&self.symbols, &self.authority);
        let blocks: Vec<_> = self
            .blocks
            .iter()
            .map(|b| print_block(&self.symbols, b))
            .collect();

        format!(
            "Biscuit {{\n\tsymbols: {:?}\n\tauthority:\n{}\n\tblocks: [\n\t\t{}]\n}}",
            self.symbols.symbols,
            authority,
            blocks.join(",\n\t")
        )
    }
}

fn print_block(symbols: &SymbolTable, block: &Block) -> String {
    let facts: Vec<_> = block.facts.iter().map(|f| symbols.print_fact(f)).collect();
    let rules: Vec<_> = block.rules.iter().map(|r| symbols.print_rule(r)).collect();
    let caveats: Vec<_> = block
        .caveats
        .iter()
        .map(|r| symbols.print_rule(r))
        .collect();

    format!(
        "Block[{}] {{\n\t\tsymbols: {:?}\n\t\tfacts: [\n\t\t\t{}]\n\t\trules:[\n\t\t\t{}]\n\t\tcaveats:[\n\t\t\t{}]\n}}",
        block.index,
        block.symbols.symbols,
        facts.join(",\n\t\t\t"),
        rules.join(",\n\t\t\t"),
        caveats.join(",\n\t\t\t"),
    )
}

#[derive(Clone, Debug)]
pub struct Block {
    /// position of the block
    pub index: u32,
    /// list of symbols introduced by this block
    pub symbols: SymbolTable,
    /// list of facts provided by this block
    pub facts: Vec<Fact>,
    /// list of rules provided by this block
    pub rules: Vec<Rule>,
    /// caveats that the token and ambient data must validate
    pub caveats: Vec<Rule>,
    /// contextual information that can be looked up before the verification
    /// (as an example, a user id to query rights into a database)
    pub context: Option<String>,
}

impl Block {
    /// creates a new block
    ///
    /// blocks should be created through the BlockBuilder interface instead, to avoid mistakes
    pub fn new(index: u32, base_symbols: SymbolTable) -> Block {
        Block {
            index,
            symbols: base_symbols,
            facts: vec![],
            rules: vec![],
            caveats: vec![],
            context: None,
        }
    }

    pub fn symbol_add(&mut self, s: &str) -> ID {
        self.symbols.add(s)
    }

    pub fn symbol_insert(&mut self, s: &str) -> u64 {
        self.symbols.insert(s)
    }

    pub fn check(
        &self,
        i: usize,
        mut world: World,
        symbols: &SymbolTable,
        verifier_caveats: &[Rule],
        queries: &HashMap<String, Rule>,
        query_results: &mut HashMap<String, HashMap<u32, Vec<Fact>>>,
    ) -> Result<(), error::Logic> {
        let authority_index = symbols.get("authority").unwrap();
        let ambient_index = symbols.get("ambient").unwrap();

        for fact in self.facts.iter().cloned() {
            if fact.predicate.ids[0] == ID::Symbol(authority_index)
                || fact.predicate.ids[0] == ID::Symbol(ambient_index)
            {
                return Err(error::Logic::InvalidBlockFact(
                    i as u32,
                    symbols.print_fact(&fact),
                ));
            }

            world.facts.insert(fact);
        }

        for rule in self.rules.iter().cloned() {
            world.rules.push(rule);
        }

        world.run();

        let mut errors = vec![];
        for (j, caveat) in self.caveats.iter().enumerate() {
            let res = world.query_rule(caveat.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Block(error::FailedBlockCaveat {
                    block_id: i as u32,
                    caveat_id: j as u32,
                    rule: symbols.print_rule(caveat),
                }));
            }
        }

        for (j, caveat) in verifier_caveats.iter().enumerate() {
            let res = world.query_rule(caveat.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    block_id: i as u32,
                    caveat_id: j as u32,
                    rule: symbols.print_rule(caveat),
                }));
            }
        }

        for (name, rule) in queries.iter() {
          let res = world.query_rule(rule.clone());
          if !res.is_empty() {
            let entry = query_results.entry(name.clone()).or_insert_with(HashMap::new);
            (*entry).insert(i as u32, res);
          }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(error::Logic::FailedCaveats(errors))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{fact, pred, rule, s, var, int};
    use super::*;
    use crate::crypto::KeyPair;
    use crate::error::*;
    use rand::prelude::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn basic() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);

        let serialized1 = {
            let mut builder = Biscuit::builder(&mut rng, &root);

            builder.add_authority_fact(&fact("right", &[s("authority"), s("file1"), s("read")]));
            builder.add_authority_fact(&fact("right", &[s("authority"), s("file2"), s("read")]));
            builder.add_authority_fact(&fact("right", &[s("authority"), s("file1"), s("write")]));

            let biscuit1 = builder.build().unwrap();

            println!("biscuit1 (authority): {}", biscuit1.print());

            biscuit1.to_vec().unwrap()
        };

        //println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));
        println!("generated biscuit token: {} bytes", serialized1.len());
        //panic!();

        /*
        for i in 0..9 {
            let biscuit1_deser = Biscuit::from(&serialized1, root.public).unwrap();

            // new caveat: can only have read access1
            let mut block2 = biscuit1_deser.create_block();

            block2.add_caveat(&rule(
                "caveat1",
                &[var(0)],
                &[
                    pred("resource", &[s("ambient"), var(0)]),
                    pred("operation", &[s("ambient"), s("read")]),
                    pred("right", &[s("authority"), var(0), s("read")]),
                ],
            ));

            let keypair2 = KeyPair::new(&mut rng);
            let biscuit2 = biscuit1_deser.append(&keypair2, block2.to_block()).unwrap();

            println!("biscuit2 (1 caveat): {}", biscuit2.print());

            serialized1 = biscuit2.to_vec().unwrap();

        }
        println!("generated biscuit token 2: {} bytes", serialized1.len());
        panic!();
        */

        let serialized2 = {
            let biscuit1_deser = Biscuit::from(&serialized1).unwrap();

            // new caveat: can only have read access1
            let mut block2 = biscuit1_deser.create_block();

            block2.add_caveat(&rule(
                "caveat1",
                &[var(0)],
                &[
                    pred("resource", &[s("ambient"), var(0)]),
                    pred("operation", &[s("ambient"), s("read")]),
                    pred("right", &[s("authority"), var(0), s("read")]),
                ],
            ));

            let keypair2 = KeyPair::new(&mut rng);
            let biscuit2 = biscuit1_deser
                .append(&mut rng, &keypair2, block2.build())
                .unwrap();

            println!("biscuit2 (1 caveat): {}", biscuit2.print());

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let serialized3 = {
            let biscuit2_deser = Biscuit::from(&serialized2).unwrap();

            // new caveat: can only access file1
            let mut block3 = biscuit2_deser.create_block();

            block3.add_caveat(&rule(
                "caveat2",
                &[s("file1")],
                &[pred("resource", &[s("ambient"), s("file1")])],
            ));

            let keypair3 = KeyPair::new(&mut rng);
            let biscuit3 = biscuit2_deser
                .append(&mut rng, &keypair3, block3.build())
                .unwrap();

            biscuit3.to_vec().unwrap()
        };

        //println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));
        println!("generated biscuit token 3: {} bytes", serialized3.len());
        //panic!();

        let final_token = Biscuit::from(&serialized3).unwrap();
        final_token.check_root_key(root.public()).unwrap();
        println!("final token:\n{}", final_token.print());
        {
            let mut symbols = final_token.symbols.clone();

            let facts = vec![
                fact("resource", &[s("ambient"), s("file1")]),
                fact("operation", &[s("ambient"), s("read")]),
            ];
            let mut ambient_facts = vec![];

            for fact in facts.iter() {
                ambient_facts.push(fact.convert(&mut symbols));
            }

            //println!("final token: {:#?}", final_token);
            //println!("ambient facts: {:#?}", ambient_facts);
            let res = final_token.check(&symbols, ambient_facts, vec![], vec![], vec![], HashMap::new());
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut symbols = final_token.symbols.clone();

            let facts = vec![
                fact("resource", &[s("ambient"), s("file2")]),
                fact("operation", &[s("ambient"), s("write")]),
            ];
            let mut ambient_facts = vec![];

            for fact in facts.iter() {
                ambient_facts.push(fact.convert(&mut symbols));
            }

            let res = final_token.check(&symbols, ambient_facts, vec![], vec![], vec![], HashMap::new());
            println!("res2: {:#?}", res);
            assert_eq!(res,
              Err(Logic::FailedCaveats(vec![
                FailedCaveat::Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: String::from("caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ") }),
                FailedCaveat::Block(FailedBlockCaveat { block_id: 1, caveat_id: 0, rule: String::from("caveat2(#file1) <- resource(#ambient, #file1) | ") })
              ])));
        }
    }

    #[test]
    fn folders() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);

        let mut builder = Biscuit::builder(&mut rng, &root);

        builder.add_right("/folder1/file1", "read");
        builder.add_right("/folder1/file1", "write");
        builder.add_right("/folder1/file2", "read");
        builder.add_right("/folder1/file2", "write");
        builder.add_right("/folder2/file3", "read");

        let biscuit1 = builder.build().unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.build())
            .unwrap();

        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("/folder1/file1");
            verifier.add_operation("read");

            let res = verifier.verify();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("/folder2/file3");
            verifier.add_operation("read");

            let res = verifier.verify();
            println!("res2: {:?}", res);
            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::FailedCaveats(vec![FailedCaveat::Block(
                    FailedBlockCaveat {
                        block_id: 0,
                        caveat_id: 0,
                        rule: String::from(
                            "prefix(0?) <- resource(#ambient, 0?) | 0? matches /folder1/*"
                        )
                    }
                ),])))
            );
        }

        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("/folder2/file1");
            verifier.add_operation("write");

            let res = verifier.verify();
            println!("res3: {:?}", res);
            assert_eq!(res,
              Err(Token::FailedLogic(Logic::FailedCaveats(vec![
                FailedCaveat::Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: String::from("prefix(0?) <- resource(#ambient, 0?) | 0? matches /folder1/*") }),
                FailedCaveat::Block(FailedBlockCaveat { block_id: 0, caveat_id: 1, rule: String::from("check_right(#read) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ") }),
              ]))));
        }
    }

    #[test]
    fn constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);

        let mut builder = Biscuit::builder(&mut rng, &root);

        builder.add_right("file1", "read");
        builder.add_right("file2", "read");

        let biscuit1 = builder.build().unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.expiration_date(SystemTime::now() + Duration::from_secs(30));
        block2.revocation_id(1234);

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.build())
            .unwrap();

        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("file1");
            verifier.add_operation("read");
            verifier.set_time();

            let res = verifier.verify();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("file1");
            verifier.add_operation("read");
            verifier.set_time();
            verifier.revocation_check(&[0, 1, 2, 5, 1234]);

            let res = verifier.verify();
            println!("res3: {:?}", res);

            // error message should be like this:
            //"Verifier caveat 0 failed: revocation_check(0?) <- revocation_id(0?) | 0? not in {2, 1234, 1, 5, 0}"
            assert!(res.is_err());
        }
    }

    #[test]
    fn sealed_token() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);
        let mut builder = Biscuit::builder(&mut rng, &root);

        builder.add_right("/folder1/file1", "read");
        builder.add_right("/folder1/file1", "write");
        builder.add_right("/folder1/file2", "read");
        builder.add_right("/folder1/file2", "write");
        builder.add_right("/folder2/file3", "read");

        let biscuit1 = builder.build().unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.build())
            .unwrap();

        //println!("biscuit2:\n{:#?}", biscuit2);
        //panic!();
        {
            let mut verifier = biscuit2.verify(root.public()).unwrap();
            verifier.add_resource("/folder1/file1");
            verifier.add_operation("read");

            let res = verifier.verify();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        let _serialized = biscuit2.to_vec().unwrap();
        //println!("biscuit2 serialized ({} bytes):\n{}", serialized.len(), serialized.to_hex(16));

        let secret = b"secret key";
        let sealed = biscuit2.seal(&secret[..]).unwrap();
        //println!("biscuit2 sealed ({} bytes):\n{}", sealed.len(), sealed.to_hex(16));

        let biscuit3 = Biscuit::from_sealed(&sealed, &secret[..]).unwrap();

        {
            let mut verifier = biscuit3.verify_sealed().unwrap();
            verifier.add_resource("/folder1/file1");
            verifier.add_operation("read");

            let res = verifier.verify();
            println!("res1: {:?}", res);
            res.unwrap();
        }
    }

    #[test]
    fn verif_no_blocks() {
      use crate::token::builder::*;

      let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
      let root = KeyPair::new(&mut rng);

      let mut builder = Biscuit::builder(&mut rng, &root);

      builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("read")]));
      builder.add_authority_fact(&fact("right", &[s("authority"), string("file2"), s("read")]));
      builder.add_authority_fact(&fact("right", &[s("authority"), string("file1"), s("write")]));

      let biscuit1 = builder.build().unwrap();
      println!("{}", biscuit1.print());

      let mut v = biscuit1.verify(root.public()).expect("omg verifier");

      v.add_authority_caveat(rule("right",
          &[s("right")],
          &[pred("right", &[s("authority"), string("file2"), s("write")])]
      ));

      //assert!(v.verify().is_err());
      let res = v.verify();
      println!("res: {:?}", res);
      assert_eq!(res,
        Err(Token::FailedLogic(Logic::FailedCaveats(vec![
          FailedCaveat::Verifier(FailedVerifierCaveat { block_id: 0, caveat_id: 0, rule: String::from("right(#right) <- right(#authority, \"file2\", #write) | ") }),
      ]))));
    }

    #[test]
    fn verifier_queries() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);

        let mut builder = Biscuit::builder(&mut rng, &root);

        builder.add_right("file1", "read");
        builder.add_right("file2", "read");

        let biscuit1 = builder.build().unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.expiration_date(SystemTime::now() + Duration::from_secs(30));
        block2.revocation_id(1234);

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.build())
            .unwrap();

        let mut block3 = biscuit2.create_block();

        block3.expiration_date(SystemTime::now() + Duration::from_secs(10));
        block3.revocation_id(5678);

        let keypair3 = KeyPair::new(&mut rng);
        let biscuit3 = biscuit2
            .append(&mut rng, &keypair3, block3.build())
            .unwrap();
        {
            let mut verifier = biscuit3.verify(root.public()).unwrap();
            verifier.add_resource("file1");
            verifier.add_operation("read");
            verifier.set_time();
            verifier.add_query("revocation_ids", rule(
                "revocation_id_verif",
                &[builder::Atom::Variable(0)],
                &[pred("revocation_id", &[builder::Atom::Variable(0)])]
            ));

            let res = verifier.verify();
            println!("res1: {:?}", res);
            assert_eq!(
              res.unwrap().get("revocation_ids").unwrap(),
              &[
                (0, vec![fact("revocation_id_verif", &[int(1234)])]),
                (1, vec![fact("revocation_id_verif", &[int(5678)])]),
              ].iter().cloned().collect()
            );
        }
    }

}
