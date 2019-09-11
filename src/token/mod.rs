use super::crypto::KeyPair;
use super::datalog::{Fact, Rule, SymbolTable, World, ID};
use super::error;
use super::format::SerializedBiscuit;
use builder::BlockBuilder;
use curve25519_dalek::ristretto::RistrettoPoint;
use prost::Message;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;

use crate::format::{convert::proto_block_to_token_block, schema};

pub mod builder;
pub mod sealed;
pub mod verifier;

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

#[derive(Clone, Debug)]
pub struct Biscuit {
    authority: Block,
    blocks: Vec<Block>,
    symbols: SymbolTable,
    container: Option<SerializedBiscuit>,
}

impl Biscuit {
    pub fn new<T: Rng + CryptoRng>(
        rng: &mut T,
        root: &KeyPair,
        authority: &Block,
    ) -> Result<Biscuit, error::Token> {
        let authority = authority.clone();

        let mut symbols = default_symbol_table();
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

    pub fn from(slice: &[u8], root: RistrettoPoint) -> Result<Self, error::Token> {
        let container = SerializedBiscuit::from_slice(slice, root).map_err(error::Token::Format)?;

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

        let mut symbols = default_symbol_table();
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

    pub fn from_sealed(slice: &[u8], secret: &[u8]) -> Result<Self, error::Token> {
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

        let mut symbols = default_symbol_table();
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

    pub fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        match self.container.as_ref() {
            None => Err(error::Token::InternalError),
            Some(c) => c.to_vec().map_err(error::Token::Format),
        }
    }

    pub fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, error::Token> {
        let sealed =
            sealed::SealedBiscuit::from_token(self, secret).map_err(error::Token::Format)?;
        sealed.to_vec().map_err(error::Token::Format)
    }

    pub fn container(&self) -> Option<&SerializedBiscuit> {
      self.container.as_ref()
    }

    pub fn check(
        &self,
        symbols: &SymbolTable,
        mut ambient_facts: Vec<Fact>,
        ambient_rules: Vec<Rule>,
        ambient_caveats: Vec<Rule>,
    ) -> Result<(), error::Logic> {
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

        // autority caveats are actually rules
        for rule in self.authority.caveats.iter().cloned() {
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
                return Err(error::Logic::InvalidAmbientFact(
                    symbols.print_fact(&fact),
                ));
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
        for (i, block) in self.blocks.iter().enumerate() {
            let w = world.clone();

            match block.check(i, w, symbols, &ambient_caveats) {
                Err(e) => match e {
                    error::Logic::FailedCaveats(mut e) => errors.extend(e.drain(..)),
                    e => return Err(e),
                },
                Ok(_) => {}
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(error::Logic::FailedCaveats(errors))
        }
    }

    pub fn create_block(&self) -> BlockBuilder {
        BlockBuilder::new((1 + self.blocks.len()) as u32, self.symbols.clone())
    }

    pub fn append<T: Rng + CryptoRng>(
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

    pub fn adjust_authority_symbols(block: &mut Block) {
        let base_symbols = default_symbol_table();

        let new_syms = block.symbols.symbols.split_off(base_symbols.symbols.len());

        block.symbols.symbols = new_syms;
    }

    pub fn adjust_block_symbols(&self, block: &mut Block) {
        let new_syms = block.symbols.symbols.split_off(self.symbols.symbols.len());

        block.symbols.symbols = new_syms;
    }

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
    let rules: Vec<_> = block
        .caveats
        .iter()
        .map(|r| symbols.print_rule(r))
        .collect();

    format!(
        "Block[{}] {{\n\t\tsymbols: {:?}\n\t\tfacts: [\n\t\t\t{}]\n\t\trules:[\n\t\t\t{}]\n}}",
        block.index,
        block.symbols.symbols,
        facts.join(",\n\t\t\t"),
        rules.join(",\n\t\t\t")
    )
}

#[derive(Clone, Debug)]
pub struct Block {
    pub index: u32,
    pub symbols: SymbolTable,
    pub facts: Vec<Fact>,
    pub caveats: Vec<Rule>,
}

impl Block {
    pub fn new(index: u32, base_symbols: SymbolTable) -> Block {
        Block {
            index,
            symbols: base_symbols,
            facts: vec![],
            caveats: vec![],
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

        for (i, caveat) in verifier_caveats.iter().enumerate() {
            let res = world.query_rule(caveat.clone());
            if res.is_empty() {
                errors.push(error::FailedCaveat::Verifier(error::FailedVerifierCaveat {
                    caveat_id: i as u32,
                    rule: symbols.print_rule(caveat),
                }));
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
    use super::builder::{fact, pred, rule, s, var, BlockBuilder};
    use super::verifier::Verifier;
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
            let symbols = default_symbol_table();
            let mut authority_block = BlockBuilder::new(0, symbols);

            authority_block.add_fact(&fact("right", &[s("authority"), s("file1"), s("read")]));
            authority_block.add_fact(&fact("right", &[s("authority"), s("file2"), s("read")]));
            authority_block.add_fact(&fact("right", &[s("authority"), s("file1"), s("write")]));

            let biscuit1 = Biscuit::new(&mut rng, &root, &authority_block.to_block()).unwrap();

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
            let biscuit2 = biscuit1_deser
                .append(&mut rng, &keypair2, block2.to_block())
                .unwrap();

            println!("biscuit2 (1 caveat): {}", biscuit2.print());

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let serialized3 = {
            let biscuit2_deser = Biscuit::from(&serialized2, root.public).unwrap();

            // new caveat: can only access file1
            let mut block3 = biscuit2_deser.create_block();

            block3.add_caveat(&rule(
                "caveat2",
                &[s("file1")],
                &[pred("resource", &[s("ambient"), s("file1")])],
            ));

            let keypair3 = KeyPair::new(&mut rng);
            let biscuit3 = biscuit2_deser
                .append(&mut rng, &keypair3, block3.clone().to_block())
                .unwrap();

            biscuit3.to_vec().unwrap()
        };

        //println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));
        println!("generated biscuit token 3: {} bytes", serialized3.len());
        //panic!();

        let final_token = Biscuit::from(&serialized3, root.public).unwrap();
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
            let res = final_token.check(&symbols, ambient_facts, vec![], vec![]);
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

            let res = final_token.check(&symbols, ambient_facts, vec![], vec![]);
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

        let symbols = default_symbol_table();
        let mut authority_block = BlockBuilder::new(0, symbols);

        authority_block.add_right("/folder1/file1", "read");
        authority_block.add_right("/folder1/file1", "write");
        authority_block.add_right("/folder1/file2", "read");
        authority_block.add_right("/folder1/file2", "write");
        authority_block.add_right("/folder2/file3", "read");

        let biscuit1 = Biscuit::new(&mut rng, &root, &authority_block.to_block()).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.to_block())
            .unwrap();

        {
            let mut verifier = Verifier::new();
            verifier.resource("/folder1/file1");
            verifier.operation("read");

            let res = verifier.verify(biscuit2.clone());
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut verifier = Verifier::new();
            verifier.resource("/folder2/file3");
            verifier.operation("read");

            let res = verifier.verify(biscuit2.clone());
            println!("res2: {:?}", res);
            assert_eq!(
                res,
                Err(Logic::FailedCaveats(vec![FailedCaveat::Block(
                    FailedBlockCaveat {
                        block_id: 0,
                        caveat_id: 0,
                        rule: String::from(
                            "prefix(0?) <- resource(#ambient, 0?) | 0? matches /folder1/*"
                        )
                    }
                ),]))
            );
        }

        {
            let mut verifier = Verifier::new();
            verifier.resource("/folder2/file1");
            verifier.operation("write");

            let res = verifier.verify(biscuit2.clone());
            println!("res3: {:?}", res);
            assert_eq!(res,
              Err(Logic::FailedCaveats(vec![
                FailedCaveat::Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: String::from("prefix(0?) <- resource(#ambient, 0?) | 0? matches /folder1/*") }),
                FailedCaveat::Block(FailedBlockCaveat { block_id: 0, caveat_id: 1, rule: String::from("check_right(#read) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ") }),
              ])));
        }
    }

    #[test]
    fn constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new(&mut rng);

        let symbols = default_symbol_table();
        let mut authority_block = BlockBuilder::new(0, symbols);

        authority_block.add_right("file1", "read");
        authority_block.add_right("file2", "read");

        let biscuit1 = Biscuit::new(&mut rng, &root, &authority_block.to_block()).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.expiration_date(SystemTime::now() + Duration::from_secs(30));
        block2.revocation_id(1234);

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.to_block())
            .unwrap();

        {
            let mut verifier = Verifier::new();
            verifier.resource("file1");
            verifier.operation("read");
            verifier.time();

            let res = verifier.verify(biscuit2.clone());
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut verifier = Verifier::new();
            verifier.resource("file1");
            verifier.operation("read");
            verifier.time();
            verifier.revocation_check(&[0, 1, 2, 5, 1234]);

            let res = verifier.verify(biscuit2.clone());
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

        let symbols = default_symbol_table();
        let mut authority_block = BlockBuilder::new(0, symbols);

        authority_block.add_right("/folder1/file1", "read");
        authority_block.add_right("/folder1/file1", "write");
        authority_block.add_right("/folder1/file2", "read");
        authority_block.add_right("/folder1/file2", "write");
        authority_block.add_right("/folder2/file3", "read");

        let biscuit1 = Biscuit::new(&mut rng, &root, &authority_block.to_block()).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new(&mut rng);
        let biscuit2 = biscuit1
            .append(&mut rng, &keypair2, block2.to_block())
            .unwrap();

        //println!("biscuit2:\n{:#?}", biscuit2);
        //panic!();
        {
            let mut verifier = Verifier::new();
            verifier.resource("/folder1/file1");
            verifier.operation("read");

            let res = verifier.verify(biscuit2.clone());
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
            let mut verifier = Verifier::new();
            verifier.resource("/folder1/file1");
            verifier.operation("read");

            let res = verifier.verify(biscuit3.clone());
            println!("res1: {:?}", res);
            res.unwrap();
        }
    }
}
