//! main structures to interact with Biscuit tokens
use std::collections::{BTreeSet, HashMap};

use self::public_keys::PublicKeys;
use super::crypto::{KeyPair, PublicKey};
use super::datalog::SymbolTable;
use super::error;
use super::format::SerializedBiscuit;
use builder::{BiscuitBuilder, BlockBuilder};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

use crate::format::convert::proto_block_to_token_block;
use crate::format::schema;
use authorizer::Authorizer;

pub mod authorizer;
pub(crate) mod block;
pub mod builder;
pub(crate) mod public_keys;
pub mod unverified;

pub use block::Block;

/// minimum supported version of the serialization format
pub const MIN_SCHEMA_VERSION: u32 = 3;
/// maximum supported version of the serialization format
pub const MAX_SCHEMA_VERSION: u32 = 3;

/// some symbols are predefined and available in every implementation, to avoid
/// transmitting them with every token
pub fn default_symbol_table() -> SymbolTable {
    SymbolTable::new()
}

/// This structure represents a valid Biscuit token
///
/// It contains multiple `Block` elements, the associated symbol table,
/// and a serialized version of this data
///
/// ```rust
/// extern crate biscuit_auth as biscuit;
///
/// use biscuit::{KeyPair, Biscuit, builder::*};
///
/// fn main() {
///   let root = KeyPair::new();
///
///   // first we define the authority block for global data,
///   // like access rights
///   // data from the authority block cannot be created in any other block
///   let mut builder = Biscuit::builder(&root);
///   builder.add_authority_fact(fact("right", &[string("/a/file1.txt"), string("read")]));
///
///   // facts and rules can also be parsed from a string
///   builder.add_authority_fact("right(\"/a/file1.txt\", \"read\")").expect("parse error");
///
///   let token1 = builder.build().unwrap();
///
///   // we can create a new block builder from that token
///   let mut builder2 = token1.create_block();
///   builder2.check_operation("read");
///
///   let token2 = token1.append(builder2).unwrap();
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Biscuit {
    pub(crate) root_key_id: Option<u32>,
    pub(crate) authority: schema::Block,
    pub(crate) blocks: Vec<schema::Block>,
    pub(crate) symbols: SymbolTable,
    pub(crate) public_keys: PublicKeys,
    pub(crate) container: SerializedBiscuit,
}

impl Biscuit {
    /// create the first block's builder
    ///
    /// call [`builder::BiscuitBuilder::build`] to create the token
    pub fn builder(root: &KeyPair) -> BiscuitBuilder {
        Biscuit::builder_with_symbols(root, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from<T, F>(slice: T, f: F) -> Result<Self, error::Token>
    where
        F: Fn(Option<u32>) -> PublicKey,
        T: AsRef<[u8]>,
    {
        Biscuit::from_with_symbols(slice.as_ref(), f, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from_base64<T, F>(slice: T, f: F) -> Result<Self, error::Token>
    where
        F: Fn(Option<u32>) -> PublicKey,
        T: AsRef<[u8]>,
    {
        Biscuit::from_base64_with_symbols(slice, f, default_symbol_table())
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        self.container.to_vec().map_err(error::Token::Format)
    }

    /// serializes the token and encode it to a (URL safe) base64 string
    pub fn to_base64(&self) -> Result<String, error::Token> {
        self.container
            .to_vec()
            .map_err(error::Token::Format)
            .map(|v| base64::encode_config(v, base64::URL_SAFE))
    }

    /// serializes the token
    pub fn serialized_size(&self) -> Result<usize, error::Token> {
        Ok(self.container.serialized_size())
    }

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<Biscuit, error::Token> {
        let container = self.container.seal()?;

        let mut token = self.clone();
        token.container = container;

        Ok(token)
    }

    /// creates a authorizer from this token
    pub fn authorizer(&self) -> Result<Authorizer, error::Token> {
        Authorizer::from_token(self)
    }

    /// runs authorization with the provided authorizer
    pub fn authorize<'t>(&self, authorizer: &Authorizer) -> Result<usize, error::Token> {
        let mut a = authorizer.clone();
        a.add_token(self)?;
        a.authorize()
    }

    /// creates a new block builder
    pub fn create_block(&self) -> BlockBuilder {
        BlockBuilder::new()
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        let keypair = KeyPair::new_with_rng(&mut rand::rngs::OsRng);
        self.append_with_keypair(&keypair, block_builder)
    }

    /// returns the list of context elements of each block
    ///
    /// the context is a free form text field in which application specific data
    /// can be stored
    pub fn context(&self) -> Vec<Option<String>> {
        let mut res = vec![self.authority.context.clone()];

        for b in self.blocks.iter() {
            res.push(b.context.clone());
        }

        res
    }

    /// returns a list of revocation identifiers for each block, in order
    ///
    /// if a token is generated with the same keys and the same content,
    /// those identifiers will stay the same
    pub fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        let mut res = Vec::new();

        res.push(self.container.authority.signature.to_bytes().to_vec());

        for block in self.container.blocks.iter() {
            res.push(block.signature.to_bytes().to_vec());
        }

        res
    }

    /// pretty printer for this token
    pub fn print(&self) -> String {
        //FIXME: must handle the unwrap here
        let authority = print_block(&self.symbols, &self.authorizer_block(0).unwrap());
        let blocks: Vec<_> = (1..self.block_count())
            .map(|i| print_block(&self.symbols, &self.authorizer_block(i).unwrap()))
            .collect();

        format!(
            "Biscuit {{\n    symbols: {:?}\n    public keys: {:?}\n    authority: {}\n    blocks: [\n        {}\n    ]\n}}",
            self.symbols.strings(),
            self.public_keys.keys.iter().map(|pk| hex::encode(pk.to_bytes())).collect::<Vec<_>>(),
            authority,
            blocks.join(",\n\t")
        )
    }

    /// prints the content of a block as Datalog source code
    pub fn print_block_source(&self, index: usize) -> Option<String> {
        //FIXME: must handle the unwrap here
        let block = self.authorizer_block(index).unwrap();

        Some(block.print_source(&self.symbols))
    }

    /// create the first block's builder, sing a provided symbol table
    fn builder_with_symbols(root: &KeyPair, symbols: SymbolTable) -> BiscuitBuilder {
        BiscuitBuilder::new(root, symbols)
    }

    /// creates a new token, using a provided CSPRNG
    ///
    /// the public part of the root keypair must be used for verification
    pub(crate) fn new_with_rng<T: RngCore + CryptoRng>(
        rng: &mut T,
        root_key_id: Option<u32>,
        root: &KeyPair,
        mut symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit, error::Token> {
        if !symbols.is_disjoint(&authority.symbols) {
            return Err(error::Token::SymbolTableOverlap);
        }

        symbols.extend(&authority.symbols);

        let blocks = vec![];

        let next_keypair = KeyPair::new_with_rng(rng);
        let container = SerializedBiscuit::new(root_key_id, root, &next_keypair, &authority)?;

        let authority = schema::Block::decode(&container.authority.data[..]).map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing block: {:?}",
                e
            )))
        })?;

        Ok(Biscuit {
            root_key_id,
            authority,
            blocks,
            symbols,
            container,
            public_keys: PublicKeys::new(),
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    fn from_with_symbols<F>(slice: &[u8], f: F, symbols: SymbolTable) -> Result<Self, error::Token>
    where
        F: Fn(Option<u32>) -> PublicKey,
    {
        let container = SerializedBiscuit::from_slice(slice, f).map_err(error::Token::Format)?;

        Biscuit::from_serialized_container(container, symbols)
    }

    fn from_serialized_container(
        container: SerializedBiscuit,
        mut symbols: SymbolTable,
    ) -> Result<Self, error::Token> {
        let (authority, blocks, public_keys) = container.extract_blocks(&mut symbols)?;

        let root_key_id = container.root_key_id;

        Ok(Biscuit {
            root_key_id,
            authority,
            blocks,
            symbols,
            container,
            public_keys,
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    fn from_base64_with_symbols<T, F>(
        slice: T,
        f: F,
        symbols: SymbolTable,
    ) -> Result<Self, error::Token>
    where
        F: Fn(Option<u32>) -> PublicKey,
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Biscuit::from_with_symbols(&decoded, f, symbols)
    }

    /// returns the internal representation of the token
    pub fn container(&self) -> &SerializedBiscuit {
        &self.container
    }

    /// adds a new block to the token, using the provided CSPRNG
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append_with_keypair(
        &self,
        keypair: &KeyPair,
        block_builder: BlockBuilder,
    ) -> Result<Self, error::Token> {
        let block = block_builder.build(self.symbols.clone());

        if !self.symbols.is_disjoint(&block.symbols) {
            return Err(error::Token::SymbolTableOverlap);
        }

        let authority = self.authority.clone();
        let mut blocks = self.blocks.clone();
        let mut symbols = self.symbols.clone();
        let mut public_keys = self.public_keys.clone();

        let container = self.container.append(keypair, &block)?;

        symbols.extend(&block.symbols);
        //FIXME: should we show an error if a key is already known?
        for key in &block.public_keys.keys {
            public_keys.insert(&key);
        }
        let deser = schema::Block::decode(
            &container
                .blocks
                .last()
                .expect("a new block was just added so the list is not empty")
                .data[..],
        )
        .map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing block: {:?}",
                e
            )))
        })?;
        blocks.push(deser);

        Ok(Biscuit {
            root_key_id: self.root_key_id,
            authority,
            blocks,
            symbols,
            public_keys,
            container,
        })
    }

    /// gets the list of symbols from a block
    pub fn block_symbols(&self, index: usize) -> Option<Vec<String>> {
        let block = if index == 0 {
            &self.authority
        } else {
            match self.blocks.get(index - 1) {
                None => return None,
                Some(block) => block,
            }
        };

        Some(block.symbols.clone())
    }

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        1 + self.blocks.len()
    }

    pub(crate) fn authorizer_block(&self, index: usize) -> Result<Block, error::Token> {
        if index == 0 {
            proto_block_to_token_block(
                &self.authority,
                self.container
                    .authority
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format)
        } else {
            if index > self.blocks.len() + 1 {
                return Err(error::Token::Format(
                    error::Format::BlockDeserializationError("invalid block index".to_string()),
                ));
            }

            proto_block_to_token_block(
                &self.blocks[index - 1],
                self.container.blocks[index - 1]
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format)
        }
    }
}

fn print_block(symbols: &SymbolTable, block: &Block) -> String {
    let facts: Vec<_> = block.facts.iter().map(|f| symbols.print_fact(f)).collect();
    let rules: Vec<_> = block.rules.iter().map(|r| symbols.print_rule(r)).collect();
    let checks: Vec<_> = block
        .checks
        .iter()
        .map(|r| symbols.print_check(r))
        .collect();

    let facts = if facts.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            facts.join(",\n                ")
        )
    };
    let rules = if rules.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            rules.join(",\n                ")
        )
    };
    let checks = if checks.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            checks.join(",\n                ")
        )
    };

    format!(
        "Block {{\n            symbols: {:?}\n            version: {}\n            context: \"{}\"\n            external key: {}\n            public keys: {:?}\n            scopes: {:?}\n            facts: [{}]\n            rules: [{}]\n            checks: [{}]\n        }}",
        block.symbols.strings(),
        block.version,
        block.context.as_deref().unwrap_or(""),
        block.external_key.as_ref().map(|k| hex::encode(k.to_bytes())).unwrap_or_else(String::new),
        block.public_keys.keys.iter().map(|k | hex::encode(k.to_bytes())).collect::<Vec<_>>(),
        block.scopes,
        facts,
        rules,
        checks,
    )
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    Authority,
    Previous,
    // index of the public key in the token's list
    PublicKey(u64),
}

#[cfg(test)]
mod tests {
    use super::builder::{check, fact, pred, rule, string, var};
    use super::*;
    use crate::crypto::KeyPair;
    use crate::error::*;
    use rand::prelude::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn basic() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let serialized1 = {
            let mut builder = Biscuit::builder(&root);

            builder
                .add_authority_fact("right(\"file1\", \"read\")")
                .unwrap();
            builder
                .add_authority_fact("right(\"file2\", \"read\")")
                .unwrap();
            builder
                .add_authority_fact("right(\"file1\", \"write\")")
                .unwrap();

            let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

            println!("biscuit1 (authority): {}", biscuit1.print());

            biscuit1.to_vec().unwrap()
        };

        //println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));
        println!("generated biscuit token: {} bytes", serialized1.len());
        //panic!();

        /*
        for i in 0..9 {
            let biscuit1_deser = Biscuit::from(&serialized1, root.public).unwrap();

            // new check: can only have read access1
            let mut block2 = biscuit1_deser.create_block();

            block2.add_check(&rule(
                "check1",
                &[var(0)],
                &[
                    pred("resource", &[var(0)]),
                    pred("operation", &[string("read")]),
                    pred("right", &[var(0), string("read")]),
                ],
            ));

            let keypair2 = KeyPair::new_with_rng(&mut rng);
            let biscuit2 = biscuit1_deser.append(&keypair2, block2.to_block()).unwrap();

            println!("biscuit2 (1 check): {}", biscuit2.print());

            serialized1 = biscuit2.to_vec().unwrap();

        }
        println!("generated biscuit token 2: {} bytes", serialized1.len());
        panic!();
        */

        let serialized2 = {
            let biscuit1_deser = Biscuit::from(&serialized1, |_| root.public()).unwrap();

            // new check: can only have read access1
            let mut block2 = biscuit1_deser.create_block();

            block2
                .add_check(rule(
                    "check1",
                    &[var("resource")],
                    &[
                        pred("resource", &[var("resource")]),
                        pred("operation", &[string("read")]),
                        pred("right", &[var("resource"), string("read")]),
                    ],
                ))
                .unwrap();

            let keypair2 = KeyPair::new_with_rng(&mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_keypair(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {}", biscuit2.print());

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let serialized3 = {
            let biscuit2_deser = Biscuit::from(&serialized2, |_| root.public()).unwrap();

            // new check: can only access file1
            let mut block3 = biscuit2_deser.create_block();

            block3
                .add_check(rule(
                    "check2",
                    &[string("file1")],
                    &[pred("resource", &[string("file1")])],
                ))
                .unwrap();

            let keypair3 = KeyPair::new_with_rng(&mut rng);
            let biscuit3 = biscuit2_deser
                .append_with_keypair(&keypair3, block3)
                .unwrap();

            biscuit3.to_vec().unwrap()
        };

        //println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));
        println!("generated biscuit token 3: {} bytes", serialized3.len());
        //panic!();

        let final_token = Biscuit::from(&serialized3, |_| root.public()).unwrap();
        println!("final token:\n{}", final_token.print());
        {
            let mut authorizer = final_token.authorizer().unwrap();

            let mut facts = vec![
                fact("resource", &[string("file1")]),
                fact("operation", &[string("read")]),
            ];

            for fact in facts.drain(..) {
                authorizer.add_fact(fact).unwrap();
            }

            //println!("final token: {:#?}", final_token);
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            let mut authorizer = final_token.authorizer().unwrap();

            let mut facts = vec![
                fact("resource", &[string("file2")]),
                fact("operation", &[string("write")]),
            ];

            for fact in facts.drain(..) {
                authorizer.add_fact(fact).unwrap();
            }

            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res2: {:#?}", res);
            assert_eq!(res,
              Err(Token::FailedLogic(Logic::Unauthorized {
                  policy: MatchedPolicy::Allow(0),
                  checks: vec![
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: String::from("check if resource($resource), operation(\"read\"), right($resource, \"read\")") }),
                FailedCheck::Block(FailedBlockCheck { block_id: 2, check_id: 0, rule: String::from("check if resource(\"file1\")") })
              ]
              })));
        }
    }

    #[test]
    fn folders() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder.add_right("/folder1/file1", "read");
        builder.add_right("/folder1/file1", "write");
        builder.add_right("/folder1/file2", "read");
        builder.add_right("/folder1/file2", "write");
        builder.add_right("/folder2/file3", "read");

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"/folder1/file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
            println!("authorizer:\n{}", authorizer.print_world());
            res.unwrap();
        }

        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"/folder2/file3\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res2: {:?}", res);
            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::Unauthorized {
                    policy: MatchedPolicy::Allow(0),
                    checks: vec![FailedCheck::Block(FailedBlockCheck {
                        block_id: 1,
                        check_id: 0,
                        rule: String::from(
                            "check if resource($resource), $resource.starts_with(\"/folder1/\")"
                        )
                    }),]
                }))
            );
        }

        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"/folder2/file1\")").unwrap();
            authorizer.add_fact("operation(\"write\")").unwrap();

            let res = authorizer.authorize();
            println!("res3: {:?}", res);
            assert_eq!(res,
              Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                  checks: vec![
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: String::from("check if resource($resource), $resource.starts_with(\"/folder1/\")") }),
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: String::from("check if resource($resource_name), operation(\"read\"), right($resource_name, \"read\")") }),
              ]})));
        }
    }

    #[test]
    fn constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder.add_right("file1", "read");
        builder.add_right("file2", "read");

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.expiration_date(SystemTime::now() + Duration::from_secs(30));
        block2.add_fact("key(1234)").unwrap();

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.set_time();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            println!("biscuit2: {}", biscuit2.print());
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.set_time();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res3: {:?}", res);

            // error message should be like this:
            //"authorizer check 0 failed: check if revocation_id($0), $0 not in [2, 1234, 1, 5, 0]"
            assert!(res.is_ok());
        }
    }

    #[test]
    fn sealed_token() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);
        let mut builder = Biscuit::builder(&root);

        builder.add_right("/folder1/file1", "read");
        builder.add_right("/folder1/file1", "write");
        builder.add_right("/folder1/file2", "read");
        builder.add_right("/folder1/file2", "write");
        builder.add_right("/folder2/file3", "read");

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.resource_prefix("/folder1/");
        block2.check_right("read");

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        //println!("biscuit2:\n{:#?}", biscuit2);
        //panic!();
        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"/folder1/file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
            res.unwrap();
        }

        let _serialized = biscuit2.to_vec().unwrap();
        //println!("biscuit2 serialized ({} bytes):\n{}", serialized.len(), serialized.to_hex(16));

        let sealed = biscuit2.seal().unwrap().to_vec().unwrap();
        //println!("biscuit2 sealed ({} bytes):\n{}", sealed.len(), sealed.to_hex(16));

        let biscuit3 = Biscuit::from(&sealed, |_| root.public()).unwrap();

        {
            let mut authorizer = biscuit3.authorizer().unwrap();
            authorizer.add_fact("resource(\"/folder1/file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.allow().unwrap();

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
            res.unwrap();
        }
    }

    #[test]
    fn verif_no_blocks() {
        use crate::token::builder::*;

        let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder
            .add_authority_fact(fact("right", &[string("file1"), string("read")]))
            .unwrap();
        builder
            .add_authority_fact(fact("right", &[string("file2"), string("read")]))
            .unwrap();
        builder
            .add_authority_fact(fact("right", &[string("file1"), string("write")]))
            .unwrap();

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();
        println!("{}", biscuit1.print());

        let mut v = biscuit1.authorizer().expect("omg authorizer");

        v.add_check(rule(
            "right",
            &[string("right")],
            &[pred("right", &[string("file2"), string("write")])],
        ))
        .unwrap();

        //assert!(v.verify().is_err());
        let res = v.authorize();
        println!("res: {:?}", res);
        assert_eq!(
            res,
            Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                checks: vec![FailedCheck::Authorizer(FailedAuthorizerCheck {
                    check_id: 0,
                    rule: String::from("check if right(\"file2\", \"write\")")
                }),]
            }))
        );
    }

    #[test]
    fn authorizer_queries() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder.add_right("file1", "read");
        builder.add_right("file2", "read");
        builder.add_authority_fact("key(0000)").unwrap();

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();

        block2.expiration_date(SystemTime::now() + Duration::from_secs(30));
        block2.add_fact("key(1234)").unwrap();

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        let mut block3 = biscuit2.create_block();

        block3.expiration_date(SystemTime::now() + Duration::from_secs(10));
        block3.add_fact("key(5678)").unwrap();

        let keypair3 = KeyPair::new_with_rng(&mut rng);
        let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
        {
            let mut authorizer = biscuit3.authorizer().unwrap();
            authorizer.add_fact("resource(\"file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            authorizer.set_time();

            // test that cloning correctly embeds the first block's facts
            let mut other_authorizer = authorizer.clone();

            let authorization_res = authorizer.authorize();
            println!("authorization result: {:?}", authorization_res);

            let res2: Result<Vec<builder::Fact>, crate::error::Token> =
                authorizer.query_all("key_verif($id) <- key($id)");
            println!("res2: {:?}", res2);
            let mut res2 = res2
                .unwrap()
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>();
            res2.sort();
            assert_eq!(
                res2,
                vec![
                    "key_verif(0)".to_string(),
                    "key_verif(1234)".to_string(),
                    "key_verif(5678)".to_string(),
                ]
            );

            let res1: Result<Vec<builder::Fact>, crate::error::Token> =
                other_authorizer.query("key_verif($id) <- key($id)", &[0].into());
            println!("res1: {:?}", res1);
            assert_eq!(
                res1.unwrap()
                    .into_iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>(),
                vec!["key_verif(0)".to_string()]
            );
        }
    }

    #[test]
    fn check_head_name() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder
            .add_authority_check(check(&[pred("resource", &[string("hello")])]))
            .unwrap();

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        // new check: can only have read access1
        let mut block2 = biscuit1.create_block();
        block2.add_fact(fact("check1", &[string("test")])).unwrap();

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        println!("biscuit2: {}", biscuit2.print());

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        {
            let mut authorizer = biscuit2.authorizer().unwrap();
            authorizer.add_fact("resource(\"file1\")").unwrap();
            authorizer.add_fact("operation(\"read\")").unwrap();
            println!("symbols before time: {:?}", authorizer.symbols);
            authorizer.set_time();

            println!("world:\n{}", authorizer.print_world());
            println!("symbols: {:?}", authorizer.symbols);

            let res = authorizer.authorize();
            println!("res1: {:?}", res);

            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                    checks: vec![FailedCheck::Block(FailedBlockCheck {
                        block_id: 0,
                        check_id: 0,
                        rule: String::from("check if resource(\"hello\")"),
                    }),]
                }))
            );
        }
    }

    /*
    #[test]
    fn check_requires_fact_in_future_block() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder
            .add_authority_check(check(&[pred("name", &[var("name")])]))
            .unwrap();

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());
        let mut authorizer1 = biscuit1.verify().unwrap();
        authorizer1.allow().unwrap();
        let res1 = authorizer1.verify();
        println!("res1: {:?}", res1);
        assert_eq!(
            res1,
            Err(Token::FailedLogic(Logic::FailedChecks(vec![
                FailedCheck::Block(FailedBlockCheck {
                    block_id: 0,
                    check_id: 0,
                    rule: String::from("check if name($name)"),
                }),
            ])))
        );

        let mut block2 = biscuit1.create_block();
        block2.add_fact(fact("name", &[string("test")])).unwrap();

        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1
            .append_with_keypair(&keypair2, block2)
            .unwrap();

        println!("biscuit2 (with name fact): {}", biscuit2.print());
        let mut authorizer2 = biscuit2.verify().unwrap();
        authorizer2.allow().unwrap();
        let res2 = authorizer2.verify();
        assert_eq!(res2, Ok(0));
    }*/

    #[test]
    fn bytes_constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);
        builder.add_authority_fact("bytes(hex:0102AB)").unwrap();
        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1.print());

        let mut block2 = biscuit1.create_block();
        block2
            .add_rule("has_bytes($0) <- bytes($0), [ hex:00000000, hex:0102AB ].contains($0)")
            .unwrap();
        let keypair2 = KeyPair::new_with_rng(&mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        let mut authorizer = biscuit2.authorizer().unwrap();
        authorizer
            .add_check("check if bytes($0), [ hex:00000000, hex:0102AB ].contains($0)")
            .unwrap();
        authorizer.allow().unwrap();

        let res = authorizer.authorize();
        println!("res1: {:?}", res);
        res.unwrap();

        let res: Vec<(Vec<u8>,)> = authorizer
            .query("data($0) <- bytes($0)", &[0].into())
            .unwrap();
        println!("query result: {:x?}", res);
        println!("query result: {:?}", res[0]);
    }

    #[test]
    fn block1_generates_authority_or_ambient() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(&mut rng);

        let serialized1 = {
            let mut builder = Biscuit::builder(&root);

            builder
                .add_authority_fact("right(\"/folder1/file1\", \"read\")")
                .unwrap();
            builder
                .add_authority_fact("right(\"/folder1/file1\", \"write\")")
                .unwrap();
            builder
                .add_authority_fact("right(\"/folder2/file1\", \"read\")")
                .unwrap();
            builder
                .add_authority_check("check if operation(\"read\")")
                .unwrap();

            let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

            println!("biscuit1 (authority): {}", biscuit1.print());

            biscuit1.to_vec().unwrap()
        };

        //println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));
        println!("generated biscuit token: {} bytes", serialized1.len());
        //panic!();

        let serialized2 = {
            let biscuit1_deser = Biscuit::from(&serialized1, |_| root.public()).unwrap();

            // new check: can only have read access1
            let mut block2 = biscuit1_deser.create_block();

            // Bypass `check if operation("read")` from authority block
            block2
                .add_rule("operation(\"read\") <- operation($any)")
                .unwrap();

            // Bypass `check if resource($file), $file.starts_with("/folder1/")` from block #1
            block2
                .add_rule("resource(\"/folder1/\") <- resource($any)")
                .unwrap();

            // Add missing rights
            block2.add_rule("right($file, $right) <- right($any1, $any2), resource($file), operation($right)")
                .unwrap();

            let keypair2 = KeyPair::new_with_rng(&mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_keypair(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {}", biscuit2.print());

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let final_token = Biscuit::from(&serialized2, |_| root.public()).unwrap();
        println!("final token:\n{}", final_token.print());

        let mut authorizer = final_token.authorizer().unwrap();
        authorizer.add_fact("resource(\"/folder2/file1\")").unwrap();
        authorizer.add_fact("operation(\"write\")").unwrap();
        authorizer
            .add_policy("allow if resource($file), operation($op), right($file, $op)")
            .unwrap();
        authorizer.deny().unwrap();

        let res = authorizer.authorize_with_limits(crate::token::authorizer::AuthorizerLimits {
            max_time: Duration::from_secs(1),
            ..Default::default()
        });
        println!("res1: {:?}", res);
        println!("authorizer:\n{}", authorizer.print_world());

        assert!(res.is_err());
    }
}