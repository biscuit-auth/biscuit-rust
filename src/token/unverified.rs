use super::{default_symbol_table, Biscuit, Block};
use crate::{
    builder::BlockBuilder,
    crypto::PublicKey,
    datalog::SymbolTable,
    error,
    format::{convert::proto_block_to_token_block, schema, SerializedBiscuit},
    KeyPair,
};
use prost::Message;

/// A token that was parsed without cryptographic signature verification
///
/// Use this if you want to attenuate or print the content of a token
/// without verifying it.
///
/// It can be converted to a [Biscuit] using [UnverifiedBiscuit::check_signature],
/// and then used for authorization
#[derive(Clone, Debug)]
pub struct UnverifiedBiscuit {
    pub(crate) authority: Block,
    pub(crate) blocks: Vec<Block>,
    pub(crate) symbols: SymbolTable,
    container: SerializedBiscuit,
}

impl UnverifiedBiscuit {
    /// deserializes a token from raw bytes
    pub fn from<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_with_symbols(slice.as_ref(), default_symbol_table())
    }

    /// deserializes a token from base64
    pub fn from_base64<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_base64_with_symbols(slice, default_symbol_table())
    }

    /// checks the signature of the token and convert it to a [Biscuit] for authorization
    pub fn check_signature<F>(self, f: F) -> Result<Biscuit, error::Format>
    where
        F: Fn(Option<u32>) -> PublicKey,
    {
        let root = f(self.container.root_key_id);
        self.container.verify(&root)?;

        Ok(Biscuit {
            root_key_id: self.container.root_key_id,
            authority: self.authority,
            blocks: self.blocks,
            symbols: self.symbols,
            container: Some(self.container),
        })
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        let keypair = KeyPair::new_with_rng(&mut rand::rngs::OsRng);
        self.append_with_keypair(&keypair, block_builder)
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

    /// creates a new block builder
    pub fn create_block(&self) -> BlockBuilder {
        BlockBuilder::new()
    }

    /// deserializes from raw bytes with a custom symbol table
    pub fn from_with_symbols(slice: &[u8], mut symbols: SymbolTable) -> Result<Self, error::Token> {
        let container = SerializedBiscuit::deserialize(slice)?;

        let authority: Block = schema::Block::decode(&container.authority.data[..])
            .map_err(|e| {
                error::Token::Format(error::Format::BlockDeserializationError(format!(
                    "error deserializing authority block: {:?}",
                    e
                )))
            })
            .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

        let mut blocks = vec![];

        for block in container.blocks.iter() {
            let deser: Block = schema::Block::decode(&block.data[..])
                .map_err(|e| {
                    error::Token::Format(error::Format::BlockDeserializationError(format!(
                        "error deserializing block: {:?}",
                        e
                    )))
                })
                .and_then(|b| proto_block_to_token_block(&b).map_err(error::Token::Format))?;

            blocks.push(deser);
        }

        symbols.extend(&authority.symbols);

        for block in blocks.iter() {
            symbols.extend(&block.symbols);
        }

        Ok(UnverifiedBiscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a token from base64 with a custom symbol table
    pub fn from_base64_with_symbols<T>(slice: T, symbols: SymbolTable) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Self::from_with_symbols(&decoded, symbols)
    }

    /// adds a new block to the token
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

        let container = self.container.append(keypair, &block)?;

        symbols.extend(&block.symbols);
        blocks.push(block);

        Ok(UnverifiedBiscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// returns a list of revocation identifiers for each block, in order
    ///
    /// if a token is generated with the same keys and the same content,
    /// those identifiers will stay the same
    pub fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        let mut res = vec![self.container.authority.signature.to_bytes().to_vec()];

        for block in self.container.blocks.iter() {
            res.push(block.signature.to_bytes().to_vec());
        }

        res
    }

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        1 + self.container.blocks.len()
    }

    /// prints the content of a block as Datalog source code
    pub fn print_block_source(&self, index: usize) -> Option<String> {
        let block = if index == 0 {
            &self.authority
        } else {
            match self.blocks.get(index - 1) {
                None => return None,
                Some(block) => block,
            }
        };

        Some(block.print_source(&self.symbols))
    }

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<UnverifiedBiscuit, error::Token> {
        let container = self.container.seal()?;
        let mut token = self.clone();
        token.container = container;
        Ok(token)
    }
}
