//! token serialization/deserialization
//!
//! Biscuit tokens are serialized to Protobuf. There are two levels of serialization:
//!
//! - serialization of Biscuit blocks to Protobuf then `Vec<u8>`
//! - serialization of a wrapper structure containing serialized blocks and the signature
use super::crypto::{self, KeyPair, PrivateKey, PublicKey, TokenNext};

use prost::Message;

use super::error;
use super::token::Block;
use crate::crypto::ExternalSignature;
use crate::datalog::SymbolTable;
use crate::token::public_keys::PublicKeys;
use ed25519_dalek::Signer;
use std::collections::HashMap;
use std::convert::TryInto;

/// Structures generated from the Protobuf schema
pub mod schema; /*{
                    include!(concat!(env!("OUT_DIR"), "/biscuit.format.schema.rs"));
                }*/

pub mod convert;

use self::convert::*;

/// Intermediate structure for token serialization
///
/// This structure contains the blocks serialized to byte arrays. Those arrays
/// will be used for the signature
#[derive(Clone, Debug)]
pub struct SerializedBiscuit {
    pub root_key_id: Option<u32>,
    pub authority: crypto::Block,
    pub blocks: Vec<crypto::Block>,
    pub proof: crypto::TokenNext,
}

impl SerializedBiscuit {
    pub fn from_slice<F: Fn(Option<u32>) -> PublicKey>(
        slice: &[u8],
        f: F,
    ) -> Result<Self, error::Format> {
        let deser = SerializedBiscuit::deserialize(slice)?;

        let root = f(deser.root_key_id);
        deser.verify(&root)?;

        Ok(deser)
    }

    pub(crate) fn deserialize(slice: &[u8]) -> Result<Self, error::Format> {
        let data = schema::Biscuit::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        if data.authority.next_key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                data.authority.next_key.algorithm
            )));
        }

        let bytes: [u8; 64] = (&data.authority.signature[..])
            .try_into()
            .map_err(|_| error::Format::InvalidSignatureSize(data.authority.signature.len()))?;

        let signature = ed25519_dalek::Signature::from_bytes(&bytes).map_err(|e| {
            error::Format::SignatureDeserializationError(format!(
                "signature deserialization error: {:?}",
                e
            ))
        })?;

        if data.authority.external_signature.is_some() {
            return Err(error::Format::DeserializationError(
                "the authority block must not contain an external signature".to_string(),
            ));
        }

        let authority = crypto::Block {
            data: data.authority.block,
            next_key: PublicKey::from_bytes(&data.authority.next_key.key)?,
            signature,
            external_signature: None,
        };

        let mut blocks = Vec::new();
        for block in &data.blocks {
            if block.next_key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
                return Err(error::Format::DeserializationError(format!(
                    "deserialization error: unexpected key algorithm {}",
                    block.next_key.algorithm
                )));
            }

            let bytes: [u8; 64] = (&block.signature[..])
                .try_into()
                .map_err(|_| error::Format::InvalidSignatureSize(block.signature.len()))?;

            let signature = ed25519_dalek::Signature::from_bytes(&bytes).map_err(|e| {
                error::Format::BlockSignatureDeserializationError(format!(
                    "block signature deserialization error: {:?}",
                    e
                ))
            })?;

            let external_signature = if let Some(ex) = block.external_signature.as_ref() {
                if ex.public_key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
                    return Err(error::Format::DeserializationError(format!(
                        "deserialization error: unexpected key algorithm {}",
                        ex.public_key.algorithm
                    )));
                }
                let bytes: [u8; 64] = (&ex.signature[..])
                    .try_into()
                    .map_err(|_| error::Format::InvalidSignatureSize(ex.signature.len()))?;

                let signature = ed25519_dalek::Signature::from_bytes(&bytes).map_err(|e| {
                    error::Format::BlockSignatureDeserializationError(format!(
                        "block external signature deserialization error: {:?}",
                        e
                    ))
                })?;

                Some(ExternalSignature {
                    public_key: PublicKey::from_bytes(&ex.public_key.key)?,
                    signature,
                })
            } else {
                None
            };

            blocks.push(crypto::Block {
                data: block.block.clone(),
                next_key: PublicKey::from_bytes(&block.next_key.key)?,
                signature,
                external_signature,
            });
        }

        let proof = match data.proof.content {
            None => {
                return Err(error::Format::DeserializationError(
                    "could not find proof".to_string(),
                ))
            }
            Some(schema::proof::Content::NextSecret(v)) => {
                TokenNext::Secret(PrivateKey::from_bytes(&v)?)
            }
            Some(schema::proof::Content::FinalSignature(v)) => {
                let bytes: [u8; 64] = (&v[..])
                    .try_into()
                    .map_err(|_| error::Format::InvalidSignatureSize(v.len()))?;
                let signature = ed25519_dalek::Signature::from_bytes(&bytes).map_err(|e| {
                    error::Format::SignatureDeserializationError(format!(
                        "final signature deserialization error: {:?}",
                        e
                    ))
                })?;
                TokenNext::Seal(signature)
            }
        };

        let deser = SerializedBiscuit {
            root_key_id: data.root_key_id,
            authority,
            blocks,
            proof,
        };

        Ok(deser)
    }

    pub(crate) fn extract_blocks(
        &self,
        symbols: &mut SymbolTable,
    ) -> Result<(schema::Block, Vec<schema::Block>, PublicKeys), error::Token> {
        let mut public_keys = PublicKeys::new();

        let authority = schema::Block::decode(&self.authority.data[..]).map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing authority block: {:?}",
                e
            )))
        })/*.and_then(|b| {
            proto_block_to_token_block(
                &b,
                container
                    .authority
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format)
        })*/?;

        symbols.extend(&SymbolTable::from(authority.symbols.clone()));

        //FIXME: should we show an error if a key is already known?
        for pk in &authority.public_keys {
            if pk.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
                return Err(error::Format::DeserializationError(format!(
                    "deserialization error: unexpected key algorithm {}",
                    pk.algorithm
                )))
                .map_err(error::Token::Format);
            }
            public_keys.insert(&PublicKey::from_bytes(&pk.key)?);
        }

        let mut blocks = vec![];

        for block in self.blocks.iter() {
            let deser = schema::Block::decode(&block.data[..]).map_err(|e| {
                error::Token::Format(error::Format::BlockDeserializationError(format!(
                    "error deserializing block: {:?}",
                    e
                )))
            })?;

            //FIXME: should we show an error if a key is already known?
            for pk in &deser.public_keys {
                if pk.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
                    return Err(error::Format::DeserializationError(format!(
                        "deserialization error: unexpected key algorithm {}",
                        pk.algorithm
                    )))
                    .map_err(error::Token::Format);
                }
                public_keys.insert(&PublicKey::from_bytes(&pk.key)?);
            }

            symbols.extend(&SymbolTable::from(deser.symbols.clone()));

            blocks.push(deser);
        }

        Ok((authority, blocks, public_keys))
    }

    /// serializes the token
    pub fn to_proto(&self) -> schema::Biscuit {
        let authority = schema::SignedBlock {
            block: self.authority.data.clone(),
            next_key: schema::PublicKey {
                algorithm: schema::public_key::Algorithm::Ed25519 as i32,
                key: self.authority.next_key.to_bytes().to_vec(),
            },
            signature: self.authority.signature.to_bytes().to_vec(),
            external_signature: None,
        };

        let mut blocks = Vec::new();
        for block in &self.blocks {
            let b = schema::SignedBlock {
                block: block.data.clone(),
                next_key: schema::PublicKey {
                    algorithm: schema::public_key::Algorithm::Ed25519 as i32,
                    key: block.next_key.to_bytes().to_vec(),
                },
                signature: block.signature.to_bytes().to_vec(),
                external_signature: None,
            };

            blocks.push(b);
        }

        schema::Biscuit {
            root_key_id: self.root_key_id,
            authority,
            blocks,
            proof: schema::Proof {
                content: match &self.proof {
                    TokenNext::Seal(signature) => Some(schema::proof::Content::FinalSignature(
                        signature.to_bytes().to_vec(),
                    )),
                    TokenNext::Secret(private) => Some(schema::proof::Content::NextSecret(
                        private.to_bytes().to_vec(),
                    )),
                },
            },
        }
    }

    pub fn serialized_size(&self) -> usize {
        self.to_proto().encoded_len()
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        let b = self.to_proto();

        let mut v = Vec::new();

        b.encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
    }

    /// creates a new token
    pub fn new(
        root_key_id: Option<u32>,
        root_keypair: &KeyPair,
        next_keypair: &KeyPair,
        authority: &Block,
    ) -> Result<Self, error::Token> {
        let mut v = Vec::new();
        token_block_to_proto_block(authority)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let signature = crypto::sign(root_keypair, next_keypair, &v)?;

        Ok(SerializedBiscuit {
            root_key_id,
            authority: crypto::Block {
                data: v,
                next_key: next_keypair.public(),
                signature,
                external_signature: None,
            },
            blocks: vec![],
            proof: TokenNext::Secret(next_keypair.private()),
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append(&self, next_keypair: &KeyPair, block: &Block) -> Result<Self, error::Token> {
        let keypair = self.proof.keypair()?;

        let mut v = Vec::new();
        token_block_to_proto_block(block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let signature = crypto::sign(&keypair, next_keypair, &v)?;

        // Add new block
        let mut blocks = self.blocks.clone();
        blocks.push(crypto::Block {
            data: v,
            next_key: next_keypair.public(),
            signature,
            external_signature: None,
        });

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            proof: TokenNext::Secret(next_keypair.private()),
        })
    }

    /// checks the signature on a deserialized token
    pub fn verify(&self, root: &PublicKey) -> Result<(), error::Format> {
        //FIXME: try batched signature verification
        let mut current_pub = root;

        crypto::verify_block_signature(&self.authority, current_pub)?;
        current_pub = &self.authority.next_key;

        for block in &self.blocks {
            crypto::verify_block_signature(block, current_pub)?;
            current_pub = &block.next_key;
        }

        match &self.proof {
            TokenNext::Secret(private) => {
                if current_pub != &private.public() {
                    return Err(error::Format::Signature(
                        error::Signature::InvalidSignature(
                            "the last public key does not match the private key".to_string(),
                        ),
                    ));
                }
            }
            TokenNext::Seal(signature) => {
                //FIXME: replace with SHA512 hashing
                let mut to_verify = Vec::new();

                let block = if self.blocks.is_empty() {
                    &self.authority
                } else {
                    &self.blocks[self.blocks.len() - 1]
                };
                to_verify.extend(&block.data);
                to_verify.extend(
                    &(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes(),
                );
                to_verify.extend(&block.next_key.to_bytes());
                to_verify.extend(&block.signature.to_bytes());

                current_pub
                    .0
                    .verify_strict(&to_verify, signature)
                    .map_err(|s| s.to_string())
                    .map_err(error::Signature::InvalidSignature)
                    .map_err(error::Format::Signature)?;
            }
        }

        Ok(())
    }

    pub fn seal(&self) -> Result<Self, error::Token> {
        let keypair = self.proof.keypair()?;

        //FIXME: replace with SHA512 hashing
        let mut to_sign = Vec::new();
        let block = if self.blocks.is_empty() {
            &self.authority
        } else {
            &self.blocks[self.blocks.len() - 1]
        };
        to_sign.extend(&block.data);
        to_sign
            .extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
        to_sign.extend(&block.next_key.to_bytes());
        to_sign.extend(&block.signature.to_bytes());

        let signature = keypair
            .kp
            .try_sign(&to_sign)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignatureGeneration)
            .map_err(error::Format::Signature)?;

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            proof: TokenNext::Seal(signature),
        })
    }
}
