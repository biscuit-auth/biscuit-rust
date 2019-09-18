//! token serialization/deserialization
//!
//! Biscuit tokens are serialized to Protobuf. There are two levels of serialization:
//!
//! - serialization of Biscuit blocks to Protobuf then `Vec<u8>`
//! - serialization of a wrapper structure containing serialized blocks and the signature
use super::crypto::{KeyPair, TokenSignature};
use crate::crypto::PublicKey;
use curve25519_dalek::ristretto::CompressedRistretto;
use prost::Message;
use rand::{CryptoRng, Rng};

use super::error;
use super::token::Block;

/// Structures generated from the Protobuf schema
pub mod schema {
    include!(concat!(env!("OUT_DIR"), "/biscuit.format.schema.rs"));
}

pub mod convert;

use self::convert::*;

/// Intermediate structure for token serialization
///
/// This structure contains the blocks serialized to byte arrays. Those arrays
/// will be used for the signature
#[derive(Clone, Debug)]
pub struct SerializedBiscuit {
    pub authority: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub keys: Vec<PublicKey>,
    pub signature: TokenSignature,
}

impl SerializedBiscuit {
    pub fn from_slice(slice: &[u8]) -> Result<Self, error::Format> {
        let data = schema::Biscuit::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let mut keys = vec![];

        for key in data.keys {
            if key.len() == 32 {
                if let Some(k) = CompressedRistretto::from_slice(&key[..]).decompress() {
                    keys.push(PublicKey(k));
                } else {
                    return Err(error::Format::DeserializationError(format!(
                        "deserialization error: cannot decompress key point"
                    )));
                }
            } else {
                return Err(error::Format::DeserializationError(format!(
                    "deserialization error: invalid size for key = {} bytes",
                    key.len()
                )));
            }
        }

        let signature = proto_sig_to_token_sig(data.signature)?;

        let deser = SerializedBiscuit {
            authority: data.authority,
            blocks: data.blocks,
            keys,
            signature,
        };

        match deser.verify() {
            Ok(()) => Ok(deser),
            Err(e) => Err(e),
        }
    }

    /// serializes the token
    pub fn to_proto(&self) -> schema::Biscuit {
        schema::Biscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            keys: self
                .keys
                .iter()
                .map(|k| Vec::from(&k.0.compress().to_bytes()[..]))
                .collect(),
            signature: token_sig_to_proto_sig(&self.signature),
        }
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
    pub fn new<T: Rng + CryptoRng>(
        rng: &mut T,
        keypair: &KeyPair,
        authority: &Block,
    ) -> Result<Self, error::Format> {
        let mut v = Vec::new();
        token_block_to_proto_block(authority)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let signature = TokenSignature::new(rng, keypair, &v);

        Ok(SerializedBiscuit {
            authority: v,
            blocks: vec![],
            keys: vec![keypair.public()],
            signature,
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append<T: Rng + CryptoRng>(
        &self,
        rng: &mut T,
        keypair: &KeyPair,
        block: &Block,
    ) -> Result<Self, error::Format> {
        let mut v = Vec::new();
        token_block_to_proto_block(block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let mut blocks = Vec::new();
        blocks.push(self.authority.clone());
        blocks.extend(self.blocks.iter().cloned());

        let signature = self.signature.sign(rng, keypair, &v);

        let mut t = SerializedBiscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            keys: self.keys.clone(),
            signature,
        };

        t.blocks.push(v);
        t.keys.push(keypair.public());

        Ok(t)
    }

    /// checks the signature on a deserialized token
    pub fn verify(&self) -> Result<(), error::Format> {
        if self.keys.is_empty() {
            return Err(error::Format::EmptyKeys);
        }

        let mut blocks = Vec::new();
        blocks.push(self.authority.clone());
        blocks.extend(self.blocks.iter().cloned());

        self.signature
            .verify(&self.keys, &blocks)
            .map_err(error::Format::Signature)
    }

    pub fn check_root_key(&self, root: PublicKey) -> Result<(), error::Format> {
        if self.keys.is_empty() {
            return Err(error::Format::EmptyKeys);
        }
        if self.keys[0] != root {
            return Err(error::Format::UnknownPublicKey);
        }

        Ok(())
    }
}
