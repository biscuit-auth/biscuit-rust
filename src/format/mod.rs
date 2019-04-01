use super::crypto::{KeyPair, TokenSignature};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use prost::Message;

use super::error;
use super::token::Block;

pub mod schema {
    include!(concat!(env!("OUT_DIR"), "/biscuit.format.schema.rs"));
}

pub mod convert;

use self::convert::*;

#[derive(Clone, Debug)]
pub struct SerializedBiscuit {
    pub authority: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub keys: Vec<RistrettoPoint>,
    pub signature: TokenSignature,
}

impl SerializedBiscuit {
    pub fn from_slice(slice: &[u8], public_key: RistrettoPoint) -> Result<Self, error::Format> {
        let data = schema::Biscuit::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let mut keys = vec![];

        for key in data.keys {
            if key.len() == 32 {
                if let Some(k) = CompressedRistretto::from_slice(&key[..]).decompress() {
                    keys.push(k);
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

        match deser.verify(public_key) {
            Ok(()) => Ok(deser),
            Err(e) => Err(e),
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        let b = schema::Biscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            keys: self
                .keys
                .iter()
                .map(|k| Vec::from(&k.compress().to_bytes()[..]))
                .collect(),
            signature: token_sig_to_proto_sig(&self.signature),
        };

        let mut v = Vec::new();

        b.encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
    }

    pub fn new(keypair: &KeyPair, authority: &Block) -> Result<Self, error::Format> {
        let mut v = Vec::new();
        token_block_to_proto_block(authority)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let signature = TokenSignature::new(keypair, &v);

        Ok(SerializedBiscuit {
            authority: v,
            blocks: vec![],
            keys: vec![keypair.public],
            signature,
        })
    }

    pub fn append(&self, keypair: &KeyPair, block: &Block) -> Result<Self, error::Format> {
        let mut v = Vec::new();
        token_block_to_proto_block(block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let mut blocks = Vec::new();
        blocks.push(self.authority.clone());
        blocks.extend(self.blocks.iter().cloned());

        let signature = self.signature.sign(&self.keys, &blocks, keypair, &v);

        let mut t = SerializedBiscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            keys: self.keys.clone(),
            signature,
        };

        t.blocks.push(v);
        t.keys.push(keypair.public);

        Ok(t)
    }

    pub fn verify(&self, public: RistrettoPoint) -> Result<(), error::Format> {
        if self.keys.is_empty() {
            return Err(error::Format::EmptyKeys);
        }
        if self.keys[0] != public {
            return Err(error::Format::UnknownPublicKey);
        }

        let mut blocks = Vec::new();
        blocks.push(self.authority.clone());
        blocks.extend(self.blocks.iter().cloned());

        self.signature
            .verify(&self.keys, &blocks)
            .map_err(error::Format::Signature)
    }
}
