use super::crypto::{KeyPair, TokenSignature};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Deserialize, Serialize};

use super::error;
use super::token::Block;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedBiscuit {
    pub authority: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub keys: Vec<RistrettoPoint>,
    pub signature: TokenSignature,
}

impl SerializedBiscuit {
    pub fn from_slice(slice: &[u8], public_key: RistrettoPoint) -> Result<Self, error::Format> {
        let deser: SerializedBiscuit = serde_cbor::from_slice(&slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        match deser.verify(public_key) {
            Ok(()) => Ok(deser),
            Err(e) => Err(e),
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        serde_cbor::ser::to_vec_packed(self)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
    }

    pub fn new(keypair: &KeyPair, authority: &Block) -> Result<Self, error::Format> {
        let v: Vec<u8> = serde_cbor::ser::to_vec_packed(authority).map_err(|e| {
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
        let v: Vec<u8> = serde_cbor::ser::to_vec_packed(block).map_err(|e| {
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
