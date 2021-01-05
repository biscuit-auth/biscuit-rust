//! structures to handle sealed tokens (using symmetric cryptography, not attenuable)
use super::Biscuit;
use crate::error;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

use crate::format::{convert::token_block_to_proto_block, schema};
use crate::prost::Message;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct SealedBiscuit {
    pub authority: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl SealedBiscuit {
    pub fn from_token(token: &Biscuit, secret: &[u8]) -> Result<Self, error::Format> {
        let mut authority = Vec::new();
        token_block_to_proto_block(&token.authority)
            .encode(&mut authority)
            .map_err(|e| {
                error::Format::BlockSerializationError(format!(
                    "error serializing authority block: {:?}",
                    e
                ))
            })?;

        let mut blocks = Vec::new();

        for block in token.blocks.iter() {
            let mut b = Vec::new();
            match token_block_to_proto_block(block).encode(&mut b) {
                Ok(_) => blocks.push(b),
                Err(e) => {
                    return Err(error::Format::BlockSerializationError(format!(
                        "error serializing block: {:?}",
                        e
                    )))
                }
            }
        }

        let mut mac = HmacSha256::new_varkey(secret).unwrap();
        mac.update(&authority);
        for block in blocks.iter() {
            mac.update(&block);
        }

        let signature: Vec<u8> = mac.finalize().into_bytes().to_vec();

        Ok(SealedBiscuit {
            authority,
            blocks,
            signature,
        })
    }

    pub fn from_slice(slice: &[u8], secret: &[u8]) -> Result<Self, error::Format> {
        let proto: schema::SealedBiscuit = schema::SealedBiscuit::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let deser = SealedBiscuit {
            authority: proto.authority,
            blocks: proto.blocks,
            signature: proto.signature,
        };

        let mut mac = HmacSha256::new_varkey(secret).unwrap();
        mac.update(&deser.authority);
        for block in deser.blocks.iter() {
            mac.update(&block);
        }

        mac.verify(&deser.signature)
            .map_err(|_| error::Format::SealedSignature)?;

        Ok(deser)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        let proto = schema::SealedBiscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            signature: self.signature.clone(),
        };

        let mut v = Vec::new();
        proto
            .encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
    }

    pub fn serialized_size(&self) -> usize {
        let proto = schema::SealedBiscuit {
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            signature: self.signature.clone(),
        };

        proto.encoded_len()
    }
}
