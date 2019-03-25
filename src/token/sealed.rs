use super::Biscuit;
use crate::error;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedBiscuit {
    pub authority: Vec<u8>,
    pub blocks: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl SealedBiscuit {
    pub fn from_token(token: &Biscuit, secret: &[u8]) -> Result<Self, error::Format> {
        let authority = serde_cbor::ser::to_vec_packed(&token.authority).map_err(|e| {
            error::Format::BlockSerializationError(format!(
                "error serializing authority block: {:?}",
                e
            ))
        })?;

        let mut blocks = Vec::new();

        for block in token.blocks.iter() {
            match serde_cbor::ser::to_vec_packed(block) {
                Ok(packed) => blocks.push(packed),
                Err(e) => {
                    return Err(error::Format::BlockSerializationError(format!(
                        "error serializing block: {:?}",
                        e
                    )))
                }
            }
        }

        let mut mac = HmacSha256::new_varkey(secret).unwrap();
        mac.input(&authority);
        for block in blocks.iter() {
            mac.input(&block);
        }

        let signature: Vec<u8> = mac.result().code().to_vec();

        Ok(SealedBiscuit {
            authority,
            blocks,
            signature,
        })
    }

    pub fn from_slice(slice: &[u8], secret: &[u8]) -> Result<Self, error::Format> {
        let deser: SealedBiscuit = serde_cbor::from_slice(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let mut mac = HmacSha256::new_varkey(secret).unwrap();
        mac.input(&deser.authority);
        for block in deser.blocks.iter() {
            mac.input(&block);
        }

        mac.verify(&deser.signature)
            .map_err(|_| error::Format::SealedSignature)?;

        Ok(deser)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        serde_cbor::ser::to_vec_packed(self)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
    }
}
