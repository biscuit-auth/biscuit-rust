use std::ops::{Deref, DerefMut};

use ed25519_dalek::Signer;
use prost::Message;

use crate::{
    builder::BlockBuilder,
    crypto::PublicKey,
    datalog::SymbolTable,
    error,
    format::{convert::token_block_to_proto_block, schema, SerializedBiscuit},
    KeyPair, PrivateKey,
};

use super::public_keys::PublicKeys;

pub struct Request {
    pub(crate) previous_key: PublicKey,
    pub(crate) public_keys: PublicKeys,
    pub(crate) builder: BlockBuilder,
}

impl Request {
    pub fn from_container(container: &SerializedBiscuit) -> Result<Request, error::Token> {
        if container.proof.is_sealed() {
            return Err(error::Token::AppendOnSealed);
        }

        let mut public_keys = PublicKeys::new();

        for pk in &schema::Block::decode(&container.authority.data[..])
            .map_err(|e| {
                error::Format::DeserializationError(format!("deserialization error: {:?}", e))
            })?
            .public_keys
        {
            public_keys.insert(&PublicKey::from_proto(&pk)?);
        }
        for block in &container.blocks {
            for pk in &schema::Block::decode(&block.data[..])
                .map_err(|e| {
                    error::Format::DeserializationError(format!("deserialization error: {:?}", e))
                })?
                .public_keys
            {
                public_keys.insert(&PublicKey::from_proto(&pk)?);
            }
        }

        let previous_key = container
            .blocks
            .last()
            .unwrap_or(&&container.authority)
            .next_key;

        Ok(Request {
            previous_key,
            public_keys,
            builder: BlockBuilder::new(),
        })
    }
    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let public_keys = self
            .public_keys
            .keys
            .iter()
            .map(|key| key.to_proto())
            .collect();

        let previous_key = self.previous_key.to_proto();

        let request = schema::ThirdPartyBlockRequest {
            previous_key,
            public_keys,
        };
        let mut v = Vec::new();

        request.encode(&mut v).map(|_| v).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {:?}",
                e
            )))
        })
    }

    pub fn serialize_base64(&self) -> Result<Vec<u8>, error::Token> {
        Ok(base64::encode_config(self.serialize()?, base64::URL_SAFE).into_bytes())
    }

    pub fn deserialize(slice: &[u8]) -> Result<Self, error::Token> {
        let data = schema::ThirdPartyBlockRequest::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let previous_key = PublicKey::from_proto(&data.previous_key)?;

        let mut public_keys = PublicKeys::new();

        for key in data.public_keys {
            public_keys.insert(&PublicKey::from_proto(&key)?);
        }

        Ok(Request {
            previous_key,
            public_keys,
            builder: BlockBuilder::new(),
        })
    }

    pub fn deserialize_base64<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Self::deserialize(&decoded)
    }

    pub fn create_response(self, private_key: PrivateKey) -> Result<Vec<u8>, error::Token> {
        let mut symbols = SymbolTable::new();
        symbols.public_keys = self.public_keys.clone();
        let block = self.builder.build(symbols);

        let mut v = Vec::new();
        token_block_to_proto_block(&block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;
        let payload = v.clone();

        v.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
        v.extend(self.previous_key.to_bytes());

        let keypair = KeyPair::from(private_key);
        let signature = keypair
            .kp
            .try_sign(&v)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignatureGeneration)
            .map_err(error::Format::Signature)?;

        let public_key = keypair.public();
        let content = schema::ThirdPartyBlockContents {
            payload,
            external_signature: schema::ExternalSignature {
                signature: signature.to_bytes().to_vec(),
                public_key: public_key.to_proto(),
            },
        };

        let mut buffer = vec![];
        content.encode(&mut buffer).map(|_| buffer).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {:?}",
                e
            )))
        })
    }

    pub fn create_response_base64(self, private_key: PrivateKey) -> Result<Vec<u8>, error::Token> {
        Ok(
            base64::encode_config(self.create_response(private_key)?, base64::URL_SAFE)
                .into_bytes(),
        )
    }
}

impl Deref for Request {
    type Target = BlockBuilder;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl DerefMut for Request {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

/*pub struct Response{}
impl Response {
    pub fn deserialize(slice: &[u8]) -> Result<Self, error::Token> {
        let data = schema::ThirdPartyBlockContents::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        if data.previous_key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
            return Err(error::Token::Format(error::Format::DeserializationError(
                format!(
                    "deserialization error: unexpected key algorithm {}",
                    data.previous_key.algorithm
                ),
            )));
        }*/
