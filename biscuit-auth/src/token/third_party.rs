use std::cmp::max;

use ed25519_dalek::Signer;
use prost::Message;

use crate::{
    builder::BlockBuilder,
    crypto::{generate_external_signature_payload_v1, PublicKey},
    datalog::SymbolTable,
    error,
    format::{convert::token_block_to_proto_block, schema, SerializedBiscuit},
    KeyPair, PrivateKey,
};

use super::THIRD_PARTY_SIGNATURE_VERSION;

/// Third party block request
#[derive(Debug)]
pub struct ThirdPartyRequest {
    pub(crate) legacy_previous_key: PublicKey,
    pub(crate) previous_signature: Vec<u8>,
}

impl ThirdPartyRequest {
    pub(crate) fn from_container(
        container: &SerializedBiscuit,
    ) -> Result<ThirdPartyRequest, error::Token> {
        if container.proof.is_sealed() {
            return Err(error::Token::AppendOnSealed);
        }

        let legacy_previous_key = container
            .blocks
            .last()
            .unwrap_or(&container.authority)
            .next_key;

        let previous_signature = container
            .blocks
            .last()
            .unwrap_or(&container.authority)
            .signature
            .to_bytes()
            .to_vec();
        Ok(ThirdPartyRequest {
            legacy_previous_key,
            previous_signature,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let legacy_previous_key = self.legacy_previous_key.to_proto();
        let previous_signature = self.previous_signature.clone();

        let request = schema::ThirdPartyBlockRequest {
            legacy_previous_key,
            legacy_public_keys: Vec::new(),
            previous_signature,
        };
        let mut v = Vec::new();

        request.encode(&mut v).map(|_| v).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {:?}",
                e
            )))
        })
    }

    pub fn serialize_base64(&self) -> Result<String, error::Token> {
        Ok(base64::encode_config(self.serialize()?, base64::URL_SAFE))
    }

    pub fn deserialize(slice: &[u8]) -> Result<Self, error::Token> {
        let data = schema::ThirdPartyBlockRequest::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let legacy_previous_key = PublicKey::from_proto(&data.legacy_previous_key)?;

        if !data.legacy_public_keys.is_empty() {
            return Err(error::Token::Format(error::Format::DeserializationError(
                "public keys were provided in third-party block request".to_owned(),
            )));
        }

        let previous_signature = data.previous_signature.to_vec();

        Ok(ThirdPartyRequest {
            legacy_previous_key,
            previous_signature,
        })
    }

    pub fn deserialize_base64<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Self::deserialize(&decoded)
    }

    /// Creates a [`ThirdPartyBlock`] signed with the third party service's [`PrivateKey`]
    pub fn create_block(
        self,
        private_key: &PrivateKey,
        block_builder: BlockBuilder,
    ) -> Result<ThirdPartyBlock, error::Token> {
        let symbols = SymbolTable::new();
        let mut block = block_builder.build(symbols);
        block.version = max(super::DATALOG_3_2, block.version);

        let mut payload = Vec::new();
        token_block_to_proto_block(&block)
            .encode(&mut payload)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {:?}", e))
            })?;

        let signed_payload = generate_external_signature_payload_v1(
            &payload,
            &self.previous_signature,
            THIRD_PARTY_SIGNATURE_VERSION,
        );

        let keypair = KeyPair::from(private_key);
        let signature = keypair
            .kp
            .try_sign(&signed_payload)
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

        Ok(ThirdPartyBlock(content))
    }
}

/// Signed third party block content
///
/// this must be integrated with the token that created the [`ThirdPartyRequest`]
/// using [`Biscuit::append_third_party`](crate::Biscuit::append_third_party)
#[derive(Clone, Debug)]
pub struct ThirdPartyBlock(pub(crate) schema::ThirdPartyBlockContents);

impl ThirdPartyBlock {
    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let mut buffer = vec![];
        self.0.encode(&mut buffer).map(|_| buffer).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {:?}",
                e
            )))
        })
    }

    pub fn serialize_base64(&self) -> Result<String, error::Token> {
        Ok(base64::encode_config(self.serialize()?, base64::URL_SAFE))
    }
}
