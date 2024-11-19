//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]
use crate::format::ThirdPartyVerificationMode;
use crate::{error::Format, format::schema};

use super::error;
#[cfg(feature = "pem")]
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::*;

use nom::Finish;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryInto, fmt::Display, hash::Hash, ops::Drop, str::FromStr};
use zeroize::Zeroize;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug)]
pub struct KeyPair {
    pub(crate) kp: ed25519_dalek::SigningKey,
}

impl KeyPair {
    pub fn new() -> Self {
        Self::new_with_rng(&mut rand::rngs::OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let kp = ed25519_dalek::SigningKey::generate(rng);

        KeyPair { kp }
    }

    pub fn from(key: &PrivateKey) -> Self {
        KeyPair {
            kp: ed25519_dalek::SigningKey::from_bytes(&key.0),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    pub fn private(&self) -> PrivateKey {
        let secret = self.kp.to_bytes();
        PrivateKey(secret)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.kp.verifying_key())
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// the private part of a [KeyPair]
#[derive(Debug)]
pub struct PrivateKey(pub(crate) ed25519_dalek::SecretKey);

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        Ok(PrivateKey(bytes))
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        PublicKey(SigningKey::from_bytes(&self.0).verifying_key())
    }
}

impl std::clone::Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey::from_bytes(&self.to_bytes()).unwrap()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, Eq)]
pub struct PublicKey(pub(crate) ed25519_dalek::VerifyingKey);

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;

        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(PublicKey)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_proto(key: &schema::PublicKey) -> Result<Self, error::Format> {
        if key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )));
        }

        PublicKey::from_bytes(&key.key)
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: schema::public_key::Algorithm::Ed25519 as i32,
            key: self.to_bytes().to_vec(),
        }
    }

    pub fn print(&self) -> String {
        self.to_string()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (crate::format::schema::public_key::Algorithm::Ed25519 as i32).hash(state);
        self.0.to_bytes().hash(state);
    }
}

impl FromStr for PublicKey {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, bytes) = biscuit_parser::parser::public_key(s)
            .finish()
            .map_err(biscuit_parser::error::LanguageError::from)?;
        Ok(PublicKey::from_bytes(&bytes)?)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed25519/{}", hex::encode(self.to_bytes()))
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: ed25519_dalek::Signature,
    pub external_signature: Option<ExternalSignature>,
    pub version: u32,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: ed25519_dalek::Signature,
}

#[derive(Clone, Debug)]
pub enum TokenNext {
    Secret(PrivateKey),
    Seal(ed25519_dalek::Signature),
}

pub fn sign(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    external_signature: Option<&ExternalSignature>,
    previous_signature: Option<&Signature>,
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_block_signature_payload_v0(&message, &next_key.public(), external_signature),
        1 => generate_block_signature_payload_v1(
            &message,
            &next_key.public(),
            external_signature,
            previous_signature,
            version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    let signature = keypair
        .kp
        .try_sign(&to_sign)
        .map_err(|s| s.to_string())
        .map_err(error::Signature::InvalidSignatureGeneration)
        .map_err(error::Format::Signature)?;

    Ok(signature)
}

pub fn verify_block_signature(
    block: &Block,
    public_key: &PublicKey,
    previous_signature: Option<&Signature>,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
            previous_signature,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key
        .0
        .verify_strict(&to_verify, &block.signature)
        .map_err(|s| s.to_string())
        .map_err(error::Signature::InvalidSignature)
        .map_err(error::Format::Signature)?;

    if let Some(external_signature) = block.external_signature.as_ref() {
        verify_external_signature(
            &block.data,
            public_key,
            previous_signature,
            external_signature,
            block.version,
            verification_mode,
        )?;
    }

    Ok(())
}

pub fn verify_external_signature(
    payload: &[u8],
    public_key: &PublicKey,
    previous_signature: Option<&Signature>,
    external_signature: &ExternalSignature,
    version: u32,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match verification_mode {
        ThirdPartyVerificationMode::UnsafeLegacy => {
            generate_external_signature_payload_v0(payload, public_key)
        }
        ThirdPartyVerificationMode::PreviousSignatureHashing => {
            let previous_signature = match previous_signature {
                Some(s) => s,
                None => {
                    return Err(error::Format::Signature(
                        error::Signature::InvalidSignature(
                            "the authority block must not contain an external signature"
                                .to_string(),
                        ),
                    ))
                }
            };
            generate_external_signature_payload_v1(
                payload,
                previous_signature.to_bytes().as_slice(),
                version,
            )
        }
    };

    external_signature
        .public_key
        .0
        .verify_strict(&to_verify, &external_signature.signature)
        .map_err(|s| s.to_string())
        .map_err(error::Signature::InvalidSignature)
        .map_err(error::Format::Signature)?;

    Ok(())
}

pub(crate) fn generate_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }
    to_verify.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
    previous_signature: Option<&Signature>,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    if let Some(signature) = previous_signature {
        to_verify.extend(b"\0PREVSIG\0".to_vec());
        to_verify.extend(signature.to_bytes().as_slice());
    }

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend(b"\0EXTERNALSIG\0".to_vec());
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }

    to_verify
}

fn generate_external_signature_payload_v0(payload: &[u8], previous_key: &PublicKey) -> Vec<u8> {
    let mut to_verify = payload.to_vec();
    to_verify.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
    to_verify.extend(&previous_key.to_bytes());

    to_verify
}

pub(crate) fn generate_external_signature_payload_v1(
    payload: &[u8],
    previous_signature: &[u8],
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0EXTERNAL\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature);
    to_verify
}

pub(crate) fn generate_seal_signature_payload_v0(block: &Block) -> Vec<u8> {
    let mut to_verify = block.data.to_vec();
    to_verify.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());
    to_verify.extend(&block.signature.to_bytes());
    to_verify
}

impl TokenNext {
    pub fn keypair(&self) -> Result<KeyPair, error::Token> {
        match &self {
            TokenNext::Seal(_) => Err(error::Token::AlreadySealed),
            TokenNext::Secret(private) => Ok(KeyPair::from(private)),
        }
    }

    pub fn is_sealed(&self) -> bool {
        match &self {
            TokenNext::Seal(_) => true,
            TokenNext::Secret(_) => false,
        }
    }
}
