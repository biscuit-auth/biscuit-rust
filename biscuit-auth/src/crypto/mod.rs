//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]
use crate::format::schema;

use super::error;
mod ed25519;
use rand_core::{CryptoRng, RngCore};
use std::hash::Hash;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug)]
pub enum KeyPair {
    Ed25519(ed25519::KeyPair),
}

impl KeyPair {
    pub fn new() -> Self {
        Self::new_with_rng(&mut rand::rngs::OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        KeyPair::Ed25519(ed25519::KeyPair::new_with_rng(rng))
    }

    pub fn from(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Ed25519(key) => KeyPair::Ed25519(ed25519::KeyPair::from(key)),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.sign(data),
        }
    }

    pub fn private(&self) -> PrivateKey {
        match self {
            KeyPair::Ed25519(key) => PrivateKey::Ed25519(key.private()),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(key) => PublicKey::Ed25519(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::private_key::Algorithm {
        match self {
            KeyPair::Ed25519(_) => crate::format::schema::private_key::Algorithm::Ed25519,
        }
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// the private part of a [KeyPair]
#[derive(Debug)]
pub enum PrivateKey {
    Ed25519(ed25519::PrivateKey),
}

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            PrivateKey::Ed25519(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_bytes(bytes)?))
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_proto(key: &schema::PrivateKey) -> Result<Self, error::Format> {
        if key.algorithm != schema::private_key::Algorithm::Ed25519 as i32 {
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )));
        }

        Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_bytes(
            &key.key,
        )?))
    }

    pub fn to_proto(&self) -> schema::PrivateKey {
        schema::PrivateKey {
            algorithm: schema::private_key::Algorithm::Ed25519 as i32,
            key: self.to_bytes().to_vec(),
        }
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::private_key::Algorithm {
        match self {
            PrivateKey::Ed25519(_) => crate::format::schema::private_key::Algorithm::Ed25519,
        }
    }
}

impl std::clone::Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey::from_bytes(&self.to_bytes()).unwrap()
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
}

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(bytes)?))
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

        Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(
            &key.key,
        )?))
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: schema::public_key::Algorithm::Ed25519 as i32,
            key: self.to_bytes().to_vec(),
        }
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.verify_signature(data, signature),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PublicKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
        }
    }

    pub fn print(&self) -> String {
        format!("ed25519/{}", hex::encode(&self.to_bytes()))
    }
}

#[derive(Clone, Debug)]
pub struct Signature(pub(crate) Vec<u8>);

impl Signature {
    pub fn from_bytes(data: &[u8]) -> Result<Self, error::Format> {
        Ok(Signature(data.to_owned()))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: Signature,
    pub external_signature: Option<ExternalSignature>,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: Signature,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub root: PublicKey,
    pub blocks: Vec<Block>,
    pub next: TokenNext,
}

#[derive(Clone, Debug)]
pub enum TokenNext {
    Secret(PrivateKey),
    Seal(Signature),
}

pub fn sign(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
) -> Result<Signature, error::Token> {
    //FIXME: replace with SHA512 hashing
    let mut to_sign = message.to_vec();
    to_sign.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_sign.extend(&next_key.public().to_bytes());

    let signature = keypair.sign(&to_sign)?;

    Ok(Signature(signature.to_bytes().to_vec()))
}

pub fn verify_block_signature(block: &Block, public_key: &PublicKey) -> Result<(), error::Format> {
    //FIXME: replace with SHA512 hashing
    let mut to_verify = block.data.to_vec();

    if let Some(signature) = block.external_signature.as_ref() {
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }
    to_verify.extend(&(block.next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());

    public_key.verify_signature(&to_verify, &block.signature)?;

    if let Some(external_signature) = block.external_signature.as_ref() {
        let mut to_verify = block.data.to_vec();
        to_verify.extend(&(public_key.algorithm() as i32).to_le_bytes());
        to_verify.extend(&public_key.to_bytes());

        external_signature
            .public_key
            .verify_signature(&to_verify, &external_signature.signature)?;
    }

    Ok(())
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
