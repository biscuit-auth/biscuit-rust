//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]
use crate::builder::Algorithm;
use crate::format::schema;
use crate::format::ThirdPartyVerificationMode;

use super::error;
mod ed25519;
mod p256;

use nom::Finish;
use rand_core::{CryptoRng, RngCore};
use std::{fmt::Display, hash::Hash, str::FromStr};

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug)]
pub enum KeyPair {
    Ed25519(ed25519::KeyPair),
    P256(p256::KeyPair),
}

impl KeyPair {
    pub fn new(algorithm: Algorithm) -> Self {
        Self::new_with_rng(algorithm, &mut rand::rngs::OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(algorithm: Algorithm, rng: &mut T) -> Self {
        match algorithm {
            Algorithm::Ed25519 => KeyPair::Ed25519(ed25519::KeyPair::new_with_rng(rng)),
            Algorithm::Secp256r1 => KeyPair::P256(p256::KeyPair::new_with_rng(rng)),
        }
    }

    pub fn from(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Ed25519(key) => KeyPair::Ed25519(ed25519::KeyPair::from(key)),
            PrivateKey::P256(key) => KeyPair::P256(p256::KeyPair::from(key)),
        }
    }

    /// deserializes from a byte array
    pub fn from_bytes(
        bytes: &[u8],
        algorithm: schema::public_key::Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            schema::public_key::Algorithm::Ed25519 => {
                Ok(KeyPair::Ed25519(ed25519::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Secp256r1 => {
                Ok(KeyPair::P256(p256::KeyPair::from_bytes(bytes)?))
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.sign(data),
            KeyPair::P256(key) => key.sign(data),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        ed25519::KeyPair::from_private_key_der(bytes)
            .map(KeyPair::Ed25519)
            .or_else(|_| p256::KeyPair::from_private_key_der(bytes).map(KeyPair::P256))
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        ed25519::KeyPair::from_private_key_pem(str)
            .map(KeyPair::Ed25519)
            .or_else(|_| p256::KeyPair::from_private_key_pem(str).map(KeyPair::P256))
    }

    pub fn private(&self) -> PrivateKey {
        match self {
            KeyPair::Ed25519(key) => PrivateKey::Ed25519(key.private()),
            KeyPair::P256(key) => PrivateKey::P256(key.private()),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(key) => PublicKey::Ed25519(key.public()),
            KeyPair::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            KeyPair::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            KeyPair::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new(Algorithm::Ed25519)
    }
}

/// the private part of a [KeyPair]
#[derive(Debug, Clone)]
pub enum PrivateKey {
    Ed25519(ed25519::PrivateKey),
    P256(p256::PrivateKey),
}

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            PrivateKey::Ed25519(key) => zeroize::Zeroizing::new(key.to_bytes()),
            PrivateKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(key.public()),
            PrivateKey::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PrivateKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PrivateKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    P256(p256::PublicKey),
}

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes().into(),
            PublicKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    pub fn from_proto(key: &schema::PublicKey) -> Result<Self, error::Format> {
        if key.algorithm == schema::public_key::Algorithm::Ed25519 as i32 {
            Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(
                &key.key,
            )?))
        } else if key.algorithm == schema::public_key::Algorithm::Secp256r1 as i32 {
            Ok(PublicKey::P256(p256::PublicKey::from_bytes(&key.key)?))
        } else {
            Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )))
        }
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: self.algorithm() as i32,
            key: self.to_bytes(),
        }
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.verify_signature(data, signature),
            PublicKey::P256(key) => key.verify_signature(data, signature),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PublicKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PublicKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }

    pub fn print(&self) -> String {
        self.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct Signature(pub(crate) Vec<u8>);

impl Signature {
    pub fn from_bytes(data: &[u8]) -> Result<Self, error::Format> {
        Ok(Signature(data.to_owned()))
    }

    pub(crate) fn from_vec(data: Vec<u8>) -> Self {
        Signature(data)
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for PublicKey {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, public_key) = biscuit_parser::parser::public_key(s)
            .finish()
            .map_err(biscuit_parser::error::LanguageError::from)?;
        Ok(PublicKey::from_bytes(
            &public_key.key,
            match public_key.algorithm {
                biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
                biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
            },
        )?)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKey::Ed25519(key) => write!(f, "ed25519/{}", hex::encode(key.to_bytes())),
            PublicKey::P256(key) => write!(f, "secp256r1/{}", hex::encode(&key.to_bytes())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: Signature,
    pub external_signature: Option<ExternalSignature>,
    pub version: u32,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: Signature,
}

#[derive(Clone, Debug)]
pub enum TokenNext {
    Secret(PrivateKey),
    Seal(Signature),
}

pub fn sign_authority_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_authority_block_signature_payload_v0(&message, &next_key.public()),
        1 => generate_authority_block_signature_payload_v1(&message, &next_key.public(), version),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    let signature = keypair.sign(&to_sign)?;

    Ok(Signature(signature.to_bytes().to_vec()))
}

pub fn sign_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
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

    Ok(keypair.sign(&to_sign)?)
}

pub fn verify_authority_block_signature(
    block: &Block,
    public_key: &PublicKey,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_authority_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key.verify_signature(&to_verify, &block.signature)
}

pub fn verify_block_signature(
    block: &Block,
    public_key: &PublicKey,
    previous_signature: &Signature,
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

    public_key.verify_signature(&to_verify, &block.signature)?;

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
    previous_signature: &Signature,
    external_signature: &ExternalSignature,
    version: u32,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match verification_mode {
        ThirdPartyVerificationMode::UnsafeLegacy => {
            generate_external_signature_payload_v0(payload, public_key)
        }
        ThirdPartyVerificationMode::PreviousSignatureHashing => {
            generate_external_signature_payload_v1(payload, previous_signature.to_bytes(), version)
        }
    };

    external_signature
        .public_key
        .verify_signature(&to_verify, &external_signature.signature)
}

pub(crate) fn generate_authority_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
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
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_authority_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify
}

pub(crate) fn generate_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature.to_bytes());

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend(b"\0EXTERNALSIG\0".to_vec());
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }

    to_verify
}

fn generate_external_signature_payload_v0(payload: &[u8], previous_key: &PublicKey) -> Vec<u8> {
    let mut to_verify = payload.to_vec();
    to_verify.extend(&(previous_key.algorithm() as i32).to_le_bytes());
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
    to_verify.extend(&(block.next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());
    to_verify.extend(block.signature.to_bytes());
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
