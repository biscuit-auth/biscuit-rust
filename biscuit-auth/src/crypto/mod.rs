//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]
use crate::{error::Format, format::schema};

use super::error;
#[cfg(feature = "pem")]
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::*;

use nom::Finish;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryInto, fmt::Display, hash::Hash, ops::Drop, path::Path, str::FromStr};
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

    #[cfg(feature = "pem")]
    pub fn from_private_key_der_file(path: impl AsRef<Path>) -> Result<Self, error::Format> {
        let kp = SigningKey::read_pkcs8_der_file(path)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem_file(path: impl AsRef<Path>) -> Result<Self, error::Format> {
        let kp = SigningKey::read_pkcs8_pem_file(path)
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
        write!(f, "ed25519/{}", hex::encode(&self.to_bytes()))
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: ed25519_dalek::Signature,
    pub external_signature: Option<ExternalSignature>,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: ed25519_dalek::Signature,
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
    Seal(ed25519_dalek::Signature),
}

pub fn sign(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
) -> Result<Signature, error::Token> {
    //FIXME: replace with SHA512 hashing
    let mut to_sign = message.to_vec();
    to_sign.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
    to_sign.extend(&next_key.public().to_bytes());

    let signature = keypair
        .kp
        .try_sign(&to_sign)
        .map_err(|s| s.to_string())
        .map_err(error::Signature::InvalidSignatureGeneration)
        .map_err(error::Format::Signature)?;

    Ok(signature)
}

pub fn verify_block_signature(block: &Block, public_key: &PublicKey) -> Result<(), error::Format> {
    //FIXME: replace with SHA512 hashing
    let mut to_verify = block.data.to_vec();

    if let Some(signature) = block.external_signature.as_ref() {
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }
    to_verify.extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());

    public_key
        .0
        .verify_strict(&to_verify, &block.signature)
        .map_err(|s| s.to_string())
        .map_err(error::Signature::InvalidSignature)
        .map_err(error::Format::Signature)?;

    if let Some(external_signature) = block.external_signature.as_ref() {
        let mut to_verify = block.data.to_vec();
        to_verify
            .extend(&(crate::format::schema::public_key::Algorithm::Ed25519 as i32).to_le_bytes());
        to_verify.extend(&public_key.to_bytes());

        external_signature
            .public_key
            .0
            .verify_strict(&to_verify, &external_signature.signature)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(error::Format::Signature)?;
    }

    Ok(())
}

impl Token {
    #[allow(dead_code)]
    pub fn new<T: RngCore + CryptoRng>(
        keypair: &KeyPair,
        next_key: &KeyPair,
        message: &[u8],
    ) -> Result<Self, error::Token> {
        let signature = sign(keypair, next_key, message)?;

        let block = Block {
            data: message.to_vec(),
            next_key: next_key.public(),
            signature,
            external_signature: None,
        };

        Ok(Token {
            root: keypair.public(),
            blocks: vec![block],
            next: TokenNext::Secret(next_key.private()),
        })
    }

    #[allow(dead_code)]
    pub fn append<T: RngCore + CryptoRng>(
        &self,
        next_key: &KeyPair,
        message: &[u8],
        external_signature: Option<ExternalSignature>,
    ) -> Result<Self, error::Token> {
        let keypair = match self.next.keypair() {
            Err(error::Token::AlreadySealed) => Err(error::Token::AppendOnSealed),
            other => other,
        }?;

        let signature = sign(&keypair, next_key, message)?;

        let block = Block {
            data: message.to_vec(),
            next_key: next_key.public(),
            signature,
            external_signature,
        };

        let mut t = Token {
            root: self.root,
            blocks: self.blocks.clone(),
            next: TokenNext::Secret(next_key.private()),
        };

        t.blocks.push(block);

        Ok(t)
    }

    #[allow(dead_code)]
    pub fn verify(&self, root: PublicKey) -> Result<(), error::Token> {
        //FIXME: try batched signature verification
        let mut current_pub = root;

        for block in &self.blocks {
            verify_block_signature(block, &current_pub)?;
            current_pub = block.next_key;
        }

        match &self.next {
            TokenNext::Secret(private) => {
                if current_pub != private.public() {
                    return Err(error::Format::Signature(error::Signature::InvalidSignature(
                        "the last public key does not match the private key".to_string(),
                    ))
                    .into());
                }
            }
            TokenNext::Seal(signature) => {
                //FIXME: replace with SHA512 hashing
                let mut to_verify = Vec::new();
                for block in &self.blocks {
                    to_verify.extend(&block.data);
                    to_verify.extend(&block.next_key.to_bytes());
                }

                current_pub
                    .0
                    .verify_strict(&to_verify, signature)
                    .map_err(|s| s.to_string())
                    .map_err(error::Signature::InvalidSignature)
                    .map_err(error::Format::Signature)?;
            }
        }

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    /*
    use super::*;
    use rand::prelude::*;
    use rand_core::SeedableRng;

    #[test]
    fn basic_signature() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message = b"hello world";
        let keypair = KeyPair::new_with_rng(&mut rng);

        let signature = keypair.sign(&mut rng, message);

        assert!(verify(&keypair.public, message, &signature));

        assert!(!verify(&keypair.public, b"AAAA", &signature));
    }

    #[test]
    fn three_messages() {
        //let mut rng: OsRng = OsRng::new().unwrap();
        //keep the same values in tests
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message1 = b"hello";
        let keypair1 = KeyPair::new_with_rng(&mut rng);

        let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

        assert_eq!(token1.verify(), Ok(()), "cannot verify first token");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2 = KeyPair::new_with_rng(&mut rng);

        let token2 = token1.append(&mut rng, &keypair2, &message2[..]);

        assert_eq!(token2.verify(), Ok(()), "cannot verify second token");

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3 = KeyPair::new_with_rng(&mut rng);

        let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

        assert_eq!(token3.verify(), Ok(()), "cannot verify third token");
    }

    #[test]
    fn change_message() {
        //let mut rng: OsRng = OsRng::new().unwrap();
        //keep the same values in tests
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);

        let message1 = b"hello";
        let keypair1 = KeyPair::new_with_rng(&mut rng);

        let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

        assert_eq!(token1.verify(), Ok(()), "cannot verify first token");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2 = KeyPair::new_with_rng(&mut rng);

        let mut token2 = token1.append(&mut rng, &keypair2, &message2[..]);

        token2.messages[1] = Vec::from(&b"you"[..]);

        assert_eq!(
            token2.verify(),
            Err(error::Signature::InvalidSignature),
            "second token should not be valid"
        );

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3 = KeyPair::new_with_rng(&mut rng);

        let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

        assert_eq!(
            token3.verify(),
            Err(error::Signature::InvalidSignature),
            "cannot verify third token"
        );
    }*/
}
