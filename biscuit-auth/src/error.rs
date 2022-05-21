//! error types
//!

use std::convert::{From, Infallible};
use thiserror::Error;

/// the global error type for Biscuit
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Token {
    #[error("internal error")]
    InternalError,
    #[error("error deserializing or verifying the token")]
    Format(Format),
    #[error("multiple blocks declare the same symbols")]
    SymbolTableOverlap,
    #[error("tried to append a block to a sealed token")]
    AppendOnSealed,
    #[error("tried to seal an already sealed token")]
    AlreadySealed,
    #[error("authorization failed")]
    FailedLogic(Logic),
    #[error("error generating Datalog")]
    Language(LanguageError),
    #[error("Reached Datalog execution limits")]
    RunLimit(RunLimit),
    #[error("Cannot convert from Term: {0}")]
    ConversionError(String),
    #[error("Cannot decode base64 token: {0}")]
    Base64(Base64Error),
}

impl From<Infallible> for Token {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<Format> for Token {
    fn from(e: Format) -> Self {
        Token::Format(e)
    }
}

impl From<Logic> for Token {
    fn from(e: Logic) -> Self {
        Token::FailedLogic(e)
    }
}

impl<'a> From<crate::parser::Error<'a>> for Token {
    fn from(e: crate::parser::Error<'a>) -> Self {
        Token::Language(LanguageError::ParseError(e.into()))
    }
}

impl<'a> From<Vec<crate::parser::Error<'a>>> for Token {
    fn from(e: Vec<crate::parser::Error<'a>>) -> Self {
        Token::Language(LanguageError::ParseError(e.into()))
    }
}

impl From<base64::DecodeError> for Token {
    fn from(e: base64::DecodeError) -> Self {
        let err = match e {
            base64::DecodeError::InvalidByte(offset, byte) => {
                Base64Error::InvalidByte(offset, byte)
            }
            base64::DecodeError::InvalidLength => Base64Error::InvalidLength,
            base64::DecodeError::InvalidLastSymbol(offset, byte) => {
                Base64Error::InvalidLastSymbol(offset, byte)
            }
        };

        Token::Base64(err)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Base64Error {
    InvalidByte(usize, u8),
    InvalidLength,
    InvalidLastSymbol(usize, u8),
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Base64Error::InvalidByte(index, byte) => {
                write!(f, "Invalid byte {}, offset {}.", byte, index)
            }
            Base64Error::InvalidLength => write!(f, "Encoded text cannot have a 6-bit remainder."),
            Base64Error::InvalidLastSymbol(index, byte) => {
                write!(f, "Invalid last symbol {}, offset {}.", byte, index)
            }
        }
    }
}

/// Errors related to the token's serialization format or cryptographic
/// signature
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Format {
    #[error("failed verifying the signature")]
    Signature(Signature),
    #[error("failed verifying the signature of a sealed token")]
    SealedSignature,
    #[error("the token does not provide intermediate public keys")]
    EmptyKeys,
    #[error("the root public key was not recognized")]
    UnknownPublicKey,
    #[error("could not deserialize the wrapper object")]
    DeserializationError(String),
    #[error("could not serialize the wrapper object")]
    SerializationError(String),
    #[error("could not deserialize the block")]
    BlockDeserializationError(String),
    #[error("could not serialize the block")]
    BlockSerializationError(String),
    #[error("Block format version is higher than supported")]
    Version {
        maximum: u32,
        minimum: u32,
        actual: u32,
    },
    #[error("invalid key size")]
    InvalidKeySize(usize),
    #[error("invalid signature size")]
    InvalidSignatureSize(usize),
    #[error("invalid key")]
    InvalidKey(String),
    #[error("could not deserialize signature")]
    SignatureDeserializationError(String),
    #[error("could not deserialize the block signature")]
    BlockSignatureDeserializationError(String),
}

/// Signature errors
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Signature {
    #[error("could not parse the signature elements")]
    InvalidFormat,
    #[error("the signature did not match")]
    InvalidSignature(String),
    #[error("could not sign")]
    InvalidSignatureGeneration(String),
}

/// errors in the Datalog evaluation
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Logic {
    #[error("a rule provided by a block is generating facts with the authority or ambient tag, or has head variables not used in its body")]
    InvalidBlockRule(u32, String),
    #[error("authorization failed")]
    Unauthorized {
        /// the policy that matched
        policy: MatchedPolicy,
        /// list of checks that failed validation
        checks: Vec<FailedCheck>,
    },
    #[error("the authorizer already contains a token")]
    AuthorizerNotEmpty,
    #[error("no matching policy was found")]
    NoMatchingPolicy {
        /// list of checks that failed validation
        checks: Vec<FailedCheck>,
    },
}

#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum MatchedPolicy {
    #[error("an allow policy matched")]
    Allow(usize),
    #[error("a deny policy matched")]
    Deny(usize),
}

/// check errors
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum FailedCheck {
    #[error("a check failed in a block")]
    Block(FailedBlockCheck),
    #[error("a check provided by the authorizer failed")]
    Authorizer(FailedAuthorizerCheck),
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct FailedBlockCheck {
    pub block_id: u32,
    pub check_id: u32,
    /// pretty print of the rule that failed
    pub rule: String,
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct FailedAuthorizerCheck {
    pub check_id: u32,
    /// pretty print of the rule that failed
    pub rule: String,
}

/// runtime limits errors
#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum RunLimit {
    #[error("too many facts generated")]
    TooManyFacts,
    #[error("too many engine iterations")]
    TooManyIterations,
    #[error("spent too much time verifying")]
    Timeout,
}

#[derive(Error, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum LanguageError {
    #[error("datalog parsing error")]
    ParseError(ParseErrors),
    #[error("datalog parameters must all be bound, provided values must all be used. {missing_parameters:?} {unused_parameters:?}")]
    Parameters {
        missing_parameters: Vec<String>,
        unused_parameters: Vec<String>,
    },
    #[error("datalog fragments must not contain unbound parameters")]
    Builder { invalid_parameters: Vec<String> },
    #[error("cannot set value for an unknown parameter")]
    UnknownParameter(String),
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct ParseErrors {
    pub errors: Vec<ParseError>,
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct ParseError {
    pub input: String,
    pub message: Option<String>,
}

impl<'a> From<crate::parser::Error<'a>> for ParseError {
    fn from(e: crate::parser::Error<'a>) -> Self {
        ParseError {
            input: e.input.to_string(),
            message: e.message,
        }
    }
}

impl<'a> From<crate::parser::Error<'a>> for ParseErrors {
    fn from(error: crate::parser::Error<'a>) -> Self {
        ParseErrors {
            errors: vec![error.into()],
        }
    }
}

impl<'a> From<Vec<crate::parser::Error<'a>>> for ParseErrors {
    fn from(errors: Vec<crate::parser::Error<'a>>) -> Self {
        ParseErrors {
            errors: errors.into_iter().map(|e| e.into()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_format_strings() {
        assert_eq!(
            format!("{}", Token::ConversionError("test".to_owned())),
            "Cannot convert from Term: test"
        );

        assert_eq!(
            format!("{}", Token::Base64(Base64Error::InvalidLength)),
            "Cannot decode base64 token: Encoded text cannot have a 6-bit remainder."
        );
    }
}
