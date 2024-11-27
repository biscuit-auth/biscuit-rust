use std::convert::TryFrom;

use crate::error;

#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub enum Algorithm {
    Ed25519,
    Secp256r1,
}

impl TryFrom<&str> for Algorithm {
    type Error = error::Format;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ed25519" => Ok(Algorithm::Ed25519),
            "secp256r1" => Ok(Algorithm::Secp256r1),
            _ => Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                value
            ))),
        }
    }
}

impl From<biscuit_parser::builder::Algorithm> for Algorithm {
    fn from(value: biscuit_parser::builder::Algorithm) -> Algorithm {
        match value {
            biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
            biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for biscuit_parser::builder::Algorithm {
    fn from(value: Algorithm) -> biscuit_parser::builder::Algorithm {
        match value {
            Algorithm::Ed25519 => biscuit_parser::builder::Algorithm::Ed25519,
            Algorithm::Secp256r1 => biscuit_parser::builder::Algorithm::Secp256r1,
        }
    }
}

impl From<crate::format::schema::public_key::Algorithm> for Algorithm {
    fn from(value: crate::format::schema::public_key::Algorithm) -> Algorithm {
        match value {
            crate::format::schema::public_key::Algorithm::Ed25519 => Algorithm::Ed25519,
            crate::format::schema::public_key::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for crate::format::schema::public_key::Algorithm {
    fn from(value: Algorithm) -> crate::format::schema::public_key::Algorithm {
        match value {
            Algorithm::Ed25519 => crate::format::schema::public_key::Algorithm::Ed25519,
            Algorithm::Secp256r1 => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}
