#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    InternalError,
    Format(Format),
    InvalidAuthorityIndex(u32),
    InvalidBlockIndex(InvalidBlockIndex),
    SymbolTableOverlap,
    Sealed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InvalidBlockIndex {
    pub expected: u32,
    pub found: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Format {
    Signature(Signature),
    SealedSignature,
    EmptyKeys,
    UnknownPublicKey,
    DeserializationError(String),
    SerializationError(String),
    BlockDeserializationError(String),
    BlockSerializationError(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    InvalidFormat,
    InvalidSignature,
}
