#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    InternalError,
    Format(Format),
    InvalidAuthorityIndex(u32),
    InvalidBlockIndex(InvalidBlockIndex),
    SymbolTableOverlap,
    Sealed,
    FailedLogic(Vec<Logic>),
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

#[derive(Clone, Debug, PartialEq)]
pub enum Logic {
    InvalidAuthorityFact(String),
    InvalidAmbientFact(String),
    InvalidBlockFact(u32, String),
    FailedCaveats(Vec<FailedCaveat>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FailedCaveat {
    Block(FailedBlockCaveat),
    Verifier(FailedVerifierCaveat),
}

#[derive(Clone, Debug, PartialEq)]
pub struct FailedBlockCaveat {
    pub block_id: u32,
    pub caveat_id: u32,
    pub rule: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FailedVerifierCaveat {
    pub caveat_id: u32,
    pub rule: String,
}
