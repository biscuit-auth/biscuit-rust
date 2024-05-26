#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Biscuit {
    #[prost(uint32, optional, tag="1")]
    pub root_key_id: ::core::option::Option<u32>,
    #[prost(message, required, tag="2")]
    pub authority: SignedBlock,
    #[prost(message, repeated, tag="3")]
    pub blocks: ::prost::alloc::vec::Vec<SignedBlock>,
    #[prost(message, required, tag="4")]
    pub proof: Proof,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedBlock {
    #[prost(bytes="vec", required, tag="1")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag="2")]
    pub next_key: PublicKey,
    #[prost(bytes="vec", required, tag="3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="4")]
    pub external_signature: ::core::option::Option<ExternalSignature>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalSignature {
    #[prost(bytes="vec", required, tag="1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag="2")]
    pub public_key: PublicKey,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(enumeration="public_key::Algorithm", required, tag="1")]
    pub algorithm: i32,
    #[prost(bytes="vec", required, tag="2")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `PublicKey`.
pub mod public_key {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Algorithm {
        Ed25519 = 0,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Proof {
    #[prost(oneof="proof::Content", tags="1, 2")]
    pub content: ::core::option::Option<proof::Content>,
}
/// Nested message and enum types in `Proof`.
pub mod proof {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(bytes, tag="1")]
        NextSecret(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag="2")]
        FinalSignature(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(string, repeated, tag="1")]
    pub symbols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub context: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="3")]
    pub version: ::core::option::Option<u32>,
    #[prost(message, repeated, tag="4")]
    pub facts_v2: ::prost::alloc::vec::Vec<FactV2>,
    #[prost(message, repeated, tag="5")]
    pub rules_v2: ::prost::alloc::vec::Vec<RuleV2>,
    #[prost(message, repeated, tag="6")]
    pub checks_v2: ::prost::alloc::vec::Vec<CheckV2>,
    #[prost(message, repeated, tag="7")]
    pub scope: ::prost::alloc::vec::Vec<Scope>,
    #[prost(message, repeated, tag="8")]
    pub public_keys: ::prost::alloc::vec::Vec<PublicKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Scope {
    #[prost(oneof="scope::Content", tags="1, 2")]
    pub content: ::core::option::Option<scope::Content>,
}
/// Nested message and enum types in `Scope`.
pub mod scope {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ScopeType {
        Authority = 0,
        Previous = 1,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(enumeration="ScopeType", tag="1")]
        ScopeType(i32),
        #[prost(int64, tag="2")]
        PublicKey(i64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactV2 {
    #[prost(message, required, tag="1")]
    pub predicate: PredicateV2,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuleV2 {
    #[prost(message, required, tag="1")]
    pub head: PredicateV2,
    #[prost(message, repeated, tag="2")]
    pub body: ::prost::alloc::vec::Vec<PredicateV2>,
    #[prost(message, repeated, tag="3")]
    pub expressions: ::prost::alloc::vec::Vec<ExpressionV2>,
    #[prost(message, repeated, tag="4")]
    pub scope: ::prost::alloc::vec::Vec<Scope>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckV2 {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<RuleV2>,
    #[prost(enumeration="check_v2::Kind", optional, tag="2")]
    pub kind: ::core::option::Option<i32>,
}
/// Nested message and enum types in `CheckV2`.
pub mod check_v2 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        One = 0,
        All = 1,
        Reject = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PredicateV2 {
    #[prost(uint64, required, tag="1")]
    pub name: u64,
    #[prost(message, repeated, tag="2")]
    pub terms: ::prost::alloc::vec::Vec<TermV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TermV2 {
    #[prost(oneof="term_v2::Content", tags="1, 2, 3, 4, 5, 6, 7, 8")]
    pub content: ::core::option::Option<term_v2::Content>,
}
/// Nested message and enum types in `TermV2`.
pub mod term_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(uint32, tag="1")]
        Variable(u32),
        #[prost(int64, tag="2")]
        Integer(i64),
        #[prost(uint64, tag="3")]
        String(u64),
        #[prost(uint64, tag="4")]
        Date(u64),
        #[prost(bytes, tag="5")]
        Bytes(::prost::alloc::vec::Vec<u8>),
        #[prost(bool, tag="6")]
        Bool(bool),
        #[prost(message, tag="7")]
        Set(super::TermSet),
        #[prost(message, tag="8")]
        Null(super::Empty),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TermSet {
    #[prost(message, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<TermV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExpressionV2 {
    #[prost(message, repeated, tag="1")]
    pub ops: ::prost::alloc::vec::Vec<Op>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Op {
    #[prost(oneof="op::Content", tags="1, 2, 3")]
    pub content: ::core::option::Option<op::Content>,
}
/// Nested message and enum types in `Op`.
pub mod op {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(message, tag="1")]
        Value(super::TermV2),
        #[prost(message, tag="2")]
        Unary(super::OpUnary),
        #[prost(message, tag="3")]
        Binary(super::OpBinary),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OpUnary {
    #[prost(enumeration="op_unary::Kind", required, tag="1")]
    pub kind: i32,
}
/// Nested message and enum types in `OpUnary`.
pub mod op_unary {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Negate = 0,
        Parens = 1,
        Length = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OpBinary {
    #[prost(enumeration="op_binary::Kind", required, tag="1")]
    pub kind: i32,
}
/// Nested message and enum types in `OpBinary`.
pub mod op_binary {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        LessThan = 0,
        GreaterThan = 1,
        LessOrEqual = 2,
        GreaterOrEqual = 3,
        Equal = 4,
        Contains = 5,
        Prefix = 6,
        Suffix = 7,
        Regex = 8,
        Add = 9,
        Sub = 10,
        Mul = 11,
        Div = 12,
        And = 13,
        Or = 14,
        Intersection = 15,
        Union = 16,
        BitwiseAnd = 17,
        BitwiseOr = 18,
        BitwiseXor = 19,
        NotEqual = 20,
        HeterogeneousEqual = 21,
        HeterogeneousNotEqual = 22,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Policy {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<RuleV2>,
    #[prost(enumeration="policy::Kind", required, tag="2")]
    pub kind: i32,
}
/// Nested message and enum types in `Policy`.
pub mod policy {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Allow = 0,
        Deny = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizerPolicies {
    #[prost(string, repeated, tag="1")]
    pub symbols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="2")]
    pub version: ::core::option::Option<u32>,
    #[prost(message, repeated, tag="3")]
    pub facts: ::prost::alloc::vec::Vec<FactV2>,
    #[prost(message, repeated, tag="4")]
    pub rules: ::prost::alloc::vec::Vec<RuleV2>,
    #[prost(message, repeated, tag="5")]
    pub checks: ::prost::alloc::vec::Vec<CheckV2>,
    #[prost(message, repeated, tag="6")]
    pub policies: ::prost::alloc::vec::Vec<Policy>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThirdPartyBlockRequest {
    #[prost(message, required, tag="1")]
    pub previous_key: PublicKey,
    #[prost(message, repeated, tag="2")]
    pub public_keys: ::prost::alloc::vec::Vec<PublicKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThirdPartyBlockContents {
    #[prost(bytes="vec", required, tag="1")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, required, tag="2")]
    pub external_signature: ExternalSignature,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizerSnapshot {
    #[prost(message, required, tag="1")]
    pub limits: RunLimits,
    #[prost(uint64, required, tag="2")]
    pub execution_time: u64,
    #[prost(message, required, tag="3")]
    pub world: AuthorizerWorld,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RunLimits {
    #[prost(uint64, required, tag="1")]
    pub max_facts: u64,
    #[prost(uint64, required, tag="2")]
    pub max_iterations: u64,
    #[prost(uint64, required, tag="3")]
    pub max_time: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorizerWorld {
    #[prost(uint32, optional, tag="1")]
    pub version: ::core::option::Option<u32>,
    #[prost(string, repeated, tag="2")]
    pub symbols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="3")]
    pub public_keys: ::prost::alloc::vec::Vec<PublicKey>,
    #[prost(message, repeated, tag="4")]
    pub blocks: ::prost::alloc::vec::Vec<SnapshotBlock>,
    #[prost(message, required, tag="5")]
    pub authorizer_block: SnapshotBlock,
    #[prost(message, repeated, tag="6")]
    pub authorizer_policies: ::prost::alloc::vec::Vec<Policy>,
    #[prost(message, repeated, tag="7")]
    pub generated_facts: ::prost::alloc::vec::Vec<GeneratedFacts>,
    #[prost(uint64, required, tag="8")]
    pub iterations: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Origin {
    #[prost(oneof="origin::Content", tags="1, 2")]
    pub content: ::core::option::Option<origin::Content>,
}
/// Nested message and enum types in `Origin`.
pub mod origin {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(message, tag="1")]
        Authorizer(super::Empty),
        #[prost(uint32, tag="2")]
        Origin(u32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeneratedFacts {
    #[prost(message, repeated, tag="1")]
    pub origins: ::prost::alloc::vec::Vec<Origin>,
    #[prost(message, repeated, tag="2")]
    pub facts: ::prost::alloc::vec::Vec<FactV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotBlock {
    #[prost(string, optional, tag="1")]
    pub context: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="2")]
    pub version: ::core::option::Option<u32>,
    #[prost(message, repeated, tag="3")]
    pub facts_v2: ::prost::alloc::vec::Vec<FactV2>,
    #[prost(message, repeated, tag="4")]
    pub rules_v2: ::prost::alloc::vec::Vec<RuleV2>,
    #[prost(message, repeated, tag="5")]
    pub checks_v2: ::prost::alloc::vec::Vec<CheckV2>,
    #[prost(message, repeated, tag="6")]
    pub scope: ::prost::alloc::vec::Vec<Scope>,
    #[prost(message, optional, tag="7")]
    pub external_key: ::core::option::Option<PublicKey>,
}
