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
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckV2 {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<RuleV2>,
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
    #[prost(oneof="term_v2::Content", tags="1, 2, 3, 4, 5, 6, 7")]
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
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TermSet {
    #[prost(message, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<TermV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConstraintV2 {
    #[prost(uint32, required, tag="1")]
    pub term: u32,
    #[prost(oneof="constraint_v2::Constraint", tags="2, 3, 4, 5")]
    pub constraint: ::core::option::Option<constraint_v2::Constraint>,
}
/// Nested message and enum types in `ConstraintV2`.
pub mod constraint_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(message, tag="2")]
        Int(super::IntConstraintV2),
        #[prost(message, tag="3")]
        String(super::StringConstraintV2),
        #[prost(message, tag="4")]
        Date(super::DateConstraintV2),
        #[prost(message, tag="5")]
        Bytes(super::BytesConstraintV2),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntConstraintV2 {
    #[prost(oneof="int_constraint_v2::Constraint", tags="1, 2, 3, 4, 5, 6, 7")]
    pub constraint: ::core::option::Option<int_constraint_v2::Constraint>,
}
/// Nested message and enum types in `IntConstraintV2`.
pub mod int_constraint_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(int64, tag="1")]
        LessThan(i64),
        #[prost(int64, tag="2")]
        GreaterThan(i64),
        #[prost(int64, tag="3")]
        LessOrEqual(i64),
        #[prost(int64, tag="4")]
        GreaterOrEqual(i64),
        #[prost(int64, tag="5")]
        Equal(i64),
        #[prost(message, tag="6")]
        InSet(super::IntSet),
        #[prost(message, tag="7")]
        NotInSet(super::IntSet),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntSet {
    #[prost(int64, repeated, tag="7")]
    pub set: ::prost::alloc::vec::Vec<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringConstraintV2 {
    #[prost(oneof="string_constraint_v2::Constraint", tags="1, 2, 3, 4, 5, 6")]
    pub constraint: ::core::option::Option<string_constraint_v2::Constraint>,
}
/// Nested message and enum types in `StringConstraintV2`.
pub mod string_constraint_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(string, tag="1")]
        Prefix(::prost::alloc::string::String),
        #[prost(string, tag="2")]
        Suffix(::prost::alloc::string::String),
        #[prost(string, tag="3")]
        Equal(::prost::alloc::string::String),
        #[prost(message, tag="4")]
        InSet(super::StringSet),
        #[prost(message, tag="5")]
        NotInSet(super::StringSet),
        #[prost(string, tag="6")]
        Regex(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringSet {
    #[prost(uint64, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DateConstraintV2 {
    #[prost(oneof="date_constraint_v2::Constraint", tags="1, 2")]
    pub constraint: ::core::option::Option<date_constraint_v2::Constraint>,
}
/// Nested message and enum types in `DateConstraintV2`.
pub mod date_constraint_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(uint64, tag="1")]
        Before(u64),
        #[prost(uint64, tag="2")]
        After(u64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesConstraintV2 {
    #[prost(oneof="bytes_constraint_v2::Constraint", tags="1, 2, 3")]
    pub constraint: ::core::option::Option<bytes_constraint_v2::Constraint>,
}
/// Nested message and enum types in `BytesConstraintV2`.
pub mod bytes_constraint_v2 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(bytes, tag="1")]
        Equal(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag="2")]
        InSet(super::BytesSet),
        #[prost(message, tag="3")]
        NotInSet(super::BytesSet),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesSet {
    #[prost(bytes="vec", repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
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
