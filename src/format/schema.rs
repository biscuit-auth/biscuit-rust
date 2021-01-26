#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Biscuit {
    #[prost(bytes="vec", required, tag="1")]
    pub authority: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", repeated, tag="2")]
    pub blocks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", repeated, tag="3")]
    pub keys: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, required, tag="4")]
    pub signature: Signature,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SealedBiscuit {
    #[prost(bytes="vec", required, tag="1")]
    pub authority: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", repeated, tag="2")]
    pub blocks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", required, tag="3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes="vec", repeated, tag="1")]
    pub parameters: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", required, tag="2")]
    pub z: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(uint32, required, tag="1")]
    pub index: u32,
    #[prost(string, repeated, tag="2")]
    pub symbols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="3")]
    pub facts_v0: ::prost::alloc::vec::Vec<FactV0>,
    #[prost(message, repeated, tag="4")]
    pub rules_v0: ::prost::alloc::vec::Vec<RuleV0>,
    #[prost(message, repeated, tag="5")]
    pub caveats_v0: ::prost::alloc::vec::Vec<CaveatV0>,
    #[prost(string, optional, tag="6")]
    pub context: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="7")]
    pub version: ::core::option::Option<u32>,
    #[prost(message, repeated, tag="8")]
    pub facts_v1: ::prost::alloc::vec::Vec<FactV1>,
    #[prost(message, repeated, tag="9")]
    pub rules_v1: ::prost::alloc::vec::Vec<RuleV1>,
    #[prost(message, repeated, tag="10")]
    pub checks_v1: ::prost::alloc::vec::Vec<CheckV1>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactV0 {
    #[prost(message, required, tag="1")]
    pub predicate: PredicateV0,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuleV0 {
    #[prost(message, required, tag="1")]
    pub head: PredicateV0,
    #[prost(message, repeated, tag="2")]
    pub body: ::prost::alloc::vec::Vec<PredicateV0>,
    #[prost(message, repeated, tag="3")]
    pub constraints: ::prost::alloc::vec::Vec<ConstraintV0>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CaveatV0 {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<RuleV0>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PredicateV0 {
    #[prost(uint64, required, tag="1")]
    pub name: u64,
    #[prost(message, repeated, tag="2")]
    pub ids: ::prost::alloc::vec::Vec<Idv0>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Idv0 {
    #[prost(enumeration="idv0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, optional, tag="2")]
    pub symbol: ::core::option::Option<u64>,
    #[prost(uint32, optional, tag="3")]
    pub variable: ::core::option::Option<u32>,
    #[prost(int64, optional, tag="4")]
    pub integer: ::core::option::Option<i64>,
    #[prost(string, optional, tag="5")]
    pub str: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag="6")]
    pub date: ::core::option::Option<u64>,
    #[prost(bytes="vec", optional, tag="7")]
    pub bytes: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `IDV0`.
pub mod idv0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Symbol = 0,
        Variable = 1,
        Integer = 2,
        Str = 3,
        Date = 4,
        Bytes = 5,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConstraintV0 {
    #[prost(uint32, required, tag="1")]
    pub id: u32,
    #[prost(enumeration="constraint_v0::Kind", required, tag="2")]
    pub kind: i32,
    #[prost(message, optional, tag="3")]
    pub int: ::core::option::Option<IntConstraintV0>,
    #[prost(message, optional, tag="4")]
    pub str: ::core::option::Option<StringConstraintV0>,
    #[prost(message, optional, tag="5")]
    pub date: ::core::option::Option<DateConstraintV0>,
    #[prost(message, optional, tag="6")]
    pub symbol: ::core::option::Option<SymbolConstraintV0>,
    #[prost(message, optional, tag="7")]
    pub bytes: ::core::option::Option<BytesConstraintV0>,
}
/// Nested message and enum types in `ConstraintV0`.
pub mod constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Int = 0,
        String = 1,
        Date = 2,
        Symbol = 3,
        Bytes = 4,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntConstraintV0 {
    #[prost(enumeration="int_constraint_v0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(int64, optional, tag="2")]
    pub lower: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="3")]
    pub larger: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="4")]
    pub lower_or_equal: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="5")]
    pub larger_or_equal: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="6")]
    pub equal: ::core::option::Option<i64>,
    #[prost(int64, repeated, tag="7")]
    pub in_set: ::prost::alloc::vec::Vec<i64>,
    #[prost(int64, repeated, tag="8")]
    pub not_in_set: ::prost::alloc::vec::Vec<i64>,
}
/// Nested message and enum types in `IntConstraintV0`.
pub mod int_constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Lower = 0,
        Larger = 1,
        LowerOrEqual = 2,
        LargerOrEqual = 3,
        Equal = 4,
        In = 5,
        NotIn = 6,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringConstraintV0 {
    #[prost(enumeration="string_constraint_v0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(string, optional, tag="2")]
    pub prefix: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub suffix: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub equal: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="5")]
    pub in_set: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="6")]
    pub not_in_set: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub regex: ::core::option::Option<::prost::alloc::string::String>,
}
/// Nested message and enum types in `StringConstraintV0`.
pub mod string_constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Prefix = 0,
        Suffix = 1,
        Equal = 2,
        In = 3,
        NotIn = 4,
        Regex = 5,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DateConstraintV0 {
    #[prost(enumeration="date_constraint_v0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, optional, tag="2")]
    pub before: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="3")]
    pub after: ::core::option::Option<u64>,
}
/// Nested message and enum types in `DateConstraintV0`.
pub mod date_constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Before = 0,
        After = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SymbolConstraintV0 {
    #[prost(enumeration="symbol_constraint_v0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, repeated, packed="false", tag="2")]
    pub in_set: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, repeated, packed="false", tag="3")]
    pub not_in_set: ::prost::alloc::vec::Vec<u64>,
}
/// Nested message and enum types in `SymbolConstraintV0`.
pub mod symbol_constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        In = 0,
        NotIn = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesConstraintV0 {
    #[prost(enumeration="bytes_constraint_v0::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(bytes="vec", optional, tag="2")]
    pub equal: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", repeated, tag="3")]
    pub in_set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", repeated, tag="4")]
    pub not_in_set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `BytesConstraintV0`.
pub mod bytes_constraint_v0 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Equal = 0,
        In = 1,
        NotIn = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactV1 {
    #[prost(message, required, tag="1")]
    pub predicate: PredicateV1,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuleV1 {
    #[prost(message, required, tag="1")]
    pub head: PredicateV1,
    #[prost(message, repeated, tag="2")]
    pub body: ::prost::alloc::vec::Vec<PredicateV1>,
    #[prost(message, repeated, tag="3")]
    pub expressions: ::prost::alloc::vec::Vec<ExpressionV1>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckV1 {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<RuleV1>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PredicateV1 {
    #[prost(uint64, required, tag="1")]
    pub name: u64,
    #[prost(message, repeated, tag="2")]
    pub ids: ::prost::alloc::vec::Vec<Idv1>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Idv1 {
    #[prost(oneof="idv1::Content", tags="1, 2, 3, 4, 5, 6, 7, 8")]
    pub content: ::core::option::Option<idv1::Content>,
}
/// Nested message and enum types in `IDV1`.
pub mod idv1 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        #[prost(uint64, tag="1")]
        Symbol(u64),
        #[prost(uint32, tag="2")]
        Variable(u32),
        #[prost(int64, tag="3")]
        Integer(i64),
        #[prost(string, tag="4")]
        String(::prost::alloc::string::String),
        #[prost(uint64, tag="5")]
        Date(u64),
        #[prost(bytes, tag="6")]
        Bytes(::prost::alloc::vec::Vec<u8>),
        #[prost(bool, tag="7")]
        Bool(bool),
        #[prost(message, tag="8")]
        Set(super::IdSet),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdSet {
    #[prost(message, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<Idv1>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConstraintV1 {
    #[prost(uint32, required, tag="1")]
    pub id: u32,
    #[prost(oneof="constraint_v1::Constraint", tags="2, 3, 4, 5, 6")]
    pub constraint: ::core::option::Option<constraint_v1::Constraint>,
}
/// Nested message and enum types in `ConstraintV1`.
pub mod constraint_v1 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(message, tag="2")]
        Int(super::IntConstraintV1),
        #[prost(message, tag="3")]
        String(super::StringConstraintV1),
        #[prost(message, tag="4")]
        Date(super::DateConstraintV1),
        #[prost(message, tag="5")]
        Symbol(super::SymbolConstraintV1),
        #[prost(message, tag="6")]
        Bytes(super::BytesConstraintV1),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntConstraintV1 {
    #[prost(oneof="int_constraint_v1::Constraint", tags="1, 2, 3, 4, 5, 6, 7")]
    pub constraint: ::core::option::Option<int_constraint_v1::Constraint>,
}
/// Nested message and enum types in `IntConstraintV1`.
pub mod int_constraint_v1 {
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
pub struct StringConstraintV1 {
    #[prost(oneof="string_constraint_v1::Constraint", tags="1, 2, 3, 4, 5, 6")]
    pub constraint: ::core::option::Option<string_constraint_v1::Constraint>,
}
/// Nested message and enum types in `StringConstraintV1`.
pub mod string_constraint_v1 {
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
    #[prost(string, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DateConstraintV1 {
    #[prost(oneof="date_constraint_v1::Constraint", tags="1, 2")]
    pub constraint: ::core::option::Option<date_constraint_v1::Constraint>,
}
/// Nested message and enum types in `DateConstraintV1`.
pub mod date_constraint_v1 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(uint64, tag="1")]
        Before(u64),
        #[prost(uint64, tag="2")]
        After(u64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SymbolConstraintV1 {
    #[prost(oneof="symbol_constraint_v1::Constraint", tags="1, 2")]
    pub constraint: ::core::option::Option<symbol_constraint_v1::Constraint>,
}
/// Nested message and enum types in `SymbolConstraintV1`.
pub mod symbol_constraint_v1 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Constraint {
        #[prost(message, tag="1")]
        InSet(super::SymbolSet),
        #[prost(message, tag="2")]
        NotInSet(super::SymbolSet),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SymbolSet {
    #[prost(uint64, repeated, tag="1")]
    pub set: ::prost::alloc::vec::Vec<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesConstraintV1 {
    #[prost(oneof="bytes_constraint_v1::Constraint", tags="1, 2, 3")]
    pub constraint: ::core::option::Option<bytes_constraint_v1::Constraint>,
}
/// Nested message and enum types in `BytesConstraintV1`.
pub mod bytes_constraint_v1 {
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
pub struct ExpressionV1 {
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
        Value(super::Idv1),
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
    }
}
