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
    pub facts: ::prost::alloc::vec::Vec<Fact>,
    #[prost(message, repeated, tag="4")]
    pub rules: ::prost::alloc::vec::Vec<Rule>,
    #[prost(message, repeated, tag="5")]
    pub caveats: ::prost::alloc::vec::Vec<Caveat>,
    #[prost(string, optional, tag="6")]
    pub context: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="7")]
    pub version: ::core::option::Option<u32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fact {
    #[prost(message, required, tag="1")]
    pub predicate: Predicate,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Rule {
    #[prost(message, required, tag="1")]
    pub head: Predicate,
    #[prost(message, repeated, tag="2")]
    pub body: ::prost::alloc::vec::Vec<Predicate>,
    #[prost(message, repeated, tag="3")]
    pub constraints: ::prost::alloc::vec::Vec<Constraint>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Caveat {
    #[prost(message, repeated, tag="1")]
    pub queries: ::prost::alloc::vec::Vec<Rule>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Predicate {
    #[prost(uint64, required, tag="1")]
    pub name: u64,
    #[prost(message, repeated, tag="2")]
    pub ids: ::prost::alloc::vec::Vec<Id>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Id {
    #[prost(enumeration="id::Kind", required, tag="1")]
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
/// Nested message and enum types in `ID`.
pub mod id {
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
pub struct Constraint {
    #[prost(uint32, required, tag="1")]
    pub id: u32,
    #[prost(enumeration="constraint::Kind", required, tag="2")]
    pub kind: i32,
    #[prost(message, optional, tag="3")]
    pub int: ::core::option::Option<IntConstraint>,
    #[prost(message, optional, tag="4")]
    pub str: ::core::option::Option<StringConstraint>,
    #[prost(message, optional, tag="5")]
    pub date: ::core::option::Option<DateConstraint>,
    #[prost(message, optional, tag="6")]
    pub symbol: ::core::option::Option<SymbolConstraint>,
    #[prost(message, optional, tag="7")]
    pub bytes: ::core::option::Option<BytesConstraint>,
}
/// Nested message and enum types in `Constraint`.
pub mod constraint {
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
pub struct IntConstraint {
    #[prost(enumeration="int_constraint::Kind", required, tag="1")]
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
/// Nested message and enum types in `IntConstraint`.
pub mod int_constraint {
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
pub struct StringConstraint {
    #[prost(enumeration="string_constraint::Kind", required, tag="1")]
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
/// Nested message and enum types in `StringConstraint`.
pub mod string_constraint {
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
pub struct DateConstraint {
    #[prost(enumeration="date_constraint::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, optional, tag="2")]
    pub before: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="3")]
    pub after: ::core::option::Option<u64>,
}
/// Nested message and enum types in `DateConstraint`.
pub mod date_constraint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Before = 0,
        After = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SymbolConstraint {
    #[prost(enumeration="symbol_constraint::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, repeated, packed="false", tag="2")]
    pub in_set: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, repeated, packed="false", tag="3")]
    pub not_in_set: ::prost::alloc::vec::Vec<u64>,
}
/// Nested message and enum types in `SymbolConstraint`.
pub mod symbol_constraint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        In = 0,
        NotIn = 1,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesConstraint {
    #[prost(enumeration="bytes_constraint::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(bytes="vec", optional, tag="2")]
    pub equal: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", repeated, tag="3")]
    pub in_set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", repeated, tag="4")]
    pub not_in_set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `BytesConstraint`.
pub mod bytes_constraint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Equal = 0,
        In = 1,
        NotIn = 2,
    }
}
