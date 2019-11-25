#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Biscuit {
    #[prost(bytes, required, tag="1")]
    pub authority: std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag="2")]
    pub blocks: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(bytes, repeated, tag="3")]
    pub keys: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(message, required, tag="4")]
    pub signature: Signature,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SealedBiscuit {
    #[prost(bytes, required, tag="1")]
    pub authority: std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag="2")]
    pub blocks: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(bytes, required, tag="3")]
    pub signature: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes, repeated, tag="1")]
    pub parameters: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(bytes, required, tag="2")]
    pub z: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(uint32, required, tag="1")]
    pub index: u32,
    #[prost(string, repeated, tag="2")]
    pub symbols: ::std::vec::Vec<std::string::String>,
    #[prost(message, repeated, tag="3")]
    pub facts: ::std::vec::Vec<Fact>,
    #[prost(message, repeated, tag="4")]
    pub rules: ::std::vec::Vec<Rule>,
    #[prost(message, repeated, tag="5")]
    pub caveats: ::std::vec::Vec<Rule>,
    #[prost(string, optional, tag="6")]
    pub context: ::std::option::Option<std::string::String>,
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
    pub body: ::std::vec::Vec<Predicate>,
    #[prost(message, repeated, tag="3")]
    pub constraints: ::std::vec::Vec<Constraint>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Predicate {
    #[prost(uint64, required, tag="1")]
    pub name: u64,
    #[prost(message, repeated, tag="2")]
    pub ids: ::std::vec::Vec<Id>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Id {
    #[prost(enumeration="id::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(uint64, optional, tag="2")]
    pub symbol: ::std::option::Option<u64>,
    #[prost(uint32, optional, tag="3")]
    pub variable: ::std::option::Option<u32>,
    #[prost(int64, optional, tag="4")]
    pub integer: ::std::option::Option<i64>,
    #[prost(string, optional, tag="5")]
    pub str: ::std::option::Option<std::string::String>,
    #[prost(uint64, optional, tag="6")]
    pub date: ::std::option::Option<u64>,
}
pub mod id {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Symbol = 0,
        Variable = 1,
        Integer = 2,
        Str = 3,
        Date = 4,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Constraint {
    #[prost(uint32, required, tag="1")]
    pub id: u32,
    #[prost(enumeration="constraint::Kind", required, tag="2")]
    pub kind: i32,
    #[prost(message, optional, tag="3")]
    pub int: ::std::option::Option<IntConstraint>,
    #[prost(message, optional, tag="4")]
    pub str: ::std::option::Option<StringConstraint>,
    #[prost(message, optional, tag="5")]
    pub date: ::std::option::Option<DateConstraint>,
    #[prost(message, optional, tag="6")]
    pub symbol: ::std::option::Option<SymbolConstraint>,
}
pub mod constraint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Int = 0,
        String = 1,
        Date = 2,
        Symbol = 3,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntConstraint {
    #[prost(enumeration="int_constraint::Kind", required, tag="1")]
    pub kind: i32,
    #[prost(int64, optional, tag="2")]
    pub lower: ::std::option::Option<i64>,
    #[prost(int64, optional, tag="3")]
    pub larger: ::std::option::Option<i64>,
    #[prost(int64, optional, tag="4")]
    pub lower_or_equal: ::std::option::Option<i64>,
    #[prost(int64, optional, tag="5")]
    pub larger_or_equal: ::std::option::Option<i64>,
    #[prost(int64, optional, tag="6")]
    pub equal: ::std::option::Option<i64>,
    #[prost(int64, repeated, tag="7")]
    pub in_set: ::std::vec::Vec<i64>,
    #[prost(int64, repeated, tag="8")]
    pub not_in_set: ::std::vec::Vec<i64>,
}
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
    pub prefix: ::std::option::Option<std::string::String>,
    #[prost(string, optional, tag="3")]
    pub suffix: ::std::option::Option<std::string::String>,
    #[prost(string, optional, tag="4")]
    pub equal: ::std::option::Option<std::string::String>,
    #[prost(string, repeated, tag="5")]
    pub in_set: ::std::vec::Vec<std::string::String>,
    #[prost(string, repeated, tag="6")]
    pub not_in_set: ::std::vec::Vec<std::string::String>,
    #[prost(string, optional, tag="7")]
    pub regex: ::std::option::Option<std::string::String>,
}
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
    pub before: ::std::option::Option<u64>,
    #[prost(uint64, optional, tag="3")]
    pub after: ::std::option::Option<u64>,
}
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
    pub in_set: ::std::vec::Vec<u64>,
    #[prost(uint64, repeated, packed="false", tag="3")]
    pub not_in_set: ::std::vec::Vec<u64>,
}
pub mod symbol_constraint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        In = 0,
        NotIn = 1,
    }
}
