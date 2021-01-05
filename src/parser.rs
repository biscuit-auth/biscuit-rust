//! Datalog text format parsing
//!
//! all of the parsers are usable with [`TryFrom`] so they can be used
//! as follows:
//!
//! ```rust
//! use std::convert::TryInto;
//! use biscuit_auth::token::builder::Fact;
//!
//! let f: Fact = "test(#data)".try_into().expect("parse error");
//! ```
//!
//! All of the methods in [BiscuitBuilder](`crate::token::builder::BiscuitBuilder`)
//! and [BlockBuilder](`crate::token::builder::BlockBuilder`) can take strings
//! as arguments too
use crate::{datalog, error, token::builder};
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag, take_while1},
    character::{
        complete::{char, digit1, multispace0 as space0},
        is_alphanumeric,
    },
    combinator::{map, map_opt, map_res, opt, recognize, value},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, pair, preceded},
    IResult,
};
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    time::{Duration, SystemTime},
};

/// parse a Datalog fact
pub fn fact(i: &str) -> IResult<&str, builder::Fact> {
    predicate(i).map(|(i, p)| (i, builder::Fact(p)))
}

/// parse a Datalog caveat
pub fn caveat(i: &str) -> IResult<&str, builder::Caveat> {
    let (i, queries) = separated_list1(
      preceded(space0, tag("||")),
      preceded(space0, rule)
    )(i)?;

    Ok((i, builder::Caveat { queries }))
}

/// parse a Datalog rule
pub fn rule(i: &str) -> IResult<&str, builder::Rule> {
    let (i, head) = rule_head(i)?;
    let (i, _) = space0(i)?;

    let (i, _) = tag("<-")(i)?;

    let (i, _) = space0(i)?;
    let (i, predicates) = separated_list1(
      preceded(space0, char(',')),
      preceded(space0, predicate)
    )(i)?;

    let (i, constraints) = if let Ok((i, _)) =
        preceded::<_, _, _, (&str, nom::error::ErrorKind), _, _>(space0, char('@'))(i)
    {
        separated_list1(preceded(space0, char(',')), constraint)(i)?
    } else {
        (i, Vec::new())
    };

    Ok((i, builder::Rule(head, predicates, constraints)))
}

impl TryFrom<&str> for builder::Fact {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        fact(value)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl TryFrom<&str> for builder::Rule {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        rule(value)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl FromStr for builder::Fact {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fact(s)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl FromStr for builder::Rule {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        rule(s)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl TryFrom<&str> for builder::Caveat {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        caveat(value)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl FromStr for builder::Caveat {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        caveat(s)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

impl FromStr for builder::Predicate {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        predicate(s)
            .map(|(_, o)| o)
            .map_err(|_| error::Token::ParseError)
    }
}

fn predicate(i: &str) -> IResult<&str, builder::Predicate> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, ids) = delimited(
        char('('),
        separated_list1(preceded(space0, char(',')), term),
        preceded(space0, char(')')),
    )(i)?;

    Ok((
        i,
        builder::Predicate {
            name: fact_name.to_string(),
            ids,
        },
    ))
}

fn rule_head(i: &str) -> IResult<&str, builder::Predicate> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, ids) = delimited(
        char('('),
        separated_list0(preceded(space0, char(',')), term),
        preceded(space0, char(')')),
    )(i)?;

    Ok((
        i,
        builder::Predicate {
            name: fact_name.to_string(),
            ids,
        },
    ))
}

fn constraint(i: &str) -> IResult<&str, builder::Constraint> {
    let (i, _) = space0(i)?;
    let (i, id) = map_res(preceded(char('$'), name), |s| s.parse())(i)?;
    let (i, kind) = constraint_kind(i)?;

    Ok((i, builder::Constraint { id, kind }))
}

#[derive(Clone)]
enum Operator {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    In,
    NotIn,
    Matches,
}

fn operator(i: &str) -> IResult<&str, Operator> {
    alt((
        value(Operator::LessOrEqual, tag("<=")),
        value(Operator::GreaterOrEqual, tag(">=")),
        value(Operator::LessThan, tag("<")),
        value(Operator::GreaterThan, tag(">")),
        value(Operator::Equal, tag("==")),
        value(Operator::In, tag("in")),
        value(Operator::NotIn, tag("not in")),
        value(Operator::Matches, tag("matches")),
    ))(i)
}

fn constraint_kind(i: &str) -> IResult<&str, builder::ConstraintKind> {
    let (i, op) = delimited(space0, operator, space0)(i)?;

    match op {
        Operator::LessThan => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::Before(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::LessThan(i))
            }),
        ))(i),
        Operator::GreaterThan => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::After(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::GreaterThan(i))
            }),
        ))(i),
        Operator::LessOrEqual => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::Before(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::LessOrEqual(i))
            }),
        ))(i),
        Operator::GreaterOrEqual => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::After(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::GreaterOrEqual(i))
            }),
        ))(i),
        Operator::Equal => alt((
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::Equal(i))
            }),
            map(parse_string, |s| {
                builder::ConstraintKind::String(datalog::StrConstraint::Equal(s))
            }),
            map(parse_bytes, |s| {
                builder::ConstraintKind::Bytes(datalog::BytesConstraint::Equal(s))
            }),
        ))(i),
        Operator::In => delimited(
            char('['),
            alt((
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_integer),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Integer(datalog::IntConstraint::In(
                            h.drain(..).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_string),
                    ),
                    |mut h| {
                        builder::ConstraintKind::String(datalog::StrConstraint::In(
                            h.drain(..).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_symbol),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Symbol(builder::SymbolConstraint::In(
                            h.drain(..).map(|s| s.to_string()).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_bytes),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Bytes(datalog::BytesConstraint::In(
                            h.drain(..).collect(),
                        ))
                    },
                ),
            )),
            preceded(space0, char(']')),
        )(i),
        Operator::NotIn => delimited(
            char('['),
            alt((
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_integer),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Integer(datalog::IntConstraint::NotIn(
                            h.drain(..).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_string),
                    ),
                    |mut h| {
                        builder::ConstraintKind::String(datalog::StrConstraint::NotIn(
                            h.drain(..).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_symbol),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Symbol(builder::SymbolConstraint::NotIn(
                            h.drain(..).map(|s| s.to_string()).collect(),
                        ))
                    },
                ),
                map(
                    separated_list1(
                        preceded(space0, char(',')),
                        preceded(space0, parse_bytes),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Bytes(datalog::BytesConstraint::NotIn(
                            h.drain(..).collect(),
                        ))
                    },
                ),
            )),
            preceded(space0, char(']')),
        )(i),
        Operator::Matches => alt((
            map_opt(parse_string, |mut s| {
                if !s.is_empty() {
                    if s.get(..1) == Some("*") {
                        let _ = s.remove(0);
                        return Some(builder::ConstraintKind::String(
                            datalog::StrConstraint::Suffix(s),
                        ));
                    } else if s.get(s.len() - 1..) == Some("*") {
                        let _ = s.pop();
                        return Some(builder::ConstraintKind::String(
                            datalog::StrConstraint::Prefix(s),
                        ));
                    }
                }
                None
            }),
            map(
                regex, //delimited(char('/'), parse_string_internal, char('/')),
                |s| builder::ConstraintKind::String(datalog::StrConstraint::Regex(s)),
            ),
        ))(i),
    }
}

fn name(i: &str) -> IResult<&str, &str> {
    let is_name_char = |c: char| is_alphanumeric(c as u8) || c == '_';

    take_while1(is_name_char)(i)
}

fn printable(i: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c != '\\' && c != '"')(i)
}

fn parse_string_internal(i: &str) -> IResult<&str, String> {
    escaped_transform(
        printable,
        '\\',
        alt((
            map(char('\\'), |_| "\\"),
            map(char('"'), |_| "\""),
            map(char('n'), |_| "\n"),
        )),
    )(i)
}

fn parse_string(i: &str) -> IResult<&str, String> {
    delimited(char('"'), parse_string_internal, char('"'))(i)
}

fn string(i: &str) -> IResult<&str, builder::Term> {
    parse_string(i).map(|(i, s)| (i, builder::Term::Str(s)))
}

fn parse_symbol(i: &str) -> IResult<&str, &str> {
    preceded(char('#'), name)(i)
}

fn symbol(i: &str) -> IResult<&str, builder::Term> {
    parse_symbol(i).map(|(i, s)| (i, builder::s(s)))
}

fn parse_integer(i: &str) -> IResult<&str, i64> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| s.parse())(i)
}
fn integer(i: &str) -> IResult<&str, builder::Term> {
    parse_integer(i).map(|(i, n)| (i, builder::int(n)))
}

fn parse_date(i: &str) -> IResult<&str, u64> {
    map_res(
        map_res(take_while1(|c: char| c != ',' && c != ' ' && c != ')'), |s| {
            let r = chrono::DateTime::parse_from_rfc3339(s);
            r
        }),
        |t| {
            let r = t.timestamp().try_into();
            r
        },
    )(i)
}

fn date(i: &str) -> IResult<&str, builder::Term> {
    parse_date(i).map(|(i, t)| (i, builder::Term::Date(t)))
}

fn parse_bytes(i: &str) -> IResult<&str, Vec<u8>> {
    preceded(
        tag("hex:"),
        map_res(
            take_while1(|c| {
                let c = c as u8;
                (b'0' <= c && c <= b'9')
                    || (b'a' <= c && c <= b'f')
                    || (b'A' <= c && c <= b'F')
            }),
            hex::decode
        )
    )(i)
}

fn bytes(i: &str) -> IResult<&str, builder::Term> {
    parse_bytes(i).map(|(i, s)| (i, builder::Term::Bytes(s)))
}

fn variable(i: &str) -> IResult<&str, builder::Term> {
    map(
        preceded(char('$'), name),
        builder::variable,
    )(i)
}

fn term(i: &str) -> IResult<&str, builder::Term> {
    preceded(space0, alt((symbol, string, date, variable, integer, bytes)))(i)
}

fn regex(i: &str) -> IResult<&str, String> {
    delimited(
        char('/'),
        escaped_transform(
            take_while1(|c: char| c != '\\' && c != '/'),
            '\\',
            alt((
                map(char('\\'), |_| "\\"),
                map(char('"'), |_| "\""),
                map(char('n'), |_| "\n"),
                map(char('/'), |_| "/"),
            )),
        ),
        char('/'),
    )(i)
}

#[cfg(test)]
mod tests {
    use crate::{datalog, token::builder};
    use std::collections::HashSet;

    #[test]
    fn name() {
        assert_eq!(
            super::name("operation(#ambient, #read)"),
            Ok(("(#ambient, #read)", "operation"))
        );
    }

    #[test]
    fn symbol() {
        assert_eq!(super::symbol("#ambient"), Ok(("", builder::s("ambient"))));
    }

    #[test]
    fn string() {
        assert_eq!(
            super::string("\"file1 a hello - 123_\""),
            Ok(("", builder::string("file1 a hello - 123_")))
        );
    }

    #[test]
    fn integer() {
        assert_eq!(super::integer("123"), Ok(("", builder::int(123))));
        assert_eq!(super::integer("-42"), Ok(("", builder::int(-42))));
    }

    #[test]
    fn date() {
        assert_eq!(
            super::date("2019-12-02T13:49:53Z"),
            Ok(("", builder::Term::Date(1575294593)))
        );
    }

    #[test]
    fn variable() {
        assert_eq!(super::variable("$1"), Ok(("", builder::variable("1"))));
    }

    #[test]
    fn constraint() {
        assert_eq!(
            super::constraint("$0 <= 2030-12-31T12:59:59+00:00"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Date(builder::DateConstraint::Before(
                        std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_secs(1924952399)
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 >= 2030-12-31T12:59:59+00:00"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Date(builder::DateConstraint::After(
                        std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_secs(1924952399)
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 < 1234"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::LessThan(1234)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 > 1234"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::GreaterThan(1234)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 <= 1234"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::LessOrEqual(
                        1234
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 >= -1234"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::GreaterOrEqual(
                        -1234
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 == 1"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::Equal(1)),
                }
            ))
        );

        let h = [1, 2].iter().cloned().collect::<HashSet<_>>();
        assert_eq!(
            super::constraint("$0 in [1, 2]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [1, 2]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::NotIn(h)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 == \"abc\""),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::Equal(
                        "abc".to_string()
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 matches \"*abc\""),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::Suffix(
                        "abc".to_string()
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 matches \"abc*\""),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::Prefix(
                        "abc".to_string()
                    )),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 matches /abc[0-9]+/"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::Regex(
                        "abc[0-9]+".to_string()
                    )),
                }
            ))
        );

        let h = ["abc".to_string(), "def".to_string()]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            super::constraint("$0 in [\"abc\", \"def\"]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [\"abc\", \"def\"]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::NotIn(h)),
                }
            ))
        );

        let h = ["abc".to_string(), "def".to_string()]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(
            super::constraint("$0 in [#abc, #def]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Symbol(builder::SymbolConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [#abc, #def]"),
            Ok((
                "",
                builder::Constraint {
                    id: "0".to_string(),
                    kind: builder::ConstraintKind::Symbol(builder::SymbolConstraint::NotIn(h)),
                }
            ))
        );
    }

    #[test]
    fn fact() {
        assert_eq!(
            super::fact("right( #authority, \"file1\", #read )"),
            Ok((
                "",
                builder::fact(
                    "right",
                    &[
                        builder::s("authority"),
                        builder::string("file1"),
                        builder::s("read")
                    ]
                )
            ))
        );
    }

    #[test]
    fn fact_with_date() {
        assert_eq!(
            super::fact("date(#ambient,2019-12-02T13:49:53Z)"),
            Ok(("",
                builder::fact(
                    "date",
                    &[
                        builder::s("ambient"),
                        builder::Term::Date(1575294593)
                    ]
                )
            ))
        );
    }


    #[test]
    fn rule() {
        assert_eq!(
            super::rule("right(#authority, $0, #read) <- resource( #ambient, $0), operation(#ambient, #read)"),
            Ok((
                "",
                builder::rule(
                    "right",
                    &[
                        builder::s("authority"),
                        builder::variable("0"),
                        builder::s("read"),
                    ],
                    &[
                        builder::pred("resource", &[builder::s("ambient"), builder::variable("0")]),
                        builder::pred("operation", &[builder::s("ambient"), builder::s("read")]),
                    ]
                )
            ))
        );
    }

    #[test]
    fn constrained_rule() {
        assert_eq!(
            super::rule("valid_date(\"file1\") <- time(#ambient, $0 ), resource( #ambient, \"file1\") @ $0 <= 2019-12-04T09:46:41+00:00"),
            Ok((
                "",
                builder::constrained_rule(
                    "valid_date",
                    &[
                        builder::string("file1"),
                    ],
                    &[
                        builder::pred("time", &[builder::s("ambient"), builder::variable("0")]),
                        builder::pred("resource", &[builder::s("ambient"), builder::string("file1")]),
                    ],
                    &[builder::Constraint {
                      id: "0".to_string(),
                      kind: builder::ConstraintKind::Date(builder::DateConstraint::Before(
                          std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1575452801))),
                    }]
                )
            ))
        );
    }

    #[test]
    fn caveat() {
        let empty: &[builder::Term] = &[];
        assert_eq!(
            super::caveat("right() <- resource(#ambient, $0), operation(#ambient, #read) || right() <- admin(#authority)"),
            Ok((
                "",
                builder::Caveat {
                    queries: vec![
                        builder::rule(
                            "right",
                            empty,
                            &[
                                builder::pred("resource", &[builder::s("ambient"), builder::variable("0")]),
                                builder::pred("operation", &[builder::s("ambient"), builder::s("read")]),
                            ]
                        ),
                        builder::rule(
                            "right",
                            empty,
                            &[
                                builder::pred("admin", &[builder::s("authority")]),
                            ]
                        ),
                    ]
                }
            ))
        );
    }
}
