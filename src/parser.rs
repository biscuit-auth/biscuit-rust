use crate::{datalog, error, token::builder};
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag, take_while1},
    character::{
        complete::{char, digit1, space0},
        is_alphanumeric,
    },
    combinator::{map, map_opt, map_res, opt, recognize, value},
    multi::separated_nonempty_list,
    sequence::{delimited, pair, preceded},
    IResult,
};
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    time::{Duration, SystemTime},
};

pub fn fact(i: &str) -> IResult<&str, builder::Fact> {
    predicate(i).map(|(i, p)| (i, builder::Fact(p)))
}

pub fn caveat(i: &str) -> IResult<&str, builder::Caveat> {
    let (i, queries) = separated_nonempty_list(
      preceded(space0, tag("||")),
      preceded(space0, rule)
    )(i)?;

    Ok((i, builder::Caveat { queries }))
}

pub fn rule(i: &str) -> IResult<&str, builder::Rule> {
    let (i, _) = char('*')(i)?;
    let (i, head) = predicate(i)?;
    let (i, _) = space0(i)?;

    let (i, _) = tag("<-")(i)?;

    let (i, _) = space0(i)?;
    let (i, predicates) = separated_nonempty_list(
      preceded(space0, char(',')),
      preceded(space0, predicate)
    )(i)?;

    let (i, constraints) = if let Ok((i, _)) =
        preceded::<_, _, _, (&str, nom::error::ErrorKind), _, _>(space0, char('@'))(i)
    {
        separated_nonempty_list(preceded(space0, char(',')), constraint)(i)?
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

fn predicate(i: &str) -> IResult<&str, builder::Predicate> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, ids) = delimited(
        char('('),
        separated_nonempty_list(preceded(space0, char(',')), atom),
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
    Lower,
    Larger,
    LowerOrEqual,
    LargerOrEqual,
    Equal,
    In,
    NotIn,
    Matches,
}

fn operator(i: &str) -> IResult<&str, Operator> {
    alt((
        value(Operator::LowerOrEqual, tag("<=")),
        value(Operator::LargerOrEqual, tag(">=")),
        value(Operator::Lower, tag("<")),
        value(Operator::Larger, tag(">")),
        value(Operator::Equal, tag("==")),
        value(Operator::In, tag("in")),
        value(Operator::NotIn, tag("not in")),
        value(Operator::Matches, tag("matches")),
    ))(i)
}

fn constraint_kind(i: &str) -> IResult<&str, builder::ConstraintKind> {
    let (i, op) = delimited(space0, operator, space0)(i)?;

    match op {
        Operator::Lower => map(parse_integer, |i| {
            builder::ConstraintKind::Integer(datalog::IntConstraint::Lower(i))
        })(i),
        Operator::Larger => map(parse_integer, |i| {
            builder::ConstraintKind::Integer(datalog::IntConstraint::Larger(i))
        })(i),
        Operator::LowerOrEqual => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::Before(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::LowerOrEqual(i))
            }),
        ))(i),
        Operator::LargerOrEqual => alt((
            map(parse_date, |d| {
                builder::ConstraintKind::Date(builder::DateConstraint::After(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(d),
                ))
            }),
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::LargerOrEqual(i))
            }),
        ))(i),
        Operator::Equal => alt((
            map(parse_integer, |i| {
                builder::ConstraintKind::Integer(datalog::IntConstraint::Equal(i))
            }),
            map(parse_string, |s| {
                builder::ConstraintKind::String(datalog::StrConstraint::Equal(s))
            }),
        ))(i),
        Operator::In => delimited(
            char('['),
            alt((
                map(
                    separated_nonempty_list(
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
                    separated_nonempty_list(
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
                    separated_nonempty_list(
                        preceded(space0, char(',')),
                        preceded(space0, parse_symbol),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Symbol(builder::SymbolConstraint::In(
                            h.drain(..).map(|s| s.to_string()).collect(),
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
                    separated_nonempty_list(
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
                    separated_nonempty_list(
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
                    separated_nonempty_list(
                        preceded(space0, char(',')),
                        preceded(space0, parse_symbol),
                    ),
                    |mut h| {
                        builder::ConstraintKind::Symbol(builder::SymbolConstraint::NotIn(
                            h.drain(..).map(|s| s.to_string()).collect(),
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

fn string(i: &str) -> IResult<&str, builder::Atom> {
    parse_string(i).map(|(i, s)| (i, builder::Atom::Str(s)))
}

fn parse_symbol(i: &str) -> IResult<&str, &str> {
    preceded(char('#'), name)(i)
}

fn symbol(i: &str) -> IResult<&str, builder::Atom> {
    parse_symbol(i).map(|(i, s)| (i, builder::s(s)))
}

fn parse_integer(i: &str) -> IResult<&str, i64> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| s.parse())(i)
}
fn integer(i: &str) -> IResult<&str, builder::Atom> {
    parse_integer(i).map(|(i, n)| (i, builder::int(n)))
}

fn parse_date(i: &str) -> IResult<&str, u64> {
    map_res(
        map_res(take_while1(|c: char| c != ',' && c != ' '), |s| {
            let r = chrono::DateTime::parse_from_rfc3339(s);
            r
        }),
        |t| {
            let r = t.timestamp().try_into();
            r
        },
    )(i)
}

fn date(i: &str) -> IResult<&str, builder::Atom> {
    parse_date(i).map(|(i, t)| (i, builder::Atom::Date(t)))
}

fn variable(i: &str) -> IResult<&str, builder::Atom> {
    map(
        map_res(preceded(char('$'), name), |s| s.parse()),
        builder::variable,
    )(i)
}

fn atom(i: &str) -> IResult<&str, builder::Atom> {
    preceded(space0, alt((symbol, string, date, variable, integer)))(i)
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
            Ok(("", builder::Atom::Date(1575294593)))
        );
    }

    #[test]
    fn variable() {
        assert_eq!(super::variable("$1"), Ok(("", builder::variable(1))));
    }

    #[test]
    fn constraint() {
        assert_eq!(
            super::constraint("$0 <= 2030-12-31T12:59:59+00:00"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
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
                    id: 0,
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
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::Lower(1234)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 > 1234"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::Larger(1234)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 <= 1234"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::LowerOrEqual(
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
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::LargerOrEqual(
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
                    id: 0,
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
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [1, 2]"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
                    kind: builder::ConstraintKind::Integer(builder::IntConstraint::NotIn(h)),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 == \"abc\""),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
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
                    id: 0,
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
                    id: 0,
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
                    id: 0,
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
                    id: 0,
                    kind: builder::ConstraintKind::String(datalog::StrConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [\"abc\", \"def\"]"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
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
                    id: 0,
                    kind: builder::ConstraintKind::Symbol(builder::SymbolConstraint::In(h.clone())),
                }
            ))
        );

        assert_eq!(
            super::constraint("$0 not in [#abc, #def]"),
            Ok((
                "",
                builder::Constraint {
                    id: 0,
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
    fn rule() {
        assert_eq!(
            super::rule("*right(#authority, $0, #read) <- resource( #ambient, $0), operation(#ambient, #read)"),
            Ok((
                "",
                builder::rule(
                    "right",
                    &[
                        builder::s("authority"),
                        builder::variable(0),
                        builder::s("read"),
                    ],
                    &[
                        builder::pred("resource", &[builder::s("ambient"), builder::variable(0)]),
                        builder::pred("operation", &[builder::s("ambient"), builder::s("read")]),
                    ]
                )
            ))
        );
    }

    #[test]
    fn constrained_rule() {
        assert_eq!(
            super::rule("*valid_date(\"file1\") <- time(#ambient, $0 ), resource( #ambient, \"file1\") @ $0 <= 2019-12-04T09:46:41+00:00"),
            Ok((
                "",
                builder::constrained_rule(
                    "valid_date",
                    &[
                        builder::string("file1"),
                    ],
                    &[
                        builder::pred("time", &[builder::s("ambient"), builder::variable(0)]),
                        builder::pred("resource", &[builder::s("ambient"), builder::string("file1")]),
                    ],
                    &[builder::Constraint {
                      id: 0,
                      kind: builder::ConstraintKind::Date(builder::DateConstraint::Before(
                          std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1575452801))),
                    }]
                )
            ))
        );
    }
}
