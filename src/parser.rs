use crate::token::builder;
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag, take_while1},
    character::{
        complete::{char, digit1, space0},
        is_alphanumeric,
    },
    combinator::{map, map_res, opt, recognize},
    multi::separated_nonempty_list,
    sequence::{delimited, pair, preceded, terminated},
    IResult,
};
use std::convert::TryInto;

fn fact(i: &str) -> IResult<&str, builder::Fact> {
    predicate(i).map((|(i, p)| (i, builder::Fact(p))))
}

fn predicate(i: &str) -> IResult<&str, builder::Predicate> {
    let (i, fact_name) = name(i)?;
    let (i, ids) = delimited(
        char('('),
        separated_nonempty_list(preceded(opt(space0), char(',')), atom),
        char(')'),
    )(i)?;

    Ok((
        i,
        builder::Predicate {
            name: fact_name.to_string(),
            ids,
        },
    ))
}

fn name(i: &str) -> IResult<&str, &str> {
    let is_name_char = |c: char| is_alphanumeric(c as u8) || c == '_';

    take_while1(is_name_char)(i)
}

fn printable(i: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c != '\\' && c != '"')(i)
}

fn string(i: &str) -> IResult<&str, builder::Atom> {
    delimited(
        char('"'),
        escaped_transform(
            printable,
            '\\',
            alt((
                map(char('\\'), |_| "\\"),
                map(char('"'), |_| "\""),
                map(char('n'), |_| "\n"),
            )),
        ),
        char('"'),
    )(i)
    .map(|(i, s)| (i, builder::Atom::Str(s)))
}

fn symbol(i: &str) -> IResult<&str, builder::Atom> {
    preceded(char('#'), name)(i).map(|(i, s)| (i, builder::s(s)))
}

fn integer(i: &str) -> IResult<&str, builder::Atom> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| s.parse())(i)
        .map(|(i, n)| (i, builder::int(n)))
}

fn date(i: &str) -> IResult<&str, builder::Atom> {
    map_res(
        map_res(
            take_while1(|c: char| c != ',' && c != ' '),
            // we should use a proper rfc3339 parser
            |s| {
                let r = time::strptime(s, "%Y-%m-%dT%H:%M:%SZ");
                println!("strptime returned {:?}", r);
                r
            },
        ),
        |t| {
            let r = t.to_timespec().sec.try_into();
            println!("try_into returned {:?}", r);
            r
        },
    )(i)
    .map(|(i, t)| (i, builder::Atom::Date(t)))
}

fn variable(i: &str) -> IResult<&str, builder::Atom> {
    map(
        map_res(terminated(name, char('?')), |s| s.parse()),
        builder::variable,
    )(i)
}

fn atom(i: &str) -> IResult<&str, builder::Atom> {
    preceded(opt(space0), alt((symbol, string, date, variable, integer)))(i)
}

#[cfg(test)]
mod tests {
    use crate::token::builder;
    use nom::IResult;

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
        assert_eq!(super::variable("1?"), Ok(("", builder::variable(1))));
    }

    #[test]
    fn fact() {
        assert_eq!(
            super::fact("right(#authority, \"file1\", #read)"),
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
}
