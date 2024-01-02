use crate::error;

use super::Term;
use super::{SymbolTable, TemporarySymbolTable};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Expression {
    pub ops: Vec<Op>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Op {
    Value(Term),
    Unary(Unary),
    Binary(Binary),
    Closure(Vec<u32>, Vec<Op>),
}

/// Unary operation code
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Unary {
    Negate,
    Parens,
    Length,
}

impl Unary {
    fn evaluate(
        &self,
        value: Term,
        symbols: &TemporarySymbolTable,
    ) -> Result<Term, error::Expression> {
        match (self, value) {
            (Unary::Negate, Term::Bool(b)) => Ok(Term::Bool(!b)),
            (Unary::Parens, i) => Ok(i),
            (Unary::Length, Term::Str(i)) => symbols
                .get_symbol(i)
                .map(|s| Term::Integer(s.len() as i64))
                .ok_or(error::Expression::UnknownSymbol(i)),
            (Unary::Length, Term::Bytes(s)) => Ok(Term::Integer(s.len() as i64)),
            (Unary::Length, Term::Set(s)) => Ok(Term::Integer(s.len() as i64)),
            _ => {
                //println!("unexpected value type on the stack");
                Err(error::Expression::InvalidType)
            }
        }
    }

    pub fn print(&self, value: String, _symbols: &SymbolTable) -> String {
        match self {
            Unary::Negate => format!("!{}", value),
            Unary::Parens => format!("({})", value),
            Unary::Length => format!("{}.length()", value),
        }
    }
}

/// Binary operation code
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Binary {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    Contains,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    NotEqual,
    LazyAnd,
    LazyOr,
    All,
    Any,
}

impl Binary {
    fn evaluate_with_closure(
        &self,
        left: Term,
        mut right: Vec<Op>,
        params: &[u32],
        ops: &mut Vec<Op>,
        values: &HashMap<u32, Term>,
        symbols: &mut TemporarySymbolTable,
    ) -> Result<Term, error::Expression> {
        match (self, left, params) {
            (Binary::LazyOr, Term::Bool(true), []) => Ok(Term::Bool(true)),
            (Binary::LazyOr, Term::Bool(false), []) => {
                ops.push(Op::Binary(Binary::Or));
                right.reverse();
                for op in right {
                    ops.push(op);
                }
                Ok(Term::Bool(false))
            }
            (Binary::LazyAnd, Term::Bool(false), []) => Ok(Term::Bool(false)),
            (Binary::LazyAnd, Term::Bool(true), []) => {
                ops.push(Op::Binary(Binary::And));
                for op in right {
                    ops.push(op);
                }
                Ok(Term::Bool(true))
            }
            (Binary::All, Term::Set(set_values), [param]) => {
                for value in set_values.iter() {
                    let ops = right
                        .clone()
                        .iter()
                        .map(|op| match op {
                            Op::Value(Term::Variable(v)) if v == param => Op::Value(value.clone()),
                            _ => op.clone(),
                        })
                        .collect::<Vec<_>>();
                    let e = Expression { ops };
                    match e.evaluate(values, symbols)? {
                        Term::Bool(true) => {}
                        Term::Bool(false) => return Ok(Term::Bool(false)),
                        _ => return Err(error::Expression::InvalidType),
                    };
                }
                Ok(Term::Bool(false))
            }
            (Binary::Any, Term::Set(set_values), [param]) => {
                for value in set_values.iter() {
                    let ops = right
                        .clone()
                        .iter()
                        .map(|op| match op {
                            Op::Value(Term::Variable(v)) if v == param => Op::Value(value.clone()),
                            _ => op.clone(),
                        })
                        .collect::<Vec<_>>();
                    let e = Expression { ops };
                    match e.evaluate(values, symbols)? {
                        Term::Bool(false) => {}
                        Term::Bool(true) => return Ok(Term::Bool(true)),
                        _ => return Err(error::Expression::InvalidType),
                    };
                }
                Ok(Term::Bool(false))
            }
            (_, _, _) => Err(error::Expression::InvalidType),
        }
    }
    fn evaluate(
        &self,
        left: Term,
        right: Term,
        symbols: &mut TemporarySymbolTable,
    ) -> Result<Term, error::Expression> {
        match (self, left, right) {
            // integer
            (Binary::LessThan, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i < j)),
            (Binary::GreaterThan, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i > j)),
            (Binary::LessOrEqual, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i <= j)),
            (Binary::GreaterOrEqual, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i >= j)),
            (Binary::Equal, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i == j)),
            (Binary::NotEqual, Term::Integer(i), Term::Integer(j)) => Ok(Term::Bool(i != j)),
            (Binary::Add, Term::Integer(i), Term::Integer(j)) => i
                .checked_add(j)
                .map(Term::Integer)
                .ok_or(error::Expression::Overflow),
            (Binary::Sub, Term::Integer(i), Term::Integer(j)) => i
                .checked_sub(j)
                .map(Term::Integer)
                .ok_or(error::Expression::Overflow),
            (Binary::Mul, Term::Integer(i), Term::Integer(j)) => i
                .checked_mul(j)
                .map(Term::Integer)
                .ok_or(error::Expression::Overflow),
            (Binary::Div, Term::Integer(i), Term::Integer(j)) => i
                .checked_div(j)
                .map(Term::Integer)
                .ok_or(error::Expression::DivideByZero),
            (Binary::BitwiseAnd, Term::Integer(i), Term::Integer(j)) => Ok(Term::Integer(i & j)),
            (Binary::BitwiseOr, Term::Integer(i), Term::Integer(j)) => Ok(Term::Integer(i | j)),
            (Binary::BitwiseXor, Term::Integer(i), Term::Integer(j)) => Ok(Term::Integer(i ^ j)),

            // string
            (Binary::Prefix, Term::Str(s), Term::Str(pref)) => {
                match (symbols.get_symbol(s), symbols.get_symbol(pref)) {
                    (Some(s), Some(pref)) => Ok(Term::Bool(s.starts_with(pref))),
                    (Some(_), None) => Err(error::Expression::UnknownSymbol(pref)),
                    _ => Err(error::Expression::UnknownSymbol(s)),
                }
            }
            (Binary::Suffix, Term::Str(s), Term::Str(suff)) => {
                match (symbols.get_symbol(s), symbols.get_symbol(suff)) {
                    (Some(s), Some(suff)) => Ok(Term::Bool(s.ends_with(suff))),
                    (Some(_), None) => Err(error::Expression::UnknownSymbol(suff)),
                    _ => Err(error::Expression::UnknownSymbol(s)),
                }
            }
            (Binary::Regex, Term::Str(s), Term::Str(r)) => {
                match (symbols.get_symbol(s), symbols.get_symbol(r)) {
                    (Some(s), Some(r)) => Ok(Term::Bool(
                        Regex::new(r).map(|re| re.is_match(s)).unwrap_or(false),
                    )),
                    (Some(_), None) => Err(error::Expression::UnknownSymbol(r)),
                    _ => Err(error::Expression::UnknownSymbol(s)),
                }
            }
            (Binary::Contains, Term::Str(s), Term::Str(pattern)) => {
                match (symbols.get_symbol(s), symbols.get_symbol(pattern)) {
                    (Some(s), Some(pattern)) => Ok(Term::Bool(s.contains(pattern))),
                    (Some(_), None) => Err(error::Expression::UnknownSymbol(pattern)),
                    _ => Err(error::Expression::UnknownSymbol(s)),
                }
            }
            (Binary::Add, Term::Str(s1), Term::Str(s2)) => {
                match (symbols.get_symbol(s1), symbols.get_symbol(s2)) {
                    (Some(s1), Some(s2)) => {
                        let s = format!("{}{}", s1, s2);
                        let sym = symbols.insert(&s);
                        Ok(Term::Str(sym))
                    }
                    (Some(_), None) => Err(error::Expression::UnknownSymbol(s2)),
                    _ => Err(error::Expression::UnknownSymbol(s1)),
                }
            }
            (Binary::Equal, Term::Str(i), Term::Str(j)) => Ok(Term::Bool(i == j)),
            (Binary::NotEqual, Term::Str(i), Term::Str(j)) => Ok(Term::Bool(i != j)),

            // date
            (Binary::LessThan, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i < j)),
            (Binary::GreaterThan, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i > j)),
            (Binary::LessOrEqual, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i <= j)),
            (Binary::GreaterOrEqual, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i >= j)),
            (Binary::Equal, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i == j)),
            (Binary::NotEqual, Term::Date(i), Term::Date(j)) => Ok(Term::Bool(i != j)),

            // symbol

            // byte array
            (Binary::Equal, Term::Bytes(i), Term::Bytes(j)) => Ok(Term::Bool(i == j)),
            (Binary::NotEqual, Term::Bytes(i), Term::Bytes(j)) => Ok(Term::Bool(i != j)),

            // set
            (Binary::Equal, Term::Set(set), Term::Set(s)) => Ok(Term::Bool(set == s)),
            (Binary::NotEqual, Term::Set(set), Term::Set(s)) => Ok(Term::Bool(set != s)),
            (Binary::Intersection, Term::Set(set), Term::Set(s)) => {
                Ok(Term::Set(set.intersection(&s).cloned().collect()))
            }
            (Binary::Union, Term::Set(set), Term::Set(s)) => {
                Ok(Term::Set(set.union(&s).cloned().collect()))
            }
            (Binary::Contains, Term::Set(set), Term::Set(s)) => Ok(Term::Bool(set.is_superset(&s))),
            (Binary::Contains, Term::Set(set), Term::Integer(i)) => {
                Ok(Term::Bool(set.contains(&Term::Integer(i))))
            }
            (Binary::Contains, Term::Set(set), Term::Date(i)) => {
                Ok(Term::Bool(set.contains(&Term::Date(i))))
            }
            (Binary::Contains, Term::Set(set), Term::Bool(i)) => {
                Ok(Term::Bool(set.contains(&Term::Bool(i))))
            }
            (Binary::Contains, Term::Set(set), Term::Str(i)) => {
                Ok(Term::Bool(set.contains(&Term::Str(i))))
            }
            (Binary::Contains, Term::Set(set), Term::Bytes(i)) => {
                Ok(Term::Bool(set.contains(&Term::Bytes(i))))
            }

            // boolean
            (Binary::And, Term::Bool(i), Term::Bool(j)) => Ok(Term::Bool(i & j)),
            (Binary::Or, Term::Bool(i), Term::Bool(j)) => Ok(Term::Bool(i | j)),
            (Binary::Equal, Term::Bool(i), Term::Bool(j)) => Ok(Term::Bool(i == j)),
            (Binary::NotEqual, Term::Bool(i), Term::Bool(j)) => Ok(Term::Bool(i != j)),

            _ => {
                //println!("unexpected value type on the stack");
                Err(error::Expression::InvalidType)
            }
        }
    }

    pub fn print(&self, left: String, right: String, _symbols: &SymbolTable) -> String {
        match self {
            Binary::LessThan => format!("{} < {}", left, right),
            Binary::GreaterThan => format!("{} > {}", left, right),
            Binary::LessOrEqual => format!("{} <= {}", left, right),
            Binary::GreaterOrEqual => format!("{} >= {}", left, right),
            Binary::Equal => format!("{} == {}", left, right),
            Binary::NotEqual => format!("{} != {}", left, right),
            Binary::Contains => format!("{}.contains({})", left, right),
            Binary::Prefix => format!("{}.starts_with({})", left, right),
            Binary::Suffix => format!("{}.ends_with({})", left, right),
            Binary::Regex => format!("{}.matches({})", left, right),
            Binary::Add => format!("{} + {}", left, right),
            Binary::Sub => format!("{} - {}", left, right),
            Binary::Mul => format!("{} * {}", left, right),
            Binary::Div => format!("{} / {}", left, right),
            Binary::And => format!("{} && {}", left, right),
            Binary::Or => format!("{} || {}", left, right),
            Binary::Intersection => format!("{}.intersection({})", left, right),
            Binary::Union => format!("{}.union({})", left, right),
            Binary::BitwiseAnd => format!("{} & {}", left, right),
            Binary::BitwiseOr => format!("{} | {}", left, right),
            Binary::BitwiseXor => format!("{} ^ {}", left, right),
            Binary::LazyAnd => format!("{left} && {right}"),
            Binary::LazyOr => format!("{left} || {right}"),
            Binary::All => format!("{left}.all({right})"),
            Binary::Any => format!("{left}.any({right})"),
        }
    }
}

#[derive(Clone, Debug)]
enum StackElem {
    Closure(Vec<u32>, Vec<Op>),
    Term(Term),
}

impl Expression {
    pub fn evaluate(
        &self,
        values: &HashMap<u32, Term>,
        symbols: &mut TemporarySymbolTable,
    ) -> Result<Term, error::Expression> {
        let mut stack: Vec<StackElem> = Vec::new();

        let mut ops = self.ops.clone();
        ops.reverse();

        while let Some(op) = ops.pop() {
            // println!("ops: {ops:?}");
            // println!("op: {:?}\t| stack: {:?}", op, stack);

            match op {
                Op::Value(Term::Variable(i)) => match values.get(&i) {
                    Some(term) => stack.push(StackElem::Term(term.clone())),
                    None => {
                        //println!("unknown variable {}", i);
                        return Err(error::Expression::UnknownVariable(i));
                    }
                },
                Op::Value(term) => stack.push(StackElem::Term(term.clone())),
                Op::Unary(unary) => match stack.pop() {
                    Some(StackElem::Term(term)) => {
                        stack.push(StackElem::Term(unary.evaluate(term, symbols)?))
                    }
                    _ => {
                        //println!("expected a value on the stack");
                        return Err(error::Expression::InvalidStack);
                    }
                },
                Op::Binary(binary) => match (stack.pop(), stack.pop()) {
                    (Some(StackElem::Term(right_term)), Some(StackElem::Term(left_term))) => stack
                        .push(StackElem::Term(
                            binary.evaluate(left_term, right_term, symbols)?,
                        )),
                    (
                        Some(StackElem::Closure(params, right_ops)),
                        Some(StackElem::Term(left_term)),
                    ) => stack.push(StackElem::Term(binary.evaluate_with_closure(
                        left_term, right_ops, &params, &mut ops, values, symbols,
                    )?)),

                    _ => {
                        //println!("expected two values on the stack");
                        return Err(error::Expression::InvalidStack);
                    }
                },
                Op::Closure(params, ops) => {
                    stack.push(StackElem::Closure(params, ops));
                }
            }
        }
        //println!("stack: {stack:?}");

        if stack.len() == 1 {
            match stack.remove(0) {
                StackElem::Term(t) => Ok(t),
                _ => Err(error::Expression::InvalidStack),
            }
        } else {
            Err(error::Expression::InvalidStack)
        }
    }

    pub fn print(&self, symbols: &SymbolTable) -> Option<String> {
        let mut stack: Vec<String> = Vec::new();

        for op in self.ops.iter() {
            //println!("op: {:?}\t| stack: {:?}", op, stack);
            match op {
                Op::Value(i) => stack.push(symbols.print_term(i)),
                Op::Unary(unary) => match stack.pop() {
                    None => return None,
                    Some(s) => stack.push(unary.print(s, symbols)),
                },
                Op::Binary(binary) => match (stack.pop(), stack.pop()) {
                    (Some(right), Some(left)) => stack.push(binary.print(left, right, symbols)),
                    _ => return None,
                },
                Op::Closure(params, ops) => {
                    let exp_body = Expression { ops: ops.clone() };
                    let body = match exp_body.print(symbols) {
                        Some(c) => c,
                        _ => return None,
                    };

                    if params.is_empty() {
                        stack.push(body);
                    } else {
                        let param_group = params
                            .iter()
                            .map(|s| symbols.print_term(&Term::Variable(*s)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        stack.push(format!("({param_group}) -> {body}"));
                    }
                }
            }
        }

        if stack.len() == 1 {
            Some(stack.remove(0))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datalog::{SymbolTable, TemporarySymbolTable};

    #[test]
    fn negate() {
        let mut symbols = SymbolTable::new();
        symbols.insert("test1");
        symbols.insert("test2");
        symbols.insert("var1");
        let mut tmp_symbols = TemporarySymbolTable::new(&symbols);

        let ops = vec![
            Op::Value(Term::Integer(1)),
            Op::Value(Term::Variable(2)),
            Op::Binary(Binary::LessThan),
            Op::Unary(Unary::Parens),
            Op::Unary(Unary::Negate),
        ];

        let values: HashMap<u32, Term> = [(2, Term::Integer(0))].iter().cloned().collect();

        println!("ops: {:?}", ops);

        let e = Expression { ops };
        println!("print: {}", e.print(&symbols).unwrap());

        let res = e.evaluate(&values, &mut tmp_symbols);
        assert_eq!(res, Ok(Term::Bool(true)));
    }

    #[test]
    fn bitwise() {
        for (op, v1, v2, expected) in [
            (Binary::BitwiseAnd, 9, 10, 8),
            (Binary::BitwiseAnd, 9, 1, 1),
            (Binary::BitwiseAnd, 9, 0, 0),
            (Binary::BitwiseOr, 1, 2, 3),
            (Binary::BitwiseOr, 2, 2, 2),
            (Binary::BitwiseOr, 2, 0, 2),
            (Binary::BitwiseXor, 1, 0, 1),
            (Binary::BitwiseXor, 1, 1, 0),
        ] {
            let symbols = SymbolTable::new();
            let mut tmp_symbols = TemporarySymbolTable::new(&symbols);

            let ops = vec![
                Op::Value(Term::Integer(v1)),
                Op::Value(Term::Integer(v2)),
                Op::Binary(op),
            ];

            println!("ops: {:?}", ops);

            let e = Expression { ops };
            println!("print: {}", e.print(&symbols).unwrap());

            let res = e.evaluate(&HashMap::new(), &mut tmp_symbols);
            assert_eq!(res, Ok(Term::Integer(expected)));
        }
    }

    #[test]
    fn checked() {
        let symbols = SymbolTable::new();
        let mut tmp_symbols = TemporarySymbolTable::new(&symbols);
        let ops = vec![
            Op::Value(Term::Integer(1)),
            Op::Value(Term::Integer(0)),
            Op::Binary(Binary::Div),
        ];

        let values = HashMap::new();
        let e = Expression { ops };
        let res = e.evaluate(&values, &mut tmp_symbols);
        assert_eq!(res, Err(error::Expression::DivideByZero));

        let ops = vec![
            Op::Value(Term::Integer(1)),
            Op::Value(Term::Integer(i64::MAX)),
            Op::Binary(Binary::Add),
        ];

        let values = HashMap::new();
        let e = Expression { ops };
        let res = e.evaluate(&values, &mut tmp_symbols);
        assert_eq!(res, Err(error::Expression::Overflow));

        let ops = vec![
            Op::Value(Term::Integer(-10)),
            Op::Value(Term::Integer(i64::MAX)),
            Op::Binary(Binary::Sub),
        ];

        let values = HashMap::new();
        let e = Expression { ops };
        let res = e.evaluate(&values, &mut tmp_symbols);
        assert_eq!(res, Err(error::Expression::Overflow));

        let ops = vec![
            Op::Value(Term::Integer(2)),
            Op::Value(Term::Integer(i64::MAX)),
            Op::Binary(Binary::Mul),
        ];

        let values = HashMap::new();
        let e = Expression { ops };
        let res = e.evaluate(&values, &mut tmp_symbols);
        assert_eq!(res, Err(error::Expression::Overflow));
    }

    #[test]
    fn printer() {
        let mut symbols = SymbolTable::new();
        symbols.insert("test1");
        symbols.insert("test2");
        symbols.insert("var1");

        let ops1 = vec![
            Op::Value(Term::Integer(-1)),
            Op::Value(Term::Variable(1026)),
            Op::Binary(Binary::LessThan),
        ];

        let ops2 = vec![
            Op::Value(Term::Integer(1)),
            Op::Value(Term::Integer(2)),
            Op::Value(Term::Integer(3)),
            Op::Binary(Binary::Add),
            Op::Binary(Binary::LessThan),
        ];

        let ops3 = vec![
            Op::Value(Term::Integer(1)),
            Op::Value(Term::Integer(2)),
            Op::Binary(Binary::Add),
            Op::Value(Term::Integer(3)),
            Op::Binary(Binary::LessThan),
        ];

        println!("ops1: {:?}", ops1);
        println!("ops2: {:?}", ops2);
        println!("ops3: {:?}", ops3);
        let e1 = Expression { ops: ops1 };
        let e2 = Expression { ops: ops2 };
        let e3 = Expression { ops: ops3 };

        assert_eq!(e1.print(&symbols).unwrap(), "-1 < $var1");

        assert_eq!(e2.print(&symbols).unwrap(), "1 < 2 + 3");

        assert_eq!(e3.print(&symbols).unwrap(), "1 + 2 < 3");
        //panic!();
    }

    #[test]
    fn laziness() {
        let symbols = SymbolTable::new();
        let mut symbols = TemporarySymbolTable::new(&symbols);

        // let ops1 = vec![
        //     Op::Value(Term::Bool(true)),
        //     Op::Suspend,
        //     Op::Value(Term::Bool(false)),
        //     Op::Suspend,
        //     Op::Value(Term::Bool(false)),
        //     Op::Unsuspend,
        //     Op::Binary(Binary::Or),
        //     Op::Unsuspend,
        //     Op::Binary(Binary::Or),
        // ];
        // let e1 = Expression { ops: ops1 };

        // let res1 = e1.evaluate(&HashMap::new(), &mut symbols).unwrap();
        // assert_eq!(res1, Term::Bool(true));

        let ops2 = vec![
            Op::Value(Term::Bool(false)),
            Op::Closure(
                vec![],
                vec![
                    Op::Value(Term::Bool(true)),
                    Op::Closure(vec![], vec![Op::Value(Term::Bool(true))]),
                    Op::Binary(Binary::LazyAnd),
                ],
            ),
            Op::Binary(Binary::LazyOr),
        ];
        let e2 = Expression { ops: ops2 };

        let res2 = e2.evaluate(&HashMap::new(), &mut symbols).unwrap();
        assert_eq!(res2, Term::Bool(true));
    }

    #[test]
    fn any() {
        let mut symbols = SymbolTable::new();
        let p = symbols.insert("param") as u32;
        let mut tmp_symbols = TemporarySymbolTable::new(&symbols);

        let ops1 = vec![
            Op::Value(Term::Set([Term::Bool(false), Term::Bool(true)].into())),
            Op::Closure(vec![p], vec![Op::Value(Term::Variable(p))]),
            Op::Binary(Binary::Any),
        ];
        let e1 = Expression { ops: ops1 };
        println!("{:?}", e1.print(&symbols));

        let res1 = e1.evaluate(&HashMap::new(), &mut tmp_symbols).unwrap();
        assert_eq!(res1, Term::Bool(true));
    }
}
