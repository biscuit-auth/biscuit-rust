use std::collections::HashMap;
use super::ID;
use super::SymbolTable;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub struct Expression {
    pub ops: Vec<Op>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Value(ID),
    Unary(Unary),
    Binary(Binary),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Unary {
    Negate,
    Parens,
}

impl Unary {
    fn evaluate(&self, value: ID) -> Option<ID> {
        match (self, value) {
            (Unary::Negate, ID::Integer(i)) => Some(ID::Integer(-1i64 * i)),
            (Unary::Negate, ID::Bool(b)) => Some(ID::Bool(!b)),
            (Unary::Parens, i) => Some(i),
             _ => {
                 //println!("unexpected value type on the stack");
                 return None;
             }
        }
    }

    pub fn print(&self, value: String, _symbols: &SymbolTable) -> String {
        match self {
            Unary::Negate => format!("-{}", value),
            Unary::Parens => format!("({})", value),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Binary {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    In,
    NotIn,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
}

impl Binary {
    fn evaluate(&self, left: ID, right: ID) -> Option<ID> {
        match (self, left, right) {
            (Binary::LessThan, ID::Integer(i), ID::Integer(j)) => Some(ID::Bool(i < j)),
            (Binary::GreaterThan, ID::Integer(i), ID::Integer(j)) => Some(ID::Bool(i > j)),
            (Binary::LessOrEqual, ID::Integer(i), ID::Integer(j)) => Some(ID::Bool(i <= j)),
            (Binary::GreaterOrEqual, ID::Integer(i), ID::Integer(j)) => Some(ID::Bool(i >= j)),
            (Binary::Equal, ID::Integer(i), ID::Integer(j)) => Some(ID::Bool(i == j)),
            (Binary::In, ID::Integer(i), ID::Set(set)) => Some(ID::Bool(set.contains(&ID::Integer(i)))),
            (Binary::NotIn, ID::Integer(i), ID::Set(set)) => Some(ID::Bool(!set.contains(&ID::Integer(i)))),

            (Binary::Prefix, ID::Str(s), ID::Str(pref)) => Some(ID::Bool(s.as_str().starts_with(pref.as_str()))),
            (Binary::Suffix, ID::Str(s), ID::Str(suff)) => Some(ID::Bool(s.as_str().ends_with(suff.as_str()))),
            (Binary::Regex, ID::Str(s), ID::Str(r)) => {
                Some(ID::Bool(Regex::new(&r).map(|re| re.is_match(&s)).unwrap_or(false)))
            },
            (Binary::Equal, ID::Str(i), ID::Str(j)) => Some(ID::Bool(i == j)),
            (Binary::In, ID::Str(i), ID::Set(set)) => Some(ID::Bool(set.contains(&ID::Str(i)))),
            (Binary::NotIn, ID::Str(i), ID::Set(set)) => Some(ID::Bool(!set.contains(&ID::Str(i)))),

            (Binary::LessOrEqual, ID::Date(i), ID::Date(j)) => Some(ID::Bool(i <= j)),
            (Binary::GreaterOrEqual, ID::Date(i), ID::Date(j)) => Some(ID::Bool(i >= j)),

            (Binary::In, ID::Symbol(i), ID::Set(set)) => Some(ID::Bool(set.contains(&ID::Symbol(i)))),
            (Binary::NotIn, ID::Symbol(i), ID::Set(set)) => Some(ID::Bool(!set.contains(&ID::Symbol(i)))),

            (Binary::Equal, ID::Bytes(i), ID::Bytes(j)) => Some(ID::Bool(i == j)),
            (Binary::In, ID::Bytes(i), ID::Set(set)) => Some(ID::Bool(set.contains(&ID::Bytes(i)))),
            (Binary::NotIn, ID::Bytes(i), ID::Set(set)) => Some(ID::Bool(!set.contains(&ID::Bytes(i)))),

            (Binary::Add, ID::Integer(i), ID::Integer(j)) => Some(ID::Integer(i + j)),
            (Binary::Sub, ID::Integer(i), ID::Integer(j)) => Some(ID::Integer(i - j)),
            (Binary::Mul, ID::Integer(i), ID::Integer(j)) => Some(ID::Integer(i * j)),
            (Binary::Div, ID::Integer(i), ID::Integer(j)) => Some(ID::Integer(i / j)),
            (Binary::And, ID::Bool(i), ID::Bool(j)) => Some(ID::Bool(i & j)),
            (Binary::Or, ID::Bool(i), ID::Bool(j)) => Some(ID::Bool(i | j)),
            _ => {
                //println!("unexpected value type on the stack");
                return None;
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
            Binary::In => format!("{} in {}", left, right),
            Binary::NotIn => format!("{} not in {}", left, right),
            Binary::Prefix => format!("{} starts with {}", left, right),
            Binary::Suffix => format!("{} ends with {}", left, right),
            Binary::Regex => format!("{} matches {}", left, right),
            Binary::Add => format!("{} + {}", left, right),
            Binary::Sub => format!("{} - {}", left, right),
            Binary::Mul => format!("{} * {}", left, right),
            Binary::Div => format!("{} / {}", left, right),
            Binary::And => format!("{} && {}", left, right),
            Binary::Or => format!("{} || {}", left, right),
        }
    }
}

impl Expression {
    pub fn evaluate(&self, values: &HashMap<u32, ID>) -> Option<ID> {
        let mut stack: Vec<ID> = Vec::new();

        for op in self.ops.iter() {
            //println!("op: {:?}\t| stack: {:?}", op, stack);
            match op {
                Op::Value(ID::Variable(i)) => match values.get(&i) {
                    Some(id) => stack.push(id.clone()),
                    None => {
                        //println!("unknown variable {}", i);
                        return None;
                    }
                }
                Op::Value(id) => stack.push(id.clone()),
                Op::Unary(unary) => match stack.pop() {
                    None => {
                        //println!("expected a value on the stack");
                        return None;
                    }
                    Some(id) => match unary.evaluate(id) {
                        Some(res) => stack.push(res),
                        None => return None,
                    }
                },
                Op::Binary(binary) => match (stack.pop(), stack.pop()) {
                    (Some(right_id), Some(left_id)) => match binary.evaluate(left_id, right_id) {
                        Some(res) => stack.push(res),
                        None => return None,
                    },
                    _ => {
                        //println!("expected two values on the stack");
                        return None;
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

    pub fn print(&self, symbols: &SymbolTable) -> Option<String> {
        let mut stack: Vec<String> = Vec::new();

        for op in self.ops.iter() {
            //println!("op: {:?}\t| stack: {:?}", op, stack);
            match op {
                Op::Value(i) => stack.push(symbols.print_id(&i)),
                Op::Unary(unary) => match stack.pop() {
                    None => return None,
                    Some(s) => stack.push(unary.print(s, symbols)),
                },
                Op::Binary(binary) => match (stack.pop(), stack.pop()) {
                    (Some(right), Some(left)) => stack.push(binary.print(left, right, symbols)),
                    _ => return None,
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
    use crate::datalog::SymbolTable;

    #[test]
    fn negate() {
        let symbols = SymbolTable {
            symbols: vec![
                "test1".to_string(),
                "test2".to_string(),
                "var1".to_string(),
            ],
        };

        let ops = vec![
            Op::Value(ID::Integer(1)),
            Op::Unary(Unary::Negate),
            Op::Value(ID::Variable(2)),
            Op::Binary(Binary::LessThan),
        ];

        let values: HashMap<u32, ID> = [(2, ID::Integer(0))]
            .iter().cloned().collect();

        println!("ops: {:?}", ops);

        let e = Expression { ops };
        println!("print: {}", e.print(&symbols).unwrap());

        let res = e.evaluate(&values);
        assert_eq!(res, Some(ID::Bool(true)));
        //panic!();
    }


    #[test]
    fn printer() {
        let symbols = SymbolTable {
            symbols: vec![
                "test1".to_string(),
                "test2".to_string(),
                "var1".to_string(),
            ],
        };

        let ops1 = vec![
            Op::Value(ID::Integer(1)),
            Op::Unary(Unary::Negate),
            Op::Value(ID::Variable(2)),
            Op::Binary(Binary::LessThan),
        ];

        let ops2 = vec![
            Op::Value(ID::Integer(1)),
            Op::Value(ID::Integer(2)),
            Op::Value(ID::Integer(3)),
            Op::Binary(Binary::Add),
            Op::Binary(Binary::LessThan),
        ];

        let ops3 = vec![
            Op::Value(ID::Integer(1)),
            Op::Value(ID::Integer(2)),
            Op::Binary(Binary::Add),
            Op::Value(ID::Integer(3)),
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

}
