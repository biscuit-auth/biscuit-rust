//! Logic language implementation for caveats
use std::collections::{HashMap, HashSet};
use std::convert::AsRef;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use regex::Regex;
use chrono::{DateTime, NaiveDateTime, Utc};

pub type Symbol = u64;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum ID {
    Symbol(Symbol),
    Variable(u32),
    Integer(i64),
    Str(String),
    Date(u64),
    Bytes(Vec<u8>),
}

impl From<&ID> for ID {
    fn from(i: &ID) -> Self {
        match i {
            ID::Symbol(ref s) => ID::Symbol(*s),
            ID::Variable(ref v) => ID::Variable(*v),
            ID::Integer(ref i) => ID::Integer(*i),
            ID::Str(ref s) => ID::Str(s.clone()),
            ID::Date(ref d) => ID::Date(*d),
            ID::Bytes(ref b) => ID::Bytes(b.clone()),
        }
    }
}

impl AsRef<ID> for ID {
    fn as_ref(&self) -> &ID {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: Symbol,
    pub ids: Vec<ID>,
}

impl Predicate {
    pub fn new(name: Symbol, ids: &[ID]) -> Predicate {
        Predicate {
            name,
            ids: ids.to_vec(),
        }
    }
}

impl AsRef<Predicate> for Predicate {
    fn as_ref(&self) -> &Predicate {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Fact {
    pub predicate: Predicate,
}

impl Fact {
    pub fn new(name: Symbol, ids: &[ID]) -> Fact {
        Fact {
            predicate: Predicate::new(name, ids),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub head: Predicate,
    pub body: Vec<Predicate>,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Constraint {
    pub id: u32,
    pub kind: ConstraintKind,
}

impl AsRef<Constraint> for Constraint {
    fn as_ref(&self) -> &Constraint {
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintKind {
    Int(IntConstraint),
    Str(StrConstraint),
    Date(DateConstraint),
    Symbol(SymbolConstraint),
    Bytes(BytesConstraint),
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntConstraint {
    Lower(i64),
    Larger(i64),
    LowerOrEqual(i64),
    LargerOrEqual(i64),
    Equal(i64),
    In(HashSet<i64>),
    NotIn(HashSet<i64>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum StrConstraint {
    Prefix(String),
    Suffix(String),
    Equal(String),
    In(HashSet<String>),
    NotIn(HashSet<String>),
    Regex(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DateConstraint {
    Before(u64),
    After(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolConstraint {
    In(HashSet<u64>),
    NotIn(HashSet<u64>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BytesConstraint {
    Equal(Vec<u8>),
    In(HashSet<Vec<u8>>),
    NotIn(HashSet<Vec<u8>>),
}

impl Constraint {
    pub fn check(&self, name: u32, id: &ID) -> bool {
        if name != self.id {
            return true;
        }

        match (id, &self.kind) {
            (ID::Variable(_), _) => panic!("should not check constraint on a variable"),
            (ID::Integer(i), ConstraintKind::Int(c)) => match c {
                IntConstraint::Lower(j) => *i < *j,
                IntConstraint::Larger(j) => *i > *j,
                IntConstraint::LowerOrEqual(j) => *i <= *j,
                IntConstraint::LargerOrEqual(j) => *i >= *j,
                IntConstraint::Equal(j) => *i == *j,
                IntConstraint::In(h) => h.contains(i),
                IntConstraint::NotIn(h) => !h.contains(i),
            },
            (ID::Str(s), ConstraintKind::Str(c)) => match c {
                StrConstraint::Prefix(pref) => s.as_str().starts_with(pref.as_str()),
                StrConstraint::Suffix(suff) => s.as_str().ends_with(suff.as_str()),
                StrConstraint::Equal(s2) => s == s2,
                StrConstraint::Regex(r) => {
                  if let Some(re) = Regex::new(r).ok() {
                    re.is_match(s)
                  } else {
                    // an invalid regex will never match
                    false
                  }
                },
                StrConstraint::In(h) => h.contains(s),
                StrConstraint::NotIn(h) => !h.contains(s),
            },
            (ID::Date(d), ConstraintKind::Date(c)) => match c {
                DateConstraint::Before(b) => d <= b,
                DateConstraint::After(b) => d >= b,
            },
            (ID::Symbol(s), ConstraintKind::Symbol(c)) => match c {
                SymbolConstraint::In(h) => h.contains(s),
                SymbolConstraint::NotIn(h) => !h.contains(s),
            },
            (ID::Bytes(s), ConstraintKind::Bytes(c)) => match c {
                BytesConstraint::Equal(s2) => s == s2,
                BytesConstraint::In(h) => h.contains(s),
                BytesConstraint::NotIn(h) => !h.contains(s),
            },
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Caveat {
    pub queries: Vec<Rule>,
}


impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({:?})", self.predicate.name, self.predicate.ids)
    }
}

impl Rule {
    pub fn apply(&self, facts: &HashSet<Fact>, new_facts: &mut Vec<Fact>) {
        let variables_set = self
            .body
            .iter()
            .flat_map(|pred| {
                pred.ids
                    .iter()
                    .filter(|id| match id {
                        ID::Variable(_) => true,
                        _ => false,
                    })
                    .map(|id| match id {
                        ID::Variable(i) => *i,
                        _ => unreachable!(),
                    })
            })
            .collect::<HashSet<_>>();

        let variables = MatchedVariables::new(variables_set);

        new_facts.extend(
            CombineIt::new(variables, &self.body, &self.constraints, facts).map(|h| {
                let mut p = self.head.clone();
                for index in 0..p.ids.len() {
                    let value = match &p.ids[index] {
                        ID::Variable(i) => match h.get(i) {
                          Some(val) => val,
                          None => {
                            println!("error: variables that appear in the head should appear in the body and constraints as well");
                            continue;
                          }
                        },
                        _ => continue,
                    };

                    p.ids[index] = value.clone();
                }

                Fact { predicate: p }
            }),
        );
    }
}

/// recursive iterator for rule application
pub struct CombineIt<'a> {
    variables: MatchedVariables,
    predicates: &'a [Predicate],
    constraints: &'a [Constraint],
    all_facts: &'a HashSet<Fact>,
    current_facts: Box<dyn Iterator<Item = &'a Fact> + 'a>,
    current_it: Option<Box<CombineIt<'a>>>,
}

impl<'a> CombineIt<'a> {
    pub fn new(
        variables: MatchedVariables,
        predicates: &'a [Predicate],
        constraints: &'a [Constraint],
        facts: &'a HashSet<Fact>,
    ) -> Self {
        let p = predicates[0].clone();
        CombineIt {
            variables,
            predicates,
            constraints,
            all_facts: facts,
            current_facts: Box::new(
                facts
                    .iter()
                    .filter(move |fact| match_preds(&fact.predicate, &p)),
            ),
            current_it: None,
        }
    }
}

impl<'a> Iterator for CombineIt<'a> {
    type Item = HashMap<u32, ID>;

    fn next(&mut self) -> Option<HashMap<u32, ID>> {
        // if we're the last iterator in the recursive chain, stop here
        if self.predicates.is_empty() {
            return self.variables.complete();
        }

        loop {
            if self.current_it.is_none() {
                //fix the first predicate
                let pred = &self.predicates[0];

                loop {
                    if let Some(current_fact) = self.current_facts.next() {
                        // create a new MatchedVariables in which we fix variables we could unify
                        // from our first predicate and the current fact
                        let mut vars = self.variables.clone();
                        let mut match_ids = true;
                        for (key, id) in pred.ids.iter().zip(&current_fact.predicate.ids) {
                            if let (ID::Variable(k), id) = (key, id) {
                                for c in self.constraints {
                                    if !c.check(*k, id) {
                                        match_ids = false;
                                        break;
                                    }
                                }
                                if !vars.insert(*k, &id) {
                                    match_ids = false;
                                }

                                if !match_ids {
                                    break;
                                }
                            }
                        }

                        if !match_ids {
                            continue;
                        }

                        if self.predicates.len() == 1 {
                            if let Some(val) = vars.complete() {
                                return Some(val);
                            } else {
                                continue;
                            }
                        } else {
                            // create a new iterator with the matched variables, the rest of the predicates,
                            // and all of the facts
                            self.current_it = Some(Box::new(CombineIt::new(
                                vars,
                                &self.predicates[1..],
                                self.constraints,
                                &self.all_facts,
                            )));
                        }
                        break;
                    } else {
                        return None;
                    }
                }
            }

            if self.current_it.is_none() {
                break None;
            }

            if let Some(val) = self.current_it.as_mut().and_then(|it| it.next()) {
                break Some(val);
            } else {
                self.current_it = None;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchedVariables(pub HashMap<u32, Option<ID>>);

impl MatchedVariables {
    pub fn new(import: HashSet<u32>) -> Self {
        MatchedVariables(import.iter().map(|key| (*key, None)).collect())
    }

    pub fn insert(&mut self, key: u32, value: &ID) -> bool {
        match self.0.get(&key) {
            Some(None) => {
                self.0.insert(key, Some(value.clone()));
                true
            }
            Some(Some(v)) => value == v,
            None => false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.0.values().all(|v| v.is_some())
    }

    pub fn complete(&self) -> Option<HashMap<u32, ID>> {
        let mut result = HashMap::new();
        for (k, v) in self.0.iter() {
            match v {
                Some(value) => result.insert(*k, value.clone()),
                None => return None,
            };
        }
        Some(result)
    }
}

pub fn fact<I: AsRef<ID>>(name: Symbol, ids: &[I]) -> Fact {
    Fact {
        predicate: Predicate {
            name,
            ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
        },
    }
}

pub fn pred<I: AsRef<ID>>(name: Symbol, ids: &[I]) -> Predicate {
    Predicate {
        name,
        ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
    }
}

pub fn rule<I: AsRef<ID>, P: AsRef<Predicate>>(
    head_name: Symbol,
    head_ids: &[I],
    predicates: &[P],
) -> Rule {
    Rule {
        head: pred(head_name, head_ids),
        body: predicates.iter().map(|p| p.as_ref().clone()).collect(),
        constraints: Vec::new(),
    }
}

pub fn constrained_rule<I: AsRef<ID>, P: AsRef<Predicate>, C: AsRef<Constraint>>(
    head_name: Symbol,
    head_ids: &[I],
    predicates: &[P],
    constraints: &[C],
) -> Rule {
    Rule {
        head: pred(head_name, head_ids),
        body: predicates.iter().map(|p| p.as_ref().clone()).collect(),
        constraints: constraints.iter().map(|c| c.as_ref().clone()).collect(),
    }
}

pub fn int(i: i64) -> ID {
    ID::Integer(i)
}

pub fn string(s: &str) -> ID {
    ID::Str(s.to_string())
}

pub fn date(t: &SystemTime) -> ID {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    ID::Date(dur.as_secs())
}

pub fn var(syms: &mut SymbolTable, name: &str) -> ID {
    let id = syms.insert(name);
    ID::Variable(id as u32)
}

pub fn match_preds(pred1: &Predicate, pred2: &Predicate) -> bool {
    pred1.name == pred2.name
        && pred1.ids.len() == pred2.ids.len()
        && pred1
            .ids
            .iter()
            .zip(&pred2.ids)
            .all(|(fid, pid)| match (fid, pid) {
                (_, ID::Variable(_)) => true,
                (ID::Variable(_), _) => true,
                (ID::Symbol(i), ID::Symbol(ref j)) => i == j,
                (ID::Integer(i), ID::Integer(j)) => i == j,
                (ID::Str(i), ID::Str(j)) => i == j,
                (ID::Date(i), ID::Date(j)) => i == j,
                _ => false,
            })
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct World {
    pub facts: HashSet<Fact>,
    pub rules: Vec<Rule>,
}

impl World {
    pub fn new() -> Self {
        World::default()
    }

    pub fn add_fact(&mut self, fact: Fact) {
        self.facts.insert(fact);
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn run(&mut self) {
        let mut index = 0;
        loop {
            let mut new_facts: Vec<Fact> = Vec::new();
            for rule in self.rules.iter() {
                rule.apply(&self.facts, &mut new_facts);
                //println!("new_facts after applying {:?}:\n{:#?}", rule, new_facts);
            }

            let len = self.facts.len();
            self.facts.extend(new_facts.drain(..));
            if self.facts.len() == len {
                break;
            }

            index += 1;
            if index == 100 {
                panic!();
            }
        }
    }

    pub fn query(&self, pred: Predicate) -> Vec<&Fact> {
        self.facts
            .iter()
            .filter(|f| {
                f.predicate.name == pred.name
                    && f.predicate
                        .ids
                        .iter()
                        .zip(&pred.ids)
                        .all(|(fid, pid)| match (fid, pid) {
                            (ID::Symbol(_), ID::Variable(_)) => true,
                            (ID::Symbol(i), ID::Symbol(ref j)) => i == j,
                            (ID::Integer(i), ID::Integer(ref j)) => i == j,
                            (ID::Str(i), ID::Str(ref j)) => i == j,
                            (ID::Date(i), ID::Date(ref j)) => i == j,
                            _ => false,
                        })
            })
            .collect::<Vec<_>>()
    }

    pub fn query_rule(&self, rule: Rule) -> Vec<Fact> {
        let mut new_facts: Vec<Fact> = Vec::new();
        rule.apply(&self.facts, &mut new_facts);
        new_facts
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SymbolTable {
    pub symbols: Vec<String>,
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable::default()
    }

    pub fn insert(&mut self, s: &str) -> Symbol {
        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => index as u64,
            None => {
                self.symbols.push(s.to_string());
                (self.symbols.len() - 1) as u64
            }
        }
    }

    pub fn add(&mut self, s: &str) -> ID {
        let id = self.insert(s);
        ID::Symbol(id)
    }

    pub fn get(&self, s: &str) -> Option<Symbol> {
        self.symbols
            .iter()
            .position(|sym| sym.as_str() == s)
            .map(|i| i as u64)
    }

    pub fn print_symbol(&self, s: Symbol) -> String {
      self.symbols.get(s as usize).map(|s| s.to_string()).unwrap_or_else(|| format!("<{}?>", s))
    }

    pub fn print_world(&self, w: &World) -> String {
        let facts = w
            .facts
            .iter()
            .map(|f| self.print_fact(f))
            .collect::<Vec<_>>();
        let rules = w
            .rules
            .iter()
            .map(|r| self.print_rule(r))
            .collect::<Vec<_>>();
        format!("World {{\n  facts: {:#?}\n  rules: {:#?}\n}}", facts, rules)
    }

    pub fn print_fact(&self, f: &Fact) -> String {
        self.print_predicate(&f.predicate)
    }

    pub fn print_predicate(&self, p: &Predicate) -> String {
        let strings = p
            .ids
            .iter()
            .map(|id| match id {
                ID::Variable(i) => format!("${}", self.print_symbol(*i as u64)),
                ID::Integer(i) => i.to_string(),
                ID::Str(s) => format!("\"{}\"", s),
                ID::Symbol(index) => format!("#{}", self.print_symbol(*index as u64)),
                ID::Date(d) => {
                    let t = UNIX_EPOCH + Duration::from_secs(*d);
                    format!("{:?}", t)
                },
                ID::Bytes(s) => format!("hex:{}", hex::encode(s)),
            })
            .collect::<Vec<_>>();
        format!(
            "{}({})",
            self.symbols
                .get(p.name as usize)
                .map(|s| s.as_str())
                .unwrap_or("<?>"),
            strings.join(", ")
        )
    }

    pub fn print_constraint(&self, c: &Constraint) -> String {
        match &c.kind {
            ConstraintKind::Int(IntConstraint::Lower(i)) => format!("${} < {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::Larger(i)) => format!("${} > {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::LowerOrEqual(i)) => format!("${} <= {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::LargerOrEqual(i)) => format!("${} >= {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::Equal(i)) => format!("${} == {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::In(i)) => format!("${} in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Int(IntConstraint::NotIn(i)) => format!("${} not in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Prefix(i)) => format!("${} matches {}*", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Suffix(i)) => format!("${} matches *{}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Equal(i)) => format!("${} == {}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::Regex(i)) => format!("${} matches /{}/", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::In(i)) => format!("${} in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Str(StrConstraint::NotIn(i)) => format!("${} not in {:?}", self.print_symbol(c.id as u64), i),
            ConstraintKind::Date(DateConstraint::Before(i)) => {
              let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(*i as i64, 0), Utc);
              format!("${} <= {}", self.print_symbol(c.id as u64), date.to_rfc3339())
            },
            ConstraintKind::Date(DateConstraint::After(i)) => {
              let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(*i as i64, 0), Utc);
              format!("${} >= {}", self.print_symbol(c.id as u64), date.to_rfc3339())
            },
            ConstraintKind::Symbol(SymbolConstraint::In(i)) => format!("${} in {:?}", c.id, i),
            ConstraintKind::Symbol(SymbolConstraint::NotIn(i)) => {
                format!("${} not in {:?}", self.print_symbol(c.id as u64), i)
            }
            ConstraintKind::Bytes(BytesConstraint::Equal(i)) => format!("${} == hex:{}", c.id, hex::encode(i)),
            ConstraintKind::Bytes(BytesConstraint::In(i)) => {
                format!("${} in {:?}", self.print_symbol(c.id as u64), i.iter()
                        .map(|s| format!("hex:{}", hex::encode(s))).collect::<HashSet<_>>())
            },
            ConstraintKind::Bytes(BytesConstraint::NotIn(i)) => {
                format!("${} not in {:?}", self.print_symbol(c.id as u64), i.iter()
                        .map(|s| format!("hex:{}", hex::encode(s))).collect::<HashSet<_>>())
            },
        }
    }

    pub fn print_rule(&self, r: &Rule) -> String {
        let res = self.print_predicate(&r.head);
        let preds: Vec<_> = r.body.iter().map(|p| self.print_predicate(p)).collect();
        let constraints: Vec<_> = r
            .constraints
            .iter()
            .map(|c| self.print_constraint(c))
            .collect();

        let c = if constraints.is_empty() {
          String::new()
        } else {
          format!(" @ {}", constraints.join(", "))
        };

        format!(
            "*{} <- {}{}",
            res,
            preds.join(", "),
            c
        )
    }

    pub fn print_caveat(&self, c: &Caveat) -> String {
        let queries = c
            .queries
            .iter()
            .map(|r| self.print_rule(r))
            .collect::<Vec<_>>();

        queries.join(" || ")
    }
}

pub fn sym(syms: &mut SymbolTable, name: &str) -> ID {
    let id = syms.insert(name);
    ID::Symbol(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let a = syms.add("A");
        let b = syms.add("B");
        let c = syms.add("C");
        let d = syms.add("D");
        let e = syms.add("e");
        let parent = syms.insert("parent");
        let grandparent = syms.insert("grandparent");

        w.add_fact(fact(parent, &[&a, &b]));
        w.add_fact(fact(parent, &[&b, &c]));
        w.add_fact(fact(parent, &[&c, &d]));

        let r1 = rule(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
            &[
                pred(parent, &[var(&mut syms, "grandparent"), var(&mut syms, "parent")]),
                pred(parent, &[var(&mut syms, "parent"), var(&mut syms, "grandchild")]),
            ],
        );

        println!("symbols: {:?}", syms);
        println!("testing r1: {}", syms.print_rule(&r1));
        let query_rule_result = w.query_rule(r1);
        println!("grandparents query_rules: {:?}", query_rule_result);
        println!("current facts: {:?}", w.facts);

        let r2 = rule(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
            &[
                pred(parent, &[var(&mut syms, "grandparent"), var(&mut syms, "parent")]),
                pred(parent, &[var(&mut syms, "parent"), var(&mut syms, "grandchild")]),
            ],
        );

        println!("adding r2: {}", syms.print_rule(&r2));
        w.add_rule(r2);

        w.run();

        println!("parents:");
        let res = w.query(pred(parent, &[var(&mut syms, "parent"), var(&mut syms, "child")]));
        for fact in res {
            println!("\t{}", syms.print_fact(fact));
        }

        println!(
            "parents of B: {:?}",
            w.query(pred(parent, &[&var(&mut syms, "parent"), &b]))
        );
        println!(
            "grandparents: {:?}",
            w.query(pred(grandparent, &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")]))
        );
        w.add_fact(fact(parent, &[&c, &e]));
        w.run();
        let mut res = w.query(pred(grandparent, &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")]));
        println!("grandparents after inserting parent(C, E): {:?}", res);

        let res = res.drain(..).cloned().collect::<HashSet<_>>();
        let compared = (vec![
            fact(grandparent, &[&a, &c]),
            fact(grandparent, &[&b, &d]),
            fact(grandparent, &[&b, &e]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res, compared);

        /*w.add_rule(rule("siblings", &[var("A"), var("B")], &[
          pred(parent, &[var(parent), var("A")]),
          pred(parent, &[var(parent), var("B")])
        ]));

        w.run();
        println!("siblings: {:#?}", w.query(pred("siblings", &[var("A"), var("B")])));
        */
    }

    #[test]
    fn numbers() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let ghi = syms.add("ghi");
        let jkl = syms.add("jkl");
        let mno = syms.add("mno");
        let aaa = syms.add("AAA");
        let bbb = syms.add("BBB");
        let ccc = syms.add("CCC");
        let t1 = syms.insert("t1");
        let t2 = syms.insert("t2");
        let join = syms.insert("join");

        w.add_fact(fact(t1, &[&int(0), &abc]));
        w.add_fact(fact(t1, &[&int(1), &def]));
        w.add_fact(fact(t1, &[&int(2), &ghi]));
        w.add_fact(fact(t1, &[&int(3), &jkl]));
        w.add_fact(fact(t1, &[&int(4), &mno]));

        w.add_fact(fact(t2, &[&int(0), &aaa, &int(0)]));
        w.add_fact(fact(t2, &[&int(1), &bbb, &int(0)]));
        w.add_fact(fact(t2, &[&int(2), &ccc, &int(1)]));

        let res = w.query_rule(rule(
            join,
            &[var(&mut syms, "left"), var(&mut syms, "right")],
            &[
                pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                pred(t2, &[var(&mut syms, "t2_id"), var(&mut syms, "right"), var(&mut syms, "id")]),
            ],
        ));
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![
            fact(join, &[&abc, &aaa]),
            fact(join, &[&abc, &bbb]),
            fact(join, &[&def, &ccc]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        // test constraints
        let res = w.query_rule(constrained_rule(
            join,
            &[var(&mut syms, "left"), var(&mut syms, "right")],
            &[
                pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                pred(t2, &[var(&mut syms, "t2_id"), var(&mut syms, "right"), var(&mut syms, "id")]),
            ],
            &[Constraint {
                id: syms.insert("id") as u32,
                kind: ConstraintKind::Int(IntConstraint::Lower(1)),
            }],
        ));
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(join, &[&abc, &aaa]), fact(join, &[&abc, &bbb])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn str() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let app_0 = syms.add("app_0");
        let app_1 = syms.add("app_1");
        let app_2 = syms.add("app_2");
        let route = syms.insert("route");
        let suff = syms.insert("route suffix");

        w.add_fact(fact(route, &[&int(0), &app_0, &string("example.com")]));
        w.add_fact(fact(route, &[&int(1), &app_1, &string("test.com")]));
        w.add_fact(fact(route, &[&int(2), &app_2, &string("test.fr")]));
        w.add_fact(fact(route, &[&int(3), &app_0, &string("www.example.com")]));
        w.add_fact(fact(route, &[&int(4), &app_1, &string("mx.example.com")]));

        fn test_suffix(w: &World, syms: &mut SymbolTable, suff: Symbol, route: Symbol, suffix: &str) -> Vec<Fact> {
            w.query_rule(constrained_rule(
                suff,
                &[var(syms, "app_id"), var(syms, "domain_name")],
                &[pred(
                    route,
                    &[var(syms, "route_id"), var(syms, "app_id"), var(syms, "domain_name")],
                )],
                &[Constraint {
                    id: syms.insert("domain_name") as u32,
                    kind: ConstraintKind::Str(StrConstraint::Suffix(suffix.to_string())),
                }],
            ))
        }

        let res = test_suffix(&w, &mut syms, suff, route, ".fr");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(suff, &[&app_2, &string("test.fr")])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = test_suffix(&w, &mut syms, suff, route, "example.com");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![
            fact(suff, &[&app_0, &string("example.com")]),
            fact(suff, &[&app_0, &string("www.example.com")]),
            fact(suff, &[&app_1, &string("mx.example.com")]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn date_constraint() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let t1 = SystemTime::now();
        println!("t1 = {:?}", t1);
        let t2 = t1 + Duration::from_secs(10);
        println!("t2 = {:?}", t2);
        let t3 = t2 + Duration::from_secs(30);
        println!("t3 = {:?}", t3);

        let t2_timestamp = t2.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let before = syms.insert("before");
        let after = syms.insert("after");

        w.add_fact(fact(x, &[&date(&t1), &abc]));
        w.add_fact(fact(x, &[&date(&t3), &def]));

        let r1 = constrained_rule(
            before,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Constraint {
                    id: syms.insert("date") as u32,
                    kind: ConstraintKind::Date(DateConstraint::Before(t2_timestamp)),
                },
                Constraint {
                    id: syms.insert("date") as u32,
                    kind: ConstraintKind::Date(DateConstraint::After(0)),
                },
            ],
        );

        println!("testing r1: {}", syms.print_rule(&r1));
        let res = w.query_rule(r1);
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(before, &[&date(&t1), &abc])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let r2 = constrained_rule(
            after,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Constraint {
                    id: syms.insert("date") as u32,
                    kind: ConstraintKind::Date(DateConstraint::After(t2_timestamp)),
                },
                Constraint {
                    id: syms.insert("date") as u32,
                    kind: ConstraintKind::Date(DateConstraint::After(0)),
                },
            ],
        );

        println!("testing r2: {}", syms.print_rule(&r2));
        let res = w.query_rule(r2);
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(after, &[&date(&t3), &def])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn set_constraint() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let int_set = syms.insert("int_set");
        let symbol_set = syms.insert("symbol_set");
        let string_set = syms.insert("string_set");

        w.add_fact(fact(x, &[&abc, &int(0), &string("test")]));
        w.add_fact(fact(x, &[&def, &int(2), &string("hello")]));

        let res = w.query_rule(constrained_rule(
            int_set,
            &[var(&mut syms, "sym"), var(&mut syms, "str")],
            &[pred(x, &[var(&mut syms, "sym"), var(&mut syms, "int"), var(&mut syms, "str")])],
            &[Constraint {
                id: syms.insert("int") as u32,
                kind: ConstraintKind::Int(IntConstraint::In([0, 1].iter().cloned().collect())),
            }],
        ));
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(int_set, &[&abc, &string("test")])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let abc_sym_id = syms.insert("abc");
        let ghi_sym_id = syms.insert("ghi");

        let res = w.query_rule(constrained_rule(
            symbol_set,
            &[var(&mut syms, "symbol"), var(&mut syms, "int"), var(&mut syms, "str")],
            &[pred(x, &[var(&mut syms, "symbol"), var(&mut syms, "int"), var(&mut syms, "str")])],
            &[Constraint {
                id: syms.insert("symbol") as u32,
                kind: ConstraintKind::Symbol(SymbolConstraint::NotIn(
                    [abc_sym_id, ghi_sym_id].iter().cloned().collect(),
                )),
            }],
        ));
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(symbol_set, &[&def, &int(2), &string("hello")])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = w.query_rule(constrained_rule(
            string_set,
            &[var(&mut syms, "sym"), var(&mut syms, "int"), var(&mut syms, "str")],
            &[pred(x, &[var(&mut syms, "sym"), var(&mut syms, "int"), var(&mut syms, "str")])],
            &[Constraint {
                id: syms.insert("str") as u32,
                kind: ConstraintKind::Str(StrConstraint::In(
                    ["test".to_string(), "aaa".to_string()]
                        .iter()
                        .cloned()
                        .collect(),
                )),
            }],
        ));
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(string_set, &[&abc, &int(0), &string("test")])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn resource() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let authority = syms.add("authority");
        let ambient = syms.add("ambient");
        let resource = syms.insert("resource");
        let operation = syms.insert("operation");
        let right = syms.insert("right");
        let file1 = syms.add("file1");
        let file2 = syms.add("file2");
        let read = syms.add("read");
        let write = syms.add("write");
        let caveat1 = syms.insert("caveat1");
        let caveat2 = syms.insert("caveat2");

        w.add_fact(fact(resource, &[&ambient, &file2]));
        w.add_fact(fact(operation, &[&ambient, &write]));
        w.add_fact(fact(right, &[&authority, &file1, &read]));
        w.add_fact(fact(right, &[&authority, &file2, &read]));
        w.add_fact(fact(right, &[&authority, &file1, &write]));

        let res = w.query_rule(rule(
            caveat1,
            &[&file1],
            &[pred(resource, &[&ambient, &file1])],
        ));

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());

        let res = w.query_rule(rule(
            caveat2,
            &[ID::Variable(0)],
            &[
                pred(resource, &[&ambient, &ID::Variable(0)]),
                pred(operation, &[&ambient, &read]),
                pred(right, &[&authority, &ID::Variable(0), &read]),
            ],
        ));

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());
    }
}
