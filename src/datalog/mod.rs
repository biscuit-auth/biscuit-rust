//! Logic language implementation for checks
use crate::time::Instant;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::AsRef;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type Symbol = u64;
mod expression;
mod symbol;
pub use expression::*;
pub use symbol::*;

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum ID {
    Variable(u32),
    Integer(i64),
    Str(Symbol),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<ID>),
}

impl From<&ID> for ID {
    fn from(i: &ID) -> Self {
        match i {
            ID::Variable(ref v) => ID::Variable(*v),
            ID::Integer(ref i) => ID::Integer(*i),
            ID::Str(ref s) => ID::Str(*s),
            ID::Date(ref d) => ID::Date(*d),
            ID::Bytes(ref b) => ID::Bytes(b.clone()),
            ID::Bool(ref b) => ID::Bool(*b),
            ID::Set(ref s) => ID::Set(s.clone()),
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
    pub expressions: Vec<Expression>,
}

impl AsRef<Expression> for Expression {
    fn as_ref(&self) -> &Expression {
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub queries: Vec<Rule>,
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({:?})", self.predicate.name, self.predicate.ids)
    }
}

impl Rule {
    pub fn apply<'a>(
        &'a self,
        facts: &'a HashSet<Fact>,
        symbols: &'a SymbolTable,
    ) -> impl Iterator<Item = Fact> + 'a {
        // gather all of the variables used in that rule
        let variables_set = self
            .body
            .iter()
            .flat_map(|pred| {
                pred.ids.iter().filter_map(|id| match id {
                    ID::Variable(i) => Some(*i),
                    _ => None,
                })
            })
            .collect::<HashSet<_>>();

        let head = self.head.clone();
        let variables = MatchedVariables::new(variables_set);
        CombineIt::new(variables, &self.body, &self.expressions, facts, symbols).filter_map(move |h| {
            let mut p = head.clone();
            for index in 0..p.ids.len() {
                let value = match &p.ids[index] {
                    ID::Variable(i) => match h.get(i) {
                      Some(val) => val,
                      None => {
                        println!("error: variables that appear in the head should appear in the body and constraints as well");
                        return None;
                      }
                    },
                    _ => continue,
                };

                p.ids[index] = value.clone();
            }

            Some(Fact { predicate: p })
        })
    }

    pub fn find_match(&self, facts: &HashSet<Fact>, symbols: &SymbolTable) -> bool {
        // gather all of the variables used in that rule
        let variables_set = self
            .body
            .iter()
            .flat_map(|pred| {
                pred.ids.iter().filter_map(|id| match id {
                    ID::Variable(i) => Some(*i),
                    _ => None,
                })
            })
            .collect::<HashSet<_>>();

        let variables = MatchedVariables::new(variables_set);

        let mut it = CombineIt::new(variables, &self.body, &self.expressions, facts, symbols).filter_map(|h| {
            let mut p = self.head.clone();
            for index in 0..p.ids.len() {
                let value = match &p.ids[index] {
                    ID::Variable(i) => match h.get(i) {
                        Some(val) => val,
                        None => {
                            println!("error: variables that appear in the head should appear in the body and constraints as well");
                            return None;
                        }
                    },
                    _ => continue,
                };

                p.ids[index] = value.clone();
            }

            Some(Fact { predicate: p })
        });

        let next = it.next();
        next.is_some()
    }
}

/// recursive iterator for rule application
pub struct CombineIt<'a> {
    variables: MatchedVariables,
    predicates: &'a [Predicate],
    expressions: &'a [Expression],
    all_facts: &'a HashSet<Fact>,
    symbols: &'a SymbolTable,
    current_facts: Box<dyn Iterator<Item = &'a Fact> + 'a>,
    current_it: Option<Box<CombineIt<'a>>>,
}

impl<'a> CombineIt<'a> {
    pub fn new(
        variables: MatchedVariables,
        predicates: &'a [Predicate],
        expressions: &'a [Expression],
        facts: &'a HashSet<Fact>,
        symbols: &'a SymbolTable,
    ) -> Self {
        let current_facts: Box<dyn Iterator<Item = &'a Fact> + 'a> = if predicates.is_empty() {
            Box::new(facts.iter())
        } else {
            let p = predicates[0].clone();
            Box::new(
                facts
                    .iter()
                    .filter(move |fact| match_preds(&p, &fact.predicate)),
            )
        };

        CombineIt {
            variables,
            predicates,
            expressions,
            all_facts: facts,
            symbols,
            current_facts,
            current_it: None,
        }
    }
}

impl<'a> Iterator for CombineIt<'a> {
    type Item = HashMap<u32, ID>;

    fn next(&mut self) -> Option<HashMap<u32, ID>> {
        // if we're the last iterator in the recursive chain, stop here
        if self.predicates.is_empty() {
            //return None;
            //return self.variables.complete();
            match self.variables.complete() {
                None => return None,
                // we got a complete set of variables, let's test the expressions
                Some(variables) => {
                    //println!("predicates empty, will test variables: {:?}", variables);
                    let mut valid = true;
                    for e in self.expressions.iter() {
                        match e.evaluate(&variables, self.symbols) {
                            Some(ID::Bool(true)) => {}
                            _res => {
                                //println!("expr returned {:?}", res);
                                valid = false;
                                break;
                            }
                        }
                    }

                    if valid {
                        return Some(variables);
                    } else {
                        return None;
                    }
                }
            }
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
                            match vars.complete() {
                                None => {
                                    //println!("variables not complete, continue");
                                    continue;
                                }
                                // we got a complete set of variables, let's test the expressions
                                Some(variables) => {
                                    //println!("will test with variables: {:?}", variables);
                                    let mut valid = true;
                                    for e in self.expressions.iter() {
                                        match e.evaluate(&variables, self.symbols) {
                                            Some(ID::Bool(true)) => {
                                                //println!("expression returned true");
                                            }
                                            _e => {
                                                //println!("expression returned {:?}", e);
                                                valid = false;
                                                break;
                                            }
                                        }
                                    }

                                    if valid {
                                        return Some(variables);
                                    } else {
                                        continue;
                                    }
                                }
                            }
                        } else {
                            // create a new iterator with the matched variables, the rest of the predicates,
                            // and all of the facts
                            self.current_it = Some(Box::new(CombineIt::new(
                                vars,
                                &self.predicates[1..],
                                self.expressions,
                                &self.all_facts,
                                &self.symbols,
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
        expressions: Vec::new(),
    }
}

pub fn expressed_rule<I: AsRef<ID>, P: AsRef<Predicate>, C: AsRef<Expression>>(
    head_name: Symbol,
    head_ids: &[I],
    predicates: &[P],
    expressions: &[C],
) -> Rule {
    Rule {
        head: pred(head_name, head_ids),
        body: predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions: expressions.iter().map(|c| c.as_ref().clone()).collect(),
    }
}

pub fn int(i: i64) -> ID {
    ID::Integer(i)
}

/*pub fn string(s: &str) -> ID {
    ID::Str(s.to_string())
}*/

pub fn date(t: &SystemTime) -> ID {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    ID::Date(dur.as_secs())
}

pub fn var(syms: &mut SymbolTable, name: &str) -> ID {
    let id = syms.insert(name);
    ID::Variable(id as u32)
}

pub fn match_preds(rule_pred: &Predicate, fact_pred: &Predicate) -> bool {
    rule_pred.name == fact_pred.name
        && rule_pred.ids.len() == fact_pred.ids.len()
        && rule_pred
            .ids
            .iter()
            .zip(&fact_pred.ids)
            .all(|(fid, pid)| match (fid, pid) {
                // the fact should not contain variables
                (_, ID::Variable(_)) => false,
                (ID::Variable(_), _) => true,
                (ID::Integer(i), ID::Integer(j)) => i == j,
                (ID::Str(i), ID::Str(j)) => i == j,
                (ID::Date(i), ID::Date(j)) => i == j,
                (ID::Bytes(i), ID::Bytes(j)) => i == j,
                (ID::Bool(i), ID::Bool(j)) => i == j,
                (ID::Set(i), ID::Set(j)) => i == j,
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

    pub fn run(&mut self, symbols: &SymbolTable) -> Result<(), crate::error::RunLimit> {
        self.run_with_limits(symbols, RunLimits::default())
    }

    pub fn run_with_limits(
        &mut self,
        symbols: &SymbolTable,
        limits: RunLimits,
    ) -> Result<(), crate::error::RunLimit> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;
        let mut index = 0;

        loop {
            let mut new_facts: Vec<Fact> = Vec::new();

            for rule in self.rules.iter() {
                new_facts.extend(rule.apply(&self.facts, symbols));
                //println!("new_facts after applying {:?}:\n{:#?}", rule, new_facts);
            }

            let len = self.facts.len();
            self.facts.extend(new_facts.drain(..));
            if self.facts.len() == len {
                break;
            }

            index += 1;
            if index == limits.max_iterations {
                return Err(crate::error::RunLimit::TooManyIterations);
            }

            if self.facts.len() >= limits.max_facts as usize {
                return Err(crate::error::RunLimit::TooManyFacts);
            }

            let now = Instant::now();
            if now >= time_limit {
                return Err(crate::error::RunLimit::Timeout);
            }
        }

        Ok(())
    }

    pub fn query(&self, pred: Predicate) -> Vec<&Fact> {
        self.facts
            .iter()
            .filter(|f| {
                f.predicate.name == pred.name
                    && f.predicate.ids.iter().zip(&pred.ids).all(|(fid, pid)| {
                        let res = match (fid, pid) {
                            //(ID::Symbol(_), ID::Variable(_)) => true,
                            //(ID::Symbol(i), ID::Symbol(ref j)) => i == j,
                            (_, ID::Variable(_)) => true,
                            (ID::Integer(i), ID::Integer(ref j)) => i == j,
                            (ID::Str(i), ID::Str(ref j)) => i == j,
                            (ID::Date(i), ID::Date(ref j)) => i == j,
                            (ID::Bytes(i), ID::Bytes(ref j)) => i == j,
                            (ID::Bool(i), ID::Bool(ref j)) => i == j,
                            (ID::Set(i), ID::Set(ref j)) => i == j,
                            _ => false,
                        };
                        res
                    })
            })
            .collect::<Vec<_>>()
    }

    pub fn query_rule(&self, rule: Rule, symbols: &SymbolTable) -> Vec<Fact> {
        let mut new_facts: Vec<Fact> = Vec::new();
        new_facts.extend(rule.apply(&self.facts, symbols));
        new_facts
    }

    pub fn query_match(&self, rule: Rule, symbols: &SymbolTable) -> bool {
        rule.find_match(&self.facts, symbols)
    }
}

pub struct RunLimits {
    pub max_facts: u32,
    pub max_iterations: u32,
    pub max_time: Duration,
}

impl std::default::Default for RunLimits {
    fn default() -> Self {
        RunLimits {
            max_facts: 1000,
            max_iterations: 100,
            max_time: Duration::from_millis(1),
        }
    }
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
                pred(
                    parent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "parent")],
                ),
                pred(
                    parent,
                    &[var(&mut syms, "parent"), var(&mut syms, "grandchild")],
                ),
            ],
        );

        println!("symbols: {:?}", syms);
        println!("testing r1: {}", syms.print_rule(&r1));
        let query_rule_result = w.query_rule(r1, &syms);
        println!("grandparents query_rules: {:?}", query_rule_result);
        println!("current facts: {:?}", w.facts);

        let r2 = rule(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
            &[
                pred(
                    parent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "parent")],
                ),
                pred(
                    parent,
                    &[var(&mut syms, "parent"), var(&mut syms, "grandchild")],
                ),
            ],
        );

        println!("adding r2: {}", syms.print_rule(&r2));
        w.add_rule(r2);

        w.run(&syms).unwrap();

        println!("parents:");
        let res = w.query(pred(
            parent,
            &[var(&mut syms, "parent"), var(&mut syms, "child")],
        ));
        for fact in res {
            println!("\t{}", syms.print_fact(fact));
        }

        println!(
            "parents of B: {:?}",
            w.query(pred(parent, &[&var(&mut syms, "parent"), &b]))
        );
        println!(
            "grandparents: {:?}",
            w.query(pred(
                grandparent,
                &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")]
            ))
        );
        w.add_fact(fact(parent, &[&c, &e]));
        w.run(&syms).unwrap();
        let mut res = w.query(pred(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
        ));
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

        let res = w.query_rule(
            rule(
                join,
                &[var(&mut syms, "left"), var(&mut syms, "right")],
                &[
                    pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                    pred(
                        t2,
                        &[
                            var(&mut syms, "t2_id"),
                            var(&mut syms, "right"),
                            var(&mut syms, "id"),
                        ],
                    ),
                ],
            ),
            &syms,
        );
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
        let res = w.query_rule(
            expressed_rule(
                join,
                &[var(&mut syms, "left"), var(&mut syms, "right")],
                &[
                    pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                    pred(
                        t2,
                        &[
                            var(&mut syms, "t2_id"),
                            var(&mut syms, "right"),
                            var(&mut syms, "id"),
                        ],
                    ),
                ],
                &[Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "id")),
                        Op::Value(ID::Integer(1)),
                        Op::Binary(Binary::LessThan),
                    ],
                }],
            ),
            &syms,
        );
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
        let example = syms.add("example.com");
        let test_com = syms.add("test.com");
        let test_fr = syms.add("test.fr");
        let www_example = syms.add("www.example.com");
        let mx_example = syms.add("mx.example.com");

        w.add_fact(fact(route, &[&int(0), &app_0, &example]));
        w.add_fact(fact(route, &[&int(1), &app_1, &test_com]));
        w.add_fact(fact(route, &[&int(2), &app_2, &test_fr]));
        w.add_fact(fact(route, &[&int(3), &app_0, &www_example]));
        w.add_fact(fact(route, &[&int(4), &app_1, &mx_example]));

        fn test_suffix(
            w: &World,
            syms: &mut SymbolTable,
            suff: Symbol,
            route: Symbol,
            suffix: &str,
        ) -> Vec<Fact> {
            let id_suff = syms.add(suffix);
            w.query_rule(
                expressed_rule(
                    suff,
                    &[var(syms, "app_id"), var(syms, "domain_name")],
                    &[pred(
                        route,
                        &[
                            var(syms, "route_id"),
                            var(syms, "app_id"),
                            var(syms, "domain_name"),
                        ],
                    )],
                    &[Expression {
                        ops: vec![
                            Op::Value(var(syms, "domain_name")),
                            Op::Value(id_suff),
                            Op::Binary(Binary::Suffix),
                        ],
                    }],
                ),
                &syms,
            )
        }

        let res = test_suffix(&w, &mut syms, suff, route, ".fr");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(suff, &[&app_2, &test_fr])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = test_suffix(&w, &mut syms, suff, route, "example.com");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![
            fact(suff, &[&app_0, &example]),
            fact(suff, &[&app_0, &www_example]),
            fact(suff, &[&app_1, &mx_example]),
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

        let r1 = expressed_rule(
            before,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(ID::Date(t2_timestamp)),
                        Op::Binary(Binary::LessOrEqual),
                    ],
                },
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(ID::Date(0)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
            ],
        );

        println!("testing r1: {}", syms.print_rule(&r1));
        let res = w.query_rule(r1, &syms);
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(before, &[&date(&t1), &abc])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let r2 = expressed_rule(
            after,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(ID::Date(t2_timestamp)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(ID::Date(0)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
            ],
        );

        println!("testing r2: {}", syms.print_rule(&r2));
        let res = w.query_rule(r2, &syms);
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
        let test = syms.add("test");
        let hello = syms.add("hello");
        let aaa = syms.add("zzz");

        w.add_fact(fact(x, &[&abc, &int(0), &test]));
        w.add_fact(fact(x, &[&def, &int(2), &hello]));

        let res = w.query_rule(
            expressed_rule(
                int_set,
                &[var(&mut syms, "sym"), var(&mut syms, "str")],
                &[pred(
                    x,
                    &[
                        var(&mut syms, "sym"),
                        var(&mut syms, "int"),
                        var(&mut syms, "str"),
                    ],
                )],
                &[Expression {
                    ops: vec![
                        Op::Value(ID::Set(
                            [ID::Integer(0), ID::Integer(1)].iter().cloned().collect(),
                        )),
                        Op::Value(var(&mut syms, "int")),
                        Op::Binary(Binary::Contains),
                    ],
                }],
            ),
            &syms,
        );

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(int_set, &[&abc, &test])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let abc_sym_id = syms.add("abc");
        let ghi_sym_id = syms.add("ghi");

        let res = w.query_rule(
            expressed_rule(
                symbol_set,
                &[
                    var(&mut syms, "symbol"),
                    var(&mut syms, "int"),
                    var(&mut syms, "str"),
                ],
                &[pred(
                    x,
                    &[
                        var(&mut syms, "symbol"),
                        var(&mut syms, "int"),
                        var(&mut syms, "str"),
                    ],
                )],
                &[Expression {
                    ops: vec![
                        Op::Value(ID::Set([abc_sym_id, ghi_sym_id].iter().cloned().collect())),
                        Op::Value(var(&mut syms, "symbol")),
                        Op::Binary(Binary::Contains),
                        Op::Unary(Unary::Negate),
                    ],
                }],
            ),
            &syms,
        );

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(symbol_set, &[&def, &int(2), &hello])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = w.query_rule(
            expressed_rule(
                string_set,
                &[
                    var(&mut syms, "sym"),
                    var(&mut syms, "int"),
                    var(&mut syms, "str"),
                ],
                &[pred(
                    x,
                    &[
                        var(&mut syms, "sym"),
                        var(&mut syms, "int"),
                        var(&mut syms, "str"),
                    ],
                )],
                &[Expression {
                    ops: vec![
                        Op::Value(ID::Set([test.clone(), aaa].iter().cloned().collect())),
                        Op::Value(var(&mut syms, "str")),
                        Op::Binary(Binary::Contains),
                    ],
                }],
            ),
            &syms,
        );
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(string_set, &[&abc, &int(0), &test])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn resource() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let resource = syms.insert("resource");
        let operation = syms.insert("operation");
        let right = syms.insert("right");
        let file1 = syms.add("file1");
        let file2 = syms.add("file2");
        let read = syms.add("read");
        let write = syms.add("write");
        let check1 = syms.insert("check1");
        let check2 = syms.insert("check2");

        w.add_fact(fact(resource, &[&file2]));
        w.add_fact(fact(operation, &[&write]));
        w.add_fact(fact(right, &[&file1, &read]));
        w.add_fact(fact(right, &[&file2, &read]));
        w.add_fact(fact(right, &[&file1, &write]));

        let res = w.query_rule(rule(check1, &[&file1], &[pred(resource, &[&file1])]), &syms);

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());

        let res = w.query_rule(
            rule(
                check2,
                &[ID::Variable(0)],
                &[
                    pred(resource, &[&ID::Variable(0)]),
                    pred(operation, &[&read]),
                    pred(right, &[&ID::Variable(0), &read]),
                ],
            ),
            &syms,
        );

        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());
    }

    #[test]
    fn int_expr() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let less_than = syms.insert("less_than");

        w.add_fact(fact(x, &[&int(-2), &abc]));
        w.add_fact(fact(x, &[&int(0), &def]));

        let r1 = expressed_rule(
            less_than,
            &[var(&mut syms, "nb"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "nb"), var(&mut syms, "val")])],
            &[Expression {
                ops: vec![
                    Op::Value(ID::Integer(5)),
                    Op::Value(ID::Integer(-4)),
                    Op::Binary(Binary::Add),
                    Op::Value(ID::Integer(-1)),
                    Op::Binary(Binary::Mul),
                    Op::Value(var(&mut syms, "nb")),
                    Op::Binary(Binary::LessThan),
                ],
            }],
        );

        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r1: {}\n", syms.print_rule(&r1));
        let res = w.query_rule(r1, &syms);
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        println!("got res: {:?}", res2);
        let compared = (vec![fact(less_than, &[&int(0), &def])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
        //panic!();
    }

    #[test]
    fn unbound_variables() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let operation = syms.insert("operation");
        let check = syms.insert("check");
        let read = syms.add("read");
        let write = syms.add("write");
        let unbound = var(&mut syms, "unbound");
        let any1 = var(&mut syms, "any1");
        let any2 = var(&mut syms, "any2");

        w.add_fact(fact(operation, &[&write]));

        let r1 = rule(
            operation,
            &[&unbound, &read],
            &[pred(operation, &[&any1, &any2])],
        );
        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r1: {}\n", syms.print_rule(&r1));
        let res = w.query_rule(r1, &syms);

        println!("generated facts:");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());

        // operation($unbound, #read) should not have been generated
        // in case it is generated though, verify that rule application
        // will not match it
        w.add_fact(fact(operation, &[&unbound, &read]));
        let r2 = rule(check, &[&read], &[pred(operation, &[&read])]);
        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r2: {}\n", syms.print_rule(&r2));
        let res = w.query_rule(r2, &syms);

        println!("generated facts:");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }
        assert!(res.is_empty());
    }
}
