//! Recovers payload layouts by folding literal object construction without executing calls or
//! control flow.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail, ensure};
use indexmap::IndexMap;
use swc_core::ecma::ast::BinaryOp;

use super::{Expression, Layout, RecordTemplate, Scope, Template};
use crate::candidates;
use crate::js::{JsValue, json};
use crate::listing::Index;
use crate::listing::fold::{self, Frame, Known, PAYLOAD_CELL};
use crate::vm::{Constant, Effect, Term};

/// Additional values tracked during payload folding. Treats decoded literals as ordinary
/// literals because only their values matter here.
#[derive(Clone, PartialEq)]
enum Held {
    /// A nonliteral expression that reads session state.
    Expression(Expression),
    /// The global object, including its `window` property.
    Global,
    Json,
    Date,
    /// Result of `Date.now()`.
    Now,
    /// A `Date.now()` result minus another value.
    Elapsed,
    /// One of the program's functions.
    Function,
    /// `RegExp(pattern)`, without flags.
    Pattern(String),
    /// The pattern's `exec` method.
    Exec(String),
    /// Result of `RegExp(pattern).exec(value)`.
    Matched {
        pattern: String,
        value: Expression,
    },
}

fn read(scope: Scope, path: Vec<String>) -> Known<Held> {
    Known::Ext(Held::Expression(Expression::Read { scope, path }))
}

/// Converts a known value, including a literal, to a session-state expression.
fn expression(known: Known<Held>) -> Option<Expression> {
    match known {
        Known::Literal(value) | Known::Decoded(value) => Some(Expression::Literal { value }),
        Known::Ext(Held::Expression(expression)) => Some(expression),
        _ => None,
    }
}

fn resolve(term: &Term, frame: &Frame<Held>, pool: &str) -> Option<Known<Held>> {
    let resolve = |term: &Term| resolve(term, frame, pool);
    // Whether `callee` is the method `name` of the global `object`.
    let method = |callee: &Term, object: Held, name: &str| {
        let object = Some(Known::Ext(object));
        matches!(callee, Term::Get(receiver, key)
            if resolve(receiver) == object
                && matches!(&**key, Term::Const(Constant::String(text)) if text == name))
    };
    Some(match term {
        Term::Cell(PAYLOAD_CELL) => read(Scope::Input, Vec::new()),
        Term::Closure { .. } => Known::Ext(Held::Function),
        Term::Call {
            callee, arguments, ..
        } if matches!(&**callee, Term::Global(name) if name == "RegExp") => {
            let flagless = match arguments.get(1) {
                None | Some(Term::Const(Constant::Undefined)) => true,
                Some(Term::Const(Constant::String(flags))) => flags.is_empty(),
                Some(_) => false,
            };
            match arguments.first()? {
                Term::Const(Constant::String(pattern)) if flagless => {
                    Known::Ext(Held::Pattern(pattern.clone()))
                }
                _ => return None,
            }
        }
        Term::Get(object, key) => match (resolve(object)?, resolve(key)?) {
            (Known::Ext(Held::Global), key) => match key.text()? {
                "JSON" => Known::Ext(Held::Json),
                "Date" => Known::Ext(Held::Date),
                "window" => read(Scope::Window, Vec::new()),
                _ => return None,
            },
            (
                Known::Ext(Held::Expression(Expression::Read {
                    mut scope,
                    mut path,
                })),
                Known::Literal(JsValue::String(key)),
            ) => {
                if scope == Scope::Window && path.is_empty() && key == "_cf_chl_opt" {
                    scope = Scope::Options;
                } else {
                    path.push(key);
                }
                read(scope, path)
            }
            (Known::Ext(Held::Pattern(pattern)), Known::Literal(JsValue::String(key)))
                if key == "exec" =>
            {
                Known::Ext(Held::Exec(pattern))
            }
            (
                Known::Ext(Held::Matched { pattern, value }),
                Known::Literal(JsValue::Number(group)),
            ) => {
                // Program numbers are doubles, so the index arrives as one.
                let group = Some(group).filter(|group| group.fract() == 0.0 && *group >= 0.0)?;
                Known::Ext(Held::Expression(Expression::Match {
                    value: Box::new(value),
                    pattern,
                    group: group as usize,
                }))
            }
            _ => return None,
        },
        Term::Binary(BinaryOp::Sub, left, right) => match resolve(left)? {
            Known::Ext(Held::Now) => Known::Ext(Held::Elapsed),
            left => Known::Ext(Held::Expression(Expression::Subtract {
                left: Box::new(expression(left)?),
                right: Box::new(expression(resolve(right)?)?),
            })),
        },
        Term::Call {
            callee, arguments, ..
        } if arguments.is_empty() => {
            if method(callee, Held::Date, "now") {
                Known::Ext(Held::Now)
            } else if let Some(Known::Ext(Held::Expression(Expression::Read {
                scope: Scope::Window,
                path,
            }))) = resolve(callee)
                && let [name] = path.as_slice()
            {
                Known::Ext(Held::Expression(Expression::Call { name: name.clone() }))
            } else {
                return None;
            }
        }
        Term::Call {
            callee, arguments, ..
        } => {
            let argument = resolve(arguments.first()?)?;
            match resolve(callee) {
                Some(Known::Decoder) => fold::decode(&argument, pool)?.forget_decoding(),
                Some(Known::Ext(Held::Exec(pattern))) if arguments.len() == 1 => {
                    Known::Ext(Held::Matched {
                        pattern,
                        value: expression(argument)?,
                    })
                }
                _ if method(callee, Held::Json, "parse") => fold::parse(&argument)?,
                _ => return None,
            }
        }
        term => frame.resolve(term)?,
    })
}

/// Recovered payload layout, record counter, checkbox record, and literal field assignments.
pub(in crate::stage2) struct Recovered<'listing> {
    pub pool: &'listing str,
    /// The record counter, which the template starts at zero.
    pub counter: String,
    pub layout: Layout,
    pub record: RecordTemplate,
    pub literals: Vec<RecordLiteral>,
}

/// Recovers the payload and any checkbox record. Tries unique header names as record-counter
/// candidates. Uses `program` to identify errors.
pub(in crate::stage2) fn recover_unique<'listing>(
    index: &Index<'listing>,
    program: &str,
) -> Result<Recovered<'listing>> {
    let (_, pool) = index
        .pool()
        .with_context(|| format!("{program} has no string pool"))?;
    let scan = scan(index, pool);
    let mut layouts = Vec::new();
    let mut failure = None;
    for counter in index.header().values() {
        match scan.layout(counter) {
            Ok(layout) => layouts.push((counter.clone(), layout)),
            Err(error) => failure = Some(error),
        }
    }
    ensure!(layouts.len() <= 1, "ambiguous {program} payload counter");
    let Some((counter, layout)) = layouts.pop() else {
        // Keep the last counter-candidate error to explain which required structure was
        // missing.
        let missing = format!("{program} has no payload template");
        return Err(match failure {
            Some(error) => error.context(missing),
            None => anyhow!(missing),
        });
    };
    Ok(Recovered {
        pool,
        counter,
        layout,
        record: scan.interaction_record()?,
        literals: scan.literals(),
    })
}

/// A recovered literal field assignment.
pub(in crate::stage2) struct RecordLiteral {
    pub pc: u32,
    pub field: String,
    pub value: JsValue,
    /// Whether the field belongs to a newly created object, such as a record, rather than the
    /// payload or an existing object.
    pub created: bool,
}

/// Every function's writes, folded once and shared by the readers of one listing.
pub(in crate::stage2) struct Scan(Vec<FunctionWrites>);

impl Scan {
    /// Recovers field sources for the second payload. Identifies the replacement template as the
    /// object published to the payload cell with its record `counter` initialized to zero.
    pub(in crate::stage2) fn layout(&self, counter: &str) -> Result<Layout> {
        let functions = &self.0;
        // The template consists of fields assigned before publication, with the record counter
        // set to zero.
        let is_template = |function: &FunctionWrites, publication: &Publication| {
            let fields: Vec<&Write> = function
                .writes
                .iter()
                .filter(|write| write.target == WriteTarget::Object(publication.object))
                .collect();
            fields.len() > 20
                && fields.iter().any(|write| {
                    write.key == counter
                        && matches!(&write.value, Written::Expression(Expression::Literal { value })
                            if value.as_f64() == Some(0.0))
                })
        };
        let templates = functions
            .iter()
            .enumerate()
            .filter_map(|(position, function)| {
                let publication = function
                    .published
                    .filter(|publication| is_template(function, publication))?;
                Some((position, function, publication))
            });
        let (template_position, template_function, publication) =
            candidates::exactly_one(templates, "counter-zero replacement template")?;
        let payload_writes = || functions.iter().flat_map(FunctionWrites::payload_writes);
        // Fields the program clears before it sends, such as a worker it keeps on the payload.
        let removed: BTreeSet<&str> = payload_writes()
            .filter(|write| matches!(write.value, Written::Removed))
            .map(|write| write.key.as_str())
            .collect();
        let mut template = IndexMap::new();
        let mut published = Vec::new();
        for write in &template_function.writes {
            match write.target {
                WriteTarget::Object(id)
                    if id == publication.object && write.pc < publication.pc =>
                {
                    let Some(expression) = write.value.expression() else {
                        bail!(
                            "template field {} at pc {} is not a projection of session state",
                            write.key,
                            write.pc
                        );
                    };
                    template.insert(write.key.clone(), expression.clone());
                }
                WriteTarget::Payload if !removed.contains(write.key.as_str()) => {
                    published.push((write.key.clone(), write.value.expression().cloned()));
                }
                _ => {}
            }
        }

        // The footer function writes the most decoded literals and copies to the payload. On a
        // tie, `max_by_key` chooses the later function. Other writers handle paths outside a
        // successful run.
        let payload_fields = |function: &FunctionWrites| -> IndexMap<String, Expression> {
            function
                .payload_writes()
                .filter_map(|write| Some((write.key.clone(), write.value.expression()?.clone())))
                .collect()
        };
        let footer = functions
            .iter()
            .enumerate()
            .filter(|(position, _)| *position != template_position)
            .map(|(_, function)| payload_fields(function))
            .max_by_key(IndexMap::len)
            .unwrap_or_default();
        let pending = payload_writes()
            .find(|write| matches!(write.value, Written::Elapsed))
            .map(|write| write.key.clone());
        // The function that clears fields before sending may write more fields after the call.
        // Ignore writes that restore cleared fields: those fields are never set on payloads built
        // by this crate.
        let mut sent = IndexMap::new();
        for function in functions {
            let Some(call) = function.sent else {
                continue;
            };
            if !function
                .payload_writes()
                .any(|write| matches!(write.value, Written::Removed))
            {
                continue;
            }
            for write in function.payload_writes() {
                if write.pc > call
                    && let Some(expression) = write.value.expression()
                    && !removed.contains(write.key.as_str())
                {
                    sent.insert(write.key.clone(), expression.clone());
                }
            }
        }
        Ok(Layout {
            template: Template { fields: template },
            published,
            footer,
            pending,
            sent,
        })
    }

    /// Literal field assignments, in program order.
    pub(in crate::stage2) fn literals(&self) -> Vec<RecordLiteral> {
        self.writes()
            .filter_map(|write| match &write.value {
                Written::Expression(Expression::Literal { value }) => Some(RecordLiteral {
                    pc: write.pc,
                    field: write.key.clone(),
                    value: value.clone(),
                    created: matches!(write.target, WriteTarget::Object(_)),
                }),
                _ => None,
            })
            .collect()
    }

    fn writes(&self) -> impl Iterator<Item = &Write> {
        self.0.iter().flat_map(|function| &function.writes)
    }

    /// The checkbox program's record construction: its literal token and input, and its start
    /// mark.
    fn interaction_record(&self) -> Result<RecordTemplate> {
        let mut objects: BTreeMap<u32, Vec<&Write>> = BTreeMap::new();
        for write in self.writes() {
            if let WriteTarget::Object(id) = write.target {
                objects.entry(id).or_default().push(write);
            }
        }
        let records = objects.into_values().filter_map(|fields| {
            // The first string literal written to the record that contains `marker`.
            let literal = |marker: &str| {
                fields.iter().find_map(|write| match &write.value {
                    Written::Expression(Expression::Literal {
                        value: JsValue::String(text),
                    }) if text.contains(marker) => Some((write.key.clone(), text.clone())),
                    _ => None,
                })
            };
            let (token_field, token) = literal("-1.2.1.1-")?;
            let (input_field, input) = literal("-1.3.1.1-")?;
            let started = fields
                .iter()
                .find(|write| matches!(write.value, Written::Now))?;
            Some(RecordTemplate {
                token_field,
                token,
                input_field,
                input: json!(input),
                started_field: started.key.clone(),
            })
        });
        candidates::exactly_one(records, "checkbox program token/input record construction")
    }
}

/// A function's writes, its published object, and the first call receiving the payload, if any.
#[derive(Default)]
struct FunctionWrites {
    writes: Vec<Write>,
    published: Option<Publication>,
    sent: Option<u32>,
}

impl FunctionWrites {
    fn payload_writes(&self) -> impl Iterator<Item = &Write> {
        self.writes
            .iter()
            .filter(|write| write.target == WriteTarget::Payload)
    }
}

/// An object a function published into the payload cell.
#[derive(Clone, Copy)]
struct Publication {
    /// Where the object was created, which identifies it.
    object: u32,
    /// Where it was published.
    pc: u32,
}

/// One write into the replacement object or the payload.
struct Write {
    pc: u32,
    target: WriteTarget,
    key: String,
    value: Written,
}

#[derive(Clone, Copy, PartialEq)]
enum WriteTarget {
    /// A new object, identified by where it was created.
    Object(u32),
    /// The payload cell's object.
    Payload,
    /// A probe record or another object outside the replacement template.
    Other,
}

enum Written {
    Expression(Expression),
    /// `Date.now()` less an earlier mark.
    Elapsed,
    Now,
    /// `undefined`, which removes the field from the serialized payload.
    Removed,
    /// A value that this analysis cannot recover and a browser must supply.
    Browser,
}

impl Written {
    fn expression(&self) -> Option<&Expression> {
        match self {
            Self::Expression(expression) => Some(expression),
            _ => None,
        }
    }
}

/// Folds each function once using values known after setup: common header values and the
/// global-object register representing `window`.
pub(in crate::stage2) fn scan(index: &Index<'_>, pool: &str) -> Scan {
    let mut setup = Frame::seeded(index.header());
    if let Some(global) = index.global() {
        setup.set(global, Some(Known::Ext(Held::Global)));
    }
    let input = Some(read(Scope::Input, Vec::new()));
    let evaluate = |frame: &Frame<Held>, term: &Term| resolve(term, frame, pool);
    let mut functions: Vec<FunctionWrites> = Vec::new();
    let mut frame = setup.clone();
    // Options a branch replaced with zero after reading them.
    let mut zeroed: BTreeSet<Vec<String>> = BTreeSet::new();
    // The object last published into the payload cell.
    let mut publication: Option<Publication> = None;
    for (&pc, instruction) in &index.listing().instructions {
        if index.is_entry(pc) || functions.is_empty() {
            frame = setup.clone();
            zeroed.clear();
            publication = None;
            functions.push(FunctionWrites::default());
        }
        let function = functions
            .last_mut()
            .expect("a function was pushed before the first instruction");
        for path in &instruction.paths {
            frame.begin();
            // Handlers expose both forms of a call; a known undefined receiver rules one out.
            if !fold::feasible(path, |term| evaluate(&frame, term)) {
                continue;
            }
            frame.follow(pc, &path.effects, evaluate, |frame, effect| {
                let resolve = |term: &Term| evaluate(frame, term);
                if let Some((_, arguments)) = effect.call()
                    && arguments.iter().any(|argument| resolve(argument) == input)
                {
                    function.sent.get_or_insert(pc);
                }
                match effect {
                    // A branch that replaces an option it read with zero.
                    Effect::Set(register, value) => {
                        if let Some(Known::Ext(Held::Expression(Expression::Read {
                            scope: Scope::Options,
                            path,
                        }))) = frame.register(*register)
                            && let Some(Known::Literal(literal)) = resolve(value)
                            && literal.as_f64() == Some(0.0)
                        {
                            zeroed.insert(path.clone());
                        }
                    }
                    Effect::SetProperty { object, key, value } => {
                        let target = match resolve(object) {
                            Some(Known::Object(id))
                                if publication.is_some_and(|published| published.object == id) =>
                            {
                                WriteTarget::Payload
                            }
                            Some(Known::Object(id)) => WriteTarget::Object(id),
                            known if known == input => WriteTarget::Payload,
                            _ => WriteTarget::Other,
                        };
                        let Some(Known::Literal(JsValue::String(key))) = resolve(key) else {
                            return;
                        };
                        let value = match resolve(value) {
                            Some(Known::Ext(Held::Expression(option)))
                                if matches!(&option, Expression::Read { scope: Scope::Options, path }
                                    if zeroed.contains(path)) =>
                            {
                                Written::Expression(Expression::OrZero {
                                    value: Box::new(option),
                                })
                            }
                            Some(Known::Ext(Held::Elapsed)) => Written::Elapsed,
                            Some(Known::Ext(Held::Now)) => Written::Now,
                            Some(Known::Undefined) => Written::Removed,
                            // Function-valued fields are omitted during serialization.
                            Some(Known::Ext(Held::Function)) => return,
                            known => known
                                .and_then(expression)
                                .map_or(Written::Browser, Written::Expression),
                        };
                        function.writes.push(Write {
                            pc,
                            target,
                            key,
                            value,
                        });
                    }
                    Effect::SetCell(PAYLOAD_CELL, value) => {
                        if let Some(Known::Object(id)) = resolve(value) {
                            publication = Some(Publication { object: id, pc });
                        }
                    }
                    _ => {}
                }
            });
        }
        function.published = function.published.or(publication);
    }
    Scan(functions)
}
