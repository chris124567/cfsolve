//! Disassembly values, effects, and exits for each feasible handler path. Byte-dependent values
//! are concrete; register-dependent values remain expressions.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::iter;

use swc_core::ecma::ast::{BinaryOp, UnaryOp};

/// A constant determined by program bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum Constant {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

/// A value an instruction computes from the registers.
#[derive(Clone, Debug, PartialEq)]
pub enum Term {
    Const(Constant),
    Reg(u8),
    /// The value a call or construction produced earlier in the instruction.
    Temp(usize),
    Cells,
    Cell(u32),
    /// A global the machine reads, such as `Math`.
    Global(String),
    /// A field of the interpreter instance.
    Field(String),
    Array(Vec<Term>),
    Object(Vec<(String, Term)>),
    Get(Box<Term>, Box<Term>),
    Call {
        callee: Box<Term>,
        this: Option<Box<Term>>,
        arguments: Vec<Term>,
    },
    New {
        callee: Box<Term>,
        arguments: Vec<Term>,
    },
    Unary(UnaryOp, Box<Term>),
    Binary(BinaryOp, Box<Term>, Box<Term>),
    /// A program function with entry `pc`, dispatch `key`, saved registers, and declared
    /// argument count.
    Closure {
        pc: u32,
        key: u8,
        parameters: Vec<u8>,
        arity: u8,
    },
    Opaque(String),
}

/// Instruction effects beyond control-flow continuation.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    Let(usize, Term),
    Set(u8, Term),
    /// Boxed because property writes are rare and inline terms would triple the size of every
    /// effect.
    SetProperty {
        object: Box<Term>,
        key: Box<Term>,
        value: Box<Term>,
    },
    SetCell(u32, Term),
    NewCell(u32),
    Throw(Term),
}

/// How one run of a handler ended.
#[derive(Clone, Debug, PartialEq)]
pub enum Exit {
    Next {
        pc: u32,
        key: u8,
    },
    Return,
    /// The program throws a register-dependent value.
    Throw,
    /// The handler reached unsupported code. Retains any continuation program counter set
    /// before that point.
    Unfollowed {
        pc: u32,
        key: u8,
        reason: String,
    },
}

impl Exit {
    /// Returns the destination of `Next` or the continuation left by `Unfollowed`.
    #[must_use]
    pub fn continues_at(&self) -> Option<Position> {
        match *self {
            Exit::Next { pc, key } | Exit::Unfollowed { pc, key, .. } => {
                Some(Position::new(pc, key))
            }
            Exit::Return | Exit::Throw => None,
        }
    }
}

/// One feasible way through a handler.
#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    pub conditions: Vec<(Term, bool)>,
    pub effects: Vec<Effect>,
    pub exit: Exit,
}

/// Decoded instruction with its feasible handler paths.
#[derive(Clone, Debug)]
pub struct Instruction {
    pub pc: u32,
    pub key: u8,
    pub opcode: u8,
    pub paths: Vec<Path>,
}

impl Instruction {
    /// Every effect of every path through the instruction, path by path.
    pub fn effects(&self) -> impl Iterator<Item = &Effect> {
        self.paths.iter().flat_map(|path| &path.effects)
    }

    /// Returns continuation program counters for the instruction's paths (see
    /// [`Exit::continues_at`]).
    pub fn exits(&self) -> impl Iterator<Item = u32> {
        self.paths
            .iter()
            .filter_map(|path| path.exit.continues_at())
            .map(|next| next.pc)
    }
}

/// Bytes that do not decode to an instruction, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct Failure {
    pub pc: u32,
    pub key: u8,
    pub cause: Cause,
}

/// Why bytes do not decode to an instruction.
#[derive(Clone, Debug, PartialEq)]
pub enum Cause {
    PastEnd,
    /// Reason the dispatch decoder stopped without producing an opcode.
    Undecoded {
        reason: String,
    },
    /// The byte decodes to an opcode the run loop has no case for.
    NoHandler {
        opcode: u8,
    },
    /// Every handler path throws, so the operands are invalid. Holds each path's exception.
    Faults {
        opcode: u8,
        reasons: Vec<String>,
    },
    TooManyPaths {
        opcode: u8,
        limit: usize,
    },
}

impl Display for Failure {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let pc = self.pc;
        match &self.cause {
            Cause::PastEnd => write!(f, "pc {pc} is past the end of the program"),
            Cause::Undecoded { reason } => write!(f, "pc {pc} decodes no opcode: {reason}"),
            Cause::NoHandler { opcode } => write!(f, "no handler for opcode {opcode} at pc {pc}"),
            Cause::Faults { opcode, reasons } => {
                let reasons = reasons.join("; ");
                write!(f, "opcode {opcode} at pc {pc} faults: {reasons}")
            }
            Cause::TooManyPaths { opcode, limit } => {
                write!(
                    f,
                    "opcode {opcode} at pc {pc} branches more than {limit} ways"
                )
            }
        }
    }
}

impl Error for Failure {}

/// Program counter and dispatch key. The same bytes decode differently under different keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Position {
    pub pc: u32,
    pub key: u8,
}

impl Position {
    #[must_use]
    pub fn new(pc: u32, key: u8) -> Self {
        Self { pc, key }
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pc, self.key)
    }
}

/// A resolved hidden branch whose matching string hash unmasks its target.
#[derive(Clone, Debug, PartialEq)]
pub struct Hidden {
    /// The compare instruction's pc.
    pub compare: u32,
    /// The string that takes the branch.
    pub string: String,
    pub target: Position,
}

/// Every instruction reachable from a program's entry.
#[derive(Clone, Debug, Default)]
pub struct Listing {
    pub instructions: BTreeMap<u32, Instruction>,
    /// Entries of the program's own functions.
    pub functions: Vec<Position>,
    pub failures: Vec<Failure>,
    pub hidden: Vec<Hidden>,
}

impl Term {
    /// Visits this term and its children, parents first.
    pub fn visit(&self, visit: &mut impl FnMut(&Term)) {
        visit(self);
        match self {
            Term::Array(elements) => {
                for element in elements {
                    element.visit(visit);
                }
            }
            Term::Object(properties) => {
                for (_, value) in properties {
                    value.visit(visit);
                }
            }
            Term::Get(left, right) | Term::Binary(_, left, right) => {
                left.visit(visit);
                right.visit(visit);
            }
            Term::Call {
                callee,
                this,
                arguments,
            } => {
                let children = iter::once(&**callee)
                    .chain(this.as_deref())
                    .chain(arguments);
                for child in children {
                    child.visit(visit);
                }
            }
            Term::New { callee, arguments } => {
                callee.visit(visit);
                for argument in arguments {
                    argument.visit(visit);
                }
            }
            Term::Unary(_, argument) => argument.visit(visit),
            Term::Const(_)
            | Term::Reg(_)
            | Term::Temp(_)
            | Term::Cells
            | Term::Cell(_)
            | Term::Global(_)
            | Term::Field(_)
            | Term::Closure { .. }
            | Term::Opaque(_) => {}
        }
    }

    /// The text of a string constant.
    #[must_use]
    pub fn string(&self) -> Option<&str> {
        match self {
            Term::Const(Constant::String(text)) => Some(text),
            _ => None,
        }
    }
}

impl Effect {
    /// Visits all terms in this effect, including nested terms.
    pub fn visit_terms(&self, visit: &mut impl FnMut(&Term)) {
        match self {
            Effect::Let(_, term)
            | Effect::Set(_, term)
            | Effect::SetCell(_, term)
            | Effect::Throw(term) => term.visit(visit),
            Effect::SetProperty { object, key, value } => {
                object.visit(visit);
                key.visit(visit);
                value.visit(visit);
            }
            Effect::NewCell(_) => {}
        }
    }

    /// The callee and arguments of a call whose result a `Let` or `Set` stores.
    #[must_use]
    pub fn call(&self) -> Option<(&Term, &[Term])> {
        let (Effect::Let(_, term) | Effect::Set(_, term)) = self else {
            return None;
        };
        match term {
            Term::Call {
                callee, arguments, ..
            } => Some((callee, arguments)),
            _ => None,
        }
    }
}

impl Display for Constant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => f.write_str("undefined"),
            Self::Null => f.write_str("null"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Number(number) => write!(f, "{number}"),
            Self::String(text) => write!(f, "{text:?}"),
        }
    }
}

/// Joins the displayed `items` with `separator`.
fn join<T: Display>(items: impl IntoIterator<Item = T>, separator: &str) -> String {
    let items: Vec<String> = items.into_iter().map(|item| item.to_string()).collect();
    items.join(separator)
}

impl Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(constant) => write!(f, "{constant}"),
            Self::Reg(register) => write!(f, "r{register}"),
            Self::Temp(temp) => write!(f, "t{temp}"),
            Self::Cells => f.write_str("cells"),
            Self::Cell(cell) => write!(f, "c{cell}"),
            Self::Global(name) => f.write_str(name),
            Self::Field(name) => write!(f, "vm.{name}"),
            Self::Array(elements) => write!(f, "[{}]", join(elements, ", ")),
            Self::Object(properties) => {
                let properties = properties
                    .iter()
                    .map(|(key, value)| format!("{key}: {value}"));
                write!(f, "{{{}}}", join(properties, ", "))
            }
            Self::Get(object, key) => member(f, object, key),
            Self::Call {
                callee,
                this: Some(this),
                arguments,
            } => {
                let arguments = iter::once(&**this).chain(arguments);
                write!(f, "{callee}.call({})", join(arguments, ", "))
            }
            Self::Call {
                callee,
                this: None,
                arguments,
            } => write!(f, "{callee}({})", join(arguments, ", ")),
            Self::New { callee, arguments } => write!(f, "new {callee}({})", join(arguments, ", ")),
            Self::Unary(operator, argument) => match operator {
                UnaryOp::TypeOf | UnaryOp::Void | UnaryOp::Delete => {
                    write!(f, "{} {argument}", operator.as_str())
                }
                _ => write!(f, "{}{argument}", operator.as_str()),
            },
            Self::Binary(operator, left, right) => {
                write!(f, "({left} {} {right})", operator.as_str())
            }
            Self::Closure {
                pc,
                key,
                parameters,
                ..
            } => {
                let parameters = parameters.iter().map(|register| format!("r{register}"));
                write!(f, "function@{pc}:{key}({})", join(parameters, ", "))
            }
            Self::Opaque(what) => write!(f, "<{what}>"),
        }
    }
}

/// Displays `object[key]`, using `object.key` when the string key is a valid identifier.
fn member(f: &mut Formatter<'_>, object: &Term, key: &Term) -> fmt::Result {
    match key {
        Term::Const(Constant::String(name)) if is_identifier(name) => write!(f, "{object}.{name}"),
        key => write!(f, "{object}[{key}]"),
    }
}

fn is_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_' || first == '$')
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        })
}

impl Display for Effect {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Let(temp, value) => write!(f, "t{temp} = {value}"),
            Self::Set(register, value) => write!(f, "r{register} = {value}"),
            Self::SetProperty { object, key, value } => {
                member(f, object, key)?;
                write!(f, " = {value}")
            }
            Self::SetCell(cell, value) => write!(f, "c{cell} = {value}"),
            Self::NewCell(cell) => write!(f, "c{cell} = new cell"),
            Self::Throw(value) => write!(f, "throw {value}"),
        }
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for path in &self.paths {
            write!(f, "{:>7} {:>3} op{:<3}", self.pc, self.key, self.opcode)?;
            if self.paths.len() > 1 {
                let conditions = path.conditions.iter().map(|(condition, taken)| {
                    format!("{}{condition}", if *taken { "" } else { "!" })
                });
                write!(f, " [{}]", join(conditions, " && "))?;
            }
            write!(f, " {}", join(&path.effects, "; "))?;
            match &path.exit {
                Exit::Next { pc, key } if *pc != self.pc + 1 => write!(f, " -> {pc}:{key}")?,
                Exit::Next { .. } | Exit::Throw => {}
                Exit::Return => f.write_str(" return")?,
                Exit::Unfollowed { pc, key, reason } => write!(f, " -> {pc}:{key} ({reason})")?,
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
