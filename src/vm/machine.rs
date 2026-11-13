//! A session's VM, found in its script and ready to decode instructions.

use std::rc::Rc;

use anyhow::{Context, Result};
use oxc::ast::ast::{Class, Function, FunctionBody, Statement};
use oxc::semantic::SymbolId;

use super::HashMap;
use super::dispatch::{Decoded, Dispatch};
use super::extract::{self, RunFunction};
use super::interpret::{self, Decrypted, Invocation, MAXIMUM_PATHS, NativeDispatch, Way};
use super::output::{Cause, Failure, Instruction, Position};
use super::session::Session;
use super::value::Value;
use crate::js::ast::Script;

/// The VM class, enclosing function body, run function layout, opcode decoder, and statements
/// executed before its scope is entered, in the script that defines them.
pub struct Definition<'a> {
    pub(super) script: Script<'a>,
    pub(super) body: &'a FunctionBody<'a>,
    pub(super) class: &'a Class<'a>,
    pub(super) prelude: Vec<&'a Statement<'a>>,
    /// Functions declared beside the class: handlers and their helpers.
    pub(super) functions: HashMap<SymbolId, &'a Function<'a>>,
    pub(super) run: RunFunction<'a>,
    /// Where the program runner starts a program.
    pub(super) entry: Position,
    dispatch: Dispatch<'a>,
}

impl<'a> Definition<'a> {
    /// Finds the VM in `script` from its program runner. Fails unless the run function's
    /// dispatch loop has the expected shape.
    pub(crate) fn from_script(script: Script<'a>) -> Result<Self> {
        let found = extract::find(script).context("finding the VM")?;
        let functions = extract::functions(&found.body.statements);
        let run = extract::run_function(script, &functions, found.run)?;
        let dispatch = Dispatch::from_loop(script, &run.dispatch)?;
        Ok(Self {
            script,
            body: found.body,
            class: found.class,
            prelude: extract::prelude(script, found.body),
            functions,
            run,
            entry: found.entry,
            dispatch,
        })
    }
}

/// One session's VM, ready to decode instructions.
pub struct Machine<'definition> {
    definition: &'definition Definition<'definition>,
    pub(super) session: Session<'definition>,
    /// The opcode decoder, run natively, if it has the recognized shape.
    pub(super) native_dispatch: Option<NativeDispatch<'definition>>,
}

/// A program, with the instance fields the constructor derives from it and the strings
/// decrypted from it so far. Decryption depends only on the program, so copies share the
/// decrypted strings.
#[derive(Clone)]
pub(super) struct Loaded<'program, 'definition> {
    program: &'program [u8],
    pub(super) fields: HashMap<String, Value<'definition>>,
    decrypted: Rc<Decrypted<'definition>>,
}

impl<'definition> Machine<'definition> {
    /// Evaluates the VM's setup code and constructor.
    pub fn try_new(definition: &'definition Definition<'_>) -> Result<Self> {
        let definition: &'definition Definition<'definition> = definition;
        let session = Session::try_new(definition)?;
        let dispatch = &definition.dispatch;
        let native_dispatch =
            NativeDispatch::recognize(&session, &dispatch.decoder, &dispatch.arguments);
        Ok(Self {
            definition,
            session,
            native_dispatch,
        })
    }

    pub(super) fn load<'program>(&self, program: &'program [u8]) -> Loaded<'program, 'definition> {
        Loaded {
            program,
            fields: self.session.constructed(program),
            decrypted: Rc::default(),
        }
    }

    /// Where the program runner starts a program.
    #[must_use]
    pub fn entry(&self) -> Position {
        self.session.entry
    }

    pub fn instruction(&self, program: &[u8], pc: u32, key: u8) -> Result<Instruction, Failure> {
        self.decode(&self.load(program), pc, key, &[])
    }

    pub(super) fn decode(
        &self,
        loaded: &Loaded<'_, 'definition>,
        pc: u32,
        key: u8,
        known: &[(u8, Value<'definition>)],
    ) -> Result<Instruction, Failure> {
        let (opcode, ways) = self.ways(loaded, pc, key, known)?;
        // The listing retains these paths, so release unused vector capacity.
        let mut paths: Vec<_> = ways.into_iter().map(|way| way.path).collect();
        paths.shrink_to_fit();
        Ok(Instruction {
            pc,
            key,
            opcode,
            paths,
        })
    }

    /// Returns the opcode at `pc` and each feasible handler path with its resulting instance
    /// fields.
    pub(super) fn ways(
        &self,
        loaded: &Loaded<'_, 'definition>,
        pc: u32,
        key: u8,
        known: &[(u8, Value<'definition>)],
    ) -> Result<(u8, Vec<Way<'definition>>), Failure> {
        let fail = |cause| Failure { pc, key, cause };
        if pc as usize >= loaded.program.len() {
            return Err(fail(Cause::PastEnd));
        }
        let native = self
            .native_dispatch
            .as_ref()
            .and_then(|native| native.decode(&self.session, loaded.program, pc, key));
        let Decoded { opcode, key: next } = match native {
            Some(decoded) => decoded,
            None => self
                .definition
                .dispatch
                .decode(&self.session, loaded.program, pc, key)
                .map_err(|reason| fail(Cause::Undecoded { reason }))?,
        };
        let handler = self
            .session
            .handlers
            .get(&opcode)
            .copied()
            .ok_or_else(|| fail(Cause::NoHandler { opcode }))?;
        let invocation = Invocation {
            session: &self.session,
            program: loaded.program,
            fields: &loaded.fields,
            decrypted: &loaded.decrypted,
            pc: pc + 1,
            key: next,
            handler,
            known,
        };
        let ways = interpret::explore(&invocation).ok_or_else(|| {
            fail(Cause::TooManyPaths {
                opcode,
                limit: MAXIMUM_PATHS,
            })
        })?;
        // Paths where the handler throws reject these operands. If every path throws, the bytes
        // do not form an instruction.
        if ways.taken.is_empty() {
            return Err(fail(Cause::Faults {
                opcode,
                reasons: ways.faults,
            }));
        }
        Ok((opcode, ways.taken))
    }
}
