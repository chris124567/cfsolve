//! A session's VM, found in its script and ready to decode instructions.

use std::cell::Cell;
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::Result;
use swc_core::ecma::ast::{BlockStmt, Class, Script, Stmt};

use super::HashMap;
use super::dispatch::Dispatch;
use super::extract::{self, Finder};
use super::interpret::{self, Decrypted, Invocation, MAXIMUM_PATHS, Way};
use super::output::{Cause, Failure, Instruction, Position};
use super::session::Session;
use super::value::Value;

thread_local! {
    static DISPATCH_NS: Cell<u128> = const { Cell::new(0) };
    static EXPLORE_NS: Cell<u128> = const { Cell::new(0) };
    static WAYS_COUNT: Cell<u64> = const { Cell::new(0) };
}

/// Count and time spent decoding dispatch opcodes versus exploring handler paths.
pub(crate) fn take_ways_profile() -> (u64, u128, u128) {
    (
        WAYS_COUNT.with(|cell| cell.replace(0)),
        DISPATCH_NS.with(|cell| cell.replace(0)),
        EXPLORE_NS.with(|cell| cell.replace(0)),
    )
}

fn profile_steps() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CFSOLVE_STEP_LOG").is_some())
}

/// The VM class, enclosing function body, opcode decoder, and statements executed before
/// its scope is entered.
pub struct Definition {
    body: BlockStmt,
    class: Class,
    prelude: Vec<Stmt>,
    dispatch: Dispatch,
}

impl Definition {
    /// Finds the VM in `script`. Fails unless a class has a `run` method whose dispatch loop has
    /// the expected shape.
    pub fn from_script(script: &Script) -> Result<Self> {
        use anyhow::Context;
        use swc_core::ecma::visit::VisitWith;

        let mut finder = Finder::default();
        script.visit_with(&mut finder);
        let (body, class) = finder.found.context("no VM class in the script")?;
        let run = extract::method(&class, "run").context("the VM class has no run method")?;
        let functions = extract::functions(&body.stmts);
        let dispatch = Dispatch::from_loop(&extract::run_method(&functions, run)?.dispatch)?;
        Ok(Self {
            prelude: extract::prelude(script, &body),
            body,
            class,
            dispatch,
        })
    }
}

/// One session's VM, ready to decode instructions.
pub struct Machine<'definition> {
    pub(super) definition: &'definition Definition,
    pub(super) session: Session<'definition>,
}

/// A program, with the instance fields the constructor derives from it and the strings
/// decrypted from it so far.
#[derive(Clone)]
pub(super) struct Loaded<'program, 'definition> {
    program: &'program [u8],
    pub(super) fields: HashMap<String, Value<'definition>>,
    decrypted: Decrypted<'definition>,
}

impl<'definition> Machine<'definition> {
    /// Evaluates the VM's setup code and constructor.
    pub fn try_new(definition: &'definition Definition) -> Result<Self> {
        let session = Session::try_new(&definition.body, &definition.class, &definition.prelude)?;
        Ok(Self {
            definition,
            session,
        })
    }

    pub(super) fn load<'program>(&self, program: &'program [u8]) -> Loaded<'program, 'definition> {
        Loaded {
            program,
            fields: self.session.constructed(program),
            decrypted: Decrypted::default(),
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

    /// Decodes the instruction at `pc` with register `register` holding `text`. Checks hashed
    /// names absent from the program's literal pool, such as HTTP headers and browser
    /// properties.
    pub fn instruction_with_string(
        &self,
        program: &[u8],
        pc: u32,
        key: u8,
        register: u8,
        text: &str,
    ) -> Result<Instruction, Failure> {
        let known = [(register, Value::string(text))];
        self.decode(&self.load(program), pc, key, &known)
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
        let measure = profile_steps();
        let started = Instant::now();
        let decoded = self
            .definition
            .dispatch
            .decode(&self.session, loaded.program, pc, key)
            .map_err(|reason| fail(Cause::Undecoded { reason }))?;
        if measure {
            DISPATCH_NS.with(|cell| cell.set(cell.get() + started.elapsed().as_nanos()));
        }
        let handler = self
            .session
            .handlers
            .get(&decoded.opcode)
            .copied()
            .ok_or_else(|| fail(Cause::NoHandler { opcode: decoded.opcode }))?;
        let invocation = Invocation {
            session: &self.session,
            program: loaded.program,
            fields: &loaded.fields,
            decrypted: &loaded.decrypted,
            pc: pc + 1,
            key: decoded.key,
            handler,
            known,
        };
        let started = Instant::now();
        let ways = interpret::explore(&invocation).ok_or_else(|| {
            fail(Cause::TooManyPaths {
                opcode: decoded.opcode,
                limit: MAXIMUM_PATHS,
            })
        })?;
        if measure {
            EXPLORE_NS.with(|cell| cell.set(cell.get() + started.elapsed().as_nanos()));
            WAYS_COUNT.with(|cell| cell.set(cell.get() + 1));
        }
        let (opcode, ways) = (decoded.opcode, ways);
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
