//! Decodes opcodes by executing the decoding statements from the dispatch loop.
//!
//! Decoding varies by build. The current build mixes a hash of the program position into each
//! opcode, so a table indexed by dispatch key and byte is insufficient.
//!
//! The loop tries an inline fast path for common instructions, then falls back to decoding. Skip
//! the fast path and execute only the fallback statements. These advance the program counter,
//! produce the switch value as the opcode, and store the next dispatch key in its register.

use anyhow::{Context, Result};
use swc_core::common::DUMMY_SP;
use swc_core::ecma::ast::{
    BinaryOp, BlockStmt, Decl, Expr, Function, Ident, Lit, ReturnStmt, Stmt,
};

use super::extract::{Argument, DispatchLoop};
use super::interpret;
use super::session::Session;
use super::value::Value;

/// Function extracted from the dispatch loop to decode opcodes.
pub(crate) struct Dispatch {
    /// `function(<loop parameters>) { var <loop locals>; <decoding>; return <opcode>; }`.
    decoder: Function,
    /// Values passed to each loop parameter.
    arguments: Vec<Argument>,
}

/// Decoded opcode and dispatch key for one program byte.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Decoded {
    pub(crate) opcode: u8,
    /// Key used to decode the instruction operands and the next opcode.
    pub(crate) key: u8,
}

impl Dispatch {
    pub(crate) fn from_loop(dispatch: &DispatchLoop<'_>) -> Result<Self> {
        let function = dispatch.function;
        let body = function
            .body
            .as_ref()
            .context("the dispatch loop function has no body")?;
        let looping = body
            .stmts
            .iter()
            .find_map(Stmt::as_while_stmt)
            .context("the dispatch loop function has no loop")?;
        let statements = match &*looping.body {
            Stmt::Block(block) => &block.stmts[..],
            statement => std::slice::from_ref(statement),
        };
        let (at, switch) = statements
            .iter()
            .enumerate()
            .find_map(|(at, statement)| Some((at, statement.as_switch()?)))
            .context("the dispatch loop has no switch")?;
        let opcode = switch
            .discriminant
            .as_ident()
            .context("the dispatch switch is not on a local")?
            .clone();
        let prefix = &statements[..at];
        // Match `<opcode> = <fast path>; if (<opcode> < 0) { <decoding> }`.
        let decoding = match prefix.last() {
            Some(Stmt::If(branch))
                if branch.alt.is_none() && is_negative(&branch.test, &opcode) =>
            {
                match &*branch.cons {
                    Stmt::Block(block) => block.stmts.clone(),
                    statement => vec![statement.clone()],
                }
            }
            _ => prefix.to_vec(),
        };
        // Preserve the loop local declarations without initializers.
        let declarations = body.stmts.iter().chain(prefix).filter_map(|statement| {
            let Stmt::Decl(Decl::Var(declaration)) = statement else {
                return None;
            };
            let mut declaration = declaration.clone();
            for declarator in &mut declaration.decls {
                declarator.init = None;
            }
            Some(Stmt::Decl(Decl::Var(declaration)))
        });
        let returned = Stmt::Return(ReturnStmt {
            span: DUMMY_SP,
            arg: Some(Box::new(Expr::Ident(opcode))),
        });
        let decoder = Function {
            body: Some(BlockStmt {
                span: body.span,
                ctxt: body.ctxt,
                stmts: declarations.chain(decoding).chain([returned]).collect(),
            }),
            ..function.clone()
        };
        Ok(Self {
            decoder,
            arguments: dispatch.arguments.clone(),
        })
    }

    /// Decodes the opcode at `pc` using `key`. Returns the reason if decoding stops.
    pub(crate) fn decode<'ast>(
        &'ast self,
        session: &Session<'ast>,
        program: &[u8],
        pc: u32,
        key: u8,
    ) -> Result<Decoded, String> {
        let arguments = self
            .arguments
            .iter()
            .map(|argument| match argument {
                Argument::Machine => Value::Machine,
                Argument::Registers => Value::Registers,
                Argument::Program => Value::Program,
                Argument::Other => Value::Undefined,
            })
            .collect();
        interpret::decode(session, program, &self.decoder, arguments, pc, key)
    }
}

/// Matches `<opcode> < 0` or `0 > <opcode>`.
fn is_negative(test: &Expr, opcode: &Ident) -> bool {
    let Some(test) = test.unwrap_parens().as_bin() else {
        return false;
    };
    let is_opcode = |expr: &Expr| expr.as_ident().is_some_and(|name| name.sym == opcode.sym);
    let is_zero = |expr: &Expr| matches!(expr, Expr::Lit(Lit::Num(number)) if number.value == 0.0);
    match test.op {
        BinaryOp::Lt => is_opcode(&test.left) && is_zero(&test.right),
        BinaryOp::Gt => is_zero(&test.left) && is_opcode(&test.right),
        _ => false,
    }
}
