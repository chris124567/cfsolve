//! Decodes opcodes by executing the decoding statements from the dispatch loop.
//!
//! Decoding varies by build. The current build mixes a hash of the program position into each
//! opcode, so a table indexed by dispatch key and byte is insufficient.
//!
//! The loop tries an inline fast path for common instructions, then falls back to decoding. Skip
//! the fast path and execute only the fallback statements. These advance the program counter,
//! produce the switch value as the opcode, and store the next dispatch key in its register.

use std::{ptr, slice};

use anyhow::{Context, Result, bail};
use oxc::ast::ast::{Expression, Function, Statement, VariableDeclaration};
use oxc::syntax::operator::BinaryOperator;

use super::extract::{Argument, DispatchLoop};
use super::interpret::{self, Routine};
use super::session::Session;
use super::value::Value;
use crate::js::ast::Script;

/// The opcode decoder extracted from the dispatch loop.
pub(crate) struct Dispatch<'a> {
    pub(super) decoder: Decoder<'a>,
    /// Values passed to each loop parameter.
    pub(super) arguments: Vec<Argument>,
}

/// The dispatch loop's decoding statements, run as
/// `function(<loop parameters>) { var <loop locals>; <decoding>; return <opcode>; }`.
pub(crate) struct Decoder<'a> {
    /// The dispatch loop, whose parameters the decoder takes.
    pub(crate) function: &'a Function<'a>,
    /// The loop's local declarations, run without their initializers.
    pub(crate) declarations: Vec<&'a VariableDeclaration<'a>>,
    pub(crate) decoding: &'a [Statement<'a>],
    /// The switch discriminant, a local holding the opcode.
    pub(crate) opcode: &'a Expression<'a>,
}

impl Decoder<'_> {
    /// The decoder as a routine the interpreter runs.
    pub(crate) fn routine(&self) -> Routine<'_> {
        Routine {
            parameters: &self.function.params,
            declarations: &self.declarations,
            statements: self.decoding,
            returns: Some(self.opcode),
            address: ptr::from_ref(self).addr(),
        }
    }
}

/// Decoded opcode and dispatch key for one program byte.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Decoded {
    pub(crate) opcode: u8,
    /// Key used to decode the instruction operands and the next opcode.
    pub(crate) key: u8,
}

impl<'a> Dispatch<'a> {
    pub(crate) fn from_loop(script: Script<'a>, dispatch: &DispatchLoop<'a>) -> Result<Self> {
        let function = dispatch.function;
        let body = function
            .body
            .as_deref()
            .context("the dispatch loop function has no body")?;
        let looping = body
            .statements
            .iter()
            .find_map(|statement| match statement {
                Statement::WhileStatement(looping) => Some(looping),
                _ => None,
            })
            .context("the dispatch loop function has no loop")?;
        let statements = block_statements(&looping.body);
        let (at, switch) = statements
            .iter()
            .enumerate()
            .find_map(|(at, statement)| match statement {
                Statement::SwitchStatement(switch) => Some((at, switch)),
                _ => None,
            })
            .context("the dispatch loop has no switch")?;
        let opcode = &switch.discriminant;
        let Expression::Identifier(opcode_name) = opcode else {
            bail!("the dispatch switch is not on a local");
        };
        let prefix = &statements[..at];
        // Match `<opcode> = <fast path>; if (<opcode> < 0) { <decoding> }`.
        let is_opcode = |expression: &Expression<'a>| {
            matches!(expression, Expression::Identifier(name)
                if script.binding(name) == script.binding(opcode_name))
        };
        let decoding = match prefix.last() {
            Some(Statement::IfStatement(branch))
                if branch.alternate.is_none() && is_negative(&branch.test, is_opcode) =>
            {
                block_statements(&branch.consequent)
            }
            _ => prefix,
        };
        // Keep the loop local declarations, without their initializers.
        let declarations = body
            .statements
            .iter()
            .chain(prefix)
            .filter_map(|statement| match statement {
                Statement::VariableDeclaration(declaration) if !declaration.kind.is_using() => {
                    Some(&**declaration)
                }
                _ => None,
            })
            .collect();
        Ok(Self {
            decoder: Decoder {
                function,
                declarations,
                decoding,
                opcode,
            },
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
        interpret::decode(session, program, self.decoder.routine(), arguments, pc, key)
    }
}

/// The statements of a block, or `statement` alone.
fn block_statements<'b, 'a>(statement: &'b Statement<'a>) -> &'b [Statement<'a>] {
    match statement {
        Statement::BlockStatement(block) => &block.body,
        statement => slice::from_ref(statement),
    }
}

/// Matches `<opcode> < 0` or `0 > <opcode>`.
fn is_negative<'a>(test: &Expression<'a>, is_opcode: impl Fn(&Expression<'a>) -> bool) -> bool {
    let Expression::BinaryExpression(test) = test.without_parentheses() else {
        return false;
    };
    match test.operator {
        BinaryOperator::LessThan => is_opcode(&test.left) && test.right.is_number_0(),
        BinaryOperator::GreaterThan => test.left.is_number_0() && is_opcode(&test.right),
        _ => false,
    }
}
