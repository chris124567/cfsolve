//! Extracts a session's encoding constants and payload template without relying on randomized
//! names. The encoding algorithms are implemented in `crate::challenge::codec`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use num_bigint::BigUint;
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
    CallExpression, Expression, Function, FunctionBody, IfStatement, ObjectExpression, Statement,
    VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::ScopeFlags;
use serde::Serialize;
use url::Url;

use crate::challenge::codec::{Codec, KEY_LENGTH, SEED_LENGTH};
use crate::challenge::expression;
use crate::challenge::installed::{self, Installed};
use crate::challenge::merge::Mapping;
use crate::challenge::payload::Field;
use crate::challenge::source::{self, InitialRequest};
use crate::challenge::state::ScriptState;
use crate::js::ast::{self, Binding, Script};
use crate::js::{JsValue, Options, Payload};
use crate::script::Source;
use crate::{candidates, vm};

/// The session's base64 alphabet: 64 distinct characters, optionally followed by the padding
/// character.
const ALPHABET_LENGTH: RangeInclusive<usize> = 64..=65;

/// One session's encoding parameters and payload template. The string fields keep the original
/// JavaScript for `encoder.json`; encoding uses validated encoding parameters.
#[derive(Clone)]
pub struct ExtractedProgram {
    pub request: InitialRequest,
    /// Iframe URL used to resolve the POST URL.
    pub iframe_url: Url,
    /// The function whose result is handed to `send`.
    pub encoder: String,
    /// The one function the encoder calls that the VM defines at runtime.
    pub key_transform: String,
    /// The runner call that initialises the VM key material with a literal program.
    pub initialize_key: String,
    pub installed: Installed,
    /// The encoder's IIFE with its browser-facing statements removed.
    pub bootstrap: String,
    pub(crate) codec: Codec,
    /// The payload template's fields, in the order the session writes them.
    pub payload_fields: Vec<Field>,
}

impl ExtractedProgram {
    /// Creates a session encoder with a fresh random seed.
    pub fn session_encoder(&self) -> Result<SessionEncoder> {
        let mut seed = [0; SEED_LENGTH];
        getrandom::fill(&mut seed).context("drawing the session key seed")?;
        Ok(SessionEncoder {
            codec: self.codec.clone(),
            seed,
        })
    }

    #[must_use]
    pub fn encoder_json(&self) -> EncoderJson<'_> {
        let payload_fields = self.payload_fields.iter().map(|field| ExportedField {
            name: &field.name,
            expression: &field.text,
            bootstrap_value: field.bootstrap_value.as_ref(),
        });
        EncoderJson {
            url: self.request.url.as_str(),
            iframe_url: self.iframe_url.as_str(),
            cf_chl: &self.request.cf_chl,
            options: &self.request.options,
            encoder: &self.encoder,
            key_transform: &self.key_transform,
            key_secret: self.codec.secret.iter().copied().map(char::from).collect(),
            initialize_key: &self.initialize_key,
            bootstrap: &self.bootstrap,
            alphabet: &self.codec.alphabet_text,
            modulus: self.codec.modulus.to_str_radix(16),
            payload_fields: payload_fields.collect(),
        }
    }
}

/// `encoder.json`: the encoding constants under stable keys, with payload expressions as source
/// text.
#[derive(Serialize)]
pub struct EncoderJson<'program> {
    pub url: &'program str,
    pub iframe_url: &'program str,
    pub cf_chl: &'program str,
    pub options: &'program Options,
    pub encoder: &'program str,
    pub key_transform: &'program str,
    pub key_secret: String,
    pub initialize_key: &'program str,
    pub bootstrap: &'program str,
    pub alphabet: &'program str,
    pub modulus: String,
    pub payload_fields: Vec<ExportedField<'program>>,
}

/// A payload template field in `encoder.json`, with its expression as source text.
#[derive(Serialize)]
pub struct ExportedField<'program> {
    pub name: &'program str,
    pub expression: &'program str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_value: Option<&'program JsValue>,
}

/// An extracted program and its parsed source. Parameter merging and iframe state are recovered
/// from the source on demand.
pub struct PreparedSession<'source> {
    script: Script<'source>,
    program: ExtractedProgram,
}

impl<'source> PreparedSession<'source> {
    /// Extracts the program from `source` fetched at `iframe_url`. Missing or ambiguous
    /// components are errors.
    pub fn try_new(source: &'source Source, iframe_url: &Url) -> Result<Self> {
        use base64::Engine;

        let script = source.script();
        let request = InitialRequest::from_script(script, iframe_url)?;
        let runner = vm::runner_name(script).context("the script installs no program runner")?;
        let mut components = Components {
            script,
            options: &request.options,
            runner,
            encoders: BTreeSet::new(),
            programs: BTreeMap::new(),
            templates: Vec::new(),
        };
        components.visit_program(script.program);
        let encoder = candidates::exactly_one(components.encoders, "XHR body encoder")?;
        let (initial_program, initialize_key) =
            candidates::exactly_one(components.programs, "literal initial VM program")?;
        let payload_fields =
            candidates::exactly_one(components.templates, "first payload template")??;

        // The encoder assignment may be a standalone statement or part of a sequence or chain.
        // Search within IIFE statements without entering their nested functions.
        let mut root = EncoderRoot {
            script,
            encoder,
            found: None,
        };
        root.visit_program(script.program);
        let root = root
            .found
            .context("could not locate encoder's enclosing IIFE")??;

        let initial_program = STANDARD
            .decode(initial_program.trim())
            .context("decoding the initial VM program")?;
        // The program installs the key transform as `window[name] = factory(secret)`.
        let installed = installed::read(source, &initial_program)?;
        let secret = installed.built.get(&root.key_transform).with_context(|| {
            format!(
                "the initial VM program does not build the key transform {}",
                root.key_transform
            )
        })?;
        // The transform reads the secret with `charCodeAt`, one byte each.
        let bytes: Option<Vec<u8>> = secret
            .chars()
            .map(|character| u8::try_from(character).ok())
            .collect();
        let secret: [u8; KEY_LENGTH] = bytes
            .and_then(|bytes| bytes.try_into().ok())
            .with_context(|| format!("the key transform's secret is not {KEY_LENGTH} bytes"))?;
        let program = ExtractedProgram {
            request,
            iframe_url: iframe_url.clone(),
            encoder: script.name(encoder).to_owned(),
            key_transform: root.key_transform,
            initialize_key,
            installed,
            bootstrap: root.bootstrap,
            codec: Codec::try_new(&root.alphabet, root.modulus, secret)?,
            payload_fields,
        };
        Ok(Self { script, program })
    }

    #[must_use]
    pub fn program(&self) -> &ExtractedProgram {
        &self.program
    }

    #[must_use]
    pub fn into_program(self) -> ExtractedProgram {
        self.program
    }

    /// How this session merges the embedding page's `extraParams`.
    pub fn mapping(&self) -> Result<Mapping> {
        Mapping::from_script(self.script)
    }

    pub fn state(&self) -> Result<ScriptState> {
        ScriptState::from_script(self.script, &self.program.request.options)
    }
}

/// State contributed by the encoder's enclosing IIFE.
struct Root {
    key_transform: String,
    alphabet: String,
    modulus: BigUint,
    bootstrap: String,
}

impl Root {
    fn read<'a>(
        script: Script<'a>,
        root: &FunctionBody<'a>,
        definition: &Expression<'a>,
    ) -> Result<Self> {
        Ok(Self {
            key_transform: key_transform(script, definition)?,
            alphabet: base64_alphabet(ast::string_literals(|literals| {
                literals.visit_function_body(root);
            }))?,
            modulus: rsa_modulus(script, root)?,
            bootstrap: bootstrap(script, root),
        })
    }
}

/// Finds the outermost immediately invoked function that defines the encoder. Calls `read`
/// while the borrowed syntax node is valid.
struct EncoderRoot<'a> {
    script: Script<'a>,
    encoder: Binding<'a>,
    found: Option<Result<Root>>,
}

impl<'a> Visit<'a> for EncoderRoot<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found.is_some() {
            return;
        }
        if let Expression::FunctionExpression(function) = call.callee.without_parentheses()
            && let Some(body) = &function.body
            && let Some(definition) = body
                .statements
                .iter()
                .find_map(|statement| defines(self.script, statement, self.encoder))
        {
            self.found = Some(Root::read(self.script, body, definition));
            return;
        }
        walk::walk_call_expression(self, call);
    }
}

/// Finds the encoder callee created by the VM at runtime. It is the only callee in `definition`
/// that no binding of the script declares and that the script never assigns as a global; any
/// remaining deobfuscation helpers have bindings.
fn key_transform(script: Script<'_>, definition: &Expression<'_>) -> Result<String> {
    let mut calls = Calls {
        script,
        globals: BTreeSet::new(),
    };
    calls.visit_expression(definition);
    let unresolved = script.scoping.root_unresolved_references();
    let assigned = |name: &str| {
        unresolved.get(name).is_some_and(|references| {
            references
                .iter()
                .any(|&reference| script.scoping.get_reference(reference).is_write())
        })
    };
    let unbound = calls
        .globals
        .into_iter()
        .filter(|name| *name != "Number" && !assigned(name))
        .map(str::to_owned);
    candidates::exactly_one(unbound, "VM-defined key transform")
}

/// Finds the custom base64 alphabet in `candidates`: a string with 64 distinct ASCII characters and
/// optional trailing padding.
pub(crate) fn base64_alphabet(candidates: impl IntoIterator<Item = String>) -> Result<String> {
    let alphabets = candidates.into_iter().filter(|candidate| {
        if !candidate.is_ascii() || !ALPHABET_LENGTH.contains(&candidate.len()) {
            return false;
        }
        let distinct: BTreeSet<&u8> = candidate.as_bytes()[..64].iter().collect();
        distinct.len() == 64
    });
    let mut alphabet = candidates::exactly_one(alphabets, "custom base64 alphabet")?;
    alphabet.truncate(64);
    Ok(alphabet)
}

/// Finds the `BigInt("0x...")` modulus wide enough to encrypt the seed.
fn rsa_modulus(script: Script<'_>, root: &FunctionBody<'_>) -> Result<BigUint> {
    let moduli = expression::assignments(root)
        .filter_map(|assignment| big_int(script, &assignment.right))
        .filter_map(|literal| BigUint::parse_bytes(literal.strip_prefix("0x")?.as_bytes(), 16))
        .filter(|modulus| modulus.bits().div_ceil(8) == SEED_LENGTH as u64);
    candidates::exactly_one(moduli, "RSA modulus")
}

/// The string the global `BigInt` is called with.
fn big_int<'a>(script: Script<'_>, expression: &Expression<'a>) -> Option<&'a str> {
    let (name, arguments) = ast::direct_call(expression)?;
    let global = name.name == "BigInt" && script.symbol(name).is_none();
    ast::static_str(arguments.first()?.as_expression()?).filter(|_| global)
}

/// Returns source for the IIFE without browser activity. Keeps VM tables, declarations, key
/// generation, and the encoder. Removes startup calls, timers, UI code, and event collection.
fn bootstrap(script: Script<'_>, root: &FunctionBody<'_>) -> String {
    let inert: Vec<&str> = root
        .statements
        .iter()
        .filter(|statement| is_inert(statement))
        .map(|statement| script.text(statement))
        .collect();
    inert.join("\n")
}

/// Whether a top-level statement can run without starting browser work.
fn is_inert(statement: &Statement<'_>) -> bool {
    match statement {
        // A conditional that only installs functions does not run their bodies.
        Statement::IfStatement(conditional) => match &conditional.consequent {
            Statement::BlockStatement(block) => block.body.iter().all(|statement| {
                expression::assignment(statement).is_some_and(|assigned| {
                    matches!(assigned.right, Expression::FunctionExpression(_))
                })
            }),
            _ => false,
        },
        // A property assignment from a call publishes browser work that must be skipped.
        // Indexed writes such as `seed[0] = Number(two)` update encoder state and are allowed.
        Statement::ExpressionStatement(statement) => {
            !matches!(&statement.expression, Expression::AssignmentExpression(assignment)
                if matches!(
                    assignment.left,
                    AssignmentTarget::StaticMemberExpression(_)
                        | AssignmentTarget::PrivateFieldExpression(_)
                ) && matches!(assignment.right, Expression::CallExpression(_)))
        }
        _ => true,
    }
}

/// Reads the fields of a payload `template`, parsing each from its source in `script`.
fn payload_fields(
    script: Script<'_>,
    template: &ObjectExpression<'_>,
    options: &Options,
) -> Result<Vec<Field>> {
    let fields = ast::key_values(template).filter_map(|property| {
        Some(Field::parse(
            ast::static_key_str(&property.key, property.computed)?.to_owned(),
            script.text(&property.value).to_owned(),
            expression::static_value(script, &property.value, options),
        ))
    });
    fields.collect()
}

/// Finds the function assigned to `encoder` within a statement.
fn defines<'a>(
    script: Script<'a>,
    statement: &Statement<'a>,
    encoder: Binding<'a>,
) -> Option<&'a Expression<'a>> {
    let mut definition = Definition {
        script,
        encoder,
        found: None,
    };
    definition.visit_statement(statement);
    definition.found
}

struct Definition<'a> {
    script: Script<'a>,
    encoder: Binding<'a>,
    found: Option<&'a Expression<'a>>,
}

impl<'a> Visit<'a> for Definition<'a> {
    // A declared function's own body belongs to it, not to the IIFE around it.
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left
            && self.script.binding(target) == self.encoder
            && let Some(function) = yielded_function(
                &self
                    .script
                    .lend(assignment, AstKind::as_assignment_expression)
                    .right,
            )
        {
            self.found = Some(function);
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(target) = &declarator.id
            && Binding::Symbol(target.symbol_id()) == self.encoder
            && let Some(init) = &self
                .script
                .lend(declarator, AstKind::as_variable_declarator)
                .init
            && let Some(function) = yielded_function(init)
        {
            self.found = Some(function);
        }
        walk::walk_variable_declarator(self, declarator);
    }
}

/// Finds the function produced by `value`, including through sequence expressions. Some sessions
/// reset the seed just before returning the encoder function.
fn yielded_function<'b, 'a>(value: &'b Expression<'a>) -> Option<&'b Expression<'a>> {
    let mut value = value.without_parentheses();
    while let Expression::SequenceExpression(sequence) = value {
        value = sequence.expressions.last()?.without_parentheses();
    }
    matches!(
        value,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
    )
    .then_some(value)
}

/// The globals called directly, as `name(...)`.
struct Calls<'a> {
    script: Script<'a>,
    globals: BTreeSet<&'a str>,
}

impl<'a> Visit<'a> for Calls<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::Identifier(name) = &call.callee
            && self.script.symbol(name).is_none()
        {
            self.globals.insert(name.name.as_str());
        }
        walk::walk_call_expression(self, call);
    }
}

/// Collects components for [`PreparedSession::try_new`].
struct Components<'session, 'a> {
    script: Script<'a>,
    options: &'session Options,
    /// The name the program runner is installed under.
    runner: String,
    /// Functions whose result is handed straight to `send`.
    encoders: BTreeSet<Binding<'a>>,
    /// Literal programs passed to the runner, each with the source of its first call.
    /// Orchestrators may repeat a program for different startup paths.
    programs: BTreeMap<String, String>,
    templates: Vec<Result<Vec<Field>>>,
}

impl<'a> Visit<'a> for Components<'_, 'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if vm::calls_runner(call, &self.runner)
            && let Some(program) = call
                .arguments
                .first()
                .and_then(|argument| ast::static_str(argument.as_expression()?))
        {
            let text = self.script.text(call).to_owned();
            self.programs.entry(program.to_owned()).or_insert(text);
        }
        if let Some(member) = call.callee.without_parentheses().as_member_expression()
            && ast::member_str(member) == Some("send")
            && let Some(argument) = call.arguments.first().and_then(Argument::as_expression)
            && let Some((encoder, _)) = ast::direct_call(argument)
        {
            self.encoders.insert(self.script.binding(encoder));
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_if_statement(&mut self, conditional: &IfStatement<'a>) {
        let options = self.options;
        source::visit_taken_branches(self, conditional, options);
    }

    fn visit_object_expression(&mut self, object: &ObjectExpression<'a>) {
        if source::is_payload_template(object, self.options) {
            self.templates
                .push(payload_fields(self.script, object, self.options));
        }
        walk::walk_object_expression(self, object);
    }
}

/// Encoder state shared by all session POSTs. The browser generates one seed; each payload's
/// padding length selects a symmetric key from that seed.
pub struct SessionEncoder {
    codec: Codec,
    seed: [u8; SEED_LENGTH],
}

impl SessionEncoder {
    #[must_use]
    pub fn encode(&self, payload: &Payload) -> String {
        self.codec.encode(payload, self.seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::ast::ParsedScript;

    /// Whether the first statement of `source` defines the global `P3`.
    fn defines_p3(source: &str) -> bool {
        let parsed = ParsedScript::parse("t.js", source).unwrap();
        let script = parsed.script();
        defines(script, &script.program.body[0], Binding::Global("P3")).is_some()
    }

    #[test]
    fn finds_the_encoder_however_its_assignment_is_spelled() {
        for source in [
            "P3 = function(Z) { return Z; };",
            // A live session combined these expressions into a sequence.
            "Zv = (Ge[0] = 0, P3 = function(Z) { return Z; });",
            "Zv = P3 = function(Z) { return Z; };",
            "P3 = (Ge[0] = 0, function(Z) { return Z; });",
            "P3 = (Ge[0] = 0, (Ge[1] = 1, (Z => Z)));",
        ] {
            assert!(defines_p3(source), "missed the encoder in: {source}");
        }
        assert!(
            !defines_p3("function f() { P3 = function() {}; }"),
            "a declared function's own body is not the IIFE's, so an assignment inside one must \
             not claim the enclosing statement"
        );
        assert!(!defines_p3("P3 = 1;"));
        assert!(!defines_p3("P3 = (function() {}, 1);"));
    }
}
