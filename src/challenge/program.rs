//! Extracts a session's encoding constants and payload template without relying on randomized
//! names. The encoding algorithms are implemented in `crate::challenge::codec`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use num_bigint::BigUint;
use serde::Serialize;
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignTarget, BindingIdent, BlockStmt, CallExpr, Callee, ClassDecl,
    Expr, FnDecl, Function, IfStmt, ObjectLit, Script, SimpleAssignTarget, Stmt, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};
use url::Url;

use crate::challenge::codec::{Codec, KEY_LENGTH, SEED_LENGTH};
use crate::challenge::expression;
use crate::challenge::installed::{self, Installed};
use crate::challenge::merge::Mapping;
use crate::challenge::payload::Field;
use crate::challenge::source::{self, InitialRequest};
use crate::challenge::state::ScriptState;
use crate::js::ast::{self, ParsedScript};
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
        Ok(self.session_encoder_with_seed(seed))
    }

    #[must_use]
    pub fn session_encoder_with_seed(&self, seed: [u8; SEED_LENGTH]) -> SessionEncoder {
        SessionEncoder {
            codec: self.codec.clone(),
            seed,
        }
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
    parsed: &'source ParsedScript,
    program: ExtractedProgram,
}

impl<'source> PreparedSession<'source> {
    /// Extracts the program from `source` fetched at `iframe_url`. Missing or ambiguous
    /// components are errors.
    pub fn try_new(source: &'source Source, iframe_url: &Url) -> Result<Self> {
        use base64::Engine;

        let parsed = source.parsed();
        let request = InitialRequest::from_parsed(parsed, iframe_url)?;
        let runner =
            vm::runner_name(&parsed.script).context("the script installs no program runner")?;
        let mut components = Components {
            parsed,
            options: &request.options,
            runner,
            encoders: BTreeSet::new(),
            programs: BTreeMap::new(),
            templates: Vec::new(),
        };
        parsed.script.visit_with(&mut components);
        let encoder = candidates::exactly_one(components.encoders, "XHR body encoder")?;
        let (initial_program, initialize_key) =
            candidates::exactly_one(components.programs, "literal initial VM program")?;
        let payload_fields =
            candidates::exactly_one(components.templates, "first payload template")?;

        // The encoder assignment may be a standalone statement or part of a sequence or chain.
        // Search within IIFE statements without entering their nested functions.
        let mut root = EncoderRoot {
            parsed,
            encoder: &encoder,
            found: None,
        };
        parsed.script.visit_with(&mut root);
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
            encoder,
            key_transform: root.key_transform,
            initialize_key,
            installed,
            bootstrap: root.bootstrap,
            codec: Codec::try_new(&root.alphabet, root.modulus, secret)?,
            payload_fields,
        };
        Ok(Self { parsed, program })
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
        Mapping::from_parsed(self.parsed)
    }

    pub fn state(&self) -> Result<ScriptState> {
        ScriptState::from_parsed(self.parsed, &self.program.request.options)
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
    fn read(root: &BlockStmt, definition: &Expr, parsed: &ParsedScript) -> Result<Self> {
        Ok(Self {
            key_transform: key_transform(&parsed.script, definition)?,
            alphabet: base64_alphabet(ast::string_literals(root))?,
            modulus: rsa_modulus(root)?,
            bootstrap: bootstrap(root, parsed),
        })
    }
}

/// Finds the outermost immediately invoked function that defines the encoder. Calls `read`
/// while the borrowed syntax node is valid.
struct EncoderRoot<'session> {
    parsed: &'session ParsedScript,
    encoder: &'session str,
    found: Option<Result<Root>>,
}

impl Visit for EncoderRoot<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if self.found.is_some() {
            return;
        }
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Fn(function) = callee.unwrap_parens()
            && let Some(body) = &function.function.body
            && let Some(definition) = body
                .stmts
                .iter()
                .find_map(|statement| defines(statement, self.encoder))
        {
            self.found = Some(Root::read(body, &definition, self.parsed));
            return;
        }
        call.visit_children_with(self);
    }
}

/// Finds the encoder callee created by the VM at runtime. It is the only callee without a binding
/// in the script; any remaining deobfuscation helpers have bindings.
fn key_transform(script: &Script, definition: &Expr) -> Result<String> {
    let mut calls = Calls::default();
    definition.visit_with(&mut calls);
    let mut bound = Bound::default();
    script.visit_with(&mut bound);
    let unbound = calls
        .0
        .into_iter()
        .filter(|name| name != "Number" && !bound.0.contains(name));
    candidates::exactly_one(unbound, "VM-defined key transform")
}

/// Names declared or assigned anywhere in the script.
#[derive(Default)]
struct Bound(BTreeSet<String>);

impl Visit for Bound {
    fn visit_binding_ident(&mut self, identifier: &BindingIdent) {
        self.0.insert(identifier.sym.to_string());
    }

    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        self.0.insert(declaration.ident.sym.to_string());
        declaration.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, declaration: &ClassDecl) {
        self.0.insert(declaration.ident.sym.to_string());
        declaration.visit_children_with(self);
    }
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
fn rsa_modulus(root: &BlockStmt) -> Result<BigUint> {
    let moduli = expression::assignments(root)
        .filter_map(|assignment| big_int(&assignment.right))
        .filter_map(|literal| BigUint::parse_bytes(literal.strip_prefix("0x")?.as_bytes(), 16))
        .filter(|modulus| modulus.bits().div_ceil(8) == SEED_LENGTH as u64);
    candidates::exactly_one(moduli, "RSA modulus")
}

/// The string `BigInt` is called with.
fn big_int(expression: &Expr) -> Option<&str> {
    let (name, arguments) = ast::direct_call(expression)?;
    ast::static_str(&arguments.first()?.expr).filter(|_| name.sym == "BigInt")
}

/// Returns source for the IIFE without browser activity. Keeps VM tables, declarations, key
/// generation, and the encoder. Removes startup calls, timers, UI code, and event collection.
fn bootstrap(root: &BlockStmt, parsed: &ParsedScript) -> String {
    let inert: Vec<&str> = root
        .stmts
        .iter()
        .filter(|statement| is_inert(statement))
        .map(|statement| parsed.text(statement))
        .collect();
    inert.join("\n")
}

/// Whether a top-level statement can run without starting browser work.
fn is_inert(statement: &Stmt) -> bool {
    match statement {
        // A conditional that only installs functions does not run their bodies.
        Stmt::If(conditional) => conditional.cons.as_block().is_some_and(|block| {
            block.stmts.iter().all(|statement| {
                expression::assignment(statement)
                    .is_some_and(|assigned| matches!(&*assigned.right, Expr::Fn(_)))
            })
        }),
        // A property assignment from a call publishes browser work that must be skipped.
        // Indexed writes such as `seed[0] = Number(two)` update encoder state and are allowed.
        Stmt::Expr(statement) => !matches!(&*statement.expr, Expr::Assign(assignment)
            if matches!(&assignment.left, AssignTarget::Simple(SimpleAssignTarget::Member(member))
                if !member.prop.is_computed())
                && matches!(&*assignment.right, Expr::Call(_))),
        _ => true,
    }
}

fn payload_fields(template: &ObjectLit, parsed: &ParsedScript, options: &Options) -> Vec<Field> {
    ast::key_values(template)
        .filter_map(|property| {
            Some(Field {
                name: ast::static_key_str(&property.key)?.to_owned(),
                // Reparsing the exported expression removes outer parentheses. Remove them here
                // too.
                expression: property.value.unwrap_parens().clone(),
                text: parsed.text(&*property.value).to_owned(),
                bootstrap_value: expression::static_value(&property.value, options),
            })
        })
        .collect()
}

/// Finds the function assigned to `name` within a statement.
fn defines(statement: &Stmt, name: &str) -> Option<Expr> {
    let mut definition = Definition { name, found: None };
    statement.visit_with(&mut definition);
    definition.found
}

struct Definition<'name> {
    name: &'name str,
    found: Option<Expr>,
}

impl Visit for Definition<'_> {
    // A declared function's own body belongs to it, not to the IIFE around it.
    fn visit_function(&mut self, _: &Function) {}
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(target)) = &assignment.left
            && target.id.sym == *self.name
            && let Some(function) = yielded_function(&assignment.right)
        {
            self.found = Some(function.clone());
        }
        assignment.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Some(target) = declarator.name.as_ident()
            && target.id.sym == *self.name
            && let Some(function) = declarator.init.as_deref().and_then(yielded_function)
        {
            self.found = Some(function.clone());
        }
        declarator.visit_children_with(self);
    }
}

/// Finds the function produced by `value`, including through sequence expressions. Some sessions
/// reset the seed just before returning the encoder function.
fn yielded_function(value: &Expr) -> Option<&Expr> {
    let mut value = value.unwrap_parens();
    while let Expr::Seq(sequence) = value {
        value = sequence.exprs.last()?.unwrap_parens();
    }
    matches!(value, Expr::Fn(_) | Expr::Arrow(_)).then_some(value)
}

/// The names called directly, as `name(...)`.
#[derive(Default)]
struct Calls(BTreeSet<String>);

impl Visit for Calls {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Ident(name) = &**callee
        {
            self.0.insert(name.sym.to_string());
        }
        call.visit_children_with(self);
    }
}

/// Collects components for [`PreparedSession::try_new`].
struct Components<'session> {
    parsed: &'session ParsedScript,
    options: &'session Options,
    /// The name the program runner is installed under.
    runner: String,
    /// Functions whose result is handed straight to `send`.
    encoders: BTreeSet<String>,
    /// Literal programs passed to the runner, each with the source of its first call.
    /// Orchestrators may repeat a program for different startup paths.
    programs: BTreeMap<String, String>,
    templates: Vec<Vec<Field>>,
}

impl Visit for Components<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if vm::calls_runner(call, &self.runner)
            && let Some(program) = call
                .args
                .first()
                .and_then(|argument| ast::static_str(&argument.expr))
        {
            let text = self.parsed.text(call).to_owned();
            self.programs.entry(program.to_owned()).or_insert(text);
        }
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Member(member) = callee.unwrap_parens()
            && ast::member_str(&member.prop) == Some("send")
            && let Some(argument) = call.args.first()
            && let Some((encoder, _)) = ast::direct_call(&argument.expr)
        {
            self.encoders.insert(encoder.sym.to_string());
        }
        call.visit_children_with(self);
    }

    fn visit_if_stmt(&mut self, conditional: &IfStmt) {
        let options = self.options;
        source::visit_taken_branches(self, conditional, options);
    }

    fn visit_object_lit(&mut self, object: &ObjectLit) {
        if source::is_payload_template(object, self.options) {
            self.templates
                .push(payload_fields(object, self.parsed, self.options));
        }
        object.visit_children_with(self);
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

    fn statement(source: &str) -> Stmt {
        ast::parse_javascript("t.js", source)
            .unwrap()
            .script
            .body
            .into_iter()
            .next()
            .unwrap()
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
            assert!(
                defines(&statement(source), "P3").is_some(),
                "missed the encoder in: {source}"
            );
        }
        assert!(
            defines(&statement("function f() { P3 = function() {}; }"), "P3").is_none(),
            "a declared function's own body is not the IIFE's, so an assignment inside one must \
             not claim the enclosing statement"
        );
        assert!(defines(&statement("P3 = 1;"), "P3").is_none());
        assert!(defines(&statement("P3 = (function() {}, 1);"), "P3").is_none());
    }
}
