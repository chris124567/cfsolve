//! Decodes the obfuscator's string table:
//!
//! ```js
//! decoder(23);  // becomes "message"
//! ```
//!
//! Recognizes the [`Table`] and solves its checksum rotation ([`Rotations`]) without executing
//! JavaScript, then replaces constant-index calls through decoders, aliases, and wrappers.
//! Removes decoding code only when no references remain. Unsupported setups stay unchanged.

use std::iter;

use swc_core::atoms::Wtf8Atom;
use swc_core::atoms::wtf8::{CodePoint, Wtf8Buf};
use swc_core::common::Span;
use swc_core::ecma::ast::{
    BinaryOp, CallExpr, Callee, Decl, Expr, ExprOrSpread, FnDecl, Function, Id, Lit, MemberProp,
    Null, Program, Stmt, Str, VarDeclOrExpr, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Bindings, names};
use super::{HashMap, HashSet, removal};
use crate::js::{self, ast};

/// Decodes supported string tables one at a time.
pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut bindings = analysis.bindings(program);
    let mut updated = None;
    let mut tried = HashSet::default();
    let mut changed = false;
    while let Some(plan) = Plan::next(program, bindings, &mut tried) {
        if plan.apply(program) {
            changed = true;
            // Analyze subsequent tables against the updated program.
            bindings = updated.insert(Bindings::collect(program));
        }
    }
    changed
}

/// Information collected before modifying a string table, sufficient to decode it.
struct Plan {
    /// The table, already rotated the way the setup leaves it.
    table: Table,
    /// The decoder and every binding that only ever holds it.
    aliases: HashSet<Id>,
    /// Wrapper functions indexed by every binding that names them.
    wrappers: HashMap<Id, Wrapper>,
    /// The call that rotates the table at runtime.
    setup: Span,
}

impl Plan {
    /// Finds the first untried decodable table in source order. Requires one setup with a
    /// solvable rotation.
    fn next(program: &Program, bindings: &Bindings, tried: &mut HashSet<Id>) -> Option<Self> {
        let mut functions = Functions::default();
        program.visit_with(&mut functions);
        let mut candidates: Vec<&FnDecl> = functions.0.values().collect();
        candidates.sort_by_key(|function| function.function.span.lo);
        for function in candidates {
            let Some(mut table) = Table::discover(function, &functions.0, bindings) else {
                continue;
            };
            // The decoder's declaration must be its only write.
            if !bindings.is_written_once(&table.decoder) || !tried.insert(table.decoder.clone()) {
                continue;
            }
            let aliases = bindings.aliases(&table.decoder);
            let mut rotations = Rotations {
                table: &table,
                aliases: &aliases,
                bindings,
                matches: vec![],
            };
            program.visit_with(&mut rotations);
            let [setup] = rotations.matches[..] else {
                continue;
            };
            table.strings.rotate_left(setup.rotation);
            let wrappers = Wrapper::discover(&functions.0, &aliases, bindings);
            return Some(Self {
                table,
                aliases,
                wrappers,
                setup: setup.call,
            });
        }
        None
    }

    /// Decodes every constant call, then removes the table machinery if nothing refers to it.
    fn apply(&self, program: &mut Program) -> bool {
        let mut decoder = DecodeStrings {
            plan: self,
            changed: false,
        };
        program.visit_mut_with(&mut decoder);

        // Try cleanup before deciding whether dynamic calls or escaped aliases still require
        // the runtime decoder.
        let mut cleaned = program.clone();
        cleaned.visit_mut_with(&mut Cleanup(self));
        let remaining = Bindings::collect(&cleaned);
        if iter::once(&self.table.provider)
            .chain(&self.aliases)
            .any(|id| remaining.references(id) > 0)
        {
            return decoder.changed;
        }
        *program = cleaned;
        true
    }

    /// Returns the constant decoder index for `callee(args)`, if known.
    fn index(&self, callee: &Id, args: &[ExprOrSpread]) -> Option<f64> {
        if args.iter().any(|argument| argument.spread.is_some()) {
            return None;
        }
        if self.aliases.contains(callee) {
            match args {
                [argument] => ast::number(&argument.expr),
                _ => None,
            }
        } else {
            self.wrappers.get(callee)?.index(args)
        }
    }

    /// Whether `function` declares the decoder or the provider.
    fn is_machinery(&self, function: &FnDecl) -> bool {
        let id = function.ident.to_id();
        id == self.table.decoder || id == self.table.provider
    }

    fn is_setup_call(&self, expression: &Expr) -> bool {
        matches!(expression, Expr::Call(call) if call.span == self.setup)
    }
}

/// `alias = other`, copying one decoder alias into another.
fn is_alias_copy(expression: &Expr, aliases: &HashSet<Id>) -> bool {
    ast::assignment(expression).is_some_and(|(id, value)| {
        aliases.contains(&id)
            && value
                .as_ident()
                .is_some_and(|id| aliases.contains(&id.to_id()))
    })
}

/// Collects single-return function declarations by binding. Decoders, providers, and wrappers
/// share this form; avoid cloning larger functions.
#[derive(Default)]
struct Functions(HashMap<Id, FnDecl>);

impl Visit for Functions {
    fn visit_fn_decl(&mut self, function: &FnDecl) {
        if ast::returned(&function.function).is_some() {
            self.0.insert(function.ident.to_id(), function.clone());
        }
        function.visit_children_with(self);
    }
}

/// Recognizes wrappers such as `function w(i, o, d) { return d = decoder, d(i + o) }`. Extra
/// decoder arguments must be literals that the decoder overwrites before reading them.
#[derive(Clone)]
struct Wrapper {
    params: Vec<Id>,
    index: Expr,
}

impl Wrapper {
    /// Every binding that names a wrapper, mapped to that wrapper.
    #[must_use]
    fn discover(
        functions: &HashMap<Id, FnDecl>,
        decoders: &HashSet<Id>,
        bindings: &Bindings,
    ) -> HashMap<Id, Self> {
        let mut wrappers = HashMap::default();
        for (id, function) in functions {
            if bindings.is_written_once(id)
                && let Some(wrapper) = Self::recognize(&function.function, decoders)
            {
                for alias in bindings.aliases(id) {
                    wrappers.insert(alias, wrapper.clone());
                }
            }
        }
        wrappers
    }

    fn recognize(function: &Function, decoders: &HashSet<Id>) -> Option<Self> {
        let params = names::parameter_ids(&function.params)?;
        // Either `return decoder(...)` or `return local = decoder, local(...)`.
        let is_decoder = |expression: &Expr| {
            expression
                .as_ident()
                .is_some_and(|id| decoders.contains(&id.to_id()))
        };
        if let Some((local, call)) = match ast::returned(function)? {
            Expr::Seq(sequence)
                if let [binding, call] = sequence.exprs.as_slice()
                    && let Some((local, decoder)) = ast::assignment(binding)
                    && params.contains(&local)
                    && is_decoder(decoder) =>
            {
                Some((Some(local), &**call))
            }
            Expr::Seq(_) => None,
            call => Some((None, call)),
        } && let Some((callee, [index, extra @ ..])) = ast::direct_call(call)
            && (local.as_ref() == Some(&callee.to_id()) || decoders.contains(&callee.to_id()))
            && index.spread.is_none()
            && extra
                .iter()
                .all(|argument| argument.spread.is_none() && matches!(*argument.expr, Expr::Lit(_)))
        {
            Some(Self {
                params,
                index: (*index.expr).clone(),
            })
        } else {
            None
        }
    }

    /// Resolves the decoder index selected by these literal arguments.
    #[must_use]
    fn index(&self, args: &[ExprOrSpread]) -> Option<f64> {
        let values: HashMap<Id, f64> = self
            .params
            .iter()
            .zip(args)
            .map(|(param, argument)| Some((param.clone(), ast::number(&argument.expr)?)))
            .collect::<Option<_>>()?;
        ast::fold_number(&self.index, &|leaf| {
            values.get(&leaf.as_ident()?.to_id()).copied()
        })
    }
}

/// Replaces constant-index calls to decoder aliases or wrappers with decoded strings. Leaves
/// the decoder, provider, and setup for [`Cleanup`].
struct DecodeStrings<'plan> {
    plan: &'plan Plan,
    changed: bool,
}

impl VisitMut for DecodeStrings<'_> {
    fn visit_mut_fn_decl(&mut self, function: &mut FnDecl) {
        if !self.plan.is_machinery(function) {
            function.visit_mut_children_with(self);
        }
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        if self.plan.is_setup_call(expression) {
            return;
        }
        expression.visit_mut_children_with(self);
        if let Some((callee, args)) = ast::direct_call(expression)
            && let Some(index) = self.plan.index(&callee.to_id(), args)
            && let Some(value) = self.plan.table.lookup(index, 0)
        {
            *expression = Expr::Lit(Lit::Str(Str {
                span: callee.span,
                value,
                raw: None,
            }));
            self.changed = true;
        }
    }
}

/// Removes the decoder, the provider, the setup call, and copies between decoder aliases.
struct Cleanup<'plan>(&'plan Plan);

impl Cleanup<'_> {
    fn is_setup(&self, expression: &Expr) -> bool {
        self.0.is_setup_call(expression) || is_alias_copy(expression, &self.0.aliases)
    }
}

impl VisitMut for Cleanup<'_> {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        removal::retain(
            statements,
            |statement| !matches!(statement, Stmt::Decl(Decl::Fn(function)) if self.0.is_machinery(function)),
        );
        removal::remove_expr_stmts(statements, |expression| self.is_setup(expression));
        statements.visit_mut_children_with(self);
    }

    fn visit_mut_var_declarator(&mut self, declaration: &mut VarDeclarator) {
        let aliases = &self.0.aliases;
        if declaration
            .name
            .as_ident()
            .is_some_and(|id| aliases.contains(&id.to_id()))
            && declaration
                .init
                .as_deref()
                .and_then(Expr::as_ident)
                .is_some_and(|id| aliases.contains(&id.to_id()))
        {
            // Retain the binding (including const's required initializer).
            declaration.init = Some(Box::new(Expr::Lit(Lit::Null(Null {
                span: declaration.span,
            }))));
        }
        declaration.visit_mut_children_with(self);
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Expr::Seq(sequence) = expression {
            // The last operand supplies the sequence's value; only drop discarded values.
            if let Some(last) = sequence.exprs.pop() {
                removal::retain(&mut sequence.exprs, |expression| !self.is_setup(expression));
                sequence.exprs.push(last);
            }
            if sequence.exprs.len() == 1 {
                *expression = *sequence.exprs.remove(0);
            }
        }
    }
}

/// A string table, its decoder, and the provider function that builds it.
struct Table {
    decoder: Id,
    provider: Id,
    offset: f64,
    strings: Vec<Wtf8Atom>,
    /// Whether the decoder reverses each entry with `Array.from(value).reverse().join('')`.
    reversed: bool,
}

impl Table {
    /// Recognizes two decoder layouts:
    ///
    /// ```js
    /// function d(i, a, v) { return i = i - 21, a = provider(), v = a[i], v }
    /// function d(i, v) { return i = i - 21, v = strings[i], Array.from(v).reverse().join('') }
    /// ```
    ///
    /// The second requires `strings` to be assigned `provider()` exactly once.
    #[must_use]
    fn discover(
        function: &FnDecl,
        functions: &HashMap<Id, FnDecl>,
        bindings: &Bindings,
    ) -> Option<Self> {
        if let Some(body) = ast::return_sequence(&function.function)
            && let Some((offset, rest)) = body.split_first()
            && let Some((index, offset)) = ast::assignment(offset)
            && function.function.params.first()?.pat.as_ident()?.to_id() == index
            && let Expr::Bin(subtract) = offset
            && subtract.op == BinaryOp::Sub
            && subtract.left.as_ident()?.to_id() == index
            && let Some(offset) = ast::number(&subtract.right)
            && offset.is_finite()
            && offset.fract() == 0.0
            && let Some((array, provider, lookup, result)) = match rest {
                [array, lookup, result]
                    if let Some((array, provider_call)) = ast::assignment(array)
                        && let Some((provider, [])) = ast::direct_call(provider_call) =>
                {
                    Some((array, provider.to_id(), lookup, result))
                }
                [lookup, result]
                    if let Some((_, Expr::Member(member))) = ast::assignment(lookup)
                        && let Some(array) = member.obj.as_ident()
                        && let Some(provider) = bindings.sole_call(&array.to_id()) =>
                {
                    Some((array.to_id(), provider, lookup, result))
                }
                _ => None,
            }
            && let Some((value, lookup)) = ast::assignment(lookup)
            && let Expr::Member(member) = lookup
            && let MemberProp::Computed(property) = &member.prop
            && member.obj.as_ident()?.to_id() == array
            && property.expr.as_ident()?.to_id() == index
            && let Some(reversed) = if result.as_ident().is_some_and(|id| id.to_id() == value) {
                Some(false)
            } else {
                (reversal_of(result)? == value).then_some(true)
            }
            && let Some(strings) = factory_strings(functions.get(&provider)?, &provider)
        {
            Some(Self {
                decoder: function.ident.to_id(),
                provider,
                offset,
                strings,
                reversed,
            })
        } else {
            None
        }
    }

    /// The decoded entry at `index` once the table is rotated left by `rotation` entries.
    #[must_use]
    fn lookup(&self, index: f64, rotation: usize) -> Option<Wtf8Atom> {
        let index =
            ast::array_index(index - self.offset).filter(|index| *index < self.strings.len())?;
        let value = &self.strings[(index + rotation) % self.strings.len()];
        Some(if self.reversed {
            reverse_code_points(value)
        } else {
            value.clone()
        })
    }
}

/// `Array.from(value).reverse().join('')`, returning `value`'s binding.
fn reversal_of(expression: &Expr) -> Option<Id> {
    if let Some((reversed, [separator])) = ast::method_call(expression, "join")
        && separator.spread.is_none()
        && ast::static_str(&separator.expr)?.is_empty()
        && let Some((from, [])) = ast::method_call(reversed, "reverse")
        && let Some((array, [value])) = ast::method_call(from, "from")
        && array.as_ident()?.sym == "Array"
        && value.spread.is_none()
    {
        Some(value.expr.as_ident()?.to_id())
    } else {
        None
    }
}

/// Reverses by JavaScript code points as `Array.from` does. Preserves surrogate pairs; moves
/// lone surrogates individually.
fn reverse_code_points(value: &Wtf8Atom) -> Wtf8Atom {
    let points: Vec<CodePoint> = value.as_wtf8().code_points().collect();
    let reversed: Wtf8Buf = points.into_iter().rev().collect();
    Wtf8Atom::from(reversed)
}

/// Reads strings returned by a self-replacing table factory:
///
/// ```js
/// function provider(v) {
///   v = `a;b`.split(`;`);
///   provider = function () { return v };
///   return provider();
/// }
/// ```
fn factory_strings(factory: &FnDecl, provider: &Id) -> Option<Vec<Wtf8Atom>> {
    if let Some([split, redefine, call]) = ast::return_sequence(&factory.function)
        && let Some((storage, split)) = ast::assignment(split)
        && let Some((object, [separator])) = ast::method_call(split, "split")
        && separator.spread.is_none()
        && let Some(separator) = ast::static_wtf8(&separator.expr)
        && let Some(strings) = split_utf16(ast::static_wtf8(object)?, separator)
        && let Some((redefined, Expr::Fn(redefine_function))) = ast::assignment(redefine)
        && redefined == *provider
        && let Some(returned) = ast::returned(&redefine_function.function)
        && returned.as_ident()?.to_id() == storage
        && redefine_function.function.params.is_empty()
        && let Some((called, [])) = ast::direct_call(call)
        && called.to_id() == *provider
    {
        Some(strings)
    } else {
        None
    }
}

/// Splits UTF-16 code units as `String.prototype.split` does, keeping lone surrogates that Rust
/// strings would corrupt. Returns `None` for an empty separator, which splits every code unit.
fn split_utf16(source: &Wtf8Atom, separator: &Wtf8Atom) -> Option<Vec<Wtf8Atom>> {
    let source: Vec<u16> = source.as_wtf8().to_ill_formed_utf16().collect();
    let separator: Vec<u16> = separator.as_wtf8().to_ill_formed_utf16().collect();
    if separator.is_empty() {
        return None;
    }
    let part = |units: &[u16]| Wtf8Atom::from(Wtf8Buf::from_ill_formed_utf16(units));
    let mut parts = Vec::new();
    let mut start = 0;
    let mut position = 0;
    while position + separator.len() <= source.len() {
        if source[position..].starts_with(&separator) {
            parts.push(part(&source[start..position]));
            position += separator.len();
            start = position;
        } else {
            position += 1;
        }
    }
    parts.push(part(&source[start..]));
    Some(parts)
}

/// Finds table-rotation calls and solves the rotation at which their decoded-entry checksums
/// match.
struct Rotations<'plan> {
    table: &'plan Table,
    aliases: &'plan HashSet<Id>,
    bindings: &'plan Bindings,
    matches: Vec<Setup>,
}

/// A call that rotates the table at runtime.
#[derive(Clone, Copy)]
struct Setup {
    call: Span,
    /// How far the call rotates the table left.
    rotation: usize,
}

impl Visit for Rotations<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Some(rotation) = self.rotation(call) {
            self.matches.push(Setup {
                call: call.span,
                rotation,
            });
        }
        call.visit_children_with(self);
    }
}

impl Rotations<'_> {
    /// Solves the rotation for `call` when its loop initializer binds only the array and known
    /// decoder aliases.
    fn rotation(&self, call: &CallExpr) -> Option<usize> {
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Fn(function) = callee.unwrap_parens()
            && let [provider, target] = call.args.as_slice()
            && provider.spread.is_none()
            && target.spread.is_none()
            && provider.expr.as_ident()?.to_id() == self.table.provider
            && let Some(target_value) = ast::number(&target.expr)
            && !function.function.is_async
            && !function.function.is_generator
            && let [provider_param, target_param, ..] = function.function.params.as_slice()
            && let Some(provider_param) = provider_param.pat.as_ident()
            && let Some(target_param) = target_param.pat.as_ident()
            && let Some(loop_body) = function.function.body.as_ref()
            && let [Stmt::For(loop_)] = loop_body.stmts.as_slice()
            && loop_.update.is_none()
            && matches!(loop_.test.as_deref(), Some(Expr::Lit(Lit::Bool(test))) if test.value)
            && let Some(VarDeclOrExpr::Expr(init)) = &loop_.init
            && let Expr::Seq(init) = &**init
            && let Some((last, leading)) = init.exprs.split_last()
            && let Some((array, array_call)) = ast::assignment(last)
            && let Some((called, [])) = ast::direct_call(array_call)
            && called.to_id() == provider_param.to_id()
            && leading
                .iter()
                .all(|expression| is_alias_copy(expression, self.aliases))
            && let Stmt::Try(try_) = &*loop_.body
            && try_.finalizer.is_none()
            && let [Stmt::If(check)] = try_.block.stmts.as_slice()
            && matches!(&*check.cons, Stmt::Break(statement) if statement.label.is_none())
            && is_rotation(check.alt.as_deref()?, &array)
            && let Some(handler) = try_.handler.as_ref()
            && let [catch] = handler.body.stmts.as_slice()
            && is_rotation(catch, &array)
            && let Expr::Seq(test) = &*check.test
            && let [checksum, comparison] = test.exprs.as_slice()
            && let Some((checksum_id, checksum)) = ast::assignment(checksum)
            && let Expr::Bin(comparison) = &**comparison
            && matches!(comparison.op, BinaryOp::EqEq | BinaryOp::EqEqEq)
            && let Some(left) = comparison.left.as_ident()
            && let Some(right) = comparison.right.as_ident()
            && ((left.to_id() == target_param.to_id() && right.to_id() == checksum_id)
                || (right.to_id() == target_param.to_id() && left.to_id() == checksum_id))
        {
            // Try at most one table length of rotations instead of executing the input loop.
            (0..self.table.strings.len())
                .find(|&rotation| self.evaluate(checksum, rotation) == Some(target_value))
        } else {
            None
        }
    }

    /// Folds the checksum under `rotation`, reading `parseInt(decoder(index))` from the table.
    fn evaluate(&self, expression: &Expr, rotation: usize) -> Option<f64> {
        ast::fold_number(expression, &|leaf| {
            let (callee, [argument]) = ast::direct_call(leaf)? else {
                return None;
            };
            let (decoder, [index]) = ast::direct_call(&argument.expr)? else {
                return None;
            };
            if callee.sym != "parseInt"
                || self.bindings.is_bound(&callee.to_id())
                || argument.spread.is_some()
                || !self.aliases.contains(&decoder.to_id())
                || index.spread.is_some()
            {
                return None;
            }
            let value = self.table.lookup(ast::number(&index.expr)?, rotation)?;
            Some(js::parse_integer(&value.to_string_lossy()))
        })
    }
}

fn is_rotation(statement: &Stmt, array: &Id) -> bool {
    if let Stmt::Expr(expression) = statement
        && let Some((object, [argument])) = ast::method_call(&expression.expr, "push")
        && let Some((shifted, [])) = ast::method_call(&argument.expr, "shift")
    {
        argument.spread.is_none()
            && object.as_ident().is_some_and(|id| &id.to_id() == array)
            && shifted.as_ident().is_some_and(|id| &id.to_id() == array)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deobfuscate::testing;

    fn fixture(offset: u32, separator: &str, consumer: &str) -> String {
        let next = offset + 1;
        let index = offset + 2;
        format!(
            r#"
        (function () {{
            function useAlias(late) {{ late = middle; return late({index}); }}
            var middle = decoder;
            (function (factory, target, alias, values, checksum) {{
                for (alias = decoder, values = factory(); true;) try {{
                    if (checksum = parseInt(alias({offset})) + parseInt(alias({next})), target === checksum)
                        break;
                    else values.push(values.shift());
                }} catch (error) {{ values.push(values.shift()); }}
            }})(provider, 18);
            function decoder(index, unused, values, result) {{
                return index = index - {offset}, values = provider(), result = values[index], result;
            }}
            function provider(values) {{
                return values = `noise{separator}7abc{separator}11def{separator}message`.split(`{separator}`),
                    provider = function () {{ return values; }}, provider();
            }}
            function shadow(decoder) {{ return decoder({index}); }}
            function x() {{ return 'unrelated x'; }}
            function d() {{ return 'unrelated d'; }}
            console.log(useAlias(), shadow(function (v) {{ return v; }}), x(), d());
            {consumer}
        }})();
        "#
        )
    }

    #[test]
    fn decodes_tables_with_any_names_offsets_delimiters_and_quoting() {
        for (offset, separator, name) in [
            (21, ";", "alpha"),
            (700, "::", "renamed"),
            (4096, "|", "thirdDecoder"),
        ] {
            let source = fixture(offset, separator, "")
                .replace("decoder", name)
                .replace("provider", "tableFactory");
            let output = testing::transform(&source);
            assert!(output.contains("return \"message\";"), "{output}");
            testing::assert_lacks(&output, &["function tableFactory(", "parseInt("]);
            testing::assert_contains(&output, &[&format!("return {name}({});", offset + 2)], &[]);
            testing::assert_contains(&output, &["function x()", "function d()"], &[]);
        }
        // Quoted tables keep their UTF-16 code units.
        let source = fixture(21, ";", "").replace(
            "`noise;7abc;11def;message`.split(`;`)",
            r#""noise;7abc;11def;\uD800"["split"](";")"#,
        );
        let output = testing::transform(&source);
        assert!(output.contains(r#"return "\uD800";"#), "{output}");
        assert!(!output.contains("function provider("), "{output}");
    }

    #[test]
    fn preserves_setups_still_needed_or_not_solved() {
        // Dynamic calls, escaped aliases, and extra arguments still need the decoder.
        for consumer in [
            "console.log(middle(input));",
            "console.log(middle(23, effect()));",
            "console.log(middle(...args));",
            "console.log(middle(22.5));",
            "console.log(middle(1000));",
            "consume(middle);",
            "consume({ middle });",
        ] {
            let output = testing::transform(&fixture(21, ";", consumer));
            assert!(output.contains("return \"message\";"), "{output}");
            let expected = ["function provider(", "function decoder(", "parseInt("];
            testing::assert_contains(&output, &expected, &[]);
        }
        // Unsolved setups and reassigned decoders.
        for source in [
            fixture(21, ";", "").replace("provider, 18", "provider, 999"),
            fixture(21, ";", "").replace("values.push(values.shift())", "values.pop()"),
            fixture(21, ";", "").replace(
                "var middle",
                "function parseInt(v) { return 0; } var middle",
            ),
            fixture(21, ";", "").replace("var middle", "decoder = replacement; var middle"),
            fixture(21, ";", "middle = replacement; console.log(middle(23));"),
        ] {
            let output = testing::transform(&source);
            assert!(!output.contains("return \"message\";"), "{output}");
            testing::assert_contains(&output, &["function provider(", "function decoder("], &[]);
        }
    }

    #[test]
    fn reverses_code_points_and_preserves_surrogates() {
        for (source, expected) in [
            (vec![], vec![]),
            (
                vec![0x61, 0xd83d, 0xde00, 0x62],
                vec![0x62, 0xd83d, 0xde00, 0x61],
            ),
            (vec![0xd800, 0x61, 0xdc00], vec![0xdc00, 0x61, 0xd800]),
            (vec![0xdc00, 0xd800], vec![0xd800, 0xdc00]),
        ] {
            let source = Wtf8Atom::from(Wtf8Buf::from_ill_formed_utf16(&source));
            let reversed = reverse_code_points(&source);
            assert_eq!(
                reversed.as_wtf8().to_ill_formed_utf16().collect::<Vec<_>>(),
                expected
            );
        }
    }
}
