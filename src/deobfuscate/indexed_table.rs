//! Inlines constant string-table reads through a single accessor:
//!
//! ```js
//! t = ["apply", "push"];
//! function a(i) { return t[i] }
//! a(1);  // becomes "push"
//! ```
//!
//! Requires one assignment of a string-literal array and no table reads outside the accessor,
//! ensuring that entries remain unchanged.

use swc_core::ecma::ast::{Expr, FnDecl, Id, Lit, MemberProp, Program, Str, VarDeclarator};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::Analysis;
use super::{HashMap, HashSet};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let bindings = analysis.bindings(program);
    let mut tables = Tables::default();
    program.visit_with(&mut tables);

    let mut changed = false;
    for Accessor { accessor, table } in tables.accessors {
        // The accessor's declaration is its only write.
        if bindings.is_written_once(&accessor)
            && bindings.is_written_once(&table)
            && bindings.references(&table) == 1
            && let Some(strings) = tables.strings.get(&table)
        {
            let mut inline = InlineTable {
                aliases: bindings.aliases(&accessor),
                strings,
                changed: false,
            };
            program.visit_mut_with(&mut inline);
            changed |= inline.changed;
        }
    }
    changed
}

/// Finds string tables and their accessor functions.
#[derive(Default)]
struct Tables {
    accessors: Vec<Accessor>,
    /// Bindings assigned string-literal arrays, paired with their contents.
    strings: HashMap<Id, Vec<Str>>,
}

/// An accessor `function a(i) { return t[i] }`.
struct Accessor {
    accessor: Id,
    table: Id,
}

impl Tables {
    fn record(&mut self, id: Id, value: &Expr) {
        let strings: Option<Vec<Str>> = value.as_array().and_then(|array| {
            array
                .elems
                .iter()
                .map(|element| {
                    let element = element
                        .as_ref()
                        .filter(|element| element.spread.is_none())?;
                    Some(element.expr.as_lit()?.as_str()?.clone())
                })
                .collect()
        });
        if let Some(strings) = strings {
            self.strings.insert(id, strings);
        }
    }
}

impl Visit for Tables {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((id, value)) = ast::assignment(expression) {
            self.record(id, value);
        }
        expression.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declaration: &VarDeclarator) {
        if let Some(id) = declaration.name.as_ident()
            && let Some(init) = &declaration.init
        {
            self.record(id.to_id(), init);
        }
        declaration.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, function: &FnDecl) {
        if let [param] = function.function.params.as_slice()
            && let Some(param) = param.pat.as_ident()
            && let Some(Expr::Member(member)) = ast::returned(&function.function)
            && let MemberProp::Computed(index) = &member.prop
            && index.expr.as_ident().map(|id| id.to_id()) == Some(param.to_id())
            && let Some(table) = member.obj.as_ident()
        {
            self.accessors.push(Accessor {
                accessor: function.ident.to_id(),
                table: table.to_id(),
            });
        }
        function.visit_children_with(self);
    }
}

struct InlineTable<'table> {
    aliases: HashSet<Id>,
    strings: &'table [Str],
    changed: bool,
}

impl VisitMut for InlineTable<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        use swc_core::common::Spanned;

        expression.visit_mut_children_with(self);
        if let Some((callee, [index])) = ast::direct_call(expression)
            && self.aliases.contains(&callee.to_id())
            && index.spread.is_none()
            && let Some(index) = ast::index_literal(&index.expr)
            && let Some(string) = self.strings.get(index)
        {
            *expression = Expr::Lit(Lit::Str(Str {
                span: expression.span(),
                ..string.clone()
            }));
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn inlines_reads_only_from_tables_that_cannot_change_or_escape() {
        let inline = |source: &str| testing::rewrite(source, super::run, /* fix= */ false);
        let output = inline(
            r#"var t; t = ["apply", "push"];
            function a(i) { return t[i]; }
            var b = a;
            f(a(0), b(1), a(2), a(n));"#,
        );
        testing::assert_contains(&output, &[r#"f("apply", "push", a(2), a(n))"#], &[]);
        for source in [
            r#"var t = ["x"]; function a(i) { return t[i]; } t.push("y"); f(a(0));"#,
            r#"var t = ["x"]; function a(i) { return t[i]; } t = ["y"]; f(a(0));"#,
            r#"var t = ["x", g()]; function a(i) { return t[i]; } f(a(0));"#,
            r#"var t = ["x"]; function a(i) { return t[i]; } a = h; f(a(0));"#,
        ] {
            assert!(inline(source).contains("f(a(0))"), "{source}");
        }
    }
}
