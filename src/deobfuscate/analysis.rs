//! Shared conservative analysis for deobfuscation rewrites.
//!
//! Oxc resolves the original program once, and moved references keep those binding identities
//! until final hygiene. Read and write counts are recollected from the current tree after each
//! change.

use oxc::allocator::{Allocator, CloneIn, GetAllocator};
use oxc::ast::ast::{
    AssignmentTarget, BindingIdentifier, Expression, IdentifierReference, Program,
};
use oxc::ast::builder::{AstBuilder, GetAstBuilder};
use oxc::semantic::Scoping;
use oxc::span::{SPAN, Span};
use oxc::str::Ident;
use oxc::syntax::node::NodeId;
use oxc::syntax::operator::{AssignmentOperator, UnaryOperator};
use oxc::syntax::reference::{Reference, ReferenceFlags, ReferenceId};
use oxc::syntax::scope::ScopeId;
use oxc::syntax::symbol::{SymbolFlags, SymbolId};
use oxc_ecmascript::GlobalContext;
use oxc_ecmascript::constant_evaluation::ConstantEvaluationCtx;
use oxc_ecmascript::side_effects::{
    MayHaveSideEffects, MayHaveSideEffectsContext, PropertyReadSideEffects,
};

mod bindings;
pub(super) mod effects;
pub(super) mod hoisting;
pub(super) mod properties;
pub(super) mod unconditional;

use bindings::Bindings;

use super::ast;

/// A binding identity. Unresolved globals use the first reference to their spelling, which lets
/// helpers assigned to globals participate without inventing symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum Id {
    Local(SymbolId),
    Global(ReferenceId),
}

impl Id {
    fn of(reference: &IdentifierReference<'_>, scoping: &Scoping) -> Option<Self> {
        let resolved = scoping.get_reference(reference.reference_id.get()?);
        match resolved.symbol_id() {
            Some(symbol) => Some(Self::Local(symbol)),
            None => {
                let globals = scoping.root_unresolved_references().get(&reference.name)?;
                globals.first().copied().map(Self::Global)
            }
        }
    }

    pub(super) fn local(self) -> Option<SymbolId> {
        match self {
            Self::Local(symbol) => Some(symbol),
            Self::Global(_) => None,
        }
    }

    pub(super) fn is_global(self) -> bool {
        matches!(self, Self::Global(_))
    }
}

/// The program's resolved scoping and the binding uses of its current tree.
pub(super) struct Analysis<'a> {
    pub ast: AstBuilder<'a>,
    pub scoping: Scoping,
    pub bindings: Bindings,
}

impl<'a> Analysis<'a> {
    pub(super) fn new(allocator: &'a Allocator, scoping: Scoping) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            scoping,
            bindings: Bindings::default(),
        }
    }

    pub(super) fn id(&self, reference: &IdentifierReference<'_>) -> Option<Id> {
        Id::of(reference, &self.scoping)
    }

    pub(super) fn expression_id(&self, expression: &Expression<'_>) -> Option<Id> {
        self.id(expression.get_identifier_reference()?)
    }

    pub(super) fn target_id(&self, target: &AssignmentTarget<'_>) -> Option<Id> {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(reference) => self.id(reference),
            _ => None,
        }
    }

    /// Matches a plain `binding = value` assignment.
    pub(super) fn assignment<'b>(
        &self,
        expression: &'b Expression<'a>,
    ) -> Option<(Id, &'b Expression<'a>)> {
        let Expression::AssignmentExpression(assignment) = expression.get_inner_expression() else {
            return None;
        };
        if assignment.operator != AssignmentOperator::Assign {
            return None;
        }
        Some((self.target_id(&assignment.left)?, &assignment.right))
    }

    /// Checks for a reference to the global `name`, which no local binding shadows.
    pub(super) fn is_global(&self, reference: &IdentifierReference<'_>, name: &str) -> bool {
        reference.name == name && self.id(reference).is_none_or(Id::is_global)
    }

    /// Checks for global `undefined`, or `void` of an operand without side effects, so dropping,
    /// repeating, or moving the expression cannot be observed.
    pub(super) fn is_undefined(&self, expression: &Expression<'_>) -> bool {
        match expression {
            Expression::Identifier(identifier) => self.is_global(identifier, "undefined"),
            Expression::UnaryExpression(unary) => {
                unary.operator == UnaryOperator::Void
                    && (ast::fold_number(&unary.argument, &|_| None).is_some()
                        || !unary.argument.may_have_side_effects(self))
            }
            _ => false,
        }
    }

    pub(super) fn scope(&self, id: Id) -> ScopeId {
        match id {
            Id::Local(symbol) => self.scoping.symbol_scope_id(symbol),
            Id::Global(_) => self.scoping.root_scope_id(),
        }
    }

    pub(super) fn name(&self, id: Id) -> &str {
        match id {
            Id::Local(symbol) => self.scoping.symbol_name(symbol),
            Id::Global(reference) => {
                let mut globals = self.scoping.root_unresolved_references().iter();
                let (name, _) = globals
                    .find(|(_, references)| references.first() == Some(&reference))
                    .expect("a global identity is the first reference to its name");
                name.as_str()
            }
        }
    }

    pub(super) fn span(&self, id: Id) -> Span {
        match id {
            Id::Local(symbol) => self.scoping.symbol_span(symbol),
            Id::Global(_) => SPAN,
        }
    }

    /// Copies `node` into the arena so later tree mutations cannot change it. Semantic IDs are
    /// kept because references must retain their original binding identities.
    pub(super) fn save<T: CloneIn<'a, Cloned = T>>(&self, node: &T) -> &'a T {
        let allocator = self.allocator();
        allocator.alloc(node.clone_in_with_semantic_ids(allocator))
    }

    /// Recollects uses from the rewritten tree while keeping the original binding identities.
    pub(super) fn refresh(&mut self, program: &Program<'a>) {
        self.bindings = Bindings::collect(program, &self.scoping)
    }

    /// Checks whether a symbol or an unresolved global already uses `name`.
    fn is_name_taken(&self, name: &str) -> bool {
        self.scoping
            .symbol_ids()
            .any(|symbol| self.scoping.symbol_name(symbol) == name)
            || self.scoping.root_unresolved_references().contains_key(name)
    }

    /// Returns the first of `base_1`, `base_2`, and so on that no symbol or global uses.
    pub(super) fn suffixed_name(&self, base: &str) -> String {
        let mut names = (1..).map(|suffix| format!("{base}_{suffix}"));
        names
            .find(|name| !self.is_name_taken(name))
            .expect("the suffixes are unbounded")
    }

    /// Creates a local named `base`, or `base_1`, `base_2`, and so on if that name is taken.
    pub(super) fn fresh_binding(
        &mut self,
        base: &str,
        scope: ScopeId,
        span: Span,
    ) -> BindingIdentifier<'a> {
        let name = if self.is_name_taken(base) {
            self.suffixed_name(base)
        } else {
            base.to_owned()
        };
        self.binding(&name, scope, span)
    }

    /// Creates a new symbol, which may reuse the spelling of another binding.
    pub(super) fn binding(
        &mut self,
        name: &str,
        scope: ScopeId,
        span: Span,
    ) -> BindingIdentifier<'a> {
        let name = Ident::from_str_in(name, &self.ast);
        let symbol = self.scoping.create_symbol(
            span,
            name,
            SymbolFlags::FunctionScopedVariable,
            scope,
            NodeId::DUMMY,
        );
        self.scoping.add_binding(scope, name, symbol);
        BindingIdentifier::new_with_symbol_id(span, name, symbol, &self.ast)
    }

    /// Creates a reference to a local and records its read and write flags in the scoping.
    pub(super) fn reference(
        &mut self,
        symbol: SymbolId,
        span: Span,
        flags: ReferenceFlags,
    ) -> IdentifierReference<'a> {
        let scope = self.scoping.symbol_scope_id(symbol);
        let name = Ident::from_str_in(self.scoping.symbol_name(symbol), &self.ast);
        let reference = self.scoping.create_reference(Reference::new_with_symbol_id(
            NodeId::DUMMY,
            symbol,
            scope,
            flags,
        ));
        self.scoping.add_resolved_reference(symbol, reference);
        IdentifierReference::new_with_reference_id(span, name, reference, &self.ast)
    }
}

impl<'a> GetAllocator<'a> for Analysis<'a> {
    fn allocator(&self) -> &'a Allocator {
        self.ast.allocator()
    }
}

impl<'a> GetAstBuilder<'a> for Analysis<'a> {
    type Builder = AstBuilder<'a>;

    fn builder(&self) -> &Self::Builder {
        &self.ast
    }
}

impl<'a> GlobalContext<'a> for Analysis<'a> {
    fn is_global_reference(&self, reference: &IdentifierReference<'a>) -> bool {
        self.id(reference).is_none_or(Id::is_global)
    }
}

/// Unknown globals and property reads may have effects; purity annotations are not trusted.
impl<'a> MayHaveSideEffectsContext<'a> for Analysis<'a> {
    fn annotations(&self) -> bool {
        false
    }

    fn manual_pure_functions(&self, _: &Expression<'_>) -> bool {
        false
    }

    fn property_read_side_effects(&self) -> PropertyReadSideEffects {
        PropertyReadSideEffects::All
    }

    fn unknown_global_side_effects(&self) -> bool {
        true
    }
}

impl<'a> ConstantEvaluationCtx<'a> for Analysis<'a> {}
