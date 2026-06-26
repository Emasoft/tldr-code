//! PHP semantic + design-pattern detection.
//!
//! pack-patterns-v1 (v0.5.0 PACK-PATTERNS): enriched from the previous
//! naming-only extractor to also detect GoF design patterns from the
//! class/method AST — Singleton, Factory, and Observer — entirely via
//! tree-sitter node kinds + field navigation (no regex/substring
//! heuristics on raw source).
//!
//! # AST shape (tree-sitter-php)
//!
//! ```text
//! class_declaration
//!   ├─ name                                  (class name -- field "name")
//!   ├─ base_clause                           (`extends Parent`)
//!   ├─ class_interface_clause                (`implements A, B`)
//!   │    └─ name                             (each interface name)
//!   └─ declaration_list
//!        ├─ property_declaration             (static_modifier? visibility?)
//!        └─ method_declaration
//!             ├─ visibility_modifier         (public/private/protected)
//!             ├─ static_modifier
//!             ├─ abstract_modifier
//!             └─ name                         (method name -- field "name")
//! ```

use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};

/// Semantic extractor for PHP.
pub struct PhpSemantics;

impl LanguageSemantics for PhpSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_declaration" => self.detect_class(node, source, file_path, signals),
            "method_declaration" | "function_definition" => {
                self.detect_function(node, source, file_path, signals)
            }
            "use_declaration" | "namespace_use_declaration" | "namespace_use_clause" => {
                self.detect_use_import(node, source, file_path, signals)
            }
            _ => {}
        }
    }
}

/// Per-method structural facts gathered from one `method_declaration`.
struct PhpMethod {
    name: String,
    is_static: bool,
    is_private: bool,
    is_abstract: bool,
    constructs_new: bool,
}

impl PhpSemantics {
    fn detect_class(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let name = match node.child_by_field_name("name") {
            Some(name_node) => node_text(name_node, source),
            None => return,
        };
        let line = node.start_position().row as u32 + 1;
        let file = file_path.display().to_string();

        let case = detect_naming_case(&name);
        signals
            .naming
            .class_names
            .push((name.clone(), case, file.clone(), line));

        // Gather structural facts.
        let is_abstract_class = has_child_kind(node, "abstract_modifier");
        let interfaces = collect_interfaces(node, source);
        let bases = collect_bases(node, source);
        let mut has_static_self_property = false;
        let methods = collect_methods(node, source, &mut has_static_self_property);

        // ---- Singleton ----------------------------------------------
        // A Singleton hides its constructor (`private function
        // __construct`) AND exposes a public *static* accessor that
        // returns the single shared instance (`getInstance` / `instance`
        // / `get_instance`), usually backed by a static `$instance`
        // property.
        let private_ctor = methods
            .iter()
            .any(|m| m.name == "__construct" && m.is_private);
        let static_accessor = methods.iter().any(|m| {
            m.is_static && is_instance_accessor_name(&m.name)
        });
        if private_ctor && static_accessor {
            signals.design_patterns.push_pattern(
                "Singleton",
                "creational",
                "php",
                name.clone(),
                file.clone(),
                line,
                format!(
                    "class `{name}` has a private constructor and a static instance accessor"
                ),
            );
        }

        // ---- Factory -------------------------------------------------
        // R7 cluster[9] #150/#158 (design-fork, see
        // decisions/r7-cl9-php-factory-name-only-heuristic.md): a Factory
        // requires EVIDENCE of construction, never a bare factory-shaped
        // method NAME. A method named `create*`/`make*`/`build*`/`new*` is
        // a factory ONLY when a freshly-constructed object REACHES a
        // `return`/`yield` (`constructs_new`, computed by
        // `construction_reaches_return`) OR it is declared `abstract` (the
        // abstract-factory contract). The CLOSEOUT refinement tightened
        // `constructs_new` from "a `new` exists in the body" to "a `new`
        // reaches a return": that drops `throw new X()` guards
        // (`createCompletionInput`), `$this->y = new X()` field mutators
        // (`createResponse(): void`) and unreturned temporaries, which the
        // earlier existence test still mis-flagged; the pre-Option-A
        // name-only branch had flagged `newLine(): void` /
        // `buildLine(): string` / `buildUri(): UriInterface` too.
        let factory_method = methods
            .iter()
            .find(|m| is_factory_method_name(&m.name) && (m.is_abstract || m.constructs_new));
        let class_named_factory = name.ends_with("Factory");
        if let Some(fm) = factory_method {
            let evidence = if fm.is_abstract {
                format!("class `{name}` declares an abstract factory method `{}`", fm.name)
            } else {
                format!("class `{name}` builds instances in `{}` via `new`", fm.name)
            };
            signals.design_patterns.push_pattern(
                "Factory",
                "creational",
                "php",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        } else if class_named_factory && methods.iter().any(|m| m.constructs_new) {
            signals.design_patterns.push_pattern(
                "Factory",
                "creational",
                "php",
                name.clone(),
                file.clone(),
                line,
                format!("class `{name}` (named *Factory) constructs instances via `new`"),
            );
        }

        // ---- Observer ------------------------------------------------
        // Subject: implements `SplSubject` / `*Subject` OR exposes the
        // attach/detach/notify trio. Observer: implements `SplObserver`
        // / `*Observer` OR exposes an `update` method on a class named
        // `*Observer`.
        let implements_subject = interfaces
            .iter()
            .chain(bases.iter())
            .any(|i| i == "SplSubject" || i.ends_with("Subject"));
        let implements_observer = interfaces
            .iter()
            .chain(bases.iter())
            .any(|i| i == "SplObserver" || i.ends_with("Observer"));
        let has_subject_trio = methods.iter().any(|m| m.name == "attach")
            && methods.iter().any(|m| m.name == "notify");
        let observer_update = methods.iter().any(|m| m.name == "update")
            && (name.ends_with("Observer") || implements_observer);

        if implements_subject || has_subject_trio {
            let evidence = if implements_subject {
                format!("class `{name}` implements a Subject interface")
            } else {
                format!("class `{name}` exposes the attach/notify Subject API")
            };
            signals.design_patterns.push_pattern(
                "Observer",
                "behavioral",
                "php",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        } else if implements_observer || observer_update {
            let evidence = if implements_observer {
                format!("class `{name}` implements an Observer interface")
            } else {
                format!("class `{name}` is an *Observer with an `update` method")
            };
            signals.design_patterns.push_pattern(
                "Observer",
                "behavioral",
                "php",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        }

        let _ = is_abstract_class;
    }

    fn detect_function(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            let case = detect_naming_case(&name);
            signals.naming.function_names.push((
                name,
                case,
                file_path.display().to_string(),
                name_node.start_position().row as u32 + 1,
            ));
        }
    }

    fn detect_use_import(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let text = node_text(node, source);
        if let Some(idx) = text.find("use ") {
            let module = text[idx + 4..].trim().trim_end_matches(';').to_string();
            if !module.is_empty() {
                signals
                    .import_patterns
                    .absolute_imports
                    .push((module, file_path.display().to_string()));
            }
        }
    }
}

/// `getInstance` / `instance` / `get_instance` / `getSingleton` — the
/// idiomatic names for a Singleton's static accessor.
fn is_instance_accessor_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "getinstance" | "instance" | "get_instance" | "getsingleton" | "singleton"
    )
}

/// Factory method names: `create*`, `make*`, `build*`, `new*`. We match
/// on the lowercase prefix so `createShape`, `makeConnection`,
/// `buildClient`, `newWidget` all qualify, while avoiding matching
/// `created`/`makeup` exact-words by requiring the verb to be a prefix
/// followed by an uppercase letter OR being the bare verb.
fn is_factory_method_name(name: &str) -> bool {
    const VERBS: [&str; 4] = ["create", "make", "build", "new"];
    for verb in VERBS {
        if let Some(rest) = name.strip_prefix(verb) {
            if rest.is_empty() {
                return true;
            }
            if rest.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Collect `implements A, B` interface names from a class declaration.
fn collect_interfaces(node: Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_interface_clause" {
            let mut ic = child.walk();
            for ichild in child.children(&mut ic) {
                if ichild.kind() == "name" || ichild.kind() == "qualified_name" {
                    out.push(node_text(ichild, source).trim().to_string());
                }
            }
        }
    }
    out
}

/// Collect the `extends Parent` base class name(s).
fn collect_bases(node: Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "base_clause" {
            let mut bc = child.walk();
            for bchild in child.children(&mut bc) {
                if bchild.kind() == "name" || bchild.kind() == "qualified_name" {
                    out.push(node_text(bchild, source).trim().to_string());
                }
            }
        }
    }
    out
}

/// Walk a class's `declaration_list` collecting per-method facts and
/// noting whether a static property exists (a Singleton hallmark).
fn collect_methods(node: Node, source: &str, has_static_property: &mut bool) -> Vec<PhpMethod> {
    let mut methods = Vec::new();
    let mut top_cursor = node.walk();
    let body = node
        .children(&mut top_cursor)
        .find(|c| c.kind() == "declaration_list");
    let body = match body {
        Some(b) => b,
        None => return methods,
    };
    let mut cursor = body.walk();
    for member in body.children(&mut cursor) {
        match member.kind() {
            "property_declaration" => {
                if has_child_kind(member, "static_modifier") {
                    *has_static_property = true;
                }
            }
            "method_declaration" => {
                let name = member
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source))
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                methods.push(PhpMethod {
                    is_static: has_child_kind(member, "static_modifier"),
                    is_private: has_visibility(member, source, "private"),
                    is_abstract: has_child_kind(member, "abstract_modifier"),
                    // R7 cluster[9] CLOSEOUT: a Factory needs a constructed
                    // object that REACHES a `return`/`yield`, not merely a
                    // `new` somewhere in the body — see
                    // `construction_reaches_return`.
                    constructs_new: construction_reaches_return(member, source),
                    name,
                });
            }
            _ => {}
        }
    }
    methods
}

/// True when `node` has a direct child of the given kind.
fn has_child_kind(node: Node, kind: &str) -> bool {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| c.kind() == kind);
    found
}

/// True when a `method_declaration` carries the given `visibility_modifier`.
fn has_visibility(node: Node, source: &str, vis: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" && node_text(child, source).trim() == vis {
            return true;
        }
    }
    false
}

/// True when a freshly-constructed object REACHES a `return`/`yield` of this
/// method — the AST-level contract for a Factory/Creation Method, per PMD's
/// `SingletonClassReturningNewInstanceRule` and WALA's
/// `FactoryBypassInterpreter` ("allocation flows to return").
///
/// This replaces the previous unscoped existence test
/// (`subtree_has_kind(method, "object_creation_expression")`) that fired on
/// ANY `new` anywhere in the body and so produced three false-positive shapes
/// (R7 cluster[9] CLOSEOUT — see
/// `decisions/r7-cl9-php-factory-name-only-heuristic.md`):
///
/// * `throw new X()` — a `throw_expression`; the object is an error sink and
///   never reaches a `return` (e.g. `CompleteCommand::createCompletionInput`,
///   `Client::createBodyStream`).
/// * `$this->y = new X()` — a field mutator; the object is stored, not
///   returned (e.g. `EasyHandle::createResponse(): void`).
/// * `new Temp()` used only as an intermediate and never returned.
///
/// Scoping the search to return/yield operands (and the defs of returned
/// locals) excludes all three automatically — they are simply never visited.
fn construction_reaches_return(method: Node, source: &str) -> bool {
    // Negative return-type filter: a `: void`/`: never` or scalar
    // (`primitive_type`/`bottom_type`) return can never carry a constructed
    // object out, so the method is not a factory regardless of body. Used
    // ONLY as a negative filter (never as positive evidence), so a class
    // return type like `buildUri(): UriInterface` is unaffected — it must
    // still pass return-reachability below.
    if let Some(rt) = method.child_by_field_name("return_type") {
        if matches!(rt.kind(), "primitive_type" | "bottom_type") {
            return false;
        }
    }
    let body = match method.child_by_field_name("body") {
        Some(b) => b,
        None => return false, // abstract / interface method: no body
    };
    let mut operands: Vec<Node> = Vec::new();
    collect_return_operands(body, &mut operands);
    operands
        .iter()
        .any(|operand| operand_reaches_new(*operand, body, source))
}

/// Recursively collect the value operand of every `return_statement` and
/// `yield_expression` reachable in `node` WITHOUT crossing a nested
/// function / closure / anonymous-class boundary (an inner closure's
/// `return` belongs to that closure, not to the enclosing method — this is
/// the boundary guard that stops `array_map(fn() => new X(), …)` from being
/// attributed to the outer factory).
fn collect_return_operands<'t>(node: Node<'t>, out: &mut Vec<Node<'t>>) {
    match node.kind() {
        // Nested-scope boundaries: do not descend. A returned arrow such as
        // `return fn() => new X()` is still handled, because that
        // `return_statement` lives in the OUTER body and its operand (the
        // arrow) is inspected by `operand_reaches_new`.
        "arrow_function" | "anonymous_function" | "anonymous_class" => return,
        "return_statement" => {
            if let Some(value) = first_named_child(node) {
                out.push(value);
            }
            return;
        }
        "yield_expression" => {
            if let Some(value) = yield_value(node) {
                out.push(value);
            }
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_return_operands(child, out);
    }
}

/// The value operand of a `yield_expression`. `yield new X()` wraps its value
/// in an `array_element_initializer`; `yield $k => new X()` puts the value
/// last in that initializer.
fn yield_value(yield_node: Node) -> Option<Node> {
    let inner = first_named_child(yield_node)?;
    if inner.kind() == "array_element_initializer" {
        last_named_child(inner)
    } else {
        Some(inner)
    }
}

/// True when the return/yield `operand` carries a freshly-constructed object.
fn operand_reaches_new(operand: Node, body: Node, source: &str) -> bool {
    let head = peel_to_head(operand);
    match head.kind() {
        // Clause (a) — the operand's chain-head IS a construction:
        // `return new X()`, `return new static()`,
        // `return (new Table($o))->setStyle($s)`.
        "object_creation_expression" => true,
        // Clause (b) — the operand is a bare local whose reaching definition
        // is `$v = new …`: `$x = new CompletionInput(); … return $x;`.
        "variable_name" => local_reaching_def_is_new(&node_text(head, source), body, source),
        // A returned arrow `fn() => new X()` is return-equivalent (its body
        // field is the construction); `fn() => throw new X()` is not.
        "arrow_function" => head
            .child_by_field_name("body")
            .map(|b| peel_to_head(b).kind() == "object_creation_expression")
            .unwrap_or(false),
        _ => false,
    }
}

/// Strip transparent wrappers from a return operand to reach the expression
/// that determines what is returned: a `parenthesized_expression`, and the
/// receiver/head (`object`/`scope` field) of a member/scoped/nullsafe access
/// or call chain — so `(new Table($o))->setStyle($s)` resolves to the inner
/// `new`. Only the object/scope field is followed, never `arguments`, so a
/// `new` buried in an argument (`return $x->with(new Helper())`) is NOT
/// reached and does not spuriously qualify.
fn peel_to_head(mut node: Node) -> Node {
    loop {
        let next = match node.kind() {
            "parenthesized_expression" => first_named_child(node),
            "member_access_expression"
            | "member_call_expression"
            | "nullsafe_member_access_expression"
            | "nullsafe_member_call_expression" => node.child_by_field_name("object"),
            "scoped_call_expression" | "scoped_property_access_expression" => {
                node.child_by_field_name("scope")
            }
            _ => return node,
        };
        match next {
            Some(inner) => node = inner,
            None => return node,
        }
    }
}

/// Clause (b) reaching-definition test: the definition of the local `var`
/// reaching a `return $var` is a fresh construction (`$var = new …`).
///
/// Mirrors PMD's `isReferenceToLocal` (only a `variable_name` LHS qualifies —
/// never `$this->field`, so `return $this->cached;` does NOT qualify) plus
/// WALA's "allocation flows to return". The reaching def is approximated, per
/// the proposal's rule "never reassigned to a non-`new` value AFTERWARD", by
/// the LAST textual write to `var`: that write must be a plain/reference
/// `$var = new …`. Because `collect_writes_to` is a pre-order (source-order)
/// walk, the last collected write is the textually-last one. This:
///   * KEEPS `…; $x = new ArrayInput($x); …; return $x;` even when an earlier
///     (conditional) `$x = array_merge(..)` write precedes the construction
///     (the `new` is the reaching def) — e.g. `CommandTester::createInput`;
///   * DROPS `$x = new X(); $x = foo(); return $x;` (reassigned afterward)
///     and `$c = Y::fromTokens(..); return $c;` (def is a static call, not a
///     `new`) — e.g. `CompleteCommand::createCompletionInput`.
/// Conservative for FP-minimisation: a later conditional non-`new` write
/// kills the local even if the `new` might still reach the return on some
/// path (a tolerated false negative, never a false positive).
fn local_reaching_def_is_new(var: &str, body: Node, source: &str) -> bool {
    let mut writes: Vec<Node> = Vec::new();
    collect_writes_to(body, var, source, &mut writes);
    match writes.last() {
        Some(last) => {
            matches!(
                last.kind(),
                "assignment_expression" | "reference_assignment_expression"
            ) && last
                .child_by_field_name("right")
                .map(|rhs| peel_to_head(rhs).kind() == "object_creation_expression")
                .unwrap_or(false)
        }
        None => false,
    }
}

/// Collect every assignment node (`=`, `op=`, `=&`) whose LEFT-hand side is
/// exactly the local `var` (a `variable_name`, never a member access),
/// without crossing a nested function / anonymous-class boundary.
fn collect_writes_to<'t>(node: Node<'t>, var: &str, source: &str, out: &mut Vec<Node<'t>>) {
    match node.kind() {
        "arrow_function" | "anonymous_function" | "anonymous_class" => return,
        "assignment_expression"
        | "augmented_assignment_expression"
        | "reference_assignment_expression" => {
            if let Some(lhs) = node.child_by_field_name("left") {
                if lhs.kind() == "variable_name" && node_text(lhs, source).as_str() == var {
                    out.push(node);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_writes_to(child, var, source, out);
    }
}

/// First named child of `node`, if any.
fn first_named_child(node: Node) -> Option<Node> {
    node.named_child(0)
}

/// Last named child of `node`, if any.
fn last_named_child(node: Node) -> Option<Node> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

/// Build the PHP language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("method_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_statement",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map.dispatch
        .insert("use_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "namespace_use_declaration",
        vec![SignalAction::CallSemantics],
    );
    map.dispatch
        .insert("namespace_use_clause", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(PhpSemantics),
    }
}
