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
        // R7 cluster[9] #150/#158 (design-fork Option A, see
        // decisions/r7-cl9-php-factory-name-only-heuristic.md): a Factory
        // requires EVIDENCE of construction, never a bare factory-shaped
        // method NAME. A method named `create*`/`make*`/`build*`/`new*` is
        // a factory ONLY when it actually constructs an object (`new` in
        // its body) OR is declared `abstract` (the abstract-factory
        // contract). The pre-fix name-only "exposes a factory method"
        // branch flagged `newLine(): void`, `buildLine(): string` and
        // `buildUri(): UriInterface` (transforms input, no `new`).
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
                    constructs_new: subtree_has_kind(member, "object_creation_expression"),
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

/// True when any descendant of `node` has the given kind.
fn subtree_has_kind(node: Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if subtree_has_kind(child, kind) {
            return true;
        }
    }
    false
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
