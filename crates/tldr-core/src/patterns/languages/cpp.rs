use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};

/// Semantic extractor for C++.
pub struct CppSemantics;

impl LanguageSemantics for CppSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_specifier" => self.detect_class(node, source, file_path, signals),
            "function_definition" => self.detect_function(node, source, file_path, signals),
            "preproc_include" => self.detect_include(node, source, file_path, signals),
            // R7 cluster[9] #25/#26: `namespace_definition` is intentionally
            // NOT handled here. A namespace name (often snake_case:
            // `detail`, `fmt`, `std`) is NOT a class and pushing it into
            // naming.class_names flipped the C++ class-naming majority to
            // snake_case. The generic walker still recurses into the
            // namespace body, so classes/functions declared inside a
            // namespace are detected by their own node handlers.
            _ => {}
        }
    }
}

impl CppSemantics {
    fn detect_class(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            let case = detect_naming_case(&name);
            signals
                .naming
                .class_names
                .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
        }
    }

    fn detect_function(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        // R7 cluster[9] #25/#26: navigate the `function_declarator` AST to
        // the real name node instead of a `split('(')`/`split_whitespace`
        // text heuristic. The old text-split grabbed the return-type token
        // for several declarator shapes (`operator bool()` -> "bool",
        // `operator int()` -> "int", `bool operator()(...)` -> "operator").
        let name = node
            .child_by_field_name("declarator")
            .and_then(|decl| extract_function_name_from_declarator(decl, source));
        if let Some(name) = name {
            let case = detect_naming_case(&name);
            signals
                .naming
                .function_names
                .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
        }
    }

    fn detect_include(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let text = node_text(node, source);
        if let Some(module) = extract_include_module(&text) {
            signals
                .import_patterns
                .absolute_imports
                .push((module, file_path.display().to_string()));
        }
    }

}

/// R7 cluster[9] #25/#26: resolve a C++ function name by navigating the
/// `function_declarator` AST to its name node, rather than splitting raw
/// text on `(` and taking the last whitespace token (which returned the
/// return-type keyword for `operator bool()`/`operator int()` and the bare
/// `operator` token for `bool operator()(...)`).
///
/// Declarator wrappers (`pointer_declarator`, `reference_declarator`,
/// `parenthesized_declarator`) are unwrapped to reach the
/// `function_declarator`, whose first declarator-position child is the
/// name. Recognised name nodes:
///   - `identifier`            free function (`regular_function`)
///   - `field_identifier`      method (`do_thing`)
///   - `qualified_identifier`  `MyClass::method` -> the trailing name
///   - `operator_name`         `operator()` / `operator+`
///   - `destructor_name`       `~Foo`
///
/// Conversion operators (`operator_cast`: `operator bool()`,
/// `operator int()`) carry no convention-meaningful identifier, so they
/// are intentionally skipped from naming statistics (returning `None`)
/// rather than mislabelled as the cast target type.
fn extract_function_name_from_declarator(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        // The actual function declarator: its declarator-position child is
        // the name node.
        "function_declarator" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = name_node_text(child, source) {
                    return Some(name);
                }
            }
            None
        }
        // Pointer/reference/parenthesized wrappers around the real
        // declarator (e.g. `int* foo()`); descend through the `declarator`
        // field to the inner function_declarator.
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|inner| extract_function_name_from_declarator(inner, source)),
        // Conversion operator (`operator bool()`): no meaningful name for
        // naming-convention purposes — skip rather than record the cast
        // target type as a "function name".
        "operator_cast" => None,
        // A bare name node directly in the declarator slot (defensive).
        _ => name_node_text(node, source),
    }
}

/// Resolve a C++ declarator name node to its identifier text. Returns
/// `None` for any node that is not a recognised name node (so type
/// keywords / parameter lists are never mistaken for the name).
fn name_node_text(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node_text(node, source)),
        // `MyClass::method_impl` — take the trailing name after the last
        // `::`, never the qualifier.
        "qualified_identifier" => {
            // The last `identifier`/`field_identifier` descendant is the
            // unqualified method name.
            let mut name = None;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "identifier" | "field_identifier" => name = Some(node_text(child, source)),
                    "qualified_identifier" => {
                        // Nested qualification (A::B::c): recurse to the tail.
                        if let Some(inner) = name_node_text(child, source) {
                            name = Some(inner);
                        }
                    }
                    "operator_name" | "destructor_name" => {
                        name = Some(node_text(child, source))
                    }
                    _ => {}
                }
            }
            name
        }
        // `operator()`, `operator+`, etc. — a real (if unusual) name.
        "operator_name" => Some(node_text(node, source)),
        // `~Foo` destructor.
        "destructor_name" => Some(node_text(node, source)),
        _ => None,
    }
}

fn extract_include_module(text: &str) -> Option<String> {
    if let Some(start) = text.find('<') {
        if let Some(end) = text[start + 1..].find('>') {
            return Some(text[start + 1..start + 1 + end].to_string());
        }
    }
    if let Some(start) = text.find('"') {
        let rest = &text[start + 1..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Build the C++ language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_specifier", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_statement",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map.dispatch
        .insert("preproc_include", vec![SignalAction::CallSemantics]);
    // R7 cluster[9] #25/#26: namespace_definition is deliberately NOT
    // dispatched — namespace names are not classes (see process_node).

    LanguageProfile {
        node_map: map,
        semantics: Box::new(CppSemantics),
    }
}
