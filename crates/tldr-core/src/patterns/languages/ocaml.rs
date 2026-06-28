use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};

/// Semantic extractor for OCaml.
pub struct OcamlSemantics;

impl LanguageSemantics for OcamlSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "let_binding" | "value_definition" => {
                self.detect_let_binding(node, source, file_path, signals)
            }
            "module_definition" | "module_binding" => {
                self.detect_module(node, source, file_path, signals)
            }
            "module_type_definition" => {
                self.detect_module_type(node, source, file_path, signals)
            }
            "open_statement" => self.detect_open(node, source, file_path, signals),
            "source_file" | "implementation" | "compilation_unit" => {
                self.detect_open_lines(source, file_path, signals)
            }
            _ => {}
        }
    }
}

impl OcamlSemantics {
    fn detect_let_binding(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let mut cursor = node.walk();
        let has_params = node.child_by_field_name("parameter").is_some()
            || node
                .children(&mut cursor)
                .any(|c| c.kind() == "parameter" || c.kind() == "fun_expression");

        if has_params {
            if let Some(pattern_node) = node.child_by_field_name("pattern") {
                let raw_name = node_text(pattern_node, source);
                let name = raw_name
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !name.is_empty() {
                    let case = detect_naming_case(&name);
                    signals.naming.function_names.push((
                name.clone(),
                case,
                file_path.display().to_string(),
                node.start_position().row as u32 + 1,
            ));
                    if name.starts_with("test_") {
                        signals.test_idioms.test_function_count += 1;
                    }
                }
            }
        }
    }

    fn detect_module(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        // A `module_definition` wraps a `module_binding`. Resolve the
        // binding so we can inspect its `module_name` / `module_parameter`
        // / `module_application` children uniformly regardless of which
        // node the walker handed us.
        let binding = if node.kind() == "module_binding" {
            Some(node)
        } else {
            first_child_of_kind(node, "module_binding")
        };

        let (name, name_line) = match binding.and_then(|b| module_binding_name(b, source)) {
            Some(pair) => pair,
            None => {
                // Defensive fallback: pull the first identifier-ish token.
                let text = node_text(node, source);
                let name = text
                    .trim_start_matches("module ")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('=')
                    .to_string();
                if name.is_empty() {
                    return;
                }
                (name, node.start_position().row as u32 + 1)
            }
        };

        // bug5-patterns-ocaml-struct: same keyword-leak guard as
        // `detect_module_type`. Under tree-sitter error recovery a reserved
        // keyword token (`struct`, `sig`, `end`, …) can surface in a name
        // field; a keyword is never a legal module identifier, so never
        // record it as a class name / functor subject.
        if is_ocaml_keyword(&name) {
            return;
        }

        let case = detect_naming_case(&name);
        signals.naming.class_names.push((
            name.clone(),
            case,
            file_path.display().to_string(),
            name_line,
        ));

        let file = file_path.display().to_string();
        let line = node.start_position().row as u32 + 1;

        if let Some(b) = binding {
            // pack-patterns-v1: a `module_parameter` child makes this
            // binding a FUNCTOR — a module parameterised by another
            // module, the OCaml analogue of a generic/template type.
            let is_functor = first_child_of_kind(b, "module_parameter").is_some();
            if is_functor {
                let params = collect_module_parameters(b, source);
                signals.design_patterns.push_pattern(
                    "Functor",
                    "module",
                    "ocaml",
                    name.clone(),
                    file.clone(),
                    line,
                    format!(
                        "module `{name}` is a functor parameterised by ({})",
                        params.join(", ")
                    ),
                );
            }

            // A `module_application` body (e.g. `module IntSet = Make(Int)`)
            // is a FUNCTOR INSTANTIATION — applying a functor to a concrete
            // module argument.
            if let Some(app) = first_child_of_kind(b, "module_application") {
                if let Some(applied) = module_application_target(app, source) {
                    signals.design_patterns.push_pattern(
                        "FunctorApplication",
                        "module",
                        "ocaml",
                        name.clone(),
                        file.clone(),
                        line,
                        format!("module `{name}` instantiates functor `{applied}`"),
                    );
                }
            }
        }
    }

    /// pack-patterns-v1: a `module_type_definition` (`module type S = sig
    /// … end`) is OCaml's interface / signature idiom — the structural
    /// analogue of an interface or typeclass. We surface it as a
    /// `ModuleSignature` design pattern.
    fn detect_module_type(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let name = match first_child_of_kind(node, "module_type_name") {
            Some(n) => node_text(n, source),
            None => return,
        };
        // bug5-patterns-ocaml-struct: tree-sitter-ocaml 0.24.2 cannot fully
        // model `module type of struct … end`; under error recovery it
        // misparses the head as a `module_type_definition` whose
        // `module_type_name` is the literal keyword `struct` (with an
        // `ERROR` "of" sibling and no `signature` body). A reserved keyword
        // is never a legal module-type identifier, so reject it rather than
        // mint a bogus `ModuleSignature` + `struct`-named naming violation.
        if name.is_empty() || is_ocaml_keyword(&name) {
            return;
        }
        let file = file_path.display().to_string();
        let line = node.start_position().row as u32 + 1;

        let case = detect_naming_case(&name);
        signals
            .naming
            .class_names
            .push((name.clone(), case, file.clone(), line));

        signals.design_patterns.push_pattern(
            "ModuleSignature",
            "module",
            "ocaml",
            name.clone(),
            file,
            line,
            format!("module type `{name}` declares a signature (interface)"),
        );
    }

    fn detect_open(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let text = node_text(node, source);
        let module = text.trim_start_matches("open ").trim().to_string();
        if !module.is_empty() {
            signals
                .import_patterns
                .absolute_imports
                .push((module, file_path.display().to_string()));
        }
    }

    fn detect_open_lines(&self, source: &str, file_path: &Path, signals: &mut PatternSignals) {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("open ") {
                let module = trimmed.trim_start_matches("open ").trim().to_string();
                if !module.is_empty() {
                    signals
                        .import_patterns
                        .absolute_imports
                        .push((module, file_path.display().to_string()));
                }
            }
        }
    }
}

/// True when `name` is an OCaml reserved keyword.
///
/// bug5-patterns-ocaml-struct: tree-sitter-ocaml cannot fully model some
/// constructs (notably `module type of struct … end`). Under error
/// recovery it can splice a bare keyword token into a `module_name` /
/// `module_type_name` field, which would otherwise be reported as a real
/// module / module-type declaration. No OCaml module or module-type
/// identifier may be a reserved keyword, so this lets the extractors
/// reject such error-recovery artifacts at the source. The list is the
/// full OCaml reserved-word set (manual §11.1) so the guard generalises
/// to every keyword that could leak, not just `struct`.
fn is_ocaml_keyword(name: &str) -> bool {
    matches!(
        name,
        "and" | "as"
            | "assert"
            | "asr"
            | "begin"
            | "class"
            | "constraint"
            | "do"
            | "done"
            | "downto"
            | "else"
            | "end"
            | "exception"
            | "external"
            | "false"
            | "for"
            | "fun"
            | "function"
            | "functor"
            | "if"
            | "in"
            | "include"
            | "inherit"
            | "initializer"
            | "land"
            | "lazy"
            | "let"
            | "lor"
            | "lsl"
            | "lsr"
            | "lxor"
            | "match"
            | "method"
            | "mod"
            | "module"
            | "mutable"
            | "new"
            | "nonrec"
            | "object"
            | "of"
            | "open"
            | "or"
            | "private"
            | "rec"
            | "sig"
            | "struct"
            | "then"
            | "to"
            | "true"
            | "try"
            | "type"
            | "val"
            | "virtual"
            | "when"
            | "while"
            | "with"
    )
}

/// First direct child of `node` whose kind equals `kind`.
fn first_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == kind);
    found
}

/// Resolve a `module_binding`'s name (the `module_name` child) and its
/// 1-based line.
fn module_binding_name(binding: Node, source: &str) -> Option<(String, u32)> {
    let name_node = first_child_of_kind(binding, "module_name")?;
    let name = node_text(name_node, source);
    if name.is_empty() {
        return None;
    }
    Some((name, name_node.start_position().row as u32 + 1))
}

/// Collect the parameter module names from a functor's `module_parameter`
/// children (e.g. `(Ord : COMPARABLE)` -> `Ord`).
fn collect_module_parameters(binding: Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if child.kind() == "module_parameter" {
            if let Some(pname) = first_child_of_kind(child, "module_name") {
                out.push(node_text(pname, source));
            }
        }
    }
    out
}

/// The functor being applied in a `module_application` (`Make (…)` ->
/// `Make`), read from the leading `module_path` / `module_name`.
fn module_application_target(app: Node, source: &str) -> Option<String> {
    if let Some(path) = first_child_of_kind(app, "module_path") {
        if let Some(name) = first_child_of_kind(path, "module_name") {
            return Some(node_text(name, source));
        }
        return Some(node_text(path, source));
    }
    first_child_of_kind(app, "module_name").map(|n| node_text(n, source))
}

/// Build the OCaml language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("let_binding", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("value_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("module_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("module_binding", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("module_type_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_expression",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map.dispatch
        .insert("open_statement", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("source_file", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("implementation", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("compilation_unit", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(OcamlSemantics),
    }
}
