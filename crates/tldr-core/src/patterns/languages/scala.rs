use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};
use crate::types::Evidence;

/// Semantic extractor for Scala.
pub struct ScalaSemantics;

impl LanguageSemantics for ScalaSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_definition" | "object_definition" | "trait_definition" => {
                self.detect_class_like(node, source, file_path, signals)
            }
            "function_definition" => self.detect_function(node, source, file_path, signals),
            "val_definition" => self.detect_val(node, source, file_path, signals),
            "import_declaration" => self.detect_import(node, source, file_path, signals),
            _ => {}
        }
    }
}

impl ScalaSemantics {
    fn detect_class_like(
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
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            let case = detect_naming_case(&name);
            signals.naming.function_names.push((
                name.clone(),
                case,
                file_path.display().to_string(),
                node.start_position().row as u32 + 1,
            ));
            if name.starts_with("test") {
                signals.test_idioms.test_function_count += 1;
            }
        }
    }

    fn detect_val(&self, node: Node, source: &str, file_path: &Path, signals: &mut PatternSignals) {
        let text = node_text(node, source);
        if text.starts_with("val ") {
            let name = text
                .trim_start_matches("val ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(':')
                .to_string();
            if !name.is_empty() {
                let case = detect_naming_case(&name);
                signals
                    .naming
                    .constant_names
                    .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
            }
        }
    }

    fn detect_import(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let text = node_text(node, source);
        let module = text
            .trim_start_matches("import")
            .trim()
            .trim_end_matches(';')
            .to_string();
        if !module.is_empty() {
            signals
                .import_patterns
                .absolute_imports
                .push((module, file_path.display().to_string()));
        }

        // R7 cluster[9] #226: a Scala wildcard import (`import x._`) is a
        // star import. tree-sitter-scala exposes the trailing `_` as a
        // `namespace_wildcard` child of the `import_declaration`. A
        // SELECTIVE brace import (`import x.{a, b}`) produces a
        // `namespace_selectors` child instead and is NOT a star import, so
        // we match strictly on `namespace_wildcard` (AST node kind, not a
        // substring of the raw text). Pre-fix scala.rs only filled
        // `absolute_imports` and never surfaced star_imports, so a repo
        // with hundreds of `import zio._` lines reported `star_imports:
        // none`.
        if subtree_has_kind(node, "namespace_wildcard") {
            let line = node.start_position().row as u32 + 1;
            let snippet = text.lines().next().unwrap_or(&text).to_string();
            signals
                .import_patterns
                .star_imports
                .push(Evidence::new(file_path.display().to_string(), line, snippet));
        }
    }
}

/// True when `node` (or any descendant) has the given tree-sitter kind.
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

/// Build the Scala language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("object_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("trait_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("val_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_expression",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map.dispatch
        .insert("import_declaration", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(ScalaSemantics),
    }
}
