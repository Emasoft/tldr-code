use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    create_evidence_from, node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics,
    SignalAction,
};
use super::super::signals::{detect_naming_case, PatternSignals};

/// Semantic extractor for Lua/Luau.
pub struct LuaSemantics;

impl LanguageSemantics for LuaSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "function_declaration" | "local_function" => {
                self.detect_function(node, source, file_path, signals)
            }
            // why: both tree-sitter-lua and tree-sitter-luau only ever emit
            // "function_call" for call expressions (verified against each
            // grammar's node-types.json); "call"/"call_expression" never
            // occur, so the dead `process_call`/call_dispatch path that used
            // to key off them was removed rather than left unreachable.
            "function_call" => self.detect_call_like(node, source, file_path, signals),
            _ => {}
        }
    }
}

impl LuaSemantics {
    fn detect_function(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let name = if let Some(name_node) = node.child_by_field_name("name") {
            node_text(name_node, source)
        } else {
            let text = node_text(node, source);
            text.split_whitespace()
                .nth(1)
                .unwrap_or("")
                .split('(')
                .next()
                .unwrap_or("")
                .to_string()
        };

        if !name.is_empty() {
            let case = detect_naming_case(&name);
            signals
                .naming
                .function_names
                .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
        }
    }

    fn detect_call_like(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let call_text = node_text(node, source);
        if call_text.contains("require(") {
            if let Some(module) = extract_string_arg(&call_text) {
                signals
                    .import_patterns
                    .absolute_imports
                    .push((module, file_path.display().to_string()));
            }
        }
        if call_text.contains("pcall(") || call_text.contains("xpcall(") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.error_handling.try_catch_blocks.push(evidence);
        }
    }
}

fn extract_string_arg(call_text: &str) -> Option<String> {
    if let Some(start) = call_text.find('\'') {
        let rest = &call_text[start + 1..];
        if let Some(end) = rest.find('\'') {
            return Some(rest[..end].to_string());
        }
    }
    if let Some(start) = call_text.find('"') {
        let rest = &call_text[start + 1..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Build the Lua/Luau language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("function_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("local_function", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_call", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(LuaSemantics),
    }
}
