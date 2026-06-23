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
            "function_call" | "call" | "call_expression" => {
                self.detect_call_like(node, source, file_path, signals)
            }
            _ => {}
        }
    }

    fn process_call(
        &self,
        call_id: &str,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let call_text = node_text(node, source);
        match call_id {
            "require" => {
                if let Some(module) = extract_string_arg(&call_text) {
                    signals
                        .import_patterns
                        .absolute_imports
                        .push((module, file_path.display().to_string()));
                }
            }
            "pcall" | "xpcall" => {
                let evidence = create_evidence_from(node, source, file_path);
                signals.error_handling.try_catch_blocks.push(evidence);
            }
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
        // T4 (v0.5.0 AUDIT-FIX): extract the function/method name from the
        // AST, not by whitespace-splitting the declaration text. The
        // tldr Lua grammar models `function_declaration` with the name as
        // either a direct `identifier` (plain/local functions), a
        // `dot_index_expression` (`function Bar.helperFn()`), or a
        // `method_index_expression` (`function Foo:doThing()`). The
        // grammar exposes NO `name` field on these, so the previous
        // `child_by_field_name("name")` always missed and the text
        // fallback captured the receiver-prefixed token `Foo:doThing`,
        // which `detect_naming_case` then mis-read as PascalCase (the
        // uppercase receiver `Foo`). That mis-attribution swung
        // luau-roact's whole naming convention to `pascal_case`.
        //
        // For the index-expression shapes we take the LAST `identifier`
        // child — the method/function segment — mirroring the receiver
        // handling already used in `analysis::references` /
        // `analysis::impact`.
        let name = self
            .extract_function_name(node, source)
            .unwrap_or_default();

        if !name.is_empty() {
            let case = detect_naming_case(&name);
            signals
                .naming
                .function_names
                .push((name, case, file_path.display().to_string(), node.start_position().row as u32 + 1));
        }
    }

    /// AST-driven name extraction for a Lua `function_declaration` /
    /// `local_function`. Returns the bare method/function identifier:
    /// the trailing `identifier` of a `dot_index_expression` /
    /// `method_index_expression`, or the direct `identifier` child.
    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        let mut cursor = node.walk();
        let mut result = None;
        for child in node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    result = Some(node_text(child, source));
                    break;
                }
                "dot_index_expression" | "method_index_expression" => {
                    result = last_identifier(child, source);
                    break;
                }
                _ => {}
            }
        }
        result
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

/// Return the text of the LAST `identifier` directly under `node`.
///
/// For a Lua `dot_index_expression` (`Bar.helperFn`) or
/// `method_index_expression` (`Foo:doThing`) the structure is
/// `identifier <sep> identifier`, so the trailing identifier is the
/// field/method name. Used to strip the receiver from a qualified
/// function-definition name (T4, v0.5.0 AUDIT-FIX).
fn last_identifier(node: Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let mut last = None;
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            last = Some(node_text(child, source));
        }
    }
    last
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
    map.dispatch
        .insert("call", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("call_expression", vec![SignalAction::CallSemantics]);

    map.call_dispatch
        .insert("require", vec![SignalAction::CallSemantics]);
    map.call_dispatch
        .insert("pcall", vec![SignalAction::CallSemantics]);
    map.call_dispatch
        .insert("xpcall", vec![SignalAction::CallSemantics]);

    LanguageProfile {
        node_map: map,
        semantics: Box::new(LuaSemantics),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::ParserPool;
    use crate::patterns::detector::PatternDetector;
    use crate::patterns::signals::NamingCase;
    use crate::types::Language;
    use std::path::PathBuf;

    fn function_names(src: &str) -> Vec<(String, NamingCase)> {
        let pool = ParserPool::new();
        let tree = pool.parse(src, Language::Lua).expect("parse lua");
        let detector = PatternDetector::new(Language::Lua, PathBuf::from("x.lua"));
        let signals = detector.detect_all(&tree, src);
        signals
            .naming
            .function_names
            .iter()
            .map(|(n, c, _, _)| (n.clone(), *c))
            .collect()
    }

    /// T4 (v0.5.0 AUDIT-FIX): `function Foo:doThing()` must record the
    /// METHOD part (`doThing`) as the function name, analyzed as
    /// camelCase — NOT the whole `Foo:doThing` token (which the
    /// whitespace-split fallback produced and which `detect_naming_case`
    /// mis-classified as PascalCase because the receiver `Foo` is
    /// uppercase). The AST shape is
    /// `function_declaration > method_index_expression(identifier ":" identifier)`.
    #[test]
    fn test_colon_method_name_split_to_method_part() {
        let names = function_names("function Foo:doThing(x)\n  return x\nend\n");
        assert_eq!(
            names,
            vec![("doThing".to_string(), NamingCase::CamelCase)],
            "colon-method must be recorded as its method segment (camelCase), \
             not the receiver-prefixed token"
        );
    }

    /// T4: dotted definition `function Bar.helperFn()` must likewise
    /// record `helperFn` (the trailing segment), via the
    /// `dot_index_expression` arm.
    #[test]
    fn test_dot_method_name_split_to_last_segment() {
        let names = function_names("function Bar.helperFn(y)\n  return y\nend\n");
        assert_eq!(
            names,
            vec![("helperFn".to_string(), NamingCase::CamelCase)],
        );
    }

    /// T4: plain global and local functions are unaffected (direct
    /// `identifier` child) — regression guard for the split logic.
    #[test]
    fn test_plain_and_local_function_names_preserved() {
        let names = function_names(
            "local function localOne()\nend\nfunction plainGlobal()\nend\n",
        );
        assert_eq!(
            names,
            vec![
                ("localOne".to_string(), NamingCase::CamelCase),
                ("plainGlobal".to_string(), NamingCase::CamelCase),
            ],
        );
    }
}
