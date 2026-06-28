//! Language profile definitions for data-driven pattern detection.
//!
//! Each language is represented by a `LanguageProfile` that bundles:
//! - A `LanguageNodeMap`: FxHashMap mapping node-type strings to signal actions
//! - A `LanguageSemantics` trait impl: behavioral extraction for complex patterns
//!
//! The generic walker calls `profile.process_node()` for each AST node.
//! The profile handles all dispatch internally.

use std::path::Path;

use rustc_hash::FxHashMap;
use tree_sitter::Node;

use super::languages;
use super::signals::*;
use crate::types::Evidence;

/// What signal target to push evidence to when a node matches.
#[derive(Debug, Clone)]
pub enum SignalTarget {
    /// Python-style try/except evidence.
    TryExceptBlocks,
    /// Try/catch evidence.
    TryCatchBlocks,
    /// Rust `?` usage evidence.
    QuestionMarkOps,
    /// Go `err ==/!= nil` checks.
    ErrNilChecks,
    /// Context manager evidence.
    ContextManagers,
    /// Deferred cleanup evidence.
    DeferStatements,
    /// Try/finally evidence.
    TryFinallyBlocks,
    /// Async/await evidence.
    AsyncAwait,
    /// Goroutine evidence.
    Goroutines,
    /// Assert statement evidence.
    AssertStatements,
}

/// What naming target to extract a name into.
#[derive(Debug, Clone)]
pub enum NamingTarget {
    /// Function name collection.
    FunctionNames,
    /// Class/module name collection.
    ClassNames,
    /// Constant name collection.
    ConstantNames,
}

/// Actions executed when a node type matches in `LanguageNodeMap`.
#[derive(Debug, Clone)]
pub enum SignalAction {
    /// Tier 1: Unconditionally push evidence to a signal target.
    PushEvidence(SignalTarget),
    /// Tier 1: Extract a name from a child field.
    ExtractNamed {
        /// Tree-sitter field name for the identifier node.
        name_field: &'static str,
        /// Target naming bucket.
        target: NamingTarget,
    },
    /// Tier 2/3: Delegate complex extraction to semantics.
    CallSemantics,
}

/// Try style used by a language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryTarget {
    /// Languages that model exceptions via try/except.
    TryExcept,
    /// Languages that model exceptions via try/catch.
    TryCatch,
}

/// Pure-data dispatch table mapping node-type strings to signal actions.
pub struct LanguageNodeMap {
    /// Primary dispatch: node_type -> actions.
    pub dispatch: FxHashMap<&'static str, Vec<SignalAction>>,
    /// Secondary dispatch for call-like nodes: call_identifier -> actions.
    pub call_dispatch: FxHashMap<&'static str, Vec<SignalAction>>,
}

impl LanguageNodeMap {
    /// Construct an empty dispatch map.
    pub fn new() -> Self {
        Self {
            dispatch: FxHashMap::default(),
            call_dispatch: FxHashMap::default(),
        }
    }
}

impl Default for LanguageNodeMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Behavioral extraction trait for language-specific logic.
pub trait LanguageSemantics: Send + Sync {
    /// Process a node that was flagged as needing semantic extraction.
    fn process_node(
        &self,
        _node: Node,
        _node_type: &str,
        _source: &str,
        _file_path: &Path,
        _signals: &mut PatternSignals,
    ) {
    }

    /// Process a call node that matched in `call_dispatch`.
    fn process_call(
        &self,
        _call_id: &str,
        _node: Node,
        _source: &str,
        _file_path: &Path,
        _signals: &mut PatternSignals,
    ) {
    }

    /// Return language-specific try target.
    fn try_target(&self) -> TryTarget {
        TryTarget::TryCatch
    }
}

/// A complete language profile: data table + behavioral trait implementation.
pub struct LanguageProfile {
    /// Node dispatch table.
    pub node_map: LanguageNodeMap,
    /// Language-specific semantic extractor.
    pub semantics: Box<dyn LanguageSemantics>,
}

impl LanguageProfile {
    /// Single dispatch point used by the generic walker.
    pub fn process_node(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let node_type = node.kind();

        if let Some(actions) = self.node_map.dispatch.get(node_type) {
            let mut needs_semantics = false;

            for action in actions {
                match action {
                    SignalAction::PushEvidence(target) => {
                        let evidence = create_evidence_from(node, source, file_path);
                        push_evidence(target, &evidence, signals);
                    }
                    SignalAction::ExtractNamed { name_field, target } => {
                        if let Some(name_node) = node.child_by_field_name(name_field) {
                            let name = node_text(name_node, source);
                            let case = detect_naming_case(&name);
                            let file = file_path.display().to_string();
                            let line = name_node.start_position().row as u32 + 1;
                            push_named(target, name, case, file, line, signals);
                        }
                    }
                    SignalAction::CallSemantics => {
                        needs_semantics = true;
                    }
                }
            }

            if needs_semantics {
                self.semantics
                    .process_node(node, node_type, source, file_path, signals);
            }
        }

        if !self.node_map.call_dispatch.is_empty() && is_call_node(node_type) {
            if let Some(call_id) = extract_call_identifier(node, source) {
                if let Some(actions) = self.node_map.call_dispatch.get(call_id.as_str()) {
                    let mut needs_call_semantics = false;

                    for action in actions {
                        match action {
                            SignalAction::PushEvidence(target) => {
                                let evidence = create_evidence_from(node, source, file_path);
                                push_evidence(target, &evidence, signals);
                            }
                            SignalAction::ExtractNamed { name_field, target } => {
                                if let Some(name_node) = node.child_by_field_name(name_field) {
                                    let name = node_text(name_node, source);
                                    let case = detect_naming_case(&name);
                                    let file = file_path.display().to_string();
                                    let line =
                                        name_node.start_position().row as u32 + 1;
                                    push_named(
                                        target, name, case, file, line, signals,
                                    );
                                }
                            }
                            SignalAction::CallSemantics => {
                                needs_call_semantics = true;
                            }
                        }
                    }

                    if needs_call_semantics {
                        self.semantics
                            .process_call(&call_id, node, source, file_path, signals);
                    }
                }
            }
        }
    }
}

/// No-op semantics for languages that only need data-driven dispatch.
pub struct NoopSemantics;

impl LanguageSemantics for NoopSemantics {}

/// Extract text from a node.
pub fn node_text(node: Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

/// Create evidence from node location/snippet.
pub fn create_evidence_from(node: Node, source: &str, file_path: &Path) -> Evidence {
    let line = node.start_position().row as u32 + 1;
    let snippet = get_snippet(node, source);
    Evidence::new(file_path.display().to_string(), line, snippet)
}

fn get_snippet(node: Node, source: &str) -> String {
    let start_line = node.start_position().row;
    let lines: Vec<&str> = source.lines().collect();
    let end_line = (start_line + 3).min(lines.len());
    lines[start_line..end_line].join("\n")
}

fn push_evidence(target: &SignalTarget, evidence: &Evidence, signals: &mut PatternSignals) {
    match target {
        SignalTarget::TryExceptBlocks => signals
            .error_handling
            .try_except_blocks
            .push(evidence.clone()),
        SignalTarget::TryCatchBlocks => signals
            .error_handling
            .try_catch_blocks
            .push(evidence.clone()),
        SignalTarget::QuestionMarkOps => signals
            .error_handling
            .question_mark_ops
            .push(evidence.clone()),
        SignalTarget::ErrNilChecks => signals.error_handling.err_nil_checks.push(evidence.clone()),
        SignalTarget::ContextManagers => signals
            .resource_management
            .context_managers
            .push(evidence.clone()),
        SignalTarget::DeferStatements => signals
            .resource_management
            .defer_statements
            .push(evidence.clone()),
        SignalTarget::TryFinallyBlocks => signals
            .resource_management
            .try_finally_blocks
            .push(evidence.clone()),
        SignalTarget::AsyncAwait => signals.async_patterns.async_await.push(evidence.clone()),
        SignalTarget::Goroutines => signals.async_patterns.goroutines.push(evidence.clone()),
        SignalTarget::AssertStatements => {
            signals.validation.assert_statements.push(evidence.clone())
        }
    }
}

fn push_named(
    target: &NamingTarget,
    name: String,
    case: NamingCase,
    file: String,
    line: u32,
    signals: &mut PatternSignals,
) {
    match target {
        NamingTarget::FunctionNames => signals
            .naming
            .function_names
            .push((name, case, file, line)),
        NamingTarget::ClassNames => signals.naming.class_names.push((name, case, file, line)),
        NamingTarget::ConstantNames => signals
            .naming
            .constant_names
            .push((name, case, file, line)),
    }
}

fn is_call_node(node_type: &str) -> bool {
    matches!(node_type, "call" | "call_expression")
}

fn extract_call_identifier(node: Node, source: &str) -> Option<String> {
    if let Some(func_node) = node.child_by_field_name("function") {
        if func_node.kind() == "identifier" || func_node.kind() == "atom" {
            return Some(node_text(func_node, source));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "atom" {
            return Some(node_text(child, source));
        }
        if child.is_named() {
            break;
        }
    }
    None
}

/// Generic type-pattern detection helper shared by language semantics.
pub fn detect_generic_patterns(type_text: &str, file_path: &Path, signals: &mut PatternSignals) {
    let common_generics = [
        "Optional", "List", "Dict", "Set", "Tuple", "Union", "Callable", "Iterator",
    ];
    for pattern in &common_generics {
        if type_text.contains(pattern) {
            signals
                .type_coverage
                .generic_patterns
                .insert(pattern.to_string());
        }
    }

    if type_text.contains("TypeVar") || type_text.contains("Generic[") {
        let evidence = Evidence::new(file_path.display().to_string(), 0, type_text.to_string());
        signals.type_coverage.generic_usage.push(evidence);
    }
}

/// Extract module name from TS/JS import text.
pub fn extract_import_module(import_text: &str) -> String {
    let re = regex::Regex::new(r#"from\s+['"]([^'"]+)['"]"#).unwrap();
    if let Some(caps) = re.captures(import_text) {
        return caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
    }
    String::new()
}

/// Python-specific semantic extraction.
pub struct PythonSemantics;

impl LanguageSemantics for PythonSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_definition" => self.detect_class(node, source, file_path, signals),
            "function_definition" => self.detect_function(node, source, file_path, signals),
            "decorator" => self.detect_decorator(node, source, file_path, signals),
            "assignment" | "typed_assignment" | "augmented_assignment" => {
                self.detect_assignment(node, source, file_path, signals)
            }
            "import_statement" | "import_from_statement" => {
                self.detect_import(node, source, file_path, signals)
            }
            "call" => self.detect_call(node, source, file_path, signals),
            _ => {}
        }
    }

    fn try_target(&self) -> TryTarget {
        TryTarget::TryExcept
    }
}

impl PythonSemantics {
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
                .push((name.clone(), case, file_path.display().to_string(), name_node.start_position().row as u32 + 1));

            if name.ends_with("Error") || name.ends_with("Exception") {
                let evidence = create_evidence_from(node, source, file_path);
                signals
                    .error_handling
                    .custom_exceptions
                    .push((name, evidence));
            }
        }

        if let Some(bases) = node.child_by_field_name("superclasses") {
            let bases_text = node_text(bases, source);
            if bases_text.contains("BaseModel") {
                let evidence = create_evidence_from(node, source, file_path);
                signals.validation.pydantic_models.push(evidence);
            }
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
                name_node.start_position().row as u32 + 1,
            ));

            if name.starts_with("test_") || name.starts_with("test") {
                signals.test_idioms.test_function_count += 1;
                if signals.test_idioms.detected_framework.is_none() {
                    signals.test_idioms.detected_framework = Some("pytest".to_string());
                }
            }

            if name == "__enter__" || name == "__exit__" {
                let evidence = create_evidence_from(node, source, file_path);
                signals
                    .resource_management
                    .enter_exit_methods
                    .push(evidence);
            }

            if name.starts_with('_') && !name.starts_with("__") {
                *signals
                    .naming
                    .private_prefixes
                    .entry("_".to_string())
                    .or_insert(0) += 1;
            }
        }

        if let Some(params) = node.child_by_field_name("parameters") {
            self.detect_param_types(params, source, file_path, signals);
        }

        if let Some(return_type) = node.child_by_field_name("return_type") {
            signals.type_coverage.typed_returns += 1;
            let return_text = node_text(return_type, source);
            detect_generic_patterns(&return_text, file_path, signals);
        } else {
            signals.type_coverage.untyped_returns += 1;
        }

        let fn_text = node_text(node, source);
        if fn_text.starts_with("async ") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.async_patterns.async_await.push(evidence);
        }
    }

    fn detect_param_types(
        &self,
        params: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let mut cursor = params.walk();
        for child in params.children(&mut cursor) {
            match child.kind() {
                "typed_parameter" | "typed_default_parameter" => {
                    signals.type_coverage.typed_params += 1;
                    let param_text = node_text(child, source);
                    detect_generic_patterns(&param_text, file_path, signals);
                }
                "identifier" | "default_parameter" => {
                    let name = node_text(child, source);
                    if name != "self" && name != "cls" {
                        signals.type_coverage.untyped_params += 1;
                    }
                }
                _ => {}
            }
        }
    }

    fn detect_decorator(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let dec_text = node_text(node, source);

        if dec_text.contains("pytest.fixture") || dec_text.contains("@fixture") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.test_idioms.pytest_fixtures.push(evidence);
            signals.test_idioms.detected_framework = Some("pytest".to_string());
        }

        if dec_text.contains("mock.patch") || dec_text.contains("@patch") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.test_idioms.mock_patches.push(evidence);
        }

        if dec_text.contains("@app.get")
            || dec_text.contains("@app.post")
            || dec_text.contains("@app.put")
            || dec_text.contains("@app.delete")
            || dec_text.contains("@router.")
        {
            let evidence = create_evidence_from(node, source, file_path);
            signals.api_conventions.fastapi_decorators.push(evidence);
        }

        if dec_text.contains("@app.route") || dec_text.contains("@blueprint.route") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.api_conventions.flask_decorators.push(evidence);
        }
    }

    fn detect_assignment(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let assignment_text = node_text(node, source);

        if assignment_text.contains("is_deleted") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.is_deleted_fields.push(evidence);
        }

        if assignment_text.contains("deleted_at") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.deleted_at_fields.push(evidence);
        }

        if let Some(left) = node.child_by_field_name("left") {
            let name = node_text(left, source);
            let case = detect_naming_case(&name);
            // language-coverage-fixes-v1 (P4.BUG-N4): also accept
            // `UpperAlpha` (single uppercase word, e.g. `KEY`, `URL`)
            // as a constant. The new `detect_naming_case` only emits
            // `UpperSnakeCase` when the name actually contains an
            // underscore.
            if case == NamingCase::UpperSnakeCase || case == NamingCase::UpperAlpha {
                signals.naming.constant_names.push((
                    name,
                    case,
                    file_path.display().to_string(),
                    left.start_position().row as u32 + 1,
                ));
            }
        }

        if node.kind() == "typed_assignment" {
            signals.type_coverage.typed_variables += 1;
        }
    }

    fn detect_import(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let import_text = node_text(node, source);

        if import_text.starts_with("from .") {
            let module = import_text
                .trim_start_matches("from ")
                .split_whitespace()
                .next()
                .unwrap_or("");
            signals
                .import_patterns
                .relative_imports
                .push((module.to_string(), file_path.display().to_string()));
        } else {
            let module = if import_text.starts_with("import ") {
                import_text
                    .trim_start_matches("import ")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
            } else if import_text.starts_with("from ") {
                import_text
                    .trim_start_matches("from ")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
            } else {
                ""
            };
            if !module.is_empty() {
                signals
                    .import_patterns
                    .absolute_imports
                    .push((module.to_string(), file_path.display().to_string()));
            }
        }

        if import_text.contains("import *") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.import_patterns.star_imports.push(evidence);
        }

        if import_text.contains(" as ") {
            let parts: Vec<&str> = import_text.split(" as ").collect();
            if parts.len() == 2 {
                let module = parts[0].split_whitespace().last().unwrap_or("");
                let alias = parts[1].split_whitespace().next().unwrap_or("");
                signals
                    .import_patterns
                    .aliases
                    .insert(module.to_string(), alias.to_string());
            }
        }
    }

    fn detect_call(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let call_text = node_text(node, source);

        if call_text.starts_with("isinstance(") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.validation.type_checks.push(evidence);
        }

        if call_text.ends_with(".close()") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.resource_management.close_calls.push(evidence);
        }
    }
}

/// TypeScript/JavaScript semantic extraction.
pub struct TypeScriptSemantics;

impl LanguageSemantics for TypeScriptSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_declaration" | "abstract_class_declaration" => {
                self.detect_class(node, source, file_path, signals);
            }
            "function_declaration" | "arrow_function" | "method_definition" => {
                self.detect_function(node, source, file_path, signals);
            }
            "try_statement" => {
                let node_text = node_text(node, source);
                if node_text.contains("finally") {
                    let evidence = create_evidence_from(node, source, file_path);
                    signals
                        .resource_management
                        .try_finally_blocks
                        .push(evidence);
                }
            }
            "interface_declaration" => {
                self.detect_interface(node, source, file_path, signals);
            }
            "variable_declaration" | "lexical_declaration" => {
                self.detect_variable(node, source, file_path, signals);
            }
            "call_expression" => {
                self.detect_call(node, source, file_path, signals);
            }
            "import_statement" => {
                self.detect_import(node, source, file_path, signals);
            }
            // fix-CF1-S20: Express detection is resolved once per file at the
            // module root (`program`). The import gate has to be visible to
            // *every* route member-call in the file regardless of source
            // order, which a per-call pass cannot guarantee — so the whole
            // file is reasoned about structurally from the root.
            "program" => {
                self.detect_express(node, source, file_path, signals);
            }
            _ => {}
        }
    }
}

impl TypeScriptSemantics {
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
                .push((name.clone(), case, file_path.display().to_string(), name_node.start_position().row as u32 + 1));

            if name.ends_with("Error") || name.ends_with("Exception") {
                let evidence = create_evidence_from(node, source, file_path);
                signals
                    .error_handling
                    .custom_exceptions
                    .push((name, evidence));
            }
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
                name_node.start_position().row as u32 + 1,
            ));

            if name.starts_with("test") || name.starts_with("it") {
                signals.test_idioms.test_function_count += 1;
            }
        }

        let fn_text = node_text(node, source);
        if fn_text.starts_with("async ") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.async_patterns.async_await.push(evidence);
        }

        if let Some(return_type) = node.child_by_field_name("return_type") {
            signals.type_coverage.typed_returns += 1;
            let return_text = node_text(return_type, source);
            detect_generic_patterns(&return_text, file_path, signals);
        }
    }

    fn detect_interface(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let iface_text = node_text(node, source);

        if iface_text.contains("isDeleted") || iface_text.contains("is_deleted") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.is_deleted_fields.push(evidence);
        }
        if iface_text.contains("deletedAt") || iface_text.contains("deleted_at") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.deleted_at_fields.push(evidence);
        }
    }

    fn detect_variable(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let var_text = node_text(node, source);

        if var_text.starts_with("const ") {
            let parts: Vec<&str> = var_text.split('=').collect();
            if let Some(decl) = parts.first() {
                let name = decl
                    .trim()
                    .trim_start_matches("const ")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim();
                let case = detect_naming_case(name);
                // language-coverage-fixes-v1 (P4.BUG-N4): also accept
            // `UpperAlpha` (single uppercase word, e.g. `KEY`, `URL`)
            // as a constant. The new `detect_naming_case` only emits
            // `UpperSnakeCase` when the name actually contains an
            // underscore.
            if case == NamingCase::UpperSnakeCase || case == NamingCase::UpperAlpha {
                    signals.naming.constant_names.push((
                        name.to_string(),
                        case,
                        file_path.display().to_string(),
                        node.start_position().row as u32 + 1,
                    ));
                }
            }
        }

        if var_text.contains("z.object")
            || var_text.contains("z.string")
            || var_text.contains("z.number")
        {
            let evidence = create_evidence_from(node, source, file_path);
            signals.validation.zod_schemas.push(evidence);
        }
    }

    fn detect_call(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let call_text = node_text(node, source);

        if call_text.starts_with("describe(")
            || call_text.starts_with("it(")
            || call_text.starts_with("test(")
        {
            let evidence = create_evidence_from(node, source, file_path);
            signals.test_idioms.jest_blocks.push(evidence);
            signals.test_idioms.detected_framework = Some("jest".to_string());
        }

        // fix-CF1-S20: Express route detection was a substring scan
        // (`.get(` + `req` + `res` anywhere in the call text) that fired on
        // incidental tokens in lodash (`_.get(request, 'a.result')`) and
        // axios (`axios.get(url, { responseType, signal: req.signal })`).
        // It is now a structural member-call match resolved at the module
        // root — see `TypeScriptSemantics::detect_express`.

        if call_text.contains("typeof ") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.validation.type_checks.push(evidence);
        }
    }

    fn detect_import(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let import_text = node_text(node, source);

        if import_text.contains("from './")
            || import_text.contains("from \"./")
            || import_text.contains("from '../")
            || import_text.contains("from \"../")
        {
            let module = extract_import_module(&import_text);
            signals
                .import_patterns
                .relative_imports
                .push((module, file_path.display().to_string()));
        } else if import_text.contains("from '") || import_text.contains("from \"") {
            let module = extract_import_module(&import_text);
            signals
                .import_patterns
                .absolute_imports
                .push((module, file_path.display().to_string()));
        }

        if import_text.contains("* as ") || import_text.contains("import *") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.import_patterns.star_imports.push(evidence);
        }
    }

    /// fix-CF1-S20: structurally decide whether this file is an Express
    /// application and, if so, push route evidence.
    ///
    /// Runs once per file (dispatched on the `program` root). It walks the
    /// AST once collecting two facts:
    ///
    /// * whether the file imports/requires the `express` package
    ///   (`import ... from 'express'` or `require('express')`), and
    /// * every member-call whose method is an Express verb/app method
    ///   (`app.get(...)`, `router.use(...)`, `app.listen(...)`).
    ///
    /// A call is counted as Express evidence when EITHER
    ///
    /// 1. it is an HTTP-verb route call that takes a callback **handler** as a
    ///    direct argument (`app.get('/', (req, res) => …)`) — the unmistakable
    ///    routing idiom that `axios.get(url, config)` and lodash
    ///    `_.get(obj, path)` never exhibit (they pass no handler function), so
    ///    this branch recognises the Express repo's own examples even though
    ///    they `require('../..')` rather than the literal `'express'`; OR
    /// 2. the file actually imports/requires `express` (the import gate) and
    ///    the call is any Express app/router method — this admits
    ///    `app.use(mw)` / `app.listen(port)` which, ungated, are too generic
    ///    (koa/connect/redux also expose `.use`).
    ///
    /// This replaces the previous substring scan, so neither lodash nor axios
    /// (which import neither `express` nor pass route handlers) can match.
    fn detect_express(
        &self,
        root: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let mut imports_express = false;
        // (node, is_handler_route, is_app_method)
        let mut candidates: Vec<(Node, bool, bool)> = Vec::new();
        collect_express_facts(root, source, &mut imports_express, &mut candidates);

        for (node, is_handler_route, is_app_method) in candidates {
            if is_handler_route || (imports_express && is_app_method) {
                let evidence = create_evidence_from(node, source, file_path);
                signals.api_conventions.express_routes.push(evidence);
            }
        }
    }
}

/// HTTP verbs that, as a member-call carrying a callback handler, are the
/// Express routing idiom (`app.get('/', (req, res) => …)`).
const EXPRESS_ROUTE_VERBS: &[&str] =
    &["get", "post", "put", "delete", "patch", "head", "options", "all"];

/// Express app/router methods. Behind the import gate, any of these on a
/// member-call is Express evidence; `use`/`listen`/`route` are included here
/// (not in [`EXPRESS_ROUTE_VERBS`]) because they are too generic to count
/// without an `express` import.
const EXPRESS_APP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "all", "use", "listen", "route",
];

/// Strip a single layer of surrounding JS string quotes (`'`, `"`, or
/// backtick) from `s`. Returns `s` unchanged when it is not quoted.
fn unquote(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        if (first == b'\'' || first == b'"' || first == b'`') && *bytes.last().unwrap() == first {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// The trailing method identifier of a member-call `obj.method(...)`.
///
/// Returns `Some("method")` only when `node` is a `call_expression` whose
/// callee (`function` field) is a `member_expression`; `None` for plain
/// `f(...)` calls or non-calls. Pure tree-sitter node-kind/field walk.
fn member_call_method(node: Node, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() != "member_expression" {
        return None;
    }
    let prop = func.child_by_field_name("property")?;
    Some(node_text(prop, source))
}

/// True when a call node has a function expression as a DIRECT argument
/// (`f(a, (req, res) => …)` / `f(a, function () {})`). A function nested
/// inside an object/array argument (e.g. an axios config `{ onUpload: fn }`)
/// is intentionally NOT matched — only top-level callback handlers count.
fn has_direct_function_argument(node: Node) -> bool {
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let has_fn = args.named_children(&mut cursor).any(|c| {
        matches!(
            c.kind(),
            "arrow_function" | "function" | "function_expression" | "generator_function"
        )
    });
    has_fn
}

/// The module specifier string of an ES `import_statement`, structurally
/// (the lone `string` child) — `import x from 'm'` -> `Some("m")`.
fn es_import_module(node: Node, source: &str) -> Option<String> {
    if node.kind() != "import_statement" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "string" {
            return Some(unquote(node_text(child, source).trim()).to_string());
        }
    }
    None
}

/// The module specifier string of a `require('m')` call, structurally — the
/// callee identifier must be `require` and the first string argument is `m`.
fn require_module(node: Node, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() != "identifier" || node_text(func, source) != "require" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.kind() == "string" {
            return Some(unquote(node_text(child, source).trim()).to_string());
        }
    }
    None
}

/// Single structural walk gathering the Express facts for a file: whether it
/// imports/requires `express`, and every candidate Express member-call tagged
/// with `(is_handler_route, is_app_method)`. See
/// [`TypeScriptSemantics::detect_express`] for how the tags are combined.
fn collect_express_facts<'a>(
    node: Node<'a>,
    source: &str,
    imports_express: &mut bool,
    candidates: &mut Vec<(Node<'a>, bool, bool)>,
) {
    if es_import_module(node, source).as_deref() == Some("express")
        || require_module(node, source).as_deref() == Some("express")
    {
        *imports_express = true;
    }

    if let Some(method) = member_call_method(node, source) {
        let is_handler_route =
            EXPRESS_ROUTE_VERBS.contains(&method.as_str()) && has_direct_function_argument(node);
        let is_app_method = EXPRESS_APP_METHODS.contains(&method.as_str());
        if is_handler_route || is_app_method {
            candidates.push((node, is_handler_route, is_app_method));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_express_facts(child, source, imports_express, candidates);
    }
}

/// Go semantic extraction.
pub struct GoSemantics;

/// pack-patterns-v1: classify a Go function/method name by visibility and
/// return `(actual_case, expected_case)`.
///
/// Go's exported/unexported distinction is purely the first rune's case
/// (Go spec §"Exported identifiers"): an uppercase first rune is
/// exported. The idiomatic convention (`golint`, Effective Go) is:
///
/// - exported  -> PascalCase  (`MixedCaps`)
/// - unexported -> camelCase  (`mixedCaps`)
///
/// We map the detected [`NamingCase`] onto the visibility-appropriate
/// expectation so the caller can decide whether the name is a genuine
/// violation. Single-word names (`New`, `min`, `GET`) come back as
/// `LowerAlpha`/`UpperAlpha`, which the violation emitter already treats
/// as compatible with both adjacent conventions; here we additionally
/// snap them to the visibility-correct expectation so they never count
/// as violations.
///
/// Returns `None` for names with no classifiable first letter (the
/// function never names an empty identifier in practice, but be defensive).
fn go_function_naming(name: &str) -> Option<(NamingCase, NamingCase)> {
    let first = name.trim_start_matches('_').chars().next()?;
    let exported = first.is_ascii_uppercase();
    let expected = if exported {
        NamingCase::PascalCase
    } else {
        NamingCase::CamelCase
    };

    let actual = detect_naming_case(name);
    Some((actual, expected))
}

/// pack-patterns-v1: whether a Go function's detected `actual` case is
/// compatible with its visibility-appropriate `expected` case (and thus
/// NOT a violation). Mirrors `naming::is_compatible` for the degenerate
/// single-word forms, specialised to Go's two valid conventions:
///
/// - exported expects `PascalCase`: a single uppercase word
///   (`UpperAlpha`, e.g. `New`, `GET`) is the pascal-degenerate form and
///   is compatible.
/// - unexported expects `CamelCase`: a single lowercase word
///   (`LowerAlpha`, e.g. `min`, `recv`) is the camel-degenerate form and
///   is compatible.
fn is_go_compatible(actual: NamingCase, expected: NamingCase) -> bool {
    matches!(
        (actual, expected),
        (NamingCase::UpperAlpha, NamingCase::PascalCase)
            | (NamingCase::LowerAlpha, NamingCase::CamelCase)
    )
}

impl LanguageSemantics for GoSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "function_declaration" | "method_declaration" => {
                self.detect_function(node, source, file_path, signals);
            }
            "if_statement" => {
                self.detect_if(node, source, file_path, signals);
            }
            "type_declaration" => {
                self.detect_type(node, source, file_path, signals);
            }
            "const_declaration" => {
                self.detect_const(node, source, file_path, signals);
            }
            _ => {}
        }
    }
}

impl GoSemantics {
    fn detect_function(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);

            if name.starts_with("Test") {
                signals.test_idioms.test_function_count += 1;
                signals.test_idioms.detected_framework = Some("go test".to_string());
            }

            // pack-patterns-v1: Go naming is VISIBILITY-DRIVEN, not a
            // single global convention. Per the Go spec & `gofmt`/`golint`
            // convention, an *exported* identifier (first rune uppercase)
            // is PascalCase ("MixedCaps") and an *unexported* identifier
            // (first rune lowercase) is camelCase ("mixedCaps"). BOTH are
            // correct and coexist in every package. Feeding all funcs into
            // one global-majority bucket flagged whichever visibility group
            // was the minority (e.g. 24 false positives on go-httprouter:
            // every correctly-named unexported camelCase func reported as
            // "expected pascal_case").
            //
            // We drive off the identifier's first-rune case (the AST decl's
            // name) to decide the visibility-appropriate expectation, then:
            //
            //   * record the func in `function_names` normalised to its
            //     visibility-correct case when it MATCHES (so the
            //     project-wide consistency score / majority stay coherent
            //     without spurious cross-visibility violations); and
            //   * emit a DIRECT precomputed violation (bypassing the
            //     meaningless global-majority comparison) when the name is
            //     genuinely WRONG for its visibility class — e.g. an
            //     exported `Bad_Name` (snake_case) or an unexported
            //     `bad_helper` (snake_case). This keeps real violations
            //     visible while eliminating the false positives.
            // Go funcs are deliberately NOT pushed into `function_names`:
            // that bucket is reduced to a SINGLE project-wide majority,
            // which is meaningless for Go's dual visibility-driven
            // conventions and would re-introduce the cross-visibility
            // false positives via `find_violations`. Instead we emit only
            // GENUINE violations (a name whose case is wrong for its own
            // visibility class) directly through `precomputed_violations`.
            //
            // reg-go-extract-v1: the func name STILL must be recorded in
            // `function_names` — that bucket is the raw function-name
            // extraction surface (snapshot / equivalence consumers read it
            // directly). PACK-PATTERNS dropped the push, which silently
            // zeroed Go function extraction. We restore the push and mark
            // the bucket `function_majority_exempt` so `signals_to_pattern`
            // SKIPS the meaningless global-majority `find_violations` over
            // Go funcs (which would re-introduce the cross-visibility false
            // positives PACK-PATTERNS eliminated); genuine violations stay
            // in `precomputed_violations`.
            let file = file_path.display().to_string();
            let line = name_node.start_position().row as u32 + 1;
            let case = detect_naming_case(&name);
            signals
                .naming
                .function_names
                .push((name.clone(), case, file.clone(), line));
            signals.naming.function_majority_exempt = true;
            if let Some((actual_case, expected_case)) = go_function_naming(&name) {
                signals.naming.precomputed_total += 1;
                if actual_case != expected_case && !is_go_compatible(actual_case, expected_case) {
                    signals.naming.precomputed_violations.push((
                        name.clone(),
                        actual_case,
                        expected_case,
                        file.clone(),
                        line,
                    ));
                }
            }
        }

        let fn_text = node_text(node, source);
        if fn_text.contains(") error") || fn_text.contains(", error)") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.error_handling.result_types.push(evidence);
        }
    }

    fn detect_if(&self, node: Node, source: &str, file_path: &Path, signals: &mut PatternSignals) {
        let if_text = node_text(node, source);
        if if_text.contains("err != nil") || if_text.contains("err == nil") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.error_handling.err_nil_checks.push(evidence);
        }
    }

    fn detect_type(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let type_text = node_text(node, source);

        if type_text.contains("IsDeleted") || type_text.contains("is_deleted") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.is_deleted_fields.push(evidence);
        }
        if type_text.contains("DeletedAt") || type_text.contains("deleted_at") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.deleted_at_fields.push(evidence);
        }

        if type_text.contains("sync.Mutex") || type_text.contains("sync.RWMutex") {
            let evidence = create_evidence_from(node, source, file_path);
            signals
                .async_patterns
                .sync_primitives
                .push(("mutex".to_string(), evidence));
        }
        if type_text.contains("chan ") {
            let evidence = create_evidence_from(node, source, file_path);
            signals
                .async_patterns
                .sync_primitives
                .push(("channel".to_string(), evidence));
        }
    }

    fn detect_const(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let const_text = node_text(node, source);
        let parts: Vec<&str> = const_text.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[1].trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            let case = detect_naming_case(name);
            signals.naming.constant_names.push((
                name.to_string(),
                case,
                file_path.display().to_string(),
                node.start_position().row as u32 + 1,
            ));
        }
    }
}

/// Rust semantic extraction.
pub struct RustSemantics;

impl LanguageSemantics for RustSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "function_item" => {
                self.detect_function(node, source, file_path, signals);
            }
            "impl_item" => {
                self.detect_impl(node, source, file_path, signals);
            }
            "enum_item" => {
                self.detect_enum(node, source, file_path, signals);
            }
            "struct_item" => {
                self.detect_struct(node, source, file_path, signals);
            }
            "use_declaration" => {
                self.detect_use(node, source, file_path, signals);
            }
            "const_item" | "static_item" => {
                self.detect_const(node, source, file_path, signals);
            }
            _ => {}
        }
    }
}

impl RustSemantics {
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
                name_node.start_position().row as u32 + 1,
            ));

            if name.starts_with("test_") {
                signals.test_idioms.test_function_count += 1;
                signals.test_idioms.detected_framework = Some("rust test".to_string());
            }
        }

        let fn_text = node_text(node, source);
        if fn_text.contains("-> Result<") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.error_handling.result_types.push(evidence);
        }

        if fn_text.starts_with("async ") || fn_text.contains(" async ") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.async_patterns.async_await.push(evidence);
        }
    }

    fn detect_impl(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let impl_text = node_text(node, source);
        if impl_text.contains("impl Drop for") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.resource_management.drop_impls.push(evidence);
        }
    }

    fn detect_enum(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source);
            if name.ends_with("Error") || name.ends_with("Err") {
                let evidence = create_evidence_from(node, source, file_path);
                signals.error_handling.error_enums.push((name, evidence));
            }
        }
    }

    fn detect_struct(
        &self,
        node: Node,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let struct_text = node_text(node, source);

        if struct_text.contains("is_deleted") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.is_deleted_fields.push(evidence);
        }
        if struct_text.contains("deleted_at") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.soft_delete.deleted_at_fields.push(evidence);
        }

        if struct_text.contains("Mutex<") || struct_text.contains("RwLock<") {
            let evidence = create_evidence_from(node, source, file_path);
            signals
                .async_patterns
                .sync_primitives
                .push(("mutex".to_string(), evidence));
        }
        if struct_text.contains("mpsc::") || struct_text.contains("channel") {
            let evidence = create_evidence_from(node, source, file_path);
            signals
                .async_patterns
                .sync_primitives
                .push(("channel".to_string(), evidence));
        }

        if struct_text.contains("tokio::") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.async_patterns.tokio_usage.push(evidence);
        }
    }

    fn detect_use(&self, node: Node, source: &str, file_path: &Path, signals: &mut PatternSignals) {
        let use_text = node_text(node, source);

        if use_text.contains("tokio") {
            let evidence = create_evidence_from(node, source, file_path);
            signals.async_patterns.tokio_usage.push(evidence);
        }

        if use_text.starts_with("use crate::") || use_text.starts_with("use super::") {
            let module = use_text
                .trim_start_matches("use ")
                .split("::")
                .next()
                .unwrap_or("");
            signals
                .import_patterns
                .relative_imports
                .push((module.to_string(), file_path.display().to_string()));
        } else if use_text.starts_with("use ") {
            let module = use_text
                .trim_start_matches("use ")
                .split("::")
                .next()
                .unwrap_or("");
            if module != "crate" && module != "super" && module != "self" {
                signals
                    .import_patterns
                    .absolute_imports
                    .push((module.to_string(), file_path.display().to_string()));
            }
        }
    }

    fn detect_const(
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
                .constant_names
                .push((name, case, file_path.display().to_string(), name_node.start_position().row as u32 + 1));
        }
    }
}

/// Java semantic extraction.
pub struct JavaSemantics;

impl LanguageSemantics for JavaSemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "class_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let case = detect_naming_case(&name);
                    signals
                        .naming
                        .class_names
                        .push((name, case, file_path.display().to_string(), name_node.start_position().row as u32 + 1));
                }
            }
            "method_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let case = detect_naming_case(&name);
                    signals.naming.function_names.push((
                name.clone(),
                case,
                file_path.display().to_string(),
                name_node.start_position().row as u32 + 1,
            ));

                    if name.starts_with("test") {
                        signals.test_idioms.test_function_count += 1;
                    }
                }
            }
            _ => {}
        }
    }
}

fn python_node_map() -> LanguageNodeMap {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_definition", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("function_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_statement",
        vec![SignalAction::PushEvidence(SignalTarget::TryExceptBlocks)],
    );
    map.dispatch.insert(
        "with_statement",
        vec![SignalAction::PushEvidence(SignalTarget::ContextManagers)],
    );
    map.dispatch.insert(
        "assert_statement",
        vec![SignalAction::PushEvidence(SignalTarget::AssertStatements)],
    );
    map.dispatch
        .insert("decorator", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("assignment", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("typed_assignment", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("augmented_assignment", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("import_statement", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("import_from_statement", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("call", vec![SignalAction::CallSemantics]);
    map
}

fn typescript_node_map() -> LanguageNodeMap {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "abstract_class_declaration",
        vec![SignalAction::CallSemantics],
    );
    map.dispatch
        .insert("function_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("arrow_function", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("method_definition", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_statement",
        vec![
            SignalAction::PushEvidence(SignalTarget::TryCatchBlocks),
            SignalAction::CallSemantics,
        ],
    );
    map.dispatch
        .insert("interface_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("variable_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("lexical_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("call_expression", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("import_statement", vec![SignalAction::CallSemantics]);
    // fix-CF1-S20: the module root drives the once-per-file structural
    // Express detection (`TypeScriptSemantics::detect_express`).
    map.dispatch
        .insert("program", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "await_expression",
        vec![SignalAction::PushEvidence(SignalTarget::AsyncAwait)],
    );
    map
}

fn go_node_map() -> LanguageNodeMap {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("function_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("method_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "defer_statement",
        vec![SignalAction::PushEvidence(SignalTarget::DeferStatements)],
    );
    map.dispatch
        .insert("if_statement", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "go_statement",
        vec![SignalAction::PushEvidence(SignalTarget::Goroutines)],
    );
    map.dispatch
        .insert("type_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("const_declaration", vec![SignalAction::CallSemantics]);
    map
}

fn rust_node_map() -> LanguageNodeMap {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("function_item", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("impl_item", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("enum_item", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("struct_item", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_expression",
        vec![SignalAction::PushEvidence(SignalTarget::QuestionMarkOps)],
    );
    map.dispatch
        .insert("use_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("const_item", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("static_item", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "async_block",
        vec![SignalAction::PushEvidence(SignalTarget::AsyncAwait)],
    );
    map.dispatch.insert(
        "await_expression",
        vec![SignalAction::PushEvidence(SignalTarget::AsyncAwait)],
    );
    map
}

fn java_node_map() -> LanguageNodeMap {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("class_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("method_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch.insert(
        "try_statement",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );
    map
}

/// Get the LanguageProfile for a given language.
pub fn language_profile(language: crate::types::Language) -> Option<LanguageProfile> {
    match language {
        crate::types::Language::Python => Some(LanguageProfile {
            node_map: python_node_map(),
            semantics: Box::new(PythonSemantics),
        }),
        crate::types::Language::TypeScript | crate::types::Language::JavaScript => {
            Some(LanguageProfile {
                node_map: typescript_node_map(),
                semantics: Box::new(TypeScriptSemantics),
            })
        }
        crate::types::Language::Go => Some(LanguageProfile {
            node_map: go_node_map(),
            semantics: Box::new(GoSemantics),
        }),
        crate::types::Language::Rust => Some(LanguageProfile {
            node_map: rust_node_map(),
            semantics: Box::new(RustSemantics),
        }),
        crate::types::Language::Java => Some(LanguageProfile {
            node_map: java_node_map(),
            semantics: Box::new(JavaSemantics),
        }),
        crate::types::Language::C => Some(languages::c::profile()),
        crate::types::Language::Cpp => Some(languages::cpp::profile()),
        crate::types::Language::CSharp => Some(languages::csharp::profile()),
        crate::types::Language::Php => Some(languages::php::profile()),
        crate::types::Language::Ruby => Some(languages::ruby::profile()),
        crate::types::Language::Kotlin => Some(languages::kotlin::profile()),
        crate::types::Language::Elixir => Some(languages::elixir::profile()),
        crate::types::Language::Lua => Some(languages::lua::profile()),
        crate::types::Language::Luau => Some(languages::lua::profile()),
        crate::types::Language::Swift => Some(languages::swift::profile()),
        crate::types::Language::Scala => Some(languages::scala::profile()),
        crate::types::Language::Ocaml => Some(languages::ocaml::profile()),
        // pack-patterns-v1 (v0.5.0 PACK-PATTERNS): Solidity now has a
        // real design-pattern profile — Ownable / Pausable /
        // ReentrancyGuard / Proxy / Factory detection driven off the
        // contract / modifier / inheritance AST.
        crate::types::Language::Solidity => Some(languages::solidity::profile()),
    }
}

#[cfg(test)]
mod grammar_tests {
    use super::*;
    use crate::types::Language;

    #[test]
    fn test_all_profile_node_types_exist_in_grammar() {
        let languages = [
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go,
            Language::Rust,
            Language::Java,
            Language::C,
            Language::Cpp,
            Language::Ruby,
            Language::Kotlin,
            Language::Swift,
            Language::CSharp,
            Language::Scala,
            Language::Php,
            Language::Lua,
            Language::Luau,
            Language::Elixir,
            Language::Ocaml,
            Language::Solidity,
        ];

        for lang in &languages {
            if let Some(profile) = language_profile(*lang) {
                for key in profile.node_map.dispatch.keys() {
                    assert!(
                        !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                        "{:?}: invalid node type string: '{}'",
                        lang,
                        key
                    );
                }
                for key in profile.node_map.call_dispatch.keys() {
                    assert!(!key.is_empty(), "{:?}: empty call_dispatch key", lang);
                }
            }
        }
    }
}

/// fix-CF1-S20: Express `framework` detection must be a structural member-call
/// match gated on a real `express` import — NOT a substring scan. These tests
/// pin the cross-language contract: Express is detected on a real Express app
/// in BOTH JavaScript and TypeScript, and is NOT falsely detected on lodash or
/// axios (whose `.get`/`.post` member-calls carry no route handler and which
/// import neither `express`).
#[cfg(test)]
mod express_detection_tests {
    use crate::ast::parser::ParserPool;
    use crate::patterns::detector::PatternDetector;
    use crate::types::Language;

    /// Parse `source` as `lang`, run the single-pass pattern detector, and
    /// report whether any Express route evidence was collected (the signal
    /// that drives `framework: "express"`).
    fn express_detected(source: &str, lang: Language) -> bool {
        let pool = ParserPool::new();
        let tree = pool.parse(source, lang).expect("fixture should parse");
        let detector = PatternDetector::new(lang, std::path::PathBuf::from("fixture"));
        let signals = detector.detect_all(&tree, source);
        !signals.api_conventions.express_routes.is_empty()
    }

    // A real Express app — CommonJS (`require`) flavour. The route handler
    // `(req, res) => …` is the structural idiom.
    const EXPRESS_APP_JS: &str = r#"
const express = require('express');
const app = express();
app.get('/', (req, res) => { res.send('ok'); });
app.post('/users', function (req, res) { res.sendStatus(201); });
app.listen(3000);
"#;

    // A real Express app — ES-module/TypeScript flavour.
    const EXPRESS_APP_TS: &str = r#"
import express from 'express';
const app = express();
app.get('/users', (req: Request, res: Response) => { res.json([]); });
app.use((req, res, next) => { next(); });
app.listen(3000);
"#;

    // lodash: `_.get(obj, path)` shares the `.get(` member-call SHAPE but
    // carries no handler and imports lodash, not express. The identifiers
    // deliberately embed the `req`/`res` substrings that fooled the old scan
    // (`request`, `result`).
    const LODASH_JS: &str = r#"
const _ = require('lodash');
function pick(request) {
  const value = _.get(request, 'body.result', null);
  return _.get(request, ['meta', 'response']);
}
"#;

    // axios: `axios.get(url, config)` — an HTTP client, not a router. The
    // config object embeds `responseType`/`req.signal` to embed the old
    // scan's `req`/`res` trigger substrings inside the call text.
    const AXIOS_TS: &str = r#"
import axios from 'axios';
async function load(req: { signal: AbortSignal }) {
  const res = await axios.get('/api/users', { responseType: 'json', signal: req.signal });
  await axios.post('/api/users', { name: 'x' });
  return res.data;
}
"#;

    #[test]
    fn express_detected_on_real_app_js_and_ts() {
        assert!(
            express_detected(EXPRESS_APP_JS, Language::JavaScript),
            "Express must be detected on a real JavaScript Express app"
        );
        assert!(
            express_detected(EXPRESS_APP_TS, Language::TypeScript),
            "Express must be detected on a real TypeScript Express app"
        );
    }

    #[test]
    fn express_not_falsely_detected_on_lodash_or_axios_js_and_ts() {
        assert!(
            !express_detected(LODASH_JS, Language::JavaScript),
            "Express must NOT be detected on lodash (JavaScript) — `_.get` is object access, not a route"
        );
        assert!(
            !express_detected(AXIOS_TS, Language::TypeScript),
            "Express must NOT be detected on axios (TypeScript) — `axios.get` is an HTTP call, not a route"
        );
    }
}
