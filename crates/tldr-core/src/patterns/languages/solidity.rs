//! Solidity design-pattern detection (pack-patterns-v1, v0.5.0 PACK-PATTERNS)
//!
//! AST-driven detection of the canonical Solidity / OpenZeppelin design
//! patterns. Every detector is driven entirely off tree-sitter node
//! kinds + field navigation — there is no regex / substring heuristic.
//!
//! # Detected patterns
//!
//! | Pattern           | Category         | Structural signature (AST)                                              |
//! |-------------------|------------------|-------------------------------------------------------------------------|
//! | `Ownable`         | access_control   | contract defines an `onlyOwner` `modifier_definition`, or `is Ownable…` |
//! | `Pausable`        | access_control   | contract defines `whenNotPaused`/`whenPaused` modifiers, or `is Pausable`|
//! | `ReentrancyGuard` | access_control   | contract defines a `nonReentrant` modifier, or `is ReentrancyGuard`     |
//! | `Proxy`           | structural       | `fallback_receive_definition` + a `delegatecall` yul builtin / `_delegate` |
//! | `Factory`         | creational       | a `function_definition` body contains a `new_expression`                |
//!
//! # AST shape (tree-sitter-solidity 1.2.13)
//!
//! ```text
//! contract_declaration
//!   ├─ "contract" / "abstract"
//!   ├─ identifier                         (name -- field "name")
//!   ├─ inheritance_specifier*             (`is A, B`)
//!   │    └─ ancestor: user_defined_type > identifier
//!   └─ contract_body
//!        ├─ modifier_definition           (first identifier child = modifier name)
//!        ├─ function_definition           (name field; body may hold new_expression)
//!        └─ fallback_receive_definition   ("fallback"/"receive" keyword child)
//! ```
//!
//! Detection anchors on the `contract_declaration` node and walks its
//! subtree ONCE, collecting the modifier names, base names, a flag for
//! "has a delegating fallback", and a flag for "constructs with `new`".
//! Each matched pattern is recorded as a [`crate::types::DesignPattern`]
//! anchored at the contract's declaration line.

use std::path::Path;

use tree_sitter::Node;

use super::super::language_profile::{
    node_text, LanguageNodeMap, LanguageProfile, LanguageSemantics, SignalAction, SignalTarget,
};
use super::super::signals::{detect_naming_case, PatternSignals};

/// Semantic extractor for Solidity design patterns.
pub struct SoliditySemantics;

impl LanguageSemantics for SoliditySemantics {
    fn process_node(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        match node_type {
            "contract_declaration" | "library_declaration" | "interface_declaration" => {
                self.detect_contract(node, node_type, source, file_path, signals)
            }
            _ => {}
        }
    }
}

/// Structural facts gathered from a single contract subtree walk.
#[derive(Default)]
struct ContractFacts {
    /// `modifier_definition` names declared in this contract.
    modifiers: Vec<String>,
    /// Inheritance base names (`is A, B`).
    bases: Vec<String>,
    /// Function names declared in this contract.
    functions: Vec<String>,
    /// True when the contract has a `fallback_receive_definition`.
    has_fallback: bool,
    /// True when the contract performs a low-level `delegatecall`
    /// (yul builtin or `.delegatecall(...)` member call).
    has_delegatecall: bool,
    /// True when the contract calls an internal `_delegate(...)`.
    calls_delegate: bool,
    /// True when any function body constructs a contract via
    /// `new SomeContract(...)` (a `new_expression` node).
    constructs_with_new: bool,
}

impl SoliditySemantics {
    fn detect_contract(
        &self,
        node: Node,
        node_type: &str,
        source: &str,
        file_path: &Path,
        signals: &mut PatternSignals,
    ) {
        let name = match node.child_by_field_name("name") {
            Some(n) => node_text(n, source),
            None => return,
        };
        let line = node.start_position().row as u32 + 1;
        let file = file_path.display().to_string();

        // Record the contract name as a class-naming signal so Solidity
        // participates in the naming consistency roll-up too.
        let case = detect_naming_case(&name);
        signals
            .naming
            .class_names
            .push((name.clone(), case, file.clone(), line));

        let mut facts = ContractFacts::default();
        collect_bases(node, source, &mut facts.bases);
        collect_facts(node, source, &mut facts);

        let kind_label = match node_type {
            "library_declaration" => "library",
            "interface_declaration" => "interface",
            _ => "contract",
        };

        // ---- Ownable -------------------------------------------------
        if facts.modifiers.iter().any(|m| m == "onlyOwner")
            || facts
                .bases
                .iter()
                .any(|b| base_matches(b, "Ownable") || base_matches(b, "Ownable2Step"))
        {
            let evidence = if facts.modifiers.iter().any(|m| m == "onlyOwner") {
                format!("{kind_label} `{name}` defines an `onlyOwner` modifier")
            } else {
                format!("{kind_label} `{name}` inherits an Ownable base")
            };
            signals.design_patterns.push_pattern(
                "Ownable",
                "access_control",
                "solidity",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        }

        // ---- Pausable ------------------------------------------------
        if facts
            .modifiers
            .iter()
            .any(|m| m == "whenNotPaused" || m == "whenPaused")
            || facts.bases.iter().any(|b| base_matches(b, "Pausable"))
        {
            let evidence = if facts
                .modifiers
                .iter()
                .any(|m| m == "whenNotPaused" || m == "whenPaused")
            {
                format!("{kind_label} `{name}` defines whenNotPaused/whenPaused modifiers")
            } else {
                format!("{kind_label} `{name}` inherits Pausable")
            };
            signals.design_patterns.push_pattern(
                "Pausable",
                "access_control",
                "solidity",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        }

        // ---- ReentrancyGuard -----------------------------------------
        if facts.modifiers.iter().any(|m| m == "nonReentrant")
            || facts
                .bases
                .iter()
                .any(|b| base_matches(b, "ReentrancyGuard"))
        {
            let evidence = if facts.modifiers.iter().any(|m| m == "nonReentrant") {
                format!("{kind_label} `{name}` defines a `nonReentrant` modifier")
            } else {
                format!("{kind_label} `{name}` inherits ReentrancyGuard")
            };
            signals.design_patterns.push_pattern(
                "ReentrancyGuard",
                "access_control",
                "solidity",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        }

        // ---- Proxy (transparent / delegating) ------------------------
        // A proxy delegates all unmatched calls to an implementation via
        // a fallback that performs `delegatecall`. We require a
        // delegating fallback (fallback + delegatecall/_delegate) OR
        // inheritance from a Proxy base.
        let delegating_fallback =
            facts.has_fallback && (facts.has_delegatecall || facts.calls_delegate);
        if delegating_fallback
            || facts
                .bases
                .iter()
                .any(|b| base_matches(b, "Proxy") || b.ends_with("Proxy"))
        {
            let evidence = if delegating_fallback {
                format!("{kind_label} `{name}` has a fallback that delegatecalls an implementation")
            } else {
                format!("{kind_label} `{name}` inherits a Proxy base")
            };
            signals.design_patterns.push_pattern(
                "Proxy",
                "structural",
                "solidity",
                name.clone(),
                file.clone(),
                line,
                evidence,
            );
        }

        // ---- Factory -------------------------------------------------
        // A factory contract creates other contracts via `new C(...)`.
        if facts.constructs_with_new {
            signals.design_patterns.push_pattern(
                "Factory",
                "creational",
                "solidity",
                name.clone(),
                file.clone(),
                line,
                format!("{kind_label} `{name}` constructs contracts via `new` expressions"),
            );
        }
    }
}

/// True when an inheritance base name `b` (possibly dotted, e.g.
/// `access.Ownable` or `OwnableUpgradeable`) refers to `target`. We
/// accept an exact match, a dotted suffix match (`*.Target`), and the
/// common OpenZeppelin `<Target>Upgradeable` variant.
fn base_matches(b: &str, target: &str) -> bool {
    let tail = b.rsplit('.').next().unwrap_or(b);
    tail == target || tail == format!("{target}Upgradeable")
}

/// Collect `is A, B` base names from the direct `inheritance_specifier`
/// children of a contract/interface declaration.
fn collect_bases(node: Node, source: &str, bases: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "inheritance_specifier" {
            continue;
        }
        if let Some(name) = first_user_defined_type_name(child, source) {
            bases.push(name);
        }
    }
}

/// Extract the base name from an `inheritance_specifier`: prefer the
/// `ancestor` field's `user_defined_type`, else scan for the first
/// `user_defined_type`/`identifier` descendant.
fn first_user_defined_type_name(spec: Node, source: &str) -> Option<String> {
    if let Some(ancestor) = spec.child_by_field_name("ancestor") {
        if let Some(name) = user_defined_type_name(ancestor, source) {
            return Some(name);
        }
    }
    let mut cursor = spec.walk();
    for child in spec.children(&mut cursor) {
        match child.kind() {
            "user_defined_type" => {
                if let Some(name) = user_defined_type_name(child, source) {
                    return Some(name);
                }
            }
            "identifier" => return Some(node_text(child, source)),
            _ => {}
        }
    }
    None
}

/// Resolve a `user_defined_type` to its name (bare identifier or dotted
/// `member_expression`).
fn user_defined_type_name(node: Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" | "member_expression" => return Some(node_text(child, source)),
            _ => {}
        }
    }
    Some(node_text(node, source))
}

/// Walk the contract subtree once, collecting modifier names, function
/// names, and the boolean flags used by the structural detectors.
///
/// We DO recurse into nested bodies (assembly blocks, statements) so
/// `delegatecall` yul builtins and `new_expression` nodes anywhere
/// inside a function body are observed. We do NOT descend into a NESTED
/// contract declaration (Solidity disallows them, but be defensive).
fn collect_facts(node: Node, source: &str, facts: &mut ContractFacts) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "modifier_definition" => {
                if let Some(name) = first_identifier_name(child, source) {
                    facts.modifiers.push(name);
                }
                // A modifier body can still contain delegatecall/new; recurse.
                collect_facts(child, source, facts);
            }
            "function_definition" | "constructor_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    facts.functions.push(node_text(name_node, source));
                } else if let Some(name) = first_identifier_name(child, source) {
                    facts.functions.push(name);
                }
                collect_facts(child, source, facts);
            }
            "fallback_receive_definition" => {
                // `fallback() ...` (not `receive()`) is the delegating
                // entry point. Distinguish via the leading keyword token.
                if has_fallback_keyword(child, source) {
                    facts.has_fallback = true;
                }
                collect_facts(child, source, facts);
            }
            "new_expression" => {
                facts.constructs_with_new = true;
            }
            "yul_evm_builtin" => {
                if node_text(child, source) == "delegatecall" {
                    facts.has_delegatecall = true;
                }
            }
            // Nested contract decl: do not bleed facts across contracts.
            "contract_declaration" | "library_declaration" | "interface_declaration" => {}
            _ => {
                // Detect `.delegatecall(...)` member calls and `_delegate(...)`
                // invocations structurally on call_expression nodes.
                if child.kind() == "call_expression" {
                    inspect_call_expression(child, source, facts);
                }
                collect_facts(child, source, facts);
            }
        }
    }
}

/// Inspect a `call_expression` for `.delegatecall(...)` member calls and
/// `_delegate(...)` invocations.
fn inspect_call_expression(node: Node, source: &str, facts: &mut ContractFacts) {
    // The callee is the first child (an `expression` wrapping either a
    // `member_expression` for `x.delegatecall` or an `identifier` for
    // `_delegate`).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "expression" | "member_expression" | "identifier" => {
                let text = node_text(child, source);
                if text == "_delegate" || text.ends_with("._delegate") {
                    facts.calls_delegate = true;
                }
                if text.ends_with(".delegatecall") {
                    facts.has_delegatecall = true;
                }
                // Recurse one level into the expression wrapper.
                if child.kind() == "expression" {
                    inspect_call_expression(child, source, facts);
                }
            }
            _ => {}
        }
    }
}

/// The first `identifier` child's text (used for modifier names, which
/// the grammar exposes as a bare identifier rather than a `name` field).
fn first_identifier_name(node: Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return Some(node_text(child, source));
        }
    }
    None
}

/// True when a `fallback_receive_definition` is a `fallback()` (vs
/// `receive()`). The keyword is a direct named/anonymous child token.
fn has_fallback_keyword(node: Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "fallback" {
            return true;
        }
        if !child.is_named() {
            if let Ok(t) = child.utf8_text(source.as_bytes()) {
                if t == "fallback" {
                    return true;
                }
            }
        }
    }
    false
}

/// Build the Solidity language profile.
pub fn profile() -> LanguageProfile {
    let mut map = LanguageNodeMap::new();
    map.dispatch
        .insert("contract_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("library_declaration", vec![SignalAction::CallSemantics]);
    map.dispatch
        .insert("interface_declaration", vec![SignalAction::CallSemantics]);
    // Solidity `try { ... } catch { ... }` external-call error handling.
    map.dispatch.insert(
        "try_statement",
        vec![SignalAction::PushEvidence(SignalTarget::TryCatchBlocks)],
    );

    LanguageProfile {
        node_map: map,
        semantics: Box::new(SoliditySemantics),
    }
}
