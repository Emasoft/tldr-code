//! Solidity-specific vulnerability detectors (v0.5.0 SOL-011 solidity-vuln-v1).
//!
//! Unlike the canonical taint-driven detectors in [`super::vuln::scan_file_vulns`],
//! these are pure AST-pattern detectors operating directly on the
//! tree-sitter-solidity parse tree. They cover language-shape security
//! anti-patterns that have no source-to-sink data-flow surface:
//!
//! 1. **`TxOrigin`** — `tx.origin` used in an authorization position
//!    (CWE-477 / SWC-115).
//! 2. **`ShadowingState`** — local variable / parameter shadows a contract
//!    state variable (CWE-1109 / SWC-119), including inherited state via
//!    the contract's `bases` list.
//! 3. **`Suicidal`** — public/external function calls `selfdestruct(...)`
//!    (or legacy `suicide(...)`) without an access-control modifier or
//!    `require(msg.sender == ...)` guard (CWE-284 / SWC-106).
//! 4. **`UncheckedLowlevel`** — return value of `.call(...)` / `.send(...)` /
//!    `.delegatecall(...)` is discarded (CWE-252 / SWC-104).
//! 5. **`LockedEther`** — contract accepts ether (has at least one
//!    `payable` function / `receive` / `fallback`) but provides NO
//!    withdraw path (`.transfer`, `.send`, `.call{value:...}`,
//!    `selfdestruct`) (CWE-664 / SWC-132).
//!
//! All findings are projected into the canonical
//! [`super::vuln::VulnFinding`] shape so CLI / SARIF / JSON consumers see
//! a uniform schema across taint-based and AST-pattern detectors.

use std::path::Path;

use tree_sitter::Node;

use crate::ast::parser::parse;
use crate::security::vuln::{
    get_cwe_id, get_remediation, severity_for_vuln_type, TaintSink, TaintSource, VulnFinding,
    VulnType,
};
use crate::types::Language;

// =============================================================================
// Public entry — invoked by scan_file_vulns when language == Solidity.
// =============================================================================

/// v0.5.0 SOL-014 M6: detector-specific human-readable message for each
/// Solidity vuln type.
///
/// The CLI `VulnFinding.description` (rendered as `message` in
/// SARIF/JSON) is populated from this string instead of the generic
/// taint-style suffix `"… with unsanitized input"` which makes no sense
/// for AST-pattern detectors that have no source/sink flow.
///
/// Messages are intentionally verbose so consumers (humans + LLMs) can
/// reason about the finding without cross-referencing CWE/SWC tables.
/// Each message:
///   1. States the anti-pattern in one sentence,
///   2. Names the security-impact / why it's dangerous, and
///   3. Names the canonical remediation in passing.
///
/// Callers that need MORE detail should join with `get_remediation` for
/// the full remediation text.
pub fn solidity_finding_message(vuln_type: VulnType) -> &'static str {
    match vuln_type {
        VulnType::TxOrigin =>
            "Use of tx.origin for authorization is unsafe; tx.origin refers to the externally-owned account that initiated the transaction chain, not the immediate caller, which makes the check vulnerable to phishing via intermediate contracts. Use msg.sender instead.",
        VulnType::ShadowingState =>
            "Local variable or parameter shadows a contract state variable; the local binding masks the storage variable inside the function body, silently breaking reads/writes that intended to refer to state. Rename the local to avoid shadowing.",
        VulnType::Suicidal =>
            "selfdestruct is callable without an access-control modifier or msg.sender guard, allowing an unauthorized caller to destroy the contract. Note that EIP-6780 changed selfdestruct's runtime semantics in Cancun (storage is no longer cleared, only the balance is forwarded), but the unguarded-public-callable pattern is still a hard-to-recover anti-pattern. Guard with onlyOwner / msg.sender == admin / equivalent.",
        VulnType::UncheckedLowlevel =>
            "Return value of a low-level call (.call / .send / .delegatecall) is discarded; failures of the external call will silently pass and subsequent code will proceed as if the call succeeded. Capture the boolean return and require(ok) before continuing.",
        VulnType::LockedEther =>
            "Contract accepts ether (via payable function, receive, fallback, or payable constructor) but provides no withdraw path (no .transfer / .send / .call{value:...} / selfdestruct call reachable from within the contract). Funds sent to this contract are permanently trapped.",
        // v0.5.0 PACK-VULN pack-vuln-v1
        VulnType::Reentrancy =>
            "An external value-bearing call (.call{value:...} / .send / .transfer) executes BEFORE the function writes the state variable it depends on, violating the Checks-Effects-Interactions pattern. The callee can re-enter this function before the state update commits and repeatedly drain funds. Move all state writes ahead of the external call, or guard the function with a reentrancy lock.",
        VulnType::UncheckedSend =>
            "The boolean returned by .send(...) is discarded. .send forwards a fixed 2300-gas stipend and returns false (rather than reverting) when the transfer fails, so a discarded return silently swallows failed payments and lets execution continue as if the transfer succeeded. Check the return with require(ok) or switch to a checked .call / pull-payment pattern.",
        VulnType::ArbitrarySend =>
            "A value transfer (.transfer / .send / .call{value:...}) sends ether to a destination derived from caller-controlled input (a function parameter or msg.data) inside a publicly-callable function with no access control. Any caller can redirect the contract's ether to an address they choose. Restrict the recipient to a vetted address or add access control.",
        VulnType::DelegatecallTainted =>
            "delegatecall is invoked on a target address derived from caller-controlled input. delegatecall runs the callee's code in THIS contract's storage context, so an attacker-chosen target can overwrite arbitrary storage (including ownership) or self-destruct the contract. Pin the delegatecall target to an immutable / access-controlled state variable.",
        // Non-Solidity vuln types should never reach this dispatcher; we
        // return an empty string rather than panicking so a misuse only
        // surfaces as a generic CLI description (the existing fallback).
        _ => "",
    }
}

/// Whether a `VulnType` is one of the Solidity AST-pattern detectors
/// implemented in this module. Used by the CLI mapping path to decide
/// between the Solidity-specific message (above) and the canonical
/// taint-style `"… with unsanitized input"` suffix used for the
/// data-flow vuln types.
pub fn is_solidity_vuln_type(vuln_type: VulnType) -> bool {
    matches!(
        vuln_type,
        VulnType::TxOrigin
            | VulnType::ShadowingState
            | VulnType::Suicidal
            | VulnType::UncheckedLowlevel
            | VulnType::LockedEther
            // v0.5.0 PACK-VULN pack-vuln-v1
            | VulnType::Reentrancy
            | VulnType::UncheckedSend
            | VulnType::ArbitrarySend
            | VulnType::DelegatecallTainted
    )
}

/// Run all Solidity AST-pattern detectors on `source` (already read by the
/// caller) and return the per-file findings, filtered by `vuln_filter` when
/// `Some`.
///
/// The caller is responsible for reading the file and providing the path
/// for the `file:` field on each finding.
pub fn scan_solidity_vulns(
    path: &Path,
    source: &str,
    vuln_filter: Option<VulnType>,
) -> Vec<VulnFinding> {
    let tree = match parse(source, Language::Solidity) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let root = tree.root_node();
    let mut findings: Vec<VulnFinding> = Vec::new();

    detect_tx_origin(&root, source, path, &mut findings);
    detect_shadowing_state(&root, source, path, &mut findings);
    detect_suicidal(&root, source, path, &mut findings);
    detect_unchecked_lowlevel(&root, source, path, &mut findings);
    detect_locked_ether(&root, source, path, &mut findings);
    // v0.5.0 PACK-VULN pack-vuln-v1: four additional AST-pattern detectors.
    detect_reentrancy(&root, source, path, &mut findings);
    detect_unchecked_send(&root, source, path, &mut findings);
    detect_arbitrary_send(&root, source, path, &mut findings);
    detect_delegatecall_tainted(&root, source, path, &mut findings);

    if let Some(ty) = vuln_filter {
        findings.retain(|f| f.vuln_type == ty);
    }
    findings
}

// =============================================================================
// Tree-walk utilities
// =============================================================================

/// Extract the textual byte range of a node as an owned `String`.
fn node_text(node: &Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

/// Recursively collect every descendant whose `kind()` is in `kinds`.
fn collect_by_kind<'a>(node: Node<'a>, kinds: &[&str], out: &mut Vec<Node<'a>>) {
    if kinds.contains(&node.kind()) {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_by_kind(child, kinds, out);
    }
}

/// Find every `contract_declaration` / `interface_declaration` /
/// `library_declaration` under `root`.
fn find_contracts<'a>(root: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    collect_by_kind(
        *root,
        &[
            "contract_declaration",
            "interface_declaration",
            "library_declaration",
        ],
        &mut out,
    );
    out
}

/// Return the body node of a contract / interface / library declaration.
/// The grammar names this child `body` in some forks; fall back to the
/// first `contract_body` / `interface_body` / `library_body` named child.
fn contract_body<'a>(contract: &Node<'a>) -> Option<Node<'a>> {
    if let Some(body) = contract.child_by_field_name("body") {
        return Some(body);
    }
    let mut cursor = contract.walk();
    for child in contract.children(&mut cursor) {
        match child.kind() {
            "contract_body" | "interface_body" | "library_body" => return Some(child),
            _ => {}
        }
    }
    None
}

/// Return the textual contract name from a contract/interface/library decl.
fn contract_name(contract: &Node, source: &str) -> String {
    contract
        .child_by_field_name("name")
        .map(|n| node_text(&n, source))
        .unwrap_or_default()
}

/// Find every `function_definition` directly under the contract body
/// (NOT recursing into nested contracts, which the Solidity grammar does
/// not actually allow but we guard against anyway).
fn contract_functions<'a>(contract: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    if let Some(body) = contract_body(contract) {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            match child.kind() {
                "function_definition"
                | "constructor_definition"
                | "fallback_receive_definition" => {
                    out.push(child);
                }
                _ => {}
            }
        }
    }
    out
}

/// Find every `state_variable_declaration` directly under a contract body.
fn contract_state_vars<'a>(contract: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    if let Some(body) = contract_body(contract) {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() == "state_variable_declaration" {
                out.push(child);
            }
        }
    }
    out
}

/// Extract the textual `name` of a `state_variable_declaration`.
fn state_var_name(node: &Node, source: &str) -> Option<String> {
    node.child_by_field_name("name")
        .map(|n| node_text(&n, source))
}

/// Visibility of a function decl, or `None` (Solidity default is
/// `internal` for contracts and `external` for interfaces, but we don't
/// synthesize the default).
fn function_visibility(node: &Node, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility" {
            return Some(node_text(&child, source).trim().to_string());
        }
    }
    None
}

/// Modifier-invocation names attached to a function decl (the names
/// inside `onlyOwner` / `nonReentrant(arg)`). Constructor decls also
/// carry modifier invocations (used for base-constructor calls like
/// `Ownable(msg.sender)` and access modifiers).
fn modifier_invocations(node: &Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifier_invocation" {
            // The modifier name is the first `identifier` child.
            let mut mc = child.walk();
            for mc_child in child.children(&mut mc) {
                if mc_child.kind() == "identifier" {
                    out.push(node_text(&mc_child, source));
                    break;
                }
            }
        }
    }
    out
}

/// Whether the function decl has any modifier whose name suggests an
/// access-control guard (`onlyOwner`, `OnlyAdmin`, `requiresAuth`, etc.).
/// We match on case-insensitive substring of the modifier name against a
/// small allow-list of access-control idioms used across OpenZeppelin /
/// Solady / Solmate.
fn has_access_control_modifier(node: &Node, source: &str) -> bool {
    let access_substrings = ["owner", "admin", "auth", "role", "onlyrole"];
    for inv in modifier_invocations(node, source) {
        let lower = inv.to_lowercase();
        for needle in &access_substrings {
            if lower.contains(needle) {
                return true;
            }
        }
    }
    false
}

/// Whether the function body has a `require(msg.sender == ...)` /
/// `require(... == msg.sender)` pattern at the top. We treat ANY
/// occurrence of `require(` + `msg.sender` + `==` on the same statement
/// as an access guard.
fn has_msg_sender_require_guard(node: &Node, source: &str) -> bool {
    let body = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return false,
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        // Only inspect statements at the very top of the body (Slither's
        // "early-revert" pattern); we don't try to be clever about
        // conditional guards inside loops.
        if child.kind() == "expression_statement" {
            let txt = node_text(&child, source);
            if txt.contains("require(")
                && txt.contains("msg.sender")
                && txt.contains("==")
            {
                return true;
            }
        }
    }
    false
}

/// Whether the function decl has state mutability `payable`.
///
/// v0.5.0 SOL-014 M5: tree-sitter-solidity emits the `payable` mutability
/// in two distinct shapes depending on the decl kind:
///
/// 1. **function_definition** / **fallback_receive_definition** wrap the
///    keyword in a `state_mutability` node, e.g.
///    `state_mutability: "payable" -> payable: "payable"`.
/// 2. **constructor_definition** carries the keyword as a BARE child node
///    of kind `"payable"` directly under the constructor (no
///    `state_mutability` wrapper).
///
/// Pre-fix, this routine only matched shape (1), so a payable constructor
/// was treated as non-payable and the locked-ether detector missed
/// `constructor() public payable {}` shapes. Now we accept BOTH shapes.
fn is_payable(node: &Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Shape (1): function / receive / fallback.
        if child.kind() == "state_mutability" && node_text(&child, source).trim() == "payable" {
            return true;
        }
        // Shape (2): constructor — `payable` keyword is a direct child of
        // the constructor_definition with no wrapper node.
        if child.kind() == "payable" {
            return true;
        }
    }
    false
}

/// Whether `node` text matches `tx.origin` (i.e. a `member_expression`
/// with `tx` object and `origin` property).
fn is_tx_origin_expr(node: &Node, source: &str) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let object = node.child_by_field_name("object").or_else(|| {
        // Some grammar forks use named-child shape with no field names.
        // We can't return a child iterator over a local cursor, so use
        // `child(0)` (first child, named-or-not). Solidity's
        // member_expression always emits the object as the first child.
        node.child(0)
    });
    let property = node.child_by_field_name("property");
    let object_txt = object.map(|n| node_text(&n, source));
    let property_txt = property.map(|n| node_text(&n, source));
    if object_txt.as_deref() == Some("tx") && property_txt.as_deref() == Some("origin") {
        return true;
    }
    // Fallback: byte-text match (handles grammar forks where field names
    // are missing). We're conservative: must be exactly `tx.origin`.
    let txt = node_text(node, source);
    let trimmed = txt.trim();
    trimmed == "tx.origin"
}

// =============================================================================
// Finding construction
// =============================================================================

/// Build a `VulnFinding` for a Solidity AST-pattern detection. The
/// `source` / `sink` records are populated with synthetic positions —
/// since there is no taint flow, both records carry the same line/snippet
/// (the suspect AST node) and the `flow_path` is a single-element
/// descriptive trail.
fn make_finding(
    vuln_type: VulnType,
    path: &Path,
    line: u32,
    snippet: &str,
    description: &str,
) -> VulnFinding {
    VulnFinding {
        vuln_type,
        file: path.to_path_buf(),
        source: TaintSource {
            variable: String::new(),
            source_type: description.to_string(),
            line,
            expression: snippet.trim().to_string(),
        },
        sink: TaintSink {
            function: String::new(),
            sink_type: description.to_string(),
            line,
            expression: snippet.trim().to_string(),
        },
        flow_path: vec![format!("{}:{}", line, description)],
        severity: severity_for_vuln_type(vuln_type).to_string(),
        remediation: get_remediation(vuln_type).to_string(),
        cwe_id: Some(get_cwe_id(vuln_type).to_string()),
    }
}

// =============================================================================
// Detector 1: tx-origin
// =============================================================================

/// Walk every function body. Emit a finding for any `tx.origin` reference
/// inside a condition position:
/// - operand of `require(...)` / `assert(...)`
/// - condition of `if` / `while`
/// - operand of `==` / `!=` against any sibling expression
fn detect_tx_origin(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    // Find every member_expression that IS `tx.origin`.
    let mut candidates: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["member_expression"], &mut candidates);
    for cand in candidates {
        if !is_tx_origin_expr(&cand, source) {
            continue;
        }
        if !is_in_condition_position(&cand) {
            continue;
        }
        let line = cand.start_position().row as u32 + 1;
        let snippet = enclosing_statement_text(&cand, source);
        findings.push(make_finding(
            VulnType::TxOrigin,
            path,
            line,
            &snippet,
            "tx.origin used in authorization condition",
        ));
    }
}

/// Walk up from `node` to determine whether it sits in a condition
/// position (require/assert arg, if/while condition, or operand of an
/// equality comparison).
fn is_in_condition_position(node: &Node) -> bool {
    let mut cur = node.parent();
    // Hop through chained expressions (e.g. `tx.origin == owner` ->
    // binary_expression, that binary is the require argument).
    let mut hops = 0;
    while let Some(p) = cur {
        if hops > 6 {
            break;
        }
        match p.kind() {
            "binary_expression" => {
                // Treat == / != as condition-like (the classic
                // `tx.origin == owner` shape).
                return true;
            }
            "if_statement" | "while_statement" | "do_while_statement" => return true,
            "call_expression" => {
                // require / assert / revert with a tx.origin-containing
                // argument is a condition position.
                if let Some(callee) = p.child_by_field_name("function") {
                    let name = callee.kind();
                    // The callee text is more reliable than the node kind
                    // (identifier vs primary_expression varies).
                    let bytes = (callee.start_byte(), callee.end_byte());
                    let _ = name;
                    let _ = bytes;
                }
                return true;
            }
            "expression_statement" => {
                // Reached the statement boundary without a condition
                // wrapper — not a condition position.
                return false;
            }
            _ => {}
        }
        cur = p.parent();
        hops += 1;
    }
    false
}

/// Walk up to the nearest enclosing statement and return its text. Falls
/// back to the node's own text when no statement parent exists.
fn enclosing_statement_text(node: &Node, source: &str) -> String {
    let mut cur = Some(*node);
    while let Some(n) = cur {
        match n.kind() {
            "expression_statement"
            | "if_statement"
            | "while_statement"
            | "do_while_statement"
            | "return_statement"
            | "variable_declaration_statement"
            | "emit_statement"
            | "revert_statement" => {
                return node_text(&n, source);
            }
            _ => {}
        }
        cur = n.parent();
    }
    node_text(node, source)
}

// =============================================================================
// Detector 2: shadowing-state
// =============================================================================

/// For each contract, collect state variable names, then walk every
/// function and flag any local variable / parameter that shares the name.
fn detect_shadowing_state(
    root: &Node,
    source: &str,
    path: &Path,
    findings: &mut Vec<VulnFinding>,
) {
    let contracts = find_contracts(root);
    for contract in &contracts {
        // Collect this contract's state vars.
        let mut state_names: Vec<String> = Vec::new();
        for sv in contract_state_vars(contract) {
            if let Some(name) = state_var_name(&sv, source) {
                if !name.is_empty() {
                    state_names.push(name);
                }
            }
        }
        if state_names.is_empty() {
            continue;
        }
        // For each function in the contract, walk params + var decls.
        for func in contract_functions(contract) {
            check_function_for_shadowing(&func, source, &state_names, path, findings);
        }
    }
}

fn check_function_for_shadowing(
    func: &Node,
    source: &str,
    state_names: &[String],
    path: &Path,
    findings: &mut Vec<VulnFinding>,
) {
    // 1. Parameters.
    let mut cursor = func.walk();
    for child in func.children(&mut cursor) {
        if child.kind() == "parameter" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = node_text(&name_node, source);
                if state_names.iter().any(|s| s == &name) {
                    let line = name_node.start_position().row as u32 + 1;
                    findings.push(make_finding(
                        VulnType::ShadowingState,
                        path,
                        line,
                        &node_text(&child, source),
                        &format!("parameter `{}` shadows contract state variable", name),
                    ));
                }
            }
        }
    }
    // 2. Local variable declarations inside the body.
    if let Some(body) = func.child_by_field_name("body") {
        let mut locals = Vec::new();
        collect_by_kind(body, &["variable_declaration_statement"], &mut locals);
        for vds in locals {
            // Find the embedded `variable_declaration` child for the name.
            let mut vc = vds.walk();
            for child in vds.children(&mut vc) {
                if child.kind() == "variable_declaration" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = node_text(&name_node, source);
                        if state_names.iter().any(|s| s == &name) {
                            let line = name_node.start_position().row as u32 + 1;
                            findings.push(make_finding(
                                VulnType::ShadowingState,
                                path,
                                line,
                                &node_text(&vds, source),
                                &format!(
                                    "local variable `{}` shadows contract state variable",
                                    name
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Detector 3: suicidal
// =============================================================================

/// Walk down the first-child chain of a `call_expression` to skip
/// `expression` / `primary_expression` wrappers and return the
/// underlying callee node (typically `member_expression` or
/// `identifier`). Returns `None` when no callee child exists.
fn resolve_callee<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    // Try the named "function" field first (some grammar forks emit it).
    if let Some(c) = call.child_by_field_name("function") {
        return Some(unwrap_expr_wrapper(c));
    }
    // Otherwise the callee is the first child of the call_expression.
    let first = call.child(0)?;
    Some(unwrap_expr_wrapper(first))
}

/// Peel `expression` / `primary_expression` wrapper nodes off `n` until
/// the underlying meaningful node (e.g. `member_expression`,
/// `identifier`, `call_expression`) is exposed.
fn unwrap_expr_wrapper<'a>(mut n: Node<'a>) -> Node<'a> {
    for _ in 0..6 {
        match n.kind() {
            "expression" | "primary_expression" => {
                if let Some(c) = n.child(0) {
                    n = c;
                    continue;
                }
            }
            _ => {}
        }
        break;
    }
    n
}

/// Find every `selfdestruct(...)` / `suicide(...)` call. For each, locate
/// the enclosing function. If the function is `public` or `external` AND
/// has no access-control modifier AND no `require(msg.sender == ...)`
/// guard, emit a finding.
fn detect_suicidal(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["call_expression"], &mut calls);
    for call in calls {
        let callee = match resolve_callee(&call) {
            Some(c) => c,
            None => continue,
        };
        let callee_text = node_text(&callee, source);
        let trimmed = callee_text.trim();
        if trimmed != "selfdestruct" && trimmed != "suicide" {
            continue;
        }
        // Walk up to enclosing function.
        let func = match enclosing_function(&call) {
            Some(f) => f,
            None => continue,
        };
        let vis = function_visibility(&func, source).unwrap_or_default();
        if vis != "public" && vis != "external" {
            continue;
        }
        if has_access_control_modifier(&func, source) {
            continue;
        }
        if has_msg_sender_require_guard(&func, source) {
            continue;
        }
        let line = call.start_position().row as u32 + 1;
        let snippet = enclosing_statement_text(&call, source);
        findings.push(make_finding(
            VulnType::Suicidal,
            path,
            line,
            &snippet,
            "selfdestruct callable without access-control guard (EIP-6780: recovery impossible)",
        ));
    }
}

/// Walk up from `node` to the nearest `function_definition` /
/// `constructor_definition` / `fallback_receive_definition`.
fn enclosing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            "function_definition"
            | "constructor_definition"
            | "fallback_receive_definition" => return Some(n),
            _ => {}
        }
        cur = n.parent();
    }
    None
}

// =============================================================================
// Detector 4: unchecked-lowlevel
// =============================================================================

/// Find every member-call `.call(...)`, `.send(...)`, `.delegatecall(...)`
/// whose return value is discarded. The parent of the wrapping
/// `call_expression` is the key test:
/// - `expression_statement` → discarded (positive).
/// - `assignment_expression` / `variable_declaration_statement` /
///   `tuple_expression` → captured (negative).
/// - argument of `require(...)` / `assert(...)` → checked (negative).
fn detect_unchecked_lowlevel(
    root: &Node,
    source: &str,
    path: &Path,
    findings: &mut Vec<VulnFinding>,
) {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["call_expression"], &mut calls);
    for call in calls {
        // Resolve the method property via `call_member_method`, which handles
        // BOTH the plain `receiver.method(...)` member-call shape AND the
        // value/gas-modified `receiver.call{value: x}(...)` shape (where the
        // callee is a `struct_expression` wrapping the member access). The
        // pre-PACK-VULN logic only matched the plain `member_expression`
        // shape, so a discarded `.call{value:...}` return slipped through.
        let (_member, prop) = match call_member_method(&call, source) {
            Some(m) => m,
            None => continue,
        };
        let prop_trimmed = prop.trim();
        if !matches!(prop_trimmed, "call" | "send" | "delegatecall") {
            continue;
        }
        // Walk up through the AST to find the meaningful parent
        // context. tree-sitter-solidity wraps every expression in an
        // `expression` / `statement` node so the direct parent of a
        // `call_expression` is typically a wrapper, not the relevant
        // assignment / expression_statement / argument.
        let mut ctx = call.parent();
        let mut steps = 0;
        let (ctx_kind, ctx_node) = loop {
            let n = match ctx {
                Some(n) => n,
                None => break ("__none__", call),
            };
            match n.kind() {
                "expression_statement"
                | "assignment_expression"
                | "variable_declaration_statement"
                | "variable_declaration_tuple"
                | "tuple_expression"
                | "call_argument"
                | "if_statement"
                | "while_statement"
                | "return_statement" => break (n.kind(), n),
                _ => {}
            }
            steps += 1;
            if steps > 6 {
                break ("__none__", call);
            }
            ctx = n.parent();
        };
        // SAFE: captured by tuple-destructure or assignment.
        if ctx_kind == "tuple_expression"
            || ctx_kind == "assignment_expression"
            || ctx_kind == "variable_declaration_statement"
            || ctx_kind == "variable_declaration_tuple"
        {
            continue;
        }
        // SAFE: argument of require / assert (we treat `call_argument`
        // chain via `is_inside_require_or_assert`).
        if is_inside_require_or_assert(&call, source) {
            continue;
        }
        // FLAG: discarded — context resolves to an `expression_statement`
        // that wraps the call without binding the return value.
        if ctx_kind == "expression_statement" {
            let line = call.start_position().row as u32 + 1;
            findings.push(make_finding(
                VulnType::UncheckedLowlevel,
                path,
                line,
                &node_text(&ctx_node, source),
                &format!("return value of `.{}` is discarded", prop_trimmed),
            ));
        }
    }
}

/// Walk up to check whether `node` is nested inside a `require(...)` /
/// `assert(...)` call as an argument expression.
fn is_inside_require_or_assert(node: &Node, source: &str) -> bool {
    let mut cur = node.parent();
    let mut hops = 0;
    while let Some(p) = cur {
        if hops > 6 {
            break;
        }
        if p.kind() == "call_expression" {
            if let Some(callee) = resolve_callee(&p) {
                let txt = node_text(&callee, source);
                let name = txt.trim();
                if name == "require" || name == "assert" {
                    return true;
                }
            }
        }
        cur = p.parent();
        hops += 1;
    }
    false
}

// =============================================================================
// Detector 5: locked-ether
// =============================================================================

/// Per contract: if at least one function/receive/fallback is payable
/// AND the contract has NO `.transfer`, `.send`, `.call{value:...}`, or
/// `selfdestruct` call anywhere in any of its functions, emit a finding
/// on the contract declaration line.
fn detect_locked_ether(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    let contracts = find_contracts(root);
    for contract in &contracts {
        // Interfaces and libraries can't lock ether (interfaces don't
        // hold state, libraries don't receive ether). Skip them.
        if contract.kind() != "contract_declaration" {
            continue;
        }
        let funcs = contract_functions(contract);
        let has_payable = funcs.iter().any(|f| is_payable_function(f, source));
        if !has_payable {
            continue;
        }
        // Search the contract body for any withdraw-shaped expression.
        let body = match contract_body(contract) {
            Some(b) => b,
            None => continue,
        };
        if has_withdraw_path(&body, source) {
            continue;
        }
        let line = contract.start_position().row as u32 + 1;
        let name = contract_name(contract, source);
        let snippet = format!("contract {} {{ ... }}", name);
        findings.push(make_finding(
            VulnType::LockedEther,
            path,
            line,
            &snippet,
            "contract accepts ether but has no withdraw path",
        ));
    }
}

/// Whether `node` is a function/constructor/fallback-receive decl whose
/// state mutability is `payable`. Also matches `receive() external
/// payable` (the fallback_receive_definition).
fn is_payable_function(node: &Node, source: &str) -> bool {
    // For both function_definition and fallback_receive_definition the
    // grammar emits a `state_mutability` child for payable.
    is_payable(node, source)
}

/// Walk the contract body for any text matching `.transfer(`, `.send(`,
/// `.call{value`, or `selfdestruct(` / `suicide(`. We mix AST walk
/// (call_expression node-kind filtering) with a fallback text-scan for
/// `.call{value:...}` because the grammar emits the gas/value
/// modification as a `call_options` node whose shape we don't want to
/// hard-code.
fn has_withdraw_path(body: &Node, source: &str) -> bool {
    // Text-level scan over the body content. Solidity is small enough
    // and AST-only would over-fit to a particular grammar fork.
    let body_text = node_text(body, source);
    if body_text.contains(".transfer(")
        || body_text.contains(".send(")
        || body_text.contains(".call{")
        || body_text.contains("selfdestruct(")
        || body_text.contains("suicide(")
    {
        return true;
    }
    false
}

// =============================================================================
// Shared AST helpers for the pack-vuln-v1 detectors (reentrancy /
// unchecked-send / arbitrary-send / delegatecall-to-tainted).
// =============================================================================

/// Resolve the *method property name* of a `call_expression` whose callee is
/// a member access (`receiver.method(...)`), returning `Some("method")`.
///
/// Handles BOTH the plain member-call shape
/// (`call_expression -> [function] member_expression`) and the
/// value/gas-modified shape
/// (`call_expression -> [function] struct_expression -> [type] member_expression`)
/// that tree-sitter-solidity emits for `receiver.call{value: x}(...)`. The
/// `struct_expression` is the `.call{...}` options block; its `[type]` field
/// holds the underlying `member_expression`.
///
/// AST-DRIVEN: navigates `[function]` / `[type]` fields and the
/// `member_expression` `[property]` field — never substring-matches.
fn call_member_method<'a>(call: &Node<'a>, source: &str) -> Option<(Node<'a>, String)> {
    let func = call.child_by_field_name("function")?;
    let func = unwrap_expr_wrapper(func);
    let member = match func.kind() {
        "member_expression" => func,
        // `.call{value:...}` → struct_expression whose `[type]` is the member.
        "struct_expression" => {
            let ty = func.child_by_field_name("type")?;
            let ty = unwrap_expr_wrapper(ty);
            if ty.kind() != "member_expression" {
                return None;
            }
            ty
        }
        _ => return None,
    };
    let prop = member.child_by_field_name("property")?;
    let prop_name = node_text(&prop, source).trim().to_string();
    Some((member, prop_name))
}

/// Receiver (object) expression of a member-access callee — the value before
/// the final `.method`. For `msg.sender.call{...}` this is `msg.sender`; for
/// `impl.delegatecall(...)` this is `impl`. Returns the receiver node.
fn member_receiver<'a>(member: &Node<'a>) -> Option<Node<'a>> {
    member
        .child_by_field_name("object")
        .map(|n| unwrap_expr_wrapper(n))
}

/// The leading identifier of an expression — the "root" name a value derives
/// from. `impl` → `impl`; `msg.sender` → `msg`; `payable(dest)` → `dest`
/// (best-effort: first `identifier` descendant in source order).
fn leading_identifier(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(node, source).trim().to_string());
    }
    // BFS in source order for the first identifier descendant.
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier" {
            return Some(node_text(&n, source).trim().to_string());
        }
        let mut c = n.walk();
        let children: Vec<Node> = n.children(&mut c).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Collect the parameter names of a `function_definition`. These are the
/// canonical *attacker-controlled* inputs for the arbitrary-send and
/// delegatecall-to-tainted detectors (a publicly-callable function's
/// parameters are caller-chosen).
fn function_param_names(func: &Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = func.walk();
    for child in func.children(&mut cursor) {
        if child.kind() == "parameter" {
            if let Some(name_node) = child.child_by_field_name("name") {
                out.push(node_text(&name_node, source).trim().to_string());
            }
        }
    }
    out
}

/// The ordered list of top-level `statement` nodes inside a function body,
/// in source order. tree-sitter-solidity wraps each statement in a
/// `statement` node under `function_body`.
fn body_statements<'a>(func: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    if let Some(body) = func.child_by_field_name("body") {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            match child.kind() {
                "statement"
                | "expression_statement"
                | "variable_declaration_statement"
                | "if_statement"
                | "for_statement"
                | "while_statement" => out.push(child),
                _ => {}
            }
        }
    }
    out
}

/// Whether `node` (or any descendant) is an `assignment_expression` whose
/// left-hand side writes to a contract state variable named in `state_names`.
/// Covers plain (`x = ...`), indexed (`balances[k] = ...`), and member
/// (`self.x = ...`) writes by inspecting the leading identifier of the LHS.
fn writes_state_var(node: &Node, source: &str, state_names: &[String]) -> bool {
    let mut assigns: Vec<Node> = Vec::new();
    collect_by_kind(*node, &["assignment_expression"], &mut assigns);
    for assign in assigns {
        if let Some(lhs) = assign.child_by_field_name("left") {
            if let Some(root) = leading_identifier(&lhs, source) {
                if state_names.iter().any(|s| s == &root) {
                    return true;
                }
            }
        }
    }
    false
}

/// Whether any low-level value-bearing external call appears under `node`.
/// Used by the reentrancy detector to locate the "interaction" step.
fn contains_external_value_call(node: &Node, source: &str) -> bool {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*node, &["call_expression"], &mut calls);
    for call in &calls {
        if let Some((_, method)) = call_member_method(call, source) {
            if matches!(method.as_str(), "call" | "send" | "transfer") {
                return true;
            }
        }
    }
    false
}

// =============================================================================
// Detector 6: reentrancy (CEI violation)
// =============================================================================

/// For each contract function: locate the FIRST external value-bearing call
/// (`.call{value:...}` / `.send` / `.transfer`). If a write to a contract
/// state variable occurs in a statement that appears AFTER that call in
/// source order, the function violates Checks-Effects-Interactions and is
/// flagged as reentrancy.
///
/// AST-DRIVEN: statement ordering comes from the `function_body` child list;
/// the external call is matched via `call_member_method`; the state write is
/// matched via `assignment_expression` LHS leading-identifier against the
/// contract's `state_variable_declaration` names — never substring.
fn detect_reentrancy(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    let contracts = find_contracts(root);
    for contract in &contracts {
        if contract.kind() != "contract_declaration" {
            continue;
        }
        let state_names: Vec<String> = contract_state_vars(contract)
            .iter()
            .filter_map(|sv| state_var_name(sv, source))
            .filter(|n| !n.is_empty())
            .collect();
        if state_names.is_empty() {
            continue;
        }
        for func in contract_functions(contract) {
            if func.kind() != "function_definition" {
                continue;
            }
            let stmts = body_statements(&func);
            // Find the index of the first statement containing an external
            // value-bearing call.
            let call_idx = stmts
                .iter()
                .position(|s| contains_external_value_call(s, source));
            let call_idx = match call_idx {
                Some(i) => i,
                None => continue,
            };
            // Any state write in a LATER statement is a CEI violation.
            let mut violating_line: Option<u32> = None;
            for stmt in stmts.iter().skip(call_idx + 1) {
                if writes_state_var(stmt, source, &state_names) {
                    violating_line = Some(stmt.start_position().row as u32 + 1);
                    break;
                }
            }
            if let Some(_line) = violating_line {
                // Report on the external-call line (the interaction), which is
                // the actionable site for a reviewer.
                let call_line = stmts[call_idx].start_position().row as u32 + 1;
                let snippet = node_text(&stmts[call_idx], source);
                findings.push(make_finding(
                    VulnType::Reentrancy,
                    path,
                    call_line,
                    &snippet,
                    "external call precedes a state-variable write (CEI violation)",
                ));
            }
        }
    }
}

// =============================================================================
// Detector 7: unchecked-send
// =============================================================================

/// Find every `receiver.send(...)` call whose boolean return value is
/// discarded — the callee `member_expression` has property `send` and the
/// call's resolved context is an `expression_statement` (not captured by an
/// assignment / tuple destructure / `require` / `if`).
///
/// AST-DRIVEN: reuses `call_member_method` for the property and the existing
/// `is_inside_require_or_assert` guard; context resolution walks parent
/// nodes by kind — never substring.
fn detect_unchecked_send(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["call_expression"], &mut calls);
    for call in calls {
        let (_member, method) = match call_member_method(&call, source) {
            Some(m) => m,
            None => continue,
        };
        if method != "send" {
            continue;
        }
        // Captured / checked contexts are SAFE.
        if is_inside_require_or_assert(&call, source) {
            continue;
        }
        let mut ctx = call.parent();
        let mut steps = 0;
        let ctx_kind = loop {
            let n = match ctx {
                Some(n) => n,
                None => break "__none__",
            };
            match n.kind() {
                "expression_statement"
                | "assignment_expression"
                | "variable_declaration_statement"
                | "variable_declaration_tuple"
                | "tuple_expression"
                | "if_statement"
                | "while_statement"
                | "return_statement" => break n.kind(),
                _ => {}
            }
            steps += 1;
            if steps > 6 {
                break "__none__";
            }
            ctx = n.parent();
        };
        // Captured (assignment / tuple / decl) or used in a condition → SAFE.
        if matches!(
            ctx_kind,
            "assignment_expression"
                | "variable_declaration_statement"
                | "variable_declaration_tuple"
                | "tuple_expression"
                | "if_statement"
                | "while_statement"
                | "return_statement"
        ) {
            continue;
        }
        if ctx_kind == "expression_statement" {
            let line = call.start_position().row as u32 + 1;
            let snippet = enclosing_statement_text(&call, source);
            findings.push(make_finding(
                VulnType::UncheckedSend,
                path,
                line,
                &snippet,
                "return value of `.send` is discarded (failed transfers pass silently)",
            ));
        }
    }
}

// =============================================================================
// Detector 8: arbitrary-send (value to attacker-controlled destination)
// =============================================================================

/// Find every value transfer (`.transfer` / `.send` / `.call{value:...}`)
/// whose RECEIVER derives from a function parameter (caller-chosen) inside a
/// public/external function with no access-control guard. Such a call lets
/// any caller redirect the contract's ether.
///
/// AST-DRIVEN: the value-call is matched via `call_member_method`; the
/// receiver root identifier via `member_receiver` + `leading_identifier`;
/// the taint set is the enclosing function's `parameter` names; access
/// control reuses `has_access_control_modifier` / `has_msg_sender_require_guard`.
fn detect_arbitrary_send(root: &Node, source: &str, path: &Path, findings: &mut Vec<VulnFinding>) {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["call_expression"], &mut calls);
    for call in calls {
        let (member, method) = match call_member_method(&call, source) {
            Some(m) => m,
            None => continue,
        };
        // For `.call`, only the value-bearing form (struct_expression with a
        // `value:` field) is a fund transfer. `call_member_method` already
        // resolved through the struct_expression; re-check the callee shape so
        // a plain `.call(data)` (no value) is not treated as a send.
        let is_value_call = match method.as_str() {
            "transfer" | "send" => true,
            "call" => {
                // The call's `[function]` must be a struct_expression carrying
                // a `value:` field for this to move ether.
                call.child_by_field_name("function")
                    .map(|f| unwrap_expr_wrapper(f))
                    .map(|f| f.kind() == "struct_expression" && node_text(&f, source).contains("value"))
                    .unwrap_or(false)
            }
            _ => false,
        };
        if !is_value_call {
            continue;
        }
        let receiver = match member_receiver(&member) {
            Some(r) => r,
            None => continue,
        };
        let root_ident = match leading_identifier(&receiver, source) {
            Some(r) => r,
            None => continue,
        };
        let func = match enclosing_function(&call) {
            Some(f) => f,
            None => continue,
        };
        if func.kind() != "function_definition" {
            continue;
        }
        let vis = function_visibility(&func, source).unwrap_or_default();
        if vis != "public" && vis != "external" {
            continue;
        }
        // Access-controlled functions are out of scope (the privileged caller
        // is trusted to choose the destination).
        if has_access_control_modifier(&func, source)
            || has_msg_sender_require_guard(&func, source)
        {
            continue;
        }
        let params = function_param_names(&func, source);
        if !params.iter().any(|p| p == &root_ident) {
            continue;
        }
        let line = call.start_position().row as u32 + 1;
        let snippet = enclosing_statement_text(&call, source);
        findings.push(make_finding(
            VulnType::ArbitrarySend,
            path,
            line,
            &snippet,
            "ether sent to a caller-controlled destination without access control",
        ));
    }
}

// =============================================================================
// Detector 9: delegatecall-to-tainted
// =============================================================================

/// Find every `target.delegatecall(...)` whose RECEIVER derives from a
/// function parameter (caller-chosen). delegatecall runs the callee's code in
/// THIS contract's storage context, so an attacker-chosen target can rewrite
/// arbitrary storage or self-destruct the contract.
///
/// AST-DRIVEN: the delegatecall is matched via `call_member_method` (property
/// == "delegatecall"); the receiver root via `member_receiver` +
/// `leading_identifier`; the taint set is the enclosing function's parameters.
fn detect_delegatecall_tainted(
    root: &Node,
    source: &str,
    path: &Path,
    findings: &mut Vec<VulnFinding>,
) {
    let mut calls: Vec<Node> = Vec::new();
    collect_by_kind(*root, &["call_expression"], &mut calls);
    for call in calls {
        let (member, method) = match call_member_method(&call, source) {
            Some(m) => m,
            None => continue,
        };
        if method != "delegatecall" {
            continue;
        }
        let receiver = match member_receiver(&member) {
            Some(r) => r,
            None => continue,
        };
        let root_ident = match leading_identifier(&receiver, source) {
            Some(r) => r,
            None => continue,
        };
        // `msg.sender` / `address(this)` receivers are not parameter-tainted.
        let func = match enclosing_function(&call) {
            Some(f) => f,
            None => continue,
        };
        if func.kind() != "function_definition" {
            continue;
        }
        let params = function_param_names(&func, source);
        if !params.iter().any(|p| p == &root_ident) {
            continue;
        }
        let line = call.start_position().row as u32 + 1;
        let snippet = enclosing_statement_text(&call, source);
        findings.push(make_finding(
            VulnType::DelegatecallTainted,
            path,
            line,
            &snippet,
            "delegatecall target derives from caller-controlled input",
        ));
    }
}
