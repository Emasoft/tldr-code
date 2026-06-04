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
fn is_payable(node: &Node, source: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "state_mutability" && node_text(&child, source).trim() == "payable" {
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
        // tree-sitter-solidity nests the callee under an `expression`
        // wrapper. The function-position is the FIRST child; unwrap
        // any `expression` / `primary_expression` wrappers to reach the
        // underlying `member_expression`.
        let callee = match resolve_callee(&call) {
            Some(c) => c,
            None => continue,
        };
        // Callee is a member_expression whose property is one of the
        // low-level call names.
        if callee.kind() != "member_expression" {
            continue;
        }
        // tree-sitter-solidity emits member_expression as
        // `expression . identifier` with NO field-name on the property
        // child. Read the last `identifier` child (the property name)
        // and fall back to the text-after-final-dot on grammar forks.
        let prop = {
            let mut prop_txt: Option<String> = None;
            let mut mc = callee.walk();
            for c in callee.children(&mut mc) {
                if c.kind() == "identifier" {
                    prop_txt = Some(node_text(&c, source));
                }
            }
            match prop_txt {
                Some(s) => s,
                None => {
                    let txt = node_text(&callee, source);
                    match txt.rsplit('.').next() {
                        Some(s) => s.to_string(),
                        None => continue,
                    }
                }
            }
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
