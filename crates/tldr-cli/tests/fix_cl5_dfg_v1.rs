//! fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): DFG use-detection / dead-store fixes.
//!
//! Four reproduced iter-3b gaps, all rooted in the per-function DFG use
//! classifier and the dead-store detector misclassifying non-variable
//! identifiers or aggregate/conditional writes:
//!
//!   * IT3-ruby-03  — `reaching-defs config_validator.rb check_target_ruby`
//!     flagged method-call names (`inspect`, `join`, `raise`, `supported?`,
//!     `supported_versions`, `rubocop_version_with_support`, `target_ruby`,
//!     `target_ruby_version`) as definite-uninitialized VARIABLES. They are
//!     method calls, not locals. Fixed by a Ruby `is_use_context` arm that
//!     drops the `method` field of a `call` node and any receiver-less bare
//!     identifier that is not a declared local.
//!
//!   * IT3-luau-03  — `dead-stores Ast/src/Parser.cpp parseIf` reported
//!     `matchThenElse@590` as a dead store. It is conditionally overwritten at
//!     596 (inside a nested `if`) and used unconditionally at 600/605. The CFG
//!     failed to split the nested `if` inside the `else { ... }`
//!     `compound_statement`, collapsing the conditional store and the later
//!     uses into one coarse block. Fixed by recursing into bare
//!     `compound_statement` nodes in the CFG extractor.
//!
//!   * IT3-typescript-01 — `dead-stores scanner.ts scanForModules` reported
//!     `moduleDefinition` (a destructured parameter) as a dead store because
//!     the analyzed function's own parameter names were collected into the
//!     import-suppression set, dropping every read of the parameter. Fixed by
//!     NOT collecting the analyzed function's own parameters into that set.
//!
//!   * IT3-solidity-02 — `dead-stores AccessControl.sol _grantRole` reported
//!     the state-variable mapping write `_roles[role].hasRole[account] = true`
//!     (line 185) as a dead store. A partial aggregate / state write is a
//!     `RefType::Update` (read-modify-write) and is never a dead store. Fixed
//!     by excluding `Update` refs from dead-store reporting.
//!
//! Gated on the real corpora under /tmp/tldr_corpora; FAIL before the fix.

use std::path::Path;
use std::process::Command;

const RUBY_CONFIG_VALIDATOR: &str =
    "/tmp/tldr_corpora/ruby-rubocop/lib/rubocop/config_validator.rb";
const LUAU_PARSER: &str = "/tmp/tldr_corpora/luau/Ast/src/Parser.cpp";
const TS_SCANNER: &str = "/tmp/tldr_corpora/typescript-nest/packages/core/scanner.ts";
const SOL_ACCESS_CONTROL: &str =
    "/tmp/tldr_corpora/solidity-openzeppelin/contracts/access/AccessControl.sol";

fn tldr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

fn reaching_defs(file: &str, func: &str) -> serde_json::Value {
    let (code, stdout, stderr) = run_tldr(&["reaching-defs", file, func, "--format", "json"]);
    assert_eq!(code, 0, "reaching-defs failed: {stdout} {stderr}");
    serde_json::from_str(&stdout).expect("reaching-defs emitted non-JSON")
}

fn dead_stores(file: &str, func: &str) -> serde_json::Value {
    let (code, stdout, stderr) = run_tldr(&["dead-stores", file, func, "--format", "json"]);
    assert_eq!(code, 0, "dead-stores failed: {stdout} {stderr}");
    serde_json::from_str(&stdout).expect("dead-stores emitted non-JSON")
}

fn uninit_vars(v: &serde_json::Value) -> Vec<String> {
    v.get("uninitialized")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("var").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn dead_store_entries(v: &serde_json::Value) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for key in ["dead_stores_ssa", "dead_stores_live_vars"] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            for item in arr {
                if let (Some(name), Some(line)) = (
                    item.get("variable").and_then(|s| s.as_str()),
                    item.get("line").and_then(|l| l.as_u64()),
                ) {
                    out.push((name.to_string(), line));
                }
            }
        }
    }
    out
}

// =============================================================================
// IT3-ruby-03: method-call names must not be flagged uninitialized.
// =============================================================================

#[test]
fn ruby_method_calls_not_uninitialized() {
    if !Path::new(RUBY_CONFIG_VALIDATOR).exists() {
        eprintln!("skipping: corpus not present at {RUBY_CONFIG_VALIDATOR}");
        return;
    }
    let v = reaching_defs(RUBY_CONFIG_VALIDATOR, "check_target_ruby");
    let names = uninit_vars(&v);
    // All of these are method calls in `check_target_ruby`, never local vars.
    for method in [
        "inspect",
        "join",
        "raise",
        "supported?",
        "supported_versions",
        "rubocop_version_with_support",
        "target_ruby",
        "target_ruby_version",
    ] {
        assert!(
            !names.iter().any(|n| n == method),
            "Ruby method call '{method}' must not be flagged uninitialized. Got: {names:?}"
        );
    }
}

// =============================================================================
// IT3-luau-03: conditional overwrite must not mark the prior store dead.
// =============================================================================

#[test]
fn luau_conditional_overwrite_not_dead_store() {
    if !Path::new(LUAU_PARSER).exists() {
        eprintln!("skipping: corpus not present at {LUAU_PARSER}");
        return;
    }
    let ds = dead_stores(LUAU_PARSER, "parseIf");
    let entries = dead_store_entries(&ds);
    assert!(
        !entries
            .iter()
            .any(|(name, line)| name == "matchThenElse" && *line == 590),
        "luau 'matchThenElse@590' is conditionally overwritten at 596 and used \
         unconditionally at 600/605 — it is live, not a dead store. Got: {entries:?}"
    );
}

// =============================================================================
// IT3-typescript-01: destructured parameter reads must not be dead stores.
// =============================================================================

#[test]
fn typescript_param_reassignment_not_dead_store() {
    if !Path::new(TS_SCANNER).exists() {
        eprintln!("skipping: corpus not present at {TS_SCANNER}");
        return;
    }
    let ds = dead_stores(TS_SCANNER, "scanForModules");
    let entries = dead_store_entries(&ds);
    assert!(
        !entries.iter().any(|(name, _)| name == "moduleDefinition"),
        "TS 'moduleDefinition' is a destructured parameter read on the RHS of its \
         own reassignments and by ctxRegistry.push — none of its stores are dead. \
         Got: {entries:?}"
    );
}

// =============================================================================
// IT3-solidity-02: state-variable mapping write is never a dead store.
// =============================================================================

#[test]
fn solidity_state_write_not_dead_store() {
    if !Path::new(SOL_ACCESS_CONTROL).exists() {
        eprintln!("skipping: corpus not present at {SOL_ACCESS_CONTROL}");
        return;
    }
    let ds = dead_stores(SOL_ACCESS_CONTROL, "_grantRole");
    let entries = dead_store_entries(&ds);
    assert!(
        !entries.iter().any(|(name, _)| name == "_roles"),
        "Solidity '_roles[role].hasRole[account] = true' is an observable state \
         write (read-modify-write Update) and can never be a dead store. Got: {entries:?}"
    );
}
