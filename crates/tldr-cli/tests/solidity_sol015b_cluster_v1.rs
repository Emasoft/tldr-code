//! solidity-sol015b-health-clones-smells-v1 (v0.5.0 SOL-015b):
//!
//! Three TODOs landed in one cluster:
//!   M9.  `tldr health <file>.sol` reports `summary.functions_analyzed > 0`.
//!        Pre-fix: `canonicalize_counters_from_structure` only counted
//!        kind=="function" definitions; Solidity contract members are
//!        emitted as kind=="method" so the count was 0.
//!   M10. `tldr clones <dir>` discovers `.sol` files (extension was missing
//!        from `is_source_file_for_clones` / `get_language_from_path` /
//!        clone fragment AST dispatch).
//!   M11. `tldr smells <file>.sol --format json` finds smells with a
//!        populated `smell_type` field (Solidity was missing from
//!        `resolve_language` so all Tier-1 AST detectors short-circuited).
//!
//! Hermetic fixtures; no `/tmp/repos/...` dependency. Each test writes its
//! own .sol files via `tempfile::TempDir`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

// =============================================================================
// Helpers
// =============================================================================

fn write_sol(dir: &std::path::Path, filename: &str, content: &str) -> PathBuf {
    let p = dir.join(filename);
    fs::write(&p, content).expect("write fixture");
    p
}

/// Path to the workspace's release `tldr` binary (canonical for integration
/// tests per the standing project rules).
fn tldr_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("target");
    p.push("release");
    p.push("tldr");
    p
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("run tldr");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}; stdout was:\n{out}"))
}

// =============================================================================
// M9 — health: walk ClassInfo.methods for Solidity
// =============================================================================

const TOKEN_VAULT: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenVault {
    uint256 public totalDeposits;

    function deposit(uint256 amount) external payable returns (bool) {
        if (amount > 0) {
            totalDeposits += amount;
        }
        return true;
    }

    function withdraw(uint256 amount) external returns (bool) {
        require(amount <= totalDeposits, \"insufficient\");
        totalDeposits -= amount;
        return true;
    }
}
";

#[test]
fn m9_health_solidity_contract_reports_nonzero_functions_analyzed() {
    // The fix wires Solidity into the health summary's per-language
    // canonicalisation so contract members (kind="method" in
    // structure/definitions) count toward `functions_analyzed`.
    let tmp = TempDir::new().expect("tempdir");
    let file = write_sol(tmp.path(), "TokenVault.sol", TOKEN_VAULT);

    let (code, stdout, stderr) = run_tldr(&[
        "health",
        file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "tldr health exited non-zero: stderr=\n{stderr}\nstdout=\n{stdout}"
    );

    let json = parse_json(&stdout);
    let functions_analyzed = json
        .pointer("/summary/functions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("summary.functions_analyzed missing in {json}"));
    assert!(
        functions_analyzed >= 2,
        "expected `summary.functions_analyzed >= 2` (TokenVault has 2 methods); got {functions_analyzed}; full json:\n{json}"
    );

    // Language should still be solidity.
    let language = json
        .pointer("/language")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(language, "solidity", "language field mismatch: {json}");

    // classes_analyzed must equal 1 (the TokenVault contract).
    let classes_analyzed = json
        .pointer("/summary/classes_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        classes_analyzed, 1,
        "expected classes_analyzed=1; got {classes_analyzed}; full json:\n{json}"
    );
}

#[test]
fn m9_health_solidity_free_function_also_counts() {
    // Top-level free functions (Solidity 0.7.1+) emit kind="function" in
    // structure/definitions and must still count in functions_analyzed.
    let src = "\
pragma solidity ^0.8.0;
function topLevelHelper(uint256 x) pure returns (uint256) {
    return x + 1;
}
contract C {
    function memberFn() external pure returns (uint256) {
        return topLevelHelper(1);
    }
}
";
    let tmp = TempDir::new().expect("tempdir");
    let file = write_sol(tmp.path(), "FreeFn.sol", src);

    let (code, stdout, _) = run_tldr(&[
        "health",
        file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0);
    let json = parse_json(&stdout);
    let functions_analyzed = json
        .pointer("/summary/functions_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        functions_analyzed >= 2,
        "expected free fn + contract member = 2; got {functions_analyzed}; full json:\n{json}"
    );
}

// =============================================================================
// M10 — clones: register .sol extension
// =============================================================================

const DUP_A: &str = "\
pragma solidity ^0.8.0;
contract Alpha {
    uint256 public totalDeposits;
    function deposit(uint256 amount) external payable returns (bool) {
        if (amount > 0) {
            totalDeposits += amount;
        }
        if (amount > 10) {
            totalDeposits += amount * 2;
        }
        if (amount > 100) {
            totalDeposits += amount * 3;
        }
        return true;
    }
}
";

const DUP_B: &str = "\
pragma solidity ^0.8.0;
contract Beta {
    uint256 public totalDeposits;
    function deposit(uint256 amount) external payable returns (bool) {
        if (amount > 0) {
            totalDeposits += amount;
        }
        if (amount > 10) {
            totalDeposits += amount * 2;
        }
        if (amount > 100) {
            totalDeposits += amount * 3;
        }
        return true;
    }
}
";

#[test]
fn m10_clones_finds_near_duplicate_sol_files() {
    let tmp = TempDir::new().expect("tempdir");
    write_sol(tmp.path(), "Alpha.sol", DUP_A);
    write_sol(tmp.path(), "Beta.sol", DUP_B);

    let (code, stdout, stderr) = run_tldr(&[
        "clones",
        tmp.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "tldr clones non-zero exit: stderr=\n{stderr}\nstdout=\n{stdout}"
    );
    let json = parse_json(&stdout);

    let files_analyzed = json
        .pointer("/stats/files_analyzed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        files_analyzed, 2,
        "expected 2 .sol files analyzed; got {files_analyzed}; full json:\n{json}"
    );

    let clones_found = json
        .pointer("/stats/clones_found")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        clones_found >= 1,
        "expected at least one clone pair between Alpha.sol and Beta.sol; got clones_found={clones_found}; full json:\n{json}"
    );

    let language = json
        .pointer("/language")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        language, "solidity",
        "expected dominant language=`solidity`; got `{language}`; full json:\n{json}"
    );
}

// =============================================================================
// M11 — smells: populate `smell_type` (the "type") for Solidity
// =============================================================================

/// Contract with a function whose nesting depth >= 5 (DeepNesting smell).
const DEEP_NESTING: &str = "\
pragma solidity ^0.8.0;
contract Nested {
    uint256 x;
    function deep(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) external {
        if (a > 0) {
            if (b > 0) {
                if (c > 0) {
                    if (d > 0) {
                        if (e > 0) {
                            x = a + b + c + d + e;
                        }
                    }
                }
            }
        }
    }
}
";

#[test]
fn m11_smells_solidity_deep_nesting_populates_smell_type() {
    let tmp = TempDir::new().expect("tempdir");
    let file = write_sol(tmp.path(), "Nested.sol", DEEP_NESTING);

    let (code, stdout, stderr) = run_tldr(&[
        "smells",
        file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "tldr smells non-zero: stderr=\n{stderr}\nstdout=\n{stdout}"
    );
    let json = parse_json(&stdout);

    let smells = json
        .get("smells")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("smells array missing; full json:\n{json}"));

    assert!(
        !smells.is_empty(),
        "expected at least one smell for a 5-level-nested function; got 0; full json:\n{json}"
    );

    // Every finding must have a populated `smell_type` field (NOT empty,
    // NOT "unknown").
    for s in smells.iter() {
        let smell_type = s
            .get("smell_type")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing smell_type on finding {s}; full json:\n{json}"));
        assert!(
            !smell_type.is_empty(),
            "empty smell_type on finding {s}; full json:\n{json}"
        );
        assert_ne!(
            smell_type, "unknown",
            "smell_type=\"unknown\" on finding {s}; full json:\n{json}"
        );
    }

    // At least one DeepNesting (`deep_nesting`) finding must be present —
    // the deeply nested `deep()` function is the smoking gun.
    let has_deep_nesting = smells.iter().any(|s| {
        s.get("smell_type")
            .and_then(|v| v.as_str())
            .map(|t| t == "deep_nesting")
            .unwrap_or(false)
    });
    assert!(
        has_deep_nesting,
        "expected at least one `deep_nesting` finding; got smell_types={:?}; full json:\n{json}",
        smells
            .iter()
            .map(|s| s.get("smell_type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

/// Contract with a function that has > 5 parameters (LongParameterList
/// smell). This exercises the `extract_file` -> `ClassInfo.methods` arm
/// (SOL-003) — distinct from the Tier-1 AST arm pinned by the
/// deep-nesting test — so a second smell type guards regression on the
/// smells side of the Solidity integration.
const LONG_PARAMS: &str = "\
pragma solidity ^0.8.0;
contract LongParamsOne {
    uint256 x;
    function manyArgs(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d,
        uint256 e,
        uint256 f,
        uint256 g
    ) external {
        x = a + b + c + d + e + f + g;
    }
}
";

#[test]
fn m11_smells_solidity_long_parameter_list_populates_smell_type() {
    let tmp = TempDir::new().expect("tempdir");
    let file = write_sol(tmp.path(), "LongParams.sol", LONG_PARAMS);

    let (code, stdout, stderr) = run_tldr(&[
        "smells",
        file.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "tldr smells non-zero: stderr=\n{stderr}\nstdout=\n{stdout}"
    );
    let json = parse_json(&stdout);

    let smells = json
        .get("smells")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("smells array missing; full json:\n{json}"));

    assert!(
        !smells.is_empty(),
        "expected at least one smell on a 7-param method; got 0; full json:\n{json}"
    );

    let has_long_params = smells.iter().any(|s| {
        s.get("smell_type")
            .and_then(|v| v.as_str())
            .map(|t| t == "long_parameter_list")
            .unwrap_or(false)
    });
    assert!(
        has_long_params,
        "expected at least one `long_parameter_list` finding; got smell_types={:?}; full json:\n{json}",
        smells
            .iter()
            .map(|s| s.get("smell_type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect::<Vec<_>>()
    );

    // smell_type must never be empty / "unknown" on any finding.
    for s in smells {
        let st = s
            .get("smell_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            !st.is_empty() && st != "unknown",
            "bad smell_type=`{st}` on finding {s}; full json:\n{json}"
        );
    }
}
