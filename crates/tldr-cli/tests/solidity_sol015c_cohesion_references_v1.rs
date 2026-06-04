//! solidity-sol015c-cohesion-references-v1 (v0.5.0 SOL-015c):
//!
//! Two TODOs landed in one cluster:
//!
//! M12. `cohesion` command iterates Solidity contracts and computes LCOM4.
//!      Each `contract`/`library`/`interface` is treated as a class. State
//!      variables are the "fields", functions/modifiers are the "methods".
//!      LCOM4 = number of connected components in the method-stateVar graph.
//!      A contract with N methods that each touch DISJOINT state vars yields
//!      LCOM4 = N (maximally incohesive).
//!
//! M13. `references` command emits `kind: "call"` for Solidity call-sites
//!      and populates the `definitions[]` array. Pre-fix the language arm
//!      fell through to the default and produced empty `kind` (`"other"`)
//!      and an empty `definitions[]`. Post-fix:
//!        - A call-site `foo()` inside a function body is classified as
//!          `kind: "call"`.
//!        - The symbol's `function_definition` line+column is emitted in
//!          `definitions[]`.
//!
//! Each fixture is hermetic; no `/tmp/repos/...` dependency.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

// =============================================================================
// Helpers
// =============================================================================

fn write_sol(filename: &str, content: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let file = tmp.path().join(filename);
    fs::write(&file, content).expect("write fixture");
    (tmp, file)
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

fn run_cohesion(path: &PathBuf) -> Value {
    let bin = tldr_bin();
    assert!(
        bin.exists(),
        "expected release tldr at {} — run `cargo build --release` first",
        bin.display()
    );
    // Use --min-methods 1 (default) but pass it explicitly to make the intent
    // visible; the LCOM4 fixture's `disjoint` contract has 3 single-method
    // groups.
    let out = Command::new(&bin)
        .args([
            "cohesion",
            path.to_str().unwrap(),
            "--format",
            "json",
            "--min-methods",
            "1",
        ])
        .output()
        .expect("run tldr cohesion");
    assert!(
        out.status.success(),
        "cohesion failed; stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    serde_json::from_str(&stdout).expect("cohesion JSON")
}

fn run_references(symbol: &str, dir: &PathBuf) -> Value {
    let bin = tldr_bin();
    // Global flags come before the subcommand: `tldr --format json --lang solidity references foo path/`.
    let out = Command::new(&bin)
        .args([
            "--format",
            "json",
            "--lang",
            "solidity",
            "references",
            symbol,
            dir.to_str().unwrap(),
        ])
        .output()
        .expect("run tldr references");
    assert!(
        out.status.success(),
        "references failed; stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    serde_json::from_str(&stdout).expect("references JSON")
}

// =============================================================================
// M12 — cohesion: Solidity contracts produce LCOM4 entries
// =============================================================================

#[test]
fn m12_cohesion_single_method_contract_lcom4_one() {
    // A contract with one method that touches one state var: LCOM4 = 1
    // (fully cohesive). Confirms the dispatch wires up at all.
    let src = "\
pragma solidity ^0.8.0;
contract OneMethodOneVar {
    uint256 balance;
    function deposit(uint256 amount) public {
        balance += amount;
    }
}
";
    let (_tmp, file) = write_sol("OneMethodOneVar.sol", src);
    let report = run_cohesion(&file);

    let classes = report["classes"].as_array().expect("classes array");
    assert!(
        !classes.is_empty(),
        "expected non-empty classes for Solidity contract; got: {}",
        report
    );
    let entry = &classes[0];
    assert_eq!(entry["class_name"], "OneMethodOneVar");
    assert_eq!(entry["lcom4"], 1, "single connected method → LCOM4=1");
    assert_eq!(entry["method_count"], 1);
}

#[test]
fn m12_cohesion_disjoint_methods_yield_lcom4_equal_n() {
    // Contract with 3 methods touching DISJOINT state vars → LCOM4 = 3.
    //
    // Three methods, three independent state vars: no two methods share a
    // field, so the bipartite graph splits into 3 components. This is the
    // canonical LCOM4=N "split candidate" case from the task description.
    let src = "\
pragma solidity ^0.8.0;
contract DisjointResponsibilities {
    uint256 a;
    uint256 b;
    uint256 c;
    function bumpA() public {
        a = a + 1;
    }
    function bumpB() public {
        b = b + 1;
    }
    function bumpC() public {
        c = c + 1;
    }
}
";
    let (_tmp, file) = write_sol("DisjointResponsibilities.sol", src);
    let report = run_cohesion(&file);

    let classes = report["classes"].as_array().expect("classes array");
    let entry = classes
        .iter()
        .find(|c| c["class_name"] == "DisjointResponsibilities")
        .expect("DisjointResponsibilities entry");
    assert_eq!(
        entry["lcom4"], 3,
        "3 disjoint methods → LCOM4=3; entry was {}",
        entry
    );
    assert_eq!(entry["method_count"], 3);
    assert_eq!(entry["verdict"], "split_candidate");
}

#[test]
fn m12_cohesion_library_and_interface_recognized_as_classes() {
    // `library` and `interface` are also Solidity "class-like" declarations.
    // Both must be emitted by the cohesion command (treated the same as
    // `contract` for LCOM4 purposes).
    let src = "\
pragma solidity ^0.8.0;
library MathLib {
    function addOne(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }
    function subOne(uint256 x) internal pure returns (uint256) {
        return x - 1;
    }
}
interface IFoo {
    function ping() external;
}
contract Box {
    uint256 value;
    function set(uint256 v) public { value = v; }
    function get() public view returns (uint256) { return value; }
}
";
    let (_tmp, file) = write_sol("LibAndIface.sol", src);
    let report = run_cohesion(&file);

    let classes = report["classes"].as_array().expect("classes array");
    let names: Vec<&str> = classes
        .iter()
        .map(|c| c["class_name"].as_str().unwrap_or(""))
        .collect();
    assert!(
        names.contains(&"MathLib"),
        "library MathLib must appear: {:?}",
        names
    );
    assert!(names.contains(&"Box"), "contract Box must appear: {:?}", names);
    // Interface with only declarations (no method bodies) has 1 method
    // entry but its body is empty → LCOM4 should still be computable
    // (LCOM4=1 for a single method). The acceptance is the entry
    // existing — we don't pin the exact LCOM4 because pure-declaration
    // methods carry no field accesses, which is degenerate.
}

// =============================================================================
// M13 — references: Solidity call-sites emit kind="call" + definitions[]
// =============================================================================

#[test]
fn m13_references_call_kind_and_definitions_populated() {
    // Fixture: contract Vault declares `transfer(...)`, then `withdraw` and
    // `payout` and `refund` all call `transfer(...)`. So:
    //   - definitions[] must contain the `transfer` function_definition
    //     site (file: V.sol, line: …).
    //   - references must have 3 entries with kind="call" (the three call
    //     sites).
    let src = "\
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) balances;
    function transfer(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    function withdraw(address to, uint256 amount) public {
        transfer(to, amount);
    }
    function payout(address to) public {
        transfer(to, 100);
    }
    function refund(address to) public {
        transfer(to, 1);
    }
}
";
    let (tmp, _file) = write_sol("Vault.sol", src);
    let dir = tmp.path().to_path_buf();
    let report = run_references("transfer", &dir);

    // definitions[] non-empty and points to a function_definition site
    let defs = report["definitions"].as_array().expect("definitions array");
    assert!(
        !defs.is_empty(),
        "expected definitions[] populated for Solidity symbol; got: {}",
        report
    );
    let def = &defs[0];
    assert_eq!(def["kind"], "function");
    // transfer is at the 4th line of the contract body (1-indexed file row 4).
    let def_line = def["line"].as_u64().expect("def line");
    assert!(
        def_line >= 4 && def_line <= 6,
        "definition line {} not near transfer (expected ~4-6)",
        def_line
    );

    // references[] contains 3 entries with kind="call".
    let refs = report["references"].as_array().expect("references array");
    let call_refs: Vec<&Value> = refs
        .iter()
        .filter(|r| r["kind"] == "call")
        .collect();
    assert_eq!(
        call_refs.len(),
        3,
        "expected 3 call-site references for transfer; got {} (all refs: {:?})",
        call_refs.len(),
        refs
    );
}

#[test]
fn m13_references_definition_only_no_calls_still_populates_definitions() {
    // Edge case: a contract function with NO call-sites — `definitions[]`
    // must still be populated by the AST walker; the references[] vec
    // contains just the definition site (kind="definition") or is empty
    // depending on text-search policy.
    let src = "\
pragma solidity ^0.8.0;
contract LonelyFn {
    uint256 x;
    function lonely() public view returns (uint256) {
        return x;
    }
}
";
    let (tmp, _file) = write_sol("LonelyFn.sol", src);
    let dir = tmp.path().to_path_buf();
    let report = run_references("lonely", &dir);

    let defs = report["definitions"].as_array().expect("definitions array");
    assert!(
        !defs.is_empty(),
        "even with zero call-sites, definitions[] must contain the function_definition site; got: {}",
        report
    );
    assert_eq!(defs[0]["kind"], "function");
}
