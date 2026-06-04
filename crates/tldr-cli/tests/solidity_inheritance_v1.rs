//! solidity-inheritance-v1 (v0.5.0 SOL-005c)
//!
//! Integration test for `tldr inheritance --lang solidity`. Validates:
//!   1. Diamond pattern (A is B,C ; B is D ; C is D) produces 4 edges.
//!   2. Declared base order is preserved (no C3 linearization in v1).
//!   3. Interface inheritance (`contract X is IFoo, IBar`) flattens to
//!      both interface parents in source order.
//!
//! Schema parity: `bases:[]` is always an array and edges carry
//! `child`, `parent`, and `kind` fields (mirroring
//! `inheritance_walker_per_lang_v1.rs`).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn parse_json(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!("Failed to parse JSON: {}\nstdout:\n{}", e, stdout);
    })
}

/// Diamond pattern: `contract A is B, C` over `B is D` and `C is D`.
/// Must produce exactly 4 inheritance relations:
///   A -> B, A -> C, B -> D, C -> D
#[test]
fn test_solidity_diamond_produces_four_edges() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Diamond.sol"),
        r#"
pragma solidity ^0.8.0;

contract D {
    uint256 public d;
}

contract B is D {
    function bfn() public {}
}

contract C is D {
    function cfn() public {}
}

contract A is B, C {
    function afn() public {}
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "solidity",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    // Verify the four expected edges exist (regardless of ordering).
    let expected = [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")];
    for (child, parent) in expected {
        let found = edges
            .iter()
            .find(|e| e["child"] == child && e["parent"] == parent);
        assert!(
            found.is_some(),
            "missing {}->{} edge in {:?}",
            child,
            parent,
            edges
        );
    }

    // Exactly 4 inheritance edges -- no spurious self-loops or
    // mis-attributed parents from grammar walk.
    assert_eq!(
        edges.len(),
        4,
        "expected exactly 4 inheritance edges, got {}: {:?}",
        edges.len(),
        edges
    );
}

/// Declared base order is preserved: `A is B, C` -> A's parents are
/// [B, C] in that exact source order (no C3 linearization in v1).
#[test]
fn test_solidity_base_order_preserved() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Order.sol"),
        r#"
pragma solidity ^0.8.0;

contract B {}
contract C {}
contract A is B, C {}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "solidity",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let nodes = v["nodes"].as_array().expect("nodes array");

    // Find node "A" and assert its bases vec is exactly [B, C] in order.
    let a = nodes
        .iter()
        .find(|n| n["name"] == "A")
        .unwrap_or_else(|| panic!("missing node A in {:?}", nodes));
    let bases = a["bases"].as_array().expect("bases array");
    let names: Vec<&str> = bases.iter().map(|b| b.as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec!["B", "C"],
        "declared base order must be preserved (B before C)"
    );
}

/// Interface inheritance: `contract X is IFoo, IBar` flattens to
/// both interface parents. Both IFoo and IBar must appear as parents
/// of X with the interface flag set on the parent nodes.
#[test]
fn test_solidity_interface_inheritance_flattened() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Iface.sol"),
        r#"
pragma solidity ^0.8.0;

interface IFoo {
    function foo() external;
}

interface IBar {
    function bar() external;
}

contract X is IFoo, IBar {
    function foo() external {}
    function bar() external {}
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "solidity",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    for parent in &["IFoo", "IBar"] {
        let found = edges
            .iter()
            .find(|e| e["child"] == "X" && e["parent"] == *parent);
        assert!(
            found.is_some(),
            "missing X->{} interface inheritance edge in {:?}",
            parent,
            edges
        );
    }

    // Interface nodes must carry the interface flag.
    let nodes = v["nodes"].as_array().expect("nodes array");
    for name in &["IFoo", "IBar"] {
        let node = nodes
            .iter()
            .find(|n| n["name"] == *name)
            .unwrap_or_else(|| panic!("missing interface node {} in {:?}", name, nodes));
        assert_eq!(
            node["interface"], true,
            "interface {} must have interface=true",
            name
        );
    }

    // X is a contract -- interface flag should be absent (skipped by serde
    // when None) or false. Assert it is NOT set to true.
    let x = nodes
        .iter()
        .find(|n| n["name"] == "X")
        .unwrap_or_else(|| panic!("missing node X in {:?}", nodes));
    assert_ne!(
        x["interface"], true,
        "contract X must not be marked as interface"
    );
}
