//! fix-pack-apicheck-v1 (v0.5.0 PACK-APICHECK): AST-driven Solidity ERC
//! conformance api-check rules.
//!
//! These tests pin the contract-level (NOT line/regex) ERC conformance
//! detectors added to `api_check.rs`:
//!
//!   * ERC001 — ERC20 conformance. A contract that claims ERC20 (inherits an
//!     ERC20 base/interface OR declares a strong subset of the ERC20 surface)
//!     must expose `totalSupply / balanceOf / transfer / transferFrom /
//!     approve / allowance` + the `Transfer` / `Approval` events. A
//!     conformant implementation (OpenZeppelin `IERC20` / `ERC20`) produces
//!     ZERO ERC001 findings; an incomplete one produces a missing-member
//!     finding.
//!
//!   * ERC002 — ERC721 conformance (ownerOf / safeTransferFrom / ...).
//!
//!   * ERC003 — SafeERC20 recommendation: a raw ERC20 `transfer` /
//!     `transferFrom` whose boolean return value is discarded should be
//!     flagged; a `require(token.transferFrom(...))` must NOT be.
//!
//! All detection is driven off the tree-sitter-solidity AST
//! (`contract_declaration` / `interface_declaration`, `function_definition`,
//! `event_definition`, `inheritance_specifier`) — never text/regex.

use std::path::PathBuf;
use std::process::Command;

fn tldr_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn fixture(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .join("tests")
        .join("fixtures")
        .join("pack_apicheck")
        .join(name)
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

fn findings_with_rule_prefix(v: &serde_json::Value, prefix: &str) -> usize {
    v.get("findings")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("rule")
                        .and_then(|r| r.get("id"))
                        .and_then(|s| s.as_str())
                        .map(|id| id.starts_with(prefix))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn finding_messages_for_rule(v: &serde_json::Value, rule_id: &str) -> Vec<String> {
    v.get("findings")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("rule")
                        .and_then(|r| r.get("id"))
                        .and_then(|s| s.as_str())
                        == Some(rule_id)
                })
                .filter_map(|f| f.get("message").and_then(|m| m.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The canonical OpenZeppelin ERC20 interface conforms fully: ZERO ERC001
/// findings against `IERC20.sol`.
#[test]
fn ierc20_interface_is_conformant() {
    let path = "/tmp/repos/solidity-openzeppelin/contracts/token/ERC20/IERC20.sol";
    if !PathBuf::from(path).exists() {
        eprintln!("skip: corpus missing {path}");
        return;
    }
    let (code, out) = run_tldr(&["api-check", path, "--format", "json"]);
    assert_eq!(code, 0, "api-check exited non-zero: {out}");
    let v = parse_json(&out);
    let n = findings_with_rule_prefix(&v, "ERC001");
    assert_eq!(
        n, 0,
        "OpenZeppelin IERC20 is a conformant ERC20 surface; expected 0 ERC001 findings, got {n}: {out}"
    );
}

/// The canonical OpenZeppelin ERC20 implementation conforms fully: ZERO
/// ERC001 findings against `ERC20.sol`.
#[test]
fn erc20_implementation_is_conformant() {
    let path = "/tmp/repos/solidity-openzeppelin/contracts/token/ERC20/ERC20.sol";
    if !PathBuf::from(path).exists() {
        eprintln!("skip: corpus missing {path}");
        return;
    }
    let (code, out) = run_tldr(&["api-check", path, "--format", "json"]);
    assert_eq!(code, 0, "api-check exited non-zero: {out}");
    let v = parse_json(&out);
    let n = findings_with_rule_prefix(&v, "ERC001");
    assert_eq!(
        n, 0,
        "OpenZeppelin ERC20 is a conformant ERC20 implementation; expected 0 ERC001 findings, got {n}: {out}"
    );
}

/// A deliberately-incomplete ERC20 (missing allowance / approve /
/// transferFrom) must produce an ERC001 missing-member finding.
#[test]
fn incomplete_erc20_flags_missing_members() {
    let path = fixture("IncompleteERC20.sol");
    let path_str = path.to_str().unwrap();
    let (code, out) = run_tldr(&["api-check", path_str, "--format", "json"]);
    assert_eq!(code, 0, "api-check exited non-zero: {out}");
    let v = parse_json(&out);
    let n = findings_with_rule_prefix(&v, "ERC001");
    assert!(
        n >= 1,
        "IncompleteERC20 is missing required ERC20 members; expected >=1 ERC001 finding, got {n}: {out}"
    );
    let messages = finding_messages_for_rule(&v, "ERC001");
    let joined = messages.join(" | ");
    assert!(
        joined.contains("allowance")
            || joined.contains("approve")
            || joined.contains("transferFrom"),
        "ERC001 finding should name a missing member (allowance/approve/transferFrom); got: {joined}"
    );
}

/// The OpenZeppelin ERC721 implementation conforms: ZERO ERC002 findings.
#[test]
fn erc721_implementation_is_conformant() {
    let path = "/tmp/repos/solidity-openzeppelin/contracts/token/ERC721/ERC721.sol";
    if !PathBuf::from(path).exists() {
        eprintln!("skip: corpus missing {path}");
        return;
    }
    let (code, out) = run_tldr(&["api-check", path, "--format", "json"]);
    assert_eq!(code, 0, "api-check exited non-zero: {out}");
    let v = parse_json(&out);
    let n = findings_with_rule_prefix(&v, "ERC002");
    assert_eq!(
        n, 0,
        "OpenZeppelin ERC721 is conformant; expected 0 ERC002 findings, got {n}: {out}"
    );
}

/// A raw ERC20 `transfer` with a discarded return value is flagged ERC003,
/// while a `require(token.transferFrom(...))` is not.
#[test]
fn raw_transfer_unchecked_recommends_safeerc20() {
    let path = fixture("RawTransferUnchecked.sol");
    let path_str = path.to_str().unwrap();
    let (code, out) = run_tldr(&["api-check", path_str, "--format", "json"]);
    assert_eq!(code, 0, "api-check exited non-zero: {out}");
    let v = parse_json(&out);
    let n = findings_with_rule_prefix(&v, "ERC003");
    assert_eq!(
        n, 1,
        "exactly one raw unchecked transfer should be flagged ERC003 (the require(...)-wrapped one must not be); got {n}: {out}"
    );
}
