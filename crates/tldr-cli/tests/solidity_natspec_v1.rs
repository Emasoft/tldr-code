//! solidity-natspec-v1 (v0.5.0 SOL-010): integration test for the
//! NatSpec doc-comment parser.
//!
//! Covers:
//!   - `parse_solidity_natspec` over `///` single-line and `/** */` block
//!   - Extraction of `@notice` / `@dev` / `@param NAME text` /
//!     `@return [NAME] text` / `@inheritdoc CONTRACT` / `@custom:KEY val`
//!     / `@title` / `@author`.
//!   - `tldr contracts` Solidity arm: `@param` → precondition,
//!     `@return` → postcondition.

use std::fs;
use std::process::Command;

use tempfile::TempDir;

use tldr_core::ast::extract::parse_solidity_natspec;

const FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MathLib
/// @author Alice
/// @notice Provides arithmetic helpers
/// @dev Internal-only library
contract Calc {
    /// @notice Multiply two integers
    /// @dev Pure math, no side effects
    /// @param x The first input
    /// @param y The second input
    /// @return result The product of x and y
    /// @custom:audit OZ-2024-001
    function mul(uint256 x, uint256 y) external pure returns (uint256 result) {
        result = x * y;
    }

    /**
     * @notice Block-style NatSpec docstring
     * @dev Uses block comment markers
     * @param a First operand
     * @param b Second operand
     * @return sum a + b
     * @inheritdoc IBase
     */
    function add(uint256 a, uint256 b) external pure returns (uint256 sum) {
        sum = a + b;
    }
}
";

fn write_fixture() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("Calc.sol");
    fs::write(&file, FIXTURE).unwrap();
    (tmp, file)
}

#[test]
fn parse_single_line_natspec_extracts_all_tags() {
    let text = "@notice Multiply two integers\n\
                @dev Pure math, no side effects\n\
                @param x The first input\n\
                @param y The second input\n\
                @return result The product of x and y\n\
                @custom:audit OZ-2024-001";
    let doc = parse_solidity_natspec(text);

    assert_eq!(
        doc.notice.as_deref(),
        Some("Multiply two integers"),
        "@notice should be captured; got: {:?}",
        doc.notice
    );
    assert_eq!(
        doc.dev.as_deref(),
        Some("Pure math, no side effects"),
        "@dev should be captured; got: {:?}",
        doc.dev
    );
    assert_eq!(doc.params.len(), 2, "should have 2 @param entries: {:?}", doc.params);
    assert_eq!(doc.params[0].name, "x");
    assert_eq!(doc.params[0].text, "The first input");
    assert_eq!(doc.params[1].name, "y");
    assert_eq!(doc.params[1].text, "The second input");

    assert_eq!(doc.returns.len(), 1, "should have 1 @return entry: {:?}", doc.returns);
    assert_eq!(doc.returns[0].name.as_deref(), Some("result"));
    assert_eq!(doc.returns[0].text, "The product of x and y");

    // @custom:audit → custom_tags["audit"] = ["OZ-2024-001"]
    let audit = doc.custom_tags.get("audit").expect("custom:audit should be present");
    assert!(
        audit.iter().any(|v| v == "OZ-2024-001"),
        "expected custom:audit to capture OZ-2024-001; got: {:?}",
        audit
    );
}

#[test]
fn parse_block_natspec_strips_leading_star_markers() {
    let text = "/**\n\
                 * @notice Block-style NatSpec docstring\n\
                 * @dev Uses block comment markers\n\
                 * @param a First operand\n\
                 * @param b Second operand\n\
                 * @return sum a + b\n\
                 * @inheritdoc IBase\n\
                 */";
    let doc = parse_solidity_natspec(text);

    assert_eq!(
        doc.notice.as_deref(),
        Some("Block-style NatSpec docstring"),
        "block @notice should be captured after stripping ` * ` prefix; got: {:?}",
        doc.notice
    );
    assert_eq!(doc.params.len(), 2);
    assert_eq!(doc.params[0].name, "a");
    assert_eq!(doc.params[0].text, "First operand");
    assert_eq!(doc.params[1].name, "b");
    assert_eq!(doc.params[1].text, "Second operand");

    assert_eq!(doc.returns.len(), 1);
    assert_eq!(doc.returns[0].name.as_deref(), Some("sum"));
    assert_eq!(doc.returns[0].text, "a + b");

    assert_eq!(
        doc.inheritdoc.as_deref(),
        Some("IBase"),
        "@inheritdoc IBase should be captured; got: {:?}",
        doc.inheritdoc
    );
}

#[test]
fn parse_natspec_with_title_and_author_metadata() {
    let text = "@title MathLib\n\
                @author Alice\n\
                @notice Provides arithmetic helpers";
    let doc = parse_solidity_natspec(text);
    assert_eq!(doc.title.as_deref(), Some("MathLib"));
    assert_eq!(doc.author.as_deref(), Some("Alice"));
    assert_eq!(doc.notice.as_deref(), Some("Provides arithmetic helpers"));
}

#[test]
fn parse_natspec_return_without_name_only_text() {
    // `@return The result value` -- no name slot
    let text = "@return The result value";
    let doc = parse_solidity_natspec(text);
    assert_eq!(doc.returns.len(), 1);
    assert!(
        doc.returns[0].name.is_none(),
        "no name slot expected; got: {:?}",
        doc.returns[0].name
    );
    assert_eq!(doc.returns[0].text, "The result value");
}

#[test]
fn parse_natspec_empty_returns_empty_doc() {
    let doc = parse_solidity_natspec("");
    assert!(doc.notice.is_none());
    assert!(doc.dev.is_none());
    assert!(doc.params.is_empty());
    assert!(doc.returns.is_empty());
    assert!(doc.inheritdoc.is_none());
    assert!(doc.custom_tags.is_empty());
}

/// Verify `tldr contracts` over a Solidity file maps `@param NAME text`
/// onto preconditions (low confidence) and `@return [NAME] text` onto
/// postconditions (low confidence).
#[test]
fn contracts_emits_natspec_param_as_precondition_and_return_as_postcondition() {
    let (_tmp, file) = write_fixture();
    let tldr = env!("CARGO_BIN_EXE_tldr");
    let output = Command::new(tldr)
        .arg("contracts")
        .arg(file.to_str().unwrap())
        .arg("mul")
        .arg("--format")
        .arg("json")
        .output()
        .expect("tldr contracts should run");
    assert!(
        output.status.success(),
        "tldr contracts failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("contracts should emit JSON");

    let pre = report["preconditions"]
        .as_array()
        .expect("preconditions array");
    let post = report["postconditions"]
        .as_array()
        .expect("postconditions array");

    // NatSpec @param x → precondition with variable "x"
    assert!(
        pre.iter().any(|c| c["variable"] == "x"
            && c["constraint"].as_str().unwrap_or("").contains("The first input")),
        "expected NatSpec @param x with 'The first input' in preconditions; got: {:#?}",
        pre
    );
    assert!(
        pre.iter().any(|c| c["variable"] == "y"
            && c["constraint"].as_str().unwrap_or("").contains("The second input")),
        "expected NatSpec @param y with 'The second input' in preconditions; got: {:#?}",
        pre
    );
    // NatSpec @return result → postcondition with variable "result" or "return"
    assert!(
        post.iter().any(|c| {
            let var = c["variable"].as_str().unwrap_or("");
            let cons = c["constraint"].as_str().unwrap_or("");
            (var == "result" || var == "return") && cons.contains("product")
        }),
        "expected NatSpec @return result with 'product' in postconditions; got: {:#?}",
        post
    );
}

#[test]
fn contracts_emits_block_natspec_param_and_return() {
    let (_tmp, file) = write_fixture();
    let tldr = env!("CARGO_BIN_EXE_tldr");
    let output = Command::new(tldr)
        .arg("contracts")
        .arg(file.to_str().unwrap())
        .arg("add")
        .arg("--format")
        .arg("json")
        .output()
        .expect("tldr contracts should run");
    assert!(
        output.status.success(),
        "tldr contracts failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("contracts should emit JSON");

    let pre = report["preconditions"]
        .as_array()
        .expect("preconditions array");
    let post = report["postconditions"]
        .as_array()
        .expect("postconditions array");
    assert!(
        pre.iter().any(|c| c["variable"] == "a"
            && c["constraint"].as_str().unwrap_or("").contains("First operand")),
        "expected block @param a with 'First operand'; got: {:#?}",
        pre
    );
    assert!(
        pre.iter().any(|c| c["variable"] == "b"
            && c["constraint"].as_str().unwrap_or("").contains("Second operand")),
        "expected block @param b with 'Second operand'; got: {:#?}",
        pre
    );
    assert!(
        post.iter().any(|c| {
            let var = c["variable"].as_str().unwrap_or("");
            let cons = c["constraint"].as_str().unwrap_or("");
            (var == "sum" || var == "return") && cons.contains("a + b")
        }),
        "expected @return sum with 'a + b'; got: {:#?}",
        post
    );
}
