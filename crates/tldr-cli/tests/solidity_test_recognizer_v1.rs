//! solidity-test-recognizer-v1 (v0.5.0 SOL-009): Foundry/Forge test
//! recognition for Solidity.
//!
//! Per oracle research, Foundry/Forge test convention:
//!   - Solidity files in `test/**/*.sol` or `tests/**/*.sol`
//!   - Inheriting from `Test` (forge-std) — for v1 we use the path
//!     heuristic (file-name + directory) only and refine inheritance
//!     transitively in a later phase.
//!   - Test functions: `test*`, `fuzz*`, `invariant_*`
//!   - Test hooks (`setUp`, `setUpAll`, etc.) are NOT tests.
//!
//! These tests live at the per-language `test_recognizer` boundary —
//! `recognize(path, source, Language::Solidity)` should return
//! `is_test_file=true` and `test_function_count` matching the visible
//! `test*`/`fuzz*`/`invariant_*` functions when the path heuristic
//! passes, and should return `is_test_file=false` with count 0 when
//! the file is outside any test directory and doesn't match the
//! test filename heuristic.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

use tldr_cli::commands::contracts::test_recognizer::recognize;
use tldr_core::types::Language;

/// Write `body` to `<dir>/<rel>` (creating parent dirs) and return the
/// full path.
fn write(dir: &Path, rel: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&p, body).unwrap();
    p
}

#[test]
fn forge_test_function_in_test_dir_matches() {
    // File at `test/MyTest.sol` with `function testFoo() public {}` → matches.
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import \"forge-std/Test.sol\";
contract MyTest is Test {
    function testFoo() public {}
}
";
    let p = write(tmp.path(), "test/MyTest.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(
        info.is_test_file,
        "test/MyTest.sol should be classified as a test file"
    );
    assert_eq!(
        info.test_function_count, 1,
        "should count exactly one test function (testFoo)"
    );
}

#[test]
fn forge_fuzz_function_in_test_dir_matches() {
    // File at `test/MyTest.sol` with `function fuzzBar(uint x) public {}` → matches.
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MyTest is Test {
    function fuzzBar(uint256 x) public {}
}
";
    let p = write(tmp.path(), "test/MyTest.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(info.is_test_file);
    assert_eq!(
        info.test_function_count, 1,
        "fuzzBar should be counted as a test (Forge fuzz convention)"
    );
}

#[test]
fn forge_invariant_function_in_test_dir_matches() {
    // File at `test/MyTest.sol` with `function invariant_Balance() public {}` → matches.
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MyTest is Test {
    function invariant_Balance() public {}
}
";
    let p = write(tmp.path(), "test/MyTest.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(info.is_test_file);
    assert_eq!(
        info.test_function_count, 1,
        "invariant_Balance should be counted as a test (Forge invariant convention)"
    );
}

#[test]
fn non_test_dir_test_function_does_not_match() {
    // File at `src/Main.sol` with `function testFoo() public {}` → does NOT
    // match (file is not in a test directory and name doesn't suggest it).
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Main {
    function testFoo() public {}
}
";
    let p = write(tmp.path(), "src/Main.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(
        !info.is_test_file,
        "src/Main.sol should NOT be classified as a test file"
    );
    assert_eq!(
        info.test_function_count, 0,
        "no functions should be counted when file is outside test directory"
    );
}

#[test]
fn setup_function_in_test_dir_does_not_match() {
    // File at `test/MyTest.sol` with `function setUp() public {}` → does NOT
    // match (test hook, not a test).
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MyTest is Test {
    function setUp() public {}
}
";
    let p = write(tmp.path(), "test/MyTest.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(
        info.is_test_file,
        "test/MyTest.sol is still a test file even if it only contains setUp"
    );
    assert_eq!(
        info.test_function_count, 0,
        "setUp is a Forge test hook, not a test function — count should be 0"
    );
}

#[test]
fn forge_test_mixed_with_hooks_and_helpers_counts_only_tests() {
    // Mixed file: setUp (hook), testA (test), helperX (helper), fuzzB (test),
    // invariant_C (test), testInternalState (test) → 4 tests counted.
    let tmp = tempdir().unwrap();
    let body = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import \"forge-std/Test.sol\";
contract FullTest is Test {
    uint256 private counter;
    function setUp() public { counter = 0; }
    function testA() public { counter = 1; }
    function helperX() internal returns (uint256) { return counter; }
    function fuzzB(uint256 x) public { counter = x; }
    function invariant_C() public {}
    function testInternalState() public {}
}
";
    let p = write(tmp.path(), "test/FullTest.sol", body);
    let src = fs::read_to_string(&p).unwrap();
    let info = recognize(&p, &src, Language::Solidity);
    assert!(info.is_test_file);
    assert_eq!(
        info.test_function_count, 4,
        "should count testA, fuzzB, invariant_C, testInternalState (4 tests, excluding setUp/helperX)"
    );
}
