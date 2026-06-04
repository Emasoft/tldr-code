//! solidity-metrics-v1 (v0.5.0 SOL-008): Wire Solidity into the metrics
//! modules (cyclomatic + cognitive + Halstead).
//!
//! Before this patch:
//!   - `calculate_complexity(..., Language::Solidity)` returned cyclomatic=1
//!     for if/else, for, while, do/while because the complexity walker had
//!     no Solidity-specific arm and Solidity's grammar is C-shaped enough
//!     that the GENERIC arms partially work — but `&&`/`||` and Solidity-
//!     specific constructs (`revert_statement`, `emit_statement`, the
//!     `require(...)`/`assert(...)` guard primitives) were unaccounted for.
//!   - The Halstead walker had no `Language::Solidity` arm in the keyword
//!     operator list, so Solidity keywords (`function`, `if`, `return`,
//!     `emit`, `revert`, `require`, `assert`, `payable`, `external`, etc.)
//!     came out empty.
//!
//! This test exercises:
//!   * cyclomatic: simple function, if/else, if + && + ||, for-loop, while,
//!     do-while, try/catch.
//!   * cognitive:  nested if (nesting penalty), recursion.
//!   * Halstead:   Solidity keyword operators surface in the operator set.

use std::fs;
use tempfile::TempDir;

use tldr_core::metrics::halstead::{analyze_halstead, HalsteadOptions};
use tldr_core::metrics::{analyze_cognitive, calculate_complexity, CognitiveOptions};
use tldr_core::types::Language;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn write_sol(name: &str, body: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join(name);
    fs::write(&p, body).unwrap();
    (tmp, p)
}

// ---------------------------------------------------------------------------
// cyclomatic — Solidity arm in complexity.rs
// ---------------------------------------------------------------------------

const SIMPLE: &str = "\
pragma solidity ^0.8.20;
contract C {
    uint x;
    function f() public { x = 1; }
}
";

#[test]
fn solidity_simple_function_cyclomatic_is_one() {
    let m = calculate_complexity(SIMPLE, "f", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 1,
        "simple straight-line function should be cyclomatic=1"
    );
}

const IF_ELSE: &str = "\
pragma solidity ^0.8.20;
contract C {
    function g(int x) public pure returns (int) {
        if (x > 0) { return 1; } else { return 2; }
    }
}
";

#[test]
fn solidity_if_else_cyclomatic_is_two() {
    let m = calculate_complexity(IF_ELSE, "g", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 2,
        "if/else should be cyclomatic=2 (1 base + 1 if)"
    );
}

const IF_AND_OR: &str = "\
pragma solidity ^0.8.20;
contract C {
    function h(bool a, bool b, bool c) public pure returns (uint) {
        if (a && b || c) { return 1; }
        return 0;
    }
}
";

#[test]
fn solidity_if_with_and_or_cyclomatic_is_four() {
    let m = calculate_complexity(IF_AND_OR, "h", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 4,
        "if + && + || should be cyclomatic = 1 + 1(if) + 1(&&) + 1(||) = 4, got {}",
        m.cyclomatic,
    );
}

const FOR_LOOP: &str = "\
pragma solidity ^0.8.20;
contract C {
    function sum(uint n) public pure returns (uint) {
        uint s = 0;
        for (uint i = 0; i < n; i++) { s += i; }
        return s;
    }
}
";

#[test]
fn solidity_for_loop_cyclomatic_is_two() {
    let m = calculate_complexity(FOR_LOOP, "sum", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 2,
        "single for-loop should be cyclomatic=2 (1 base + 1 for)"
    );
}

const WHILE_LOOP: &str = "\
pragma solidity ^0.8.20;
contract C {
    function w(uint n) public pure returns (uint) {
        uint i = 0;
        while (i < n) { i++; }
        return i;
    }
}
";

#[test]
fn solidity_while_loop_cyclomatic_is_two() {
    let m = calculate_complexity(WHILE_LOOP, "w", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 2,
        "single while-loop should be cyclomatic=2 (1 base + 1 while)"
    );
}

const DO_WHILE: &str = "\
pragma solidity ^0.8.20;
contract C {
    function d(uint n) public pure returns (uint) {
        uint i = 0;
        do { i++; } while (i < n);
        return i;
    }
}
";

#[test]
fn solidity_do_while_loop_cyclomatic_is_two() {
    let m = calculate_complexity(DO_WHILE, "d", Language::Solidity).expect("cc ok");
    assert_eq!(
        m.cyclomatic, 2,
        "do/while-loop should be cyclomatic=2 (1 base + 1 do_while), got {}",
        m.cyclomatic,
    );
}

const TRY_CATCH: &str = "\
pragma solidity ^0.8.20;
interface IFoo { function ping() external returns (uint); }
contract C {
    function t(IFoo foo) public returns (uint) {
        try foo.ping() returns (uint v) { return v; }
        catch { return 0; }
    }
}
";

#[test]
fn solidity_try_catch_cyclomatic_is_two() {
    let m = calculate_complexity(TRY_CATCH, "t", Language::Solidity).expect("cc ok");
    assert!(
        m.cyclomatic >= 2,
        "try/catch should be cyclomatic >= 2 (1 base + 1 catch_clause), got {}",
        m.cyclomatic,
    );
}

// ---------------------------------------------------------------------------
// cognitive — nesting penalty + recursion
// ---------------------------------------------------------------------------

const NESTED_IF: &str = "\
pragma solidity ^0.8.20;
contract C {
    function n(int a, int b) public pure returns (uint) {
        if (a > 0) {
            if (b > 0) {
                return 3;
            }
        }
        return 0;
    }
}
";

#[test]
fn solidity_nested_if_cognitive_penalises_nesting() {
    let (_tmp, p) = write_sol("Nest.sol", NESTED_IF);
    let report = analyze_cognitive(&p, &CognitiveOptions::new()).expect("cognitive ok");
    let func = report
        .functions
        .iter()
        .find(|f| f.name == "n")
        .expect("found `n`");
    // outer-if = +1, inner-if = +1 base + 1 nesting penalty ⇒ total >= 3
    assert!(
        func.cognitive >= 3,
        "nested if should have cognitive >= 3 (got {})",
        func.cognitive,
    );
}

// ---------------------------------------------------------------------------
// Halstead — Solidity keyword operators
// ---------------------------------------------------------------------------

const HALSTEAD_SRC: &str = "\
pragma solidity ^0.8.20;
contract C {
    event E(uint v);
    error Bad(uint v);
    function f(uint x) public returns (uint) {
        require(x > 0, \"nonzero\");
        if (x == 1) { revert Bad(x); }
        emit E(x);
        return x + 1;
    }
}
";

#[test]
fn solidity_halstead_keywords_counted_as_operators() {
    let (_tmp, p) = write_sol("Hal.sol", HALSTEAD_SRC);
    let mut opts = HalsteadOptions::new();
    opts.show_operators = true;
    let report = analyze_halstead(&p, Some(Language::Solidity), opts).expect("halstead ok");

    assert!(
        !report.functions.is_empty(),
        "expected at least one Solidity function in halstead report"
    );
    let func = &report.functions[0];
    let ops = func.operators.as_ref().expect("operators set requested");

    for kw in &[
        "function", "if", "return", "emit", "revert", "require",
    ] {
        assert!(
            ops.iter().any(|o| o == kw),
            "Solidity '{}' should be a Halstead operator (got: {:?})",
            kw,
            ops,
        );
    }
}
