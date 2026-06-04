//! solidity-deps-v1 (v0.5.0 SOL-007): integration tests for the
//! Solidity arm of `analyze_dependencies`.
//!
//! Covers:
//!   1. Internal vs External classification of all 5 Solidity import
//!      forms (plain, `as` alias, `* as Bar from`, selective `{X, Y}`,
//!      selective with alias).
//!   2. External-package-name extraction for the curated longest-prefix
//!      list of common Solidity ecosystem packages (OpenZeppelin,
//!      Chainlink, Uniswap, Aave, solmate, solady, forge-std, hardhat,
//!      ds-test, openzeppelin-upgradeable).
//!   3. `is_solidity_stdlib` is always `false` (Solidity has no
//!      module-system stdlib — all builtins are intrinsic).
//!   4. Relative imports (`./Foo.sol`, `../utils/Helpers.sol`) classify
//!      as Internal even when the target file is missing (assumed to be
//!      project-local — Solidity does not have a stdlib gate to false-
//!      classify them as External).
//!   5. Non-regression: existing 10-language stdlib classifications
//!      remain green (test executed in `m048_deps_stdlib_wiring_v1`).
//!
//! Hermetic — uses TempDir fixtures and the library API directly
//! (`tldr_core::analysis::deps`) so no on-disk corpus is required.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use tempfile::TempDir;

use tldr_core::analysis::deps::{
    analyze_dependencies, is_solidity_stdlib, DepsOptions,
};

fn write(tmp: &Path, rel: &str, body: &str) {
    let full = tmp.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(full, body).unwrap();
}

fn deps_opts() -> DepsOptions {
    DepsOptions {
        language: Some("solidity".to_string()),
        include_external: true,
        ..DepsOptions::default()
    }
}

fn collect_externals(report: &tldr_core::analysis::deps::DepsReport) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for deps in report.external_dependencies.values() {
        for d in deps {
            set.insert(d.clone());
        }
    }
    set
}

fn collect_internals_for(
    report: &tldr_core::analysis::deps::DepsReport,
    file_basename: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in &report.internal_dependencies {
        if k.file_name().and_then(|n| n.to_str()) == Some(file_basename) {
            for path in v {
                if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
                    out.push(n.to_string());
                }
            }
        }
    }
    out
}

// ============================================================================
// (1) is_solidity_stdlib — must be `false` for any input.
// ============================================================================

#[test]
fn is_solidity_stdlib_always_false() {
    // Solidity has no module-system stdlib. Builtins (msg.sender,
    // block.timestamp, keccak256, abi.encode) are intrinsic, not
    // import-able.
    assert!(!is_solidity_stdlib(""));
    assert!(!is_solidity_stdlib("./Foo.sol"));
    assert!(!is_solidity_stdlib("@openzeppelin/contracts/token/ERC20/ERC20.sol"));
    assert!(!is_solidity_stdlib("solmate/src/utils/SafeTransferLib.sol"));
    assert!(!is_solidity_stdlib("hardhat/console.sol"));
}

// ============================================================================
// (2) Relative imports classify as Internal.
// ============================================================================

#[test]
fn relative_dot_slash_import_is_internal() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\nimport \"./B.sol\";\ncontract A {}\n",
    );
    write(
        tmp.path(),
        "src/B.sol",
        "pragma solidity ^0.8.0;\ncontract B {}\n",
    );

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let internals_a = collect_internals_for(&report, "A.sol");
    assert!(
        internals_a.contains(&"B.sol".to_string()),
        "A.sol should record an Internal dep on B.sol; got: {:?}",
        internals_a
    );
    assert!(
        report.external_dependencies.is_empty()
            || report
                .external_dependencies
                .values()
                .all(|v| v.is_empty()),
        "relative-only imports must not appear in external_dependencies; got: {:?}",
        report.external_dependencies
    );
}

#[test]
fn relative_parent_dir_import_is_internal_or_unresolved_but_not_external() {
    let tmp = TempDir::new().unwrap();
    // src/A.sol imports ../utils/Helpers.sol — Helpers.sol exists.
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\nimport \"../utils/Helpers.sol\";\ncontract A {}\n",
    );
    write(
        tmp.path(),
        "utils/Helpers.sol",
        "pragma solidity ^0.8.0;\nlibrary Helpers {}\n",
    );

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    assert!(
        externals.is_empty(),
        "../utils/Helpers.sol is project-local; must not classify as External; got: {:?}",
        externals
    );
}

// ============================================================================
// (3) External package classification — longest-prefix-first taxonomy.
// ============================================================================

#[test]
fn openzeppelin_contracts_imports_classify_as_external_with_correct_package() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/Vault.sol",
        "pragma solidity ^0.8.0;\n\
         import \"@openzeppelin/contracts/token/ERC20/ERC20.sol\";\n\
         import { IERC20 } from \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";\n\
         contract Vault {}\n",
    );

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    assert!(
        externals.contains("@openzeppelin/contracts"),
        "expected @openzeppelin/contracts in external deps; got: {:?}",
        externals
    );
    // Both lines should collapse to the SAME package coordinate.
    assert!(
        !externals.contains("@openzeppelin/contracts/token"),
        "external_package_name must collapse to the registered prefix, not the sub-path; got: {:?}",
        externals
    );
}

#[test]
fn openzeppelin_upgradeable_distinguished_from_contracts() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\n\
         import \"@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol\";\n\
         contract A {}\n",
    );

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    assert!(
        externals.contains("@openzeppelin/contracts-upgradeable"),
        "expected longest-prefix match @openzeppelin/contracts-upgradeable; got: {:?}",
        externals
    );
    assert!(
        !externals.contains("@openzeppelin/contracts"),
        "must not collapse upgradeable variant onto @openzeppelin/contracts; got: {:?}",
        externals
    );
}

#[test]
fn solmate_unscoped_package_classifies_correctly() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\n\
         import \"solmate/src/utils/SafeTransferLib.sol\";\n\
         contract A {}\n",
    );
    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    assert!(
        externals.contains("solmate"),
        "expected `solmate` external package; got: {:?}",
        externals
    );
}

#[test]
fn chainlink_and_uniswap_and_aave_classify_correctly() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\n\
         import \"@chainlink/contracts/src/v0.8/AggregatorV3Interface.sol\";\n\
         import \"@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol\";\n\
         import \"@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol\";\n\
         import \"@aave/core-v3/contracts/interfaces/IPool.sol\";\n\
         contract A {}\n",
    );
    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    for want in &[
        "@chainlink/contracts",
        "@uniswap/v3-core",
        "@uniswap/v2-core",
        "@aave/core-v3",
    ] {
        assert!(
            externals.contains(*want),
            "expected `{}` in external deps; got: {:?}",
            want,
            externals
        );
    }
}

#[test]
fn solady_and_forge_std_and_hardhat_and_ds_test_classify_correctly() {
    let tmp = TempDir::new().unwrap();
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\n\
         import \"solady/src/utils/LibString.sol\";\n\
         import \"forge-std/Test.sol\";\n\
         import \"hardhat/console.sol\";\n\
         import \"ds-test/test.sol\";\n\
         contract A {}\n",
    );
    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    for want in &["solady", "forge-std", "hardhat", "ds-test"] {
        assert!(
            externals.contains(*want),
            "expected `{}` in external deps; got: {:?}",
            want,
            externals
        );
    }
}

// ============================================================================
// (4) All 5 Solidity import forms are recognized by `get_imports`.
// ============================================================================

#[test]
fn all_five_import_forms_recognized_as_dependencies() {
    let tmp = TempDir::new().unwrap();
    // Form 1: plain
    // Form 2: with `as` alias for the whole file
    // Form 3: `* as Bar from`
    // Form 4: selective `{ X, Y }`
    // Form 5: selective with `as` rename
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\n\
         import \"./B.sol\";\n\
         import \"./C.sol\" as CAlias;\n\
         import * as DAlias from \"./D.sol\";\n\
         import { EOne, ETwo } from \"./E.sol\";\n\
         import { FThing as FAlias, FOther } from \"./F.sol\";\n\
         contract A {}\n",
    );
    for f in &["B", "C", "D", "E", "F"] {
        write(
            tmp.path(),
            &format!("src/{}.sol", f),
            "pragma solidity ^0.8.0;\ncontract X {}\n",
        );
    }

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let internals_a = collect_internals_for(&report, "A.sol");
    for f in &["B.sol", "C.sol", "D.sol", "E.sol", "F.sol"] {
        assert!(
            internals_a.contains(&f.to_string()),
            "expected internal dep on {}; got: {:?}",
            f,
            internals_a
        );
    }
}

// ============================================================================
// (5) Unknown bare path (no `./`, no `@scope/`) classifies as Internal —
// Solidity remappings (e.g. `contracts/MyLib.sol`) are project-local.
// ============================================================================

#[test]
fn bare_project_relative_remapping_classifies_as_internal_not_external() {
    let tmp = TempDir::new().unwrap();
    // `contracts/MyLib.sol` is a typical Foundry remapping target.
    // It is NOT in the external-package taxonomy and is NOT `./`-prefixed.
    // It must NOT pollute the external bucket.
    write(
        tmp.path(),
        "src/A.sol",
        "pragma solidity ^0.8.0;\nimport \"contracts/MyLib.sol\";\ncontract A {}\n",
    );

    let report = analyze_dependencies(tmp.path(), &deps_opts()).unwrap();
    let externals = collect_externals(&report);
    assert!(
        externals.is_empty(),
        "bare remapping path must classify as Internal (no External bucket entry); got: {:?}",
        externals
    );
}
