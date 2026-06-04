//! solidity-ast-extractor-v1 (v0.5.0 SOL-004): integration tests for
//! the `extractor.rs` Solidity arm — the structure / definition /
//! cohesion parallel pipeline.
//!
//! Covers Phase 4 wiring of:
//!   - `extract_functions` (Solidity) → free-function names at file scope.
//!   - `extract_methods` (Solidity) → contract/interface/library members.
//!   - `extract_classes` (Solidity) → contract/interface/library names.
//!   - `collect_definitions` (Solidity) → DefinitionInfo entries with
//!     kind = "contract"|"interface"|"library"|"modifier"|"event"|
//!     "error"|"struct"|"enum"|"method"|"function"|"field"|"constant".
//!   - `is_inside_class_or_impl` (Solidity) → `contract_body`-aware so
//!     member function classification is `method`, not `function`.
//!   - `decl_keyword_line_from_node` is enabled for Solidity (M-109
//!     cross-pipeline invariant: structure ↔ extract agree on line).
//!
//! Hermetic fixtures (no `/tmp/repos/...` dep) so tests are portable.

use std::fs;
use tempfile::TempDir;

use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::ast::get_code_structure;
use tldr_core::types::Language;

/// Master fixture covering every Phase 4 surface:
/// - contract with `is Ownable, ReentrancyGuard`
/// - NatSpec `///` docstring on contract + on a function
/// - state variable (`uint256 public totalDeposits;`)
/// - event with one indexed + one non-indexed param
/// - custom error with two typed params
/// - modifier with empty params + body
/// - struct + enum at contract scope
/// - constructor + fallback + receive
/// - function with `external payable` + two modifier invocations
const FIXTURE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Token vault
/// @notice A simple vault contract
contract TokenVault is Ownable, ReentrancyGuard {
    uint256 public totalDeposits;
    event Deposit(address indexed user, uint256 amount);
    error InsufficientBalance(uint256 available, uint256 required);
    modifier nonReentrant() { _; }
    struct UserData { uint256 amount; }
    enum Status { Active, Inactive }

    constructor() {}

    fallback() external payable {}
    receive() external payable {}

    /// @notice Deposit ether
    /// @param amount Amount to deposit
    function deposit(uint256 amount) external payable onlyOwner nonReentrant returns (bool) {
        totalDeposits += amount;
        return true;
    }
}
";

fn write_fixture(name: &str, src: &str) -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join(name);
    fs::write(&file, src).unwrap();
    (tmp, file)
}

// =============================================================================
// extract_functions / extract_classes / extract_methods — name lists
// =============================================================================

#[test]
fn structure_emits_contract_as_class_name() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None)
        .expect("get_code_structure ok");
    assert_eq!(st.files.len(), 1, "expected one file");
    let f = &st.files[0];
    assert!(
        f.classes.contains(&"TokenVault".to_string()),
        "expected `TokenVault` in classes[]; got {:?}",
        f.classes
    );
}

#[test]
fn structure_emits_member_function_as_method_not_function() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    // `deposit` is a contract member -> appears in `methods`, NOT in `functions`.
    assert!(
        f.methods.contains(&"deposit".to_string()),
        "expected `deposit` in methods[]; got methods={:?}",
        f.methods
    );
    assert!(
        !f.functions.contains(&"deposit".to_string()),
        "did NOT expect `deposit` in free-functions; got {:?}",
        f.functions
    );
}

#[test]
fn structure_no_free_functions_when_all_are_contract_members() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    assert!(
        f.functions.is_empty(),
        "expected zero free functions in TokenVault.sol; got {:?}",
        f.functions
    );
}

#[test]
fn structure_emits_free_function_at_file_scope() {
    let src = "\
pragma solidity ^0.8.0;
function topLevelHelper(uint256 x) pure returns (uint256) {
    return x + 1;
}
contract Foo {}
";
    let (_tmp, file) = write_fixture("FreeFn.sol", src);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    assert!(
        f.functions.contains(&"topLevelHelper".to_string()),
        "expected `topLevelHelper` in functions[] (file-scope, NOT a contract member); got {:?}",
        f.functions
    );
    // And it must NOT appear as a method.
    assert!(
        !f.methods.contains(&"topLevelHelper".to_string()),
        "did NOT expect `topLevelHelper` in methods[]; got {:?}",
        f.methods
    );
}

// =============================================================================
// collect_definitions — DefinitionInfo entries with proper `kind`
// =============================================================================

#[test]
fn definitions_emit_contract_kind() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    let tv = f
        .definitions
        .iter()
        .find(|d| d.name == "TokenVault")
        .unwrap_or_else(|| {
            panic!(
                "expected `TokenVault` in definitions[]; got {:?}",
                f.definitions
                    .iter()
                    .map(|d| (&d.name, &d.kind))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        tv.kind, "contract",
        "expected kind=\"contract\"; got kind={:?}",
        tv.kind
    );
}

#[test]
fn definitions_emit_interface_and_library_kinds() {
    let src = "\
pragma solidity ^0.8.0;
interface IFoo { function ping() external view; }
library MathLib { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }
contract Bar {}
";
    let (_tmp, file) = write_fixture("MultiKind.sol", src);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    let by_name: std::collections::HashMap<&str, &str> = f
        .definitions
        .iter()
        .map(|d| (d.name.as_str(), d.kind.as_str()))
        .collect();

    assert_eq!(
        by_name.get("IFoo").copied(),
        Some("interface"),
        "expected `IFoo` as kind=interface; defs={:?}",
        f.definitions
            .iter()
            .map(|d| (&d.name, &d.kind))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        by_name.get("MathLib").copied(),
        Some("library"),
        "expected `MathLib` as kind=library"
    );
    assert_eq!(
        by_name.get("Bar").copied(),
        Some("contract"),
        "expected `Bar` as kind=contract"
    );
}

#[test]
fn definitions_emit_modifier_event_error_kinds() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    let by_kind = |name: &str| -> Option<String> {
        f.definitions
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.kind.clone())
    };

    assert_eq!(
        by_kind("nonReentrant").as_deref(),
        Some("modifier"),
        "expected `nonReentrant` as kind=modifier; defs={:?}",
        f.definitions
            .iter()
            .map(|d| (&d.name, &d.kind))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        by_kind("Deposit").as_deref(),
        Some("event"),
        "expected `Deposit` as kind=event"
    );
    assert_eq!(
        by_kind("InsufficientBalance").as_deref(),
        Some("error"),
        "expected `InsufficientBalance` as kind=error"
    );
}

#[test]
fn definitions_emit_struct_and_enum_kinds() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    let by_kind = |name: &str| -> Option<String> {
        f.definitions
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.kind.clone())
    };
    assert_eq!(
        by_kind("UserData").as_deref(),
        Some("struct"),
        "expected contract-scope `UserData` as kind=struct"
    );
    assert_eq!(
        by_kind("Status").as_deref(),
        Some("enum"),
        "expected contract-scope `Status` as kind=enum"
    );
}

#[test]
fn definitions_emit_constructor_fallback_receive_as_methods() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    for (name, expected_kind) in [
        ("constructor", "method"),
        ("fallback", "method"),
        ("receive", "method"),
    ] {
        let d = f
            .definitions
            .iter()
            .find(|d| d.name == name && d.kind == expected_kind)
            .unwrap_or_else(|| {
                panic!(
                    "expected `{}` as kind=\"{}\" in definitions[]; got {:?}",
                    name,
                    expected_kind,
                    f.definitions
                        .iter()
                        .map(|d| (&d.name, &d.kind))
                        .collect::<Vec<_>>()
                )
            });
        let _ = d; // silence unused
    }
}

#[test]
fn definitions_emit_deposit_as_method() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    let deposit = f
        .definitions
        .iter()
        .find(|d| d.name == "deposit")
        .expect("deposit must be in definitions[]");
    assert_eq!(
        deposit.kind, "method",
        "deposit is a contract member; expected kind=method"
    );
}

#[test]
fn definitions_emit_state_variable_as_field() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    let total = f
        .definitions
        .iter()
        .find(|d| d.name == "totalDeposits")
        .unwrap_or_else(|| {
            panic!(
                "expected `totalDeposits` in definitions[]; got {:?}",
                f.definitions
                    .iter()
                    .map(|d| (&d.name, &d.kind))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        total.kind, "field",
        "expected contract-scope state var as kind=field"
    );
}

#[test]
fn definitions_emit_file_scope_constant() {
    let src = "\
pragma solidity ^0.8.0;
uint256 constant MAX_SUPPLY = 1000;
contract Foo {}
";
    let (_tmp, file) = write_fixture("Const.sol", src);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];
    let max = f
        .definitions
        .iter()
        .find(|d| d.name == "MAX_SUPPLY")
        .unwrap_or_else(|| {
            panic!(
                "expected `MAX_SUPPLY` in definitions[]; got {:?}",
                f.definitions
                    .iter()
                    .map(|d| (&d.name, &d.kind))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        max.kind, "constant",
        "expected file-scope MAX_SUPPLY as kind=constant"
    );
}

// =============================================================================
// M-109 invariant: structure ↔ extract pipeline agreement on line numbers
// =============================================================================

#[test]
fn structure_and_extract_agree_on_contract_line() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);

    // --- extract side (source of truth) ---
    let ext = extract_file_with_lang(&file, None, Some(Language::Solidity))
        .expect("extract_file_with_lang ok");
    assert_eq!(ext.classes.len(), 1, "expected one class from extract");
    let extract_class_line = ext.classes[0].line_number;

    // --- structure side (must agree) ---
    let st = get_code_structure(&file, Language::Solidity, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let tv = f
        .definitions
        .iter()
        .find(|d| d.name == "TokenVault")
        .expect("TokenVault in definitions[]");
    assert_eq!(
        tv.line_start, extract_class_line,
        "M-109: structure says TokenVault line={}, extract says line={}",
        tv.line_start, extract_class_line
    );
    // Sanity: NatSpec `///` comments precede the contract decl in the
    // fixture, so the decl-keyword line is past the doc-comment block.
    // The `contract` keyword sits on line 6 (1-indexed) of the fixture.
    assert_eq!(
        tv.line_start, 6,
        "expected `contract` keyword line, not the NatSpec block above it"
    );
}

#[test]
fn structure_and_extract_agree_on_deposit_method_line() {
    let (_tmp, file) = write_fixture("TokenVault.sol", FIXTURE);

    let ext = extract_file_with_lang(&file, None, Some(Language::Solidity))
        .expect("extract ok");
    let cls = &ext.classes[0];
    let deposit = cls
        .methods
        .iter()
        .find(|m| m.name == "deposit")
        .expect("deposit method in extract");
    let extract_line = deposit.line_number;

    let st = get_code_structure(&file, Language::Solidity, 1000, None)
        .expect("structure ok");
    let f = &st.files[0];
    let def = f
        .definitions
        .iter()
        .find(|d| d.name == "deposit" && d.kind == "method")
        .expect("deposit method in structure");
    assert_eq!(
        def.line_start, extract_line,
        "M-109: structure says deposit line={}, extract says line={}",
        def.line_start, extract_line
    );
}

// =============================================================================
// is_inside_class_or_impl: contract body recognition
// =============================================================================

#[test]
fn function_inside_library_classified_as_method_not_function() {
    let src = "\
pragma solidity ^0.8.0;
library MathLib {
    function add(uint a, uint b) internal pure returns (uint) { return a + b; }
}
";
    let (_tmp, file) = write_fixture("MathLib.sol", src);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    // `add` is a library member -> method, not function.
    let add_def = f
        .definitions
        .iter()
        .find(|d| d.name == "add")
        .expect("add must be in definitions[]");
    assert_eq!(
        add_def.kind, "method",
        "library-scope function must classify as `method`; got kind={:?}",
        add_def.kind
    );
    // And it must be in methods[], not functions[].
    assert!(
        f.methods.contains(&"add".to_string()),
        "expected `add` in methods[]; got {:?}",
        f.methods
    );
    assert!(
        !f.functions.contains(&"add".to_string()),
        "did NOT expect `add` in free-functions; got {:?}",
        f.functions
    );
}

#[test]
fn function_inside_interface_classified_as_method() {
    let src = "\
pragma solidity ^0.8.0;
interface IFoo {
    function ping() external view returns (uint256);
}
";
    let (_tmp, file) = write_fixture("IFoo.sol", src);
    let st = get_code_structure(&file, Language::Solidity, 1000, None).unwrap();
    let f = &st.files[0];

    let ping = f
        .definitions
        .iter()
        .find(|d| d.name == "ping")
        .expect("ping must be in definitions[]");
    assert_eq!(
        ping.kind, "method",
        "interface function must classify as `method`; got kind={:?}",
        ping.kind
    );
}
