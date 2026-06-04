//! solidity-ast-extract-v1 (v0.5.0 SOL-003): integration test for the
//! Solidity AST extraction layer.
//!
//! Covers the Phase 3 wiring of:
//!   - `extract_solidity_classes_detailed` → `ClassInfo` with
//!     `kind = Some("contract"|"interface"|"library")`
//!   - `extract_solidity_functions_detailed` →
//!     `FunctionInfo` with visibility / state_mutability /
//!     `modifier_invocations` (surfaced via `decorators`)
//!   - `build_solidity_modifier_info` → `ModifierInfo` (contract-scope)
//!   - `build_solidity_event_info` → `EventInfo` (per-param `indexed`)
//!   - `build_solidity_error_info` → `ErrorInfo` (typed params)
//!   - NatSpec `///` and `/** */` docstring preservation
//!   - `extract_solidity_class_bases` → flattened `is A, B` list
//!
//! Hermetic fixture (no `/tmp/repos/...` dep) so the test is portable.

use std::fs;
use tempfile::TempDir;

use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::types::Language;

/// Sample Solidity fixture covering every Phase 3 extraction kind:
/// - contract + inheritance specifiers (`is Ownable, ReentrancyGuard`)
/// - NatSpec `///` docstring on contract + on a function
/// - state variable (`uint256 public totalDeposits;`)
/// - event with one indexed + one non-indexed param
/// - custom error with two typed params (0.8.4+)
/// - modifier with empty params + body
/// - function with `external payable` + two modifier invocations +
///   `returns (bool)`
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

    /// @notice Deposit ether
    /// @param amount Amount to deposit
    function deposit(uint256 amount) external payable onlyOwner nonReentrant returns (bool) {
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
        return true;
    }
}
";

fn write_fixture() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("TokenVault.sol");
    fs::write(&file, FIXTURE).unwrap();
    (tmp, file)
}

#[test]
fn extract_emits_single_contract_class_with_correct_kind_and_bases() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity))
        .expect("extract should succeed");

    assert_eq!(
        m.classes.len(),
        1,
        "expected exactly 1 class (the contract), got: {:?}",
        m.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    let c = &m.classes[0];
    assert_eq!(c.name, "TokenVault");
    assert_eq!(c.kind.as_deref(), Some("contract"));
    assert_eq!(
        c.bases,
        vec!["Ownable".to_string(), "ReentrancyGuard".to_string()],
        "expected `is Ownable, ReentrancyGuard` to flatten into bases"
    );
}

#[test]
fn extract_emits_contract_natspec_docstring_verbatim() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    let ds = c
        .docstring
        .as_ref()
        .expect("contract should have a NatSpec docstring");
    assert!(
        ds.contains("@title Token vault"),
        "docstring should preserve @title verbatim; got: {ds:?}"
    );
    assert!(
        ds.contains("@notice A simple vault contract"),
        "docstring should preserve @notice verbatim; got: {ds:?}"
    );
}

#[test]
fn extract_emits_function_with_visibility_state_mutability_and_modifiers() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(
        c.methods.len(),
        1,
        "expected exactly 1 method, got: {:?}",
        c.methods.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let f = &c.methods[0];
    assert_eq!(f.name, "deposit");
    assert!(f.is_method, "deposit is a method of TokenVault");
    assert!(!f.is_async, "Solidity has no async");
    assert_eq!(
        f.visibility.as_deref(),
        Some("external"),
        "deposit declared `external`"
    );
    // solidity-sol013-cluster-v1 (v0.5.0 SOL-013 M3): state_mutability
    // is now its OWN field on FunctionInfo, NOT mixed into decorators.
    // `decorators` carries only user-defined modifier invocations.
    assert_eq!(
        f.state_mutability.as_deref(),
        Some("payable"),
        "expected state_mutability=`payable` on its own field; got: {:?}",
        f.state_mutability
    );
    assert!(
        !f.decorators.contains(&"payable".to_string()),
        "state_mutability MUST NOT leak into decorators after SOL-013 M3; got: {:?}",
        f.decorators
    );
    assert!(
        f.decorators.contains(&"onlyOwner".to_string()),
        "expected `onlyOwner` modifier-invocation in decorators; got: {:?}",
        f.decorators
    );
    assert!(
        f.decorators.contains(&"nonReentrant".to_string()),
        "expected `nonReentrant` modifier-invocation in decorators; got: {:?}",
        f.decorators
    );
    assert_eq!(
        f.params,
        vec!["amount".to_string()],
        "deposit takes one named param"
    );
    assert_eq!(
        f.return_type.as_deref(),
        Some("bool"),
        "deposit returns bool"
    );
}

#[test]
fn extract_emits_function_natspec_docstring() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    let f = &c.methods[0];
    let ds = f
        .docstring
        .as_ref()
        .expect("deposit should have a NatSpec docstring");
    assert!(
        ds.contains("@notice Deposit ether"),
        "deposit docstring should preserve @notice; got: {ds:?}"
    );
    assert!(
        ds.contains("@param amount Amount to deposit"),
        "deposit docstring should preserve @param; got: {ds:?}"
    );
}

#[test]
fn extract_emits_contract_scope_modifier() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(
        c.modifiers.len(),
        1,
        "expected exactly 1 contract-scope modifier; got: {:?}",
        c.modifiers.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    let md = &c.modifiers[0];
    assert_eq!(md.name, "nonReentrant");
    assert!(md.params.is_empty(), "nonReentrant() has no params");
    assert!(md.body_present, "modifier has a body");
    assert!(!md.is_virtual);
    assert!(!md.is_override);
    // File-scope module modifiers list should be empty (the modifier
    // is inside the contract).
    assert!(
        m.modifiers.is_empty(),
        "no file-scope modifiers in fixture; got: {:?}",
        m.modifiers.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn extract_emits_event_with_indexed_param() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(c.events.len(), 1, "expected exactly 1 event");
    let ev = &c.events[0];
    assert_eq!(ev.name, "Deposit");
    assert!(!ev.is_anonymous);
    assert_eq!(ev.params.len(), 2, "Deposit has 2 params");
    // First param: `address indexed user`.
    assert_eq!(ev.params[0].name, "user");
    assert_eq!(ev.params[0].type_, "address");
    assert!(ev.params[0].indexed, "first param `user` is indexed");
    // Second param: `uint256 amount` (non-indexed).
    assert_eq!(ev.params[1].name, "amount");
    assert_eq!(ev.params[1].type_, "uint256");
    assert!(
        !ev.params[1].indexed,
        "second param `amount` is NOT indexed"
    );
}

#[test]
fn extract_emits_custom_error_with_typed_params() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert_eq!(c.errors.len(), 1, "expected exactly 1 custom error");
    let er = &c.errors[0];
    assert_eq!(er.name, "InsufficientBalance");
    assert_eq!(er.params.len(), 2);
    assert_eq!(er.params[0].name, "available");
    assert_eq!(er.params[0].type_.as_deref(), Some("uint256"));
    assert_eq!(er.params[1].name, "required");
    assert_eq!(er.params[1].type_.as_deref(), Some("uint256"));
}

#[test]
fn extract_emits_state_variable_as_class_field() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = &m.classes[0];
    assert!(
        c.fields.iter().any(|f| f.name == "totalDeposits"),
        "expected state var `totalDeposits` in class fields; got: {:?}",
        c.fields.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let f = c
        .fields
        .iter()
        .find(|f| f.name == "totalDeposits")
        .unwrap();
    assert_eq!(f.field_type.as_deref(), Some("uint256"));
    assert_eq!(f.visibility.as_deref(), Some("public"));
}

#[test]
fn extract_solidity_module_has_correct_language() {
    let (_tmp, file) = write_fixture();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert_eq!(m.language, Language::Solidity);
    // No top-level functions (the only function is a contract member).
    assert!(
        m.functions.is_empty(),
        "expected zero file-scope functions; got: {:?}",
        m.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    // No file-scope events/errors either.
    assert!(m.events.is_empty());
    assert!(m.errors.is_empty());
}

#[test]
fn extract_interface_kind_distinguished_from_contract() {
    let src = "\
pragma solidity ^0.8.0;
interface IFoo {
    function ping() external view returns (uint256);
}
contract Bar {}
library Util {}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("MultiKind.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert_eq!(m.classes.len(), 3, "expected 3 top-level decls");

    let by_name: std::collections::HashMap<&str, &str> = m
        .classes
        .iter()
        .map(|c| (c.name.as_str(), c.kind.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(by_name.get("IFoo"), Some(&"interface"));
    assert_eq!(by_name.get("Bar"), Some(&"contract"));
    assert_eq!(by_name.get("Util"), Some(&"library"));

    // The interface's `ping` should be a method with `view`
    // state_mutability on its own field after SOL-013 M3.
    let i_foo = m.classes.iter().find(|c| c.name == "IFoo").unwrap();
    assert_eq!(i_foo.methods.len(), 1);
    let ping = &i_foo.methods[0];
    assert_eq!(ping.name, "ping");
    assert_eq!(ping.visibility.as_deref(), Some("external"));
    assert_eq!(
        ping.state_mutability.as_deref(),
        Some("view"),
        "expected state_mutability=`view` on its own field; got: {:?}",
        ping.state_mutability
    );
    assert!(
        !ping.decorators.contains(&"view".to_string()),
        "state_mutability MUST NOT leak into decorators; got: {:?}",
        ping.decorators
    );
}

// ---------------------------------------------------------------------------
// solidity-sol013-cluster-v1 (v0.5.0 SOL-013): M2 + M3 regression tests.
// ---------------------------------------------------------------------------

/// SOL-013 M2: a `error InsufficientBalance(uint256 x);` declared at file
/// scope (Solidity 0.8.4+ free-standing errors) must populate
/// `ModuleInfo.errors`, not be silently dropped.
#[test]
fn extract_sol013_m2_file_scope_error_populates_module_errors() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

error InsufficientBalance(uint256 available, uint256 required);

contract Vault {
    function withdraw(uint256 amount) external {
        revert InsufficientBalance(0, amount);
    }
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("FreeError.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();

    assert_eq!(
        m.errors.len(),
        1,
        "expected 1 file-scope error in ModuleInfo.errors; got: {:?}",
        m.errors.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    let er = &m.errors[0];
    assert_eq!(er.name, "InsufficientBalance");
    assert_eq!(er.params.len(), 2);
    assert_eq!(er.params[0].name, "available");
    assert_eq!(er.params[0].type_.as_deref(), Some("uint256"));
    assert_eq!(er.params[1].name, "required");
    assert_eq!(er.params[1].type_.as_deref(), Some("uint256"));

    // The contract-scope errors list must remain empty — the error lives
    // at file scope, not inside Vault.
    let vault = m.classes.iter().find(|c| c.name == "Vault").unwrap();
    assert!(
        vault.errors.is_empty(),
        "file-scope error MUST NOT leak into ClassInfo.errors; got: {:?}",
        vault.errors.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// SOL-013 M2: a `event TopLevelEvent(...)` declared at file scope
/// (Solidity 0.8.22+ free-standing events) must populate
/// `ModuleInfo.events`, not be silently dropped.
#[test]
fn extract_sol013_m2_file_scope_event_populates_module_events() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

event GlobalLog(address indexed who, uint256 amount);

contract Emitter {
    function ping() external {
        emit GlobalLog(msg.sender, 1);
    }
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("FreeEvent.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();

    assert_eq!(
        m.events.len(),
        1,
        "expected 1 file-scope event in ModuleInfo.events; got: {:?}",
        m.events.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    let ev = &m.events[0];
    assert_eq!(ev.name, "GlobalLog");
    assert!(!ev.is_anonymous);
    assert_eq!(ev.params.len(), 2);
    assert_eq!(ev.params[0].name, "who");
    assert_eq!(ev.params[0].type_, "address");
    assert!(ev.params[0].indexed);
    assert_eq!(ev.params[1].name, "amount");
    assert_eq!(ev.params[1].type_, "uint256");
    assert!(!ev.params[1].indexed);

    // The contract-scope events list must remain empty — the event lives
    // at file scope, not inside Emitter.
    let emitter = m.classes.iter().find(|c| c.name == "Emitter").unwrap();
    assert!(
        emitter.events.is_empty(),
        "file-scope event MUST NOT leak into ClassInfo.events; got: {:?}",
        emitter.events.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

/// SOL-013 M2: a file with file-scope errors AND a contract that has its
/// own contract-scope errors must produce both lists correctly — neither
/// list bleeds into the other.
#[test]
fn extract_sol013_m2_file_scope_and_contract_scope_errors_independent() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

error FileLevelErr(uint256 x);

contract C {
    error ContractLevelErr(address a);
    function f() external {
        revert ContractLevelErr(address(0));
    }
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("BothScopeErrors.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();

    // Module-scope list has only the file-level error.
    let module_names: Vec<&str> = m.errors.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        module_names,
        vec!["FileLevelErr"],
        "ModuleInfo.errors should contain ONLY file-scope errors; got: {:?}",
        module_names
    );

    // Contract-scope list has only the contract-level error.
    let c = m.classes.iter().find(|c| c.name == "C").unwrap();
    let class_names: Vec<&str> = c.errors.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        class_names,
        vec!["ContractLevelErr"],
        "ClassInfo.errors should contain ONLY contract-scope errors; got: {:?}",
        class_names
    );
}

/// SOL-013 M3: a function declared `public payable onlyOwner nonReentrant`
/// must surface state_mutability=`payable` on its OWN field and
/// `decorators=[onlyOwner, nonReentrant]` — `payable` must NOT appear in
/// `decorators`.
#[test]
fn extract_sol013_m3_state_mutability_separated_from_decorators() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pay {
    modifier onlyOwner() { _; }
    modifier nonReentrant() { _; }

    function buy() public payable onlyOwner nonReentrant returns (uint256) {
        return 0;
    }

    function peek() public view returns (uint256) { return 1; }
    function constFn() public pure returns (uint256) { return 2; }
    function mutate(uint256 x) public { _ = x; }
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("StateMut.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();

    let c = m.classes.iter().find(|c| c.name == "Pay").unwrap();
    let by_name: std::collections::HashMap<&str, &_> =
        c.methods.iter().map(|f| (f.name.as_str(), f)).collect();

    // buy: state_mutability=payable, decorators=[onlyOwner, nonReentrant]
    let buy = by_name.get("buy").expect("missing buy");
    assert_eq!(
        buy.state_mutability.as_deref(),
        Some("payable"),
        "buy.state_mutability should be `payable`; got: {:?}",
        buy.state_mutability
    );
    assert!(
        !buy.decorators.contains(&"payable".to_string()),
        "buy.decorators MUST NOT contain `payable`; got: {:?}",
        buy.decorators
    );
    assert!(
        buy.decorators.contains(&"onlyOwner".to_string()),
        "buy.decorators should contain user modifier `onlyOwner`; got: {:?}",
        buy.decorators
    );
    assert!(
        buy.decorators.contains(&"nonReentrant".to_string()),
        "buy.decorators should contain user modifier `nonReentrant`; got: {:?}",
        buy.decorators
    );

    // peek: state_mutability=view, decorators=[]
    let peek = by_name.get("peek").expect("missing peek");
    assert_eq!(peek.state_mutability.as_deref(), Some("view"));
    assert!(
        !peek.decorators.contains(&"view".to_string()),
        "peek.decorators MUST NOT contain `view`; got: {:?}",
        peek.decorators
    );

    // constFn: state_mutability=pure
    let cfn = by_name.get("constFn").expect("missing constFn");
    assert_eq!(cfn.state_mutability.as_deref(), Some("pure"));
    assert!(
        !cfn.decorators.contains(&"pure".to_string()),
        "constFn.decorators MUST NOT contain `pure`; got: {:?}",
        cfn.decorators
    );

    // mutate: no state_mutability keyword present in source — must be None.
    let mutate = by_name.get("mutate").expect("missing mutate");
    assert!(
        mutate.state_mutability.is_none(),
        "mutate has no explicit state_mutability; got: {:?}",
        mutate.state_mutability
    );
}

/// SOL-013 M3: a `receive() external payable` falls through the fallback
/// extractor — state_mutability must still surface on its own field, not
/// in decorators.
#[test]
fn extract_sol013_m3_receive_state_mutability_separated() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Receiver {
    receive() external payable {}
    fallback() external payable {}
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("Receive.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();

    let c = m.classes.iter().find(|c| c.name == "Receiver").unwrap();
    let recv = c
        .methods
        .iter()
        .find(|f| f.name == "receive")
        .expect("missing receive");
    assert_eq!(
        recv.state_mutability.as_deref(),
        Some("payable"),
        "receive.state_mutability should be `payable`; got: {:?}",
        recv.state_mutability
    );
    assert!(
        !recv.decorators.contains(&"payable".to_string()),
        "receive.decorators MUST NOT contain `payable`; got: {:?}",
        recv.decorators
    );

    let fb = c
        .methods
        .iter()
        .find(|f| f.name == "fallback")
        .expect("missing fallback");
    assert_eq!(
        fb.state_mutability.as_deref(),
        Some("payable"),
        "fallback.state_mutability should be `payable`; got: {:?}",
        fb.state_mutability
    );
    assert!(
        !fb.decorators.contains(&"payable".to_string()),
        "fallback.decorators MUST NOT contain `payable`; got: {:?}",
        fb.decorators
    );
}

/// SOL-013 M3: a `constructor() payable` must surface payable on the
/// state_mutability field (the constructor extractor takes a separate
/// path from regular functions).
#[test]
fn extract_sol013_m3_constructor_payable_state_mutability() {
    let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract C {
    constructor() payable {}
}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("CtorPayable.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    let c = m.classes.iter().find(|c| c.name == "C").unwrap();
    let ctor = c
        .methods
        .iter()
        .find(|f| f.name == "constructor")
        .expect("missing constructor");
    assert_eq!(
        ctor.state_mutability.as_deref(),
        Some("payable"),
        "constructor.state_mutability should be `payable`; got: {:?}",
        ctor.state_mutability
    );
    assert!(
        !ctor.decorators.contains(&"payable".to_string()),
        "constructor.decorators MUST NOT contain `payable`; got: {:?}",
        ctor.decorators
    );
}

#[test]
fn extract_file_scope_constant_emits_constant_field() {
    let src = "\
pragma solidity ^0.8.0;
uint256 constant MAX_SUPPLY = 1000;
contract Foo {}
";
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("Const.sol");
    fs::write(&file, src).unwrap();
    let m = extract_file_with_lang(&file, None, Some(Language::Solidity)).unwrap();
    assert!(
        m.constants.iter().any(|c| c.name == "MAX_SUPPLY"
            && c.is_constant
            && c.field_type.as_deref() == Some("uint256")),
        "expected `MAX_SUPPLY` as file-scope constant; got: {:?}",
        m.constants
    );
}
