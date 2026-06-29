//! CFr-RW1 generalization + false-positive guard: C++11 trailing-return types
//! (`auto f(...) -> T`) in the `interface` and `contracts` commands.
//!
//! Wave-1 S2 fixed `tldr extract` so a trailing-return function reports the
//! declared type `T` instead of the bare `auto` placeholder, by reading the
//! `trailing_return_type` AST node off the `function_declarator`. The fix did
//! NOT reach `tldr interface` or `tldr contracts`, which have their OWN C/C++
//! return-type extraction and still rendered `: auto` / `return: auto`.
//!
//! This residual test asserts BOTH halves of the anti-treadmill contract:
//!   (a) the NEW sibling cases are now correct — `interface` AND `contracts`
//!       report the real trailing type `T` (`int`, `char*`, …); and
//!   (b) the ORIGINAL CF case still passes — `extract` (the reference) keeps
//!       reporting the real trailing type for the SAME source; plus a
//!       false-positive guard that a genuinely-deduced `auto` (no trailing
//!       return) KEEPS the `auto` placeholder in every command (no over-reach).
//!
//! Purely AST-driven: the trailing type is read from the `trailing_return_type`
//! node's `type_descriptor`, gated on the leading type being the `auto`
//! placeholder — never on a name list or substring heuristic.

use std::fs;

use tempfile::TempDir;
use tldr_cli::commands::contracts::contracts::run_contracts;
use tldr_cli::commands::patterns::interface::extract_interface_with_lang;
use tldr_core::ast::extract::extract_file_with_lang;
use tldr_core::Language;

/// Fixture exercising the trailing-return shape plus the two guards (a genuinely
/// deduced `auto` with no trailing return, and an ordinary leading-typed fn).
const CPP_TRAILING_RETURN: &str = r#"
#include <cstddef>

// C++11 trailing-return free function: the leading `type` field is the `auto`
// placeholder; the real return type `int` lives in the `trailing_return_type`.
auto trailing_int() -> int { return 0; }

// Pointer-returning trailing return: the trailing type carries the `*`.
auto trailing_ptr() -> char* { return nullptr; }

// FALSE-POSITIVE GUARD: a genuinely-deduced `auto` (NO trailing return) must
// keep the `auto` placeholder — there is no declared type to recover.
auto deduced_auto() { return 42; }

// Unrelated leading-typed function — must be wholly unaffected.
long normal_long(int n) { return n; }
"#;

fn write_fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("trailing.cc");
    fs::write(&path, CPP_TRAILING_RETURN).unwrap();
    (temp, path)
}

fn signature_of<'a>(
    info: &'a tldr_cli::commands::patterns::types::InterfaceInfo,
    name: &str,
) -> &'a str {
    info.functions
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.signature.as_str())
        .unwrap_or_else(|| panic!("function {name:?} missing from interface: {:?}", info.functions))
}

/// (a) sibling — `tldr interface`: trailing-return functions render the real
/// declared type, and a genuinely-deduced `auto` keeps the placeholder.
#[test]
fn cfr_rw1_interface_reads_cpp_trailing_return_type() {
    let (_tmp, path) = write_fixture();
    let info = extract_interface_with_lang(&path, CPP_TRAILING_RETURN, Language::Cpp).unwrap();

    let trailing_int = signature_of(&info, "trailing_int");
    assert!(
        trailing_int.contains(": int") && !trailing_int.contains(": auto"),
        "interface: trailing_int should report `int`, not the `auto` placeholder; got {trailing_int:?}"
    );

    let trailing_ptr = signature_of(&info, "trailing_ptr");
    assert!(
        trailing_ptr.contains("char") && !trailing_ptr.contains(": auto"),
        "interface: trailing_ptr should report a `char*` type, not `auto`; got {trailing_ptr:?}"
    );

    // False-positive guard: deduced `auto` (no trailing return) keeps `auto`.
    let deduced = signature_of(&info, "deduced_auto");
    assert!(
        deduced.contains(": auto"),
        "interface: a genuinely-deduced `auto` must keep the placeholder; got {deduced:?}"
    );

    // Ordinary leading-typed function unaffected.
    let normal = signature_of(&info, "normal_long");
    assert!(
        normal.contains(": long"),
        "interface: leading-typed `long` function must be unchanged; got {normal:?}"
    );
}

fn has_return_postcondition(file: &std::path::Path, func: &str, expected: &str) -> bool {
    let report = run_contracts(file, func, Language::Cpp, 100).unwrap();
    report
        .postconditions
        .iter()
        .any(|p| p.constraint == expected)
}

/// (a) sibling — `tldr contracts`: the return postcondition uses the real
/// trailing type, and a deduced `auto` keeps the placeholder.
#[test]
fn cfr_rw1_contracts_reads_cpp_trailing_return_type() {
    let (_tmp, path) = write_fixture();

    assert!(
        has_return_postcondition(&path, "trailing_int", "return: int"),
        "contracts: trailing_int must emit `return: int`, got {:?}",
        run_contracts(&path, "trailing_int", Language::Cpp, 100)
            .unwrap()
            .postconditions
    );
    assert!(
        !has_return_postcondition(&path, "trailing_int", "return: auto"),
        "contracts: trailing_int must NOT emit the bare `return: auto` placeholder"
    );

    assert!(
        has_return_postcondition(&path, "trailing_ptr", "return: char*"),
        "contracts: trailing_ptr must emit `return: char*`, got {:?}",
        run_contracts(&path, "trailing_ptr", Language::Cpp, 100)
            .unwrap()
            .postconditions
    );

    // False-positive guard: deduced `auto` keeps the `auto` placeholder.
    assert!(
        has_return_postcondition(&path, "deduced_auto", "return: auto"),
        "contracts: a genuinely-deduced `auto` must keep the `return: auto` placeholder"
    );
}

/// (b) reference — `tldr extract` (the original S2 CF fix) still reports the
/// real trailing type for the SAME source. Locks the residual to the original.
#[test]
fn cfr_rw1_extract_reference_still_reads_trailing_return() {
    let (_tmp, path) = write_fixture();
    let module = extract_file_with_lang(&path, None, Some(Language::Cpp)).unwrap();

    let ret = |name: &str| -> Option<String> {
        module
            .functions
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.return_type.clone())
    };

    assert_eq!(
        ret("trailing_int").as_deref(),
        Some("int"),
        "extract reference: trailing_int return_type must be `int`, got {:?}",
        ret("trailing_int")
    );
    assert!(
        ret("trailing_ptr").as_deref().unwrap_or("").contains("char"),
        "extract reference: trailing_ptr return_type must mention `char`, got {:?}",
        ret("trailing_ptr")
    );
}
