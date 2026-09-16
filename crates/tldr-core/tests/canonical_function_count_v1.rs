//! canonical-function-enumerator-v1 — milestone tests
//!
//! Verifies that `health.summary.functions_analyzed`,
//! `structure` (sum of `functions` + `methods`), and `dead.total_functions`
//! all return the same count on the same input. The fourth command
//! `verify` is intentionally OUT of scope: its `coverage.total_functions`
//! reports a different metric (contract-amenable functions).

use std::fs;
use std::path::Path;

use tempfile::tempdir;

use tldr_core::ast::count_functions_canonical;
use tldr_core::quality::complexity::analyze_complexity;
use tldr_core::quality::dead_code::analyze_dead_code;
use tldr_core::types::Language;
use tldr_core::IgnoreSpec;

fn structure_func_method_sum(path: &Path, lang: Language) -> u32 {
    let s = tldr_core::get_code_structure(path, lang, 0, Some(&IgnoreSpec::default())).unwrap();
    let mut total: u32 = 0;
    for f in &s.files {
        total = total.saturating_add(f.functions.len() as u32);
        total = total.saturating_add(f.methods.len() as u32);
    }
    total
}

fn complexity_count(path: &Path, lang: Language) -> u32 {
    let r = analyze_complexity(path, Some(lang), None).unwrap();
    r.functions_analyzed as u32
}

fn dead_count(path: &Path, lang: Language) -> u32 {
    let r = analyze_dead_code(path, Some(lang), &[]).unwrap();
    r.functions_analyzed as u32
}

#[test]
fn test_canonical_count_agrees_health_structure_dead_python() {
    let dir = tempdir().unwrap();
    // 3 top-level functions + 1 class with 4 methods (incl. dunders) = 7
    fs::write(
        dir.path().join("a.py"),
        "def f1():\n    pass\n\ndef f2():\n    pass\n\nclass C:\n    def __init__(self):\n        pass\n    def m1(self):\n        pass\n    def m2(self):\n        pass\n    def __repr__(self):\n        return ''\n",
    )
    .unwrap();
    fs::write(dir.path().join("b.py"), "def g1():\n    pass\n").unwrap();

    let canonical = count_functions_canonical(dir.path(), Language::Python);
    let from_health = complexity_count(dir.path(), Language::Python);
    let from_structure = structure_func_method_sum(dir.path(), Language::Python);
    let from_dead = dead_count(dir.path(), Language::Python);

    assert_eq!(canonical, 7, "canonical should be 7 (3 top + 4 methods)");
    assert_eq!(
        from_health, canonical,
        "health (complexity.functions_analyzed) must equal canonical"
    );
    assert_eq!(
        from_structure, canonical,
        "structure sum(funcs + methods) must equal canonical"
    );
    assert_eq!(
        from_dead, canonical,
        "dead.total_functions must equal canonical"
    );
}

#[test]
fn test_canonical_count_agrees_health_structure_dead_rust() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("lib.rs"),
        "pub fn top1() {}\npub fn top2() {}\nstruct S;\nimpl S {\n    pub fn m1(&self) {}\n    pub fn m2(&self) {}\n}\n",
    )
    .unwrap();

    let canonical = count_functions_canonical(dir.path(), Language::Rust);
    let from_health = complexity_count(dir.path(), Language::Rust);
    let from_structure = structure_func_method_sum(dir.path(), Language::Rust);
    let from_dead = dead_count(dir.path(), Language::Rust);

    assert_eq!(canonical, 4);
    assert_eq!(from_health, canonical, "rust: health == canonical");
    assert_eq!(from_structure, canonical, "rust: structure == canonical");
    assert_eq!(from_dead, canonical, "rust: dead == canonical");
}

#[test]
fn test_canonical_count_agrees_health_structure_dead_javascript() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("a.js"),
        "function top1() {}\nfunction top2() {}\nclass C {\n  m1() {}\n  m2() {}\n}\n",
    )
    .unwrap();

    let canonical = count_functions_canonical(dir.path(), Language::JavaScript);
    let from_health = complexity_count(dir.path(), Language::JavaScript);
    let from_structure = structure_func_method_sum(dir.path(), Language::JavaScript);
    let from_dead = dead_count(dir.path(), Language::JavaScript);

    assert_eq!(canonical, 4);
    assert_eq!(from_health, canonical, "js: health == canonical");
    assert_eq!(from_structure, canonical, "js: structure == canonical");
    assert_eq!(from_dead, canonical, "js: dead == canonical");
}
