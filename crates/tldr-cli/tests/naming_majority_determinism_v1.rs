//! naming-majority-determinism-v1 — regression tests for non-deterministic
//! `tldr patterns` output exposed by `language-coverage-fixes-v1`
//! (commit ef5f6cf).
//!
//! Root cause: `crates/tldr-core/src/patterns/naming.rs::detect_majority_convention`
//! used `HashMap<NamingCase, usize>` + `max_by_key(count)`, which
//! produced non-deterministic results on COUNT TIES. When `UpperAlpha`
//! (single-word uppercase, e.g. `E1`) tied with `PascalCase` (e.g.
//! `UserService`) at 1+1 in the class-name list, the chosen "majority"
//! varied run-to-run. Roughly 1 in 3 runs chose `UpperAlpha`, which
//! then made `UserService` (a PascalCase identifier) appear as a
//! violation against an `UpperAlpha` expectation, displayed in JSON
//! after `naming_case_to_convention` collapse as
//! `{name:"UserService", expected:"pascal_case", actual:"pascal_case"}`
//! — a self-violation that is impossible per `is_compatible(Pascal, Pascal) → true`.
//!
//! Fix: tie-break is now (count desc, specificity desc, sort_key asc),
//! where concrete conventions (snake/camel/Pascal/UPPER_SNAKE) outrank
//! degenerate single-word forms (`LowerAlpha`, `UpperAlpha`). The
//! secondary `sort_key` ensures full determinism even when concretes
//! tie with concretes or degenerates with degenerates.
//!
//! These tests assert the two contracts:
//!
//! 1. **Concrete-over-degenerate tie-break**: a synthetic Java fixture
//!    with `1 × PascalCase + 1 × UpperAlpha` classes resolves majority
//!    to `pascal_case` and reports zero self-violations
//!    (`expected == actual`).
//! 2. **Run-to-run determinism**: 3 consecutive `tldr patterns` runs
//!    on the same fixture produce byte-identical naming output
//!    (`naming.classes`, `naming.functions`, sorted `naming.violations`).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// Run `tldr <args>` and parse stdout as JSON.
fn run_json(args: &[&str]) -> Value {
    let out = tldr_cmd()
        .args(args)
        .args(["--format", "json", "-q"])
        .output()
        .unwrap_or_else(|e| panic!("spawn {:?}: {}", args, e));
    assert!(
        out.status.success(),
        "tldr {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tldr {:?} JSON parse failed: {}\nstdout={}",
            args,
            e,
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Synthetic Java fixture matching the P4.BUG-N4 reproducer: one
/// `PascalCase` class (`UserService`) + one `UpperAlpha` class (`E1`),
/// with 4 `CamelCase` methods + 2 `LowerAlpha` methods.
const SERVICE_JAVA: &str = r#"
package demo;

public class UserService {
    public void findUserById(int id) { }
    public void getAllUsers() { }
    public void createUser(String name) { }
    public void print() { }
    public void save() { }
}

class E1 {
    public void doWork() { }
}
"#;

/// Test 1: Tie-break must prefer the concrete sibling (`PascalCase`)
/// over the degenerate one (`UpperAlpha`). After the fix, majority
/// resolves to `pascal_case` deterministically, and no violation has
/// `expected == actual`.
#[test]
fn test_majority_breaks_ties_toward_concrete_over_degenerate() {
    let dir = TempDir::new().unwrap();
    write(&dir.path().join("Service.java"), SERVICE_JAVA);

    let v = run_json(&["patterns", dir.path().to_str().unwrap()]);

    // Class-naming majority must be the concrete sibling.
    let classes = v
        .pointer("/naming/classes")
        .and_then(|c| c.as_str())
        .unwrap_or("<missing>");
    assert_eq!(
        classes,
        "pascal_case",
        "naming.classes should resolve to pascal_case (the concrete \
         sibling), not the degenerate upper_alpha → pascal_case \
         collapse path; got {:?}. Full naming block: {:?}",
        classes,
        v.pointer("/naming")
    );

    // No self-violation: the spurious "PascalCase against PascalCase"
    // entry that appeared in ~⅔ of pre-fix runs must never show up.
    let violations = v
        .pointer("/naming/violations")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for viol in &violations {
        let expected = viol.get("expected").and_then(|x| x.as_str()).unwrap_or("");
        let actual = viol.get("actual").and_then(|x| x.as_str()).unwrap_or("");
        assert!(
            expected != actual,
            "naming violation has expected == actual ({:?} == {:?}) — \
             impossible per is_compatible({}, {}) early-return. \
             Full violation: {:?}",
            expected,
            actual,
            expected,
            actual,
            viol
        );
    }
}

/// Test 2: Run `tldr patterns` 3 times on identical input and assert
/// the relevant naming subset is byte-identical across all runs. This
/// is the direct contract the milestone fixes — pre-fix, the same
/// fixture produced different `naming.classes` / `naming.violations`
/// across runs because of HashMap iteration order.
#[test]
fn test_patterns_output_deterministic_across_repeats() {
    let dir = TempDir::new().unwrap();
    write(&dir.path().join("Service.java"), SERVICE_JAVA);

    let path_arg = dir.path().to_str().unwrap();

    fn naming_subset(v: &Value) -> Value {
        // Extract just the naming fields we care about, with violations
        // sorted for set-equality comparison (file/line/name keys are
        // stable identifiers).
        let naming = v.pointer("/naming").cloned().unwrap_or(Value::Null);
        let classes = naming.get("classes").cloned().unwrap_or(Value::Null);
        let functions = naming.get("functions").cloned().unwrap_or(Value::Null);
        let constants = naming.get("constants").cloned().unwrap_or(Value::Null);
        let private_prefix = naming.get("private_prefix").cloned().unwrap_or(Value::Null);
        let mut violations = naming
            .get("violations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        // Sort violations by (file, line, name) for deterministic
        // comparison across runs even if internal order differs.
        violations.sort_by(|a, b| {
            let key = |x: &Value| {
                (
                    x.get("file")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    x.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                    x.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                )
            };
            key(a).cmp(&key(b))
        });
        serde_json::json!({
            "classes": classes,
            "functions": functions,
            "constants": constants,
            "private_prefix": private_prefix,
            "violations": violations,
        })
    }

    let r1 = naming_subset(&run_json(&["patterns", path_arg]));
    let r2 = naming_subset(&run_json(&["patterns", path_arg]));
    let r3 = naming_subset(&run_json(&["patterns", path_arg]));

    assert_eq!(
        r1, r2,
        "tldr patterns naming output non-deterministic between run 1 \
         and run 2: {} vs {}",
        r1, r2
    );
    assert_eq!(
        r2, r3,
        "tldr patterns naming output non-deterministic between run 2 \
         and run 3: {} vs {}",
        r2, r3
    );
}
