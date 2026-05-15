//! cluster-misc-v1: Two mechanical gap fixes bundled in one test file.
//!
//! # CLUSTER-M-042 — Elixir api-check / smells description fallback
//!
//! Pre-fix: `tldr api-check <elixir-file>` produces findings with no top-level
//! `description` field (it lives only in `.rule.description`). Same for `tldr
//! smells` — each smell entry has no `description` field.
//!
//! Post-fix: each `MisuseFinding` and `SmellFinding` carries a top-level
//! `description` field whose value is the rule / smell-type description string.
//!
//! # CLUSTER-M-044 — C++ dead-code: destructors / virtual methods excluded
//!
//! Pre-fix: `tldr dead` on C++ code flags `~Destructor` methods as
//! `possibly_dead`. Destructors are always implicitly called by the runtime
//! when an object goes out of scope or `delete` is invoked; they must never
//! appear in dead-code output.
//!
//! Post-fix:
//! - `~ClassName` functions are NOT in `possibly_dead`.
//! - `virtual` methods with body are NOT in `possibly_dead`.
//! - Non-virtual, non-destructor public uncalled methods ARE in `possibly_dead`
//!   (regression guard).

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// =============================================================================
// M-042: Elixir api-check finding has non-null description field
// =============================================================================

/// api-check finding for Elixir must have a non-null, non-empty `description`
/// field at the top level of each finding (not only nested in `.rule.description`).
#[test]
fn test_elixir_api_check_finding_has_description() {
    let dir = TempDir::new().unwrap();

    // Write an Elixir file that triggers EX001 (String.to_atom)
    fs::write(
        dir.path().join("app.ex"),
        r#"defmodule App do
  def unsafe(input) do
    String.to_atom(input)
  end
end
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["api-check", &path, "--lang", "elixir", "--format", "json", "-q"]);

    assert_eq!(code, 0, "tldr api-check failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "api-check output is not valid JSON: {}\nstdout:\n{}",
            e, stdout
        )
    });

    let findings = v
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("api-check output must have 'findings' array");

    assert!(
        !findings.is_empty(),
        "expected at least one EX001 finding for String.to_atom; got none\nstdout:\n{}",
        stdout
    );

    for finding in findings {
        let description = finding.get("description");
        assert!(
            description.is_some(),
            "finding is missing top-level 'description' field: {:?}",
            finding
        );
        let desc_str = description
            .and_then(|d| d.as_str())
            .unwrap_or("");
        assert!(
            !desc_str.is_empty(),
            "finding 'description' is present but empty: {:?}",
            finding
        );
    }
}

/// smells report for Elixir must have a non-null, non-empty `description` field
/// on each smell entry.
#[test]
fn test_elixir_smells_finding_has_description() {
    let dir = TempDir::new().unwrap();

    // Write a module with a long method to reliably trigger a smell
    let long_fn: String = {
        let mut lines = String::from("defmodule BigMod do\n  def long_fn do\n");
        for i in 0..60 {
            lines.push_str(&format!("    x{} = {}\n", i, i));
        }
        lines.push_str("  end\nend\n");
        lines
    };
    fs::write(dir.path().join("big.ex"), long_fn).unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["smells", &path, "--lang", "elixir", "--format", "json", "-q"]);

    assert_eq!(code, 0, "tldr smells failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "smells output is not valid JSON: {}\nstdout:\n{}",
            e, stdout
        )
    });

    let smells = v
        .get("smells")
        .and_then(|s| s.as_array())
        .expect("smells output must have 'smells' array");

    assert!(
        !smells.is_empty(),
        "expected at least one smell for the long_fn method; got none\nstdout:\n{}",
        stdout
    );

    for smell in smells {
        let description = smell.get("description");
        assert!(
            description.is_some(),
            "smell entry is missing top-level 'description' field: {:?}",
            smell
        );
        let desc_str = description
            .and_then(|d| d.as_str())
            .unwrap_or("");
        assert!(
            !desc_str.is_empty(),
            "smell 'description' is present but empty: {:?}",
            smell
        );
    }
}

// =============================================================================
// M-044: C++ destructor NOT in possibly_dead
// =============================================================================

/// A C++ destructor (`~ClassName`) must never appear in `possibly_dead`.
/// Destructors are implicitly invoked by the runtime; flagging them as dead is
/// always a false positive.
#[test]
fn test_cpp_destructor_not_in_possibly_dead() {
    let dir = TempDir::new().unwrap();

    // A class with a public destructor that is never explicitly called in code.
    // The normal method `doWork` is also public and never called — it should
    // appear as possibly_dead (regression guard).
    fs::write(
        dir.path().join("widget.cpp"),
        r#"
class Widget {
public:
    Widget() {}
    ~Widget() {}
    void doWork() {}
};

int main() {
    return 0;
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "cpp", "--format", "json", "-q"]);

    assert_eq!(code, 0, "tldr dead failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "dead output is not valid JSON: {}\nstdout:\n{}",
            e, stdout
        )
    });

    // No destructor should appear in possibly_dead or dead_functions
    for key in &["dead_functions", "possibly_dead"] {
        if let Some(arr) = v.get(*key).and_then(|x| x.as_array()) {
            for item in arr {
                let name = item
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                // Strip Class.method prefix if present
                let bare = name.rsplit('.').next().unwrap_or(name);
                assert!(
                    !bare.starts_with('~'),
                    "C++ destructor '{}' must not appear in '{}': {:?}",
                    name,
                    key,
                    item
                );
            }
        }
    }
}

/// A C++ `virtual` method (with body) must not appear in `possibly_dead`.
/// Virtual methods are dispatched polymorphically; flagging them as dead is
/// a false positive since they can be called via base-class pointers.
#[test]
fn test_cpp_virtual_method_not_in_possibly_dead() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("base.cpp"),
        r#"
class Base {
public:
    virtual void onEvent() {}
    virtual ~Base() {}
};

class Derived : public Base {
public:
    void onEvent() override {}
};

int main() {
    return 0;
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "cpp", "--format", "json", "-q"]);

    assert_eq!(code, 0, "tldr dead failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "dead output is not valid JSON: {}\nstdout:\n{}",
            e, stdout
        )
    });

    // `onEvent` is virtual — must not appear as possibly_dead
    for key in &["dead_functions", "possibly_dead"] {
        if let Some(arr) = v.get(*key).and_then(|x| x.as_array()) {
            for item in arr {
                let name = item
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let bare = name.rsplit('.').next().unwrap_or(name);
                assert!(
                    !bare.starts_with('~'),
                    "C++ destructor '{}' must not appear in '{}': {:?}",
                    name,
                    key,
                    item
                );
                // virtual method `onEvent` should not be flagged
                assert_ne!(
                    bare, "onEvent",
                    "virtual method 'onEvent' must not appear in '{}': {:?}",
                    key, item
                );
            }
        }
    }
}

/// Regression guard: a non-virtual, non-destructor, public, uncalled C++ method
/// MUST still appear in `possibly_dead`.
#[test]
fn test_cpp_plain_uncalled_public_method_in_possibly_dead() {
    let dir = TempDir::new().unwrap();

    fs::write(
        dir.path().join("thing.cpp"),
        r#"
class Thing {
public:
    void utilityHelper() {}
};

int main() {
    return 0;
}
"#,
    )
    .unwrap();

    let path = dir.path().to_string_lossy().to_string();
    let (code, stdout, stderr) =
        run_tldr(&["dead", &path, "--lang", "cpp", "--format", "json", "-q"]);

    assert_eq!(code, 0, "tldr dead failed (stderr: {})", stderr);

    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "dead output is not valid JSON: {}\nstdout:\n{}",
            e, stdout
        )
    });

    let possibly_dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .expect("dead output must have 'possibly_dead' array");

    let found = possibly_dead.iter().any(|item| {
        item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .contains("utilityHelper")
    });

    assert!(
        found,
        "expected 'utilityHelper' in possibly_dead (regression guard for non-virtual methods)\npossibly_dead:\n{:?}",
        possibly_dead
    );
}
