//! fix-cl4-interface-v1 (v0.5.0 CL-4)
//!
//! Regression tests for the iter-3b "inferior interface/contracts extractor"
//! cluster (GH #78) plus the C++ per-file `classes[]` enum leak:
//!
//!  - IT3-java-03    : `tldr interface` collapsed every Java method to the
//!                     enclosing class line. Each method must now report its
//!                     own decl-keyword line, matching `structure`/`extract`.
//!  - IT3-scala-01/02/03 : Scala curried+generic `def bounded[F[_], A]
//!                     (capacity: Int)(implicit F: ...)` dropped the value
//!                     parameter `capacity` and reported the type parameters
//!                     `F, A` as params across explain / context / contracts
//!                     / interface. The value clause(s) must now be captured.
//!  - IT3-javascript-03 : `tldr references` returned `definitions: []` for a
//!                     member-assigned function `app.X = function X(){}`.
//!  - cpp per-file classes leak : `structure tinyxml2.h --lang cpp` listed
//!                     enum names (`Mode`/`XMLError`) in `files[].classes`.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns early when
//! its corpus is absent and otherwise asserts against hand-counted ground
//! truth from the iter-3b audit.

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


use std::path::Path;
use std::process::Command;

fn tldr_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    std::path::PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (exit, stdout)
}

fn parse_json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or(serde_json::Value::Null)
}

const PETCONTROLLER: &str = "/tmp/repos/java-petclinic/src/main/java/org/springframework/samples/petclinic/owner/PetController.java";
const QUEUE_SCALA: &str = "/tmp/repos/scala-cats-effect/std/shared/src/main/scala/cats/effect/std/Queue.scala";

// ============================================================================
// IT3-java-03 — interface reports a distinct per-method decl-keyword line
// ============================================================================
#[test]
fn cl4_java_interface_methods_carry_distinct_decl_lines() {
    if !corpus_ready(PETCONTROLLER) {
        return;
    }
    let (rc, out) = run_tldr(&["interface", PETCONTROLLER, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);

    let lines: Vec<u64> = v["functions"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f["lineno"].as_u64()).collect())
        .unwrap_or_default();
    assert!(!lines.is_empty(), "expected functions[] to be non-empty");

    // Pre-fix every method collapsed to the class line (46). Post-fix each
    // method must report its own decl-keyword line — the 11 PetController
    // methods are at 56/62/67/75/89/94/100/107/130/135/167 (hand-counted,
    // anchored past `@ModelAttribute` / `@GetMapping` annotation lines).
    let distinct: std::collections::HashSet<u64> = lines.iter().copied().collect();
    assert!(
        distinct.len() >= 10,
        "java interface methods must carry distinct per-method lines; \
         got {:?}",
        lines
    );
    assert!(
        !distinct.contains(&46) || distinct.len() > 1,
        "methods must not all collapse to the class line (46); got {:?}",
        lines
    );
    for expected in &[56u64, 62, 67, 75, 89, 94, 100, 107, 130, 135, 167] {
        assert!(
            distinct.contains(expected),
            "expected a method at line {} (matching structure/extract); \
             got {:?}",
            expected,
            lines
        );
    }
}

// ============================================================================
// IT3-java-03 — interface per-method line agrees with structure
// ============================================================================
#[test]
fn cl4_java_interface_lines_match_structure() {
    if !corpus_ready(PETCONTROLLER) {
        return;
    }
    let (rc_i, out_i) = run_tldr(&["interface", PETCONTROLLER, "--format", "json"]);
    let (rc_s, out_s) = run_tldr(&["structure", PETCONTROLLER, "--format", "json"]);
    assert_eq!(rc_i, 0);
    assert_eq!(rc_s, 0);
    let vi = parse_json(&out_i);
    let vs = parse_json(&out_s);

    // structure method line set (from method_infos)
    let struct_lines: std::collections::HashSet<u64> = vs["files"][0]["method_infos"]
        .as_array()
        .map(|a| a.iter().filter_map(|m| m["line"].as_u64()).collect())
        .unwrap_or_default();
    let iface_lines: std::collections::HashSet<u64> = vi["functions"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f["lineno"].as_u64()).collect())
        .unwrap_or_default();

    assert!(!struct_lines.is_empty(), "structure method_infos empty");
    // Every interface method line must be a real method line per structure.
    for l in &iface_lines {
        assert!(
            struct_lines.contains(l),
            "interface line {} not present in structure method lines {:?}",
            l,
            struct_lines
        );
    }
}

// ============================================================================
// IT3-scala-01/02/03 — curried+generic value param `capacity` captured
// ============================================================================
#[test]
fn cl4_scala_explain_captures_value_param_not_type_param() {
    if !corpus_ready(QUEUE_SCALA) {
        return;
    }
    let (rc, out) = run_tldr(&["explain", QUEUE_SCALA, "bounded", "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let params: Vec<String> = v["signature"]["params"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    // Pre-fix params were the TYPE params [F, A]; the real value parameter
    // `capacity` was dropped. Post-fix `capacity` MUST appear, and the bare
    // type variable `A` (a type param, never a value param) MUST NOT.
    assert!(
        params.iter().any(|p| p == "capacity"),
        "explain must report the value parameter `capacity`; got {:?}",
        params
    );
    assert!(
        !params.iter().any(|p| p == "A"),
        "type parameter `A` must not be reported as a value param; got {:?}",
        params
    );
}

#[test]
fn cl4_scala_interface_signature_includes_value_clause() {
    if !corpus_ready(QUEUE_SCALA) {
        return;
    }
    let (rc, out) = run_tldr(&["interface", QUEUE_SCALA, "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);

    let mut sig: Option<String> = None;
    if let Some(classes) = v["classes"].as_array() {
        for c in classes {
            if let Some(methods) = c["methods"].as_array() {
                for m in methods {
                    if m["name"].as_str() == Some("bounded") {
                        sig = m["signature"].as_str().map(|s| s.to_string());
                    }
                }
            }
        }
    }
    let sig = sig.expect("interface must report method `bounded`");
    // The signature must carry the curried value clause `(capacity: Int)`,
    // not merely the type-parameter list `[F[_], A]`.
    assert!(
        sig.contains("capacity"),
        "interface signature for `bounded` must include value clause \
         `(capacity: Int)`; got `{}`",
        sig
    );
}

#[test]
fn cl4_scala_contracts_precondition_is_value_param() {
    if !corpus_ready(QUEUE_SCALA) {
        return;
    }
    let (rc, out) = run_tldr(&["contracts", QUEUE_SCALA, "bounded", "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let vars: Vec<String> = v["preconditions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["variable"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        vars.iter().any(|x| x == "capacity"),
        "contracts must derive a precondition for value param `capacity`; \
         got {:?}",
        vars
    );
    // Type variable `A` must never become a precondition variable.
    assert!(
        !vars.iter().any(|x| x == "A"),
        "type parameter `A` must not be a precondition variable; got {:?}",
        vars
    );
}

// ============================================================================
// IT3-javascript-03 — references resolves a member-assigned function def
// ============================================================================
#[test]
fn cl4_js_references_resolves_member_assigned_function() {
    let dir = "/tmp/tldr_corpora/js-express";
    if !corpus_ready(dir) {
        return;
    }
    // `app.defaultConfiguration = function defaultConfiguration() {...}` is a
    // member-assignment of a named function expression (Express's public
    // API idiom). Pre-fix `definitions[]` was empty; post-fix it must carry
    // the lib/application.js:90 declaration site.
    let (rc, out) = run_tldr(&[
        "references",
        "defaultConfiguration",
        dir,
        "--format",
        "json",
    ]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let defs = v["definitions"].as_array().cloned().unwrap_or_default();
    assert!(
        !defs.is_empty(),
        "references must report the member-assigned definition site; \
         got definitions=[]"
    );
    assert!(
        defs.iter().any(|d| {
            d["file"]
                .as_str()
                .map(|f| f.ends_with("application.js"))
                .unwrap_or(false)
                && d["line"].as_u64() == Some(90)
        }),
        "expected a definition at lib/application.js:90; got {:?}",
        defs
    );
}

// ============================================================================
// cpp per-file classes leak — enums excluded from files[].classes
// ============================================================================
#[test]
fn cl4_cpp_structure_classes_exclude_enums() {
    let file = "/tmp/repos/cpp-tinyxml2/tinyxml2.h";
    if !corpus_ready(file) {
        return;
    }
    let (rc, out) = run_tldr(&["structure", file, "--lang", "cpp", "--format", "json"]);
    assert_eq!(rc, 0);
    let v = parse_json(&out);
    let classes: Vec<String> = v["files"][0]["classes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Real cpp classes must still be present.
    for expected in &["XMLDocument", "XMLElement", "XMLNode"] {
        assert!(
            classes.iter().any(|c| c == expected),
            "real cpp class `{}` must remain in classes[]; got {:?}",
            expected,
            classes
        );
    }
    // Enum names must be gone from classes[].
    for enum_name in &["Mode", "XMLError", "Whitespace", "ElementClosingType"] {
        assert!(
            !classes.iter().any(|c| c == enum_name),
            "enum `{}` must NOT appear in files[].classes; got {:?}",
            enum_name,
            classes
        );
    }

    // Enums must still be reachable via definitions[] with kind="enum".
    let enum_defs: Vec<&str> = v["files"][0]["definitions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|d| d["kind"].as_str() == Some("enum"))
                .filter_map(|d| d["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        enum_defs.contains(&"Mode") && enum_defs.contains(&"XMLError"),
        "enums must remain in definitions[] (kind=enum); got {:?}",
        enum_defs
    );
}
