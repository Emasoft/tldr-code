//! extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002):
//!
//! Pre-fix audit assertion (Phase-22 audit, cluster M-002):
//! > "Function span begins at leading annotation line (e.g. `@Deprecated`,
//! >  `@Override`, `@deprecated`, `@inlinable`) instead of the
//! >  `def`/`func`/`method` declaration keyword line. The W-A fix landed
//! >  for `definition`/`references` (scan-forward) but NOT for
//! >  `extract`/`slice`/`explain`."
//!
//! Verdict: REAL BUG. tree-sitter's `method_declaration` /
//! `function_declaration` / `function_definition` nodes start at their
//! first child — which is `modifiers` / `attribute` for annotation-
//! decorated declarations. `extract_*_function_info` /
//! `extract_*_class_info` and `explain`'s `get_line_number(func_node)`
//! both read `node.start_position()` directly, so the reported line is
//! the annotation line, not the decl-keyword line.
//!
//! Fix: AST-walker normaliser — scan the function/class node's children
//! and use the start position of the first child that is NOT an
//! annotation / modifiers / attribute node. Applied at
//! `extract_*_function_info` + `extract_*_class_info` for java, kotlin,
//! scala, swift, and reused at `explain`'s `find_function_node` site.
//! `slice` reads bounds through `find_function_bounds`, which calls
//! `find_function_node` and `node.start_position()`; we apply the same
//! normaliser there.
//!
//! Test contract: for a real source per language with an annotation-
//! decorated declaration whose annotation is on a different line from
//! the decl keyword, all three of `extract`, `slice`, and `explain`
//! MUST report the decl-keyword line, not the annotation line.
//!
//! Coverage: java (`@Override`), kotlin (`@Deprecated(...)` multi-line),
//! scala (`@deprecated`), swift (`@inlinable`). 12 assertions
//! (4 langs × 3 commands).

use std::path::{Path, PathBuf};
use std::process::Command;

const PETCLINIC_CORPUS: &str = "/tmp/repos/spring-petclinic";
const KOTLIN_CORPUS: &str = "/tmp/repos/kotlin-datetime";
const SCALA_CORPUS: &str = "/tmp/repos/scala-cats-effect";
const SWIFT_CORPUS: &str = "/tmp/repos/swift-collections";

fn tldr_bin() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set under cargo test");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("target")
        .join("release")
        .join("tldr")
}

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(tldr_bin())
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

/// Walk `extract` JSON and return `(line, line_end)` for the named
/// function — searched in top-level `functions[]` then inside every
/// class's `methods[]`.
fn find_extract_func_line(stdout: &str, name: &str) -> Option<(u32, u32)> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    if let Some(arr) = v.get("functions").and_then(|x| x.as_array()) {
        for f in arr {
            if f.get("name").and_then(|n| n.as_str()) == Some(name) {
                let l = f.get("line").and_then(|l| l.as_u64())?;
                let e = f
                    .get("line_end")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(l);
                return Some((l as u32, e as u32));
            }
        }
    }
    if let Some(arr) = v.get("classes").and_then(|x| x.as_array()) {
        for c in arr {
            if let Some(methods) = c.get("methods").and_then(|x| x.as_array()) {
                for m in methods {
                    if m.get("name").and_then(|n| n.as_str()) == Some(name) {
                        let l = m.get("line").and_then(|l| l.as_u64())?;
                        let e = m
                            .get("line_end")
                            .and_then(|l| l.as_u64())
                            .unwrap_or(l);
                        return Some((l as u32, e as u32));
                    }
                }
            }
        }
    }
    None
}

/// Pull `line_start` from `tldr explain` JSON output.
fn parse_explain_line_start(stdout: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    v.get("line_start").and_then(|l| l.as_u64()).map(|n| n as u32)
}

/// Pull the smallest line from `tldr slice` `slice_lines[]` (or `lines[]`),
/// which represents the function's first source line in the slice when
/// the criterion line is anywhere inside the body. We use this as a
/// proxy for "slice resolved the function bounds starting at line X".
fn parse_slice_min_line(stdout: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let arr = v.get("lines")?.as_array()?;
    arr.iter()
        .filter_map(|x| x.as_u64())
        .min()
        .map(|n| n as u32)
}

// =============================================================================
// JAVA — PetTypeFormatter.print (line 45 `@Override`, line 46 decl)
// =============================================================================

#[test]
fn extract_java_method_decl_keyword_line() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!("[skip] java extract: corpus missing");
        return;
    }
    let file = format!(
        "{}/src/main/java/org/springframework/samples/petclinic/owner/PetTypeFormatter.java",
        PETCLINIC_CORPUS
    );
    let (exit, stdout, stderr) = run_tldr(&["extract", &file, "--format", "json"]);
    assert_eq!(exit, 0, "java extract must succeed. stderr=\n{}", stderr);
    let (line, _end) = find_extract_func_line(&stdout, "print")
        .expect("extract must report `print`");
    assert_eq!(
        line, 46,
        "M-002 java: `print` should start at decl-keyword line 46 (after `@Override` at 45); got {}",
        line
    );
}

#[test]
fn slice_java_method_decl_keyword_line() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!("[skip] java slice: corpus missing");
        return;
    }
    let file = format!(
        "{}/src/main/java/org/springframework/samples/petclinic/owner/PetTypeFormatter.java",
        PETCLINIC_CORPUS
    );
    // Pick criterion line inside the function body (line 47 = `String name = ...`).
    let (exit, stdout, stderr) =
        run_tldr(&["slice", &file, "print", "47", "--format", "json"]);
    assert_eq!(exit, 0, "java slice must succeed. stderr=\n{}", stderr);
    let min_line =
        parse_slice_min_line(&stdout).expect("java slice must produce at least one line");
    // After fix the slice's bounds-resolution starts at decl line 46 (not 45).
    assert!(
        min_line >= 46,
        "M-002 java slice: min line should be >= 46 (decl keyword); got {}",
        min_line
    );
}

#[test]
fn explain_java_method_decl_keyword_line() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!("[skip] java explain: corpus missing");
        return;
    }
    let file = format!(
        "{}/src/main/java/org/springframework/samples/petclinic/owner/PetTypeFormatter.java",
        PETCLINIC_CORPUS
    );
    let (exit, stdout, stderr) =
        run_tldr(&["explain", &file, "print", "--format", "json"]);
    assert_eq!(exit, 0, "java explain must succeed. stderr=\n{}", stderr);
    let line_start =
        parse_explain_line_start(&stdout).expect("explain must emit line_start");
    assert_eq!(
        line_start, 46,
        "M-002 java explain: line_start should be 46 (decl keyword), not 45 (annotation); got {}",
        line_start
    );
}

// =============================================================================
// KOTLIN — DayOfWeekJvm.kt: `DayOfWeek` fn at line 19 with @Deprecated(...)
// starting at line 13 (multi-line annotation + @Suppress + @kotlin.internal).
// =============================================================================

#[test]
fn extract_kotlin_function_decl_keyword_line() {
    if !Path::new(KOTLIN_CORPUS).exists() {
        eprintln!("[skip] kotlin extract: corpus missing");
        return;
    }
    let file = format!("{}/core/jvm/src/DayOfWeekJvm.kt", KOTLIN_CORPUS);
    let (exit, stdout, stderr) = run_tldr(&["extract", &file, "--format", "json"]);
    assert_eq!(exit, 0, "kotlin extract must succeed. stderr=\n{}", stderr);
    let (line, _end) = find_extract_func_line(&stdout, "DayOfWeek")
        .expect("extract must report `DayOfWeek`");
    assert_eq!(
        line, 19,
        "M-002 kotlin: `DayOfWeek` should start at decl-keyword line 19 (`public fun`); got {} (annotation starts line 13)",
        line
    );
}

#[test]
fn slice_kotlin_function_decl_keyword_line() {
    if !Path::new(KOTLIN_CORPUS).exists() {
        eprintln!("[skip] kotlin slice: corpus missing");
        return;
    }
    let file = format!("{}/core/jvm/src/DayOfWeekJvm.kt", KOTLIN_CORPUS);
    let (exit, stdout, stderr) =
        run_tldr(&["slice", &file, "DayOfWeek", "20", "--format", "json"]);
    assert_eq!(exit, 0, "kotlin slice must succeed. stderr=\n{}", stderr);
    let min_line =
        parse_slice_min_line(&stdout).expect("kotlin slice must produce at least one line");
    assert!(
        min_line >= 19,
        "M-002 kotlin slice: min line should be >= 19 (decl keyword); got {}",
        min_line
    );
}

#[test]
fn explain_kotlin_function_decl_keyword_line() {
    if !Path::new(KOTLIN_CORPUS).exists() {
        eprintln!("[skip] kotlin explain: corpus missing");
        return;
    }
    let file = format!("{}/core/jvm/src/DayOfWeekJvm.kt", KOTLIN_CORPUS);
    let (exit, stdout, stderr) =
        run_tldr(&["explain", &file, "DayOfWeek", "--format", "json"]);
    assert_eq!(exit, 0, "kotlin explain must succeed. stderr=\n{}", stderr);
    let line_start =
        parse_explain_line_start(&stdout).expect("kotlin explain must emit line_start");
    assert_eq!(
        line_start, 19,
        "M-002 kotlin explain: line_start should be 19 (decl keyword), not 13 (annotation); got {}",
        line_start
    );
}

// =============================================================================
// SCALA — IO.scala: `interpret` method on line 2344 with `@deprecated` on
// line 2343. The first occurrence in the class body — there is a SECOND
// `interpret` overload at line 2348 with `@static`. We pin the first.
// =============================================================================

#[test]
fn extract_scala_method_decl_keyword_line() {
    if !Path::new(SCALA_CORPUS).exists() {
        eprintln!("[skip] scala extract: corpus missing");
        return;
    }
    let file = format!(
        "{}/core/shared/src/main/scala/cats/effect/IO.scala",
        SCALA_CORPUS
    );
    let (exit, stdout, stderr) = run_tldr(&["extract", &file, "--format", "json"]);
    assert_eq!(exit, 0, "scala extract must succeed. stderr=\n{}", stderr);
    // Look inside `SyncStep` private object for the first `interpret`.
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("scala extract JSON");
    let classes = v
        .get("classes")
        .and_then(|x| x.as_array())
        .expect("scala extract has classes");
    // tree-sitter-scala emits TWO `SyncStep` ClassInfo entries (one for
    // the parameterized class header at line 2338 and one for the
    // companion-object body at line 2340 which carries the methods);
    // find the one that actually contains `interpret`.
    let sync_step = classes
        .iter()
        .find(|c| {
            c.get("name").and_then(|n| n.as_str()) == Some("SyncStep")
                && c.get("methods")
                    .and_then(|x| x.as_array())
                    .map(|ms| {
                        ms.iter().any(|m| {
                            m.get("name").and_then(|n| n.as_str()) == Some("interpret")
                        })
                    })
                    .unwrap_or(false)
        })
        .expect("scala extract has SyncStep with interpret");
    let methods = sync_step
        .get("methods")
        .and_then(|x| x.as_array())
        .expect("SyncStep has methods");
    let first_interpret = methods
        .iter()
        .find(|m| m.get("name").and_then(|n| n.as_str()) == Some("interpret"))
        .expect("SyncStep has interpret");
    let line = first_interpret
        .get("line")
        .and_then(|l| l.as_u64())
        .expect("interpret has line");
    assert_eq!(
        line as u32, 2344,
        "M-002 scala: first `interpret` should start at decl-keyword line 2344, not 2343 (`@deprecated`); got {}",
        line
    );
}

#[test]
fn slice_scala_method_decl_keyword_line() {
    if !Path::new(SCALA_CORPUS).exists() {
        eprintln!("[skip] scala slice: corpus missing");
        return;
    }
    let file = format!(
        "{}/core/shared/src/main/scala/cats/effect/IO.scala",
        SCALA_CORPUS
    );
    // Body line 2346 is inside `interpret(io, limit, MaxSteps)`.
    let (exit, stdout, stderr) =
        run_tldr(&["slice", &file, "interpret", "2346", "--format", "json"]);
    assert_eq!(exit, 0, "scala slice must succeed. stderr=\n{}", stderr);
    let min_line =
        parse_slice_min_line(&stdout).expect("scala slice must produce at least one line");
    assert!(
        min_line >= 2344,
        "M-002 scala slice: min line should be >= 2344 (decl keyword); got {}",
        min_line
    );
}

#[test]
fn explain_scala_method_decl_keyword_line() {
    if !Path::new(SCALA_CORPUS).exists() {
        eprintln!("[skip] scala explain: corpus missing");
        return;
    }
    let file = format!(
        "{}/core/shared/src/main/scala/cats/effect/IO.scala",
        SCALA_CORPUS
    );
    let (exit, stdout, stderr) =
        run_tldr(&["explain", &file, "interpret", "--format", "json"]);
    assert_eq!(exit, 0, "scala explain must succeed. stderr=\n{}", stderr);
    let line_start =
        parse_explain_line_start(&stdout).expect("scala explain must emit line_start");
    assert_eq!(
        line_start, 2344,
        "M-002 scala explain: line_start should be 2344 (decl keyword), not 2343 (annotation); got {}",
        line_start
    );
}

// =============================================================================
// SWIFT — SortedSet+Subscripts.swift: `_firstTreeIndex` at line 93 with
// `@inlinable` at line 92.
// =============================================================================

#[test]
fn extract_swift_method_decl_keyword_line() {
    if !Path::new(SWIFT_CORPUS).exists() {
        eprintln!("[skip] swift extract: corpus missing");
        return;
    }
    let file = format!(
        "{}/Sources/SortedCollections/SortedSet/SortedSet+Subscripts.swift",
        SWIFT_CORPUS
    );
    let (exit, stdout, stderr) = run_tldr(&["extract", &file, "--format", "json"]);
    assert_eq!(exit, 0, "swift extract must succeed. stderr=\n{}", stderr);
    let (line, _end) = find_extract_func_line(&stdout, "_firstTreeIndex")
        .expect("extract must report `_firstTreeIndex`");
    assert_eq!(
        line, 93,
        "M-002 swift: `_firstTreeIndex` should start at decl-keyword line 93 (`internal func`); got {} (annotation at 92)",
        line
    );
}

#[test]
fn slice_swift_method_decl_keyword_line() {
    if !Path::new(SWIFT_CORPUS).exists() {
        eprintln!("[skip] swift slice: corpus missing");
        return;
    }
    let file = format!(
        "{}/Sources/SortedCollections/SortedSet/SortedSet+Subscripts.swift",
        SWIFT_CORPUS
    );
    // Body line 94 = `let i = _root.startIndex(forKey: element)`.
    let (exit, stdout, stderr) = run_tldr(&[
        "slice",
        &file,
        "_firstTreeIndex",
        "94",
        "--format",
        "json",
    ]);
    assert_eq!(exit, 0, "swift slice must succeed. stderr=\n{}", stderr);
    let min_line =
        parse_slice_min_line(&stdout).expect("swift slice must produce at least one line");
    assert!(
        min_line >= 93,
        "M-002 swift slice: min line should be >= 93 (decl keyword); got {}",
        min_line
    );
}

#[test]
fn explain_swift_method_decl_keyword_line() {
    if !Path::new(SWIFT_CORPUS).exists() {
        eprintln!("[skip] swift explain: corpus missing");
        return;
    }
    let file = format!(
        "{}/Sources/SortedCollections/SortedSet/SortedSet+Subscripts.swift",
        SWIFT_CORPUS
    );
    let (exit, stdout, stderr) =
        run_tldr(&["explain", &file, "_firstTreeIndex", "--format", "json"]);
    assert_eq!(exit, 0, "swift explain must succeed. stderr=\n{}", stderr);
    let line_start =
        parse_explain_line_start(&stdout).expect("swift explain must emit line_start");
    assert_eq!(
        line_start, 93,
        "M-002 swift explain: line_start should be 93 (decl keyword), not 92 (annotation); got {}",
        line_start
    );
}
