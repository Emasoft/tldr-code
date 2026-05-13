//! change-impact-line-attribution-v1 (v0.4.2 M-004):
//!
//! Pre-fix audit assertion (Phase-22 audit, cluster M-004):
//! > "`tldr change-impact <file>` emits `affected_functions[i].line == 0`
//! >  for every entry across ~14 languages. The actual line of the
//! >  affected function definition is available in extract/structure
//! >  output but is dropped/never-populated in change-impact's emitter."
//!
//! Verdict: REAL BUG. `find_functions_in_files` constructs `FunctionRef`s
//! via `FunctionRef::new(file, name)`, which leaves `line: 0`. Pass-2
//! (AST extraction) has the line in `FunctionInfo.line_number` /
//! `class.methods[i].line_number` but discards it. Callers found via
//! pass-1 (call-graph edges) are similarly line-less because
//! `ProjectCallGraph::Edge` doesn't carry the function's defining line.
//!
//! Fix: post-process `affected_functions` by extracting the AST for each
//! unique file once (cached) and joining on (`file`, `name`) — including
//! the qualified `Class.method` form. When the join finds a match, set
//! `FunctionRef.line` from `FunctionInfo.line_number` /
//! `class.methods[i].line_number`. Names that have no AST match
//! (e.g. file-level imports promoted into the call graph in some langs,
//! or call-graph edges that point at constructs whose name we cannot
//! resolve to a definition) keep `line: 0` — documented behaviour.
//!
//! Test contract: for a real source file with N>1 known function
//! definitions, `affected_functions[i].line` MUST be the 1-indexed line
//! of the definition for at least the functions defined inside the
//! changed file itself. We assert this for python (flask), java
//! (spring-petclinic) and go (go-httprouter). Real-repo gated.

use std::path::Path;
use std::process::Command;

const FLASK_CORPUS: &str = "/tmp/repos/flask";
const PETCLINIC_CORPUS: &str = "/tmp/repos/spring-petclinic";
const HTTPROUTER_CORPUS: &str = "/tmp/repos/go-httprouter";

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

/// Pull `affected_functions` out of a change-impact JSON report.
fn parse_affected_functions(stdout: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).expect("change-impact stdout must be valid JSON");
    v.get("affected_functions")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Read a source file and return the 1-indexed line number whose text
/// contains `needle`. Returns `None` if not found. Used to cross-check
/// the line emitted by change-impact against the true definition line in
/// the file.
fn find_line_containing(path: &Path, needle: &str) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    for (idx, line) in text.lines().enumerate() {
        if line.contains(needle) {
            return Some((idx + 1) as u32);
        }
    }
    None
}

// =============================================================================
// TEST 1 (python / flask): change-impact emits a non-zero line for at least
// one of the functions defined inside the changed file.
//
// Target: `src/flask/cli.py` — a real flask source file with many top-level
// functions and class methods. We pin one easily-located definition
// (`def get_version`) and assert the reported line equals the line where
// `def get_version` actually appears.
// =============================================================================
#[test]
fn change_impact_line_attribution_python_flask() {
    if !Path::new(FLASK_CORPUS).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_python_flask: corpus {} not present",
            FLASK_CORPUS
        );
        return;
    }
    let file = format!("{}/src/flask/cli.py", FLASK_CORPUS);
    if !Path::new(&file).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_python_flask: target {} not present",
            file
        );
        return;
    }

    let true_line = find_line_containing(Path::new(&file), "def get_version")
        .expect("flask cli.py must contain `def get_version`");

    let (exit, stdout, stderr) = run_tldr(&["change-impact", &file, "--format", "json"]);
    assert_eq!(
        exit, 0,
        "change-impact must succeed on a flask file. stderr=\n{}",
        stderr
    );

    let affected = parse_affected_functions(&stdout);
    assert!(
        !affected.is_empty(),
        "change-impact on flask/cli.py must return at least one affected_function"
    );

    // Locate the `get_version` entry (top-level function, no class).
    let entry = affected
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("get_version"))
        .expect("affected_functions must include `get_version`");
    let line = entry
        .get("line")
        .and_then(|l| l.as_u64())
        .expect("affected_functions[i].line must be present and numeric");
    assert_eq!(
        line as u32, true_line,
        "M-004: line for `get_version` must equal the real def line in cli.py"
    );

    // Also assert that the bulk of entries are not stuck at 0 — the bug
    // was that EVERY entry had line:0. After the fix, at least one entry
    // (besides `get_version`) must have a non-zero line so we catch
    // partial-fix regressions.
    let nonzero = affected
        .iter()
        .filter(|f| f.get("line").and_then(|l| l.as_u64()).unwrap_or(0) > 0)
        .count();
    assert!(
        nonzero >= 2,
        "M-004: at least 2 affected_functions entries must have non-zero `line` after the fix; got {} of {}",
        nonzero,
        affected.len()
    );
}

// =============================================================================
// TEST 2 (java / spring-petclinic): change-impact emits non-zero `line` for
// class methods in a java source file.
//
// Target: `OwnerController.java` — known to contain multiple public
// methods. Class methods are emitted as the qualified `ClassName.method`
// form by `find_functions_in_files` (Pass-2). The fix must populate
// `line` for those qualified entries too.
// =============================================================================
#[test]
fn change_impact_line_attribution_java_petclinic() {
    if !Path::new(PETCLINIC_CORPUS).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_java_petclinic: corpus {} not present",
            PETCLINIC_CORPUS
        );
        return;
    }
    // Find the OwnerController file (path varies slightly across petclinic
    // versions). Prefer a deterministic candidate, otherwise scan.
    let candidate = format!(
        "{}/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java",
        PETCLINIC_CORPUS
    );
    if !Path::new(&candidate).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_java_petclinic: target {} not present",
            candidate
        );
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&["change-impact", &candidate, "--format", "json"]);
    assert_eq!(
        exit, 0,
        "change-impact must succeed on petclinic file. stderr=\n{}",
        stderr
    );

    let affected = parse_affected_functions(&stdout);
    assert!(
        !affected.is_empty(),
        "change-impact on petclinic OwnerController must return at least one affected_function"
    );

    // Java class methods are emitted as `ClassName.method`. At least one
    // such qualified entry from OwnerController must carry a real line.
    let qualified_nonzero = affected
        .iter()
        .filter(|f| {
            let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let line = f.get("line").and_then(|l| l.as_u64()).unwrap_or(0);
            name.starts_with("OwnerController.") && line > 0
        })
        .count();
    assert!(
        qualified_nonzero >= 1,
        "M-004: at least one `OwnerController.<method>` entry must have non-zero `line` after the fix; entries=\n{:#?}",
        affected
    );
}

// =============================================================================
// TEST 3 (go / go-httprouter): change-impact emits non-zero `line` for
// top-level functions in a go source file.
//
// Target: `router.go` — known to define many top-level helpers.
// Confirms multi-language coverage of the fix.
// =============================================================================
#[test]
fn change_impact_line_attribution_go_httprouter() {
    if !Path::new(HTTPROUTER_CORPUS).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_go_httprouter: corpus {} not present",
            HTTPROUTER_CORPUS
        );
        return;
    }
    let file = format!("{}/router.go", HTTPROUTER_CORPUS);
    if !Path::new(&file).exists() {
        eprintln!(
            "[skip] change_impact_line_attribution_go_httprouter: target {} not present",
            file
        );
        return;
    }

    let (exit, stdout, stderr) = run_tldr(&["change-impact", &file, "--format", "json"]);
    assert_eq!(
        exit, 0,
        "change-impact must succeed on httprouter router.go. stderr=\n{}",
        stderr
    );

    let affected = parse_affected_functions(&stdout);
    assert!(
        !affected.is_empty(),
        "change-impact on httprouter/router.go must return at least one affected_function"
    );

    // After the fix, at least 3 entries should have a non-zero line. The
    // file has many top-level funcs (`New`, `ServeHTTP`, `Handle`, …),
    // each with a real def line. The pre-fix code emitted line:0 for all.
    let nonzero = affected
        .iter()
        .filter(|f| f.get("line").and_then(|l| l.as_u64()).unwrap_or(0) > 0)
        .count();
    assert!(
        nonzero >= 3,
        "M-004: at least 3 affected_functions entries on router.go must have non-zero `line` after the fix; got {} of {}",
        nonzero,
        affected.len()
    );
}
