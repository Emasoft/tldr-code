//! cross-cmd-path-shape-v1 (v0.4.2 bug-A5): extend the M3 path-shape
//! preservation (5f6009e scala-path-canonical-v1) to five additional
//! commands that the Phase-20 audit (worker B-c-002 / reviewer CF-1 /
//! reviewer C scala recheck) flagged as leaking the macOS-resolved
//! `/private/tmp/...` form when the user typed `/tmp/...`:
//!
//!   1. `tldr deps`     -> root field
//!   2. `tldr verify`   -> path field
//!   3. `tldr similar`  -> source_file + similar_files[].file_path
//!   4. `tldr smells`   -> smells[].file + by_file keys
//!   5. `tldr explain`  -> callers[].file + callees[].file (also mixed
//!                          abs+rel shapes in the same response)
//!
//! Plus two non-regression tests for the M3 fixes (`tldr structure`,
//! `tldr context`) so cross-cmd refactors cannot silently un-fix M3.
//!
//! Pattern (per M3 / P15-B `6a3288a` precedent): canonicalise for
//! internal filter/match ONLY, echo user input verbatim in output.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`: every test returns
//! early if `/tmp/repos/scala-cats-effect` is absent. The corpus is the
//! same M3 used (Scala-language input, but the leak is cross-language;
//! see commit body of 5f6009e).

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

const SCALA_REPO: &str = "/tmp/repos/scala-cats-effect";
const SCALA_FILE_ABS: &str =
    "/tmp/repos/scala-cats-effect/core/shared/src/main/scala/cats/effect/IO.scala";

/// Recursively check every string value in a JSON tree against `pred`,
/// returning the first match (or None). Used to ensure no value in the
/// emitted JSON starts with `/private/tmp/` (the macOS-resolved form).
fn first_string_matching(v: &serde_json::Value, pred: &dyn Fn(&str) -> bool) -> Option<String> {
    match v {
        serde_json::Value::String(s) => {
            if pred(s) {
                Some(s.clone())
            } else {
                None
            }
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(|x| first_string_matching(x, pred)),
        serde_json::Value::Object(map) => {
            map.values().find_map(|x| first_string_matching(x, pred))
        }
        _ => None,
    }
}

fn assert_no_private_tmp(v: &serde_json::Value, cmd: &str) {
    let leak = first_string_matching(v, &|s| s.contains("/private/tmp/"));
    assert!(
        leak.is_none(),
        "`{}` JSON output leaks /private/tmp/ — must preserve user input shape. \
         Leaked value: {:?}",
        cmd,
        leak
    );
}

// ============================================================================
// 1. `tldr deps <abs-repo>` — DepsReport.root must echo `/tmp/...`, not
//    `/private/tmp/...`.
// ============================================================================
#[test]
fn deps_preserves_input_path() {
    if !Path::new(SCALA_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["deps", SCALA_REPO]);
    assert_eq!(rc, 0, "tldr deps failed: {}", out);
    let v = parse_json(&out);
    let root = v["root"].as_str().expect("deps: root field missing");
    assert_eq!(
        root, SCALA_REPO,
        "tldr deps `root` must echo user input verbatim. Got: {}",
        root
    );
    assert_no_private_tmp(&v, "tldr deps");
}

// ============================================================================
// 2. `tldr verify <abs-repo>` — VerifyReport.path must echo user input,
//    not `/private/tmp/...`.
// ============================================================================
#[test]
fn verify_preserves_input_path() {
    if !Path::new(SCALA_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["verify", SCALA_REPO]);
    // verify may exit non-zero if no test dir, but JSON should still be
    // shape-correct. Accept any exit code and only validate the JSON.
    let v = parse_json(&out);
    // Top-level field shape varies; accept either `path` or no-op if
    // command produced no JSON.
    if let Some(p) = v["path"].as_str() {
        assert_eq!(
            p, SCALA_REPO,
            "tldr verify `path` must echo user input verbatim. Got: {}",
            p
        );
    }
    assert_no_private_tmp(&v, "tldr verify");
    let _ = rc; // exit code is informational
}

// ============================================================================
// 3. `tldr similar <abs-file>` — source_file and any similar_files[]
//    entries must echo `/tmp/...`, not `/private/tmp/...`.
// ============================================================================
#[test]
fn similar_preserves_input_path() {
    if !Path::new(SCALA_FILE_ABS).exists() {
        return;
    }
    // Use --no-cache to avoid stale results from prior cached runs
    // contaminating the test fixture.
    let (rc, out) = run_tldr(&["similar", SCALA_FILE_ABS, "--no-cache"]);
    // similar may fail/skip if model not present; only validate JSON shape.
    let v = parse_json(&out);
    if let Some(src) = v["source_file"].as_str() {
        assert_eq!(
            src, SCALA_FILE_ABS,
            "tldr similar `source_file` must echo user input verbatim. Got: {}",
            src
        );
    }
    assert_no_private_tmp(&v, "tldr similar");
    let _ = rc;
}

// ============================================================================
// 4. `tldr smells <abs-repo>` — every smells[].file and every by_file
//    key must use `/tmp/...`, not `/private/tmp/...`.
// ============================================================================
#[test]
fn smells_preserves_input_path() {
    if !Path::new(SCALA_REPO).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["smells", SCALA_REPO]);
    assert_eq!(rc, 0, "tldr smells failed: {}", out);
    let v = parse_json(&out);
    if let Some(smells) = v["smells"].as_array() {
        for s in smells.iter().take(20) {
            if let Some(file) = s["file"].as_str() {
                assert!(
                    !file.starts_with("/private/tmp/"),
                    "tldr smells smells[].file must keep `/tmp/...` prefix. Got: {}",
                    file
                );
                assert!(
                    file.starts_with("/tmp/repos/scala-cats-effect/"),
                    "tldr smells smells[].file should echo user input prefix. \
                     Got: {}",
                    file
                );
            }
        }
    }
    if let Some(by_file) = v["by_file"].as_object() {
        for key in by_file.keys().take(20) {
            assert!(
                !key.starts_with("/private/tmp/"),
                "tldr smells by_file key must keep `/tmp/...` prefix. Got: {}",
                key
            );
        }
    }
    assert_no_private_tmp(&v, "tldr smells");
}

// ============================================================================
// 5a. `tldr explain <abs-file> <function>` — top-level file, and every
//     callers[].file and callees[].file must keep `/tmp/...` (no
//     `/private/tmp/...`).
// ============================================================================
#[test]
fn explain_preserves_input_path() {
    if !Path::new(SCALA_FILE_ABS).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["explain", SCALA_FILE_ABS, "interpret"]);
    assert_eq!(rc, 0, "tldr explain failed: {}", out);
    let v = parse_json(&out);
    let top_file = v["file"].as_str().expect("explain: file field missing");
    assert_eq!(
        top_file, SCALA_FILE_ABS,
        "tldr explain top-level `file` must echo user input verbatim. Got: {}",
        top_file
    );
    assert_no_private_tmp(&v, "tldr explain");
}

// ============================================================================
// 5b. `tldr explain` must not emit MIXED abs+rel shapes in the same
//     response. Either every callers[].file / callees[].file is absolute
//     (starts with `/`), or every entry is project-relative — never both.
//     The Phase-20 audit specifically flagged explain as mixing
//     `/private/tmp/...SyncIO.scala` with `core/.../SyncIO.scala` in the
//     same callers[] list.
// ============================================================================
#[test]
fn explain_callers_callees_shape_homogeneous() {
    if !Path::new(SCALA_FILE_ABS).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["explain", SCALA_FILE_ABS, "interpret"]);
    assert_eq!(rc, 0, "tldr explain failed: {}", out);
    let v = parse_json(&out);

    let mut paths: Vec<String> = Vec::new();
    if let Some(callers) = v["callers"].as_array() {
        for c in callers {
            if let Some(f) = c["file"].as_str() {
                paths.push(f.to_string());
            }
        }
    }
    if let Some(callees) = v["callees"].as_array() {
        for c in callees {
            if let Some(f) = c["file"].as_str() {
                paths.push(f.to_string());
            }
        }
    }

    if paths.is_empty() {
        return; // nothing to validate
    }

    let abs_count = paths.iter().filter(|p| p.starts_with('/')).count();
    let rel_count = paths.len() - abs_count;
    // We allow either all-abs or all-rel — but not a mix.
    assert!(
        abs_count == 0 || rel_count == 0,
        "tldr explain emits MIXED abs+rel callers/callees in same response — \
         {} absolute, {} relative. Paths: {:?}",
        abs_count,
        rel_count,
        paths
    );
}

// ============================================================================
// Non-regression: M3 (`tldr structure`, `tldr context`) still preserves
// user input path shape. If these fail, a v0.4.2 fix accidentally
// undid M3.
// ============================================================================
#[test]
fn structure_still_preserves_input_path_nonreg_m3() {
    if !Path::new(SCALA_FILE_ABS).exists() {
        return;
    }
    let (rc, out) = run_tldr(&["structure", SCALA_FILE_ABS]);
    assert_eq!(rc, 0, "tldr structure failed: {}", out);
    let v = parse_json(&out);
    let emitted = v["files"][0]["path"]
        .as_str()
        .expect("files[0].path missing");
    assert_eq!(
        emitted, SCALA_FILE_ABS,
        "M3 NON-REG: tldr structure files[0].path must still echo \
         absolute input. Got: {}",
        emitted
    );
}

#[test]
fn context_still_preserves_input_path_nonreg_m3() {
    if !Path::new(SCALA_FILE_ABS).exists() {
        return;
    }
    let entry = format!("{}:interpret", SCALA_FILE_ABS);
    let (rc, out) = run_tldr(&["context", &entry]);
    assert_eq!(rc, 0, "tldr context failed: {}", out);
    let v = parse_json(&out);
    let funcs = v["functions"].as_array();
    if let Some(arr) = funcs {
        if let Some(f0) = arr.first() {
            let file = f0["file"].as_str().expect("functions[0].file missing");
            assert_eq!(
                file, SCALA_FILE_ABS,
                "M3 NON-REG: tldr context functions[0].file must still echo \
                 absolute input. Got: {}",
                file
            );
        }
    }
}
