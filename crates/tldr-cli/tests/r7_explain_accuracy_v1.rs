//! r7_explain_accuracy_v1 (v0.5.0 CLOSEOUT, R7 cluster #8 "explain")
//!
//! Four explain-OWN accuracy defects reproduced live against the release
//! binary on the `/tmp/tldr_corpora_b` corpus and fixed at the root cause
//! in `crates/tldr-cli/src/commands/remaining/explain.rs`:
//!
//!  * R1 PATH RE-ROOTING (relative input): callees[]/callees[].file that
//!    are project-relative get the ANALYZED FILE'S OWN DIRECTORY prepended,
//!    yielding non-existent doubled paths (e.g.
//!    `src/main/java/.../owner/` + `src/main/java/.../model/Person.java`).
//!    Root: `user_project_root_from_input` failed to find the project root
//!    for a RELATIVE input path (its non-canonicalised marker walk-up
//!    bottoms out at "" and never checks CWD/`.`), so it returned the
//!    file's immediate parent as the "root", which branch-3 of
//!    `restore_explain_path_shape` then joined onto already-repo-relative
//!    callee paths.
//!
//!  * R2 `<external>` SENTINEL TREATED AS A PATH: external/stdlib callees
//!    (correctly named `<external>`) got the project root joined onto them
//!    -> `src/main/java/.../owner/<external>`. `<external>` is a relative
//!    path so branch-3 rewrote it.
//!
//!  * R3 RUBY PARAMS DROPPED: `signature.params` omitted optional
//!    (`block = nil`), splat (`*values`), keyword/double-splat params.
//!    Root: explain ran its OWN python-shaped `extract_params` (which only
//!    matches python node-kinds) for Ruby because Ruby exposes a
//!    `parameters` field; the canonical `extract_function_params` fallback
//!    was gated behind `params.is_empty()` and never fired.
//!
//!  * R4 ELIXIR CALLEE POLLUTION: callees[] listed `def` (keyword), the
//!    function's OWN name (from its `def NAME(args)` head), `case`, `if`,
//!    `with` (control-flow keywords that tree-sitter-elixir spells as
//!    `call` nodes). Root: `find_callees_recursive` had no Elixir
//!    keyword/self filter (contrast the C/C++ `is_cpp_non_callee` guard).
//!
//! Real-repo gated: each test returns early when its corpus file is
//! absent. These drive the PRODUCTION binary and FAIL if the fix is
//! reverted.

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

/// Run `tldr` with the given args, from working directory `cwd`.
fn run_tldr_in(cwd: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
        .env("TLDR_NO_DAEMON", "1")
        .current_dir(cwd)
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

fn callee_names(v: &serde_json::Value) -> Vec<String> {
    v["callees"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c["name"].as_str().map(|s| s.to_string()))
        .collect()
}

fn callee_files(v: &serde_json::Value) -> Vec<String> {
    v["callees"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c["file"].as_str().map(|s| s.to_string()))
        .collect()
}

fn param_names(v: &serde_json::Value) -> Vec<String> {
    v["signature"]["params"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            p["name"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| p.as_str().map(|s| s.to_string()))
        })
        .filter(|s| !s.is_empty())
        .collect()
}

const JAVA_REPO: &str = "/tmp/tldr_corpora_b/java-petclinic";
const JAVA_REL_FILE: &str =
    "src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";

const ELIXIR_PHX_REPO: &str = "/tmp/tldr_corpora_b/elixir-phoenix";
const ELIXIR_PLUG_REPO: &str = "/tmp/tldr_corpora_b/elixir-plug";

const RUBY_REPO: &str = "/tmp/tldr_corpora_b/ruby-sinatra";
const RUBY_FILE: &str = "lib/sinatra/base.rb";

const PY_REPO: &str = "/tmp/tldr_corpora_b/python-requests";
const PY_FILE: &str = "src/requests/auth.py";

// ============================================================================
// R1 — relative input must NOT double the path. Every project-relative
// callee file must resolve to a file that actually exists on disk; in
// particular no path may contain the analyzed file's own parent directory
// prepended to a repo-relative callee path.
// ============================================================================
#[test]
fn r1_java_relative_input_does_not_double_callee_paths() {
    if !Path::new(JAVA_REPO).join(JAVA_REL_FILE).exists() {
        eprintln!("[skip] r1: {} absent", JAVA_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(JAVA_REPO, &["explain", JAVA_REL_FILE, "processFindForm"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);

    let files = callee_files(&v);
    assert!(!files.is_empty(), "expected some callees for processFindForm");

    // The doubling signature: `.../owner/` (the file's dir) prepended to
    // another `src/main/java/...` segment. No real path contains
    // `src/main/...` twice.
    for f in &files {
        let occurrences = f.matches("src/main/java").count();
        assert!(
            occurrences <= 1,
            "R1: callee file path is DOUBLED (file's own dir prepended to a \
             repo-relative path): {:?}",
            f
        );
    }

    // Every in-project callee path (i.e. not the `<external>` sentinel and
    // not abs outside the repo) must point at a file that EXISTS.
    for f in &files {
        if f.contains("<external>") {
            continue;
        }
        let abs = if Path::new(f).is_absolute() {
            std::path::PathBuf::from(f)
        } else {
            Path::new(JAVA_REPO).join(f)
        };
        assert!(
            abs.exists(),
            "R1: in-project callee path does not exist on disk: {:?} (resolved {:?})",
            f,
            abs
        );
    }
}

// ============================================================================
// R2 — the `<external>` sentinel must be emitted verbatim, never joined
// with the project root.
// ============================================================================
#[test]
fn r2_external_sentinel_is_not_path_joined() {
    if !Path::new(JAVA_REPO).join(JAVA_REL_FILE).exists() {
        eprintln!("[skip] r2: {} absent", JAVA_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(JAVA_REPO, &["explain", JAVA_REL_FILE, "processFindForm"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);

    let files = callee_files(&v);
    // processFindForm calls stdlib/JDK methods (isEmpty, rejectValue, ...)
    // which the per-file walker tags `<external>`.
    let has_external = files.iter().any(|f| f.contains("<external>"));
    assert!(
        has_external,
        "expected at least one <external> callee for processFindForm; got {:?}",
        files
    );

    for f in &files {
        if f.contains("<external>") {
            assert_eq!(
                f, "<external>",
                "R2: <external> sentinel must be emitted verbatim, not joined \
                 with a path; got {:?}",
                f
            );
        }
    }
}

// ============================================================================
// R3 — Ruby optional/splat/keyword params must round-trip through
// explain.signature.params (matching `extract`).
//   process_route(pattern, conditions, block = nil, values = [])
// ============================================================================
#[test]
fn r3_ruby_optional_params_are_not_dropped() {
    if !Path::new(RUBY_REPO).join(RUBY_FILE).exists() {
        eprintln!("[skip] r3: {} absent", RUBY_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(RUBY_REPO, &["explain", RUBY_FILE, "process_route"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);
    let names = param_names(&v);
    for expected in &["pattern", "conditions", "block", "values"] {
        assert!(
            names.iter().any(|n| n == expected),
            "R3: ruby process_route must include optional param `{}`; got {:?}",
            expected,
            names
        );
    }
}

// ============================================================================
// R4 — Elixir control-flow keywords (def/if/case/with/...) and the
// function's own def-head name must NOT appear as callees.
//   allow_jsonp's real callees: validate_jsonp_callback!, register_before_send,
//   json_response?, put_resp_header, resp, jsonp_body.
// ============================================================================
#[test]
fn r4_elixir_callees_exclude_keywords_and_self() {
    let ctrl = "lib/phoenix/controller.ex";
    if !Path::new(ELIXIR_PHX_REPO).join(ctrl).exists() {
        eprintln!("[skip] r4: {} absent", ELIXIR_PHX_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(ELIXIR_PHX_REPO, &["explain", ctrl, "allow_jsonp"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);
    let names = callee_names(&v);

    // No control-flow / definition keyword may be a callee.
    for kw in &[
        "def", "defp", "defmacro", "defmodule", "if", "unless", "case", "cond", "with", "for",
        "receive", "try", "quote", "fn",
    ] {
        assert!(
            !names.iter().any(|n| n == kw),
            "R4: elixir keyword `{}` must not be a callee; got {:?}",
            kw,
            names
        );
    }
    // The function's own name (def head) must not be a callee.
    assert!(
        !names.iter().any(|n| n == "allow_jsonp"),
        "R4: function's own def-head name `allow_jsonp` must not be a callee; got {:?}",
        names
    );
    // The real calls must still be present (no over-suppression).
    for real in &["validate_jsonp_callback!", "put_resp_header"] {
        assert!(
            names.iter().any(|n| n == real),
            "R4: real callee `{}` was dropped; got {:?}",
            real,
            names
        );
    }
}

#[test]
fn r4_elixir_basic_auth_callees_exclude_keywords_and_self() {
    let f = "lib/plug/basic_auth.ex";
    if !Path::new(ELIXIR_PLUG_REPO).join(f).exists() {
        eprintln!("[skip] r4 basic_auth: {} absent", ELIXIR_PLUG_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(ELIXIR_PLUG_REPO, &["explain", f, "basic_auth"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);
    let names = callee_names(&v);
    for kw in &["def", "defp", "case", "if", "with", "cond"] {
        assert!(
            !names.iter().any(|n| n == kw),
            "R4: elixir keyword `{}` must not be a callee; got {:?}",
            kw,
            names
        );
    }
    assert!(
        !names.iter().any(|n| n == "basic_auth"),
        "R4: own def-head name `basic_auth` must not be a callee; got {:?}",
        names
    );
}

// ============================================================================
// R3 NON-REGRESSION — Python keeps its rich {name, type} param entries.
// ============================================================================
#[test]
fn r3_python_keeps_rich_typed_params_nonreg() {
    if !Path::new(PY_REPO).join(PY_FILE).exists() {
        eprintln!("[skip] r3 python nonreg: {} absent", PY_REPO);
        return;
    }
    let (rc, out) = run_tldr_in(PY_REPO, &["explain", PY_FILE, "_basic_auth_str"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);
    let params = v["signature"]["params"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let names = param_names(&v);
    for expected in &["username", "password"] {
        assert!(
            names.iter().any(|n| n == expected),
            "python _basic_auth_str must include `{}`; got {:?}",
            expected,
            names
        );
    }
    // Non-regression: python's rich walker must still emit `type` fields.
    let any_typed = params.iter().any(|p| p["type"].is_string());
    assert!(
        any_typed,
        "R3 NON-REG: python signature.params must keep type annotations; got {:?}",
        params
    );
}

// ============================================================================
// R1/R2 ABSOLUTE-input non-regression — absolute input already resolved
// correctly; the fix must keep callers/callees homogeneous and leak-free.
// ============================================================================
#[test]
fn r1_absolute_input_paths_stay_homogeneous_nonreg() {
    let abs = format!("{}/{}", JAVA_REPO, JAVA_REL_FILE);
    if !Path::new(&abs).exists() {
        eprintln!("[skip] r1 abs nonreg: {} absent", abs);
        return;
    }
    let (rc, out) = run_tldr_in(JAVA_REPO, &["explain", &abs, "processFindForm"]);
    assert_eq!(rc, 0, "explain failed: {}", out);
    let v = parse_json(&out);

    // Top-level file echoes absolute input.
    assert_eq!(
        v["file"].as_str().unwrap_or_default(),
        abs,
        "top-level file must echo absolute input"
    );

    let mut paths = callee_files(&v);
    if let Some(callers) = v["callers"].as_array() {
        for c in callers {
            if let Some(f) = c["file"].as_str() {
                paths.push(f.to_string());
            }
        }
    }
    // Drop the <external> sentinel from the homogeneity check.
    let real: Vec<&String> = paths.iter().filter(|p| !p.contains("<external>")).collect();
    if real.is_empty() {
        return;
    }
    let abs_count = real.iter().filter(|p| p.starts_with('/')).count();
    let rel_count = real.len() - abs_count;
    assert!(
        abs_count == 0 || rel_count == 0,
        "R1 abs nonreg: MIXED abs+rel callers/callees ({} abs, {} rel): {:?}",
        abs_count,
        rel_count,
        real
    );
    // No double-rooting and no /private/tmp leak with absolute input either.
    for f in &real {
        assert!(
            f.matches("src/main/java").count() <= 1,
            "R1 abs nonreg: doubled path {:?}",
            f
        );
        assert!(
            !f.contains("/private/tmp/"),
            "R1 abs nonreg: /private/tmp leak {:?}",
            f
        );
    }
}
