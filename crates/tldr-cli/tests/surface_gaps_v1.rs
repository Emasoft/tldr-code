//! surface-gaps-v1 — regression tests for 2 bugs covering the
//! "advertised but missing/wrong feature" surface (M5):
//!
//! - BUG-6:  `tldr impact` exported-but-no-callers note string referenced
//!   a non-existent `--workspace-root` flag. Fix: rewrite the note to
//!   describe the actual analyzed root and the canonical monorepo
//!   workflow ("run from the directory that contains all callers")
//!   without dangling a phantom flag.
//! - BUG-19: `tldr calls`, `tldr inheritance`, `tldr impact`, and
//!   `tldr hubs` all rejected `--format dot` even though call graphs
//!   and class hierarchies are the canonical Graphviz use cases. Fix:
//!   extend the format gate's `DOT_SUPPORTED` list to include these
//!   commands and wire each command's `is_dot()` arm to a real DOT
//!   emitter (`format_calls_dot`, `format_impact_dot`, `format_hubs_dot`,
//!   and the pre-existing `tldr_core::inheritance::format_dot`).

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use assert_cmd::Command;
use std::path::PathBuf;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Resolve the flask corpus. The corpus was renamed to `python-flask`
/// (the legacy `flask` path is honored as a fallback). Returns `None` when
/// the corpus is not present OR is an empty skeleton (git clone with no
/// working tree), so callers can skip cleanly rather than hard-fail.
fn flask_repo() -> Option<PathBuf> {
    for cand in ["/tmp/repos/python-flask", "/tmp/repos/flask"] {
        let p = PathBuf::from(cand);
        if corpus_ready(&p) {
            return Some(p);
        }
    }
    eprintln!("[skip] flask corpus not present under /tmp/repos/python-flask or /tmp/repos/flask");
    None
}

fn run_stdout(args: &[&str]) -> String {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

// =============================================================================
// BUG-6: impact note must not reference a phantom --workspace-root flag
// =============================================================================

#[test]
fn impact_note_no_phantom_workspace_root_flag() {
    // Sweep multiple flask functions to maximize the chance of hitting the
    // exported branch (the one that previously emitted the dangling
    // `--workspace-root` reference).
    let Some(path) = flask_repo() else { return; };
    let path_str = path.to_str().unwrap();
    let candidates = [
        "url_for",
        "send_file",
        "_make_timedelta",
        "wsgi_app",
        "dispatch_request",
        "preprocess_request",
        "finalize_request",
        "full_dispatch_request",
        "handle_user_exception",
        "handle_exception",
        "jsonify",
        "cli_main",
    ];
    for fn_name in &candidates {
        let stdout = run_stdout(&["impact", fn_name, path_str]);
        // We don't care if jq parses — we care about the literal flag.
        assert!(
            !stdout.to_lowercase().contains("--workspace-root"),
            "BUG-6 regression: `tldr impact {fn_name}` JSON contains a phantom \
             `--workspace-root` flag reference; the flag does not exist on the \
             impact command. Output was:\n{stdout}"
        );
        assert!(
            !stdout.to_lowercase().contains("workspace-root"),
            "BUG-6 regression: `tldr impact {fn_name}` JSON contains a \
             `workspace-root` substring; remove the dangling reference. \
             Output was:\n{stdout}"
        );
    }
}

// =============================================================================
// BUG-19: --format dot must be supported by call-graph commands
// =============================================================================

fn assert_valid_dot(label: &str, dot: &str) {
    let trimmed = dot.trim_start();
    assert!(
        trimmed.starts_with("digraph"),
        "{label}: expected DOT to start with `digraph`, got:\n{dot}"
    );
    assert!(
        trimmed.contains('{') && trimmed.contains('}'),
        "{label}: DOT body must be braced. Got:\n{dot}"
    );
}

#[test]
fn calls_dot_output_valid() {
    let Some(path) = flask_repo() else { return; };
    let dot = run_stdout(&["calls", path.to_str().unwrap(), "--format", "dot"]);
    assert_valid_dot("calls", &dot);
    let edge_count = dot.matches("->").count();
    assert!(
        edge_count >= 1,
        "BUG-19 regression: `tldr calls --format dot` emitted no edges (got {edge_count}). \
         Expected the call graph for flask to produce many edges. Output was:\n{dot}"
    );
}

#[test]
fn inheritance_dot_output_valid() {
    let Some(path) = flask_repo() else { return; };
    let dot = run_stdout(&["inheritance", path.to_str().unwrap(), "--format", "dot"]);
    assert_valid_dot("inheritance", &dot);
    let edge_count = dot.matches("->").count();
    assert!(
        edge_count >= 1,
        "BUG-19 regression: `tldr inheritance --format dot` emitted no edges (got {edge_count}). \
         Expected flask's class hierarchy to produce at least a few inheritance edges. \
         Output was:\n{dot}"
    );
}

#[test]
fn hubs_dot_output_valid() {
    let Some(path) = flask_repo() else { return; };
    let dot = run_stdout(&["hubs", path.to_str().unwrap(), "--format", "dot"]);
    assert_valid_dot("hubs", &dot);
    // hubs DOT is intentionally node-centric (the report does not carry the
    // surrounding call edges); we only require valid `digraph` framing and
    // at least one node line. Edges, when present, are synthetic invisible
    // chains for layout — but we don't require them.
    assert!(
        dot.contains("[label="),
        "BUG-19 regression: `tldr hubs --format dot` emitted no labeled nodes. \
         Output was:\n{dot}"
    );
}

#[test]
fn impact_dot_output_valid() {
    // Use a function with known callers in flask so the impact graph is
    // non-empty.
    let Some(path) = flask_repo() else { return; };
    let dot = run_stdout(&[
        "impact",
        "url_for",
        path.to_str().unwrap(),
        "--format",
        "dot",
    ]);
    assert_valid_dot("impact", &dot);
    // We don't strictly require >=1 edge here because the chosen function
    // may be an entry point with no callers in some flask versions. But the
    // command MUST NOT error out.
    let edge_count = dot.matches("->").count();
    assert!(
        edge_count >= 1 || dot.lines().count() >= 5,
        "BUG-19 regression: `tldr impact url_for --format dot` produced \
         neither edges nor a non-trivial header. Output was:\n{dot}"
    );
}

// =============================================================================
// BUG-19: format gate must NOT reject dot for these commands
// =============================================================================

#[test]
fn dot_format_no_longer_rejected_for_callgraph_commands() {
    // The pre-fix error message contained the literal substring
    // "DOT is only emitted by: clones, deps." — verify that every
    // call-graph / hierarchy command no longer surfaces this error.
    let Some(path) = flask_repo() else { return; };
    let path_str = path.to_str().unwrap();
    let cmds: &[&[&str]] = &[
        &["calls", path_str, "--format", "dot"],
        &["inheritance", path_str, "--format", "dot"],
        &["hubs", path_str, "--format", "dot"],
        &["impact", "url_for", path_str, "--format", "dot"],
    ];
    for cmd in cmds {
        let output = tldr_cmd().args(*cmd).output().expect("run tldr");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("DOT is only emitted by: clones, deps"),
            "BUG-19 regression: `tldr {}` still rejects --format dot with the \
             legacy DOT_SUPPORTED gate. Stderr was:\n{stderr}",
            cmd.join(" ")
        );
        assert!(
            !stderr.contains("not supported by"),
            "BUG-19 regression: `tldr {}` rejects --format dot. Stderr was:\n{stderr}",
            cmd.join(" ")
        );
        assert!(
            output.status.success(),
            "BUG-19 regression: `tldr {}` exited with non-zero status. Stderr:\n{stderr}",
            cmd.join(" ")
        );
    }
}
