//! TRDD-BKALIK1B — `tldr todo --detail dead` and `tldr bugbot check` must
//! report unreadable source files in their own emitted report, not merely
//! print them to stderr.
//!
//! Dead-code analysis is whole-program: a function whose only caller lives
//! in a file the scan couldn't decode is reported dead (or a real caller
//! looks like a false "born dead") when it isn't. Before the fix,
//! `run_dead_analysis` (todo) and `compose_born_dead_scoped` (bugbot)
//! discarded the skip list (`eprintln!`/silent `if let Ok`) instead of
//! carrying it into their JSON output.
//!
//! Fixtures: `design/reproducers/TRDD-BKALIK1B/` — 3 readable Python files
//! (control.py, good.py, late_nul.py) and 5 files the scanner cannot decode
//! (bad.py, nobom.py, u16be.py, u32be.py, u32le.py).
//!
//! The assertion is on the WARNING TEXT naming each skipped file, never on
//! mere absence from the results — absence is exactly what the bug produced
//! too (a `files_skipped`/`warnings` reader must not accept "I don't see it"
//! as proof).

use std::path::Path;
use std::process::Command;

use serde_json::Value;

const FIXTURE: &str = "../../design/reproducers/TRDD-BKALIK1B";
const UNREADABLE: &[&str] = &["bad.py", "nobom.py", "u16be.py", "u32be.py", "u32le.py"];
const READABLE: &[&str] = &["control.py", "good.py", "late_nul.py"];

fn tldr_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tldr"))
}

// ---------------------------------------------------------------------------
// `tldr todo --detail dead`
// ---------------------------------------------------------------------------

#[test]
fn todo_dead_detail_reports_every_unreadable_file_by_name_in_warnings() {
    let output = tldr_bin()
        .args([
            "todo", FIXTURE, "--detail", "dead", "-f", "json", "-l", "python",
        ])
        .output()
        .expect("tldr todo failed to run");

    assert!(
        output.status.success(),
        "todo should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value =
        serde_json::from_slice(&output.stdout).expect("todo stdout should be valid JSON");
    let dead = &json["sub_results"]["dead_code"];
    assert!(
        !dead.is_null(),
        "expected sub_results.dead to be populated by --detail dead, got: {json}"
    );

    // Control: the scan must have actually happened. `functions_analyzed`
    // (via the report's `functions_analyzed` wire key, see
    // tldr-core/src/types.rs:2521) comes from the 3 READABLE fixture files
    // (control.py alone defines gamma/delta). A run that found nothing
    // would also show `files_skipped: 0`, so this is checked BEFORE the
    // skip assertions rather than instead of them.
    let functions_analyzed = dead["functions_analyzed"]
        .as_u64()
        .expect("functions_analyzed field present");
    assert!(
        functions_analyzed > 0,
        "control failed: expected >0 functions analyzed from the readable fixtures, got: {dead}"
    );

    // Assert the ONE real wire field name, not a hedge between two spellings
    // — a hedge cannot fail on a rename.
    assert_eq!(
        dead["files_skipped"].as_u64(),
        Some(UNREADABLE.len() as u64),
        "report: {dead}"
    );

    let warnings = dead["warnings"]
        .as_array()
        .expect("warnings array present")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    for name in UNREADABLE {
        assert!(
            warnings.iter().any(|w| w.contains(name)),
            "expected a warning naming {name}, got: {warnings:?}"
        );
    }
    for name in READABLE {
        assert!(
            !warnings.iter().any(|w| w.contains(name)),
            "readable file {name} must not appear in warnings, got: {warnings:?}"
        );
    }
}

/// The DEFAULT invocation — no `--detail` — still names every unreadable file.
///
/// This is a separate test because the report fields cannot carry it: the
/// `DeadCodeReport` reaches the output only via `sub_results.insert(..)`, which
/// is gated on `--detail <analysis>`. A plain `tldr todo` never takes that
/// branch, so stderr is the ONLY channel on the path most users run, and a fix
/// that wires up the report while dropping the stderr line is a regression the
/// `--detail` test above passes straight through.
#[test]
fn todo_without_detail_still_names_every_unreadable_file_on_stderr() {
    let output = tldr_bin()
        .args(["todo", FIXTURE, "-l", "python"])
        .output()
        .expect("tldr todo failed to run");

    assert!(
        output.status.success(),
        "todo should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Negative control FIRST: a readable file must never be announced as
    // skipped. Checked before the skip assertions so that a build which warns
    // about everything cannot pass by satisfying them.
    for name in READABLE {
        assert!(
            !stderr.contains(name),
            "readable file {name} must not be announced as skipped, stderr: {stderr}"
        );
    }

    // Bind to the ANNOUNCEMENT, not merely the filename, and require both on the
    // SAME line. Plain `tldr todo` runs every sub-analysis, and another one
    // already emits `Warning: skipping <path> due to parse error` for these same
    // fixtures. A bare `stderr.contains(name)` is therefore satisfied with the
    // `eprintln!` in run_dead_analysis deleted -- measured, not supposed -- so it
    // would be a test that cannot fail. `Warning: Skipped` (capital S, from
    // `skipped_file_warning`) is what only the dead-analysis announcement emits.
    for name in UNREADABLE {
        assert!(
            stderr
                .lines()
                .any(|l| l.contains("Warning: Skipped") && l.contains(name)),
            "default `tldr todo` must announce skipped file {name}, stderr: {stderr}"
        );
    }

    // Deliberately NO exact-count assertion pinning the number of
    // `Warning: Skipped` lines to UNREADABLE.len(). It would add exactly one
    // case the loop above misses -- the rival `Warning: skipping` from the
    // complexity analysis someday being reworded to collide with this shape --
    // and that is speculative. The loop is the guard that earns its place: it is
    // red-proofed by measurement (delete the `eprintln!` in run_dead_analysis
    // and this test exits 101).
    //
    // Do NOT justify the absence by `skipped_file_warning`'s "every command MUST
    // adopt it" doc comment (tldr-core/src/fs/mod.rs:140). That mandates the
    // report's `warnings` FIELD, not a stderr line -- bugbot adopted the helper
    // and emits a finding with no stderr output at all -- so adoption alone
    // would not move this count.
}

// ---------------------------------------------------------------------------
// `tldr bugbot check` — born-dead scoped scan
// ---------------------------------------------------------------------------

fn create_test_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();

    Command::new("git")
        .args(["init"])
        .current_dir(&path)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(&path)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&path)
        .output()
        .unwrap();

    std::fs::write(
        path.join("lib.rs"),
        "fn main() {\n    helper();\n}\n\nfn helper() -> i32 {\n    42\n}\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(&path)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&path)
        .output()
        .unwrap();

    (dir, path)
}

#[test]
fn bugbot_check_reports_a_scoped_unreadable_file_as_a_skipped_file_finding() {
    let (_dir, path) = create_test_repo();

    // Uncommitted change: insert a genuinely unused function (this is the
    // control -- it proves the scan really ran and produced a real finding,
    // not just an empty report with `files_skipped: 0`).
    std::fs::write(
        path.join("lib.rs"),
        "fn main() {\n    helper();\n}\n\nfn helper() -> i32 {\n    42\n}\n\nfn unused_func() -> bool {\n    true\n}\n",
    )
    .unwrap();

    // Uncommitted, untracked file the scan cannot decode (raw UTF-16BE
    // bytes, same fixture bytes proven to fail decoding elsewhere in this
    // repo). It is a "changed file" per `git ls-files --others`, so
    // `compose_born_dead_scoped`'s tier-1 scan hits it and must record the
    // skip instead of silently swallowing the `parse_file` error.
    let unreadable_bytes = std::fs::read(
        Path::new(FIXTURE).join("u16be.py"),
    )
    .expect("read u16be.py fixture bytes");
    std::fs::write(path.join("weird.rs"), &unreadable_bytes).unwrap();

    let output = tldr_bin()
        .args(["--lang", "rust", "--format", "json", "bugbot", "check"])
        .arg(&path)
        .args(["--no-fail", "--no-tools"])
        .output()
        .expect("bugbot check failed to run");

    assert!(
        output.status.success(),
        "bugbot check --no-fail should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value =
        serde_json::from_slice(&output.stdout).expect("bugbot check stdout should be valid JSON");
    let findings = json["findings"].as_array().expect("findings should be array");

    // Control: the born-dead scan actually ran and found the real dead
    // function. Checked BEFORE the skip assertion below -- a pipeline that
    // silently analyzed nothing would also report 0 skipped files.
    let born_dead: Vec<&Value> = findings
        .iter()
        .filter(|f| f["finding_type"] == "born-dead")
        .collect();
    assert!(
        !born_dead.is_empty(),
        "control failed: expected a born-dead finding for 'unused_func', got: {}",
        serde_json::to_string_pretty(&json).unwrap()
    );
    assert!(
        born_dead[0]["function"]
            .as_str()
            .unwrap_or("")
            .contains("unused_func"),
        "born-dead finding should reference 'unused_func', got: {}",
        born_dead[0]["function"]
    );

    // The actual assertion: the unreadable file is named in a
    // machine-readable finding, not just on stderr.
    let skip_findings: Vec<&Value> = findings
        .iter()
        .filter(|f| f["finding_type"] == "skipped-file")
        .collect();
    assert!(
        !skip_findings.is_empty(),
        "expected a 'skipped-file' finding for weird.rs, got: {}",
        serde_json::to_string_pretty(&json).unwrap()
    );
    assert!(
        skip_findings
            .iter()
            .any(|f| f["message"].as_str().unwrap_or("").contains("weird.rs")),
        "expected a skipped-file finding naming weird.rs, got: {skip_findings:?}"
    );
    assert_eq!(
        skip_findings[0]["severity"], "low",
        "skipped-file finding should be low severity, got: {skip_findings:?}"
    );
}
