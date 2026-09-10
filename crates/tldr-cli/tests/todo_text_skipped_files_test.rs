//! TRDD-OGK2ROKJ — `tldr todo` in TEXT mode must name (or count) skipped
//! files in its stdout report, matching the `dead`/`calls` precedent
//! (`dead.rs:566-575`, `calls.rs:352-359`), instead of only announcing them
//! on stderr (`todo.rs:475`).
//!
//! Fixtures: `design/reproducers/TRDD-BKALIK1B/` — same fixture the sibling
//! JSON-mode regression test (`skipped_files_todo_bugbot_test.rs`) already
//! uses: 3 readable Python files and 5 files the scanner cannot decode.
//!
//! Assertions bind to STDOUT only (`Command::output()` captures stdout and
//! stderr on separate streams; nothing here merges them). `todo.rs:475`
//! already writes the file names to stderr — a harness that accidentally
//! read stderr, or merged the two streams, would pass on the unfixed binary.

use std::process::Command;

const FIXTURE: &str = "../../design/reproducers/TRDD-BKALIK1B";
const UNREADABLE: &[&str] = &["bad.py", "nobom.py", "u16be.py", "u32be.py", "u32le.py"];
const READABLE: &[&str] = &["control.py", "good.py", "late_nul.py"];

fn tldr_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tldr"))
}

#[test]
fn todo_text_mode_names_every_skipped_file_in_stdout_report() {
    // `-f text` explicit: `tldr todo`'s default format is JSON (confirmed by
    // running the bare command), so an unqualified invocation here would
    // test the wrong code path and pass on the unfixed formatter.
    let output = tldr_bin()
        .args(["todo", FIXTURE, "-l", "python", "-f", "text"])
        .output()
        .expect("tldr todo failed to run");

    assert!(
        output.status.success(),
        "todo should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Count line, same shape as the `dead`/`calls` precedent.
    assert!(
        stdout.contains(&format!("Files skipped: {}", UNREADABLE.len())),
        "expected stdout to report the skipped-file count, stdout: {stdout}"
    );

    for name in UNREADABLE {
        assert!(
            stdout.lines().any(|l| l.trim_start().starts_with("Skipped") && l.contains(name)),
            "expected stdout report to name skipped file {name}, stdout: {stdout}"
        );
    }

    // Negative control: a readable file must never appear on a `Skipped ...`
    // line. It may legitimately appear elsewhere (e.g. a `Location:` line
    // for one of its own functions), so the check is scoped to skip lines,
    // not to stdout as a whole.
    for name in READABLE {
        assert!(
            !stdout
                .lines()
                .any(|l| l.trim_start().starts_with("Skipped") && l.contains(name)),
            "readable file {name} must not appear on a skipped-file line, stdout: {stdout}"
        );
    }
}

/// Clean-run control: a directory with no unreadable file must NOT print a
/// skipped-file line. Without this, an assertion that always prints the
/// line would still pass the positive test above.
#[test]
fn todo_text_mode_omits_skipped_line_when_nothing_was_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("clean.py"), "def foo():\n    return 1\n")
        .expect("write clean fixture");

    let output = tldr_bin()
        .args(["todo", dir.path().to_str().unwrap(), "-l", "python", "-f", "text"])
        .output()
        .expect("tldr todo failed to run");

    assert!(
        output.status.success(),
        "todo should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Files skipped"),
        "clean run must not report a skipped-file line, stdout: {stdout}"
    );
}
