//! logs-command-v1 — integration tests for `tldr logs`.
//!
//! `tldr logs <file> [--from TS] [--to TS] [--level LEVEL] [--grep PAT]`
//! streams the file through the native log-entry scanner (`ast::logs`) and
//! emits the entries that pass every active filter. These tests pin:
//!
//! 1. total/matched counts for a level-only filter (with the `warning` →
//!    `warn` alias normalization),
//! 2. an inclusive `--from`/`--to` window over ISO timestamps (entries with
//!    a *comparable* timestamp outside the window are excluded silently;
//!    entries with a missing or year-less syslog timestamp are excluded AND
//!    counted in `unfilterable`),
//! 3. `--grep` as a case-sensitive substring over the entry's raw text —
//!    INCLUDING its continuation lines (a stack frame matches its entry),
//! 4. combined filters and the filter ORDER (level/grep run before the
//!    interval check, so an entry the level filter rejects never counts as
//!    unfilterable),
//! 5. the JSON document shape (`logs-command-v1` schema),
//! 6. text mode: matched entries printed as raw source lines with a `--`
//!    separator between entries,
//! 7. exit codes: a nonexistent file (or a directory) is an error.
//!
//! The binary is invoked via `assert_cmd::cargo::cargo_bin!("tldr")`,
//! mirroring body_command_test.rs.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// The shared fixture: ~20 lines mixing ISO/RFC3339, space-separated
/// datetime, epoch, syslog and bracketed-level shapes, every level family,
/// one stack-trace continuation block (lines 6-7), and one garbage line
/// (line 3, which — having no entry marker — attaches to the DEBUG entry on
/// line 2 as a continuation).
///
/// Parsed entry map (the test expectations below are derived from this):
///
/// | entry | lines | level  | timestamp                 |
/// |-------|-------|--------|---------------------------|
/// | E1    | 1     | info   | 2026-09-14T08:00:00Z      |
/// | E2    | 2-3   | debug  | 2026-09-14T08:00:05Z      |
/// | E3    | 4     | info   | 2026-09-14T08:01:00Z      |
/// | E4    | 5-7   | error  | 2026-09-14T08:01:02Z      |
/// | E5    | 8     | warn   | 2026-09-14T08:01:03Z      |
/// | E6    | 9     | (none) | 1726298460 (2024 epoch)   |
/// | E7    | 10    | info   | 2026-09-14T09:30:00Z      |
/// | E8    | 11    | (none) | Sep 14 09:31:00 (no year) |
/// | E9    | 12    | (none) | Sep 14 09:31:05 (no year) |
/// | E10   | 13    | error  | 2026-09-14T09:31:10Z      |
/// | E11   | 14    | info   | 2026-09-14T09:31:11Z      |
/// | E12   | 15    | debug  | (none — `[debug]`)        |
/// | E13   | 16    | error  | (none — `FATAL:`)         |
/// | E14   | 17    | info   | 2026-09-14T10:00:00Z      |
const FIXTURE: &str = "\
2026-09-14T08:00:00Z INFO service starting
2026-09-14T08:00:05Z DEBUG config loaded
garbage startup banner, no timestamp
2026-09-14T08:01:00Z INFO request received
2026-09-14T08:01:02Z ERROR query failed
Traceback (most recent call last):
  File \"db.py\", line 42, in query
2026-09-14T08:01:03Z WARN retry scheduled
1726298460 epoch entry line
2026-09-14T09:30:00Z INFO recovered
Sep 14 09:31:00 host sshd[4242]: Accepted key
Sep 14 09:31:05 host sshd[4243]: Failed password
2026-09-14T09:31:10Z ERROR disk full
2026-09-14T09:31:11Z INFO cleanup started
[debug] entering maintenance loop
FATAL: out of memory
2026-09-14T10:00:00Z INFO shutdown complete
";

fn write_fixture(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("server.log");
    fs::write(&path, FIXTURE).expect("write server.log fixture");
    path
}

/// Run `tldr logs` with `--format json` and return the parsed document.
fn logs_json(file: &PathBuf, extra_args: &[&str]) -> Value {
    let output = tldr_cmd()
        .args([
            "logs",
            file.to_str().expect("utf-8 path"),
            "--format",
            "json",
        ])
        .args(extra_args)
        .output()
        .expect("run tldr logs");
    assert!(
        output.status.success(),
        "tldr logs {:?} failed: stderr = {}",
        extra_args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse logs JSON from stdout")
}

/// (1) Level-only filter: exact normalized matches; `warning` normalizes to
/// the same filter as `warn`; no interval filter → unfilterable stays 0.
#[test]
fn level_only_filter_counts_and_alias_normalization() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    // total_entries is filter-independent: 14 entries (see the entry map).
    let info = logs_json(&file, &["--level", "info"]);
    assert_eq!(info["total_entries"], 14);
    assert_eq!(info["matched"], 5, "info entries: E1, E3, E7, E11, E14");
    assert_eq!(info["unfilterable"], 0);

    let error = logs_json(&file, &["--level", "error"]);
    assert_eq!(error["matched"], 3, "error entries: E4, E10, E13(FATAL)");
    assert_eq!(error["unfilterable"], 0);

    let debug = logs_json(&file, &["--level", "debug"]);
    assert_eq!(debug["matched"], 2, "debug entries: E2, E12");

    // `warning` → `warn`: the alias resolves to the same single entry.
    let warn_alias = logs_json(&file, &["--level", "warning"]);
    assert_eq!(warn_alias["matched"], 1);
    let warn = logs_json(&file, &["--level", "warn"]);
    assert_eq!(warn["matched"], 1);
    assert_eq!(
        warn["entries"][0]["line_start"], 8,
        "the warn entry starts on line 8"
    );

    // Case-insensitivity of the filter value.
    let upper = logs_json(&file, &["--level", "ERROR"]);
    assert_eq!(upper["matched"], 3);
}

/// (2) Inclusive from/to window over ISO timestamps: comparable timestamps
/// outside the window are excluded silently; missing/year-less timestamps
/// are excluded AND counted in `unfilterable`.
#[test]
fn from_to_window_and_unfilterable_accounting() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    // Window [09:00:00Z, 09:59:59Z]: matches E7 (09:30:00), E10 (09:31:10),
    // E11 (09:31:11). E6's 2024 epoch timestamp IS comparable → silently
    // excluded. E8/E9 (year-less syslog), E12/E13 (no timestamp) are
    // UNCOMPARABLE → unfilterable = 4.
    let json = logs_json(
        &file,
        &[
            "--from",
            "2026-09-14T09:00:00Z",
            "--to",
            "2026-09-14T09:59:59Z",
        ],
    );
    assert_eq!(json["total_entries"], 14);
    assert_eq!(json["matched"], 3);
    assert_eq!(json["unfilterable"], 4);
    let lines: Vec<u64> = json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["line_start"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, vec![10, 13, 14], "matched entries in source order");

    // Inclusive bounds: --from exactly at an entry's timestamp keeps it.
    // >= 09:31:10Z: E10 (09:31:10), E11 (09:31:11), E14 (10:00:00) → 3.
    // Unfilterable is the same 4 as above (E8/E9 syslog, E12/E13 no ts);
    // E6 (2024 epoch) is comparable → silently excluded, never counted.
    let inclusive = logs_json(&file, &["--from", "2026-09-14T09:31:10Z"]);
    assert_eq!(
        inclusive["matched"], 3,
        "E10, E11, E14 — bounds are inclusive"
    );
    assert_eq!(inclusive["unfilterable"], 4, "E8, E9, E12, E13");
}

/// (3) Grep: case-sensitive substring over the entry's raw text — a stack
/// frame's text matches its containing entry.
#[test]
fn grep_matches_entry_text_including_continuations() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    // "query" appears on the ERROR entry's start line AND inside its stack
    // frame continuation — one entry either way.
    let json = logs_json(&file, &["--grep", "query"]);
    assert_eq!(json["matched"], 1);
    assert_eq!(json["entries"][0]["line_start"], 5);
    assert_eq!(json["entries"][0]["line_end"], 7);

    // Case-sensitive: "Query" does not occur in the fixture.
    let case = logs_json(&file, &["--grep", "Query"]);
    assert_eq!(case["matched"], 0);

    // "db.py" occurs ONLY in the continuation line — the match must surface
    // the whole entry (its start line, not the continuation).
    let cont = logs_json(&file, &["--grep", "db.py"]);
    assert_eq!(cont["matched"], 1);
    assert_eq!(cont["entries"][0]["line_start"], 5);
}

/// (4) Combined filters: level/grep apply before the interval check, so an
/// entry rejected by the level filter never inflates `unfilterable`.
#[test]
fn combined_filters_apply_in_order() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    // error + window: E10 matches; E13 (FATAL, no timestamp) passes the
    // level filter but is uncomparable → unfilterable = 1. E4 is outside
    // the window (comparable → silent). The DEBUG/garbage/syslog entries
    // fail the level filter BEFORE the interval check → NOT unfilterable.
    let json = logs_json(
        &file,
        &[
            "--level",
            "error",
            "--from",
            "2026-09-14T09:00:00Z",
            "--to",
            "2026-09-14T10:00:00Z",
        ],
    );
    assert_eq!(json["matched"], 1);
    assert_eq!(json["unfilterable"], 1);
    assert_eq!(json["entries"][0]["line_start"], 13);

    // level + grep: only the "disk full" error survives.
    let both = logs_json(&file, &["--level", "error", "--grep", "disk"]);
    assert_eq!(both["matched"], 1);
    assert_eq!(both["entries"][0]["line_start"], 13);
    assert_eq!(
        both["unfilterable"], 0,
        "no interval filter → never unfilterable"
    );

    // level + window, info: E7 (09:30), E11 (09:31:11), E14 (10:00) pass
    // both; E1/E3 are info but before the window (comparable → silent).
    // The syslog/garbage entries fail the level filter → NOT unfilterable,
    // so unfilterable stays 0 even under an active --from.
    let info_window = logs_json(
        &file,
        &["--level", "info", "--from", "2026-09-14T09:00:00Z"],
    );
    assert_eq!(info_window["matched"], 3, "E7, E11, E14");
    assert_eq!(
        info_window["unfilterable"], 0,
        "no info-level entry lacks a timestamp"
    );
}

/// (5) JSON shape: the `logs-command-v1` document and entry rows.
#[test]
fn json_shape_is_stable() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    let json = logs_json(&file, &["--level", "error"]);

    let obj = json.as_object().expect("top-level object");
    for key in [
        "file",
        "total_entries",
        "matched",
        "unfilterable",
        "entries",
    ] {
        assert!(
            obj.contains_key(key),
            "logs-command-v1: top-level key `{key}` missing"
        );
    }
    assert_eq!(obj["file"].as_str().unwrap(), file.display().to_string());

    let rows = obj["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let r = row.as_object().expect("entry row object");
        for key in [
            "line_start",
            "line_end",
            "byte_start",
            "byte_end",
            "level",
            "timestamp",
        ] {
            assert!(
                r.contains_key(key),
                "logs-command-v1: entry key `{key}` missing"
            );
        }
        // Byte spans are ordered and level is normalized or null.
        assert!(r["byte_end"].as_u64().unwrap() > r["byte_start"].as_u64().unwrap());
        match r["level"] {
            Value::Null => {}
            ref s => assert!(
                ["error", "warn", "info", "debug"].contains(&s.as_str().unwrap()),
                "level must be a normalized value, got {s}"
            ),
        }
    }

    // The FATAL entry (no timestamp) serializes its timestamp as null and
    // its level as the normalized "error".
    let fatal = rows
        .iter()
        .find(|r| r["line_start"].as_u64() == Some(16))
        .expect("FATAL entry row");
    assert_eq!(fatal["level"], "error");
    assert!(fatal["timestamp"].is_null());
}

/// (6) Text mode: matched entries printed as their raw source lines with a
/// `--` separator BETWEEN entries (none before the first or after the last).
#[test]
fn text_mode_prints_raw_lines_with_separator() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    let output = tldr_cmd()
        .args([
            "logs",
            file.to_str().unwrap(),
            "--format",
            "text",
            "--level",
            "error",
        ])
        .output()
        .expect("run tldr logs --format text");
    assert!(
        output.status.success(),
        "stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = "\
2026-09-14T08:01:02Z ERROR query failed
Traceback (most recent call last):
  File \"db.py\", line 42, in query
--
2026-09-14T09:31:10Z ERROR disk full
--
FATAL: out of memory
";
    assert_eq!(
        stdout, expected,
        "text mode must print raw entry lines with -- separators"
    );

    // Single match → no separator at all.
    let single = tldr_cmd()
        .args([
            "logs",
            file.to_str().unwrap(),
            "--format",
            "text",
            "--level",
            "warn",
        ])
        .output()
        .expect("run tldr logs --format text");
    assert!(single.status.success());
    assert_eq!(
        String::from_utf8_lossy(&single.stdout),
        "2026-09-14T08:01:03Z WARN retry scheduled\n"
    );
}

/// (7) Exit codes: nonexistent file and directory paths are errors.
#[test]
fn nonexistent_file_and_directory_are_errors() {
    // Nonexistent file → non-zero exit, named error.
    tldr_cmd()
        .args(["logs", "/definitely/not/here/server.log"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Path not found"));

    // A directory is not a log file → non-zero exit.
    let dir = TempDir::new().expect("tempdir");
    tldr_cmd()
        .args(["logs", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Not a file"));

    // An unparseable --from is a hard error, not a silent empty result.
    let file = write_fixture(&dir);
    tldr_cmd()
        .args(["logs", file.to_str().unwrap(), "--from", "not-a-timestamp"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Could not parse --from"));
}

/// Schema hygiene: the report is additive-safe by construction (new command),
/// but the `--format compact` path must emit the same document minified.
#[test]
fn compact_format_emits_the_same_document() {
    let dir = TempDir::new().expect("tempdir");
    let file = write_fixture(&dir);

    let output = tldr_cmd()
        .args([
            "logs",
            file.to_str().unwrap(),
            "--format",
            "compact",
            "--level",
            "info",
        ])
        .output()
        .expect("run tldr logs --format compact");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("compact JSON parses");
    assert_eq!(value["matched"], 5);
    assert_eq!(value["total_entries"], 14);
}
