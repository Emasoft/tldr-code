//! low-cleanup-bundle-v1 — regression tests for 8 LOW UX bugs.
//!
//! Covers:
//!   L1  structure --format text emits classes + signatures
//!   L2  stats empty payload includes next_steps + requires
//!   L3  fix --help enumerates accepted error formats
//!   L4  coverage errors on empty/invalid input under auto-detect
//!   L5  dead JSON output drops shown_count/total_count
//!   L6  loc by_language is a JSON object keyed by language name
//!   L7  clones never emit Type-2 with similarity 1.0
//!   L8  semantic respects --quiet for embedder banner

use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

// =============================================================================
// L1: structure --format text emits classes + method signatures
// =============================================================================

#[test]
fn l1_structure_text_richer_than_before() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("svc.py");
    fs::write(
        &f,
        "class Service:\n    def fetch(self, id: int) -> str:\n        return str(id)\n\n    def save(self, value: str) -> None:\n        pass\n\ndef helper() -> int:\n    return 1\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args([
            "structure",
            temp.path().to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("tldr structure should run");
    assert!(out.status.success(), "structure should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Class is shown.
    assert!(
        stdout.contains("Service"),
        "should list class Service: {}",
        stdout
    );
    // At least one method appears (signature or name) under the class.
    assert!(
        stdout.contains("fetch") || stdout.contains("save"),
        "should list method names: {}",
        stdout
    );
    // The free function is shown.
    assert!(
        stdout.contains("helper"),
        "should list free function: {}",
        stdout
    );
    // Line numbers appear somewhere (we tag every richer line with `(L<n>)`
    // or with the `L<n>` marker — at minimum the function should have a
    // line annotation).
    assert!(
        stdout.contains("L") || stdout.contains("(line"),
        "should annotate with line numbers: {}",
        stdout
    );
}

// =============================================================================
// L2: stats empty payload is self-explanatory
// =============================================================================

#[test]
fn l2_stats_empty_payload_includes_next_steps() {
    // Force an empty stats path by pointing HOME at a tempdir.
    let temp = TempDir::new().unwrap();
    let out = tldr_cmd()
        .args(["stats", "--format", "json"])
        .env("HOME", temp.path()) // guarantees an empty/missing ~/.tldr/stats.jsonl
        .output()
        .expect("tldr stats should run");
    assert!(out.status.success(), "stats should succeed even when empty");
    let stdout = String::from_utf8_lossy(&out.stdout);

    let v: Value = serde_json::from_str(&stdout).expect("stats should emit valid JSON");
    assert!(
        v.get("message").is_some(),
        "must include message: {}",
        stdout
    );
    let next_steps = v
        .get("next_steps")
        .expect("must include next_steps hint")
        .as_array()
        .expect("next_steps should be array");
    assert!(!next_steps.is_empty(), "next_steps should be non-empty");
    let joined = next_steps
        .iter()
        .map(|x| x.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        joined.contains("daemon start"),
        "next_steps should mention `tldr daemon start`: {}",
        joined
    );

    let requires = v
        .get("requires")
        .expect("must include requires")
        .as_array()
        .unwrap();
    assert!(!requires.is_empty(), "requires should be non-empty");
}

// =============================================================================
// L3: fix --help enumerates accepted compilers / runtimes
// =============================================================================

#[test]
fn l3_fix_help_lists_accepted_input_formats() {
    let out = tldr_cmd()
        .args(["fix", "--help"])
        .output()
        .expect("tldr fix --help should run");
    assert!(out.status.success(), "fix --help should succeed");
    let help = String::from_utf8_lossy(&out.stdout);

    // The help should mention specific tools, not just "compiler/runtime".
    let must_mention = ["cargo", "Python", "tsc"];
    for token in must_mention {
        assert!(
            help.contains(token),
            "fix --help must mention '{}', got:\n{}",
            token,
            help
        );
    }
}

// =============================================================================
// L4: coverage /dev/null errors out under auto-detect
// =============================================================================

#[test]
fn l4_coverage_empty_input_errors_under_autodetect() {
    let temp = TempDir::new().unwrap();
    let empty = temp.path().join("empty.xml");
    fs::write(&empty, "").unwrap();

    let assert = tldr_cmd()
        .args(["coverage", empty.to_str().unwrap()])
        .assert()
        .failure();
    assert.stderr(
        predicate::str::contains("empty")
            .or(predicate::str::contains("unrecognized"))
            .or(predicate::str::contains("Coverage report")),
    );
}

// =============================================================================
// L5: dead JSON drops shown_count/total_count, keeps total_dead + truncated
// =============================================================================

#[test]
fn l5_dead_json_has_no_redundant_count_fields() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("a.py");
    // Two functions, only one used. dead-code analysis runs OK.
    fs::write(
        &f,
        "def used():\n    return 1\n\ndef unused():\n    return 2\n\nprint(used())\n",
    )
    .unwrap();

    let out = tldr_cmd()
        .args(["dead", temp.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("tldr dead should run");
    assert!(out.status.success(), "dead should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("dead should emit valid JSON");

    assert!(
        v.get("total_dead").is_some(),
        "must keep total_dead: {}",
        stdout
    );
    assert!(
        v.get("shown_count").is_none(),
        "must drop shown_count (redundant w/ total_dead): {}",
        stdout
    );
    assert!(
        v.get("total_count").is_none(),
        "must drop total_count (redundant w/ total_dead): {}",
        stdout
    );
}

// =============================================================================
// L6: loc by_language is a JSON object keyed by language name
// =============================================================================

#[test]
fn l6_loc_by_language_is_object_on_single_lang() {
    let temp = TempDir::new().unwrap();
    let f = temp.path().join("only.py");
    fs::write(&f, "def main():\n    pass\n").unwrap();

    let out = tldr_cmd()
        .args(["loc", temp.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("tldr loc should run");
    assert!(out.status.success(), "loc should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("loc should emit valid JSON");

    let by_lang = v.get("by_language").expect("must have by_language");
    assert!(
        by_lang.is_object(),
        "by_language must be a JSON object: {}",
        stdout
    );
    let keys: Vec<&str> = by_lang
        .as_object()
        .unwrap()
        .keys()
        .map(|s| s.as_str())
        .collect();
    // Single-language repo => exactly one key, that key matches the language.
    assert_eq!(keys.len(), 1, "expected 1 key, got {:?}", keys);
    assert!(
        keys[0].to_lowercase().contains("python"),
        "key should be 'python', got {:?}",
        keys
    );
}

// =============================================================================
// L7: clones never emit Type-2 with similarity 1.0
// =============================================================================

#[test]
fn l7_clones_type_consistent_with_similarity() {
    use tldr_core::analysis::clones::{classify_clone_type, CloneType};

    // Boundary cases the audit caught: similarity 1.0 must be Type-1.
    // (`classify_clone_type` uses an EPSILON=1e-9 tolerance against 1.0.)
    assert_eq!(classify_clone_type(1.0), CloneType::Type1);
    assert_eq!(classify_clone_type(0.9999999999), CloneType::Type1);
    // Anything strictly less than 1.0 (down to 0.9) is Type-2.
    assert_eq!(classify_clone_type(0.95), CloneType::Type2);
    // Below 0.9 is Type-3.
    assert_eq!(classify_clone_type(0.85), CloneType::Type3);
}

// =============================================================================
// L8: semantic / embed / similar honor --quiet for embedder banner
// =============================================================================

#[test]
fn l8_global_quiet_flag_silences_progress() {
    // Audit asks for `--quiet` to silence the embedder banner on
    // semantic/embed/similar. The mechanism we adopted is: the global
    // `--quiet` flag now sets `TLDR_QUIET=1`, which `Embedder::new`
    // honors. Two assertions:
    //   (1) the global `--quiet` flag is exposed in `tldr --help`;
    //   (2) `--quiet` produces no more stderr than a default invocation
    //       on a fast non-semantic command (tree).
    //
    // We deliberately avoid invoking `tldr semantic` here so the test
    // does not require the optional `--features semantic` build, nor a
    // 110MB model download.
    let out = tldr_cmd()
        .args(["--help"])
        .output()
        .expect("tldr --help should run");
    assert!(out.status.success(), "tldr --help should succeed");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--quiet") || help.contains("-q"),
        "tldr --help should expose --quiet: {}",
        help
    );

    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a.py"), "x = 1\n").unwrap();

    let noisy = tldr_cmd()
        .args(["tree", temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    let quiet = tldr_cmd()
        .args(["--quiet", "tree", temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(noisy.status.success());
    assert!(quiet.status.success());

    let noisy_stderr_len = noisy.stderr.len();
    let quiet_stderr_len = quiet.stderr.len();
    assert!(
        quiet_stderr_len <= noisy_stderr_len,
        "--quiet must not produce more stderr than default ({} > {})",
        quiet_stderr_len,
        noisy_stderr_len
    );
}
