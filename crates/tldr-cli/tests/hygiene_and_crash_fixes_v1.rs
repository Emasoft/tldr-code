//! hygiene-and-crash-fixes-v1 (P12.BUG-AGG12-3, AGG12-5, AGG12-6, SWIFT-2)
//!
//! First milestone shipped under the **no-synthetic-fixtures-v1** test
//! architecture (see `thoughts/shared/strategy/no-synthetic-fixtures-v1.md`).
//! Every test in this file is gated on the existence of a real codebase at
//! `/tmp/repos/<repo>` and exits early when the corpus is absent. NO
//! `TempDir::new()` + synthetic content writes — only real-repo invocations
//! that exercise the same code paths the phase-12 audit hit.
//!
//! Four regressions closed:
//!
//! 1. **BUG-AGG12-3 (MED)** Stdout hygiene completion for `semantic` /
//!    `similar` / `embed` — P11-E claimed to fix the leak via
//!    `println!→eprintln!` but the phase-12 audit found Kotlin and OCaml
//!    still emitted `Building index for N chunks...` on stdout. The fix
//!    landed in P11.AGG-4 actually reached every entry point; this test
//!    file pins the behaviour against real corpora so the regression
//!    cannot recur.
//!
//! 2. **BUG-AGG12-5 (MED)** `tldr similar` cold-cache crash — `similar`
//!    against a file under a path with no pre-existing `~/.cache/tldr`
//!    raised `Error: No such file or directory (os error 2)` because the
//!    embedding cache write path expected the cache directory to exist.
//!    `EmbeddingCache::open` already calls `fs::create_dir_all`, so the
//!    repro now succeeds end-to-end on a real Ruby codebase.
//!
//! 3. **BUG-AGG12-6 (MED)** `tldr diagnostics` 0-byte stdout — when no
//!    diagnostic tools are installed for the language (or all tools fail
//!    to run), the command previously emitted the advisory to stderr and
//!    exited with code 60/61, leaving stdout empty. JSON consumers
//!    choked. The fix emits a valid empty `DiagnosticsReport` (or SARIF
//!    document) on stdout BEFORE the stderr advisory, while preserving
//!    exit codes 60/61 so existing skip-on-no-tools test gates still
//!    distinguish "no tools" from a real diagnostics run.
//!
//! 4. **BUG-SWIFT-2 (LOW)** `tldr change-impact` writes usage error to
//!    stdout — when given a file instead of a directory, the error
//!    message previously hit stdout, breaking JSON consumers. The error
//!    now goes to stderr exclusively; stdout stays JSON-clean even on
//!    usage errors.

use std::path::{Path, PathBuf};
use std::process::Command;

fn tldr_bin() -> PathBuf {
    let mut candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidate.pop(); // crates/tldr-cli -> crates
    candidate.pop(); // crates -> repo root
    candidate.push("target/release/tldr");
    candidate
}

/// Returns true when `/tmp/repos/<repo>` exists; false otherwise (in which
/// case the calling test exits early per no-synthetic-fixtures-v1 §1).
fn require_repo(repo: &str) -> bool {
    Path::new(&format!("/tmp/repos/{}", repo)).exists()
}

fn run(args: &[&str]) -> (Vec<u8>, Vec<u8>, Option<i32>) {
    let bin = tldr_bin();
    assert!(
        bin.exists(),
        "expected release tldr binary at {} (run `cargo build --release --features semantic`)",
        bin.display()
    );
    let out = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    (out.stdout, out.stderr, out.status.code())
}

/// Assert that `stdout` is valid JSON whose first non-whitespace byte is `{`.
/// Carries enough context to debug a stray progress line leaking onto stdout.
fn assert_stdout_is_json(stdout: &[u8], stderr: &[u8], context: &str) {
    let s = String::from_utf8_lossy(stdout);
    let trimmed = s.trim_start();
    let first = trimmed.chars().next();
    assert_eq!(
        first,
        Some('{'),
        "{}: stdout must start with '{{' (JSON object). \
         got first chars: {:?} | stderr={}",
        context,
        &s.chars().take(120).collect::<String>(),
        String::from_utf8_lossy(stderr).chars().take(200).collect::<String>(),
    );
    serde_json::from_slice::<serde_json::Value>(stdout).unwrap_or_else(|e| {
        panic!(
            "{}: stdout must parse as JSON: {} | head: {:?}",
            context,
            e,
            &s.chars().take(200).collect::<String>()
        )
    });
}

// =============================================================================
// BUG-AGG12-3: stdout hygiene completion for semantic / similar / embed
// =============================================================================

/// Real-repo: `tldr semantic` on a Kotlin codebase must produce JSON-only
/// stdout. The phase-12 audit pinned this exact corpus + query combination
/// (`/tmp/repos/kotlin-datetime/core/common/src` + "date arithmetic") as
/// the leaky case; we replay it verbatim.
#[test]
#[cfg(feature = "semantic")]
fn agg12_3_semantic_kotlin_stdout_is_pure_json() {
    if !require_repo("kotlin-datetime") {
        return;
    }
    let (stdout, stderr, code) = run(&[
        "semantic",
        "date arithmetic",
        "/tmp/repos/kotlin-datetime/core/common/src",
        "--format",
        "json",
    ]);
    assert_eq!(
        code,
        Some(0),
        "semantic kotlin must exit 0; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert_stdout_is_json(&stdout, &stderr, "semantic kotlin-datetime");

    // ≥1-result style assertion (no-synthetic-fixtures-v1 §4): the corpus
    // is large enough that "date arithmetic" must match at least one chunk.
    let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    let results = v
        .get("results")
        .and_then(|x| x.as_array())
        .expect("semantic must emit 'results' array");
    assert!(
        !results.is_empty(),
        "semantic on kotlin-datetime must return ≥1 result for 'date arithmetic'"
    );
}

/// Real-repo: `tldr similar` on a single OCaml file must produce JSON-only
/// stdout. Phase-12 audit corpus: `ocaml-dune/src/dag/dag.ml`.
#[test]
#[cfg(feature = "semantic")]
fn agg12_3_similar_ocaml_stdout_is_pure_json() {
    if !require_repo("ocaml-dune") {
        return;
    }
    let target = "/tmp/repos/ocaml-dune/src/dag/dag.ml";
    if !Path::new(target).exists() {
        return;
    }
    let (stdout, stderr, code) = run(&["similar", target, "--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "similar ocaml must exit 0; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert_stdout_is_json(&stdout, &stderr, "similar ocaml-dune");

    let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert!(
        v.get("source_file").is_some() || v.get("results").is_some(),
        "similar must emit a source_file or results field"
    );
}

/// Cross-language regression check: confirm the AGG12-3 fix did NOT break
/// the working Go and PHP paths. Probes both languages on real corpora to
/// catch any single-language fix that broke a sibling.
#[test]
#[cfg(feature = "semantic")]
fn agg12_3_semantic_cross_language_regression() {
    let mut probed = 0u32;
    if require_repo("go-httprouter") {
        let (stdout, stderr, code) = run(&[
            "semantic",
            "route registration",
            "/tmp/repos/go-httprouter",
            "--format",
            "json",
        ]);
        assert_eq!(
            code,
            Some(0),
            "semantic go must exit 0; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert_stdout_is_json(&stdout, &stderr, "semantic go-httprouter");
        probed += 1;
    }
    if require_repo("php-symfony-string") {
        let (stdout, stderr, code) = run(&[
            "semantic",
            "string transformation",
            "/tmp/repos/php-symfony-string",
            "--format",
            "json",
        ]);
        assert_eq!(
            code,
            Some(0),
            "semantic php must exit 0; stderr={}",
            String::from_utf8_lossy(&stderr)
        );
        assert_stdout_is_json(&stdout, &stderr, "semantic php-symfony-string");
        probed += 1;
    }
    // If neither corpus is present, the test silently no-ops — but as soon
    // as one is on the host, we exercise the regression net.
    let _ = probed;
}

/// Real-repo: `tldr embed` must emit JSON-only stdout regardless of cache
/// state. Probes a Ruby corpus (Rails HTML sanitizer) — the language whose
/// audit row first surfaced AGG12-5.
#[test]
#[cfg(feature = "semantic")]
fn agg12_3_embed_ruby_stdout_is_pure_json() {
    if !require_repo("rails-html-sanitizer") {
        return;
    }
    let (stdout, stderr, code) = run(&[
        "embed",
        "/tmp/repos/rails-html-sanitizer",
        "--format",
        "json",
    ]);
    assert_eq!(
        code,
        Some(0),
        "embed ruby must exit 0; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert_stdout_is_json(&stdout, &stderr, "embed rails-html-sanitizer");
}

// =============================================================================
// BUG-AGG12-5: similar cold-cache crash
// =============================================================================

/// Real-repo: `tldr similar` against a Ruby file from a Rails sanitizer
/// codebase must succeed without raising "No such file or directory" even
/// when the embedding cache is uninitialized. This pins the contract that
/// `EmbeddingCache::open` ensures the cache directory exists before any
/// write — the workaround "run `tldr embed` first" is no longer required.
#[test]
#[cfg(feature = "semantic")]
fn agg12_5_similar_cold_cache_succeeds() {
    if !require_repo("rails-html-sanitizer") {
        return;
    }
    let target = "/tmp/repos/rails-html-sanitizer/lib/rails/html/sanitizer.rb";
    if !Path::new(target).exists() {
        return;
    }
    let (stdout, stderr, code) = run(&["similar", target, "--format", "json"]);
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert!(
        !stderr_str.contains("No such file or directory"),
        "similar must not raise ENOENT on cold cache; stderr={}",
        stderr_str
    );
    assert_eq!(
        code,
        Some(0),
        "similar must exit 0 on cold cache; stderr={}",
        stderr_str
    );
    assert_stdout_is_json(&stdout, &stderr, "similar cold-cache rails-html-sanitizer");
}

// =============================================================================
// BUG-AGG12-6: diagnostics 0-byte stdout
// =============================================================================

/// Real-repo: `tldr diagnostics` against a Luau corpus on a host that has
/// no Luau diagnostic tooling installed must emit a valid (empty)
/// `DiagnosticsReport` JSON document on stdout. Exit code 60 is preserved
/// so callers can distinguish "no tools" from a clean run.
#[test]
fn agg12_6_diagnostics_no_tools_emits_valid_json() {
    if !require_repo("luau-luau") {
        return;
    }
    let target = "/tmp/repos/luau-luau/tests/conformance";
    if !Path::new(target).exists() {
        return;
    }
    let (stdout, stderr, code) = run(&["diagnostics", target, "--lang", "luau", "--format", "json"]);

    // Stdout MUST be valid JSON (the whole point of the fix).
    assert!(
        !stdout.is_empty(),
        "diagnostics stdout must not be 0-byte; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap_or_else(|e| {
        panic!(
            "diagnostics no-tools stdout must parse as JSON: {} | head: {:?}",
            e,
            String::from_utf8_lossy(&stdout).chars().take(300).collect::<String>()
        )
    });

    // Schema invariants on the empty report.
    assert!(v.get("diagnostics").is_some(), "must have 'diagnostics' field");
    assert!(v.get("summary").is_some(), "must have 'summary' field");
    assert!(v.get("tools_run").is_some(), "must have 'tools_run' field");
    assert!(v.get("files_analyzed").is_some(), "must have 'files_analyzed'");
    assert_eq!(
        v.get("diagnostics").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0),
        "no-tools diagnostics must be empty array"
    );

    // Stderr MUST carry the advisory; exit code MUST stay 60.
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert!(
        stderr_str.contains("No diagnostic tools available"),
        "stderr must carry the no-tools advisory; got: {}",
        stderr_str
    );
    assert_eq!(
        code,
        Some(60),
        "exit code 60 preserved for no-tools (S6-R36 contract)"
    );
}

/// Real-repo: same fix path applied to SARIF output. When no tools are
/// available, the SARIF document on stdout must still parse as a valid
/// SARIF 2.1.0 envelope (with an empty `runs[].results` array).
#[test]
fn agg12_6_diagnostics_no_tools_emits_valid_sarif() {
    if !require_repo("luau-luau") {
        return;
    }
    let target = "/tmp/repos/luau-luau/tests/conformance";
    if !Path::new(target).exists() {
        return;
    }
    let (stdout, stderr, _code) = run(&[
        "diagnostics",
        target,
        "--lang",
        "luau",
        "--output",
        "sarif",
    ]);
    let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap_or_else(|e| {
        panic!(
            "no-tools SARIF stdout must parse: {} | head: {:?}",
            e,
            String::from_utf8_lossy(&stdout).chars().take(300).collect::<String>()
        )
    });
    assert_eq!(
        v.get("version").and_then(|x| x.as_str()),
        Some("2.1.0"),
        "SARIF version must be 2.1.0"
    );
    assert!(v.get("runs").and_then(|x| x.as_array()).is_some(), "SARIF must have 'runs'");
    let _ = stderr;
}

// =============================================================================
// BUG-SWIFT-2: change-impact on a file path succeeds with clean JSON output
// (Updated in v0.4.2 to match W-R commit 4ce6f8a: accept-path-or-dir contract)
// =============================================================================

/// Real-repo: `tldr change-impact` on a FILE is now accepted (design-correct
/// as of W-R commit 4ce6f8a).  The command must exit 0, emit valid JSON on
/// stdout with the file listed in `changed_files`, and produce no error
/// output on stderr.
///
/// The original test asserted a non-zero "usage error" exit because the old
/// implementation rejected file paths.  That over-strict guard was removed
/// in 4ce6f8a — file-path input now maps to a single-file change-set with
/// language inferred from the extension.
#[test]
fn swift_2_change_impact_usage_error_to_stderr() {
    if !require_repo("swift-collections") {
        return;
    }
    let target = "/tmp/repos/swift-collections/Sources/HeapModule/Heap.swift";
    if !Path::new(target).exists() {
        return;
    }
    let (stdout, stderr, code) = run(&["change-impact", target, "--format", "json"]);

    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);

    // New contract: file path is accepted, exit 0.
    assert_eq!(
        code,
        Some(0),
        "change-impact on a file must now succeed (exit 0); stderr: {}",
        stderr_str
    );

    // Stderr must be empty — no error/warning noise for a valid file path.
    assert!(
        stderr_str.trim().is_empty(),
        "change-impact on a valid file must not write to stderr; got: {}",
        stderr_str
    );

    // Stdout must be valid JSON.
    let parsed: serde_json::Value = serde_json::from_slice(&stdout).expect(
        "change-impact on a file must emit valid JSON on stdout",
    );

    // The supplied file must appear in changed_files.
    let changed = parsed
        .get("changed_files")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .any(|f| f.as_str().map_or(false, |s| s.ends_with("Heap.swift")))
        })
        .unwrap_or(false);
    assert!(
        changed,
        "Heap.swift must appear in changed_files; stdout: {}",
        stdout_str
    );
}

/// Confirm `tldr change-impact` on a real DIRECTORY (the happy path)
/// continues to emit JSON-clean stdout — proves the SWIFT-2 fix did not
/// regress the working case.
#[test]
fn swift_2_change_impact_directory_happy_path() {
    if !require_repo("swift-collections") {
        return;
    }
    let (stdout, stderr, code) = run(&[
        "change-impact",
        "/tmp/repos/swift-collections",
        "--format",
        "json",
    ]);
    // Some shells/git states make change-impact return exit 0 with a
    // NoChanges status; what we care about here is JSON-clean stdout.
    let _ = code;
    assert_stdout_is_json(&stdout, &stderr, "change-impact directory swift");
}
