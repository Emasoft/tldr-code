//! w1_interface_utf8_v1 (v0.5.0 AUDIT-FIX, W1-interface-utf8):
//!
//! Pre-fix audit assertion (high):
//! > "`tldr interface <dir>` aborts the ENTIRE run with exit 1 and ZERO
//! >  output the moment it hits the first non-UTF-8 file, instead of
//! >  skipping it. Repro: `tldr interface /tmp/tldr_corpora_b/c-redis` ->
//! >  exit 1, stderr `parse error in .../deps/lua/test/life.lua: file is
//! >  not valid UTF-8`, 0 bytes stdout, even though 783 valid C/H files
//! >  exist. Same on the luau corpus (tests/conformance/literals.luau)."
//!
//! Verdict: REAL BUG. Verified pre-fix against the release binary: a single
//! file with one invalid UTF-8 byte (0xA5) in a scanned directory aborted
//! the whole walk before the per-file skip arm could run.
//!
//! Root cause: the directory-walk loop used the patterns-local
//! `read_file_safe`, which does a HARD `String::from_utf8` and propagated
//! `?` out of `run()`. The resilient commands (`structure`/`loc`) instead
//! read via `tldr_core::encoding::read_source_file` -> `from_utf8_lossy`
//! (lossy content + warning), or skip binary files.
//!
//! Fix (this v1, precedent-based): the interface directory walk now reads
//! through `encoding::read_source_file` and is non-fatal per file — lossy
//! files are still analyzed (warning to stderr), binary files are skipped
//! with a warning, and per-file IO errors are skipped with a warning. The
//! JSON/text report on stdout stays a clean `Vec<InterfaceInfo>`.
//!
//! These tests drive the PRODUCTION command path (the release binary) and
//! are genuine guards: they FAIL (exit 1 / empty stdout) if the fix is
//! reverted to `read_file_safe?`.

use std::path::{Path, PathBuf};
use std::process::Command;

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
        .env("TLDR_NO_DAEMON", "1")
        .args(args)
        .output()
        .expect("failed to run tldr binary");
    let exit = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (exit, stdout, stderr)
}

/// A real C source file with a genuine public function the extractor must
/// surface.
const VALID_C: &str = "int add_numbers(int a, int b) {\n    return a + b;\n}\n";

// ==========================================================================
// Core regression: one non-UTF-8 file must NOT abort the directory walk.
// ==========================================================================

#[test]
fn w1_interface_dir_with_invalid_utf8_file_is_non_fatal() {
    let dir = tempfile::tempdir().expect("tempdir");

    // (a) A valid C file with a real function.
    std::fs::write(dir.path().join("ok.c"), VALID_C).expect("write ok.c");

    // (b) A file with an invalid UTF-8 byte (0xA5 — a stray Latin-1 byte
    //     that is NOT valid UTF-8), mirroring the corpus `life.lua` /
    //     `literals.luau` failure. `.lua` is a scanned source extension.
    let mut bad: Vec<u8> = b"-- comment with bad byte: ".to_vec();
    bad.push(0xA5);
    bad.extend_from_slice(b"\nlocal function helper() return 1 end\n");
    std::fs::write(dir.path().join("bad.lua"), &bad).expect("write bad.lua");

    let dir_str = dir.path().to_string_lossy().into_owned();
    let (rc, stdout, stderr) =
        run_tldr(&["interface", &dir_str, "--format", "json", "-q"]);

    // 1. The run must NOT abort: exit 0, not 1.
    assert_eq!(
        rc, 0,
        "interface on a dir containing a non-UTF-8 file must exit 0 \
         (was {rc}); stderr:\n{stderr}"
    );

    // 2. Output must be NON-EMPTY and contain the valid file's interface.
    assert!(
        !stdout.trim().is_empty(),
        "interface output must be non-empty; stderr:\n{stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("interface dir output must be valid JSON");
    let arr = v.as_array().expect("dir interface output is a JSON array");
    let found_add = arr.iter().any(|info| {
        info.get("functions")
            .and_then(|f| f.as_array())
            .map(|fns| {
                fns.iter().any(|f| {
                    f.get("name").and_then(|n| n.as_str()) == Some("add_numbers")
                })
            })
            .unwrap_or(false)
    });
    assert!(
        found_add,
        "valid ok.c interface (`add_numbers`) must be present despite the \
         bad file; stdout:\n{stdout}"
    );

    // 3. The bad file must be reported as a NON-FATAL warning (not swallowed
    //    silently), on stderr — the same non-silent channel the resilient
    //    core uses for recoverable per-file skips.
    assert!(
        stderr.to_lowercase().contains("warning")
            && (stderr.contains("bad.lua") || stderr.to_lowercase().contains("utf-8")),
        "the non-UTF-8 file must surface as a warning (not be swallowed); \
         stderr:\n{stderr}"
    );

    // 4. The pre-fix HARD-error message must NOT appear as a fatal abort.
    assert!(
        !stderr.starts_with("Error:"),
        "interface must not emit a fatal `Error:` for a non-UTF-8 file in a \
         directory walk; stderr:\n{stderr}"
    );
}

// ==========================================================================
// Adjacent correctness guard: a binary file in the dir is skipped + warned,
// the run still succeeds and emits the valid file.
// ==========================================================================

#[test]
fn w1_interface_dir_with_binary_file_is_non_fatal() {
    let dir = tempfile::tempdir().expect("tempdir");

    std::fs::write(dir.path().join("ok.c"), VALID_C).expect("write ok.c");

    // A "source-extensioned" file that is actually binary (contains NUL
    // bytes). The tolerant reader classifies it as Binary and skips it.
    let mut binary: Vec<u8> = b"int x".to_vec();
    binary.extend_from_slice(&[0x00, 0x00, 0x01, 0x02, 0x00]);
    std::fs::write(dir.path().join("blob.c"), &binary).expect("write blob.c");

    let dir_str = dir.path().to_string_lossy().into_owned();
    let (rc, stdout, stderr) =
        run_tldr(&["interface", &dir_str, "--format", "json", "-q"]);

    assert_eq!(
        rc, 0,
        "interface on a dir with a binary file must exit 0 (was {rc}); \
         stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("add_numbers"),
        "valid ok.c interface must still be emitted; stdout:\n{stdout}"
    );
}

// ==========================================================================
// Adjacent correctness guard: the SINGLE-file path is intentionally
// unchanged — a user explicitly naming a non-UTF-8 file still gets a hard
// error (correct: there is nothing else to fall back to). This pins that the
// fix touched ONLY the directory-walk arm.
// ==========================================================================

#[test]
fn w1_interface_single_non_utf8_file_still_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bad: Vec<u8> = b"-- bad: ".to_vec();
    bad.push(0xA5);
    bad.extend_from_slice(b"\n");
    let bad_path = dir.path().join("only.lua");
    std::fs::write(&bad_path, &bad).expect("write only.lua");

    let bad_str = bad_path.to_string_lossy().into_owned();
    let (rc, _stdout, stderr) =
        run_tldr(&["interface", &bad_str, "--format", "json", "-q"]);

    assert_ne!(
        rc, 0,
        "interface on a single explicitly-named non-UTF-8 file should still \
         fail (the dir-walk tolerance must not leak into the single-file \
         path); stderr:\n{stderr}"
    );
}

// ==========================================================================
// Live corpus guards (skip with a printed reason when the corpus is absent),
// matching the pattern used in cl6_interface_v1.rs.
// ==========================================================================

#[test]
fn w1_interface_c_redis_corpus_is_non_fatal() {
    let corpus = "/tmp/tldr_corpora_b/c-redis";
    if !Path::new(corpus).exists() {
        eprintln!("SKIP: {corpus} not present");
        return;
    }
    let (rc, stdout, stderr) = run_tldr(&["interface", corpus, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "interface on c-redis must exit 0 despite non-UTF-8 deps/lua files \
         (was {rc}); stderr:\n{}",
        stderr.lines().take(5).collect::<Vec<_>>().join("\n")
    );
    assert!(
        !stdout.trim().is_empty(),
        "interface on c-redis must emit non-empty output"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("c-redis interface output must be valid JSON");
    let arr = v.as_array().expect("c-redis interface output is a JSON array");
    assert!(
        !arr.is_empty(),
        "c-redis has 700+ valid C/H files; interface must surface some"
    );
}

#[test]
fn w1_interface_luau_corpus_is_non_fatal() {
    let corpus = "/tmp/tldr_corpora_b/luau";
    if !Path::new(corpus).exists() {
        eprintln!("SKIP: {corpus} not present");
        return;
    }
    let (rc, stdout, stderr) = run_tldr(&["interface", corpus, "--format", "json", "-q"]);
    assert_eq!(
        rc, 0,
        "interface on luau must exit 0 despite the non-UTF-8 \
         tests/conformance/literals.luau (was {rc}); stderr:\n{}",
        stderr.lines().take(5).collect::<Vec<_>>().join("\n")
    );
    assert!(
        !stdout.trim().is_empty(),
        "interface on luau must emit non-empty output"
    );
}
