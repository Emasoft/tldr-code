//! TYPESCRIPT-LARGE-FILE-PERF-V1 — uniform oversize-file skip policy
//!
//! Six commands (structure, calls, smells, dead, secure, plus other
//! parse-based scanners) timed out at 30 s when pointed at a single
//! 2.3 MB auto-generated TypeScript declaration file
//! (`/tmp/repos/ts-dom-gen/baselines/dom.generated.d.ts`). The same
//! repo's `src/` finished in 0.02 s. The bottleneck was super-linear
//! per-file analysis on a dense `.d.ts` artefact that's rarely
//! valuable to analyse deeply.
//!
//! The fix centralises the file-size policy in
//! [`tldr_core::fs::oversize`] and enforces it at file-read time in
//! [`tldr_core::ast::parser::parse_file_with_lang`]. Auto-generated
//! / minified artefacts (`.d.ts`, `.min.js`, `.bundle.css`, …) get a
//! stricter cap; normal source files get the general cap. Since
//! limits-stretch-v1 (2025-09) those caps are 64 MiB and 2 GiB
//! respectively (up from the historical 512 KB / 10 MB) — see
//! [`tldr_core::fs::oversize::MAX_AUTOGEN_FILE_SIZE_BYTES`] and
//! [`tldr_core::fs::oversize::MAX_FILE_SIZE_BYTES`]. Oversize files
//! surface as a structured warning + a non-zero `files_skipped`
//! counter (mirrors the M-X5 / M-Y2 UTF-8-tolerance pattern), never a
//! hard error.
//!
//! This suite imports the real constants instead of re-declaring
//! them, so it can never contradict the policy it tests.
//!
//! Fixture budget: these are CLI end-to-end tests, so no fixture is
//! larger than ~1 MB. Under the stretched caps the smallest file the
//! policy actually skips is 64 MiB + 1 byte (autogen) or 2 GiB + 1
//! byte (source), so the two oversize-skip cases are `#[ignore]`-gated
//! opt-ins — their fixtures are derived from the real constants
//! (64 MiB + 16 KB and 1.5 × 64 MiB) and are stat-checked, never
//! parsed, so the opt-in runs themselves stay fast. Everything else
//! here runs on small fixtures and pins the CURRENT policy
//! observably: what used to be "a 768 KB `.d.ts` is skipped" is now
//! "a 768 KB `.d.ts` is analysed".

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::tempdir;

use tldr_core::fs::oversize::{max_size_for, MAX_AUTOGEN_FILE_SIZE_BYTES, MAX_FILE_SIZE_BYTES};

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// Run `tldr structure <dir> --lang typescript -f json` and return the
/// parsed JSON report.
fn structure_json(dir: &Path) -> Result<serde_json::Value, String> {
    let output = tldr_cmd()
        .arg("structure")
        .arg(dir.to_str().unwrap())
        .arg("--lang")
        .arg("typescript")
        .arg("-f")
        .arg("json")
        .output()
        .expect("structure must execute");
    if !output.status.success() {
        return Err(format!(
            "structure must succeed; status={:?}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .map_err(|e| format!("structure stdout must be valid JSON; err: {e}; stdout: {stdout}"))
}

/// Build a tempdir with one normal `.ts` file and one over-cap
/// `.d.ts` file. Returns the tempdir guard so the caller controls
/// lifetime.
///
/// The bad file is sized at the REAL auto-gen cap
/// ([`MAX_AUTOGEN_FILE_SIZE_BYTES`]) + 16 KB so it crosses the
/// current 64 MiB threshold. That is far beyond the ~1 MB fixture
/// budget of the default suite (and beyond the ~10 MB CLI-test
/// budget generally), which is why the only test using this helper is
/// `#[ignore]`-gated. The oversized file is stat-checked by the size
/// policy, never parsed, so the opt-in run itself is fast.
fn make_oversize_dts_dir() -> tempfile::TempDir {
    let dir = tempdir().unwrap();

    // Tiny valid file — must always be analysed.
    fs::write(
        dir.path().join("good.ts"),
        b"export function ok(): number { return 1; }\n",
    )
    .unwrap();

    // Over-cap auto-generated declaration file. Content is repeated
    // valid TypeScript so the bytes themselves are not the issue —
    // the size policy is the only reason this gets skipped.
    let oversized_bytes = MAX_AUTOGEN_FILE_SIZE_BYTES as usize + 16 * 1024;
    let chunk = b"export interface I { x: number; }\n";
    let mut bytes: Vec<u8> = Vec::with_capacity(oversized_bytes);
    while bytes.len() < oversized_bytes {
        bytes.extend_from_slice(chunk);
    }
    fs::write(dir.path().join("dom.generated.d.ts"), bytes).unwrap();

    dir
}

/// The size policy routes by path class using the imported real
/// constants: autogen suffixes get the autogen cap, normal source gets
/// the source cap, and `.jsonl`/`.ndjson` are uncapped (streamed
/// row-by-row). The autogen cap stays strictly below the source cap —
/// the whole reason the two classes exist.
#[test]
fn test_size_policy_routes_by_path_class() {
    assert_eq!(
        max_size_for(Path::new("dom.generated.d.ts")),
        MAX_AUTOGEN_FILE_SIZE_BYTES,
        "auto-gen suffix must be capped by MAX_AUTOGEN_FILE_SIZE_BYTES"
    );
    assert_eq!(
        max_size_for(Path::new("src.ts")),
        MAX_FILE_SIZE_BYTES,
        "normal source must be capped by MAX_FILE_SIZE_BYTES"
    );
    assert_eq!(
        max_size_for(Path::new("rows.jsonl")),
        u64::MAX,
        ".jsonl/.ndjson are streamed row-by-row and must be uncapped"
    );
    assert!(
        MAX_AUTOGEN_FILE_SIZE_BYTES < MAX_FILE_SIZE_BYTES,
        "policy invariant: the autogen cap must stay below the source cap \
         (autogen = {}, source = {})",
        MAX_AUTOGEN_FILE_SIZE_BYTES,
        MAX_FILE_SIZE_BYTES
    );
}

/// Under the stretched policy a sub-MB `.d.ts` is well inside the
/// 64 MiB auto-gen cap and must be ANALYSED, not skipped. (The
/// historical 512 KB cap skipped exactly this fixture — this test
/// pins the new behaviour at a size the old policy would have
/// rejected.)
#[test]
fn test_dts_under_autogen_cap_is_analyzed() {
    let dir = tempdir().unwrap();

    // 768 KB of repeated valid declarations: above the OLD 512 KB
    // auto-gen cap, far below the current 64 MiB one.
    let target_bytes = 768 * 1024;
    assert!(
        (target_bytes as u64) < MAX_AUTOGEN_FILE_SIZE_BYTES,
        "test sizing invariant: fixture must sit under the current auto-gen cap"
    );
    let chunk = b"export interface I { x: number; }\n";
    let mut bytes: Vec<u8> = Vec::with_capacity(target_bytes);
    while bytes.len() < target_bytes {
        bytes.extend_from_slice(chunk);
    }
    fs::write(dir.path().join("dom.generated.d.ts"), bytes).unwrap();

    // Companion small valid file so the dir isn't single-file.
    fs::write(dir.path().join("ok.ts"), b"export const x: number = 0;\n").unwrap();

    let report = structure_json(dir.path()).unwrap_or_else(|e| panic!("{e}"));

    // No skip indicator: `files_skipped` and `warnings` are additive
    // fields, omitted entirely on a clean scan.
    assert!(
        report.get("files_skipped").is_none(),
        "a .d.ts under the 64 MiB auto-gen cap MUST NOT be skipped; report={}",
        report
    );
    assert!(
        report.get("warnings").is_none(),
        "a .d.ts under the 64 MiB auto-gen cap must produce no warnings; report={}",
        report
    );

    // And the declaration file was actually analysed, not skipped.
    let files = report
        .get("files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        files.len(),
        2,
        "both the .d.ts and the .ts must be analysed; report={}",
        report
    );
    let dts_analysed = files.iter().any(|f| {
        f.get("path")
            .and_then(|p| p.as_str())
            .map_or(false, |p| p.ends_with("dom.generated.d.ts"))
    });
    assert!(
        dts_analysed,
        "the .d.ts must appear among the analysed files; report={}",
        report
    );
}

/// Negative control: a normal `.ts` file far below the 2 GiB source
/// cap MUST NOT be skipped — the auto-gen cap doesn't apply to non
/// auto-gen extensions. (Sized above the historical 512 KB auto-gen
/// cap so this also proves a normal source file was never subject to
/// the auto-gen cap, old or new.)
#[test]
fn test_normal_ts_file_below_source_cap_not_skipped() {
    let dir = tempdir().unwrap();

    // 768 KB normal .ts: above the OLD auto-gen cap but far below the
    // current 2 GiB source cap. Should be analysed normally.
    let target_bytes = 768 * 1024;
    assert!(
        (target_bytes as u64) < MAX_FILE_SIZE_BYTES,
        "test sizing invariant: fixture must sit under the current source cap"
    );
    let chunk = b"export const a: number = 1;\n";
    let mut bytes: Vec<u8> = Vec::with_capacity(target_bytes);
    while bytes.len() < target_bytes {
        bytes.extend_from_slice(chunk);
    }
    fs::write(dir.path().join("big.ts"), bytes).unwrap();

    let report = structure_json(dir.path()).unwrap_or_else(|e| panic!("{e}"));

    // files_skipped is omitted on clean inputs (skip_serializing_if).
    assert!(
        report.get("files_skipped").is_none(),
        "a normal .ts far below the 2 GiB source cap MUST NOT be skipped \
         (auto-gen cap applies only to .d.ts/.min.js/.bundle.* extensions); \
         report={}",
        report
    );
    let files = report
        .get("files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !files.is_empty(),
        "structure must still analyse the valid .ts file; report={}",
        report
    );
}

/// `test_skip_oversize_file_with_warning` — the headline test from
/// the milestone spec. Synthetic dir with 1 valid file + 1 file >
/// the auto-gen cap; the scan must complete, `files_skipped` must
/// include the oversize file, and `warnings` must name it.
///
/// **Why `#[ignore]`:** under the stretched policy the auto-gen cap is
/// [`MAX_AUTOGEN_FILE_SIZE_BYTES`] (64 MiB), so the smallest fixture
/// that crosses it is 64 MiB + 16 KB — far beyond the ~10 MB fixture
/// budget for CLI end-to-end tests. The oversized file is
/// stat-checked, never parsed, so the run itself is fast in either
/// profile. Opt-in:
///
/// `timeout 600 cargo test -p tldr-cli --test typescript_large_file_perf_v1 -- --ignored test_skip_oversize_file_with_warning`
#[test]
#[ignore = "requires a 64 MiB + 16 KB fixture (MAX_AUTOGEN_FILE_SIZE_BYTES + 16 KB) to cross the stretched auto-gen cap; see doc comment for the opt-in command"]
fn test_skip_oversize_file_with_warning() {
    let dir = make_oversize_dts_dir();

    let started = Instant::now();
    let report = structure_json(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let elapsed = started.elapsed();

    // Must finish well under the historical 30 s timeout — the cap
    // policy is what makes this fast. A 5 s budget gives huge
    // headroom on slow CI runners while still catching a regression.
    assert!(
        elapsed < Duration::from_secs(15),
        "structure took {:?}; oversize policy must skip the over-cap \
         auto-gen file rather than analyse it",
        elapsed,
    );

    let files_skipped = report
        .get("files_skipped")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        files_skipped, 1,
        "structure must report files_skipped=1 for the oversize \
         .d.ts; report={}",
        report
    );

    let warnings = report
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        warnings.len(),
        1,
        "structure must emit exactly one warning for the oversize \
         file; warnings={:?}",
        warnings
    );
    let warning = warnings[0].as_str().unwrap_or("");
    assert!(
        warning.contains("dom.generated.d.ts"),
        "warning must reference the skipped file path; got: {}",
        warning
    );
    assert!(
        warning.contains("exceeds"),
        "warning must use the documented 'exceeds' phrasing; got: {}",
        warning
    );

    // Sanity: the small file is still analysed.
    let files = report
        .get("files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !files.is_empty(),
        "structure must still analyse the valid .ts file; report={:?}",
        files
    );
}

/// `test_dts_files_have_lower_cap` — synthetic `.d.ts` that exceeds
/// the auto-gen-specific cap but stays under the general source cap.
/// Must be skipped (proving the auto-gen branch fires, with the
/// "auto-generated/minified files" warning label).
///
/// **Why `#[ignore]`:** the straddle band under the stretched policy
/// is (64 MiB, 2 GiB); the smallest honest fixture is
/// 1.5 × [`MAX_AUTOGEN_FILE_SIZE_BYTES`] = 96 MiB — far beyond the
/// ~10 MB fixture budget. The oversized file is stat-checked, never
/// parsed, so the run itself is fast in either profile. Opt-in:
///
/// `timeout 600 cargo test -p tldr-cli --test typescript_large_file_perf_v1 -- --ignored test_dts_files_have_lower_cap`
#[test]
#[ignore = "requires a 96 MiB fixture (1.5 x MAX_AUTOGEN_FILE_SIZE_BYTES) to straddle the stretched caps; see doc comment for the opt-in command"]
fn test_dts_files_have_lower_cap() {
    let dir = tempdir().unwrap();

    // 1.5x the real auto-gen cap: strictly inside the (auto-gen,
    // source) straddle band. Sized deliberately so the auto-gen
    // branch is provably the rule that applied (a source-capped file
    // would need 2 GiB).
    let target_bytes =
        MAX_AUTOGEN_FILE_SIZE_BYTES as usize + MAX_AUTOGEN_FILE_SIZE_BYTES as usize / 2;
    assert!(
        target_bytes < MAX_FILE_SIZE_BYTES as usize,
        "test sizing invariant: must straddle the two caps so the \
         auto-gen branch is what fires"
    );
    let chunk = b"export type T = number;\n";
    let mut bytes: Vec<u8> = Vec::with_capacity(target_bytes);
    while bytes.len() < target_bytes {
        bytes.extend_from_slice(chunk);
    }
    fs::write(dir.path().join("autogen.d.ts"), bytes).unwrap();

    // Companion small valid file so the dir isn't empty.
    fs::write(dir.path().join("ok.ts"), b"export const x: number = 0;\n").unwrap();

    let report = structure_json(dir.path()).unwrap_or_else(|e| panic!("{e}"));

    let files_skipped = report
        .get("files_skipped")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(
        files_skipped, 1,
        "a .d.ts above the auto-gen cap but below the source cap MUST be \
         skipped under the auto-gen policy; report={}",
        report,
    );

    let warnings = report
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let warning = warnings.first().and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        warning.contains("autogen.d.ts"),
        "warning must reference the skipped .d.ts; got: {}",
        warning
    );
    assert!(
        warning.contains("auto-generated/minified files"),
        "warning must label the skipped file under the auto-gen \
         category (so users know why a sub-source-cap file was \
         rejected when the headline cap is the source cap); got: {}",
        warning
    );
}
