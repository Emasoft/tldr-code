//! DEPS-AND-SURFACE-GRACEFUL-DEGRADE-V1 — soft-skip oversize files in `tldr deps`
//! and emit empty-but-valid JSON from `tldr surface` when no static entrypoint
//! exists.
//!
//! Prior to M-Z11, the deps and surface commands aborted on inputs that other
//! commands (`vuln`, `secure`, `structure`) tolerate gracefully:
//!
//! - `tldr deps --lang typescript /tmp/repos/ts-dom-gen` →
//!   `Error: File too large: dom.generated.d.ts is 3MB (max 1MB)` (exit 6)
//!   even though the rest of the repo is healthy.
//! - `tldr surface --lang typescript /tmp/repos/ts-dom-gen` →
//!   `Error: Parse error in /tmp/repos/ts-dom-gen: typescript package
//!   'ts-dom-gen' found ... but no supported static entrypoint was found.`
//!   (exit 10) even though that's a normal state for a build-tooling repo.
//!
//! These tests synthesise the same shapes and assert both commands now
//! complete with exit 0 and a structured `warnings` array.

use assert_cmd::Command;
use std::fs;
use std::io::Write as _;
use tempfile::tempdir;
use tldr_core::fs::oversize::MAX_AUTOGEN_FILE_SIZE_BYTES;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// `tldr deps` MUST soft-skip oversize files (per the central `oversize`
/// policy) and emit valid JSON — same pattern as `vuln`, `secure`,
/// `structure`. This test reproduces the canonical
/// `dom.generated.d.ts` shape: one valid `.ts` plus one oversize `.d.ts`
/// in a tempdir.
///
/// FIXTURE CHOICE — SPARSE, NOT MATERIALISED (deps-oversize-fixture-v1): the
/// exercised command path is `DepsArgs::run` → `analyze_dependencies` →
/// `partition_files_by_size` → `check_size`, which STATS the file and, on
/// `Oversize`, skips it WITHOUT ever reading it — so a sparse fixture
/// (`File::set_len`, the same trick `fs::oversize`'s own boundary tests and
/// `ooxml_structure_v1` use) exercises the REAL 512 MiB auto-gen cap at
/// ~zero I/O cost. The injectable-cap seam alternative (secure.rs
/// `max_file_size_override`, a `#[arg(skip)]` in-process field) is
/// unreachable from a spawned-binary integration test without adding a new
/// env-var surface, and `#[ignore]`-gating would only hide a test that a
/// sparse fixture keeps fast and in the default path. The leading
/// declaration keeps the artefact shape recognisable; the zero-filled hole
/// beyond it is never parsed on this path.
#[test]
fn test_deps_skips_oversize_files_gracefully() {
    let dir = tempdir().unwrap();

    // 1 valid TypeScript source.
    fs::write(
        dir.path().join("good.ts"),
        b"export function safe(): number { return 1; }\n",
    )
    .unwrap();

    // 1 oversize auto-generated `.d.ts` (above the autogen cap so the
    // size policy triggers). Sparse: `set_len` extends the logical size
    // cap + 16KB past the small declaration header without writing those
    // bytes — the deps path only stats oversize files, never reads them.
    let mut f = fs::File::create(dir.path().join("dom.generated.d.ts")).unwrap();
    f.write_all(b"export declare const padded: string;\n")
        .unwrap();
    f.set_len(MAX_AUTOGEN_FILE_SIZE_BYTES + 16 * 1024).unwrap(); // cap + 16KB
    drop(f);

    let output = tldr_cmd()
        .arg("deps")
        .arg("--lang")
        .arg("typescript")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("deps must execute");

    assert!(
        output.status.success(),
        "deps must NOT abort on an oversize file (status: {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "deps stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });

    // Validate files_skipped + warnings include the oversize file.
    let files_skipped = json
        .get("files_skipped")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        files_skipped >= 1,
        "files_skipped must be >= 1 when an oversize file is present, got {} (json: {})",
        files_skipped,
        json
    );

    let warnings = json
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("dom.generated.d.ts")),
        "warnings must mention the oversize dom.generated.d.ts file; got: {:?}",
        warnings
    );
}

/// `tldr surface` MUST emit a valid empty-surface JSON document with a
/// structured warning when a TypeScript directory has no resolvable
/// static entrypoint, instead of aborting with exit 10.
#[test]
fn test_surface_emits_empty_when_no_entrypoint() {
    let dir = tempdir().unwrap();

    // package.json with NO `main` / `module` / `exports` / `bin` and
    // NO standard entrypoint file (no `index.ts`, `src/index.ts`, etc.)
    // — i.e. a build-tooling repo like `ts-dom-gen` whose package.json
    // only exposes `scripts`.
    fs::write(
        dir.path().join("package.json"),
        br#"{
  "name": "ts-empty-package",
  "version": "0.0.1",
  "private": true,
  "scripts": {
    "build": "echo build"
  }
}
"#,
    )
    .unwrap();

    let output = tldr_cmd()
        .arg("surface")
        .arg("--lang")
        .arg("typescript")
        .arg(dir.path().to_str().unwrap())
        .arg("-f")
        .arg("json")
        .output()
        .expect("surface must execute");

    assert!(
        output.status.success(),
        "surface must NOT abort when no static entrypoint exists (status: {:?}, stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "surface stdout must be valid JSON; err: {}; stdout: {}",
            e, stdout
        )
    });

    let apis = json
        .get("apis")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        apis.is_empty(),
        "surface must emit an empty `apis: []` for an entrypoint-less directory; got {} entries",
        apis.len()
    );

    let warnings = json
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !warnings.is_empty(),
        "surface must emit at least one warning explaining the empty result; json: {}",
        json
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("entrypoint")),
        "warning must mention 'entrypoint' so users understand why the surface is empty; got: {:?}",
        warnings
    );
}
