//! rust-deps-wiring-v1 (v0.4.2 bug-C5 / VAL-RUST-DEPS / CF-RUST-DEPS)
//!
//! Pre-fix audit assertion: `tldr deps /tmp/repos/ripgrep` returns
//! "0 modules and 0 edges". In practice the resolver produces ~172
//! edges, but the *quality* is severely degraded: `mod tests;`
//! declarations at the bottom of unit-test-bearing files (e.g.
//! `crates/cli/src/escape.rs`, `crates/searcher/src/lines.rs`)
//! resolve via a global bare-name index match to the **integration
//! test** file `tests/tests.rs`, producing 36+ spurious incoming
//! edges to that single file. Workspace cross-crate `use ignore::...`
//! from `crates/core/main.rs` falls through entirely.
//!
//! Post-fix:
//!   1. `mod foo;` declarations resolve to a SIBLING file
//!      (`<dir>/foo.rs` or `<dir>/foo/mod.rs`), not to a global
//!      bare-name match somewhere else in the tree;
//!   2. `use crate::foo::bar` resolves relative to the current file's
//!      OWNING crate (discovered via the nearest ancestor Cargo.toml
//!      that owns a `src/lib.rs` or `src/main.rs`);
//!   3. workspace cross-crate `use other_crate::foo` resolves to that
//!      crate's lib.rs root via a crate-name index;
//!   4. `std::`, `core::`, `alloc::` imports are filtered before
//!      resolution.
//!
//! Real-repo gated per no-synthetic-fixtures-v1: each test returns
//! early when its `/tmp/repos/<repo>` corpus is absent.

/// True when `dir` exists AND contains at least one non-`.git` regular
/// file (or is itself a regular file). CI/dev environments sometimes
/// leave the corpus directories present as empty skeletons (a `git`
/// clone with no working tree); `Path::exists()` is then `true` but every
/// analysis returns 0 files. These real-repo tests must skip cleanly in
/// that case rather than assert against empty output.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(p) else {
            return false;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => {
                    if walk(&path, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() {
        return true;
    }
    root.exists() && walk(root, 0)
}


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

fn run_tldr(args: &[&str]) -> (i32, String) {
    let out = Command::new(tldr_bin())
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

const RG_CORPUS: &str = "/tmp/repos/ripgrep";
const KT_CORPUS: &str = "/tmp/repos/kotlin-datetime";

// ============================================================================
// TEST 1: `tldr deps <rust-repo>` must produce a non-empty module graph
//         AND must not pile every spurious bare-name match onto a single
//         integration-test file.
// ============================================================================
#[test]
fn rust_deps_has_non_zero_modules() {
    if !corpus_ready(RG_CORPUS) {
        eprintln!(
            "[skip] rust_deps_has_non_zero_modules: corpus {} not present",
            RG_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", RG_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on ripgrep; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert!(
        !internal.is_empty(),
        "deps must list rust files in internal_dependencies; got empty map"
    );

    let total_edges: usize = internal
        .values()
        .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
        .sum();
    assert!(
        total_edges > 0,
        "rust deps must aggregate imports into a graph (total_edges > 0); \
         got {} edges across {} files",
        total_edges,
        internal.len()
    );

    // Quality gate: the pre-fix bug funnelled 36+ edges into
    // `tests/tests.rs` via a global bare-name `mod tests;` match. After
    // the fix, sibling-resolution must keep that figure bounded — any
    // single target receiving >20 incoming edges in ripgrep is a strong
    // signal that the bare-name fallback is misfiring.
    let mut incoming: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_src, deps) in &internal {
        if let Some(arr) = deps.as_array() {
            for d in arr {
                if let Some(t) = d.as_str() {
                    *incoming.entry(t.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    if let Some(rogue) = incoming.get("tests/tests.rs") {
        assert!(
            *rogue <= 5,
            "tests/tests.rs has {} incoming edges — bare-name `mod tests;` \
             at the bottom of crate-internal files is leaking into the \
             top-level integration test file. Pre-fix: 36 incoming. \
             Sibling-resolution must keep this <= 5.",
            rogue
        );
    }
}

// ============================================================================
// TEST 2: at least one same-crate `use crate::...` import inside ripgrep
//         must resolve to another .rs file in the same crate's src/ tree.
// ============================================================================
#[test]
fn rust_deps_resolves_intra_crate_use() {
    if !corpus_ready(RG_CORPUS) {
        eprintln!(
            "[skip] rust_deps_resolves_intra_crate_use: corpus {} not present",
            RG_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", RG_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on ripgrep; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();

    // Concrete same-crate edge we know exists in ripgrep:
    //   crates/core/main.rs has `use crate::flags::{HiArgs, SearchMode};`
    //   which must resolve to crates/core/flags/mod.rs (sibling submodule
    //   of main.rs inside the `core` crate's src tree at crates/core/).
    let main_deps = internal
        .get("crates/core/main.rs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let main_targets: Vec<String> = main_deps
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    assert!(
        main_targets
            .iter()
            .any(|t| t == "crates/core/flags/mod.rs"),
        "crates/core/main.rs must resolve `use crate::flags` to its \
         sibling `crates/core/flags/mod.rs`. Actual targets: {:?}",
        main_targets
    );

    // Additional broad check: at least one pair where source and target
    // live under the same `crates/<name>/src/` (or `crates/<name>/`)
    // ancestor — confirms intra-crate path-based wiring on more than
    // one crate.
    fn same_crate(src: &str, tgt: &str) -> Option<String> {
        let s_parts: Vec<&str> = src.split('/').collect();
        let t_parts: Vec<&str> = tgt.split('/').collect();
        if s_parts.len() >= 2
            && t_parts.len() >= 2
            && s_parts[0] == "crates"
            && t_parts[0] == "crates"
            && s_parts[1] == t_parts[1]
        {
            Some(s_parts[1].to_string())
        } else {
            None
        }
    }

    let mut intra_pairs: Vec<(String, String, String)> = Vec::new();
    for (src, deps) in &internal {
        if let Some(arr) = deps.as_array() {
            for d in arr {
                if let Some(tgt) = d.as_str() {
                    if let Some(cr) = same_crate(src, tgt) {
                        intra_pairs.push((cr, src.clone(), tgt.to_string()));
                    }
                }
            }
        }
    }

    assert!(
        intra_pairs.len() >= 5,
        "expected >= 5 intra-crate edges across ripgrep's workspace; got {} \
         (sample: {:?})",
        intra_pairs.len(),
        intra_pairs.iter().take(3).collect::<Vec<_>>()
    );
}

// ============================================================================
// TEST 3 (non-regression): kotlin deps still wires up correctly.
//         W-H's kotlin-deps-wiring-v1 fix must not be broken by the
//         rust-only changes.
// ============================================================================
#[test]
fn kotlin_deps_still_wires() {
    if !corpus_ready(KT_CORPUS) {
        eprintln!(
            "[skip] kotlin_deps_still_wires: corpus {} not present",
            KT_CORPUS
        );
        return;
    }

    let (rc, out) = run_tldr(&["deps", KT_CORPUS, "--format", "json"]);
    assert_eq!(rc, 0, "deps must succeed on kotlin-datetime; got rc={}", rc);

    let v = parse_json(&out);
    let internal = v["internal_dependencies"]
        .as_object()
        .cloned()
        .unwrap_or_default();

    let total_edges: usize = internal
        .values()
        .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
        .sum();

    // W-H baseline: 317 internal edges across 223 files. Use a
    // conservative floor that still catches a regression where the rust
    // refactor accidentally rewired the kotlin path.
    assert!(
        total_edges >= 100,
        "kotlin deps non-regression: kotlin-datetime must still produce \
         >= 100 internal edges; got {} (was 317 at W-H fix time)",
        total_edges
    );
}
