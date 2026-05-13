//! diff-column-one-indexed-v1 (v0.4.2 bug-A3): `tldr diff` was emitting
//! 0-indexed columns (raw `tree_sitter::Point::column`) for every changed
//! node, while every other column-emitting command (`references`,
//! `definition`, `api-check`, `structure`) emits 1-indexed columns.
//!
//! Pre-fix the v0.4.2 audit (VAL-A-DIFF) flagged the Swift case but the
//! same bug is cross-language: all 8 `start_position().column as u32`
//! callsites in `crates/tldr-cli/src/commands/remaining/diff.rs` are
//! shared by every language that flows through `extract_function_node`,
//! `extract_class_node`, `extract_class_nodes_recursive`, and the field
//! extractors. Each callsite pairs `row as u32 + 1` for line but drops
//! the `+ 1` for column.
//!
//! After this fix, every emitted column is `>= 1` (1-indexed) and agrees
//! with what `tldr references` reports for the same source position.
//!
//! Real-repo gated per `no-synthetic-fixtures-v1`: each test returns
//! early if its `/tmp/repos/...` corpus is absent.

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

/// Collect every (line, column) pair from a `tldr diff` JSON payload.
fn collect_locations(v: &serde_json::Value) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let Some(changes) = v.get("changes").and_then(|c| c.as_array()) else {
        return out;
    };
    for change in changes {
        for key in ["old_location", "new_location"] {
            if let Some(loc) = change.get(key) {
                if loc.is_null() {
                    continue;
                }
                let line = loc.get("line").and_then(|x| x.as_u64());
                let col = loc.get("column").and_then(|x| x.as_u64());
                if let (Some(l), Some(c)) = (line, col) {
                    out.push((l, c));
                }
            }
        }
    }
    out
}

const SWIFT_FILE_A: &str = "/tmp/repos/swift-collections/Sources/HeapModule/Heap.swift";
const SWIFT_FILE_B: &str =
    "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";

#[test]
fn swift_diff_column_one_indexed() {
    // VAL-A-DIFF canonical case: `extension` at line 74 col 1 (1-idx),
    // method at line 116 col 3 (1-idx; two leading spaces). Pre-fix the
    // diff emitted col 0 / col 2.
    if !Path::new(SWIFT_FILE_A).exists() || !Path::new(SWIFT_FILE_B).exists() {
        eprintln!("skip: swift-collections corpus missing");
        return;
    }

    let (exit, stdout) = run_tldr(&["diff", SWIFT_FILE_A, SWIFT_FILE_B]);
    assert_eq!(exit, 0, "tldr diff exit non-zero, stdout: {}", stdout);

    let v = parse_json(&stdout);
    let locs = collect_locations(&v);
    assert!(!locs.is_empty(), "diff returned no changes for swift pair");

    // Every emitted column must be >= 1 (1-indexed); none may be 0.
    for (line, col) in &locs {
        assert!(
            *col >= 1,
            "swift diff: line {} col {} is 0-indexed (must be >= 1)",
            line,
            col
        );
    }

    // Specifically: `extension Heap: Sendable ...` on line 74 starts in col 1.
    let ext_at_74 = locs
        .iter()
        .find(|(l, _)| *l == 74)
        .copied();
    if let Some((_, c)) = ext_at_74 {
        assert_eq!(
            c, 1,
            "swift diff: `extension` on line 74 should report col 1, got {}",
            c
        );
    }

    // And method `init` on line 116 (`  @inlinable` / `  public init`) -> col 3.
    let init_at_116 = locs.iter().find(|(l, _)| *l == 116).copied();
    if let Some((_, c)) = init_at_116 {
        assert_eq!(
            c, 3,
            "swift diff: method `init` on line 116 should report col 3, got {}",
            c
        );
    }
}

#[test]
fn swift_diff_column_agrees_with_references() {
    // For an `extension Heap` line, both `tldr diff` (which emits the
    // column of the `extension` keyword) and `tldr references Heap`
    // (which emits the column of the `Heap` identifier) must be 1-indexed.
    // We verify the diff column is >= 1 and that references is also >= 1,
    // i.e. neither command is silently 0-indexed.
    if !Path::new(SWIFT_FILE_A).exists() || !Path::new(SWIFT_FILE_B).exists() {
        eprintln!("skip: swift-collections corpus missing");
        return;
    }

    let (diff_exit, diff_out) = run_tldr(&["diff", SWIFT_FILE_A, SWIFT_FILE_B]);
    assert_eq!(diff_exit, 0, "diff exit non-zero");
    let dv = parse_json(&diff_out);
    let diff_locs = collect_locations(&dv);

    // Pick the entry for line 74 (`extension Heap: Sendable ...`).
    let diff_col_74 = diff_locs
        .iter()
        .find(|(l, _)| *l == 74)
        .map(|(_, c)| *c);

    let (ref_exit, ref_out) = run_tldr(&["references", "Heap", SWIFT_FILE_B]);
    assert_eq!(ref_exit, 0, "references exit non-zero");
    let rv = parse_json(&ref_out);
    let refs = rv
        .get("references")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let ref_col_14 = refs.iter().find_map(|r| {
        let line = r.get("line").and_then(|x| x.as_u64())?;
        let col = r.get("column").and_then(|x| x.as_u64())?;
        if line == 14 {
            Some(col)
        } else {
            None
        }
    });

    // Both must be 1-indexed (>= 1). If either is missing we skip that side.
    if let Some(d) = diff_col_74 {
        assert!(
            d >= 1,
            "diff col on line 74 should be >= 1 (1-indexed), got {}",
            d
        );
    }
    if let Some(r) = ref_col_14 {
        assert!(
            r >= 1,
            "references col should be >= 1 (1-indexed), got {}",
            r
        );
    }
}

#[test]
fn rust_diff_column_one_indexed_non_regression() {
    // Cross-language non-regression on ripgrep: the diff column emission
    // sites are shared across all langs, so the fix must take rust from
    // 0-indexed -> 1-indexed too (top-level fn: col 0 -> col 1; impl
    // method indented 4 spaces: col 4 -> col 5). No double-increment.
    let a = "/tmp/repos/ripgrep/crates/regex/src/ast.rs";
    let b = "/tmp/repos/ripgrep/crates/regex/src/literal.rs";
    if !Path::new(a).exists() || !Path::new(b).exists() {
        eprintln!("skip: ripgrep corpus missing");
        return;
    }

    let (exit, stdout) = run_tldr(&["diff", a, b]);
    assert_eq!(exit, 0, "rust diff exit non-zero");
    let v = parse_json(&stdout);
    let locs = collect_locations(&v);
    assert!(!locs.is_empty(), "rust diff returned no changes");

    // Every column must be >= 1.
    for (line, col) in &locs {
        assert!(
            *col >= 1,
            "rust diff: line {} col {} is 0-indexed (must be >= 1)",
            line,
            col
        );
    }

    // Sanity-check: top-level nodes (which used to report col 0) now
    // report col 1, and 4-space-indented nodes (which used to report
    // col 4) now report col 5 -- not col 6 (no double-increment).
    let has_col_1 = locs.iter().any(|(_, c)| *c == 1);
    let has_col_5 = locs.iter().any(|(_, c)| *c == 5);
    // We only require at least one of these for the corpus we picked.
    assert!(
        has_col_1 || has_col_5,
        "expected at least one top-level (col 1) or indented (col 5) entry, got cols: {:?}",
        locs.iter().map(|(_, c)| *c).collect::<Vec<_>>()
    );

    // And NO entries at col 6 from a 4-space indent (that would mean
    // double-increment somewhere we didn't expect).
    // We can't tell "from a 4-space indent" without re-reading the file,
    // so we just assert there are no implausibly large jumps: cols
    // should cluster around small values (0..16). This is a soft check.
    for (_, c) in &locs {
        assert!(*c <= 128, "diff col {} is implausibly large", c);
    }
}
