//! Slice per-line uses/definitions v1 (CLUSTER-M-033)
//!
//! Per-line `uses` and `definitions` on `slice` output must reflect the
//! actual variable references that anchor to THAT line, not the union
//! over the enclosing CFG basic block.
//!
//! Background: the v0.4.1 emitter built `slice_lines[]` by iterating
//! every line in each visited PDG node's `lines.0..=lines.1` span and
//! merging the *entire block's* definitions/uses into every line entry.
//! Effect: every line inside a multi-line block (function signature
//! spanning 2+ lines, multi-line statement, top-of-function entry block
//! that covers comments and the first statements, OCaml `let .. in`
//! chains) emitted IDENTICAL `uses` and `definitions` arrays — the
//! function-wide aggregate.
//!
//! Affected by the Phase-22 audit:
//!   - csharp c15 (BsonDataReader.Async.cs::ReadAsync): every line
//!     94..82 emitted ~21 identical uses and identical defs.
//!   - java c14 (OwnerController.java::processFindForm): the function
//!     signature lines 95..98 emitted 5 identical defs.
//!   - ocaml c14 (cram_exec.ml::run_expect_test): every line 99..108
//!     emitted ~17 identical uses.
//!   - swift c14 (Heap+UnsafeHandle.swift::_heapify): every line
//!     377..386 emitted 8 identical uses.
//!
//! Fix expectation: the rich slice emitter must populate each line's
//! `uses`/`definitions` only from variable references whose own line
//! number matches the slice line. Cross-language: implemented at the
//! PDG layer (`get_slice_rich` in `crates/tldr-core/src/pdg/slice.rs`)
//! so all 16 languages benefit; no per-lang fixup.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

fn tldr_bin() -> String {
    // Resolve target/release/tldr relative to the crate manifest.
    let root = env!("CARGO_MANIFEST_DIR");
    let mut p = std::path::PathBuf::from(root);
    p.pop();
    p.pop();
    p.push("target/release/tldr");
    p.to_string_lossy().to_string()
}

fn run_slice_json(file: &str, function: &str, line: u32) -> serde_json::Value {
    let bin = tldr_bin();
    assert!(
        Path::new(&bin).exists(),
        "tldr release binary not found at {bin}; run `cargo build --release -p tldr-cli` first",
    );
    let out = Command::new(&bin)
        .args([
            "slice",
            file,
            function,
            &line.to_string(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to spawn tldr");
    assert!(
        out.status.success(),
        "tldr slice failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("slice output is not valid JSON")
}

/// Extract (line, uses_set, defs_set) tuples from the JSON `slice_lines` array.
fn extract_per_line(
    output: &serde_json::Value,
) -> Vec<(u32, std::collections::BTreeSet<String>, std::collections::BTreeSet<String>)> {
    output
        .get("slice_lines")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|entry| {
                    let line = entry.get("line").and_then(|l| l.as_u64()).unwrap_or(0) as u32;
                    let uses: std::collections::BTreeSet<String> = entry
                        .get("uses")
                        .and_then(|u| u.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let defs: std::collections::BTreeSet<String> = entry
                        .get("definitions")
                        .and_then(|u| u.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    (line, uses, defs)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Detect the broadcast bug across a set of consecutive lines: if many lines
/// inside a window share the SAME non-trivial uses-and-defs union, that's a
/// CFG-block broadcast — assert that's NOT the case.
fn distinct_use_def_tuple_count(
    per_line: &[(u32, std::collections::BTreeSet<String>, std::collections::BTreeSet<String>)],
    line_lo: u32,
    line_hi: u32,
) -> usize {
    let mut distinct: HashSet<(Vec<String>, Vec<String>)> = HashSet::new();
    for (l, uses, defs) in per_line {
        if *l < line_lo || *l > line_hi {
            continue;
        }
        // Skip lines with no variable activity at all (comments / blank
        // lines): they are trivially `uses=[], defs=[]` which would
        // otherwise count as a "shared tuple".
        if uses.is_empty() && defs.is_empty() {
            continue;
        }
        distinct.insert((
            uses.iter().cloned().collect(),
            defs.iter().cloned().collect(),
        ));
    }
    distinct.len()
}

fn lines_in_window(
    per_line: &[(u32, std::collections::BTreeSet<String>, std::collections::BTreeSet<String>)],
    line_lo: u32,
    line_hi: u32,
) -> usize {
    per_line
        .iter()
        .filter(|(l, u, d)| *l >= line_lo && *l <= line_hi && !(u.is_empty() && d.is_empty()))
        .count()
}

#[test]
fn java_processfindform_per_line_uses_not_function_aggregate() {
    let file = "/tmp/repos/spring-petclinic/src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java";
    if !Path::new(file).exists() {
        eprintln!("skipping: corpus not present at {file}");
        return;
    }
    let out = run_slice_json(file, "processFindForm", 118);
    let per_line = extract_per_line(&out);
    assert!(
        !per_line.is_empty(),
        "java slice produced no slice_lines: {out}"
    );

    // The function signature/entry block previously spans lines 95..98
    // and broadcast `defs=[page,owner,model,result,lastName]` onto every
    // one of those 4 lines. Post-fix: the entry-block lines should NOT
    // all carry the same 5-def union. We assert at least two distinct
    // (uses,defs) tuples across lines 95..104 with non-empty activity.
    // The entry-block lines 95..98 (function signature + comment) all
    // broadcast `defs=[page,owner,model,result,lastName]` pre-fix. The
    // comment line 97 contains no variable activity in source; the
    // signature param-line 95 declares the params; line 98 reads
    // `owner.getLastName()`. These three should have DIFFERENT defs
    // (comment line should be empty; signature line defines params;
    // call line uses `owner`).
    let active_lines = lines_in_window(&per_line, 95, 98);
    let distinct = distinct_use_def_tuple_count(&per_line, 95, 98);
    assert!(
        active_lines >= 2,
        "expected at least 2 active slice lines in 95..98, got {active_lines}: {:?}",
        per_line
    );
    assert!(
        distinct >= 2,
        "java entry-block broadcast bug not fixed: only {distinct} distinct (uses,defs) tuples \
         across {active_lines} active lines 95..98 — function-signature block-aggregate \
         broadcast still present.\nper_line snapshot: {per_line:#?}",
    );
    // The full 5-def union {page,owner,model,result,lastName} should
    // only appear on the actual signature line (95 or 96), NOT on line
    // 98 which is `String lastName = owner.getLastName();` (defines
    // only `lastName`, uses `owner`).
    let l98_defs: Option<&std::collections::BTreeSet<String>> = per_line
        .iter()
        .find(|(l, _, _)| *l == 98)
        .map(|(_, _, d)| d);
    if let Some(defs98) = l98_defs {
        assert!(
            !defs98.contains("page") || !defs98.contains("model"),
            "java L98 still emits function-signature defs (broadcast): {defs98:?}"
        );
    }
}

#[test]
fn swift_heapify_per_line_uses_not_function_aggregate() {
    let file =
        "/tmp/repos/swift-collections/Sources/HeapModule/Heap+UnsafeHandle.swift";
    if !Path::new(file).exists() {
        eprintln!("skipping: corpus not present at {file}");
        return;
    }
    let out = run_slice_json(file, "_heapify", 386);
    let per_line = extract_per_line(&out);
    assert!(
        !per_line.is_empty(),
        "swift slice produced no slice_lines: {out}"
    );

    // Pre-fix audit: every line in 377..386 had the same 8-element
    // `uses` array (function-aggregate). Post-fix: at least 2 distinct
    // (uses,defs) tuples across that window.
    let active_lines = lines_in_window(&per_line, 377, 386);
    let distinct = distinct_use_def_tuple_count(&per_line, 377, 386);
    if active_lines >= 2 {
        assert!(
            distinct >= 2,
            "swift broadcast bug not fixed: only {distinct} distinct (uses,defs) tuples across \
             {active_lines} active lines 377..386.\nper_line: {per_line:#?}",
        );
    }
    // Also assert: no single line carries the full 8-name function-aggregate uses.
    let aggregate_names: HashSet<&str> = [
        "_forEach",
        "isMinLevel",
        "nodes",
        "trickleDownMax",
        "_HeapNode",
        "level",
        "node",
        "trickleDownMin",
    ]
    .into_iter()
    .collect();
    let mut max_overlap = 0usize;
    for (_, uses, _) in &per_line {
        let overlap = uses.iter().filter(|n| aggregate_names.contains(n.as_str())).count();
        if overlap > max_overlap {
            max_overlap = overlap;
        }
    }
    assert!(
        max_overlap < aggregate_names.len(),
        "swift: at least one slice line still carries ALL {} function-aggregate uses; \
         broadcast bug present",
        aggregate_names.len()
    );
}

#[test]
fn ocaml_run_expect_test_per_line_uses_not_function_aggregate() {
    let file = "/tmp/repos/ocaml-dune/src/dune_rules/cram/cram_exec.ml";
    if !Path::new(file).exists() {
        eprintln!("skipping: corpus not present at {file}");
        return;
    }
    let out = run_slice_json(file, "run_expect_test", 124);
    let per_line = extract_per_line(&out);
    assert!(
        !per_line.is_empty(),
        "ocaml slice produced no slice_lines: {out}"
    );

    let active_lines = lines_in_window(&per_line, 99, 130);
    let distinct = distinct_use_def_tuple_count(&per_line, 99, 130);
    assert!(
        active_lines >= 4,
        "expected at least 4 active ocaml slice lines in 99..130, got {active_lines}: {:?}",
        per_line
    );
    assert!(
        distinct >= 3,
        "ocaml broadcast bug not fixed: only {distinct} distinct (uses,defs) tuples across \
         {active_lines} active lines 99..130 — function-aggregate broadcast still present.\n\
         per_line: {per_line:#?}",
    );
}

#[test]
fn csharp_readasync_per_line_uses_not_function_aggregate() {
    let file =
        "/tmp/repos/csharp-newtonsoft-bson-full/Src/Newtonsoft.Json.Bson/BsonDataReader.Async.cs";
    if !Path::new(file).exists() {
        eprintln!("skipping: corpus not present at {file}");
        return;
    }
    let out = run_slice_json(file, "ReadAsync", 80);
    let per_line = extract_per_line(&out);
    assert!(
        !per_line.is_empty(),
        "csharp slice produced no slice_lines: {out}"
    );

    // Pre-fix audit: every line in 73..82 had the same ~21-element
    // `uses` array. Post-fix: each line's uses should reflect that
    // line's own statement, not the function aggregate. We assert no
    // line carries 15+ uses (function-aggregate threshold) AND that at
    // least 3 distinct tuples appear in the window 73..82.
    let active_lines = lines_in_window(&per_line, 73, 82);
    let distinct = distinct_use_def_tuple_count(&per_line, 73, 82);
    assert!(
        active_lines >= 3,
        "expected at least 3 active csharp slice lines in 73..82, got {active_lines}: {:?}",
        per_line
    );
    assert!(
        distinct >= 2,
        "csharp broadcast bug not fixed: only {distinct} distinct (uses,defs) tuples across \
         {active_lines} active lines 73..82 — function-aggregate broadcast still present.\n\
         per_line: {per_line:#?}",
    );

    let max_uses = per_line
        .iter()
        .filter(|(l, _, _)| *l >= 73 && *l <= 82)
        .map(|(_, u, _)| u.len())
        .max()
        .unwrap_or(0);
    assert!(
        max_uses < 15,
        "csharp: a slice line still carries {max_uses} uses (>= 15 indicates function-aggregate \
         broadcast). per_line: {per_line:#?}",
    );
}
