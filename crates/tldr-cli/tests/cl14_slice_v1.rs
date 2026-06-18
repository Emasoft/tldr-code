//! cl14-slice-v1 (v0.5.0 CL-14, GH #80)
//!
//! Tests that `tldr slice` honors slice *direction* within a single basic
//! block (single-block CFG), performing intra-block def-use traversal instead
//! of collapsing to the full block line range.
//!
//! # Bug (GH #80)
//!
//! For functions whose body is a single straight-line CFG basic block (very
//! common for short methods across languages), `tldr slice` ignored the
//! requested direction and returned the *entire* function body for both
//! `--direction backward` and `--direction forward`.
//!
//! Root cause: a visited PDG node corresponds to a CFG *basic block* — a
//! multi-line span. The slice line-mapping expanded each visited node's whole
//! `lines.0..=lines.1` range, so when the criterion line sat in the middle of
//! a block, every line of the block (including statements *after* the
//! criterion for a backward slice, and *before* it for a forward slice)
//! was emitted. Backward reachability from the criterion was never honored.
//!
//! `tldr chop` was already correct because it intersects forward(source) with
//! backward(target) and clips to the requested interval, which cancels the
//! over-inclusion. This test uses `chop` semantics as the reference for what
//! a directional slice should respect.
//!
//! # Fix
//!
//! Within the basic block(s) reached by the slice, restrict the emitted lines
//! to those connected to the criterion line via intra-block data dependence
//! (DFG def-use chains), honoring direction:
//! - backward: criterion line + lines that (transitively) *define* values used
//!   at the criterion. Never include lines that are only reachable forward.
//! - forward: criterion line + lines that (transitively) *use* values defined
//!   at the criterion.
//!
//! # Invariants asserted (real corpora)
//!
//! For a backward slice from criterion line `c`:
//!   1. No emitted statement line is strictly greater than `c`
//!      (a backward slice cannot include code that runs after the criterion).
//!   2. `c` itself is in the slice.
//! For a forward slice from criterion line `c`:
//!   3. No emitted statement line is strictly less than `c`.
//!   4. `c` itself is in the slice.
//!   5. backward != forward (direction is actually honored — the bug made
//!      them identical).

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use std::process::Command;

/// Swift corpus: `_HeapNode.swift` `init(offset:level:)` spans lines 23-30 as
/// a single straight-line block:
///   23  internal init(offset: Int, level: Int) {
///   24    assert(offset >= 0)
///   25  #if COLLECTIONS_INTERNAL_CHECKS
///   26    assert(level == Self.level(forOffset: offset))
///   27  #endif
///   28    self.offset = offset
///   29    self.level = level
///   30  }
const SWIFT_FILE: &str =
    "/tmp/tldr_corpora/swift-collections/Sources/HeapModule/_HeapNode.swift";

/// Scala corpus: `ByteStack.scala` `push(stack, op)` spans lines 39-47 as a
/// single straight-line block:
///   39  def push(stack: js.Array[Int], op: Byte): js.Array[Int] = {
///   40    val c = stack(0)
///   41    val use = growIfNeeded(stack, c)
///   42    val s = (c >> 3) + 1
///   43    val shift = (c & 7) << 2
///   44    use(s) = (use(s) & ~(0xffffffff << shift)) | (op << shift)
///   45    use(0) += 1
///   46    use
///   47  }
const SCALA_FILE: &str =
    "/tmp/tldr_corpora/scala-cats-effect/core/js/src/main/scala/cats/effect/ByteStack.scala";

/// Run `tldr slice <file> <fn> <line> -d <dir>` and return the `lines` array.
fn run_slice(file: &str, function: &str, line: u32, direction: &str) -> Vec<u32> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file,
            function,
            &line.to_string(),
            "-d",
            direction,
            "-q",
        ])
        .output()
        .expect("failed to execute tldr slice");

    assert!(
        output.status.success(),
        "slice should succeed for {file}::{function}:{line} [{direction}]: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("slice output not valid JSON: {e}\nstdout: {stdout}"));

    v["lines"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_u64().unwrap() as u32).collect())
        .unwrap_or_default()
}

/// Lines that carry actual statement code (used to ignore the closing brace /
/// signature lines that some backends attach to the criterion's block for
/// structural reasons). We restrict the "after the criterion" assertion to
/// statement lines so the test targets the real bug — over-inclusion of
/// downstream *statements* — and is not brittle to a trailing `}` line.
fn statement_lines(file: &str, function: &str, line: u32, direction: &str) -> Vec<u32> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args([
            "slice",
            file,
            function,
            &line.to_string(),
            "-d",
            direction,
            "-q",
        ])
        .output()
        .expect("failed to execute tldr slice");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let mut lines = Vec::new();
    if let Some(arr) = v["slice_lines"].as_array() {
        for sl in arr {
            let l = sl["line"].as_u64().unwrap() as u32;
            let code = sl["code"].as_str().unwrap_or("").trim();
            // Skip empty lines and lines that are purely a closing brace.
            if code.is_empty() || code == "}" {
                continue;
            }
            lines.push(l);
        }
    }
    lines
}

fn assert_backward_excludes_after(file: &str, function: &str, criterion: u32, label: &str) {
    let lines = run_slice(file, function, criterion, "backward");
    assert!(
        lines.contains(&criterion),
        "{label}: backward slice from {criterion} must contain the criterion; got {lines:?}"
    );

    let stmt_lines = statement_lines(file, function, criterion, "backward");
    let after: Vec<u32> = stmt_lines.iter().copied().filter(|&l| l > criterion).collect();
    assert!(
        after.is_empty(),
        "{label}: backward slice from {criterion} must NOT include statement lines AFTER \
         the criterion (a backward slice cannot depend on code that runs later); \
         offending lines: {after:?}; full lines: {lines:?}"
    );
}

fn assert_forward_excludes_before(file: &str, function: &str, criterion: u32, label: &str) {
    let lines = run_slice(file, function, criterion, "forward");
    assert!(
        lines.contains(&criterion),
        "{label}: forward slice from {criterion} must contain the criterion; got {lines:?}"
    );

    let stmt_lines = statement_lines(file, function, criterion, "forward");
    let before: Vec<u32> = stmt_lines
        .iter()
        .copied()
        .filter(|&l| l < criterion)
        .collect();
    assert!(
        before.is_empty(),
        "{label}: forward slice from {criterion} must NOT include statement lines BEFORE \
         the criterion (a forward slice only contains code affected by the criterion); \
         offending lines: {before:?}; full lines: {lines:?}"
    );
}

#[test]
fn swift_backward_slice_excludes_statements_after_criterion() {
    if !corpus_ready(SWIFT_FILE) {
        eprintln!("[skip] swift slice: corpus file not present");
        return;
    }
    // Criterion line 28 (`self.offset = offset`). Line 29 (`self.level = level`)
    // runs after it and must be excluded from the backward slice.
    assert_backward_excludes_after(SWIFT_FILE, "init", 28, "swift/_HeapNode.init");
}

#[test]
fn swift_forward_slice_excludes_statements_before_criterion() {
    if !corpus_ready(SWIFT_FILE) {
        eprintln!("[skip] swift slice: corpus file not present");
        return;
    }
    // Criterion line 29 (`self.level = level`). Lines 24/26/28 run before it
    // and must be excluded from the forward slice.
    assert_forward_excludes_before(SWIFT_FILE, "init", 29, "swift/_HeapNode.init");
}

#[test]
fn swift_backward_and_forward_differ() {
    if !corpus_ready(SWIFT_FILE) {
        eprintln!("[skip] swift slice: corpus file not present");
        return;
    }
    // The bug made backward == forward (both = whole body). They must differ.
    let back = run_slice(SWIFT_FILE, "init", 28, "backward");
    let fwd = run_slice(SWIFT_FILE, "init", 28, "forward");
    assert_ne!(
        back, fwd,
        "swift/_HeapNode.init: backward and forward slices from line 28 must differ \
         (direction must be honored); both = {back:?}"
    );
}

#[test]
fn scala_backward_slice_excludes_statements_after_criterion() {
    if !corpus_ready(SCALA_FILE) {
        eprintln!("[skip] scala slice: corpus file not present");
        return;
    }
    // push: criterion line 42 (`val s = (c >> 3) + 1`). Lines 43-46 run after
    // it and must be excluded from the backward slice.
    assert_backward_excludes_after(SCALA_FILE, "push", 42, "scala/ByteStack.push");
}

#[test]
fn scala_forward_slice_excludes_statements_before_criterion() {
    if !corpus_ready(SCALA_FILE) {
        eprintln!("[skip] scala slice: corpus file not present");
        return;
    }
    // push: criterion line 43 (`val shift = (c & 7) << 2`). Lines 40-42 run
    // before it and must be excluded from the forward slice.
    assert_forward_excludes_before(SCALA_FILE, "push", 43, "scala/ByteStack.push");
}

#[test]
fn scala_backward_and_forward_differ() {
    if !corpus_ready(SCALA_FILE) {
        eprintln!("[skip] scala slice: corpus file not present");
        return;
    }
    let back = run_slice(SCALA_FILE, "push", 43, "backward");
    let fwd = run_slice(SCALA_FILE, "push", 43, "forward");
    assert_ne!(
        back, fwd,
        "scala/ByteStack.push: backward and forward slices from line 43 must differ; \
         both = {back:?}"
    );
}
