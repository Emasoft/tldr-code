//! elixir-per-clause-dfg-cfg-v1 (v0.4.2 cluster M-031)
//!
//! Per-clause iteration for Elixir DFG/CFG commands.
//!
//! Before this fix, the multi-clause-aware function finder advanced past
//! the bodyless head and returned the FIRST body-bearing clause (the fix
//! from `elixir-multiclause-and-mix-v1` / commit `8f95de7`). That gave
//! sensible (single) results for the first clause but completely hid the
//! later clauses — including different-arity versions. For
//! `Plug.Conn.send_resp` there are 5 def clauses: 1-arity heads at lines
//! 437/439/443/453 (bodyless head + 3 body clauses) and a 3-arity body
//! at line 595. The single-clause finder collapsed everything to the
//! first body clause at 439-441.
//!
//! This cluster fixes that by iterating EVERY `def NAME` clause and
//! emitting a per-clause report (`per_clauses: [...]`) keyed by
//! `(name, arity, start_line)`. The legacy top-level fields stay
//! populated with the first-clause result for backwards compatibility,
//! so single-clause Elixir and non-Elixir consumers see no behaviour
//! change.
//!
//! Affected commands (M-031 scope, 9 cells): `reaching-defs`,
//! `available`, `dead-stores`, `slice`, `taint`, `resources`,
//! `complexity`, `explain`, `references`.
//!
//! Test gating: requires `/tmp/repos/elixir-plug` (the canonical Plug
//! corpus used by the rest of the v0.4.2 audit suite).

use std::path::{Path, PathBuf};
use std::process::Command;

fn tldr_bin() -> PathBuf {
    let mut candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidate.pop(); // crates/tldr-cli -> crates
    candidate.pop(); // crates -> repo root
    candidate.push("target/release/tldr");
    candidate
}

fn run_tldr(args: &[&str]) -> (String, String, bool) {
    let bin = tldr_bin();
    assert!(
        bin.exists(),
        "expected release tldr binary at {} (run `cargo build --release`)",
        bin.display()
    );
    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to execute tldr binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn plug_repo_present() -> bool {
    Path::new("/tmp/repos/elixir-plug/lib/plug/conn.ex").is_file()
}

/// Helper: parse the `per_clauses` array (if present) and assert there
/// are >= 2 distinct (start_line, arity) clauses for the requested fn.
fn assert_per_clauses_distinct(stdout: &str, command: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("{command}: JSON parse failed: {e}\nstdout={stdout}"));
    let per = v
        .get("per_clauses")
        .and_then(|x| x.as_array())
        .unwrap_or_else(|| {
            panic!(
                "{command}: missing `per_clauses` array — multi-clause Elixir \
                 functions must surface every clause. Got: {stdout}"
            )
        });
    assert!(
        per.len() >= 2,
        "{command}: expected >= 2 per-clause entries for send_resp (it has 5 \
         clauses across 2 arities), got {}. Full output: {stdout}",
        per.len()
    );
    // Verify distinct (start_line, arity) tuples.
    let tuples: std::collections::HashSet<(u64, u64)> = per
        .iter()
        .filter_map(|c| {
            let line = c.get("start_line").and_then(|x| x.as_u64())?;
            let arity = c.get("arity").and_then(|x| x.as_u64())?;
            Some((line, arity))
        })
        .collect();
    assert!(
        tuples.len() >= 2,
        "{command}: per_clauses must have distinct (start_line, arity) keys, \
         got {} distinct out of {} entries. Full output: {stdout}",
        tuples.len(),
        per.len()
    );
    v
}

#[test]
fn elixir_reaching_defs_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "reaching-defs",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "reaching-defs failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "reaching-defs");
}

#[test]
fn elixir_complexity_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "complexity",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "complexity failed: stderr={stderr}");
    let v = assert_per_clauses_distinct(&stdout, "complexity");
    // Distinct metric values across clauses (per-clause analysis, not broadcast).
    let per = v.get("per_clauses").and_then(|x| x.as_array()).unwrap();
    let locs: std::collections::HashSet<u64> = per
        .iter()
        .filter_map(|c| c.get("lines_of_code").and_then(|x| x.as_u64()))
        .collect();
    assert!(
        locs.len() >= 2,
        "complexity: per-clause LOC must vary across clauses (got {locs:?}). \
         If broadcast, every clause would show the same LOC."
    );
}

#[test]
fn elixir_slice_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    // Use a line inside the first clause as the criterion, but require
    // per-clause emission to include every clause anyway.
    let (stdout, stderr, ok) = run_tldr(&[
        "slice",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "440",
        "--format",
        "json",
    ]);
    assert!(ok, "slice failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "slice");
}

#[test]
fn elixir_available_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "available",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "available failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "available");
}

#[test]
fn elixir_dead_stores_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "dead-stores",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "dead-stores failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "dead-stores");
}

#[test]
fn elixir_taint_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "taint",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "taint failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "taint");
}

#[test]
fn elixir_resources_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "resources",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "resources failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "resources");
}

#[test]
fn elixir_explain_emits_per_clause_for_send_resp() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "explain",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "--format",
        "json",
    ]);
    assert!(ok, "explain failed: stderr={stderr}");
    assert_per_clauses_distinct(&stdout, "explain");
}

/// Non-Elixir single-clause functions must NOT grow a `per_clauses` field
/// (no broadcast, no regression for the other 15 languages). Sanity check
/// via a Python file: complexity on a simple def should NOT include a
/// `per_clauses` array.
#[test]
fn non_elixir_does_not_emit_per_clauses() {
    use std::fs;
    let tmp = std::env::temp_dir().join("m031_no_per_clauses_python.py");
    fs::write(
        &tmp,
        "def foo(x):\n    if x > 0:\n        return x\n    return -x\n",
    )
    .unwrap();
    let (stdout, stderr, ok) = run_tldr(&[
        "complexity",
        tmp.to_str().unwrap(),
        "foo",
        "--format",
        "json",
    ]);
    assert!(ok, "complexity failed: stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v.get("per_clauses").is_none(),
        "python single-clause function must NOT emit per_clauses, got: {stdout}"
    );
}

/// Single-clause Elixir functions must NOT emit `per_clauses` (only
/// genuine multi-clause defs do). Use a synthetic single-def file to
/// avoid corpus dependency.
#[test]
fn single_clause_elixir_does_not_emit_per_clauses() {
    use std::fs;
    let tmp = std::env::temp_dir().join("m031_single_clause.ex");
    fs::write(
        &tmp,
        "defmodule M do\n  def foo(x) do\n    x + 1\n  end\nend\n",
    )
    .unwrap();
    let (stdout, stderr, ok) = run_tldr(&[
        "complexity",
        tmp.to_str().unwrap(),
        "foo",
        "--format",
        "json",
    ]);
    assert!(ok, "complexity failed: stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v.get("per_clauses").is_none(),
        "single-clause elixir function must NOT emit per_clauses, got: {stdout}"
    );
}
