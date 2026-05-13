//! elixir-multiclause-and-mix-v1 (v0.4.2 bug-E1-E2)
//!
//! 1. **E1: Multi-clause body-level analyses (`slice`, `complexity`,
//!    `taint`, `contracts`, `reaching-defs`, `dead-stores`,
//!    `resources`, `explain`)**
//!
//!    Elixir functions can be declared as multi-clause sets — a bodyless
//!    spec head followed by one or more body-bearing clauses (e.g.
//!    `Plug.Conn.send_resp/1` at lib/plug/conn.ex:437 has a bodyless
//!    `def send_resp(conn)` head and four body-bearing clauses at
//!    439, 443, 453 and 595 — `extract` reports all five distinct
//!    entries).  Before this fix `find_function_node` returned the
//!    FIRST def matching the name. Because the bodyless head appears
//!    first in source order, all body-level analyses computed metrics
//!    on a single-line signature stub: `complexity` returned 1 / LOC=1,
//!    `slice` returned a single line.  Now the function finder advances
//!    past Elixir bodyless heads to the first body-bearing clause.
//!
//! 2. **E2: Mix reflection callbacks `project/0` and `application/0`**
//!
//!    `mix.exs` is the build manifest for every Elixir project. Its
//!    top-level `def project` and `def application` are reflection
//!    callbacks invoked by the `Mix` build tool — they have zero
//!    explicit callers in the project source but are NOT dead. Prior
//!    to this fix `tldr dead` flagged them as `possibly_dead`. They are
//!    now framework entry points (same mechanism that rescues
//!    `wsgi.py` / `views.py` for Python web frameworks).
//!
//! These tests are gated on the elixir-plug repository being checked
//! out at `/tmp/repos/elixir-plug` (matches the rest of the v0.4.2
//! audit-followup suite).

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
        "expected release tldr binary at {} (run `cargo build --release --features semantic`)",
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
        && Path::new("/tmp/repos/elixir-plug/mix.exs").is_file()
}

/// E1: `tldr complexity` on a multi-clause Elixir function MUST inspect a
/// body-bearing clause, not the bodyless spec head. `Plug.Conn.send_resp/1`
/// has 4 body-bearing clauses; at minimum one branches (the `:set` clause
/// calls `run_before_send/2` and pattern-matches on `{:ok, body, payload}`)
/// so cyclomatic must be >= 2 OR LOC must be greater than 1.
#[test]
fn elixir_complexity_send_resp_finds_real_body() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&[
        "complexity",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
    ]);
    assert!(ok, "tldr complexity failed: stderr={}", stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("complexity JSON parse failed: {} :: stdout={}", e, stdout));
    let loc = v
        .get("lines_of_code")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let cyclo = v.get("cyclomatic").and_then(|x| x.as_u64()).unwrap_or(0);
    assert!(
        loc > 1 || cyclo > 1,
        "send_resp/1 has 4 body-bearing clauses — complexity should reflect a real body, \
         not the bodyless head (loc={}, cyclomatic={}). Full report: {}",
        loc,
        cyclo,
        stdout
    );
}

/// E1: `tldr slice` MUST advance past the bodyless head to the first
/// body-bearing clause. Slicing on line 440 (`raise ArgumentError, ...`,
/// the body of the `:unset` clause at 439-441) MUST produce a non-empty
/// slice. Before the fix the function finder returned the bodyless head
/// at 437 (lines 437-437) and the slicer reported the criterion line
/// as outside the function (`lines: []`, line_count=0).
///
/// Scope note (v0.4.2 bug-E1 minimal fix): this test validates the
/// "skip-to-first-body-bearing-clause" semantics — slicing on lines
/// that fall in a LATER clause (e.g. 443-451 `:set`, 453-455
/// `AlreadySentError`) is deferred to a future per-clause iteration
/// pass. The current fix prevents the worst regression: bodyless-head
/// stubs being treated as the full function.
#[test]
fn elixir_slice_send_resp_finds_real_body() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    // Slice on line 440 — inside the first body-bearing clause
    // (`def send_resp(%Conn{state: :unset}) do` at 439-441).
    let (stdout, stderr, ok) = run_tldr(&[
        "slice",
        "/tmp/repos/elixir-plug/lib/plug/conn.ex",
        "send_resp",
        "440",
    ]);
    assert!(ok, "tldr slice failed: stderr={}", stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("slice JSON parse failed: {} :: stdout={}", e, stdout));
    let line_count = v.get("line_count").and_then(|x| x.as_u64()).unwrap_or(0);
    let explanation = v
        .get("explanation")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    assert!(
        line_count >= 1,
        "slice at line 440 (body of the first body-bearing clause) should \
         produce >= 1 slice line, got {} (explanation={:?}). \
         The function finder is still returning a bodyless head. \
         Full report: {}",
        line_count,
        explanation,
        stdout
    );
    // And the OOR diagnostic must NOT fire — bounds must reflect a
    // body-bearing clause, not the single-line bodyless head.
    assert!(
        !explanation.contains("437-437"),
        "slice still resolving send_resp to the bodyless head at line 437. \
         Explanation: {:?}. Full report: {}",
        explanation,
        stdout
    );
}

/// E2: `tldr dead` on `elixir-plug` MUST NOT flag `mix.exs::project/0`
/// as `possibly_dead`. It is the Mix build-tool reflection callback.
#[test]
fn elixir_dead_excludes_mix_exs_project() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&["dead", "/tmp/repos/elixir-plug"]);
    assert!(ok, "tldr dead failed: stderr={}", stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dead JSON parse failed: {} :: head={}", e, &stdout[..stdout.len().min(400)]));
    let dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let offenders: Vec<&serde_json::Value> = dead
        .iter()
        .filter(|d| {
            d.get("file")
                .and_then(|f| f.as_str())
                .is_some_and(|s| s.ends_with("mix.exs"))
                && d.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| s == "project" || s.ends_with(".project"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "mix.exs::project/0 is a Mix reflection callback (build-tool entry point) — \
         must not be flagged as possibly_dead. Found {} offender(s): {:?}",
        offenders.len(),
        offenders
    );
}

/// E2: same as above for `mix.exs::application/0`.
#[test]
fn elixir_dead_excludes_mix_exs_application() {
    if !plug_repo_present() {
        eprintln!("skipping: /tmp/repos/elixir-plug not present");
        return;
    }
    let (stdout, stderr, ok) = run_tldr(&["dead", "/tmp/repos/elixir-plug"]);
    assert!(ok, "tldr dead failed: stderr={}", stderr);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dead JSON parse failed: {} :: head={}", e, &stdout[..stdout.len().min(400)]));
    let dead = v
        .get("possibly_dead")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let offenders: Vec<&serde_json::Value> = dead
        .iter()
        .filter(|d| {
            d.get("file")
                .and_then(|f| f.as_str())
                .is_some_and(|s| s.ends_with("mix.exs"))
                && d.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| s == "application" || s.ends_with(".application"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "mix.exs::application/0 is a Mix reflection callback (build-tool entry point) — \
         must not be flagged as possibly_dead. Found {} offender(s): {:?}",
        offenders.len(),
        offenders
    );
}
