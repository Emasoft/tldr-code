//! cfg-ruby-rebuild-v1 (v0.4.2 M-102)
//!
//! Ruby CFG keystone defect: every Ruby control-flow construct
//! (`if`/`elsif`/`unless`, `case`/`when`, `while`/`until`, `for`,
//! `loop do`, `break`/`next`, `begin`/`rescue`/`ensure`,
//! `*_modifier`) was lowered as a single straight-line block,
//! producing `cyclomatic:1, num_blocks:2, num_edges:0,
//! has_loops:false` regardless of the construct count.
//!
//! The cognitive-complexity AST visitor already recognises Ruby's
//! node kinds correctly (≈38 cognitive for the hermetic fixture
//! used here), which proves the tree-sitter-ruby grammar emits the
//! right node names. The bug lived entirely in the CFG-lowering
//! pass (`crates/tldr-core/src/cfg/extractor.rs`) and the
//! cyclomatic decision-counter
//! (`crates/tldr-core/src/metrics/complexity.rs`).
//!
//! This fix wires every Ruby control-flow node kind into the CFG
//! builder + decision counter, restoring `complexity`, `slice`,
//! `available`, `reaching-defs`, `dead-stores`, `taint`, `chop`,
//! `context`, `health`, `hotspots`, `debt`, and `explain` for
//! Ruby in a single pass.
//!
//! Test gating: fully hermetic — fixture written to a tempdir, no
//! external corpus required.

use std::path::PathBuf;
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

/// Hermetic fixture exercising every Ruby control-flow production
/// covered by the CFG lowering pass. Each method is intentionally
/// minimal so the assertion targets are predictable.
const RUBY_FIXTURE: &str = r#"# cfg-ruby-rebuild-v1 hermetic fixture
class Animal
  # 6 paths: enter, if-true, elsif-true, else, plus while/until/case
  # are split into separate methods below to keep each assertion focused.

  # if / elsif / else
  def if_method(x)
    if x > 0
      "positive"
    elsif x < 0
      "negative"
    else
      "zero"
    end
  end

  # case / when / else
  def case_method(n)
    case n
    when 1 then "one"
    when 2 then "two"
    when 3 then "three"
    else "many"
    end
  end

  # while loop with break
  def while_method(a)
    while a > 0
      a -= 1
      break if a == 5
    end
    a
  end

  # until loop with next (continue)
  def until_method(b)
    until b > 10
      b += 1
      next if b == 3
    end
    b
  end

  # for ... in loop
  def for_method(items)
    total = 0
    for i in items
      total += i
    end
    total
  end

  # loop do ... end (Kernel#loop with do_block)
  def loop_method(n)
    loop do
      n -= 1
      break if n <= 0
    end
    n
  end

  # begin / rescue / ensure
  def begin_method
    begin
      risky_call
    rescue StandardError => e
      handle_error(e)
    ensure
      cleanup
    end
  end

  # unless / modifier forms
  def modifier_method(flag, x, y)
    return x if flag
    return y unless flag
    0
  end

  # Big composite covering the iter-2 Animal.describe shape
  # (if + elsif + case-3-arms + while + until + break)
  def describe(x, n, a, b)
    if x > 0
      result = "pos"
    elsif x < 0
      result = "neg"
    else
      result = "zero"
    end
    case n
    when 1 then result += "-1"
    when 2 then result += "-2"
    else result += "-many"
    end
    while a > 0
      a -= 1
      break if a == 5
    end
    until b > 10
      b += 1
    end
    result
  end
end
"#;

fn fixture_path() -> PathBuf {
    let dir = std::env::temp_dir().join("tldr_cfg_ruby_v1");
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let file = dir.join("animal.rb");
    std::fs::write(&file, RUBY_FIXTURE).expect("write fixture");
    file
}

fn complexity_json(file: &PathBuf, function: &str) -> serde_json::Value {
    let (stdout, stderr, ok) = run_tldr(&[
        "complexity",
        file.to_str().unwrap(),
        function,
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "complexity {} failed: stderr={}\nstdout={}",
        function, stderr, stdout
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "complexity {}: JSON parse failed: {}\nstdout={}",
            function, e, stdout
        )
    })
}

/// `tldr explain` exposes `num_blocks`, `num_edges`, `has_loops` as part of
/// the `complexity` sub-object — fields not present on bare
/// `tldr complexity` output. The Ruby CFG cascade gates on the explain
/// path for structural assertions.
fn explain_complexity_json(file: &PathBuf, function: &str) -> serde_json::Value {
    let (stdout, stderr, ok) = run_tldr(&[
        "explain",
        file.to_str().unwrap(),
        function,
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "explain {} failed: stderr={}\nstdout={}",
        function, stderr, stdout
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "explain {}: JSON parse failed: {}\nstdout={}",
            function, e, stdout
        )
    });
    v.get("complexity").cloned().unwrap_or_else(|| {
        panic!(
            "explain {}: missing `complexity` sub-object. Full: {}",
            function, v
        )
    })
}

fn assert_cyclomatic_at_least(v: &serde_json::Value, function: &str, expected: u64) {
    let cyc = v
        .get("cyclomatic")
        .and_then(|x| x.as_u64())
        .unwrap_or_else(|| panic!("{}: missing cyclomatic in {}", function, v));
    assert!(
        cyc >= expected,
        "{}: cyclomatic must be >= {} (Ruby CFG keystone), got {}. Full: {}",
        function,
        expected,
        cyc,
        v
    );
}

fn assert_has_loops(v: &serde_json::Value, function: &str, expected: bool) {
    let actual = v
        .get("has_loops")
        .and_then(|x| x.as_bool())
        .unwrap_or_else(|| panic!("{}: missing has_loops in {}", function, v));
    assert_eq!(
        actual, expected,
        "{}: has_loops must be {}, got {}. Full: {}",
        function, expected, actual, v
    );
}

fn assert_num_edges_positive(v: &serde_json::Value, function: &str) {
    let ne = v
        .get("num_edges")
        .and_then(|x| x.as_u64())
        .unwrap_or_else(|| panic!("{}: missing num_edges in {}", function, v));
    assert!(
        ne > 0,
        "{}: num_edges must be > 0 (CFG must have edges for control-flow construct), \
         got {}. Full: {}",
        function,
        ne,
        v
    );
}

fn assert_num_blocks_at_least(v: &serde_json::Value, function: &str, expected: u64) {
    let nb = v
        .get("num_blocks")
        .and_then(|x| x.as_u64())
        .unwrap_or_else(|| panic!("{}: missing num_blocks in {}", function, v));
    assert!(
        nb >= expected,
        "{}: num_blocks must be >= {}, got {}. Full: {}",
        function,
        expected,
        nb,
        v
    );
}

#[test]
fn ruby_if_elsif_else_creates_branches() {
    let file = fixture_path();
    // Cyclomatic comes from `tldr complexity` (canonical
    // `calculate_complexity`); structural fields come from `tldr explain`.
    let cv = complexity_json(&file, "if_method");
    assert_cyclomatic_at_least(&cv, "if_method", 3);

    let ev = explain_complexity_json(&file, "if_method");
    assert_num_blocks_at_least(&ev, "if_method", 3);
    assert_num_edges_positive(&ev, "if_method");
}

#[test]
fn ruby_case_when_creates_branches() {
    let file = fixture_path();
    let cv = complexity_json(&file, "case_method");
    // 3 when-clauses → cyclomatic >= 4
    assert_cyclomatic_at_least(&cv, "case_method", 4);

    let ev = explain_complexity_json(&file, "case_method");
    assert_num_blocks_at_least(&ev, "case_method", 3);
    assert_num_edges_positive(&ev, "case_method");
}

#[test]
fn ruby_while_loop_creates_loop_header() {
    let file = fixture_path();
    let cv = complexity_json(&file, "while_method");
    // while + break-if = 2 decision points → cyclomatic >= 3
    assert_cyclomatic_at_least(&cv, "while_method", 3);

    let ev = explain_complexity_json(&file, "while_method");
    assert_has_loops(&ev, "while_method", true);
    assert_num_edges_positive(&ev, "while_method");
}

#[test]
fn ruby_until_loop_creates_loop_header() {
    let file = fixture_path();
    let cv = complexity_json(&file, "until_method");
    // until + next-if = 2 decision points → cyclomatic >= 3
    assert_cyclomatic_at_least(&cv, "until_method", 3);

    let ev = explain_complexity_json(&file, "until_method");
    assert_has_loops(&ev, "until_method", true);
    assert_num_edges_positive(&ev, "until_method");
}

#[test]
fn ruby_for_in_loop_creates_loop_header() {
    let file = fixture_path();
    let cv = complexity_json(&file, "for_method");
    assert_cyclomatic_at_least(&cv, "for_method", 2);

    let ev = explain_complexity_json(&file, "for_method");
    assert_has_loops(&ev, "for_method", true);
    assert_num_edges_positive(&ev, "for_method");
}

#[test]
fn ruby_loop_do_creates_loop_header() {
    let file = fixture_path();
    let cv = complexity_json(&file, "loop_method");
    // loop + break-if = 2 decision points → cyclomatic >= 3
    assert_cyclomatic_at_least(&cv, "loop_method", 3);

    let ev = explain_complexity_json(&file, "loop_method");
    assert_has_loops(&ev, "loop_method", true);
    assert_num_edges_positive(&ev, "loop_method");
}

#[test]
fn ruby_begin_rescue_ensure_creates_exception_branches() {
    let file = fixture_path();
    let cv = complexity_json(&file, "begin_method");
    // rescue clause = 1 decision point → cyclomatic >= 2
    assert_cyclomatic_at_least(&cv, "begin_method", 2);

    let ev = explain_complexity_json(&file, "begin_method");
    assert_num_edges_positive(&ev, "begin_method");
}

#[test]
fn ruby_modifier_forms_create_branches() {
    let file = fixture_path();
    let cv = complexity_json(&file, "modifier_method");
    // `return ... if flag` + `return ... unless flag` = 2 modifier branches
    // → cyclomatic >= 3 (base 1 + 2 modifier decision points)
    assert_cyclomatic_at_least(&cv, "modifier_method", 3);

    let ev = explain_complexity_json(&file, "modifier_method");
    assert_num_edges_positive(&ev, "modifier_method");
}

#[test]
fn ruby_describe_composite_cascade() {
    // This is the iter-2 keystone repro: Animal.describe with
    // if/elsif/case-3-arms/while/until/break → cyclomatic must be
    // substantially > 1.
    let file = fixture_path();
    let cv = complexity_json(&file, "describe");

    // Decision points: if(1) + elsif(1) + when-arms(3) + while(1) + break-if(1)
    // + until(1) = 8 → cyclomatic >= 7 (allow some grammar variance).
    assert_cyclomatic_at_least(&cv, "describe", 7);

    let ev = explain_complexity_json(&file, "describe");
    assert_has_loops(&ev, "describe", true);
    assert_num_edges_positive(&ev, "describe");
    assert_num_blocks_at_least(&ev, "describe", 8);
}

#[test]
fn ruby_cfg_cascade_into_slice_and_reaching_defs() {
    // Spot-check that the cascading commands no longer return flat CFGs.
    // We don't assert exact values (those vary by command semantics) but
    // require that the responses parse and the function is resolved.
    let file = fixture_path();

    // slice: must locate the function and produce a non-error report.
    let (stdout, stderr, ok) = run_tldr(&[
        "slice",
        file.to_str().unwrap(),
        "describe",
        "20",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "slice cascade failed: stderr={}\nstdout={}",
        stderr, stdout
    );
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("slice JSON parse: {}\nstdout={}", e, stdout));
    // slice must at minimum identify the function name.
    assert!(
        v.get("function")
            .and_then(|x| x.as_str())
            .map(|s| s.contains("describe"))
            .unwrap_or(false)
            || v.get("criterion").is_some()
            || v.get("slice").is_some(),
        "slice: cascade output missing expected fields. Full: {}",
        v
    );

    // reaching-defs: must succeed.
    let (stdout, stderr, ok) = run_tldr(&[
        "reaching-defs",
        file.to_str().unwrap(),
        "describe",
        "--format",
        "json",
    ]);
    assert!(
        ok,
        "reaching-defs cascade failed: stderr={}\nstdout={}",
        stderr, stdout
    );
}
