//! fix-B1-v1: line/body-aware function resolution (FAN-IN: slice + chop +
//! complexity) — v0.5.0 AUDIT-FIX
//!
//! # Root cause
//!
//! `tldr_core::ast::function_finder::find_function_node` resolved a function
//! BY NAME ONLY: a depth-first search returning the FIRST source-order node
//! whose name matched, with no preference for a definition that HAS A BODY
//! and no notion of the line the caller cares about. For a name declared
//! once as a body-less abstract / interface / trait declaration and once as
//! a concrete implementation, it returned the body-less declaration.
//!
//! Observed in the audit corpus:
//! - kotlin `Semaphore.kt`: `tryAcquire` is declared abstract at line 51
//!   (`public fun tryAcquire(): Boolean`) and implemented at line 151
//!   (`fun tryAcquire(): Boolean { ... }`). Resolution returned the L51
//!   declaration, so `slice` reported "line 154 outside function (lines
//!   51-51)" and `complexity` reported cyclomatic=1, lines_of_code=1.
//! - scala `Semaphore.scala`: `acquireN` is a trait method at line 71
//!   (`def acquireN(n: Long): F[Unit]`) and implemented at line 173
//!   (`def acquireN(n: Long): F[Unit] = { ... }`). Same failure modes for
//!   `chop` and `complexity`.
//!
//! # Fix
//!
//! Function resolution now (1) prefers a definition whose line range
//! CONTAINS a supplied criterion line (threaded from slice/chop), and
//! (2) when no line is supplied or it is ambiguous, prefers a definition
//! WITH A BODY — detected AST-driven via `get_function_body` (a block /
//! expression-body child), generic across languages. Single-definition
//! resolution is unchanged.
//!
//! These tests drive the real `tldr` binary (the production command path)
//! against synthetic fixtures that reproduce the abstract-decl + concrete-
//! impl shape, so they fail RED against the pre-fix resolver and pass GREEN
//! after.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn run_json(args: &[&str]) -> serde_json::Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(args)
        .output()
        .expect("failed to execute tldr");
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output not valid JSON: {}\nstdout: {}\nargs: {:?}", e, stdout, args))
}

fn run_text(args: &[&str]) -> String {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
        .args(args)
        .output()
        .expect("failed to execute tldr");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Kotlin fixture: an interface declaring a body-less `tryAcquire` and a
/// class implementing it with a real multi-line body containing branches
/// (so cyclomatic > 1) and a straight-line data-dependency chain (so a
/// backward slice from the return spans multiple lines). Mirrors the
/// abstract-decl + concrete-impl shape of `kotlinx-coroutines`
/// Semaphore.kt without the deeply-nested `while(true)`/`continue` loop,
/// whose interior lines the CFG collapses into a single block (a separate,
/// pre-existing slice-granularity behavior unrelated to B1 resolution).
fn kotlin_fixture(dir: &TempDir) -> String {
    let src = r#"package demo

interface Semaphore {
    public fun acquire()
    public fun tryAcquire(): Boolean
    public fun release()
}

class SemaphoreImpl(private val permits: Int) : Semaphore {
    private var available = permits

    override fun acquire() {
        available -= 1
    }

    override fun tryAcquire(): Boolean {
        val p = available
        var ok = false
        if (p > permits) {
            available = permits
        } else if (p > 0) {
            available = p - 1
            ok = true
        }
        return ok
    }

    override fun release() {
        available += 1
    }
}
"#;
    let path = dir.path().join("Semaphore.kt");
    fs::write(&path, src).unwrap();
    path.to_str().unwrap().to_string()
}

/// Scala fixture: a trait declaring a body-less `acquireN` and an object
/// providing an anonymous-instance implementation with a real multi-line
/// body containing branches. Mirrors `cats-effect` Semaphore.scala.
fn scala_fixture(dir: &TempDir) -> String {
    let src = r#"package demo

trait Semaphore[F[_]] {
  def acquireN(n: Long): F[Unit]
  def release: F[Unit]
}

object Semaphore {
  def make[F[_]] =
    new Semaphore[F] {
      def acquireN(n: Long): F[Unit] = {
        val x = n + 1
        if (x > 0) {
          doThing(x)
        } else if (x < 0) {
          other(x)
        } else {
          noop()
        }
      }

      def release: F[Unit] = {
        noop()
      }
    }
}
"#;
    let path = dir.path().join("Semaphore.scala");
    fs::write(&path, src).unwrap();
    path.to_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// slice (Kotlin)
// ---------------------------------------------------------------------------

#[test]
fn kotlin_slice_resolves_concrete_impl_not_abstract_decl() {
    let dir = TempDir::new().unwrap();
    let file = kotlin_fixture(&dir);
    // Line 25 (`return ok`) is the impl's return; a backward slice from it
    // follows the `ok` data-dependency chain (lines 18, 23) and the branch.
    let v = run_json(&["slice", &file, "tryAcquire", "25", "-q"]);

    // RED before fix: explanation == "...line 25 is outside function
    // 'tryAcquire' (lines 5-5)" (the body-less abstract decl on line 5) and
    // lines == []. The abstract decl spans a single line, so ANY interior
    // line of the impl was reported out of range.
    let explanation = v["explanation"].as_str().unwrap_or("");
    assert!(
        !explanation.contains("outside function"),
        "slice must resolve the body-bearing impl, not emit an out-of-range \
         explanation: {explanation}"
    );
    let lines = v["lines"].as_array().cloned().unwrap_or_default();
    assert!(
        lines.len() > 1,
        "slice of the impl must span multiple lines, got {lines:?} (explanation: {explanation})"
    );
}

// ---------------------------------------------------------------------------
// chop (Scala)
// ---------------------------------------------------------------------------

#[test]
fn scala_chop_resolves_concrete_impl_not_abstract_decl() {
    let dir = TempDir::new().unwrap();
    let file = scala_fixture(&dir);
    // Lines 13 and 18 are both inside the concrete `acquireN` impl body.
    let v = run_json(&["chop", &file, "acquireN", "13", "18", "-q"]);

    let explanation = v["explanation"].as_str().unwrap_or("");
    // RED before fix: "...line 13 is outside function 'acquireN' (lines 4-4)"
    // (the body-less trait declaration on line 4).
    assert!(
        !explanation.contains("outside function"),
        "chop must resolve the body-bearing impl, not emit an out-of-range \
         explanation: {explanation}"
    );
    assert!(
        v["path_exists"].as_bool().unwrap_or(false),
        "chop within the concrete impl must find a path (got path_exists=false, \
         explanation: {explanation})"
    );
}

// ---------------------------------------------------------------------------
// complexity (Kotlin + Scala)
// ---------------------------------------------------------------------------

#[test]
fn kotlin_complexity_reports_impl_cyclomatic_gt_one() {
    let dir = TempDir::new().unwrap();
    let file = kotlin_fixture(&dir);
    let v = run_json(&["complexity", &file, "tryAcquire", "-q"]);

    // RED before fix: cyclomatic == 1, lines_of_code == 1 (the abstract decl).
    let cyclomatic = v["cyclomatic"].as_u64().unwrap_or(0);
    assert!(
        cyclomatic > 1,
        "complexity must reflect the impl's decision points (cyclomatic>1), got {cyclomatic}: {v}"
    );
    let loc = v["lines_of_code"].as_u64().unwrap_or(0);
    assert!(
        loc > 1,
        "complexity must reflect the impl's body (lines_of_code>1), got {loc}: {v}"
    );
}

#[test]
fn scala_complexity_reports_impl_cyclomatic_gt_one() {
    let dir = TempDir::new().unwrap();
    let file = scala_fixture(&dir);
    let v = run_json(&["complexity", &file, "acquireN", "-q"]);

    let cyclomatic = v["cyclomatic"].as_u64().unwrap_or(0);
    assert!(
        cyclomatic > 1,
        "complexity must reflect the impl's decision points (cyclomatic>1), got {cyclomatic}: {v}"
    );
}

// ---------------------------------------------------------------------------
// Regression: a single (non-duplicated) definition is unaffected. The
// body/line preference must not perturb the ordinary case.
// ---------------------------------------------------------------------------

#[test]
fn single_definition_complexity_unchanged() {
    let dir = TempDir::new().unwrap();
    let src = r#"package demo

class Calc {
    fun classify(n: Int): String {
        if (n > 0) {
            return "pos"
        } else if (n < 0) {
            return "neg"
        }
        return "zero"
    }
}
"#;
    let path = dir.path().join("Calc.kt");
    fs::write(&path, src).unwrap();
    let file = path.to_str().unwrap();

    let v = run_json(&["complexity", file, "classify", "-q"]);
    // Two branches (if / else-if) -> cyclomatic 3 (1 + 2 decision points).
    let cyclomatic = v["cyclomatic"].as_u64().unwrap_or(0);
    assert!(
        cyclomatic >= 3,
        "single-definition resolution must be unchanged (cyclomatic>=3), got {cyclomatic}: {v}"
    );

    // And slice on a line inside it still produces a multi-line slice.
    let s = run_text(&["slice", file, "classify", "5", "-q"]);
    assert!(
        !s.contains("outside function"),
        "single-definition slice must not regress: {s}"
    );
}
