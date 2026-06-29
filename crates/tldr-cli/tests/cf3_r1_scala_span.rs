//! CF3-R1 (v0.5.0 RC CF-wave): the span-keyed commands `complexity`,
//! `explain`, and `reaching-defs` must STOP at a Scala function's real body
//! and exclude a trailing `/** ScalaDoc */` that tree-sitter-scala folds into
//! the previous expression-bodied `def`'s span.
//!
//! tree-sitter-scala parses
//!
//! ```scala
//! def provideSome[R0] =
//!   new Applied[R0](self)
//!
//! /** doc for the NEXT def */
//! def provide[E1] = impl()
//! ```
//!
//! such that the `/** ... */` block-comment documenting `provide` is FOLDED
//! into `provideSome`'s `indented_block` as a trailing child. Raw
//! `node.end_position()` therefore over-extends `provideSome` into the doc,
//! inflating `complexity.lines_of_code`, `explain.line_end`, and the
//! `reaching-defs` basic-block span. The fix routes the function/statement
//! end-line through the Scala-gated `decl_end_line_from_node` normaliser and
//! drops folded comment nodes from the CFG, so all three commands stop at the
//! body. The fix is a no-op for every other language (Python control).

use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

/// `provideSome` (lines 2-3) is immediately followed by a `/** ScalaDoc */`
/// (lines 5-7) documenting `provide` (lines 8-9). tree-sitter-scala folds that
/// doc into `provideSome`'s span.
const SCALA_SRC: &str = "\
trait Thing {
  def provideSome[R0] =
    new Applied[R0](self)

  /**
   * Doc for the NEXT def, not provideSome.
   */
  def provide[E1] =
    impl()
}
";

/// Non-folding control language: a Python function whose span never absorbs a
/// following declaration's comment. The normaliser must be a faithful no-op.
const PY_SRC: &str = "def g():\n    return 1\n";

fn run_json(dir: &Path, args: &[&str]) -> Value {
    let out = tldr_cmd()
        .current_dir(dir)
        .args(args)
        .output()
        .expect("tldr binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("expected JSON from `{:?}`; got:\n{}\nerr: {}", args, stdout, e))
}

#[test]
fn scala_span_commands_exclude_trailing_scaladoc() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("Thing.scala");
    std::fs::write(&file, SCALA_SRC).unwrap();
    let fname = "Thing.scala";

    // --- complexity: lines_of_code must count the body (2-3), not 2-7/2-8.
    let cx = run_json(
        dir.path(),
        &["complexity", fname, "provideSome", "--format", "json"],
    );
    let loc = cx["lines_of_code"].as_u64().unwrap();
    assert_eq!(
        loc, 2,
        "complexity.lines_of_code must stop at the body (lines 2-3 => 2), not extend \
         into the trailing ScalaDoc; got {loc}\nfull: {cx}"
    );

    // --- explain: line_end must be the body line (3), not the doc line (7/8).
    let ex = run_json(
        dir.path(),
        &["explain", fname, "provideSome", "--format", "json"],
    );
    let line_end = ex["line_end"].as_u64().unwrap();
    assert_eq!(
        line_end, 3,
        "explain.line_end must stop at the body (line 3), not extend into the \
         trailing ScalaDoc; got {line_end}\nfull: {ex}"
    );

    // --- reaching-defs: no CFG basic block may reach into the ScalaDoc (>=5).
    let rd = run_json(
        dir.path(),
        &["reaching-defs", fname, "provideSome", "--format", "json"],
    );
    let blocks = rd["blocks"].as_array().expect("reaching-defs has blocks");
    assert!(!blocks.is_empty(), "expected CFG blocks; got {rd}");
    for b in blocks {
        let end = b["lines"][1].as_u64().unwrap();
        assert!(
            end <= 3,
            "reaching-defs block {} span must stop at the body (<=3), not extend into \
             the trailing ScalaDoc (lines 5-7); got end={end}\nfull: {rd}",
            b["id"]
        );
    }
}

#[test]
fn non_scala_control_unchanged() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("ctrl.py");
    std::fs::write(&file, PY_SRC).unwrap();
    let fname = "ctrl.py";

    // The Scala-gated normaliser must be a faithful no-op for Python: `g`
    // spans lines 1-2 with no trailing comment to absorb.
    let cx = run_json(dir.path(), &["complexity", fname, "g", "--format", "json"]);
    assert_eq!(
        cx["lines_of_code"].as_u64().unwrap(),
        2,
        "python complexity must be unchanged (no-op); full: {cx}"
    );

    let ex = run_json(dir.path(), &["explain", fname, "g", "--format", "json"]);
    assert_eq!(
        ex["line_end"].as_u64().unwrap(),
        2,
        "python explain.line_end must be unchanged (no-op); full: {ex}"
    );
}
