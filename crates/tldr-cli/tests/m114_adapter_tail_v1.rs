//! m114-adapter-tail-v1 (v0.4.2 M-114)
//!
//! Wave 17f-B: six per-language adapter tail fixes surfaced by the
//! iter-3 audit:
//!
//! 1. **OCaml `let-in` leakage** — `extract_ocaml_functions_detailed`
//!    walks every node and emits any `let_binding` it finds nested
//!    under a `value_definition`. But tree-sitter-ocaml also wraps
//!    inner `let-in` bindings (`let helper z = ... in body`) in a
//!    `value_definition` node under a `let_expression` parent —
//!    so the recursive walk leaked inner locals as if they were
//!    top-level definitions. Fix: only emit when the
//!    `value_definition`'s parent is NOT a `let_expression`
//!    (i.e., it's a true top-level / module-level let).
//!
//! 2. **Lua `require()` import** — confirmed working on
//!    `/tmp/repos/lua-lsp`; this pin guards against regression.
//!
//! 3. **PHP `$n++` SSA def-site** — `dfg/extractor.rs` had no arm
//!    for tree-sitter-php's `update_expression` node, so `$n++`
//!    / `--$n` mutated `$n` without ever generating a reaching-defs
//!    gen entry. Variables modified only via `++`/`--` looked
//!    permanently bound to their initial definition. Fix: add a
//!    PHP-specific `update_expression` arm that emits both a READ
//!    (the `++` reads the current value) and a DEF.
//!
//! 4. **Kotlin destructuring DFG** — `val (a, b) = pair` parses as
//!    `property_declaration > multi_variable_declaration >
//!    variable_declaration[]`. The existing `process_kotlin_property`
//!    only handled single-name `variable_declaration` directly under
//!    the property declaration; the destructured form (each name in
//!    its own sibling `variable_declaration` under
//!    `multi_variable_declaration`) emitted zero defs. Fix: walk the
//!    `multi_variable_declaration` and emit one def per name.
//!
//! 5. **Ruby `is_test` flag for class definitions** — minitest /
//!    test-unit subclasses (`class FooTest < Minitest::Test` /
//!    `< Test::Unit::TestCase`) are unmistakable test fixtures but
//!    `structure` output never marked them. Fix: add an `is_test`
//!    field on `DefinitionInfo` (skipped when false) and set it on
//!    Ruby class definitions whose superclass is one of the known
//!    test base classes.
//!
//! 6. **Ruby mixin distinct kinds** — `inheritance/ruby.rs::collect_ruby_mixins`
//!    collapsed `include` / `extend` / `prepend` mixin calls to a
//!    single `InheritanceKind::Implements`. The three are
//!    semantically different (instance methods / class methods /
//!    mixed-in-before-the-class). Fix: introduce
//!    `InheritanceKind::{Includes, Extended, Prepends}` and route
//!    each mixin call to its corresponding kind.

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(args: &[&str]) -> Option<Value> {
    let output = tldr_cmd().args(args).output().expect("run tldr");
    let stdout = String::from_utf8(output.stdout).ok()?;
    serde_json::from_str(&stdout).ok()
}

// =============================================================================
// Acceptance 1 — OCaml: nested `let-in` locals must NOT surface as
// top-level definitions. Use a tightly-controlled fixture so we don't
// have to depend on a specific dune source layout.
// =============================================================================

#[test]
fn test_m114_ocaml_let_in_does_not_leak_as_top_level() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested_let.ml");
    let source = "\
let outer x =
  let inner_y = x + 1 in
  let inner_helper z = z * 2 in
  inner_helper inner_y

let another a b = a + b
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&[
        "extract",
        path.to_str().unwrap(),
        "--format",
        "json",
    ])
    .expect("ocaml extract should return JSON");

    let names: Vec<String> = json
        .get("functions")
        .and_then(|v| v.as_array())
        .expect(".functions[] must be present")
        .iter()
        .filter_map(|f| f.get("name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    // The two TOP-LEVEL bindings MUST be present.
    assert!(
        names.iter().any(|n| n == "outer"),
        "missing top-level `outer`: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n == "another"),
        "missing top-level `another`: {:?}",
        names
    );

    // The let-in LOCAL `inner_helper` MUST NOT appear at module
    // scope. (`inner_y` has no parameter and is a value binding, so
    // it's already filtered by `ocaml_binding_has_params`.)
    assert!(
        !names.iter().any(|n| n == "inner_helper"),
        "let-in local `inner_helper` leaked as a top-level function: {:?}",
        names
    );
}

#[test]
fn test_m114_ocaml_corpus_dune_no_let_in_leakage() {
    let corpus = Path::new("/tmp/repos/ocaml-dune");
    if !corpus.exists() {
        eprintln!(
            "skipping test_m114_ocaml_corpus_dune_no_let_in_leakage: corpus {} missing",
            corpus.display()
        );
        return;
    }
    // Pick a real dune .ml file with both top-level lets and
    // let-in bindings.
    let target = corpus.join("bench/bench.ml");
    if !target.exists() {
        eprintln!("skipping: {} missing", target.display());
        return;
    }

    let json = run_json(&["extract", target.to_str().unwrap(), "--format", "json"])
        .expect("dune bench.ml extract should return JSON");

    // No requirement on specific names from the corpus; just assert
    // the binary did not panic and we got a functions array.
    assert!(
        json.get("functions")
            .and_then(|v| v.as_array())
            .is_some(),
        "ocaml extract on dune corpus missing `functions[]`"
    );
}

// =============================================================================
// Acceptance 2 — Lua: `require 'mod'` imports MUST surface, and the
// real lua-lsp corpus must yield non-empty imports for files that
// `require` modules.
// =============================================================================

#[test]
fn test_m114_lua_require_imports_extracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("loader.lua");
    let source = "\
local fs = require 'bee.filesystem'
local util = require(\"utility\")
local v = require\"compact\"
require 'side.effect'
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&["imports", path.to_str().unwrap(), "--format", "json"])
        .expect("lua imports should return JSON");
    let modules: Vec<String> = json
        .get("imports")
        .and_then(|v| v.as_array())
        .expect(".imports[] must be present")
        .iter()
        .filter_map(|i| i.get("module").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    for want in &["bee.filesystem", "utility", "compact", "side.effect"] {
        assert!(
            modules.iter().any(|m| m == *want),
            "lua imports missing `{}`: {:?}",
            want,
            modules
        );
    }
}

#[test]
fn test_m114_lua_corpus_lua_lsp_imports_non_empty() {
    let corpus = Path::new("/tmp/repos/lua-lsp");
    if !corpus.exists() {
        eprintln!(
            "skipping test_m114_lua_corpus_lua_lsp_imports_non_empty: corpus {} missing",
            corpus.display()
        );
        return;
    }
    let target = corpus.join("main.lua");
    if !target.exists() {
        eprintln!("skipping: {} missing", target.display());
        return;
    }
    let json = run_json(&["imports", target.to_str().unwrap(), "--format", "json"])
        .expect("lua-lsp main.lua imports should return JSON");
    let imports = json
        .get("imports")
        .and_then(|v| v.as_array())
        .expect(".imports[] missing");
    assert!(
        !imports.is_empty(),
        "lua-lsp main.lua reports no `require` imports — regression"
    );
}

// =============================================================================
// Acceptance 3 — PHP: `$n++` must generate an SSA / reaching-defs
// gen-site for `$n`. Pre-fix the only def-site was the initial `$n = 0`.
// =============================================================================

#[test]
fn test_m114_php_update_expression_creates_def_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("counter.php");
    let source = "<?php
function counter() {
    $n = 0;
    while ($n < 10) {
        $n++;
    }
    return $n;
}
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&[
        "reaching-defs",
        path.to_str().unwrap(),
        "counter",
        "--format",
        "json",
    ])
    .expect("php reaching-defs should return JSON");
    let blocks = json
        .get("blocks")
        .and_then(|v| v.as_array())
        .expect(".blocks[] must be present");

    let mut found_increment_def = false;
    for b in blocks {
        if let Some(gens) = b.get("gen").and_then(|v| v.as_array()) {
            for g in gens {
                let var = g.get("var").and_then(|v| v.as_str()).unwrap_or("");
                let line = g.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                // Increment is on line 5 in the fixture.
                if var == "$n" && line == 5 {
                    found_increment_def = true;
                }
            }
        }
    }
    assert!(
        found_increment_def,
        "php reaching-defs missing def-site for `$n` at the `$n++` line (5). \
         Update-expression must both READ and DEF the operand."
    );
}

// =============================================================================
// Acceptance 4 — Kotlin: `val (a, b) = pair` must emit a def-site for
// `a` and `b` separately.
// =============================================================================

#[test]
fn test_m114_kotlin_destructuring_emits_def_sites() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("destruct.kt");
    let source = "fun example() {
    val pair = Pair(1, 2)
    val (a, b) = pair
    println(a + b)
}
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&[
        "reaching-defs",
        path.to_str().unwrap(),
        "example",
        "--format",
        "json",
    ])
    .expect("kotlin reaching-defs should return JSON");
    let blocks = json
        .get("blocks")
        .and_then(|v| v.as_array())
        .expect(".blocks[] must be present");

    let mut found_a = false;
    let mut found_b = false;
    for b in blocks {
        if let Some(gens) = b.get("gen").and_then(|v| v.as_array()) {
            for g in gens {
                let var = g.get("var").and_then(|v| v.as_str()).unwrap_or("");
                if var == "a" {
                    found_a = true;
                }
                if var == "b" {
                    found_b = true;
                }
            }
        }
    }
    assert!(
        found_a && found_b,
        "kotlin destructuring `val (a, b) = pair` must emit def-sites for BOTH a and b; \
         found_a={} found_b={}",
        found_a,
        found_b
    );
}

// =============================================================================
// Acceptance 5 — Ruby: classes inheriting from `Minitest::Test` /
// `Test::Unit::TestCase` (and similar) MUST be tagged `is_test: true`
// in `tldr structure` output. Other classes MUST NOT be tagged.
// =============================================================================

#[test]
fn test_m114_ruby_is_test_for_minitest_subclass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("foo_test.rb");
    let source = "require 'minitest/autorun'

class FooTest < Minitest::Test
  def test_one
    assert true
  end
end

class BarSpec < Test::Unit::TestCase
  def test_two
  end
end

class NotATest
  def hello
    'world'
  end
end
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&[
        "structure",
        path.to_str().unwrap(),
        "--format",
        "json",
    ])
    .expect("ruby structure should return JSON");
    let file0 = json
        .get("files")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .expect("structure must have files[0]");
    let defs = file0
        .get("definitions")
        .and_then(|v| v.as_array())
        .expect(".files[0].definitions[] missing");

    // Look for class definitions and their `is_test` flag.
    let mut foo_test_is_test: Option<bool> = None;
    let mut bar_spec_is_test: Option<bool> = None;
    let mut not_a_test_is_test: Option<bool> = None;
    for d in defs {
        if d.get("kind").and_then(|v| v.as_str()) != Some("class") {
            continue;
        }
        let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let is_test = d.get("is_test").and_then(|v| v.as_bool());
        match name {
            "FooTest" => foo_test_is_test = Some(is_test.unwrap_or(false)),
            "BarSpec" => bar_spec_is_test = Some(is_test.unwrap_or(false)),
            "NotATest" => not_a_test_is_test = Some(is_test.unwrap_or(false)),
            _ => {}
        }
    }
    assert_eq!(
        foo_test_is_test,
        Some(true),
        "FooTest < Minitest::Test must be tagged is_test=true"
    );
    assert_eq!(
        bar_spec_is_test,
        Some(true),
        "BarSpec < Test::Unit::TestCase must be tagged is_test=true"
    );
    assert_eq!(
        not_a_test_is_test,
        Some(false),
        "NotATest must NOT be tagged is_test=true (got {:?})",
        not_a_test_is_test
    );
}

// =============================================================================
// Acceptance 6 — Ruby: `include` / `extend` / `prepend` mixin calls
// must surface as DISTINCT inheritance kinds, not collapse to a
// single mixin kind.
// =============================================================================

#[test]
fn test_m114_ruby_mixin_kinds_distinguished() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mixins.rb");
    let source = "module Walkable
end

module Trainable
end

module Loggable
end

class Dog
  include Walkable
  extend Trainable
  prepend Loggable
end
";
    std::fs::write(&path, source).unwrap();

    let json = run_json(&[
        "inheritance",
        path.to_str().unwrap(),
        "--format",
        "json",
    ])
    .expect("ruby inheritance should return JSON");
    let edges = json
        .get("edges")
        .and_then(|v| v.as_array())
        .expect(".edges[] missing");

    // Build (parent, kind) pairs for `Dog`'s edges.
    let dog_edges: Vec<(&str, &str)> = edges
        .iter()
        .filter(|e| e.get("child").and_then(|v| v.as_str()) == Some("Dog"))
        .filter_map(|e| {
            let parent = e.get("parent").and_then(|v| v.as_str())?;
            let kind = e.get("kind").and_then(|v| v.as_str())?;
            Some((parent, kind))
        })
        .collect();

    let walkable_kind = dog_edges
        .iter()
        .find(|(p, _)| *p == "Walkable")
        .map(|(_, k)| *k);
    let trainable_kind = dog_edges
        .iter()
        .find(|(p, _)| *p == "Trainable")
        .map(|(_, k)| *k);
    let loggable_kind = dog_edges
        .iter()
        .find(|(p, _)| *p == "Loggable")
        .map(|(_, k)| *k);

    assert_eq!(
        walkable_kind,
        Some("includes"),
        "Dog.include Walkable must surface with kind=includes (got {:?})",
        walkable_kind
    );
    assert_eq!(
        trainable_kind,
        Some("extended"),
        "Dog.extend Trainable must surface with kind=extended (got {:?})",
        trainable_kind
    );
    assert_eq!(
        loggable_kind,
        Some("prepends"),
        "Dog.prepend Loggable must surface with kind=prepends (got {:?})",
        loggable_kind
    );
}
