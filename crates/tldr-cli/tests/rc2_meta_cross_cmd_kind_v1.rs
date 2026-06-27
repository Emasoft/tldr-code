//! rc2-meta-stage4 — CROSS-COMMAND KIND-AGREEMENT INVARIANT (v0.5.0 CLOSEOUT)
//!
//! THE CAPSTONE / anti-re-drift guard for the whole rc2-meta refactor.
//!
//! Stages 1-3 made the canonical `classify_node` discriminator the single
//! source of truth that `structure`, `extract` and `interface` all consult.
//! This test LOCKS that result: for every language fixture it asserts the three
//! commands AGREE ON THE KIND of every entity they SHARE.
//!
//! CRITICAL PRINCIPLE — *views differ, facts agree*:
//!   * We assert KIND-FACT agreement on the INTERSECTION (a name present, with a
//!     non-empty kind, in >= 2 of the three commands). We do NOT assert identical
//!     MEMBERSHIP. `interface` legitimately shows the PUBLIC-only surface and may
//!     omit private items; `structure` has containment while `interface` /
//!     `extract` flatten. A private helper absent from `interface` is CORRECT,
//!     not a failure.
//!   * A command that emits NO kind for a name (empty / absent `kind`) ABSTAINS:
//!     it is not claiming a rival kind, so it never triggers a disagreement.
//!     (Most `extract.functions[]` / `interface.functions[]` entries carry no
//!     `kind` outside Elixir — they abstain.)
//!
//! NO-GAMING: where a genuine kind disagreement surfaces that is a DOCUMENTED
//! pre-existing modeling difference, it is encoded as an EXPLICIT, COMMENTED
//! allowance below (never a silent skip). The principled allowances are:
//!
//!   A1. ELIXIR def-flattening — module-level `def`/`defp`: `structure` labels it
//!       `kind:"method"` (it carries module containment context) while
//!       `interface` flattens it to `kind:"function"`. The {function, method}
//!       pair is the documented structure-vs-interface seam (#57). NOTE: this
//!       allowance is scoped to {function, method} ONLY — `macro` stays its own
//!       kind, so `defmacro`/`defmacrop` MUST agree as `kind:"macro"` across
//!       commands (the durable #57 payoff this whole refactor exists to lock).
//!
//!   A2. SCALA def-flattening — a `def` member of an `object`/`trait`/`class`:
//!       `structure` reports it `kind:"function"` (its entry-kind switch resolves
//!       the bare `function_definition` on the function axis) while `interface`
//!       nests it under the owner as a `method`. Same {function, method} seam as
//!       A1 (containment-flatten vs nest). Class-axis kinds (class/object/trait/
//!       enum/type) MUST still agree exactly.
//!
//!   A3. GO structure coarse class-axis default — `structure`'s legacy entry-kind
//!       switch reports `kind:"class"` for a Go `type_spec`, whereas `extract` /
//!       `interface` route the carrier through `classify_node` and specialize it
//!       to `struct` / `interface` / `type`. Stage-3-Go EXPLICITLY deferred
//!       routing `structure`'s class-axis default through `classify_node`
//!       (documented verbatim in `rc2_meta_stage3_go_v1.rs:160-164`: "structure's
//!       legacy entry-kind switch reports the class-axis default `class` for Go
//!       type_specs and is intentionally NOT changed by this Stage-3 slice"). It
//!       is therefore a documented pre-existing modeling difference, scoped here
//!       to {class}-vs-{struct|interface|type} for Go ONLY.
//!
//! Authoritative fixture origins (the plan §5): the TS fixture is the canonical
//! `/tmp/rc2_ts.ts`; the Elixir macro shape mirrors the real corpus
//! `elixir-plug/lib/plug/builder.ex` (`defmacro __using__`/`__before_compile__`
//! at lines ~148/172/249/279). Fixtures are embedded (machine-independent) so the
//! invariant runs in CI without the external corpus.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_json(cmd: &str, path: &Path) -> Value {
    let assert = tldr_cmd()
        .args([cmd, path.to_str().unwrap(), "--format", "json", "-q"])
        .env("TLDR_NO_DAEMON", "1")
        .assert()
        .success();
    let out = assert.get_output();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{cmd} must emit valid JSON: {e}\nstdout:\n{stdout}"))
}

fn push_kind(out: &mut Vec<(String, String)>, name: Option<&str>, kind: Option<&str>) {
    let name = name.unwrap_or("").to_string();
    let kind = kind.unwrap_or("").to_string();
    // Only record entries that carry BOTH a name and a non-empty kind. An empty
    // kind ABSTAINS (the command makes no kind claim for that name).
    if !name.is_empty() && !kind.is_empty() {
        out.push((name, kind));
    }
}

/// `structure.files[].definitions[].{name,kind}`.
fn structure_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("structure", file);
    let mut out = Vec::new();
    if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
        for f in files {
            if let Some(defs) = f.get("definitions").and_then(|d| d.as_array()) {
                for d in defs {
                    push_kind(
                        &mut out,
                        d.get("name").and_then(|n| n.as_str()),
                        d.get("kind").and_then(|k| k.as_str()),
                    );
                }
            }
        }
    }
    out
}

/// `extract.classes[].{name,kind}` ∪ `extract.functions[].{name,kind}`.
fn extract_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("extract", file);
    let mut out = Vec::new();
    for bucket in ["classes", "functions"] {
        if let Some(arr) = v.get(bucket).and_then(|c| c.as_array()) {
            for c in arr {
                push_kind(
                    &mut out,
                    c.get("name").and_then(|n| n.as_str()),
                    c.get("kind").and_then(|k| k.as_str()),
                );
            }
        }
    }
    out
}

/// `interface.classes[].{name,kind}` ∪ each class's `methods[]` (implicit
/// `kind:"method"`) ∪ `interface.functions[].{name,kind}`.
fn interface_kinds(file: &Path) -> Vec<(String, String)> {
    let v = run_json("interface", file);
    let mut out = Vec::new();
    if let Some(arr) = v.get("classes").and_then(|c| c.as_array()) {
        for c in arr {
            push_kind(
                &mut out,
                c.get("name").and_then(|n| n.as_str()),
                c.get("kind").and_then(|k| k.as_str()),
            );
            // Members of a class are, by construction, methods. The MethodInfo
            // struct carries no `kind` discriminator, so the kind is implicit.
            if let Some(methods) = c.get("methods").and_then(|m| m.as_array()) {
                for m in methods {
                    push_kind(&mut out, m.get("name").and_then(|n| n.as_str()), Some("method"));
                }
            }
        }
    }
    if let Some(arr) = v.get("functions").and_then(|c| c.as_array()) {
        for c in arr {
            push_kind(
                &mut out,
                c.get("name").and_then(|n| n.as_str()),
                c.get("kind").and_then(|k| k.as_str()),
            );
        }
    }
    out
}

/// Aggregate per-name kind claims across the three commands.
///
/// Returns `name -> (number of distinct commands that asserted a kind, the union
/// of kinds asserted)`. A name only participates in the invariant when it is
/// asserted (non-empty kind) by >= 2 commands — the INTERSECTION.
fn aggregate(
    s: &[(String, String)],
    e: &[(String, String)],
    i: &[(String, String)],
) -> BTreeMap<String, (usize, BTreeSet<String>)> {
    let mut by_name: BTreeMap<String, (BTreeSet<usize>, BTreeSet<String>)> = BTreeMap::new();
    for (cmd_idx, list) in [s, e, i].iter().enumerate() {
        for (name, kind) in list.iter() {
            let entry = by_name.entry(name.clone()).or_default();
            entry.0.insert(cmd_idx);
            entry.1.insert(kind.clone());
        }
    }
    by_name
        .into_iter()
        .map(|(name, (cmds, kinds))| (name, (cmds.len(), kinds)))
        .collect()
}

/// The principled allowance gate. Returns `Some(reason)` when a kind
/// disagreement for `name` in `lang` is a DOCUMENTED pre-existing modeling
/// difference (A1/A2/A3 in the module doc), `None` otherwise (a real
/// disagreement that must FAIL).
fn allowed_disagreement(lang: &str, kinds: &BTreeSet<String>) -> Option<&'static str> {
    let callable: BTreeSet<String> = ["function".to_string(), "method".to_string()].into();
    match lang {
        // A1 / A2 — Elixir & Scala def-flattening: structure-vs-interface seam,
        // scoped strictly to {function, method} (macro etc. excluded).
        "elixir" | "scala" if kinds.is_subset(&callable) => {
            Some("def-flattening seam (structure containment vs interface flatten); {function,method} only")
        }
        // A3 — Go structure coarse class-axis default (Stage-3-Go deferral):
        // structure reports `class` where extract/interface specialize.
        "go" if kinds.contains("class")
            && kinds
                .iter()
                .all(|k| matches!(k.as_str(), "class" | "struct" | "interface" | "type")) =>
        {
            Some("Go structure type_spec coarse `class` default (documented Stage-3-Go deferral)")
        }
        _ => None,
    }
}

/// Core invariant: scan the per-name aggregation, returning
/// `(shared_count, violations)` where `shared_count` is the number of names
/// asserted (non-empty kind) by >= 2 commands and `violations` are the
/// un-allowed kind disagreements among them.
fn kind_violations(
    lang: &str,
    s: &[(String, String)],
    e: &[(String, String)],
    i: &[(String, String)],
) -> (usize, Vec<String>) {
    let agg = aggregate(s, e, i);
    let mut shared = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for (name, (cmd_count, kinds)) in &agg {
        if *cmd_count < 2 {
            // Asserted by at most one command -> not in the intersection.
            continue;
        }
        shared += 1;
        if kinds.len() <= 1 {
            continue; // agreement
        }
        if allowed_disagreement(lang, kinds).is_some() {
            continue; // documented modeling difference (A1/A2/A3)
        }
        violations.push(format!("`{name}` -> {kinds:?}"));
    }
    (shared, violations)
}

/// Run the agreement invariant for one language fixture. `require_shared`
/// enforces a non-vacuous intersection (>= 1 shared entity); pass `false` only
/// for documented view-disjoint languages (see `ocaml_kinds_agree`).
fn assert_kind_agreement(lang: &str, filename: &str, src: &str, require_shared: bool) {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join(filename);
    fs::write(&file, src).unwrap();

    let s = structure_kinds(&file);
    let e = extract_kinds(&file);
    let i = interface_kinds(&file);
    let (shared, violations) = kind_violations(lang, &s, &e, &i);

    assert!(
        violations.is_empty(),
        "[{lang}] cross-command KIND disagreement (not a principled view diff):\n  {}\n\
         structure={s:?}\n  extract={e:?}\n  interface={i:?}",
        violations.join("\n  ")
    );
    if require_shared {
        // Guard against a vacuous green: the fixture must SHARE at least one
        // entity across >= 2 commands, otherwise the invariant proves nothing.
        assert!(
            shared >= 1,
            "[{lang}] no entity shared across >=2 commands — fixture proves nothing.\n\
             structure={s:?}\n  extract={e:?}\n  interface={i:?}"
        );
    }
}

// ============================================================================
// PER-LANGUAGE FIXTURES (embedded, machine-independent)
// ============================================================================

#[test]
fn typescript_kinds_agree() {
    // The plan's canonical /tmp/rc2_ts.ts: interface Foo, type Bar/Baz, class Qux
    // (+ a private helper, which legitimately stays a `method` in both structure
    // and interface — no allowance needed).
    assert_kind_agreement(
        "typescript",
        "rc2_ts.ts",
        "export interface Foo { b(): void; }\n\
         export type Bar = { x: number };\n\
         export type Baz = string | number;\n\
         export class Qux {\n  m(): void {}\n  private helper(): number { return 1; }\n}\n",
        true,
    );
}

#[test]
fn scala_kinds_agree() {
    // class / object / trait / enum / type-alias must AGREE exactly; the `def`
    // members (foo/bar) ride the A2 def-flattening allowance.
    assert_kind_agreement(
        "scala",
        "Demo.scala",
        "package demo\n\
         class MyClass(val x: Int)\n\
         object MyObject { def foo(): Int = 1 }\n\
         trait MyTrait { def bar(): Unit }\n\
         enum Color { case Red, Green, Blue }\n\
         type MyAlias = Int\n",
        true,
    );
}

#[test]
fn elixir_kinds_agree() {
    // The #57 payoff: `defmacro`/`defmacrop` must agree as `kind:"macro"` across
    // structure & interface. Plain `def`/`defp` ride the A1 def-flattening
    // allowance ({function, method}). Shape mirrors elixir-plug/builder.ex.
    assert_kind_agreement(
        "elixir",
        "my_mod.ex",
        "defmodule MyMod do\n\
         \x20 defmacro mac1(opts) do\n    quote do: unquote(opts)\n  end\n\n\
         \x20 defmacrop mac2(x) do\n    quote do: unquote(x)\n  end\n\n\
         \x20 def fun1(a), do: a\n\n\
         \x20 defp fun2(b), do: b\n\
         end\n",
        true,
    );
}

#[test]
fn ocaml_kinds_agree() {
    // OCaml is the one DOCUMENTED view-disjoint language: the three commands
    // surface non-overlapping axes — `structure` emits only the function axis
    // (`add`/`f`), `interface` emits only the type/module axis (`color`/`pair`),
    // and `extract` abstains (no `kind` on its function entries). No name carries
    // a non-empty kind in >= 2 commands, so the intersection is legitimately
    // empty (NOT an accidental vacuous fixture). We therefore run the
    // contradiction check with `require_shared=false` AND add a positive
    // function-vs-value assertion below so the test is never vacuously green.
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("demo.ml");
    fs::write(
        &file,
        "let add x y = x + y\n\
         let pi = 3.14\n\
         let f = fun x -> x + 1\n\
         type color = Red | Green | Blue\n\
         type pair = int * int\n",
    )
    .unwrap();

    let s = structure_kinds(&file);
    let e = extract_kinds(&file);
    let i = interface_kinds(&file);
    let (_shared, violations) = kind_violations("ocaml", &s, &e, &i);
    assert!(
        violations.is_empty(),
        "[ocaml] cross-command KIND disagreement:\n  {}\n  structure={s:?}\n  extract={e:?}\n  interface={i:?}",
        violations.join("\n  ")
    );

    // POSITIVE function-vs-value fact (the rc2 OCaml payoff,
    // `ocaml_value_definition_is_function`): the function `add` MUST appear on
    // structure's function axis, while the value `pi` MUST NOT — a value is not a
    // function. A regression that lumps values back onto the function axis (the
    // killed `ocaml_binding_has_params_simple` heuristic) flips this.
    assert!(
        s.iter().any(|(n, k)| n == "add" && k == "function"),
        "[ocaml] `add` must be kind:\"function\" in structure; structure={s:?}"
    );
    assert!(
        !s.iter().any(|(n, _)| n == "pi"),
        "[ocaml] value `pi` must NOT surface on structure's function axis; structure={s:?}"
    );
    // And the type aliases must agree wherever a kind is emitted: interface
    // reports them as `type` (color/pair); none may be mislabeled.
    for (n, k) in &i {
        if n == "color" || n == "pair" {
            assert_eq!(k, "type", "[ocaml] `{n}` must be kind:\"type\"; interface={i:?}");
        }
    }
}

#[test]
fn rust_kinds_agree() {
    assert_kind_agreement(
        "rust",
        "a.rs",
        "pub struct S { pub x: i32 }\n\
         pub enum E { A, B }\n\
         pub trait T { fn m(&self); }\n\
         pub fn freefn() -> i32 { 1 }\n\
         impl S { pub fn meth(&self) -> i32 { self.x } }\n",
        true,
    );
}

#[test]
fn go_kinds_agree() {
    // struct / interface carriers: extract & interface specialize via
    // classify_node; structure rides the A3 coarse-`class` allowance.
    assert_kind_agreement(
        "go",
        "a.go",
        "package demo\n\
         type Point struct { X int }\n\
         type Stringer interface { String() string }\n\
         func FreeFn() int { return 1 }\n\
         func (p Point) Meth() int { return p.X }\n",
        true,
    );
}

#[test]
fn python_kinds_agree() {
    assert_kind_agreement(
        "python",
        "a.py",
        "class Animal:\n    def speak(self): pass\n\ndef free_fn(): pass\n",
        true,
    );
}

#[test]
fn java_kinds_agree() {
    assert_kind_agreement(
        "java",
        "A.java",
        "public class Foo {\n  public int meth() { return 1; }\n}\n\
         public interface Bar { void b(); }\n\
         public enum E { A, B }\n",
        true,
    );
}

#[test]
fn ruby_kinds_agree() {
    assert_kind_agreement(
        "ruby",
        "a.rb",
        "class Dog\n  def bark; end\nend\n\
         module M\n  def helper; end\nend\n\
         def free_fn; end\n",
        true,
    );
}

#[test]
fn swift_kinds_agree() {
    assert_kind_agreement(
        "swift",
        "a.swift",
        "public class C { public func m() {} }\n\
         public struct S { public func n() {} }\n\
         public protocol P { func p() }\n\
         public enum E { case a, b }\n\
         public func freeFn() {}\n",
        true,
    );
}

#[test]
fn php_kinds_agree() {
    assert_kind_agreement(
        "php",
        "a.php",
        "<?php\n\
         class Foo { public function meth() {} }\n\
         interface Bar { public function b(); }\n\
         function freeFn() {}\n",
        true,
    );
}

#[test]
fn csharp_kinds_agree() {
    assert_kind_agreement(
        "csharp",
        "A.cs",
        "public class Foo { public int Meth() => 1; }\n\
         public interface Bar { void B(); }\n\
         public enum E { A, B }\n\
         public struct S { public int X; }\n",
        true,
    );
}
