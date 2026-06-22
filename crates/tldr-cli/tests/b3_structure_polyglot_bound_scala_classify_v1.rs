//! b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3)
//!
//! Two independent root causes pinned here:
//!
//! ## ROOT CAUSE 1 — polyglot `structure` on a directory is pathological
//!
//! The CL-15 default (multi-language directory scan) iterates EVERY detected
//! language and merges their files. On a real repo whose tree is dominated by
//! one language but also carries a handful of generated/vendored
//! documentation-site assets in a *different* language (the `java-retrofit`
//! corpus ships a 754 KB minified `website/public/.../main.js` dokka bundle),
//! the minority-language pass reads that bundle and emits a ~211 MB structure
//! dump. The dominant Java source alone is ~1.7 MB.
//!
//! The fix scopes the default polyglot scan to the **primary language family**:
//! a detected language is analyzed only when its file count is a meaningful
//! share of the dominant language's count. A genuinely balanced multi-language
//! tree (the CL-15 contract) keeps every language because each is a large share
//! of the dominant; a 306-Java-vs-34-docs-JS tree drops the docs noise. Dropped
//! minority languages are NOT silent — a stderr warning names them (the CL-15
//! "never silent" principle).
//!
//! ## ROOT CAUSE 2 — Scala `type` / containers mis-classified
//!
//! `classify_definition_node` put the `type_definition` node kind in `is_class`
//! UNCONDITIONALLY (the comment says "OCaml type definition"). For Scala that
//! mislabels a `type X = ...` alias as `kind:"class"`, and Scala's idiomatic
//! containers (`object`, `trait`, `enum`) were absent from the `definitions[]`
//! axis entirely. The fix language-gates the classification so OCaml keeps its
//! behaviour while Scala `type` surfaces as `kind:"type"` and Scala
//! `object`/`trait`/`enum` surface as their own container kinds.

use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn run_structure_json(path: &Path, extra: &[&str]) -> (Value, String) {
    let mut args: Vec<String> = vec![
        "structure".into(),
        path.to_str().unwrap().into(),
        "--format".into(),
        "json".into(),
        "-q".into(),
    ];
    for e in extra {
        args.push((*e).into());
    }
    let assert = tldr_cmd().args(&args).assert().success();
    let out = assert.get_output();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("structure must emit valid JSON: {e}\nstdout:\n{stdout}"));
    (v, stderr)
}

/// Collect every `definitions[].{name,kind}` pair across all files.
fn collect_defs(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
        for f in files {
            if let Some(defs) = f.get("definitions").and_then(|d| d.as_array()) {
                for d in defs {
                    let name = d.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let kind = d.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
                    out.push((name, kind));
                }
            }
        }
    }
    out
}

// =============================================================================
// ROOT CAUSE 1: polyglot directory scan is bounded to the primary family
// =============================================================================

/// A directory whose tree is dominated by one language (many small source
/// files) plus a single very large minority-language "docs bundle" file must
/// NOT have the minority pass blow the output up: the default polyglot scan
/// scopes to the dominant family, so the bundle is never read.
///
/// RED before the fix: the JS bundle pass is included and the merged structure
/// contains the bundle's definitions (and is enormous). GREEN after: the bundle
/// language is below the dominance share and excluded, so the bundle marker is
/// absent and the output is small.
#[test]
fn polyglot_structure_scopes_to_primary_family_excludes_skewed_minority() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    // Dominant language: 30 small Python files (clearly the primary family).
    for i in 0..30 {
        fs::write(
            root.join(format!("mod_{i}.py")),
            format!("def py_fn_{i}():\n    return {i}\n"),
        )
        .unwrap();
    }

    // Minority language: ONE big generated-docs-style JS bundle. Its functions
    // carry a unique marker so we can detect whether the JS pass ran. We make
    // it large (many defs) so that, if scanned, it dominates output size.
    let mut bundle = String::new();
    for i in 0..4000 {
        bundle.push_str(&format!("function docsBundleMarker_{i}(){{return {i};}}\n"));
    }
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("bundle.js"), &bundle).unwrap();

    let (v, stderr) = run_structure_json(root, &[]);
    let defs = collect_defs(&v);

    // Python (dominant, 30/31 = ~97%) MUST be analyzed.
    assert!(
        defs.iter().any(|(n, _)| n.starts_with("py_fn_")),
        "dominant Python family must be analyzed; got defs: {:?}",
        defs.iter().take(8).collect::<Vec<_>>()
    );

    // The skewed JS docs bundle (1/31 = ~3%) must NOT be analyzed: its marker
    // functions must be absent from the merged structure.
    let bundle_defs = defs.iter().filter(|(n, _)| n.starts_with("docsBundleMarker_")).count();
    assert_eq!(
        bundle_defs, 0,
        "skewed minority docs bundle must be excluded from the default polyglot \
         scan, but {bundle_defs} of its definitions leaked into the output"
    );

    // The exclusion must NOT be silent: stderr names the dropped language.
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("javascript") && lower.contains("warn"),
        "dropping a minority language must emit a stderr WARNING naming it; got stderr:\n{stderr}"
    );
}

/// CL-15 preservation: a genuinely BALANCED multi-language tree (equal file
/// counts) must still analyze EVERY language — the dominance gate keeps all of
/// them because each is a large share of the dominant. This guards against the
/// fix over-reaching and re-introducing the silent-drop the CL-15 contract
/// outlawed.
#[test]
fn polyglot_structure_balanced_tree_keeps_all_languages() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    fs::write(
        root.join("alpha.py"),
        "def py_balanced():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        root.join("beta.go"),
        "package main\nfunc goBalanced() int { return 2 }\n",
    )
    .unwrap();
    fs::write(
        root.join("gamma.ts"),
        "function tsBalanced(): number { return 3; }\n",
    )
    .unwrap();

    let (v, _stderr) = run_structure_json(root, &[]);
    let defs = collect_defs(&v);
    let names: Vec<&String> = defs.iter().map(|(n, _)| n).collect();

    assert!(
        names.iter().any(|n| n.as_str() == "py_balanced"),
        "balanced polyglot must include Python; got: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.as_str() == "goBalanced"),
        "balanced polyglot must include Go; got: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.as_str() == "tsBalanced"),
        "balanced polyglot must include TypeScript; got: {names:?}"
    );
}

/// Explicit `--lang` must be UNAFFECTED by the dominance gate: the user asked
/// for exactly one language and gets exactly that language's files, even when
/// it is a tiny minority of the tree.
#[test]
fn explicit_lang_bypasses_dominance_gate() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    for i in 0..30 {
        fs::write(
            root.join(format!("mod_{i}.py")),
            format!("def py_fn_{i}():\n    return {i}\n"),
        )
        .unwrap();
    }
    fs::write(
        root.join("tiny.go"),
        "package main\nfunc minorityGoFn() int { return 7 }\n",
    )
    .unwrap();

    // Pin Go explicitly — even though it is 1/31 of the tree it MUST be analyzed.
    let (v, _stderr) = run_structure_json(root, &["--lang", "go"]);
    let defs = collect_defs(&v);
    assert!(
        defs.iter().any(|(n, _)| n == "minorityGoFn"),
        "explicit --lang go must analyze Go even as a tiny minority; got: {defs:?}"
    );
    // And it must NOT have pulled in Python (single-language restriction).
    assert!(
        !defs.iter().any(|(n, _)| n.starts_with("py_fn_")),
        "explicit --lang go must not analyze Python; got: {defs:?}"
    );
}

// =============================================================================
// ROOT CAUSE 2: Scala type / object / trait / enum classification
// =============================================================================

const SCALA_SRC: &str = r#"package demo

type ResultAlias = String

class Container[A] {
  def get: A = ???
}

object Singleton {
  def helper(x: Int): Int = x + 1
}

trait Show[A] {
  def show(a: A): String
}

enum Color {
  case Red, Green, Blue
}
"#;

fn scala_defs() -> Vec<(String, String)> {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("Demo.scala");
    fs::write(&file, SCALA_SRC).unwrap();
    let (v, _stderr) = run_structure_json(&file, &["--lang", "scala"]);
    collect_defs(&v)
}

/// A Scala `type X = ...` alias must NOT be classified as `class`. It is a type
/// alias and must surface with `kind:"type"`.
#[test]
fn scala_type_alias_is_kind_type_not_class() {
    let defs = scala_defs();
    let result = defs
        .iter()
        .find(|(n, _)| n == "ResultAlias")
        .unwrap_or_else(|| panic!("Scala `type ResultAlias` must appear in definitions; got: {defs:?}"));
    assert_eq!(
        result.1, "type",
        "Scala `type X = ...` must classify as kind:\"type\", not \"{}\"; got: {:?}",
        result.1, defs
    );
}

/// Scala `object` (idiomatic singleton container) must be present in the
/// `definitions[]` axis with a container kind (`object`), not dropped.
#[test]
fn scala_object_container_present() {
    let defs = scala_defs();
    let obj = defs
        .iter()
        .find(|(n, _)| n == "Singleton")
        .unwrap_or_else(|| panic!("Scala `object Singleton` must appear in definitions; got: {defs:?}"));
    assert_eq!(
        obj.1, "object",
        "Scala `object` must classify as kind:\"object\"; got: {:?}",
        defs
    );
}

/// Scala `trait` must be present with `kind:"trait"`.
#[test]
fn scala_trait_container_present() {
    let defs = scala_defs();
    let tr = defs
        .iter()
        .find(|(n, _)| n == "Show")
        .unwrap_or_else(|| panic!("Scala `trait Show` must appear in definitions; got: {defs:?}"));
    assert_eq!(
        tr.1, "trait",
        "Scala `trait` must classify as kind:\"trait\"; got: {:?}",
        defs
    );
}

/// Scala `enum` must be present with `kind:"enum"`.
#[test]
fn scala_enum_container_present() {
    let defs = scala_defs();
    let en = defs
        .iter()
        .find(|(n, _)| n == "Color")
        .unwrap_or_else(|| panic!("Scala `enum Color` must appear in definitions; got: {defs:?}"));
    assert_eq!(
        en.1, "enum",
        "Scala `enum` must classify as kind:\"enum\"; got: {:?}",
        defs
    );
}

/// The ordinary Scala `class` must still classify as `class` (no regression).
#[test]
fn scala_class_still_class() {
    let defs = scala_defs();
    let cl = defs
        .iter()
        .find(|(n, _)| n == "Container")
        .unwrap_or_else(|| panic!("Scala `class Container` must appear in definitions; got: {defs:?}"));
    assert_eq!(cl.1, "class", "Scala `class` must remain kind:\"class\"; got: {:?}", defs);
}

/// OCaml preservation: OCaml `type_definition` must keep its prior behaviour.
/// On HEAD the OCaml `type` produces NO `definitions[]` entry (the name lives
/// in a nested `type_binding > type_constructor`, so the shared name lookup
/// returns None and the class-classified node is dropped). The language gate
/// must NOT change that — OCaml must not suddenly start emitting `type` defs,
/// and crucially must NOT emit a Scala-style `kind:"type"`/`"object"` for any
/// OCaml construct. We pin the stable observable: the OCaml `let` function is
/// present and no definition is classified with the Scala-only container kinds.
#[test]
fn ocaml_type_definition_behaviour_preserved() {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("demo.ml");
    fs::write(
        &file,
        "type color = Red | Green | Blue\nlet make x = x + 1\n",
    )
    .unwrap();
    let (v, _stderr) = run_structure_json(&file, &["--lang", "ocaml"]);
    let defs = collect_defs(&v);

    // The OCaml function is still extracted.
    assert!(
        defs.iter().any(|(n, k)| n == "make" && k == "function"),
        "OCaml `let make` must remain a function definition; got: {defs:?}"
    );
    // No OCaml definition adopts the Scala-only `type` container kind: the
    // Scala gate must not leak into OCaml classification.
    assert!(
        !defs.iter().any(|(_, k)| k == "type"),
        "OCaml classification must not emit Scala `kind:\"type\"`; got: {defs:?}"
    );
}
