//! doclinks-v1 — the document reference graph, end to end.
//!
//! Pins the three surfaces of the document-reference core working together:
//!
//! 1. `tldr imports` on markdown/html/xml emits link targets as ImportInfo
//!    (`module` = raw target, `is_from = true`, `alias` = provenance label).
//! 2. `tldr importers <file> <root> --lang markdown` finds the documents that
//!    LINK to a target (path matching — doc arm of `module_matches`).
//! 3. `tldr impact <root>/<file>` on a document computes the file-level blast
//!    radius: the transitive reverse-link closure via the existing impact BFS
//!    keyed `(file, "<doc>")` — with `total_targets == 1`, external URLs
//!    absent from the graph, and depth-correct nesting.
//!
//! Fixture (tempdir): `index.md` → `a.md` → `b.md` → `c.md#frag` (c.md
//! intentionally absent — the link still shows up in imports but contributes
//! no edge), plus `page.html` and `schema.xml` for the html/xml field pins.
//! No daemon is started; every command takes the direct-compute path.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: impl AsRef<Path>, body: &str) {
    let p = p.as_ref();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

fn build_doc_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(root.join("index.md"), "# Index\n\n[A](a.md)\n");
    write(
        root.join("a.md"),
        "# A\n\n[B](b.md) and [ext](https://example.com/x)\n",
    );
    write(root.join("b.md"), "# B\n\n[C](c.md#frag)\n");
    write(
        root.join("page.html"),
        r##"<!DOCTYPE html>
<html>
<head><script src="app.js"></script></head>
<body>
<a href="other.html">Other</a>
<img src="img/logo.png" alt="logo">
<a href="#section">Jump</a>
</body>
</html>
"##,
    );
    write(
        root.join("schema.xml"),
        r#"<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="style.xsl"?>
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:xlink="http://www.w3.org/1999/xlink"
      xmlns:xi="http://www.w3.org/2001/XInclude"
      xsi:noNamespaceSchemaLocation="schema/root.xsd">
  <xi:include href="parts/one.xml"/>
  <child xlink:href="more.xml"/>
</root>
"#,
    );
    dir
}

fn run_json(args: &[&str], cwd: &Path) -> (Option<i32>, Value) {
    let output = tldr_cmd()
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("run tldr {:?}: {e}", args));
    let code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout of {args:?} is not JSON ({e}): {stdout:?}"));
    (code, json)
}

fn collect_files(node: &Value, acc: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            if let Some(file) = map.get("file").and_then(|f| f.as_str()) {
                acc.push(file.to_string());
            }
            for value in map.values() {
                collect_files(value, acc);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_files(item, acc);
            }
        }
        _ => {}
    }
}

// =============================================================================
// (1) imports
// =============================================================================

/// `tldr imports index.md` — markdown links ride the ImportInfo shape with
/// the raw target in `module`, `is_from: true` and the link text as `alias`.
#[test]
fn imports_markdown_emits_link_targets_with_provenance() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "index.md", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));

    // schema-unification-v1 BUG-18 envelope shape.
    assert_eq!(json["language"], "markdown");
    assert!(
        json["file"].as_str().unwrap_or("").ends_with("index.md"),
        "envelope.file = {}",
        json["file"]
    );

    let imports = json["imports"].as_array().expect("imports array");
    assert_eq!(imports.len(), 1, "index.md links exactly one target");
    assert_eq!(imports[0]["module"], "a.md");
    assert_eq!(imports[0]["is_from"], true);
    assert_eq!(imports[0]["alias"], "A", "alias = link text");
    // names is skip_serializing_if empty for document links.
    assert!(imports[0]["names"].is_null());
}

/// The external URL stays in the imports output (it is a real reference)
/// while the fragment-only target does not.
#[test]
fn imports_markdown_keeps_external_urls_drops_fragments() {
    let dir = build_doc_project();
    let root = dir.path();

    let (_, json) = run_json(&["imports", "a.md", "-f", "json", "-q"], root);
    let modules: Vec<&str> = json["imports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert!(modules.contains(&"b.md"), "modules = {modules:?}");
    assert!(
        modules.contains(&"https://example.com/x"),
        "external URLs stay in imports output, got {modules:?}"
    );

    let (_, json) = run_json(&["imports", "b.md", "-f", "json", "-q"], root);
    let modules: Vec<&str> = json["imports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert_eq!(modules, vec!["c.md#frag"], "raw target kept exactly");
}

/// HTML field pin: href/src ride `module`, the attribute name rides `alias`,
/// the fragment-only anchor is dropped.
#[test]
fn imports_html_fields() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "page.html", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "html");

    let imports = json["imports"].as_array().unwrap();
    let modules: Vec<&str> = imports
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert!(modules.contains(&"other.html"), "{modules:?}");
    assert!(modules.contains(&"app.js"), "{modules:?}");
    assert!(modules.contains(&"img/logo.png"), "{modules:?}");
    assert!(!modules.iter().any(|m| m.starts_with('#')), "{modules:?}");

    let href = imports
        .iter()
        .find(|i| i["module"] == "other.html")
        .expect("other.html entry");
    assert_eq!(href["alias"], "href", "alias = attribute name");
    assert_eq!(href["is_from"], true);

    let script = imports
        .iter()
        .find(|i| i["module"] == "app.js")
        .expect("app.js entry");
    assert_eq!(script["alias"], "src");
}

/// XML field pin: xml-stylesheet PI, xsi:noNamespaceSchemaLocation,
/// xi:include href and xlink:href — each with its role label in `alias`.
#[test]
fn imports_xml_fields() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "schema.xml", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "xml");

    let imports = json["imports"].as_array().unwrap();
    let by_module = |m: &str| {
        imports
            .iter()
            .find(|i| i["module"] == m)
            .unwrap_or_else(|| panic!("{m} missing from {:?}", imports))
    };

    assert_eq!(by_module("style.xsl")["alias"], "xml-stylesheet");
    assert_eq!(
        by_module("schema/root.xsd")["alias"],
        "xsi:nonamespaceschemalocation"
    );
    assert_eq!(
        by_module("parts/one.xml")["alias"],
        "href",
        "xi:include href"
    );
    assert_eq!(by_module("more.xml")["alias"], "xlink:href");
    for entry in imports {
        assert_eq!(entry["is_from"], true);
    }
}

// =============================================================================
// (2) importers
// =============================================================================

/// `tldr importers a.md <root> --lang markdown` finds index.md — the doc arm
/// of module_matches resolves link targets by path.
#[test]
fn importers_finds_markdown_linker() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "a.md",
            root.to_str().unwrap(),
            "--lang",
            "markdown",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["module"], "a.md");
    assert_eq!(json["total"], 1, "only index.md links a.md: {json}");

    let importers = json["importers"].as_array().unwrap();
    assert!(importers[0]["file"].as_str().unwrap().ends_with("index.md"));
    assert_eq!(importers[0]["line"], 3, "the [A](a.md) line");
    assert!(importers[0]["import_statement"]
        .as_str()
        .unwrap()
        .contains("a.md"));
}

/// Fragment/query suffixes normalize away: `importers c.md` finds b.md even
/// though the link is written `c.md#frag`.
#[test]
fn importers_normalizes_fragments() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "c.md",
            root.to_str().unwrap(),
            "--lang",
            "markdown",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total"], 1);
    assert!(json["importers"][0]["file"]
        .as_str()
        .unwrap()
        .ends_with("b.md"));
}

/// A target nobody links to yields an honest empty report (exit 0).
#[test]
fn importers_no_linkers_reports_empty() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "nobody-links-me.md",
            root.to_str().unwrap(),
            "--lang",
            "markdown",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total"], 0);
    assert_eq!(json["importers"].as_array().unwrap().len(), 0);
}

// =============================================================================
// (3) impact — document blast radius
// =============================================================================

/// `tldr impact <root>/b.md` — the transitive reverse-link closure contains
/// index.md and a.md with depth-correct nesting, total_targets == 1, the
/// "<doc>" provenance note, and NO external URL anywhere in the graph.
#[test]
fn impact_document_transitive_reverse_link_closure() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("b.md").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0), "impact on a document must succeed");

    assert_eq!(json["total_targets"], 1);
    let targets = json["targets"].as_object().unwrap();
    assert_eq!(targets.len(), 1);
    let (key, tree) = targets.iter().next().unwrap();
    assert!(key.ends_with("b.md:<doc>"), "targets key = {key}");
    assert_eq!(tree["function"], "<doc>");
    assert_eq!(tree["note"], "discovered via document link");

    // Depth-correct nesting: b.md <- a.md <- index.md.
    assert_eq!(tree["caller_count"], 1);
    let callers = tree["callers"].as_array().unwrap();
    assert_eq!(callers.len(), 1);
    assert!(callers[0]["file"].as_str().unwrap().ends_with("a.md"));
    assert_eq!(callers[0]["caller_count"], 1);
    let grandparents = callers[0]["callers"].as_array().unwrap();
    assert_eq!(grandparents.len(), 1);
    assert!(grandparents[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("index.md"));
    assert_eq!(grandparents[0]["caller_count"], 0);

    // Closure membership + external-URL absence, checked over every file in
    // the report (not just the spine).
    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("index.md")),
        "closure must contain index.md: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("a.md")),
        "closure must contain a.md"
    );
    assert!(
        !files.iter().any(|f| f.contains("example.com")),
        "external URLs never enter the graph: {files:?}"
    );
}

/// Depth semantics are inherited from the impact BFS: `--depth 1` keeps the
/// direct caller (a.md) and truncates its subtree.
#[test]
fn impact_document_depth_truncation() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("b.md").to_str().unwrap(),
            "--depth",
            "1",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));

    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    let callers = tree["callers"].as_array().unwrap();
    assert_eq!(callers.len(), 1);
    assert!(callers[0]["file"].as_str().unwrap().ends_with("a.md"));
    assert_eq!(
        callers[0]["truncated"], true,
        "a.md's subtree is cut at depth 1"
    );
    assert!(callers[0]["callers"].as_array().unwrap().is_empty());
}

/// The doc file can also arrive in the PATH slot (`tldr impact <func>
/// <root>/b.md`) — same closure, same shape.
#[test]
fn impact_document_via_path_slot() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            "whatever",
            root.join("b.md").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total_targets"], 1);
    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert!(tree["callers"].as_array().unwrap().len() >= 1);
}

/// A document nobody links to succeeds with an empty closure (honest entry
/// point), and the root note still carries the document provenance.
#[test]
fn impact_document_without_linkers_is_empty_closure() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("index.md").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total_targets"], 1);
    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(tree["caller_count"], 0);
    assert!(tree["callers"].as_array().unwrap().is_empty());
    assert_eq!(tree["note"], "discovered via document link");
}

/// Exit codes: missing document → non-zero; existing document → 0.
#[test]
fn impact_document_exit_codes() {
    let dir = build_doc_project();
    let root = dir.path();

    let out = tldr_cmd()
        .args(["impact", root.join("missing.md").to_str().unwrap(), "-q"])
        .current_dir(root)
        .output()
        .expect("run impact on missing doc");
    assert!(
        !out.status.success(),
        "impact on a missing document must fail"
    );

    let out = tldr_cmd()
        .args(["imports", root.join("missing.md").to_str().unwrap(), "-q"])
        .current_dir(root)
        .output()
        .expect("run imports on missing doc");
    assert!(!out.status.success(), "imports on a missing file must fail");
}
