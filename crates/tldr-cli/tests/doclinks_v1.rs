//! doclinks-v1 — the document reference graph, end to end.
//!
//! Pins the three surfaces of the document-reference core working together:
//!
//! 1. `tldr imports` on markdown/html/xml emits link targets as ImportInfo
//!    (`module` = raw target, `is_from = true`, `alias` = provenance label);
//!    css/latex loaded elements (`@import`, `url()`, `\input`,
//!    `\includegraphics`, `\bibliography`) ride the same shape.
//! 2. `tldr importers <file> <root> --lang markdown|latex` finds the
//!    documents that LINK to a target (path matching — doc arm of
//!    `module_matches`).
//! 3. `tldr impact <root>/<file>` on a document computes the file-level blast
//!    radius: the transitive reverse-link closure via the existing impact BFS
//!    keyed `(file, "<doc>")` — with `total_targets == 1`, external URLs
//!    absent from the graph, and depth-correct nesting.
//!
//! Fixtures (tempdirs): `build_doc_project` has `index.md` → `a.md` →
//! `b.md` → `c.md#frag` (c.md intentionally absent — the link still shows up
//! in imports but contributes no edge), plus `page.html` and `schema.xml` for
//! the html/xml field pins. `build_style_project` has the css/latex/md-fence
//! batch: `styles.css` → `theme.css` via @import plus font/image url() loads,
//! `main.tex` → chapter/graphic/bibliography targets, and `a.md` with a real
//! link plus a fenced example block whose fake links must stay inert.
//! `build_config_project` has the config batch: `openapi.json` `$ref` →
//! `schemas/user.json` (nested, so a `package.json` root marker resolves the
//! impact doc-root), `deploy.yaml` `$ref` → `config/base.yaml` next to an
//! inert Actions `include:` matrix and local-action `uses:`, `app.toml`'s
//! path-shaped string value → `img/logo.svg`, and `main.sh` sourcing
//! `lib/common.sh` via `source` and the POSIX `.` spelling. The plain-text
//! batch adds `build_text_project`: `notes.txt` carries a bare URL, an
//! angle-wrapped path with spaces (`<./docs/guide with spaces.md>`, real on
//! disk), a shell-escaped path and a plain relative path (`./b.txt`), pinning
//! the prose reference scan end to end (imports fields, the impact closure
//! of the spaced target, and importers `--lang text`). No
//! daemon is started; every command takes the direct-compute path.

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

/// Fixture for the css/latex/md-fence batch: `styles.css` imports
/// `theme.css` and loads a font + an image through `url()` (the "loaded
/// elements"); `main.tex` inputs a chapter, includes a graphic and declares
/// a two-file bibliography; `a.md` carries a real link plus a fenced example
/// block whose fake links must stay inert.
fn build_style_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(
        root.join("styles.css"),
        concat!(
            "@import \"theme.css\";\n",
            "@font-face {\n",
            "  font-family: \"Inter\";\n",
            "  src: url(fonts/a.woff2) format(\"woff2\");\n",
            "}\n",
            ".hero {\n",
            "  background: url(img/hero.png) no-repeat;\n",
            "}\n",
        ),
    );
    write(root.join("theme.css"), "body { margin: 0; }\n");
    write(root.join("fonts/a.woff2"), "woff2");
    write(root.join("img/hero.png"), "png");

    write(
        root.join("main.tex"),
        "\\input{chapters/ch1}\n\\includegraphics{fig.png}\n\\bibliography{refs,more}\n",
    );
    write(root.join("chapters/ch1.tex"), "\\section{One}\n");
    write(root.join("refs.bib"), "@book{k, title={K}}\n");
    write(root.join("more.bib"), "@book{m, title={M}}\n");
    write(root.join("fig.png"), "png");

    write(
        root.join("a.md"),
        r#"# A

[real](real.md)

```rust
let x = "[fake](nope.md)";
let u = <https://fake.example>;
```

tail
"#,
    );
    write(root.join("real.md"), "# Real\n");
    dir
}

/// Fixture for the config batch: `openapi.json` carries an external `$ref`
/// to `schemas/user.json` (plus a non-string `extends` and an internal JSON
/// Pointer that must both stay inert); `deploy.yaml` has a real `$ref` to
/// `config/base.yaml` next to an Actions-style `strategy.matrix.include`
/// that must NOT emit (and a local-action `uses:` — the key policy is
/// deliberately strict: only `$ref`/`extends`); `app.toml` carries a
/// path-shaped string value plus the classic non-path negatives; `main.sh`
/// sources `lib/common.sh` with both `source` and the POSIX `.` spelling.
/// A minimal `package.json` marks the project root so `explain_project_root`
/// resolves the doc-root for NESTED impact targets (`schemas/user.json`).
fn build_config_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(
        root.join("package.json"),
        r#"{ "name": "fixture", "private": true }"#,
    );
    write(
        root.join("openapi.json"),
        r##"{
  "openapi": "3.0.0",
  "info": { "title": "api", "version": "1.0.0" },
  "components": {
    "schemas": {
      "user": { "$ref": "./schemas/user.json", "extends": 42 },
      "pet": { "$ref": "#/components/schemas/user" }
    }
  }
}"##,
    );
    write(root.join("schemas/user.json"), r#"{ "type": "object" }"#);

    write(
        root.join("deploy.yaml"),
        concat!(
            "name: deploy\n",
            "on: push\n",
            "jobs:\n",
            "  deploy:\n",
            "    strategy:\n",
            "      matrix:\n",
            "        include:\n",
            "          - os: ubuntu-latest\n",
            "            config: ./ci/linux.yaml\n",
            "    steps:\n",
            "      - run: ./build.sh\n",
            "  publish:\n",
            "    uses: ./.github/actions/publish\n",
            "deploy:\n",
            "  $ref: \"./config/base.yaml\"\n",
        ),
    );
    write(root.join("config/base.yaml"), "shared: true\n");

    write(
        root.join("app.toml"),
        concat!(
            "name = \"tldr\"\n",
            "version = \"1.2.3\"\n",
            "code = \"foo_bar\"\n",
            "\n",
            "[assets]\n",
            "asset = \"./img/logo.svg\"\n",
        ),
    );
    write(
        root.join("img/logo.svg"),
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/> "#,
    );

    write(
        root.join("main.sh"),
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "source ./lib/common.sh\n",
            ". /etc/profile\n",
            "# source ./lib/decoy.sh\n",
            "echo .hidden\n",
        ),
    );
    write(root.join("lib/common.sh"), "log() { echo \"$*\"; }\n");
    dir
}

/// Fixture for the plain-text batch: `notes.txt` carries the whole prose
/// reference surface — a bare URL, an angle-wrapped path with spaces, a
/// shell-escaped path and a plain relative path — plus a spaced target file
/// (`docs/guide with spaces.md`, real on disk) and a second `.txt` to link
/// to.
fn build_text_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Root marker: the impact target (`docs/guide with spaces.md`) is NESTED,
    // so `explain_project_root` needs a project marker at the root to resolve
    // the doc-root to the project (the same trick build_config_project uses
    // for `schemas/user.json`).
    write(
        root.join("package.json"),
        r#"{ "name": "fixture", "private": true }"#,
    );
    write(
        root.join("notes.txt"),
        concat!(
            "Project notes.\n",
            "\n",
            "See https://example.com/docs for the upstream manual.\n",
            "The full guide lives at <./docs/guide with spaces.md>.\n",
            "Shell-escaped dump: cat my\\ file.txt\n",
            "Related: ./b.txt\n",
        ),
    );
    write(root.join("docs/guide with spaces.md"), "# Guide\n");
    write(root.join("b.txt"), "second plain-text file\n");
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

// =============================================================================
// (4) css / latex / md-fence batch (build_style_project)
// =============================================================================

/// `tldr imports styles.css` — the @import and both url() loads ride
/// ImportInfo in source order: `alias` = "import" for @import, "url" for
/// url() tokens (the loaded elements: stylesheet, font, image).
#[test]
fn imports_css_emits_import_and_url_targets() {
    let dir = build_style_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "styles.css", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "css");

    let imports = json["imports"].as_array().unwrap();
    assert_eq!(imports.len(), 3, "exactly the 3 loaded elements: {json}");

    assert_eq!(imports[0]["module"], "theme.css");
    assert_eq!(imports[0]["alias"], "import");
    assert_eq!(imports[0]["is_from"], true);

    assert_eq!(imports[1]["module"], "fonts/a.woff2");
    assert_eq!(imports[1]["alias"], "url");

    assert_eq!(imports[2]["module"], "img/hero.png");
    assert_eq!(imports[2]["alias"], "url");
}

/// `tldr imports main.tex` — one ImportInfo per braced target: `\input`
/// keeps the raw path (no .tex appended), `\includegraphics` rides its
/// command name, and `\bibliography{refs,more}` comma-splits into two
/// entries with the same command alias.
#[test]
fn imports_latex_emits_one_entry_per_target() {
    let dir = build_style_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "main.tex", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "latex");

    let imports = json["imports"].as_array().unwrap();
    assert_eq!(imports.len(), 4, "ch1 + fig + refs + more: {json}");

    let by_module = |m: &str| {
        imports
            .iter()
            .find(|i| i["module"] == m)
            .unwrap_or_else(|| panic!("{m} missing from {:?}", imports))
    };
    assert_eq!(by_module("chapters/ch1")["alias"], "input");
    assert_eq!(by_module("fig.png")["alias"], "includegraphics");
    assert_eq!(by_module("refs")["alias"], "bibliography");
    assert_eq!(by_module("more")["alias"], "bibliography");
    for entry in imports {
        assert_eq!(entry["is_from"], true);
    }
}

/// Markdown fenced example blocks are masked: the fake link and autolink
/// inside the fence never emit, the real link outside does.
#[test]
fn imports_markdown_fenced_example_block_stays_inert() {
    let dir = build_style_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "a.md", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    let modules: Vec<&str> = json["imports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert!(
        modules.contains(&"real.md"),
        "the real link emits: {modules:?}"
    );
    assert!(
        !modules.iter().any(|m| m.contains("nope.md")),
        "the fake link inside the fence must NOT emit: {modules:?}"
    );
    assert!(
        !modules.iter().any(|m| m.contains("fake.example")),
        "the fake autolink inside the fence must NOT emit: {modules:?}"
    );
    assert_eq!(modules.len(), 1, "exactly the real link: {modules:?}");
}

/// `tldr importers chapters/ch1.tex <root> --lang latex` finds main.tex —
/// the doc arm of module_matches works for latex path targets.
#[test]
fn importers_finds_latex_input_source() {
    let dir = build_style_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "chapters/ch1.tex",
            root.to_str().unwrap(),
            "--lang",
            "latex",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total"], 1, "only main.tex inputs ch1: {json}");
    assert!(json["importers"][0]["file"]
        .as_str()
        .unwrap()
        .ends_with("main.tex"));
    assert!(json["importers"][0]["import_statement"]
        .as_str()
        .unwrap()
        .contains("chapters/ch1"));
}

/// `tldr impact <root>/theme.css` — the reverse closure of an @import'ed
/// stylesheet contains styles.css (the loaded-element edge is a real
/// document-reference edge).
#[test]
fn impact_css_import_closure_finds_the_stylesheet() {
    let dir = build_style_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("theme.css").to_str().unwrap(),
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
    assert_eq!(tree["note"], "discovered via document link");
    let callers = tree["callers"].as_array().unwrap();
    assert_eq!(callers.len(), 1, "styles.css imports theme.css: {json}");
    assert!(callers[0]["file"].as_str().unwrap().ends_with("styles.css"));
}

// =============================================================================
// (5) config batch (build_config_project): json / yaml / toml / bash
// =============================================================================

/// `tldr imports openapi.json` — the AST-keyed `$ref` key policy: the
/// external `./schemas/user.json` emits with `alias: "$ref"`, the
/// non-string `extends: 42` and the internal JSON Pointer stay inert.
#[test]
fn imports_json_emits_only_external_ref_keys() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "openapi.json", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "json");

    let imports = json["imports"].as_array().unwrap();
    assert_eq!(imports.len(), 1, "exactly the external $ref: {json}");
    assert_eq!(imports[0]["module"], "./schemas/user.json");
    assert_eq!(imports[0]["alias"], "$ref", "alias = the matched key");
    assert_eq!(imports[0]["is_from"], true);
}

/// `tldr imports deploy.yaml` — `$ref` emits; the Actions
/// `strategy.matrix.include` (whose entries carry a path-looking
/// `config:` value) and the local-action `uses:` do NOT — YAML is
/// key-gated on `$ref`/`extends` only.
#[test]
fn imports_yaml_ref_emits_include_matrix_and_uses_stay_inert() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "deploy.yaml", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "yaml");

    let imports = json["imports"].as_array().unwrap();
    let modules: Vec<&str> = imports
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert_eq!(
        modules,
        vec!["./config/base.yaml"],
        "exactly the $ref target: {modules:?}"
    );
    assert!(!modules.iter().any(|m| m.contains("linux.yaml")));
    assert!(!modules.iter().any(|m| m.contains("actions/publish")));
}

/// `tldr imports app.toml` — the string-value path scan surfaces the
/// path-shaped value with alias `path`; bare words (`tldr`), version
/// strings (`1.2.3`) and `foo_bar` never emit.
#[test]
fn imports_toml_path_scan_with_non_path_negatives() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "app.toml", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "toml");

    let imports = json["imports"].as_array().unwrap();
    assert_eq!(imports.len(), 1, "exactly the path value: {json}");
    assert_eq!(imports[0]["module"], "./img/logo.svg");
    assert_eq!(imports[0]["alias"], "path");
}

/// `tldr imports main.sh` — `source ./lib/common.sh` and `. /etc/profile`
/// both emit (alias `source`); the commented-out `source` decoy and
/// `echo .hidden` stay inert.
#[test]
fn imports_bash_source_with_posix_dot_and_comment_negatives() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "main.sh", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "bash");

    let imports = json["imports"].as_array().unwrap();
    let modules: Vec<&str> = imports
        .iter()
        .filter_map(|i| i["module"].as_str())
        .collect();
    assert_eq!(
        modules,
        vec!["./lib/common.sh", "/etc/profile"],
        "line-ordered source targets: {modules:?}"
    );
    for entry in imports {
        assert_eq!(entry["alias"], "source");
    }
    assert!(!modules.iter().any(|m| m.contains("decoy")));
    assert!(!modules.iter().any(|m| m.contains("hidden")));
}

/// `tldr importers` across the four new doc arms — path normalization is
/// identical to the md/html/xml/css/latex arm (`./`-stripping, exact +
/// path-suffix match).
#[test]
fn importers_finds_config_reference_sources() {
    let dir = build_config_project();
    let root = dir.path();

    for (query, lang, expected_file) in [
        ("schemas/user.json", "json", "openapi.json"),
        ("lib/common.sh", "bash", "main.sh"),
        ("img/logo.svg", "toml", "app.toml"),
        ("config/base.yaml", "yaml", "deploy.yaml"),
    ] {
        let (code, json) = run_json(
            &[
                "importers",
                query,
                root.to_str().unwrap(),
                "--lang",
                lang,
                "-f",
                "json",
                "-q",
            ],
            root,
        );
        assert_eq!(code, Some(0), "importers {query} --lang {lang}");
        assert_eq!(json["total"], 1, "importers {query} --lang {lang}: {json}");
        assert!(
            json["importers"][0]["file"]
                .as_str()
                .unwrap()
                .ends_with(expected_file),
            "importers {query} --lang {lang}: {json}"
        );
    }
}

/// `tldr impact <root>/schemas/user.json` — a nested JSON config target's
/// reverse-link closure reaches openapi.json (the `package.json` marker
/// resolves the doc root for the nested file).
#[test]
fn impact_json_config_closure_finds_the_referring_schema() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("schemas/user.json").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0), "impact on a json config must succeed");
    assert_eq!(json["total_targets"], 1);

    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(tree["function"], "<doc>");
    assert_eq!(tree["note"], "discovered via document link");

    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("openapi.json")),
        "closure must contain openapi.json: {files:?}"
    );
}

/// The yaml arm closes the loop too: `tldr impact <root>/config/base.yaml`
/// finds deploy.yaml through its `$ref`.
#[test]
fn impact_yaml_config_closure_finds_the_referring_workflow() {
    let dir = build_config_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("config/base.yaml").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["total_targets"], 1);

    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("deploy.yaml")),
        "closure must contain deploy.yaml: {files:?}"
    );
}

/// Fixture for the virtual-documents batch: `page.html` embeds an inline
/// `<style>` (an `@import`ed stylesheet + a font and an image through
/// `url()`) and an inline `<script>` (an ESM import of `./lib/x.js` and a
/// multi-line `fetch("api/v1.json")` — the string forms its own token, so
/// the path scan extracts it cleanly). The referenced targets exist on disk
/// (a `package.json` root marker resolves the impact doc-root). This pins
/// the virtual-documents-v1 blast-radius story end to end: embedded
/// documents' outbound references join the HOST file's imports with `via`
/// provenance, and targets referenced ONLY from an embedded script/style are
/// discoverable through `tldr impact` — including non-document targets
/// (the `.js` code file via the single-arg file rule and the binary `.woff2`
/// font, any-target-impact-v1).
fn build_virtual_doc_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(
        root.join("package.json"),
        r#"{ "name": "fixture", "private": true }"#,
    );
    write(
        root.join("page.html"),
        r#"<!DOCTYPE html>
<html>
<head>
<style>
@import url("theme.css");
@font-face {
  font-family: "Inter";
  src: url(fonts/a.woff2) format("woff2");
}
.hero { background: url(img/hero.png); }
</style>
<script src="app.js"></script>
</head>
<body>
<script>
import { init } from './lib/x.js';
import { extra } from './lib/x.js';
const res = await fetch(
  "api/v1.json"
);
export function boot() {
  return init();
}
</script>
</body>
</html>
"#,
    );
    write(root.join("theme.css"), "body { margin: 0; }\n");
    write(root.join("fonts/a.woff2"), "woff2-bytes\n");
    write(root.join("img/hero.png"), "png\n");
    write(root.join("lib/x.js"), "export const init = () => 1;\n");
    write(root.join("api/v1.json"), "{ \"v\": 1 }\n");
    write(root.join("app.js"), "// external script\n");
    dir
}

// =============================================================================
// (7) virtual-documents batch (build_virtual_doc_project): embedded
//     <script>/<style> bodies are indexed virtual documents
// =============================================================================

/// `tldr imports page.html` — the host's own rows (the external script's
/// `src`) stay via-less, while the embedded documents' outbound references
/// carry `via` provenance: the style's loaded elements under
/// `page.html#style-1`, the script's import + fetch targets under
/// `page.html#script-1`. The script imports `./lib/x.js` TWICE — the
/// `(module, via)` dedup collapses them to ONE row (the first import's
/// names survive).
#[test]
fn imports_html_embedded_documents_join_the_host_imports_with_via() {
    let dir = build_virtual_doc_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "page.html", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "html");

    let imports = json["imports"].as_array().unwrap();
    let find = |module: &str| {
        imports
            .iter()
            .filter(|i| i["module"] == module)
            .collect::<Vec<_>>()
    };

    // Host-level row (written in the markup itself): no `via`.
    let app = find("app.js");
    assert_eq!(app.len(), 1, "the external script's src row: {imports:?}");
    assert_eq!(app[0]["alias"], "src");
    assert!(
        app[0]["via"].is_null(),
        "host-level rows carry no virtual-document provenance"
    );

    // The embedded STYLE's loaded elements, provenance `page.html#style-1`.
    let theme = find("theme.css");
    assert_eq!(theme.len(), 1, "the @import target: {imports:?}");
    assert_eq!(theme[0]["alias"], "import");
    assert_eq!(theme[0]["via"], "page.html#style-1");
    assert_eq!(theme[0]["is_from"], true);

    let woff = find("fonts/a.woff2");
    assert_eq!(woff.len(), 1, "the @font-face url() load: {imports:?}");
    assert_eq!(woff[0]["alias"], "url");
    assert_eq!(woff[0]["via"], "page.html#style-1");

    let hero = find("img/hero.png");
    assert_eq!(hero.len(), 1, "the background url() load: {imports:?}");
    assert_eq!(hero[0]["alias"], "url");
    assert_eq!(hero[0]["via"], "page.html#style-1");

    // The embedded SCRIPT's references, provenance `page.html#script-1`.
    // Two `import` lines from the same module → ONE row (dedup by
    // (module, via)); the first import's names survive.
    let xjs = find("./lib/x.js");
    assert_eq!(
        xjs.len(),
        1,
        "the same module imported twice is one (module, via) edge: {imports:?}"
    );
    assert_eq!(xjs[0]["via"], "page.html#script-1");
    assert_eq!(
        xjs[0]["names"],
        serde_json::json!(["init"]),
        "the FIRST import's names survive the dedup"
    );

    let api = find("api/v1.json");
    assert_eq!(api.len(), 1, "the fetch target: {imports:?}");
    assert_eq!(api[0]["via"], "page.html#script-1");
    assert_eq!(api[0]["alias"], "path");
}

/// The definitions of `tldr structure page.html` agree with the imports'
/// `via` names: the style's selector/at-rule rows carry `container` =
/// `page.html#style-1` (the same walk numbers both sides).
#[test]
fn structure_containers_agree_with_imports_via_naming() {
    let dir = build_virtual_doc_project();
    let root = dir.path();

    let (code, json) = run_json(&["structure", "page.html", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));

    let definitions = json["files"][0]["definitions"].as_array().unwrap();
    let containers: Vec<&str> = definitions
        .iter()
        .filter_map(|d| d["container"].as_str())
        .collect();
    assert!(
        containers.contains(&"page.html#style-1"),
        "style rows carry their virtual document's name: {containers:?}"
    );
    assert!(
        containers.contains(&"page.html#script-1"),
        "script rows carry their virtual document's name: {containers:?}"
    );
    assert!(
        definitions
            .iter()
            .filter(|d| d["kind"] == "element")
            .all(|d| d["container"].is_null()),
        "host element rows stay container-less"
    );
}

/// `tldr impact <root>/lib/x.js` — a CODE-language file referenced ONLY from
/// an inline script is discoverable: the single-argument file target takes
/// the document-link path (any-target-impact-v1 slot asymmetry), and the
/// script-1 import edge resolves `./lib/x.js` against page.html's directory.
#[test]
fn impact_code_file_referenced_only_by_inline_script_finds_the_page() {
    let dir = build_virtual_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("lib/x.js").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0), "impact on a code file target must succeed");

    assert_eq!(json["total_targets"], 1);
    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(tree["function"], "<doc>");
    assert_eq!(tree["note"], "discovered via document link");
    assert_eq!(tree["caller_count"], 1, "page.html imports ./lib/x.js");
    assert!(tree["callers"].as_array().unwrap()[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("page.html"));
}

/// `tldr impact <root>/fonts/a.woff2` — a BINARY target (not a doc language,
/// not a code language) referenced only from the embedded style's `url()`
/// load takes the document-link closure too: `resolve_doc_target` matches by
/// existence, never by the target's own type.
#[test]
fn impact_binary_asset_referenced_only_by_embedded_style_finds_the_page() {
    let dir = build_virtual_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("fonts/a.woff2").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(
        code,
        Some(0),
        "impact on a binary asset target must succeed"
    );

    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(tree["note"], "discovered via document link");
    assert_eq!(tree["caller_count"], 1, "the style-1 url() edge");
    assert!(tree["callers"].as_array().unwrap()[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("page.html"));
}

/// The fetch target closes the loop as well: `api/v1.json` is referenced
/// only by the script's `fetch(...)` string.
#[test]
fn impact_fetch_target_referenced_only_by_inline_script_finds_the_page() {
    let dir = build_virtual_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("api/v1.json").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));

    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("page.html")),
        "closure must contain page.html: {files:?}"
    );
}

// =============================================================================
// (8) plain-text batch (build_text_project): .txt prose references
// =============================================================================

/// `tldr imports notes.txt` — the prose reference scan emits one ImportInfo
/// per shape, in source order: bare URL (trailing sentence period stays out),
/// angle-wrapped path with spaces (contents verbatim), shell-escaped path
/// (backslash escape removed — that IS the real path) and the plain relative
/// path token.
#[test]
fn imports_text_emits_urls_and_paths_in_source_order() {
    let dir = build_text_project();
    let root = dir.path();

    let (code, json) = run_json(&["imports", "notes.txt", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "text", "notes.txt resolves to Text");

    let imports = json["imports"].as_array().unwrap();
    assert_eq!(imports.len(), 4, "exactly the 4 prose references: {json}");

    assert_eq!(imports[0]["module"], "https://example.com/docs");
    assert_eq!(imports[0]["alias"], "url");
    assert_eq!(imports[0]["is_from"], true);

    assert_eq!(imports[1]["module"], "./docs/guide with spaces.md");
    assert_eq!(imports[1]["alias"], "angle-link");

    assert_eq!(imports[2]["module"], "my file.txt", "escape syntax removed");
    assert_eq!(imports[2]["alias"], "escaped-path");

    assert_eq!(imports[3]["module"], "./b.txt");
    assert_eq!(imports[3]["alias"], "path");
}

/// `tldr impact <root>/docs/guide with spaces.md` — the angle-wrapped
/// raw-space target resolves (spaces are legal path characters; the
/// resolution layer also tries the percent-decoded spelling), so the
/// closure finds notes.txt.
#[test]
fn impact_text_angle_target_closure_finds_the_referring_notes() {
    let dir = build_text_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "impact",
            root.join("docs/guide with spaces.md").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0), "impact on a plain-text-referenced doc");
    assert_eq!(json["total_targets"], 1);

    let tree = json["targets"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(tree["function"], "<doc>");
    assert_eq!(tree["note"], "discovered via document link");

    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("notes.txt")),
        "closure must contain notes.txt: {files:?}"
    );
}

/// `tldr importers b.txt <root> --lang text` finds notes.txt — the doc arm
/// of module_matches works for the plain-text reference surface.
#[test]
fn importers_finds_text_reference_source() {
    let dir = build_text_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "b.txt",
            root.to_str().unwrap(),
            "--lang",
            "text",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["module"], "b.txt");
    assert_eq!(json["total"], 1, "only notes.txt references b.txt: {json}");
    assert!(json["importers"][0]["file"]
        .as_str()
        .unwrap()
        .ends_with("notes.txt"));
    assert!(json["importers"][0]["import_statement"]
        .as_str()
        .unwrap()
        .contains("b.txt"));
}

// =============================================================================
// (6) VD-2 — foreignObject recursion: blast radius through the nested chain
// =============================================================================

/// Fixture for the foreignObject chain: `page.html` embeds an inline `<svg>`
/// whose `<foreignObject>` holds html with an outer script and a NESTED
/// `<svg>`/`<foreignObject>` whose script imports `./deep-data.json` — the
/// target is referenced ONLY by the deepest virtual script document.
fn build_foreign_object_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Root marker: the impact target is a plain file, so
    // `explain_project_root` needs a project marker at the root (the same
    // trick build_config_project uses for `schemas/user.json`).
    write(
        root.join("package.json"),
        r#"{ "name": "fixture", "private": true }"#,
    );
    write(
        root.join("page.html"),
        r#"<!DOCTYPE html>
<html>
<body>
<svg>
  <foreignObject>
    <div>
      <script>
        function boot() { return 1; }
      </script>
      <svg>
        <foreignObject>
          <div>
            <script>
              import "./deep-data.json";
              function deep() { return 2; }
            </script>
          </div>
        </foreignObject>
      </svg>
    </div>
  </foreignObject>
</svg>
</body>
</html>
"#,
    );
    write(root.join("deep-data.json"), r#"{ "kind": "data" }"#);
    dir
}

/// The whole chain end to end: `tldr imports page.html` carries the deepest
/// script's import with its hierarchical `via` provenance
/// (`page.html#fo-2#script-1`), and `tldr impact <root>/deep-data.json`
/// walks the reverse-link edge back to page.html — a target referenced only
/// inside a nested foreignObject document is discoverable from the host.
#[test]
fn foreignobject_chain_blast_radius_reaches_the_host() {
    let dir = build_foreign_object_project();
    let root = dir.path();

    // (1) imports: the deep reference rides the HOST file's imports with the
    // hierarchical via name.
    let (code, json) = run_json(&["imports", "page.html", "-f", "json", "-q"], root);
    assert_eq!(code, Some(0));
    assert_eq!(json["language"], "html");

    let imports = json["imports"].as_array().unwrap();
    let deep = imports
        .iter()
        .find(|i| i["module"] == "./deep-data.json")
        .unwrap_or_else(|| panic!("./deep-data.json missing from {imports:?}"));
    assert_eq!(
        deep["via"], "page.html#fo-2#script-1",
        "via = the deepest virtual document's hierarchical container: {deep}"
    );
    assert_eq!(deep["is_from"], true);
    assert!(
        !imports
            .iter()
            .any(|i| i["module"] == "./deep-data.json" && i["via"] != "page.html#fo-2#script-1"),
        "exactly one row for the deep reference, correctly attributed: {imports:?}"
    );

    // (2) impact: the target's reverse-link closure contains page.html.
    let (code, json) = run_json(
        &[
            "impact",
            root.join("deep-data.json").to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0), "impact on the data target must succeed");

    let mut files = Vec::new();
    collect_files(&json, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("page.html")),
        "the closure must reach page.html through the foreignObject chain: \
         total_targets={}, files={files:?}",
        json["total_targets"]
    );
}
