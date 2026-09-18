//! body-elements-v1 — `tldr body <file> <name>` resolves ELEMENT names.
//!
//! Before this suite existed, `body <file> <name>` could only resolve
//! function-kind AST nodes: every non-function definition — markdown
//! headings, CSS selectors, JSON/YAML/TOML keys, CSV records, log entries,
//! text headings, Python classes — dead-ended with "Function '<name>' not
//! found". Two fixes are pinned here:
//!
//! 1. **Bash function kinds** (tldr-core `function_finder`): bash
//!    `function_definition` resolves through the FUNCTION path, so its body
//!    follows the function-path byte convention — the trailing newline of
//!    the last line is INCLUDED.
//! 2. **Element-definition fallback** (tldr-cli `body`): when the function
//!    search fails, the name is looked up in the structure extractor's
//!    definition table. Definitions WITH byte spans are sliced
//!    byte-faithfully (`source[byte_start..byte_end]` IS the element —
//!    leading indentation excluded, trailing newline per the producer);
//!    definitions with only a line span (code-language classes, constants,
//!    …) use the same line machinery MINUS the trailing newline.
//!    script-inner-js-v1 rides this path: a symbol defined inside an inline
//!    `<script>` of an HTML/SVG host is a definition of the HOST file with
//!    global byte spans, so `tldr body page.html sayHi` extracts the JS
//!    function's exact bytes out of the HTML.
//!
//! Every expectation below is a byte-for-byte comparison against a literal
//! fixture, mirroring body_command_test.rs's harness style.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).expect("write fixture");
    path
}

fn body_json(file: &PathBuf, name: &str) -> Value {
    let output = tldr_cmd()
        .args([
            "body",
            file.to_str().expect("utf-8 path"),
            name,
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .expect("run tldr body");
    assert!(
        output.status.success(),
        "tldr body {name} failed: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse body JSON from stdout")
}

/// (1) Bash: `say_hi() { … }` resolves through the FUNCTION path — lines
/// 1..3 and the trailing newline of line 3 INCLUDED in `body`.
#[test]
fn bash_function_resolves_via_function_kinds() {
    let dir = TempDir::new().expect("tempdir");
    let src = "say_hi() {\n  echo \"hi\"\n}\n\nsay_hi\n";
    let file = write(&dir, "env.sh", src);

    let json = body_json(&file, "say_hi");

    assert_eq!(json["function"], "say_hi");
    assert_eq!(json["language"], "bash");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 3);
    // Function-path convention: the newline terminating the last line is
    // part of the body (24 element bytes + 1 newline). This is what
    // distinguishes the function path from the element byte path.
    let expected = "say_hi() {\n  echo \"hi\"\n}\n";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}

/// (2) Markdown heading: the heading's tree-sitter region sliced
/// byte-faithfully (the md BLOCK grammar's heading node includes the
/// terminating newline — its exact region, byte-for-byte).
#[test]
fn markdown_heading_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "# Setup\n\nInstall the tools.\n\n# Teardown\n\nRemove the tools.\n";
    let file = write(&dir, "guide.md", src);

    let json = body_json(&file, "Setup");

    assert_eq!(json["function"], "Setup");
    assert_eq!(json["language"], "markdown");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 1);
    assert_eq!(json["line_count"], 1);
    assert_eq!(
        json["body"].as_str().expect("body is a string"),
        "# Setup\n"
    );
    assert_eq!(json["byte_count"], 8);

    // The later heading resolves too (first-match is per requested name).
    let json = body_json(&file, "Teardown");
    assert_eq!(json["line_start"], 5);
    assert_eq!(
        json["body"].as_str().expect("body is a string"),
        "# Teardown\n"
    );
}

/// (3) CSS selector: the `rule_set` region is the rule itself — starts at
/// the selector's first byte, ends at `}`. The trailing newline is NOT part
/// of the node, so `body` must not add one.
#[test]
fn css_selector_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "div.container {\n  color: red;\n}\n\np {\n  margin: 0;\n}\n";
    let file = write(&dir, "style.css", src);

    let json = body_json(&file, "div.container");

    assert_eq!(json["function"], "div.container");
    assert_eq!(json["language"], "css");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 3);
    let expected = "div.container {\n  color: red;\n}";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}

/// (4) CSV record (byte path): a record's region is first field byte → last
/// field byte, terminating newline EXCLUDED (ast::csvscan). The record name
/// is its first column's text.
#[test]
fn csv_record_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "item,qty\nwidget,2\ngadget,5\n";
    let file = write(&dir, "data.csv", src);

    let json = body_json(&file, "widget");

    assert_eq!(json["function"], "widget");
    assert_eq!(json["language"], "csv");
    assert_eq!(json["line_start"], 2);
    assert_eq!(json["line_end"], 2);
    assert_eq!(json["body"].as_str().expect("body is a string"), "widget,2");
    assert_eq!(json["byte_count"], 8);
}

/// (5) JSON key (byte path): the `pair` region starts mid-line at the quote.
/// With same-named keys at different depths, the FIRST definition in source
/// order wins (definitions are emitted pre-order; documented rule).
#[test]
fn json_key_body_is_byte_exact_and_first_match_wins() {
    let dir = TempDir::new().expect("tempdir");
    let src = "{\n  \"name\": \"tldr\",\n  \"nested\": {\n    \"name\": \"inner\"\n  }\n}\n";
    let file = write(&dir, "pkg.json", src);

    let json = body_json(&file, "name");

    assert_eq!(json["function"], "name");
    assert_eq!(json["language"], "json");
    // The OUTER pair (line 2), not the nested one (line 4).
    assert_eq!(json["line_start"], 2);
    assert_eq!(json["line_end"], 2);
    assert_eq!(
        json["body"].as_str().expect("body is a string"),
        "\"name\": \"tldr\""
    );
    assert_eq!(json["byte_count"], 14);
}

/// (6) Log entry (byte path): the entry's region is the raw line, newline
/// excluded; the name is the normalized level.
#[test]
fn log_entry_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "2026-09-14T08:34:49Z ERROR disk full on /dev/sda1\n\
               2026-09-14T08:35:02Z INFO retry scheduled\n";
    let file = write(&dir, "server.log", src);

    let json = body_json(&file, "error");

    assert_eq!(json["function"], "error");
    assert_eq!(json["language"], "log");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 1);
    assert_eq!(
        json["body"].as_str().expect("body is a string"),
        "2026-09-14T08:34:49Z ERROR disk full on /dev/sda1"
    );
    assert_eq!(json["byte_count"], 49);
}

/// (7) Text heading (byte path): the TOC scanner's ALL-CAPS heading region.
#[test]
fn text_heading_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "RELEASE NOTES\n\nsome body text\n";
    let file = write(&dir, "notes.txt", src);

    let json = body_json(&file, "RELEASE NOTES");

    assert_eq!(json["function"], "RELEASE NOTES");
    assert_eq!(json["language"], "text");
    assert_eq!(json["line_start"], 1);
    assert_eq!(json["line_end"], 1);
    assert_eq!(
        json["body"].as_str().expect("body is a string"),
        "RELEASE NOTES"
    );
    assert_eq!(json["byte_count"], 13);
}

/// (8) Code-language definition WITHOUT a byte span (a Python class) takes
/// the line fallback: same line machinery as the function path but the
/// trailing newline EXCLUDED — the region is the element itself. A class is
/// not a function-kind node, so only the fallback can find it.
#[test]
fn python_class_uses_line_path_without_trailing_newline() {
    let dir = TempDir::new().expect("tempdir");
    let src =
        "import os\n\n\"\"\"Doc.\"\"\"\nclass Widget:\n    def size(self):\n        return 1\n";
    let file = write(&dir, "w.py", src);

    let json = body_json(&file, "Widget");

    assert_eq!(json["function"], "Widget");
    assert_eq!(json["language"], "python");
    assert_eq!(json["line_start"], 4);
    assert_eq!(json["line_end"], 6);
    let expected = "class Widget:\n    def size(self):\n        return 1";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}

/// (9) Fidelity control: a decorated Python FUNCTION still resolves through
/// the function path — bounds start at the first decorator and the trailing
/// newline stays INCLUDED. The fallback must not change function behavior.
#[test]
fn python_decorated_function_keeps_function_path_fidelity() {
    let dir = TempDir::new().expect("tempdir");
    let src = "import functools\n\n@functools.lru_cache(maxsize=None)\ndef handler(request):\n    \
               return request\n";
    let file = write(&dir, "deco.py", src);

    let json = body_json(&file, "handler");

    assert_eq!(json["function"], "handler");
    assert_eq!(json["language"], "python");
    assert_eq!(json["line_start"], 3, "bounds must start at the decorator");
    assert_eq!(json["line_end"], 5);
    let expected =
        "@functools.lru_cache(maxsize=None)\ndef handler(request):\n    return request\n";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}

/// (10) Text mode emits the element's raw bytes verbatim (no decoration, no
/// added newline) — proven on the CSS selector, whose region has no
/// trailing newline.
#[test]
fn element_text_mode_writes_verbatim_bytes() {
    let dir = TempDir::new().expect("tempdir");
    let src = "p {\n  margin: 0;\n}\n";
    let file = write(&dir, "style.css", src);

    let output = tldr_cmd()
        .args([
            "body",
            file.to_str().expect("utf-8 path"),
            "p",
            "--format",
            "text",
            "--quiet",
        ])
        .output()
        .expect("run tldr body");
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        "p {\n  margin: 0;\n}".as_bytes(),
        "text stdout must be the exact element bytes"
    );
}

/// (11) A name that is neither a function nor any definition keeps the
/// original error shape — non-zero exit, the message names BOTH the name
/// and the file, and stdout stays empty.
#[test]
fn not_found_error_shape_is_unchanged() {
    let dir = TempDir::new().expect("tempdir");
    let md = write(&dir, "guide.md", "# Setup\n\nInstall the tools.\n");
    let py = write(&dir, "w.py", "class Widget:\n    pass\n");

    for (file, name) in [(&md, "nosuchthing"), (&py, "does_not_exist")] {
        let output = tldr_cmd()
            .args(["body", file.to_str().expect("utf-8 path"), name, "--quiet"])
            .output()
            .expect("run tldr body");
        assert!(
            !output.status.success(),
            "missing name must exit non-zero ({name})"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(name),
            "error must name the symbol: {stderr}"
        );
        assert!(
            stderr.contains(file.file_name().unwrap().to_str().unwrap()),
            "error must name the file: {stderr}"
        );
        assert!(output.stdout.is_empty(), "stdout must stay empty on error");
    }
}

/// (12) script-inner-js-v1: a symbol defined inside an inline `<script>` of
/// an HTML host resolves through the element fallback's BYTE path — the
/// definition's byte span is the symbol's exact source inside the host file
/// (global offsets, translated by the script-inner emitter), so the body is
/// the JS function verbatim with no surrounding markup and no trailing
/// newline. The host file's own language (html) has no function-kind nodes,
/// so only the fallback can find it.
#[test]
fn html_inline_script_function_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "<!DOCTYPE html>\n\
               <html>\n\
               <body>\n\
               <script>\n\
               function sayHi(name) {\n\
               \x20 return \"hi \" + name;\n\
               }\n\
               </script>\n\
               </body>\n\
               </html>\n";
    let file = write(&dir, "page.html", src);

    let json = body_json(&file, "sayHi");

    assert_eq!(json["function"], "sayHi");
    assert_eq!(json["language"], "html");
    // FILE lines (the virtual document's lines translated onto the host).
    assert_eq!(json["line_start"], 5);
    assert_eq!(json["line_end"], 7);
    let expected = "function sayHi(name) {\n  return \"hi \" + name;\n}";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}

/// (13) virtual-documents-v1: a SELECTOR defined inside an embedded `<style>`
/// of an HTML host resolves through the same byte path — the selector row's
/// byte span is the rule's exact source inside the host file, so `tldr body
/// page.html .hero` extracts the CSS rule verbatim (no markup, no trailing
/// newline). The style is a named virtual document (`page.html#style-1`),
/// but `body` lookup is by NAME and byte-span-first — the container rides
/// along for consumers that care.
#[test]
fn html_embedded_style_selector_body_is_byte_exact() {
    let dir = TempDir::new().expect("tempdir");
    let src = "<!DOCTYPE html>\n\
               <html>\n\
               <head>\n\
               <style>\n\
               .hero { color: red; }\n\
               </style>\n\
               </head>\n\
               <body></body>\n\
               </html>\n";
    let file = write(&dir, "page.html", src);

    let json = body_json(&file, ".hero");

    assert_eq!(json["function"], ".hero");
    assert_eq!(json["language"], "html");
    // FILE line (the virtual document's line translated onto the host).
    assert_eq!(json["line_start"], 5);
    assert_eq!(json["line_end"], 5);
    let expected = ".hero { color: red; }";
    assert_eq!(json["body"].as_str().expect("body is a string"), expected);
    assert_eq!(json["byte_count"], expected.len());
}
