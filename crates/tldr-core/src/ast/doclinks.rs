//! Document link extraction (doclinks-v1)
//!
//! Documents reference other files through hyperlinks. This module turns the
//! link surface of the document formats into [`ImportInfo`] entries so the
//! existing import pipeline (`tldr imports` → `tldr importers` → document
//! blast radius in `analysis::doc_impact`) works for non-code files exactly
//! the way it works for source code.
//!
//! # ImportInfo mapping decision
//!
//! `ImportInfo` (types.rs:1579-1593) already carries *path strings* — the C
//! `#include "local.h"` precedent (`extract_c_imports` in `ast::imports`)
//! rides the verbatim path through `module`. Documents reuse that precedent
//! field-for-field:
//!
//! - `module` = the raw link target **exactly as written** (`./a.md`,
//!   `c.md#frag`, `https://example.com/x` stay untouched — and LaTeX targets
//!   keep the bare command argument, with no `.tex` appended). Resolution /
//!   normalization is a downstream concern (`analysis::doc_impact` and the
//!   `module_matches` doc arm in `analysis::importers`), not an extraction
//!   one — extraction must stay a faithful, lossless index of the source.
//! - `names` = empty (a link has no imported symbols).
//! - `is_from` = `true`. The closest analogue of a from-import: the target
//!   is referenced *by name, at a point of use*, which is what `is_from`
//!   communicates to consumers.
//! - `alias` = a provenance label describing WHERE the link came from:
//!   markdown link text (truncated to 100 chars), the reference-definition
//!   label, the HTML attribute name (`href`/`src`/…), the XML role
//!   (attribute name / `xml-stylesheet` / `doctype-system`), the CSS role
//!   (`import` / `url`), or the LaTeX command name (`input` /
//!   `includegraphics` / …).
//!
//! # Bare-data formats (CSV/TSV) — no reference surface by design
//!
//! `Csv`/`Tsv` (CSV/TSV batch, 2026-09) emit NOTHING here. A CSV/TSV file is
//! bare tabular data: it has no link/path convention at all — a generic
//! string scan over cell text would fabricate file edges out of every
//! URL-looking address column and product-code-looking path column, exactly
//! the false-edge class the JSON/YAML key allow-list exists to prevent. They
//! are also NOT document languages (`is_doc_language` stays untouched), so
//! they never enter the document link graph; their structure surface is the
//! record/cell element scanner in `ast::csvscan`.
//!
//! # Loaded elements (CSS and LaTeX)
//!
//! CSS `@import` and `url()` targets are **loaded elements**: a stylesheet
//! that imports another stylesheet or references a font/image resource
//! through `url()` genuinely loads that file when it is applied, so each
//! target is a real reference edge — the CSS analogue of a hyperlink. The
//! LaTeX file-bearing commands (`\input`, `\include`, `\includegraphics`,
//! `\bibliography`, `\addbibresource`, `\usepackage`, `\documentclass`) are
//! the same for documents — one `ImportInfo` per braced target, the
//! `\bibliography` argument comma-split.
//!
//! # Scope and masking
//!
//! - **Masked now:** markdown *inline code spans* (`` `[x](y.md)` `` must not
//!   look like a link) AND markdown *code blocks* — fenced (``` / ~~~,
//!   opening fence ≤3 spaces indent, closing fence the same char with
//!   length ≥ the opener's) and indented (a ≥4-space-indented line after a
//!   blank line; a conservative heuristic, see `mask_code_blocks`). Example
//!   links inside code blocks therefore never emit. All masking is
//!   byte-length-preserving so match offsets stay valid against the
//!   original source.
//! - HTML comments and `<script>` bodies are not masked (documented scope:
//!   the attribute scan is textual, like the C include scan); the CSS and
//!   LaTeX scans are likewise textual (comments are not masked).
//!
//! # JSON and YAML — the AST-keyed `$ref` / `extends` key policy
//!
//! JSON and YAML are **AST-keyed** extractors: they walk the tree-sitter tree
//! (passed in by the caller — `get_imports` has already parsed it) and emit a
//! mapping pair ONLY when its KEY is exactly `$ref` or `extends` and its
//! VALUE is a string. `alias` = the matched key, exactly as written (the same
//! provenance-as-name rule the HTML/XML attribute scan uses).
//!
//! Why a key allow-list and nothing else: JSON and YAML have NO general
//! "path string" convention — a generic string scan would fabricate edges out
//! of descriptions, IDs, titles and versions. The two keys chosen are the
//! de-facto cross-tool reference keys: `$ref` (JSON Schema/OpenAPI external
//! pointers, swagger-style composition) and `extends` (Compose-style file
//! inheritance, GitLab CI job templates). JSON Pointer internals
//! (`"$ref": "#/components/schemas/X"`) are suppressed by the shared
//! `emittable` rule (fragment-only targets emit nothing).
//!
//! YAML additionally refuses, BY DESIGN, to scan keys named `include`,
//! `resources`, `import` and the like even though those conventions do load
//! files (Compose `include:`, GitHub Actions `strategy.matrix.include`,
//! kustomize `resources:`). The false-positive analysis: Actions `include:`
//! is a matrix EXPANSION key whose entries are parameter maps, not files —
//! scanning it would fabricate a file edge out of every matrix parameter;
//! kustomize `resources:` entries are real files but the key name is
//! overloaded across tools with wildly different value types (strings,
//! objects, lists of maps), so a scan cannot tell a path from a name without
//! per-tool schemas. Suppress-only for ambiguous conventions: a convention
//! is wired only when its key alone disambiguates the value (`$ref`,
//! `extends`), never when the value's TYPE has to carry the meaning. Values
//! must be scalars — a `$ref` whose value is a mapping/sequence is skipped.
//!
//! # TOML — the string-value path scan
//!
//! TOML has no reference convention at all (`$ref` is not idiomatic there),
//! so TOML uses a different, honestly-heuristic surface: every STRING value
//! in the tree (basic + literal strings, in tables and inline tables) that
//! "looks like a path or URL" per [`looks_like_path_or_url`] emits, with
//! alias `path`. This surfaces config-referenced assets (`asset =
//! "./img/logo.svg"`), theme/config loads and remote references. The
//! heuristic is deliberately conservative (see the function docs) and false
//! positives ARE possible (e.g. `dir = "assets/v1.2"` — a dotted directory
//! name reads like an extension); it is kept because TOML consumers asked
//! for config-file loads, and unresolved targets are inert downstream. There
//! is NO key filter and NO cap — deterministic source (tree) order.
//!
//! # Bash — `source` / `.`
//!
//! Bash is scanned line-by-line (extraction stays regex-textual; the shell
//! has no import statement, `source` is a builtin): a line-anchored pattern
//! matches the `source`/`.` operator only after a line start or a `;`, `&&`
//! or `||` separator, followed by whitespace and a target token. The `.`
//! (POSIX) form additionally requires a `/` in the target — `. TOKEN` is
//! textually ambiguous (`.`, `..`, arithmetic, `.hidden`-style words), while
//! a real dot-sourced path virtually always contains a separator. Quoted
//! targets are unwrapped only when the quotes BALANCE within the token (the
//! capture stops at whitespace, so `"a b.sh"` is unbalanced and skipped).
//! Full-line `#` comments are truncated before matching (suppress-only);
//! mid-line `#` truncation can only remove candidates, never add them.
//! Known limitation (kept simple by design): `if … ; then source x.sh` on a
//! single line does not match — the keyword forms `then|else|do` are not
//! separators here.
//!
//! # External targets
//!
//! `data:` URIs and `#fragment`-only targets emit nothing. http(s) URLs ARE
//! emitted (they are real references worth indexing) but they can never
//! resolve to project files downstream — `doc_impact` and the importers doc
//! matcher treat `://` targets as external and skip them.

//! # Plain text — the whole-document reference scan (`scan_paths_and_urls`)
//!
//! Plain text (`.txt`/`.text`) has no link syntax at all, so its reference
//! surface is "anything in the prose that LOOKS like a URL or a path". The
//! scan is a single left-to-right pass ([`scan_paths_and_urls`]) with four
//! shapes, tried at each position in this order (one span never emits twice —
//! an angle-wrapped URL is consumed by the angle shape, not also by the URL
//! shape):
//!
//! | Shape | Example | Target | `alias` |
//! |-------|---------|--------|---------|
//! | bare URL | `see https://example.com/x.` | the URL with trailing `.,;:!?"'` trimmed | `url` |
//! | angle-wrapped | `<./docs/guide with spaces.md>` | the contents verbatim (spaces INCLUDED — that is the whole point of the angle form) | `angle-link` |
//! | shell-escaped path | `cat my\ file.txt` | the UNESCAPED path (`my file.txt`) — the backslash-space is shell escape SYNTAX; removing it yields the real path | `escaped-path` |
//! | plain path token | `see ./b.txt, ok?` | the token with surrounding punctuation split off | `path` |
//!
//! Filters: angle contents must contain `:`/`/`/`.` (keeps HTML-ish `<div>`
//! tokens out); every target passes the shared `emittable` rule (`data:` URIs
//! and `#fragment`-only targets never emit) and the plain-path shape
//! additionally passes [`looks_like_path_or_url`]. **Percent-encoded tokens
//! are kept RAW** (`./docs/my%20file.txt` stays `%20` at extraction — the
//! resolution layer (`analysis::doc_impact::resolve_doc_target`) tries the
//! percent-DECODED spelling as a fallback, and decoding at extraction would
//! lose the distinction between a file literally named `a%20b.md` and its
//! decoded reading). Bare URLs, angle-wrapped targets and escaped paths can
//! never resolve to project files when they are external, exactly like every
//! other format's external targets.
//!
//! False-positive classes are broader than the other formats by necessity
//! (prose has no link syntax to key on): any prose token that passes
//! [`looks_like_path_or_url`] emits — version-y directory references
//! (`assets/v1.2`), dotted words with separators — the same accepted class
//! the TOML string-value scan documents. Unresolved targets are inert
//! downstream.

use lazy_static::lazy_static;
use regex::Regex;
use tree_sitter::{Node, Tree};

use crate::types::{ImportInfo, Language};

lazy_static! {
    /// Markdown inline links and images: `[text](dest)` / `![alt](dest)`,
    /// optional `"title"` / `'title'` / `(title)` after the destination,
    /// destination optionally wrapped in `<>`. Link text may contain one
    /// level of balanced brackets (the badge pattern `["["-nested](…)`)
    /// so `[![img](i.png)](t.md)` reports `t.md`, not the inner image.
    static ref MD_INLINE: Regex = Regex::new(
        r#"(?P<bang>!?)\[(?P<text>(?:[^\[\]\n]|\[[^\]\n]*\])*)\]\(\s*(?P<dest><[^<>]*>|[^\s)]+)(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?\s*\)"#
    )
    .expect("MD_INLINE regex");

    /// Markdown autolinks: `<token>` with no inner whitespace or angle
    /// brackets. A heuristic filter in `autolink_target` (token must look
    /// like a URI/path: contain `:`, `/` or `.`) keeps bare HTML-ish tokens
    /// (`<div>`, `<b>`) out.
    static ref MD_AUTOLINK: Regex = Regex::new(r"<(?P<dest>[^<>\s]+)>").expect("MD_AUTOLINK regex");

    /// Markdown reference definitions: `[label]: dest` at (up to) three
    /// spaces of indent. `(?m)` anchors `^` at every line start; offsets are
    /// absolute so they sort naturally against inline matches.
    static ref MD_REFDEF: Regex = Regex::new(
        r"(?m)^[ \t]{0,3}\[(?P<label>[^\]\n]+)\]:[ \t]*(?P<dest><[^<>]*>|[^\s]+)"
    )
    .expect("MD_REFDEF regex");

    /// Generic `name="value"` / `name='value'` / `name=value` attribute
    /// pattern shared by the HTML and XML scanners. The captured name is
    /// filtered in code against each format's allowed set — this avoids
    /// lookaheads (unsupported by the `regex` crate) while still rejecting
    /// `data-foo="…"` for the HTML `data` attribute.
    static ref HTML_ATTR: Regex = Regex::new(
        r#"(?i)(?P<name>[a-zA-Z_][a-zA-Z0-9_.:-]*)\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<uq>[^\s"'`>]+))"#
    )
    .expect("HTML_ATTR regex");

    /// XML processing instruction `<?xml-stylesheet … ?>` (lazy body up to
    /// the first `?>`).
    static ref XML_STYLESHEET_PI: Regex =
        Regex::new(r"(?is)<\?xml-stylesheet\b.*?\?>").expect("XML_STYLESHEET_PI regex");

    /// `href="…"` / `href='…'` inside a `xml-stylesheet` PI.
    static ref PI_HREF: Regex = Regex::new(
        r#"(?i)\bhref\b\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')"#
    )
    .expect("PI_HREF regex");

    /// DOCTYPE declaration (internal subsets with `>` inside are out of
    /// scope — the scan stops at the first `>`, same as the C include scan).
    static ref XML_DOCTYPE: Regex =
        Regex::new(r"(?is)<!doctype\b[^>]*>").expect("XML_DOCTYPE regex");

    /// `SYSTEM "…"` / `SYSTEM '…'` inside a DOCTYPE.
    static ref DOCTYPE_SYSTEM: Regex = Regex::new(
        r#"(?i)\bsystem\b\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)')"#
    )
    .expect("DOCTYPE_SYSTEM regex");

    /// CSS `@import` rules: `@import "path";` / `@import url(path);` /
    /// `@import url("path") media;` — lazy body up to the first `;` so the
    /// optional media-query tail (parens included) is consumed. The target
    /// is picked in code: the `url(...)` form via `u` (quotes stripped by
    /// `strip_quotes`), else the bare quoted string via `dq`/`sq`.
    static ref CSS_IMPORT: Regex = Regex::new(
        r#"(?i)@import\s+(?:url\(\s*(?P<u>[^;]*?)\s*\)|"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)')[^;]*;"#
    )
    .expect("CSS_IMPORT regex");

    /// CSS `url()` tokens anywhere (declarations, `@font-face` `src:`,
    /// `background:`/`background-image:`, `content:`, …): `url(path)`,
    /// `url("path")`, `url('path')`. Empty / `data:` / `#fragment` targets
    /// are dropped by `emittable`; non-path function calls like
    /// `url(var(--font))` are dropped by the paren/comma sanity filter in
    /// `extract_css_links` (an UNQUOTED token containing `(`, `,`, `[` or
    /// `]` cannot be a filesystem path). Quoted targets keep any such
    /// characters — `url("a (1).png")` is a real file name.
    static ref CSS_URL: Regex = Regex::new(
        r#"(?i)\burl\(\s*(?:"(?P<dq>[^"\n]*)"|'(?P<sq>[^'\n]*)'|(?P<raw>[^)"'\n]*))\s*\)"#
    )
    .expect("CSS_URL regex");

    /// LaTeX file-bearing commands (see `extract_latex_links`): the command
    /// must start with `\`, may carry a `*` star form, and must be followed
    /// by an optional `[...]` options group and then the braced argument.
    /// (The `regex` crate has no look-around; the structural `\{`
    /// requirement IS the word boundary on the command name —
    /// `\bibliographystyle{plain}` fails because after `bibliography` comes
    /// `style`, not `{`, and `\myinput{x}` / `\inputx{y}` fail the same
    /// way.) Alternation is longest-first so `\includegraphics` wins over
    /// its `\include` prefix without relying on backtracking order.
    static ref LATEX_COMMAND: Regex = Regex::new(
        r#"\\(?P<cmd>includegraphics|addbibresource|documentclass|bibliography|usepackage|include|input)\*?\s*(?:\[[^\]\n]*\]\s*)?\{(?P<arg>[^}\n]*)\}"#
    )
    .expect("LATEX_COMMAND regex");
}

/// Link targets that never become imports: empty, `data:` URIs (inline
/// payloads, not references) and `#fragment`-only anchors (in-page jumps,
/// not file references). Everything else — relative paths, root-relative
/// paths, absolute paths, and external http(s) URLs — emits.
fn emittable(target: &str) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.len() >= 5 && trimmed.as_bytes()[..5].eq_ignore_ascii_case(b"data:") {
        return false;
    }
    if trimmed.starts_with('#') {
        return false;
    }
    true
}

/// Extract document links as [`ImportInfo`] entries.
///
/// One entry per link, in deterministic source order (ascending byte
/// offset; ties keep scan order). See the module docs for the ImportInfo
/// mapping and the masking scope.
///
/// `tree` is the caller's parsed syntax tree when the language has a
/// tree-sitter grammar. The AST-keyed extractors (JSON/YAML/TOML) REQUIRE
/// it and emit nothing when it is `None` — callers (`get_imports`) always
/// parse first, so the tree arrives already built and no double parse
/// happens. The regex-only extractors (markdown/html/xml/css/latex/bash)
/// ignore the tree.
pub fn extract_doc_links(language: Language, source: &str, tree: Option<&Tree>) -> Vec<ImportInfo> {
    match language {
        Language::Markdown => extract_markdown_links(source),
        Language::Html => extract_html_links(source),
        Language::Xml => extract_xml_links(source),
        Language::Css => extract_css_links(source),
        Language::Latex => extract_latex_links(source),
        Language::Json => extract_json_ref_links(source, tree),
        Language::Yaml => extract_yaml_ref_links(source, tree),
        Language::Toml => extract_toml_path_links(source, tree),
        Language::Bash => extract_bash_source_links(source),
        Language::Text => extract_text_links(source),
        _ => Vec::new(),
    }
}

// =============================================================================
// JSON — the AST-keyed `$ref` / `extends` key policy
// =============================================================================

/// JSON: emit only `pair` nodes whose key is exactly `$ref` or `extends`
/// and whose value is a string (raw, quotes already stripped by taking the
/// `string_content` child). Nothing else — JSON has no general path-string
/// convention and a generic scan would fabricate edges (see the module
/// docs). Internal JSON Pointers (`"#/components/…"`), `data:` URIs and
/// empty values are dropped by `emittable`. `alias` = the matched key.
/// Requires `tree`; `None` yields no emissions.
fn extract_json_ref_links(source: &str, tree: Option<&Tree>) -> Vec<ImportInfo> {
    const REF_KEYS: [&str; 2] = ["$ref", "extends"];
    let Some(tree) = tree else {
        return Vec::new();
    };
    let mut imports = Vec::new();
    walk_json_pairs(tree.root_node(), source, &mut |key, value| {
        if REF_KEYS.contains(&key) && emittable(value) {
            imports.push(doc_import(value, key));
        }
    });
    imports
}

/// Walk every JSON `pair` (nested objects recurse) and call `f` with the
/// pair's key text (exact, unquoted) and its string value, when the value
/// IS a string. Non-string values (number/bool/null/object/array) call
/// nothing for that pair but do not stop the recursion.
fn walk_json_pairs<'a>(node: Node<'a>, source: &'a str, f: &mut impl FnMut(&str, &str)) {
    if node.kind() == "pair" {
        // Grammar (tree-sitter-json): `pair` fields `key: string` and
        // `value: _value` (the supertype lands as a concrete node —
        // `string` for string values).
        let key = node.child_by_field_name("key").and_then(|k| {
            k.children(&mut k.walk())
                .find(|c| c.kind() == "string_content")
                .map(|c| &source[c.byte_range()])
        });
        let value = node.child_by_field_name("value").and_then(|v| {
            if v.kind() == "string" {
                v.children(&mut v.walk())
                    .find(|c| c.kind() == "string_content")
                    .map(|c| &source[c.byte_range()])
            } else {
                None
            }
        });
        if let (Some(key), Some(value)) = (key, value) {
            f(key, value);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_json_pairs(child, source, f);
    }
}

// =============================================================================
// YAML — the AST-keyed `$ref` / `extends` key policy (include/resources
// suppression documented in the module docs)
// =============================================================================

/// YAML: emit only mapping pairs (`block_mapping_pair` in block context,
/// `flow_pair` in flow mappings) whose KEY text (plain or quoted scalar,
/// unquoted) is exactly `$ref` or `extends` and whose VALUE resolves to a
/// scalar string. Sequence/mapping values are skipped (scalar-only — a
/// `$ref` pointing at a mapping is not a file reference). Keys named
/// `include`/`resources`/`import` are deliberately NOT scanned — see the
/// module docs for the false-positive analysis. `alias` = the matched key.
/// Requires `tree`; `None` yields no emissions.
fn extract_yaml_ref_links(source: &str, tree: Option<&Tree>) -> Vec<ImportInfo> {
    const REF_KEYS: [&str; 2] = ["$ref", "extends"];
    let Some(tree) = tree else {
        return Vec::new();
    };
    let mut imports = Vec::new();
    walk_yaml_pairs(tree.root_node(), source, &mut |key, value| {
        if REF_KEYS.contains(&key) && emittable(value) {
            imports.push(doc_import(value, key));
        }
    });
    imports
}

/// Walk every YAML mapping pair and call `f` with the key text and scalar
/// value text when both resolve. Handles both pair kinds (the grammar wraps
/// pair fields in `block_node`/`flow_node`; the scalar hides one level down,
/// the same structure `ast::elements` walks for definitions).
fn walk_yaml_pairs<'a>(node: Node<'a>, source: &'a str, f: &mut impl FnMut(&str, &str)) {
    if node.kind() == "block_mapping_pair" || node.kind() == "flow_pair" {
        let key = node
            .child_by_field_name("key")
            .and_then(|k| yaml_scalar_text(&k, source));
        let value = node
            .child_by_field_name("value")
            .and_then(|v| yaml_scalar_text(&v, source));
        if let (Some(key), Some(value)) = (key, value) {
            f(&key, &value);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_yaml_pairs(child, source, f);
    }
}

/// Text of a YAML scalar node: plain / single-quoted / double-quoted
/// scalars carry it directly (quotes stripped); `block_node`/`flow_node`
/// wrappers descend one level to the scalar child (the grammar wraps pair
/// fields — verified against tree-sitter-yaml 0.7.0 node-types). Anything
/// else (mappings, sequences, aliases, anchors, block scalars) is not a
/// scalar string → `None`.
fn yaml_scalar_text(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" => {
            Some(unquote_yaml(&source[node.byte_range()]))
        }
        "block_node" | "flow_node" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(
                    child.kind(),
                    "plain_scalar" | "single_quote_scalar" | "double_quote_scalar"
                ) {
                    return Some(unquote_yaml(&source[child.byte_range()]));
                }
            }
            None
        }
        _ => None,
    }
}

/// Strip one layer of matching YAML `'` / `"` scalar quoting (the quoting
/// is syntax, not content — same rule as [`strip_quotes`]).
fn unquote_yaml(s: &str) -> String {
    strip_quotes(s).to_string()
}

// =============================================================================
// TOML — the string-value path scan (no key policy; heuristic documented
// in the module docs and in `looks_like_path_or_url`)
// =============================================================================

/// TOML: every `pair` whose value is a `string` and whose content passes
/// [`looks_like_path_or_url`] emits, in deterministic tree order — no key
/// filter, no cap. TOML has no reference convention, so the path-shaped
/// strings themselves are the surface (config-referenced assets, theme and
/// config loads, remote URLs); false positives are possible and accepted
/// (unresolved targets are inert downstream). `alias` = `"path"`. Requires
/// `tree`; `None` yields no emissions.
fn extract_toml_path_links(source: &str, tree: Option<&Tree>) -> Vec<ImportInfo> {
    let Some(tree) = tree else {
        return Vec::new();
    };
    let mut imports = Vec::new();
    walk_toml_strings(tree.root_node(), source, &mut |value| {
        if looks_like_path_or_url(value) && emittable(value) {
            imports.push(doc_import(value, "path"));
        }
    });
    imports
}

/// Walk every TOML `pair` (tables, table arrays and inline tables recurse)
/// and call `f` with each STRING value's content. The grammar's `pair` has
/// no named fields — the leading key part is a `bare_key`/`quoted_key`/
/// `dotted_key` child and the value is a typed child (`string`, `integer`,
/// `float`, `boolean`, dates, `array`, `inline_table`); only `string`
/// children are reported. Unlike JSON, the TOML grammar has NO
/// `string_content` node — the `string` node's own byte range INCLUDES the
/// quote tokens (verified against tree-sitter-toml-ng-0.7.0 grammar.js), so
/// the quotes are stripped here.
fn walk_toml_strings(node: Node, source: &str, f: &mut impl FnMut(&str)) {
    if node.kind() == "pair" {
        let value = node
            .children(&mut node.walk())
            .find(|c| c.kind() == "string");
        if let Some(value) = value {
            f(strip_toml_quotes(&source[value.byte_range()]));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_toml_strings(child, source, f);
    }
}

/// Strip the TOML string wrapper: `"""…"""` / `'''…'''` (multiline) shed
/// three quotes per side, `"…"` / `'…'` one. Anything else comes back
/// untouched (defensive — the grammar always wraps).
fn strip_toml_quotes(s: &str) -> &str {
    for q in ["\"\"\"", "'''"] {
        if let Some(inner) = s.strip_prefix(q) {
            if let Some(inner) = inner.strip_suffix(q) {
                return inner;
            }
        }
    }
    strip_quotes(s)
}

/// Heuristic: does this TOML string value look like a path or URL?
///
/// TRUE for: `http://…` / `https://…` URLs; `./x` and `../x`; absolute
/// `/x`; `~/x`; and relative paths that contain a `/` AND a dot-extension
/// on the last segment (`assets/logo.svg`, `config/dev.toml`).
///
/// FALSE for: bare words (`tldr`, `1.2.3`, `foo_bar` — no `/`); bare
/// filenames without a directory (`logo.svg`); `#`-fragments; `data:` URIs
/// and other non-http scheme tokens; values with ANY whitespace; values
/// containing `{`/`}` (template/interpolation braces) or `<`/`>`; empty
/// strings and directory-only references (`assets/` — the last segment has
/// no extension). Known accepted false-positive class: dotted directory
/// names read like extensions (`assets/v1.2` → true).
pub(crate) fn looks_like_path_or_url(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.chars().any(char::is_whitespace) {
        return false;
    }
    if t.contains(['{', '}', '<', '>']) {
        return false;
    }
    // `#`-fragments and `data:` URIs are the same suppression the other
    // extractors apply through `emittable`; non-http scheme tokens
    // (`mailto:x`, `ftp://…`) are not filesystem paths either.
    if t.starts_with('#') {
        return false;
    }
    if let Some(scheme_end) = t.find(':') {
        let head = &t[..scheme_end];
        if head.len() >= 4 && head[..4].eq_ignore_ascii_case("data") {
            return false;
        }
        if t[..scheme_end].contains('/') {
            // A colon AFTER a slash is ordinary in paths (`a/b:c`), not a
            // scheme marker — fall through to the path rules.
        } else if !t.starts_with("http://") && !t.starts_with("https://") {
            return false;
        }
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        return true;
    }
    if t.starts_with("./") || t.starts_with("../") {
        return true;
    }
    if t.starts_with('/') || t.starts_with("~/") {
        return true;
    }
    // Relative with a separator AND a dot-extension on the last segment.
    if t.contains('/') {
        let last = t.rsplit('/').next().unwrap_or("");
        if let Some(dot) = last.rfind('.') {
            return dot > 0 && dot + 1 < last.len();
        }
    }
    false
}

// =============================================================================
// Bash — `source` / `.` (line-anchored regex; rules documented in the
// module docs)
// =============================================================================

lazy_static! {
    /// Bash `source`/`.` invocation, matched PER LINE after comment
    /// truncation. The operator must sit right after a line start or a
    /// `;` / `&&` / `||` separator (plus optional blanks) — that IS the
    /// "preceded by whitespace/start" requirement, and it also keeps
    /// `echo .hidden` / `xsource y.sh` / a trailing `echo .foo` inert: the
    /// anchored prefix cannot skip over ordinary words. The target token
    /// stops at whitespace and shell metacharacters (`; # & |`).
    static ref BASH_SOURCE: Regex = Regex::new(
        r"(?:^|;|&&|\|\|)[ \t]*(?:(?P<kw>source)|(?P<dot>\.))(?P<sp>[ \t]+)(?P<target>[^\s;#&|]+)"
    )
    .expect("BASH_SOURCE regex");
}

/// Bash: one [`ImportInfo`] per `source TARGET` / `. TARGET` invocation, in
/// line order. `alias` = `"source"` for both spellings (the `.` form IS the
/// POSIX `source`). Extra rules: the dot form requires a `/` in the target;
/// quoted targets are unwrapped only when the quotes balance inside the
/// captured token (unbalanced → the quoted string had spaces and is
/// skipped); full-line comments are truncated before matching.
fn extract_bash_source_links(source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    for line in source.lines() {
        // Truncate at the first `#` — suppress-only (a comment can hide a
        // candidate, never create one; quoted `#` in echo strings cannot
        // fabricate a source statement because the operator prefix still
        // has to match).
        let code = line.split('#').next().unwrap_or(line);
        for caps in BASH_SOURCE.captures_iter(code) {
            let dot_form = caps.name("dot").is_some();
            let raw = caps.name("target").map(|m| m.as_str()).unwrap_or("");
            let (target, balanced) = balance_strip_quotes(raw);
            if !balanced || target.is_empty() {
                continue;
            }
            // The POSIX `.` spelling is textually ambiguous (`. 5`, `. ..`,
            // a `.hidden` word after a separator) — require a real path
            // separator in its target. `source` stays unrestricted.
            if dot_form && !target.contains('/') {
                continue;
            }
            if emittable(&target) {
                imports.push(doc_import(&target, "source"));
            }
        }
    }
    imports
}

/// Strip one layer of `"` / `'` quoting from a bash target token ONLY when
/// the quotes balance (the token capture stops at whitespace, so a quoted
/// string containing spaces arrives as an unbalanced prefix like `"a` —
/// that must not emit). Returns `(unquoted, was_balanced)`.
fn balance_strip_quotes(raw: &str) -> (String, bool) {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        (raw[1..raw.len() - 1].to_string(), true)
    } else if bytes.first() == Some(&b'"') || bytes.first() == Some(&b'\'') {
        (raw.to_string(), false)
    } else {
        (raw.to_string(), true)
    }
}

// =============================================================================
// Plain text — the whole-document reference scan (no grammar, no link syntax;
// rules documented in the module docs and in `scan_paths_and_urls`)
// =============================================================================

/// Punctuation split off the ENDS of a plain-path token before the
/// [`looks_like_path_or_url`] test ("see ./b.txt, ok?" → `./b.txt`).
/// Sentence punctuation included (a trailing `.` is prose, not an extension);
/// interior characters are never touched.
const TOKEN_PUNCT: &[char] = &[
    '(', ')', '[', ']', '{', '}', '<', '>', ',', ';', ':', '!', '?', '"', '\'', '.',
];

/// Split surrounding punctuation off a plain-path token WITHOUT eating the
/// `.` of a `./` / `../` prefix — that dot is the path's relative-to-here
/// marker, not sentence punctuation ("see ./b.txt." keeps its `./`, loses
/// only the trailing sentence period). Trailing punctuation strips freely;
/// interior characters are never touched.
fn trim_token_punct(t: &str) -> &str {
    let mut end = t.len();
    while let Some(c) = t[..end].chars().next_back() {
        if TOKEN_PUNCT.contains(&c) {
            end -= c.len_utf8();
        } else {
            break;
        }
    }
    let mut start = 0usize;
    while let Some(c) = t[start..end].chars().next() {
        if !TOKEN_PUNCT.contains(&c) {
            break;
        }
        if c == '.' && (t[start..end].starts_with("./") || t[start..end].starts_with("../")) {
            break;
        }
        start += c.len_utf8();
    }
    &t[start..end]
}

/// Extract the reference surface of a plain-text document: one
/// `(target, alias)` pair per URL/path-shaped token, in source order, each
/// source span emitted at most once (a single left-to-right pass cannot
/// revisit a span — an angle-wrapped URL is consumed by the angle shape and
/// is therefore never also a bare-URL hit). See the module docs for the
/// shape table and the false-positive classes.
#[must_use]
pub(crate) fn scan_paths_and_urls(source: &str) -> Vec<(String, String)> {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut hits: Vec<(usize, (String, String))> = Vec::new();
    let mut i = 0usize;

    while i < len {
        let b = bytes[i];

        // 1. Angle-wrapped target: `<…>` with the closing `>` on the same
        //    line (contents may contain spaces — the angle form EXISTS to
        //    carry them). Unmatched `<` falls through to token scanning.
        if b == b'<' {
            if let Some(close) = source[i + 1..].find(['>', '\n']).map(|p| i + 1 + p) {
                if close < len && bytes[close] == b'>' {
                    let contents = &source[i + 1..close];
                    let t = contents.trim();
                    if !t.is_empty()
                        && emittable(t)
                        && (t.contains(':') || t.contains('/') || t.contains('.'))
                    {
                        hits.push((i, (t.to_string(), "angle-link".to_string())));
                    }
                    i = close + 1;
                    continue;
                }
            }
            // No closing `>` on this line: not an angle target. Advance past
            // the `<` so it cannot start a token that would contain it.
            i += 1;
            continue;
        }

        // 2. Bare URL: `https?://` + body of non-space/non-`)`/non-angle/
        //    non-quote chars, trailing sentence punctuation trimmed.
        if source[i..].starts_with("http://") || source[i..].starts_with("https://") {
            let mut j = i;
            while j < len
                && !matches!(
                    bytes[j],
                    b' ' | b'\t' | b'\r' | b'\n' | b')' | b'<' | b'>' | b'"' | b'\''
                )
            {
                j += 1;
            }
            let target = source[i..j].trim_end_matches(['.', ',', ';', ':', '!', '?', '"', '\'']);
            if emittable(target) {
                hits.push((i, (target.to_string(), "url".to_string())));
            }
            i = j;
            continue;
        }

        // 3/4. Whitespace-separated token — where a SPACE PRECEDED BY A
        //      BACKSLASH does not break the token (the shell-escape form
        //      `my\ file.txt` is one token despite its interior space).
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < len {
            if bytes[i].is_ascii_whitespace() {
                // Only a literal SPACE is shell-escapable here — a
                // backslash-newline is a line continuation, not part of the
                // path, so it must break the token.
                if bytes[i] == b' ' && bytes[i - 1] == b'\\' {
                    i += 1;
                    continue;
                }
                break;
            }
            i += 1;
        }
        let raw = &source[start..i];

        // Shell-escaped path: the token contains a backslash-space (escape
        // SYNTAX). The target is the UNESCAPED path — that IS the real path
        // on disk; the backslashes are not part of it.
        if raw.contains("\\ ") {
            let trimmed = trim_token_punct(raw);
            let target = trimmed.replace("\\ ", " ");
            if emittable(&target) {
                hits.push((start, (target, "escaped-path".to_string())));
            }
            continue;
        }

        // Plain path token: surrounding punctuation split off, then the
        // shared heuristic. A token that (after trimming) turns out to be a
        // URL — `(https://example.com/x)` — reports with the `url` alias.
        let t = trim_token_punct(raw);
        if t.is_empty() {
            continue;
        }
        if t.starts_with("http://") || t.starts_with("https://") {
            let target = t.trim_end_matches(['.', ',', ';', ':', '!', '?', '"', '\'']);
            if emittable(target) {
                hits.push((start, (target.to_string(), "url".to_string())));
            }
            continue;
        }
        if looks_like_path_or_url(t) && emittable(t) {
            hits.push((start, (t.to_string(), "path".to_string())));
        }
    }

    // Deterministic source order; dedup by byte offset (defensive — the
    // single pass never revisits a span, but the contract is "same span
    // never twice" and this makes it hold by construction).
    hits.sort_by_key(|(offset, _)| *offset);
    hits.dedup_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, hit)| hit).collect()
}

/// Plain text: one [`ImportInfo`] per URL/path-shaped token in the prose
/// (`alias` = the shape that produced it — `url`/`angle-link`/`escaped-path`/
/// `path`). The scan is purely textual; the (placeholder) tree is ignored.
fn extract_text_links(source: &str) -> Vec<ImportInfo> {
    scan_paths_and_urls(source)
        .into_iter()
        .map(|(target, alias)| doc_import(&target, &alias))
        .collect()
}

/// Markdown: inline links, images, autolinks and reference definitions.
fn extract_markdown_links(source: &str) -> Vec<ImportInfo> {
    // Mask code BLOCKS (fenced + indented — example links inside them must
    // never emit) and then inline code spans (byte-length preserving), so
    // every later match offset stays valid against the original source.
    let masked = mask_code_blocks(source);
    let masked = mask_inline_code_spans(&masked);
    let mut hits: Vec<(usize, ImportInfo)> = Vec::new();
    // A second byte-length-preserving mask: reference definitions are
    // extracted first and then blanked so the autolink pass cannot
    // double-report their `<…>`-wrapped destinations.
    let mut masked_bytes = masked.as_bytes().to_vec();

    for caps in MD_REFDEF.captures_iter(&masked) {
        let whole = caps.get(0).expect("whole match");
        let dest = unwrap_angle(caps.name("dest").map(|m| m.as_str()).unwrap_or(""));
        if !emittable(&dest) {
            continue;
        }
        let label = caps.name("label").map(|m| m.as_str()).unwrap_or("");
        hits.push((
            whole.start(),
            doc_import(&dest, &truncate_chars(label, 100)),
        ));
        mask_span(&mut masked_bytes, &(whole.start()..whole.end()));
    }
    let masked = String::from_utf8(masked_bytes).unwrap_or(masked);

    for caps in MD_INLINE.captures_iter(&masked) {
        let whole = caps.get(0).expect("whole match");
        let dest = unwrap_angle(caps.name("dest").map(|m| m.as_str()).unwrap_or(""));
        if !emittable(&dest) {
            continue;
        }
        let text = caps.name("text").map(|m| m.as_str()).unwrap_or("");
        hits.push((whole.start(), doc_import(&dest, &truncate_chars(text, 100))));
    }

    for caps in MD_AUTOLINK.captures_iter(&masked) {
        let whole = caps.get(0).expect("whole match");
        let dest = caps.name("dest").map(|m| m.as_str()).unwrap_or("");
        if let Some(target) = autolink_target(dest) {
            // The autolink's text IS its target — that is the provenance.
            hits.push((whole.start(), doc_import(&target, &target)));
        }
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, import)| import).collect()
}

/// An autolink target only counts when it looks like a URI or a path.
/// `<http://…>`, `<mailto:…>`, `<a/b.md>`, `<notes.md>` pass; bare HTML-ish
/// tokens (`<div>`, `<b>`, `<sub>`) do not. (No lookarounds in the `regex`
/// crate, so the heuristic lives here.)
fn autolink_target(dest: &str) -> Option<String> {
    if !emittable(dest) {
        return None;
    }
    if dest.contains(':') || dest.contains('/') || dest.contains('.') {
        Some(dest.to_string())
    } else {
        None
    }
}

/// HTML (and .xhtml, which rides the HTML grammar): link-bearing attributes
/// `href`, `src`, `poster`, `data`, `action`, `cite`, `background` with
/// double/single/unquoted values. `alias` = the (lowercased) attribute name.
fn extract_html_links(source: &str) -> Vec<ImportInfo> {
    const ALLOWED: [&str; 7] = [
        "href",
        "src",
        "poster",
        "data",
        "action",
        "cite",
        "background",
    ];
    extract_attrs_at(source, &ALLOWED)
        .into_iter()
        .map(|(_, import)| import)
        .collect()
}

/// XML/SVG: `xlink:href`, `xsi:schemaLocation`, `xsi:noNamespaceSchemaLocation`
/// and plain `href` (which also covers `xi:include href`), plus the
/// `<?xml-stylesheet … href="…"?>` processing instruction and the DOCTYPE
/// `SYSTEM "…"` literal. `alias` = role label.
fn extract_xml_links(source: &str) -> Vec<ImportInfo> {
    const ALLOWED: [&str; 4] = [
        "href",
        "xlink:href",
        "xsi:schemalocation",
        "xsi:nonamespaceschemalocation",
    ];

    let mut hits: Vec<(usize, ImportInfo)> = Vec::new();
    let mut masked = source.as_bytes().to_vec();

    // 1. xml-stylesheet PIs — extracted from the original text, then masked
    //    so the generic attribute pass cannot double-report their href.
    for pi in XML_STYLESHEET_PI.find_iter(source) {
        let span = pi.start()..pi.end();
        if let Some(caps) = PI_HREF.captures(&source[span.clone()]) {
            let href = caps
                .name("dq")
                .or_else(|| caps.name("sq"))
                .map(|m| m.as_str())
                .unwrap_or("");
            if emittable(href) {
                hits.push((span.start, doc_import(href, "xml-stylesheet")));
            }
        }
        mask_span(&mut masked, &span);
    }

    // 2. DOCTYPE SYSTEM literals — same extract-then-mask treatment.
    for doctype in XML_DOCTYPE.find_iter(source) {
        let span = doctype.start()..doctype.end();
        if let Some(caps) = DOCTYPE_SYSTEM.captures(&source[span.clone()]) {
            let system = caps
                .name("dq")
                .or_else(|| caps.name("sq"))
                .map(|m| m.as_str())
                .unwrap_or("");
            if emittable(system) {
                hits.push((span.start, doc_import(system, "doctype-system")));
            }
        }
        mask_span(&mut masked, &span);
    }

    // 3. Generic attribute pass over the masked source (offsets unchanged).
    hits.extend(extract_attrs_at(
        &String::from_utf8_lossy(&masked),
        &ALLOWED,
    ));

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, import)| import).collect()
}

/// Run the generic attribute regex and keep only the allowed names, keeping
/// each match's byte offset so callers can merge with other scan passes in
/// deterministic source order. `alias` = lowercased attribute name; unquoted
/// values shed one trailing `/` (the self-closing marker of
/// `<img src=x.png/>`, never part of a filesystem target).
fn extract_attrs_at(source: &str, allowed: &[&str]) -> Vec<(usize, ImportInfo)> {
    let mut hits = Vec::new();
    for caps in HTML_ATTR.captures_iter(source) {
        let whole = caps.get(0).expect("whole match");
        let raw_name = caps.name("name").map(|m| m.as_str()).unwrap_or("");
        let name = raw_name.to_ascii_lowercase();
        if !allowed.contains(&name.as_str()) {
            continue;
        }
        let mut value = caps
            .name("dq")
            .or_else(|| caps.name("sq"))
            .map(|m| m.as_str())
            .unwrap_or_else(|| caps.name("uq").map(|m| m.as_str()).unwrap_or(""));
        if caps.name("uq").is_some() {
            if let Some(stripped) = value.strip_suffix('/') {
                value = stripped;
            }
        }
        if !emittable(value) {
            continue;
        }
        hits.push((whole.start(), doc_import(value, &name)));
    }
    hits
}

/// CSS: `@import` rules and `url()` tokens. Both are **loaded elements** —
/// a stylesheet that `@import`s another stylesheet, or references a
/// font/image resource through `url()`, genuinely loads that file when it
/// is applied, so each target is a real reference edge (the CSS analogue of
/// a hyperlink; `tldr impact` treats them as such).
///
/// - `@import "path";` / `@import url(path);` / `@import url("path") media;`
///   → one entry, `alias` = `"import"`. The whole statement is masked after
///   extraction so the generic `url()` pass cannot double-report its target.
/// - `url(path)` inside any declaration (`src:` in `@font-face`,
///   `background:`/`background-image:`, `content:`, … — the scan is
///   textual, it does not care which property) → one entry per token,
///   `alias` = `"url"`. `data:` URIs and `#fragment`-only targets are
///   dropped by `emittable`; unquoted tokens containing `(`, `,`, `[` or
///   `]` are dropped as non-paths (`url(var(--font))`).
///
/// Deterministic source order (ascending byte offset, ties in scan order).
/// Like the HTML/XML scans this is textual — CSS comments are not masked.
fn extract_css_links(source: &str) -> Vec<ImportInfo> {
    let mut hits: Vec<(usize, ImportInfo)> = Vec::new();
    // Extract-then-mask: @import statements are pulled from the original
    // text and blanked so the generic url() pass cannot double-report the
    // url(...) form of an @import (offsets unchanged — mask is spaces).
    let mut masked = source.as_bytes().to_vec();

    for caps in CSS_IMPORT.captures_iter(source) {
        let whole = caps.get(0).expect("whole match");
        let target = if let Some(u) = caps.name("u") {
            strip_quotes(u.as_str())
        } else if let Some(dq) = caps.name("dq") {
            dq.as_str()
        } else {
            caps.name("sq").map(|m| m.as_str()).unwrap_or("")
        };
        if emittable(target) {
            hits.push((whole.start(), doc_import(target, "import")));
        }
        mask_span(&mut masked, &(whole.start()..whole.end()));
    }

    for caps in CSS_URL.captures_iter(&String::from_utf8_lossy(&masked)) {
        let whole = caps.get(0).expect("whole match");
        let (target, quoted) = if let Some(dq) = caps.name("dq") {
            (dq.as_str(), true)
        } else if let Some(sq) = caps.name("sq") {
            (sq.as_str(), true)
        } else {
            (caps.name("raw").map(|m| m.as_str()).unwrap_or(""), false)
        };
        let target = target.trim();
        if !emittable(target) {
            continue;
        }
        // An unquoted CSS url token may not contain these (they make it a
        // function call or a selector fragment, not a filesystem path).
        if !quoted && target.contains(['(', ',', '[', ']']) {
            continue;
        }
        hits.push((whole.start(), doc_import(target, "url")));
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, import)| import).collect()
}

/// LaTeX: file-bearing commands, one [`ImportInfo`] per braced target.
/// `alias` = the command name — the command IS the provenance:
///
/// | command | targets emitted |
/// |---|---|
/// | `\input{name}` / `\include{name}` | one |
/// | `\includegraphics[opts]{name}` (incl. `*` form) | one |
/// | `\usepackage[opts]{pkg}` | one |
/// | `\documentclass[opts]{cls}` | one |
/// | `\addbibresource{name}` | one |
/// | `\bibliography{a,b}` | one PER comma-separated part |
///
/// Targets keep the raw string exactly as written — no `.tex` is appended
/// and no path normalization happens (LaTeX resolution — kpathsea,
/// `\graphicspath`, BIBINPUTS — stays downstream, same decision as the
/// markdown/HTML raw-target rule). Whitespace around comma-split
/// `\bibliography` parts is trimmed (bibtex semantics); empty parts are
/// dropped. The scan is textual — LaTeX `%` comments are not masked.
fn extract_latex_links(source: &str) -> Vec<ImportInfo> {
    let mut hits: Vec<(usize, ImportInfo)> = Vec::new();
    for caps in LATEX_COMMAND.captures_iter(source) {
        let whole = caps.get(0).expect("whole match");
        let cmd = caps.name("cmd").map(|m| m.as_str()).unwrap_or("");
        let arg = caps.name("arg").map(|m| m.as_str()).unwrap_or("");
        let offset = whole.start();
        if cmd == "bibliography" {
            for part in arg.split(',') {
                let part = part.trim();
                if emittable(part) {
                    hits.push((offset, doc_import(part, cmd)));
                }
            }
        } else if emittable(arg) {
            hits.push((offset, doc_import(arg, cmd)));
        }
    }
    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, import)| import).collect()
}

fn doc_import(module: &str, alias: &str) -> ImportInfo {
    ImportInfo {
        module: module.to_string(),
        names: Vec::new(),
        is_from: true,
        alias: Some(alias.to_string()),
    }
}

/// Strip a syntactic `<>` destination wrapper (markdown destination syntax,
/// not part of the target string).
fn unwrap_angle(dest: &str) -> String {
    let trimmed = dest.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('<') && trimmed.ends_with('>') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Truncate a provenance label to `max` **characters** (not bytes).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Replace the bytes of `span` with spaces (byte-length preserving, keeps
/// every later match offset valid).
fn mask_span(bytes: &mut [u8], span: &std::ops::Range<usize>) {
    for b in &mut bytes[span.start..span.end] {
        *b = b' ';
    }
}

/// Mask markdown inline code spans (CommonMark rule: a run of N backticks
/// closes at the next run of exactly N backticks). Byte-length preserving:
/// match offsets against the masked copy are valid against the original.
/// Fenced/indented code BLOCKS are handled separately by `mask_code_blocks`,
/// which runs BEFORE this pass.
fn mask_inline_code_spans(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let mut open_len = 0;
        while i + open_len < bytes.len() && bytes[i + open_len] == b'`' {
            open_len += 1;
        }
        // Look for a closing run of exactly `open_len` backticks.
        let mut j = i + open_len;
        let mut close = None;
        while j < bytes.len() {
            if bytes[j] == b'`' {
                let mut run = 0;
                while j + run < bytes.len() && bytes[j + run] == b'`' {
                    run += 1;
                }
                if run == open_len {
                    close = Some(j);
                    break;
                }
                j += run;
            } else {
                j += 1;
            }
        }
        match close {
            Some(end) => {
                mask_span(&mut out, &(i..end + open_len));
                i = end + open_len;
            }
            // Unclosed run — literal backticks, nothing to mask.
            None => i += open_len,
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Strip one layer of matching `"` / `'` quotes (the CSS `url("…")` /
/// `@import "…"` wrappers are syntax, not part of the target).
fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// Mask markdown code BLOCKS (CommonMark-ish, byte-length preserving) so
/// example links inside them never emit:
///
/// - **Fenced blocks** (`mask_fenced_code_blocks`): an opening fence is a
///   line with ≤3 leading spaces followed by a run of ≥3 backticks or ≥3
///   tildes plus an optional info string (for backtick fences the info
///   string must not contain a backtick — CommonMark). The block runs to
///   the first line with ≤3 leading spaces that is a run of the SAME fence
///   char with length ≥ the opener's and nothing else (closers carry no
///   info string). An unclosed fence masks to end of input.
/// - **Indented blocks** (`mask_indented_code_blocks`): a line indented ≥4
///   spaces directly after a blank line (or the start of the document)
///   opens a block that continues over blank and ≥4-space-indented lines.
///   This is a CONSERVATIVE HEURISTIC: it does not model list/table
///   context, so a deeply-indented list continuation after a blank line can
///   be masked too. That only ever SUPPRESSES an emission (a real link
///   written that way is missed — and in CommonMark such a line usually
///   *is* a code block), never fabricates one.
///
/// Both passes write spaces into the output buffer, so match offsets
/// against the masked copy stay valid against the original (same trick as
/// `mask_inline_code_spans`). The fenced pass runs first; the indented pass
/// reads the original lines and simply over-mask — the two cannot
/// disagree, because a 4-space-indented line is never a fence opener/closer
/// (fences require ≤3 indent).
fn mask_code_blocks(source: &str) -> String {
    let mut out = source.as_bytes().to_vec();
    mask_fenced_code_blocks(source, &mut out);
    mask_indented_code_blocks(source, &mut out);
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// A line's leading-space count. Tabs are not counted — a tab-indented line
/// is neither a fence candidate nor a code-block candidate in this scanner
/// (conservative; avoids tab-width ambiguity).
fn leading_spaces(line: &[u8]) -> usize {
    line.iter().take_while(|&&b| b == b' ').count()
}

/// If `bytes` starts with a run of ≥3 identical fence characters (backtick
/// or tilde), return `(char, run_length)`.
fn fence_run(bytes: &[u8]) -> Option<(u8, usize)> {
    let first = *bytes.first()?;
    if first != b'`' && first != b'~' {
        return None;
    }
    let run = bytes.iter().take_while(|&&b| b == first).count();
    if run >= 3 {
        Some((first, run))
    } else {
        None
    }
}

fn mask_fenced_code_blocks(source: &str, out: &mut [u8]) {
    let mut in_fence = false;
    let mut fence_char = b'`';
    let mut fence_len = 0usize;
    let mut block_start = 0usize;

    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let bytes = line.as_bytes();
        let line_end = offset + bytes.len();
        let indent = leading_spaces(bytes);
        let rest = &bytes[indent..];
        if in_fence {
            // Closing fence: ≤3 indent, SAME char, length ≥ the opener's,
            // and nothing else on the line (whitespace allowed).
            if indent <= 3 {
                if let Some((ch, run)) = fence_run(rest) {
                    // The trailing newline rides the line (split_inclusive).
                    let tail_blank = rest[run..]
                        .iter()
                        .all(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n');
                    if ch == fence_char && run >= fence_len && tail_blank {
                        mask_span(out, &(block_start..line_end));
                        in_fence = false;
                    }
                }
            }
        } else if indent <= 3 {
            // Opening fence (≤3 indent, ≥3 of one fence char). CommonMark:
            // a backtick fence's info string may not contain a backtick —
            // such a line is NOT a fence and its content stays scannable.
            if let Some((ch, run)) = fence_run(rest) {
                let info = &rest[run..];
                if ch != b'`' || !info.contains(&b'`') {
                    in_fence = true;
                    fence_char = ch;
                    fence_len = run;
                    block_start = offset;
                }
            }
        }
        offset = line_end;
    }
    if in_fence {
        mask_span(out, &(block_start..source.len()));
    }
}

fn mask_indented_code_blocks(source: &str, out: &mut [u8]) {
    let mut in_block = false;
    let mut block_start = 0usize;
    // Start of document behaves like a blank predecessor line.
    let mut prev_blank = true;

    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let bytes = line.as_bytes();
        let line_end = offset + bytes.len();
        let is_blank = bytes
            .iter()
            .all(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n');
        let indent = leading_spaces(bytes);
        if in_block && !is_blank && indent < 4 {
            // A non-blank, <4-indent line ends the block BEFORE this line.
            mask_span(out, &(block_start..offset));
            in_block = false;
        }
        if !in_block && !is_blank && prev_blank && indent >= 4 {
            in_block = true;
            block_start = offset;
        }
        prev_blank = is_blank;
        offset = line_end;
    }
    if in_block {
        mask_span(out, &(block_start..source.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    fn targets(imports: &[ImportInfo]) -> Vec<&str> {
        imports.iter().map(|i| i.module.as_str()).collect()
    }

    fn aliases(imports: &[ImportInfo]) -> Vec<Option<&str>> {
        imports.iter().map(|i| i.alias.as_deref()).collect()
    }

    /// Convenience for the REGEX-ONLY extractors, which ignore the tree
    /// argument entirely: every pre-existing markdown/html/xml/css/latex
    /// pin calls through this 2-arg wrapper (documenting that those
    /// extractors never need a parse). The AST-keyed languages
    /// (JSON/YAML/TOML) are pinned through [`ast_doc`] below, which parses
    /// and passes the real tree — the same shape `get_imports` hands over.
    fn extract_doc_links(language: Language, source: &str) -> Vec<ImportInfo> {
        super::extract_doc_links(language, source, None)
    }

    /// Parse `source` with the language's grammar and run the full
    /// extractor with the tree — the exact call shape of
    /// `extract_imports_from_tree`.
    fn ast_doc(language: Language, source: &str) -> Vec<ImportInfo> {
        let tree = parse(source, language).expect("parse fixture");
        super::extract_doc_links(language, source, Some(&tree))
    }

    // =========================================================================
    // Shared ImportInfo mapping invariants
    // =========================================================================

    #[test]
    fn mapping_is_from_true_and_names_empty() {
        let imports = extract_doc_links(Language::Markdown, "[guide](guide.md)");
        assert_eq!(imports.len(), 1);
        assert!(imports[0].is_from, "document links ride is_from=true");
        assert!(imports[0].names.is_empty());
        assert_eq!(imports[0].module, "guide.md");
        assert_eq!(imports[0].alias.as_deref(), Some("guide"));
    }

    // =========================================================================
    // Markdown
    // =========================================================================

    #[test]
    fn markdown_inline_link_with_title() {
        let imports = extract_doc_links(
            Language::Markdown,
            "[setup](./docs/setup.md \"Setup guide\") next [api](api.md 'ref')",
        );
        assert_eq!(targets(&imports), vec!["./docs/setup.md", "api.md"]);
        // module is the raw target exactly as written (./ preserved).
        assert_eq!(imports[0].module, "./docs/setup.md");
        assert_eq!(aliases(&imports), vec![Some("setup"), Some("api")]);
    }

    #[test]
    fn markdown_image_uses_alt_text_as_alias() {
        let imports = extract_doc_links(Language::Markdown, "![logo](assets/logo.png)");
        assert_eq!(targets(&imports), vec!["assets/logo.png"]);
        assert_eq!(aliases(&imports), vec![Some("logo")]);
    }

    #[test]
    fn markdown_badge_nested_brackets_report_outer_target() {
        let imports = extract_doc_links(Language::Markdown, "[![Build](badge.svg)](build.md)");
        assert_eq!(targets(&imports), vec!["build.md"]);
        assert_eq!(aliases(&imports), vec![Some("![Build](badge.svg)")]);
    }

    #[test]
    fn markdown_autolink_url_and_path() {
        let imports = extract_doc_links(
            Language::Markdown,
            "See <https://example.com/x> and <notes.md> and <sub/dir/file.md>",
        );
        assert_eq!(
            targets(&imports),
            vec!["https://example.com/x", "notes.md", "sub/dir/file.md"]
        );
        // Autolink provenance = the target itself (it is the link text).
        assert_eq!(
            aliases(&imports),
            vec![
                Some("https://example.com/x"),
                Some("notes.md"),
                Some("sub/dir/file.md")
            ]
        );
    }

    #[test]
    fn markdown_autolink_rejects_htmlish_tokens() {
        let imports = extract_doc_links(Language::Markdown, "a <div> and a <b> stay inert");
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn markdown_reference_definition_multiline() {
        let source = "# Title\n\n[guide]: docs/guide.md\n[api]: <ref/api.md> \"API\"\n\nbody\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["docs/guide.md", "ref/api.md"]);
        assert_eq!(aliases(&imports), vec![Some("guide"), Some("api")]);
    }

    #[test]
    fn markdown_refdef_does_not_confuse_inline_links() {
        // Reference definitions are block-level (line-start) constructs.
        let source = "[text](target.md)\n\n[lbl]: ref.md\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["target.md", "ref.md"]);
        // A refdef line is not also an inline link.
        assert_eq!(aliases(&imports), vec![Some("text"), Some("lbl")]);
    }

    #[test]
    fn markdown_code_span_looking_text_is_inert() {
        let imports =
            extract_doc_links(Language::Markdown, "use `` `[skip](me.md)` `` inline here");
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn markdown_code_span_masking_preserves_surrounding_links() {
        let source = "[real](real.md) then `[fake](fake.md)` then [last](last.md)";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md", "last.md"]);
    }

    #[test]
    fn markdown_data_uri_and_fragment_only_are_skipped() {
        let imports = extract_doc_links(
            Language::Markdown,
            "[a](data:image/png;base64,AAAA) [b](#section) [c](ok.md)",
        );
        assert_eq!(targets(&imports), vec!["ok.md"]);
    }

    #[test]
    fn markdown_external_url_emits_as_is() {
        let imports = extract_doc_links(Language::Markdown, "[ext](https://example.com/x)");
        assert_eq!(targets(&imports), vec!["https://example.com/x"]);
    }

    #[test]
    fn markdown_source_order_is_deterministic() {
        let source = "[z](z.md)\n\n[lbl]: a.md\n\n[y](y.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["z.md", "a.md", "y.md"]);
    }

    #[test]
    fn markdown_long_link_text_truncated_to_100_chars() {
        let long = "x".repeat(250);
        let imports = extract_doc_links(Language::Markdown, &format!("[{long}](t.md)"));
        assert_eq!(
            imports[0].alias.as_ref().map(|a| a.chars().count()),
            Some(100)
        );
        assert_eq!(imports[0].module, "t.md");
    }

    #[test]
    fn markdown_angle_destination_unwrapped() {
        let imports = extract_doc_links(Language::Markdown, "[t](<a b.md>)");
        assert_eq!(targets(&imports), vec!["a b.md"]);
    }

    // =========================================================================
    // HTML
    // =========================================================================

    #[test]
    fn html_href_src_double_quoted() {
        let source = r#"<a href="other.html">x</a><script src="app.js"></script>"#;
        let imports = extract_doc_links(Language::Html, source);
        assert_eq!(targets(&imports), vec!["other.html", "app.js"]);
        assert_eq!(aliases(&imports), vec![Some("href"), Some("src")]);
    }

    #[test]
    fn html_single_and_unquoted_values() {
        let source = r#"<a href='s.html'>x</a><img src=logo.png alt=y>"#;
        let imports = extract_doc_links(Language::Html, source);
        assert_eq!(targets(&imports), vec!["s.html", "logo.png"]);
    }

    #[test]
    fn html_unquoted_self_closing_slash_stripped() {
        let imports = extract_doc_links(Language::Html, r#"<img src=logo.png/>"#);
        assert_eq!(targets(&imports), vec!["logo.png"]);
    }

    #[test]
    fn html_all_link_bearing_attributes() {
        let source = r#"<video poster="p.png" data="d.bin" action="/submit" cite="c.md" background="bg.gif">"#;
        let imports = extract_doc_links(Language::Html, source);
        assert_eq!(
            targets(&imports),
            vec!["p.png", "d.bin", "/submit", "c.md", "bg.gif"]
        );
        assert_eq!(
            aliases(&imports),
            vec![
                Some("poster"),
                Some("data"),
                Some("action"),
                Some("cite"),
                Some("background")
            ]
        );
    }

    #[test]
    fn html_data_dash_attribute_not_matched_as_data() {
        let imports = extract_doc_links(Language::Html, r#"<div data-config="cfg.json"></div>"#);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn html_attr_names_case_insensitive() {
        let imports = extract_doc_links(Language::Html, r#"<A HREF="up.html">x</A>"#);
        assert_eq!(targets(&imports), vec!["up.html"]);
        assert_eq!(aliases(&imports), vec![Some("href")]);
    }

    #[test]
    fn html_fragment_only_and_data_uri_skipped() {
        let imports = extract_doc_links(
            Language::Html,
            r##"<a href="#top">t</a><img src="data:image/gif;base64,R0="><a href="real.html">r</a>"##,
        );
        assert_eq!(targets(&imports), vec!["real.html"]);
    }

    #[test]
    fn html_other_attributes_ignored() {
        let imports = extract_doc_links(
            Language::Html,
            r#"<div class="a.md" id="b.md" title="c.md">"#,
        );
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    // =========================================================================
    // XML / SVG
    // =========================================================================

    #[test]
    fn xml_attributes_href_xlink_schema_location() {
        let source = r#"<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:noNamespaceSchemaLocation="schema/root.xsd"><child xlink:href="more.xml"/></root>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(targets(&imports), vec!["schema/root.xsd", "more.xml"]);
        assert_eq!(
            aliases(&imports),
            vec![Some("xsi:nonamespaceschemalocation"), Some("xlink:href")]
        );
    }

    #[test]
    fn xml_xi_include_href_rides_plain_href() {
        let source = r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="parts/one.xml"/></root>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(targets(&imports), vec!["parts/one.xml"]);
        assert_eq!(aliases(&imports), vec![Some("href")]);
    }

    #[test]
    fn xml_stylesheet_pi() {
        let source =
            r#"<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="style.xsl"?><root/>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(targets(&imports), vec!["style.xsl"]);
        assert_eq!(aliases(&imports), vec![Some("xml-stylesheet")]);
    }

    #[test]
    fn xml_stylesheet_pi_href_not_double_reported() {
        let source = r#"<?xml-stylesheet type="text/xsl" href="style.xsl"?><root a="b"/>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(imports.len(), 1, "PI href must appear exactly once");
    }

    #[test]
    fn xml_doctype_system_literal() {
        let source = r#"<?xml version="1.0"?><!DOCTYPE note SYSTEM "note.dtd"><note/>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(targets(&imports), vec!["note.dtd"]);
        assert_eq!(aliases(&imports), vec![Some("doctype-system")]);
    }

    #[test]
    fn xml_svg_image_href() {
        let source = r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="img.png"/></svg>"#;
        let imports = extract_doc_links(Language::Xml, source);
        assert_eq!(targets(&imports), vec!["img.png"]);
    }

    #[test]
    fn xml_plain_elements_without_link_attrs_are_inert() {
        let imports = extract_doc_links(Language::Xml, r#"<root><item id="a.md"/></root>"#);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn xml_data_uri_skipped() {
        let imports = extract_doc_links(Language::Xml, r#"<img href="data:text/plain,hi"/>"#);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    // =========================================================================
    // CSS
    // =========================================================================

    #[test]
    fn css_import_double_quoted() {
        let imports = extract_doc_links(Language::Css, "@import \"theme.css\";\n");
        assert_eq!(targets(&imports), vec!["theme.css"]);
        assert_eq!(aliases(&imports), vec![Some("import")]);
        assert!(imports[0].is_from);
    }

    #[test]
    fn css_import_single_quoted() {
        let imports = extract_doc_links(Language::Css, "@import 'theme.css';\n");
        assert_eq!(targets(&imports), vec!["theme.css"]);
        assert_eq!(aliases(&imports), vec![Some("import")]);
    }

    #[test]
    fn css_import_url_unquoted_quoted_and_media_tail() {
        let imports = extract_doc_links(
            Language::Css,
            "@import url(a.css);\n@import url(\"b.css\") screen;\n@import url('c.css') print;\n",
        );
        assert_eq!(targets(&imports), vec!["a.css", "b.css", "c.css"]);
        assert_eq!(aliases(&imports), vec![Some("import"); 3]);
    }

    #[test]
    fn css_import_keyword_case_insensitive() {
        let imports = extract_doc_links(Language::Css, "@IMPORT url(A.css);\n");
        assert_eq!(targets(&imports), vec!["A.css"]);
    }

    #[test]
    fn css_import_url_form_not_double_reported() {
        let imports = extract_doc_links(Language::Css, "@import url(theme.css);\n");
        assert_eq!(
            imports.len(),
            1,
            "url() inside @import must not double-report: {:?}",
            imports
        );
        assert_eq!(aliases(&imports), vec![Some("import")]);
    }

    #[test]
    fn css_font_face_and_background_urls() {
        let source = "@font-face {\n  font-family: \"Inter\";\n  src: url(fonts/a.woff2) format(\"woff2\");\n}\n.hero { background: url(\"img/hero.png\") no-repeat; }\n.icon { background-image: url('i/logo.svg'); }";
        let imports = extract_doc_links(Language::Css, source);
        assert_eq!(
            targets(&imports),
            vec!["fonts/a.woff2", "img/hero.png", "i/logo.svg"]
        );
        assert_eq!(aliases(&imports), vec![Some("url"); 3]);
    }

    #[test]
    fn css_data_uri_and_fragment_only_skipped() {
        let source = ".a { background: url(data:image/png;base64,AAAA); }\n.b { clip-path: url(#mask); }\n.c { color: red; }";
        let imports = extract_doc_links(Language::Css, source);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn css_unquoted_function_call_is_not_a_path() {
        // url(var(--font)) — the unquoted token stops at `)` and is not a
        // filesystem path.
        let imports = extract_doc_links(Language::Css, "p { font-family: url(var(--font)); }");
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn css_url_spaces_around_path() {
        let imports = extract_doc_links(Language::Css, ".a { background: url( img/hero.png ); }");
        assert_eq!(targets(&imports), vec!["img/hero.png"]);
    }

    #[test]
    fn css_source_order_is_deterministic() {
        let source =
            ".a { background: url(z.png); }\n@import url(a.css);\n.b { content: url(m.png); }";
        let imports = extract_doc_links(Language::Css, source);
        assert_eq!(targets(&imports), vec!["z.png", "a.css", "m.png"]);
    }

    #[test]
    fn css_non_url_properties_are_inert() {
        // Quoted strings in non-url() positions are values, not references.
        let imports = extract_doc_links(
            Language::Css,
            ".a { color: #fff; font-family: \"x.md\"; }\n",
        );
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn css_scan_is_textual_comments_not_masked() {
        // Documented scope: the scan is textual (like the HTML attribute
        // scan), so a url() inside a comment DOES emit.
        let imports = extract_doc_links(Language::Css, "/* .b { background: url(c.png); } */\n");
        assert_eq!(targets(&imports), vec!["c.png"]);
    }

    // =========================================================================
    // LaTeX
    // =========================================================================

    #[test]
    fn latex_input_and_include() {
        let imports = extract_doc_links(
            Language::Latex,
            "\\input{chapters/ch1}\n\\include{chapters/app}\n",
        );
        assert_eq!(targets(&imports), vec!["chapters/ch1", "chapters/app"]);
        assert_eq!(aliases(&imports), vec![Some("input"), Some("include")]);
        assert!(imports[0].is_from);
    }

    #[test]
    fn latex_includegraphics_opts_and_starred() {
        let imports = extract_doc_links(
            Language::Latex,
            "\\includegraphics[width=0.8\\textwidth]{fig.png}\n\\includegraphics*[scale=0.5]{img.png}\n\\includegraphics*{bare.png}\n",
        );
        assert_eq!(targets(&imports), vec!["fig.png", "img.png", "bare.png"]);
        assert_eq!(aliases(&imports), vec![Some("includegraphics"); 3]);
    }

    #[test]
    fn latex_usepackage_and_documentclass_opts() {
        let imports = extract_doc_links(
            Language::Latex,
            "\\documentclass[11pt]{article}\n\\usepackage[T1]{fontenc}\n\\usepackage{graphicx}\n",
        );
        assert_eq!(targets(&imports), vec!["article", "fontenc", "graphicx"]);
        assert_eq!(
            aliases(&imports),
            vec![
                Some("documentclass"),
                Some("usepackage"),
                Some("usepackage")
            ]
        );
    }

    #[test]
    fn latex_bibliography_comma_split() {
        let imports = extract_doc_links(Language::Latex, "\\bibliography{refs,more}\n");
        assert_eq!(targets(&imports), vec!["refs", "more"]);
        assert_eq!(aliases(&imports), vec![Some("bibliography"); 2]);
    }

    #[test]
    fn latex_bibliography_parts_trimmed_and_empty_dropped() {
        let imports = extract_doc_links(Language::Latex, "\\bibliography{ refs , more , }\n");
        assert_eq!(targets(&imports), vec!["refs", "more"]);
    }

    #[test]
    fn latex_addbibresource() {
        let imports = extract_doc_links(Language::Latex, "\\addbibresource{refs.bib}\n");
        assert_eq!(targets(&imports), vec!["refs.bib"]);
        assert_eq!(aliases(&imports), vec![Some("addbibresource")]);
    }

    #[test]
    fn latex_targets_kept_raw_no_tex_appended() {
        let imports = extract_doc_links(Language::Latex, "\\input{./chapters/app}\n");
        assert_eq!(targets(&imports), vec!["./chapters/app"]);
    }

    #[test]
    fn latex_no_false_positives_on_prose_or_lookalikes() {
        // \section{input} / \subsection{include}: the ARGUMENT is a handled
        // word, the command is not — nothing emits. \bibliographystyle is a
        // different command; \myinput / \inputx fail the command-name word
        // boundary; a bare "input" without a backslash is prose.
        let source = "\\section{input}\n\\subsection{include}\n\\bibliographystyle{plain}\n\\myinput{x}\n\\inputx{y}\nthe word input alone does nothing\n";
        let imports = extract_doc_links(Language::Latex, source);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn latex_source_order_is_deterministic() {
        let source = "\\input{a}\n\\usepackage{b}\n\\input{c}\n";
        let imports = extract_doc_links(Language::Latex, source);
        assert_eq!(targets(&imports), vec!["a", "b", "c"]);
    }

    // =========================================================================
    // Markdown code-block masking
    // =========================================================================

    #[test]
    fn markdown_fenced_block_links_are_inert() {
        let source = concat!(
            "# T\n\n```rust\n",
            "let x = \"[fake](x.md)\";\n",
            "let u = <https://fake.example>;\n",
            "```\n\ntail\n"
        );
        let imports = extract_doc_links(Language::Markdown, source);
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn markdown_real_links_around_fences_still_emit() {
        let source = "[before](before.md)\n\n```\n[fake](fake.md)\n```\n\n[after](after.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["before.md", "after.md"]);
    }

    #[test]
    fn markdown_backtick_fence_with_backticks_inside_string() {
        // The ``` inside the string literal is fence CONTENT (a closing
        // fence carries nothing else), so the block runs to the real closer
        // and the link after it still emits.
        let source = "```rust\nlet s = \"```\";\n```\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_tilde_fence_closed_by_longer_run() {
        // ~~~ opener (≥3) closed by a LONGER run of the same char.
        let source = "~~~\n[fake](fake.md)\n~~~~~\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_backticks_inside_tilde_fence_are_content() {
        // A ``` line inside a ~~~ fence is content (different fence char).
        let source = "~~~\n```\n[fake](fake.md)\n```\n~~~\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_fence_info_string_masked_too() {
        let source = "```rust title=\"[fake](fake.md)\"\n[fake](fake.md)\n```\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_backtick_info_string_with_backtick_is_not_a_fence() {
        // CommonMark: a backtick fence's info string may not contain a
        // backtick — this line is NOT a fence, so the link below emits.
        let source = "``` a ` b\n[fake](fake.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["fake.md"]);
    }

    #[test]
    fn markdown_refdef_inside_fence_is_inert() {
        let source = "```\n[lbl]: ref.md\n```\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_unclosed_fence_masks_to_eof() {
        let source = "[before](before.md)\n\n```\n[fake](fake.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["before.md"]);
    }

    #[test]
    fn markdown_fence_indent_up_to_three_spaces() {
        let source = "   ```\n[fake](fake.md)\n   ```\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_indented_code_block_is_masked() {
        let source = "# T\n\n    [fake](fake.md)\n    <https://fake.example>\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn markdown_indented_block_needs_blank_line_before() {
        // A paragraph line followed by a 4-space line is a lazy
        // continuation, not a code block — the link still emits (heuristic
        // scope, and correct CommonMark too).
        let source = "text\n    [fake](fake.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["fake.md"]);
    }

    #[test]
    fn markdown_indented_block_over_blank_lines() {
        // Blank lines INSIDE an indented block keep it open.
        let source = "# T\n\n    [fake](fake.md)\n\n    [also-fake](nope.md)\n\n[real](real.md)\n";
        let imports = extract_doc_links(Language::Markdown, source);
        assert_eq!(targets(&imports), vec!["real.md"]);
    }

    #[test]
    fn mask_code_blocks_is_byte_length_preserving() {
        let source = "a\n\n```\n[fake](fake.md)\n```\n\nb\n";
        let masked = mask_code_blocks(source);
        assert_eq!(masked.len(), source.len());
        assert!(!masked.contains("[fake]"), "got {masked:?}");
        // The masked span runs through the closing fence's own newline, so
        // the tail keeps only the blank line + "b".
        assert!(masked.starts_with("a\n\n") && masked.ends_with("\nb\n"));
    }

    // =========================================================================
    // Language gating
    // =========================================================================

    /// Log and Python still have no link surface. (Css/Latex joined in
    /// doclinks-v1's css/latex batch; JSON/YAML/TOML/Bash joined with the
    /// config batch — each has its own extractor section and pins above.
    /// Log never parses through tree-sitter and Bash is pinned in the
    /// bash section; neither appears here because the config batch turned
    /// JSON/YAML/TOML/Bash into doc languages.)
    #[test]
    fn non_document_languages_emit_nothing() {
        for lang in [Language::Log, Language::Python] {
            let imports = extract_doc_links(
                lang,
                "[a](b.md) <x href=\"y.md\"> @import \"z.css\"; \\input{w.tex}",
            );
            assert!(imports.is_empty(), "{lang:?} must emit nothing");
        }
    }

    /// The AST-keyed extractors REQUIRE a tree — `None` (no parse) yields
    /// no emissions rather than a regex fallback. The JSON pin is
    /// representative; YAML/TOML share the dispatcher arm shape.
    #[test]
    fn ast_keyed_extractors_need_the_tree() {
        let src = r#"{"$ref": "./b.json"}"#;
        assert!(super::extract_doc_links(Language::Json, src, None).is_empty());
        let yaml = "root:\n  $ref: ./b.yaml\n";
        assert!(super::extract_doc_links(Language::Yaml, yaml, None).is_empty());
        let toml = "asset = \"./b.svg\"\n";
        assert!(super::extract_doc_links(Language::Toml, toml, None).is_empty());
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    #[test]
    fn truncate_chars_counts_characters_not_bytes() {
        assert_eq!(
            truncate_chars("é".repeat(60).as_str(), 100).chars().count(),
            60
        );
        assert_eq!(truncate_chars(&"x".repeat(150), 100).chars().count(), 100);
    }

    #[test]
    fn mask_inline_code_spans_is_byte_length_preserving() {
        let source = "a `[x](y)` b";
        let masked = mask_inline_code_spans(source);
        assert_eq!(masked.len(), source.len());
        assert!(!masked.contains("[x](y)"), "got {masked:?}");
        assert!(masked.starts_with("a ") && masked.ends_with(" b"));
    }

    #[test]
    fn mask_inline_code_spans_handles_double_backticks() {
        let source = "a ``x `[y](z.md)` y`` b";
        let masked = mask_inline_code_spans(source);
        assert!(!masked.contains("y.md"), "got {masked:?}");
    }

    // =========================================================================
    // JSON — AST-keyed `$ref` / `extends`
    // =========================================================================

    #[test]
    fn json_ref_and_extends_emit_with_key_aliases() {
        let src = r#"{
  "openapi": "3.0.0",
  "components": {
    "schemas": {
      "user": { "$ref": "./schemas/user.json", "extends": "base.json" }
    }
  },
  "name": "./not-a-ref.json",
  "version": 3
}"#;
        let imports = ast_doc(Language::Json, src);
        assert_eq!(targets(&imports), vec!["./schemas/user.json", "base.json"]);
        assert_eq!(aliases(&imports), vec![Some("$ref"), Some("extends")]);
        assert!(imports.iter().all(|i| i.is_from && i.names.is_empty()));
    }

    #[test]
    fn json_non_string_ref_values_ignored() {
        let src = r#"{
  "a": { "$ref": 42 },
  "b": { "extends": null },
  "c": { "$ref": {} },
  "d": { "$ref": ["./x.json"] }
}"#;
        assert!(ast_doc(Language::Json, src).is_empty());
    }

    #[test]
    fn json_internal_pointers_and_data_uris_suppressed() {
        let src = r##"{
  "ptr": { "$ref": "#/components/schemas/User" },
  "inline": { "$ref": "data:application/json,{}" },
  "blank": { "$ref": "" }
}"##;
        assert!(ast_doc(Language::Json, src).is_empty());
    }

    #[test]
    fn json_external_url_still_emits() {
        let src = r#"{ "allOf": { "$ref": "https://schemas.example.org/user.json" } }"#;
        let imports = ast_doc(Language::Json, src);
        assert_eq!(
            targets(&imports),
            vec!["https://schemas.example.org/user.json"]
        );
        assert_eq!(aliases(&imports), vec![Some("$ref")]);
    }

    // =========================================================================
    // YAML — AST-keyed `$ref` / `extends`
    // =========================================================================

    #[test]
    fn yaml_ref_and_extends_plain_quoted_and_flow() {
        let src = "service:\n  $ref: ./config/base.yaml\n  '$ref': \"./other.yaml\"\n  extends: 'tpl.yaml'\nflow: {extends: \"flow-base.yaml\"}\n";
        let imports = ast_doc(Language::Yaml, src);
        assert_eq!(
            targets(&imports),
            vec![
                "./config/base.yaml",
                "./other.yaml",
                "tpl.yaml",
                "flow-base.yaml"
            ]
        );
        assert_eq!(
            aliases(&imports),
            vec![Some("$ref"), Some("$ref"), Some("extends"), Some("extends")]
        );
    }

    #[test]
    fn yaml_actions_include_matrix_stays_inert() {
        // GitHub Actions `strategy.matrix.include` expands PARAMETERS, not
        // files — and even a path-looking string inside it must not emit
        // (YAML is key-gated, deliberately unlike the TOML path scan).
        let src = "name: deploy\non: push\njobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - os: ubuntu-latest\n            config: ./ci/linux.yaml\n    steps:\n      - run: ./build.sh\n";
        assert!(ast_doc(Language::Yaml, src).is_empty());
    }

    #[test]
    fn yaml_include_and_resources_keys_not_scanned() {
        // Compose `include:`, kustomize `resources:` — suppress-only by
        // policy (module docs: the value TYPE cannot disambiguate without
        // per-tool schemas).
        let src = "include:\n  - ./compose.db.yaml\nresources:\n  - ./deploy.yaml\nimport:\n  - ./x.yaml\n";
        assert!(ast_doc(Language::Yaml, src).is_empty());
    }

    #[test]
    fn yaml_non_scalar_ref_values_ignored() {
        let src = "a:\n  $ref:\n    - ./x.yaml\nb:\n  $ref:\n    key: ./y.yaml\n";
        assert!(ast_doc(Language::Yaml, src).is_empty());
    }

    #[test]
    fn yaml_ref_with_inline_comment_keeps_clean_target() {
        let src = "root:\n  $ref: ./base.yaml # the shared base\n";
        let imports = ast_doc(Language::Yaml, src);
        assert_eq!(targets(&imports), vec!["./base.yaml"]);
    }

    // =========================================================================
    // TOML — string-value path scan
    // =========================================================================

    #[test]
    fn toml_path_shaped_strings_emit_with_path_alias() {
        let src = concat!(
            "name = \"tldr\"\n",
            "version = \"1.2.3\"\n",
            "\n",
            "[assets]\n",
            "asset = \"./img/logo.svg\"\n",
            "theme = \"config/dev.toml\"\n",
            "parent = \"../shared.toml\"\n",
            "abs = \"/etc/app/conf.toml\"\n",
            "home = \"~/x.toml\"\n",
            "remote = \"https://example.com/logo.png\"\n",
            "\n",
            "[style]\n",
            "inline = { icon = \"assets/icon.svg\" }\n",
        );
        let imports = ast_doc(Language::Toml, src);
        assert_eq!(
            targets(&imports),
            vec![
                "./img/logo.svg",
                "config/dev.toml",
                "../shared.toml",
                "/etc/app/conf.toml",
                "~/x.toml",
                "https://example.com/logo.png",
                "assets/icon.svg",
            ]
        );
        assert_eq!(
            aliases(&imports),
            vec![Some("path"); 7],
            "alias = the heuristic's role label"
        );
    }

    #[test]
    fn toml_non_path_strings_emit_nothing() {
        let src = concat!(
            "name = \"tldr\"\n",
            "version = \"1.2.3\"\n",
            "code = \"foo_bar\"\n",
            "frag = \"#/definitions/User\"\n",
            "uri = \"data:image/png;base64,AAAA\"\n",
            "mail = \"mailto:ops@example.com\"\n",
            "spaced = \"my file.svg\"\n",
            "braced = \"{var}/x.toml\"\n",
            "angled = \"<x.svg>\"\n",
            "nodir = \"logo.svg\"\n",
            "dir = \"assets/\"\n",
            "count = 3\n",
            "tags = [\"./not-in-array.svg\"]\n",
        );
        assert!(ast_doc(Language::Toml, src).is_empty());
    }

    #[test]
    fn looks_like_path_or_url_table() {
        let yes = [
            "https://example.com/a.png",
            "http://example.com",
            "./a.svg",
            "../shared/dev.toml",
            "/etc/app/conf.toml",
            "~/x.toml",
            "assets/logo.svg",
            "config/dev.toml",
        ];
        let no = [
            "",
            "tldr",
            "1.2.3",
            "foo_bar",
            "logo.svg",
            "#fragment",
            "data:image/png;base64,AA",
            "mailto:ops@example.com",
            "ftp://files.example.com/a.zip",
            "my file.svg",
            "{var}/x.toml",
            "<x.svg>",
            "assets/",
            "assets/.hidden",
        ];
        for s in yes {
            assert!(looks_like_path_or_url(s), "{s:?} must look like a path");
        }
        for s in no {
            assert!(
                !looks_like_path_or_url(s),
                "{s:?} must NOT look like a path"
            );
        }
    }

    // =========================================================================
    // Bash — `source` / `.`
    // =========================================================================

    #[test]
    fn bash_source_forms_emit_in_line_order() {
        let src = "#!/usr/bin/env bash\nset -euo pipefail\nsource ./env.sh\n  source vars.sh\n. /etc/profile\nfoo; source x.sh\nbar && source y.sh\nbaz || source z.sh\n";
        let imports = extract_doc_links(Language::Bash, src);
        assert_eq!(
            targets(&imports),
            vec![
                "./env.sh",
                "vars.sh",
                "/etc/profile",
                "x.sh",
                "y.sh",
                "z.sh"
            ]
        );
        assert_eq!(
            aliases(&imports),
            vec![Some("source"); 6],
            "the `.` form is the POSIX spelling of source"
        );
        assert!(imports.iter().all(|i| i.is_from && i.names.is_empty()));
    }

    #[test]
    fn bash_dot_form_requires_a_path_separator() {
        // `. ./env.sh` emits; `. hidden` (no `/`) stays inert — the
        // whitespace-adjacent dot is textually ambiguous.
        let src = ". ./env.sh\n. hidden\n  . ../lib/x.sh\n";
        let imports = extract_doc_links(Language::Bash, src);
        assert_eq!(targets(&imports), vec!["./env.sh", "../lib/x.sh"]);
    }

    #[test]
    fn bash_negatives() {
        let src = "echo .hidden\necho .foo\n#source comment\n  # . ./x.sh\nsource\nxsource y.sh\n.  \n./build.sh\n";
        assert!(
            extract_doc_links(Language::Bash, src).is_empty(),
            "no source/. operator in any of these lines"
        );
    }

    #[test]
    fn bash_quoted_targets() {
        let src = "source \"$CONF/env.sh\"\nsource './opt/run.sh'\nsource \"a b.sh\"\n";
        let imports = extract_doc_links(Language::Bash, src);
        // `"$CONF/env.sh"` and `'./opt/run.sh'` balance → quotes stripped;
        // `"a b.sh"` captures unbalanced (`"a` — the token stops at the
        // space) and is skipped.
        assert_eq!(targets(&imports), vec!["$CONF/env.sh", "./opt/run.sh"]);
    }

    #[test]
    fn bash_inline_comments_are_suppress_only() {
        let src = "source ./env.sh # load the env\n. /etc/profile.d/lang.sh  # locale\n";
        let imports = extract_doc_links(Language::Bash, src);
        assert_eq!(
            targets(&imports),
            vec!["./env.sh", "/etc/profile.d/lang.sh"]
        );
    }

    #[test]
    fn balance_strip_quotes_rules() {
        assert_eq!(balance_strip_quotes("\"a.sh\""), ("a.sh".into(), true));
        assert_eq!(balance_strip_quotes("'a.sh'"), ("a.sh".into(), true));
        assert_eq!(balance_strip_quotes("a.sh"), ("a.sh".into(), true));
        assert_eq!(balance_strip_quotes("\"a"), ("\"a".into(), false));
        assert_eq!(balance_strip_quotes("'"), ("'".into(), false));
    }

    // =========================================================================
    // Plain text — scan_paths_and_urls (bare URLs / angle / escaped / paths)
    // =========================================================================

    #[test]
    fn text_bare_url_trailing_period_trimmed() {
        let imports = extract_doc_links(
            Language::Text,
            "See https://example.com/docs. Also https://example.com/a?",
        );
        assert_eq!(
            targets(&imports),
            vec!["https://example.com/docs", "https://example.com/a"]
        );
        assert_eq!(aliases(&imports), vec![Some("url"), Some("url")]);
        assert!(imports.iter().all(|i| i.is_from && i.names.is_empty()));
    }

    #[test]
    fn text_angle_path_with_spaces() {
        let imports =
            extract_doc_links(Language::Text, "Guide: <./docs/guide with spaces.md> here");
        assert_eq!(targets(&imports), vec!["./docs/guide with spaces.md"]);
        assert_eq!(aliases(&imports), vec![Some("angle-link")]);
    }

    #[test]
    fn text_angle_wrapped_url_is_not_double_reported() {
        // The angle span is consumed once — the inner URL must not ALSO emit
        // as a bare `url` (dedup by span, the documented contract).
        let imports = extract_doc_links(Language::Text, "see <https://example.com/x> now");
        assert_eq!(targets(&imports), vec!["https://example.com/x"]);
        assert_eq!(aliases(&imports), vec![Some("angle-link")]);
    }

    #[test]
    fn text_escaped_path_target_is_the_unescaped_real_path() {
        let imports = extract_doc_links(Language::Text, "cat my\\ file.txt for details");
        assert_eq!(
            targets(&imports),
            vec!["my file.txt"],
            "backslash escape removed"
        );
        assert_eq!(aliases(&imports), vec![Some("escaped-path")]);
    }

    #[test]
    fn text_percent_encoded_token_kept_raw() {
        // Extraction keeps `%20` verbatim — the resolution layer
        // (analysis::doc_impact) tries the decoded spelling as a fallback.
        let imports = extract_doc_links(Language::Text, "open ./docs/my%20file.txt now");
        assert_eq!(targets(&imports), vec!["./docs/my%20file.txt"]);
        assert_eq!(aliases(&imports), vec![Some("path")]);
    }

    #[test]
    fn text_plain_path_token_with_punctuation_split() {
        let imports = extract_doc_links(Language::Text, "Config in (./etc/app.yaml), done.");
        assert_eq!(targets(&imports), vec!["./etc/app.yaml"]);
        assert_eq!(aliases(&imports), vec![Some("path")]);
    }

    #[test]
    fn text_parenthesised_url_reports_with_url_alias() {
        let imports = extract_doc_links(Language::Text, "(https://example.com/x)");
        assert_eq!(targets(&imports), vec!["https://example.com/x"]);
        assert_eq!(aliases(&imports), vec![Some("url")]);
    }

    #[test]
    fn text_prose_and_bare_words_stay_inert() {
        // No separators, no extensions-with-slash, no schemes: nothing to
        // emit. `guide.md` alone (bare filename, no directory) is inert by
        // the shared looks_like_path_or_url rule.
        let src = "just some words\nanother line here\nsee guide.md alone\n";
        assert!(
            extract_doc_links(Language::Text, src).is_empty(),
            "bare prose must not fabricate references"
        );
    }

    #[test]
    fn text_htmlish_angle_tokens_stay_inert() {
        let imports = extract_doc_links(Language::Text, "a <div> and <b> stay inert");
        assert!(imports.is_empty(), "got {:?}", imports);
    }

    #[test]
    fn text_fragment_and_data_targets_suppressed() {
        let imports = extract_doc_links(Language::Text, "jump <#section> skip <data:x> ./ok.md");
        assert_eq!(targets(&imports), vec!["./ok.md"]);
    }

    #[test]
    fn text_source_order_is_deterministic_and_mixed() {
        let src = concat!(
            "Intro\n",
            "see https://example.com/docs for upstream\n",
            "full guide: <./docs/guide with spaces.md>\n",
            "raw dump: cat my\\ file.txt\n",
            "related: ./b.txt\n",
        );
        let imports = extract_doc_links(Language::Text, src);
        assert_eq!(
            targets(&imports),
            vec![
                "https://example.com/docs",
                "./docs/guide with spaces.md",
                "my file.txt",
                "./b.txt",
            ]
        );
        assert_eq!(
            aliases(&imports),
            vec![
                Some("url"),
                Some("angle-link"),
                Some("escaped-path"),
                Some("path")
            ]
        );
    }

    #[test]
    fn text_repeated_token_emits_per_occurrence_not_per_span() {
        // Dedup is by span, not by target: two separate occurrences of the
        // same URL are two references; one occurrence is exactly one entry.
        let src = "a https://x.io/a and https://x.io/a end\n";
        let imports = extract_doc_links(Language::Text, src);
        assert_eq!(targets(&imports), vec!["https://x.io/a", "https://x.io/a"]);
    }

    #[test]
    fn text_scan_paths_and_urls_pairs_match_extract_doc_links() {
        // The pub(crate) scanner and the ImportInfo extractor agree.
        let src = "u https://a.io/p\np ./x/y.md\n";
        let pairs = scan_paths_and_urls(src);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("https://a.io/p".to_string(), "url".to_string()));
        assert_eq!(pairs[1], ("./x/y.md".to_string(), "path".to_string()));
    }
}
