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
//! - **Deferred (next batch):** JSON/YAML/TOML path-strings, bash `source`,
//!   and plain text — no link surface is wired for those languages yet.
//! - HTML comments and `<script>` bodies are not masked (documented scope:
//!   the attribute scan is textual, like the C include scan); the CSS and
//!   LaTeX scans are likewise textual (comments are not masked).
//!
//! # External targets
//!
//! `data:` URIs and `#fragment`-only targets emit nothing. http(s) URLs ARE
//! emitted (they are real references worth indexing) but they can never
//! resolve to project files downstream — `doc_impact` and the importers doc
//! matcher treat `://` targets as external and skip them.

use lazy_static::lazy_static;
use regex::Regex;

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
pub fn extract_doc_links(language: Language, source: &str) -> Vec<ImportInfo> {
    match language {
        Language::Markdown => extract_markdown_links(source),
        Language::Html => extract_html_links(source),
        Language::Xml => extract_xml_links(source),
        Language::Css => extract_css_links(source),
        Language::Latex => extract_latex_links(source),
        _ => Vec::new(),
    }
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

    fn targets(imports: &[ImportInfo]) -> Vec<&str> {
        imports.iter().map(|i| i.module.as_str()).collect()
    }

    fn aliases(imports: &[ImportInfo]) -> Vec<Option<&str>> {
        imports.iter().map(|i| i.alias.as_deref()).collect()
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

    /// Css and Latex ARE document languages now (their extractors live in
    /// the CSS/LaTeX sections above); these languages still have no link
    /// surface.
    #[test]
    fn non_document_languages_emit_nothing() {
        for lang in [
            Language::Json,
            Language::Yaml,
            Language::Toml,
            Language::Log,
            Language::Bash,
            Language::Python,
        ] {
            let imports = extract_doc_links(
                lang,
                "[a](b.md) <x href=\"y.md\"> @import \"z.css\"; \\input{w.tex}",
            );
            assert!(imports.is_empty(), "{lang:?} must emit nothing");
        }
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
}
