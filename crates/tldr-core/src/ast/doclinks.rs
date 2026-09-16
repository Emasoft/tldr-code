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
//!   `c.md#frag`, `https://example.com/x` stay untouched). Resolution /
//!   normalization is a downstream concern (`analysis::doc_impact` and the
//!   `module_matches` doc arm in `analysis::importers`), not an extraction
//!   one — extraction must stay a faithful, lossless index of the source.
//! - `names` = empty (a link has no imported symbols).
//! - `is_from` = `true`. The closest analogue of a from-import: the target
//!   is referenced *by name, at a point of use*, which is what `is_from`
//!   communicates to consumers.
//! - `alias` = a provenance label describing WHERE the link came from:
//!   markdown link text (truncated to 100 chars), the reference-definition
//!   label, the HTML attribute name (`href`/`src`/…), or the XML role
//!   (attribute name / `xml-stylesheet` / `doctype-system`).
//!
//! # Scope and masking plan
//!
//! - **Masked now:** markdown *inline code spans* (`` `[x](y.md)` `` must not
//!   look like a link). The masking is byte-length-preserving so match
//!   offsets stay valid against the original source.
//! - **Deferred (next batch):** markdown *fenced/indented code blocks* are
//!   NOT masked yet — a link-shaped line inside a fence currently emits.
//!   CSS `url()`/`@import` and LaTeX `\href`/`\include` extractors land in
//!   their own batches (kept out of this commit by design).
//! - HTML comments and `<script>` bodies are not masked either (documented
//!   scope: attribute scan is textual, like the C include scan).
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
        _ => Vec::new(),
    }
}

/// Markdown: inline links, images, autolinks and reference definitions.
fn extract_markdown_links(source: &str) -> Vec<ImportInfo> {
    // Mask inline code spans (byte-length preserving) so `` `[x](y.md)` ``
    // stays inert. Fenced/indented code blocks are NOT masked in this batch
    // (documented deferral — see module docs).
    let masked = mask_inline_code_spans(source);
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
/// Fenced/indented code BLOCKS are deliberately not handled here (next
/// batch — see module docs).
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
    // Language gating
    // =========================================================================

    #[test]
    fn non_document_languages_emit_nothing() {
        for lang in [
            Language::Css,
            Language::Latex,
            Language::Json,
            Language::Yaml,
            Language::Toml,
            Language::Log,
            Language::Bash,
            Language::Python,
        ] {
            let imports = extract_doc_links(lang, "[a](b.md) <x href=\"y.md\">");
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
