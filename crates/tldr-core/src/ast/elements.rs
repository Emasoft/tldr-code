//! Element extraction for data/config formats (element-extraction-v1, Phase E).
//!
//! Formats have no functions/classes/methods, so `extract_definitions` returns
//! EMPTY for them — a `tldr structure config.json` report was previously all
//! headings and no rows. This module walks the same tree-sitter tree and emits
//! **element-level definitions** through the existing `DefinitionInfo` channel
//! (`kind` is a free `String`, so no schema break): structure, the daemon, and
//! every other `extract_file_structure` consumer see them automatically.
//!
//! # Kind taxonomy (the authoritative table for this module)
//!
//! | Language | Kind        | What it is                                                            | Name                          | Region                                             |
//! |----------|-------------|-----------------------------------------------------------------------|-------------------------------|----------------------------------------------------|
//! | JSON     | `key`       | every object property (`pair`), at ANY nesting depth                   | the key, unquoted              | the `pair` node incl. its value; array items are NOT definitions, but a property whose value is an array/object still emits its key once |
//! | TOML     | `section`   | `[table.path]` / `[[table.path]]` headers                              | the dotted path, keys unquoted | the whole `table`/`table_array_element` block       |
//! | TOML     | `key`       | every key/value `pair` — top-level, inside a section, or in an inline table | the key (dotted keys joined with `.`), unquoted | the `pair` node |
//! | YAML     | `document`  | each `---`-delimited document of the stream                            | `document-N` (N = 1-indexed source-order position) | the `document` node incl. its `---` marker |
//! | YAML     | `key`       | mapping keys of each document — top-level and nested (the JSON/TOML recursion convention; full-fidelity since V-YAML 2026-09) | the key, unquoted              | the `block_mapping_pair`/`flow_pair` (key + whole value subtree) |
//! | Bash     | `function`  | `function_definition` (`name() {}` and `function name {}`)             | the function name              | the whole `function_definition` node |
//! | XML/SVG  | `element`   | every `element` node — paired (`STag … ETag`) and self-closing (`EmptyElemTag`) alike, at ANY depth | the tag name; `tag#id` when an `id` attribute exists, else `tag.<first-class>` when a `class` attribute does | the whole `element` node incl. children |
//! | XML/SVG  | `selector` / `at-rule` | the CSS body of a `<style>` element (style-inner-css-v1, below) — same rows a standalone stylesheet would emit | as CSS | the inner rule/at-rule node, re-based onto full-file coordinates |
//! | HTML     | `element`   | every `element` (paired or wrapping a `self_closing_tag`), `script_element`, and `style_element` | the tag name; `tag#id` when an `id` attribute exists | the whole element node incl. children |
//! | HTML     | `selector` / `at-rule` | the CSS body of a `style_element` (style-inner-css-v1, below) | as CSS | the inner rule/at-rule node, re-based onto full-file coordinates |
//! | HTML+SVG | JS kinds    | the JS body of an inline `<script>` (script-inner-js-v1, below) — the same rows a standalone `.js` file emits | as JS | the inner JS definition node, re-based onto full-file coordinates |
//! | CSS      | `selector`  | every `rule_set` — top level OR nested inside an at-rule block          | the full selector text, whitespace-collapsed (`h1,\n  .card` → `h1, .card`) | the whole `rule_set` |
//! | CSS      | `at-rule`   | every BLOCK-bearing at-rule (`at_rule`, `media_statement`, `supports_statement`, `keyframes_statement`) | the at-keyword (`@media`, `@keyframes`, `@font-face`, …) | the whole statement incl. its block |
//! | LaTeX    | `section`   | every sectioning command (`part`, `chapter`, `section`, `subsection`, `subsubsection`, `paragraph`, `subparagraph` — starred variants and KOMA `\addsec`/`\addchap`/`\addpart` fold into the same node kinds) | the heading text: the braced group after the command, whitespace-collapsed; when the heading embeds commands the raw braced text is kept; with no braced heading, the command token | the whole sectioning node — the grammar nests the section's content inside it, so it spans to the next sectioning command of equal-or-higher level (or `\end{document}`/EOF) |
//! | LaTeX    | `environment` | every `\begin{env} … \end{env}` block (`generic_environment` plus the grammar's specialized `math`/`verbatim`/`listing`/`minted`/`comment`/`luacode`/`pycode`/`sageblock`/`sagesilent`/`asy`/`asydef` environment kinds); nested environments recurse | the environment name from `\begin{env}` | the whole environment node (`begin` → `end` incl. content) |
//! | Markdown | `heading`   | every ATX heading (`#`…`######`) and setext heading (`text` + `===`/`---` underline) | the heading text (inline content collapsed; the `#`/underline markers are separate grammar children and never enter the name) | the heading node itself — setext = the heading lines + underline, ATX = the marker line; NOT content-spanning (see `walk_markdown`) |
//! | Markdown | `code-block` | every fenced code block (backtick/tilde fences); indented code blocks (4-space) emit too — the block grammar gives them their own node kind | the info string's first `language` token (a ```rust fence → `rust`); `"code-block"` when there is no language token (plain fences, indented blocks) | the whole code-block node incl. both fence lines |
//! | Markdown | `table`     | every pipe table | the header-row cell texts joined with `" \| "` (whitespace-collapsed; the delimiter row is never part of the name) | the whole `pipe_table` node |
//!
//! ## Style-inner CSS (style-inner-css-v1)
//!
//! The CSS grammar ALSO runs on the `<style>` bodies embedded in HTML and
//! SVG documents: the body of an HTML `style_element` (its `raw_text` child)
//! and of an XML/SVG `style` element (the `CharData` — or CDATA-wrapped
//! `CData` — children of its `content` node) is parsed with the CSS grammar
//! and emits the same `selector` / `at-rule` rows a standalone `.css` file
//! would, AFTER the owning element's `element` row. Spans are re-based onto
//! FULL-file coordinates (bytes += the body's file offset; lines += the
//! `\n` count before the body), so `full_source[byte_start..byte_end]` is
//! the exact selector/at-rule source text and the line numbers are the
//! file's. A whitespace-only body emits nothing; a failed inner parse keeps
//! just the element row.
//!
//! ## Script-inner JS (script-inner-js-v1)
//!
//! The JAVASCRIPT grammar ALSO runs on the bodies of INLINE `<script>`
//! elements embedded in HTML and SVG hosts: each such body is parsed with
//! `Language::JavaScript` (the non-TSX `LANGUAGE_TYPESCRIPT` dialect — the
//! same grammar `tldr structure` uses for `.js` files) and the unified
//! definition walk (`ast::extractor::extract_definition_entries`) emits its
//! `function`/`class`/`method`/`constant`/`field`/`call`/… rows exactly as a
//! standalone `.js` file would, AFTER the owning script element's `element`
//! row. The rows ride the host file's `definitions` array with a
//! **provenance marker**: `DefinitionInfo::container` =
//! `<hostfilename>#script-N` — the virtual document's name, where N is the
//! 1-based source-order index over the file's EXTRACTED scripts (an external
//! script and a non-JS type never become virtual documents and consume no
//! number; the numbering is per file across both the HTML and the SVG walk,
//! deterministic). Host-file definitions carry `container: None`, so a
//! virtual-script symbol is always distinguishable from same-named host
//! elements (collisions are allowed; body lookup is byte-span-first).
//!
//! Detection rules, per script element:
//! - **External → skipped.** An HTML `script_element` with a `src` attribute
//!   (or an XML `script` with `src`/`href`/`xlink:href` — SVG 1.1 loaded
//!   scripts by `xlink:href`, SVG 2 by `href`) references another file;
//!   `tldr imports` (doclinks) already indexes that reference and the body
//!   is not inline code. Such external scripts keep their empty
//!   `raw_text`/`content` body — nothing would emit anyway, but the skip is
//!   explicit so an empty inline script and an external one are the same
//!   "no virtual document" outcome.
//! - **Non-JS `type` → skipped.** The `type` attribute must be ABSENT or one
//!   of the JS mimes (`text/javascript`, `application/javascript`,
//!   `module`, `text/ecmascript`; matched case-insensitively after
//!   trimming). Anything else — `application/json` data blocks, `importmap`,
//!   `text/babel`/JSX, `text/plain`, templates — is not JavaScript and is
//!   not parsed (documented skip).
//! - **Whitespace-only body → nothing** (no wasted parse); **a body whose
//!   JS parse has error nodes → nothing** (a syntax-broken script emits no
//!   definitions; a partial error-recovered tree would fabricate rows).
//!   Neither can fail the host walk: one bad script costs only its own rows.
//!
//! Spans re-base onto FULL-file coordinates exactly like the style-inner CSS
//! path (bytes += the body's file offset; lines/`definition_line` += the
//! `\n` count before the body), so `full_source[byte_start..byte_end]` is
//! the symbol's exact source text in the host file and `tldr body
//! page.html sayHi` slices the script's bytes out of the HTML. One
//! documented asymmetry: the byte span is the JS definition NODE (the
//! declaration), while `line_start` keeps the code-language attached-trivia
//! semantics (a JSDoc comment above the function widens the LINE span but
//! not the byte span) — the same fields mean exactly what they mean for a
//! standalone `.js` file. Scripts are extracted only when a host label is
//! available (the `extract_elements` `host` argument, the host file's file
//! name): the OOXML part walker passes `None`, and
//! a nameless host cannot name a virtual document.
//!
//! # Virtual documents and outbound references (virtual-documents-v1)
//!
//! Embedded `<script>` and `<style>` bodies are not decoration: each
//! successfully processed body IS a document — a JS program or a stylesheet —
//! and both halves of that statement are now indexed.
//!
//! 1. **Definitions carry provenance.** script-inner-js-v1 named its rows
//!    `<hostfilename>#script-N` (above). virtual-documents-v1 closes the
//!    symmetry for CSS: every `<style>` body that actually emits (non-empty,
//!    CSS parse succeeds) is numbered per file with a `style_no` counter
//!    mirroring `script_no` — the SAME continuity rule, a whitespace-only or
//!    unparseable body consumes no number — and its `selector`/`at-rule` rows
//!    carry `DefinitionInfo::container` = `<hostfilename>#style-N`. Host
//!    element rows keep `container: None`, so a style row is always
//!    distinguishable from a same-named host element. A nameless host (OOXML
//!    parts) cannot name a virtual document: those style
//!    bodies keep emitting their rows exactly as style-inner-css-v1 shipped
//!    them — container-less, and they consume no number.
//!
//! 2. **Outbound references join the host graph.** An embedded document that
//!    references another file creates a real blast-radius edge from the HOST
//!    file. The same walks that emit definitions therefore also collect
//!    `ImportInfo` rows (see [`embedded_document_refs`]):
//!    - from each extracted SCRIPT body: the JS import surface
//!      (`import … from 'x'`, `require('x')`, `export … from 'x'` — the
//!      `ast::imports` JavaScript extractor run over the body's parsed tree)
//!      PLUS the doclinks path/URL scanner over the body text (fetch/xhr
//!      string arguments; see the caveat on [`script_outbound_refs`]);
//!    - from each successfully processed STYLE body: the doclinks CSS
//!      extractor (`@import`/`url()` — the loaded elements) over the body
//!      text.
//!
//! Every row is stamped with the new additive `ImportInfo::via` field = the
//! virtual document's name (`page.html#script-1`, `page.html#style-2`) — the
//! same naming as `container` — so a consumer can tell an embedded document's
//! reference from one written in the host markup (`via: None`). Hosts without
//! a name collect nothing (no virtual documents → nothing to attribute). Rows
//! are deduplicated per virtual document by the `(module, via)` pair: a
//! script that imports the same URL twice contributes ONE row (the first
//! source-ordered one survives, so an `import` row wins over a later
//! text-scan row of the same string), while the same URL referenced from two
//! different virtual documents produces two rows with different `via` values
//! — the provenance IS the edge identity.
//!
//! The rows surface everywhere the host file's imports do — `tldr imports`
//! and `tldr structure` (via `ast::extract` → `extract_imports_from_tree`),
//! `tldr importers`, and the document blast-radius graph
//! (`analysis::doc_impact` builds its reverse map from `get_imports`) —
//! so a target referenced only from an inline script or style is
//! discoverable end to end.
//!
//! 3. **foreignObject recursion (VD-2, `process_embedded_html`):** the HTML
//!    content nested inside an SVG `foreignObject` — in a standalone
//!    `.svg`/`.xml` host OR in an inline `<svg>` inside an HTML page — is a
//!    document too: it is re-parsed with the HTML grammar as a **virtual html
//!    document** named `<host>#fo-N`, it emits its own `element` rows
//!    (markup is markup — consistent with the model), and its inline
//!    scripts/styles recurse exactly like the host's, producing hierarchical
//!    names: `page.html#fo-1#script-1`, `page.html#fo-1#style-1`, and one
//!    level deeper `page.html#fo-2#script-1`. Every nested document's
//!    OUTBOUND references merge into the host imports with `via` = the full
//!    hierarchical container name.
//!
//!    # Termination (why circular html→svg→foreignObject→html cannot hang)
//!
//!    1. **Strict-substring invariant.** Every recursive re-parse operates on
//!       a content slice STRICTLY CONTAINED in the document it came from —
//!       the slice is the bytes between the `foreignObject` start/end tags,
//!       which are strictly inside the parent's content. Recursion only ever
//!       descends into strictly smaller byte ranges of the SAME file, so
//!       termination is guaranteed by the strictly-decreasing size alone.
//!       There is NO cross-file parsing at the extraction layer: external
//!       `src`/`data`/`href` attributes stay references (the host doclink
//!       scan indexes them; the scripts' `src`/`href` gates skip them), and
//!       the reference GRAPH handles cross-file reachability. That is what
//!       makes cycles impossible: `a.html` referencing `b.svg` never parses
//!       `b.svg`'s content here — only a same-file byte slice is re-parsed.
//!    2. **`MAX_EMBED_DEPTH` (8)** — belt-and-braces against pathological
//!       nesting (stack depth): a virtual document at nesting level > 8 is
//!       skipped with ONE warning on the host structure ("embedded document
//!       nesting exceeds depth 8; deeper levels skipped: <container>").
//!    3. **`MAX_VIRTUAL_DOCS_PER_FILE` (256)** — belt-and-braces against
//!       quadratic blowup: the TOTAL number of embedded documents (scripts +
//!       styles + foreignObject html documents, across ALL levels) per FILE;
//!       beyond the budget, further documents are skipped with ONE warning.
//!
//!    # Node shapes (verified against the wired grammars, probe dump)
//!
//!    - HTML walker: a `foreignObject` inside inline `<svg>` is a generic
//!      `element` (the html grammar has no dedicated kind; `tag_name` keeps
//!      the source spelling, so the match is case-insensitive — the browser
//!      parser adjusts foreign tag case). Its content is the byte range
//!      between `start_tag` and `end_tag`. `script_element`/`style_element`
//!      inside inline `<svg>` are the SAME dedicated kinds as anywhere else
//!      in HTML (`start_tag raw_text? end_tag`), so the host walk reaches
//!      them by normal recursion and numbers them at the HOST level; only
//!      `foreignObject` content is re-owned by a nested virtual document.
//!    - XML walker: a `foreignObject` `element` (case-sensitive match — the
//!      SVG spelling; XML is case-sensitive like the `style`/`script` checks)
//!      holds its content in a `content` child whose byte range spans the
//!      embedded markup — `element` children (the common shape:
//!      `<div>…</div>` IS an `element` there), `CharData` text, or a
//!      `CDSect` wrapper around a `CData` text chunk (the same shape family
//!      the style/script bodies use). A lone CDATA-wrapped body is
//!      UNWRAPPED (the `<![CDATA[` wrapper would only trip the html
//!      grammar's error recovery); any other content re-parses from the
//!      whole `content` range. A self-closing `<foreignObject/>`
//!      (`EmptyElemTag`) has no `content` child and yields nothing.
//!
//!    The host walk SKIPS the foreignObject subtree after handing it to the
//!    virtual document (its elements would otherwise emit twice — once
//!    container-less from the host walk and once from the document).
//!    Nameless hosts (OOXML parts) cannot name a virtual
//!    document, so for them the subtree is NOT skipped and nothing recurses
//!    — the pre-VD-2 behavior exactly. Files WITHOUT a foreignObject walk
//!    byte-identically to the pre-VD-2 engine.
//!
//!    Malformed nested content (the re-parse carries error nodes) emits
//!    NOTHING for that document, adds ONE warning naming it, never fails
//!    the host, and consumes no `#fo-N` number (the numbering-continuity
//!    pin: only successfully processed documents consume numbers — the same
//!    rule scripts/styles pin for `#script-N`/`#style-N`). Empty or
//!    whitespace-only content emits nothing and consumes nothing.
//!
//! # SVG (and other XML dialects)
//!
//! SVG is ordinary XML to this module: `.svg` maps to `Language::Xml`, so
//! `g`, `path`, `defs`, `style`, `linearGradient`, … all surface as nested
//! `element` definitions in source order — that IS the requested
//! groups/paths/elements/definitions/styles coverage — and each carries a
//! `#id` name wherever an `id` attribute exists. TWO special cases run
//! inner-grammar walkers: `<style>` (style-inner-css-v1, above — its CSS
//! body emits as `selector`/`at-rule` rows) and `<script>`
//! (script-inner-js-v1, above — its JS body emits as JS definition rows in a
//! `<file>#script-N` virtual document).
//!
//! Non-elements never emit: XML prolog/doctypedecl/PIs/comments and HTML
//! doctype/comments are skipped by kind, CSS `;`-terminated statements
//! (`import_statement`, `charset_statement`, `namespace_statement`,
//! `postcss_statement`) have no block and are not regions, CSS
//! declarations are not definitions, and LaTeX preamble commands
//! (`\usepackage`, `\title`, `\label`, `\newcommand`, …), the
//! environment-DEFINING commands (`environment_definition` = `\newenvironment`,
//! `theorem_definition` = `\newtheorem`) and the brace/dollar math zones
//! (`displayed_equation`, `inline_formula` — no begin/end pair) never emit.
//!
//! Markdown non-elements (markdown batch, 2026-09): paragraphs, lists and
//! list items (incl. task-list markers), block quotes, thematic breaks
//! (`---`/`***`), HTML blocks, link reference definitions, YAML front matter
//! (`minus_metadata`/`plus_metadata`) and the grammar's bookkeeping nodes
//! (`section`, `block_continuation`, markers) never emit — they are
//! candidates for a future batch, not definitions today. Markdown also
//! parses through the tree-sitter-md BLOCK grammar ONLY: the crate ships the
//! block and inline grammars as two separate LanguageFns with no combined
//! language, so inline content stays as opaque `inline` node text (emphasis,
//! code spans and links are not individually parsed; heading names are their
//! raw inline text, whitespace-collapsed).
//!
//! # Spans
//!
//! - `byte_start`/`byte_end`: the node's `byte_range()` exactly; `byte_end` is
//!   EXCLUSIVE, so `source[byte_start..byte_end]` is the element text and
//!   starts with its first token. These are `None` for non-format code
//!   languages (the format engine, XML/HTML/CSS included, always populates
//!   them) — with ONE exception: script-inner JS definitions
//!   (script-inner-js-v1) populate them, re-based onto full-file coordinates,
//!   so body-by-name slices the host file.
//! - `line_start`: first line (1-indexed) containing node bytes.
//! - `line_end`: last line (1-indexed) containing node bytes — the trailing
//!   `end_position().row + 1` convention would spill onto a phantom line when
//!   a node's last byte is a newline (e.g. a YAML document or TOML table that
//!   runs to EOF), so that one newline is attributed to the element's last
//!   real line instead.
//! - `definition_line`: `None` — formats carry no trivia/declaration split.
//! - `signature`: a one-line summary (the element's first source line), so
//!   text-mode and JSON consumers see what the region opens with.
//!
//! # Depth (markup-node-tree-v1)
//!
//! Markup element rows carry `DefinitionInfo::depth = Some(n)` — the element's
//! nesting level within its document, root-level elements at 0, children at 1,
//! … — so consumers can navigate 100 MB XML documents level by level instead
//! of reading one flat 2.4M-row list:
//!
//! | Format | Depth semantics |
//! |--------|-----------------|
//! | XML/SVG/HTML/XHTML (`walk_xml`/`walk_html`) | tree-sitter tree nesting: the document's root element(s) are 0, each nested element +1; `element`, `script_element` and `style_element` rows all carry it |
//! | OOXML (`.docx`/`.xlsx`/`.pptx`) | PER-PART depth: each zip part is walked as its own XML document, so every part's root elements are 0 again; `signature` already carries the part path that scopes the depth |
//! | Embedded virtual documents (`<host>#fo-N`, script/style documents' element rows) | depth restarts at 0 WITHIN the virtual document and the `container` field identifies the document the depth belongs to |
//! | Inner CSS (`selector`/`at-rule`) and inner JS rows | `None` — they are not markup nodes |
//! | JSON/YAML/TOML `key`, TOML `section`, YAML `document`, bash `function`, LaTeX, Markdown, log/text/csv/sql/env/ignore rows, code-language definitions | `None` — not markup node trees (SQL tables could carry depth 0; deliberately left `None`, the schema outline is flat) |
//!
//! `structure --max-depth N` keeps every definition whose depth is `None`
//! (the filter narrows markup elements only) or whose depth is `<= N`.
//!
//! # Depth cap (stack safety)
//!
//! Tree-sitter imposes NO tree-depth limit, and every walker here is a
//! recursive pre-order descent over its tree — a pathological
//! tens-of-thousands-deep nested file (machine-generated JSON/XML/YAML do
//! exist) used to overflow the 2 MiB rayon worker stack (8 MiB main thread)
//! and SIGSEGV-abort the process. Every walker therefore refuses to descend
//! past [`MAX_ELEMENT_DEPTH`] (2,000 levels): deeper nodes AND their subtrees
//! are skipped with ONE warning per file ("markup nesting exceeds depth
//! …; deeper elements skipped"), latched through [`EmbedBudget`] so a host
//! plus its embedded documents never repeat it. Parents always emit before
//! children (pre-order), so what survives the cap is a consistent tree
//! prefix.
//!
//! # Determinism
//!
//! Every walker is a pre-order depth-first traversal emitting in source order.
//! No HashMap/HashSet iteration participates in output ordering.

use tree_sitter::{Node, Tree};

use crate::ast::extract_doc_links;
use crate::ast::imports::extract_imports_from_tree;
use crate::types::{DefinitionInfo, ImportInfo, Language};

/// VD-2: the deepest virtual-document nesting level that still processes.
/// Level 1 is the first `foreignObject` document (the host file itself is
/// level 0); a document at level > 8 is skipped with one warning. Belt and
/// braces ONLY — the strict-substring invariant already guarantees
/// termination (see the module docs); this cap bounds the recursion STACK
/// against pathological 50-deep nesting.
pub(crate) const MAX_EMBED_DEPTH: usize = 8;

/// VD-2: the total number of embedded virtual documents (inline scripts +
/// inline styles + foreignObject html documents, across ALL levels) one file
/// may produce. Beyond the budget, further documents are skipped with one
/// warning. Belt and braces ONLY — guards against quadratic blowup on a
/// pathologically script-stuffed file.
pub(crate) const MAX_VIRTUAL_DOCS_PER_FILE: usize = 256;

/// FIX-1a (walker depth cap): the deepest nesting level any format walker
/// still descends into. At deeper nodes the walk stops (the node AND its
/// subtree are skipped) after ONE per-tree warning.
///
/// Why it exists: tree-sitter 0.25 imposes NO tree-depth limit, and every
/// walker below is a recursive pre-order descent over that tree. Rayon
/// workers run 2 MiB stacks (the main thread 8 MiB), so a pathological
/// tens-of-thousands-deep nested file — machine-generated JSON/XML/YAML do
/// exist — used to overflow the stack and SIGSEGV-abort the process,
/// uncatchable and worse under the parallel extraction fan-out. The cap
/// turns the abort into a warned, bounded truncation.
///
/// What the depth counts: for the markup walkers ([`walk_xml`],
/// [`walk_html`], [`walk_embedded_html`]) it is the EXISTING element depth
/// (root elements = 0, transparent grammar wrappers skipped); for the
/// format walkers ([`walk_json`], [`walk_toml`], [`walk_yaml`]) it is raw
/// TREE nesting (every node visit +1) — either way it is exactly the
/// recursion the cap bounds. 2,000 levels is orders of magnitude beyond
/// real files (the deepest hand-written markup nests a few dozen levels)
/// while keeping the recursion cost comfortably inside a 2 MiB worker
/// stack.
///
/// Scope: per TREE (one [`extract_elements_inner`] dispatch — a file, an
/// OOXML part, a virtual document), with the warning LATCHED per FILE via
/// [`EmbedBudget::depth_cap_warned`], so a host plus its embedded documents
/// produce at most ONE depth warning. Parents always emit before their
/// children (pre-order), so the emitted prefix is a consistent tree prefix.
pub(crate) const MAX_ELEMENT_DEPTH: u32 = 2_000;

/// Extract format elements as `DefinitionInfo` entries.
///
/// `host` is the host file's FILE NAME (e.g. `"page.html"`), used ONLY to
/// name the virtual documents of embedded inline scripts and styles
/// (script-inner-js-v1 / virtual-documents-v1): `Some(name)` enables
/// script-inner JS extraction (`<file>#script-N` provenance) and style
/// container provenance (`<file>#style-N`), `None` disables both — callers
/// without a host file name (OOXML zip parts, unit probes)
/// keep the pre-virtual-document behavior byte-for-byte.
///
/// Returns an EMPTY vec for every non-format (code) language — the caller
/// (`extractor::extract_file_structure`) appends the result to its
/// `definitions` unconditionally.
pub fn extract_elements(
    language: Language,
    tree: &Tree,
    source: &str,
    host: Option<&str>,
) -> Vec<DefinitionInfo> {
    extract_elements_inner(language, tree, source, host).0
}

/// virtual-documents-v1 + VD-2: [`extract_elements`] plus the WARNING
/// channel — the per-file warnings the embedded-document recursion produced
/// (foreignObject nesting beyond `MAX_EMBED_DEPTH`, the
/// `MAX_VIRTUAL_DOCS_PER_FILE` budget, malformed nested content). The
/// structure path (`extractor::extract_file_structure`) merges them into the
/// file's warning channel so `CodeStructure.warnings` reports them; the
/// plain [`extract_elements`] (OOXML parts, unit probes)
/// keeps its signature and drops them.
pub(crate) fn extract_elements_with_warnings(
    language: Language,
    tree: &Tree,
    source: &str,
    host: Option<&str>,
) -> (Vec<DefinitionInfo>, Vec<String>) {
    let (defs, _, warnings) = extract_elements_inner(language, tree, source, host);
    (defs, warnings)
}

/// virtual-documents-v1: the OUTBOUND reference rows of an HTML/XML host's
/// embedded virtual documents (inline `<script>` JS bodies and `<style>` CSS
/// bodies), as `ImportInfo` entries stamped with
/// `via = <hostfilename>#script-N|#style-N`.
///
/// This is the imports half of the virtual-document walk — the definitions
/// half is [`extract_elements`]. The two run the SAME deterministic pre-order
/// walk (same body discovery, same numbering counters), so a row's `via`
/// name always matches the `container` of the definitions emitted for the
/// same body: `tldr structure page.html` and `tldr imports page.html` agree
/// on `#script-1`/`#style-1` naming.
///
/// `host` is the host file's FILE NAME, the same argument
/// [`extract_elements`] takes. `None` (OOXML parts) yields
/// an EMPTY vec — a nameless host has no named virtual documents and
/// therefore no attributable edges. Every other language returns empty too:
/// only Html/Xml hosts embed script/style documents.
///
/// Consumers: `get_imports` (→ `tldr imports`, `tldr importers`, the
/// `analysis::doc_impact` reverse-link graph) and `extract_from_tree` (→ the
/// `FileStructure.imports` array) — see `ast::imports`, the Html/Xml arm.
pub(crate) fn embedded_document_refs(
    language: Language,
    tree: &Tree,
    source: &str,
    host: Option<&str>,
) -> Vec<ImportInfo> {
    extract_elements_inner(language, tree, source, host).1
}

/// Both halves of the virtual-document walk (definitions + outbound refs +
/// warnings), in one pre-order pass so numbering stays consistent between
/// them. `embedded_document_refs` (the imports half) runs the same walk and
/// drops the warnings — `ImportInfo` has no channel for them, and the
/// definitions half surfaces them deterministically on the structure path.
fn extract_elements_inner(
    language: Language,
    tree: &Tree,
    source: &str,
    host: Option<&str>,
) -> (Vec<DefinitionInfo>, Vec<ImportInfo>, Vec<String>) {
    let mut elements = Vec::new();
    let mut state = WalkState::new(host);
    let root = tree.root_node();

    match language {
        // FIX-1a: every walker takes the shared `state` (warnings + the
        // per-file depth-cap latch) and a depth counter — the recursion
        // guard of `MAX_ELEMENT_DEPTH`.
        Language::Json => walk_json(root, source, &mut state, &mut elements, 0),
        Language::Toml => walk_toml(root, source, &mut state, &mut elements, 0),
        Language::Yaml => walk_yaml(root, source, &mut state, &mut elements, 0),
        Language::Bash => walk_bash(root, source, &mut elements),
        // Formats extension, batch E2: markup/stylesheets flow through the
        // same element engine (kinds `element` / `selector` / `at-rule`).
        // script-inner-js-v1: the script counter is per FILE — the 1-based
        // `#script-N` numbering spans the whole host document in source order.
        // virtual-documents-v1 adds the parallel `#style-N` counter and the
        // outbound-reference collection for both.
        // markup-node-tree-v1: the markup walks start their depth counter at
        // 0 (root-level elements); one counter per document — the OOXML
        // per-part walks each dispatch here fresh, so a part's depth is
        // part-relative, and the embedded-document recursion restarts its
        // own counter per virtual document.
        Language::Xml => walk_xml(root, source, &mut state, &mut elements, 0),
        Language::Html => walk_html(root, source, &mut state, &mut elements, 0),
        Language::Css => walk_css(root, source, &mut elements),
        // LaTeX batch (2025-11): document markup joins the same engine
        // (kinds `section` / `environment`).
        Language::Latex => walk_latex(root, source, &mut elements),
        // Markdown batch (2026-09): document markup joins the same engine
        // (kinds `heading` / `code-block` / `table`) via the tree-sitter-md
        // BLOCK grammar.
        Language::Markdown => walk_markdown(root, source, &mut elements),
        // Code languages never had elements.
        _ => {}
    }

    (elements, state.refs, state.warnings)
}

/// Walker state threaded through the HTML/XML pre-order walks (private).
struct WalkState<'h> {
    /// 1-based source-order counter over the file's EXTRACTED scripts
    /// (numbering-continuity pin: consumed only by bodies that actually
    /// become virtual documents).
    script_no: u32,
    /// The SAME counter for `<style>` bodies (virtual-documents-v1) —
    /// identical continuity rule.
    style_no: u32,
    /// Outbound reference rows collected from embedded virtual documents
    /// (virtual-documents-v1). Empty unless the host is named.
    refs: Vec<ImportInfo>,
    /// VD-2 warnings of the embedded-document recursion (nesting depth,
    /// document budget, malformed nested content) — surfaced through
    /// `extract_elements_with_warnings` onto `CodeStructure.warnings`.
    warnings: Vec<String>,
    /// VD-2 per-file recursion controls (host label, foreignObject counter,
    /// document budget). The host label lives HERE (not as a separate field):
    /// `process_embedded_html`'s only mutable-state vehicle is the budget, so
    /// the naming root must ride with it wherever the recursion goes.
    budget: EmbedBudget<'h>,
}

impl<'h> WalkState<'h> {
    fn new(host: Option<&'h str>) -> Self {
        Self {
            script_no: 0,
            style_no: 0,
            refs: Vec::new(),
            warnings: Vec::new(),
            budget: EmbedBudget::new(host),
        }
    }

    /// The host file's FILE NAME — enables virtual-document extraction
    /// (script-inner-js-v1, style containers, outbound refs, VD-2
    /// foreignObject recursion). `None` for nameless hosts (OOXML parts):
    /// no virtual documents at any level.
    fn host(&self) -> Option<&'h str> {
        self.budget.host
    }
}

/// VD-2 per-file mutable controls for the embedded-document recursion — the
/// `budget` parameter of [`process_embedded_html`]. One instance per file,
/// threaded mutably through every level so the whole file shares one budget,
/// one foreignObject counter, and one warning latch of each kind.
struct EmbedBudget<'h> {
    /// The host file's FILE NAME (the naming root for `<host>#fo-N` names
    /// and the budget warning). `None` = nameless host: the whole
    /// virtual-document machinery stays inert.
    host: Option<&'h str>,
    /// 1-based per-FILE foreignObject counter — consumed only by
    /// successfully processed documents (continuity pin; a malformed or
    /// depth-refused document gives its number back).
    fo_no: u32,
    /// Virtual documents consumed so far — scripts + styles + foreignObject
    /// html documents, ALL levels.
    docs: u32,
    /// The cap on `docs` — `MAX_VIRTUAL_DOCS_PER_FILE` in production,
    /// injected smaller by the budget unit test.
    limit: usize,
    /// Latch: the budget-exhausted warning is emitted once per file.
    budget_warned: bool,
    /// Latch: the depth-cap warning is emitted once per file.
    depth_warned: bool,
    /// FIX-1a: latch for the element-tree depth cap ([`MAX_ELEMENT_DEPTH`])
    /// — shared by the HOST walk and every embedded-document walk of the
    /// file, so one file yields at most ONE depth warning.
    depth_cap_warned: bool,
}

impl<'h> EmbedBudget<'h> {
    fn new(host: Option<&'h str>) -> Self {
        Self {
            host,
            fo_no: 0,
            docs: 0,
            limit: MAX_VIRTUAL_DOCS_PER_FILE,
            budget_warned: false,
            depth_warned: false,
            depth_cap_warned: false,
        }
    }
}

/// FIX-1a: fire the ONE per-file element-depth-cap warning (the
/// embed-budget latch pattern). Called at the node a walker refuses to
/// descend past — [`MAX_ELEMENT_DEPTH`] has the full semantics.
fn warn_element_depth_cap(budget: &mut EmbedBudget, warnings: &mut Vec<String>) {
    if !budget.depth_cap_warned {
        budget.depth_cap_warned = true;
        warnings.push(format!(
            "markup nesting exceeds depth {MAX_ELEMENT_DEPTH}; deeper elements skipped"
        ));
    }
}

/// Consume one virtual-document slot from the file's budget. `false` = the
/// budget is exhausted: the caller skips its document (consuming NO number —
/// a skipped document never becomes a virtual document) after the ONE
/// per-file warning has been emitted.
fn take_doc_slot(budget: &mut EmbedBudget, warnings: &mut Vec<String>) -> bool {
    if budget.docs >= budget.limit as u32 {
        if !budget.budget_warned {
            budget.budget_warned = true;
            let host = budget.host.unwrap_or("<unnamed>");
            warnings.push(format!(
                "Skipped embedded documents of {host}: the virtual-document budget \
                 ({} documents) is exhausted; further embedded scripts, styles and \
                 foreignObject documents are not indexed",
                budget.limit
            ));
        }
        return false;
    }
    budget.docs += 1;
    true
}

/// Number of `\n` bytes in `source` before `offset` — the line base an
/// inner-tree row must add to become a FULL-file line (the inner tree's row 0
/// is the physical row `offset` starts on). Shared by the script/style inner
/// extraction and the VD-2 recursion rebasing.
fn line_base_before(source: &str, offset: usize) -> u32 {
    source.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
}

/// Re-base an inner-tree definition onto FULL-file coordinates and push it
/// (bytes += the inner source's offset in the file, lines += the newlines
/// before it). The slice-back invariant: `full_source[bs..be]` stays the
/// exact source text of the definition.
fn push_rebased(
    mut def: DefinitionInfo,
    byte_base: usize,
    line_base: u32,
    out: &mut Vec<DefinitionInfo>,
) {
    if let Some(start) = def.byte_start.as_mut() {
        *start += byte_base as u64;
    }
    if let Some(end) = def.byte_end.as_mut() {
        *end += byte_base as u64;
    }
    def.line_start += line_base;
    def.line_end += line_base;
    if let Some(line) = def.definition_line.as_mut() {
        *line += line_base;
    }
    out.push(def);
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Build an element definition from a node: line span from the node's rows
/// (trailing-newline trimmed, see the module doc), byte span from the node's
/// byte range, signature = the element's first source line.
///
/// markup-node-tree-v1: `depth` is the element's nesting level within its
/// document (root-level elements = 0, children = 1, …). The markup walkers
/// (`walk_xml`/`walk_html`, including the embedded-document recursion and the
/// OOXML per-part walks) pass `Some(depth)`; every other producer of this
/// helper (JSON/TOML/YAML keys, sections, documents, CSS rows, …) passes
/// `None` — they are not markup node trees.
fn element_def(
    kind: &str,
    name: String,
    node: Node,
    source: &str,
    depth: Option<u32>,
) -> DefinitionInfo {
    let bytes = source.as_bytes();
    let line_start = node.start_position().row as u32 + 1;
    // A node whose last byte is a newline would put `end_position().row + 1`
    // on the phantom line after it (worse: a YAML document or TOML table at
    // EOF lands one line past the file). That newline belongs to the element's
    // last real line, so stop there.
    let line_end =
        if node.end_byte() > node.start_byte() && bytes.get(node.end_byte() - 1) == Some(&b'\n') {
            node.end_position().row as u32
        } else {
            node.end_position().row as u32 + 1
        };

    let signature = source[node.byte_range()]
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    DefinitionInfo {
        name,
        kind: kind.to_string(),
        line_start,
        line_end,
        definition_line: None,
        byte_start: Some(node.start_byte() as u64),
        byte_end: Some(node.end_byte() as u64),
        signature,
        // Host-file elements carry no virtual-document provenance — only
        // script-inner JS rows do (script-inner-js-v1).
        container: None,
        depth,
    }
}

/// Strip one pair of surrounding single/double quotes (JSON/YAML/TOML keys).
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        text[1..text.len() - 1].to_string()
    } else {
        text.to_string()
    }
}

// =============================================================================
// JSON — kind "key" per object property (nested keys recurse)
// =============================================================================

/// FIX-1a: `depth` is the raw TREE nesting level (every node visit +1) —
/// the recursion this walk performs; past [`MAX_ELEMENT_DEPTH`] the node
/// and its subtree are skipped with the one per-file depth warning.
fn walk_json(
    node: Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
    depth: u32,
) {
    if depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(&mut state.budget, &mut state.warnings);
        return;
    }

    if node.kind() == "pair" {
        // `pair` fields: key (string), value (_value). A pair IS the region
        // (key + value, whatever the value is — object, array, scalar), so a
        // property with an array/object value emits its key exactly once.
        if let Some(key) = node.child_by_field_name("key") {
            out.push(element_def(
                "key",
                json_key_name(&key, source),
                node,
                source,
                None,
            ));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_json(child, source, state, out, depth + 1);
    }
}

/// JSON key text: the grammar nests the raw key inside `string` →
/// `string_content`; prefer the content child, fall back to unquoting.
fn json_key_name(key: &Node, source: &str) -> String {
    let mut cursor = key.walk();
    for child in key.children(&mut cursor) {
        if child.kind() == "string_content" {
            return source[child.byte_range()].to_string();
        }
    }
    unquote(&source[key.byte_range()])
}

// =============================================================================
// TOML — kind "section" per table header + kind "key" per pair
// =============================================================================

/// FIX-1a: `depth` is the raw TREE nesting level (every node visit +1) —
/// the recursion this walk performs; past [`MAX_ELEMENT_DEPTH`] the node
/// and its subtree are skipped with the one per-file depth warning.
fn walk_toml(
    node: Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
    depth: u32,
) {
    if depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(&mut state.budget, &mut state.warnings);
        return;
    }

    match node.kind() {
        "table" | "table_array_element" => {
            // Header = the key-part children before the first `pair`.
            let path = toml_header_path(&node, source);
            if !path.is_empty() {
                out.push(element_def("section", path, node, source, None));
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, state, out, depth + 1);
            }
        }
        "pair" => {
            if let Some(name) = toml_pair_name(&node, source) {
                out.push(element_def("key", name, node, source, None));
            }
            // Recurse so inline-table pairs (`x = { a = 1 }`) surface too.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, state, out, depth + 1);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_toml(child, source, state, out, depth + 1);
            }
        }
    }
}

/// Dotted path of a `[header]`: the key-part named children before the first
/// `pair` (bare_key / quoted_key / dotted_key), joined with `.`.
fn toml_header_path(table: &Node, source: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = table.walk();
    for child in table.children(&mut cursor) {
        if child.kind() == "pair" {
            break;
        }
        match child.kind() {
            "bare_key" | "quoted_key" => parts.push(unquote(&source[child.byte_range()])),
            "dotted_key" => parts.extend(toml_key_parts(&child, source)),
            _ => {}
        }
    }
    parts.join(".")
}

/// Key text of a `pair`'s leading key part (bare / quoted / dotted).
fn toml_pair_name(pair: &Node, source: &str) -> Option<String> {
    let mut cursor = pair.walk();
    for child in pair.children(&mut cursor) {
        match child.kind() {
            "bare_key" | "quoted_key" => {
                return Some(unquote(&source[child.byte_range()]));
            }
            "dotted_key" => {
                return Some(toml_key_parts(&child, source).join("."));
            }
            _ => {}
        }
    }
    None
}

/// Flatten a `dotted_key` (which may nest dotted_keys) into its parts in
/// source order, unquoting each.
fn toml_key_parts(dotted: &Node, source: &str) -> Vec<String> {
    let mut parts = Vec::new();
    collect_key_parts(*dotted, source, &mut parts);
    parts
}

fn collect_key_parts(node: Node, source: &str, parts: &mut Vec<String>) {
    match node.kind() {
        "bare_key" | "quoted_key" => parts.push(unquote(&source[node.byte_range()])),
        "dotted_key" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_key_parts(child, source, parts);
            }
        }
        _ => {}
    }
}

// =============================================================================
// YAML — kind "document" per --- document + kind "key" per mapping pair
// (nested keys recurse, the JSON/TOML walker convention; full-fidelity since
// V-YAML 2026-09 — one whole-file parse through the vendored int32-row
// patched grammar, so keys at every depth are grammar nodes we can name)
// =============================================================================

/// FIX-1a: `depth` is the raw TREE nesting level (every node visit +1) —
/// the recursion this walk performs; past [`MAX_ELEMENT_DEPTH`] the node
/// and its subtree are skipped with the one per-file depth warning.
fn walk_yaml(
    node: Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
    depth: u32,
) {
    if depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(&mut state.budget, &mut state.warnings);
        return;
    }

    // The root is a `stream` of `document` nodes (multi-doc files repeat the
    // node; the `---` marker is INSIDE its document's span).
    //
    // FIX-1a (F11, document numbering): the `document-N` counter runs over
    // `document` children ONLY. Numbering via `enumerate()` over ALL stream
    // children let an error-recovery child (an `ERROR` node the grammar
    // inserts for malformed bytes between documents) shift every later
    // document's number — `document-3` could be the second real document.
    // Real documents are numbered 1..k in source order now, regardless of
    // whatever recovery nodes sit between them.
    if node.kind() == "stream" {
        let mut doc_no: usize = 0;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "document" {
                doc_no += 1;
                out.push(element_def(
                    "document",
                    format!("document-{doc_no}"),
                    child,
                    source,
                    None,
                ));
                walk_yaml(child, source, state, out, depth + 1);
            }
        }
        return;
    }

    // Every mapping pair — block or flow, at any depth — IS its region (key
    // plus the whole value subtree), the same rule as JSON's `pair`. Walking
    // ALL nodes covers every nesting shape: mappings under mappings, mappings
    // inside sequences (`- a: 1`), flow mappings inside block contexts.
    if node.kind() == "block_mapping_pair" || node.kind() == "flow_pair" {
        if let Some(name) = yaml_pair_name(&node, source) {
            out.push(element_def("key", name, node, source, None));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_yaml(child, source, state, out, depth + 1);
    }
}

/// YAML key text: `key` field → flow/block node → scalar child; unquote
/// single/double-quoted scalars, keep plain scalars verbatim.
fn yaml_pair_name(pair: &Node, source: &str) -> Option<String> {
    let key = pair.child_by_field_name("key")?;
    let mut cursor = key.walk();
    for child in key.children(&mut cursor) {
        if child.kind() == "plain_scalar"
            || child.kind() == "single_quote_scalar"
            || child.kind() == "double_quote_scalar"
        {
            return Some(unquote(&source[child.byte_range()]));
        }
        // flow_node/block_node wrappers: descend one level.
        let mut inner = child.walk();
        for scalar in child.children(&mut inner) {
            if scalar.kind() == "plain_scalar"
                || scalar.kind() == "single_quote_scalar"
                || scalar.kind() == "double_quote_scalar"
            {
                return Some(unquote(&source[scalar.byte_range()]));
            }
        }
    }
    None
}

// =============================================================================
// Bash — kind "function" per function_definition
// =============================================================================

fn walk_bash(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    if node.kind() == "function_definition" {
        // Both `build() { … }` and `function build { … }` put the name in the
        // `name` field (a `word` node) — bash is format-tier but has real,
        // region-bearing functions, so it flows through the element engine.
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = source[name_node.byte_range()].to_string();
            out.push(element_def("function", name, node, source, None));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_bash(child, source, out);
    }
}

// =============================================================================
// XML + SVG — kind "element" per element node (nested elements recurse)
// =============================================================================

/// XML (`tree_sitter_xml::LANGUAGE_XML`; serves .svg/.xsd/.xsl too): every
/// element-bearing syntax lives inside an `element` node — the grammar's
/// `element` rule is `STag content? ETag` or `EmptyElemTag` (self-closing), so
/// ONE node kind covers paired and self-closing elements alike (verified
/// against `tree-sitter-xml-0.7.0/xml/src/node-types.json`). Prolog, XML
/// declaration, doctypedecl, PIs and comments are not `element` nodes and
/// never emit; nested elements recurse in source order.
///
/// style-inner-css-v1 (SVG): an `element` whose tag name is exactly `style`
/// (XML is case-sensitive; SVG's lowercase spelling is the one recognized)
/// carries its CSS body inside its `content` child — verified empirically
/// against the wired grammar (probe dump): a plain body surfaces as a named
/// `CharData` child of `content` (the whole body INCLUDING the leading and
/// trailing newlines is one chunk), and a CDATA-wrapped body as
/// `content` → `CDSect` → `CData` (the `CData` text node is one level below
/// `content`, inside the `CDSect` wrapper — the `CDStart`/`]]>` tokens are
/// anonymous siblings). Every such chunk is parsed with the CSS grammar and
/// emits its selectors/at-rules with spans re-based onto FULL-file
/// coordinates (see [`emit_style_inner_css`]) — `<defs><style>` nesting needs
/// no special casing because the recursion reaches the style element at any
/// depth.
///
/// script-inner-js-v1 (SVG): the SAME body shapes (`content` → `CharData`,
/// or `content` → `CDSect` → `CData` — one grammar, one shape family) on an
/// `element` whose tag name is exactly `script` are parsed with the
/// JAVASCRIPT grammar and emit JS definition rows in a
/// `<hostfilename>#script-N` virtual document (see
/// [`emit_script_inner_js`]). External scripts (`src`/`href`/`xlink:href`
/// attribute — SVG 1.1 loaded by `xlink:href`, SVG 2 by `href`) and non-JS
/// `type` values are skipped; a self-closing `<script …/>` (`EmptyElemTag`)
/// has no content and emits nothing on its own.
///
/// markup-node-tree-v1: `depth` is the element's nesting level in the CURRENT
/// document — the number of ANCESTOR elements (root-level elements = 0). The
/// top-level caller (and each OOXML part walk) starts at 0; recursion passes
/// `depth + 1` when descending FROM an element and `depth` through every
/// grammar wrapper (`document`, XML `content`, text nodes), so grammar
/// bookkeeping nodes never inflate the markup level. Every `element` row
/// carries `Some(depth)`; inner-CSS/inner-JS rows are not markup elements and
/// keep `None`.
fn walk_xml(
    node: Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
    depth: u32,
) {
    // FIX-1a: depth cap — tree-sitter imposes no tree-depth limit and this
    // recursive walk runs on a 2 MiB rayon worker stack, so a pathological
    // tens-of-thousands-deep document used to SIGSEGV. Past the cap the node
    // AND its subtree are skipped (the element was not emitted yet — the
    // emitted prefix stays a consistent parent-before-children tree) with
    // ONE per-file warning.
    if depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(&mut state.budget, &mut state.warnings);
        return;
    }

    // VD-2: true after a foreignObject handed its content to a nested virtual
    // document — the subtree is the document's, not the host walk's.
    let mut skip_children = false;
    if node.kind() == "element" {
        if let Some(name) = xml_element_name(&node, source) {
            out.push(element_def("element", name, node, source, Some(depth)));
        }
        let tag = xml_tag_name(&node, source);
        if tag.as_deref() == Some("style") {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() != "content" {
                    continue;
                }
                let mut inner = child.walk();
                for text in child.children(&mut inner) {
                    match text.kind() {
                        // Plain body: one CharData chunk holding the whole CSS
                        // text (leading/trailing newlines included).
                        "CharData" => emit_style_inner_css(&text, source, state, out),
                        // CDATA body: descend the CDSect wrapper for the
                        // CData text node (verified shape above).
                        "CDSect" => {
                            let mut sect = text.walk();
                            for part in text.children(&mut sect) {
                                if part.kind() == "CData" {
                                    emit_style_inner_css(&part, source, state, out);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // script-inner-js-v1: same body shapes, JS grammar, virtual document.
        if tag.as_deref() == Some("script") && state.host().is_some() {
            let (external, script_type) = xml_script_attrs(&node, source);
            if !external && is_js_script_type(script_type.as_deref()) {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() != "content" {
                        continue;
                    }
                    let mut inner = child.walk();
                    for text in child.children(&mut inner) {
                        match text.kind() {
                            "CharData" => emit_script_inner_js(&text, source, state, out),
                            "CDSect" => {
                                let mut sect = text.walk();
                                for part in text.children(&mut sect) {
                                    if part.kind() == "CData" {
                                        emit_script_inner_js(&part, source, state, out);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        // VD-2: a `foreignObject` (case-sensitive — the SVG spelling, like
        // the `style`/`script` checks) carries HTML content: re-parsed with
        // the HTML grammar as the virtual document `<host>#fo-N`, its
        // scripts/styles/nested foreignObjects recursing depth-bounded. The
        // subtree is then SKIPPED — the document owns its elements (they
        // would otherwise emit twice). A self-closing `<foreignObject/>` has
        // no `content` child and no children at all, so it never reaches the
        // processing arm below.
        if tag.as_deref() == Some("foreignObject") && state.host().is_some() {
            if let Some((start, end)) = xml_foreign_object_slice(&node, source) {
                let host = state.host().unwrap_or_default();
                let WalkState {
                    refs,
                    warnings,
                    budget,
                    ..
                } = state;
                process_foreign_object_content(
                    &source[start..end],
                    start,
                    line_base_before(source, start),
                    0,
                    host,
                    budget,
                    warnings,
                    out,
                    refs,
                );
                skip_children = true;
            }
        }
    }

    if !skip_children {
        // Descending FROM an element adds one markup level; grammar wrappers
        // (`content` et al.) are transparent to the element tree.
        let child_depth = if node.kind() == "element" {
            depth + 1
        } else {
            depth
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_xml(child, source, state, out, child_depth);
        }
    }
}

/// The HTML slice of an XML `foreignObject` element: the byte range of its
/// `content` child — the `CData` text when the body is a lone CDATA-wrapped
/// chunk (the `<![CDATA[` wrapper would only trip the html grammar's error
/// recovery; verified shape: `content` → `CDSect` → `CData`), else the whole
/// `content` range (which is where the `CharData` text AND the nested
/// `element` children — the common markup shape — live). `None` without a
/// `content` child (self-closing `EmptyElemTag`, or the flat error-recovery
/// shape of a broken host document, which has no `element`/`content` nodes
/// left to descend into).
fn xml_foreign_object_slice(element: &Node, source: &str) -> Option<(usize, usize)> {
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() != "content" {
            continue;
        }
        let mut cdata: Option<(usize, usize)> = None;
        let mut meaningful_others = false;
        let mut inner = child.walk();
        for part in child.children(&mut inner) {
            match part.kind() {
                "CDSect" => {
                    let mut sect = part.walk();
                    for piece in part.children(&mut sect) {
                        if piece.kind() == "CData" {
                            let range = piece.byte_range();
                            cdata = Some((range.start, range.end));
                        }
                    }
                }
                // Whitespace-only CharData around a lone CDSect is padding,
                // not a second content fragment.
                "CharData" if !source[part.byte_range()].trim().is_empty() => {
                    meaningful_others = true;
                }
                "element" => meaningful_others = true,
                _ => {}
            }
        }
        return match (cdata, meaningful_others) {
            (Some(range), false) => Some(range),
            _ => {
                let range = child.byte_range();
                Some((range.start, range.end))
            }
        };
    }
    None
}

/// (external, type) of an XML `script` element: the `src`/`href`/
/// `xlink:href` attributes make it an EXTERNAL script (nothing inline to
/// extract; doclinks indexes the reference), `type` is its declared MIME
/// (case preserved — [`is_js_script_type`] does the matching). Attributes
/// are the `Attribute` named children of the `STag`; attributes on a
/// self-closing `EmptyElemTag` never reach here because that shape has no
/// `content` to extract anyway.
fn xml_script_attrs(element: &Node, source: &str) -> (bool, Option<String>) {
    let mut external = false;
    let mut script_type = None;
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() != "STag" {
            continue;
        }
        let mut tag_cursor = child.walk();
        for part in child.children(&mut tag_cursor) {
            if part.kind() != "Attribute" {
                continue;
            }
            let (name, value) = xml_attribute(&part, source);
            match name.as_str() {
                "src" | "href" | "xlink:href" => external = true,
                "type" if script_type.is_none() => script_type = value,
                _ => {}
            }
        }
    }
    (external, script_type)
}

/// Raw tag name of an XML `element`: the `Name` child of its `STag`
/// (self-closing `EmptyElemTag` elements have no CSS body, so the STag-only
/// lookup is sufficient for the style-inner check; `None` for self-closing
/// and grammar-error shapes). Distinct from [`xml_element_name`], which
/// refines the name with `#id`/`.class` suffixes.
fn xml_tag_name(element: &Node, source: &str) -> Option<String> {
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() != "STag" {
            continue;
        }
        let mut tag_cursor = child.walk();
        for part in child.children(&mut tag_cursor) {
            if part.kind() == "Name" {
                return Some(source[part.byte_range()].to_string());
            }
        }
    }
    None
}

/// Name of an XML `element`: the tag name from the `Name` child of its start
/// tag (`STag`/`EmptyElemTag`), refined to `tag#id` when an `id` attribute
/// exists, else `tag.<first-class>` when a `class` attribute does. Attributes
/// are the `Attribute` named children of the start tag; their value is the
/// quoted `AttValue` text with its surrounding `"`/`'` stripped.
fn xml_element_name(element: &Node, source: &str) -> Option<String> {
    let mut tag = None;
    let mut id = None;
    let mut class = None;

    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() != "STag" && child.kind() != "EmptyElemTag" {
            continue; // `content` / `ETag` carry no naming information
        }
        let mut tag_cursor = child.walk();
        for part in child.children(&mut tag_cursor) {
            match part.kind() {
                "Name" if tag.is_none() => tag = Some(source[part.byte_range()].to_string()),
                // NB: the xml grammar uses PascalCase kinds (Attribute,
                // AttValue) where html uses snake_case.
                "Attribute" => {
                    let (name, value) = xml_attribute(&part, source);
                    match (name.as_str(), value) {
                        ("id", v) if id.is_none() => id = v,
                        ("class", v) if class.is_none() => class = v,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    let tag = tag?;
    if let Some(id) = id {
        return Some(format!("{tag}#{id}"));
    }
    if let Some(first_class) = class.as_deref().and_then(|c| c.split_whitespace().next()) {
        return Some(format!("{tag}.{first_class}"));
    }
    Some(tag)
}

/// (name, value) of an XML `Attribute` node (`Name = AttValue`); the value is
/// `None` for the (grammar-illegal but error-recovery possible) valueless
/// form. `AttValue` wraps the raw quoted text, so strip one quote pair.
fn xml_attribute(attribute: &Node, source: &str) -> (String, Option<String>) {
    let mut name = String::new();
    let mut value = None;
    let mut cursor = attribute.walk();
    for child in attribute.children(&mut cursor) {
        match child.kind() {
            "Name" if name.is_empty() => name = source[child.byte_range()].to_string(),
            "AttValue" => value = Some(unquote(&source[child.byte_range()])),
            _ => {}
        }
    }
    (name, value)
}

// =============================================================================
// HTML — kind "element" per element / script_element / style_element
// =============================================================================

/// HTML (`tree_sitter_html::LANGUAGE`; serves .xhtml too): the element-bearing
/// node kinds are `element` (paired via `start_tag … end_tag`, or wrapping a
/// lone `self_closing_tag` for void/self-closed tags), plus `script_element`
/// and `style_element` (each `start_tag raw_text? end_tag`) — verified against
/// `tree-sitter-html-0.23.2/src/node-types.json`. `doctype` and `comment` are
/// skipped by kind; nested elements recurse in source order.
///
/// style-inner-css-v1: a `style_element`'s CSS body is the named `raw_text`
/// child (verified: `style_element = start_tag raw_text? end_tag`). When that
/// body is non-empty it is parsed with the CSS grammar and its
/// selectors/at-rules emit too, with spans re-based onto FULL-file
/// coordinates (see [`emit_style_inner_css`]).
///
/// script-inner-js-v1: a `script_element` has the SAME shape
/// (`script_element = start_tag raw_text? end_tag` — verified against
/// `tree-sitter-html-0.23.2/src/node-types.json` + probe dump; an EXTERNAL
/// `<script src=…></script>` still carries an `raw_text` child, it is just
/// EMPTY) — its `raw_text` body of an inline, JS-typed script is parsed with
/// the JAVASCRIPT grammar and emits JS definition rows in a
/// `<hostfilename>#script-N` virtual document (see
/// [`emit_script_inner_js`]). A `src` attribute makes the script external —
/// doclinks already indexes that reference — and a non-JS `type` is not
/// JavaScript; both are skipped before any parse.
///
/// markup-node-tree-v1: `depth` is the element's nesting level in the current
/// document — the number of ANCESTOR elements (root-level = 0); the top-level
/// caller starts at 0, recursion passes `depth + 1` when descending FROM an
/// element-bearing node and `depth` through every other node (doctype,
/// comments, text). `element`, `script_element` and `style_element` rows all
/// carry `Some(depth)` (a script/style element IS a markup node; its inner
/// CSS/JS rows are not and keep `None`).
fn walk_html(
    node: Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
    depth: u32,
) {
    // FIX-1a: depth cap — same rationale as [`walk_xml`] (no tree-depth
    // limit in tree-sitter, 2 MiB rayon worker stacks): past
    // [`MAX_ELEMENT_DEPTH`] the node and its subtree are skipped with ONE
    // per-file warning.
    if depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(&mut state.budget, &mut state.warnings);
        return;
    }

    // VD-2: true after a foreignObject handed its content to a nested virtual
    // document — the subtree is the document's, not the host walk's.
    let mut skip_children = false;
    match node.kind() {
        "element" => {
            if let Some(name) = html_element_name(&node, source) {
                out.push(element_def("element", name, node, source, Some(depth)));
            }
            // VD-2: a `foreignObject` inside inline `<svg>` (matched
            // case-insensitively — the html grammar keeps the source
            // spelling while the browser parser adjusts foreign tag case)
            // carries HTML content: re-parsed with the HTML grammar as the
            // virtual document `<host>#fo-N`, its scripts/styles/nested
            // foreignObjects recursing depth-bounded. The subtree is then
            // SKIPPED — the document owns its elements. Nameless hosts keep
            // the pre-VD-2 behavior (no name → no document → normal descent).
            // FIX-1b (F6): the skip is gated on the content range EXISTING,
            // mirroring the xml arm — a start-tag-only foreignObject (html
            // error recovery for an unclosed tag: an `element` with a
            // `start_tag` but no `end_tag` → no content range) has nothing
            // to hand off, and its children must stay in the HOST walk
            // instead of being silently dropped.
            if html_tag_is_foreign_object(&node, source) && state.host().is_some() {
                if let Some((start, end)) = html_element_content_range(&node) {
                    let host = state.host().unwrap_or_default();
                    let WalkState {
                        refs,
                        warnings,
                        budget,
                        ..
                    } = state;
                    process_foreign_object_content(
                        &source[start..end],
                        start,
                        line_base_before(source, start),
                        0,
                        host,
                        budget,
                        warnings,
                        out,
                        refs,
                    );
                    skip_children = true;
                }
            }
        }
        "script_element" => {
            if let Some(name) = html_element_name(&node, source) {
                out.push(element_def("element", name, node, source, Some(depth)));
            }
            if state.host().is_some() {
                let (external, script_type) = html_script_attrs(&node, source);
                if !external && is_js_script_type(script_type.as_deref()) {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "raw_text" {
                            emit_script_inner_js(&child, source, state, out);
                        }
                    }
                }
            }
        }
        "style_element" => {
            if let Some(name) = html_element_name(&node, source) {
                out.push(element_def("element", name, node, source, Some(depth)));
            }
            // The CSS body: the `raw_text` child of the style_element itself.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "raw_text" {
                    emit_style_inner_css(&child, source, state, out);
                }
            }
        }
        _ => {}
    }

    if !skip_children {
        // Descending FROM an element-bearing node adds one markup level;
        // every other node is transparent to the element tree.
        let child_depth = match node.kind() {
            "element" | "script_element" | "style_element" => depth + 1,
            _ => depth,
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_html(child, source, state, out, child_depth);
        }
    }
}

/// Raw `tag_name` of an HTML element (no `#id` refinement — see
/// [`html_element_name`] for the naming view): the text of the `tag_name`
/// child of its `start_tag` / `self_closing_tag`.
fn html_raw_tag_name(element: &Node, source: &str) -> Option<String> {
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() == "start_tag" || child.kind() == "self_closing_tag" {
            let mut tag_cursor = child.walk();
            for part in child.children(&mut tag_cursor) {
                if part.kind() == "tag_name" {
                    return Some(source[part.byte_range()].to_string());
                }
            }
        }
    }
    None
}

/// VD-2: is this HTML element a `<foreignObject>` container? Case-insensitive
/// — the html grammar preserves the source spelling of the `tag_name`
/// (`foreignObject`, `foreignobject`, `FOREIGNOBJECT` all parse), and the
/// browser parser adjusts foreign element case anyway.
fn html_tag_is_foreign_object(element: &Node, source: &str) -> bool {
    html_raw_tag_name(element, source).is_some_and(|tag| tag.eq_ignore_ascii_case("foreignobject"))
}

/// Byte range of an HTML `element`'s CONTENT — `(start_tag.end, end_tag.start)`
/// (verified shape: `element = start_tag … end_tag` with the content as the
/// children between them). `None` without both tags (self-closing/void
/// elements, and the start-tag-only error-recovery shape), in which case
/// there is nothing to re-parse.
fn html_element_content_range(element: &Node) -> Option<(usize, usize)> {
    let mut start = None;
    let mut end = None;
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        match child.kind() {
            "start_tag" => start = Some(child.end_byte()),
            "end_tag" => end = Some(child.start_byte()),
            _ => {}
        }
    }
    match (start, end) {
        (Some(s), Some(e)) if e >= s => Some((s, e)),
        _ => None,
    }
}

/// (external, type) of an HTML `script_element`: a `src` attribute (on its
/// `start_tag` — the only external form HTML has) makes the script EXTERNAL,
/// `type` is its declared MIME (case preserved — [`is_js_script_type`] does
/// the matching). Attributes are the `attribute` children of the start tag;
/// the value comes quoted (`quoted_attribute_value`) or bare
/// (`attribute_value`) and `html_attribute` already surfaces it verbatim.
fn html_script_attrs(script_element: &Node, source: &str) -> (bool, Option<String>) {
    let mut external = false;
    let mut script_type = None;
    let mut cursor = script_element.walk();
    for child in script_element.children(&mut cursor) {
        if child.kind() != "start_tag" && child.kind() != "self_closing_tag" {
            continue;
        }
        let mut tag_cursor = child.walk();
        for part in child.children(&mut tag_cursor) {
            if part.kind() != "attribute" {
                continue;
            }
            let (name, value) = html_attribute(&part, source);
            if name.eq_ignore_ascii_case("src") {
                external = true;
            } else if name.eq_ignore_ascii_case("type") && script_type.is_none() {
                script_type = value;
            }
        }
    }
    (external, script_type)
}

/// The `type` gate of script-inner-js-v1: a script's body is JavaScript when
/// the `type` attribute is ABSENT (the HTML default is JS) or one of the JS
/// MIME values — `text/javascript`, `application/javascript`, `module`,
/// `text/ecmascript` — matched case-insensitively after trimming. Anything
/// else (`application/json` data blocks, `importmap`, `speculationrules`,
/// `text/babel`/JSX, `text/plain`, templates) is NOT JavaScript and the body
/// is never parsed: it would be garbage under the JS grammar.
fn is_js_script_type(script_type: Option<&str>) -> bool {
    match script_type {
        None => true,
        Some(t) => matches!(
            t.trim().to_ascii_lowercase().as_str(),
            "text/javascript" | "application/javascript" | "module" | "text/ecmascript"
        ),
    }
}

/// Name of an HTML element: the `tag_name` of its `start_tag` (or of its
/// `self_closing_tag`), suffixed `#id` when an `id` attribute is present.
/// Attribute values come from `attribute_value` — either a direct child of
/// `attribute` (unquoted syntax) or wrapped in `quoted_attribute_value` (the
/// grammar already strips the quotes).
fn html_element_name(element: &Node, source: &str) -> Option<String> {
    let mut cursor = element.walk();
    for child in element.children(&mut cursor) {
        if child.kind() == "start_tag" || child.kind() == "self_closing_tag" {
            return html_start_tag_name(&child, source);
        }
    }
    None
}

fn html_start_tag_name(tag: &Node, source: &str) -> Option<String> {
    let mut name = None;
    let mut id = None;
    let mut cursor = tag.walk();
    for child in tag.children(&mut cursor) {
        match child.kind() {
            "tag_name" if name.is_none() => name = Some(source[child.byte_range()].to_string()),
            "attribute" => {
                let (attr, value) = html_attribute(&child, source);
                if attr == "id" && id.is_none() {
                    id = value;
                }
            }
            _ => {}
        }
    }
    name.map(|tag| match id {
        Some(id) => format!("{tag}#{id}"),
        None => tag,
    })
}

/// (name, value) of an HTML `attribute` node (`attribute_name (= value)?`);
/// the value is surfaced verbatim — the grammar keeps it unquoted inside
/// `quoted_attribute_value`.
fn html_attribute(attribute: &Node, source: &str) -> (String, Option<String>) {
    let mut name = None;
    let mut value = None;
    let mut cursor = attribute.walk();
    for child in attribute.children(&mut cursor) {
        match child.kind() {
            "attribute_name" => name = Some(source[child.byte_range()].to_string()),
            "attribute_value" => value = Some(source[child.byte_range()].to_string()),
            "quoted_attribute_value" => {
                let mut inner = child.walk();
                for quoted in child.children(&mut inner) {
                    if quoted.kind() == "attribute_value" {
                        value = Some(source[quoted.byte_range()].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    (name.unwrap_or_default(), value)
}

// =============================================================================
// style-inner CSS — the body of html <style> / xml (svg) <style> elements
// (style-inner-css-v1), parsed with the CSS grammar and re-based onto the
// FULL file's coordinates
// =============================================================================

/// Parse one `<style>` body chunk (the `raw_text` child of an HTML
/// `style_element`, a `CharData` child of an XML `style` element's `content`,
/// or the `CData` node inside that content's `CDSect` wrapper) with the CSS
/// grammar and emit its selectors/at-rules.
///
/// Spans are re-based onto FULL-file coordinates so the module's slice-back
/// invariant holds for inner definitions too:
///
/// - `byte_start`/`byte_end` += the body's byte offset in the full file. The
///   inner defs are byte offsets into `source[body.byte_range()]` — the SAME
///   bytes at `body.start_byte() + offset` in the full file, so the shifted
///   span slices back to the identical selector/at-rule text.
/// - `line_start`/`line_end`/`definition_line` += the number of `\n` bytes in
///   the full file BEFORE the body (`line_base`). The inner tree's line 1 is
///   the physical line the body starts on (the `<style>` tag's line), so
///   inner line N is full line `N + line_base`.
///
/// virtual-documents-v1: when the walk has a host file name
/// ([`WalkState::host`]), the body is a named virtual document — `state`'s
/// `style_no` counter is consumed ONLY by a body that actually emits
/// (non-empty + CSS parse succeeds, the same continuity rule the script
/// counter pins), every emitted row carries `container` =
/// `<hostfilename>#style-N`, and the doclinks CSS scan over the body text
/// (`@import` / `url()` — the loaded elements) contributes
/// `via`-provenanced outbound-reference rows to `state.refs` (deduplicated
/// by the `(module, via)` pair, see [`dedup_refs`]). A nameless host keeps
/// the pre-virtual-documents behavior: rows emit container-less, no number
/// is consumed, no references are collected (nothing to attribute them to).
///
/// Guards: an empty/whitespace-only body emits nothing (no wasted parse) and
/// a failed inner parse keeps just the element definition — the element row
/// is already pushed by the caller, so this function can only ADD rows, never
/// crash the walk. (Unlike the script path, a CSS tree with error nodes still
/// walks — style-inner-css-v1's shipped extraction is error-tolerant and that
/// behavior is unchanged; "successfully processed" for numbering means the
/// parse itself succeeded.)
///
/// The heavy lifting lives in [`emit_style_document`], the core shared with
/// the VD-2 foreignObject recursion; this host-path adapter only derives the
/// body's FULL-file position from the host tree's node.
fn emit_style_inner_css(
    body: &Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
) {
    let WalkState {
        style_no,
        refs,
        warnings,
        budget,
        ..
    } = state;
    let host = budget.host;
    let offset = body.start_byte();
    let line_base = line_base_before(source, offset);
    emit_style_document(
        &source[body.byte_range()],
        offset,
        line_base,
        host,
        style_no,
        budget,
        warnings,
        out,
        refs,
    );
}

/// The style-body core shared by the HOST walk ([`emit_style_inner_css`],
/// byte/line base derived from the host tree) and the VD-2 foreignObject
/// recursion (byte/line base composed through the nesting levels).
///
/// `text` is the CSS body; `byte_base`/`line_base` position it in the FULL
/// file. `container_prefix` is `Some(<host or document name>)` for a named
/// virtual document — the style number is consumed from `*counter` ONLY after
/// the empty and parse guards pass and a budget slot is taken
/// (`<prefix>#style-N`), the rows are stamped with it, and the stylesheet's
/// loaded elements (`@import`/`url()`) become `via`-provenanced reference
/// rows — or `None` for a nameless host (container-less rows, no number, no
/// slot, no references — the pre-virtual-documents behavior).
///
/// Returns whether the body became a virtual document (or, for a nameless
/// host, emitted its rows): `false` = empty or failed parse — the caller
/// consumed nothing.
#[allow(clippy::too_many_arguments)]
fn emit_style_document(
    text: &str,
    byte_base: usize,
    line_base: u32,
    container_prefix: Option<&str>,
    counter: &mut u32,
    budget: &mut EmbedBudget,
    warnings: &mut Vec<String>,
    out_defs: &mut Vec<DefinitionInfo>,
    out_imports: &mut Vec<ImportInfo>,
) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let Ok(tree) = crate::ast::parser::PARSER_POOL.parse(text, Language::Css) else {
        return false;
    };

    // Named virtual document: budget slot + style number + container stamp;
    // nameless hosts keep container-less rows and consume nothing.
    let via = match container_prefix {
        Some(prefix) => {
            if !take_doc_slot(budget, warnings) {
                return false;
            }
            *counter += 1;
            let name = format!("{prefix}#style-{}", *counter);
            Some(name)
        }
        None => None,
    };

    let mut inner = Vec::new();
    walk_css(tree.root_node(), text, &mut inner);
    for def in inner {
        let mut def = def;
        def.container = via.clone();
        push_rebased(def, byte_base, line_base, out_defs);
    }

    // Outbound references: the stylesheet's loaded elements (`@import`/`url()`)
    // are blast-radius edges from the HOST file, attributed to this virtual
    // document. Nameless hosts collect nothing.
    if let Some(via) = &via {
        let rows = crate::ast::extract_doc_links(Language::Css, text, None)
            .into_iter()
            .map(|mut row| {
                row.via = Some(via.clone());
                row
            })
            .collect();
        out_imports.extend(dedup_refs(rows));
    }
    true
}

// =============================================================================
// script-inner JS — the body of html script_element / xml (svg) script
// elements (script-inner-js-v1), parsed with the JAVASCRIPT grammar and
// re-based onto the FULL file's coordinates
// =============================================================================

/// Parse one inline `<script>` body chunk (the `raw_text` child of an HTML
/// `script_element`, a `CharData` child of an XML `script` element's
/// `content`, or the `CData` node inside that content's `CDSect` wrapper)
/// with the JAVASCRIPT grammar and emit its definitions as rows of the
/// virtual document `<host>#script-N`.
///
/// The JS rows are the unified definition walk's output
/// (`ast::extractor::extract_definition_entries`) — the exact
/// `function`/`class`/`method`/`constant`/`field`/`call`/… set a standalone
/// `.js` file reports — with every span re-based onto FULL-file coordinates
/// so the host file's slice-back invariant holds:
///
/// - `byte_start`/`byte_end` = the JS definition NODE's range + the body's
///   byte offset in the full file. `full_source[byte_start..byte_end]` is
///   the symbol's exact source text in the host file — this is what makes
///   `tldr body page.html sayHi` slice the script's bytes out of the HTML
///   byte-exactly. (The code-language convention of leaving byte spans
///   `None` is deliberately overridden here: the body's definition is
///   addressable inside the host, like any format element.)
/// - `line_start`/`line_end`/`definition_line` += the number of `\n` bytes
///   in the full file BEFORE the body (`line_base`) — the inner tree's row 0
///   is the physical row the body starts on, so inner line N is full line
///   `N + line_base` (the same math as [`emit_style_inner_css`]). The LINE
///   span keeps the code-language attached-trivia semantics: a JSDoc comment
///   above a function widens the line span but not the byte span, exactly as
///   for a standalone `.js` file.
/// - `container` = `<host>#script-N` on EVERY row; `name`/`kind`/
///   `signature` stay the JS symbol's own values.
///
/// Guards (checked by the callers and here): an empty/whitespace-only body
/// emits nothing (no wasted parse); a body whose JS parse carries error
/// nodes emits NOTHING — a syntax-broken script must not fabricate rows out
/// of error-recovered garbage; a failed parse (`Err`) likewise. Neither can
/// fail the host walk — one bad script costs only its own rows. `state`'s
/// `script_no` is consumed ONLY by a body that actually becomes a virtual
/// document (non-empty, JS-typed, parses clean), so `#script-N` numbers stay
/// contiguous over the file's extracted scripts.
///
/// virtual-documents-v1: a body that becomes a virtual document ALSO
/// contributes OUTBOUND reference rows to `state.refs` — the JS import
/// surface (`import … from 'x'` / `require('x')` / `export … from 'x'`, via
/// the `ast::imports` JavaScript extractor run on the SAME parsed tree) plus
/// the doclinks path/URL scan over the body text (fetch/xhr string
/// arguments). Every row is stamped `via = <host>#script-N` (the same name
/// the definitions carry in `container`) and the merge is deduplicated by
/// the `(module, via)` pair — a script that imports the same URL twice
/// yields one row, the first source-ordered one surviving (so an `import`
/// row with its imported names wins over a later text-scan row of the same
/// string).
///
/// The heavy lifting lives in [`emit_script_document`], the core shared with
/// the VD-2 foreignObject recursion; this host-path adapter only derives the
/// body's FULL-file position from the host tree's node.
fn emit_script_inner_js(
    body: &Node,
    source: &str,
    state: &mut WalkState,
    out: &mut Vec<DefinitionInfo>,
) {
    let WalkState {
        script_no,
        refs,
        warnings,
        budget,
        ..
    } = state;
    let host = budget.host.expect(
        "emit_script_inner_js is only called from walks with a host label \
         (callers gate on WalkState::host)",
    );
    let offset = body.start_byte();
    let line_base = line_base_before(source, offset);
    emit_script_document(
        &source[body.byte_range()],
        offset,
        line_base,
        host,
        script_no,
        budget,
        warnings,
        out,
        refs,
    );
}

/// The script-body core shared by the HOST walk ([`emit_script_inner_js`],
/// byte/line base derived from the host tree) and the VD-2 foreignObject
/// recursion (byte/line base composed through the nesting levels).
///
/// `text` is the JS body; `byte_base`/`line_base` position it in the FULL
/// file; `container_prefix` is the naming root of the document the script
/// lives in (`<host>` at the top level, `<host>#fo-N` inside a foreignObject
/// document). The script number is consumed from `*counter` ONLY after the
/// empty/parse guards pass and a budget slot is taken, so `#script-N`
/// numbers stay contiguous over each document's extracted scripts. Rows are
/// re-based onto FULL-file coordinates (see [`push_rebased`]) and stamped
/// `container = <prefix>#script-N`; the body's outbound references (JS import
/// surface + the doclinks path/URL scan) ride `out_imports` with
/// `via = <prefix>#script-N`, deduplicated by `(module, via)`.
///
/// Returns whether the body became a virtual document: `false` = empty,
/// failed parse, or error-carrying parse — nothing was emitted and no
/// number/slot was consumed (the checks precede every mutation).
#[allow(clippy::too_many_arguments)]
fn emit_script_document(
    text: &str,
    byte_base: usize,
    line_base: u32,
    container_prefix: &str,
    counter: &mut u32,
    budget: &mut EmbedBudget,
    warnings: &mut Vec<String>,
    out_defs: &mut Vec<DefinitionInfo>,
    out_imports: &mut Vec<ImportInfo>,
) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let Ok(tree) = crate::ast::parser::PARSER_POOL.parse(text, Language::JavaScript) else {
        return false;
    };
    if tree.root_node().has_error() {
        return false;
    }
    if !take_doc_slot(budget, warnings) {
        return false;
    }

    *counter += 1;
    let container = format!("{container_prefix}#script-{}", *counter);

    for entry in crate::ast::extract_definition_entries(&tree, text, Language::JavaScript) {
        let mut info = entry.info;
        let node_start = entry.node.start_byte() as u64 + byte_base as u64;
        let node_end = entry.node.end_byte() as u64 + byte_base as u64;
        info.byte_start = Some(node_start);
        info.byte_end = Some(node_end);
        info.line_start += line_base;
        info.line_end += line_base;
        if let Some(line) = info.definition_line.as_mut() {
            *line += line_base;
        }
        info.container = Some(container.clone());
        out_defs.push(info);
    }

    // Outbound references (virtual-documents-v1): the script's import
    // surface, then the path/URL scan of the body text, all attributed to
    // this virtual document and deduplicated by (module, via).
    let mut rows = extract_imports_from_tree(&tree, text, Language::JavaScript).unwrap_or_default();
    rows.extend(extract_doc_links(Language::Text, text, None));
    out_imports.extend(dedup_refs(
        rows.into_iter()
            .map(|mut row| {
                row.via = Some(container.clone());
                row
            })
            .collect(),
    ));
    true
}

/// virtual-documents-v1: collapse one virtual document's outbound-reference
/// rows to their `(module, via)` identity — the SAME reference written twice
/// inside one embedded document (two `import`s from one module, a URL
/// appearing in two `url()` tokens, an import row and a text-scan row of the
/// same string) is ONE edge; first-in-scan-order wins (so a JS `import` row
/// with its imported names survives over a later text-scan row of the same
/// string). Two different virtual documents referencing the same module stay
/// two rows: their `via` provenance differs, and the provenance IS the edge
/// identity.
fn dedup_refs(rows: Vec<ImportInfo>) -> Vec<ImportInfo> {
    let mut seen: std::collections::HashSet<(String, Option<String>)> =
        std::collections::HashSet::new();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if seen.insert((row.module.clone(), row.via.clone())) {
            out.push(row);
        }
    }
    out
}

// =============================================================================
// VD-2 — foreignObject recursion: the html content inside an SVG
// <foreignObject> (or inside an inline <svg> in an HTML page) re-parsed with
// the HTML grammar as a depth-bounded virtual document <host>#fo-N
// =============================================================================

/// Hand ONE foreignObject's content to the virtual-document machinery — the
/// entry both walkers share (the HOST walks call it at `parent_depth = 0`
/// with the host's name; [`walk_embedded_html`] calls it for NESTED
/// foreignObjects with the current document's name and depth). Owns the
/// guards and the file-wide consumption so the recursion helper itself stays
/// pure:
///
/// 1. empty/whitespace content → nothing, consumes nothing (no number, no
///    slot);
/// 2. `parent_depth + 1 > MAX_EMBED_DEPTH` → ONE warning naming the parent
///    container, nothing consumed (levels > 8 stay unprocessed);
/// 3. budget exhausted → the ONE per-file warning, nothing consumed;
/// 4. otherwise the `#fo-N` name is assigned (`budget.fo_no` + slot) and
///    [`process_embedded_html`] runs — on a `false` return (malformed
///    content) both are GIVEN BACK, so only successfully processed documents
///    consume numbers (the numbering-continuity pin).
///
/// Termination is the strict-substring invariant (see the module docs): the
/// caller's slice is strictly contained in its parent document, so every
/// recursion level operates on strictly fewer bytes of the same file. The
/// depth cap and budget are belt-and-braces, not the termination argument.
#[allow(clippy::too_many_arguments)]
fn process_foreign_object_content(
    html: &str,
    byte_base: usize,
    line_base: u32,
    parent_depth: usize,
    parent_container: &str,
    budget: &mut EmbedBudget,
    warnings: &mut Vec<String>,
    out_defs: &mut Vec<DefinitionInfo>,
    out_imports: &mut Vec<ImportInfo>,
) {
    if html.trim().is_empty() {
        return;
    }
    let depth = parent_depth + 1;
    if depth > MAX_EMBED_DEPTH {
        if !budget.depth_warned {
            budget.depth_warned = true;
            warnings.push(format!(
                "embedded document nesting exceeds depth {MAX_EMBED_DEPTH}; \
                 deeper levels skipped: {parent_container}"
            ));
        }
        return;
    }
    if !take_doc_slot(budget, warnings) {
        return;
    }
    let Some(host) = budget.host else {
        // Unreachable: both walkers gate on a named host before recursing.
        return;
    };
    budget.fo_no += 1;
    let container = format!("{host}#fo-{}", budget.fo_no);
    if !process_embedded_html(
        html,
        byte_base,
        line_base,
        depth,
        &container,
        budget,
        warnings,
        out_defs,
        out_imports,
    ) {
        // Malformed content: the document never existed — no rows, no refs,
        // no name in any output. Give the number and the slot back so the
        // `#fo-N` numbering stays contiguous over the file's processed
        // foreignObjects.
        budget.fo_no -= 1;
        budget.docs -= 1;
    }
}

/// The VD-2 per-document extraction: parse `html` (a foreignObject's content
/// slice — STRICTLY CONTAINED in the parent document, which is what
/// terminates the recursion) with the HTML grammar and walk it, emitting
///
/// - `element` rows for the embedded markup, `container` =
///   `container_prefix` (the document's own hierarchical name);
/// - `script_element`/`style_element` bodies as nested virtual documents
///   `<container_prefix>#script-M` / `#style-M` (M counted per document) via
///   the shared [`emit_script_document`]/[`emit_style_document`] cores, their
///   outbound refs merging into `out_imports` with `via` = the full
///   hierarchical name;
/// - nested `foreignObject`s (inside inline `<svg>`s) recursively as sibling
///   virtual documents `<host>#fo-K` — the per-file counter lives in
///   `budget`, so a chain page.html → fo-1 → fo-2 → … names flatly per file
///   while scripts/styles name hierarchically inside their document.
///
/// `byte_base`/`line_base` position `html` in the FULL file (composed
/// additively through the nesting levels); `depth` is this document's
/// 1-based nesting level. Returns whether the document processed (parse
/// clean): a malformed re-parse emits ONE warning naming the document and
/// `false` — it never fails the host, and the caller gives the consumed
/// number/slot back.
#[allow(clippy::too_many_arguments)]
fn process_embedded_html(
    html: &str,
    byte_base: usize,
    line_base: u32,
    depth: usize,
    container_prefix: &str,
    budget: &mut EmbedBudget,
    warnings: &mut Vec<String>,
    out_defs: &mut Vec<DefinitionInfo>,
    out_imports: &mut Vec<ImportInfo>,
) -> bool {
    let Ok(tree) = crate::ast::parser::PARSER_POOL.parse(html, Language::Html) else {
        return false;
    };
    if tree.root_node().has_error() {
        warnings.push(format!(
            "Skipped embedded html document '{container_prefix}': the nested markup \
             does not parse as HTML (malformed content); its definitions and \
             references are not indexed"
        ));
        return false;
    }
    // `#script-M` / `#style-M` are numbered PER DOCUMENT (hierarchical
    // naming) — fresh counters here, unlike the file-level counters of the
    // top-level walk. markup-node-tree-v1: the element-depth counter is
    // likewise PER DOCUMENT — the virtual document's root-level elements sit
    // at depth 0 (the doc's `container` identifies the document, so depth
    // never needs to be global).
    let mut script_no = 0u32;
    let mut style_no = 0u32;
    walk_embedded_html(
        tree.root_node(),
        html,
        byte_base,
        line_base,
        depth,
        0,
        container_prefix,
        &mut script_no,
        &mut style_no,
        budget,
        warnings,
        out_defs,
        out_imports,
    );
    true
}

/// The embedded document's own pre-order walk (the HTML walker over a
/// re-parsed tree): same element/script/style kinds as [`walk_html`], but
/// every row carries the document's `container`, spans re-base through
/// `byte_base`/`line_base`, script/style numbering is the document-local
/// counters, and a `foreignObject` element recurses through
/// [`process_foreign_object_content`] instead of descending.
///
/// markup-node-tree-v1: `depth` (usize) stays the VIRTUAL-DOCUMENT nesting
/// level the `MAX_EMBED_DEPTH` cap counts (1 = first foreignObject document);
/// `elem_depth` (u32) is the ELEMENT nesting level WITHIN this virtual
/// document — the number of ancestor elements, the document's root-level
/// elements at 0 — and it restarts at 0 in every nested document
/// ([`process_embedded_html`] passes 0). The `container` field identifies the
/// document a depth belongs to.
#[allow(clippy::too_many_arguments)]
fn walk_embedded_html(
    node: Node,
    html: &str,
    byte_base: usize,
    line_base: u32,
    depth: usize,
    elem_depth: u32,
    container: &str,
    script_no: &mut u32,
    style_no: &mut u32,
    budget: &mut EmbedBudget,
    warnings: &mut Vec<String>,
    out_defs: &mut Vec<DefinitionInfo>,
    out_imports: &mut Vec<ImportInfo>,
) {
    // VD-2: true after a nested foreignObject handed its content to its own
    // virtual document — the subtree is that document's.
    let mut skip_children = false;
    // FIX-1a: same element-depth cap as the host walkers, applied to this
    // virtual document's own element nesting (`elem_depth` restarts at 0 per
    // document). The warning rides the FILE's budget latch, so a host plus
    // its embedded documents still produce at most ONE depth warning.
    if elem_depth > MAX_ELEMENT_DEPTH {
        warn_element_depth_cap(budget, warnings);
        return;
    }
    match node.kind() {
        "element" => {
            if let Some(name) = html_element_name(&node, html) {
                let mut def = element_def("element", name, node, html, Some(elem_depth));
                def.container = Some(container.to_string());
                push_rebased(def, byte_base, line_base, out_defs);
            }
            if html_tag_is_foreign_object(&node, html) {
                if let Some((start, end)) = html_element_content_range(&node) {
                    let nested = &html[start..end];
                    let nested_byte_base = byte_base + start;
                    let nested_line_base = line_base + line_base_before(html, start);
                    process_foreign_object_content(
                        nested,
                        nested_byte_base,
                        nested_line_base,
                        depth,
                        container,
                        budget,
                        warnings,
                        out_defs,
                        out_imports,
                    );
                }
                skip_children = true;
            }
        }
        "script_element" => {
            if let Some(name) = html_element_name(&node, html) {
                let mut def = element_def("element", name, node, html, Some(elem_depth));
                def.container = Some(container.to_string());
                push_rebased(def, byte_base, line_base, out_defs);
            }
            // Same external/type gates as the host walk: an external `src`
            // stays a REFERENCE (the host doclink scan indexes it) and never
            // becomes a virtual document; no cross-file parsing happens here.
            let (external, script_type) = html_script_attrs(&node, html);
            if !external && is_js_script_type(script_type.as_deref()) {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "raw_text" {
                        let offset = child.start_byte();
                        emit_script_document(
                            &html[child.byte_range()],
                            byte_base + offset,
                            line_base + line_base_before(html, offset),
                            container,
                            script_no,
                            budget,
                            warnings,
                            out_defs,
                            out_imports,
                        );
                    }
                }
            }
        }
        "style_element" => {
            if let Some(name) = html_element_name(&node, html) {
                let mut def = element_def("element", name, node, html, Some(elem_depth));
                def.container = Some(container.to_string());
                push_rebased(def, byte_base, line_base, out_defs);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "raw_text" {
                    let offset = child.start_byte();
                    emit_style_document(
                        &html[child.byte_range()],
                        byte_base + offset,
                        line_base + line_base_before(html, offset),
                        Some(container),
                        style_no,
                        budget,
                        warnings,
                        out_defs,
                        out_imports,
                    );
                }
            }
        }
        _ => {}
    }

    if !skip_children {
        // Same ancestor-count rule as [`walk_html`]: descending from an
        // element-bearing node adds one markup level.
        let child_depth = match node.kind() {
            "element" | "script_element" | "style_element" => elem_depth + 1,
            _ => elem_depth,
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_embedded_html(
                child,
                html,
                byte_base,
                line_base,
                depth,
                child_depth,
                container,
                script_no,
                style_no,
                budget,
                warnings,
                out_defs,
                out_imports,
            );
        }
    }
}

// =============================================================================
// CSS — kind "selector" per rule_set + kind "at-rule" per block at-rule
// =============================================================================

/// CSS (`tree_sitter_css::LANGUAGE`): `rule_set` nodes (prelude `selectors` +
/// `block`) emit kind `selector`; BLOCK-bearing at-rules emit kind `at-rule`.
/// tree-sitter-css 0.23.2 gives the common at-rules dedicated statement kinds
/// (`media_statement`, `supports_statement`, `keyframes_statement`) with the
/// keyword baked in as an anonymous token, while every other block at-rule
/// parses as generic `at_rule` with a named `at_keyword` child (verified
/// against `tree-sitter-css-0.23.2/src/node-types.json` + `grammar.json`).
/// `;`-terminated statements (`import_statement`, `charset_statement`,
/// `namespace_statement`, `postcss_statement`) have no block and never emit;
/// declarations are not definitions. Rules nested inside an at-rule block —
/// the media-query case, CSS nesting — recurse and emit their own selectors.
fn walk_css(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    match node.kind() {
        "rule_set" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "selectors" {
                    let name = collapse_whitespace(&source[child.byte_range()]);
                    out.push(element_def("selector", name, node, source, None));
                    break;
                }
            }
        }
        "media_statement" | "supports_statement" | "keyframes_statement" => {
            let name = css_at_rule_name(&node, source);
            out.push(element_def("at-rule", name, node, source, None));
        }
        "at_rule" => {
            // Generic at-rules may also terminate with `;` (no block); only
            // block-bearing ones are structural at-rule regions.
            let mut has_block = false;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "block" {
                    has_block = true;
                    break;
                }
            }
            if has_block {
                let name = css_at_rule_name(&node, source);
                out.push(element_def("at-rule", name, node, source, None));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_css(child, source, out);
    }
}

/// Name of a CSS at-rule: the `at_keyword` child when the grammar exposes one
/// (`at_rule`, `keyframes_statement`), else the statement's first token — for
/// `media_statement`/`supports_statement` the keyword is an anonymous literal
/// at the node's start (`@media`/`@supports`).
fn css_at_rule_name(rule: &Node, source: &str) -> String {
    let mut cursor = rule.walk();
    for child in rule.children(&mut cursor) {
        if child.kind() == "at_keyword" {
            return source[child.byte_range()].to_string();
        }
    }
    source[rule.byte_range()]
        .split(|c: char| c.is_whitespace() || c == '{')
        .next()
        .unwrap_or("")
        .to_string()
}

/// CSS selector text: collapse every whitespace run to one space and trim, so
/// `h1,\n  .card` reads as `h1, .card`.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// =============================================================================
// LaTeX — kind "section" per sectioning command + kind "environment" per
// \begin{env} … \end{env} block
// =============================================================================

/// Node kinds of the LaTeX grammar that wrap a `\begin{env} … \end{env}`
/// block (verified against `codebook-tree-sitter-latex-0.6.1/src/node-types.json`
/// — the republished latex-lsp grammar: all of them carry required
/// `begin`/`end` fields pointing at `begin`/`end` nodes). `generic_environment` covers every non-special-cased name
/// (document, itemize, figure, table, center, …); the grammar gives the
/// common special-content environments dedicated kinds (`math_environment`
/// for equation/align/gather/multline/…, `verbatim_environment`,
/// `listing_environment`, `minted_environment`, `comment_environment`,
/// `luacode_environment`, `pycode_environment`, `sageblock_environment`,
/// `sagesilent_environment`, `asy_environment`, `asydef_environment`).
/// `environment_definition` (\newenvironment) and `theorem_definition`
/// (\newtheorem) are NOT in this list — they define environments in the
/// preamble, they do not open one.
const LATEX_ENVIRONMENT_KINDS: &[&str] = &[
    "generic_environment",
    "math_environment",
    "verbatim_environment",
    "listing_environment",
    "minted_environment",
    "comment_environment",
    "luacode_environment",
    "pycode_environment",
    "sageblock_environment",
    "sagesilent_environment",
    "asy_environment",
    "asydef_environment",
];

/// LaTeX (`codebook_tree_sitter_latex::LANGUAGE`; serves .tex/.sty/.cls).
/// Two element kinds, both shape-given by the grammar (verified against
/// `codebook-tree-sitter-latex-0.6.1/src/node-types.json`, the republished
/// latex-lsp/tree-sitter-latex grammar):
///
/// - `section`: the sectioning commands are DEDICATED named nodes — `part`,
///   `chapter`, `section`, `subsection`, `subsubsection`, `paragraph`,
///   `subparagraph` (one kind per level; starred variants `\section*` and the
///   KOMA spellings `\addsec`/`\addchap`/`\addpart` fold into the same node
///   kind). The grammar nests the section's CONTENT inside the sectioning
///   node: a `section` node's allowed children include
///   `subsection`/`subsubsection`/`paragraph`/`subparagraph` (its own level
///   and below, never a sibling `section`), `chapter` includes `section` but
///   not a sibling `chapter`, and so on down the hierarchy. A section node's
///   byte range therefore ALREADY spans everything up to the next sectioning
///   command of equal-or-higher level (or `\end{document}`/EOF) — the
///   content-spanning region LaTeX semantics call for, delivered by the tree
///   itself; no sibling-boundary math is needed (and none could be as
///   faithful: the hierarchy is the grammar's, not reconstructible from
///   sibling pointers alone).
/// - `environment`: every begin/end-bearing environment node spans its whole
///   `\begin{…} … \end{…}` range and nests (a `generic_environment`'s
///   children include every environment kind), so nested environments
///   recurse and each gets its own definition in source order.
///
/// Preamble commands and math zones never emit (see the module doc).
fn walk_latex(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    let kind = node.kind();
    if matches!(
        kind,
        "part"
            | "chapter"
            | "section"
            | "subsection"
            | "subsubsection"
            | "paragraph"
            | "subparagraph"
    ) {
        out.push(element_def(
            "section",
            latex_section_name(&node, source),
            node,
            source,
            None,
        ));
    } else if LATEX_ENVIRONMENT_KINDS.contains(&kind) {
        if let Some(name) = latex_environment_name(&node, source) {
            out.push(element_def("environment", name, node, source, None));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_latex(child, source, out);
    }
}

/// Heading text of a sectioning node: the source text of its braced `text`
/// group (`curly_group` field `text`), whitespace-collapsed. If the heading
/// embeds nested commands (`\section{The \emph{Fast} Method}`) the raw
/// braced text is kept verbatim — word-collecting would silently drop the
/// emphasised words. With no usable braced heading (degenerate `\section`
/// with no argument) the command token itself names the element so the
/// structure report still shows a navigable row.
fn latex_section_name(section: &Node, source: &str) -> String {
    if let Some(text) = section.child_by_field_name("text") {
        // `curly_group` spans `{ … }`; the heading is the braced interior.
        let raw = &source[text.byte_range()];
        let inner = raw
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(raw);
        if !inner.contains('\\') {
            let plain = collapse_whitespace(inner);
            if !plain.is_empty() {
                return plain;
            }
        }
        let trimmed = inner.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    section
        .child_by_field_name("command")
        .map(|c| source[c.byte_range()].to_string())
        .unwrap_or_default()
}

/// Environment name: the `begin` child's `name` field — a `curly_group_text`
/// wrapping the bare environment word (`\begin{itemize}` → `itemize`). The
/// grammar marks `name` required on `begin`, so the `None` path is reserved
/// for malformed trees; an unusable name suppresses the element (matching
/// the XML walker's behaviour for a tagless element).
fn latex_environment_name(environment: &Node, source: &str) -> Option<String> {
    let name = environment
        .child_by_field_name("begin")?
        .child_by_field_name("name")?;
    let raw = &source[name.byte_range()];
    let inner = raw
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(raw);
    let name = collapse_whitespace(inner);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// =============================================================================
// Markdown — kind "heading" per ATX/setext heading, kind "code-block" per
// fenced/indented code block, kind "table" per pipe table
// =============================================================================

/// Markdown (`tree_sitter_md::LANGUAGE`, the BLOCK grammar of the
/// tree-sitter-grammars crate `tree-sitter-md 0.5.3`; serves .md/.markdown).
/// Three element kinds, all shape-given by the grammar (verified against
/// `tree-sitter-md-0.5.3/tree-sitter-markdown/src/node-types.json` — the
/// BLOCK grammar's node types, exposed by the crate's `NODE_TYPES_BLOCK`):
///
/// - `heading`: ATX headings are dedicated `atx_heading` nodes whose `#`
///   markers are separate `atx_h1_marker`…`atx_h6_marker` children and whose
///   text is the (optional) `heading_content` field — an `inline` node — so
///   taking only the content naturally strips the markers. Setext headings
///   are dedicated `setext_heading` nodes whose text is the `heading_content`
///   field (a `paragraph` node spanning the heading lines) and whose
///   `setext_h1_underline`/`setext_h2_underline` children are siblings of
///   that paragraph — so the heading NODE spans text + underline while the
///   NAME comes from the paragraph alone. Regions are the heading nodes
///   themselves, NOT content-spanning: unlike LaTeX (where the grammar nests
///   section content inside the sectioning node), the markdown block grammar
///   keeps the content in SIBLING nodes (`section` wrappers hold heading +
///   content as separate children), so a heading region is exactly its own
///   line(s).
/// - `code-block`: `fenced_code_block` nodes span open fence → close fence
///   (both `fenced_code_block_delimiter` children included); the info string
///   is an `info_string` child whose named `language` child (when present)
///   names the block (```rust → `rust`). Plain fences and
///   `indented_code_block` nodes (a dedicated kind in this grammar, so they
///   are included) carry no language and name `"code-block"`.
/// - `table`: `pipe_table` nodes span header → last row. The header row is a
///   `pipe_table_header` child holding one `pipe_table_cell` per column; the
///   name joins those cell texts with `" | "` (whitespace-collapsed). The
///   `pipe_table_delimiter_row` (the `|---|---|` line) is a separate child
///   and never contributes to the name.
///
/// Everything else (paragraphs, lists, block quotes, thematic breaks, HTML
/// blocks, link reference definitions, front matter) never emits — see the
/// module doc for the future-batch list. INLINE SPANS ARE NOT PARSED: the
/// crate exposes the block and inline grammars as two separate LanguageFns
/// (`LANGUAGE` / `INLINE_LANGUAGE`) with no combined language; `ParserPool`
/// wires the block grammar only, so `inline` nodes are opaque text and
/// heading names keep their raw inline spelling (emphasis markers, backticks
/// and link syntax inside a heading survive verbatim in the name).
fn walk_markdown(node: Node, source: &str, out: &mut Vec<DefinitionInfo>) {
    match node.kind() {
        "atx_heading" | "setext_heading" => {
            let name = markdown_heading_name(&node, source);
            if !name.is_empty() {
                out.push(element_def("heading", name, node, source, None));
            }
        }
        "fenced_code_block" => {
            let name = markdown_fenced_code_name(&node, source)
                .unwrap_or_else(|| "code-block".to_string());
            out.push(element_def("code-block", name, node, source, None));
        }
        "indented_code_block" => {
            // The block grammar emits dedicated nodes for 4-space-indented
            // code (verified against node-types.json) — include them under
            // the same kind, always named "code-block" (no info string
            // exists for the indented form).
            out.push(element_def(
                "code-block",
                "code-block".to_string(),
                node,
                source,
                None,
            ));
        }
        "pipe_table" => {
            let name = markdown_table_name(&node, source);
            if !name.is_empty() {
                out.push(element_def("table", name, node, source, None));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_markdown(child, source, out);
    }
}

/// Heading text: the `heading_content` field's source text, whitespace-
/// collapsed. For ATX headings the field is an `inline` node (the `#`
/// markers are separate children, so they never reach the name); for setext
/// headings it is a `paragraph` node spanning the heading lines (the
/// underline is a sibling child of the setext node, so it never reaches the
/// name either). Degenerate headings with no content (`#` alone) name the
/// element with their first token below; empty names suppress the element.
fn markdown_heading_name(heading: &Node, source: &str) -> String {
    match heading.child_by_field_name("heading_content") {
        Some(content) => collapse_whitespace(&source[content.byte_range()]),
        None => String::new(),
    }
}

/// Code-block name from the fenced form's `info_string` child: the info
/// string's first named `language` child (per node-types.json the
/// `info_string` rule parses a leading language token into a dedicated
/// `language` node, with `backslash_escape`/`entity_reference`/
/// `numeric_character_reference` as the other possible children). Returns
/// `None` when there is no info string or no language token — the caller
/// falls back to `"code-block"`.
fn markdown_fenced_code_name(block: &Node, source: &str) -> Option<String> {
    let mut cursor = block.walk();
    for child in block.children(&mut cursor) {
        if child.kind() == "info_string" {
            let mut info_cursor = child.walk();
            for token in child.children(&mut info_cursor) {
                if token.kind() == "language" {
                    let name = collapse_whitespace(&source[token.byte_range()]);
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            return None;
        }
    }
    None
}

/// Table name: the `pipe_table_header` child's `pipe_table_cell` texts,
/// whitespace-collapsed and joined with `" | "` in source order. The
/// delimiter row (`|---|---|`) is a separate `pipe_table_delimiter_row`
/// child and is ignored.
fn markdown_table_name(table: &Node, source: &str) -> String {
    let mut cursor = table.walk();
    for child in table.children(&mut cursor) {
        if child.kind() == "pipe_table_header" {
            let mut cells = Vec::new();
            let mut header_cursor = child.walk();
            for cell in child.children(&mut header_cursor) {
                if cell.kind() == "pipe_table_cell" {
                    cells.push(collapse_whitespace(&source[cell.byte_range()]));
                }
            }
            return cells.join(" | ");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    /// FIX-1a (F11): yaml `document-N` numbering runs over `document`
    /// children ONLY. An error-recovery child the grammar inserts INTO THE
    /// STREAM between documents must not shift the numbering of every later
    /// document (the pre-fix `enumerate()` over ALL stream children numbered
    /// the third real document `document-4` here).
    ///
    /// Fixture: an unterminated double-quote line between documents. The
    /// vendored grammar recovers with an ERROR child in the stream — verified
    /// child shape (and pinned below): document, document, ERROR, document.
    #[test]
    fn yaml_document_numbering_skips_error_recovery_children() {
        let src = "a: 1\n---\n\"\n---\nb: 2\n";
        let tree = parse(src, Language::Yaml).unwrap();

        // Sanity: the fixture really triggers a stream-level recovery child
        // BETWEEN documents. If the grammar's recovery shape ever changes,
        // re-derive this pin from the new shape.
        {
            let root = tree.root_node();
            let mut cursor = root.walk();
            let kinds: Vec<&str> = root.children(&mut cursor).map(|c| c.kind()).collect();
            assert_eq!(
                kinds,
                vec!["document", "document", "ERROR", "document"],
                "fixture no longer triggers stream-level error recovery between documents"
            );
        }

        let defs = extract_elements(Language::Yaml, &tree, src, None);
        let docs: Vec<&str> = defs
            .iter()
            .filter(|d| d.kind == "document")
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(
            docs,
            vec!["document-1", "document-2", "document-3"],
            "the three REAL documents are numbered 1..3 in source order, whatever recovery \
             nodes sit between them"
        );
        // The last document's content is intact too (its keys still emit).
        assert!(
            defs.iter().any(|d| d.kind == "key" && d.name == "b"),
            "the document after the recovery node still extracts: {defs:#?}"
        );
    }

    #[test]
    fn non_format_languages_return_empty() {
        let tree = parse("def foo(): pass", Language::Python).unwrap();
        assert!(extract_elements(Language::Python, &tree, "def foo(): pass", None).is_empty());
        let tree = parse("fn foo() {}", Language::Rust).unwrap();
        assert!(extract_elements(Language::Rust, &tree, "fn foo() {}", None).is_empty());
    }

    /// virtual-documents-v1: a NAMELESS host (the OOXML part walker passes
    /// `None`) keeps the pre-virtual-documents
    /// behavior — style bodies still emit their selector rows (the
    /// style-inner-css-v1 contract) but container-less, and the embedded
    /// reference scan collects NOTHING (no name to attribute edges to).
    #[test]
    fn nameless_host_keeps_style_rows_container_less_and_collects_no_refs() {
        let src = "<html><style>a{ color: red; }</style></html>";
        let tree = parse(src, Language::Html).unwrap();
        let (defs, refs, _) = extract_elements_inner(Language::Html, &tree, src, None);
        let selector = defs
            .iter()
            .find(|d| d.kind == "selector" && d.name == "a")
            .expect("style-inner CSS row still emits without a host label");
        assert!(
            selector.container.is_none(),
            "nameless host cannot name a virtual document: {selector:?}"
        );
        assert!(refs.is_empty(), "no host label → no attributable refs");

        // The SAME source WITH a host label: container + via-provenanced
        // loaded-element rows (here: none in the CSS — only the container
        // pin matters).
        let (with_host, _, _) = extract_elements_inner(Language::Html, &tree, src, Some("p.html"));
        let selector = with_host
            .iter()
            .find(|d| d.kind == "selector" && d.name == "a")
            .expect("style-inner CSS row with a host label");
        assert_eq!(selector.container.as_deref(), Some("p.html#style-1"));
    }

    #[test]
    fn markup_formats_emit_elements_with_id_and_class_naming() {
        // HTML: paired elements, a script_element, a style_element, an id
        // name, and a void (self-closing) element. The style element's CSS
        // body ALSO emits (style-inner-css-v1): `a{}` parses as a rule_set
        // whose selector row lands right after the owning `style` element.
        // The script is EXTERNAL (`src`), so no virtual JS document is
        // extracted and no `container` rows appear.
        let src = "<html><head><title>Page</title><style>a{}</style></head>\
                   <body><script src=\"app.js\"></script><br/></body></html>";
        let tree = parse(src, Language::Html).unwrap();
        let elements = extract_elements(Language::Html, &tree, src, Some("page.html"));
        let named: Vec<(String, String)> = elements
            .iter()
            .map(|e| (e.kind.clone(), e.name.clone()))
            .collect();
        assert_eq!(
            named,
            vec![
                ("element".to_string(), "html".to_string()),
                ("element".to_string(), "head".to_string()),
                ("element".to_string(), "title".to_string()),
                ("element".to_string(), "style".to_string()),
                ("selector".to_string(), "a".to_string()),
                ("element".to_string(), "body".to_string()),
                ("element".to_string(), "script".to_string()),
                ("element".to_string(), "br".to_string()),
            ]
        );
        // The external script_element emits as a plain element and its `src`
        // reference is doclinks' business — no inner JS rows (script-inner-js-v1
        // skips external scripts); the only non-`element` kind is the
        // inner-CSS selector row.

        // XML: id-naming and class-naming on nested elements.
        let src = "<?xml version=\"1.0\"?><root id=\"r\"><child/></root>";
        let tree = parse(src, Language::Xml).unwrap();
        let elements = extract_elements(Language::Xml, &tree, src, Some("p.xml"));
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["root#r", "child"]);

        // CSS: selectors and at-rules, with the media-query inner rule
        // surfacing as its own nested selector.
        let src = "body { color: red; }\n@media (min-width: 1px) { b { color: blue } }\n";
        let tree = parse(src, Language::Css).unwrap();
        let elements = extract_elements(Language::Css, &tree, src, None);
        let kinds: Vec<&str> = elements.iter().map(|e| e.kind.as_str()).collect();
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(kinds, vec!["selector", "at-rule", "selector"]);
        assert_eq!(names, vec!["body", "@media", "b"]);
    }

    #[test]
    fn json_array_items_are_not_definitions() {
        let src = r#"{"items": [1, {"a": 2}]}"#;
        let tree = parse(src, Language::Json).unwrap();
        let elements = extract_elements(Language::Json, &tree, src, None);
        let names: Vec<&str> = elements.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["items", "a"], "array scalars are not elements");
        // The outer key spans the whole array; the nested key only its pair.
        assert_eq!(elements[0].line_start, 1);
        assert_eq!(elements[0].line_end, 1);
        // The nested pair's slice is exactly its `"a": 2` region (the object's
        // closing brace belongs to the object, not the pair).
        let nested = &elements[1];
        let slice = &src[nested.byte_start.unwrap() as usize..nested.byte_end.unwrap() as usize];
        assert_eq!(slice, r#""a": 2"#);
    }

    #[test]
    fn yaml_documents_are_numbered_in_source_order() {
        let src = "a: 1\n---\nb: 2\n";
        let tree = parse(src, Language::Yaml).unwrap();
        let elements = extract_elements(Language::Yaml, &tree, src, None);
        let named: Vec<(String, String)> = elements
            .iter()
            .map(|e| (e.kind.clone(), e.name.clone()))
            .collect();
        assert_eq!(
            named,
            vec![
                ("document".to_string(), "document-1".to_string()),
                ("key".to_string(), "a".to_string()),
                ("document".to_string(), "document-2".to_string()),
                ("key".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn byte_spans_slice_back_to_the_element() {
        let src = "x = { a = 1, b = 2 }\n[table]\ny = 3\n";
        let tree = parse(src, Language::Toml).unwrap();
        let elements = extract_elements(Language::Toml, &tree, src, None);
        for e in &elements {
            let (start, end) = match (e.byte_start, e.byte_end) {
                (Some(s), Some(en)) => (s as usize, en as usize),
                other => panic!("element {:?} must carry byte spans, got {other:?}", e.name),
            };
            assert!(end > start, "element {:?} must be non-empty", e.name);
            let slice = &src[start..end];
            assert!(
                slice.starts_with(e.name.as_str()) || slice.starts_with('['),
                "slice for {:?} must start with the element's first token: {slice:?}",
                e.name
            );
        }
        let kinds: Vec<&str> = elements.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["key", "key", "key", "section", "key"]);
    }

    #[test]
    fn markdown_headings_code_blocks_and_tables() {
        // ATX names strip the `#` markers (separate grammar children); the
        // ```rust fence names by its info-string language token; the plain
        // fence and the indented block fall back to "code-block"; the table
        // name joins header cells with " | " and ignores the delimiter row.
        let src = "# Top\n\n```rust\nfn main() {}\n```\n\n```\nplain\n```\n\n| Col A | Col B |\n| ----- | ----- |\n| a     | b     |\n";
        let tree = parse(src, Language::Markdown).unwrap();
        let elements = extract_elements(Language::Markdown, &tree, src, None);
        let sequence: Vec<(String, String)> = elements
            .iter()
            .map(|e| (e.kind.clone(), e.name.clone()))
            .collect();
        assert_eq!(
            sequence,
            vec![
                ("heading".to_string(), "Top".to_string()),
                ("code-block".to_string(), "rust".to_string()),
                ("code-block".to_string(), "code-block".to_string()),
                ("table".to_string(), "Col A | Col B".to_string()),
            ]
        );

        // The heading region is the heading node only (NOT content-spanning):
        // exactly the `# Top` line.
        let heading = &elements[0];
        assert_eq!(heading.line_start, 1);
        assert_eq!(heading.line_end, 1);
        let slice = &src[heading.byte_start.unwrap() as usize..heading.byte_end.unwrap() as usize];
        // The heading node's byte range ends with the line's newline (the
        // line-end attribution trims that phantom line; the byte span does
        // not).
        assert_eq!(slice, "# Top\n");

        // The fenced code-block region spans BOTH fence lines, and its slice
        // opens with the opening fence.
        let code = &elements[1];
        assert_eq!(code.line_start, 3);
        assert_eq!(code.line_end, 5);
        let slice = &src[code.byte_start.unwrap() as usize..code.byte_end.unwrap() as usize];
        assert!(slice.starts_with("```rust"), "slice: {slice:?}");

        // The table region spans header through the last body row.
        let table = &elements[3];
        assert_eq!(table.line_start, 11);
        assert_eq!(table.line_end, 13);
        let slice = &src[table.byte_start.unwrap() as usize..table.byte_end.unwrap() as usize];
        assert!(slice.starts_with("| Col A |"), "slice: {slice:?}");
    }

    #[test]
    fn elements_carry_byte_spans_and_code_languages_do_not() {
        let json_src = r#"{"k": 1}"#;
        let tree = parse(json_src, Language::Json).unwrap();
        let elements = extract_elements(Language::Json, &tree, json_src, None);
        assert_eq!(elements.len(), 1);
        assert!(elements[0].byte_start.is_some() && elements[0].byte_end.is_some());
        assert!(elements[0].definition_line.is_none());
        assert!(elements[0].container.is_none());

        let tree = parse("fn foo() {}", Language::Rust).unwrap();
        // (code-language path returns empty — byte spans stay None everywhere
        // until the code-language batch populates them)
        assert!(extract_elements(Language::Rust, &tree, "fn foo() {}", None).is_empty());
    }

    // =========================================================================
    // VD-2 — budget, depth cap, malformed content (direct helper probes)
    // =========================================================================

    /// The spec pins both caps as constants; they are the contract the
    /// warning messages interpolate.
    #[test]
    fn embed_caps_are_the_spec_values() {
        assert_eq!(MAX_EMBED_DEPTH, 8);
        assert_eq!(MAX_VIRTUAL_DOCS_PER_FILE, 256);
    }

    /// Budget pin (testability design): `EmbedBudget::limit` is injected —
    /// a direct walk with a limit of 2 lets the FIRST TWO virtual documents
    /// (here: one script + one style, slots are consumed in source order
    /// across ALL kinds) become `#script-1`/`#style-1` and skips the rest
    /// with exactly ONE budget warning. The budget counts ALL virtual
    /// documents of the file, across all levels (scripts + styles +
    /// foreignObject documents).
    #[test]
    fn budget_exhaustion_skips_documents_and_warns_once() {
        let src = "<html><body>\
                   <script>function a() { return 1; }</script>\
                   <style>.s { color: red; }</style>\
                   <script>function b() { return 2; }</script>\
                   <script>function c() { return 3; }</script>\
                   </body></html>";
        let tree = parse(src, Language::Html).unwrap();
        let mut state = WalkState::new(Some("budget.html"));
        state.budget.limit = 2; // the injected, tiny budget
        let mut out = Vec::new();
        walk_html(tree.root_node(), src, &mut state, &mut out, 0);

        // Documents 1-2 processed (the script and the style), documents 3+
        // (scripts b and c) skipped.
        assert!(
            out.iter().any(|d| d.kind == "function"
                && d.name == "a"
                && d.container.as_deref() == Some("budget.html#script-1")),
            "the first script must process: {out:#?}"
        );
        assert!(
            out.iter().any(|d| d.kind == "selector"
                && d.name == ".s"
                && d.container.as_deref() == Some("budget.html#style-1")),
            "the style must process: {out:#?}"
        );
        assert!(
            !out.iter().any(|d| d.name == "b"),
            "the second script is beyond the budget and must not emit: {out:#?}"
        );
        assert!(
            !out.iter().any(|d| d.name == "c"),
            "the third script is beyond the budget and must not emit: {out:#?}"
        );
        assert_eq!(state.warnings.len(), 1, "exactly ONE budget warning");
        assert!(
            state.warnings[0].contains("budget"),
            "the warning names the budget: {:?}",
            state.warnings[0]
        );
        assert!(
            state.warnings[0].contains("budget.html"),
            "the warning names the host: {:?}",
            state.warnings[0]
        );
    }

    /// The budget applies at EVERY level: the foreignObject documents
    /// themselves consume slots too (they are virtual documents like the
    /// scripts they contain), and a refused document's subtree stays
    /// skipped — its inner scripts must not leak into host-level `#script-N`
    /// numbering.
    #[test]
    fn budget_counts_foreign_object_documents() {
        let src = "<svg><foreignObject><div><p>x</p></div></foreignObject></svg>";
        let tree = parse(src, Language::Xml).unwrap();
        let mut state = WalkState::new(Some("fo.svg"));
        state.budget.limit = 0; // no documents affordable at all
        let mut out = Vec::new();
        walk_xml(tree.root_node(), src, &mut state, &mut out, 0);

        // The host element rows for svg/foreignObject emit (the walk itself
        // is untouched), but the content is owned by NO document and not
        // walked by the host either.
        assert!(
            out.iter().any(|d| d.kind == "element" && d.name == "svg"),
            "the host element rows still emit: {out:#?}"
        );
        assert!(
            !out.iter().any(|d| d.name == "div"),
            "the budget-refused document's subtree stays skipped: {out:#?}"
        );
        assert!(
            !out.iter().any(|d| d.container.is_some()),
            "no virtual document was affordable: {out:#?}"
        );
        assert_eq!(state.warnings.len(), 1);
    }

    /// Malformed nested content (direct helper probe): a re-parse carrying
    /// error nodes emits NOTHING for that document, warns once naming it,
    /// and the `#fo-N` number is given back — the next document takes it.
    #[test]
    fn malformed_foreign_object_content_is_skipped_with_warning_and_no_number() {
        let mut budget = EmbedBudget::new(Some("broken.html"));
        let mut warnings = Vec::new();
        let mut defs = Vec::new();
        let mut refs = Vec::new();

        // `<div><p>unclosed` — no closing tags (verified has_error shape).
        process_foreign_object_content(
            "<div><p>unclosed",
            0,
            0,
            0,
            "broken.html",
            &mut budget,
            &mut warnings,
            &mut defs,
            &mut refs,
        );
        assert!(
            defs.is_empty(),
            "nothing emitted for the broken doc: {defs:#?}"
        );
        assert_eq!(refs.len(), 0, "no references either");
        assert_eq!(warnings.len(), 1, "one warning: {warnings:?}");
        assert!(
            warnings[0].contains("broken.html#fo-1"),
            "the warning names the would-be document: {:?}",
            warnings[0]
        );
        assert_eq!(budget.fo_no, 0, "the number was given back");
        assert_eq!(budget.docs, 0, "the slot was given back");

        // The NEXT document takes #fo-1 (continuity pin).
        let mut defs2 = Vec::new();
        process_foreign_object_content(
            "<div id=\"ok\"><p>fine</p></div>",
            0,
            0,
            0,
            "broken.html",
            &mut budget,
            &mut warnings,
            &mut defs2,
            &mut refs,
        );
        assert!(
            defs2
                .iter()
                .any(|d| d.name == "div#ok" && d.container.as_deref() == Some("broken.html#fo-1")),
            "the next fo takes #fo-1: {defs2:#?}"
        );
        assert_eq!(warnings.len(), 1, "still exactly the one malformed warning");
    }

    /// Empty/whitespace content: nothing, consumes nothing, no warning.
    #[test]
    fn whitespace_foreign_object_content_consumes_nothing() {
        let mut budget = EmbedBudget::new(Some("empty.html"));
        let mut warnings = Vec::new();
        let mut defs = Vec::new();
        let mut refs = Vec::new();
        process_foreign_object_content(
            "  \n\t ",
            0,
            0,
            0,
            "empty.html",
            &mut budget,
            &mut warnings,
            &mut defs,
            &mut refs,
        );
        assert!(defs.is_empty() && refs.is_empty() && warnings.is_empty());
        assert_eq!(budget.fo_no, 0, "no number consumed");
        assert_eq!(budget.docs, 0, "no slot consumed");
    }
}
