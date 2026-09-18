//! symbol-fidelity-v1 — the executable spec for symbol line-span fidelity.
//!
//! CONTRACT UNDER TEST (this suite is the spec; the extractor is fixed in the NEXT step and
//! is expected to be RED against this suite today):
//!
//! 1. `DefinitionInfo::line_start` (types.rs:1385) must be the FIRST line of the symbol's
//!    attached trivia region: any decorator/attribute/annotation node, plus an
//!    IMMEDIATELY-CONTIGUOUS comment block above (no blank line between the trivia and the
//!    definition). `line_end` stays the last line of the symbol.
//! 2. DETACHED trivia (blank line between the comment block and the definition) must NOT be
//!    included — `line_start` stays at the definition (or at attached decorators).
//! 3. Wrapper-node languages must use the WRAPPER's span:
//!    - Python `decorated_definition` (tree-sitter-python 0.23.6, field `definition`)
//!    - TS/JS `export_statement` when it wraps exactly ONE declaration
//!      (tree-sitter-typescript 0.23.2: `export_statement = SEQ(REPEAT(decorator), 'export',
//!      declaration)` — decorators above `export` are INSIDE the wrapper).
//! 4. `signature` must remain the clean signature view: it starts with the definition keyword
//!    where the language has one (`def`/`fn`/`func`/`function`/`fun`/`let`), and never carries
//!    decorators/attributes/annotations/doc comments (no leading `@`, `#[`, `[`, `///`, `/*`).
//! 5. (`definition_line` — the declaration-keyword line — is a FUTURE field on
//!    `DefinitionInfo`; it lands with the fix step and is deliberately NOT asserted here.)
//!
//! CURRENT BEHAVIOUR (what the fix must change):
//! `collect_definitions` (extractor.rs:1960-2071) derives `line_start`/`line_end` directly from
//! `node.start_position()`/`end_position()` (extractor.rs:2014-2015) of the node matched by
//! `classify_definition_node` (extractor.rs:2996-3039). The table has NO wrapper kinds, so:
//!   - Python `decorated_definition` is recursed THROUGH (decorators clipped),
//!   - Rust `attribute_item`/`line_comment` doc comments are sibling nodes (clipped),
//!   - TS/JS decorators above `export` are siblings of `export_statement` (clipped), and the
//!     inner `function_declaration`/`class_declaration` is what gets emitted,
//!   - Java/Kotlin/Swift/C#/PHP/Scala annotations are children INSIDE the declaration node, so
//!     `line_start` over-lands on the annotation and the signature view picks the modifiers
//!     node (their `modifiers`/`attribute_list`/`annotation` kinds are not in the
//!     `extract_def_signature` skip list, extractor.rs:3204-3221),
//!   - C/C++/Go/Ruby/Lua/Luau/OCaml/Elixir doc comments are siblings (clipped).
//! In-repo precedent for unwrapping wrapper nodes: tldr-cli contracts/specs.rs:317-348
//! (`decorated_definition` → `child_by_field_name("definition")`).
//!
//! GRAMMAR FACTS PINNED FOR THE FIX (verified against node-types.json / grammar.json in the
//! cargo registry, `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`):
//!   - python 0.23.6: `decorated_definition` (fields: definition) wraps `function_definition` /
//!     `class_definition`; `decorator` named children of the wrapper; `comment` is a SIBLING.
//!   - rust 0.23.3: `function_item` (no attribute field); `attribute_item` and doc
//!     `line_comment` (fields: doc) are SIBLINGS in `source_file`.
//!   - typescript 0.23.2 (also used for JavaScript — parser.rs:134-135 routes
//!     `Language::JavaScript` to `LANGUAGE_TYPESCRIPT`): `export_statement` fields
//!     `declaration`/`decorator`; `class_declaration` fields include `decorator` (decorators
//!     written directly above a non-exported `class` land INSIDE it); decorated class-body
//!     methods parse as `SEQ(repeat(decorator), method_definition)` inside `class_body` — the
//!     decorator is a SIBLING of `method_definition`. There is NO `decorated_definition` node.
//!   - go 0.23.4: `function_declaration`/`method_declaration`; `comment` sibling.
//!   - java 0.23.5: `method_declaration = SEQ(modifiers?, _method_header, body)` — annotations
//!     (`marker_annotation`/`annotation`) live inside the `modifiers` child → node starts on
//!     the annotation; `line_comment`/`block_comment` siblings.
//!   - kotlin-ng 1.1.0: `function_declaration = SEQ(modifiers?, 'fun', ...)` → annotation
//!     inside; `line_comment`/`multiline_comment` siblings.
//!   - swift 0.7.1: `function_declaration = SEQ(_bodyless_function_declaration, body)`,
//!     `_bodyless_function_declaration` starts with optional `modifiers` whose alternatives
//!     include `attribute` → `@objc` inside the declaration node.
//!   - c-sharp 0.23.1: `method_declaration = SEQ(attribute_list*, modifier*, ...)` → `#[…]`-style
//!     `[Fact]` attribute_list inside the declaration node.
//!   - php 0.23.11: `function_definition` has an `attributes` FIELD (attribute_list inside the
//!     declaration node); `comment` sibling.
//!   - scala 0.24.0: `function_definition = SEQ(_function_declaration, body)`,
//!     `_function_declaration = SEQ(annotation*, modifiers?, 'def', ...)` → annotation inside.
//!   - c 0.23.4 / cpp 0.23.4: `function_definition`; `comment` sibling.
//!   - lua 0.2.0 / luau 1.2.0: global `function name()` parses as `function_declaration`
//!     (fields: body/name/parameters); `comment` sibling.
//!   - elixir 0.3.4: `def`/`defp`/`defmodule` parse as `call` nodes (field `target`);
//!     `try_elixir_call_definition` (extractor.rs:2908-2967) derives the span from the call
//!     node; `comment` sibling.
//!   - ocaml 0.24.2 (grammars/ocaml): top-level `let` parses as `value_definition` (child
//!     `let_binding`); `comment` sibling.
//!
//! EXPECTED STATE OF THIS SUITE TODAY: the attached-trivia cases (positive) are RED — that
//! failure matrix is the deliverable of this step. The detached-trivia negatives and the
//! already-wrapper-covered cases (e.g. TS `export function`) are the green regression guards.
//! Nothing here asserts `definition_line` (future field, lands with the fix).

use std::fs;

use tempfile::TempDir;
use tldr_core::types::DefinitionInfo;
use tldr_core::{get_code_structure, Language};

// =============================================================================
// Helpers: fixture → public structure extraction → span/signature assertions
// =============================================================================

/// Write `content` to `<tempdir>/<filename>` and run the PUBLIC structure extraction on the
/// file with an EXPLICIT language (never autodetection):
/// `get_code_structure(path, language, 0, None)` (extractor.rs:32-37, re-exported at the
/// crate root, lib.rs:102; single-file mode honors the caller language, extractor.rs:255).
fn extract_definitions(filename: &str, content: &str, language: Language) -> Vec<DefinitionInfo> {
    let dir = TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
    let path = dir.path().join(filename);
    fs::write(&path, content)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: failed to write fixture {filename}: {e}"));

    let structure = get_code_structure(&path, language, 0, None)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: extraction failed for {filename}: {e}"));

    assert_eq!(
        structure.files.len(),
        1,
        "symbol-fidelity-v1 [{filename}]: expected exactly one FileStructure, got {}",
        structure.files.len()
    );
    structure.files[0].definitions.clone()
}

/// Find a definition by exact name, dumping the full definition list on miss so a RED run
/// reads as a report (this is the "cannot even find the symbol" surface).
fn find_def<'a>(defs: &'a [DefinitionInfo], file: &str, name: &str) -> &'a DefinitionInfo {
    defs.iter().find(|d| d.name == name).unwrap_or_else(|| {
        panic!(
            "symbol-fidelity-v1 [{file}]: symbol `{name}` not found in definitions.\n\
             Extracted definitions ({})=\n{defs:#?}",
            defs.len()
        )
    })
}

/// EXACT span assertion: the failure message is the actual-vs-expected report row.
fn assert_span(
    def: &DefinitionInfo,
    file: &str,
    symbol: &str,
    expected_start: u32,
    expected_end: u32,
) {
    assert!(
        def.line_start == expected_start && def.line_end == expected_end,
        "symbol-fidelity-v1 [{file}] `{symbol}`: expected line span \
         {expected_start}..{expected_end}, got {}..{} (kind=`{}`)",
        def.line_start,
        def.line_end,
        def.kind
    );
}

/// Signature must remain the clean view: starts with the language's definition keyword.
fn assert_signature_starts_with(def: &DefinitionInfo, file: &str, symbol: &str, prefix: &str) {
    assert!(
        def.signature.starts_with(prefix),
        "symbol-fidelity-v1 [{file}] `{symbol}`: signature must stay clean and start with \
         {prefix:?}, got {:?}",
        def.signature
    );
}

/// Signature must not carry decorators/attributes/annotations/doc comments (languages whose
/// declaration has no single leading keyword: Java/C/C#/C/C++/TS-methods/TS-classes).
fn assert_signature_clean(def: &DefinitionInfo, file: &str, symbol: &str, must_contain: &str) {
    let sig = def.signature.trim_start();
    for marker in ["@", "//", "///", "/*", "*", "#[", "#", "["] {
        assert!(
            !sig.starts_with(marker),
            "symbol-fidelity-v1 [{file}] `{symbol}`: signature must stay clean (no \
             decorators/attributes/doc comments), but it starts with {marker:?}: {sig:?}"
        );
    }
    assert!(
        sig.contains(must_contain),
        "symbol-fidelity-v1 [{file}] `{symbol}`: signature must contain {must_contain:?}, \
         got {sig:?}"
    );
}

// =============================================================================
// Python — tree-sitter-python 0.23.6, wrapper kind `decorated_definition`
// =============================================================================

#[test]
fn python_attached_decorators_positive() {
    // L1 blank | L2 @deco_a | L3 @deco2(arg) | L4 def foo(): | L5 docstring | L6 return
    let defs = extract_definitions(
        "foo.py",
        r#"
@deco_a
@deco2(arg)
def foo():
    """Docstring."""
    return 42
"#,
        Language::Python,
    );
    let foo = find_def(&defs, "foo.py", "foo");
    // DESIRED: wrapper `decorated_definition` span + trivia = decorator block (L2..L6).
    // TODAY: function_definition is emitted directly (wrapper recursed through) → 4..6.
    assert_span(foo, "foo.py", "foo", 2, 6);
    // Signature must stay the clean `def` view (no decorators, no docstring).
    assert_signature_starts_with(foo, "foo.py", "foo", "def foo():");
}

#[test]
fn python_attached_decorator_on_method_positive() {
    // L1 blank | L2 class | L3 @property | L4 def size | L5 return
    let defs = extract_definitions(
        "widget.py",
        r#"
class Widget:
    @property
    def size(self):
        return 1
"#,
        Language::Python,
    );
    let size = find_def(&defs, "widget.py", "size");
    assert_span(size, "widget.py", "size", 3, 5);
    assert_signature_starts_with(size, "widget.py", "size", "def size(self):");
}

#[test]
fn python_detached_comment_negative() {
    // L1 blank | L2 comment | L3 blank | L4 def bar(): | L5 return
    let defs = extract_definitions(
        "bar.py",
        r#"
# detached note about bar

def bar():
    return 1
"#,
        Language::Python,
    );
    let bar = find_def(&defs, "bar.py", "bar");
    // Detached comment must NOT be absorbed: def stays at L4..L5.
    assert_span(bar, "bar.py", "bar", 4, 5);
    assert_signature_starts_with(bar, "bar.py", "bar", "def bar():");
}

// =============================================================================
// Rust — tree-sitter-rust 0.23.3, `attribute_item` + doc `line_comment` are siblings
// =============================================================================

#[test]
fn rust_attached_doc_and_attributes_positive() {
    // L1 blank | L2 /// doc | L3 #[derive] | L4 #[test] | L5 fn | L6 body | L7 }
    let defs = extract_definitions(
        "sample.rs",
        r#"
/// Doc comment for foo.
#[derive(Debug)]
#[test]
fn foo() -> u32 {
    42
}
"#,
        Language::Rust,
    );
    let foo = find_def(&defs, "sample.rs", "foo");
    // DESIRED: doc comment + contiguous attribute block included → L2..L7.
    // TODAY: function_item starts at `fn` → 5..7.
    assert_span(foo, "sample.rs", "foo", 2, 7);
    assert_signature_starts_with(foo, "sample.rs", "foo", "fn foo() -> u32 {");
}

#[test]
fn rust_detached_comment_negative() {
    // L1 blank | L2 // note | L3 blank | L4 fn | L5 body | L6 }
    let defs = extract_definitions(
        "plain.rs",
        r#"
// detached note

fn plain() -> u32 {
    1
}
"#,
        Language::Rust,
    );
    let plain = find_def(&defs, "plain.rs", "plain");
    assert_span(plain, "plain.rs", "plain", 4, 6);
    assert_signature_starts_with(plain, "plain.rs", "plain", "fn plain() -> u32 {");
}

// =============================================================================
// TypeScript — tree-sitter-typescript 0.23.2, wrapper kind `export_statement`
// (Language::JavaScript parses with the SAME grammar — parser.rs:134-135)
// =============================================================================

#[test]
fn typescript_attached_class_and_method_decorators_positive() {
    // L1 blank | L2-L4 @Component({...}) | L5 export class Foo { | L6 @Input() | L7 render | L8 }
    let defs = extract_definitions(
        "component.ts",
        r#"
@Component({
  selector: "app-foo",
})
export class Foo {
  @Input()
  render(): void {}
}
"#,
        Language::TypeScript,
    );
    let foo = find_def(&defs, "component.ts", "Foo");
    // DESIRED: `export_statement` wrapper span (its `decorator` field holds the @Component
    // block, grammar: SEQ(REPEAT(decorator), 'export', declaration)) → L2..L8.
    // TODAY: inner class_declaration emitted → 5..8.
    assert_span(foo, "component.ts", "Foo", 2, 8);
    assert_signature_clean(foo, "component.ts", "Foo", "class Foo");

    let render = find_def(&defs, "component.ts", "render");
    // DESIRED: decorated method's trivia region starts at @Input() → L6..L7.
    // TODAY: method_definition emitted alone → 7..7 (decorator is a sibling in class_body).
    assert_span(render, "component.ts", "render", 6, 7);
    assert_signature_clean(render, "component.ts", "render", "render(): void");
}

#[test]
fn typescript_export_function_wrapper_green_guard() {
    // L1 blank | L2 export function bar(): number { | L3 return | L4 }
    let defs = extract_definitions(
        "util.ts",
        r#"
export function bar(): number {
  return 1;
}
"#,
        Language::TypeScript,
    );
    let bar = find_def(&defs, "util.ts", "bar");
    // Wrapper span == declaration span here, so this is already correct today: 2..4.
    assert_span(bar, "util.ts", "bar", 2, 4);
    assert_signature_starts_with(bar, "util.ts", "bar", "function bar(): number {");
}

#[test]
fn typescript_detached_comment_negative() {
    // L1 blank | L2 // note | L3 blank | L4 export function note | L5 return | L6 }
    let defs = extract_definitions(
        "note.ts",
        r#"
// detached note

export function note(): number {
  return 2;
}
"#,
        Language::TypeScript,
    );
    let note = find_def(&defs, "note.ts", "note");
    assert_span(note, "note.ts", "note", 4, 6);
    assert_signature_starts_with(note, "note.ts", "note", "function note(): number {");
}

// =============================================================================
// JavaScript — same grammar as TS (LANGUAGE_TYPESCRIPT), JSDoc block is a `comment` sibling
// =============================================================================

#[test]
fn javascript_attached_jsdoc_positive() {
    // L1 blank | L2-L4 JSDoc | L5 export function add | L6 return | L7 }
    let defs = extract_definitions(
        "math.js",
        r#"
/**
 * Adds two numbers.
 */
export function add(a, b) {
  return a + b;
}
"#,
        Language::JavaScript,
    );
    let add = find_def(&defs, "math.js", "add");
    // DESIRED: contiguous JSDoc above the export wrapper → L2..L7. TODAY: 5..7.
    assert_span(add, "math.js", "add", 2, 7);
    assert_signature_starts_with(add, "math.js", "add", "function add(a, b) {");
}

#[test]
fn javascript_detached_comment_negative() {
    // L1 blank | L2 // note | L3 blank | L4 function lone | L5 return | L6 }
    let defs = extract_definitions(
        "plain.js",
        r#"
// detached note

function lone(a, b) {
  return a + b;
}
"#,
        Language::JavaScript,
    );
    let lone = find_def(&defs, "plain.js", "lone");
    assert_span(lone, "plain.js", "lone", 4, 6);
    assert_signature_starts_with(lone, "plain.js", "lone", "function lone(a, b) {");
}

// =============================================================================
// Embedded scripts (script-inner-js-v1) — an inline <script>'s symbols ride
// the HOST file's definition table as a virtual JS document: same JS spans
// and signatures, translated onto host-file lines, provenance in `container`
// =============================================================================

/// HTML host with ONE inline script whose function carries an attached JSDoc
/// comment — the case that exercises every translated field at once:
/// the trivia-widened line span, the declaration line, the byte span (the
/// declaration NODE, not the trivia), the signature, the container.
const HTML_VIRTUAL_DOC_FIXTURE: &str = "<!DOCTYPE html>\n\
                                        <html>\n\
                                        <body>\n\
                                        <script>\n\
                                        /** Adds two numbers. */\n\
                                        function add(a, b) {\n\
                                        \x20 return a + b;\n\
                                        }\n\
                                        </script>\n\
                                        </body>\n\
                                        </html>\n";

#[test]
fn html_inline_script_symbols_carry_virtual_document_provenance() {
    // L1 <!DOCTYPE html> | L2 <html> | L3 <body> | L4 <script>
    // L5 /** Adds two numbers. */ | L6 function add(a, b) { | L7 return | L8 }
    // L9 </script> | L10 </body> | L11 </html>
    let defs = extract_definitions("virtual.html", HTML_VIRTUAL_DOC_FIXTURE, Language::Html);

    let add = find_def(&defs, "virtual.html", "add");
    // The JS trivia semantics survive translation: the attached JSDoc widens
    // the LINE span (inner lines 2..5 → FILE lines 5..8, line_base = 3) and
    // `definition_line` stays the `function` keyword line (inner 3 → 6).
    assert_span(add, "virtual.html", "add", 5, 8);
    assert_eq!(
        add.definition_line,
        Some(6),
        "definition_line must translate onto the file's declaration line"
    );
    // Provenance: the virtual document name, `<hostfilename>#script-1`.
    assert_eq!(
        add.container.as_deref(),
        Some("virtual.html#script-1"),
        "embedded-script definitions must carry their virtual document's name"
    );
    // The signature stays the clean JS view.
    assert_signature_starts_with(add, "virtual.html", "add", "function add(a, b) {");
    // The byte span is the declaration NODE re-based onto the host file, so
    // full_source[bs..be] is the exact JS source inside the HTML (the JSDoc
    // comment above it is NOT part of the byte span).
    let (bs, be) = (
        add.byte_start
            .expect("virtual-script defs carry byte spans") as usize,
        add.byte_end.expect("virtual-script defs carry byte spans") as usize,
    );
    assert_eq!(
        &HTML_VIRTUAL_DOC_FIXTURE[bs..be],
        "function add(a, b) {\n  return a + b;\n}",
        "byte span must slice back to the exact JS source in the host file"
    );

    // Host element rows stay container-less: `add` is the only container row.
    assert!(
        defs.iter()
            .filter(|d| d.kind == "element")
            .all(|d| d.container.is_none()),
        "host element definitions must not carry a container"
    );
}

// =============================================================================
// Embedded styles (virtual-documents-v1) — a <style> body's selector rows
// ride the HOST file's definition table as a named virtual document
// `<host>#style-N`, mirroring the script containers above
// =============================================================================

/// HTML host with ONE embedded style: its selector carries the virtual
/// document's name `styled.html#style-1` while the host element rows stay
/// container-less, and the byte span slices back to the exact rule text in
/// the host file (the style-inner spans were already global; the container
/// is what makes the rows navigable AS a virtual document).
#[test]
fn html_embedded_style_selectors_carry_virtual_document_provenance() {
    const FIXTURE: &str = "<!DOCTYPE html>\n\
                           <html>\n\
                           <head>\n\
                           <style>\n\
                           .hero { color: red; }\n\
                           </style>\n\
                           </head>\n\
                           <body></body>\n\
                           </html>\n";
    let defs = extract_definitions("styled.html", FIXTURE, Language::Html);

    let hero = defs
        .iter()
        .find(|d| d.kind == "selector" && d.name == ".hero")
        .expect("the embedded style's selector is a definition of the host file");
    // Provenance: the virtual document name, `<hostfilename>#style-1` —
    // the exact naming the style's outbound-reference rows use in `via`
    // (see `ImportInfo::via`).
    assert_eq!(
        hero.container.as_deref(),
        Some("styled.html#style-1"),
        "embedded-style definitions must carry their virtual document's name"
    );
    // Span fidelity: full-file line and an exact byte slice-back.
    assert_span(hero, "styled.html", "selector:.hero", 5, 5);
    let (bs, be) = (
        hero.byte_start
            .expect("virtual-style defs carry byte spans") as usize,
        hero.byte_end.expect("virtual-style defs carry byte spans") as usize,
    );
    assert_eq!(
        &FIXTURE[bs..be],
        ".hero { color: red; }",
        "byte span must slice back to the exact CSS source in the host file"
    );

    // Host element rows stay container-less.
    assert!(
        defs.iter()
            .filter(|d| d.kind == "element")
            .all(|d| d.container.is_none()),
        "host element definitions must not carry a container"
    );
}

// =============================================================================
// Java — tree-sitter-java 0.23.5, annotations live INSIDE method_declaration (modifiers child)
// =============================================================================

#[test]
fn java_attached_javadoc_and_annotations_positive() {
    // L1 blank | L2 class | L3-L5 javadoc | L6 @Override | L7 @SuppressWarnings | L8 method
    // L9 return | L10 } | L11 }
    let defs = extract_definitions(
        "Foo.java",
        r#"
public class Foo {
    /**
     * Computes the value.
     */
    @Override
    @SuppressWarnings("x")
    public int compute(int x) {
        return x;
    }
}
"#,
        Language::Java,
    );
    let compute = find_def(&defs, "Foo.java", "compute");
    // DESIRED: javadoc block + annotation block (contiguous) → L3..L10.
    // TODAY: method_declaration starts at its modifiers child (@Override) → 6..10.
    assert_span(compute, "Foo.java", "compute", 3, 10);
    assert_signature_clean(compute, "Foo.java", "compute", "compute(int x)");
}

#[test]
fn java_detached_javadoc_negative() {
    // L1 blank | L2 class | L3-L5 javadoc | L6 blank | L7 method | L8 return | L9 } | L10 }
    let defs = extract_definitions(
        "Plain.java",
        r#"
public class Plain {
    /**
     * Detached javadoc.
     */

    public int lone(int x) {
        return x;
    }
}
"#,
        Language::Java,
    );
    let lone = find_def(&defs, "Plain.java", "lone");
    assert_span(lone, "Plain.java", "lone", 7, 9);
    assert_signature_clean(lone, "Plain.java", "lone", "lone(int x)");
}

// =============================================================================
// Kotlin — tree-sitter-kotlin-ng 1.1.0, annotations INSIDE function_declaration (modifiers)
// =============================================================================

#[test]
fn kotlin_attached_doc_and_annotation_positive() {
    // L1 blank | L2 class | L3-L5 doc | L6 @JvmStatic | L7 fun | L8 return | L9 } | L10 }
    let defs = extract_definitions(
        "Foo.kt",
        r#"
class Foo {
    /**
     * Docs.
     */
    @JvmStatic
    fun compute(x: Int): Int {
        return x
    }
}
"#,
        Language::Kotlin,
    );
    let compute = find_def(&defs, "Foo.kt", "compute");
    // DESIRED: doc block + annotation → L3..L9. TODAY: 6..9 (modifiers child).
    assert_span(compute, "Foo.kt", "compute", 3, 9);
    assert_signature_starts_with(compute, "Foo.kt", "compute", "fun compute");
}

#[test]
fn kotlin_detached_comment_negative() {
    // L1 blank | L2 class | L3 // note | L4 blank | L5 fun | L6 return | L7 } | L8 }
    let defs = extract_definitions(
        "Plain.kt",
        r#"
class Plain {
    // detached note

    fun lone(x: Int): Int {
        return x
    }
}
"#,
        Language::Kotlin,
    );
    let lone = find_def(&defs, "Plain.kt", "lone");
    assert_span(lone, "Plain.kt", "lone", 5, 7);
    assert_signature_starts_with(lone, "Plain.kt", "lone", "fun lone");
}

// =============================================================================
// Swift — tree-sitter-swift 0.7.1, `attribute` (@objc) INSIDE function_declaration
// =============================================================================

#[test]
fn swift_attached_doc_and_attribute_positive() {
    // L1 blank | L2 /// doc | L3 @objc | L4 func | L5 return | L6 }
    let defs = extract_definitions(
        "Sample.swift",
        r#"
/// Docs.
@objc
func compute(x: Int) -> Int {
    return x
}
"#,
        Language::Swift,
    );
    let compute = find_def(&defs, "Sample.swift", "compute");
    // DESIRED: doc comment included (contiguous above the attribute) → L2..L6.
    // TODAY: function_declaration starts at the @objc attribute → 3..6.
    assert_span(compute, "Sample.swift", "compute", 2, 6);
    assert_signature_starts_with(compute, "Sample.swift", "compute", "func compute");
}

#[test]
fn swift_detached_comment_negative() {
    // L1 blank | L2 // note | L3 blank | L4 func | L5 return | L6 }
    let defs = extract_definitions(
        "Plain.swift",
        r#"
// detached note

func lone(x: Int) -> Int {
    return x
}
"#,
        Language::Swift,
    );
    let lone = find_def(&defs, "Plain.swift", "lone");
    assert_span(lone, "Plain.swift", "lone", 4, 6);
    assert_signature_starts_with(lone, "Plain.swift", "lone", "func lone");
}

// =============================================================================
// C# — tree-sitter-c-sharp 0.23.1, attribute_list INSIDE method_declaration
// =============================================================================

#[test]
fn csharp_attached_doc_and_attribute_positive() {
    // L1 blank | L2-L3 class | L4-L6 /// doc | L7 [Fact] | L8 method | L9 { | L10 return
    // L11 } | L12 }
    let defs = extract_definitions(
        "Foo.cs",
        r#"
public class Foo
{
    /// <summary>
    /// Computes.
    /// </summary>
    [Fact]
    public int Compute(int x)
    {
        return x;
    }
}
"#,
        Language::CSharp,
    );
    let compute = find_def(&defs, "Foo.cs", "Compute");
    // DESIRED: doc block + attribute_list (contiguous) → L4..L11.
    // TODAY: method_declaration starts at its attribute_list child → 7..11.
    assert_span(compute, "Foo.cs", "Compute", 4, 11);
    assert_signature_clean(compute, "Foo.cs", "Compute", "Compute(int x)");
}

#[test]
fn csharp_detached_comment_negative() {
    // L1 blank | L2-L3 class | L4 // note | L5 blank | L6 method | L7 { | L8 return | L9 } | L10 }
    let defs = extract_definitions(
        "Plain.cs",
        r#"
public class Plain
{
    // detached note

    public int Lone(int x)
    {
        return x;
    }
}
"#,
        Language::CSharp,
    );
    let lone = find_def(&defs, "Plain.cs", "Lone");
    assert_span(lone, "Plain.cs", "Lone", 6, 9);
    assert_signature_clean(lone, "Plain.cs", "Lone", "Lone(int x)");
}

// =============================================================================
// Go — tree-sitter-go 0.23.4, `comment` is a sibling of function_declaration
// =============================================================================

#[test]
fn go_attached_doc_comment_positive() {
    // L1 blank | L2 package | L3 blank | L4 // Foo does… | L5 func | L6 return | L7 }
    let defs = extract_definitions(
        "foo.go",
        r#"
package main

// Foo does the thing.
func Foo() int {
    return 1
}
"#,
        Language::Go,
    );
    let foo = find_def(&defs, "foo.go", "Foo");
    // DESIRED: directly-attached doc comment → L4..L7. TODAY: 5..7.
    assert_span(foo, "foo.go", "Foo", 4, 7);
    assert_signature_starts_with(foo, "foo.go", "Foo", "func Foo() int {");
}

#[test]
fn go_detached_comment_negative() {
    // L1 blank | L2 package | L3 blank | L4 // note | L5 blank | L6 func | L7 return | L8 }
    let defs = extract_definitions(
        "plain.go",
        r#"
package main

// Detached note.

func Detached() int {
    return 2
}
"#,
        Language::Go,
    );
    let detached = find_def(&defs, "plain.go", "Detached");
    assert_span(detached, "plain.go", "Detached", 6, 8);
    assert_signature_starts_with(detached, "plain.go", "Detached", "func Detached() int {");
}

// =============================================================================
// Ruby — tree-sitter-ruby 0.23.1, `comment` is a sibling of `method`
// =============================================================================

#[test]
fn ruby_attached_comment_positive() {
    // L1 blank | L2 # comment | L3 def add | L4 body | L5 end
    let defs = extract_definitions(
        "sample.rb",
        r#"
# Adds two numbers.
def add(a, b)
  a + b
end
"#,
        Language::Ruby,
    );
    let add = find_def(&defs, "sample.rb", "add");
    // DESIRED: attached comment → L2..L5. TODAY: 3..5.
    assert_span(add, "sample.rb", "add", 2, 5);
    assert_signature_starts_with(add, "sample.rb", "add", "def add(a, b)");
}

#[test]
fn ruby_detached_comment_negative() {
    // L1 blank | L2 # note | L3 blank | L4 def lone | L5 body | L6 end
    let defs = extract_definitions(
        "plain.rb",
        r#"
# detached note

def lone(a)
  a
end
"#,
        Language::Ruby,
    );
    let lone = find_def(&defs, "plain.rb", "lone");
    assert_span(lone, "plain.rb", "lone", 4, 6);
    assert_signature_starts_with(lone, "plain.rb", "lone", "def lone(a)");
}

// =============================================================================
// PHP — tree-sitter-php 0.23.11, attribute_list is a FIELD of function_definition
// =============================================================================

#[test]
fn php_attached_doc_and_attribute_positive() {
    // L1 <?php | L2 blank | L3-L5 doc | L6 #[Attribute] | L7 function | L8 return | L9 }
    let defs = extract_definitions(
        "sample.php",
        r#"<?php

/**
 * Docs.
 */
#[Attribute]
function sample(int $x): int {
    return $x;
}
"#,
        Language::Php,
    );
    let sample = find_def(&defs, "sample.php", "sample");
    // DESIRED: doc block + attribute (contiguous) → L3..L9.
    // TODAY: function_definition starts at its attributes field → 6..9.
    assert_span(sample, "sample.php", "sample", 3, 9);
    assert_signature_starts_with(
        sample,
        "sample.php",
        "sample",
        "function sample(int $x): int {",
    );
}

#[test]
fn php_detached_comment_negative() {
    // L1 <?php | L2 blank | L3 // note | L4 blank | L5 function | L6 return | L7 }
    let defs = extract_definitions(
        "plain.php",
        r#"<?php

// detached note

function lone(int $x): int {
    return $x;
}
"#,
        Language::Php,
    );
    let lone = find_def(&defs, "plain.php", "lone");
    assert_span(lone, "plain.php", "lone", 5, 7);
    assert_signature_starts_with(lone, "plain.php", "lone", "function lone(int $x): int {");
}

// =============================================================================
// Scala — tree-sitter-scala 0.24.0, annotation INSIDE function_definition
// =============================================================================

#[test]
fn scala_attached_doc_and_annotation_positive() {
    // L1 blank | L2 object | L3-L5 doc | L6 @annotation | L7 def | L8 }
    let defs = extract_definitions(
        "Holder.scala",
        r#"
object Holder {
    /**
     * Docs.
     */
    @annotation
    def compute(x: Int): Int = x
}
"#,
        Language::Scala,
    );
    let compute = find_def(&defs, "Holder.scala", "compute");
    // DESIRED: doc block + annotation → L3..L7. TODAY: 6..7 (annotation child).
    assert_span(compute, "Holder.scala", "compute", 3, 7);
    assert_signature_starts_with(compute, "Holder.scala", "compute", "def compute");
}

#[test]
fn scala_detached_comment_negative() {
    // L1 blank | L2 object | L3 // note | L4 blank | L5 def | L6 }
    let defs = extract_definitions(
        "Plain.scala",
        r#"
object Plain {
    // detached note

    def lone(x: Int): Int = x
}
"#,
        Language::Scala,
    );
    let lone = find_def(&defs, "Plain.scala", "lone");
    assert_span(lone, "Plain.scala", "lone", 5, 5);
    assert_signature_starts_with(lone, "Plain.scala", "lone", "def lone");
}

// =============================================================================
// C — tree-sitter-c 0.23.4, `comment` is a sibling of function_definition
// =============================================================================

#[test]
fn c_attached_comment_positive() {
    // L1 blank | L2 /* brief */ | L3 int add | L4 return | L5 }
    let defs = extract_definitions(
        "sample.c",
        r#"
/* Adds two numbers. */
int add(int a, int b) {
    return a + b;
}
"#,
        Language::C,
    );
    let add = find_def(&defs, "sample.c", "add");
    // DESIRED: attached comment → L2..L5. TODAY: 3..5.
    assert_span(add, "sample.c", "add", 2, 5);
    assert_signature_clean(add, "sample.c", "add", "add(int a, int b)");
}

#[test]
fn c_detached_comment_negative() {
    // L1 blank | L2 /* note */ | L3 blank | L4 int lone | L5 return | L6 }
    let defs = extract_definitions(
        "plain.c",
        r#"
/* detached note */

int lone(int a) {
    return a;
}
"#,
        Language::C,
    );
    let lone = find_def(&defs, "plain.c", "lone");
    assert_span(lone, "plain.c", "lone", 4, 6);
    assert_signature_clean(lone, "plain.c", "lone", "lone(int a)");
}

// =============================================================================
// C++ — tree-sitter-cpp 0.23.4, `comment` is a sibling of function_definition
// =============================================================================

#[test]
fn cpp_attached_doc_comment_positive() {
    // L1 blank | L2 /// doc | L3 int compute | L4 return | L5 }
    let defs = extract_definitions(
        "sample.cpp",
        r#"
/// Docs for compute.
int compute(int x) {
    return x;
}
"#,
        Language::Cpp,
    );
    let compute = find_def(&defs, "sample.cpp", "compute");
    // DESIRED: attached doc comment → L2..L5. TODAY: 3..5.
    assert_span(compute, "sample.cpp", "compute", 2, 5);
    assert_signature_clean(compute, "sample.cpp", "compute", "compute(int x)");
}

#[test]
fn cpp_detached_comment_negative() {
    // L1 blank | L2 /// note | L3 blank | L4 int lone | L5 return | L6 }
    let defs = extract_definitions(
        "plain.cpp",
        r#"
/// detached note

int lone(int a) {
    return a;
}
"#,
        Language::Cpp,
    );
    let lone = find_def(&defs, "plain.cpp", "lone");
    assert_span(lone, "plain.cpp", "lone", 4, 6);
    assert_signature_clean(lone, "plain.cpp", "lone", "lone(int a)");
}

// =============================================================================
// Lua — tree-sitter-lua 0.2.0, `comment` is a sibling of function_declaration
// =============================================================================

#[test]
fn lua_attached_comment_positive() {
    // L1 blank | L2 -- comment | L3 function add | L4 return | L5 end
    let defs = extract_definitions(
        "sample.lua",
        r#"
-- Adds two numbers.
function add(a, b)
  return a + b
end
"#,
        Language::Lua,
    );
    let add = find_def(&defs, "sample.lua", "add");
    // DESIRED: attached comment → L2..L5. TODAY: 3..5.
    assert_span(add, "sample.lua", "add", 2, 5);
    assert_signature_starts_with(add, "sample.lua", "add", "function add(a, b)");
}

#[test]
fn lua_detached_comment_negative() {
    // L1 blank | L2 -- note | L3 blank | L4 function lone | L5 return | L6 end
    let defs = extract_definitions(
        "plain.lua",
        r#"
-- detached note

function lone(a, b)
  return a + b
end
"#,
        Language::Lua,
    );
    let lone = find_def(&defs, "plain.lua", "lone");
    assert_span(lone, "plain.lua", "lone", 4, 6);
    assert_signature_starts_with(lone, "plain.lua", "lone", "function lone(a, b)");
}

// =============================================================================
// Luau — tree-sitter-luau 1.2.0, same shapes as Lua
// =============================================================================

#[test]
fn luau_attached_comment_positive() {
    // L1 blank | L2 -- comment | L3 function add | L4 return | L5 end
    let defs = extract_definitions(
        "sample.luau",
        r#"
-- Adds two numbers.
function add(a, b)
  return a + b
end
"#,
        Language::Luau,
    );
    let add = find_def(&defs, "sample.luau", "add");
    // DESIRED: attached comment → L2..L5. TODAY: 3..5.
    assert_span(add, "sample.luau", "add", 2, 5);
    assert_signature_starts_with(add, "sample.luau", "add", "function add(a, b)");
}

#[test]
fn luau_detached_comment_negative() {
    // L1 blank | L2 -- note | L3 blank | L4 function lone | L5 return | L6 end
    let defs = extract_definitions(
        "plain.luau",
        r#"
-- detached note

function lone(a, b)
  return a + b
end
"#,
        Language::Luau,
    );
    let lone = find_def(&defs, "plain.luau", "lone");
    assert_span(lone, "plain.luau", "lone", 4, 6);
    assert_signature_starts_with(lone, "plain.luau", "lone", "function lone(a, b)");
}

// =============================================================================
// Elixir — tree-sitter-elixir 0.3.4, def/defp are `call` nodes (extractor.rs:2908-2967);
// `@doc "…"` is documentation trivia; `comment` is a sibling
// =============================================================================

#[test]
fn elixir_attached_doc_attribute_positive() {
    // L1 blank | L2 defmodule | L3 @doc "…" | L4 def add | L5 body | L6 end | L7 end
    let defs = extract_definitions(
        "sample.ex",
        r#"
defmodule Sample do
  @doc "Adds two numbers."
  def add(a, b) do
    a + b
  end
end
"#,
        Language::Elixir,
    );
    let add = find_def(&defs, "sample.ex", "add");
    // DESIRED: @doc trivia region attached to the def call node → L3..L6. TODAY: 4..6.
    assert_span(add, "sample.ex", "add", 3, 6);
    assert_signature_starts_with(add, "sample.ex", "add", "def add(a, b)");
}

#[test]
fn elixir_detached_comment_negative() {
    // L1 blank | L2 defmodule | L3 # note | L4 blank | L5 def lone | L6 body | L7 end | L8 end
    let defs = extract_definitions(
        "plain.ex",
        r#"
defmodule Plain do
  # detached note

  def lone(a) do
    a
  end
end
"#,
        Language::Elixir,
    );
    let lone = find_def(&defs, "plain.ex", "lone");
    assert_span(lone, "plain.ex", "lone", 5, 7);
    assert_signature_starts_with(lone, "plain.ex", "lone", "def lone(a)");
}

// =============================================================================
// OCaml — tree-sitter-ocaml 0.24.2, top-level `let` = value_definition; `comment` sibling
// =============================================================================

#[test]
fn ocaml_attached_comment_positive() {
    // L1 blank | L2 (* comment *) | L3 let add a b = a + b
    let defs = extract_definitions(
        "sample.ml",
        r#"
(* Adds two numbers. *)
let add a b = a + b
"#,
        Language::Ocaml,
    );
    let add = find_def(&defs, "sample.ml", "add");
    // DESIRED: attached comment → L2..L3. TODAY: 3..3.
    assert_span(add, "sample.ml", "add", 2, 3);
    assert_signature_starts_with(add, "sample.ml", "add", "let add a b = a + b");
}

#[test]
fn ocaml_detached_comment_negative() {
    // L1 blank | L2 (* note *) | L3 blank | L4 let lone a = a
    let defs = extract_definitions(
        "plain.ml",
        r#"
(* detached note *)

let lone a = a
"#,
        Language::Ocaml,
    );
    let lone = find_def(&defs, "plain.ml", "lone");
    assert_span(lone, "plain.ml", "lone", 4, 4);
    assert_signature_starts_with(lone, "plain.ml", "lone", "let lone a = a");
}

// =============================================================================
// Formats — element-extraction-v1 baseline.
//
// json/yaml/toml emit ELEMENT definitions (kind = key / section / document;
// bash emits real `function` definitions) via `ast::elements`, appended
// inside `extract_file_structure`. Their exact spans live in the dedicated
// `element_extraction_v1` suite; here we pin only the transition:
// the four formats carry their element kinds, and since batch E2 the markup
// formats flow through the same engine (xml/svg/html → `element`,
// css → `selector`/`at-rule`, latex → `section`/`environment`).
// =============================================================================

#[test]
fn json_yaml_toml_bash_definitions_are_elements() {
    let cases: &[(&str, &str, Language, &[&str])] = &[
        (
            "pinned.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
            Language::Toml,
            &["section", "key", "key"],
        ),
        (
            "pinned.json",
            "{\"name\": \"demo\", \"items\": [1, 2, 3]}\n",
            Language::Json,
            &["key", "key"],
        ),
        (
            "pinned.yaml",
            "name: demo\nitems:\n  - one\n  - two\n",
            Language::Yaml,
            &["document", "key", "key"],
        ),
        (
            "pinned.sh",
            "build() {\n  echo building\n}\n",
            Language::Bash,
            &["function"],
        ),
    ];

    for (filename, content, language, expected_kinds) in cases {
        let dir =
            TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
        let path = dir.path().join(filename);
        fs::write(&path, content)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write {filename} failed: {e}"));
        let structure = get_code_structure(&path, *language, 0, None)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: {filename} extraction failed: {e}"));
        assert_eq!(
            structure.files.len(),
            1,
            "symbol-fidelity-v1 [{filename}]: expected exactly one FileStructure"
        );
        let defs = &structure.files[0].definitions;
        let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(
            kinds, *expected_kinds,
            "symbol-fidelity-v1 [{filename}]: expected element-kind sequence (source order), \
             got {defs:#?}"
        );
        // Element byte spans are populated (code languages keep None).
        for d in defs {
            assert!(
                d.byte_start.is_some() && d.byte_end.is_some(),
                "symbol-fidelity-v1 [{filename}]: element {}:`{}` must carry byte spans",
                d.kind,
                d.name
            );
        }
    }
}

#[test]
fn latex_definitions_are_elements() {
    // LaTeX (2025-11) flows through the same element engine: sectioning
    // commands emit `section` (content-spanning — the grammar nests each
    // section's content inside the sectioning node), `\begin{env}`…`\end{env}`
    // blocks emit `environment`. `\label` and body text never emit.
    let cases: &[(&str, &str, Language, &[&str])] = &[(
        "pinned.tex",
        "\\section{Intro}\nbody text\n\\begin{itemize}\n\\item a\n\\end{itemize}\n",
        Language::Latex,
        &["section", "environment"],
    )];

    for (filename, content, language, expected_kinds) in cases {
        let dir =
            TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
        let path = dir.path().join(filename);
        fs::write(&path, content)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write {filename} failed: {e}"));
        let structure = get_code_structure(&path, *language, 0, None)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: {filename} extraction failed: {e}"));
        assert_eq!(
            structure.files.len(),
            1,
            "symbol-fidelity-v1 [{filename}]: expected exactly one FileStructure"
        );
        let defs = &structure.files[0].definitions;
        let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(
            kinds, *expected_kinds,
            "symbol-fidelity-v1 [{filename}]: expected element-kind sequence (source order), \
             got {defs:#?}"
        );
        // Element byte spans are populated (code languages keep None).
        for d in defs {
            assert!(
                d.byte_start.is_some() && d.byte_end.is_some(),
                "symbol-fidelity-v1 [{filename}]: element {}:`{}` must carry byte spans",
                d.kind,
                d.name
            );
        }
    }
}

/// MARKDOWN PIN (`markdown_definitions_are_elements`, markdown batch 2026-09):
/// `.md` flows through the same element engine via the tree-sitter-md BLOCK
/// grammar: ATX and setext headings emit `heading` (named after the heading
/// text — the `#`/underline markers are separate grammar children), fenced
/// code blocks emit `code-block` (named after the info string's `language`
/// token, `"code-block"` when there is none), and pipe tables emit `table`
/// (named after the header-row cells joined with `" | "`). Body prose never
/// emits. Exact spans live in the dedicated `element_extraction_v1` suite.
#[test]
fn markdown_definitions_are_elements() {
    let fixture =
        "# Intro\n\nSome prose.\n\n```rust\nfn main() {}\n```\n\n| A | B |\n| - | - |\n| 1 | 2 |\n";
    let dir = TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
    let path = dir.path().join("README.md");
    fs::write(&path, fixture)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write README.md failed: {e}"));

    let structure = get_code_structure(&path, Language::Markdown, 0, None)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: README.md extraction failed: {e}"));
    assert_eq!(
        structure.files.len(),
        1,
        "symbol-fidelity-v1 [README.md]: expected exactly one FileStructure"
    );
    assert_eq!(
        structure.language,
        Some(Language::Markdown),
        "symbol-fidelity-v1 [README.md]: language must report markdown"
    );
    let defs = &structure.files[0].definitions;

    // EXACT element sequence, source order: heading, code-block, table.
    // The prose paragraph never emits.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("heading", "Intro"),
        ("code-block", "rust"),
        ("table", "A | B"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "symbol-fidelity-v1 [README.md]: expected exact markdown element sequence, got {defs:#?}"
    );

    // Every element carries byte spans (the format-tier contract).
    for d in defs {
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "symbol-fidelity-v1 [README.md]: element {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
    }
}

#[test]
fn xml_html_css_definitions_are_elements() {
    let cases: &[(&str, &str, Language, &[&str])] = &[
        (
            "pinned.html",
            "<!DOCTYPE html>\n<html>\n  <body>\n    <p>hello</p>\n  </body>\n</html>\n",
            Language::Html,
            &["element", "element", "element"],
        ),
        (
            "pinned.css",
            "body {\n  color: red;\n}\n",
            Language::Css,
            &["selector"],
        ),
        (
            "pinned.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n  <item id=\"1\"/>\n</root>\n",
            Language::Xml,
            // `item` carries an id attribute → its name is `item#1` in the
            // dedicated suite; here we pin the KIND sequence only.
            &["element", "element"],
        ),
    ];

    for (filename, content, language, expected_kinds) in cases {
        let dir =
            TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
        let path = dir.path().join(filename);
        fs::write(&path, content)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write {filename} failed: {e}"));
        let structure = get_code_structure(&path, *language, 0, None)
            .unwrap_or_else(|e| panic!("symbol-fidelity-v1: {filename} extraction failed: {e}"));
        assert_eq!(
            structure.files.len(),
            1,
            "symbol-fidelity-v1 [{filename}]: expected exactly one FileStructure"
        );
        let defs = &structure.files[0].definitions;
        let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(
            kinds, *expected_kinds,
            "symbol-fidelity-v1 [{filename}]: expected element-kind sequence (source order), \
             got {defs:#?}"
        );
        // Element byte spans are populated (code languages keep None).
        for d in defs {
            assert!(
                d.byte_start.is_some() && d.byte_end.is_some(),
                "symbol-fidelity-v1 [{filename}]: element {}:`{}` must carry byte spans",
                d.kind,
                d.name
            );
        }
    }
}

/// LOG PIN (`log_entries_are_elements`, log batch): `.log` files never reach
/// a tree-sitter tree (no maintained log grammar exists on crates.io), so
/// the native, streaming scanner in `ast::logs` is the ONLY source of log
/// definitions. `tldr structure <file>.log` must surface one `entry`
/// definition per parsed log entry — named after the normalized level (or
/// `"entry"` for level-less entries), with byte spans and
/// `definition_line` = the entry's start line. A stack-trace continuation
/// block must be absorbed into the failing entry's region rather than
/// emitted as its own (garbage) definitions.
#[test]
fn log_entries_are_elements() {
    let fixture = "\
2026-09-14T08:34:49Z INFO service started
2026-09-14T08:34:50Z ERROR query failed
Traceback (most recent call last):
  File \"db.py\", line 42, in query
2026-09-14 08:35:01,123 WARN slow query
[error] disk usage 91%
";
    let dir = TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
    let path = dir.path().join("server.log");
    fs::write(&path, fixture)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write server.log failed: {e}"));

    let structure = get_code_structure(&path, Language::Log, 0, None)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: server.log extraction failed: {e}"));
    assert_eq!(
        structure.files.len(),
        1,
        "symbol-fidelity-v1 [server.log]: expected exactly one FileStructure"
    );
    assert_eq!(
        structure.language,
        Some(Language::Log),
        "symbol-fidelity-v1 [server.log]: language must report log"
    );
    let defs = &structure.files[0].definitions;

    // EXACT entry sequence, source order — one definition per entry.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("entry", "info"),
        ("entry", "error"),
        ("entry", "warn"),
        ("entry", "error"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "symbol-fidelity-v1 [server.log]: expected exact entry sequence, got {defs:#?}"
    );

    // The stack-trace continuation lines attach to the ERROR entry (lines
    // 2-4), so no extra definitions appear for them.
    let error = defs
        .iter()
        .find(|d| d.name == "error" && d.line_start == 2)
        .unwrap_or_else(|| {
            panic!("symbol-fidelity-v1 [server.log]: ERROR entry (line 2) not found.\n{defs:#?}")
        });
    assert!(
        error.line_end == 4,
        "symbol-fidelity-v1 [server.log]: ERROR entry must absorb its stack trace (lines 2..=4), \
         got {}..{}",
        error.line_start,
        error.line_end
    );

    // Every entry: byte spans present + definition_line = start line.
    for d in defs {
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "symbol-fidelity-v1 [server.log]: entry {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "symbol-fidelity-v1 [server.log]: entry {}:`{}` definition_line must be its start line",
            d.kind,
            d.name
        );
    }
}

/// TEXT PIN (`text_headings_are_elements`, plain-text batch): `.txt` files
/// never reach a tree-sitter tree (plain text has no syntax to parse — the
/// Log no-grammar precedent), so the heuristic TOC scanner in `ast::toc` is
/// the ONLY source of text definitions. `tldr structure <file>.txt` must
/// surface one `heading` definition per TOC heading — named after the
/// collapsed heading text (ATX/underline markers stripped, numbering
/// prefixes kept), with byte spans and `definition_line` = the heading's
/// first line. Prose and colon-terminated ALL-CAPS label lines stay inert.
#[test]
fn text_headings_are_elements() {
    let fixture = "\
OVERVIEW

Introduction
============

1. Setup
1.1. Requirements

lowercase prose stays inert
SEE ALSO:
";
    let dir = TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
    let path = dir.path().join("notes.txt");
    fs::write(&path, fixture)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write notes.txt failed: {e}"));

    let structure = get_code_structure(&path, Language::Text, 0, None)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: notes.txt extraction failed: {e}"));
    assert_eq!(
        structure.files.len(),
        1,
        "symbol-fidelity-v1 [notes.txt]: expected exactly one FileStructure"
    );
    assert_eq!(
        structure.language,
        Some(Language::Text),
        "symbol-fidelity-v1 [notes.txt]: language must report text"
    );
    let defs = &structure.files[0].definitions;

    // EXACT heading sequence, source order — one definition per heading;
    // prose and the `SEE ALSO:` label line never emit.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("heading", "OVERVIEW"),
        ("heading", "Introduction"),
        ("heading", "1. Setup"),
        ("heading", "1.1. Requirements"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "symbol-fidelity-v1 [notes.txt]: expected exact heading sequence, got {defs:#?}"
    );

    // The setext heading's region covers BOTH lines (text + underline).
    let setext = defs
        .iter()
        .find(|d| d.name == "Introduction")
        .unwrap_or_else(|| {
            panic!("symbol-fidelity-v1 [notes.txt]: setext heading not found.\n{defs:#?}")
        });
    assert_eq!(
        setext.line_start, 3,
        "symbol-fidelity-v1 [notes.txt]: setext heading starts at its text line"
    );
    assert_eq!(
        setext.line_end, 4,
        "symbol-fidelity-v1 [notes.txt]: setext region includes the underline line"
    );
    let slice = &fixture[setext.byte_start.unwrap() as usize..setext.byte_end.unwrap() as usize];
    assert_eq!(
        slice, "Introduction\n============",
        "symbol-fidelity-v1 [notes.txt]: setext byte region = text + underline"
    );

    // Every heading: byte spans present + definition_line = start line +
    // empty signature (prose has none).
    for d in defs {
        assert_eq!(d.kind, "heading");
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "symbol-fidelity-v1 [notes.txt]: heading {} must carry byte spans",
            d.name
        );
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "symbol-fidelity-v1 [notes.txt]: heading {} definition_line must be its start line",
            d.name
        );
        assert!(
            d.signature.is_empty(),
            "symbol-fidelity-v1 [notes.txt]: prose has no signatures"
        );
    }
}

/// CSV PIN (`csv_records_and_header_cells_are_elements`, CSV/TSV batch):
/// `.csv`/`.tsv` files never reach a tree-sitter tree — the only CSV grammar
/// crate on crates.io (`tree-sitter-csv` 1.2.0) is unbuildable (its `cc
/// ~1.0.82` build-dep semver-conflicts with the `cc ^1.2.10` the pinned ts
/// 0.25 stack requires) and its ts-0.20-era exports ship no bridge
/// LanguageFns (root `Cargo.toml` audit note) — so the native, streaming RFC
/// 4180 scanner in `ast::csvscan` is the ONLY source of CSV definitions. `tldr
/// structure <file>.csv` must surface one `record` definition per record —
/// named after the first field's text (else `row-N`) — plus `cell` definitions
/// for the FIRST record's fields (the header convention), with exact byte
/// spans (`source[byte_start..byte_end]` IS the record/cell region, quoted
/// commas and embedded newlines included) and `definition_line` = the start
/// line. Records must not split on delimiters/newlines INSIDE quoted fields.
#[test]
fn csv_records_and_header_cells_are_elements() {
    let fixture = "sku,product,notes\n\
                   A-1,Widget,\"round, blue\"\n\
                   A-2,Gadget,\"sells\n\
                   well, sometimes\"\n";
    let dir = TempDir::new().unwrap_or_else(|e| panic!("symbol-fidelity-v1: tempdir failed: {e}"));
    let path = dir.path().join("data.csv");
    fs::write(&path, fixture)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: write data.csv failed: {e}"));

    let structure = get_code_structure(&path, Language::Csv, 0, None)
        .unwrap_or_else(|e| panic!("symbol-fidelity-v1: data.csv extraction failed: {e}"));
    assert_eq!(
        structure.files.len(),
        1,
        "symbol-fidelity-v1 [data.csv]: expected exactly one FileStructure"
    );
    assert_eq!(
        structure.language,
        Some(Language::Csv),
        "symbol-fidelity-v1 [data.csv]: language must report csv"
    );
    let defs = &structure.files[0].definitions;

    // EXACT sequence, source order — the header record with its cells, then
    // one record per data row.
    let sequence: Vec<(String, String)> = defs
        .iter()
        .map(|d| (d.kind.clone(), d.name.clone()))
        .collect();
    let expected: Vec<(String, String)> = [
        ("record", "sku"),
        ("cell", "sku"),
        ("cell", "product"),
        ("cell", "notes"),
        ("record", "A-1"),
        ("record", "A-2"),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), n.to_string()))
    .collect();
    assert_eq!(
        sequence, expected,
        "symbol-fidelity-v1 [data.csv]: expected exact record/cell sequence, got {defs:#?}"
    );

    // The quoted field's comma must NOT split record A-1, and its region is
    // the exact physical line (quotes included).
    let a1 = defs
        .iter()
        .find(|d| d.kind == "record" && d.name == "A-1")
        .unwrap_or_else(|| {
            panic!("symbol-fidelity-v1 [data.csv]: record A-1 not found.\n{defs:#?}")
        });
    assert_eq!(
        &fixture[a1.byte_start.unwrap() as usize..a1.byte_end.unwrap() as usize],
        "A-1,Widget,\"round, blue\"",
        "symbol-fidelity-v1 [data.csv]: record A-1 region = its exact source line"
    );

    // The embedded newline inside A-2's quoted field must NOT split it into
    // two records: the record spans lines 3-4 and its byte region
    // reconstructs both lines (comma and newline included).
    let a2 = defs
        .iter()
        .find(|d| d.kind == "record" && d.name == "A-2")
        .unwrap_or_else(|| {
            panic!("symbol-fidelity-v1 [data.csv]: record A-2 not found.\n{defs:#?}")
        });
    assert_eq!(
        (a2.line_start, a2.line_end),
        (3, 4),
        "symbol-fidelity-v1 [data.csv]: record A-2 must absorb its embedded newline (lines 3..=4)"
    );
    assert_eq!(
        &fixture[a2.byte_start.unwrap() as usize..a2.byte_end.unwrap() as usize],
        "A-2,Gadget,\"sells\nwell, sometimes\"",
        "symbol-fidelity-v1 [data.csv]: record A-2 region = the exact two-line source region"
    );

    // Every element: byte spans present + definition_line = start line +
    // empty signature (a data row has nothing signature-shaped).
    for d in defs {
        assert!(
            d.byte_start.is_some() && d.byte_end.is_some(),
            "symbol-fidelity-v1 [data.csv]: {}:`{}` must carry byte spans",
            d.kind,
            d.name
        );
        assert_eq!(
            d.definition_line,
            Some(d.line_start),
            "symbol-fidelity-v1 [data.csv]: {}:`{}` definition_line must be its start line",
            d.kind,
            d.name
        );
        assert!(
            d.signature.is_empty(),
            "symbol-fidelity-v1 [data.csv]: {}:`{}` data rows have no signatures",
            d.kind,
            d.name
        );
    }
}
