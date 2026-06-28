//! Interface command - Public API extraction
//!
//! Extracts the public interface (API surface) from source files.
//! Supports all languages with tree-sitter grammars: Python, Rust, Go,
//! TypeScript, JavaScript, Java, C, C++, Ruby, C#, Scala, PHP, Lua, Luau,
//! Elixir, and OCaml.
//!
//! # Features
//!
//! - Extracts public functions (language-appropriate visibility rules)
//! - Extracts public classes/structs/traits with their public methods
//! - Captures export declarations when present (e.g., Python `__all__`)
//! - Marks async functions/methods
//! - Includes function signatures with type annotations
//! - Includes docstrings/doc comments when present
//!
//! # Example
//!
//! ```bash
//! tldr interface src/api.py
//! tldr interface src/lib.rs
//! tldr interface src/ --format text
//! ```

use std::path::{Path, PathBuf};

use clap::Args;
use tldr_core::walker::walk_project;
use tree_sitter::Node;

use super::error::{PatternsError, PatternsResult};
use super::types::{ClassInfo, FunctionInfo, InterfaceInfo, MethodInfo, ValueInfo};
use super::validation::{read_file_safe, validate_directory_path, validate_file_path};
use crate::output::OutputFormat;
use tldr_core::ast::ParserPool;
use tldr_core::types::Language;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Arguments for the interface command.
#[derive(Debug, Clone, Args)]
pub struct InterfaceArgs {
    /// File or directory to analyze
    #[arg(required = true)]
    pub path: PathBuf,

    /// Project root for path validation
    #[arg(long)]
    pub project_root: Option<PathBuf>,
}

// =============================================================================
// Language-Aware Node Kind Configuration
// =============================================================================

/// Node kinds that represent function definitions for a given language.
fn function_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["function_definition"],
        Language::Rust => &["function_item"],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::TypeScript | Language::JavaScript => &[
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        // interface-per-lang-v1 (v0.4.2 M-022): C headers expose public API
        // as `declaration` nodes whose declarator is a `function_declarator`
        // (function prototypes, e.g. `int foo(int x);` in sds.h). The
        // walker filters non-function declarations via
        // `is_c_function_prototype` so fields/typedefs do not surface.
        Language::C | Language::Cpp => &["function_definition", "declaration"],
        Language::Ruby => &["method", "singleton_method"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        // tree-sitter-scala emits `function_declaration` for bodyless/abstract
        // `def f(): T` (trait & abstract-class contracts) and
        // `function_definition` for defs WITH a body. Both must be collected or
        // the entire abstract surface of a trait is dropped (#207: zio Clock
        // listed only the one concrete `unsafe`). Matches the precedent in
        // function_finder.rs / clones / the scala callgraph.
        Language::Scala => &["function_definition", "function_declaration", "def_definition"],
        Language::Php => &["function_definition", "method_declaration"],
        Language::Lua | Language::Luau => {
            &["function_declaration", "function_definition_statement"]
        }
        Language::Elixir => &["call"], // `def` and `defp` are calls in elixir tree-sitter
        Language::Ocaml => &["let_binding", "value_definition"],
        // real-repo-fixes-v1 (P9.BUG-R6/R7): wire kotlin/swift surface forms
        // for top-level/standalone function definitions.
        Language::Kotlin | Language::Swift => &["function_declaration"],
        // v0.5.0 SOL-001
        Language::Solidity => &[
            "function_definition",
            "constructor_definition",
            "fallback_function_definition",
            "receive_function_definition",
            "modifier_definition",
        ],
    }
}

/// Node kinds that represent class/struct/trait definitions for a given language.
fn class_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["class_definition"],
        Language::Rust => &["struct_item", "impl_item", "trait_item", "enum_item"],
        Language::Go => &["type_declaration"],
        Language::Java => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
        Language::TypeScript | Language::JavaScript => &[
            "class_declaration",
            "abstract_class_declaration",
            "interface_declaration",
            "type_alias_declaration",
            // rc2-ts-interface-typealias-lumped-as-classes: capture & kind-tag
            // TS enums (graphify PR #708 + `structure` both treat enums as
            // first-class members of this union) instead of silently dropping
            // them.
            "enum_declaration",
        ],
        Language::C => &["struct_specifier"],
        Language::Cpp => &["struct_specifier", "class_specifier"],
        Language::Ruby => &["class", "module"],
        Language::CSharp => &[
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
        ],
        // RC2-META Stage 3 (scala): mirror the TS rc2-ts union — capture &
        // kind-tag Scala `enum_definition` / `type_definition` (type aliases)
        // as first-class members of the interface surface instead of silently
        // dropping them. `structure` already surfaces both; this makes
        // `interface` agree.
        Language::Scala => &[
            "class_definition",
            "object_definition",
            "trait_definition",
            "enum_definition",
            "type_definition",
        ],
        Language::Php => &["class_declaration", "interface_declaration"],
        Language::Lua | Language::Luau => &[], // Lua doesn't have class syntax
        Language::Elixir => &["call"],         // defmodule is a call in elixir tree-sitter
        // CF1-S4 (v0.5.0 RC): OCaml's class-shaped carriers are FOUR distinct
        // node kinds, not two. `module_definition` (kind="module") and
        // `type_definition` (kind="type") were already collected, but the two
        // genuine OOP-class forms were missing entirely, so `interface` listed
        // dozens of modules + type aliases and ZERO real classes. Add the real
        // class carriers so they surface (relabeled by kind, see
        // `ts_js_entry_kind`): `class_definition` (`class c = object … end`,
        // kind="class") and `class_type_definition` (`class type ct = object …
        // end`, the OCaml class *signature* / interface analogue,
        // kind="interface"). The module/type entries keep their own kinds and
        // are therefore no longer miscounted as classes. Node shapes verified
        // against tree-sitter-ocaml 0.24.2 node-types.json (mirrors
        // `crates/tldr-core/src/inheritance/ocaml.rs`).
        Language::Ocaml => &[
            "module_definition",
            "type_definition",
            "class_definition",
            "class_type_definition",
        ],
        // real-repo-fixes-v1 (P9.BUG-R6): kotlin classes/objects/interfaces.
        // Kotlin's tree-sitter grammar emits `class_declaration` for
        // `class`, `interface`, `enum class`, `data class`, etc., and
        // `object_declaration` for singleton `object` blocks.
        // RC2-META Stage 3 (kotlin): `type_alias` (`typealias H = ...`) is a
        // top-level type-defining construct surfaced as `kind:"type"` via the
        // canonical classifier — additive, previously dropped from `interface`.
        Language::Kotlin => &["class_declaration", "object_declaration", "type_alias"],
        // real-repo-fixes-v1 (P9.BUG-R7): swift classes/protocols. The
        // tree-sitter-swift grammar uses `class_declaration` for
        // class/struct/enum/actor/extension and `protocol_declaration`
        // separately. Including all gives a useful interface surface even
        // when files only contain extensions (e.g.
        // swift-collections/.../Span+Extras.swift).
        Language::Swift => &["class_declaration", "protocol_declaration"],
        // v0.5.0 SOL-001: Solidity contract / interface / library are
        // the three class-shaped containers.
        Language::Solidity => &[
            "contract_declaration",
            "interface_declaration",
            "library_declaration",
        ],
    }
}

/// Node kinds that represent decorated/annotated definitions.
fn decorator_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["decorated_definition"],
        Language::Java => &["annotation"],
        Language::TypeScript | Language::JavaScript => &["decorator"],
        Language::CSharp => &["attribute_list"],
        Language::Rust => &["attribute_item"],
        _ => &[],
    }
}

/// Node kinds for method definitions inside classes/structs.
fn method_node_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["function_definition"],
        Language::Rust => &["function_item"],
        Language::Go => &["method_declaration"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::TypeScript | Language::JavaScript => {
            &["method_definition", "public_field_definition"]
        }
        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
        // include `declaration` and `field_declaration` so member-function
        // *declarations* in header files (e.g. `int Parse(const char* xml);`)
        // surface as methods, not just inline `function_definition` bodies.
        // Non-function declarations (fields, typedefs) are filtered out by
        // `is_cpp_member_function_declaration` inside collect_methods_from_body.
        Language::C | Language::Cpp => {
            &["function_definition", "field_declaration", "declaration"]
        }
        Language::Ruby => &["method", "singleton_method"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        // Include `function_declaration` (bodyless/abstract `def f(): T`) so
        // trait/abstract-class method contracts surface as methods, not just
        // defs with bodies (#207). See function_node_kinds(Scala) above.
        Language::Scala => &["function_definition", "function_declaration", "def_definition"],
        Language::Php => &["method_declaration"],
        Language::Elixir => &["call"],
        // CF1-S4 (v0.5.0 RC): OCaml module bodies hold members as
        // `value_definition` / `let_binding`, but an OCaml CLASS body
        // (`object … end` = `object_expression`) holds them as
        // `method_definition`, and a CLASS TYPE body (`class_body_type`) holds
        // method contracts as `method_specification` / `method_type`. Add those
        // three so a real OCaml class/class-type surfaces its methods instead of
        // an empty `methods: []`. Additive — module bodies never contain these
        // kinds, so module method collection is unaffected.
        Language::Ocaml => &[
            "let_binding",
            "value_definition",
            "method_definition",
            "method_specification",
            "method_type",
        ],
        // interface-per-lang-v1 (v0.4.2 M-022): Kotlin/Swift class
        // bodies hold methods as `function_declaration` nodes. Without
        // this entry, every Kotlin class and every Swift class /
        // extension reported `methods: []`.
        Language::Kotlin | Language::Swift => &["function_declaration"],
        // v0.5.0 SOL-015a (M7): Solidity contract/interface/library
        // bodies (`contract_body`) hold methods as
        // `function_definition` / `constructor_definition` /
        // `fallback_function_definition` / `receive_function_definition`
        // / `modifier_definition` nodes. Without this arm,
        // `tldr interface TokenVault.sol` reported `methods: []` for
        // every contract.
        Language::Solidity => &[
            "function_definition",
            "constructor_definition",
            "fallback_function_definition",
            "receive_function_definition",
            "modifier_definition",
        ],
        _ => &[],
    }
}

// =============================================================================
// Public Name Detection (Language-Aware)
// =============================================================================

/// Check if a name is public based on language conventions.
///
/// - Python: names not starting with `_`
/// - Rust: `pub` keyword (checked at node level, not name level)
/// - Go: names starting with uppercase
/// - Ruby: methods not starting with `_` (private is keyword-based)
/// - Other languages: generally all names are considered public
///   (visibility modifiers are checked at the node level)
#[inline]
pub fn is_public_name(name: &str) -> bool {
    !name.starts_with('_')
}

/// Check if a name is public based on language-specific rules.
fn is_public_for_lang(name: &str, lang: Language) -> bool {
    match lang {
        Language::Python | Language::Ruby | Language::Lua | Language::Luau => {
            !name.starts_with('_')
        }
        Language::Go => {
            // Go exports start with an uppercase letter
            name.chars().next().is_some_and(|c| c.is_uppercase())
        }
        // For Rust, Java, TS, C#, etc. - visibility is determined by modifiers,
        // not naming. We check modifiers at the node level.
        _ => true,
    }
}

/// Check if a Rust node has truly public visibility (`pub`).
///
/// interface-per-lang-v1 (v0.4.2 M-022): the legacy check returned true
/// for any visibility_modifier text starting with `"pub"`, which also
/// matched the restricted forms `pub(crate)`, `pub(super)`, and
/// `pub(in crate::foo)`. Those items are not part of the crate's public
/// API and must not surface in `tldr interface`. Only accept bare
/// `"pub"` (no parenthesized scope) here.
fn is_rust_pub(node: Node, source: &[u8]) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "visibility_modifier" {
                let text = node_text(child, source).trim();
                // True public: exactly `pub` (no `pub(crate)` / `pub(super)` / `pub(in …)`).
                return text == "pub";
            }
        }
    }
    false
}

/// Check if a Java/C#/PHP/TS node has public access modifier.
///
/// RC2-1-visibility-csharp-java-php: the legacy fall-through returned `true`
/// unconditionally whenever no `public` keyword was *seen*, so an explicit
/// `private`/`protected`/`internal` member leaked into the public surface and
/// `private_method_count` was always 0 for csharp/java/php. The repair returns
/// `false` when an explicit non-public access modifier child is present, while
/// still treating a member with NO access keyword as public — preserving the
/// language-level default for Java interface methods, C# interface/enum
/// members, and PHP interface methods, none of which carry a visibility
/// keyword (mirrors `surface/csharp.rs` / `surface/java.rs` interface-member
/// special-casing).
fn has_public_modifier(node: Node, source: &[u8]) -> bool {
    // Implicit visibility (no explicit access modifier) stays public.
    explicit_access_visibility(node, source).unwrap_or(true)
}

/// AST-driven access-modifier classification shared by Java / C# / PHP / TS.
///
/// Returns:
///   - `Some(true)`  — an explicit `public` access modifier is present;
///   - `Some(false)` — an explicit non-public access modifier
///     (`private`/`protected`/`internal`/`file`) is present and there is no
///     `public`;
///   - `None`        — NO explicit access modifier at all (implicit
///     visibility: interface/enum members, Java package-private).
///
/// Every grammar shape used by the routed languages is recognised by node
/// kind (NOT a source-text scan):
///   - tree-sitter-java: a single `modifiers` wrapper whose access keyword is
///     an anonymous token child (`kind()` IS the keyword) — mirrors
///     `extract_java_visibility` (ast/extract.rs);
///   - tree-sitter-c-sharp: individual `modifier` named children whose text is
///     the keyword — mirrors `extract_csharp_visibility`;
///   - tree-sitter-php: a direct `visibility_modifier` child whose text is the
///     keyword — mirrors the `visibility_modifier` harvest in ast/extract.rs;
///   - tree-sitter-typescript: an `accessibility_modifier` child.
fn explicit_access_visibility(node: Node, source: &[u8]) -> Option<bool> {
    let mut explicit_non_public = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // Java: keyword tokens live INSIDE a `modifiers` wrapper; the
            // keyword's own `kind()` is the literal ("public"/"private"/…), with
            // a node-text fallback for grammars that expose it as raw text.
            "modifiers" => {
                let mut mc = child.walk();
                for m in child.children(&mut mc) {
                    let class = classify_access_keyword(m.kind())
                        .or_else(|| classify_access_keyword(node_text(m, source).trim()));
                    match class {
                        Some(true) => return Some(true),
                        Some(false) => explicit_non_public = true,
                        None => {}
                    }
                }
            }
            // C# `modifier`, a generic `access_modifier` wrapper, PHP
            // `visibility_modifier`, and TS `accessibility_modifier` all carry
            // the access keyword as the node's own text.
            "modifier" | "access_modifier" | "visibility_modifier"
            | "accessibility_modifier" => {
                match classify_access_keyword(node_text(child, source).trim()) {
                    Some(true) => return Some(true),
                    Some(false) => explicit_non_public = true,
                    None => {}
                }
            }
            _ => {}
        }
    }
    if explicit_non_public {
        Some(false)
    } else {
        None
    }
}

/// Classify an access-modifier keyword. `Some(true)` = `public`,
/// `Some(false)` = an explicit non-public access level, `None` = not an access
/// modifier at all (e.g. `static`/`final`/`abstract`/`readonly`/annotations).
fn classify_access_keyword(kw: &str) -> Option<bool> {
    match kw {
        "public" => Some(true),
        // Java/PHP `private`/`protected`; C# adds `internal` and `file`.
        "private" | "protected" | "internal" | "file" => Some(false),
        _ => None,
    }
}

/// Check if a C/C++ function is `static` (file-local, not public).
fn is_c_static(node: Node, source: &[u8]) -> bool {
    // Check for storage_class_specifier "static" before the function
    if let Some(prev) = node.prev_sibling() {
        if prev.kind() == "storage_class_specifier" {
            return node_text(prev, source) == "static";
        }
    }
    // Check declarator specifiers
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "storage_class_specifier" && node_text(child, source) == "static" {
                return true;
            }
        }
    }
    false
}

/// Language-aware visibility check for a node.
fn is_node_public(node: Node, source: &[u8], lang: Language) -> bool {
    let name = get_node_name(node, source, lang);
    let name_str = name.as_deref().unwrap_or("");

    match lang {
        Language::Rust => {
            // language-specific-bugs-v1 (P14.AGG14-10): `impl_item` blocks
            // are not declarations; they are method-collecting containers
            // and never carry their own `pub` modifier. Always treat them
            // as visible — the methods inside still get their own
            // `is_method_public` filtering. Without this, every
            // `impl Foo { pub fn ... }` block was filtered out at the
            // class layer, so `tldr interface` reported every struct with
            // `methods: 0` even when the inherent impl exposed dozens of
            // public methods.
            if node.kind() == "impl_item" {
                return true;
            }
            is_rust_pub(node, source)
        }
        // rc2-meta-stage4 (visibility unification): the name-based visibility
        // rules (Go uppercase-export; Python/Ruby/Lua/Luau leading-underscore)
        // are routed through the SHARED `is_public_for_lang` model — the same
        // single source of truth `is_method_public` already consults for these
        // languages — so the class-axis and member-axis visibility projections
        // can never drift apart. Membership-preserving (identical predicate),
        // it merely de-duplicates the rule into one place.
        Language::Go | Language::Python | Language::Ruby | Language::Lua | Language::Luau => {
            is_public_for_lang(name_str, lang)
        }
        Language::Java | Language::CSharp => has_public_modifier(node, source),
        Language::C | Language::Cpp => !is_c_static(node, source),
        // interface-per-lang-v1 (v0.4.2 M-022): scala default is public.
        // Filter only when an explicit `private` / `protected`
        // access_modifier appears inside a `modifiers` wrapper.
        Language::Scala => !is_scala_non_public(node, source),
        // rc2-ts-interface-typealias-lumped-as-classes (#243): TS/JS
        // exportedness is STRUCTURAL — the `export` marker lives on the
        // wrapping `export_statement`, never on the declaration node. A
        // top-level declaration is exported iff, after unwrapping at most one
        // `ambient_declaration` layer (handles `export declare interface/
        // class/type`), its parent is an `export_statement`. Non-exported
        // file-local decls sit directly under `program` / a statement_block /
        // a module body, so they are correctly filtered out of `classes[]`
        // (and, via the name-chain fallback, out of `all_exports[]`). This is
        // an AST parent-kind gate, NOT a source-line regex.
        Language::TypeScript | Language::JavaScript => {
            let mut p = node.parent();
            while matches!(p.map(|n| n.kind()), Some("ambient_declaration")) {
                p = p.and_then(|n| n.parent());
            }
            matches!(p.map(|n| n.kind()), Some("export_statement"))
        }
        // For other languages, default to public
        _ => true,
    }
}

/// RC2-2-visibility-ts-kotlin-swift: return true when a Swift declaration is
/// non-public for the interface member view, i.e. it carries an explicit
/// `private` or `fileprivate` access level. tree-sitter-swift exposes the
/// access keyword as a `visibility_modifier` (or `access_level_modifier`) that
/// is either a direct child of the declaration or nested under a `modifiers`
/// wrapper — mirroring `extract_swift_visibility` in `ast/extract.rs`. The
/// Swift default is `internal`, and `internal`/`public`/`open`/`package` all
/// stay public here, so only the two file-scoped levels are filtered.
fn swift_member_is_non_public(node: Node, source: &[u8]) -> bool {
    matches!(
        swift_access_keyword(node, source).as_deref(),
        Some("private" | "fileprivate")
    )
}

/// AST-driven read of a Swift declaration's access keyword. Returns the bare
/// keyword (`public`/`open`/`internal`/`fileprivate`/`private`/`package`) when
/// an explicit access modifier is present, or `None` for the implicit default.
/// The leading-token split tolerates the `private(set)` / `fileprivate(set)`
/// property forms (the surfaced keyword is the access level, not `(set)`).
fn swift_access_keyword(node: Node, source: &[u8]) -> Option<String> {
    const KEYWORDS: &[&str] = &[
        "public",
        "open",
        "internal",
        "fileprivate",
        "private",
        "package",
    ];
    fn leading_keyword(text: &str) -> Option<String> {
        let kw = text
            .trim()
            .split(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        if KEYWORDS.contains(&kw) {
            Some(kw.to_string())
        } else {
            None
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "visibility_modifier" | "access_level_modifier" => {
                if let Some(kw) = leading_keyword(node_text(child, source)) {
                    return Some(kw);
                }
            }
            "modifiers" => {
                let mut mc = child.walk();
                for m in child.children(&mut mc) {
                    if matches!(m.kind(), "visibility_modifier" | "access_level_modifier") {
                        if let Some(kw) = leading_keyword(node_text(m, source)) {
                            return Some(kw);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// interface-per-lang-v1 (v0.4.2 M-022): return true when a Scala
/// definition carries an explicit `private` or `protected` access
/// modifier. tree-sitter-scala emits these under a `modifiers >
/// access_modifier` child whose text is the keyword.
fn is_scala_non_public(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mc = child.walk();
            for m in child.children(&mut mc) {
                if m.kind() == "access_modifier" {
                    let txt = node_text(m, source).trim();
                    if txt == "private" || txt == "protected" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// =============================================================================
// Name Extraction
// =============================================================================

/// Get the name of a definition node based on language.
fn get_node_name<'a>(node: Node<'a>, source: &'a [u8], lang: Language) -> Option<String> {
    // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE): when
    // tree-sitter-cpp misparses `class TINYXML2_LIB Foo { ... };` as a
    // function_definition wrapping a `class_specifier` whose `name` field
    // points at the export-macro identifier (`TINYXML2_LIB`, `MYLIB_EXPORT`,
    // …), the canonical `child_by_field_name("name")` lookup below would
    // surface the MACRO as the class name. Detect the misparse shape
    // (class_specifier with no body field, parent is function_definition,
    // followed by an `identifier` sibling) and return the corrected real
    // class name instead. See BUG-CPP-P20-02 / tinyxml2.h regression.
    if matches!(lang, Language::Cpp)
        && matches!(node.kind(), "class_specifier" | "struct_specifier")
    {
        if let Some(corrected) = extract_cpp_macro_misparsed_class_name(node, source) {
            return Some(corrected);
        }
    }

    // First try the common "name" field
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(node_text(name_node, source).to_string());
    }

    match lang {
        Language::C | Language::Cpp => {
            // C/C++ function_definition has a "declarator" field
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_c_declarator_name(declarator, source);
            }
        }
        Language::Go => {
            // Go type_declaration wraps type_spec which has the name
            if node.kind() == "type_declaration" {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_spec" {
                            if let Some(name_node) = child.child_by_field_name("name") {
                                return Some(node_text(name_node, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        Language::Kotlin => {
            // RC2-META Stage 3 (kotlin): `typealias Name = T` stores the alias
            // name under the grammar's `type` field (an `identifier`), not a
            // `name` field, so the common lookup above misses it.
            if node.kind() == "type_alias" {
                if let Some(t) = node.child_by_field_name("type") {
                    return Some(node_text(t, source).to_string());
                }
            }
        }
        Language::Rust => {
            // Rust impl_item doesn't always have a "name" field
            if node.kind() == "impl_item" {
                // CF1-S4 (v0.5.0 RC): normalize the impl'd type to its BASE
                // name. The `type` field of an `impl<…> Foo<T, U> { … }` block is
                // a `generic_type` whose verbatim text carries the type
                // arguments (`Foo<'a, M, W>`), so the impl surfaced under a
                // DIFFERENT name than its `struct Foo` declaration
                // (`Foo` vs `Foo<'a, M, W>`) — an inconsistent class entry that
                // `merge_rust_impl_entries` could not always coalesce. Peel the
                // `generic_type` to its `type` field (AST-structural, NOT a
                // substring scan) so every Rust entry renders the bare base name.
                if let Some(type_node) = node.child_by_field_name("type") {
                    return Some(rust_type_base_name(type_node, source));
                }
                // Fallback: find type_identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_identifier" || child.kind() == "generic_type" {
                            return Some(rust_type_base_name(child, source));
                        }
                    }
                }
            }
        }
        Language::Elixir => {
            // In Elixir, `def` and `defmodule` are call nodes
            // The first argument is the name
            if node.kind() == "call" {
                if let Some(target) = node.child(0) {
                    let target_text = node_text(target, source);
                    if target_text == "def"
                        || target_text == "defp"
                        || target_text == "defmacro"
                        || target_text == "defmacrop"
                        || target_text == "defmodule"
                    {
                        // The Elixir tree-sitter grammar exposes the
                        // arguments either via a named "arguments" field
                        // or as the second positional child depending on
                        // grammar version. Try field first, fall back to
                        // child(1) — and accept either an `arguments`
                        // wrapper or a bare `call`/`identifier`.
                        let args_node = node
                            .child_by_field_name("arguments")
                            .or_else(|| node.child(1));
                        if let Some(args) = args_node {
                            // If args is the `arguments` wrapper, peel one
                            // level. Otherwise `args` itself is the first
                            // argument node (call / identifier / alias).
                            let first_arg = if args.kind() == "arguments" {
                                args.child(0)
                            } else {
                                Some(args)
                            };
                            if let Some(first_arg) = first_arg {
                                // For def/defp, the first arg may be a call (name + params)
                                if first_arg.kind() == "call" {
                                    if let Some(fn_name) = first_arg.child(0) {
                                        return Some(node_text(fn_name, source).to_string());
                                    }
                                }
                                // For def with a guard: `def fn(x) when guard`,
                                // the first arg is a `binary_operator` whose
                                // left side is the call we want.
                                if first_arg.kind() == "binary_operator" {
                                    let mut bin_cursor = first_arg.walk();
                                    for bin_child in first_arg.children(&mut bin_cursor) {
                                        if bin_child.kind() == "call" {
                                            if let Some(fname) = bin_child.child(0) {
                                                return Some(
                                                    node_text(fname, source).to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                                return Some(node_text(first_arg, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        Language::Ocaml => {
            // OCaml `value_definition` wraps one or more `let_binding` children.
            // The function name lives on `let_binding.pattern` (a `value_name`).
            // BUG-AGG-8 (P11): the interface extractor was walking
            // `value_definition` directly and querying `child_by_field_name("name")`
            // which doesn't exist for OCaml — leaving every name empty.
            if node.kind() == "value_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "let_binding" {
                        if let Some(pat) = child.child_by_field_name("pattern") {
                            return Some(node_text(pat, source).to_string());
                        }
                    }
                }
            }
            if node.kind() == "let_binding" {
                if let Some(pat) = node.child_by_field_name("pattern") {
                    return Some(node_text(pat, source).to_string());
                }
            }
            // language-adapters-completeness-v1 (BUG-AGG12-9): the
            // synthetic class node for an OCaml file is a
            // `module_definition` (e.g. `module Make (V) = struct ... end`
            // in dune's dag.ml). The grammar does not expose a `name`
            // field on `module_definition`; the name lives on the
            // first `module_name` child of the inner `module_binding`.
            // P11's BUG-AGG-8 fix only addressed the function-level
            // extractor (`value_definition` / `let_binding`); module
            // wrappers remained nameless, surfacing as empty strings in
            // every interface report for files that wrap their content
            // in a functor or named module.
            if node.kind() == "module_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "module_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if bind_child.kind() == "module_name" {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                }
            }
            // CF1-S4 (v0.5.0 RC): a real OCaml class. `class_definition` wraps
            // one or more `class_binding` children; the name lives on the
            // binding's `class_name` child (there is no `name` field). Mirrors
            // `extract_class_binding` in `inheritance/ocaml.rs`.
            if node.kind() == "class_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "class_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if bind_child.kind() == "class_name" {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                }
            }
            // CF1-S4: `class type ct = object … end` — the OCaml class signature.
            // `class_type_definition` wraps `class_type_binding`, whose name is
            // the `class_type_name` child.
            if node.kind() == "class_type_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "class_type_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if bind_child.kind() == "class_type_name" {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                }
            }
            // CF1-S4: class members. `method_definition` (in `object_expression`)
            // and `method_specification` / `method_type` (in `class_body_type`)
            // all carry the member name as a `method_name` child, not a `name`
            // field, so the common lookup above misses it.
            if matches!(
                node.kind(),
                "method_definition" | "method_specification" | "method_type"
            ) {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "method_name" {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
            // `type t = { ... }` and similar — the type name is the
            // first `type_constructor` (or fallback identifier) child.
            if node.kind() == "type_definition" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "type_binding" {
                        let mut bind_cursor = child.walk();
                        for bind_child in child.children(&mut bind_cursor) {
                            if matches!(
                                bind_child.kind(),
                                "type_constructor" | "type_constructor_path"
                            ) {
                                return Some(node_text(bind_child, source).to_string());
                            }
                        }
                    }
                    if matches!(child.kind(), "type_constructor" | "type_constructor_path") {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Lua | Language::Luau => {
            // Try the "name" field first (already done above), then check child nodes
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" || child.kind() == "dot_index_expression" {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Ruby => {
            // Ruby methods: first identifier child after "def"
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" || child.kind() == "constant" {
                        return Some(node_text(child, source).to_string());
                    }
                }
            }
        }
        _ => {}
    }

    None
}

/// CF1-S4 (v0.5.0 RC): return the BASE name of a Rust type node, peeling any
/// generic-argument layer structurally. A `generic_type` (`Foo<T, U>`) exposes
/// its base as the `type` field child (a `type_identifier` or
/// `scoped_type_identifier`), so we descend that field instead of slicing the
/// node text on `<` — this stays AST-driven and is recursion-safe for nested
/// generics. Any other type node (bare `type_identifier`, `scoped_type_identifier`)
/// is already its own base and is returned verbatim.
fn rust_type_base_name(type_node: Node, source: &[u8]) -> String {
    if type_node.kind() == "generic_type" {
        if let Some(base) = type_node.child_by_field_name("type") {
            return rust_type_base_name(base, source);
        }
    }
    node_text(type_node, source).to_string()
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
/// Detect the export-macro misparse shape and return the real class name.
///
/// tree-sitter-cpp parses `class TINYXML2_LIB Foo { ... };` as:
///   function_definition
///     class_specifier (name=type_identifier "TINYXML2_LIB", no body field)
///     identifier "Foo"             <-- the REAL class name
///     [ERROR : public Base]?       <-- base-clause hint (optional)
///     compound_statement { ... }   <-- the REAL class body
///
/// Returns `Some(real_name)` only when the class_specifier:
///   1. has no `body` field of its own (would have been `field_declaration_list`),
///   2. has a `function_definition` parent, AND
///   3. an `identifier` sibling appears after it inside that parent.
///
/// Otherwise returns `None` so callers fall back to the canonical name field.
fn extract_cpp_macro_misparsed_class_name(
    class_node: Node,
    source: &[u8],
) -> Option<String> {
    // Real class declarations have a field_declaration_list body. If a body
    // is present, this is NOT the macro-misparse shape.
    if class_node.child_by_field_name("body").is_some() {
        return None;
    }
    // Defense-in-depth: also reject if the class_specifier has a
    // field_declaration_list anywhere among its direct children (some
    // grammar versions may not expose it via the "body" field name).
    let mut self_cursor = class_node.walk();
    for child in class_node.children(&mut self_cursor) {
        if child.kind() == "field_declaration_list" {
            return None;
        }
    }

    // Look up to a function_definition parent — that's the misparse wrapper.
    let parent = class_node.parent()?;
    if parent.kind() != "function_definition" {
        return None;
    }

    // Find the class_specifier's position among parent's children, then
    // scan forward for the first `identifier` (the real class name).
    let mut pcursor = parent.walk();
    let mut saw_class_specifier = false;
    for sib in parent.children(&mut pcursor) {
        if !saw_class_specifier {
            if sib.id() == class_node.id() {
                saw_class_specifier = true;
            }
            continue;
        }
        // After the class_specifier, the next bare `identifier` is the
        // real class name. Skip ERROR / compound_statement wrappers.
        if sib.kind() == "identifier" {
            let text = node_text(sib, source).to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): return the
/// `compound_statement` sibling that holds the real class body when
/// `class_specifier` is the macro-misparse shape. Returns `None` for the
/// canonical (well-parsed) shape so callers fall back to
/// `field_declaration_list`.
fn extract_cpp_macro_misparsed_class_body<'a>(class_node: Node<'a>) -> Option<Node<'a>> {
    if class_node.child_by_field_name("body").is_some() {
        return None;
    }
    let parent = class_node.parent()?;
    if parent.kind() != "function_definition" {
        return None;
    }
    let mut pcursor = parent.walk();
    let mut saw_class_specifier = false;
    for sib in parent.children(&mut pcursor) {
        if !saw_class_specifier {
            if sib.id() == class_node.id() {
                saw_class_specifier = true;
            }
            continue;
        }
        if sib.kind() == "compound_statement" {
            return Some(sib);
        }
    }
    None
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): true iff this
/// `function_definition` is actually a macro-prefixed class declaration
/// (e.g. `class TINYXML2_LIB Foo { ... };`) that tree-sitter-cpp misparsed.
/// Used by the deep walker so the misparsed wrapper is not emitted as a
/// top-level function (the inner class_specifier produces the class entry
/// instead).
fn is_cpp_macro_misparsed_class_wrapper(func_def: Node) -> bool {
    if func_def.kind() != "function_definition" {
        return false;
    }
    let mut cursor = func_def.walk();
    for child in func_def.children(&mut cursor) {
        if matches!(child.kind(), "class_specifier" | "struct_specifier") {
            if child.child_by_field_name("body").is_some() {
                continue;
            }
            // No own body — confirm there's a compound_statement sibling
            // so the misparse shape is unambiguous (otherwise the
            // class_specifier could be a forward declaration nested in
            // an unrelated function signature).
            let mut sib_cursor = func_def.walk();
            let mut saw = false;
            for sib in func_def.children(&mut sib_cursor) {
                if !saw {
                    if sib.id() == child.id() {
                        saw = true;
                    }
                    continue;
                }
                if sib.kind() == "compound_statement" {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract name from a C/C++ declarator (which may be nested).
///
/// cl6-interface-v1 (GH #78): besides the plain `identifier` /
/// `field_identifier` leaves, C++ member-function declarators terminate in
/// three other named leaves that the legacy extractor dropped (producing an
/// empty name → the member silently vanished from `tldr interface`):
///
///   * `destructor_name`     → `~StrPair`
///   * `operator_name`       → `operator[]`, `operator=`, `operator==`
///   * `qualified_identifier` / `scoped_identifier`
///     → out-of-class definitions `Foo::method`; we keep the trailing
///     name segment (`method`) so the member matches its in-class
///     spelling, falling back to the full qualified text only when the
///     segment cannot be resolved.
///
/// This mirrors the canonical leaf handling in
/// `tldr-core::analysis::references::find_cpp_declarator_match`.
fn extract_c_declarator_name(declarator: Node, source: &[u8]) -> Option<String> {
    match declarator.kind() {
        // Plain leaves and the C++ operator / destructor leaves all carry the
        // member name verbatim as their own text.
        "identifier" | "field_identifier" | "destructor_name" | "operator_name" => {
            return Some(node_text(declarator, source).to_string());
        }
        "qualified_identifier" | "scoped_identifier" => {
            // `Foo::bar` — the trailing `name` field is the member's own
            // (possibly further-qualified) name. Recurse into it so a
            // `Foo::Inner::method` resolves to `method`.
            if let Some(name_node) = declarator.child_by_field_name("name") {
                if let Some(resolved) = extract_c_declarator_name(name_node, source) {
                    return Some(resolved);
                }
            }
            // Couldn't resolve the trailing segment — keep the full
            // qualified text so the member doesn't disappear entirely.
            return Some(node_text(declarator, source).to_string());
        }
        _ => {}
    }
    // function_declarator (and the pointer/reference/parenthesized/init
    // wrappers a return type introduces) carries the name via its
    // `declarator` field.
    if let Some(inner) = declarator.child_by_field_name("declarator") {
        return extract_c_declarator_name(inner, source);
    }
    // cl6-interface-v1 (GH #78): some wrapper declarators do NOT expose the
    // inner declarator via the `declarator` field — notably
    // `reference_declarator` / `pointer_declarator` for a `T& operator[]()` /
    // `T* foo()` return type, where the inner `function_declarator` is a bare
    // positional child after the `&` / `*` token. Scan all children for the
    // next recursable declarator or named leaf so these names are not dropped.
    let mut cursor = declarator.walk();
    for child in declarator.children(&mut cursor) {
        if matches!(
            child.kind(),
            "identifier"
                | "field_identifier"
                | "destructor_name"
                | "operator_name"
                | "qualified_identifier"
                | "scoped_identifier"
                | "function_declarator"
                | "pointer_declarator"
                | "reference_declarator"
                | "parenthesized_declarator"
                | "init_declarator"
        ) {
            if let Some(resolved) = extract_c_declarator_name(child, source) {
                return Some(resolved);
            }
        }
    }
    None
}

// =============================================================================
// __all__ Extraction (Python-specific)
// =============================================================================

/// Extract the contents of `__all__` if defined in the module (Python only).
pub fn extract_all_exports(root: Node, source: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        if child.kind() == "expression_statement" {
            if let Some(assignment) = child.child(0) {
                if assignment.kind() == "assignment" {
                    if let Some(left) = assignment.child_by_field_name("left") {
                        if left.kind() == "identifier" {
                            let name = node_text(left, source);
                            if name == "__all__" {
                                if let Some(right) = assignment.child_by_field_name("right") {
                                    return extract_list_strings(right, source);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Extract string elements from a list node.
fn extract_list_strings(node: Node, source: &[u8]) -> Option<Vec<String>> {
    if node.kind() != "list" {
        return None;
    }

    let mut exports = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "string" {
            let text = node_text(child, source);
            let cleaned = text
                .trim_start_matches(['"', '\''])
                .trim_end_matches(['"', '\'']);
            exports.push(cleaned.to_string());
        }
    }

    if exports.is_empty() {
        None
    } else {
        Some(exports)
    }
}

// =============================================================================
// Signature Extraction (Language-Aware)
// =============================================================================

/// Extract the function signature from a definition node.
///
/// For Python, reconstructs from parameter nodes.
/// For other languages, extracts the raw text of parameters and return type.
pub fn extract_function_signature(func_node: Node, source: &[u8], lang: Language) -> String {
    match lang {
        Language::Python => extract_python_signature(func_node, source),
        Language::Rust => extract_rust_signature(func_node, source),
        Language::Go => extract_go_signature(func_node, source),
        Language::Java | Language::CSharp => extract_java_like_signature(func_node, source),
        Language::TypeScript | Language::JavaScript => extract_ts_signature(func_node, source),
        Language::C | Language::Cpp => extract_c_signature(func_node, source),
        Language::Ruby => extract_ruby_signature(func_node, source),
        Language::Php => extract_php_signature(func_node, source),
        Language::Scala => extract_scala_signature(func_node, source),
        Language::Ocaml => extract_ocaml_signature(func_node, source),
        Language::Elixir => extract_elixir_signature(func_node, source),
        Language::Swift => extract_swift_signature(func_node, source),
        // CF1-S4 (v0.5.0 RC): Kotlin & Solidity had no signature arm, so every
        // function/method rendered `signature: ""` (the generic fallback's
        // `child_by_field_name("parameters")` finds nothing — neither grammar
        // exposes a `parameters` field). Both reconstruct the signature span
        // AST-driven, mirroring the Swift extractor.
        Language::Kotlin => extract_kotlin_signature(func_node, source),
        Language::Solidity => extract_solidity_signature(func_node, source),
        _ => extract_generic_signature(func_node, source),
    }
}

/// Kotlin signature: the `(parameters)` clause plus any `: ReturnType` (and
/// `where` constraints), excluding the body.
///
/// CF1-S4 (v0.5.0 RC): tree-sitter-kotlin-ng models a `function_declaration`
/// with the parameter list as a `function_value_parameters` child and the
/// return type as a sibling `type` node BETWEEN the parameters and the
/// `function_body` — there is no `parameters` field, so the generic extractor
/// returned an empty string for every Kotlin function (#CF1). Slice the source
/// from the parameter clause up to (but excluding) the body, capturing
/// `(x: Int): String` verbatim. For abstract / interface members with no body
/// the span runs to the node end (`(): Int`).
fn extract_kotlin_signature(func_node: Node, source: &[u8]) -> String {
    let mut params: Option<Node> = None;
    let mut body: Option<Node> = None;
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        match child.kind() {
            "function_value_parameters" if params.is_none() => params = Some(child),
            "function_body" => body = Some(child),
            _ => {}
        }
    }

    let Some(p) = params else {
        return extract_generic_signature(func_node, source);
    };
    let start = p.start_byte();
    let end = match body {
        Some(b) => b.start_byte(),
        None => func_node.end_byte(),
    };
    if start >= end || end > source.len() {
        return extract_generic_signature(func_node, source);
    }
    std::str::from_utf8(&source[start..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Solidity signature: the `(parameters)` clause plus the visibility /
/// mutability / modifier keywords and the `returns (...)` clause, excluding the
/// body.
///
/// CF1-S4 (v0.5.0 RC): tree-sitter-solidity models a `function_definition`'s
/// parameters as LOOSE `parameter` children (no `parameter_list` wrapper and no
/// `parameters` field), with the `return_type`, `visibility` and
/// `state_mutability` as sibling nodes after the closing `)`. The generic
/// extractor therefore returned an empty string for every Solidity
/// function/method/modifier/constructor (#CF1). Slice from the opening `(` of
/// the parameter clause up to the body (or node end for a bodyless interface
/// requirement), yielding e.g. `(address to, uint256 amount) external returns
/// (bool)`.
fn extract_solidity_signature(func_node: Node, source: &[u8]) -> String {
    let mut open_paren: Option<Node> = None;
    let mut body: Option<Node> = None;
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "(" && open_paren.is_none() {
            open_paren = Some(child);
        }
        if child.kind() == "function_body" {
            body = Some(child);
        }
    }

    let Some(open) = open_paren else {
        return extract_generic_signature(func_node, source);
    };
    let start = open.start_byte();
    let end = match body {
        Some(b) => b.start_byte(),
        None => func_node.end_byte(),
    };
    if start >= end || end > source.len() {
        return extract_generic_signature(func_node, source);
    }
    std::str::from_utf8(&source[start..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Swift signature: the parameter clause plus any `async`/`throws` effects and
/// the `-> ReturnType`. tree-sitter-swift does NOT expose a `parameters` field
/// (params are loose `parameter` children between `(` and `)`), so the generic
/// `child_by_field_name("parameters")` extractor returned an empty string for
/// EVERY Swift method (#239). Reconstruct AST-driven by slicing the source from
/// the opening `(` up to (but excluding) the `function_body` — this captures
/// `(using e: Encoder) throws -> URLRequest` verbatim while dropping the body.
/// For `init`/bodyless/protocol requirements the same span logic applies.
fn extract_swift_signature(func_node: Node, source: &[u8]) -> String {
    // Find the opening `(` of the parameter clause and the body (if any).
    let mut open_paren: Option<Node> = None;
    let mut body: Option<Node> = None;
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "(" && open_paren.is_none() {
            open_paren = Some(child);
        }
        if child.kind() == "function_body" {
            body = Some(child);
        }
    }

    let Some(open) = open_paren else {
        // No parameter clause found — fall back to the generic extractor.
        return extract_generic_signature(func_node, source);
    };

    let start = open.start_byte();
    // End at the body's start (dropping `{ ... }`), else at the node end
    // (bodyless protocol/abstract requirement).
    let end = match body {
        Some(b) => b.start_byte(),
        None => func_node.end_byte(),
    };
    if start >= end || end > source.len() {
        return extract_generic_signature(func_node, source);
    }
    std::str::from_utf8(&source[start..end])
        .unwrap_or("")
        .trim()
        .to_string()
}

/// OCaml signature: walk the `let_binding` parameters and optional return type.
///
/// BUG-AGG-8 (P11): without an OCaml-specific signature extractor the
/// generic fallback (`child_by_field_name("parameters")`) returns nothing,
/// so signatures are empty strings even when names are present.
fn extract_ocaml_signature(func_node: Node, source: &[u8]) -> String {
    // Find the inner let_binding if we were handed a value_definition.
    let binding_owned;
    let binding = if func_node.kind() == "value_definition" {
        let mut found: Option<Node> = None;
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                found = Some(child);
                break;
            }
        }
        match found {
            Some(b) => {
                binding_owned = b;
                binding_owned
            }
            None => return String::new(),
        }
    } else {
        func_node
    };

    let mut params = Vec::new();
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        if child.kind() == "parameter" {
            // Parameter may have a "pattern" field with value_pattern /
            // typed_pattern / unit / tuple_pattern, or fall back to the
            // raw text.
            if let Some(pattern) = child.child_by_field_name("pattern") {
                let text = node_text(pattern, source).trim();
                if !text.is_empty() {
                    params.push(text.to_string());
                    continue;
                }
            }
            // Fallback: walk children for value_pattern / value_name.
            let mut inner_cursor = child.walk();
            let mut handled = false;
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "value_pattern" || inner.kind() == "value_name" {
                    params.push(node_text(inner, source).to_string());
                    handled = true;
                    break;
                }
            }
            if !handled {
                let text = node_text(child, source).trim();
                if !text.is_empty() {
                    params.push(text.to_string());
                }
            }
        }
    }

    let mut sig = format!("({})", params.join(", "));

    // Optional return type: `: type` between the last parameter and `=`.
    let return_type = extract_ocaml_signature_return_type(binding, source);
    if let Some(ret) = return_type {
        sig.push_str(" : ");
        sig.push_str(&ret);
    }

    sig
}

fn extract_ocaml_signature_return_type(binding: Node, source: &[u8]) -> Option<String> {
    let mut last_was_colon = false;
    let mut past_all_params = false;
    let mut cursor = binding.walk();
    for child in binding.children(&mut cursor) {
        let kind = child.kind();
        if kind == "parameter" {
            past_all_params = false;
            last_was_colon = false;
            continue;
        }
        if kind != "parameter" && !past_all_params {
            past_all_params = true;
        }
        if past_all_params && kind == ":" {
            last_was_colon = true;
            continue;
        }
        if last_was_colon && kind == "=" {
            return None;
        }
        if last_was_colon && kind != "=" {
            let t = node_text(child, source).trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
            last_was_colon = false;
        }
        if kind == "=" {
            break;
        }
    }
    None
}

/// Elixir signature: extract the parameter list of a `def`/`defp`/`defmacro`
/// call node. BUG-AGG-9 (P11): without an Elixir-specific signature
/// extractor, `tldr interface` would emit empty signatures for Elixir
/// modules even after wiring up name extraction.
fn extract_elixir_signature(func_node: Node, source: &[u8]) -> String {
    if func_node.kind() != "call" {
        return String::new();
    }
    // Structure: (call (identifier "def") (arguments (call (identifier "name") (arguments ...))))
    let args_node = match func_node
        .child_by_field_name("arguments")
        .or_else(|| func_node.child(1))
    {
        Some(a) => a,
        None => return String::new(),
    };
    let first_arg = if args_node.kind() == "arguments" {
        match args_node.child(0) {
            Some(a) => a,
            None => return String::new(),
        }
    } else {
        args_node
    };

    // Identifier-only def (no params): `def foo do ... end`
    if first_arg.kind() == "identifier" {
        return "()".to_string();
    }

    // call form: `def foo(a, b)` -> first_arg is a call(name, arguments)
    let inner_call = match first_arg.kind() {
        "call" => first_arg,
        "binary_operator" => {
            // `def foo(...) when guard` — find the inner call.
            let mut found: Option<Node> = None;
            let mut cursor = first_arg.walk();
            for c in first_arg.children(&mut cursor) {
                if c.kind() == "call" {
                    found = Some(c);
                    break;
                }
            }
            match found {
                Some(c) => c,
                None => return String::new(),
            }
        }
        _ => return String::new(),
    };

    // The call's second child is its `arguments` block. The arguments
    // text is the raw source slice — for `def foo(a, b)` that's `(a, b)`,
    // so just emit it verbatim. When it's a bareword call (no parens) the
    // text won't have surrounding parens; wrap it in that case.
    if let Some(call_args) = inner_call.child(1) {
        if call_args.kind() == "arguments" {
            let raw = node_text(call_args, source).trim();
            if raw.starts_with('(') && raw.ends_with(')') {
                return raw.to_string();
            }
            return format!("({})", raw);
        }
    }
    "()".to_string()
}

/// Python signature: reconstruct from parameter nodes.
fn extract_python_signature(func_node: Node, source: &[u8]) -> String {
    let mut params = Vec::new();

    if let Some(params_node) = func_node.child_by_field_name("parameters") {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            match child.kind() {
                "identifier" => {
                    params.push(node_text(child, source).to_string());
                }
                "typed_parameter" => {
                    params.push(extract_typed_parameter(child, source));
                }
                "default_parameter" => {
                    params.push(extract_default_parameter(child, source));
                }
                "typed_default_parameter" => {
                    params.push(extract_typed_default_parameter(child, source));
                }
                "list_splat_pattern" | "dictionary_splat_pattern" => {
                    params.push(node_text(child, source).to_string());
                }
                _ => {}
            }
        }
    }

    let params_str = params.join(", ");
    let mut signature = format!("({})", params_str);

    if let Some(return_type) = func_node.child_by_field_name("return_type") {
        let return_text = node_text(return_type, source);
        signature.push_str(" -> ");
        signature.push_str(return_text);
    }

    signature
}

/// Rust signature: extract parameters and return type.
fn extract_rust_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(" -> ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Go signature: extract parameters and return type.
fn extract_go_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(result) = func_node.child_by_field_name("result") {
        sig.push(' ');
        sig.push_str(node_text(result, source));
    }

    sig
}

/// Java/C# signature: extract parameters from formal_parameters.
fn extract_java_like_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    // Try "parameters" field first, then look for "formal_parameters" or a parameter_list child
    let params_node = func_node.child_by_field_name("parameters").or_else(|| {
        // Search for formal_parameters or parameter_list node among children
        let mut cursor = func_node.walk();
        let found = func_node
            .children(&mut cursor)
            .find(|&child| child.kind() == "formal_parameters" || child.kind() == "parameter_list");
        found
    });

    if let Some(params) = params_node {
        sig.push_str(node_text(params, source));
    }

    // For Java, check for return type (it's the "type" field)
    if let Some(ret) = func_node.child_by_field_name("type") {
        // Prepend return type
        let ret_text = node_text(ret, source);
        sig = format!("{}: {}", sig, ret_text);
    }

    sig
}

/// TypeScript/JavaScript signature.
fn extract_ts_signature(func_node: Node, source: &[u8]) -> String {
    // RC2-META Stage 1: route the TS/JS signature through the shared
    // header-span resolver so `interface` renders the SAME un-mangled
    // signature as `structure`/`extract`. The legacy code concatenated the
    // `parameters` field with the `return_type` field whose text ALREADY
    // carries its own leading `: ` — producing the mangled double colon
    // `(): : void` and dropping the method name entirely. The shared resolver
    // pins the header span (name + params + return type, excluding the body),
    // yielding `m(): void`.
    let src = std::str::from_utf8(source).unwrap_or("");
    tldr_core::ast::entity::signature_from_header(func_node, src)
}

/// C/C++ signature: extract from declarator.
fn extract_c_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        // The declarator includes function name and parameter list
        // We want just the parameters portion
        if let Some(params) = declarator.child_by_field_name("parameters") {
            sig.push_str(node_text(params, source));
        }
    }

    // Return type is typically the first child (type specifier)
    if let Some(type_node) = func_node.child_by_field_name("type") {
        let type_text = node_text(type_node, source);
        if !type_text.is_empty() {
            sig = format!("{}: {}", sig, type_text);
        }
    }

    sig
}

/// Ruby signature.
fn extract_ruby_signature(func_node: Node, source: &[u8]) -> String {
    if let Some(params) = func_node.child_by_field_name("parameters") {
        node_text(params, source).to_string()
    } else {
        // Check for method_parameters child
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "method_parameters" {
                return node_text(child, source).to_string();
            }
        }
        "()".to_string()
    }
}

/// PHP signature.
fn extract_php_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(": ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Scala signature.
fn extract_scala_signature(func_node: Node, source: &[u8]) -> String {
    // cl4-interface-v1 (IT3-scala-01/02/03, GH #78): a Scala
    // `function_definition` exposes BOTH its type-parameter list and every
    // (possibly curried) value-parameter clause under the SAME field name
    // `parameters`. The tree-sitter-scala grammar models them as distinct
    // node KINDS, though: `type_parameters` for `[F[_], A]` and `parameters`
    // for `(capacity: Int)` / `(implicit F: ...)`. The previous extractor
    // used `child_by_field_name("parameters")`, which returns only the FIRST
    // such child — the `type_parameters` list — so the real value parameter
    // `capacity` was dropped and the type parameters were reported as params.
    // Walk all field-`parameters` children and keep the curried value
    // clauses (kind == "parameters"), preserving the leading type-parameter
    // list separately so generic methods still surface their type variables.
    let mut type_params = String::new();
    let mut value_clauses = String::new();
    let mut cursor = func_node.walk();
    let mut idx = 0u32;
    for child in func_node.children(&mut cursor) {
        if func_node.field_name_for_child(idx) == Some("parameters") {
            match child.kind() {
                "type_parameters" => {
                    // Only one type-parameter list is legal; keep the first.
                    if type_params.is_empty() {
                        type_params.push_str(node_text(child, source));
                    }
                }
                "parameters" => {
                    // Curried value clauses: concatenate each `(...)` clause
                    // verbatim so `(capacity: Int)(implicit F: ...)` is kept.
                    value_clauses.push_str(node_text(child, source));
                }
                _ => {}
            }
        }
        idx += 1;
    }

    let mut sig = String::new();
    sig.push_str(&type_params);
    sig.push_str(&value_clauses);

    if let Some(ret) = func_node.child_by_field_name("return_type") {
        sig.push_str(": ");
        sig.push_str(node_text(ret, source));
    }

    sig
}

/// Generic signature: try to find parameters/return type fields.
fn extract_generic_signature(func_node: Node, source: &[u8]) -> String {
    let mut sig = String::new();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        sig.push_str(node_text(params, source));
    }

    sig
}

/// Extract a typed parameter (name: type) - Python-specific.
fn extract_typed_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child(0)
        .filter(|c| c.kind() == "identifier")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let type_hint = node
        .child_by_field_name("type")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    if type_hint.is_empty() {
        name.to_string()
    } else {
        format!("{}: {}", name, type_hint)
    }
}

/// Extract a default parameter (name=default) - Python-specific.
fn extract_default_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let value = node
        .child_by_field_name("value")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    format!("{} = {}", name, value)
}

/// Extract a typed default parameter (name: type = default) - Python-specific.
fn extract_typed_default_parameter(node: Node, source: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let type_hint = node
        .child_by_field_name("type")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let value = node
        .child_by_field_name("value")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    if type_hint.is_empty() {
        format!("{} = {}", name, value)
    } else {
        format!("{}: {} = {}", name, type_hint, value)
    }
}

// =============================================================================
// Function Info Extraction (Language-Aware)
// =============================================================================

/// Extract function information from a function definition node.
pub fn extract_function_info(func_node: Node, source: &[u8], lang: Language) -> FunctionInfo {
    let name = get_node_name(func_node, source, lang).unwrap_or_default();
    let signature = extract_function_signature(func_node, source, lang);
    let lineno = func_node.start_position().row as u32 + 1;
    let is_async = detect_async(func_node, source, lang);
    let docstring = extract_docstring(func_node, source, lang);

    // RC2-META Stage 3 (elixir): tag the entity kind from the canonical
    // `classify_node` discriminator so `interface` reports `defmacro`/
    // `defmacrop` as kind="macro" and `def`/`defp` as kind="function" — the
    // #57 bidirectional seam (structure's `definitions` now agrees on
    // kind="macro" for the same nodes).
    //
    // RC2-META Stage 3 (java): extend the same canonical population to Java so
    // `interface` reports `method_declaration` as kind="method" and
    // `constructor_declaration` as kind="constructor", in agreement with
    // `structure`/`extract`. Every other (non-elixir, non-java) language keeps
    // `kind: None` (omitted from JSON via `skip_serializing_if`).
    //
    // RC2-META Stage 3 (lua/luau): Lua has no `class`/`method`/`macro` surface —
    // a module's public functions are plain `function_declaration` /
    // `function_definition_statement` nodes, which the canonical `classify_node`
    // maps to `EntityKind::Function`. Populating the additive `kind` here makes
    // `interface` report `kind:"function"` for every exported Lua/Luau function,
    // in agreement with what `structure`'s `definitions` already emits
    // (kind="function"). No class kind is invented for the table-convention
    // "classes" (those have no single AST node `classify_node` can classify).
    let kind = if lang == Language::Elixir
        || lang == Language::Java
        || lang == Language::Lua
        || lang == Language::Luau
    {
        let src_str = std::str::from_utf8(source).unwrap_or("");
        tldr_core::ast::entity::classify_node(func_node, lang, src_str)
            .map(|k| k.as_str().to_string())
    } else {
        None
    };

    FunctionInfo {
        name,
        signature,
        docstring,
        lineno,
        is_async,
        kind,
    }
}

/// Detect if a function is async.
fn detect_async(func_node: Node, source: &[u8], lang: Language) -> bool {
    match lang {
        Language::Python => {
            let func_text = node_text(func_node, source);
            func_text.starts_with("async ")
        }
        Language::Rust => {
            // Check for "async" keyword child
            for i in 0..func_node.child_count() {
                if let Some(child) = func_node.child(i) {
                    if node_text(child, source) == "async" {
                        return true;
                    }
                }
            }
            false
        }
        Language::TypeScript | Language::JavaScript => {
            // Check for async keyword
            let func_text = node_text(func_node, source);
            func_text.starts_with("async ")
        }
        Language::CSharp => {
            // interface-per-lang-v1 (v0.4.2 M-022): tree-sitter-c-sharp
            // emits `modifier` nodes (singular, one per keyword) as
            // direct children of `method_declaration`, not under a
            // `modifiers` field. The legacy `child_by_field_name`
            // lookup therefore always returned None and every method
            // reported `is_async:false`.
            let mut cursor = func_node.walk();
            for child in func_node.children(&mut cursor) {
                if child.kind() == "modifier" && node_text(child, source) == "async" {
                    return true;
                }
            }
            // Defense-in-depth: also accept the legacy `modifiers` field
            // shape for grammar versions that may wrap them.
            if let Some(modifiers) = func_node.child_by_field_name("modifiers") {
                return node_text(modifiers, source).contains("async");
            }
            false
        }
        Language::Elixir => {
            // Elixir doesn't have async keyword in the traditional sense
            false
        }
        _ => false,
    }
}

// =============================================================================
// Docstring / Doc Comment Extraction (Language-Aware)
// =============================================================================

/// Extract docstring or doc comment from a function or class node.
fn extract_docstring(node: Node, source: &[u8], lang: Language) -> Option<String> {
    match lang {
        Language::Python => extract_python_docstring(node, source),
        Language::Rust => extract_rust_doc_comment(node, source),
        Language::Go => extract_go_doc_comment(node, source),
        Language::Java | Language::CSharp | Language::Scala | Language::Php => {
            extract_javadoc_comment(node, source)
        }
        Language::TypeScript | Language::JavaScript => extract_jsdoc_comment(node, source),
        Language::Ruby => extract_ruby_comment(node, source),
        Language::Elixir => extract_elixir_doc(node, source),
        _ => None,
    }
}

/// Python docstring: first string in function/class body.
fn extract_python_docstring(node: Node, source: &[u8]) -> Option<String> {
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        let first_stmt = body.children(&mut cursor).next();
        if let Some(child) = first_stmt {
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.child(0) {
                    if expr.kind() == "string" {
                        let text = node_text(expr, source);
                        let cleaned = text
                            .trim_start_matches("\"\"\"")
                            .trim_start_matches("'''")
                            .trim_end_matches("\"\"\"")
                            .trim_end_matches("'''")
                            .trim();
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Rust doc comments: /// or //! preceding the node.
fn extract_rust_doc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        let kind = sib.kind();
        if kind == "line_comment" {
            let text = node_text(sib, source);
            if text.starts_with("///") || text.starts_with("//!") {
                let content = text
                    .trim_start_matches("///")
                    .trim_start_matches("//!")
                    .trim();
                comments.push(content.to_string());
            } else {
                break;
            }
        } else if kind == "attribute_item" {
            // Skip attributes between doc comments
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Go doc comment: preceding line comment block.
fn extract_go_doc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "comment" {
            let text = node_text(sib, source);
            let content = text.trim_start_matches("//").trim();
            comments.push(content.to_string());
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Javadoc-style: /** ... */ preceding the node.
fn extract_javadoc_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        let kind = sib.kind();
        if kind == "block_comment" || kind == "comment" || kind == "multiline_comment" {
            let text = node_text(sib, source);
            if text.starts_with("/**") {
                let cleaned = text
                    .trim_start_matches("/**")
                    .trim_end_matches("*/")
                    .lines()
                    .map(|l| l.trim().trim_start_matches('*').trim())
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Some(cleaned);
            }
        } else if kind == "annotation" || kind == "marker_annotation" || kind == "attribute_list" {
            // Skip annotations/attributes
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }
    None
}

/// JSDoc: /** ... */ preceding the node.
fn extract_jsdoc_comment(node: Node, source: &[u8]) -> Option<String> {
    extract_javadoc_comment(node, source)
}

/// Ruby: # comments preceding the node.
fn extract_ruby_comment(node: Node, source: &[u8]) -> Option<String> {
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "comment" {
            let text = node_text(sib, source);
            let content = text.trim_start_matches('#').trim();
            comments.push(content.to_string());
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }

    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join("\n"))
    }
}

/// Elixir: @doc or @moduledoc preceding the node.
fn extract_elixir_doc(node: Node, source: &[u8]) -> Option<String> {
    let mut prev = node.prev_sibling();

    while let Some(sib) = prev {
        if sib.kind() == "unary_operator" || sib.kind() == "call" {
            let text = node_text(sib, source);
            if text.starts_with("@doc") || text.starts_with("@moduledoc") {
                // Extract the string content
                let cleaned = text
                    .trim_start_matches("@moduledoc")
                    .trim_start_matches("@doc")
                    .trim()
                    .trim_start_matches("\"\"\"")
                    .trim_end_matches("\"\"\"")
                    .trim_start_matches('"')
                    .trim_end_matches('"')
                    .trim();
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
        } else if sib.kind() == "comment" {
            // skip
        } else {
            break;
        }
        prev = sib.prev_sibling();
    }
    None
}

// =============================================================================
// Class Info Extraction (Language-Aware)
// =============================================================================

/// Extract class/struct/trait information from a definition node.
pub fn extract_class_info(class_node: Node, source: &[u8], lang: Language) -> ClassInfo {
    let name = get_node_name(class_node, source, lang).unwrap_or_default();
    let lineno = class_node.start_position().row as u32 + 1;

    // Extract base classes / implemented interfaces
    let bases = extract_base_classes(class_node, source, lang);

    // Extract methods
    let mut methods = Vec::new();
    let mut private_method_count = 0u32;

    let method_kinds = method_node_kinds(lang);
    let body_node = find_body_node(class_node, lang);

    if let Some(body) = body_node {
        collect_methods_from_body(
            body,
            source,
            lang,
            method_kinds,
            &mut methods,
            &mut private_method_count,
        );
    }

    // RC2-META Stage 3 (go): Go's container/type discriminator is NOT decidable
    // from the bare node-kind string — every Go type is a `type_declaration`
    // wrapping a `type_spec` (struct / interface / defined type) or `type_alias`.
    // Use the node-aware canonical `classify_node` (single source of truth) so
    // `interface` reports `struct`/`interface`/`type`/`class` in agreement with
    // `extract`, instead of an undifferentiated `kind: None`. Additive.
    let kind = match lang {
        // RC2-META Stage 3 (kotlin): like Go, Kotlin's container discriminator is
        // NOT decidable from the bare node-kind string — `class` / `interface` /
        // `enum class` are all `class_declaration`, distinguished structurally
        // (the `interface` keyword token, an `enum_class_body` child). Route
        // through the node-aware canonical `classify_node` (single source of
        // truth) so `interface` reports `class`/`interface`/`enum`/`object`/`type`
        // in agreement with `extract`, instead of an undifferentiated `kind:None`.
        // Additive.
        // RC2-META Stage 3 (swift): like Go/Kotlin, Swift's container
        // discriminator is NOT decidable from the bare node-kind string —
        // `class` / `struct` / `enum` / `extension` / `actor` are all
        // `class_declaration`, distinguished structurally by the leading keyword
        // token; `protocol_declaration` maps to Interface. Route through the
        // node-aware canonical `classify_node` (single source of truth) so
        // `interface` reports `class`/`struct`/`enum`/`interface` in agreement
        // with `extract`/`structure`, instead of an undifferentiated `kind:None`.
        // Additive.
        Language::Go | Language::Kotlin | Language::Swift => {
            let src_str = std::str::from_utf8(source).unwrap_or("");
            tldr_core::ast::entity::classify_node(class_node, lang, src_str)
                .map(|k| k.as_str().to_string())
        }
        // rc2-ts-interface-typealias-lumped-as-classes: the discriminating
        // tree-sitter node kind is LIVE here (the dispatcher matched
        // `class_node.kind()` against `class_node_kinds`). Record it for
        // TS/JS so the `interface` command stops lumping interfaces / type
        // aliases / enums into an undifferentiated class bucket. Other
        // languages keep `kind: None` (JSON stays byte-identical via the
        // `skip_serializing_if` guard on the field).
        _ => ts_js_entry_kind(class_node.kind(), lang),
    };

    ClassInfo {
        name,
        kind,
        lineno,
        bases,
        methods,
        private_method_count,
    }
}

/// rc2-ts-interface-typealias-lumped-as-classes: map a tree-sitter
/// TypeScript/JavaScript declaration node kind to the `ClassInfo.kind`
/// discriminator ("class"/"interface"/"type"/"enum"). Returns `None` for any
/// non-TS/JS language so their `interface` JSON stays byte-identical.
/// AST-keyed — no source-text scanning.
fn ts_js_entry_kind(node_kind: &str, lang: Language) -> Option<String> {
    match lang {
        Language::TypeScript | Language::JavaScript => {
            let kind = match node_kind {
                "interface_declaration" => "interface",
                "type_alias_declaration" => "type",
                "enum_declaration" => "enum",
                // class_declaration | abstract_class_declaration | class
                _ => "class",
            };
            Some(kind.to_string())
        }
        // RC2-META Stage 3 (scala): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use), so
        // `interface` reports class/object/trait/enum/type instead of an
        // undifferentiated class bucket. Node kinds reaching here are exactly
        // the `class_node_kinds(Scala)` members.
        Language::Scala => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (ocaml): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth). OCaml's interface "class" axis is exactly
        // `class_node_kinds(Ocaml)` = {`module_definition`, `type_definition`},
        // so `interface` now reports `kind:"module"` for a `module M = struct
        // ... end` and `kind:"type"` for a `type t = ...` alias, instead of an
        // undifferentiated `kind: None`. Additive — agrees with the
        // `EntityKind::Module` / `EntityKind::TypeAlias` that structure emits.
        //
        // CF1-S4 (v0.5.0 RC): the canonical `classify_node_kind` has no OCaml
        // arm for the two real class carriers (`class_definition` /
        // `class_type_definition`), so relabel them HERE (AST node-kind keyed,
        // no source scan): a `class … = object … end` is `kind="class"` and a
        // `class type … = object … end` is `kind="interface"` (the OCaml class
        // *signature* analogue, matching the `interface = Some(true)` tag the
        // `inheritance` walker assigns). Modules/types keep their own
        // `classify_node_kind` answer ("module"/"type"), so they are no longer
        // miscounted as classes.
        Language::Ocaml => match node_kind {
            "class_definition" => Some("class".to_string()),
            "class_type_definition" => Some("interface".to_string()),
            _ => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
                .map(|k| k.as_str().to_string()),
        },
        // RC2-META Stage 3 (rust): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use). The
        // node kinds reaching here are exactly `class_node_kinds(Rust)` =
        // {`struct_item`, `impl_item`, `trait_item`, `enum_item`}, which map to
        // `struct`/`class`/`trait`/`enum`. Additive — formerly `kind: None`.
        // (Free `fn`s are FunctionInfo, not classes; impl-block methods are
        // folded into their owner's `methods`, so no method/function kind
        // ambiguity arises in this class-carrier population.)
        Language::Rust => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (java): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use). The
        // node kinds reaching here are exactly `class_node_kinds(Java)` =
        // {`class_declaration`, `interface_declaration`, `enum_declaration`},
        // which map to `class`/`interface`/`enum`. Additive — formerly
        // `kind: None`.
        Language::Java => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (csharp): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use). The
        // node kinds reaching here are exactly `class_node_kinds(CSharp)` =
        // {`class_declaration`, `interface_declaration`, `struct_declaration`},
        // which map to `class`/`interface`/`struct`. Additive — formerly
        // `kind: None`.
        Language::CSharp => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (ruby): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use). The
        // node kinds reaching here are exactly `class_node_kinds(Ruby)` =
        // {`class`, `module`}, which map to `class`/`module`. Additive — formerly
        // `kind: None`. (Ruby modules are class-like carriers; their methods are
        // folded into `methods`, so no method/function ambiguity arises here.)
        Language::Ruby => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (python): populate the `interface` `ClassInfo.kind`
        // from the canonical, string-keyed `classify_node_kind` discriminator
        // (single source of truth — same answer `extract`/`structure` use). The
        // node kinds reaching here are exactly `class_node_kinds(Python)` =
        // {`class_definition`}, which maps to `class`. Additive — formerly
        // `kind: None`. (Python methods are folded into `methods`, so no
        // method/function ambiguity arises at the class-kind level.)
        Language::Python => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (c): populate the `interface` `ClassInfo.kind` from the
        // canonical, string-keyed `classify_node_kind` discriminator (single
        // source of truth — same answer `structure` uses). C has no classes in
        // the `extract` family (`extract_classes_detailed` is a no-op for C) and
        // `interface`'s `class_node_kinds(C)` = {`struct_specifier`}, so the only
        // node kind reaching here is `struct_specifier`, which the canonical
        // classifier maps to `EntityKind::Struct` (`union_specifier` -> Struct,
        // `enum_specifier` -> Enum are likewise covered should the class-carrier
        // set ever widen). Additive — formerly `kind: None` (omitted from JSON);
        // `interface` now reports `kind:"struct"` for a C struct in agreement with
        // `structure`'s `definitions[]` entry-kind. C has no classes, no methods,
        // and no `class`/`union` carriers in `class_node_kinds(C)`, so no
        // method/function or struct/union ambiguity arises here.
        Language::C => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (cpp): populate the `interface` `ClassInfo.kind` from
        // the canonical, string-keyed `classify_node_kind` discriminator (single
        // source of truth — same answer `extract`/`structure` use). The node
        // kinds reaching here are exactly `class_node_kinds(Cpp)` =
        // {`struct_specifier`, `class_specifier`}, which the canonical classifier
        // maps to `EntityKind::Struct` / `EntityKind::Class`. Additive — formerly
        // `kind: None` (omitted from JSON via the `skip_serializing_if` guard);
        // `interface` now reports `kind:"class"` / `kind:"struct"` in agreement
        // with `extract`/`structure`. (`union_specifier` -> Struct,
        // `enum_specifier` -> Enum are likewise covered should the class-carrier
        // set ever widen.)
        Language::Cpp => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        // RC2-META Stage 3 (php): populate the `interface` `ClassInfo.kind` from
        // the canonical, string-keyed `classify_node_kind` discriminator (single
        // source of truth — same answer `extract`/`structure` use). The node
        // kinds reaching here are exactly `class_node_kinds(Php)` =
        // {`class_declaration`, `interface_declaration`}, which map to
        // `class`/`interface`. Additive — formerly `kind: None` (omitted via the
        // `skip_serializing_if` guard); `interface` now reports `kind:"class"` /
        // `kind:"interface"` in agreement with `extract`/`structure`. (PHP traits
        // are not in `class_node_kinds(Php)`, so no trait/class ambiguity arises
        // here; methods are folded into their owner's `methods`.)
        Language::Php => tldr_core::ast::entity::classify_node_kind(node_kind, lang)
            .map(|k| k.as_str().to_string()),
        _ => None,
    }
}

/// Find the body/block node of a class/struct definition.
fn find_body_node<'a>(class_node: Node<'a>, lang: Language) -> Option<Node<'a>> {
    // Try common field names
    if let Some(body) = class_node.child_by_field_name("body") {
        return Some(body);
    }
    if let Some(body) = class_node.child_by_field_name("members") {
        return Some(body);
    }

    match lang {
        Language::Rust => {
            // For impl_item, look for declaration_list
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "declaration_list" {
                    return Some(child);
                }
            }
            None
        }
        Language::Java | Language::CSharp => {
            // class_body or interface_body
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_body"
                    || child.kind() == "interface_body"
                    || child.kind() == "enum_body"
                    || child.kind() == "declaration_list"
                {
                    return Some(child);
                }
            }
            None
        }
        Language::TypeScript | Language::JavaScript => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_body" {
                    return Some(child);
                }
            }
            None
        }
        Language::Cpp => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "field_declaration_list" {
                    return Some(child);
                }
            }
            // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): macro-misparsed
            // class bodies live on the `compound_statement` sibling of the
            // class_specifier inside the wrapping function_definition.
            extract_cpp_macro_misparsed_class_body(class_node)
        }
        Language::Ruby => {
            // Ruby class body is inside a body_statement child
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "body_statement" {
                    return Some(child);
                }
            }
            // Fallback: use the class node itself
            Some(class_node)
        }
        // A3c-interface-ocaml (v0.5.0 BACKLOG): `module M = struct ... end` is
        // a `module_definition` wrapping a `module_binding` whose `body` field
        // is the module expression. For a structure body (`struct ... end`) the
        // body node is a `structure` (or `module_content`); its direct children
        // are the `value_definition` / `let_binding` items that
        // `collect_methods_from_body` enumerates into `methods[]` (the same
        // `method_node_kinds(Ocaml)` set). The default arm below only scans the
        // *direct* children of `module_definition` for a "body"/"block"-named
        // node, but OCaml's struct body lives one level deeper inside
        // `module_binding`, so every OCaml module previously surfaced with
        // `methods: []`. Functor applications / module aliases
        // (`module M = Make (X)`, `module M = N`) carry a `module_application` /
        // `module_path` body with no struct items and correctly continue to
        // yield no methods. `type_definition` (the other `class_node_kinds(Ocaml)`
        // member) has no `module_binding` child and falls through to `None`,
        // matching its zero-method type-alias semantics. Mirrors the canonical
        // OCaml descent used by the callgraph extractor
        // (crates/tldr-core/src/callgraph/languages/ocaml.rs: module_binding.body
        // -> "structure" | "module_content").
        Language::Ocaml => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "module_binding" {
                    if let Some(body) = child.child_by_field_name("body") {
                        if matches!(body.kind(), "structure" | "module_content") {
                            return Some(body);
                        }
                    }
                }
                // CF1-S4 (v0.5.0 RC): a real OCaml class. `class_definition >
                // class_binding`, whose `body` field is the `object_expression`
                // (`object … end`) holding the `method_definition` members.
                if child.kind() == "class_binding" {
                    if let Some(body) = child.child_by_field_name("body") {
                        if body.kind() == "object_expression" {
                            return Some(body);
                        }
                    }
                }
                // CF1-S4: a class signature. `class_type_definition >
                // class_type_binding`, whose `body` field is the
                // `class_body_type` holding `method_specification` contracts.
                if child.kind() == "class_type_binding" {
                    if let Some(body) = child.child_by_field_name("body") {
                        if body.kind() == "class_body_type" {
                            return Some(body);
                        }
                    }
                }
            }
            None
        }
        _ => {
            // Default: try common body kinds
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                let kind = child.kind();
                if kind.contains("body")
                    || kind.contains("block")
                    || kind == "declaration_list"
                    || kind == "template_body"
                {
                    return Some(child);
                }
            }
            None
        }
    }
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): true iff this
/// `declaration`/`field_declaration` node wraps a member-function
/// declaration (declarator chain reaches a `function_declarator`). Field
/// and typedef declarations are rejected so non-method members don't get
/// mis-counted in `methods[]`.
fn is_cpp_member_function_declaration(node: Node) -> bool {
    let kind = node.kind();
    if kind != "declaration" && kind != "field_declaration" {
        return false;
    }
    // Walk the `declarator` field chain, peeling pointer_declarator /
    // reference_declarator wrappers, until we either hit a
    // `function_declarator` (yes) or a leaf identifier (no).
    let mut current = node.child_by_field_name("declarator");
    let mut hops = 0usize;
    while let Some(decl) = current {
        if hops > 6 {
            return false;
        }
        match decl.kind() {
            "function_declarator" => return true,
            "pointer_declarator"
            | "reference_declarator"
            | "init_declarator"
            | "parenthesized_declarator" => {
                // cl6-interface-v1 (GH #78): a `reference_declarator` /
                // `pointer_declarator` introduced by a `T&` / `T*` return
                // type does NOT expose its inner declarator via the
                // `declarator` field — the inner `function_declarator` is a
                // bare positional child after the `&` / `*` token. Without
                // scanning positional children too, `Vec& operator=(...)`
                // (a bodiless `field_declaration`) was wrongly rejected and
                // dropped from `methods[]`. Prefer the field, fall back to
                // the first wrapper/function declarator child.
                current = decl.child_by_field_name("declarator");
                if current.is_none() {
                    let mut c = decl.walk();
                    current = decl.children(&mut c).find(|ch| {
                        matches!(
                            ch.kind(),
                            "function_declarator"
                                | "pointer_declarator"
                                | "reference_declarator"
                                | "init_declarator"
                                | "parenthesized_declarator"
                        )
                    });
                }
            }
            _ => return false,
        }
        hops += 1;
    }
    false
}

/// CF1-S4 (v0.5.0 RC): classify a Ruby class-body statement as a bareword
/// visibility-section directive. Returns `Some(true)` for a bare `private` /
/// `protected` (subsequent instance methods become private), `Some(false)` for
/// a bare `public` (reset to public), and `None` for anything else — including
/// the TARGETED `private :sym` / `private def …` forms, which carry an argument
/// and therefore parse as a `call`/`method_call` rather than a bare
/// `identifier`. AST node-kind keyed, no source-line scan.
fn ruby_visibility_section(node: Node, source: &[u8]) -> Option<bool> {
    if node.kind() != "identifier" {
        return None;
    }
    match node_text(node, source).trim() {
        "private" | "protected" => Some(true),
        "public" => Some(false),
        _ => None,
    }
}

/// Collect methods from a class body node.
fn collect_methods_from_body(
    body: Node,
    source: &[u8],
    lang: Language,
    method_kinds: &[&str],
    methods: &mut Vec<MethodInfo>,
    private_count: &mut u32,
) {
    let mut cursor = body.walk();
    let decorator_kinds = decorator_node_kinds(lang);

    // CF1-S4 (v0.5.0 RC): Ruby visibility-section state. A bareword `private`
    // (or `protected`) statement with no arguments flips every subsequent
    // instance-method definition in the same body to private until a `public`
    // line resets it. tree-sitter-ruby parses such a bare directive as an
    // `identifier` sibling of the `method` nodes (the `private :sym` /
    // `private def …` TARGETED forms parse as `call`/`method_call` WITH an
    // argument and are intentionally NOT treated as a section toggle). Without
    // this, every method after a bare `private` leaked into the public surface
    // and `private_method_count` stayed 0.
    let mut ruby_section_private = false;

    for child in body.children(&mut cursor) {
        let kind = child.kind();

        if lang == Language::Ruby {
            if let Some(is_private_section) = ruby_visibility_section(child, source) {
                ruby_section_private = is_private_section;
                continue;
            }
        }

        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): in a macro-misparsed
        // class body (`compound_statement`), tree-sitter-cpp nests
        // declarations under a `labeled_statement` whose label is the
        // access-specifier keyword (`public:` / `private:` / `protected:`).
        // Recurse so the inner method declarations still surface.
        if matches!(lang, Language::C | Language::Cpp) && kind == "labeled_statement" {
            // Heuristic: only treat as access-specifier wrapper when the
            // label is one of the cpp visibility keywords; otherwise it's
            // a real labeled_statement (goto target) and should be skipped.
            let label_text = child
                .child(0)
                .map(|c| node_text(c, source))
                .unwrap_or("");
            if matches!(label_text, "public" | "private" | "protected") {
                collect_methods_from_body(
                    child,
                    source,
                    lang,
                    method_kinds,
                    methods,
                    private_count,
                );
            }
            continue;
        }

        // cl6-interface-v1 (GH #78): in a macro-misparsed class body
        // (`class TINYXML2_LIB StrPair { ... }` → `compound_statement`),
        // tree-sitter-cpp cannot reconcile a bodiless destructor / operator
        // declaration with the function-body context and emits the member's
        // `function_declarator` orphaned inside a bare `ERROR` node — e.g.
        // `~StrPair();` becomes `ERROR > function_declarator > destructor_name`
        // followed by a stray `expression_statement > ;`. The standard
        // `method_kinds` match below never sees these, so the destructor /
        // operator silently vanished. Recover them AST-driven: when a cpp
        // `ERROR` (or recurse-worthy wrapper) directly carries a
        // `function_declarator`, extract the member name from that declarator
        // (its `destructor_name` / `operator_name` / `field_identifier` leaf).
        if matches!(lang, Language::C | Language::Cpp) && kind == "ERROR" {
            let mut ec = child.walk();
            for ec_child in child.children(&mut ec) {
                if ec_child.kind() == "function_declarator" {
                    if let Some(decl) = ec_child.child_by_field_name("declarator") {
                        if let Some(method_name) = extract_c_declarator_name(decl, source) {
                            if !method_name.is_empty()
                                && is_method_public(&method_name, ec_child, source, lang)
                            {
                                let signature =
                                    extract_function_signature(ec_child, source, lang);
                                let is_async = detect_async(ec_child, source, lang);
                                methods.push(MethodInfo {
                                    name: method_name,
                                    signature,
                                    lineno: ec_child.start_position().row as u32 + 1,
                                    is_async,
                                });
                            }
                        }
                    }
                }
            }
            continue;
        }

        if method_kinds.contains(&kind) {
            // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3): `declaration` /
            // `field_declaration` nodes match both member functions AND
            // non-method members (fields, typedefs). Filter so only
            // function declarations become methods.
            if matches!(lang, Language::C | Language::Cpp)
                && matches!(kind, "declaration" | "field_declaration")
                && !is_cpp_member_function_declaration(child)
            {
                continue;
            }
            let method_name = get_node_name(child, source, lang).unwrap_or_default();
            if method_name.is_empty() {
                continue;
            }
            // CF1-S4 (v0.5.0 RC): a Ruby `def` (kind == "method", an instance
            // method) under an active `private`/`protected` section is private
            // regardless of its name. `def self.x` (`singleton_method`) is
            // unaffected by the section directive, matching Ruby semantics.
            let in_private_section =
                lang == Language::Ruby && ruby_section_private && kind == "method";
            if !in_private_section && is_method_public(&method_name, child, source, lang) {
                methods.push(extract_method_info(child, source, lang));
            } else {
                *private_count += 1;
            }
        } else if decorator_kinds.contains(&kind) {
            // Handle decorated methods (Python, Java annotations, etc.)
            if let Some(def) = find_definition_in_decorated(child, method_kinds) {
                let method_name = get_node_name(def, source, lang).unwrap_or_default();
                if is_method_public(&method_name, def, source, lang) {
                    methods.push(extract_method_info(def, source, lang));
                } else {
                    *private_count += 1;
                }
            }
        }
    }
}

/// Check if a method is public based on language conventions.
fn is_method_public(name: &str, node: Node, source: &[u8], lang: Language) -> bool {
    match lang {
        // rc2-meta-stage4 (visibility unification): name-based languages share
        // the single `is_public_for_lang` model (mirrors the class-axis
        // `is_node_public`), so member-axis and class-axis visibility agree.
        Language::Python | Language::Ruby | Language::Lua | Language::Luau | Language::Go => {
            is_public_for_lang(name, lang)
        }
        Language::Rust => is_rust_pub(node, source),
        // RC2-1-visibility-csharp-java-php: PHP joins Java/C# on the shared
        // AST modifier-child predicate. PHP `method_declaration` carries a
        // direct `visibility_modifier` child for `private`/`protected`; absence
        // of one (interface methods, or a bare `function`) is implicit-public.
        // Previously PHP fell through to `_ => true`, so every PHP method was
        // counted public and `private_method_count` was always 0.
        Language::Java | Language::CSharp | Language::Php => has_public_modifier(node, source),
        // RC2-2-visibility-ts-kotlin-swift: TS/JS members carry an explicit
        // `accessibility_modifier` (`private`/`protected`/`public`); Kotlin nests
        // its access keyword under `modifiers > visibility_modifier`, where
        // `private`/`protected`/`internal` are non-public and `public` /
        // the implicit default stay public. Both AST shapes are already
        // recognised by the shared `has_public_modifier` predicate (via
        // `explicit_access_visibility`), so route them through it instead of the
        // `_ => true` fall-through that previously leaked every private member
        // into the public set and pinned `private_method_count` at 0.
        Language::TypeScript | Language::JavaScript | Language::Kotlin => {
            has_public_modifier(node, source)
        }
        // Swift's DEFAULT visibility is `internal` (module-wide), so — unlike
        // C#/Kotlin where `internal` is non-public — only the file-scoped levels
        // `private`/`fileprivate` are non-public for the interface member view.
        // `internal`/`public`/`open`/`package` and the implicit default all
        // remain in the public method set.
        Language::Swift => !swift_member_is_non_public(node, source),
        // interface-per-lang-v1 (v0.4.2 M-022): exclude scala `private`
        // / `protected` methods from the public method list.
        Language::Scala => !is_scala_non_public(node, source),
        // v0.5.0 SOL-015a (M7): exclude Solidity contract methods marked
        // `internal` or `private`. Methods without a visibility keyword
        // surface (legacy pre-0.5 Solidity defaulted to `public`).
        // `fallback_function_definition` / `receive_function_definition`
        // / `constructor_definition` are always externally observable
        // (constructor is one-time but is part of the contract's typed
        // ABI for deployment, which differs from the runtime-surface
        // semantics in `surface/solidity.rs`).
        Language::Solidity => !solidity_method_is_internal_or_private(node, source),
        _ => true,
    }
}

/// v0.5.0 SOL-015a (M7): inspect a Solidity function/modifier definition's
/// `visibility` child. Returns true if the function is declared
/// `internal` or `private`. Functions with no `visibility` child OR with
/// `public`/`external` return false (i.e. they remain in the public
/// method list).
fn solidity_method_is_internal_or_private(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility" {
            let t = node_text(child, source).trim();
            return matches!(t, "internal" | "private");
        }
    }
    false
}

/// Extract base classes / superclasses / implemented interfaces.
fn extract_base_classes(class_node: Node, source: &[u8], lang: Language) -> Vec<String> {
    let mut bases = Vec::new();

    match lang {
        Language::Python => {
            if let Some(superclasses) = class_node.child_by_field_name("superclasses") {
                let mut cursor = superclasses.walk();
                for child in superclasses.children(&mut cursor) {
                    if child.kind() == "identifier" || child.kind() == "attribute" {
                        bases.push(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::Java => {
            // Java exposes the parent via the `superclass` field and the
            // implemented interfaces via the `interfaces` field.
            if let Some(super_node) = class_node.child_by_field_name("superclass") {
                bases.push(node_text(super_node, source).to_string());
            }
            if let Some(interfaces) = class_node.child_by_field_name("interfaces") {
                let mut cursor = interfaces.walk();
                for child in interfaces.children(&mut cursor) {
                    if child.kind() == "type_identifier" || child.kind() == "generic_type" {
                        bases.push(node_text(child, source).to_string());
                    }
                }
            }
        }
        Language::CSharp => {
            // tree-sitter-c-sharp does NOT use Java's `superclass`/`interfaces`
            // fields — it groups the base type + interfaces under a `base_list`
            // node. Using the Java field names left C# bases ALWAYS empty (#38:
            // newtonsoft-bson 0/61 classes had bases though `inheritance` found
            // 28 edges). Delegate to the shared extractor used by the
            // `inheritance` command so both agree.
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_csharp_bases(
                    &class_node,
                    src,
                ));
            }
        }
        // #153: PHP previously had NO arm here (fell through to `_ => {}`), so
        // `extends`/`implements` were never captured (guzzle ServerException
        // reported bases=[] though it extends BadResponseException). Delegate to
        // the shared PHP base extractor (reads base_clause + class_interface_clause).
        Language::Php => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_php_bases(&class_node, src));
            }
        }
        // Kotlin/Swift also lacked arms (no bases at all). Delegate to the
        // shared extractors (delegation_specifiers / inheritance clause).
        Language::Kotlin => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_kotlin_bases(
                    &class_node,
                    src,
                ));
            }
        }
        Language::Swift => {
            if let Ok(src) = std::str::from_utf8(source) {
                bases.extend(tldr_core::ast::extract::extract_swift_bases(
                    &class_node,
                    src,
                ));
            }
        }
        Language::Rust => {
            // For trait_item, look for trait bounds
            // For impl_item, look for the trait being implemented
            if class_node.kind() == "impl_item" {
                if let Some(trait_node) = class_node.child_by_field_name("trait") {
                    bases.push(node_text(trait_node, source).to_string());
                }
            }
        }
        Language::TypeScript | Language::JavaScript => {
            // Check for extends_clause or implements_clause
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "class_heritage" {
                    let mut inner_cursor = child.walk();
                    for clause in child.children(&mut inner_cursor) {
                        if clause.kind() == "extends_clause" || clause.kind() == "implements_clause"
                        {
                            let mut type_cursor = clause.walk();
                            for type_child in clause.children(&mut type_cursor) {
                                if type_child.kind() == "identifier"
                                    || type_child.kind() == "type_identifier"
                                {
                                    bases.push(node_text(type_child, source).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Language::Ruby => {
            if let Some(super_node) = class_node.child_by_field_name("superclass") {
                bases.push(node_text(super_node, source).to_string());
            }
        }
        Language::Go => {
            // Go type_declaration doesn't have base classes per se
            // But embedded structs could be found in struct fields
        }
        Language::Scala => {
            if let Some(extends) = class_node.child_by_field_name("extends") {
                bases.push(node_text(extends, source).to_string());
            }
        }
        // v0.5.0 SOL-015a (M7): Solidity inheritance is flattened from
        // `inheritance_specifier` children. Each specifier has an
        // `ancestor` field of kind `user_defined_type` (which itself
        // wraps an `identifier` or `member_expression`). Mirrors the
        // extractor's `extract_solidity_class_bases` semantics
        // (see crates/tldr-core/src/ast/extract.rs) so that
        // `tldr interface` and the schema extractor agree on `bases`.
        Language::Solidity => {
            let mut cursor = class_node.walk();
            for child in class_node.children(&mut cursor) {
                if child.kind() == "inheritance_specifier" {
                    if let Some(ancestor) = child.child_by_field_name("ancestor") {
                        if let Some(name) = solidity_user_defined_type_leaf(ancestor, source) {
                            bases.push(name);
                        }
                    } else {
                        // Fallback: scan for a `user_defined_type` child directly.
                        let mut ic = child.walk();
                        for ichild in child.children(&mut ic) {
                            if ichild.kind() == "user_defined_type" {
                                if let Some(name) = solidity_user_defined_type_leaf(ichild, source)
                                {
                                    bases.push(name);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    bases
}

/// v0.5.0 SOL-015a (M7): extract the leaf identifier of a
/// `user_defined_type` node. The grammar wraps the name in either an
/// `identifier` (bare `Ownable`) or a `member_expression` (namespaced
/// `OpenZeppelin.Ownable`). Mirrors `solidity_user_defined_type_name`
/// in `crates/tldr-core/src/ast/extract.rs`.
fn solidity_user_defined_type_leaf<'a>(node: Node<'a>, source: &'a [u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => return Some(node_text(child, source).to_string()),
            "member_expression" => return Some(node_text(child, source).to_string()),
            _ => {}
        }
    }
    Some(node_text(node, source).to_string())
}

/// Find a function/class definition inside a decorated_definition node.
fn find_definition_in_decorated<'a>(node: Node<'a>, target_kinds: &[&str]) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .find(|&child| target_kinds.contains(&child.kind()));
    found
}

/// Extract method information from a function definition node.
fn extract_method_info(func_node: Node, source: &[u8], lang: Language) -> MethodInfo {
    let name = get_node_name(func_node, source, lang).unwrap_or_default();
    let signature = extract_function_signature(func_node, source, lang);
    let is_async = detect_async(func_node, source, lang);
    // cl4-interface-v1 (IT3-java-03, GH #78): capture the method's own
    // declaration line so the flat `functions[]` view no longer collapses
    // every method to the enclosing class line. Anchor to the decl-keyword
    // line (skipping leading `@Override` / `@ModelAttribute` annotation and
    // modifier children) via the SAME normaliser `extract` / `explain` /
    // `slice` use, so the per-method line agrees across every pipeline
    // (v0.4.2 M-002 convention).
    let lineno = tldr_core::ast::extract::decl_keyword_line_from_node(&func_node);

    MethodInfo {
        name,
        signature,
        lineno,
        is_async,
    }
}

// =============================================================================
// Interface Extraction (Language-Aware)
// =============================================================================

/// Extract the public interface from a source file.
///
/// Detects the language from the file extension and uses the appropriate
/// tree-sitter grammar and node kinds. Uses sibling-aware detection so a
/// `.h` header next to `.cpp` translation units is parsed with the C++
/// grammar — without this, `tldr interface tinyxml2.h` parses as C and
/// returns zero classes (real-repo-fixes-v1 P9.BUG-R2).
pub fn extract_interface(path: &Path, source: &str) -> PatternsResult<InterfaceInfo> {
    let lang = Language::from_path_with_siblings(path).unwrap_or(Language::Python);
    extract_interface_with_lang(path, source, lang)
}

/// interface-per-lang-v1 (v0.4.2 M-022): parse a `.mli` file using
/// tree-sitter-ocaml's dedicated `LANGUAGE_OCAML_INTERFACE` grammar and
/// emit `val name : type` declarations as public functions. The
/// implementation grammar (`LANGUAGE_OCAML`) cannot represent these
/// declarations, so without this routing every `.mli` reported
/// `functions:[]`.
fn extract_ocaml_mli_interface(path: &Path, source: &str) -> PatternsResult<InterfaceInfo> {
    use tree_sitter::Parser;

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ocaml::LANGUAGE_OCAML_INTERFACE.into())
        .map_err(|e| {
            PatternsError::parse_error(
                path,
                format!("Failed to load OCaml interface grammar: {}", e),
            )
        })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        PatternsError::parse_error(path, "OCaml interface parser returned no tree".to_string())
    })?;
    let root = tree.root_node();
    let source_bytes = source.as_bytes();

    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut classes: Vec<ClassInfo> = Vec::new();

    walk_ocaml_mli(root, source_bytes, &mut functions, &mut classes);

    let mut names: Vec<String> = functions
        .iter()
        .map(|f| f.name.clone())
        .chain(classes.iter().map(|c| c.name.clone()))
        .collect();
    names.sort();
    names.dedup();

    Ok(InterfaceInfo {
        file: path.display().to_string(),
        all_exports: names,
        functions,
        classes,
        values: Vec::new(),
    })
}

/// Walk an OCaml `.mli` AST collecting `value_specification` (val decl)
/// and `type_definition` / `module_type_definition` nodes.
fn walk_ocaml_mli(
    node: Node,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        match kind {
            "value_specification" => {
                // children: `val` `value_name` `:` <type_expr>
                let mut name: Option<String> = None;
                let mut type_text: Option<String> = None;
                let mut name_cursor = child.walk();
                for sub in child.children(&mut name_cursor) {
                    match sub.kind() {
                        "value_name" => {
                            name = Some(node_text(sub, source).trim().to_string());
                        }
                        "val" | ":" => {}
                        _ => {
                            if name.is_some() && type_text.is_none() {
                                type_text =
                                    Some(node_text(sub, source).trim().to_string());
                            }
                        }
                    }
                }
                if let Some(n) = name {
                    let lineno = child.start_position().row as u32 + 1;
                    let signature = type_text
                        .map(|t| format!(": {}", t))
                        .unwrap_or_default();
                    functions.push(FunctionInfo {
                        name: n,
                        signature,
                        docstring: None,
                        lineno,
                        is_async: false,
                        kind: None,
                    });
                }
            }
            "type_definition" => {
                // Surface as a class entry for parity with the .ml path.
                let lineno = child.start_position().row as u32 + 1;
                let mut tcursor = child.walk();
                for sub in child.children(&mut tcursor) {
                    if sub.kind() == "type_binding" {
                        let mut bcursor = sub.walk();
                        for b in sub.children(&mut bcursor) {
                            if matches!(b.kind(), "type_constructor" | "type_constructor_path") {
                                let name = node_text(b, source).trim().to_string();
                                if !name.is_empty() {
                                    classes.push(ClassInfo {
                                        name,
                                        kind: None,
                                        lineno,
                                        bases: Vec::new(),
                                        methods: Vec::new(),
                                        private_method_count: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Recurse into nested module-types / signature bodies.
                walk_ocaml_mli(child, source, functions, classes);
            }
        }
    }
}

/// Extract the public interface from a source file with an explicit language.
pub fn extract_interface_with_lang(
    path: &Path,
    source: &str,
    lang: Language,
) -> PatternsResult<InterfaceInfo> {
    let source_bytes = source.as_bytes();

    // interface-per-lang-v1 (v0.4.2 M-022): `.mli` interface files use a
    // dedicated tree-sitter-ocaml grammar (`LANGUAGE_OCAML_INTERFACE`).
    // The standard OCaml grammar mis-parses `val name : type` because
    // that form is only legal in `.mli`. Route `.mli` to the dedicated
    // grammar before falling back to ParserPool.
    let is_ocaml_interface = lang == Language::Ocaml
        && path
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| e.eq_ignore_ascii_case("mli"))
            .unwrap_or(false);
    if is_ocaml_interface {
        return extract_ocaml_mli_interface(path, source);
    }

    // Parse with ParserPool (multi-language)
    let pool = ParserPool::new();
    let tree = pool
        .parse(source, lang)
        .map_err(|e| PatternsError::parse_error(path, format!("Failed to parse: {}", e)))?;

    let root = tree.root_node();

    // Extract __all__ exports (Python-specific)
    let explicit_all_exports = if lang == Language::Python {
        extract_all_exports(root, source_bytes)
    } else {
        None
    };

    // Determine node kinds for this language
    let func_kinds = function_node_kinds(lang);
    let class_kinds = class_node_kinds(lang);
    let decorator_kinds = decorator_node_kinds(lang);

    // Extract public functions and classes
    let (mut functions, mut classes) = collect_top_level_definitions(
        root,
        source_bytes,
        lang,
        func_kinds,
        class_kinds,
        decorator_kinds,
    );

    let mut values: Vec<ValueInfo> = Vec::new();

    // A3a-js-ts-export-engine (v0.5.0 BACKLOG): resolve the full set of
    // JavaScript / TypeScript export idioms that pre-class and ESM modules use
    // to declare their public API. Run AFTER `collect_top_level_definitions`
    // (which already captured `export function` / `export class` via the
    // `export_statement` wrapper) so member-assignment, reverse-binding,
    // export-const/arrow-const and object-literal-default exports are folded in
    // alongside the direct declarations. `values[]` carries the non-function
    // exported names (identifier re-exports, primitive/object const exports)
    // so every resolved export still surfaces in `all_exports`.
    if matches!(lang, Language::JavaScript | Language::TypeScript) {
        collect_js_member_exports(
            root,
            source_bytes,
            lang,
            &mut functions,
            &mut classes,
            &mut values,
        );
        collect_js_declared_exports(
            root,
            source_bytes,
            &mut functions,
            &mut classes,
            &mut values,
        );
    }

    // rc2-lua-interface-return-table-convention: a Lua/Luau module's public
    // surface is exactly the field set of the table it `return`s at end of
    // file — NOT the underscore-convention union of every collected function.
    // When a terminal `return {…}` / `return M` table is present, read the
    // export set from it (the authoritative module contract per
    // Programming-in-Lua §15.2, LuaLS, Teal, LDoc): this fixes both the
    // over-report (non-exported `local function` helpers) and the under-report
    // (branch-nested defs + non-function `local`s that the function-only
    // walker never collected). `None` (dynamic / `return require(...)` / no
    // return-table) falls back to the legacy union heuristic below.
    let lua_exports = if matches!(lang, Language::Lua | Language::Luau) {
        collect_lua_module_exports(root, source_bytes, lang)
    } else {
        None
    };

    // schema-cleanup-v1 BUG-22: populate `all_exports` as a non-null
    // array. Prefer the explicit `__all__` (Python only); otherwise
    // fall back to the union of public function and class names —
    // mirroring "import *" semantics. Empty modules → `[]`.
    let all_exports = if let Some(explicit) = explicit_all_exports {
        explicit
    } else if let Some(exports) = lua_exports {
        // Override with the return-table contract. Build the authoritative
        // export name set, reconcile `functions[]` against it (filter
        // over-reported helpers, synthesize branch-nested / missing exported
        // functions), and route non-function exports to `values[]`.
        reconcile_lua_exports(&exports, &mut functions, &mut values)
    } else {
        // schema-cleanup-v1 BUG-22 + A3a-js-ts-export-engine: the export name
        // set is the union of public function, class and value names. `values`
        // is empty for every language except Lua/Luau (handled above) and
        // JS/TS, so chaining it here is a no-op elsewhere while letting JS/TS
        // non-function exports (identifier re-exports, const/object values)
        // appear in `all_exports`.
        let mut names: Vec<String> = functions
            .iter()
            .map(|f| f.name.clone())
            .chain(classes.iter().map(|c| c.name.clone()))
            .chain(values.iter().map(|v| v.name.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    };

    Ok(InterfaceInfo {
        file: path.display().to_string(),
        all_exports,
        functions,
        classes,
        values,
    })
}

// =============================================================================
// Lua / Luau return-table export model
// (rc2-lua-interface-return-table-convention)
// =============================================================================

/// A single export read from a Lua/Luau module's terminal `return` table.
///
/// `name` is the exported KEY (the return-table field name / accumulator
/// field). `lineno` is the alias-resolved definition site (the local/function
/// def the value points at), falling back to the value/field site when the
/// value is an inline literal or unresolved. `is_function` decides whether the
/// export is reconciled into `functions[]` or routed to `values[]`.
struct LuaExport {
    name: String,
    lineno: u32,
    is_function: bool,
    signature: String,
    value_kind: Option<String>,
}

/// A definition discovered while scanning a Lua/Luau chunk: used to alias-resolve
/// a return-table value identifier back to its def site.
#[derive(Clone)]
struct LuaDef {
    lineno: u32,
    is_function: bool,
    signature: String,
    value_kind: Option<String>,
}

/// Read a Lua/Luau module's public export set from its terminal `return` table.
///
/// Returns `Some(exports)` when the chunk ends in a recognizable export shape
/// (a `table_constructor` literal, a `return M` accumulator identifier, or a
/// `setmetatable(M, …)` wrapper around either). Returns `None` for dynamic
/// tails (`return require('x')`, a computed expression, or no return at all),
/// in which case the caller falls back to the legacy heuristic.
///
/// The Lua and Luau grammars are byte-for-byte identical on every node used
/// here (`return_statement` → `expression_list` → `table_constructor` →
/// `field{name,value}`; `function_declaration{name,parameters}`;
/// `variable_declaration` → `assignment_statement` → `variable_list` +
/// `expression_list`), so a single shared path serves both languages.
fn collect_lua_module_exports(
    root: Node,
    source: &[u8],
    lang: Language,
) -> Option<Vec<LuaExport>> {
    // Locate the LAST top-level `return_statement` (a chunk may have only one,
    // but be defensive).
    let mut ret: Option<Node> = None;
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "return_statement" {
            ret = Some(child);
        }
    }
    let ret = ret?;

    // `return_statement` has a single optional `expression_list` child.
    let expr_list = {
        let mut c = ret.walk();
        let found = ret.children(&mut c).find(|n| n.kind() == "expression_list");
        found
    }?;

    // The exported value is the last expression in the list (`return a, M`).
    let tail = {
        let mut last = None;
        let mut c = expr_list.walk();
        for n in expr_list.children(&mut c) {
            if n.is_named() {
                last = Some(n);
            }
        }
        last
    }?;

    let symbols = build_lua_symbol_table(root, source, lang);
    resolve_lua_export_tail(tail, root, source, lang, &symbols)
}

/// Resolve a return-tail expression into an export set, unwrapping
/// `setmetatable(...)` and dispatching on the literal-table vs accumulator
/// shapes. Recursive to handle `return setmetatable(M, mt)`.
fn resolve_lua_export_tail(
    tail: Node,
    root: Node,
    source: &[u8],
    lang: Language,
    symbols: &std::collections::HashMap<String, LuaDef>,
) -> Option<Vec<LuaExport>> {
    match tail.kind() {
        // SHAPE 1 — literal: `return { a = a, b = ... }`.
        "table_constructor" => Some(collect_lua_table_exports(tail, source, lang, symbols)),
        // SHAPE 2 — accumulator: `return M` where `M.x = …` / `function M.y()`.
        "identifier" | "variable" => {
            let name = node_text(tail, source).trim();
            // A bare identifier that names a local table = accumulator.
            // If we can't see any fields written onto it, still return an
            // empty/derived set rather than the union (the contract is "M's
            // fields", even if zero) — but only when M is a known local table.
            let m = lua_base_identifier(tail, source)?;
            Some(collect_lua_accumulator_exports(root, source, lang, &m, symbols, name))
        }
        // SHAPE 4 — `return setmetatable(M, mt)`: unwrap to first argument.
        "function_call" => {
            let callee = {
                let mut c = tail.walk();
                let found = tail.children(&mut c).find(|n| n.is_named());
                found
            }?;
            if node_text(callee, source).trim() != "setmetatable" {
                return None;
            }
            let args = {
                let mut c = tail.walk();
                let found = tail.children(&mut c).find(|n| n.kind() == "arguments");
                found
            }?;
            let first = {
                let mut c = args.walk();
                let found = args.children(&mut c).find(|n| n.is_named());
                found
            }?;
            resolve_lua_export_tail(first, root, source, lang, symbols)
        }
        _ => None,
    }
}

/// SHAPE 1: collect exports from a `table_constructor` literal. Each `field`
/// whose `name` is an identifier is an export key; its `value` is alias-resolved
/// to a def site.
fn collect_lua_table_exports(
    table: Node,
    source: &[u8],
    _lang: Language,
    symbols: &std::collections::HashMap<String, LuaDef>,
) -> Vec<LuaExport> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor = table.walk();
    for field in table.children(&mut cursor) {
        if field.kind() != "field" {
            continue;
        }
        // Three field shapes (grammar.js): `[expr] = expr` (computed key,
        // `name` is an expression — skip), `Name = expr` (identifier key — the
        // export case), and bare `expr` (positional — no `name` field, skip).
        let key = match field.child_by_field_name("name") {
            Some(k) if k.kind() == "identifier" => k,
            _ => continue,
        };
        let key_text = node_text(key, source).trim().to_string();
        if key_text.is_empty() || !seen.insert(key_text.clone()) {
            continue;
        }
        let value = field.child_by_field_name("value");
        let export = lua_export_from_value(key_text, key, value, source, symbols);
        out.push(export);
    }
    out
}

/// SHAPE 2: collect exports for an accumulator table `M` — every `M.x = …`
/// assignment and `function M.y() … end` declaration anywhere in the chunk
/// (descending if/else, do, for, while bodies). A table key is a set, so the
/// result is deduped by name.
fn collect_lua_accumulator_exports(
    root: Node,
    source: &[u8],
    lang: Language,
    m: &str,
    symbols: &std::collections::HashMap<String, LuaDef>,
    _tail_name: &str,
) -> Vec<LuaExport> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // SHAPE 2a — literal-bound accumulator: `local M = { a = …, b = … }`.
    // The fields `M` was CONSTRUCTED with are part of its export set exactly
    // like later `M.x = …` member writes, but the accumulator walk below only
    // sees post-declaration mutations. Harvest the initial table constructor
    // first (it wins the dedup, recording each field at its literal site).
    if let Some(literal) = lua_accumulator_literal(root, source, m) {
        for export in collect_lua_table_exports(literal, source, lang, symbols) {
            if seen.insert(export.name.clone()) {
                out.push(export);
            }
        }
    }
    collect_lua_accumulator_walk(root, source, lang, m, symbols, &mut out, &mut seen);
    out
}

/// Find the `table_constructor` literal that local table `m` was initially
/// bound to (`local m = { … }`), if any, so its fields fold into the
/// accumulator's export set. First binding wins (defensive against rebinds).
///
/// Shared verbatim by Lua and Luau: the `variable_declaration` →
/// `assignment_statement` → (`variable_list`, `expression_list`) →
/// `table_constructor` shape is byte-for-byte identical in both grammars.
fn lua_accumulator_literal<'a>(root: Node<'a>, source: &[u8], m: &str) -> Option<Node<'a>> {
    if root.kind() == "variable_declaration" {
        let mut c = root.walk();
        for child in root.children(&mut c) {
            if child.kind() != "assignment_statement" {
                continue;
            }
            if let Some((targets, values)) = lua_assignment_parts(child) {
                for (i, target) in targets.iter().enumerate() {
                    let names_m = matches!(target.kind(), "identifier" | "variable")
                        && lua_base_identifier(*target, source).as_deref() == Some(m);
                    if names_m {
                        if let Some(value) = values.get(i) {
                            if value.kind() == "table_constructor" {
                                return Some(*value);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if let Some(found) = lua_accumulator_literal(child, source, m) {
            return Some(found);
        }
    }
    None
}

/// Split a `function M.x()` name node (`dot_index_expression`) or a
/// `function M:x()` colon-method name node (`method_index_expression`) into
/// `(base_identifier, field_name)`. The dot form names its field via the
/// `field` child; the colon form via `method`. Returns `None` for any other
/// name shape (plain `identifier`, bracket-index, etc.).
fn lua_member_decl_parts(name_node: Node, source: &[u8]) -> Option<(String, String)> {
    match name_node.kind() {
        "dot_index_expression" => lua_dot_parts(name_node, source),
        "method_index_expression" => {
            let table = name_node.child_by_field_name("table")?;
            let method = name_node.child_by_field_name("method")?;
            let base = lua_base_identifier(table, source)?;
            let method_text = node_text(method, source).trim().to_string();
            if method_text.is_empty() {
                return None;
            }
            Some((base, method_text))
        }
        _ => None,
    }
}

fn collect_lua_accumulator_walk(
    node: Node,
    source: &[u8],
    lang: Language,
    m: &str,
    symbols: &std::collections::HashMap<String, LuaDef>,
    out: &mut Vec<LuaExport>,
    seen: &mut std::collections::HashSet<String>,
) {
    // `function M.foo() … end` (dot_index_expression name) and
    // `function M:foo() … end` (method_index_expression name, the colon-method
    // form) both bind a public field `foo` onto the accumulator `M`. The two
    // grammars are identical except for the node that holds the field name
    // (`field` for dots, `method` for colons); `lua_member_decl_parts`
    // resolves both into `(base, field)`.
    if function_node_kinds(lang).contains(&node.kind()) {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Some((base, field)) = lua_member_decl_parts(name_node, source) {
                if base == m && seen.insert(field.clone()) {
                    out.push(LuaExport {
                        name: field,
                        lineno: node.start_position().row as u32 + 1,
                        is_function: true,
                        signature: lua_params_text(node, source),
                        value_kind: None,
                    });
                }
            }
        }
    }

    // `M.x = …` / `M["x"] = …` assignment_statement.
    if node.kind() == "assignment_statement" {
        if let Some((targets, values)) = lua_assignment_parts(node) {
            for (i, target) in targets.iter().enumerate() {
                if let Some(field) = lua_member_field_of(*target, source, m) {
                    if seen.insert(field.clone()) {
                        let value = values.get(i).copied();
                        out.push(lua_export_from_value(
                            field,
                            *target,
                            value,
                            source,
                            symbols,
                        ));
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_lua_accumulator_walk(child, source, lang, m, symbols, out, seen);
    }
}

/// Build an export entry from a return-table / accumulator value expression,
/// alias-resolving identifiers back to their chunk-level definitions.
fn lua_export_from_value(
    name: String,
    key_node: Node,
    value: Option<Node>,
    source: &[u8],
    symbols: &std::collections::HashMap<String, LuaDef>,
) -> LuaExport {
    let key_line = key_node.start_position().row as u32 + 1;
    let value = match value {
        Some(v) => v,
        None => {
            return LuaExport {
                name,
                lineno: key_line,
                is_function: false,
                signature: String::new(),
                value_kind: Some("value".to_string()),
            }
        }
    };
    match value.kind() {
        // Inline anonymous function: `name = function(...) … end`.
        k if k == "function_definition"
            || k == "function_definition_statement"
            || function_node_kinds(Language::Lua).contains(&k) =>
        {
            LuaExport {
                name,
                lineno: value.start_position().row as u32 + 1,
                is_function: true,
                signature: lua_params_text(value, source),
                value_kind: None,
            }
        }
        // Alias to a local/function: `name = otherName` — resolve to its def.
        "identifier" | "variable" => {
            let target = node_text(value, source).trim();
            if let Some(def) = symbols.get(target) {
                LuaExport {
                    name,
                    lineno: def.lineno,
                    is_function: def.is_function,
                    signature: def.signature.clone(),
                    value_kind: if def.is_function {
                        None
                    } else {
                        def.value_kind.clone().or_else(|| Some("value".to_string()))
                    },
                }
            } else {
                // LDoc's dynamic case: record at the field/assignment site
                // rather than dropping — never revert to the name-union.
                LuaExport {
                    name,
                    lineno: value.start_position().row as u32 + 1,
                    is_function: false,
                    signature: String::new(),
                    value_kind: Some("value".to_string()),
                }
            }
        }
        // Inline literal (boolean/number/string/table/...): a non-function field.
        other => LuaExport {
            name,
            lineno: value.start_position().row as u32 + 1,
            is_function: false,
            signature: String::new(),
            value_kind: Some(lua_value_kind(other).to_string()),
        },
    }
}

/// Build a name → definition map for a Lua/Luau chunk by deep-walking it
/// (descending into branch/loop bodies), so a return-table value identifier
/// can be alias-resolved to the local/function it names. First definition of a
/// name wins (so a multi-branch `function getPrefix` collapses to one).
fn build_lua_symbol_table(
    root: Node,
    source: &[u8],
    lang: Language,
) -> std::collections::HashMap<String, LuaDef> {
    let mut map = std::collections::HashMap::new();
    build_lua_symbol_table_walk(root, source, lang, &mut map);
    map
}

fn build_lua_symbol_table_walk(
    node: Node,
    source: &[u8],
    lang: Language,
    map: &mut std::collections::HashMap<String, LuaDef>,
) {
    // Named function declarations: `function f()` / `local function f()`.
    if function_node_kinds(lang).contains(&node.kind()) {
        if let Some(name_node) = node.child_by_field_name("name") {
            if name_node.kind() == "identifier" {
                let name = node_text(name_node, source).trim().to_string();
                map.entry(name).or_insert_with(|| LuaDef {
                    lineno: node.start_position().row as u32 + 1,
                    is_function: true,
                    signature: lua_params_text(node, source),
                    value_kind: None,
                });
            }
        }
    }

    // `local a, b = x, y` / `local t = {}` — variable_declaration wrapping an
    // assignment_statement (with values) or a bare variable_list (forward decl).
    if node.kind() == "variable_declaration" {
        let mut c = node.walk();
        for child in node.children(&mut c) {
            if child.kind() == "assignment_statement" {
                if let Some((targets, values)) = lua_assignment_parts(child) {
                    for (i, target) in targets.iter().enumerate() {
                        if target.kind() == "variable" || target.kind() == "identifier" {
                            let name = lua_base_identifier(*target, source);
                            if let Some(name) = name {
                                let value = values.get(i).copied();
                                let (is_fn, sig, kind) = lua_value_classify(value, source);
                                map.entry(name).or_insert(LuaDef {
                                    lineno: child.start_position().row as u32 + 1,
                                    is_function: is_fn,
                                    signature: sig,
                                    value_kind: kind,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        build_lua_symbol_table_walk(child, source, lang, map);
    }
}

/// Classify a value expression for symbol-table purposes.
fn lua_value_classify(
    value: Option<Node>,
    source: &[u8],
) -> (bool, String, Option<String>) {
    match value {
        Some(v)
            if v.kind() == "function_definition"
                || v.kind() == "function_definition_statement" =>
        {
            (true, lua_params_text(v, source), None)
        }
        Some(v) => (false, String::new(), Some(lua_value_kind(v.kind()).to_string())),
        None => (false, String::new(), Some("value".to_string())),
    }
}

/// Map a value node kind to a coarse export `kind` discriminator.
fn lua_value_kind(kind: &str) -> &'static str {
    match kind {
        "table_constructor" => "table",
        "string" => "string",
        "number" => "number",
        "true" | "false" | "boolean" => "boolean",
        "nil" => "nil",
        "function_definition" | "function_definition_statement" => "function",
        _ => "value",
    }
}

/// Extract the parameter text (`(a, b)`) of a function-bearing node.
fn lua_params_text(node: Node, source: &[u8]) -> String {
    if let Some(params) = node.child_by_field_name("parameters") {
        return node_text(params, source).to_string();
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameters" {
            return node_text(child, source).to_string();
        }
    }
    String::new()
}

/// Split an `assignment_statement` into (target nodes, value nodes), paired by
/// position. The node has a `variable_list` and an `expression_list` child.
fn lua_assignment_parts<'a>(node: Node<'a>) -> Option<(Vec<Node<'a>>, Vec<Node<'a>>)> {
    let mut var_list = None;
    let mut expr_list = None;
    let mut c = node.walk();
    for child in node.children(&mut c) {
        match child.kind() {
            "variable_list" => var_list = Some(child),
            "expression_list" => expr_list = Some(child),
            _ => {}
        }
    }
    let var_list = var_list?;
    let targets: Vec<Node> = {
        let mut vc = var_list.walk();
        var_list
            .children(&mut vc)
            .filter(|n| n.is_named() && n.kind() != "attribute")
            .collect()
    };
    let values: Vec<Node> = match expr_list {
        Some(el) => {
            let mut ec = el.walk();
            el.children(&mut ec).filter(|n| n.is_named()).collect()
        }
        None => Vec::new(),
    };
    Some((targets, values))
}

/// If `target` is a `dot_index_expression` / `bracket_index_expression` rooted
/// at `m` (`m.x` / `m["x"]`), return the field name `x`.
fn lua_member_field_of(target: Node, source: &[u8], m: &str) -> Option<String> {
    // `variable` may wrap the index expression; descend one level.
    let inner = if target.kind() == "variable" {
        let mut c = target.walk();
        let found = target.children(&mut c).find(|n| n.is_named());
        found.unwrap_or(target)
    } else {
        target
    };
    match inner.kind() {
        "dot_index_expression" => {
            let (base, field) = lua_dot_parts(inner, source)?;
            if base == m {
                Some(field)
            } else {
                None
            }
        }
        "bracket_index_expression" => {
            let base = inner.child_by_field_name("table")?;
            if lua_base_identifier(base, source)? != m {
                return None;
            }
            let key = inner.child_by_field_name("field")?;
            let text = node_text(key, source).trim();
            // Only string-literal keys yield a stable field name.
            let unq = text.trim_matches(|c| c == '"' || c == '\'');
            if unq.is_empty() || unq == text {
                // Not a quoted string literal — skip computed keys.
                None
            } else {
                Some(unq.to_string())
            }
        }
        _ => None,
    }
}

/// Split a `dot_index_expression` (`base.field`) into `(base_identifier, field)`.
fn lua_dot_parts(node: Node, source: &[u8]) -> Option<(String, String)> {
    let table = node.child_by_field_name("table")?;
    let field = node.child_by_field_name("field")?;
    let base = lua_base_identifier(table, source)?;
    let field_text = node_text(field, source).trim().to_string();
    Some((base, field_text))
}

/// Resolve a node to its leading identifier text (unwrapping `variable`).
fn lua_base_identifier(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(node_text(node, source).trim().to_string()),
        "variable" => {
            let mut c = node.walk();
            let first = node.children(&mut c).find(|n| n.is_named())?;
            lua_base_identifier(first, source)
        }
        _ => None,
    }
}

/// Reconcile the return-table export set against the collected `functions[]`:
/// filter over-reported helpers (kept only if exported), synthesize exported
/// functions the walker never collected (branch-nested defs), and route
/// non-function exports to `values[]`. Returns the sorted/deduped `all_exports`.
fn reconcile_lua_exports(
    exports: &[LuaExport],
    functions: &mut Vec<FunctionInfo>,
    values: &mut Vec<ValueInfo>,
) -> Vec<String> {
    use std::collections::HashSet;
    let export_names: HashSet<&str> = exports.iter().map(|e| e.name.as_str()).collect();

    // 1. Drop over-reported helpers — keep only functions that are exported.
    functions.retain(|f| export_names.contains(f.name.as_str()));

    // 2. Synthesize exported functions the walker missed (branch-nested /
    //    accumulator-member defs) and route non-function exports to values[].
    let present: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
    for export in exports {
        if export.is_function {
            if !present.contains(&export.name) {
                functions.push(FunctionInfo {
                    name: export.name.clone(),
                    signature: export.signature.clone(),
                    docstring: None,
                    lineno: export.lineno,
                    is_async: false,
                    // RC2-META Stage 3 (lua/luau): a branch-nested / accumulator
                    // export the function-walker missed is still a Lua function
                    // (`export.is_function`), which `classify_node` classifies as
                    // `EntityKind::Function`. Tag the additive `kind` from the
                    // canonical enum string (single source of truth — same answer
                    // `extract_function_info` produces for the walker-collected
                    // exports) so every exported function carries `kind:"function"`
                    // uniformly, regardless of which path emitted it.
                    kind: Some(tldr_core::ast::entity::EntityKind::Function.as_str().to_string()),
                });
            }
        } else {
            values.push(ValueInfo {
                name: export.name.clone(),
                lineno: export.lineno,
                kind: export.value_kind.clone(),
            });
        }
    }

    // 3. all_exports = the authoritative key set, sorted & deduped.
    let mut names: Vec<String> = exports.iter().map(|e| e.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

/// Container node kinds whose children should be treated as top-level for
/// the purpose of public-interface extraction.
///
/// Real-world repos commonly wrap top-level classes/functions in:
/// * C++: `namespace foo { ... }`, `extern "C" { ... }`, `#if/#elif` preproc
/// * C#: `namespace Foo { ... }` and `namespace Foo;` (file-scoped)
/// * C/C++: preproc conditional branches gating typedefs and inline functions
///
/// Without recursion, `tldr interface` reported zero classes for cpp/csharp
/// even though `tldr extract` listed them — real-repo-fixes-v1 (P9.BUG-R2/R5).
fn is_interface_container(kind: &str) -> bool {
    matches!(
        kind,
        "namespace_definition"
            | "namespace_declaration"
            | "file_scoped_namespace_declaration"
            | "linkage_specification"
            | "preproc_if"
            | "preproc_ifdef"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_elifdef"
            | "declaration_list"
            // tree-sitter-cpp commonly produces ERROR / function_definition
            // wrappers in real-world headers (e.g. tinyxml2.h) when macro
            // names like `TINYXML2_LIB` confuse the parser. Recurse into
            // these so embedded class_specifier nodes still surface.
            | "ERROR"
            | "compound_statement"
            // C# wraps the whole file content under various namespace forms
            // and global_statement/file_scoped_namespace bodies.
            | "global_statement"
    )
}

/// Languages where misparses are common enough that we should walk the full
/// AST looking for class/function nodes, not just direct children of root.
///
/// For these languages `tldr extract` already does a deep walk; matching that
/// behaviour for `tldr interface` keeps the two commands consistent.
/// real-repo-fixes-v1 (P9.BUG-R2/R5/R6/R7).
fn needs_deep_walk(lang: Language) -> bool {
    matches!(
        lang,
        Language::Cpp
            | Language::C
            | Language::CSharp
            | Language::Kotlin
            | Language::Swift
    )
}

/// interface-per-lang-v1 (v0.4.2 M-022) + A3a-js-ts-export-engine (v0.5.0):
/// scan a JS/TS file for top-level member-export forms that pre-class and
/// CommonJS JavaScript modules use to declare their public API:
///
/// * `Foo.prototype.bar = function (...) { ... }`     -> method `bar` on `Foo`
/// * `Foo.prototype.bar = (...) => { ... }`           -> method `bar` on `Foo`
/// * `exports.X = function (...) { ... }`             -> top-level function `X`
/// * `module.exports.X = function (...) { ... }`      -> top-level function `X`
/// * `<alias>.X = function (...) { ... }`             -> top-level function `X`
/// * `<alias>.X = <expr>` (non-function)             -> exported value `X`
///
/// `<alias>` is any identifier bound to `module.exports` / the default export
/// — either forward (`var app = exports = module.exports = {}`) or reverse
/// (`module.exports = res` / `export default axios`), resolved by
/// [`collect_js_module_export_aliases`]. The reverse form is the Express
/// `lib/response.js` (`module.exports = res; res.send = function … {}`) and
/// axios `lib/axios.js` (`export default axios; axios.all = function … {}`)
/// idiom — without alias resolution the entire public surface was invisible to
/// `tldr interface` (empty `all_exports`/`functions`/`classes`).
///
/// Non-function member RHS values (identifier / member re-exports such as
/// `axios.spread = spread`) are routed to `values[]` so they still surface in
/// `all_exports` rather than being dropped.
fn collect_js_member_exports(
    root: Node,
    source: &[u8],
    lang: Language,
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    values: &mut Vec<ValueInfo>,
) {
    use std::collections::HashSet;
    let mut existing_funcs: HashSet<(String, u32)> = HashSet::new();
    for f in functions.iter() {
        existing_funcs.insert((f.name.clone(), f.lineno));
    }
    let mut existing_values: HashSet<String> = values.iter().map(|v| v.name.clone()).collect();

    // First pass: collect identifiers that alias `module.exports` /
    // `exports` (forward and reverse bindings). Express's `lib/application.js`
    // does `var app = exports = module.exports = {};` — every subsequent
    // `app.X = function …` is part of the public API but would otherwise be
    // invisible because `app` is just an identifier. The reverse form
    // (`module.exports = res; res.send = …`) is resolved the same way.
    let module_export_aliases = collect_js_module_export_aliases(root, source);

    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        // `expression_statement` wraps a single assignment_expression in JS.
        if child.kind() != "expression_statement" {
            continue;
        }
        let assign = match child.child(0) {
            Some(c) if c.kind() == "assignment_expression" => c,
            _ => continue,
        };
        // A possibly-chained assignment `res.contentType = res.type =
        // function … {}` binds EVERY left-hand member to the same terminal
        // value. Resolve all of them (Express `lib/response.js` declares
        // `res.set`/`res.header` and `res.contentType`/`res.type` this way).
        let (lhs_nodes, final_rhs) = js_unchain_assignment(assign);
        let final_rhs = match final_rhs {
            Some(r) => r,
            None => continue,
        };
        let rhs_is_func = is_js_function_value(final_rhs);
        let lineno = assign.start_position().row as u32 + 1;
        // Inspect each LHS member expression. We accept any of:
        //   - <ident>.prototype.<name>         -> method on class <ident>
        //   - exports.<name>                   -> top-level export
        //   - module.exports.<name>            -> top-level export
        //   - <alias>.<name>                   -> top-level export
        for lhs in lhs_nodes {
            let resolved = resolve_js_export_lhs(lhs, source, &module_export_aliases);
            match resolved {
            Some(JsExportTarget::Prototype { class_name, member }) => {
                // Prototype data members (non-function RHS) are not part of the
                // callable method surface; only function-valued assignments are
                // recorded as methods.
                if !rhs_is_func || !is_public_name(&member) {
                    continue;
                }
                let signature = extract_js_member_signature(final_rhs, source);
                let is_async = is_js_function_async(final_rhs, source);
                let class_entry = classes
                    .iter_mut()
                    .find(|c| c.name == class_name);
                let method = MethodInfo {
                    name: member.clone(),
                    signature: signature.clone(),
                    lineno,
                    is_async,
                };
                if let Some(entry) = class_entry {
                    // Avoid duplicating an existing method record.
                    let already = entry
                        .methods
                        .iter()
                        .any(|m| m.name == method.name);
                    if !already {
                        entry.methods.push(method);
                    }
                } else {
                    // No class entry exists yet — synthesize one so the
                    // method is reachable. The lineno of the class entry
                    // points at the first prototype assignment.
                    classes.push(ClassInfo {
                        name: class_name.clone(),
                        // JS prototype-based class synthesized from a
                        // `Foo.prototype.bar = ...` assignment.
                        kind: Some("class".to_string()),
                        lineno,
                        bases: Vec::new(),
                        methods: vec![method],
                        private_method_count: 0,
                    });
                }
            }
            Some(JsExportTarget::ModuleExport { name }) => {
                if !is_public_name(&name) {
                    continue;
                }
                if rhs_is_func {
                    let key = (name.clone(), lineno);
                    if existing_funcs.contains(&key)
                        || functions.iter().any(|f| f.name == name)
                    {
                        continue;
                    }
                    existing_funcs.insert(key);
                    functions.push(FunctionInfo {
                        name,
                        signature: extract_js_member_signature(final_rhs, source),
                        docstring: None,
                        lineno,
                        is_async: is_js_function_async(final_rhs, source),
                        kind: None,
                    });
                } else {
                    // Non-function member export (identifier / member / literal
                    // re-export). Surface the name as an exported value so it
                    // is not dropped from `all_exports`.
                    if functions.iter().any(|f| f.name == name)
                        || classes.iter().any(|c| c.name == name)
                        || !existing_values.insert(name.clone())
                    {
                        continue;
                    }
                    values.push(ValueInfo {
                        name,
                        lineno,
                        kind: Some(js_value_kind(final_rhs)),
                    });
                }
            }
            None => {}
            }
        }
    }
    let _ = lang;
}

/// Unchain a (possibly nested) assignment expression `a = b = … = <value>`,
/// returning every left-hand-side node and the terminal (rightmost) value.
/// Pure AST traversal of the `assignment_expression` `left`/`right` fields.
fn js_unchain_assignment<'a>(assign: Node<'a>) -> (Vec<Node<'a>>, Option<Node<'a>>) {
    let mut lhss = Vec::new();
    let mut current = assign;
    loop {
        if let Some(l) = current.child_by_field_name("left") {
            lhss.push(l);
        }
        match current.child_by_field_name("right") {
            Some(r) if r.kind() == "assignment_expression" => current = r,
            other => return (lhss, other),
        }
    }
}

/// AST-derived value-kind discriminator for a JS/TS export RHS node, mirroring
/// the additive `ValueInfo::kind` slot used by Lua. Pure node-kind mapping (no
/// regex / source-text heuristics).
fn js_value_kind(node: Node) -> String {
    match node.kind() {
        "object" => "object",
        "array" => "array",
        "string" | "template_string" => "string",
        "number" => "number",
        "true" | "false" => "boolean",
        "identifier" | "member_expression" => "reference",
        _ => "value",
    }
    .to_string()
}

/// Resolved target of a JS member-export assignment LHS.
enum JsExportTarget {
    /// `Class.prototype.method = ...`
    Prototype { class_name: String, member: String },
    /// `exports.X = ...` or `module.exports.X = ...`
    ModuleExport { name: String },
}

/// Parse `Foo.prototype.bar`, `exports.bar`, `module.exports.bar`, or
/// `<alias>.bar` (where `<alias>` is a known `module.exports` alias)
/// from the LHS of an assignment. Returns `None` for any other shape.
fn resolve_js_export_lhs(
    lhs: Node,
    source: &[u8],
    module_export_aliases: &std::collections::HashSet<String>,
) -> Option<JsExportTarget> {
    if lhs.kind() != "member_expression" {
        return None;
    }
    // The terminal property name is the `property` child.
    let prop = lhs.child_by_field_name("property")?;
    let prop_name = node_text(prop, source).to_string();
    let object = lhs.child_by_field_name("object")?;

    // Case 1: <ident>.prototype.<name>
    if object.kind() == "member_expression" {
        if let (Some(inner_obj), Some(inner_prop)) = (
            object.child_by_field_name("object"),
            object.child_by_field_name("property"),
        ) {
            let inner_prop_text = node_text(inner_prop, source);
            if inner_prop_text == "prototype" && inner_obj.kind() == "identifier" {
                return Some(JsExportTarget::Prototype {
                    class_name: node_text(inner_obj, source).to_string(),
                    member: prop_name,
                });
            }
            // module.exports.<name>
            if inner_obj.kind() == "identifier"
                && node_text(inner_obj, source) == "module"
                && inner_prop_text == "exports"
            {
                return Some(JsExportTarget::ModuleExport { name: prop_name });
            }
        }
    }
    // Case 2: exports.<name>
    if object.kind() == "identifier" && node_text(object, source) == "exports" {
        return Some(JsExportTarget::ModuleExport { name: prop_name });
    }
    // Case 3: <alias>.<name>, where <alias> was bound to
    // `module.exports` (e.g. `var app = exports = module.exports = {};`
    // in express's application.js).
    if object.kind() == "identifier" {
        let ident = node_text(object, source);
        if module_export_aliases.contains(ident) {
            return Some(JsExportTarget::ModuleExport { name: prop_name });
        }
    }
    None
}

/// interface-per-lang-v1 (v0.4.2 M-022) + A3a-js-ts-export-engine (v0.5.0):
/// scan the program root for identifiers bound to `module.exports` / the
/// default export, in BOTH binding directions, and return the alias set:
///
/// * forward: `var X = exports = module.exports = ...` (or `let`/`const`) —
///   `X` aliases the exports object.
/// * reverse (CJS): `module.exports = X;` / `exports = X;` — the local `X`
///   becomes the exports object (Express `lib/response.js`).
/// * reverse (ESM): `export default X;` — the local `X` is the default export
///   (axios `lib/axios.js`).
///
/// Every subsequent `<alias>.member = …` assignment is then resolved as part
/// of the module's public surface by [`collect_js_member_exports`].
fn collect_js_module_export_aliases(
    root: Node,
    source: &[u8],
) -> std::collections::HashSet<String> {
    let mut aliases = std::collections::HashSet::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            // Forward binding: `var X = module.exports[ = …]`.
            "lexical_declaration" | "variable_declaration" => {
                let mut ic = child.walk();
                for decl in child.children(&mut ic) {
                    if decl.kind() != "variable_declarator" {
                        continue;
                    }
                    let name_node = match decl.child_by_field_name("name") {
                        Some(n) => n,
                        None => continue,
                    };
                    let value = match decl.child_by_field_name("value") {
                        Some(v) => v,
                        None => continue,
                    };
                    if name_node.kind() != "identifier" {
                        continue;
                    }
                    // The value can be `exports = module.exports = {}` (a
                    // chained assignment_expression), or directly
                    // `module.exports`. Walk the chain looking for either form.
                    if js_value_is_module_exports_chain(value, source) {
                        aliases.insert(node_text(name_node, source).to_string());
                    }
                }
            }
            // Reverse binding (CJS): `module.exports = X;` / `exports = X;`.
            "expression_statement" => {
                if let Some(assign) = child.child(0) {
                    if assign.kind() == "assignment_expression" {
                        let lhs = assign.child_by_field_name("left");
                        let rhs = assign.child_by_field_name("right");
                        if let (Some(lhs), Some(rhs)) = (lhs, rhs) {
                            if rhs.kind() == "identifier"
                                && js_value_is_module_exports_chain(lhs, source)
                            {
                                aliases.insert(node_text(rhs, source).to_string());
                            }
                        }
                    }
                }
            }
            // Reverse binding (ESM): `export default X;`.
            "export_statement" => {
                if js_export_statement_is_default(child) {
                    if let Some(value) = child.child_by_field_name("value") {
                        if value.kind() == "identifier" {
                            aliases.insert(node_text(value, source).to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    aliases
}

/// True when an `export_statement` is a default export (`export default …`),
/// detected by the presence of a `default` child token.
fn js_export_statement_is_default(node: Node) -> bool {
    let mut cursor = node.walk();
    let is_default = node.children(&mut cursor).any(|c| c.kind() == "default");
    is_default
}

/// A3a-js-ts-export-engine (v0.5.0 BACKLOG): resolve the *declared* JS/TS
/// export idioms that `collect_js_member_exports` (member assignments) and the
/// `export_statement` direct-declaration walk (`export function` / `export
/// class`) do not already cover:
///
/// * `export const f = (…) => …;` / `export const g = function (…) {…}`
///   (arrow-const / function-const)           -> function `f` / `g`
/// * `export const C = class {…}`              -> class `C`
/// * `export const X = <literal | ref>`        -> exported value `X`
/// * `export default { a() {}, b: () => …, c }` / `module.exports = { … }`
///   (object literal)                          -> each member as function / value
/// * `export default <local>` / `module.exports = <local>` where `<local>` is
///   `const <local> = () => …` / `function` / `class` / `{ … }`
///                                             -> function / class / object members
///
/// Names are deduplicated across `functions` / `classes` / `values`
/// (first-writer-wins) so an export already captured by the direct walk or the
/// member-assignment pass is never duplicated.
fn collect_js_declared_exports(
    root: Node,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    values: &mut Vec<ValueInfo>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "export_statement" => {
                // `export const X = …;` (declaration field carries the binding).
                if let Some(decl) = child.child_by_field_name("declaration") {
                    if matches!(decl.kind(), "lexical_declaration" | "variable_declaration") {
                        collect_js_declarator_exports(decl, source, functions, classes, values);
                    }
                    continue;
                }
                // `export default …;`
                if js_export_statement_is_default(child) {
                    if let Some(value) = child.child_by_field_name("value") {
                        add_js_default_export(value, source, root, functions, classes, values);
                    }
                }
            }
            "expression_statement" => {
                // `module.exports = …;` / `exports = …;` whole-object default.
                if let Some(assign) = child.child(0) {
                    if assign.kind() != "assignment_expression" {
                        continue;
                    }
                    if let (Some(lhs), Some(rhs)) = (
                        assign.child_by_field_name("left"),
                        assign.child_by_field_name("right"),
                    ) {
                        // Only the whole-object form (`module.exports = …`),
                        // NOT member assignments (`module.exports.x = …`), which
                        // `collect_js_member_exports` already resolves.
                        if js_value_is_module_exports_chain(lhs, source) {
                            add_js_default_export(rhs, source, root, functions, classes, values);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Classify each `variable_declarator` of an `export const/let/var` binding and
/// route it to `functions` (arrow / function value), `classes` (class
/// expression value) or `values` (any other literal / reference).
fn collect_js_declarator_exports(
    decl: Node,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    values: &mut Vec<ValueInfo>,
) {
    let mut ic = decl.walk();
    for d in decl.children(&mut ic) {
        if d.kind() != "variable_declarator" {
            continue;
        }
        let name_node = match d.child_by_field_name("name") {
            Some(n) if n.kind() == "identifier" => n,
            _ => continue,
        };
        let name = node_text(name_node, source).to_string();
        let lineno = name_node.start_position().row as u32 + 1;
        let value = d.child_by_field_name("value");
        classify_js_named_export(&name, lineno, value, source, functions, classes, values);
    }
}

/// Resolve a `export default <expr>` / `module.exports = <expr>` value to its
/// exported surface: object literals expand to members, function/class values
/// surface under the binding name, and a bare local identifier is resolved to
/// its top-level declaration first.
fn add_js_default_export(
    value: Node,
    source: &[u8],
    root: Node,
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    values: &mut Vec<ValueInfo>,
) {
    match value.kind() {
        "object" => expand_js_object_members(value, source, functions, values),
        "identifier" => {
            // Resolve `export default local` / `module.exports = local` to the
            // local's top-level declaration and classify that.
            let name = node_text(value, source).to_string();
            if let Some(decl_value) = resolve_js_local_decl_value(root, source, &name) {
                if decl_value.kind() == "object" {
                    expand_js_object_members(decl_value, source, functions, values);
                } else {
                    let lineno = decl_value.start_position().row as u32 + 1;
                    // Only surface the local itself when it is a function/class
                    // literal; namespace objects built via calls (e.g.
                    // `Object.create(...)`, `createInstance(...)`) expose their
                    // API through `<local>.member = …` assignments, already
                    // resolved by `collect_js_member_exports`.
                    if is_js_function_value(decl_value) || js_is_class_value(decl_value) {
                        classify_js_named_export(
                            &name,
                            lineno,
                            Some(decl_value),
                            source,
                            functions,
                            classes,
                            values,
                        );
                    }
                }
            }
        }
        _ => {}
    }
}

/// Find the top-level `const/let/var <name> = <value>` declaration and return
/// its value node, if any.
fn resolve_js_local_decl_value<'a>(
    root: Node<'a>,
    source: &[u8],
    name: &str,
) -> Option<Node<'a>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if !matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            continue;
        }
        let mut ic = child.walk();
        for d in child.children(&mut ic) {
            if d.kind() != "variable_declarator" {
                continue;
            }
            if let Some(n) = d.child_by_field_name("name") {
                if n.kind() == "identifier" && node_text(n, source) == name {
                    return d.child_by_field_name("value");
                }
            }
        }
    }
    None
}

/// Expand an object-literal export (`export default { … }` /
/// `module.exports = { … }`) into its members: `method_definition` and
/// function/arrow-valued `pair`s become functions; every other member
/// (`pair` with a literal/reference value, `shorthand_property_identifier`)
/// becomes an exported value.
fn expand_js_object_members(
    object: Node,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    values: &mut Vec<ValueInfo>,
) {
    let mut cursor = object.walk();
    for member in object.children(&mut cursor) {
        match member.kind() {
            "method_definition" => {
                let name = match member.child_by_field_name("name") {
                    Some(n) => node_text(n, source).to_string(),
                    None => continue,
                };
                let lineno = member.start_position().row as u32 + 1;
                let signature = member
                    .child_by_field_name("parameters")
                    .map(|p| node_text(p, source).to_string())
                    .unwrap_or_default();
                let is_async = is_js_function_async(member, source);
                push_js_function(functions, values, name, signature, lineno, is_async);
            }
            "pair" => {
                let key = match member.child_by_field_name("key") {
                    Some(k) => k,
                    None => continue,
                };
                // Only stable identifier / string keys yield a name.
                let name = match key.kind() {
                    "property_identifier" => node_text(key, source).to_string(),
                    "string" => node_text(key, source)
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string(),
                    _ => continue,
                };
                if name.is_empty() {
                    continue;
                }
                let lineno = member.start_position().row as u32 + 1;
                match member.child_by_field_name("value") {
                    Some(v) if is_js_function_value(v) => {
                        let signature = extract_js_member_signature(v, source);
                        let is_async = is_js_function_async(v, source);
                        push_js_function(functions, values, name, signature, lineno, is_async);
                    }
                    Some(v) => {
                        push_js_value(functions, values, name, lineno, js_value_kind(v));
                    }
                    None => {}
                }
            }
            "shorthand_property_identifier" => {
                let name = node_text(member, source).to_string();
                let lineno = member.start_position().row as u32 + 1;
                push_js_value(functions, values, name, lineno, "reference".to_string());
            }
            _ => {}
        }
    }
}

/// True when a node is a class value (`class C {}` / anonymous `class {}`).
fn js_is_class_value(node: Node) -> bool {
    matches!(node.kind(), "class" | "class_declaration")
}

/// Route a single named export (`<name> = <value>`) to the correct bucket.
fn classify_js_named_export(
    name: &str,
    lineno: u32,
    value: Option<Node>,
    source: &[u8],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    values: &mut Vec<ValueInfo>,
) {
    match value {
        Some(v) if is_js_function_value(v) => {
            let signature = extract_js_member_signature(v, source);
            let is_async = is_js_function_async(v, source);
            push_js_function(functions, values, name.to_string(), signature, lineno, is_async);
        }
        Some(v) if js_is_class_value(v) => {
            if !js_name_taken(functions, classes, values, name) {
                classes.push(ClassInfo {
                    name: name.to_string(),
                    kind: Some("class".to_string()),
                    lineno,
                    bases: Vec::new(),
                    methods: Vec::new(),
                    private_method_count: 0,
                });
            }
        }
        Some(v) => {
            push_js_value(functions, values, name.to_string(), lineno, js_value_kind(v));
        }
        None => {}
    }
}

/// True when `name` is already recorded in any export bucket.
fn js_name_taken(
    functions: &[FunctionInfo],
    classes: &[ClassInfo],
    values: &[ValueInfo],
    name: &str,
) -> bool {
    functions.iter().any(|f| f.name == name)
        || classes.iter().any(|c| c.name == name)
        || values.iter().any(|v| v.name == name)
}

/// Push a resolved function export, deduplicated by name across all buckets.
fn push_js_function(
    functions: &mut Vec<FunctionInfo>,
    values: &mut [ValueInfo],
    name: String,
    signature: String,
    lineno: u32,
    is_async: bool,
) {
    if name.is_empty() {
        return;
    }
    if functions.iter().any(|f| f.name == name) || values.iter().any(|v| v.name == name) {
        return;
    }
    functions.push(FunctionInfo {
        name,
        signature,
        docstring: None,
        lineno,
        is_async,
        kind: None,
    });
}

/// Push a resolved value export, deduplicated by name across all buckets.
fn push_js_value(
    functions: &[FunctionInfo],
    values: &mut Vec<ValueInfo>,
    name: String,
    lineno: u32,
    kind: String,
) {
    if name.is_empty() {
        return;
    }
    if functions.iter().any(|f| f.name == name) || values.iter().any(|v| v.name == name) {
        return;
    }
    values.push(ValueInfo {
        name,
        lineno,
        kind: Some(kind),
    });
}

/// Returns true when the expression is `module.exports`, `exports`, or
/// an assignment chain that includes either (the typical idiom
/// `exports = module.exports = {}`).
fn js_value_is_module_exports_chain(node: Node, source: &[u8]) -> bool {
    match node.kind() {
        "member_expression" => {
            // module.exports
            let obj = node.child_by_field_name("object");
            let prop = node.child_by_field_name("property");
            if let (Some(o), Some(p)) = (obj, prop) {
                if o.kind() == "identifier"
                    && node_text(o, source) == "module"
                    && node_text(p, source) == "exports"
                {
                    return true;
                }
            }
            false
        }
        "identifier" => node_text(node, source) == "exports",
        "assignment_expression" => {
            // Walk both sides of the chain.
            let l = node.child_by_field_name("left");
            let r = node.child_by_field_name("right");
            if let Some(l) = l {
                if js_value_is_module_exports_chain(l, source) {
                    return true;
                }
            }
            if let Some(r) = r {
                if js_value_is_module_exports_chain(r, source) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_js_function_value(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "arrow_function" | "function" | "generator_function"
    )
}

fn is_js_function_async(node: Node, source: &[u8]) -> bool {
    let text = node_text(node, source);
    text.starts_with("async ") || text.starts_with("async(")
}

fn extract_js_member_signature(rhs: Node, source: &[u8]) -> String {
    // Both function_expression and arrow_function carry a `parameters`
    // field (formal_parameters). Fall back to scanning children for
    // formal_parameters / parenthesized parameter list.
    if let Some(params) = rhs.child_by_field_name("parameters") {
        return node_text(params, source).to_string();
    }
    let mut cursor = rhs.walk();
    for child in rhs.children(&mut cursor) {
        if child.kind() == "formal_parameters" {
            return node_text(child, source).to_string();
        }
    }
    String::new()
}

/// Collect top-level function and class definitions from the AST root.
///
/// Recurses one level into language-appropriate container nodes (PHP
/// declaration list; C++/C# namespaces; cpp preprocessor branches) so that
/// public types defined inside `namespace { ... }` or `#if ... #endif`
/// blocks are surfaced — without this, real cpp/csharp codebases report zero
/// classes (P9.BUG-R2/R5).
fn collect_top_level_definitions(
    root: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    decorator_kinds: &[&str],
) -> (Vec<FunctionInfo>, Vec<ClassInfo>) {
    let mut functions = Vec::new();
    let mut classes = Vec::new();
    if needs_deep_walk(lang) {
        // Walk the whole AST, collecting top-level (non-method) functions
        // and class-like nodes wherever they appear. Mirrors `tldr extract`'s
        // behaviour for languages where misparses or namespace wrapping are
        // common in real-world code.
        deep_collect(
            root,
            source,
            lang,
            func_kinds,
            class_kinds,
            &mut functions,
            &mut classes,
            0,
        );
    } else {
        visit_top_level(
            root,
            source,
            lang,
            func_kinds,
            class_kinds,
            decorator_kinds,
            &mut functions,
            &mut classes,
            0,
        );
    }

    // language-specific-bugs-v1 (P14.AGG14-10): post-process Rust class
    // entries to merge `impl Foo { ... }` blocks into the corresponding
    // `struct Foo` / `enum Foo` / `trait Foo` entry. Without this, the
    // output contained both a `struct GlobSet` (methods=[]) AND an
    // `impl GlobSet` (whose methods were the actual API surface) — and
    // the user saw `methods: 0` on the struct.
    if matches!(lang, Language::Rust) {
        merge_rust_impl_entries(&mut classes);
    }

    // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
    // collapse duplicate cpp class entries that arise when a forward
    // declaration (`class XMLDocument;` at file top, methods=[]) and the
    // real definition (`class TINYXML2_LIB XMLDocument { ... };` later,
    // methods populated) both surface. Keep the entry with the richer
    // methods/bases and drop the other. Without this pass, `tldr interface
    // tinyxml2.h` would emit two XMLDocument entries.
    if matches!(lang, Language::Cpp) {
        dedupe_cpp_class_entries(&mut classes);
    }

    // language-specific-bugs-v1 (P14.AGG14-17): for Java (and the same
    // class-only languages where every public function lives inside a
    // class and the top-level `functions[]` would otherwise always be
    // empty), copy each public method into the top-level
    // `functions[]` array as a flat entry. Method entries stay inside
    // the class entry so consumers that index by class still work; the
    // flat `functions[]` array now matches the convention python /
    // typescript already follow (every callable a downstream consumer
    // could call is reachable without dereferencing a `classes[]`
    // entry first).
    if matches!(lang, Language::Java | Language::Kotlin) {
        flatten_class_methods_to_functions(&classes, &mut functions);
    }

    // A3a-js-ts-export-engine (v0.5.0 BACKLOG): the JavaScript / TypeScript
    // member-assignment, reverse-binding and declared-export idioms are now
    // resolved at the `extract_interface` call site (so the `values[]` channel
    // is threadable). `collect_top_level_definitions` is intentionally left to
    // the language-agnostic direct-declaration walk for JS/TS here.
    (functions, classes)
}

/// language-specific-bugs-v1 (P14.AGG14-17): flatten every public method
/// from `classes` into `functions` as a top-level entry, deduplicated by
/// `(name, lineno)`. Used for class-only languages (Java, Kotlin) so that
/// `tldr interface SomeController.java | jq '.functions | length'` is
/// non-zero whenever the file declares a class with public methods —
/// matching the contract Python / TypeScript already satisfy at the
/// schema level (every public callable is enumerable from `functions[]`
/// without dereferencing `classes[]`).
fn flatten_class_methods_to_functions(
    classes: &[ClassInfo],
    functions: &mut Vec<FunctionInfo>,
) {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    for f in functions.iter() {
        seen.insert((f.name.clone(), f.lineno));
    }
    for class in classes {
        for method in &class.methods {
            // cl4-interface-v1 (IT3-java-03, GH #78): `MethodInfo` now
            // carries its own declaration line, so the flat `functions[]`
            // view reports the real per-method line (matching `structure` /
            // `extract`) instead of collapsing every method to the enclosing
            // class line. Dedup on `(name, method_line)` — two overloads now
            // remain distinct because their lines differ.
            let key = (method.name.clone(), method.lineno);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            functions.push(FunctionInfo {
                name: method.name.clone(),
                signature: method.signature.clone(),
                docstring: None,
                lineno: method.lineno,
                is_async: method.is_async,
                kind: None,
            });
        }
    }
}

/// language-specific-bugs-v1 (P14.AGG14-10): coalesce duplicate Rust class
/// entries. After the walker has gathered `struct`/`enum`/`trait` entries
/// AND every `impl <Type>` block as separate `ClassInfo`s (because both
/// node kinds are listed in `class_node_kinds(Language::Rust)`), this pass
/// finds each impl whose `name` matches an existing struct/enum/trait
/// entry and folds the impl's methods into the matching entry. impl
/// blocks with no struct/enum/trait counterpart in the same file (e.g.
/// `impl SomeTrait for ExternalType { ... }` where `ExternalType` lives
/// elsewhere) are dropped entirely — we cannot attach them to anything in
/// this file's interface and surfacing them with the trait/type name as a
/// "class" was misleading.
fn merge_rust_impl_entries(classes: &mut Vec<ClassInfo>) {
    use std::collections::HashSet;

    // Step 1: index the lineno of every non-impl class entry so we keep
    // their stable ordering when re-inserting methods.
    let mut struct_like_indices: HashSet<String> = HashSet::new();
    for c in classes.iter() {
        // We treat any entry whose name doesn't carry generic / for-clause
        // syntax as struct-like. impl entries carry the impl'd type name
        // verbatim (which may include generics like `Foo<T>`), so we
        // strip generics on lookup keys.
        let key = strip_generics(&c.name);
        struct_like_indices.insert(key);
    }
    let _ = struct_like_indices; // (only used implicitly via the merge)

    // Step 2: separate impl entries from struct/enum/trait entries by
    // lineno - we don't have a `kind` discriminator, so we re-scan: any
    // entry whose name appears more than once is an impl-block duplicate.
    let mut name_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for c in classes.iter() {
        *name_counts.entry(strip_generics(&c.name)).or_insert(0) += 1;
    }

    // Step 3: walk classes in order. For each entry whose name is a
    // duplicate, fold its methods into the FIRST entry with the same
    // name (the canonical struct/enum/trait location). Mark folded
    // entries for removal.
    let mut canonical_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut to_remove: Vec<usize> = Vec::new();
    for (i, c) in classes.iter().enumerate() {
        let key = strip_generics(&c.name);
        canonical_index.entry(key).or_insert(i);
    }

    for i in 0..classes.len() {
        let key = strip_generics(&classes[i].name);
        let canonical = match canonical_index.get(&key) {
            Some(&idx) => idx,
            None => continue,
        };
        if i == canonical {
            continue;
        }
        // Fold methods (and bases) into canonical.
        let methods = std::mem::take(&mut classes[i].methods);
        let bases = std::mem::take(&mut classes[i].bases);
        let private_count = classes[i].private_method_count;

        let canonical_entry = &mut classes[canonical];
        for m in methods {
            let already = canonical_entry.methods.iter().any(|existing| {
                existing.name == m.name && existing.signature == m.signature
            });
            if !already {
                canonical_entry.methods.push(m);
            }
        }
        for b in bases {
            if !canonical_entry.bases.contains(&b) {
                canonical_entry.bases.push(b);
            }
        }
        canonical_entry.private_method_count =
            canonical_entry.private_method_count.saturating_add(private_count);
        to_remove.push(i);
    }

    // Remove duplicates in reverse order so indices remain valid.
    for idx in to_remove.into_iter().rev() {
        classes.remove(idx);
    }

    // Step 4: drop any remaining entries whose name count was originally
    // > 1 but which are now empty placeholders (this happens for
    // `impl Trait for ExternalType` where ExternalType has no
    // struct/enum/trait declaration in the same file — the impl entry
    // was folded into the canonical, leaving the canonical entry as a
    // duplicate-of-self; nothing to drop in that case). Reserved for
    // future expansion.
    let _ = name_counts;
}

/// cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
/// collapse cpp class entries that share a name. Forward declarations
/// (`class Foo;`) and real definitions (`class TINYXML2_LIB Foo { ... };`)
/// both produce a `ClassInfo` for `Foo`; we keep the one with non-empty
/// methods and drop the other. If both are empty (multiple forward decls)
/// the first occurrence wins. Bases/methods are unioned into the surviving
/// entry to preserve any info from the dropped duplicate.
fn dedupe_cpp_class_entries(classes: &mut Vec<ClassInfo>) {
    use std::collections::HashMap;

    if classes.len() <= 1 {
        return;
    }

    // First pass: pick a canonical index per name — prefer the entry with
    // the most methods, tie-break by lowest line number for stability.
    let mut canonical_for: HashMap<String, usize> = HashMap::new();
    for (i, c) in classes.iter().enumerate() {
        if c.name.is_empty() {
            continue;
        }
        match canonical_for.get(&c.name).copied() {
            None => {
                canonical_for.insert(c.name.clone(), i);
            }
            Some(prev) => {
                let prev_methods = classes[prev].methods.len();
                let cur_methods = c.methods.len();
                let take_current = cur_methods > prev_methods
                    || (cur_methods == prev_methods && c.lineno < classes[prev].lineno);
                if take_current {
                    canonical_for.insert(c.name.clone(), i);
                }
            }
        }
    }

    // Second pass: union methods/bases from each non-canonical duplicate
    // into the canonical entry, then mark for removal.
    let mut to_remove: Vec<usize> = Vec::new();
    let mut transfers: Vec<(usize, usize)> = Vec::new(); // (from, to)
    for (i, c) in classes.iter().enumerate() {
        if c.name.is_empty() {
            continue;
        }
        if let Some(&canonical) = canonical_for.get(&c.name) {
            if canonical != i {
                transfers.push((i, canonical));
                to_remove.push(i);
            }
        }
    }
    for (from, to) in transfers {
        // Take methods/bases out of `from` (it's about to be removed).
        let from_methods = std::mem::take(&mut classes[from].methods);
        let from_bases = std::mem::take(&mut classes[from].bases);
        let from_private = classes[from].private_method_count;
        let target = &mut classes[to];
        for m in from_methods {
            let already = target
                .methods
                .iter()
                .any(|e| e.name == m.name && e.signature == m.signature);
            if !already {
                target.methods.push(m);
            }
        }
        for b in from_bases {
            if !target.bases.contains(&b) {
                target.bases.push(b);
            }
        }
        target.private_method_count =
            target.private_method_count.saturating_add(from_private);
    }
    // Remove in reverse so indices stay valid.
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.into_iter().rev() {
        classes.remove(idx);
    }
}

/// Strip generic / lifetime parameters from a Rust type name.
/// `Vec<T>` -> `Vec`, `Foo<'a>` -> `Foo`, `Bar` -> `Bar`.
fn strip_generics(name: &str) -> String {
    if let Some(idx) = name.find('<') {
        name[..idx].trim().to_string()
    } else {
        name.trim().to_string()
    }
}

/// Walk the entire AST of a file, collecting class-like nodes and any
/// function definitions that are NOT methods inside a class.
///
/// Used for cpp/c/csharp/kotlin/swift where:
/// * cpp headers often have macro-prefixed `class TINYXML2_LIB Foo` that
///   confuse tree-sitter into emitting ERROR / function_definition wrappers
///   around the namespace body, so plain root-children iteration misses them.
/// * csharp wraps everything under one or more `namespace_declaration` /
///   `file_scoped_namespace_declaration` nodes.
/// * kotlin/swift normally have classes at the file root, but extension-only
///   files (Span+Extras.swift) and nested object_declaration trees benefit
///   from a full walk.
#[allow(clippy::too_many_arguments)]
fn deep_collect(
    node: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    // review-followup-v1 (Concern 4): defense-in-depth bound matching
    // `visit_top_level`'s `MAX_CONTAINER_DEPTH = 8`. Tree-sitter limits
    // real-code nesting in practice, but a corrupt or adversarial AST
    // could still produce deep recursion; cap it here for consistency.
    const MAX_DEEP_WALK_DEPTH: usize = 8;
    if depth > MAX_DEEP_WALK_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if class_kinds.contains(&kind) {
            // C/C++ `struct_specifier` / `class_specifier` with NO `body` field
            // is a TYPE REFERENCE, not a definition: `sizeof(struct sdshdr5)`,
            // a cast `(struct list*)x`, a param `struct Bar *p`, `extern struct
            // T v`, or a forward decl `class Foo;`. Emitting these listed
            // phantom "classes" named by the referenced type (c-sds reported
            // sdshdr5/8/16/32/64 as classes from `sizeof`; c-redis reported a
            // bogus `list` from a cast). `structure`'s extract_c_structs already
            // requires a body; mirror that here so the two pipelines agree.
            //
            // EXCEPTION (cpp-interface-macro-filter-v1 regression fix): the
            // export-macro misparse `class TINYXML2_LIB Foo { ... };` ALSO has
            // no `body` field on its `class_specifier` — tree-sitter-cpp hangs
            // the real `compound_statement` body off the wrapping
            // `function_definition` instead (verified by AST dump:
            // function_definition -> [class_specifier(name=MACRO, no body),
            // identifier(Foo), compound_statement{...}]). That node IS a real
            // class definition, so it must NOT be filtered as a type-ref.
            // `extract_cpp_macro_misparsed_class_body` returns `Some` exactly
            // for this shape (and `None` for genuine bodyless type-refs /
            // forward-decls), so it cleanly distinguishes the two. The same
            // helper feeds `get_node_name` (real name) and `find_body_node`
            // (real methods), so once admitted the entry resolves correctly.
            let is_cpp_macro_misparsed_class = matches!(lang, Language::Cpp)
                && kind == "class_specifier"
                && extract_cpp_macro_misparsed_class_body(child).is_some();
            let is_bodyless_c_type_ref = matches!(lang, Language::C | Language::Cpp)
                && matches!(kind, "struct_specifier" | "class_specifier")
                && child.child_by_field_name("body").is_none()
                && !is_cpp_macro_misparsed_class;

            // Avoid double-counting nested classes when an enclosing class
            // already collected its inner methods/types via extract_class_info.
            // Top-level rule: a class node is "top-level" iff it isn't itself
            // contained in another class-kind ancestor.
            if !is_bodyless_c_type_ref
                && !is_inside_class_ancestor(child, class_kinds)
                && is_node_public(child, source, lang)
            {
                let info = extract_class_info(child, source, lang);
                // Skip empty/anonymous misparses where extract returned no name.
                if !info.name.is_empty() {
                    classes.push(info);
                }
            }
            // Still recurse into the body — nested classes that are themselves
            // public should also surface (mirrors tree-walk behaviour of
            // `tldr extract` for cpp / csharp).
            deep_collect(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }
        // cpp-interface-macro-filter-v1 (v0.4.2 bug-B3 / VAL-CPP-IFACE):
        // suppress the synthetic `function_definition` wrapper that
        // tree-sitter-cpp emits around `class TINYXML2_LIB Foo { ... };`.
        // The inner `class_specifier` already produced the (corrected)
        // class entry above, so adding this wrapper to `functions[]` would
        // surface a phantom function (e.g. `StrPair` at line 133 with
        // signature `": class TINYXML2_LIB"`). We still recurse into the
        // wrapper because the misparsed body (`compound_statement`) may
        // itself contain nested macro-prefixed classes worth surfacing.
        if matches!(lang, Language::Cpp)
            && kind == "function_definition"
            && is_cpp_macro_misparsed_class_wrapper(child)
        {
            deep_collect(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }
        if func_kinds.contains(&kind)
            && !is_inside_class_ancestor(child, class_kinds)
            && is_node_public(child, source, lang)
        {
            // interface-per-lang-v1 (v0.4.2 M-022): C / C++ also list
            // `declaration` under `func_kinds` so function prototypes
            // (e.g. `int foo(int);` in a `.h`) surface. Non-function
            // declarations (typedefs, struct fields, externs) must be
            // filtered here so they do not contaminate `functions[]`.
            if matches!(lang, Language::C | Language::Cpp)
                && kind == "declaration"
                && !is_cpp_member_function_declaration(child)
            {
                deep_collect(
                    child,
                    source,
                    lang,
                    func_kinds,
                    class_kinds,
                    functions,
                    classes,
                    depth + 1,
                );
                continue;
            }
            functions.push(extract_function_info(child, source, lang));
        }
        deep_collect(
            child,
            source,
            lang,
            func_kinds,
            class_kinds,
            functions,
            classes,
            depth + 1,
        );
    }
}

/// cl6-interface-v1 (GH #78): true when `node` is a wrapper that holds
/// top-level-style class / function definitions but is not itself a class
/// or function. The non-deep-walk walker (`visit_top_level`) descends into
/// these so their inner public definitions surface as top-level exports.
///
/// Recognised wrappers, per the tree-sitter grammars (verified against the
/// pinned corpora):
///   * TS / JS `export_statement`
///     `export class Foo`, `export function f`, `export default class D`,
///     `@Dec() export class Foo` — the definition is a child of the
///     `export_statement`, never of the program root.
///   * Scala `package_clause` BLOCK form
///     `package p { class C; object O }` — the nested definitions live in
///     a `template_body` sibling of the `package_identifier`. The
///     file-level form `package p` (no block) has no `template_body` and
///     is intentionally NOT treated as a wrapper: its definitions are
///     already direct children of the compilation unit.
fn is_interface_wrapper(node: Node, lang: Language) -> bool {
    match lang {
        Language::TypeScript | Language::JavaScript => node.kind() == "export_statement",
        Language::Scala => {
            // Only the block form (carrying a `template_body`) wraps nested
            // definitions; the bare `package p` clause does not.
            if node.kind() == "package_clause" {
                let mut cursor = node.walk();
                return node
                    .children(&mut cursor)
                    .any(|c| c.kind() == "template_body");
            }
            // The package block's definitions live one level deeper, inside
            // the `package_clause`'s `template_body`. Recurse into that body
            // (but ONLY when it belongs to a `package_clause` — a
            // `template_body` owned by a `class`/`object`/`trait` is that
            // type's own member block and is handled by `extract_class_info`
            // / `collect_nested_classes`, not as a top-level container).
            node.kind() == "template_body"
                && node
                    .parent()
                    .map(|p| p.kind() == "package_clause")
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// cl6-interface-v1 (GH #78): collect public *nested* class-like definitions
/// declared inside a class/object body, recursing so arbitrarily deep
/// nesting surfaces. Only class-kind nodes are emitted — methods inside the
/// body belong to the enclosing class's `methods[]` and must not leak into
/// the top-level `functions[]` array.
fn collect_nested_classes(
    body: Node,
    source: &[u8],
    lang: Language,
    class_kinds: &[&str],
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    const MAX_NESTED_DEPTH: usize = 8;
    if depth > MAX_NESTED_DEPTH {
        return;
    }
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if class_kinds.contains(&child.kind()) {
            if is_node_public(child, source, lang) {
                let info = extract_class_info(child, source, lang);
                if !info.name.is_empty() {
                    classes.push(info);
                }
            }
            // Recurse into this nested class's body for deeper nesting.
            if let Some(inner_body) = find_body_node(child, lang) {
                collect_nested_classes(
                    inner_body,
                    source,
                    lang,
                    class_kinds,
                    classes,
                    depth + 1,
                );
            }
        } else {
            // Descend through non-class structural nodes (e.g. Ruby
            // `body_statement`, decorator wrappers) to reach nested
            // class declarations that aren't direct children of `body`.
            // Stop short of re-entering a class body we've already
            // handled above (guarded by the class-kind branch).
            collect_nested_classes(child, source, lang, class_kinds, classes, depth + 1);
        }
    }
}

/// Check whether a node is contained within a class/struct/interface ancestor.
/// Used to distinguish top-level functions from methods.
fn is_inside_class_ancestor(node: Node, class_kinds: &[&str]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if class_kinds.contains(&parent.kind()) {
            return true;
        }
        current = parent.parent();
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn visit_top_level(
    node: Node,
    source: &[u8],
    lang: Language,
    func_kinds: &[&str],
    class_kinds: &[&str],
    decorator_kinds: &[&str],
    functions: &mut Vec<FunctionInfo>,
    classes: &mut Vec<ClassInfo>,
    depth: usize,
) {
    // Bound recursion conservatively — we only ever need to descend through
    // a handful of namespace/preproc levels in real-world code.
    const MAX_CONTAINER_DEPTH: usize = 8;
    if depth > MAX_CONTAINER_DEPTH {
        return;
    }

    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let kind = child.kind();

        // Elixir-specific dispatch: `call` nodes match BOTH func_kinds and
        // class_kinds, so the original logic always took the function
        // branch and `defmodule` calls were dropped. BUG-AGG-9 (P11):
        // restructure so we route on the call target name.
        //
        // - `def` / `defmacro` -> public function
        // - `defp` / `defmacrop` -> private, skip
        // - `defmodule` -> recurse into its `do_block` so nested public
        //   `def`s surface as top-level exports (matches `tldr extract`'s
        //   walk; mirrors how the Plug.Conn module exposes its public
        //   API even though every function lives one level deep).
        if lang == Language::Elixir && kind == "call" {
            let target_text = child.child(0).map(|t| node_text(t, source)).unwrap_or("");
            match target_text {
                "def" | "defmacro" => {
                    functions.push(extract_function_info(child, source, lang));
                }
                "defp" | "defmacrop" => {
                    // private, skip
                }
                "defmodule" => {
                    // Recurse into the module body. Module body is a `do_block`
                    // child of the call node.
                    let mut mod_cursor = child.walk();
                    for mod_child in child.children(&mut mod_cursor) {
                        if mod_child.kind() == "do_block" {
                            visit_top_level(
                                mod_child,
                                source,
                                lang,
                                func_kinds,
                                class_kinds,
                                decorator_kinds,
                                functions,
                                classes,
                                depth + 1,
                            );
                        }
                    }
                }
                _ => {}
            }
            continue;
        }

        // cl6-interface-v1 (GH #78): descend into wrapper nodes that hold
        // class / function definitions but are not themselves classes or
        // functions. Without this, the pre-fix walker (which only iterated
        // *direct children* of the file root and recursed for PHP only)
        // silently dropped:
        //   * TS/JS `export class Foo` / `export function f` / `export
        //     default class D` — the definition is a child of an
        //     `export_statement` wrapper, not of the program root.
        //   * Scala `package p { class C }` — `package_clause` carries the
        //     nested definitions in a `template_body` sibling of the
        //     `package_identifier`.
        // These wrappers are recursed into with the SAME `visit_top_level`
        // logic so their inner definitions surface as top-level exports.
        if is_interface_wrapper(child, lang) {
            visit_top_level(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                decorator_kinds,
                functions,
                classes,
                depth + 1,
            );
            continue;
        }

        if func_kinds.contains(&kind) {
            if is_node_public(child, source, lang) {
                functions.push(extract_function_info(child, source, lang));
            }
        } else if class_kinds.contains(&kind) {
            if is_node_public(child, source, lang) {
                classes.push(extract_class_info(child, source, lang));
            }
            // cl6-interface-v1 (GH #78): a class body may itself declare
            // public *nested* classes (Ruby `class Outer; class Inner;
            // end; end`, Scala `object O { class C }`). The pre-fix walker
            // stopped at the outer class and never recursed, so `Inner`
            // vanished. Recurse into the body collecting ONLY nested
            // class-like definitions — methods inside the body are part of
            // the enclosing class's own `methods[]` (gathered by
            // `extract_class_info`) and must NOT leak into top-level
            // `functions[]`.
            if let Some(body) = find_body_node(child, lang) {
                collect_nested_classes(
                    body,
                    source,
                    lang,
                    class_kinds,
                    classes,
                    depth + 1,
                );
            }
        } else if decorator_kinds.contains(&kind) {
            // Handle decorated definitions (Python)
            if let Some(def) = find_definition_in_decorated(child, func_kinds) {
                if is_node_public(def, source, lang) {
                    functions.push(extract_function_info(def, source, lang));
                }
            } else if let Some(class_def) = find_definition_in_decorated(child, class_kinds) {
                if is_node_public(class_def, source, lang) {
                    classes.push(extract_class_info(class_def, source, lang));
                }
            }
        } else if is_interface_container(kind) {
            // Recurse into namespace / preproc / linkage containers so that
            // classes defined inside `namespace foo { ... }` (cpp/csharp) or
            // gated by `#if ... #endif` (cpp) surface as top-level exports.
            visit_top_level(
                child,
                source,
                lang,
                func_kinds,
                class_kinds,
                decorator_kinds,
                functions,
                classes,
                depth + 1,
            );
        } else if lang == Language::Php {
            // PHP wraps everything in a program > php_tag + declaration list.
            // Recurse one level for these.
            let mut inner_cursor = child.walk();
            for inner_child in child.children(&mut inner_cursor) {
                let inner_kind = inner_child.kind();
                if func_kinds.contains(&inner_kind) {
                    if is_node_public(inner_child, source, lang) {
                        functions.push(extract_function_info(inner_child, source, lang));
                    }
                } else if class_kinds.contains(&inner_kind)
                    && is_node_public(inner_child, source, lang)
                {
                    classes.push(extract_class_info(inner_child, source, lang));
                }
            }
        }
    }
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format interface info as human-readable text.
pub fn format_interface_text(info: &InterfaceInfo) -> String {
    let mut lines = Vec::new();

    // Header
    lines.push(format!("File: {}", info.file));
    lines.push(String::new());

    // Public exports (from __all__ if present, else inferred from
    // public function/class names — see InterfaceInfo::all_exports).
    if !info.all_exports.is_empty() {
        lines.push("Exports:".to_string());
        for name in &info.all_exports {
            lines.push(format!("  {}", name));
        }
        lines.push(String::new());
    }

    // Functions
    if !info.functions.is_empty() {
        lines.push("Functions:".to_string());
        for func in &info.functions {
            let async_marker = if func.is_async { "async " } else { "" };
            lines.push(format!(
                "  {}def {}{}  [line {}]",
                async_marker, func.name, func.signature, func.lineno
            ));
            if let Some(ref doc) = func.docstring {
                // Truncate long docstrings
                let doc_preview = if doc.len() > 60 {
                    format!("{}...", &doc[..57])
                } else {
                    doc.clone()
                };
                lines.push(format!("      \"{}\"", doc_preview));
            }
        }
        lines.push(String::new());
    }

    // Values (Lua/Luau non-function exports — rc2-lua-interface-return-table-convention)
    if !info.values.is_empty() {
        lines.push("Values:".to_string());
        for value in &info.values {
            let kind = value
                .kind
                .as_deref()
                .map(|k| format!("{} ", k))
                .unwrap_or_default();
            lines.push(format!("  {}{}  [line {}]", kind, value.name, value.lineno));
        }
        lines.push(String::new());
    }

    // Classes
    if !info.classes.is_empty() {
        lines.push("Classes:".to_string());
        for class in &info.classes {
            let bases_str = if class.bases.is_empty() {
                String::new()
            } else {
                format!("({})", class.bases.join(", "))
            };
            lines.push(format!(
                "  class {}{}  [line {}]",
                class.name, bases_str, class.lineno
            ));

            for method in &class.methods {
                let async_marker = if method.is_async { "async " } else { "" };
                lines.push(format!(
                    "    {}def {}{}",
                    async_marker, method.name, method.signature
                ));
            }

            if class.private_method_count > 0 {
                lines.push(format!(
                    "    ({} private methods)",
                    class.private_method_count
                ));
            }
        }
        lines.push(String::new());
    }

    // Summary
    let total_methods: u32 = info.classes.iter().map(|c| c.methods.len() as u32).sum();
    lines.push(format!(
        "Summary: {} functions, {} classes, {} public methods",
        info.functions.len(),
        info.classes.len(),
        total_methods
    ));

    lines.join("\n")
}

// =============================================================================
// Entry Point
// =============================================================================

/// Check if a file has a supported source code extension.
fn is_supported_source_file(path: &Path) -> bool {
    Language::from_path(path).is_some()
}

/// Run the interface command.
pub fn run(args: InterfaceArgs, format: OutputFormat) -> anyhow::Result<()> {
    let path = &args.path;

    if path.is_dir() {
        // Validate directory
        let canonical_dir = if let Some(ref root) = args.project_root {
            super::validation::validate_file_path_in_project(path, root)?
        } else {
            validate_directory_path(path)?
        };

        // Collect all supported source files recursively
        let mut results = Vec::new();
        let mut entries: Vec<PathBuf> = walk_project(&canonical_dir)
            .filter(|e| e.path().is_file() && is_supported_source_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        // Sort for deterministic output
        entries.sort();

        for file_path in entries {
            // W1-interface-utf8 (v0.5.0 AUDIT-FIX): the directory walk must
            // never abort the whole run on a single non-UTF-8 / binary file.
            // Previously this used the patterns-local `read_file_safe`, which
            // does a HARD `String::from_utf8` and propagated `?` out of
            // `run()` — so one stray `life.lua` / `literals.luau` byte
            // (0xA5) aborted with exit 1 and zero output even though
            // hundreds of valid files remained. Use the SAME tolerant reader
            // the resilient commands (`structure`/`loc`) use via
            // `get_code_structure` -> `parse_file` (`encoding::read_source_file`
            // -> `from_utf8_lossy`): lossy files are still analyzed (with a
            // warning), binary files are skipped, and per-file IO errors are
            // non-fatal. Warnings go to stderr — the SAME non-silent channel
            // the core recoverable-skip arm uses
            // (`extractor.rs`: `eprintln!("Warning: Skipping ...")`) — so the
            // JSON/text report on stdout stays a clean `Vec<InterfaceInfo>`
            // and warnings are never swallowed.
            let source = match tldr_core::encoding::read_source_file(&file_path) {
                Ok(tldr_core::encoding::FileReadResult::Ok(content)) => content,
                Ok(tldr_core::encoding::FileReadResult::Lossy { content, warning }) => {
                    eprintln!("Warning: {}", warning);
                    content
                }
                Ok(tldr_core::encoding::FileReadResult::Binary) => {
                    eprintln!(
                        "Warning: Skipping {} - appears to be a binary file",
                        file_path.display()
                    );
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Skipping {} - {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            };
            match extract_interface(&file_path, &source) {
                Ok(info) => results.push(info),
                Err(_) => {
                    // Skip files that fail to parse (unsupported grammars, etc.)
                    continue;
                }
            }
        }

        // Output
        match format {
            OutputFormat::Text => {
                for info in &results {
                    println!("{}", format_interface_text(info));
                    println!();
                }
            }
            OutputFormat::Compact => {
                let json = serde_json::to_string(&results)?;
                println!("{}", json);
            }
            _ => {
                let json = serde_json::to_string_pretty(&results)?;
                println!("{}", json);
            }
        }
    } else {
        // Single file
        let canonical_path = if let Some(ref root) = args.project_root {
            super::validation::validate_file_path_in_project(path, root)?
        } else {
            validate_file_path(path)?
        };

        let source = read_file_safe(&canonical_path)?;
        let mut info = extract_interface(&canonical_path, &source)?;

        // (path-and-schema-cleanup-v3 P3.BUG-N2) Echo the user-supplied
        // path in the JSON `file` field. The canonical path is used for
        // the actual read, but the emit path mirrors the input verbatim
        // so macOS does not rewrite `/tmp/...` to `/private/tmp/...`.
        info.file = path.display().to_string();

        // Output
        match format {
            OutputFormat::Text => {
                println!("{}", format_interface_text(&info));
            }
            OutputFormat::Compact => {
                let json = serde_json::to_string(&info)?;
                println!("{}", json);
            }
            _ => {
                let json = serde_json::to_string_pretty(&info)?;
                println!("{}", json);
            }
        }
    }

    Ok(())
}

// =============================================================================
// Utilities
// =============================================================================

/// Get the text content of a node.
fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tldr_core::ast::entity::{classify_node_kind, EntityKind};

    const GUARD_LANGUAGES: &[Language] = &[
        Language::Python,
        Language::TypeScript,
        Language::JavaScript,
        Language::Go,
        Language::Rust,
        Language::Java,
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Kotlin,
        Language::Scala,
        Language::Php,
        Language::Ruby,
        Language::Lua,
        Language::Luau,
        Language::Elixir,
        Language::Ocaml,
        Language::Swift,
        Language::Solidity,
    ];

    /// RC2-META Stage 2 fourth-table guard: every node kind accepted by
    /// `interface`'s local `function_node_kinds` / `class_node_kinds` /
    /// `method_node_kinds` tables must agree with the canonical
    /// `entity::classify_node_kind` on the relevant axis. Locks the local copies
    /// so they can never drift to an answer the shared classifier disagrees with.
    #[test]
    fn interface_node_kind_tables_match_classify_node() {
        for &lang in GUARD_LANGUAGES {
            for &k in function_node_kinds(lang) {
                if k == "call" {
                    continue; // Elixir def/defp — node-aware only.
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_function_axis) == Some(true),
                    "interface function_node_kinds({lang:?}) {k:?} -> {ek:?} not function-axis"
                );
            }
            for &k in method_node_kinds(lang) {
                if k == "call" {
                    continue;
                }
                // CF1-S4 (v0.5.0 RC): OCaml class-member kinds are resolved
                // node-aware by `interface` (`get_node_name` reads the
                // `method_name` child) — the shared STRING classifier
                // `classify_node_kind` has no OCaml class/method arm, exactly the
                // node-aware-only situation the Elixir `call` exception above
                // covers. (Extending entity.rs's OCaml arm is a separate
                // tldr-core follow-up; the local table is the source of truth
                // for these member kinds.)
                if lang == Language::Ocaml
                    && matches!(k, "method_definition" | "method_specification" | "method_type")
                {
                    continue;
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_function_axis) == Some(true),
                    "interface method_node_kinds({lang:?}) {k:?} -> {ek:?} not function-axis"
                );
            }
            for &k in class_node_kinds(lang) {
                if k == "call" {
                    continue; // Elixir defmodule — node-aware only.
                }
                // CF1-S4 (v0.5.0 RC): OCaml's two real class carriers are labeled
                // node-aware by `interface` (`ts_js_entry_kind`:
                // class_definition -> "class", class_type_definition ->
                // "interface"); the shared string classifier has no OCaml class
                // arm yet, mirroring the `call` node-aware exception.
                if lang == Language::Ocaml
                    && matches!(k, "class_definition" | "class_type_definition")
                {
                    continue;
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_class_axis) == Some(true),
                    "interface class_node_kinds({lang:?}) {k:?} -> {ek:?} not class-axis"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // is_public_name tests (backward-compatible)
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_public_name_public() {
        assert!(is_public_name("my_function"));
        assert!(is_public_name("MyClass"));
        assert!(is_public_name("process"));
        assert!(is_public_name("x"));
    }

    #[test]
    fn test_is_public_name_private() {
        assert!(!is_public_name("_private"));
        assert!(!is_public_name("__dunder__"));
        assert!(!is_public_name("_PrivateClass"));
        assert!(!is_public_name("__init__"));
    }

    // -------------------------------------------------------------------------
    // Python: extract_all_exports tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_all_exports_present() {
        let source = r#"
__all__ = ['foo', 'bar', 'Baz']

def foo():
    pass
"#;
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();

        let exports = extract_all_exports(root, source.as_bytes());
        assert!(exports.is_some());
        let exports = exports.unwrap();
        assert_eq!(exports.len(), 3);
        assert!(exports.contains(&"foo".to_string()));
        assert!(exports.contains(&"bar".to_string()));
        assert!(exports.contains(&"Baz".to_string()));
    }

    #[test]
    fn test_extract_all_exports_absent() {
        let source = r#"
def foo():
    pass
"#;
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();

        let exports = extract_all_exports(root, source.as_bytes());
        assert!(exports.is_none());
    }

    // -------------------------------------------------------------------------
    // Python: extract_function_signature tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_function_signature_simple() {
        let source = "def foo(x, y): pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert_eq!(sig, "(x, y)");
    }

    #[test]
    fn test_extract_function_signature_typed() {
        let source = "def foo(x: int, y: str) -> bool: pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert!(sig.contains("x: int"), "sig = {:?}", sig);
        assert!(sig.contains("y: str"), "sig = {:?}", sig);
        assert!(sig.contains("-> bool"), "sig = {:?}", sig);
    }

    #[test]
    fn test_extract_function_signature_default() {
        let source = "def foo(x: int = 10): pass";
        let pool = ParserPool::new();
        let tree = pool.parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let func_node = root.child(0).unwrap();

        let sig = extract_function_signature(func_node, source.as_bytes(), Language::Python);
        assert!(sig.contains("x: int = 10") || sig.contains("x: int=10"));
    }

    // -------------------------------------------------------------------------
    // Python: extract_interface tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_public_functions() {
        let source = r#"
def public_func():
    """A public function."""
    pass

def _private_func():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.functions.len(), 1);
        assert_eq!(info.functions[0].name, "public_func");
    }

    #[test]
    fn test_extract_interface_public_classes() {
        let source = r#"
class PublicClass:
    def public_method(self):
        pass

    def _private_method(self):
        pass

class _PrivateClass:
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.classes.len(), 1);
        assert_eq!(info.classes[0].name, "PublicClass");
        assert_eq!(info.classes[0].methods.len(), 1);
        assert_eq!(info.classes[0].methods[0].name, "public_method");
        assert_eq!(info.classes[0].private_method_count, 1);
    }

    #[test]
    fn test_extract_interface_async_function() {
        let source = r#"
async def async_func():
    pass

def sync_func():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.functions.len(), 2);

        let async_fn = info.functions.iter().find(|f| f.name == "async_func");
        assert!(async_fn.is_some());
        assert!(async_fn.unwrap().is_async);

        let sync_fn = info.functions.iter().find(|f| f.name == "sync_func");
        assert!(sync_fn.is_some());
        assert!(!sync_fn.unwrap().is_async);
    }

    #[test]
    fn test_extract_interface_with_all() {
        let source = r#"
__all__ = ['foo', 'Bar']

def foo():
    pass

def bar():
    pass

class Bar:
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        // schema-cleanup-v1 BUG-22: all_exports is now Vec<String>
        // (never null). When `__all__` is present, it carries those.
        assert!(!info.all_exports.is_empty());
        assert!(info.all_exports.contains(&"foo".to_string()));
        assert!(info.all_exports.contains(&"Bar".to_string()));
    }

    #[test]
    fn test_extract_interface_docstrings() {
        let source = r#"
def documented():
    """This is a docstring."""
    pass

def undocumented():
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        let documented = info.functions.iter().find(|f| f.name == "documented");
        assert!(documented.is_some());
        assert!(documented.unwrap().docstring.is_some());
        assert!(documented
            .unwrap()
            .docstring
            .as_ref()
            .unwrap()
            .contains("docstring"));

        let undocumented = info.functions.iter().find(|f| f.name == "undocumented");
        assert!(undocumented.is_some());
        assert!(undocumented.unwrap().docstring.is_none());
    }

    #[test]
    fn test_extract_interface_class_bases() {
        let source = r#"
class Child(Parent, Mixin):
    pass
"#;
        let info = extract_interface(Path::new("test.py"), source).unwrap();

        assert_eq!(info.classes.len(), 1);
        assert_eq!(info.classes[0].bases.len(), 2);
        assert!(info.classes[0].bases.contains(&"Parent".to_string()));
        assert!(info.classes[0].bases.contains(&"Mixin".to_string()));
    }

    // -------------------------------------------------------------------------
    // format_interface_text tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_format_interface_text() {
        let info = InterfaceInfo {
            file: "test.py".to_string(),
            all_exports: vec!["foo".to_string()],
            functions: vec![FunctionInfo {
                name: "foo".to_string(),
                signature: "(x: int) -> str".to_string(),
                docstring: Some("A function.".to_string()),
                lineno: 5,
                is_async: false,
                kind: None,
            }],
            classes: vec![ClassInfo {
                name: "MyClass".to_string(),
                kind: None,
                lineno: 10,
                bases: vec!["Base".to_string()],
                methods: vec![MethodInfo {
                    name: "method".to_string(),
                    signature: "(self)".to_string(),
                    lineno: 11,
                    is_async: false,
                }],
                private_method_count: 2,
            }],
            values: vec![],
        };

        let text = format_interface_text(&info);
        assert!(text.contains("File: test.py"));
        assert!(text.contains("foo"));
        assert!(text.contains("MyClass"));
        assert!(text.contains("Base"));
        assert!(text.contains("method"));
        assert!(text.contains("2 private methods"));
    }

    // =========================================================================
    // Multi-language tests
    // =========================================================================

    // -------------------------------------------------------------------------
    // Rust
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_rust_pub_functions() {
        let source = r#"
/// Adds two numbers.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn private_helper() -> bool {
    true
}

pub async fn async_fetch() -> String {
    String::new()
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        assert_eq!(
            info.functions.len(),
            2,
            "Should find 2 pub functions, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        let add_fn = info.functions.iter().find(|f| f.name == "add");
        assert!(add_fn.is_some(), "Should find 'add' function");
        let add_fn = add_fn.unwrap();
        assert!(
            add_fn.signature.contains("a: i32"),
            "sig = {:?}",
            add_fn.signature
        );
        assert!(
            add_fn.signature.contains("-> i32"),
            "sig = {:?}",
            add_fn.signature
        );
        assert!(add_fn.docstring.is_some(), "Should have doc comment");
        assert!(add_fn
            .docstring
            .as_ref()
            .unwrap()
            .contains("Adds two numbers"));
        assert!(!add_fn.is_async);

        let async_fn = info.functions.iter().find(|f| f.name == "async_fetch");
        assert!(async_fn.is_some(), "Should find 'async_fetch' function");
        assert!(async_fn.unwrap().is_async);
    }

    #[test]
    fn test_extract_interface_rust_struct_impl() {
        let source = r#"
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Point { x, y }
    }

    fn internal(&self) {}
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        // Should find struct and impl as classes
        assert!(
            !info.classes.is_empty(),
            "Should find at least struct/impl, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        // Check the struct
        let point_struct = info.classes.iter().find(|c| c.name == "Point");
        assert!(point_struct.is_some(), "Should find Point struct/impl");
    }

    #[test]
    fn test_extract_interface_rust_trait() {
        let source = r#"
pub trait Drawable {
    fn draw(&self);
    fn resize(&mut self, factor: f64);
}
"#;
        let info = extract_interface(Path::new("test.rs"), source).unwrap();

        let trait_info = info.classes.iter().find(|c| c.name == "Drawable");
        assert!(trait_info.is_some(), "Should find Drawable trait");
    }

    // -------------------------------------------------------------------------
    // Go
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_go_exported_functions() {
        let source = r#"
package main

// ProcessData handles data processing.
func ProcessData(input string) (string, error) {
    return input, nil
}

func internalHelper() bool {
    return true
}
"#;
        let info = extract_interface(Path::new("test.go"), source).unwrap();

        // Go: exported functions start with uppercase
        assert_eq!(
            info.functions.len(),
            1,
            "Should find 1 exported function, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert_eq!(info.functions[0].name, "ProcessData");
        assert!(
            info.functions[0].docstring.is_some(),
            "Should have doc comment"
        );
    }

    // -------------------------------------------------------------------------
    // TypeScript
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_typescript_class() {
        // rc2-ts-interface-typealias-lumped-as-classes (#243): the `interface`
        // command now filters non-exported TS decls (they are not part of the
        // public API surface). The definitions are `export`ed so they still
        // surface; the class carrier carries `kind == "class"`.
        let source = r#"
export class UserService {
    async fetchUser(id: string): Promise<User> {
        return {} as User;
    }

    private internalMethod(): void {}
}

export function processData(input: string): number {
    return input.length;
}
"#;
        let info = extract_interface(Path::new("test.ts"), source).unwrap();

        // Should find both the class and the function
        assert!(
            !info.functions.is_empty() || !info.classes.is_empty(),
            "Should find definitions: functions={:?}, classes={:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let svc = info
            .classes
            .iter()
            .find(|c| c.name == "UserService")
            .expect("UserService present");
        assert_eq!(svc.kind.as_deref(), Some("class"));
    }

    // ====================================================================
    // A3a-js-ts-export-engine (v0.5.0 BACKLOG): JS/TS export idiom resolver.
    // GENERALIZATION: every idiom shape (reverse-binding, export-default-object,
    // export-const, arrow-const) must resolve exports for BOTH js AND ts.
    // ====================================================================

    /// Helper: assert `all_exports` contains every expected name.
    fn assert_exports(info: &InterfaceInfo, expected: &[&str]) {
        for name in expected {
            assert!(
                info.all_exports.iter().any(|e| e == name),
                "expected export `{}` in all_exports={:?} (functions={:?}, classes={:?}, values={:?})",
                name,
                info.all_exports,
                info.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
                info.classes.iter().map(|c| &c.name).collect::<Vec<_>>(),
                info.values.iter().map(|v| &v.name).collect::<Vec<_>>(),
            );
        }
    }

    /// Shape: reverse-binding CommonJS — `module.exports = res;` followed by
    /// `res.member = function …`. This is Express `lib/response.js`. Resolve for
    /// both .js and .ts.
    #[test]
    fn test_export_engine_reverse_binding_cjs_js_and_ts() {
        let source = r#"
var res = Object.create(proto);
module.exports = res;
res.status = function status(code) { return code; };
res.send = function send(body) { return body; };
res.json = (obj) => obj;
"#;
        for (path, lang) in [("response.js", "js"), ("response.ts", "ts")] {
            let info = extract_interface(Path::new(path), source).unwrap();
            assert_exports(&info, &["status", "send", "json"]);
            assert!(
                info.functions.iter().any(|f| f.name == "send"),
                "[{lang}] send must be a resolved function, got {:?}",
                info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
            );
        }
    }

    /// Shape: reverse-binding ESM — `export default axios;` followed by
    /// `axios.member = function …` and identifier re-exports. axios
    /// `lib/axios.js`. Resolve for both .js and .ts.
    #[test]
    fn test_export_engine_reverse_binding_esm_default_js_and_ts() {
        let source = r#"
const axios = createInstance(defaults);
axios.all = function all(promises) { return promises; };
axios.formToJSON = (thing) => thing;
axios.spread = spread;
export default axios;
"#;
        for path in ["axios.js", "axios.ts"] {
            let info = extract_interface(Path::new(path), source).unwrap();
            // function-valued members resolve as functions
            assert_exports(&info, &["all", "formToJSON"]);
            // identifier re-export surfaces as a value (not dropped)
            assert_exports(&info, &["spread"]);
        }
    }

    /// Shape: export-default object literal — members become exports. Resolve
    /// for both .js and .ts.
    #[test]
    fn test_export_engine_export_default_object_js_and_ts() {
        let source = r#"
export default {
  one() { return 1; },
  two: function() { return 2; },
  three: () => 3,
  version: 42,
};
"#;
        for path in ["mod.js", "mod.ts"] {
            let info = extract_interface(Path::new(path), source).unwrap();
            assert_exports(&info, &["one", "two", "three", "version"]);
            assert!(
                info.functions.iter().any(|f| f.name == "one")
                    && info.functions.iter().any(|f| f.name == "three"),
                "object method + arrow member must be functions"
            );
            assert!(
                info.values.iter().any(|v| v.name == "version"),
                "non-function member must be a value"
            );
        }
    }

    /// Shape: `module.exports = { … }` CJS object default. Resolve for both
    /// .js and .ts.
    #[test]
    fn test_export_engine_module_exports_object_js_and_ts() {
        let source = r#"
function helper(a) { return a; }
module.exports = {
  helper: helper,
  build: function build() { return 1; },
  run: () => 2,
};
"#;
        for path in ["cjs.js", "cjs.ts"] {
            let info = extract_interface(Path::new(path), source).unwrap();
            assert_exports(&info, &["helper", "build", "run"]);
        }
    }

    /// Shape: export-const + arrow-const — `export const f = (…) => …` and
    /// `export const g = function …`. Resolve for both .js and .ts.
    #[test]
    fn test_export_engine_export_const_arrow_js_and_ts() {
        let source = r#"
export const alpha = (x) => x + 1;
export const beta = function beta(y) { return y * 2; };
export const VERSION = "1.0.0";
export const Widget = class Widget {};
"#;
        for path in ["consts.js", "consts.ts"] {
            let info = extract_interface(Path::new(path), source).unwrap();
            assert_exports(&info, &["alpha", "beta", "VERSION", "Widget"]);
            assert!(
                info.functions.iter().any(|f| f.name == "alpha"),
                "arrow-const export must be a function"
            );
            assert!(
                info.values.iter().any(|v| v.name == "VERSION"),
                "primitive const export must be a value"
            );
        }
    }

    /// Shape: reverse-binding ESM with a single arrow local default —
    /// `const delta = () => …; export default delta;`. Resolve for both langs.
    #[test]
    fn test_export_engine_default_arrow_local_js_and_ts() {
        let source = r#"
const delta = (z) => z * 3;
export default delta;
"#;
        for path in ["d.js", "d.ts"] {
            let info = extract_interface(Path::new(path), source).unwrap();
            assert_exports(&info, &["delta"]);
            assert!(
                info.functions.iter().any(|f| f.name == "delta"),
                "default-exported arrow local must resolve as a function"
            );
        }
    }

    /// Regression guard: a private (non-exported) local must NOT leak into the
    /// export surface.
    #[test]
    fn test_export_engine_private_local_not_exported() {
        let source = r#"
const privateHelper = (x) => x;
export const publicFn = (y) => y;
"#;
        let info = extract_interface(Path::new("p.ts"), source).unwrap();
        assert_exports(&info, &["publicFn"]);
        assert!(
            !info.all_exports.iter().any(|e| e == "privateHelper"),
            "private local must not be exported, got {:?}",
            info.all_exports
        );
    }

    #[test]
    fn test_extract_interface_typescript_interface() {
        // rc2-ts-interface-typealias-lumped-as-classes: interface and type
        // alias carriers must now carry an AST-derived `kind` discriminator,
        // and (#243) only the exported decls surface.
        let source = r#"
export interface User {
    id: string;
    name: string;
    email: string;
}

export type Status = "active" | "inactive";
"#;
        let info = extract_interface(Path::new("test.ts"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find interface/type declarations, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        let user = info.classes.iter().find(|c| c.name == "User").unwrap();
        assert_eq!(user.kind.as_deref(), Some("interface"));
        let status = info.classes.iter().find(|c| c.name == "Status").unwrap();
        assert_eq!(status.kind.as_deref(), Some("type"));
    }

    #[test]
    fn test_extract_interface_ts_kind_discriminator_and_export_gate() {
        // rc2-ts-interface-typealias-lumped-as-classes char test: the minimal
        // mixed fixture from the proposal's ## Reproduction (1 non-exported
        // interface, 1 exported interface, 1 non-exported type alias, 1
        // exported class, 1 exported enum).
        let source = r#"
interface PrivateLocal { a: number; }
export interface PublicOne { b: string; }
type LocalAlias = string | number;
export class RealClass { run(): void {} }
export enum Color { Red, Green }
"#;
        let info = extract_interface(Path::new("t243.ts"), source).unwrap();
        let names: Vec<&str> = info.classes.iter().map(|c| c.name.as_str()).collect();

        // #243: non-exported file-local decls are filtered from classes[].
        assert!(
            !names.contains(&"PrivateLocal"),
            "non-exported interface must be filtered, got {names:?}"
        );
        assert!(
            !names.contains(&"LocalAlias"),
            "non-exported type alias must be filtered, got {names:?}"
        );

        // #243: and from all_exports[] (the name-chain fallback).
        assert!(!info.all_exports.contains(&"PrivateLocal".to_string()));
        assert!(!info.all_exports.contains(&"LocalAlias".to_string()));

        // Exported decls surface, each kind-tagged from its tree-sitter node.
        let kind_of = |n: &str| {
            info.classes
                .iter()
                .find(|c| c.name == n)
                .and_then(|c| c.kind.as_deref())
        };
        assert_eq!(kind_of("PublicOne"), Some("interface"));
        assert_eq!(kind_of("RealClass"), Some("class"));
        assert_eq!(kind_of("Color"), Some("enum"));

        // The real class count is exactly the entries with kind == "class".
        let class_count = info
            .classes
            .iter()
            .filter(|c| c.kind.as_deref() == Some("class"))
            .count();
        assert_eq!(class_count, 1, "exactly one real class");
    }

    #[test]
    fn test_ts_export_gate_wrapper_shapes() {
        // rc2-ts-interface-typealias-lumped-as-classes: the AST parent-kind
        // export gate (`is_node_public` for TS) must accept exported wrapper
        // shapes and reject bare (file-local) ones.

        // exported interface -> present
        let info = extract_interface(
            Path::new("a.ts"),
            "export interface Exported { x: number; }\n",
        )
        .unwrap();
        assert!(info.classes.iter().any(|c| c.name == "Exported"));

        // bare interface -> filtered
        let info =
            extract_interface(Path::new("b.ts"), "interface Bare { x: number; }\n").unwrap();
        assert!(!info.classes.iter().any(|c| c.name == "Bare"));

        // export default class -> present (decl still in `declaration` field)
        let info = extract_interface(
            Path::new("c.ts"),
            "export default class Defaulted { run(): void {} }\n",
        )
        .unwrap();
        assert!(info.classes.iter().any(|c| c.name == "Defaulted"));

        // re-export `export { X }` -> no `declaration` child -> no leak
        let info = extract_interface(
            Path::new("d.ts"),
            "class Hidden { run(): void {} }\nexport { Hidden };\n",
        )
        .unwrap();
        assert!(
            !info.classes.iter().any(|c| c.name == "Hidden"),
            "re-export must not surface the file-local class"
        );
    }

    // -------------------------------------------------------------------------
    // Java
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_java_class() {
        let source = r#"
/**
 * Service for managing users.
 */
public class UserService {
    public String getUser(String id) {
        return id;
    }

    private void internalCleanup() {}
}
"#;
        let info = extract_interface(Path::new("test.java"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find Java class, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        if let Some(cls) = info.classes.iter().find(|c| c.name == "UserService") {
            assert!(!cls.methods.is_empty(), "Should find public methods");
        }
    }

    // -------------------------------------------------------------------------
    // C
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_c_functions() {
        let source = r#"
int add(int a, int b) {
    return a + b;
}

static int internal_helper(void) {
    return 42;
}
"#;
        let info = extract_interface(Path::new("test.c"), source).unwrap();

        // Non-static C functions should be public
        assert_eq!(
            info.functions.len(),
            1,
            "Should find 1 non-static function, got: {:?}",
            info.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert_eq!(info.functions[0].name, "add");
    }

    // -------------------------------------------------------------------------
    // Ruby
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_interface_ruby_class() {
        let source = r#"
class UserManager
  def find_user(id)
    # find user
  end

  def _private_method
    # private
  end
end
"#;
        let info = extract_interface(Path::new("test.rb"), source).unwrap();

        assert!(
            !info.classes.is_empty(),
            "Should find Ruby class, got: {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        if let Some(cls) = info.classes.iter().find(|c| c.name == "UserManager") {
            assert_eq!(
                cls.methods.len(),
                1,
                "Should find 1 public method, got: {:?}",
                cls.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
            );
            assert_eq!(cls.methods[0].name, "find_user");
            assert_eq!(cls.private_method_count, 1);
        }
    }

    // -------------------------------------------------------------------------
    // is_public_for_lang tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_public_for_go() {
        assert!(is_public_for_lang("ProcessData", Language::Go));
        assert!(!is_public_for_lang("processData", Language::Go));
    }

    #[test]
    fn test_is_public_for_python() {
        assert!(is_public_for_lang("process_data", Language::Python));
        assert!(!is_public_for_lang("_private", Language::Python));
    }

    // -------------------------------------------------------------------------
    // is_supported_source_file tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_supported_source_file() {
        assert!(is_supported_source_file(Path::new("test.py")));
        assert!(is_supported_source_file(Path::new("test.rs")));
        assert!(is_supported_source_file(Path::new("test.go")));
        assert!(is_supported_source_file(Path::new("test.ts")));
        assert!(is_supported_source_file(Path::new("test.java")));
        assert!(is_supported_source_file(Path::new("test.c")));
        assert!(is_supported_source_file(Path::new("test.rb")));
        assert!(is_supported_source_file(Path::new("test.cs")));
        assert!(!is_supported_source_file(Path::new("test.txt")));
        assert!(!is_supported_source_file(Path::new("test.md")));
    }

    /// (fix-R7-cl2-c-structref-v1) A C `struct_specifier` used only as a TYPE
    /// REFERENCE — `sizeof(struct sdshdr5)`, a cast, a param type — has no body
    /// and must NOT be reported as a class/export. Only the struct WITH a body
    /// is a definition.
    #[test]
    fn test_interface_c_struct_type_reference_not_class() {
        let source = r#"
struct sdshdr5 {
    unsigned char flags;
    char buf[];
};

int sdslen(void) {
    return sizeof(struct sdshdr8) + sizeof(struct sdshdr16);
}
"#;
        let info = extract_interface(Path::new("test.c"), source).unwrap();
        let class_names: Vec<&str> = info.classes.iter().map(|c| c.name.as_str()).collect();
        // The bodyless type references must NOT appear as classes.
        assert!(
            !class_names.contains(&"sdshdr8"),
            "`sizeof(struct sdshdr8)` (no body) must not be a class, got {:?}",
            class_names
        );
        assert!(
            !class_names.contains(&"sdshdr16"),
            "`sizeof(struct sdshdr16)` (no body) must not be a class, got {:?}",
            class_names
        );
        assert!(
            !info.all_exports.iter().any(|e| e == "sdshdr8"),
            "type-reference `sdshdr8` must not be an export, got {:?}",
            info.all_exports
        );
        // The real definition (with body) IS a class.
        assert!(
            class_names.contains(&"sdshdr5"),
            "the defined `struct sdshdr5` (with body) must be a class, got {:?}",
            class_names
        );
    }

    /// (fix-R7-cl2-csharp-bases-v1) C# bases live under a `base_list` node, not
    /// Java's `superclass`/`interfaces` fields. The C# arm must capture the base
    /// type (was always empty: #38).
    #[test]
    fn test_interface_csharp_bases_captured() {
        let source = r#"
public class JsonException : Exception
{
    public void Throw() {}
}
"#;
        let info = extract_interface(Path::new("test.cs"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "JsonException")
            .expect("JsonException class");
        assert!(
            cls.bases.iter().any(|b| b == "Exception"),
            "C# base `Exception` must be captured, got {:?}",
            cls.bases
        );
    }

    /// (fix-R7-cl2-php-bases-v1) PHP had no base arm (#153). `extends` must be
    /// captured.
    #[test]
    fn test_interface_php_bases_captured() {
        let source = r#"<?php
class ServerException extends BadResponseException
{
    public function getResponse() {}
}
"#;
        let info = extract_interface(Path::new("test.php"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "ServerException")
            .expect("ServerException class");
        assert!(
            cls.bases.iter().any(|b| b == "BadResponseException"),
            "PHP base `BadResponseException` must be captured, got {:?}",
            cls.bases
        );
    }

    // -------------------------------------------------------------------------
    // RC2-1-visibility-csharp-java-php: explicit private/protected/internal
    // members must be EXCLUDED from the public `methods` set and tallied in
    // `private_method_count`, while implicit-visibility (interface/enum)
    // members carrying NO access keyword stay public. Symptom class spans
    // csharp + java + php; this gate asserts ALL THREE plus implicit-public
    // preservation, so a single-language fix cannot pass.
    // -------------------------------------------------------------------------

    fn cls_named<'a>(info: &'a InterfaceInfo, name: &str) -> &'a ClassInfo {
        info.classes
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "class {name:?} not found, got {:?}",
                    info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn test_interface_java_excludes_private_protected_methods_rc2_1() {
        let source = r#"
public class UserService {
    public String getUser(String id) { return id; }
    private void cleanup() {}
    protected int helper() { return 0; }
}
"#;
        let info = extract_interface(Path::new("test.java"), source).unwrap();
        let cls = cls_named(&info, "UserService");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "getUser"),
            "public method must surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "cleanup"),
            "private method must be excluded from public set, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "helper"),
            "protected method must be excluded from public set, got {names:?}"
        );
        assert_eq!(
            cls.private_method_count, 2,
            "private + protected must be tallied"
        );
    }

    #[test]
    fn test_interface_java_interface_methods_implicit_public_rc2_1() {
        // Java interface methods carry NO access keyword yet are public.
        let source = r#"
public interface Repository {
    String find(String id);
    void save(Object o);
}
"#;
        let info = extract_interface(Path::new("test.java"), source).unwrap();
        let cls = cls_named(&info, "Repository");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "find") && names.iter().any(|n| *n == "save"),
            "implicit-public interface methods must surface, got {names:?}"
        );
        assert_eq!(
            cls.private_method_count, 0,
            "no explicit private modifiers => 0 private methods"
        );
    }

    #[test]
    fn test_interface_csharp_excludes_private_internal_protected_methods_rc2_1() {
        let source = r#"
public class Writer
{
    public void Write() {}
    private void Flush() {}
    protected void Reset() {}
    internal void Sync() {}
}
"#;
        let info = extract_interface(Path::new("test.cs"), source).unwrap();
        let cls = cls_named(&info, "Writer");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "Write"),
            "public method must surface, got {names:?}"
        );
        for hidden in ["Flush", "Reset", "Sync"] {
            assert!(
                !names.iter().any(|n| *n == hidden),
                "{hidden} (non-public) must be excluded, got {names:?}"
            );
        }
        assert_eq!(
            cls.private_method_count, 3,
            "private + protected + internal must be tallied"
        );
    }

    #[test]
    fn test_interface_csharp_interface_members_implicit_public_rc2_1() {
        // C# interface members carry NO access keyword yet are public.
        let source = r#"
public interface IWriter
{
    void Write();
    string Name();
}
"#;
        let info = extract_interface(Path::new("test.cs"), source).unwrap();
        let cls = cls_named(&info, "IWriter");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "Write") && names.iter().any(|n| *n == "Name"),
            "implicit-public interface members must surface, got {names:?}"
        );
        assert_eq!(cls.private_method_count, 0);
    }

    #[test]
    fn test_interface_php_excludes_private_protected_methods_rc2_1() {
        let source = r#"<?php
class Client {
    public function send() {}
    private function open() {}
    protected function close() {}
}
"#;
        let info = extract_interface(Path::new("test.php"), source).unwrap();
        let cls = cls_named(&info, "Client");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "send"),
            "public method must surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "open"),
            "private method must be excluded, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "close"),
            "protected method must be excluded, got {names:?}"
        );
        assert_eq!(
            cls.private_method_count, 2,
            "private + protected must be tallied"
        );
    }

    #[test]
    fn test_interface_php_interface_methods_implicit_public_rc2_1() {
        // PHP interface methods without a visibility keyword are public.
        let source = r#"<?php
interface Sender {
    function send($req);
    function ping();
}
"#;
        let info = extract_interface(Path::new("test.php"), source).unwrap();
        let cls = cls_named(&info, "Sender");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "send") && names.iter().any(|n| *n == "ping"),
            "implicit-public interface methods must surface, got {names:?}"
        );
        assert_eq!(cls.private_method_count, 0);
    }

    #[test]
    fn test_interface_visibility_other_langs_unchanged_rc2_1() {
        // Guard: the has_public_modifier repair must NOT bleed into languages
        // that resolve visibility by other means. Rust uses `pub`; a non-pub
        // method must still be excluded (is_rust_pub path), and a `pub` method
        // must surface — proving the modifier-child inspection did not regress
        // the C/Cpp/Kotlin/Swift/Elixir/OCaml `_ => true` fall-through siblings.
        let rust = r#"
pub struct Foo;
impl Foo {
    pub fn visible(&self) {}
    fn hidden(&self) {}
}
"#;
        let info = extract_interface(Path::new("test.rs"), rust).unwrap();
        let cls = cls_named(&info, "Foo");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "visible"),
            "rust pub method must surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "hidden"),
            "rust non-pub method must stay excluded, got {names:?}"
        );
        assert_eq!(cls.private_method_count, 1);
    }

    // -------------------------------------------------------------------------
    // RC2-2-visibility-ts-kotlin-swift: the member-axis visibility gate must
    // read the AST access modifier for TS (`accessibility_modifier`), Kotlin
    // (`modifiers > visibility_modifier`), and Swift (`visibility_modifier`)
    // instead of falling through to `_ => true`. Without this, every TS / Kotlin
    // / Swift method counted as public, `private_method_count` was always 0, and
    // explicit private members leaked into the public `methods` set. This gate
    // spans ALL THREE languages plus implicit-public preservation, so a
    // single-language fix cannot pass.
    // -------------------------------------------------------------------------

    #[test]
    fn test_interface_typescript_excludes_private_protected_methods_rc2_2() {
        let source = r#"
export class Service {
    public connect() {}
    ping() {}
    private secret() {}
    protected helper() {}
}
"#;
        let info = extract_interface(Path::new("test.ts"), source).unwrap();
        let cls = cls_named(&info, "Service");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "connect"),
            "explicit-public method must surface, got {names:?}"
        );
        assert!(
            names.iter().any(|n| *n == "ping"),
            "implicit-public (no modifier) method must surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "secret"),
            "private method must be excluded, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "helper"),
            "protected method must be excluded, got {names:?}"
        );
        assert_eq!(
            cls.private_method_count, 2,
            "private + protected must be tallied"
        );
    }

    #[test]
    fn test_interface_kotlin_excludes_private_protected_internal_methods_rc2_2() {
        let source = r#"
class Service {
    fun ping() {}
    public fun connect() {}
    private fun secret() {}
    protected fun helper() {}
    internal fun debugOnly() {}
}
"#;
        let info = extract_interface(Path::new("test.kt"), source).unwrap();
        let cls = cls_named(&info, "Service");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "ping"),
            "implicit-public (Kotlin default) method must surface, got {names:?}"
        );
        assert!(
            names.iter().any(|n| *n == "connect"),
            "explicit-public method must surface, got {names:?}"
        );
        for hidden in ["secret", "helper", "debugOnly"] {
            assert!(
                !names.iter().any(|n| *n == hidden),
                "{hidden} (non-public) must be excluded, got {names:?}"
            );
        }
        assert_eq!(
            cls.private_method_count, 3,
            "private + protected + internal must be tallied"
        );
    }

    #[test]
    fn test_interface_swift_excludes_private_fileprivate_methods_rc2_2() {
        // Swift's DEFAULT visibility is `internal`; for the interface member
        // view only `private`/`fileprivate` are non-public — `internal` and the
        // implicit default stay in the public method set.
        let source = r#"
public class Service {
    public func connect() {}
    func ping() {}
    internal func sync() {}
    private func secret() {}
    fileprivate func helper() {}
}
"#;
        let info = extract_interface(Path::new("test.swift"), source).unwrap();
        let cls = cls_named(&info, "Service");
        let names: Vec<&String> = cls.methods.iter().map(|m| &m.name).collect();
        assert!(
            names.iter().any(|n| *n == "connect"),
            "explicit-public method must surface, got {names:?}"
        );
        assert!(
            names.iter().any(|n| *n == "ping"),
            "implicit (internal-default) method must stay public, got {names:?}"
        );
        assert!(
            names.iter().any(|n| *n == "sync"),
            "explicit `internal` method must stay public in interface view, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "secret"),
            "private method must be excluded, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| *n == "helper"),
            "fileprivate method must be excluded, got {names:?}"
        );
        assert_eq!(
            cls.private_method_count, 2,
            "private + fileprivate must be tallied"
        );
    }

    /// RC2-META Stage 3 (swift): `interface`'s ClassInfo.kind must be populated
    /// via the canonical `classify_node` — class/struct/enum/protocol surface
    /// their real kind instead of `kind: None`.
    #[test]
    fn test_interface_swift_class_kind_rc2_meta_stage3() {
        let source = r#"
public class Animal {
    public func speak() -> String { return "" }
}

public struct Point {
    public var x: Int
}

public enum Color {
    case red
}

public protocol Greet {
    func hi()
}
"#;
        let info = extract_interface(Path::new("test.swift"), source).unwrap();
        let kind_of = |name: &str| -> Option<String> {
            info.classes
                .iter()
                .find(|c| c.name == name)
                .and_then(|c| c.kind.clone())
        };
        assert_eq!(kind_of("Animal").as_deref(), Some("class"), "classes: {:?}", info.classes);
        assert_eq!(kind_of("Point").as_deref(), Some("struct"), "classes: {:?}", info.classes);
        assert_eq!(kind_of("Color").as_deref(), Some("enum"), "classes: {:?}", info.classes);
        assert_eq!(
            kind_of("Greet").as_deref(),
            Some("interface"),
            "swift protocol -> kind:interface; classes: {:?}",
            info.classes
        );
    }

    /// (fix-R7-cl2-swift-signature-v1) Swift method signatures were always
    /// empty in `interface` (#239) because the generic signature builder used a
    /// `parameters` field that tree-sitter-swift does not expose. The Swift arm
    /// must reconstruct `(params) throws -> ReturnType` from the AST.
    #[test]
    fn test_interface_swift_method_signature_not_empty() {
        let source = r#"
public class Api {
    public func asURLRequest(using e: Encoder) throws -> URLRequest {
        return r
    }
}
"#;
        let info = extract_interface(Path::new("test.swift"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "Api")
            .expect("Api class");
        let m = cls
            .methods
            .iter()
            .find(|m| m.name == "asURLRequest")
            .expect("asURLRequest method");
        assert!(
            !m.signature.trim().is_empty(),
            "Swift method signature must not be empty"
        );
        // The signature must carry the parameter and the return type.
        assert!(
            m.signature.contains("Encoder"),
            "signature must include the param type `Encoder`, got {:?}",
            m.signature
        );
        assert!(
            m.signature.contains("URLRequest"),
            "signature must include return type `URLRequest`, got {:?}",
            m.signature
        );
        // Body braces must NOT appear in the signature.
        assert!(
            !m.signature.contains('{'),
            "signature must drop the body, got {:?}",
            m.signature
        );
    }

    /// (fix-R7-cl2-scala-abstract-v1) A Scala trait's abstract (bodyless) `def`s
    /// parse as `function_declaration` and must surface as methods — the whole
    /// point of `interface` for a trait contract (#207 dropped all but the one
    /// concrete def).
    #[test]
    fn test_interface_scala_abstract_trait_methods() {
        let source = r#"
trait Clock {
  def currentTime(unit: TimeUnit): Long
  def nanoTime: Long
  def instant: Instant
}
"#;
        let info = extract_interface(Path::new("test.scala"), source).unwrap();
        let cls = info
            .classes
            .iter()
            .find(|c| c.name == "Clock")
            .expect("Clock trait");
        let method_names: Vec<&str> = cls.methods.iter().map(|m| m.name.as_str()).collect();
        for expected in ["currentTime", "nanoTime", "instant"] {
            assert!(
                method_names.contains(&expected),
                "abstract trait method `{}` must surface, got {:?}",
                expected,
                method_names
            );
        }
    }

    /// RC2-META Stage 3 (scala): `interface` must populate `ClassInfo.kind`
    /// for every Scala container/type via the canonical classifier
    /// (`class`/`object`/`trait`/`enum`/`type`), and must STOP dropping
    /// `enum_definition` / `type_definition` (type aliases) from the surface.
    #[test]
    fn test_interface_scala_kind_population_and_enum_type_emitted() {
        let source = r#"
class Plain {
  def f(x: Int): Int = x
}
object Companion {}
trait Greeter {
  def hello: String
}
enum Color { case Red, Green, Blue }
type MyInt = Int
"#;
        let info = extract_interface(Path::new("test.scala"), source).unwrap();
        let kind_of = |n: &str| -> Option<String> {
            info.classes
                .iter()
                .find(|c| c.name == n)
                .and_then(|c| c.kind.clone())
        };

        assert_eq!(kind_of("Plain").as_deref(), Some("class"), "{:?}", info.classes);
        assert_eq!(
            kind_of("Companion").as_deref(),
            Some("object"),
            "{:?}",
            info.classes
        );
        assert_eq!(kind_of("Greeter").as_deref(), Some("trait"), "{:?}", info.classes);
        // formerly DROPPED by interface (absent from class_node_kinds(Scala)).
        assert_eq!(
            kind_of("Color").as_deref(),
            Some("enum"),
            "scala enum must surface in interface with kind:\"enum\"; got {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert_eq!(
            kind_of("MyInt").as_deref(),
            Some("type"),
            "scala type alias must surface in interface with kind:\"type\"; got {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    /// RC2-META Stage 3 (ocaml): `interface` must populate `ClassInfo.kind`
    /// for OCaml's container/type axis via the canonical classifier — a
    /// `module M = struct .. end` carries `kind:"module"` and a `type t = ..`
    /// alias carries `kind:"type"`, replacing the former undifferentiated
    /// `kind: None`. Node kinds reaching `extract_class_info` are exactly
    /// `class_node_kinds(Ocaml)` = {module_definition, type_definition}.
    #[test]
    fn test_interface_ocaml_kind_population_module_and_type() {
        let source = r#"
module Greeter = struct
  let hello name = "hi " ^ name
end

type color = Red | Green | Blue

type alias_t = int
"#;
        let info = extract_interface(Path::new("test.ml"), source).unwrap();
        let kind_of = |n: &str| -> Option<String> {
            info.classes
                .iter()
                .find(|c| c.name == n)
                .and_then(|c| c.kind.clone())
        };

        assert_eq!(
            kind_of("Greeter").as_deref(),
            Some("module"),
            "ocaml module must surface in interface with kind:\"module\"; got {:?}",
            info.classes
                .iter()
                .map(|c| (&c.name, &c.kind))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            kind_of("color").as_deref(),
            Some("type"),
            "ocaml type definition must carry kind:\"type\"; got {:?}",
            info.classes
                .iter()
                .map(|c| (&c.name, &c.kind))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            kind_of("alias_t").as_deref(),
            Some("type"),
            "ocaml type alias must carry kind:\"type\"; got {:?}",
            info.classes
                .iter()
                .map(|c| (&c.name, &c.kind))
                .collect::<Vec<_>>()
        );
    }

    /// A3c-interface-ocaml (v0.5.0 BACKLOG): `tldr interface` must enumerate
    /// the `let`/value methods of an OCaml module's `struct ... end` body —
    /// previously every module surfaced with `methods: []` because
    /// `find_body_node` had no OCaml arm and the default scan never reached
    /// the `structure` body nested one level down inside `module_binding`.
    ///
    /// GENERALIZATION: this asserts the fix covers EVERY OCaml module-binding
    /// variant in the symptom class, not just the one plain form:
    ///   * plain          `module M = struct .. end`            (dune form)
    ///   * signature-annot `module M : sig .. end = struct .. end` (lwt form,
    ///                      e.g. `Basic_helpers`, `Resolution_loop`)
    ///   * functor         `module Make (X) = struct .. end`     (dune dag.ml)
    ///   * nested          inner module enumerates its own methods
    /// and that the no-body variants correctly yield ZERO methods (no false
    /// positives):
    ///   * functor-application `module M = Make (X)`             (lwt Storage_map)
    ///   * module alias        `module M = N`                    (lwt Lwt_sequence)
    #[test]
    fn test_interface_ocaml_module_methods_enumerated_all_variants() {
        let source = r#"
module Plain = struct
  let plain_a x = x + 1
  let plain_b y = y * 2
end

module Annotated : sig
  val ann_a : int -> int
end = struct
  let ann_a x = x + 1
  let ann_b y = y - 1
end

module Make (V : sig end) = struct
  let make_a v = v
  let make_b v = v
end

module Outer = struct
  let outer_a x = x
  module Inner = struct
    let inner_a y = y
  end
end

module AliasMod = Plain
module AppliedMod = Make (struct end)
"#;
        let info = extract_interface(Path::new("variants.ml"), source).unwrap();
        let methods_of = |n: &str| -> Vec<String> {
            info.classes
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.methods.iter().map(|m| m.name.clone()).collect())
                .unwrap_or_default()
        };

        // Plain struct: both let-bindings enumerate.
        assert_eq!(
            methods_of("Plain"),
            vec!["plain_a".to_string(), "plain_b".to_string()],
            "plain `module M = struct .. end` must enumerate its let methods; \
             classes={:?}",
            info.classes
                .iter()
                .map(|c| (&c.name, c.methods.len()))
                .collect::<Vec<_>>()
        );

        // Signature-annotated struct (the lwt form): the STRUCT body's
        // let-bindings enumerate (not the sig's `val`s) — the `body` field
        // resolves to the `struct` side of `: sig .. end = struct .. end`.
        assert_eq!(
            methods_of("Annotated"),
            vec!["ann_a".to_string(), "ann_b".to_string()],
            "`module M : sig .. end = struct .. end` must enumerate the struct \
             body's let methods; got {:?}",
            methods_of("Annotated")
        );

        // Functor with a struct body: methods enumerate.
        assert_eq!(
            methods_of("Make"),
            vec!["make_a".to_string(), "make_b".to_string()],
            "functor `module Make (X) = struct .. end` must enumerate its let \
             methods; got {:?}",
            methods_of("Make")
        );

        // Outer module: its OWN let-binding enumerates; the nested module is a
        // separate class entry, NOT folded into Outer's methods.
        assert_eq!(
            methods_of("Outer"),
            vec!["outer_a".to_string()],
            "outer module must enumerate only its own let methods (nested module \
             is a separate class); got {:?}",
            methods_of("Outer")
        );

        // Nested module now surfaces as its own class with its methods.
        assert_eq!(
            methods_of("Inner"),
            vec!["inner_a".to_string()],
            "nested OCaml module must surface as its own class with enumerated \
             methods; classes={:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );

        // No-body variants: functor application + alias must yield ZERO methods
        // (the body is a `module_application` / `module_path`, not a `structure`).
        assert!(
            methods_of("AliasMod").is_empty(),
            "module alias `module M = N` must yield no methods; got {:?}",
            methods_of("AliasMod")
        );
        assert!(
            methods_of("AppliedMod").is_empty(),
            "functor application `module M = Make (X)` must yield no methods; \
             got {:?}",
            methods_of("AppliedMod")
        );
    }

    // -------------------------------------------------------------------------
    // rc2-lua-interface-return-table-convention: exports = terminal return table
    // -------------------------------------------------------------------------

    /// querystring.lua shape: SHAPE 1 literal `return { a = a, ... }` whose
    /// values alias top-level `local function`s. Two non-exported helpers
    /// (`charToHex`, `hexToChar`) must NOT leak in (the over-report).
    const QUERYSTRING_LUA: &str = r#"
local function hexToChar(hex)
  return string.char(tonumber(hex, 16))
end

local function charToHex(c)
  return string.format("%%%02X", string.byte(c))
end

local function urldecode(str)
  return str
end

local function urlencode(str)
  return str
end

local function stringify(tbl, sep, eq)
  return ""
end

local function parse(str, sep, eq)
  return {}
end

return {
  urldecode = urldecode,
  urlencode = urlencode,
  stringify = stringify,
  parse = parse,
}
"#;

    /// pathjoin.lua shape: SHAPE 1 literal whose values reference a non-function
    /// `local` (`isWindows`) and functions defined ONLY inside `if/else`
    /// branches (`getPrefix`/`splitPath`/`joinParts`) — the under-report.
    const PATHJOIN_LUA: &str = r#"
local getPrefix, splitPath, joinParts

local isWindows = false

if isWindows then
  function getPrefix(path)
    return path
  end
  function splitPath(path)
    return {}
  end
  function joinParts(prefix, parts, i, j)
    return ""
  end
else
  function getPrefix(path)
    return path
  end
  function splitPath(path)
    return {}
  end
  function joinParts(prefix, parts, i, j)
    return ""
  end
end

local function pathJoin(...)
  return ""
end

return {
  isWindows = isWindows,
  getPrefix = getPrefix,
  splitPath = splitPath,
  joinParts = joinParts,
  pathJoin = pathJoin,
}
"#;

    fn sorted_exports(info: &InterfaceInfo) -> Vec<String> {
        let mut v = info.all_exports.clone();
        v.sort();
        v
    }

    /// TEST 1 — OVER-REPORT fixed (SHAPE 1 literal + alias).
    #[test]
    fn test_interface_lua_overreport_return_table_only() {
        let info = extract_interface(Path::new("querystring.lua"), QUERYSTRING_LUA).unwrap();
        assert_eq!(
            sorted_exports(&info),
            vec!["parse", "stringify", "urldecode", "urlencode"],
            "all_exports must be exactly the return-table keys"
        );
        // Non-exported helpers must be absent from BOTH all_exports and functions[].
        for leaked in ["charToHex", "hexToChar"] {
            assert!(
                !info.all_exports.iter().any(|n| n == leaked),
                "{} must not leak into all_exports",
                leaked
            );
            assert!(
                !info.functions.iter().any(|f| f.name == leaked),
                "{} must not leak into functions[]",
                leaked
            );
        }
    }

    /// TEST 2 — UNDER-REPORT fixed (branch-nested + non-function exports).
    #[test]
    fn test_interface_lua_underreport_branch_nested_and_value() {
        let info = extract_interface(Path::new("pathjoin.lua"), PATHJOIN_LUA).unwrap();
        assert_eq!(
            sorted_exports(&info),
            vec!["getPrefix", "isWindows", "joinParts", "pathJoin", "splitPath"],
            "all_exports must be the full return-table key set"
        );
        // isWindows is a non-function local → must appear in all_exports AND values[].
        assert!(info.all_exports.iter().any(|n| n == "isWindows"));
        assert!(
            info.values.iter().any(|v| v.name == "isWindows"),
            "isWindows must get a values[] detail entry, got {:?}",
            info.values
        );
        // getPrefix is defined in BOTH if/else branches → set-deduped to ONE.
        assert_eq!(
            info.all_exports.iter().filter(|n| *n == "getPrefix").count(),
            1,
            "branch-duplicated getPrefix must collapse to one export"
        );
        // Branch-nested exported functions are surfaced as functions[].
        assert!(
            info.functions.iter().any(|f| f.name == "getPrefix"),
            "branch-nested getPrefix must surface in functions[]"
        );
    }

    /// TEST 3 — SHAPE 2 accumulator `local M = {}; function M.x() … ; M.y = z; return M`,
    /// including a member function defined inside a `do … end` block.
    #[test]
    fn test_interface_lua_accumulator_return_m() {
        let source = r#"
local M = {}

function M.foo(a)
  return a
end

do
  function M.nested(b)
    return b
  end
end

local function helper()
  return 1
end

M.bar = helper
M.version = "1.0"

local function privateNotExported()
  return 0
end

return M
"#;
        let info = extract_interface(Path::new("accum.lua"), source).unwrap();
        assert_eq!(
            sorted_exports(&info),
            vec!["bar", "foo", "nested", "version"],
            "accumulator exports = M's field set"
        );
        assert!(
            !info.all_exports.iter().any(|n| n == "privateNotExported"),
            "non-member local must not be exported"
        );
        assert!(
            info.values.iter().any(|v| v.name == "version"),
            "string field M.version must be a values[] entry"
        );
    }

    /// TEST 4 — SHAPE 4 unwrap + fallback boundary.
    #[test]
    fn test_interface_lua_setmetatable_unwrap_and_fallback() {
        // setmetatable(M, mt) unwraps to M.
        let wrapped = r#"
local M = {}
function M.go() end
return setmetatable(M, { __index = {} })
"#;
        let info = extract_interface(Path::new("wrapped.lua"), wrapped).unwrap();
        assert_eq!(sorted_exports(&info), vec!["go"]);

        // Dynamic tail `return require('x')` → analyzer returns None, falls back
        // to the heuristic (no panic, sensible non-empty output).
        let dynamic = r#"
local function exported()
  return 1
end
return require("other")
"#;
        let info = extract_interface(Path::new("dyn.lua"), dynamic).unwrap();
        assert!(
            info.all_exports.iter().any(|n| n == "exported"),
            "dynamic tail must fall back to the function-union heuristic"
        );
    }

    /// TEST 5 — cross-grammar parity: the same fixtures as `.luau` yield identical
    /// export sets (the export-table grammar path is byte-identical).
    #[test]
    fn test_interface_luau_parity() {
        let lua = extract_interface(Path::new("querystring.lua"), QUERYSTRING_LUA).unwrap();
        let luau = extract_interface(Path::new("querystring.luau"), QUERYSTRING_LUA).unwrap();
        assert_eq!(sorted_exports(&lua), sorted_exports(&luau));

        let lua_pj = extract_interface(Path::new("pathjoin.lua"), PATHJOIN_LUA).unwrap();
        let luau_pj = extract_interface(Path::new("pathjoin.luau"), PATHJOIN_LUA).unwrap();
        assert_eq!(sorted_exports(&lua_pj), sorted_exports(&luau_pj));
    }

    /// TEST 6 (fix-PW1-A3b) — GENERALIZATION GATE. One fixture exercises BOTH
    /// uncovered module idioms at once: (a) the literal-bound accumulator
    /// (`local Lib = { compute = function… , PI = 3.14 }` — fields the table is
    /// CONSTRUCTED with, which the post-declaration accumulator walk never saw)
    /// and (b) the colon-method (`function Lib:greet()` — a
    /// `method_index_expression` name the dot-only walk dropped). It also keeps
    /// the already-working dot-method (`function Lib.staticHelper()`) as a
    /// regression guard. The fixture is run through BOTH the `.lua` and `.luau`
    /// extension paths, so all four cells of the symptom matrix
    /// (lua×luau × accumulator-literal×colon-method) are asserted together. A
    /// fix that closes only one idiom or only one language fails the exact
    /// export-set equality below.
    #[test]
    fn test_interface_lua_luau_literal_accumulator_and_colon_methods() {
        const SRC: &str = r#"
local Lib = {
  compute = function(x)
    return x
  end,
  PI = 3.14,
}

function Lib:greet(name)
  return "hi " .. name
end

function Lib.staticHelper(y)
  return y
end

local function privateHelper()
  return 0
end

return Lib
"#;

        for (path, label) in [("mod.lua", "lua"), ("mod.luau", "luau")] {
            let info = extract_interface(Path::new(path), SRC).unwrap();

            // (1) Export set is EXACTLY M's full field surface across both idioms.
            assert_eq!(
                sorted_exports(&info),
                vec!["PI", "compute", "greet", "staticHelper"],
                "[{label}] all_exports must union the literal-bound fields \
                 (compute, PI), the colon-method (greet) and the dot-method \
                 (staticHelper)"
            );

            // (2) The colon-method AND the literal-bound inline function AND the
            //     dot-method must all land in functions[] (each `is_function`).
            for fname in ["greet", "compute", "staticHelper"] {
                assert!(
                    info.functions.iter().any(|f| f.name == fname),
                    "[{label}] function export `{fname}` must appear in functions[]"
                );
            }

            // (3) The non-function literal field is routed to values[].
            assert!(
                info.values.iter().any(|v| v.name == "PI"),
                "[{label}] number field PI must be a values[] entry, not a function"
            );

            // (4) A non-member local must never leak as an export.
            assert!(
                !info.all_exports.iter().any(|n| n == "privateHelper"),
                "[{label}] non-member local `privateHelper` must not be exported"
            );
        }
    }
}

// =============================================================================
// CF1-S4 (v0.5.0 RC): `tldr interface` signature + classification — the
// generalization gate. ONE test asserting correctness across the full symptom
// class: kotlin, solidity, ocaml, rust, ruby. Faithful inline fixtures (no
// corpus dependency). Each sub-assertion FAILS on the pre-fix source and PASSES
// after the fix, so the anti-treadmill property holds for every listed language.
// =============================================================================
#[cfg(test)]
mod cf1_s4_interface_v1 {
    use super::{extract_function_signature, extract_interface_with_lang};
    use std::path::Path;
    use tldr_core::ast::ParserPool;
    use tldr_core::types::Language;

    fn iface(name: &str, src: &str, lang: Language) -> super::InterfaceInfo {
        extract_interface_with_lang(Path::new(name), src, lang)
            .unwrap_or_else(|e| panic!("[{name}] extract failed: {e}"))
    }

    // --- KOTLIN ---------------------------------------------------------------
    // Bug: every Kotlin function/method rendered `signature: ""`.
    #[test]
    fn kotlin_function_signatures_are_non_empty() {
        let src = "\
fun add(a: Int, b: Int): Int { return a + b }

class Calc {
    fun mul(x: Int, y: Int): Int { return x * y }
}
";
        let info = iface("calc.kt", src, Language::Kotlin);
        let add = info
            .functions
            .iter()
            .find(|f| f.name == "add")
            .expect("kotlin: `add` must surface");
        assert!(
            add.signature.contains("a: Int") && add.signature.contains("Int"),
            "kotlin: `add` signature must carry params + return, got {:?}",
            add.signature
        );
        let calc = info
            .classes
            .iter()
            .find(|c| c.name == "Calc")
            .expect("kotlin: class `Calc` must surface");
        let mul = calc
            .methods
            .iter()
            .find(|m| m.name == "mul")
            .expect("kotlin: method `mul` must surface");
        assert!(
            mul.signature.contains("x: Int"),
            "kotlin: method `mul` signature must be non-empty, got {:?}",
            mul.signature
        );
    }

    // --- SOLIDITY -------------------------------------------------------------
    // Bug: every Solidity function/method rendered `signature: ""`.
    #[test]
    fn solidity_function_signatures_are_non_empty() {
        let src = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IThing {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Thing {
    function doIt(uint256 x) public returns (uint256) { return x; }
}
";
        let info = iface("thing.sol", src, Language::Solidity);
        let ithing = info
            .classes
            .iter()
            .find(|c| c.name == "IThing")
            .expect("solidity: interface `IThing` must surface");
        let transfer = ithing
            .methods
            .iter()
            .find(|m| m.name == "transfer")
            .expect("solidity: method `transfer` must surface");
        assert!(
            transfer.signature.contains("address to")
                && transfer.signature.contains("returns (bool)"),
            "solidity: `transfer` signature must carry params + returns, got {:?}",
            transfer.signature
        );
        let thing = info
            .classes
            .iter()
            .find(|c| c.name == "Thing")
            .expect("solidity: contract `Thing` must surface");
        let do_it = thing
            .methods
            .iter()
            .find(|m| m.name == "doIt")
            .expect("solidity: method `doIt` must surface");
        assert!(
            do_it.signature.contains("uint256 x"),
            "solidity: `doIt` signature must be non-empty, got {:?}",
            do_it.signature
        );
    }

    // --- OCAML ----------------------------------------------------------------
    // Bug: `classes` listed only modules + type aliases, ZERO real classes.
    #[test]
    fn ocaml_real_classes_surface_and_modules_types_keep_their_kind() {
        let src = "\
module M = struct
  let f x = x + 1
end

type t = { a : int }

class counter = object
  val mutable n = 0
  method incr = n <- n + 1
  method get = n
end

class type observer = object
  method notify : int -> unit
end
";
        let info = iface("thing.ml", src, Language::Ocaml);
        let kind_of = |name: &str| -> Option<String> {
            info.classes
                .iter()
                .find(|c| c.name == name)
                .and_then(|c| c.kind.clone())
        };

        // A real `class … = object … end` now surfaces, labeled "class".
        assert_eq!(
            kind_of("counter").as_deref(),
            Some("class"),
            "ocaml: `class counter` must surface with kind=class; classes={:?}",
            info.classes
                .iter()
                .map(|c| (c.name.clone(), c.kind.clone()))
                .collect::<Vec<_>>()
        );
        // A `class type … = object … end` surfaces as the interface analogue.
        assert_eq!(
            kind_of("observer").as_deref(),
            Some("interface"),
            "ocaml: `class type observer` must surface with kind=interface"
        );
        // Modules and types keep their own kind — NOT miscounted as classes.
        assert_eq!(
            kind_of("M").as_deref(),
            Some("module"),
            "ocaml: module `M` must keep kind=module"
        );
        assert_eq!(
            kind_of("t").as_deref(),
            Some("type"),
            "ocaml: type `t` must keep kind=type"
        );
        // The real class exposes its methods (find_body_node + method kinds).
        let counter = info.classes.iter().find(|c| c.name == "counter").unwrap();
        assert!(
            counter.methods.iter().any(|m| m.name == "incr")
                && counter.methods.iter().any(|m| m.name == "get"),
            "ocaml: class `counter` must surface its methods, got {:?}",
            counter.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
    }

    // --- RUST -----------------------------------------------------------------
    // Bug: impl blocks rendered the impl'd type WITH generic args
    // (`StandardImpl<'a, M, W>`), inconsistent with the bare `struct` name.
    #[test]
    fn rust_class_names_are_normalized_without_generics() {
        let src = "\
pub struct Standard<W> { inner: W }

impl<W: Clone> Standard<W> {
    pub fn run(&self) {}
}

// Standalone impl whose base type has no struct decl in this file: it survives
// as its own entry, so its name exercises the generic-normalization directly.
impl<'a, M, W> StandardImpl<'a, M, W> {
    pub fn go(&self) {}
}
";
        let info = iface("standard.rs", src, Language::Rust);
        // No class entry may carry generic-argument syntax in its name.
        assert!(
            info.classes.iter().all(|c| !c.name.contains('<')),
            "rust: class names must be normalized (no `<…>`), got {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        // Both the merged struct and the standalone impl render their base name.
        assert!(
            info.classes.iter().any(|c| c.name == "Standard"),
            "rust: `Standard` must surface (bare)"
        );
        assert!(
            info.classes.iter().any(|c| c.name == "StandardImpl"),
            "rust: standalone impl must render as bare `StandardImpl`, got {:?}",
            info.classes.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    // --- RUBY -----------------------------------------------------------------
    // Bug: a bareword `private` section was ignored; `private_method_count`
    // stayed 0 and private methods leaked into the public method list.
    #[test]
    fn ruby_bare_private_section_marks_following_methods_private() {
        let src = "\
class Account
  def deposit(x)
  end

  def balance
  end

  private

  def secret
  end

  def hidden
  end
end
";
        let info = iface("account.rb", src, Language::Ruby);
        let account = info
            .classes
            .iter()
            .find(|c| c.name == "Account")
            .expect("ruby: class `Account` must surface");
        // Public methods before `private` stay public.
        assert!(
            account.methods.iter().any(|m| m.name == "deposit")
                && account.methods.iter().any(|m| m.name == "balance"),
            "ruby: public methods must stay public, got {:?}",
            account.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        // Methods after a bare `private` are NOT in the public method list.
        assert!(
            !account.methods.iter().any(|m| m.name == "secret")
                && !account.methods.iter().any(|m| m.name == "hidden"),
            "ruby: methods after bare `private` must not be public, got {:?}",
            account.methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        // …and they are counted as private.
        assert!(
            account.private_method_count >= 2,
            "ruby: private_method_count must be >= 2 after a bare `private`, got {}",
            account.private_method_count
        );
    }

    // --- AST-shape sanity (guards the structural assumptions above) -----------
    // A bare Ruby `private` parses as a bare `identifier`, and the OCaml class
    // carriers parse as the node kinds the fix keys on. This pins the grammar
    // contract so a tree-sitter bump that changes it fails loudly here.
    #[test]
    fn ast_shape_assumptions_hold() {
        let pool = ParserPool::new();

        // Ruby: the bare `private` directive is an `identifier`.
        let rb = "class C\n  private\n  def x\n  end\nend\n";
        let tree = pool.parse(rb, Language::Ruby).unwrap();
        let mut found_private_identifier = false;
        walk(&tree.root_node(), &mut |n| {
            if n.kind() == "identifier"
                && &rb.as_bytes()[n.start_byte()..n.end_byte()] == b"private"
            {
                found_private_identifier = true;
            }
        });
        assert!(
            found_private_identifier,
            "ruby: bare `private` is expected to parse as an `identifier` node"
        );

        // OCaml: class / class-type carriers and the method member node.
        let ml = "class c = object method m = 1 end\nclass type ct = object method n : int end\n";
        let tree = pool.parse(ml, Language::Ocaml).unwrap();
        let (mut has_class, mut has_class_type, mut has_method_def) = (false, false, false);
        walk(&tree.root_node(), &mut |n| match n.kind() {
            "class_definition" => has_class = true,
            "class_type_definition" => has_class_type = true,
            "method_definition" => has_method_def = true,
            _ => {}
        });
        assert!(
            has_class && has_class_type && has_method_def,
            "ocaml: expected class_definition / class_type_definition / method_definition nodes"
        );
    }

    fn walk(node: &tree_sitter::Node, f: &mut impl FnMut(&tree_sitter::Node)) {
        f(node);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(&child, f);
        }
    }

    // --- direct signature-extractor probe (kotlin + solidity) -----------------
    // Pins the extractor functions directly so a regression in either arm is
    // attributable without the full interface pipeline.
    #[test]
    fn extract_function_signature_kotlin_solidity_direct() {
        let pool = ParserPool::new();

        let kt = "fun f(a: Int): String { return \"\" }\n";
        let tree = pool.parse(kt, Language::Kotlin).unwrap();
        let mut sig = String::new();
        walk(&tree.root_node(), &mut |n| {
            if n.kind() == "function_declaration" {
                sig = extract_function_signature(*n, kt.as_bytes(), Language::Kotlin);
            }
        });
        assert!(
            sig.contains("a: Int") && sig.contains("String"),
            "kotlin direct: signature must carry params+return, got {sig:?}"
        );

        let sol = "contract C { function g(uint256 n) public pure returns (uint256) { return n; } }\n";
        let tree = pool.parse(sol, Language::Solidity).unwrap();
        let mut sig = String::new();
        walk(&tree.root_node(), &mut |n| {
            if n.kind() == "function_definition" {
                sig = extract_function_signature(*n, sol.as_bytes(), Language::Solidity);
            }
        });
        assert!(
            sig.contains("uint256 n") && sig.contains("returns (uint256)"),
            "solidity direct: signature must carry params+returns, got {sig:?}"
        );
    }
}
