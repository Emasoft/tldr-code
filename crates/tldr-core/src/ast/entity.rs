//! Canonical entity span + signature resolver (RC2-META Stage 1).
//!
//! The three signature producers — `structure` (`extractor::collect_definitions`
//! → `method_infos`), `interface` (`patterns::interface::extract_function_signature`),
//! and `extract` (`extract.rs` detailed arms) — historically each sliced the
//! WHOLE declaration node and mangled signatures differently:
//!
//! ```text
//! structure : "m(): void {} }"   (first source line of the whole node — body leaks in)
//! interface : "(): : void"       (params field + return-type field whose text already
//!                                 carries its own leading `: `, producing a double colon)
//! ```
//!
//! The root fix (validated against rust-analyzer `ptr` vs `name_ptr`, and LSP
//! `range` vs `selectionRange`) is to render a signature from the declaration
//! HEADER span — the name + parameter list + return type — and to STOP at the
//! body block. [`signature_from_header`] is that shared, AST-driven resolver.
//!
//! This module is intentionally minimal for Stage 1. It GROWS in Stage 2 (a
//! shared `classify_node` discriminator); do NOT pre-build the kind enum here.

use crate::types::Language;
use serde::{Deserialize, Serialize};
use tree_sitter::Node;

/// A byte/row span pinned from a tree-sitter node.
///
/// Mirrors the LSP `range` (whole node) vs `selectionRange` (name) split: the
/// `signature` producers want the HEADER span, not the whole-node span, so the
/// body block never leaks into the rendered signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start byte offset into the source.
    pub start_byte: usize,
    /// Exclusive end byte offset into the source.
    pub end_byte: usize,
    /// 0-indexed start row.
    pub start_row: usize,
    /// 0-indexed end row.
    pub end_row: usize,
}

impl Span {
    /// Pin a [`Span`] from a tree-sitter node (the whole-node `range`).
    pub fn from_node(node: Node) -> Self {
        Span {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_row: node.start_position().row,
            end_row: node.end_position().row,
        }
    }
}

/// The byte offset where the declaration BODY block begins, if any.
///
/// Used to bound the header span so an inline body (`{ ... }` on the same line
/// as the signature, e.g. `m(): void {}`) is excluded. AST-driven: prefers the
/// grammar's explicit `body` field, then falls back to the well-known block
/// node kinds across the supported grammars. NO source-text/regex heuristics.
fn body_start_byte(node: Node) -> Option<usize> {
    // The explicit `body` field covers the large majority of function/method
    // declaration nodes across TS/JS, Rust, Go, Java, C#, Kotlin, Scala,
    // Python, C/C++, PHP, Swift.
    if let Some(b) = node.child_by_field_name("body") {
        return Some(b.start_byte());
    }
    // Fallback: scan for the first child that is a recognised body block.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "statement_block"      // TS/JS
            | "block"              // Rust / Python / Lua / Kotlin
            | "function_body"      // Swift
            | "compound_statement" // C / C++
            | "do_block"           // Elixir
            | "field_declaration_list" => {
                return Some(child.start_byte());
            }
            _ => {}
        }
    }
    None
}

/// Byte offset of the first child that is NOT a leading comment / attribute /
/// decorator — i.e. the start of the real declaration header.
///
/// Mirrors the skip-list used by `extractor::extract_def_signature` so the two
/// resolvers agree on where the header begins (doc comments, Rust `#[...]`,
/// Python `@decorator`, etc. are skipped).
fn header_start_byte(node: Node) -> usize {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "line_comment" | "block_comment" | "comment" | "attribute_item"
            | "attribute" | "decorator" | "decorator_list" => continue,
            _ => return child.start_byte(),
        }
    }
    node.start_byte()
}

/// Render a single-line signature from the declaration HEADER span.
///
/// The header span is `[first-meaningful-child .. body-block-start)`, clipped to
/// the first source line so a multi-line header collapses to its declaration
/// line exactly as the legacy first-line extractor did (zero churn for the
/// common multi-line case). The ONLY behavioural change versus the legacy
/// whole-node first-line slice is that an inline body block (`{ ... }` on the
/// signature line) is excluded — which is precisely the mangling this fixes:
///
/// ```text
/// "m(): void {} }"  ->  "m(): void"
/// ```
///
/// AST-driven: spans are pinned via tree-sitter node fields/children, never via
/// regex or string trimming of arbitrary source.
pub fn signature_from_header(node: Node, source: &str) -> String {
    let header_start = header_start_byte(node);

    // Clip to the first source line of the header (legacy parity for multi-line
    // declarations whose body opens on a later line).
    let rest = source.get(header_start..).unwrap_or("");
    let first_line_end = header_start + rest.find('\n').unwrap_or(rest.len());

    // Stop at the body block if it opens within the first line.
    let end = match body_start_byte(node) {
        Some(b) if b > header_start => first_line_end.min(b),
        _ => first_line_end,
    };

    let sig = source.get(header_start..end).unwrap_or("").trim().to_string();
    if !sig.is_empty() {
        return sig;
    }

    // Fallback: whole-node first line (matches the legacy last-resort behaviour).
    source
        .get(node.start_byte()..)
        .and_then(|s| s.lines().next())
        .unwrap_or("")
        .trim()
        .to_string()
}

// =============================================================================
// RC2-META Stage 2 — the canonical entity discriminator.
// =============================================================================
//
// Historically the "is this a class / function?" decision was duplicated across
// ≥10 divergent per-language tables (`function_finder::get_function_node_kinds` /
// `get_class_node_kinds`, `patterns::interface::{function,class,method}_node_kinds`,
// `extractor::classify_definition_node`, `remaining::explain::get_function_node_kinds`,
// `remaining::diff::get_class_node_kinds`, `security::ast_utils::function_node_kinds`).
// Each drifted independently, so the same source construct could be a `class`
// in one command and dropped in another.
//
// [`EntityKind`] + [`classify_node_kind`] / [`classify_node`] are the single
// canonical answer those tables are LOCKED to (see the `*_matches_classify_node`
// guard tests in this crate and in `tldr-cli`). classify_node is intentionally
// the RICHER union of every table (e.g. it classifies TS `type_alias_declaration`
// even though `function_finder` / `classify_definition_node` still omit it). The
// existing tables keep their EXACT current membership in Stage 2 to preserve
// byte-identical command output; the guard tests prove no table can ever return
// an answer that DISAGREES with classify_node (re-drift fails CI). Physically
// folding each table's membership up to the full union is the per-language
// Stage 3 migration, gated by its own corpus diff.

/// Closed superset of LSP `SymbolKind`, covering all 16 tldr languages.
///
/// LSP's 26-variant `SymbolKind` lacks `Trait`, `TypeAlias`, `Macro`, the OCaml
/// `Value` distinction, and the Solidity-native kinds, so this is a SUPERSET; a
/// total `to_lsp_symbol_kind()` projection at the LSP boundary is a later
/// concern (kept native in tldr JSON). Serializes as the exact stable lowercase
/// strings already emitted by `collect_definitions` / `ts_entry_kind`
/// (`"interface"` / `"type"` / `"enum"` / `"class"` / `"method"` / `"function"`
/// / `"struct"` / `"trait"` / `"module"` / `"object"` / `"contract"` /
/// `"library"`) so a future migration cannot introduce a value-level JSON diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityKind {
    // LSP-direct (1:1):
    Module,
    Class,
    Struct,
    Interface,
    Enum,
    EnumMember,
    Function,
    Method,
    Constructor,
    Field,
    Property,
    Constant,
    Object,
    // tldr-native (no LSP variant — keep native, project lossily at the boundary):
    /// Rust/Scala/PHP trait. -> LSP Interface.
    Trait,
    /// TS/Scala/Rust/OCaml type alias. -> LSP Class. Serialized as `"type"`.
    #[serde(rename = "type")]
    TypeAlias,
    /// Rust/Elixir macro. -> LSP Function.
    Macro,
    /// OCaml `let x = 1` value binding. -> LSP Variable/Constant.
    Value,
    // Solidity-native:
    /// Solidity `contract`. -> LSP Class.
    Contract,
    /// Solidity `library`. -> LSP Class.
    Library,
    /// Solidity `modifier`. -> LSP Method.
    Modifier,
    /// Solidity `event`. -> LSP Event.
    Event,
    /// Solidity custom `error`. -> LSP Struct.
    Error,
}

impl EntityKind {
    /// The canonical stable lowercase string for this kind — byte-identical to
    /// the `serde` `rename_all = "lowercase"` (+ `TypeAlias` → `"type"`)
    /// serialization. Used by the `extract` / `interface` `ClassInfo.kind`
    /// producers so the populated JSON string matches the serialized enum
    /// exactly (single source of truth; no per-language kind table).
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Module => "module",
            EntityKind::Class => "class",
            EntityKind::Struct => "struct",
            EntityKind::Interface => "interface",
            EntityKind::Enum => "enum",
            EntityKind::EnumMember => "enummember",
            EntityKind::Function => "function",
            EntityKind::Method => "method",
            EntityKind::Constructor => "constructor",
            EntityKind::Field => "field",
            EntityKind::Property => "property",
            EntityKind::Constant => "constant",
            EntityKind::Object => "object",
            EntityKind::Trait => "trait",
            EntityKind::TypeAlias => "type",
            EntityKind::Macro => "macro",
            EntityKind::Value => "value",
            EntityKind::Contract => "contract",
            EntityKind::Library => "library",
            EntityKind::Modifier => "modifier",
            EntityKind::Event => "event",
            EntityKind::Error => "error",
        }
    }

    /// True for kinds that live on the FUNCTION axis (`is_func` in the legacy
    /// `classify_definition_node` (bool, bool) contract). Modifier/Event/Error
    /// are function-axis to match the Solidity rows of `classify_definition_node`.
    pub fn is_function_axis(self) -> bool {
        matches!(
            self,
            EntityKind::Function
                | EntityKind::Method
                | EntityKind::Constructor
                | EntityKind::Macro
                | EntityKind::Modifier
                | EntityKind::Event
                | EntityKind::Error
        )
    }

    /// True for kinds that live on the CLASS / type-container axis (`is_class`
    /// in the legacy `classify_definition_node` (bool, bool) contract).
    pub fn is_class_axis(self) -> bool {
        matches!(
            self,
            EntityKind::Class
                | EntityKind::Struct
                | EntityKind::Interface
                | EntityKind::Enum
                | EntityKind::Trait
                | EntityKind::Object
                | EntityKind::Module
                | EntityKind::TypeAlias
                | EntityKind::Contract
                | EntityKind::Library
        )
    }
}

/// Canonical string-keyed classifier: map a tree-sitter node KIND + language to
/// its [`EntityKind`]. This is the UNION of every per-language table in the
/// codebase, language-gated so a node-kind string reused across grammars with
/// different semantics (`type_definition` in OCaml vs Scala, `struct_declaration`
/// in C# vs Solidity, `enum_declaration` across Java/C#/PHP/Kotlin vs Solidity)
/// resolves correctly.
///
/// Returns `None` for kinds that are not entity declarations, and for the Elixir
/// `call` node whose discriminator is only decidable from the callee keyword —
/// use [`classify_node`] for that (it reads the `def`/`defp`/`defmacro` head).
pub fn classify_node_kind(kind: &str, language: Language) -> Option<EntityKind> {
    use EntityKind::*;
    let ek = match language {
        Language::Python => match kind {
            "function_definition" | "async_function_definition" => Function,
            "class_definition" => Class,
            _ => return None,
        },
        Language::TypeScript | Language::JavaScript => match kind {
            "function_declaration" | "function_expression" | "arrow_function"
            | "generator_function" | "generator_function_declaration" | "function" => Function,
            "method_definition" | "method_signature" | "abstract_method_signature"
            | "public_field_definition" => Method,
            "class_declaration" | "class" | "abstract_class_declaration" => Class,
            "interface_declaration" => Interface,
            "type_alias_declaration" => TypeAlias,
            "enum_declaration" => Enum,
            _ => return None,
        },
        Language::Go => match kind {
            "function_declaration" | "func_literal" | "function_type" => Function,
            "method_declaration" => Method,
            "type_declaration" => Class,
            "type_spec" => Struct,
            _ => return None,
        },
        Language::Rust => match kind {
            "function_item" => Function,
            "struct_item" => Struct,
            "enum_item" => Enum,
            "trait_item" => Trait,
            "impl_item" => Class,
            "union_item" => Struct,
            _ => return None,
        },
        Language::Java => match kind {
            "method_declaration" => Method,
            "constructor_declaration" => Constructor,
            "class_declaration" => Class,
            "interface_declaration" => Interface,
            "enum_declaration" => Enum,
            "record_declaration" => Class,
            _ => return None,
        },
        Language::C | Language::Cpp => match kind {
            "function_definition" | "declaration" => Function,
            "field_declaration" => Method,
            "class_specifier" => Class,
            "struct_specifier" | "union_specifier" => Struct,
            "enum_specifier" => Enum,
            _ => return None,
        },
        Language::Ruby => match kind {
            "method" | "singleton_method" => Method,
            "class" => Class,
            "module" => Module,
            _ => return None,
        },
        Language::Php => match kind {
            "function_definition" => Function,
            "method_declaration" => Method,
            "class_declaration" => Class,
            "interface_declaration" => Interface,
            "trait_declaration" => Trait,
            "enum_declaration" => Enum,
            _ => return None,
        },
        Language::CSharp => match kind {
            "method_declaration" => Method,
            "constructor_declaration" => Constructor,
            "class_declaration" => Class,
            "interface_declaration" => Interface,
            "struct_declaration" => Struct,
            "record_declaration" => Class,
            "enum_declaration" => Enum,
            _ => return None,
        },
        Language::Kotlin => match kind {
            "function_declaration" => Function,
            "class_declaration" => Class,
            "object_declaration" | "companion_object" => Object,
            _ => return None,
        },
        Language::Scala => match kind {
            "function_definition" | "function_declaration" | "def_definition"
            | "val_definition" => Function,
            "class_definition" => Class,
            "object_definition" => Object,
            "trait_definition" => Trait,
            "type_definition" => TypeAlias,
            "enum_definition" => Enum,
            _ => return None,
        },
        // Elixir def/defp/defmacro/defmacrop/defmodule are `call` nodes —
        // only decidable from the callee keyword (see `classify_node`).
        Language::Elixir => return None,
        Language::Lua | Language::Luau => match kind {
            "function_declaration" | "function_definition" | "local_function"
            | "function_definition_statement" => Function,
            _ => return None,
        },
        Language::Swift => match kind {
            "function_declaration" => Function,
            "init_declaration" => Constructor,
            "class_declaration" | "extension_declaration" => Class,
            // tree-sitter-swift also emits a dedicated `struct_declaration`
            // (diff's Swift container table lists it alongside class/protocol).
            "struct_declaration" => Struct,
            "protocol_declaration" => Interface,
            // `function_type` is a Swift closure TYPE annotation, never a def.
            _ => return None,
        },
        Language::Ocaml => match kind {
            // String level: a value binding is function-shaped by default;
            // `classify_node` refines a non-function binding to `Value`.
            "let_binding" | "value_definition" => Function,
            "module_definition" => Module,
            "type_definition" => TypeAlias,
            _ => return None,
        },
        Language::Solidity => match kind {
            "function_definition"
            | "fallback_function_definition"
            | "receive_function_definition"
            | "fallback_receive_definition" => Function,
            "constructor_definition" => Constructor,
            "modifier_definition" => Modifier,
            "event_definition" => Event,
            "error_declaration" => Error,
            "contract_declaration" => Contract,
            "library_declaration" => Library,
            "interface_declaration" => Interface,
            "struct_declaration" => Struct,
            "enum_declaration" => Enum,
            _ => return None,
        },
    };
    Some(ek)
}

/// The canonical, node-aware discriminator. Delegates to [`classify_node_kind`]
/// for the string-decidable majority, then applies the two STRUCTURAL rules that
/// a bare node-kind string cannot express:
///
/// * OCaml — a `value_definition` / `let_binding` is a [`EntityKind::Function`]
///   only when it is function-shaped (`≥1 parameter` child OR a `fun_expression`
///   / `function_expression` body); otherwise it is a plain [`EntityKind::Value`].
///   This reuses the verified `ocaml_value_definition_is_function` predicate.
/// * Elixir — `def`/`defp` → [`EntityKind::Function`], `defmacro`/`defmacrop` →
///   [`EntityKind::Macro`], `defmodule` → [`EntityKind::Module`] (the
///   `try_elixir_call_definition` call-based rule), read from the callee keyword.
pub fn classify_node(node: Node, language: Language, source: &str) -> Option<EntityKind> {
    let kind = node.kind();

    if language == Language::Elixir && kind == "call" {
        return classify_elixir_call(node, source);
    }

    // RC2-META Stage 3 (go): a Go type is classified by the UNDERLYING type of
    // its `type_spec` (or by the dedicated `type_alias` node), not by the bare
    // node-kind string. `classify_node_kind` cannot express this (it only sees a
    // string), so it conservatively maps `type_spec` to the class axis; the
    // node-aware path below refines it:
    //   `type X struct {...}`     (type_spec → struct_type)    -> Struct
    //   `type X interface {...}`  (type_spec → interface_type) -> Interface
    //   `type X = Y`              (type_alias)                 -> TypeAlias
    //   `type X <other>`          (defined type, e.g. `float64`) -> Class
    // The `type_declaration` wrapper drills into its inner spec/alias child.
    // All four results stay on the CLASS axis, so the Stage-2 string-keyed
    // consumers (`function_finder`, the agreement test) remain byte-identical.
    if language == Language::Go {
        match kind {
            "type_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(ek) = go_type_node_kind(child) {
                        return Some(ek);
                    }
                }
            }
            "type_spec" | "type_alias" => {
                if let Some(ek) = go_type_node_kind(node) {
                    return Some(ek);
                }
            }
            _ => {}
        }
    }

    let base = classify_node_kind(kind, language)?;

    if matches!(language, Language::Ocaml)
        && matches!(kind, "value_definition" | "let_binding")
        && !ocaml_node_is_function(node)
    {
        return Some(EntityKind::Value);
    }

    Some(base)
}

/// Structural OCaml function-shape test, mirroring
/// `extractor::ocaml_value_definition_is_function`: a binding is a function if
/// any `let_binding` it owns (or itself, when a `let_binding` is passed) has a
/// `parameter` child or a `fun_expression` / `function_expression` body.
fn ocaml_node_is_function(node: Node) -> bool {
    fn binding_is_function(binding: Node) -> bool {
        let mut cursor = binding.walk();
        for child in binding.children(&mut cursor) {
            match child.kind() {
                "parameter" | "fun_expression" | "function_expression" => return true,
                _ => {}
            }
        }
        false
    }

    if node.kind() == "let_binding" {
        return binding_is_function(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "let_binding" && binding_is_function(child) {
            return true;
        }
    }
    false
}

/// Classify an Elixir `call` node by its callee keyword.
fn classify_elixir_call(node: Node, source: &str) -> Option<EntityKind> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "identifier" {
            continue;
        }
        let keyword = child.utf8_text(source.as_bytes()).ok()?;
        return match keyword {
            "def" | "defp" => Some(EntityKind::Function),
            "defmacro" | "defmacrop" => Some(EntityKind::Macro),
            "defmodule" => Some(EntityKind::Module),
            _ => None,
        };
    }
    None
}

/// RC2-META Stage 3 (go): classify a Go type-definition node by its underlying
/// shape. Returns `None` for any node that is not a `type_spec` / `type_alias`
/// (so the caller falls through to the string-keyed `classify_node_kind`).
///
/// * `type_alias` (`type X = Y`)                     -> [`EntityKind::TypeAlias`]
/// * `type_spec` whose `type` field is `struct_type` -> [`EntityKind::Struct`]
/// * `type_spec` whose `type` field is `interface_type` -> [`EntityKind::Interface`]
/// * `type_spec` with any other underlying type      -> [`EntityKind::Class`]
///   (a defined type such as `type Celsius float64` — `structure`'s legacy
///   entry-kind switch likewise reports it as the class-axis default).
fn go_type_node_kind(node: Node) -> Option<EntityKind> {
    match node.kind() {
        "type_alias" => Some(EntityKind::TypeAlias),
        "type_spec" => Some(match node.child_by_field_name("type").map(|t| t.kind()) {
            Some("struct_type") => EntityKind::Struct,
            Some("interface_type") => EntityKind::Interface,
            _ => EntityKind::Class,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;
    use crate::types::Language;

    /// Find the first descendant node of the given kind (depth-first).
    fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn ts_method_signature_excludes_inline_body() {
        let source = "class Qux { m(): void {} }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let method = find_kind(tree.root_node(), "method_definition")
            .expect("method_definition node");
        // Whole-node text is the mangled "m(): void {}"; the header span must
        // drop the body block entirely.
        assert_eq!(signature_from_header(method, source), "m(): void");
    }

    #[test]
    fn ts_function_signature_excludes_inline_body() {
        let source = "function add(a: number, b: number): number { return a + b; }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let func = find_kind(tree.root_node(), "function_declaration")
            .expect("function_declaration node");
        assert_eq!(
            signature_from_header(func, source),
            "function add(a: number, b: number): number"
        );
    }

    #[test]
    fn ts_constructor_signature_excludes_inline_body() {
        let source = "class P { constructor(x: number) { this.x = x; } }\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let ctor = find_kind(tree.root_node(), "method_definition")
            .expect("constructor method_definition node");
        assert_eq!(signature_from_header(ctor, source), "constructor(x: number)");
    }

    #[test]
    fn bodyless_method_signature_is_unchanged() {
        // An interface method signature has NO body block; the header span is
        // the whole single-line node (trailing `;` preserved — legacy parity).
        let source = "interface Foo {\n  b(): void;\n}\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let sig_node = find_kind(tree.root_node(), "method_signature")
            .expect("method_signature node");
        assert_eq!(signature_from_header(sig_node, source), "b(): void;");
    }

    #[test]
    fn multiline_header_collapses_to_declaration_line() {
        // The opening brace is on a LATER line, so the header span is just the
        // first declaration line — identical to the legacy first-line slice.
        let source = "function foo(\n  a: number\n): void {\n  return;\n}\n";
        let tree = parse(source, Language::TypeScript).unwrap();
        let func = find_kind(tree.root_node(), "function_declaration")
            .expect("function_declaration node");
        assert_eq!(signature_from_header(func, source), "function foo(");
    }
}

// =============================================================================
// RC2-META Stage 2 — canonical classifier tests.
// =============================================================================
//
// Two kinds of guard live here:
//   1. GRAMMAR-GROUND-TRUTH: parse real fixtures and pin the EntityKind for the
//      verified per-language arms (TS / Scala / OCaml / Elixir). These lock the
//      grammar rules so a future edit cannot silently re-map a node kind.
//   2. THE FOURTH-TABLE GUARD: enumerate the membership of every in-crate
//      classification table (`function_finder` ×2, `ast_utils` ×1) and assert
//      each accepted node kind agrees with `classify_node_kind` on the relevant
//      axis. A table can never drift to an answer classify_node disagrees with
//      without failing CI. (The `tldr-cli` tables — `interface`, `explain`,
//      `diff` — carry the equivalent guard next to their own definitions, since
//      those functions are private to that crate.)
#[cfg(test)]
mod classify_tests {
    use super::*;
    use crate::ast::function_finder::{get_class_node_kinds, get_function_node_kinds};
    use crate::ast::parser::parse;
    use crate::security::ast_utils;
    use crate::types::Language;

    const ALL_LANGUAGES: &[Language] = &[
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

    fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    fn collect_kind<'a>(node: Node<'a>, kind: &str, out: &mut Vec<Node<'a>>) {
        if node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_kind(child, kind, out);
        }
    }

    // ---- serde stable strings (no value-level JSON diff on migration) -------
    #[test]
    fn entity_kind_serializes_to_stable_strings() {
        let cases = [
            (EntityKind::Interface, "\"interface\""),
            (EntityKind::TypeAlias, "\"type\""),
            (EntityKind::Enum, "\"enum\""),
            (EntityKind::Class, "\"class\""),
            (EntityKind::Method, "\"method\""),
            (EntityKind::Function, "\"function\""),
            (EntityKind::Struct, "\"struct\""),
            (EntityKind::Trait, "\"trait\""),
            (EntityKind::Module, "\"module\""),
            (EntityKind::Object, "\"object\""),
            (EntityKind::Contract, "\"contract\""),
            (EntityKind::Library, "\"library\""),
            (EntityKind::Macro, "\"macro\""),
            (EntityKind::Value, "\"value\""),
        ];
        for (ek, expected) in cases {
            assert_eq!(serde_json::to_string(&ek).unwrap(), expected, "{ek:?}");
        }
    }

    // ---- as_str() must mirror the serde serialization exactly ---------------
    // (the `extract`/`interface` `kind` producers use `as_str()`, so any drift
    // from the serialized enum would put a wrong string in the JSON).
    #[test]
    fn entity_kind_as_str_matches_serde() {
        for ek in [
            EntityKind::Module,
            EntityKind::Class,
            EntityKind::Struct,
            EntityKind::Interface,
            EntityKind::Enum,
            EntityKind::EnumMember,
            EntityKind::Function,
            EntityKind::Method,
            EntityKind::Constructor,
            EntityKind::Field,
            EntityKind::Property,
            EntityKind::Constant,
            EntityKind::Object,
            EntityKind::Trait,
            EntityKind::TypeAlias,
            EntityKind::Macro,
            EntityKind::Value,
            EntityKind::Contract,
            EntityKind::Library,
            EntityKind::Modifier,
            EntityKind::Event,
            EntityKind::Error,
        ] {
            let serde_str = serde_json::to_string(&ek).unwrap();
            assert_eq!(format!("\"{}\"", ek.as_str()), serde_str, "{ek:?}");
        }
    }

    // ---- grammar ground truth ----------------------------------------------
    #[test]
    fn ts_grammar_ground_truth() {
        let src = "abstract class A {}\ninterface I {}\ntype T = number;\nenum E { X }\n";
        let tree = parse(src, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let abs = find_kind(root, "abstract_class_declaration").expect("abstract class");
        assert_eq!(classify_node(abs, Language::TypeScript, src), Some(EntityKind::Class));
        let iface = find_kind(root, "interface_declaration").expect("interface");
        assert_eq!(
            classify_node(iface, Language::TypeScript, src),
            Some(EntityKind::Interface)
        );
        let alias = find_kind(root, "type_alias_declaration").expect("type alias");
        assert_eq!(
            classify_node(alias, Language::TypeScript, src),
            Some(EntityKind::TypeAlias)
        );
        let en = find_kind(root, "enum_declaration").expect("enum");
        assert_eq!(classify_node(en, Language::TypeScript, src), Some(EntityKind::Enum));
    }

    #[test]
    fn scala_grammar_ground_truth() {
        let src = "type X = Int\nobject O {}\ntrait T {}\n";
        let tree = parse(src, Language::Scala).unwrap();
        let root = tree.root_node();
        let ty = find_kind(root, "type_definition").expect("scala type_definition");
        assert_eq!(classify_node(ty, Language::Scala, src), Some(EntityKind::TypeAlias));
        let obj = find_kind(root, "object_definition").expect("scala object");
        assert_eq!(classify_node(obj, Language::Scala, src), Some(EntityKind::Object));
        let tr = find_kind(root, "trait_definition").expect("scala trait");
        assert_eq!(classify_node(tr, Language::Scala, src), Some(EntityKind::Trait));
    }

    #[test]
    fn go_grammar_ground_truth() {
        let src = "package p\n\ntype S struct { x int }\n\ntype I interface { M() error }\n\ntype Celsius float64\n\ntype Alias = S\n\nfunc (s *S) M() error { return nil }\n\nfunc Free() int { return 0 }\n";
        let tree = parse(src, Language::Go).unwrap();
        let root = tree.root_node();

        // `type S struct {...}` -> Struct (type_spec → struct_type)
        let s = find_kind(root, "type_spec").expect("go type_spec (struct)");
        assert_eq!(classify_node(s, Language::Go, src), Some(EntityKind::Struct));

        // The `type_declaration` wrapper drills into its inner spec.
        let s_decl = find_kind(root, "type_declaration").expect("go type_declaration");
        assert_eq!(
            classify_node(s_decl, Language::Go, src),
            Some(EntityKind::Struct),
            "type_declaration wrapper resolves via its inner type_spec"
        );

        // Collect every type_spec to reach the interface / defined-type ones.
        let mut specs = Vec::new();
        collect_kind(root, "type_spec", &mut specs);
        let kinds: Vec<_> = specs
            .iter()
            .filter_map(|n| classify_node(*n, Language::Go, src))
            .collect();
        assert!(kinds.contains(&EntityKind::Struct), "struct: {kinds:?}");
        assert!(kinds.contains(&EntityKind::Interface), "interface: {kinds:?}");
        assert!(
            kinds.contains(&EntityKind::Class),
            "defined type `type Celsius float64` -> Class: {kinds:?}"
        );

        // `type Alias = S` -> TypeAlias (dedicated type_alias node).
        let alias = find_kind(root, "type_alias").expect("go type_alias");
        assert_eq!(classify_node(alias, Language::Go, src), Some(EntityKind::TypeAlias));

        // Function-axis nodes still classify via the string-keyed path.
        let m = find_kind(root, "method_declaration").expect("go method");
        assert_eq!(classify_node(m, Language::Go, src), Some(EntityKind::Method));
        let f = find_kind(root, "function_declaration").expect("go function");
        assert_eq!(classify_node(f, Language::Go, src), Some(EntityKind::Function));
    }

    #[test]
    fn ocaml_function_vs_value_is_structural() {
        let fsrc = "let f = fun x -> x\n";
        let ftree = parse(fsrc, Language::Ocaml).unwrap();
        let fnode = find_kind(ftree.root_node(), "value_definition").expect("ocaml value_definition");
        assert_eq!(
            classify_node(fnode, Language::Ocaml, fsrc),
            Some(EntityKind::Function),
            "let f = fun x -> x is a Function"
        );

        let vsrc = "let x = 1\n";
        let vtree = parse(vsrc, Language::Ocaml).unwrap();
        let vnode = find_kind(vtree.root_node(), "value_definition").expect("ocaml value_definition");
        assert_eq!(
            classify_node(vnode, Language::Ocaml, vsrc),
            Some(EntityKind::Value),
            "let x = 1 is a Value"
        );
    }

    #[test]
    fn elixir_def_vs_defmacro() {
        let src = "defmodule M do\n  def bar(x) do\n    x\n  end\n\n  defmacro foo(x) do\n    x\n  end\nend\n";
        let tree = parse(src, Language::Elixir).unwrap();
        let mut calls = Vec::new();
        collect_kind(tree.root_node(), "call", &mut calls);
        let kinds: Vec<_> = calls
            .iter()
            .filter_map(|n| classify_node(*n, Language::Elixir, src))
            .collect();
        assert!(kinds.contains(&EntityKind::Module), "defmodule -> Module: {kinds:?}");
        assert!(kinds.contains(&EntityKind::Function), "def -> Function: {kinds:?}");
        assert!(kinds.contains(&EntityKind::Macro), "defmacro -> Macro: {kinds:?}");
    }

    // ---- the fourth-table guard (in-crate tables) --------------------------
    #[test]
    fn function_finder_tables_match_classify_node() {
        for &lang in ALL_LANGUAGES {
            for &k in get_function_node_kinds(lang) {
                if k == "call" {
                    continue; // Elixir def/defp — node-aware only.
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_function_axis) == Some(true),
                    "get_function_node_kinds({lang:?}) member {k:?} -> {ek:?} is not function-axis"
                );
            }
            for &k in get_class_node_kinds(lang) {
                if k == "call" {
                    continue; // Elixir defmodule — node-aware only.
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_class_axis) == Some(true),
                    "get_class_node_kinds({lang:?}) member {k:?} -> {ek:?} is not class-axis"
                );
            }
        }
    }

    #[test]
    fn ast_utils_function_table_matches_classify_node() {
        for &lang in ALL_LANGUAGES {
            for &k in ast_utils::function_node_kinds(lang) {
                if k == "call" {
                    continue;
                }
                let ek = classify_node_kind(k, lang);
                assert!(
                    ek.map(EntityKind::is_function_axis) == Some(true),
                    "ast_utils::function_node_kinds({lang:?}) member {k:?} -> {ek:?} is not function-axis"
                );
            }
        }
    }
}
