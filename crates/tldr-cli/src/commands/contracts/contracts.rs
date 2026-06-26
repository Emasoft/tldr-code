//! Contracts command - Pre/postcondition inference from source code.
//!
//! Analyzes guard clauses, assertions, type checks, and return patterns
//! to infer preconditions, postconditions, and invariants for all supported
//! languages.
//!
//! # TIGER Mitigations Addressed
//! - T07: Regex DoS - Use compiled regex with limits
//! - T08: AST stack overflow - check_ast_depth() limits traversal depth
//!
//! # Detection Patterns
//!
//! | Pattern | Confidence | Example |
//! |---------|------------|---------|
//! | `if <cond>: raise/throw/panic` | High | Guard clause -> negated precondition |
//! | `assert <cond>` / `assert!(<cond>)` | High | Direct assertion -> precondition |
//! | `if not isinstance(...)`: raise | High | Direct type precondition (Python) |
//! | Assert after `result =` | High | Postcondition on result |
//! | Type annotations / signatures | Low | Parameter types -> type preconditions |
//!
//! # Supported Languages
//!
//! Python, Go, Rust, Java, TypeScript/JavaScript, C, C++, Ruby, C#, Scala,
//! PHP, Lua, Luau, Elixir, OCaml, and more via tree-sitter grammars.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

use tldr_core::ast::extract::decl_keyword_line_from_node;
use tldr_core::ast::ParserPool;
use tldr_core::Language;

use crate::output::{OutputFormat, OutputWriter};

use super::error::{ContractsError, ContractsResult};
#[cfg(test)]
use super::types::Confidence;
use super::types::{Condition, ContractsReport, OutputFormat as ContractsOutputFormat};
use super::validation::{
    check_ast_depth, read_file_safe, validate_file_path, validate_function_name, MAX_AST_DEPTH,
    MAX_CONDITIONS_PER_FUNCTION,
};

// =============================================================================
// Language Configuration
// =============================================================================

/// Language-specific AST node kinds for contract extraction.
///
/// Each language has different tree-sitter grammar node names for equivalent
/// constructs (e.g., `if_statement` vs `if_expression`, `raise_statement` vs
/// `throw_statement`). This config maps those differences.
#[derive(Debug, Clone)]
struct LanguageConfig {
    /// Node kinds for function definitions (e.g., "function_definition", "function_declaration")
    function_kinds: &'static [&'static str],
    /// Node kinds for class/struct/impl containers that may hold methods
    class_kinds: &'static [&'static str],
    /// Node kinds for if-statements/expressions
    if_kinds: &'static [&'static str],
    /// Node kinds for assert statements/macros
    assert_kinds: &'static [&'static str],
    /// Node kinds for raise/throw/panic statements
    throw_kinds: &'static [&'static str],
    /// Node kinds for return statements/expressions
    return_kinds: &'static [&'static str],
    /// Node kinds for loop constructs
    loop_kinds: &'static [&'static str],
    /// Node kinds for assignment statements
    assignment_kinds: &'static [&'static str],
    /// Field name for function name in the AST
    func_name_field: &'static str,
    /// Field name for function body in the AST
    func_body_field: &'static str,
    /// Field name for if-condition in the AST
    if_condition_field: &'static str,
    /// Field name for if-consequence (then-block) in the AST
    if_consequence_field: &'static str,
    /// Field name for if-alternative (else-block) in the AST
    if_alternative_field: &'static str,
    /// Field name for function parameters
    func_params_field: &'static str,
    /// Field name for return type annotation
    return_type_field: &'static str,
    /// Field name for class body
    class_body_field: &'static str,
    /// Field name for loop body
    loop_body_field: &'static str,
    /// Whether the language uses `not` prefix (Python) or `!` prefix
    negation_prefix: &'static str,
    /// Whether the language has isinstance-style type checks
    has_isinstance: bool,
    /// Node kinds for typed parameters (for type annotation extraction)
    typed_param_kinds: &'static [&'static str],
    /// Whether the assert is a macro (Rust: assert!) vs statement (Python: assert)
    assert_is_macro: bool,
    /// Function names that act as precondition assertions when called directly
    /// (e.g., Kotlin: require, check; Swift: precondition, assert; Luau: assert)
    assert_call_names: &'static [&'static str],
    /// Function names that act as error/throw when called directly
    /// (e.g., Luau: error; Swift: fatalError, preconditionFailure)
    error_call_names: &'static [&'static str],
    /// Node kinds for call expressions (e.g., "call_expression", "function_call")
    call_kinds: &'static [&'static str],
    /// v0.5.0 CL-10 (GH #81): the source language. Stored so per-function
    /// line attribution can be normalised past leading annotation/attribute
    /// children for grammars that emit them (Java `@Override`, Swift
    /// `@inlinable`, C# `[Test]`, …) via [`func_decl_line`]. Defaults to
    /// `Python` in the per-language constructors and is overwritten by
    /// [`LanguageConfig::for_language`].
    language: Language,
}

impl LanguageConfig {
    fn for_language(lang: Language) -> Self {
        let mut config = match lang {
            Language::Python => Self::python(),
            Language::Go => Self::go(),
            Language::Rust => Self::rust(),
            Language::Java => Self::java(),
            Language::TypeScript | Language::JavaScript => Self::typescript(),
            Language::C => Self::c(),
            Language::Cpp => Self::cpp(),
            Language::Ruby => Self::ruby(),
            Language::CSharp => Self::csharp(),
            Language::Scala => Self::scala(),
            Language::Php => Self::php(),
            Language::Lua => Self::lua(),
            Language::Luau => Self::luau(),
            Language::Elixir => Self::elixir(),
            Language::Ocaml => Self::ocaml(),
            Language::Kotlin => Self::kotlin(),
            Language::Swift => Self::swift(),
            // v0.5.0 SOL-001 Solidity foundation
            Language::Solidity => Self::solidity(),
        };
        // v0.5.0 CL-10: the per-language constructors default `language` to
        // `Python`; record the real language so `func_decl_line` can pick
        // the correct line-normalisation gate. (TypeScript/JavaScript share
        // one constructor — store the concrete variant passed in.)
        config.language = lang;
        config
    }

    /// v0.5.0 CL-10 (GH #81): return the 1-indexed decl-keyword line for a
    /// function/method `func` node, normalising past leading
    /// annotation/attribute/modifier children for the grammars that emit
    /// them (Java `@Override`, Swift `@inlinable` / `@discardableResult`,
    /// C# `[Test]`, Kotlin/Scala modifier families). For every other
    /// language `decl_keyword_line_from_node` returns the bare
    /// `func.start_position()` line (the decl keyword IS the first child),
    /// so the gate only changes behaviour where a real drift exists.
    ///
    /// The language gate is kept identical to
    /// `ast::extractor::collect_definitions` and `metrics::cognitive` so the
    /// `contracts` per-condition `source_line` agrees with `structure` /
    /// `extract` / `cognitive` for the SAME symbol.
    fn func_decl_line(&self, func: Node) -> u32 {
        if matches!(
            self.language,
            Language::Java
                | Language::Solidity
                | Language::Swift
                | Language::Kotlin
                | Language::Scala
                | Language::CSharp
        ) {
            decl_keyword_line_from_node(&func)
        } else {
            func.start_position().row as u32 + 1
        }
    }

    /// v0.5.0 SOL-001: Solidity contracts/specs config — initial node
    /// kinds wired from oracle research (function_definition,
    /// contract_declaration / interface_declaration / library_declaration
    /// for class-shaped containers, modifier invocations applied at
    /// declaration). `require` / `assert` / `revert` are intrinsic to
    /// Solidity, so we list them as assert/error names. Detailed
    /// pre/postcondition extraction lands in SOL-006.
    fn solidity() -> Self {
        Self {
            function_kinds: &[
                "function_definition",
                "constructor_definition",
                "fallback_function_definition",
                "receive_function_definition",
            ],
            class_kinds: &[
                "contract_declaration",
                "interface_declaration",
                "library_declaration",
            ],
            if_kinds: &["if_statement"],
            assert_kinds: &[],
            throw_kinds: &["revert_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement", "do_while_statement"],
            assignment_kinds: &[
                "assignment_expression",
                "variable_declaration_statement",
                "state_variable_declaration",
            ],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            // v0.5.0 SOL-CONV-R1-2 (M14b): the tree-sitter-solidity grammar
            // names the then-branch field `body`, not `consequence`. With
            // the wrong field name the per-language guard-precondition
            // walker treated every `if (cond) revert Err()` as if it had
            // no throw in the consequence and dropped it from the surface.
            if_consequence_field: "body",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_parameters",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            // Solidity uses `require(cond, msg)` for preconditions and
            // `assert(cond)` for invariants; `revert(...)` raises.
            assert_call_names: &["require", "assert"],
            error_call_names: &["revert"],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn python() -> Self {
        Self {
            function_kinds: &["function_definition"],
            class_kinds: &["class_definition"],
            if_kinds: &["if_statement"],
            assert_kinds: &["assert_statement"],
            throw_kinds: &["raise_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement"],
            assignment_kinds: &["assignment", "expression_statement"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "not",
            has_isinstance: true,
            typed_param_kinds: &["typed_parameter", "typed_default_parameter"],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["call"],
            language: Language::Python,
        }
    }

    fn go() -> Self {
        Self {
            function_kinds: &["function_declaration", "method_declaration"],
            class_kinds: &[],
            if_kinds: &["if_statement"],
            assert_kinds: &[],                  // Go has no built-in assert
            throw_kinds: &["return_statement"], // Go uses early return for errors; also panic
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement"],
            assignment_kinds: &["assignment_statement", "short_var_declaration"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "result",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter_declaration"],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &["panic"],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn rust() -> Self {
        Self {
            function_kinds: &["function_item"],
            class_kinds: &["impl_item", "trait_item"],
            if_kinds: &["if_expression"],
            assert_kinds: &["macro_invocation"], // assert!(), debug_assert!()
            throw_kinds: &["return_expression"], // panic!() is also a macro_invocation
            return_kinds: &["return_expression"],
            loop_kinds: &["for_expression", "while_expression", "loop_expression"],
            assignment_kinds: &[
                "let_declaration",
                "assignment_expression",
                "expression_statement",
            ],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: true,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn java() -> Self {
        Self {
            function_kinds: &["method_declaration", "constructor_declaration"],
            class_kinds: &["class_declaration", "interface_declaration"],
            if_kinds: &["if_statement"],
            assert_kinds: &["assert_statement"],
            throw_kinds: &["throw_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement", "enhanced_for_statement"],
            assignment_kinds: &[
                "assignment_expression",
                "local_variable_declaration",
                "expression_statement",
            ],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["formal_parameter"],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["method_invocation"],
            language: Language::Python,
        }
    }

    fn typescript() -> Self {
        Self {
            function_kinds: &[
                "function_declaration",
                "method_definition",
                "arrow_function",
            ],
            class_kinds: &["class_declaration"],
            if_kinds: &["if_statement"],
            assert_kinds: &[], // No built-in assert statement (assert is a function call)
            throw_kinds: &["throw_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &[
                "for_statement",
                "while_statement",
                "for_in_statement",
                "for_of_statement",
            ],
            assignment_kinds: &[
                "assignment_expression",
                "variable_declaration",
                "lexical_declaration",
                "expression_statement",
            ],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["required_parameter", "optional_parameter"],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn c() -> Self {
        Self {
            function_kinds: &["function_definition"],
            class_kinds: &[],
            if_kinds: &["if_statement"],
            assert_kinds: &[], // assert() is a macro/call
            throw_kinds: &["return_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement", "do_statement"],
            assignment_kinds: &[
                "assignment_expression",
                "declaration",
                "expression_statement",
            ],
            func_name_field: "declarator",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "declarator",
            return_type_field: "type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter_declaration"],
            assert_is_macro: false,
            assert_call_names: &["assert"],
            error_call_names: &["abort", "exit"],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn cpp() -> Self {
        Self {
            function_kinds: &["function_definition"],
            class_kinds: &["class_specifier", "struct_specifier"],
            if_kinds: &["if_statement"],
            assert_kinds: &[],
            throw_kinds: &["throw_statement", "return_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &[
                "for_statement",
                "while_statement",
                "do_statement",
                "for_range_loop",
            ],
            assignment_kinds: &[
                "assignment_expression",
                "declaration",
                "expression_statement",
            ],
            func_name_field: "declarator",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "declarator",
            return_type_field: "type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter_declaration"],
            assert_is_macro: false,
            assert_call_names: &["assert"],
            error_call_names: &["abort", "exit"],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn ruby() -> Self {
        Self {
            function_kinds: &["method"],
            class_kinds: &["class", "module"],
            if_kinds: &["if", "unless"],
            assert_kinds: &[],
            throw_kinds: &["raise", "call"], // raise is a method call in Ruby
            return_kinds: &["return"],
            loop_kinds: &["while", "until", "for"],
            assignment_kinds: &["assignment"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &[],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &["raise"],
            call_kinds: &["call"],
            language: Language::Python,
        }
    }

    fn csharp() -> Self {
        Self {
            function_kinds: &["method_declaration", "constructor_declaration"],
            class_kinds: &[
                "class_declaration",
                "interface_declaration",
                "struct_declaration",
            ],
            if_kinds: &["if_statement"],
            assert_kinds: &[],
            throw_kinds: &["throw_statement"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement", "foreach_statement"],
            assignment_kinds: &[
                "assignment_expression",
                "local_declaration_statement",
                "expression_statement",
            ],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["invocation_expression"],
            language: Language::Python,
        }
    }

    fn scala() -> Self {
        Self {
            function_kinds: &["function_definition"],
            class_kinds: &["class_definition", "object_definition", "trait_definition"],
            if_kinds: &["if_expression"],
            assert_kinds: &[], // assert is a function call
            throw_kinds: &["throw_expression"],
            return_kinds: &["return_expression"],
            loop_kinds: &["while_expression", "for_expression"],
            assignment_kinds: &["assignment_expression", "val_definition", "var_definition"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            assert_call_names: &["assert", "require"],
            error_call_names: &[],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn php() -> Self {
        Self {
            function_kinds: &["function_definition", "method_declaration"],
            class_kinds: &["class_declaration"],
            if_kinds: &["if_statement"],
            assert_kinds: &[],
            throw_kinds: &["throw_expression"],
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement", "foreach_statement"],
            assignment_kinds: &["assignment_expression", "expression_statement"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "return_type",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["simple_parameter"],
            assert_is_macro: false,
            assert_call_names: &["assert"],
            error_call_names: &[],
            call_kinds: &["function_call_expression"],
            language: Language::Python,
        }
    }

    fn lua() -> Self {
        Self {
            function_kinds: &["function_declaration", "function_definition_statement"],
            class_kinds: &[],
            if_kinds: &["if_statement"],
            assert_kinds: &[], // assert() is a function call in Lua
            throw_kinds: &["return_statement"], // error() is a function call
            return_kinds: &["return_statement"],
            loop_kinds: &[
                "for_statement",
                "while_statement",
                "repeat_statement",
                "for_numeric_statement",
                "for_generic_statement",
            ],
            assignment_kinds: &["assignment_statement", "variable_declaration"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "not",
            has_isinstance: false,
            typed_param_kinds: &[],
            assert_is_macro: false,
            assert_call_names: &["assert"],
            error_call_names: &["error"],
            call_kinds: &["function_call"],
            language: Language::Python,
        }
    }

    fn elixir() -> Self {
        Self {
            function_kinds: &["call"], // def/defp are function calls in Elixir tree-sitter
            class_kinds: &["call"],    // defmodule is also a call
            if_kinds: &["call"],       // if/unless are also calls in Elixir
            assert_kinds: &[],
            throw_kinds: &["call"],                 // raise is a function call
            return_kinds: &[],                      // Elixir returns last expression
            loop_kinds: &["call"],                  // for/Enum.each are calls
            assignment_kinds: &["binary_operator"], // = is a binary op
            func_name_field: "target",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "arguments",
            return_type_field: "",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &[],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &["raise"],
            call_kinds: &["call"],
            language: Language::Python,
        }
    }

    fn ocaml() -> Self {
        Self {
            function_kinds: &["let_binding", "value_definition"],
            class_kinds: &["module_definition"],
            if_kinds: &["if_expression"],
            assert_kinds: &["assert_expression"],
            throw_kinds: &["raise_expression"],
            return_kinds: &[],
            loop_kinds: &["while_expression", "for_expression"],
            assignment_kinds: &["let_binding"],
            func_name_field: "pattern",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameter",
            return_type_field: "",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "not",
            has_isinstance: false,
            typed_param_kinds: &[],
            assert_is_macro: false,
            assert_call_names: &[],
            error_call_names: &[],
            call_kinds: &["application"],
            language: Language::Python,
        }
    }

    fn kotlin() -> Self {
        Self {
            function_kinds: &["function_declaration"],
            class_kinds: &["class_declaration", "object_declaration"],
            if_kinds: &["if_expression"],
            assert_kinds: &[], // assert/require/check are function calls, not statement kinds
            throw_kinds: &["throw_expression"],
            return_kinds: &["return_expression"],
            loop_kinds: &["for_statement", "while_statement"],
            assignment_kinds: &["assignment", "property_declaration"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "function_value_parameters",
            return_type_field: "type",
            class_body_field: "class_body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            assert_call_names: &[
                "assert",
                "require",
                "check",
                "requireNotNull",
                "checkNotNull",
            ],
            error_call_names: &[],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn swift() -> Self {
        Self {
            function_kinds: &["function_declaration"],
            class_kinds: &[
                "class_declaration",
                "struct_declaration",
                "protocol_declaration",
            ],
            if_kinds: &["if_statement", "guard_statement"],
            assert_kinds: &[], // precondition/assert are function calls
            throw_kinds: &["control_transfer_statement"], // Swift throw/return via control_transfer_statement
            return_kinds: &["control_transfer_statement"],
            loop_kinds: &["for_statement", "while_statement", "repeat_while_statement"],
            assignment_kinds: &["assignment", "property_declaration"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "body", // Swift parameters are children of function_declaration directly
            return_type_field: "return_type",
            class_body_field: "class_body",
            loop_body_field: "body",
            negation_prefix: "!",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            assert_call_names: &["precondition", "assert", "assertionFailure"],
            error_call_names: &["fatalError", "preconditionFailure"],
            call_kinds: &["call_expression"],
            language: Language::Python,
        }
    }

    fn luau() -> Self {
        Self {
            function_kinds: &["function_declaration", "function_definition"],
            class_kinds: &[],
            if_kinds: &["if_statement"],
            assert_kinds: &[], // assert() is a function call in Luau
            throw_kinds: &["return_statement"], // error() is a function call
            return_kinds: &["return_statement"],
            loop_kinds: &["for_statement", "while_statement"],
            assignment_kinds: &["assignment_statement", "variable_declaration"],
            func_name_field: "name",
            func_body_field: "body",
            if_condition_field: "condition",
            if_consequence_field: "consequence",
            if_alternative_field: "alternative",
            func_params_field: "parameters",
            return_type_field: "",
            class_body_field: "body",
            loop_body_field: "body",
            negation_prefix: "not",
            has_isinstance: false,
            typed_param_kinds: &["parameter"],
            assert_is_macro: false,
            assert_call_names: &["assert"],
            error_call_names: &["error"],
            call_kinds: &["function_call"],
            language: Language::Python,
        }
    }

    /// Check if a node kind is a function definition
    fn is_function(&self, kind: &str) -> bool {
        self.function_kinds.contains(&kind)
    }

    /// Check if a node kind is a class/container
    fn is_class(&self, kind: &str) -> bool {
        self.class_kinds.contains(&kind)
    }

    /// Check if a node kind is an if-statement/expression
    fn is_if(&self, kind: &str) -> bool {
        self.if_kinds.contains(&kind)
    }

    /// Check if a node kind is an assert statement/macro
    fn is_assert(&self, kind: &str) -> bool {
        self.assert_kinds.contains(&kind)
    }

    /// Check if a node kind is a throw/raise/panic statement
    fn is_throw(&self, kind: &str) -> bool {
        self.throw_kinds.contains(&kind)
    }

    /// Check if a node kind is a loop
    fn is_loop(&self, kind: &str) -> bool {
        self.loop_kinds.contains(&kind)
    }

    /// Check if a node kind is an assignment
    fn is_assignment(&self, kind: &str) -> bool {
        self.assignment_kinds.contains(&kind)
    }

    /// Check if a node kind is a call expression
    fn is_call(&self, kind: &str) -> bool {
        self.call_kinds.contains(&kind)
    }

    /// Check if a function name is an assertion-like call (e.g., require, check, assert)
    fn is_assert_call_name(&self, name: &str) -> bool {
        self.assert_call_names.contains(&name)
    }

    /// Check if a function name is an error/throw-like call (e.g., error, fatalError)
    fn is_error_call_name(&self, name: &str) -> bool {
        self.error_call_names.contains(&name)
    }

    /// Whether this language has call-based assertion patterns
    fn has_assert_calls(&self) -> bool {
        !self.assert_call_names.is_empty()
    }

    /// Whether this language has call-based error patterns
    fn has_error_calls(&self) -> bool {
        !self.error_call_names.is_empty()
    }
}

// =============================================================================
// CLI Arguments
// =============================================================================

/// Infer pre/postconditions from guard clauses, assertions, and type checks.
///
/// Analyzes source code to detect contracts:
/// - Preconditions from guard clauses (`if x < 0: raise` / `if x < 0 { panic!() }`)
/// - Preconditions from assertions (`assert x > 0` / `assert!(x > 0)`)
/// - Type constraints from isinstance checks (Python)
/// - Postconditions from assertions on result variables
///
/// Supports all languages with tree-sitter grammars.
///
/// # Example
///
/// ```bash
/// tldr contracts src/module.py process_data
/// tldr contracts src/lib.rs validate --format text
/// tldr contracts src/main.go processData
/// ```
#[derive(Debug, Args)]
pub struct ContractsArgs {
    /// Source file to analyze
    pub file: PathBuf,

    /// Function name to analyze
    pub function: String,

    /// Output format (json or text). Prefer global --format/-f flag.
    #[arg(
        long = "output-format",
        short = 'o',
        hide = true,
        default_value = "json"
    )]
    pub output_format: ContractsOutputFormat,

    /// Programming language (auto-detected from file extension if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Maximum conditions to report per category
    #[arg(long, default_value = "100")]
    pub limit: usize,

    /// m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt in to the
    /// bare-name fallback for Rust / C / C++ `Class::method` inputs.
    /// See `complexity.rs::ComplexityArgs::qualified` for the full
    /// rationale.
    #[arg(long)]
    pub qualified: bool,
}

impl ContractsArgs {
    /// Run the contracts command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate inputs
        let canonical_path = validate_file_path(&self.file)?;
        validate_function_name(&self.function)?;

        // Determine language (FM-22, FM-44: no silent Python fallback)
        let language = match self.lang {
            Some(l) => l,
            None => Language::from_path(&self.file).ok_or_else(|| ContractsError::ParseError {
                file: self.file.clone(),
                message: format!(
                    "Cannot determine language for '{}'. Use --lang to specify.",
                    self.file.display()
                ),
            })?,
        };

        // m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt-in bare-name
        // canonicalisation. Default is strict-qualified (no-op).
        let function = tldr_core::ast::function_finder::resolve_qualified_function_name(
            &self.function,
            language,
            self.qualified,
        );

        writer.progress(&format!(
            "Analyzing contracts for {}::{}...",
            self.file.display(),
            function
        ));

        // Verify we have a tree-sitter grammar for this language
        if ParserPool::get_ts_language(language).is_none() {
            return Err(ContractsError::ParseError {
                file: self.file.clone(),
                message: format!("No tree-sitter grammar available for {:?}", language),
            }
            .into());
        }

        // Parse and analyze
        let mut report = run_contracts(&canonical_path, &function, language, self.limit)?;

        // (path-and-schema-cleanup-v3 P3.BUG-N2) Echo the user-supplied
        // path in the JSON `file` field. `validate_file_path` is still
        // called above for existence/traversal, but the canonical value
        // is discarded for emit so macOS does not rewrite `/tmp/...`
        // to `/private/tmp/...`. Mirrors the M2 BUG-8 fix.
        report.file = self.file.clone();

        // Output based on format
        let use_text = matches!(self.output_format, ContractsOutputFormat::Text)
            || matches!(format, OutputFormat::Text);

        if use_text {
            let text = format_contracts_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

// =============================================================================
// Core Analysis Functions
// =============================================================================

/// Run contracts analysis on a file and function.
///
/// # Arguments
/// * `file` - Path to the source file
/// * `function` - Name of the function to analyze
/// * `language` - Programming language
/// * `limit` - Maximum conditions per category
///
/// # Returns
/// ContractsReport with detected preconditions, postconditions, and invariants.
pub fn run_contracts(
    file: &Path,
    function: &str,
    language: Language,
    limit: usize,
) -> ContractsResult<ContractsReport> {
    // Read the file
    let source = read_file_safe(file)?;

    // Get language configuration
    let config = LanguageConfig::for_language(language);
    let _ = config.return_kinds;

    // Parse with tree-sitter (multi-language)
    let tree = parse_source(&source, language, file)?;
    let root = tree.root_node();

    // contracts-type-printer-v1 (CLUSTER-M-046): OCaml `.mli` interface
    // files have NO function bodies — only `val name : type` specifications.
    // Handle them via a dedicated extractor that turns each arrow-separated
    // segment of the type signature into a low-confidence pre/postcondition.
    if language == Language::Ocaml && is_ocaml_interface_file(file) {
        return extract_ocaml_interface_contracts(root, function, source.as_bytes(), file, limit);
    }

    // Find the function in the AST
    let func_node =
        find_function_node(root, function, source.as_bytes(), &config).ok_or_else(|| {
            ContractsError::FunctionNotFound {
                function: function.to_string(),
                file: file.to_path_buf(),
            }
        })?;

    // Extract contracts with depth limiting
    let mut preconditions = Vec::new();
    let mut postconditions = Vec::new();
    let mut invariants = Vec::new();

    // Track lines used for postconditions to avoid duplicating in preconditions
    let mut postcondition_lines = HashSet::new();

    // Extract postconditions first (asserts after result assignment)
    extract_postconditions(
        func_node,
        source.as_bytes(),
        &mut postconditions,
        0,
        &config,
    )?;
    for cond in &postconditions {
        postcondition_lines.insert(cond.source_line);
    }

    // Extract preconditions from guard clauses and asserts
    extract_preconditions(
        func_node,
        source.as_bytes(),
        &mut preconditions,
        &postcondition_lines,
        0,
        &config,
    )?;

    // Extract type annotation preconditions (low confidence)
    extract_type_annotation_preconditions(
        func_node,
        source.as_bytes(),
        &mut preconditions,
        &config,
    )?;

    // Extract untyped parameter preconditions (low confidence)
    // This captures parameters that have no type annotations (e.g., Python's `def f(x, y, **kwargs)`)
    extract_untyped_param_preconditions(func_node, source.as_bytes(), &mut preconditions, &config)?;

    // Extract return type postconditions (low confidence)
    extract_return_type_postconditions(func_node, source.as_bytes(), &mut postconditions, &config)?;

    // Extract contracts from docstrings (Python :param/:return:) and JSDoc (@param/@returns)
    extract_docstring_contracts(
        func_node,
        source.as_bytes(),
        &mut preconditions,
        &mut postconditions,
        &config,
        language,
    )?;

    // Extract loop invariants
    extract_invariants(func_node, source.as_bytes(), &mut invariants, 0, &config)?;

    // contracts-type-printer-v1 (CLUSTER-M-046):
    // - Elixir @spec ingestion. Walk siblings of the `def` call to find the
    //   matching `@spec name(t1, t2) :: ret` and emit one precondition per
    //   typed argument plus a return postcondition.
    // - Swift `guard let X = Y else { return }` recognition: emit
    //   `X != nil` precondition.
    if language == Language::Elixir {
        extract_elixir_at_spec(
            func_node,
            function,
            source.as_bytes(),
            &mut preconditions,
            &mut postconditions,
        );
    }
    if language == Language::Swift {
        extract_swift_guard_let(func_node, source.as_bytes(), &mut preconditions, &config);
    }

    // Deduplicate conditions
    preconditions = deduplicate_conditions(preconditions);
    postconditions = deduplicate_conditions(postconditions);
    invariants = deduplicate_conditions(invariants);

    // Apply limits
    preconditions.truncate(limit.min(MAX_CONDITIONS_PER_FUNCTION));
    postconditions.truncate(limit.min(MAX_CONDITIONS_PER_FUNCTION));
    invariants.truncate(limit.min(MAX_CONDITIONS_PER_FUNCTION));

    Ok(ContractsReport {
        function: function.to_string(),
        file: file.to_path_buf(),
        preconditions,
        postconditions,
        invariants,
    })
}

/// Parse source code with the appropriate tree-sitter grammar.
///
/// contracts-type-printer-v1 (CLUSTER-M-046): `.mli` OCaml interface files
/// need the dedicated `LANGUAGE_OCAML_INTERFACE` grammar — the implementation
/// grammar (`LANGUAGE_OCAML`) doesn't recognise `val name : type`
/// signatures, so contracts on `.mli` files would otherwise return an empty
/// AST and "function not found".
fn parse_source(source: &str, language: Language, file: &Path) -> ContractsResult<Tree> {
    let ts_language = if language == Language::Ocaml && is_ocaml_interface_file(file) {
        tree_sitter_ocaml::LANGUAGE_OCAML_INTERFACE.into()
    } else {
        ParserPool::get_ts_language(language).ok_or_else(|| ContractsError::ParseError {
            file: file.to_path_buf(),
            message: format!("No tree-sitter grammar for {:?}", language),
        })?
    };

    let mut parser = Parser::new();
    parser
        .set_language(&ts_language)
        .map_err(|e| ContractsError::ParseError {
            file: file.to_path_buf(),
            message: format!("Failed to set {:?} language: {}", language, e),
        })?;

    parser
        .parse(source, None)
        .ok_or_else(|| ContractsError::ParseError {
            file: file.to_path_buf(),
            message: "Parsing returned None".to_string(),
        })
}

/// Return true for OCaml interface (`.mli`) files. Used by [`parse_source`]
/// to pick the dedicated interface grammar.
fn is_ocaml_interface_file(file: &Path) -> bool {
    file.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("mli"))
        .unwrap_or(false)
}

/// contracts-type-printer-v1 (CLUSTER-M-046): extract pre/postconditions
/// from an OCaml `.mli` interface file's `val name : type` signature.
///
/// The interface grammar parses each `val` declaration as a
/// `value_specification` node whose direct children are the keyword
/// `val`, a `value_name` (the identifier), `:`, and a type expression.
/// We walk all `value_specification` nodes, match `value_name == function`,
/// then split the type expression on top-level `->` to derive one
/// precondition per parameter type and one postcondition per return type.
///
/// All emitted conditions are low-confidence because the signature only
/// constrains the static type, not runtime values.
fn extract_ocaml_interface_contracts(
    root: Node,
    function: &str,
    source: &[u8],
    file: &Path,
    limit: usize,
) -> ContractsResult<ContractsReport> {
    let spec_node =
        find_ocaml_value_specification(root, function, source).ok_or_else(|| {
            ContractsError::FunctionNotFound {
                function: function.to_string(),
                file: file.to_path_buf(),
            }
        })?;

    let line = spec_node.start_position().row as u32 + 1;
    let type_text = ocaml_value_spec_type_text(spec_node, source).unwrap_or_default();
    let parts = split_top_level_arrows(&type_text);

    let mut preconditions: Vec<Condition> = Vec::new();
    let mut postconditions: Vec<Condition> = Vec::new();

    if parts.len() >= 2 {
        // All but the last component are parameter types.
        for (idx, ty) in parts[..parts.len() - 1].iter().enumerate() {
            let ty = ty.trim();
            if ty.is_empty() {
                continue;
            }
            let name = format!("arg{}", idx + 1);
            preconditions.push(Condition::low(
                name.clone(),
                format!("{}: {}", name, ty),
                line,
            ));
        }
        if let Some(ret) = parts.last() {
            let ret = ret.trim();
            if !ret.is_empty() && ret != "unit" {
                postconditions.push(Condition::low(
                    "return".to_string(),
                    format!("return: {}", ret),
                    line,
                ));
            }
        }
    } else if !type_text.trim().is_empty() {
        // Zero-arrow signature — single value of some type. Treat the type as
        // a return postcondition (e.g., `val pi : float`).
        let ty = type_text.trim();
        if ty != "unit" {
            postconditions.push(Condition::low(
                "return".to_string(),
                format!("return: {}", ty),
                line,
            ));
        }
    }

    preconditions.truncate(limit.min(MAX_CONDITIONS_PER_FUNCTION));
    postconditions.truncate(limit.min(MAX_CONDITIONS_PER_FUNCTION));

    Ok(ContractsReport {
        function: function.to_string(),
        file: file.to_path_buf(),
        preconditions,
        postconditions,
        invariants: Vec::new(),
    })
}

/// Walk a tree-sitter-ocaml interface tree for a `value_specification`
/// whose `value_name` child matches the requested function.
fn find_ocaml_value_specification<'a>(
    root: Node<'a>,
    function: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "value_specification" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "value_name" {
                    let name = get_node_text(child, source);
                    if name.trim() == function {
                        return Some(node);
                    }
                    break;
                }
            }
        }
        let mut cursor = node.walk();
        let kids: Vec<_> = node.children(&mut cursor).collect();
        for kid in kids.into_iter().rev() {
            stack.push(kid);
        }
    }
    None
}

/// Extract the type-expression text from a `value_specification` node by
/// concatenating every child after the `value_name`/`:` prefix.
fn ocaml_value_spec_type_text<'a>(spec: Node<'a>, source: &'a [u8]) -> Option<String> {
    let mut after_colon = false;
    let mut buf = String::new();
    let mut cursor = spec.walk();
    for child in spec.children(&mut cursor) {
        let kind = child.kind();
        if kind == ":" {
            after_colon = true;
            continue;
        }
        if after_colon {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(get_node_text(child, source));
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// Split a type string on top-level `->`, respecting bracket nesting.
/// Used to break an OCaml/Elixir-spec type signature into params + return.
fn split_top_level_arrows(s: &str) -> Vec<String> {
    let mut depth: i32 = 0;
    let mut parts = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            '-' if depth == 0 && i + 1 < chars.len() && chars[i + 1] == '>' => {
                parts.push(current.trim().to_string());
                current.clear();
                i += 2;
                continue;
            }
            _ => current.push(ch),
        }
        i += 1;
    }
    parts.push(current.trim().to_string());
    parts
}

// =============================================================================
// AST Navigation
// =============================================================================

/// Find a function definition node by name (multi-language).
///
/// Accepts either a bare function name (`run`) or a qualified
/// `Class.method` form (`Flask.run`). When a qualified name is given:
///   1. Locate the class via [`find_class_node_contracts`].
///   2. Search the method inside the class subtree.
///   3. If the class is missing or the method is not inside it, fall
///      back to resolving the LAST component as a bare name across the
///      whole AST.
fn find_function_node<'a>(
    root: Node<'a>,
    function_name: &str,
    source: &[u8],
    config: &LanguageConfig,
) -> Option<Node<'a>> {
    if function_name.contains('.') {
        let parts: Vec<&str> = function_name.split('.').collect();
        if parts.len() >= 2 {
            let class_name = parts[0];
            let remainder = parts[1..].join(".");
            if let Some(class_node) = find_class_node_contracts(root, class_name, source) {
                let scope = class_node
                    .child_by_field_name("body")
                    .unwrap_or(class_node);
                if let Some(found) =
                    find_function_recursive(scope, &remainder, source, config, 0)
                {
                    return Some(found);
                }
            }
            // Fallback: bare-name lookup with the last component.
            let last = *parts.last().unwrap();
            return find_function_recursive(root, last, source, config, 0);
        }
    }
    // context-file-func-cross-lang-and-cpp-qualified-v1 (P14.AGG14-3):
    // Accept C++ `Class::method` qualified form. The C++ extractor
    // stores the bare last segment for both inline class methods and
    // out-of-class definitions (`void XMLDocument::Parse(...) {...}`),
    // so we descend into the matching class scope first and fall back
    // to a bare-name search using the rightmost `::`-separated segment.
    if function_name.contains("::") {
        let parts: Vec<&str> = function_name.split("::").collect();
        if parts.len() >= 2 {
            let class_name = parts[0];
            let remainder = parts[1..].join("::");
            if let Some(class_node) = find_class_node_contracts(root, class_name, source) {
                let scope = class_node
                    .child_by_field_name("body")
                    .unwrap_or(class_node);
                if let Some(found) =
                    find_function_recursive(scope, &remainder, source, config, 0)
                {
                    return Some(found);
                }
            }
            let last = *parts.last().unwrap();
            return find_function_recursive(root, last, source, config, 0);
        }
    }
    // Recursive search through the entire AST
    find_function_recursive(root, function_name, source, config, 0)
}

/// Locate a class/struct/trait/interface container by name. Used to
/// scope `Class.method` lookups in [`find_function_node`].
fn find_class_node_contracts<'a>(
    root: Node<'a>,
    class_name: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    const CLASS_KINDS: &[&str] = &[
        "class_definition",
        "class_declaration",
        "class",
        "interface_declaration",
        "struct_item",
        "enum_item",
        "trait_item",
        "impl_item",
        "union_item",
        "class_specifier",
        "struct_specifier",
        "union_specifier",
        "enum_declaration",
        "record_declaration",
        "trait_declaration",
        "struct_declaration",
        "object_declaration",
        "object_definition",
        "trait_definition",
        "protocol_declaration",
        "extension_declaration",
        "module",
    ];

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if CLASS_KINDS.contains(&node.kind()) {
            let name_match = node.child_by_field_name("name").is_some_and(|n| {
                get_node_text(n, source) == class_name
            });
            if name_match {
                return Some(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "constant"
                ) {
                    if get_node_text(child, source) == class_name {
                        return Some(node);
                    }
                    break;
                }
            }
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Recursively search for a function node by name.
fn find_function_recursive<'a>(
    node: Node<'a>,
    function_name: &str,
    source: &[u8],
    config: &LanguageConfig,
    depth: usize,
) -> Option<Node<'a>> {
    if depth > MAX_AST_DEPTH {
        return None;
    }

    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if config.is_function(child.kind()) {
            // Elixir: call nodes where target is "def"/"defp" — name is in arguments
            if child.kind() == "call" {
                if let Some(target) = child.child_by_field_name("target") {
                    let target_text = get_node_text(target, source);
                    if target_text == "def" || target_text == "defp" {
                        // The function name is the first child of the arguments.
                        // Two surface syntaxes are common:
                        //   * `def name, do: expr` — args.child(0) is the
                        //     identifier `name` (or a `call` node wrapping
                        //     it when params are present).
                        //   * `def name do ... end` — the WHOLE
                        //     `name do ... end` is itself a `call` node
                        //     whose target is `name` and whose body is a
                        //     `do_block`. tree-sitter-elixir places this
                        //     `call` as args.child(0), but field "arguments"
                        //     may be absent on the outer `def` call when
                        //     the body is a do-block; in that case the
                        //     `do_block` is the `call`'s OWN child, not
                        //     under "arguments". Fall back to scanning all
                        //     children for any nested identifier/call.
                        let extracted_name = extract_elixir_def_name(child, source);
                        if let Some(name) = extracted_name {
                            if name == function_name {
                                return Some(child);
                            }
                        }
                    }
                }
            }

            // OCaml: value_definition -> let_binding -> pattern field
            if child.kind() == "value_definition" {
                let mut inner = child.walk();
                for sub in child.children(&mut inner) {
                    if sub.kind() == "let_binding" {
                        if let Some(pattern_node) = sub.child_by_field_name("pattern") {
                            let name = get_node_text(pattern_node, source);
                            if name == function_name {
                                return Some(child);
                            }
                        }
                    }
                }
            }

            // Try the configured name field first
            if let Some(name_node) = child.child_by_field_name(config.func_name_field) {
                let name = get_node_text(name_node, source);
                // For C/C++, the declarator field may be a function_declarator wrapping the name
                if name == function_name {
                    return Some(child);
                }
                // Check if the name_node contains the function name (e.g., C declarators)
                if name.contains(function_name) {
                    // Verify it's an exact name match by checking for identifier child
                    if let Some(found) = find_identifier_match(name_node, function_name, source) {
                        let _ = found; // We found the match
                        return Some(child);
                    }
                }
            }
            // Fallback: search for identifier children directly
            if find_name_in_children(child, function_name, source) {
                return Some(child);
            }
        }

        // Check for arrow functions in variable declarations (TS/JS pattern):
        // lexical_declaration / variable_declaration -> variable_declarator -> name + value(arrow_function)
        if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            let mut decl_cursor = child.walk();
            for decl_child in child.children(&mut decl_cursor) {
                if decl_child.kind() == "variable_declarator" {
                    if let Some(name_node) = decl_child.child_by_field_name("name") {
                        let var_name = get_node_text(name_node, source);
                        if var_name == function_name {
                            if let Some(value_node) = decl_child.child_by_field_name("value") {
                                if matches!(
                                    value_node.kind(),
                                    "arrow_function"
                                        | "function"
                                        | "function_expression"
                                        | "generator_function"
                                ) {
                                    return Some(value_node);
                                }
                            }
                        }
                    }
                }
            }
        }

        // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS function-expression
        // assignments. CommonJS / prototype patterns:
        //   app.use = function() {}
        //   Foo.prototype.bar = function() {}
        //   handler = () => {}
        // tree-sitter-javascript wraps the assignment in
        // `expression_statement -> assignment_expression`. The function body is
        // the right-hand side of the assignment_expression.
        if child.kind() == "assignment_expression" {
            if let (Some(left), Some(right)) = (
                child.child_by_field_name("left"),
                child.child_by_field_name("right"),
            ) {
                let target_name = match left.kind() {
                    "identifier" => Some(get_node_text(left, source).to_string()),
                    "member_expression" => left
                        .child_by_field_name("property")
                        .map(|p| get_node_text(p, source).to_string()),
                    _ => None,
                };
                if let Some(name) = target_name {
                    if name == function_name
                        && matches!(
                            right.kind(),
                            "arrow_function"
                                | "function"
                                | "function_expression"
                                | "generator_function"
                        )
                    {
                        return Some(right);
                    }
                }
            }
        }

        // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS object literal pair —
        //   { foo: function() {} } / { foo: () => {} }
        if child.kind() == "pair" {
            if let (Some(key), Some(value)) = (
                child.child_by_field_name("key"),
                child.child_by_field_name("value"),
            ) {
                let key_name = match key.kind() {
                    "property_identifier" | "identifier" => {
                        get_node_text(key, source).to_string()
                    }
                    "string" => get_node_text(key, source)
                        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                        .to_string(),
                    _ => String::new(),
                };
                if key_name == function_name
                    && matches!(
                        value.kind(),
                        "arrow_function"
                            | "function"
                            | "function_expression"
                            | "generator_function"
                    )
                {
                    return Some(value);
                }
            }
        }

        // Search inside class/struct/impl containers
        if config.is_class(child.kind()) {
            if let Some(body) = child.child_by_field_name(config.class_body_field) {
                if let Some(found) =
                    find_function_recursive(body, function_name, source, config, depth + 1)
                {
                    return Some(found);
                }
            }
            // Also try searching directly in the class node
            if let Some(found) =
                find_function_recursive(child, function_name, source, config, depth + 1)
            {
                return Some(found);
            }
        }

        // For languages with nested scopes, wrappers, and exports
        if child.kind() == "block"
            || child.kind() == "declaration_list"
            || child.kind() == "module"
            || child.kind() == "source_file"
            || child.kind() == "program"
            || child.kind() == "compound_statement"
            || child.kind() == "export_statement"
            || child.kind() == "export_default_declaration"
            || child.kind() == "decorated_definition"
            || child.kind() == "namespace_declaration"
            || child.kind() == "module_declaration"
            || child.kind() == "class_body"
            || child.kind() == "enum_body"
            || child.kind() == "translation_unit"
            || child.kind() == "do_block"            // Elixir do/end blocks
            || child.kind() == "stab_clause"         // Elixir fn -> clauses
            || child.kind() == "body"                // Elixir/OCaml body nodes
            || child.kind() == "arguments"           // Elixir defmodule arguments
            || child.kind() == "structure"           // OCaml module structures
            || child.kind() == "structure_item"      // OCaml top-level items
            || child.kind() == "module_definition"   // OCaml module/functor defs
            || child.kind() == "module_binding"      // OCaml module binding
            || child.kind() == "functor"             // OCaml functors
            // C/C++ preprocessor branch nodes — tree-sitter-cpp wraps `#if`/
            // `#elif`/`#else` content in these, and `static inline` functions
            // defined inside (e.g. tinyxml2.cpp:65 `TIXML_SNPRINTF`) are
            // otherwise skipped by the recursive walk. real-repo-fixes-v1
            // (P9.BUG-R1).
            || child.kind() == "preproc_if"
            || child.kind() == "preproc_ifdef"
            || child.kind() == "preproc_else"
            || child.kind() == "preproc_elif"
            || child.kind() == "preproc_elifdef"
            || child.kind() == "linkage_specification" // extern "C" { ... }
            || child.kind() == "namespace_definition"  // C++ namespace { ... }
            // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS wraps top-level
            // CommonJS-style assignments (`app.foo = function(){}`) in
            // `expression_statement -> assignment_expression`. The bare
            // `assignment_expression` and `pair` cases are matched directly
            // above; descend into `expression_statement` and `object` so the
            // recursion reaches them.
            || child.kind() == "expression_statement"
            || child.kind() == "object"
        {
            if let Some(found) =
                find_function_recursive(child, function_name, source, config, depth + 1)
            {
                return Some(found);
            }
        }
    }

    None
}

/// Check if a node contains an identifier matching the function name.
fn find_identifier_match<'a>(
    node: Node<'a>,
    function_name: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    if node.kind() == "identifier" || node.kind() == "name" {
        let text = get_node_text(node, source);
        if text == function_name {
            return Some(node);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_identifier_match(child, function_name, source) {
            return Some(found);
        }
    }
    None
}

/// Check if any direct child identifiers match the function name.
fn find_name_in_children(func_node: Node, function_name: &str, source: &[u8]) -> bool {
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if (child.kind() == "identifier" || child.kind() == "name")
            && get_node_text(child, source) == function_name
        {
            return true;
        }
    }
    false
}

/// Extract the function name from an Elixir `def`/`defp` call node.
///
/// Handles both surface syntaxes:
/// * `def name, do: expr` — args.child(0) is the bare identifier (or a
///   `call` wrapping it when params are present).
/// * `def name do ... end` — args.child(0) is the bare identifier `name`,
///   and the `do_block` is a separate sibling of the outer `def` call
///   (NOT under the `arguments` field). tree-sitter-elixir does not
///   expose `arguments` as a named field on the outer `def` call, so we
///   locate the arguments node by kind among direct children.
fn extract_elixir_def_name(def_call: Node, source: &[u8]) -> Option<String> {
    // tree-sitter-elixir does NOT expose "arguments" as a named field on
    // the outer `def` call (only as a child of kind=arguments). Locate
    // the arguments node by kind among direct children.
    let mut args_node: Option<Node> = None;
    let mut cursor = def_call.walk();
    for c in def_call.children(&mut cursor) {
        if c.kind() == "arguments" {
            args_node = Some(c);
            break;
        }
    }
    if let Some(args) = args_node {
        if let Some(first_arg) = args.child(0) {
            // Bare identifier — common case for `def main do ... end`.
            if first_arg.kind() == "identifier" {
                return Some(get_node_text(first_arg, source).to_string());
            }
            // `call` wrapping it — `def name(arg1, arg2), do: ...`.
            if first_arg.kind() == "call" {
                if let Some(target) = first_arg.child_by_field_name("target") {
                    return Some(get_node_text(target, source).to_string());
                }
            }
            // Guard syntax: `def foo(x) when ..., do: ...` — args.child(0)
            // is a `binary_operator` whose LHS holds the function name.
            if first_arg.kind() == "binary_operator" {
                if let Some(lhs) = first_arg.child(0) {
                    if lhs.kind() == "identifier" {
                        return Some(get_node_text(lhs, source).to_string());
                    }
                    if lhs.kind() == "call" {
                        if let Some(target) = lhs.child_by_field_name("target") {
                            return Some(get_node_text(target, source).to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Find the first identifier or name node among direct children.
fn find_first_identifier(node: Node) -> Option<Node> {
    // Direct identifier child fast path.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "name" {
            return Some(child);
        }
    }
    // verification-and-metrics-completeness-v1 (P12.AGG12-11): C / C++
    // parameter declarations wrap the parameter name in a sequence of
    // declarator nodes — `pointer_declarator`, `array_declarator`,
    // `parenthesized_declarator`, `init_declarator` — depending on the
    // parameter's type (e.g. `const char *init` -> pointer_declarator >
    // identifier). Recurse through these wrappers so the parameter name is
    // recovered (without this, `tldr contracts c-sds/sds.c sdsnew`
    // returned an empty preconditions list).
    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        match child.kind() {
            "pointer_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "init_declarator"
            | "function_declarator"
            | "abstract_pointer_declarator"
            | "reference_declarator" => {
                if let Some(found) = find_first_identifier(child) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Get text content of a node.
fn get_node_text<'a>(node: Node<'a>, source: &'a [u8]) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() {
        std::str::from_utf8(&source[start..end]).unwrap_or("")
    } else {
        ""
    }
}

/// Get the function body node.
/// solidity-sol016-cluster-v1 M14: peel a Solidity `statement` wrapper.
///
/// The tree-sitter-solidity grammar wraps every concrete statement
/// (expression_statement, if_statement, revert_statement, ...) inside a
/// `statement` named node. The contracts extractor's per-language `kind`
/// dispatch checks the concrete kind, so we must unwrap before
/// inspecting. For all other languages, function-body children are
/// already the concrete statement nodes and this helper is a no-op.
fn unwrap_solidity_statement(node: Node<'_>) -> Node<'_> {
    if node.kind() != "statement" {
        return node;
    }
    // Solidity `statement` is required to have exactly one named child
    // (the concrete statement). Walk named children; if exactly one
    // exists, return it; else fall back to the wrapper to remain a
    // no-op on grammar drift.
    let mut cursor = node.walk();
    let mut found: Option<Node<'_>> = None;
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        if found.is_some() {
            return node;
        }
        found = Some(child);
    }
    found.unwrap_or(node)
}

/// R7 RC1 (invariants-specs cluster): peel a Swift `statements` body wrapper.
///
/// tree-sitter-swift's `function_body` wraps every top-level body statement in
/// an intermediate `statements` named node:
///   function_declaration -> function_body{`{`, statements{call_expression,
///   property_declaration, control_transfer_statement, ...}, `}`}
///
/// The contracts extractors (extract_preconditions / extract_postconditions /
/// extract_invariants) iterate the DIRECT children of the body returned by
/// `get_function_body`, so without this unwrap they only ever see `{`, the
/// `statements` wrapper, and `}` — never the real `call_expression`/guard
/// statements. As a result Swift `precondition()`/`assert()`/`guard` were
/// invisible and preconditions were always empty.
///
/// Swift is the only supported language whose function body interposes a
/// `statements` node, so gating on `kind() == "statements"` is naturally
/// language-safe and a no-op everywhere else. When the wrapper is absent (or
/// the grammar drifts) the original body node is returned unchanged.
fn unwrap_statements_wrapper(body: Node<'_>) -> Node<'_> {
    let mut cursor = body.walk();
    let mut stmts: Option<Node<'_>> = None;
    for child in body.children(&mut cursor) {
        if child.kind() == "statements" {
            if stmts.is_some() {
                // More than one `statements` child: unexpected grammar shape,
                // stay a no-op rather than guess.
                return body;
            }
            stmts = Some(child);
        }
    }
    stmts.unwrap_or(body)
}

fn get_function_body<'a>(func: Node<'a>, config: &LanguageConfig) -> Option<Node<'a>> {
    // Try the configured field name first
    if let Some(body) = func.child_by_field_name(config.func_body_field) {
        // If the body node has a "block" child, prefer that (e.g., Swift function_body -> block)
        if let Some(block) = body.child_by_field_name("body") {
            return Some(unwrap_statements_wrapper(block));
        }
        return Some(unwrap_statements_wrapper(body));
    }

    // Fallback: search for common body node kinds among children
    // This handles Kotlin where function_body is a child node (not a named field)
    let mut cursor = func.walk();
    for child in func.children(&mut cursor) {
        let kind = child.kind();
        if kind == "function_body" || kind == "block" || kind == "compound_statement" {
            // For function_body wrappers, look inside for a block
            if kind == "function_body" {
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "block" {
                        return Some(unwrap_statements_wrapper(inner_child));
                    }
                }
                // If no block inside function_body, return function_body itself
                return Some(unwrap_statements_wrapper(child));
            }
            return Some(unwrap_statements_wrapper(child));
        }
    }

    None
}

// =============================================================================
// Precondition Extraction
// =============================================================================

/// Collect the identifier/name leaf texts referenced anywhere under `node`
/// (AST-driven, no regex). Skips the implicit-receiver names self/cls/this.
///
/// Used so the entry-precondition scope test can compare the names an assert
/// condition references against the parameter set and the body-local
/// definition map.
fn collect_identifier_names(node: Node, source: &[u8], out: &mut HashSet<String>) {
    let kind = node.kind();
    if kind == "identifier" || kind == "name" {
        let text = get_node_text(node, source);
        if text != "self" && text != "cls" && text != "this" {
            out.insert(text.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifier_names(child, source, out);
    }
}

/// Collect the formal-parameter identifier names of `func` (AST-driven).
///
/// Reuses [`collect_value_param_clauses`] (which already handles Scala
/// currying, C/C++ `function_declarator`, and Swift `body`-field params) and
/// harvests the parameter identifiers from each clause, preferring the
/// `name`/`pattern` field of typed-parameter nodes and otherwise taking bare
/// `identifier`/`name` children. Type-annotation subtrees are not descended.
fn collect_param_names(func: Node, source: &[u8], config: &LanguageConfig) -> HashSet<String> {
    let mut params = HashSet::new();
    for clause in collect_value_param_clauses(func, config) {
        collect_param_identifiers(clause, source, config, &mut params);
    }
    params
}

/// Recursive worker for [`collect_param_names`].
fn collect_param_identifiers(
    node: Node,
    source: &[u8],
    config: &LanguageConfig,
    out: &mut HashSet<String>,
) {
    // C/C++ `function_declarator` mixes the function-name identifier with the
    // parameter list — descend only into the parameter list (mirrors
    // `extract_untyped_params_recursive`).
    if node.kind() == "function_declarator" {
        if let Some(plist) = node.child_by_field_name("parameters") {
            collect_param_identifiers(plist, source, config, out);
            return;
        }
        let mut local = node.walk();
        for child in node.children(&mut local) {
            if child.kind() == "parameter_list" {
                collect_param_identifiers(child, source, config, out);
                return;
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if config.typed_param_kinds.contains(&kind) {
            let name_node = child
                .child_by_field_name("name")
                .or_else(|| child.child_by_field_name("pattern"))
                .or_else(|| find_first_identifier(child));
            if let Some(n) = name_node {
                let t = get_node_text(n, source);
                if t != "self" && t != "cls" && t != "this" {
                    out.insert(t.to_string());
                }
            }
        } else if kind == "identifier" || kind == "name" {
            let t = get_node_text(child, source);
            if t != "self" && t != "cls" && t != "this" {
                out.insert(t.to_string());
            }
        } else if kind == "default_parameter" || kind == "optional_parameter" {
            if let Some(n) = child.child_by_field_name("name") {
                out.insert(get_node_text(n, source).to_string());
            }
        } else if !kind.contains("type") && kind != "(" && kind != ")" && kind != "," && kind != ":"
        {
            // Nested grouping (tuple patterns / parameter sublists). Descend,
            // but never into a type-annotation subtree.
            collect_param_identifiers(child, source, config, out);
        }
    }
}

/// Build the body-local definition map: for every name (re)assigned inside
/// `body`, record the earliest 1-based line of its assignment.
///
/// Names absent from this map are entry-state (formal parameters / receiver
/// fields / globals); names present are body-locals. This is the single linear
/// def-order pass the entry-vs-body decision needs (no CFG/dominance).
fn collect_first_assignments(
    node: Node,
    source: &[u8],
    config: &LanguageConfig,
    out: &mut HashMap<String, u32>,
) {
    if config.is_assignment(node.kind()) {
        record_assignment_targets(node, source, out);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_first_assignments(child, source, config, out);
    }
}

/// Record the left-hand target identifier(s) of a single assignment node into
/// `out`, keyed on the earliest assignment line. Only the assignment *target*
/// (left/pattern/name field, or the syntax left of the first `=`/`:=` token)
/// is harvested — never the right-hand side — so a parameter used on the RHS is
/// not mistaken for a body-local.
fn record_assignment_targets(node: Node, source: &[u8], out: &mut HashMap<String, u32>) {
    let line = node.start_position().row as u32 + 1;
    let mut targets: Vec<Node> = Vec::new();

    // Prefer splitting on the assignment operator: this captures EVERY left-
    // hand target (`local a, b = ...`) where a `name`/`left` field would expose
    // only the first. Match the (augmented-)assignment tokens, never the
    // comparison operators (`==`, `~=`, `<=`, ...).
    let mut op_byte: Option<usize> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named()
            && matches!(
                child.kind(),
                "=" | ":=" | "+=" | "-=" | "*=" | "/=" | "%=" | "//=" | "..=" | "^=" | "|=" | "&="
            )
        {
            op_byte = Some(child.start_byte());
            break;
        }
    }
    if let Some(ob) = op_byte {
        let mut c2 = node.walk();
        for child in node.children(&mut c2) {
            if child.is_named() && child.start_byte() < ob {
                targets.push(child);
            }
        }
    } else if let Some(left) = node.child_by_field_name("left") {
        targets.push(left);
    } else if let Some(pat) = node.child_by_field_name("pattern") {
        targets.push(pat);
    } else if let Some(name) = node.child_by_field_name("name") {
        targets.push(name);
    }
    for t in targets {
        let mut ids = HashSet::new();
        collect_identifier_names(t, source, &mut ids);
        for name in ids {
            out.entry(name)
                .and_modify(|l| {
                    if line < *l {
                        *l = line;
                    }
                })
                .or_insert(line);
        }
    }
}

/// Decide whether an assert whose condition references `referenced` (at 1-based
/// `line`) expresses an *entry* precondition rather than an in-body assertion.
///
/// A name is entry-state when it is a formal parameter (`params`) or is never
/// assigned in the body (receiver field / global — absent from `first_assign`).
/// A name that is a body-local assigned at or before the assert is NOT entry
/// state, so the assert is an in-body assertion and must not be surfaced as a
/// precondition (R2/R3: a body-local does not exist at entry).
fn is_entry_precondition(
    referenced: &HashSet<String>,
    line: u32,
    params: &HashSet<String>,
    first_assign: &HashMap<String, u32>,
) -> bool {
    for name in referenced {
        if params.contains(name) {
            continue;
        }
        if let Some(&def_line) = first_assign.get(name) {
            if line >= def_line {
                return false;
            }
        }
    }
    true
}

/// Emit assert-derived preconditions from a single statement node (the
/// assert/call branches of [`extract_preconditions`], factored out so the
/// guard-if consequence descent (Piece 2) can reuse them). The guard-clause
/// (throw-negation) branch is intentionally NOT included here.
fn collect_asserts_from_stmt(
    stmt: Node,
    source: &[u8],
    config: &LanguageConfig,
    params: &HashSet<String>,
    first_assign: &HashMap<String, u32>,
    out: &mut Vec<Condition>,
) {
    let kind = stmt.kind();
    if config.is_assert(kind) {
        if let Some(cond) = precondition_from_assert(stmt, source, config, params, first_assign) {
            out.push(cond);
        }
    } else if config.assert_is_macro && kind == "expression_statement" {
        let mut inner = stmt.walk();
        for child in stmt.children(&mut inner) {
            if config.is_assert(child.kind()) {
                if let Some(cond) =
                    precondition_from_assert(child, source, config, params, first_assign)
                {
                    out.push(cond);
                }
            }
        }
    } else if config.has_assert_calls() && config.is_call(kind) {
        if let Some(cond) =
            precondition_from_assert_call(stmt, source, config, params, first_assign)
        {
            out.push(cond);
        }
    } else if config.has_assert_calls() && kind == "expression_statement" {
        let mut inner = stmt.walk();
        for child in stmt.children(&mut inner) {
            let candidate = if child.kind() == "expression" {
                let mut inner_cursor = child.walk();
                let found = child
                    .children(&mut inner_cursor)
                    .find(|c| config.is_call(c.kind()));
                found.unwrap_or(child)
            } else {
                child
            };
            if config.is_call(candidate.kind()) {
                if let Some(cond) =
                    precondition_from_assert_call(candidate, source, config, params, first_assign)
                {
                    out.push(cond);
                }
            }
        }
    }
}

/// Locate the unconditional then-branch (`consequence`) node of a guard-if.
///
/// Most grammars expose it via `config.if_consequence_field`. Some (e.g.
/// tree-sitter-kotlin-ng) attach the then-block as an UNLABELED child, so fall
/// back to the first wrapper-kind child that is neither the condition nor the
/// `alternative` (else/elseif) arm — which, by grammar order, is the then-block.
fn guard_consequence_node<'a>(stmt: Node<'a>, config: &LanguageConfig) -> Option<Node<'a>> {
    if let Some(c) = stmt.child_by_field_name(config.if_consequence_field) {
        return Some(c);
    }
    let mut idx = 0u32;
    let mut cursor = stmt.walk();
    for child in stmt.children(&mut cursor) {
        let fname = stmt.field_name_for_child(idx);
        idx += 1;
        if fname == Some(config.if_condition_field) || fname == Some(config.if_alternative_field) {
            continue;
        }
        if matches!(child.kind(), "block" | "statements" | "control_structure_body") {
            return Some(child);
        }
    }
    None
}

/// Walk a guard-if `consequence` for top-level assert/call statements (Piece 2,
/// facet a). Wrapper nodes (`block` / `statements` / `control_structure_body`,
/// e.g. Kotlin/Swift) are unwrapped so the assert is reached, but nested
/// `if`/loop bodies are NOT descended (they are conditional, not unconditional-
/// entry guards) — `collect_asserts_from_stmt` simply ignores those kinds.
fn collect_guard_consequence_asserts(
    node: Node,
    source: &[u8],
    config: &LanguageConfig,
    params: &HashSet<String>,
    first_assign: &HashMap<String, u32>,
    out: &mut Vec<Condition>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        if matches!(child.kind(), "block" | "statements" | "control_structure_body") {
            collect_guard_consequence_asserts(child, source, config, params, first_assign, out);
        } else {
            let stmt = unwrap_solidity_statement(child);
            collect_asserts_from_stmt(stmt, source, config, params, first_assign, out);
        }
    }
}

/// Extract preconditions from guard clauses and assertions (multi-language).
fn extract_preconditions(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    skip_lines: &HashSet<u32>,
    depth: usize,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    check_ast_depth(depth, &PathBuf::from("<source>"))?;

    let body = match get_function_body(func, config) {
        Some(b) => b,
        None => return Ok(()),
    };

    // Per-function scope/order context (root-cause dataflow the Condition
    // struct never carried): the formal-parameter set and the earliest line on
    // which each name is (re)assigned in the body. These drive the
    // entry-precondition-vs-body-assertion decision inside the assert emitters.
    let params = collect_param_names(func, source, config);
    let mut first_assign: HashMap<String, u32> = HashMap::new();
    collect_first_assignments(body, source, config, &mut first_assign);

    let mut cursor = body.walk();
    for raw_stmt in body.children(&mut cursor) {
        // solidity-sol016-cluster-v1 M14: Solidity wraps every concrete
        // statement (expression_statement, if_statement, return_statement,
        // revert_statement, ...) inside a `statement` named node. Peel
        // that wrapper here so the downstream `kind` checks see the
        // concrete statement kind. For other languages the wrapper does
        // not exist; `unwrap_solidity_statement` is a no-op when there
        // is exactly zero or more than one named child or the node kind
        // is not `statement`.
        let stmt = unwrap_solidity_statement(raw_stmt);
        let line = stmt.start_position().row as u32 + 1;

        // Skip lines already used for postconditions
        if skip_lines.contains(&line) {
            continue;
        }

        let kind = stmt.kind();

        if config.is_if(kind) {
            // Pattern: if <cond>: raise/throw/panic ...
            if body_contains_throw(stmt, source, config) {
                if let Some(cond) = precondition_from_guard(stmt, source, config) {
                    conditions.push(cond);
                }
            }
            // Piece 2 (facet a): param-asserts-only descent into a leading
            // guard-if `consequence` block, INDEPENDENT of `body_contains_throw`.
            // A leading `if cfg then assert(param ...) end` lifts its parameter
            // asserts to entry preconditions. Key on node KIND `if_statement`
            // (already true here via `config.is_if`); descend ONLY the
            // unconditional `consequence` (never `alternative` / elseif/else);
            // a missing/empty consequence yields `None` and is skipped. The
            // Piece-1 scope/order predicate inside the emitters guarantees only
            // genuine PARAM asserts survive, so body-locals nested in the guard
            // are still dropped.
            if let Some(consequence) = guard_consequence_node(stmt, config) {
                collect_guard_consequence_asserts(
                    consequence,
                    source,
                    config,
                    &params,
                    &first_assign,
                    conditions,
                );
            }
        } else if config.is_assert(kind) {
            // Pattern: assert <expr> / assert!(<expr>)
            if let Some(cond) =
                precondition_from_assert(stmt, source, config, &params, &first_assign)
            {
                conditions.push(cond);
            }
        } else if config.assert_is_macro && kind == "expression_statement" {
            // For Rust: both assert!() and if_expression appear wrapped in expression_statement.
            //
            // assert!() -> expression_statement > macro_invocation
            // if x < 0 { return Err(...); } -> expression_statement > if_expression
            //
            // The if_expression case is the guard clause pattern using `return Err(...)`.
            let mut inner = stmt.walk();
            for child in stmt.children(&mut inner) {
                if config.is_assert(child.kind()) {
                    if let Some(cond) =
                        precondition_from_assert(child, source, config, &params, &first_assign)
                    {
                        conditions.push(cond);
                    }
                } else if config.is_if(child.kind()) {
                    // Guard clause: if <cond> { return Err(...) } or if <cond> { panic!(...) }
                    if body_contains_throw(child, source, config) {
                        if let Some(cond) = precondition_from_guard(child, source, config) {
                            conditions.push(cond);
                        }
                    }
                }
            }
        } else if config.has_assert_calls() && config.is_call(kind) {
            // Pattern: require(cond), check(cond), assert(cond), precondition(cond)
            // These are call expressions that act as assertions (Kotlin, Swift, Luau)
            if let Some(cond) =
                precondition_from_assert_call(stmt, source, config, &params, &first_assign)
            {
                conditions.push(cond);
            }
        } else if config.has_assert_calls() && kind == "expression_statement" {
            // Call expressions may be wrapped in expression_statement.
            // For Solidity the wrapping is two-deep:
            //   expression_statement > expression > call_expression
            // The walk below unwraps one extra `expression` layer when
            // present.
            let mut inner = stmt.walk();
            for child in stmt.children(&mut inner) {
                let candidate = if child.kind() == "expression" {
                    // Solidity: peel the `expression` wrapper to find
                    // the inner call_expression.
                    let mut inner_cursor = child.walk();
                    let found = child
                        .children(&mut inner_cursor)
                        .find(|c| config.is_call(c.kind()));
                    found.unwrap_or(child)
                } else {
                    child
                };
                if config.is_call(candidate.kind()) {
                    if let Some(cond) = precondition_from_assert_call(
                        candidate,
                        source,
                        config,
                        &params,
                        &first_assign,
                    ) {
                        conditions.push(cond);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Extract precondition from a call expression that acts as an assertion.
///
/// Pattern: `require(x >= 0)` -> precondition: `x >= 0` (Kotlin)
/// Pattern: `precondition(x >= 0, "msg")` -> precondition: `x >= 0` (Swift)
/// Pattern: `assert(x >= 0, "msg")` -> precondition: `x >= 0` (Luau)
/// Pattern: `require(x >= 0, "Positive only")` -> precondition with
///   variable=`x >= 0`, constraint=`"x >= 0: Positive only"` (Solidity).
fn precondition_from_assert_call(
    call_node: Node,
    source: &[u8],
    config: &LanguageConfig,
    params: &HashSet<String>,
    first_assign: &HashMap<String, u32>,
) -> Option<Condition> {
    let call_name = extract_call_name(call_node, source)?;
    if !config.is_assert_call_name(&call_name) {
        return None;
    }
    let line = call_node.start_position().row as u32 + 1;

    // Extract the first argument as the condition
    let first_arg = extract_first_call_argument(call_node, source)?;
    let arg_text = first_arg.trim().to_string();

    if arg_text.is_empty() {
        return None;
    }

    // Root-cause entry-vs-body discrimination: an assert that references a
    // body-local defined at or before it is an in-body assertion, NOT an entry
    // contract — drop it (R3: relabel/drop, never a confidence downgrade, since
    // verify's coverage metric counts presence not confidence). When the first
    // argument node cannot be located the referenced set is empty and the
    // assert is kept (conservative, no regression).
    if let Some(arg_node) = first_call_argument_node(call_node) {
        let mut referenced = HashSet::new();
        collect_identifier_names(arg_node, source, &mut referenced);
        if !is_entry_precondition(&referenced, line, params, first_assign) {
            return None;
        }
    }

    // solidity-sol016-cluster-v1 M14: when a second string-literal
    // argument is present (Solidity `require(cond, "msg")`), splice
    // the message text into the constraint so the human-readable
    // reason is preserved on the precondition surface.
    let message = extract_second_call_string_argument(call_node, source);
    let constraint = match message {
        Some(msg) if !msg.is_empty() => format!("{}: {}", arg_text, msg),
        _ => arg_text.clone(),
    };

    Some(Condition::high(arg_text, constraint, line))
}

/// solidity-sol016-cluster-v1 M14: extract the second argument's
/// string-literal text from a call expression, with surrounding quotes
/// stripped. Returns `None` when the second argument is absent or is
/// not a string literal.
fn extract_second_call_string_argument(call_node: Node, source: &[u8]) -> Option<String> {
    // Solidity: call_expression has direct `call_argument` named
    // children. Walk and return the second one's inner literal text.
    let mut cursor = call_node.walk();
    let mut idx = 0;
    for child in call_node.children(&mut cursor) {
        if child.kind() == "call_argument" {
            idx += 1;
            if idx == 2 {
                // Walk the call_argument's children for a string-shaped node.
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    let txt = get_node_text(inner_child, source);
                    if inner_child.kind() == "string"
                        || inner_child.kind() == "string_literal"
                        || (txt.starts_with('"') && txt.ends_with('"'))
                        || (txt.starts_with('\'') && txt.ends_with('\''))
                    {
                        return Some(
                            txt.trim_matches('"')
                                .trim_matches('\'')
                                .to_string(),
                        );
                    }
                }
                // Otherwise: try the call_argument text directly.
                let txt = get_node_text(child, source);
                let trimmed = txt.trim();
                if (trimmed.starts_with('"') && trimmed.ends_with('"'))
                    || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                {
                    return Some(
                        trimmed
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string(),
                    );
                }
                return None;
            }
        }
    }
    None
}

/// Extract the name of a function being called.
fn extract_call_name(call_node: Node, source: &[u8]) -> Option<String> {
    // Try "function" field first (many languages)
    if let Some(func) = call_node.child_by_field_name("function") {
        return Some(get_node_text(func, source).to_string());
    }

    // Try "name" field (Luau function_call)
    if let Some(name) = call_node.child_by_field_name("name") {
        return Some(get_node_text(name, source).to_string());
    }

    // Fallback: first child that looks like an identifier or navigation_expression
    let mut cursor = call_node.walk();
    for child in call_node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "identifier" || kind == "simple_identifier" || kind == "name" {
            return Some(get_node_text(child, source).to_string());
        }
        // For navigation expressions like obj.method, get the full text
        if kind == "navigation_expression" {
            return Some(get_node_text(child, source).to_string());
        }
    }

    None
}

/// Extract the first argument text from a call expression.
fn extract_first_call_argument(call_node: Node, source: &[u8]) -> Option<String> {
    // Try "arguments" field first
    if let Some(args) = call_node.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for arg in args.children(&mut cursor) {
            let kind = arg.kind();
            if kind != "(" && kind != ")" && kind != "," && kind != "{" && kind != "}" {
                return Some(get_node_text(arg, source).to_string());
            }
        }
    }

    // solidity-sol016-cluster-v1 M14: Solidity call_expression has
    // direct named `call_argument` children (not a wrapper arguments
    // node). Walk the call_node's children and return the first
    // `call_argument`'s inner expression.
    let mut cursor = call_node.walk();
    for child in call_node.children(&mut cursor) {
        if child.kind() == "call_argument" {
            // call_argument wraps an `expression` named child.
            let mut inner = child.walk();
            for inner_child in child.children(&mut inner) {
                if inner_child.is_named() {
                    return Some(get_node_text(inner_child, source).to_string());
                }
            }
            // Fallback to raw text of the call_argument
            return Some(get_node_text(child, source).to_string());
        }
    }

    // For Kotlin: call_expression has children [expression, value_arguments]
    // For Swift: call_expression has children [expression, call_suffix],
    //   and call_suffix wraps the real `value_arguments`:
    //   call_suffix -> value_arguments -> ( value_argument ... )
    //   so descend one level into the `value_arguments` before scanning args,
    //   otherwise the whole "(!isEmpty, \"msg\")" arg list is returned and the
    //   diagnostic message string leaks into the extracted condition.
    let mut cursor = call_node.walk();
    for raw_child in call_node.children(&mut cursor) {
        let raw_kind = raw_child.kind();
        if raw_kind == "value_arguments" || raw_kind == "call_suffix" || raw_kind == "argument_list"
        {
            // Swift: unwrap call_suffix -> value_arguments. For Kotlin the
            // value_arguments node is already the direct child, so this is a
            // no-op (no nested value_arguments to find).
            let child = if raw_kind == "call_suffix" {
                let mut suffix_cursor = raw_child.walk();
                let found = raw_child
                    .children(&mut suffix_cursor)
                    .find(|c| c.kind() == "value_arguments");
                found.unwrap_or(raw_child)
            } else {
                raw_child
            };
            let mut inner = child.walk();
            for arg in child.children(&mut inner) {
                let ak = arg.kind();
                if ak != "("
                    && ak != ")"
                    && ak != ","
                    && ak != "{"
                    && ak != "}"
                    && ak != "value_argument"
                    && ak != "annotated_lambda"
                {
                    return Some(get_node_text(arg, source).to_string());
                }
                // Unwrap value_argument to get the expression inside
                if ak == "value_argument" {
                    let mut va_cursor = arg.walk();
                    for va_child in arg.children(&mut va_cursor) {
                        let vak = va_child.kind();
                        if vak != "value_argument_label" && vak != ":" {
                            return Some(get_node_text(va_child, source).to_string());
                        }
                    }
                }
            }
        }
    }

    // Last resort: extract from the full call text by finding the first parenthesized argument
    let text = get_node_text(call_node, source);
    if let Some(start) = text.find('(') {
        let rest = &text[start + 1..];
        // Find the first comma or closing paren
        let end = rest
            .find(',')
            .or_else(|| rest.find(')'))
            .unwrap_or(rest.len());
        let arg = rest[..end].trim();
        if !arg.is_empty() {
            return Some(arg.to_string());
        }
    }

    None
}

/// Check if an if-statement body contains a throw/raise/panic statement (multi-language).
fn body_contains_throw(if_stmt: Node, source: &[u8], config: &LanguageConfig) -> bool {
    // For Swift guard_statement: the else block is where the throw/fatalError goes
    if if_stmt.kind() == "guard_statement" {
        // guard_statement children include "else" keyword and "statements" block
        let mut cursor = if_stmt.walk();
        for child in if_stmt.children(&mut cursor) {
            if (child.kind() == "statements" || child.kind() == "else")
                && node_tree_contains_throw(child, source, config)
            {
                return true;
            }
        }
        // Also check all children recursively (guard may have different structure)
        return node_tree_contains_throw(if_stmt, source, config);
    }

    // Check the consequence (then-block) field
    if let Some(consequence) = if_stmt.child_by_field_name(config.if_consequence_field) {
        if node_tree_contains_throw(consequence, source, config) {
            return true;
        }
    }

    // Also check direct children (for various grammar shapes)
    let mut cursor = if_stmt.walk();
    for child in if_stmt.children(&mut cursor) {
        if config.is_throw(child.kind()) {
            return true;
        }
        // v0.5.0 SOL-CONV-R1-2 (M14b): tree-sitter-solidity uses
        // `block_statement` for the braced consequence and wraps EVERY
        // statement (including the if's own body) in a `statement` node.
        // Both need recursion to find a deeper throw.
        if (child.kind() == "block"
            || child.kind() == "compound_statement"
            || child.kind() == "function_body"
            || child.kind() == "statements"
            || child.kind() == "block_statement"
            || child.kind() == "statement")
            && node_tree_contains_throw(child, source, config)
        {
            return true;
        }
    }

    // For Rust: check for panic!() macro inside the block
    if config.assert_is_macro {
        if let Some(consequence) = if_stmt.child_by_field_name(config.if_consequence_field) {
            if block_contains_panic_macro(consequence, source) {
                return true;
            }
        }
    }

    false
}

/// Check if a node tree contains any throw/raise statements or error function calls.
fn node_tree_contains_throw(node: Node, source: &[u8], config: &LanguageConfig) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if config.is_throw(child.kind()) {
            return true;
        }
        // For Rust: check for panic!() macros
        if config.assert_is_macro
            && child.kind() == "macro_invocation"
            && is_panic_macro(child, source)
        {
            return true;
        }
        // Check for error function calls (e.g., Luau error(), Swift fatalError())
        if config.has_error_calls() && config.is_call(child.kind()) {
            if let Some(name) = extract_call_name(child, source) {
                if config.is_error_call_name(&name) {
                    return true;
                }
            }
        }
        // Check expression_statement wrapping throw or error call
        if child.kind() == "expression_statement" {
            let mut inner = child.walk();
            for grandchild in child.children(&mut inner) {
                if config.is_throw(grandchild.kind()) {
                    return true;
                }
                if config.assert_is_macro
                    && grandchild.kind() == "macro_invocation"
                    && is_panic_macro(grandchild, source)
                {
                    return true;
                }
                if config.has_error_calls() && config.is_call(grandchild.kind()) {
                    if let Some(name) = extract_call_name(grandchild, source) {
                        if config.is_error_call_name(&name) {
                            return true;
                        }
                    }
                }
            }
        }
        // Recurse into blocks, statements, and other containers
        if (child.kind() == "block"
            || child.kind() == "compound_statement"
            || child.kind() == "function_body"
            || child.kind() == "statements"
            || child.kind() == "block_statement"
            || child.kind() == "statement")
            && node_tree_contains_throw(child, source, config)
        {
            return true;
        }
    }
    false
}

/// Check if a block contains a panic!() macro invocation (Rust-specific).
fn block_contains_panic_macro(block: Node, source: &[u8]) -> bool {
    let mut cursor = block.walk();
    for child in block.children(&mut cursor) {
        if child.kind() == "macro_invocation" && is_panic_macro(child, source) {
            return true;
        }
        if child.kind() == "expression_statement" {
            let mut inner = child.walk();
            for grandchild in child.children(&mut inner) {
                if grandchild.kind() == "macro_invocation" && is_panic_macro(grandchild, source) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a macro_invocation is panic!(), todo!(), unreachable!(), etc.
fn is_panic_macro(node: Node, source: &[u8]) -> bool {
    if node.kind() != "macro_invocation" {
        return false;
    }
    if let Some(macro_node) = node.child_by_field_name("macro") {
        let name = get_node_text(macro_node, source);
        return matches!(name, "panic" | "todo" | "unreachable" | "unimplemented");
    }
    // Fallback: check the text
    let text = get_node_text(node, source);
    text.starts_with("panic!") || text.starts_with("todo!") || text.starts_with("unreachable!")
}

/// Check if a macro_invocation is an assert macro (Rust: assert!, debug_assert!, assert_eq!, etc.)
fn is_assert_macro(node: Node, source: &[u8]) -> bool {
    if node.kind() != "macro_invocation" {
        return false;
    }
    if let Some(macro_node) = node.child_by_field_name("macro") {
        let name = get_node_text(macro_node, source);
        return name.starts_with("assert") || name.starts_with("debug_assert");
    }
    let text = get_node_text(node, source);
    text.starts_with("assert") || text.starts_with("debug_assert")
}

/// Extract precondition from a guard clause by negating the condition (multi-language).
///
/// Pattern: `if x < 0: raise ValueError` -> precondition: `x >= 0`
/// Pattern: `if x < 0 { panic!("...") }` -> precondition: `x >= 0`
/// Pattern: `guard !data.isEmpty else { fatalError(...) }` -> precondition: `!data.isEmpty` (Swift)
fn precondition_from_guard(
    if_stmt: Node,
    source: &[u8],
    config: &LanguageConfig,
) -> Option<Condition> {
    // For Swift guard statements: the condition IS the precondition (not negated)
    // guard <condition> else { throw/fatalError }
    if if_stmt.kind() == "guard_statement" {
        let line = if_stmt.start_position().row as u32 + 1;
        if let Some(condition_node) = if_stmt.child_by_field_name(config.if_condition_field) {
            let condition_text = get_node_text(condition_node, source);
            return Some(Condition::high(
                condition_text.to_string(),
                condition_text.to_string(),
                line,
            ));
        }
        // Fallback: use the full guard text before "else"
        let full_text = get_node_text(if_stmt, source);
        if let Some(else_pos) = full_text.find("else") {
            let guard_cond = full_text[5..else_pos].trim(); // skip "guard "
            if !guard_cond.is_empty() {
                return Some(Condition::high(
                    guard_cond.to_string(),
                    guard_cond.to_string(),
                    line,
                ));
            }
        }
        return None;
    }

    let raw_condition_node = if_stmt.child_by_field_name(config.if_condition_field)?;
    let line = if_stmt.start_position().row as u32 + 1;

    // v0.5.0 SOL-CONV-R1-2 (M14b): the tree-sitter-solidity grammar wraps
    // every if-condition expression in an `expression` named node, e.g.
    //   if_statement.condition = expression > binary_expression
    // Peel that wrapper so the kind dispatch below sees the concrete
    // comparison kind (binary_expression / comparison_operator) and
    // produces a high-confidence negated precondition rather than the
    // generic `!(expr)` fallback.
    let condition_node = if raw_condition_node.kind() == "expression" {
        let mut cursor = raw_condition_node.walk();
        let mut inner = raw_condition_node;
        for child in raw_condition_node.children(&mut cursor) {
            if child.is_named() {
                inner = child;
                break;
            }
        }
        inner
    } else {
        raw_condition_node
    };
    let condition_text = get_node_text(condition_node, source);

    match condition_node.kind() {
        "comparison_operator" | "binary_expression" => {
            // if x < 0: raise -> precondition x >= 0
            if let Some(negated) = negate_comparison(condition_node, source) {
                let var = extract_left_operand(condition_node, source);
                return Some(Condition::high(var, negated, line));
            }
            // Fallback for binary expressions we can't negate
            let negated = format!("{} ({})", config.negation_prefix, condition_text);
            return Some(Condition::medium(condition_text.to_string(), negated, line));
        }
        "not_operator" => {
            // Python: if not isinstance(x, T): raise -> precondition isinstance(x, T)
            if let Some(operand) = condition_node.child_by_field_name("argument") {
                let operand_text = get_node_text(operand, source);
                if operand.kind() == "call"
                    && config.has_isinstance
                    && is_isinstance_call(operand, source)
                {
                    let var = extract_isinstance_var(operand, source);
                    return Some(Condition::high(var, operand_text.to_string(), line));
                } else {
                    return Some(Condition::medium(
                        operand_text.to_string(),
                        operand_text.to_string(),
                        line,
                    ));
                }
            }
        }
        "unary_expression" | "prefix_expression" => {
            // C/Java/Rust/TS: if (!expr) { throw ... } -> precondition expr
            // The operand is typically the second child (after the operator)
            let mut cursor = condition_node.walk();
            for child in condition_node.children(&mut cursor) {
                if child.kind() != "!" && child.kind() != "not" {
                    let operand_text = get_node_text(child, source);
                    if !operand_text.is_empty() {
                        return Some(Condition::medium(
                            operand_text.to_string(),
                            operand_text.to_string(),
                            line,
                        ));
                    }
                }
            }
            // Try the operand field
            if let Some(operand) = condition_node.child_by_field_name("operand") {
                let operand_text = get_node_text(operand, source);
                return Some(Condition::medium(
                    operand_text.to_string(),
                    operand_text.to_string(),
                    line,
                ));
            }
        }
        "call" | "call_expression" => {
            if config.has_isinstance && is_isinstance_call(condition_node, source) {
                let negated = format!("{} ({})", config.negation_prefix, condition_text);
                return Some(Condition::medium(condition_text.to_string(), negated, line));
            }
            let negated = format!("{} ({})", config.negation_prefix, condition_text);
            return Some(Condition::medium(condition_text.to_string(), negated, line));
        }
        "parenthesized_expression" => {
            // Unwrap parentheses and recurse on inner expression
            let mut cursor = condition_node.walk();
            for child in condition_node.children(&mut cursor) {
                if child.kind() != "(" && child.kind() != ")" {
                    // Create a synthetic if-like analysis on the inner expression
                    let inner_text = get_node_text(child, source);
                    if child.kind() == "comparison_operator" || child.kind() == "binary_expression"
                    {
                        if let Some(negated) = negate_comparison(child, source) {
                            let var = extract_left_operand(child, source);
                            return Some(Condition::high(var, negated, line));
                        }
                    }
                    let negated = format!("{} ({})", config.negation_prefix, inner_text);
                    return Some(Condition::medium(inner_text.to_string(), negated, line));
                }
            }
        }
        _ => {
            // Generic: if <expr>: raise -> precondition not (<expr>)
            let negated = format!("{} ({})", config.negation_prefix, condition_text);
            return Some(Condition::medium(condition_text.to_string(), negated, line));
        }
    }

    None
}

/// Extract precondition from an assert statement or macro (multi-language).
///
/// Pattern: `assert x > 0` -> precondition: `x > 0`
/// Pattern: `assert!(x > 0)` -> precondition: `x > 0` (Rust)
fn precondition_from_assert(
    assert_stmt: Node,
    source: &[u8],
    config: &LanguageConfig,
    params: &HashSet<String>,
    first_assign: &HashMap<String, u32>,
) -> Option<Condition> {
    let line = assert_stmt.start_position().row as u32 + 1;

    if config.assert_is_macro {
        // Rust: assert!(), debug_assert!(), assert_eq!(), etc.
        if !is_assert_macro(assert_stmt, source) {
            return None;
        }
        // Extract the condition from the macro arguments
        // The token_tree child contains the arguments
        let condition_text = extract_macro_args(assert_stmt, source)?;
        // Entry-vs-body discrimination over the macro's referenced identifiers
        // (the macro-name identifier is entry-neutral and never disqualifies).
        let mut referenced = HashSet::new();
        collect_identifier_names(assert_stmt, source, &mut referenced);
        if !is_entry_precondition(&referenced, line, params, first_assign) {
            return None;
        }
        return Some(Condition::high(
            condition_text.clone(),
            condition_text,
            line,
        ));
    }

    // Standard assert statement (Python, Java, OCaml)
    let condition_node = extract_assert_condition(assert_stmt, source)?;
    let condition_text = get_node_text(condition_node, source);

    // Entry-vs-body discrimination: drop asserts that reference a body-local
    // defined at or before this line (in-body assertion, not entry contract).
    let mut referenced = HashSet::new();
    collect_identifier_names(condition_node, source, &mut referenced);
    if !is_entry_precondition(&referenced, line, params, first_assign) {
        return None;
    }

    match condition_node.kind() {
        "call" if config.has_isinstance && is_isinstance_call(condition_node, source) => {
            // assert isinstance(x, T)
            let var = extract_isinstance_var(condition_node, source);
            Some(Condition::high(var, condition_text.to_string(), line))
        }
        "comparison_operator" | "binary_expression" => {
            // assert x > 0
            let var = extract_left_operand(condition_node, source);
            Some(Condition::high(var, condition_text.to_string(), line))
        }
        _ => {
            // Generic assert
            Some(Condition::medium(
                condition_text.to_string(),
                condition_text.to_string(),
                line,
            ))
        }
    }
}

/// Extract the condition node from an assert statement.
fn extract_assert_condition<'a>(assert_stmt: Node<'a>, _source: &[u8]) -> Option<Node<'a>> {
    let mut cursor = assert_stmt.walk();
    for child in assert_stmt.children(&mut cursor) {
        // Skip keywords like "assert"
        let kind = child.kind();
        if kind != "assert" && kind != "assert_keyword" && !kind.starts_with("assert") {
            return Some(child);
        }
    }
    None
}

/// Extract the argument text from a macro invocation (Rust assert!(...)).
fn extract_macro_args(macro_node: Node, source: &[u8]) -> Option<String> {
    // Look for token_tree child which contains the arguments
    let mut cursor = macro_node.walk();
    for child in macro_node.children(&mut cursor) {
        if child.kind() == "token_tree" {
            let text = get_node_text(child, source);
            // Strip surrounding parens
            let trimmed = text.trim();
            if trimmed.starts_with('(') && trimmed.ends_with(')') {
                return Some(trimmed[1..trimmed.len() - 1].trim().to_string());
            }
            return Some(trimmed.to_string());
        }
    }
    // Fallback: extract from the full text
    let text = get_node_text(macro_node, source);
    // Pattern: assert!(condition) or assert_eq!(a, b)
    if let Some(start) = text.find('(') {
        if let Some(end) = text.rfind(')') {
            return Some(text[start + 1..end].trim().to_string());
        }
    }
    None
}

// =============================================================================
// Postcondition Extraction
// =============================================================================

/// Extract postconditions from assertions after result assignment (multi-language).
fn extract_postconditions(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    depth: usize,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    check_ast_depth(depth, &PathBuf::from("<source>"))?;

    let body = match get_function_body(func, config) {
        Some(b) => b,
        None => return Ok(()),
    };

    let mut result_assigned = false;
    let mut cursor = body.walk();

    for stmt in body.children(&mut cursor) {
        // Track if 'result' has been assigned
        if config.is_assignment(stmt.kind()) && has_result_assignment(stmt, source, config) {
            result_assigned = true;
        }

        // assert after result assignment -> postcondition
        if result_assigned {
            if config.is_assert(stmt.kind()) {
                if let Some(cond) = postcondition_from_assert(stmt, source, config) {
                    conditions.push(cond);
                }
            } else if config.assert_is_macro && stmt.kind() == "expression_statement" {
                // Rust: assert!() in expression_statement
                let mut inner = stmt.walk();
                for child in stmt.children(&mut inner) {
                    if config.is_assert(child.kind()) && is_assert_macro(child, source) {
                        if let Some(cond) = postcondition_from_assert(child, source, config) {
                            conditions.push(cond);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check if a statement assigns to a variable named 'result' (multi-language).
fn has_result_assignment(stmt: Node, source: &[u8], config: &LanguageConfig) -> bool {
    // Check "left" field (Python assignment)
    if let Some(left) = stmt.child_by_field_name("left") {
        let text = get_node_text(left, source);
        if text == "result" {
            return true;
        }
    }

    // Check "pattern" field (Rust let binding)
    if let Some(pattern) = stmt.child_by_field_name("pattern") {
        let text = get_node_text(pattern, source);
        if text == "result" {
            return true;
        }
    }

    // Check "name" field (various let/var declarations)
    if let Some(name) = stmt.child_by_field_name("name") {
        let text = get_node_text(name, source);
        if text == "result" {
            return true;
        }
    }

    // Handle children containing assignment
    let mut cursor = stmt.walk();
    for child in stmt.children(&mut cursor) {
        if config.is_assignment(child.kind()) {
            if let Some(left) = child.child_by_field_name("left") {
                let text = get_node_text(left, source);
                if text == "result" {
                    return true;
                }
            }
        }
        // Check identifiers that look like result assignment
        if child.kind() == "identifier" || child.kind() == "name" {
            let text = get_node_text(child, source);
            if text == "result" {
                // Make sure this is an assignment context (has = after it)
                if let Some(next) = child.next_sibling() {
                    let next_text = get_node_text(next, source);
                    if next_text == "=" || next_text == ":=" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Extract postcondition from an assert statement after result assignment (multi-language).
fn postcondition_from_assert(
    assert_stmt: Node,
    source: &[u8],
    config: &LanguageConfig,
) -> Option<Condition> {
    let line = assert_stmt.start_position().row as u32 + 1;

    if config.assert_is_macro {
        // Rust: assert!(), assert_eq!() etc.
        if !is_assert_macro(assert_stmt, source) {
            return None;
        }
        let condition_text = extract_macro_args(assert_stmt, source)?;
        let var = if condition_text.contains("result") {
            "result".to_string()
        } else {
            condition_text.clone()
        };
        return Some(Condition::high(var, condition_text, line));
    }

    let condition_node = extract_assert_condition(assert_stmt, source)?;
    let condition_text = get_node_text(condition_node, source);

    // Find if 'result' is referenced
    let var = find_result_var(condition_node, source);

    Some(Condition::high(var, condition_text.to_string(), line))
}

/// Find a variable containing 'result' in an expression.
fn find_result_var(node: Node, source: &[u8]) -> String {
    // Check this node
    if node.kind() == "identifier" {
        let text = get_node_text(node, source);
        if text.contains("result") {
            return text.to_string();
        }
    }

    // Check children recursively
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let found = find_result_var(child, source);
        if found.contains("result") {
            return found;
        }
    }

    // Fall back to the full expression
    get_node_text(node, source).to_string()
}

// =============================================================================
// Type Annotation Extraction
// =============================================================================

/// Extract preconditions from function parameter type annotations (multi-language).
///
/// Pattern: `def f(x: int)` -> precondition: `isinstance(x, int)` (low confidence, Python)
/// Pattern: `fn f(x: i32)` -> precondition: `x: i32` (low confidence, Rust)
/// Pattern: `void f(int x)` -> precondition: `x: int` (low confidence, Java/C)
fn extract_type_annotation_preconditions(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    let clauses = collect_value_param_clauses(func, config);
    if clauses.is_empty() {
        return Ok(());
    }

    // v0.5.0 CL-10 (GH #81): anchor to the decl-keyword line, not a leading
    // `@Override` / `@inlinable` / `[Test]` line.
    let line = config.func_decl_line(func);

    // Recursively search for typed parameters across every (curried) clause.
    for params in clauses {
        extract_typed_params_recursive(params, source, conditions, config, line);
    }

    Ok(())
}

/// contracts-type-printer-v1 (CLUSTER-M-046): Scala
/// `(implicit X: T, Y: U)` parameter groups carry an `implicit` keyword
/// child. They represent compiler-resolved type-class evidence, not
/// caller-supplied arguments, so they MUST NOT appear as preconditions on
/// the function value.
fn is_scala_implicit_parameter_group(node: Node) -> bool {
    if node.kind() != "parameters" {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "implicit" {
            return true;
        }
    }
    false
}

/// cl4-interface-v1 (IT3-scala-01/02/03, GH #78): collect the value
/// parameter-clause node(s) of a function declaration.
///
/// For most languages a function declares exactly one parameter list under
/// `config.func_params_field`, so `child_by_field_name` is sufficient. Scala
/// is the exception: a `function_definition` carries BOTH its
/// `type_parameters` (`[F[_], A]`) and one-or-more curried `parameters`
/// value clauses (`(capacity: Int)(implicit F: ...)`) under the SAME field
/// name `parameters`. `child_by_field_name` returns only the first such
/// child — the type-parameter list — so the real value parameters were
/// dropped and the type variables were mis-reported as parameters. Here we
/// select, AST-driven by node KIND, only the `parameters`-kind value clauses
/// (the type-parameter list has kind `type_parameters` and is excluded).
fn collect_value_param_clauses<'a>(func: Node<'a>, config: &LanguageConfig) -> Vec<Node<'a>> {
    if config.language == Language::Scala {
        let mut clauses = Vec::new();
        let mut cursor = func.walk();
        let mut idx = 0u32;
        for child in func.children(&mut cursor) {
            if func.field_name_for_child(idx) == Some(config.func_params_field)
                && child.kind() == "parameters"
            {
                clauses.push(child);
            }
            idx += 1;
        }
        return clauses;
    }
    match func.child_by_field_name(config.func_params_field) {
        Some(p) => vec![p],
        None => Vec::new(),
    }
}

/// Recursively extract typed parameter information.
fn extract_typed_params_recursive(
    node: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
    line: u32,
) {
    if is_scala_implicit_parameter_group(node) {
        return;
    }
    // verification-and-metrics-completeness-v1 (P12.AGG12-11): same
    // function-declarator skip as the untyped variant — the C/C++
    // `function_declarator` mixes the function-name identifier with the
    // parameter list, so descend straight into the parameter_list to
    // avoid mistaking the function name for a parameter.
    if node.kind() == "function_declarator" {
        if let Some(plist) = node.child_by_field_name("parameters") {
            extract_typed_params_recursive(plist, source, conditions, config, line);
            return;
        }
        let mut local = node.walk();
        for child in node.children(&mut local) {
            if child.kind() == "parameter_list" {
                extract_typed_params_recursive(child, source, conditions, config, line);
                return;
            }
        }
        return;
    }

    let mut cursor = node.walk();

    for param in node.children(&mut cursor) {
        let kind = param.kind();

        // Check if this is a typed parameter kind for the language
        if config.typed_param_kinds.contains(&kind) {
            let name_node = param
                .child_by_field_name("name")
                .or_else(|| param.child_by_field_name("pattern"))
                .or_else(|| {
                    // Find first identifier child
                    find_first_identifier(param)
                });

            let type_node = param
                .child_by_field_name("type")
                .or_else(|| param.child_by_field_name("type_annotation"));

            if let (Some(name_node), Some(type_node)) = (name_node, type_node) {
                let name = get_node_text(name_node, source);
                let base_type = get_node_text(type_node, source);

                // Skip self/cls/this
                if name == "self" || name == "cls" || name == "this" {
                    continue;
                }

                // contracts-type-printer-v1 (CLUSTER-M-046): in C/C++ the
                // `type` field only holds the base type (`char`); pointer
                // qualifiers / `&` references live in the declarator chain
                // (`pointer_declarator` / `reference_declarator`). Recover
                // them from the param's `declarator` child so
                // `const char *init` renders as `init: char *`, not
                // `init: char`.
                let qualifiers = collect_c_param_qualifiers(param);
                let type_str = if qualifiers.is_empty() {
                    base_type.to_string()
                } else {
                    format!("{} {}", base_type, qualifiers)
                };

                let constraint = if config.has_isinstance {
                    format!("isinstance({}, {})", name, type_str)
                } else {
                    format!("{}: {}", name, type_str)
                };
                conditions.push(Condition::low(name.to_string(), constraint, line));
            }
        }

        // For C/C++ function_declarator -> parameter_list
        if kind == "function_declarator" || kind == "parameter_list" {
            extract_typed_params_recursive(param, source, conditions, config, line);
        }
    }
}

/// contracts-type-printer-v1 (CLUSTER-M-046): walk a C/C++
/// `parameter_declaration` node's declarator chain and collect the
/// pointer / reference indirection markers (`*`, `**`, `&`).
///
/// tree-sitter-c parses `const char *init` as:
///     parameter_declaration
///       type_qualifier "const"
///       primitive_type "char"          ← field "type"
///       pointer_declarator             ← field "declarator"
///         "*"
///         identifier "init"
///
/// The `type` field strips the `*`, so the previous extractor rendered
/// `init: char`. We descend through `pointer_declarator` /
/// `reference_declarator` / `abstract_pointer_declarator` /
/// `abstract_reference_declarator` (and their `parenthesized_declarator`
/// wrappers) accumulating one marker per indirection level.
fn collect_c_param_qualifiers(param: Node) -> String {
    let declarator = match param.child_by_field_name("declarator") {
        Some(d) => d,
        None => return String::new(),
    };
    let mut marks = String::new();
    collect_indirection_marks(declarator, &mut marks);
    marks
}

fn collect_indirection_marks(node: Node, marks: &mut String) {
    match node.kind() {
        "pointer_declarator" | "abstract_pointer_declarator" => marks.push('*'),
        "reference_declarator" | "abstract_reference_declarator" => marks.push('&'),
        _ => {}
    }
    // Recurse into nested declarators (multi-level pointer / reference).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "pointer_declarator"
            | "abstract_pointer_declarator"
            | "reference_declarator"
            | "abstract_reference_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "init_declarator" => collect_indirection_marks(child, marks),
            _ => {}
        }
    }
}

/// contracts-type-printer-v1 (CLUSTER-M-046): consume an Elixir `@spec`
/// attribute adjacent to the located function definition and emit typed
/// preconditions + a typed return postcondition.
///
/// AST shape for `@spec name(t1, t2) :: ret`:
/// ```text
/// unary_operator
///   @
///   call
///     identifier "spec"
///     arguments
///       binary_operator                       <- "::"
///         call                                <- name + arg types
///           identifier "name"
///           arguments
///             ( arg-type … )
///         "::"
///         <return-type-expr>
/// ```
///
/// Conditions are tagged low-confidence to mirror the type-annotation
/// emission used by other languages — the @spec is a type-level claim,
/// not an executable check.
///
/// DESIGN-park: the alternative — treating @spec ONLY as a type hint that
/// does NOT produce contract entries — is recorded in
/// `/tmp/audit_phase22/design_judgement_parked.md`. The defensible default
/// chosen here is the same one already used for typed parameters in
/// Rust/Go/Java: a `@spec`-derived type becomes a low-confidence pre/post.
fn extract_elixir_at_spec(
    func_node: Node,
    function: &str,
    source: &[u8],
    preconditions: &mut Vec<Condition>,
    postconditions: &mut Vec<Condition>,
) {
    // The `@spec` is a sibling of the `def` call inside the surrounding
    // do_block / source / module body. Walk previous siblings and look
    // for the matching unary_operator pattern. We only consider the
    // closest preceding @spec to avoid mixing unrelated specs.
    let mut prev = func_node.prev_sibling();
    while let Some(node) = prev {
        if node.kind() == "unary_operator" {
            if let Some((arg_types, return_type)) =
                parse_elixir_spec_unary_operator(node, function, source)
            {
                let line = node.start_position().row as u32 + 1;
                for (idx, ty) in arg_types.iter().enumerate() {
                    let ty = ty.trim();
                    if ty.is_empty() {
                        continue;
                    }
                    let name = format!("arg{}", idx + 1);
                    preconditions.push(Condition::low(
                        name.clone(),
                        format!("{}: {}", name, ty),
                        line,
                    ));
                }
                let ret = return_type.trim();
                if !ret.is_empty() {
                    postconditions.push(Condition::low(
                        "return".to_string(),
                        format!("return: {}", ret),
                        line,
                    ));
                }
                return;
            }
        }
        prev = node.prev_sibling();
    }
}

/// Attempt to parse a `unary_operator(@, call(spec, args))` Elixir @spec
/// attribute as `(arg_types, return_type)`. Returns `None` unless the
/// inner `call`'s name matches `function`.
fn parse_elixir_spec_unary_operator<'a>(
    unary: Node<'a>,
    function: &str,
    source: &'a [u8],
) -> Option<(Vec<String>, String)> {
    let mut cursor = unary.walk();
    let mut inner_call: Option<Node<'a>> = None;
    for child in unary.children(&mut cursor) {
        if child.kind() == "call" {
            inner_call = Some(child);
            break;
        }
    }
    let spec_call = inner_call?;
    let target = spec_call.child_by_field_name("target")?;
    if get_node_text(target, source) != "spec" {
        return None;
    }

    // The spec call has an `arguments` child holding a `binary_operator` (::)
    // whose LHS is the function-application `name(arg_t1, arg_t2)` and
    // whose RHS is the return type.
    let mut c2 = spec_call.walk();
    let mut args_node: Option<Node> = None;
    for child in spec_call.children(&mut c2) {
        if child.kind() == "arguments" {
            args_node = Some(child);
            break;
        }
    }
    let args = args_node?;
    let bin = args.child(0)?;
    if bin.kind() != "binary_operator" {
        return None;
    }
    // Operator must be `::`. The `operator` field (when present) or the
    // middle child holds the operator token.
    let mut found_dcolon = false;
    let mut cc = bin.walk();
    for child in bin.children(&mut cc) {
        if child.kind() == "::" {
            found_dcolon = true;
            break;
        }
    }
    if !found_dcolon {
        return None;
    }
    // LHS — the function-application that names the spec target.
    let lhs = bin.child(0)?;
    // RHS — return type (the LAST child after the `::`).
    let rhs = bin.child(bin.child_count().saturating_sub(1))?;

    // Extract function name + arg types from LHS.
    let (name, arg_types) = match lhs.kind() {
        "call" => {
            let tgt = lhs.child_by_field_name("target")?;
            let mut name = get_node_text(tgt, source).to_string();
            let mut arg_types: Vec<String> = Vec::new();
            // The `arguments` child carries the comma-separated arg types.
            let mut lcur = lhs.walk();
            for c in lhs.children(&mut lcur) {
                if c.kind() == "arguments" {
                    let mut ac = c.walk();
                    for at in c.children(&mut ac) {
                        let kind = at.kind();
                        if kind == "(" || kind == ")" || kind == "," {
                            continue;
                        }
                        let txt = get_node_text(at, source).trim().to_string();
                        if !txt.is_empty() {
                            arg_types.push(txt);
                        }
                    }
                }
            }
            // Defensive: bare `name :: t` may parse the LHS as `identifier`,
            // not `call`. Handled in the other arm.
            let _ = &mut name;
            (name, arg_types)
        }
        "identifier" => (get_node_text(lhs, source).to_string(), Vec::new()),
        _ => return None,
    };

    if name != function {
        return None;
    }
    Some((arg_types, get_node_text(rhs, source).trim().to_string()))
}

/// contracts-type-printer-v1 (CLUSTER-M-046): recognise Swift
/// `guard let X = Y else { … }` optional-binding statements anywhere in
/// the function body and emit a high-confidence `X != nil` precondition.
///
/// After the guard succeeds, `X` is unconditionally non-nil for the rest
/// of the function — semantically equivalent to a precondition on the
/// continuation.
///
/// tree-sitter-swift parses the binding as
/// `guard_statement(guard, value_binding_pattern(let), simple_identifier
/// "X", =, …, else, { … })` — i.e., the bound name is a direct
/// `simple_identifier` sibling of the `value_binding_pattern`.
fn extract_swift_guard_let(
    func_node: Node,
    source: &[u8],
    preconditions: &mut Vec<Condition>,
    _config: &LanguageConfig,
) {
    walk_swift_guard_let(func_node, source, preconditions, 0);
}

fn walk_swift_guard_let(
    node: Node,
    source: &[u8],
    preconditions: &mut Vec<Condition>,
    depth: usize,
) {
    if depth > MAX_AST_DEPTH {
        return;
    }
    if node.kind() == "guard_statement" {
        if let Some(name) = swift_guard_let_binding_name(node, source) {
            let line = node.start_position().row as u32 + 1;
            let constraint = format!("{} != nil", name);
            preconditions.push(Condition::high(name, constraint, line));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_swift_guard_let(child, source, preconditions, depth + 1);
    }
}

/// Return the binding name of a Swift `guard let X = …` if the guard
/// statement is an optional-binding form. Returns `None` for plain
/// `guard <bool> else …` guards (handled by the existing
/// `precondition_from_guard` path).
fn swift_guard_let_binding_name(guard_stmt: Node, source: &[u8]) -> Option<String> {
    let mut cursor = guard_stmt.walk();
    let mut saw_value_binding = false;
    for child in guard_stmt.children(&mut cursor) {
        match child.kind() {
            "value_binding_pattern" => {
                saw_value_binding = true;
            }
            "simple_identifier" if saw_value_binding => {
                let name = get_node_text(child, source).trim().to_string();
                if !name.is_empty() {
                    return Some(name);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract postcondition from return type annotation (multi-language).
///
/// Pattern: `def f() -> int` -> postcondition: `isinstance(return, int)` (low confidence, Python)
/// Pattern: `fn f() -> i32` -> postcondition: `return: i32` (low confidence, Rust)
fn extract_return_type_postconditions(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    if config.return_type_field.is_empty() {
        return Ok(());
    }

    let return_type = match func.child_by_field_name(config.return_type_field) {
        Some(rt) => rt,
        None => return Ok(()),
    };

    // v0.5.0 CL-10 (GH #81): anchor to the decl-keyword line.
    let line = config.func_decl_line(func);
    let type_str = get_node_text(return_type, source);

    // Skip void/None/unit return types
    if type_str == "None" || type_str == "void" || type_str == "()" || type_str.is_empty() {
        return Ok(());
    }

    let constraint = if config.has_isinstance {
        format!("isinstance(return, {})", type_str)
    } else {
        format!("return: {}", type_str)
    };
    conditions.push(Condition::low("return".to_string(), constraint, line));

    Ok(())
}

// =============================================================================
// Untyped Parameter Extraction
// =============================================================================

/// fix-R2-themeE (RC3): collect the parameter names a Lua/Luau function body
/// marks OPTIONAL via an `assert(... or <param> == nil ...)` guard.
///
/// Roact-style code documents optional parameters with a disjunction inside an
/// assert: `assert(typeof(props) == 'table' or props == nil)`. The presence of
/// the `... or <param> == nil` clause is the source's OWN statement that the
/// parameter may be absent — so the untyped-parameter heuristic must not emit
/// `parameter <param> is required` for it. These asserts are frequently nested
/// inside `if config.typeChecks then ... end`, so the scan recurses through the
/// whole body (any block / if-statement), not just the top-level statements.
///
/// AST-driven, no regex:
/// - Locate `assert(...)` calls by KIND (`config.is_call`) + callee name
///   (`config.is_assert_call_name`), reusing the existing `extract_call_name`.
/// - In the assert's first argument, find a boolean `or` node (a
///   `binary_expression`/`binary_operator` whose operator token KIND is `or`).
/// - In either `or` operand, find an equality `<ident> == nil` /
///   `nil == <ident>` and record the identifier.
fn collect_optional_params_from_body(
    func: Node,
    source: &[u8],
    config: &LanguageConfig,
) -> HashSet<String> {
    let mut optional = HashSet::new();
    if !config.has_assert_calls() {
        return optional;
    }
    let body = match get_function_body(func, config) {
        Some(b) => b,
        None => return optional,
    };
    collect_optional_params_walk(body, source, config, &mut optional);
    optional
}

/// Recursive worker for [`collect_optional_params_from_body`]: walk every node,
/// and whenever an assert call is found, harvest `<param> == nil` operands from
/// any `or` disjunction in its first argument.
fn collect_optional_params_walk(
    node: Node,
    source: &[u8],
    config: &LanguageConfig,
    optional: &mut HashSet<String>,
) {
    if config.is_call(node.kind()) {
        if let Some(name) = extract_call_name(node, source) {
            if config.is_assert_call_name(&name) {
                if let Some(arg) = first_call_argument_node(node) {
                    collect_or_nil_params(arg, source, optional);
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_optional_params_walk(child, source, config, optional);
    }
}

/// Return the first argument NODE of a call (the AST analogue of
/// [`extract_first_call_argument`], which returns text). Handles the Lua/Luau
/// `arguments` wrapper, the Solidity `call_argument` shape, the Swift
/// `call_suffix > value_arguments` nesting, and the generic argument-list
/// shapes. (The returned node may itself be a `value_argument` wrapper — that
/// is fine for identifier collection, which recurses.)
fn first_call_argument_node(call_node: Node) -> Option<Node> {
    if let Some(args) = call_node.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for arg in args.children(&mut cursor) {
            if arg.is_named() {
                return Some(arg);
            }
        }
    }
    // Solidity: direct `call_argument` named children.
    let mut cursor = call_node.walk();
    for child in call_node.children(&mut cursor) {
        if child.kind() == "call_argument" {
            let mut inner = child.walk();
            for ic in child.children(&mut inner) {
                if ic.is_named() {
                    return Some(ic);
                }
            }
            return Some(child);
        }
    }
    // Fallback: scan children for an `arguments`/argument-list wrapper, peeling
    // a Swift `call_suffix` to reach the inner `value_arguments`.
    let mut cursor = call_node.walk();
    for raw_child in call_node.children(&mut cursor) {
        let raw_kind = raw_child.kind();
        let child = if raw_kind == "call_suffix" {
            let mut suffix_cursor = raw_child.walk();
            let mut found = None;
            for c in raw_child.children(&mut suffix_cursor) {
                if c.kind() == "value_arguments" {
                    found = Some(c);
                    break;
                }
            }
            match found {
                Some(va) => va,
                None => continue,
            }
        } else if raw_kind == "arguments"
            || raw_kind == "argument_list"
            || raw_kind == "value_arguments"
        {
            raw_child
        } else {
            continue;
        };
        let mut inner = child.walk();
        for arg in child.children(&mut inner) {
            let ak = arg.kind();
            if arg.is_named() && ak != "value_argument" {
                return Some(arg);
            }
            if ak == "value_argument" {
                // Unwrap to the inner expression (skip argument labels).
                let mut va_cursor = arg.walk();
                for va_child in arg.children(&mut va_cursor) {
                    let vak = va_child.kind();
                    if va_child.is_named() && vak != "value_argument_label" {
                        return Some(va_child);
                    }
                }
                return Some(arg);
            }
        }
    }
    None
}

/// Within `node`, find boolean `or` disjunctions and record any
/// `<identifier> == nil` / `nil == <identifier>` operand's identifier into
/// `optional`. Recurses so nested disjunctions are covered.
fn collect_or_nil_params(node: Node, source: &[u8], optional: &mut HashSet<String>) {
    if is_boolean_or_node(node, source) {
        // Inspect the two operands of the `or` for a `<param> == nil` equality.
        for operand in binary_named_operands(node) {
            if let Some(name) = ident_compared_to_nil(operand, source) {
                optional.insert(name);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_or_nil_params(child, source, optional);
    }
}

/// True if `node` is a binary expression whose operator is the boolean `or`.
/// Lua/Luau expose the operator as an unnamed token child with KIND `or`; some
/// grammars expose an `operator` field whose text is `or` / `||`.
fn is_boolean_or_node(node: Node, source: &[u8]) -> bool {
    if !matches!(node.kind(), "binary_expression" | "binary_operator") {
        return false;
    }
    if let Some(op) = node.child_by_field_name("operator") {
        return matches!(op.kind(), "or" | "||")
            || matches!(get_node_text(op, source), "or" | "||");
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() && matches!(child.kind(), "or" | "||") {
            return true;
        }
    }
    false
}

/// Return the NAMED operands (left/right) of a binary node, preferring the
/// `left`/`right` fields and falling back to the first & last named children.
fn binary_named_operands(node: Node) -> Vec<Node> {
    if let (Some(l), Some(r)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        return vec![l, r];
    }
    let mut named = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            named.push(child);
        }
    }
    if named.len() >= 2 {
        let first = named[0];
        let last = named[named.len() - 1];
        vec![first, last]
    } else {
        named
    }
}

/// If `node` is an equality `<identifier> == nil` (or `nil == <identifier>`),
/// return the identifier name. The operator must be `==`; the `nil` operand is
/// a `nil` literal node. Lua/Luau use `binary_expression` with an unnamed `==`
/// token and a `nil` literal child.
fn ident_compared_to_nil(node: Node, source: &[u8]) -> Option<String> {
    if !matches!(
        node.kind(),
        "binary_expression" | "binary_operator" | "comparison_operator"
    ) {
        return None;
    }
    // Operator must be `==`.
    let op_is_eq = if let Some(op) = node.child_by_field_name("operator") {
        matches!(op.kind(), "==")
            || get_node_text(op, source) == "=="
    } else {
        let mut cursor = node.walk();
        let mut found = false;
        for child in node.children(&mut cursor) {
            if !child.is_named() && child.kind() == "==" {
                found = true;
                break;
            }
        }
        found
    };
    if !op_is_eq {
        return None;
    }

    let operands = binary_named_operands(node);
    if operands.len() != 2 {
        return None;
    }
    let (a, b) = (operands[0], operands[1]);
    let a_nil = is_nil_literal(a, source);
    let b_nil = is_nil_literal(b, source);
    // Exactly one side must be `nil`; the other must be a bare identifier.
    let ident_node = match (a_nil, b_nil) {
        (false, true) => a,
        (true, false) => b,
        _ => return None,
    };
    if ident_node.kind() == "identifier" {
        return Some(get_node_text(ident_node, source).to_string());
    }
    None
}

/// True if `node` is a Lua/Luau `nil` literal.
fn is_nil_literal(node: Node, source: &[u8]) -> bool {
    node.kind() == "nil" || get_node_text(node, source).trim() == "nil"
}

/// Extract preconditions from untyped function parameters.
///
/// For languages where parameters can appear without type annotations (e.g., Python, JavaScript),
/// this extracts basic "parameter is required" preconditions from the parameter list.
///
/// Handles:
/// - Plain identifiers: `def f(x, y)` -> preconditions for x, y
/// - Default parameters: `def f(x=1)` -> precondition with default info
/// - Splat/rest params: `def f(*args, **kwargs)` -> preconditions for args, kwargs
///
/// These are low confidence since they only indicate parameter existence, not constraints.
fn extract_untyped_param_preconditions(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    let clauses = collect_value_param_clauses(func, config);
    if clauses.is_empty() {
        return Ok(());
    }

    // v0.5.0 CL-10 (GH #81): anchor to the decl-keyword line.
    let line = config.func_decl_line(func);

    // Collect names already covered by typed_param extraction to avoid duplicates
    let existing_vars: HashSet<String> = conditions.iter().map(|c| c.variable.clone()).collect();

    // fix-R2-themeE (RC3): params the body marks optional via
    // `assert(... or <param> == nil ...)` must NOT receive a
    // "parameter <param> is required" precondition. Scan the body once and pass
    // the optional set down so the recursive emitter can suppress them.
    let optional_params = collect_optional_params_from_body(func, source, config);

    for params in clauses {
        extract_untyped_params_recursive(
            params,
            source,
            conditions,
            config,
            line,
            &existing_vars,
            &optional_params,
        );
    }

    Ok(())
}

/// Recursively extract untyped parameter names from the parameter list.
///
/// fix-R2-themeE (RC3): `optional_params` carries the names the body marked
/// optional via `assert(... or <param> == nil ...)`. A plain untyped parameter
/// in that set is skipped instead of emitting `parameter <name> is required`.
fn extract_untyped_params_recursive(
    node: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
    line: u32,
    existing_vars: &HashSet<String>,
    optional_params: &HashSet<String>,
) {
    // contracts-type-printer-v1 (CLUSTER-M-046): skip Scala
    // `(implicit ...)` parameter groups — see
    // `is_scala_implicit_parameter_group` for the rationale.
    if is_scala_implicit_parameter_group(node) {
        return;
    }
    // verification-and-metrics-completeness-v1 (P12.AGG12-11): when the
    // current node is a C/C++ `function_declarator`, only descend into
    // its `parameter_list` child. Otherwise the recursion sees the
    // function-name `identifier` (a sibling of the parameter list inside
    // the declarator) and emits a bogus precondition like
    // `parameter sdsnew is required` for every C function. The `_declarator`
    // suffix covers nested forms (`pointer_declarator`, `array_declarator`,
    // `function_declarator`, `parenthesized_declarator`) that may wrap the
    // parameter list when the function returns a pointer / array.
    if node.kind() == "function_declarator" {
        if let Some(plist) = node.child_by_field_name("parameters") {
            extract_untyped_params_recursive(
                plist,
                source,
                conditions,
                config,
                line,
                existing_vars,
                optional_params,
            );
            return;
        }
        // Some grammar versions don't expose a `parameters` field name —
        // fall back to the first `parameter_list` child by kind.
        let mut local = node.walk();
        for child in node.children(&mut local) {
            if child.kind() == "parameter_list" {
                extract_untyped_params_recursive(
                    child,
                    source,
                    conditions,
                    config,
                    line,
                    existing_vars,
                    optional_params,
                );
                return;
            }
        }
        // No parameter list at all: nothing to extract.
        return;
    }

    let mut cursor = node.walk();

    for param in node.children(&mut cursor) {
        let kind = param.kind();

        // Skip typed parameters (already handled by extract_type_annotation_preconditions)
        if config.typed_param_kinds.contains(&kind) {
            continue;
        }

        // Skip punctuation and keywords
        if kind == "(" || kind == ")" || kind == "," || kind == ":" {
            continue;
        }

        match kind {
            // Plain untyped parameter (Python: identifier, JS: identifier)
            "identifier" | "name" => {
                let name = get_node_text(param, source);
                // Skip self/cls/this
                if name == "self" || name == "cls" || name == "this" {
                    continue;
                }
                if existing_vars.contains(name) {
                    continue;
                }
                // fix-R2-themeE (RC3): the body's own
                // `assert(... or <name> == nil ...)` declares this parameter
                // optional, so do NOT emit a "is required" precondition for it.
                if optional_params.contains(name) {
                    continue;
                }
                let constraint = format!("parameter {} is required", name);
                conditions.push(Condition::low(name.to_string(), constraint, line));
            }

            // Default parameter: Python `x=1`, JS `x = 1`
            "default_parameter" => {
                if let Some(name_node) = param.child_by_field_name("name") {
                    let name = get_node_text(name_node, source);
                    if name == "self" || name == "cls" || name == "this" {
                        continue;
                    }
                    if existing_vars.contains(name) {
                        continue;
                    }
                    let default_val = param
                        .child_by_field_name("value")
                        .map(|v| get_node_text(v, source))
                        .unwrap_or("?");
                    let constraint = format!("parameter {} (default: {})", name, default_val);
                    conditions.push(Condition::low(name.to_string(), constraint, line));
                }
            }

            // Python *args: list_splat_pattern
            "list_splat_pattern" => {
                let mut inner = param.walk();
                for child in param.children(&mut inner) {
                    if child.kind() == "identifier" {
                        let name = get_node_text(child, source);
                        if !existing_vars.contains(name) {
                            let constraint = format!("parameter *{} (variadic positional)", name);
                            conditions.push(Condition::low(name.to_string(), constraint, line));
                        }
                        break;
                    }
                }
            }

            // Python **kwargs: dictionary_splat_pattern
            "dictionary_splat_pattern" => {
                let mut inner = param.walk();
                for child in param.children(&mut inner) {
                    if child.kind() == "identifier" {
                        let name = get_node_text(child, source);
                        if !existing_vars.contains(name) {
                            let constraint = format!("parameter **{} (variadic keyword)", name);
                            conditions.push(Condition::low(name.to_string(), constraint, line));
                        }
                        break;
                    }
                }
            }

            // JS/TS rest parameter: rest_pattern / rest_element
            "rest_pattern" | "rest_element" => {
                let mut inner = param.walk();
                for child in param.children(&mut inner) {
                    if child.kind() == "identifier" {
                        let name = get_node_text(child, source);
                        if !existing_vars.contains(name) {
                            let constraint = format!("parameter ...{} (rest)", name);
                            conditions.push(Condition::low(name.to_string(), constraint, line));
                        }
                        break;
                    }
                }
            }

            // Recurse into sub-containers (e.g., formal_parameters wrapper)
            "formal_parameters" | "parameters" | "parameter_list" => {
                extract_untyped_params_recursive(
                    param,
                    source,
                    conditions,
                    config,
                    line,
                    existing_vars,
                    optional_params,
                );
            }

            _ => {}
        }
    }
}

// =============================================================================
// Docstring / JSDoc Extraction
// =============================================================================

/// Extract contracts from docstrings (Python) and JSDoc comments (JS/TS).
///
/// Detects:
/// - Python: `:param name:`, `:type name:`, `:return:`, `:rtype:` (Sphinx-style)
/// - Python: `@param name`, `@return` (alternative style)
/// - JS/TS: `@param {type} name`, `@returns {type}` (JSDoc)
///
/// These produce low-confidence conditions since docstrings are documentation,
/// not executable checks.
fn extract_docstring_contracts(
    func: Node,
    source: &[u8],
    preconditions: &mut Vec<Condition>,
    postconditions: &mut Vec<Condition>,
    config: &LanguageConfig,
    language: Language,
) -> ContractsResult<()> {
    // v0.5.0 CL-10 (GH #81): anchor to the decl-keyword line.
    let line = config.func_decl_line(func);

    // Collect existing variables to avoid duplicates
    let existing_pre_vars: HashSet<String> =
        preconditions.iter().map(|c| c.variable.clone()).collect();
    let existing_post_vars: HashSet<String> =
        postconditions.iter().map(|c| c.variable.clone()).collect();

    match language {
        Language::Python => {
            // Python docstrings are expression_statement > string as first statement in body
            let docstring = extract_python_docstring(func, source, config);
            if let Some(doc_text) = docstring {
                extract_sphinx_params(
                    &doc_text,
                    preconditions,
                    postconditions,
                    line,
                    &existing_pre_vars,
                    &existing_post_vars,
                );
            }
        }
        Language::JavaScript | Language::TypeScript => {
            // JSDoc comments appear as comment nodes before the function
            let jsdoc = extract_jsdoc_comment(func, source);
            if let Some(doc_text) = jsdoc {
                extract_jsdoc_params(
                    &doc_text,
                    preconditions,
                    postconditions,
                    line,
                    &existing_pre_vars,
                    &existing_post_vars,
                );
            }
        }
        // solidity-natspec-v1 (v0.5.0 SOL-010): NatSpec `///` / `/** */`
        // comments are sibling `comment` nodes preceding the function
        // declaration. `tldr_core::ast::extract::collect_solidity_natspec_text`
        // collects the raw comment text exactly as `extract_solidity_docstring`
        // does for FunctionInfo, then `parse_solidity_natspec` returns a
        // structured `NatSpecDoc`. We then map `@param NAME text` onto
        // low-confidence preconditions and `@return [NAME] text` onto
        // low-confidence postconditions, mirroring the JSDoc/Sphinx wiring.
        Language::Solidity => {
            // The Solidity helper takes &str; safe to convert because
            // `read_file_safe` already validated UTF-8.
            if let Ok(source_str) = std::str::from_utf8(source) {
                if let Some(doc_text) =
                    tldr_core::ast::extract::collect_solidity_natspec_text(&func, source_str)
                {
                    extract_natspec_params(
                        &doc_text,
                        preconditions,
                        postconditions,
                        line,
                        &existing_pre_vars,
                        &existing_post_vars,
                    );
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// solidity-natspec-v1 (v0.5.0 SOL-010): Map a NatSpec doc-comment block
/// onto pre/postconditions.
///
/// - `@param NAME text` → low-confidence precondition with variable=NAME
///   and constraint = "NAME: text" (matches the JSDoc shape so downstream
///   consumers don't need a Solidity-specific code path).
/// - `@return NAME text` → low-confidence postcondition with variable=NAME
///   (when named-returns are declared) or `"return"` (when unnamed) and
///   constraint = "returns: text" (matches JSDoc/Sphinx return shape).
fn extract_natspec_params(
    natspec: &str,
    preconditions: &mut Vec<Condition>,
    postconditions: &mut Vec<Condition>,
    line: u32,
    existing_pre_vars: &HashSet<String>,
    existing_post_vars: &HashSet<String>,
) {
    let doc = tldr_core::ast::extract::parse_solidity_natspec(natspec);

    for param in doc.params {
        if existing_pre_vars.contains(&param.name) {
            continue;
        }
        let constraint = if param.text.is_empty() {
            format!("parameter {} is required", param.name)
        } else {
            format!("{}: {}", param.name, param.text)
        };
        preconditions.push(Condition::low(param.name, constraint, line));
    }

    for ret in doc.returns {
        // Pick the variable label: named-return name when present, else
        // the generic `"return"` slot used by JSDoc/Sphinx.
        let var = ret.name.clone().unwrap_or_else(|| "return".to_string());
        if existing_post_vars.contains(&var) {
            continue;
        }
        let constraint = if ret.text.is_empty() {
            format!("returns: {}", var)
        } else {
            format!("returns: {}", ret.text)
        };
        postconditions.push(Condition::low(var, constraint, line));
    }

    // solidity-sol016-cluster-v1 M14: parse "Requirements:" /
    // "Conditions:" sections nested inside `@notice` / `@dev` bodies.
    // Each bulleted line ("- ..." or "* ...") becomes a low-confidence
    // precondition with variable=`"requirement"` so callers can
    // distinguish from `@param`-derived entries.
    for body in [doc.notice.as_deref(), doc.dev.as_deref()].iter().flatten() {
        for bullet in extract_natspec_requirement_bullets(body) {
            preconditions.push(Condition::low(
                "requirement",
                bullet,
                line,
            ));
        }
    }
}

/// solidity-sol016-cluster-v1 M14: extract bullet-listed requirements
/// from a NatSpec `@notice`/`@dev` body.
///
/// Recognises a "Requirements:" or "Conditions:" marker (case
/// insensitive) and collects every following whitespace-separated
/// bullet (`- text`, `* text`, `• text`) until the next non-bullet
/// line. NatSpec normalisation already concatenates continuation lines
/// with single spaces, so the marker and bullets appear here as a flat
/// string. We split on the marker then look for bullet shapes.
fn extract_natspec_requirement_bullets(body: &str) -> Vec<String> {
    let lower = body.to_lowercase();
    let marker_idx = lower
        .find("requirements:")
        .or_else(|| lower.find("conditions:"));
    let Some(idx) = marker_idx else {
        return Vec::new();
    };
    // Slice the tail starting AFTER the marker (which is 13 or 11 chars).
    let marker_len = if lower[idx..].starts_with("requirements:") {
        "requirements:".len()
    } else {
        "conditions:".len()
    };
    let tail = &body[idx + marker_len..];

    let mut bullets = Vec::new();
    // Bullets can be separated by " - " or " * " or " • " after
    // NatSpec normalisation collapsed line breaks into single spaces.
    // Split on whitespace boundaries followed by a bullet marker.
    let mut remaining = tail.trim_start();
    while let Some(b_idx) = first_bullet_index(remaining) {
        // Trim everything before the bullet marker (free-form prose).
        remaining = &remaining[b_idx..];
        // Strip the leading bullet character ("- ", "* ", "• ").
        let after_marker = remaining
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim_start_matches('•')
            .trim_start();
        // Find the next bullet (or end of string).
        let next = first_bullet_index(after_marker).unwrap_or(after_marker.len());
        let bullet_text = after_marker[..next].trim();
        if !bullet_text.is_empty() {
            bullets.push(bullet_text.to_string());
        }
        if next >= after_marker.len() {
            break;
        }
        remaining = &after_marker[next..];
    }
    bullets
}

/// Find the byte index of the next bullet marker (`-`, `*`, or `•`)
/// that is either at the start of `s` or follows whitespace. Returns
/// `None` if no such marker exists.
fn first_bullet_index(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'-' || *b == b'*' {
            // Must be at start or preceded by whitespace.
            if i == 0 || bytes[i - 1].is_ascii_whitespace() {
                // Must be followed by whitespace (avoid matching
                // negation operators like `-1`).
                if bytes
                    .get(i + 1)
                    .copied()
                    .is_some_and(|c| c.is_ascii_whitespace())
                {
                    return Some(i);
                }
            }
        }
    }
    // Also try the UTF-8 bullet character `•` (E2 80 A2).
    if let Some(idx) = s.find('•') {
        // Must be at start or preceded by whitespace.
        let before_ok = idx == 0
            || s[..idx]
                .chars()
                .last()
                .is_some_and(|c| c.is_whitespace());
        if before_ok {
            return Some(idx);
        }
    }
    None
}

/// Extract a Python docstring from a function definition.
///
/// In tree-sitter, the docstring is the first `expression_statement` child
/// of the function body, containing a `string` node.
fn extract_python_docstring<'a>(
    func: Node<'a>,
    source: &'a [u8],
    config: &LanguageConfig,
) -> Option<String> {
    let body = func.child_by_field_name(config.func_body_field)?;

    let mut cursor = body.walk();
    if let Some(stmt) = body.children(&mut cursor).next() {
        if stmt.kind() == "expression_statement" {
            // Check for string child (docstring)
            let mut inner = stmt.walk();
            for child in stmt.children(&mut inner) {
                if child.kind() == "string" || child.kind() == "concatenated_string" {
                    let text = get_node_text(child, source);
                    // Strip triple quotes
                    let stripped = text
                        .trim_start_matches("\"\"\"")
                        .trim_start_matches("'''")
                        .trim_start_matches("r\"\"\"")
                        .trim_start_matches("r'''")
                        .trim_end_matches("\"\"\"")
                        .trim_end_matches("'''");
                    return Some(stripped.to_string());
                }
            }
        }
    }

    None
}

/// Extract a JSDoc comment that precedes a function declaration.
///
/// In tree-sitter, comments are typically siblings before the function node.
/// JSDoc comments start with `/**`.
fn extract_jsdoc_comment(func: Node, source: &[u8]) -> Option<String> {
    // Walk backward through preceding siblings to find a comment
    let mut node = func;

    // First check if the function is inside a wrapper (export_statement, etc.)
    // by looking at parent's preceding children
    if let Some(parent) = func.parent() {
        if parent.kind() == "export_statement"
            || parent.kind() == "export_default_declaration"
            || parent.kind() == "decorated_definition"
        {
            node = parent;
        }
    }

    let mut prev = node.prev_sibling();
    if let Some(sibling) = prev {
        if sibling.kind() == "comment" {
            let text = get_node_text(sibling, source);
            if text.starts_with("/**") {
                // Strip comment markers
                let stripped = text
                    .trim_start_matches("/**")
                    .trim_end_matches("*/")
                    .lines()
                    .map(|l| l.trim().trim_start_matches('*').trim())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Some(stripped);
            }
        }
    }

    // Also check if there is a leading comment in the parent scope
    // For `program > comment, function_declaration` pattern
    prev = node.prev_sibling();
    while let Some(sibling) = prev {
        let kind = sibling.kind();
        if kind == "comment" {
            let text = get_node_text(sibling, source);
            if text.starts_with("/**") {
                let stripped = text
                    .trim_start_matches("/**")
                    .trim_end_matches("*/")
                    .lines()
                    .map(|l| l.trim().trim_start_matches('*').trim())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Some(stripped);
            }
        }
        prev = sibling.prev_sibling();
    }

    None
}

/// Extract Sphinx-style docstring parameters and return types.
///
/// Patterns:
/// - `:param name: description` -> precondition
/// - `:type name: typename` -> type precondition
/// - `:return: description` or `:returns: description` -> postcondition
/// - `:rtype: typename` -> return type postcondition
fn extract_sphinx_params(
    docstring: &str,
    preconditions: &mut Vec<Condition>,
    postconditions: &mut Vec<Condition>,
    line: u32,
    existing_pre_vars: &HashSet<String>,
    existing_post_vars: &HashSet<String>,
) {
    // :param name: description
    let param_re = Regex::new(r":param\s+(\w+)\s*:(.*)").unwrap();
    // :type name: typename
    let type_re = Regex::new(r":type\s+(\w+)\s*:\s*(.+)").unwrap();
    // :return: or :returns: description
    let return_re = Regex::new(r":returns?\s*:(.*)").unwrap();
    // :rtype: typename
    let rtype_re = Regex::new(r":rtype\s*:\s*(.+)").unwrap();

    // Track params we add from :param so we can merge with :type
    let mut param_types: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // First pass: collect :type annotations
    for cap in type_re.captures_iter(docstring) {
        let name = cap[1].trim().to_string();
        let type_str = cap[2].trim().to_string();
        param_types.insert(name, type_str);
    }

    // Second pass: extract :param entries
    for cap in param_re.captures_iter(docstring) {
        let name = cap[1].trim().to_string();
        let desc = cap[2].trim().to_string();

        if existing_pre_vars.contains(&name) {
            continue;
        }

        let constraint = if let Some(type_str) = param_types.get(&name) {
            format!("{}: {} ({})", name, type_str, desc)
        } else {
            format!("{}: {}", name, desc)
        };

        preconditions.push(Condition::low(name, constraint, line));
    }

    // Extract :rtype postcondition
    for cap in rtype_re.captures_iter(docstring) {
        let type_str = cap[1].trim().to_string();
        if !type_str.is_empty() && !existing_post_vars.contains("return") {
            let constraint = format!("isinstance(return, {})", type_str);
            postconditions.push(Condition::low("return".to_string(), constraint, line));
        }
    }

    // Extract :return: description (only if no :rtype already added a postcondition)
    let has_rtype = postconditions.iter().any(|c| c.variable == "return");
    if !has_rtype {
        for cap in return_re.captures_iter(docstring) {
            let desc = cap[1].trim().to_string();
            if !desc.is_empty() && !existing_post_vars.contains("return") {
                let constraint = format!("returns: {}", desc);
                postconditions.push(Condition::low("return".to_string(), constraint, line));
                break; // Only take the first :return:
            }
        }
    }
}

/// Extract JSDoc @param and @returns entries.
///
/// Patterns:
/// - `@param {type} name - description` -> precondition
/// - `@param {type} name description` -> precondition (no dash)
/// - `@param name description` -> precondition (no type)
/// - `@returns {type} description` or `@return {type} description` -> postcondition
fn extract_jsdoc_params(
    jsdoc: &str,
    preconditions: &mut Vec<Condition>,
    postconditions: &mut Vec<Condition>,
    line: u32,
    existing_pre_vars: &HashSet<String>,
    existing_post_vars: &HashSet<String>,
) {
    // @param {type} name - description (type is optional)
    let param_with_type_re = Regex::new(r"@param\s+\{([^}]+)\}\s+(\w+)\s*[-:]?\s*(.*)").unwrap();
    let param_no_type_re = Regex::new(r"@param\s+(\w+)\s*[-:]?\s*(.*)").unwrap();
    // @returns {type} description or @return {type} description
    let returns_with_type_re = Regex::new(r"@returns?\s+\{([^}]+)\}\s*(.*)").unwrap();
    let returns_no_type_re = Regex::new(r"@returns?\s+(.+)").unwrap();

    // Extract @param with type first (more specific pattern)
    let mut seen_params: HashSet<String> = HashSet::new();

    for cap in param_with_type_re.captures_iter(jsdoc) {
        let type_str = cap[1].trim().to_string();
        let name = cap[2].trim().to_string();
        let desc = cap[3].trim().to_string();

        if existing_pre_vars.contains(&name) || seen_params.contains(&name) {
            continue;
        }
        seen_params.insert(name.clone());

        let constraint = if desc.is_empty() {
            format!("{}: {}", name, type_str)
        } else {
            format!("{}: {} ({})", name, type_str, desc)
        };
        preconditions.push(Condition::low(name, constraint, line));
    }

    // Extract @param without type (only for params not already found)
    for cap in param_no_type_re.captures_iter(jsdoc) {
        let name = cap[1].trim().to_string();
        let desc = cap[2].trim().to_string();

        if existing_pre_vars.contains(&name) || seen_params.contains(&name) {
            continue;
        }
        seen_params.insert(name.clone());

        let constraint = if desc.is_empty() {
            format!("parameter {} is required", name)
        } else {
            format!("{}: {}", name, desc)
        };
        preconditions.push(Condition::low(name, constraint, line));
    }

    // Extract @returns with type
    let mut has_return = existing_post_vars.contains("return");
    for cap in returns_with_type_re.captures_iter(jsdoc) {
        if has_return {
            break;
        }
        let type_str = cap[1].trim().to_string();
        let desc = cap[2].trim().to_string();

        let constraint = if desc.is_empty() {
            format!("return: {}", type_str)
        } else {
            format!("return: {} ({})", type_str, desc)
        };
        postconditions.push(Condition::low("return".to_string(), constraint, line));
        has_return = true;
    }

    // Extract @returns without type (fallback)
    if !has_return {
        for cap in returns_no_type_re.captures_iter(jsdoc) {
            let desc = cap[1].trim().to_string();
            // Skip if it looks like a type annotation we already matched
            if desc.starts_with('{') {
                continue;
            }
            if !desc.is_empty() {
                let constraint = format!("returns: {}", desc);
                postconditions.push(Condition::low("return".to_string(), constraint, line));
                break;
            }
        }
    }
}

// =============================================================================
// Invariant Extraction
// =============================================================================

/// Extract invariants from assertions inside loops (multi-language).
fn extract_invariants(
    func: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    depth: usize,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    check_ast_depth(depth, &PathBuf::from("<source>"))?;

    let body = match get_function_body(func, config) {
        Some(b) => b,
        None => return Ok(()),
    };

    extract_invariants_from_block(body, source, conditions, depth + 1, config)?;

    Ok(())
}

/// Recursively extract invariants from a block, looking for loops (multi-language).
fn extract_invariants_from_block(
    block: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    depth: usize,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    if depth > MAX_AST_DEPTH {
        return Ok(());
    }

    let mut cursor = block.walk();

    for stmt in block.children(&mut cursor) {
        let kind = stmt.kind();

        if config.is_loop(kind) {
            // Look for asserts inside this loop
            if let Some(loop_body) = stmt.child_by_field_name(config.loop_body_field) {
                extract_asserts_as_invariants(loop_body, source, conditions, config)?;
            }
        } else if config.is_if(kind) {
            // Check nested blocks
            if let Some(consequence) = stmt.child_by_field_name(config.if_consequence_field) {
                extract_invariants_from_block(consequence, source, conditions, depth + 1, config)?;
            }
            if let Some(alternative) = stmt.child_by_field_name(config.if_alternative_field) {
                extract_invariants_from_block(alternative, source, conditions, depth + 1, config)?;
            }
        }
    }

    Ok(())
}

/// Extract assert statements/macros as invariants from a loop body (multi-language).
fn extract_asserts_as_invariants(
    block: Node,
    source: &[u8],
    conditions: &mut Vec<Condition>,
    config: &LanguageConfig,
) -> ContractsResult<()> {
    let mut cursor = block.walk();

    for stmt in block.children(&mut cursor) {
        let kind = stmt.kind();

        if config.is_assert(kind) {
            if config.assert_is_macro {
                // Rust: assert!() macro
                if is_assert_macro(stmt, source) {
                    if let Some(args) = extract_macro_args(stmt, source) {
                        let line = stmt.start_position().row as u32 + 1;
                        conditions.push(Condition::medium(args.clone(), args, line));
                    }
                }
            } else {
                // Standard assert statement
                let mut inner_cursor = stmt.walk();
                for child in stmt.children(&mut inner_cursor) {
                    if child.kind() != "assert" && child.kind() != "assert_keyword" {
                        let constraint = get_node_text(child, source);
                        let line = stmt.start_position().row as u32 + 1;
                        conditions.push(Condition::medium(
                            constraint.to_string(),
                            constraint.to_string(),
                            line,
                        ));
                        break;
                    }
                }
            }
        } else if config.assert_is_macro && kind == "expression_statement" {
            // Rust: assert!() inside expression_statement
            let mut inner = stmt.walk();
            for child in stmt.children(&mut inner) {
                if config.is_assert(child.kind()) && is_assert_macro(child, source) {
                    if let Some(args) = extract_macro_args(child, source) {
                        let line = stmt.start_position().row as u32 + 1;
                        conditions.push(Condition::medium(args.clone(), args, line));
                    }
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Condition Negation
// =============================================================================

/// Negate a comparison operator expression.
///
/// `x < 0` -> `x >= 0`
fn negate_comparison(node: Node, source: &[u8]) -> Option<String> {
    // Find the operator
    let mut cursor = node.walk();
    let mut left = None;
    let mut op = None;
    let mut right = None;

    for child in node.children(&mut cursor) {
        let kind = child.kind();
        match kind {
            "<" | ">" | "<=" | ">=" | "==" | "!=" => {
                op = Some(get_node_text(child, source));
            }
            _ => {
                if left.is_none() {
                    left = Some(child);
                } else if right.is_none() {
                    right = Some(child);
                }
            }
        }
    }

    let left_node = left?;
    let right_node = right?;
    let op_text = op?;

    let left_text = get_node_text(left_node, source);
    let right_text = get_node_text(right_node, source);

    let negated_op = negate_operator(op_text)?;
    Some(format!("{} {} {}", left_text, negated_op, right_text))
}

/// Negate a comparison operator.
fn negate_operator(op: &str) -> Option<&'static str> {
    match op {
        "<" => Some(">="),
        "<=" => Some(">"),
        ">" => Some("<="),
        ">=" => Some("<"),
        "==" => Some("!="),
        "!=" => Some("=="),
        "is" => Some("is not"),
        "is not" => Some("is"),
        "in" => Some("not in"),
        "not in" => Some("in"),
        _ => None,
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a call node is an isinstance call.
fn is_isinstance_call(node: Node, source: &[u8]) -> bool {
    if node.kind() != "call" {
        return false;
    }

    if let Some(func) = node.child_by_field_name("function") {
        let func_name = get_node_text(func, source);
        return func_name == "isinstance";
    }

    false
}

/// Extract the variable being checked in an isinstance call.
fn extract_isinstance_var(node: Node, source: &[u8]) -> String {
    if let Some(args) = node.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for arg in args.children(&mut cursor) {
            let kind = arg.kind();
            if kind != "(" && kind != ")" && kind != "," {
                return get_node_text(arg, source).to_string();
            }
        }
    }
    "?".to_string()
}

/// Extract the left operand from a comparison.
fn extract_left_operand(node: Node, source: &[u8]) -> String {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Return the first non-operator child
        let kind = child.kind();
        match kind {
            "<" | ">" | "<=" | ">=" | "==" | "!=" | "is" | "is not" | "in" | "not in" => continue,
            _ => return get_node_text(child, source).to_string(),
        }
    }
    get_node_text(node, source).to_string()
}

/// Deduplicate conditions by (variable, constraint) tuple.
fn deduplicate_conditions(mut conditions: Vec<Condition>) -> Vec<Condition> {
    let mut seen = HashSet::new();
    conditions.retain(|c| {
        let key = (c.variable.clone(), c.constraint.clone());
        seen.insert(key)
    });
    conditions
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Format a contracts report as human-readable text.
pub fn format_contracts_text(report: &ContractsReport) -> String {
    let mut output = String::new();

    output.push_str(&format!("Function: {}\n", report.function));

    let mut any_contracts = false;

    for (label, conds) in [
        ("Preconditions", &report.preconditions),
        ("Postconditions", &report.postconditions),
        ("Invariants", &report.invariants),
    ] {
        if !conds.is_empty() {
            any_contracts = true;
            output.push_str(&format!("  {}:\n", label));
            for c in conds {
                output.push_str(&format!(
                    "    - {} ({}, line {}, {})\n",
                    c.constraint, c.variable, c.source_line, c.confidence
                ));
            }
        }
    }

    if !any_contracts {
        output.push_str("  (none detected)\n");
    }

    output
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const PYTHON_GUARD_CLAUSES: &str = r#"
def process_data(x, data):
    if x < 0:
        raise ValueError("x must be non-negative")
    if not isinstance(data, list):
        raise TypeError("data must be a list")
    result = sum(data) + x
    return result
"#;

    const PYTHON_ASSERTS: &str = r#"
def calculate(a, b):
    assert a > 0
    assert isinstance(b, int)
    result = a * b
    return result
"#;

    const PYTHON_POSTCONDITIONS: &str = r#"
def divide(a, b):
    if b == 0:
        raise ZeroDivisionError("Cannot divide by zero")
    result = a / b
    assert result is not None
    return result
"#;

    #[test]
    fn test_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.py");
        fs::write(&file_path, PYTHON_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "process_data", Language::Python, 100).unwrap();

        // Should detect preconditions from guard clauses
        assert!(
            !report.preconditions.is_empty(),
            "Should detect preconditions"
        );

        // Check for x >= 0 (negation of x < 0)
        let has_x_precond = report
            .preconditions
            .iter()
            .any(|p| p.variable.contains("x") && p.constraint.contains(">="));
        assert!(has_x_precond, "Should detect x >= 0 precondition");
    }

    #[test]
    fn test_assert_extraction() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("asserts.py");
        fs::write(&file_path, PYTHON_ASSERTS).unwrap();

        let report = run_contracts(&file_path, "calculate", Language::Python, 100).unwrap();

        assert!(
            report.preconditions.len() >= 2,
            "Should detect at least 2 preconditions"
        );

        // Check for a > 0
        let has_a_precond = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("a > 0") || p.constraint.contains("a>0"));
        assert!(has_a_precond, "Should detect a > 0 precondition");
    }

    #[test]
    fn test_postcondition_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("postcond.py");
        fs::write(&file_path, PYTHON_POSTCONDITIONS).unwrap();

        let report = run_contracts(&file_path, "divide", Language::Python, 100).unwrap();

        // Should detect postcondition: result is not None
        assert!(
            !report.postconditions.is_empty(),
            "Should detect postconditions"
        );

        let has_result_postcond = report
            .postconditions
            .iter()
            .any(|p| p.variable.contains("result") && p.constraint.contains("None"));
        assert!(
            has_result_postcond,
            "Should detect result is not None postcondition"
        );
    }

    #[test]
    fn test_confidence_scoring() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.py");
        fs::write(&file_path, PYTHON_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "process_data", Language::Python, 100).unwrap();

        // Guard clause preconditions should have high confidence
        for precond in &report.preconditions {
            if precond.constraint.contains(">=") || precond.constraint.contains("isinstance") {
                assert_eq!(
                    precond.confidence,
                    Confidence::High,
                    "Guard clause should have High confidence"
                );
            }
        }
    }

    #[test]
    fn test_function_not_found() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.py");
        fs::write(&file_path, "def foo(): pass").unwrap();

        let result = run_contracts(&file_path, "nonexistent", Language::Python, 100);
        assert!(result.is_err());

        match result.unwrap_err() {
            ContractsError::FunctionNotFound { function, .. } => {
                assert_eq!(function, "nonexistent");
            }
            e => panic!("Expected FunctionNotFound, got {:?}", e),
        }
    }

    #[test]
    fn test_empty_function() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("empty.py");
        fs::write(&file_path, "def empty(): pass").unwrap();

        let report = run_contracts(&file_path, "empty", Language::Python, 100).unwrap();

        assert!(report.preconditions.is_empty());
        assert!(report.postconditions.is_empty());
        assert!(report.invariants.is_empty());
    }

    #[test]
    fn test_deduplicate_conditions() {
        let conditions = vec![
            Condition::high("x", "x > 0", 1),
            Condition::high("x", "x > 0", 2), // Duplicate
            Condition::high("y", "y > 0", 3),
        ];

        let deduped = deduplicate_conditions(conditions);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_negate_operator() {
        assert_eq!(negate_operator("<"), Some(">="));
        assert_eq!(negate_operator("<="), Some(">"));
        assert_eq!(negate_operator(">"), Some("<="));
        assert_eq!(negate_operator(">="), Some("<"));
        assert_eq!(negate_operator("=="), Some("!="));
        assert_eq!(negate_operator("!="), Some("=="));
        assert_eq!(negate_operator("is"), Some("is not"));
        assert_eq!(negate_operator("is not"), Some("is"));
    }

    // =========================================================================
    // Multi-language tests
    // =========================================================================

    const RUST_GUARD_CLAUSES: &str = r#"
fn process_data(x: i32, data: &[i32]) -> i32 {
    if x < 0 {
        panic!("x must be non-negative");
    }
    assert!(data.len() > 0);
    let result = data.iter().sum::<i32>() + x;
    assert!(result >= 0);
    result
}
"#;

    #[test]
    fn test_rust_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.rs");
        fs::write(&file_path, RUST_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "process_data", Language::Rust, 100).unwrap();

        // Should detect preconditions from guard clause (panic) and assert!
        assert!(
            !report.preconditions.is_empty(),
            "Rust: Should detect preconditions, got: {:?}",
            report.preconditions
        );
    }

    #[test]
    fn test_rust_assert_macro() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("asserts.rs");
        fs::write(&file_path, RUST_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "process_data", Language::Rust, 100).unwrap();

        // Should detect assert!() as preconditions
        let has_assert = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("data.len() > 0") || p.constraint.contains("len"));
        assert!(
            has_assert,
            "Rust: Should detect assert!(data.len() > 0), got: {:?}",
            report.preconditions
        );
    }

    #[test]
    fn test_rust_postcondition() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("postcond.rs");
        fs::write(&file_path, RUST_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "process_data", Language::Rust, 100).unwrap();

        // Should detect postcondition: assert!(result >= 0) after result assignment
        assert!(
            !report.postconditions.is_empty(),
            "Rust: Should detect postconditions after result assignment, got: {:?}",
            report.postconditions
        );
    }

    const GO_GUARD_CLAUSES: &str = r#"
package main

import "errors"

func processData(x int, data []int) (int, error) {
    if x < 0 {
        return 0, errors.New("x must be non-negative")
    }
    if len(data) == 0 {
        return 0, errors.New("data must not be empty")
    }
    result := 0
    for _, v := range data {
        result += v
    }
    return result + x, nil
}
"#;

    #[test]
    fn test_go_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.go");
        fs::write(&file_path, GO_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::Go, 100).unwrap();

        // Should detect preconditions from guard clauses with early return
        assert!(
            !report.preconditions.is_empty(),
            "Go: Should detect preconditions from guard clauses, got: {:?}",
            report.preconditions
        );

        // Check for x >= 0 (negation of x < 0)
        let has_x_precond = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains(">=") || p.constraint.contains("x"));
        assert!(
            has_x_precond,
            "Go: Should detect x >= 0 precondition, got: {:?}",
            report.preconditions
        );
    }

    const JAVA_GUARD_CLAUSES: &str = r#"
public class Processor {
    public int processData(int x, int[] data) {
        if (x < 0) {
            throw new IllegalArgumentException("x must be non-negative");
        }
        assert data.length > 0;
        int result = 0;
        for (int v : data) {
            result += v;
        }
        return result + x;
    }
}
"#;

    #[test]
    fn test_java_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("Processor.java");
        fs::write(&file_path, JAVA_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::Java, 100).unwrap();

        // Should detect preconditions from guard clauses with throw
        assert!(
            !report.preconditions.is_empty(),
            "Java: Should detect preconditions, got: {:?}",
            report.preconditions
        );
    }

    #[test]
    fn test_java_assert_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("Assert.java");
        fs::write(&file_path, JAVA_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::Java, 100).unwrap();

        // Should detect assert statement
        let has_assert = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("data.length") || p.constraint.contains("length"));
        assert!(
            has_assert,
            "Java: Should detect assert data.length > 0, got: {:?}",
            report.preconditions
        );
    }

    const TS_GUARD_CLAUSES: &str = r#"
function processData(x: number, data: number[]): number {
    if (x < 0) {
        throw new Error("x must be non-negative");
    }
    if (data.length === 0) {
        throw new Error("data must not be empty");
    }
    let result = data.reduce((a, b) => a + b, 0) + x;
    return result;
}
"#;

    #[test]
    fn test_ts_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.ts");
        fs::write(&file_path, TS_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::TypeScript, 100).unwrap();

        // Should detect preconditions from guard clauses with throw
        assert!(
            !report.preconditions.is_empty(),
            "TypeScript: Should detect preconditions from throw guards, got: {:?}",
            report.preconditions
        );
    }

    #[test]
    fn test_ts_type_annotations() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("typed.ts");
        fs::write(&file_path, TS_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::TypeScript, 100).unwrap();

        // Should detect type annotations as low-confidence preconditions
        let has_type_precond = report
            .preconditions
            .iter()
            .any(|p| p.confidence == Confidence::Low && p.constraint.contains("number"));
        assert!(
            has_type_precond,
            "TypeScript: Should detect type annotation preconditions, got: {:?}",
            report.preconditions
        );
    }

    const CPP_GUARD_CLAUSES: &str = r#"
#include <stdexcept>
#include <vector>

int processData(int x, const std::vector<int>& data) {
    if (x < 0) {
        throw std::invalid_argument("x must be non-negative");
    }
    int result = 0;
    for (int v : data) {
        result += v;
    }
    return result + x;
}
"#;

    #[test]
    fn test_cpp_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("guards.cpp");
        fs::write(&file_path, CPP_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "processData", Language::Cpp, 100).unwrap();

        // Should detect preconditions from guard clauses with throw
        assert!(
            !report.preconditions.is_empty(),
            "C++: Should detect preconditions from throw guards, got: {:?}",
            report.preconditions
        );
    }

    const CSHARP_GUARD_CLAUSES: &str = r#"
public class Processor {
    public int ProcessData(int x, int[] data) {
        if (x < 0) {
            throw new ArgumentException("x must be non-negative");
        }
        if (data.Length == 0) {
            throw new ArgumentException("data must not be empty");
        }
        int result = 0;
        foreach (int v in data) {
            result += v;
        }
        return result + x;
    }
}
"#;

    #[test]
    fn test_csharp_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("Processor.cs");
        fs::write(&file_path, CSHARP_GUARD_CLAUSES).unwrap();

        let report = run_contracts(&file_path, "ProcessData", Language::CSharp, 100).unwrap();

        // Should detect preconditions from guard clauses with throw
        assert!(
            !report.preconditions.is_empty(),
            "C#: Should detect preconditions from throw guards, got: {:?}",
            report.preconditions
        );
    }

    // Test that all major languages successfully parse (no panics)
    #[test]
    fn test_multi_language_no_panic() {
        let temp = TempDir::new().unwrap();

        let test_cases: Vec<(&str, Language, &str, &str)> = vec![
            ("test.py", Language::Python, "foo", "def foo(x):\n    if x < 0:\n        raise ValueError('bad')\n    return x\n"),
            ("test.go", Language::Go, "foo", "package main\nfunc foo(x int) int {\n    if x < 0 {\n        return -1\n    }\n    return x\n}\n"),
            ("test.rs", Language::Rust, "foo", "fn foo(x: i32) -> i32 {\n    if x < 0 {\n        panic!(\"bad\");\n    }\n    x\n}\n"),
            ("test.java", Language::Java, "foo", "class T {\n    int foo(int x) {\n        if (x < 0) {\n            throw new RuntimeException(\"bad\");\n        }\n        return x;\n    }\n}\n"),
            ("test.ts", Language::TypeScript, "foo", "function foo(x: number): number {\n    if (x < 0) {\n        throw new Error('bad');\n    }\n    return x;\n}\n"),
            ("test.c", Language::C, "foo", "int foo(int x) {\n    if (x < 0) {\n        return -1;\n    }\n    return x;\n}\n"),
            ("test.cpp", Language::Cpp, "foo", "int foo(int x) {\n    if (x < 0) {\n        throw -1;\n    }\n    return x;\n}\n"),
            ("test.cs", Language::CSharp, "Foo", "class T {\n    int Foo(int x) {\n        if (x < 0) {\n            throw new Exception(\"bad\");\n        }\n        return x;\n    }\n}\n"),
        ];

        for (filename, lang, func_name, source) in test_cases {
            let file_path = temp.path().join(filename);
            fs::write(&file_path, source).unwrap();

            let result = run_contracts(&file_path, func_name, lang, 100);
            assert!(
                result.is_ok(),
                "{:?}: Should parse without error, got: {:?}",
                lang,
                result.err()
            );

            let report = result.unwrap();
            // Every test case has a guard clause, so should detect at least one precondition
            assert!(
                !report.preconditions.is_empty(),
                "{:?}: Should detect at least one precondition from guard clause, got: {:?}",
                lang,
                report
            );
        }
    }

    #[test]
    fn test_find_ts_arrow_function_contracts() {
        let ts_source = r#"
const getDuration = (start: Date, end: Date): number => {
    if (!start || !end) {
        throw new Error("invalid arguments");
    }
    return end.getTime() - start.getTime();
};
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("arrow.ts");
        fs::write(&file_path, ts_source).unwrap();

        let result = run_contracts(&file_path, "getDuration", Language::TypeScript, 100);
        assert!(
            result.is_ok(),
            "Should find TS arrow function 'getDuration' for contracts analysis, got: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // P3 Bug Fix Tests: Untyped parameters and docstrings
    // =========================================================================

    /// Python function with untyped parameters should produce basic preconditions
    /// from parameter names alone (the function clearly takes `method`, `url`, `**kwargs`).
    #[test]
    fn test_python_untyped_params_produce_preconditions() {
        let source = r#"
def request(method, url, **kwargs):
    """Sends a request."""
    with sessions.Session() as session:
        return session.request(method=method, url=url, **kwargs)
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("api.py");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "request", Language::Python, 100).unwrap();

        // Should detect at least basic preconditions from parameter names
        let has_method_param = report.preconditions.iter().any(|p| p.variable == "method");
        let has_url_param = report.preconditions.iter().any(|p| p.variable == "url");

        assert!(
            has_method_param,
            "Should detect 'method' parameter as precondition, got: {:?}",
            report.preconditions
        );
        assert!(
            has_url_param,
            "Should detect 'url' parameter as precondition, got: {:?}",
            report.preconditions
        );
    }

    /// Python function with typed parameters should produce preconditions
    /// with type info even when there are no guard clauses.
    #[test]
    fn test_python_typed_params_no_guards() {
        let source = r#"
def greet(name: str, count: int = 1) -> str:
    return (name + "! ") * count
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("greet.py");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "greet", Language::Python, 100).unwrap();

        // Should have type annotation preconditions (low confidence)
        let has_name_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "name" && p.constraint.contains("str"));
        let has_count_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "count" && p.constraint.contains("int"));
        let has_return_type = report
            .postconditions
            .iter()
            .any(|p| p.constraint.contains("str"));

        assert!(
            has_name_type,
            "Should detect name: str type precondition, got: {:?}",
            report.preconditions
        );
        assert!(
            has_count_type,
            "Should detect count: int type precondition, got: {:?}",
            report.preconditions
        );
        assert!(
            has_return_type,
            "Should detect -> str return type postcondition, got: {:?}",
            report.postconditions
        );
    }

    /// Python docstring with :param and :return: should produce contracts.
    #[test]
    fn test_python_docstring_param_extraction() {
        let source = r#"
def request(method, url, **kwargs):
    """Constructs and sends a Request.

    :param method: method for the new Request object.
    :param url: URL for the new Request object.
    :param params: (optional) Dictionary to send in the query string.
    :return: Response object
    :rtype: requests.Response
    """
    with sessions.Session() as session:
        return session.request(method=method, url=url, **kwargs)
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("api.py");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "request", Language::Python, 100).unwrap();

        // Should extract docstring params as preconditions
        let has_method = report.preconditions.iter().any(|p| p.variable == "method");
        let has_url = report.preconditions.iter().any(|p| p.variable == "url");

        assert!(
            has_method,
            "Should extract :param method from docstring, got: {:?}",
            report.preconditions
        );
        assert!(
            has_url,
            "Should extract :param url from docstring, got: {:?}",
            report.preconditions
        );

        // Should extract :rtype as postcondition
        let has_return = report.postconditions.iter().any(|p| {
            p.constraint.contains("Response") || p.constraint.contains("requests.Response")
        });
        assert!(
            has_return,
            "Should extract :rtype from docstring as postcondition, got: {:?}",
            report.postconditions
        );
    }

    /// Python **kwargs should be recognized as a parameter
    #[test]
    fn test_python_kwargs_parameter() {
        let source = r#"
def request(method, url, **kwargs):
    pass
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("kwargs.py");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "request", Language::Python, 100).unwrap();

        // Should detect kwargs as a parameter
        let has_kwargs = report
            .preconditions
            .iter()
            .any(|p| p.variable == "kwargs" || p.variable == "**kwargs");

        assert!(
            has_kwargs,
            "Should detect **kwargs parameter, got: {:?}",
            report.preconditions
        );
    }

    /// TypeScript function with typed params but no guard clauses should produce contracts.
    #[test]
    fn test_typescript_typed_params_no_guards() {
        let source = r#"
function processData(x: number, data: string[]): string {
    return data.join(", ") + x.toString();
}
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("process.ts");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "processData", Language::TypeScript, 100).unwrap();

        // Should detect type annotations as preconditions
        let has_x_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "x" && p.constraint.contains("number"));
        let has_data_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "data" && p.constraint.contains("string"));

        assert!(
            has_x_type,
            "Should detect x: number type precondition, got: {:?}",
            report.preconditions
        );
        assert!(
            has_data_type,
            "Should detect data: string[] type precondition, got: {:?}",
            report.preconditions
        );

        // Should detect return type postcondition
        let has_return = report
            .postconditions
            .iter()
            .any(|p| p.constraint.contains("string"));
        assert!(
            has_return,
            "Should detect return type string postcondition, got: {:?}",
            report.postconditions
        );
    }

    /// JSDoc @param and @returns should produce contracts for JS/TS functions.
    #[test]
    fn test_jsdoc_param_extraction() {
        let source = r#"
/**
 * Sends a request to the server.
 * @param {string} method - The HTTP method.
 * @param {string} url - The request URL.
 * @returns {Promise<Response>} The server response.
 */
function request(method, url) {
    return fetch(url, { method: method });
}
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("api.js");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "request", Language::JavaScript, 100).unwrap();

        // Should extract JSDoc @param as preconditions
        let has_method = report.preconditions.iter().any(|p| p.variable == "method");
        let has_url = report.preconditions.iter().any(|p| p.variable == "url");

        assert!(
            has_method,
            "Should extract @param method from JSDoc, got: {:?}",
            report.preconditions
        );
        assert!(
            has_url,
            "Should extract @param url from JSDoc, got: {:?}",
            report.preconditions
        );

        // Should extract @returns as postcondition
        let has_return = report
            .postconditions
            .iter()
            .any(|p| p.constraint.contains("Promise") || p.constraint.contains("Response"));
        assert!(
            has_return,
            "Should extract @returns from JSDoc as postcondition, got: {:?}",
            report.postconditions
        );
    }

    /// Rust function with `return Err(...)` guard clauses should produce preconditions.
    ///
    /// This tests the pattern:
    /// ```rust
    /// fn transfer(amount: f64) -> Result<(), String> {
    ///     if amount <= 0.0 { return Err("Amount must be positive".to_string()); }
    /// }
    /// ```
    /// The `return Err(...)` is the Rust equivalent of `throw`/`raise`, and should
    /// be detected as a guard clause that produces a HIGH-confidence precondition.
    const RUST_RETURN_ERR_GUARDS: &str = r#"
fn transfer(amount: f64) -> Result<(), String> {
    if amount <= 0.0 {
        return Err("Amount must be positive".to_string());
    }
    if amount > 10000.0 {
        return Err("Amount exceeds limit".to_string());
    }
    Ok(())
}
"#;

    #[test]
    fn test_rust_return_err_guard_clause_detection() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("transfer.rs");
        fs::write(&file_path, RUST_RETURN_ERR_GUARDS).unwrap();

        let report = run_contracts(&file_path, "transfer", Language::Rust, 100).unwrap();

        // Should detect preconditions from `return Err(...)` guard clauses
        assert!(
            !report.preconditions.is_empty(),
            "Rust: Should detect preconditions from `return Err(...)` guard clauses, got: {:?}",
            report.preconditions
        );

        // `if amount <= 0.0 { return Err(...) }` -> precondition: amount > 0.0
        let has_amount_pos = report
            .preconditions
            .iter()
            .any(|p| p.variable.contains("amount") && p.constraint.contains(">"));
        assert!(
            has_amount_pos,
            "Rust: Should detect `amount > 0.0` precondition (negation of `amount <= 0.0`), got: {:?}",
            report.preconditions
        );

        // `if amount > 10000.0 { return Err(...) }` -> precondition: amount <= 10000.0
        let has_amount_limit = report
            .preconditions
            .iter()
            .any(|p| p.variable.contains("amount") && p.constraint.contains("<="));
        assert!(
            has_amount_limit,
            "Rust: Should detect `amount <= 10000.0` precondition (negation of `amount > 10000.0`), got: {:?}",
            report.preconditions
        );

        // All guard clause preconditions should have High confidence
        for precond in &report.preconditions {
            if precond.constraint.contains(">") || precond.constraint.contains("<=") {
                assert_eq!(
                    precond.confidence,
                    Confidence::High,
                    "Rust `return Err(...)` guard should produce High confidence, got: {:?}",
                    precond
                );
            }
        }
    }

    /// Go function with typed parameters but no error checks should still produce contracts.
    #[test]
    fn test_go_typed_params_no_guards() {
        let source = r#"
package main

func add(x int, y int) int {
    return x + y
}
"#;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("add.go");
        fs::write(&file_path, source).unwrap();

        let report = run_contracts(&file_path, "add", Language::Go, 100).unwrap();

        // Should detect parameter types as preconditions
        let has_x_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "x" && p.constraint.contains("int"));
        let has_y_type = report
            .preconditions
            .iter()
            .any(|p| p.variable == "y" && p.constraint.contains("int"));

        assert!(
            has_x_type,
            "Should detect x: int parameter type, got: {:?}",
            report.preconditions
        );
        assert!(
            has_y_type,
            "Should detect y: int parameter type, got: {:?}",
            report.preconditions
        );

        // Should detect return type
        let has_return = report
            .postconditions
            .iter()
            .any(|p| p.constraint.contains("int"));
        assert!(
            has_return,
            "Should detect int return type postcondition, got: {:?}",
            report.postconditions
        );
    }

    // =========================================================================
    // RC1 (R7 invariants-specs cluster): Swift contracts must detect
    // precondition()/assert()/guard. tree-sitter-swift wraps the top-level
    // body statements in an intermediate `statements` node that the
    // precondition body-walk never unwrapped, so Swift call-asserts were
    // never visited and `preconditions` was always empty.
    // =========================================================================

    const SWIFT_PRECONDITION_CALL: &str = r#"
struct Heap {
    var isEmpty: Bool = false

    mutating func replaceMin(with replacement: Int) -> Int {
        precondition(!isEmpty, "No element to replace")
        var removed = replacement
        return removed
    }
}
"#;

    #[test]
    fn test_swift_precondition_call_detected() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("Heap.swift");
        fs::write(&file_path, SWIFT_PRECONDITION_CALL).unwrap();

        let report = run_contracts(&file_path, "replaceMin", Language::Swift, 100).unwrap();

        // The `precondition(!isEmpty, ...)` call lives under the `statements`
        // wrapper inside `function_body`. It must be surfaced as a precondition.
        assert!(
            !report.preconditions.is_empty(),
            "Swift: should detect precondition() call, got: {:?}",
            report.preconditions
        );
        let has_isempty = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("isEmpty") || p.variable.contains("isEmpty"));
        assert!(
            has_isempty,
            "Swift: precondition should reference isEmpty, got: {:?}",
            report.preconditions
        );
        // The extracted condition must be ONLY the first argument (`!isEmpty`),
        // not the whole `(!isEmpty, "No element to replace")` argument list:
        // the diagnostic message string must not leak into the constraint.
        let leaks_message = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("No element to replace"));
        assert!(
            !leaks_message,
            "Swift: precondition constraint must not include the message string, got: {:?}",
            report.preconditions
        );
    }

    const SWIFT_GUARD_AND_ASSERT: &str = r#"
struct Stack {
    var count: Int = 0

    func popChecked(_ index: Int) -> Int {
        guard index >= 0 else {
            fatalError("index must be non-negative")
        }
        assert(count > 0, "stack must be non-empty")
        return index
    }
}
"#;

    #[test]
    fn test_swift_guard_and_assert_detected() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("Stack.swift");
        fs::write(&file_path, SWIFT_GUARD_AND_ASSERT).unwrap();

        let report = run_contracts(&file_path, "popChecked", Language::Swift, 100).unwrap();

        // Both the guard-with-fatalError and the assert() call live under the
        // `statements` wrapper. Each should yield a precondition.
        let has_guard = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("index") || p.variable.contains("index"));
        let has_assert = report
            .preconditions
            .iter()
            .any(|p| p.constraint.contains("count") || p.variable.contains("count"));
        assert!(
            has_guard,
            "Swift: should detect guard precondition on index, got: {:?}",
            report.preconditions
        );
        assert!(
            has_assert,
            "Swift: should detect assert() precondition on count, got: {:?}",
            report.preconditions
        );
    }

    // -------------------------------------------------------------------------
    // fix-R2-themeE (RC3): Lua/Luau untyped-parameter "all required" must
    // honour `or x == nil` optionality asserts. createElement's body guards
    // `props`/`children` with `assert(typeof(props) == 'table' or props == nil)`
    // (nested in `if config.typeChecks then`), so those params are OPTIONAL —
    // only `component` is genuinely required. Before the fix the untyped-param
    // extractor unconditionally emitted "parameter <name> is required" for all
    // three, never scanning the body.
    // -------------------------------------------------------------------------

    const LUA_OPTIONAL_PARAMS: &str = r#"
local function createElement(component, props, children)
    assert(typeof(component) == 'string')
    if config.typeChecks then
        assert(typeof(props) == 'table' or props == nil)
        assert(typeof(children) == 'table' or children == nil)
    end
    return { component = component }
end
"#;


    /// RC3: `props`/`children` made optional by `or x == nil` asserts must NOT
    /// carry a "parameter X is required" precondition; `component` (no such
    /// disjunction) must remain required. Lua variant.
    #[test]
    fn rc3_lua_or_nil_assert_marks_param_optional() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("createElement.lua");
        fs::write(&file_path, LUA_OPTIONAL_PARAMS).unwrap();

        let report = run_contracts(&file_path, "createElement", Language::Lua, 100).unwrap();

        let is_required = |name: &str| {
            report.preconditions.iter().any(|p| {
                p.variable == name && p.constraint == format!("parameter {} is required", name)
            })
        };

        assert!(
            is_required("component"),
            "RC3: `component` has no `or ==nil` guard and must stay required; got {:?}",
            report.preconditions
        );
        assert!(
            !is_required("props"),
            "RC3: `props` is guarded by `or props == nil` and must NOT be 'is required'; got {:?}",
            report.preconditions
        );
        assert!(
            !is_required("children"),
            "RC3: `children` is guarded by `or children == nil` and must NOT be 'is required'; got {:?}",
            report.preconditions
        );
    }

    /// RC3 (Luau blast-radius): the Luau grammar wraps each formal in a
    /// `parameter` node which the untyped-param extractor already treats as a
    /// typed-param kind and skips — so Luau never emitted "parameter X is
    /// required" for these to begin with. The Lua-targeted optionality fix must
    /// NOT regress Luau into newly emitting (or dropping anything from) that
    /// path. Pin Luau's actual behavior: none of the three appear as
    /// "is required", and the genuine `typeof(component)=='string'` assert
    /// precondition is still present.
    #[test]
    fn rc3_luau_param_required_behavior_unchanged() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("createElement.luau");
        fs::write(&file_path, LUA_OPTIONAL_PARAMS).unwrap();

        let report = run_contracts(&file_path, "createElement", Language::Luau, 100).unwrap();

        let is_required = |name: &str| {
            report.preconditions.iter().any(|p| {
                p.variable == name && p.constraint == format!("parameter {} is required", name)
            })
        };

        for name in ["component", "props", "children"] {
            assert!(
                !is_required(name),
                "RC3 (Luau): `{}` must not carry an 'is required' precondition (grammar wraps it in a `parameter` node); got {:?}",
                name,
                report.preconditions
            );
        }
        // The explicit guard assert is still surfaced.
        assert!(
            report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("typeof(component)")),
            "RC3 (Luau): the `assert(typeof(component) == 'string')` guard must still surface; got {:?}",
            report.preconditions
        );
    }

    /// RC3 blast-radius: a plain Lua function with NO `or ==nil` guards must
    /// keep ALL its params "is required" (the optionality scan must not
    /// over-fire and silence genuinely-required params).
    #[test]
    fn rc3_lua_plain_params_all_still_required() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("add.lua");
        let src = r#"
local function add(a, b)
    return a + b
end
"#;
        fs::write(&file_path, src).unwrap();

        let report = run_contracts(&file_path, "add", Language::Lua, 100).unwrap();

        for name in ["a", "b"] {
            assert!(
                report.preconditions.iter().any(|p| {
                    p.variable == name
                        && p.constraint == format!("parameter {} is required", name)
                }),
                "RC3 blast: plain param `{}` (no optionality guard) must stay required; got {:?}",
                name,
                report.preconditions
            );
        }
    }

    // -------------------------------------------------------------------------
    // fix-R3-rc2: precondition walk must be scope-aware.
    //   Facet (a): a PARAM assert nested in a leading guard-if consequence is
    //   recovered as an entry precondition (Piece 2 descent).
    //   Facet (b): a top-level assert on a BODY-LOCAL is NOT an entry contract
    //   and must leave `preconditions[]` (Piece 1 scope/order predicate).
    // -------------------------------------------------------------------------

    /// Facet (a) positive (Luau): `if cfg then assert(x ~= nil) end` lifts the
    /// guarded PARAM assert to a high-confidence entry precondition.
    #[test]
    fn rc2_luau_guarded_param_assert_recovered() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("f.luau");
        let src = r#"
local function f(x)
    if cfg then
        assert(x ~= nil)
    end
    return x
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "f", Language::Luau, 100).unwrap();

        let recovered = report
            .preconditions
            .iter()
            .find(|p| p.variable.contains("x") && p.constraint.contains("~= nil"));
        let recovered = recovered.unwrap_or_else(|| {
            panic!(
                "facet (a): guarded param assert `x ~= nil` must be recovered; got {:?}",
                report.preconditions
            )
        });
        assert_eq!(
            recovered.confidence,
            Confidence::High,
            "facet (a): recovered guarded param assert must be high confidence; got {:?}",
            report.preconditions
        );
    }

    /// Facet (a) positive (Lua): mirror of the Luau case.
    #[test]
    fn rc2_lua_guarded_param_assert_recovered() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("f.lua");
        let src = r#"
local function f(x)
    if cfg then
        assert(x ~= nil)
    end
    return x
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "f", Language::Lua, 100).unwrap();

        assert!(
            report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("~= nil") && p.confidence == Confidence::High),
            "facet (a) Lua: guarded param assert `x ~= nil` must be recovered as high; got {:?}",
            report.preconditions
        );
    }

    /// Facet (a) positive (Kotlin): `if (cfg) { require(x > 0) }` recovers the
    /// guarded param assert via the same Piece-2 descent (cross-language).
    #[test]
    fn rc2_kotlin_guarded_require_recovered() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("F.kt");
        let src = r#"
fun f(x: Int): Int {
    if (cfg) {
        require(x > 0)
    }
    return x
}
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "f", Language::Kotlin, 100).unwrap();

        assert!(
            report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("x > 0") && p.confidence == Confidence::High),
            "facet (a) Kotlin: guarded `require(x > 0)` must be recovered as high; got {:?}",
            report.preconditions
        );
    }

    /// Facet (a) negative: a BODY-LOCAL assert nested in a guard-if must NOT be
    /// promoted — Piece 2 + Piece 1 compose so only param asserts survive.
    #[test]
    fn rc2_luau_guarded_body_local_assert_not_promoted() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("g.luau");
        let src = r#"
local function g(p)
    local v = compute()
    if cfg then
        assert(v ~= nil)
    end
    return p
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "g", Language::Luau, 100).unwrap();

        assert!(
            !report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("v ~= nil")),
            "facet (a) neg: body-local `v` asserted in a guard-if must NOT be a precondition; got {:?}",
            report.preconditions
        );
    }

    /// Facet (a) `else`/`elseif` guard: an assert inside an `alternative` arm
    /// must NOT be promoted — only the unconditional `consequence` is descended.
    #[test]
    fn rc2_luau_else_arm_assert_not_promoted() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("h.luau");
        let src = r#"
local function h(x)
    if cfg then
        return x
    else
        assert(x ~= nil)
    end
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "h", Language::Luau, 100).unwrap();

        assert!(
            !report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("~= nil")),
            "facet (a): assert in an `else` arm must NOT be promoted; got {:?}",
            report.preconditions
        );
    }

    /// Facet (a) empty then-branch: `if cfg then end` (no consequence block)
    /// must not panic.
    #[test]
    fn rc2_luau_empty_then_no_panic() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("e.luau");
        let src = r#"
local function e(x)
    if cfg then end
    return x
end
"#;
        fs::write(&file_path, src).unwrap();
        // Must not panic; result is fine either way.
        let _ = run_contracts(&file_path, "e", Language::Luau, 100).unwrap();
    }

    /// Facet (b) (Luau): the `expectfail` reproduction — all three asserts
    /// reference body-locals (`success`/`actual`) so none may surface as an
    /// entry precondition. Includes the MIXED case (`string.find(actual,
    /// expected, ...)` references param `expected` AND local `actual`).
    #[test]
    fn rc2_luau_body_local_asserts_dropped() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("classes.luau");
        let src = r#"
local function expectfail(s, expected, f)
    local success, actual = pcall(f)
    assert(not success)
    assert(type(actual) == "string")
    assert(string.find(actual, expected, 1, true))
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "expectfail", Language::Luau, 100).unwrap();

        for needle in ["success", "actual", "string.find"] {
            assert!(
                !report
                    .preconditions
                    .iter()
                    .any(|p| p.constraint.contains(needle) || p.variable.contains(needle)),
                "facet (b): body-local assert referencing `{}` must leave preconditions[]; got {:?}",
                needle,
                report.preconditions
            );
        }
    }

    /// Facet (b) precision must not over-fire: a DIRECT-body assert on a pure
    /// PARAM stays a high-confidence precondition (no recall regression).
    #[test]
    fn rc2_luau_direct_param_assert_still_high() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("d.luau");
        let src = r#"
local function d(component)
    assert(component ~= nil)
    return component
end
"#;
        fs::write(&file_path, src).unwrap();
        let report = run_contracts(&file_path, "d", Language::Luau, 100).unwrap();

        assert!(
            report
                .preconditions
                .iter()
                .any(|p| p.constraint.contains("component ~= nil")
                    && p.confidence == Confidence::High),
            "facet (b) no-over-fire: direct param assert must stay high; got {:?}",
            report.preconditions
        );
    }
}
