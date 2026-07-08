//! Per-language policy table for language-specific resolution behavior.
//!
//! This module is intentionally additive: consumers still use their existing
//! code paths until later policy-wiring work migrates them here.

use crate::types::Language;
use std::str::FromStr;

/// How a language's module string yields a bare-suffix alias in the func index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasStyle {
    /// Dotted or bare module name with no `./`, `crate::`, or `/`.
    DottedSuffix,
    /// No bare-suffix alias.
    None,
}

/// Per-language policy for language-specific name-resolution behavior.
#[derive(Debug, Clone, Copy)]
pub struct LanguagePolicy {
    /// Builtin type/exception/function names that must not be treated as project constructors.
    pub builtins: &'static [&'static str],
    /// Whether the module string gets a bare dot-suffix alias in the func index.
    pub module_alias_style: AliasStyle,
    /// The module path separator this language uses in its `path_to_module` output.
    pub path_separator: &'static str,
    /// Whether module paths are dotted (`a.b.c`) as opposed to slashed, `::`, or relative.
    pub dotted_module_paths: bool,
}

/// Return the language policy row for a supported language.
pub fn policy_for(language: Language) -> LanguagePolicy {
    match language {
        Language::Python => LanguagePolicy {
            builtins: crate::callgraph::PYTHON_BUILTINS,
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::TypeScript => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::JavaScript => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::Go => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::Rust => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::None,
            path_separator: "::",
            dotted_module_paths: false,
        },
        Language::Java => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::C => LanguagePolicy {
            builtins: &[],
            // VERIFY@VAL-012: `path_to_module_c` preserves root-file bare names
            // and nested slash paths; nested paths currently make `is_python_style`
            // false, so the conservative row is no suffix alias.
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::Cpp => LanguagePolicy {
            builtins: &[],
            // VERIFY@VAL-012: same mixed root-vs-nested shape as C.
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::Ruby => LanguagePolicy {
            builtins: &[],
            // VERIFY@VAL-012: slash-separated require paths make nested Ruby
            // module keys `is_python_style == false`; root-file keys are bare.
            module_alias_style: AliasStyle::None,
            path_separator: "/",
            dotted_module_paths: false,
        },
        Language::Kotlin => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Swift => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::CSharp => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Scala => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Php => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: "\\",
            dotted_module_paths: false,
        },
        Language::Lua => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Luau => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Elixir => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Ocaml => LanguagePolicy {
            builtins: &[],
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
        Language::Solidity => LanguagePolicy {
            builtins: &[],
            // VERIFY@VAL-012: `path_to_module` currently falls through to the
            // Python-style helper for Solidity, which produces a dotted key.
            module_alias_style: AliasStyle::DottedSuffix,
            path_separator: ".",
            dotted_module_paths: true,
        },
    }
}

/// Returns true when the configured language exposes bare dotted module suffix aliases.
pub fn module_uses_dotted_alias(lang_str: &str) -> bool {
    Language::from_str(lang_str)
        .map(|lang| policy_for(lang).module_alias_style == AliasStyle::DottedSuffix)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{module_uses_dotted_alias, policy_for, AliasStyle};
    use crate::types::Language;

    #[test]
    fn language_policy_has_explicit_row_for_every_language() {
        let rows = [
            (
                Language::Python,
                AliasStyle::DottedSuffix,
                ".",
                true,
                true,
            ),
            (Language::TypeScript, AliasStyle::None, "/", false, false),
            (Language::JavaScript, AliasStyle::None, "/", false, false),
            (Language::Go, AliasStyle::None, "/", false, false),
            (Language::Rust, AliasStyle::None, "::", false, false),
            (Language::Java, AliasStyle::DottedSuffix, ".", true, false),
            (Language::C, AliasStyle::None, "/", false, false),
            (Language::Cpp, AliasStyle::None, "/", false, false),
            (Language::Ruby, AliasStyle::None, "/", false, false),
            (Language::Kotlin, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Swift, AliasStyle::DottedSuffix, ".", true, false),
            (Language::CSharp, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Scala, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Php, AliasStyle::DottedSuffix, "\\", false, false),
            (Language::Lua, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Luau, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Elixir, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Ocaml, AliasStyle::DottedSuffix, ".", true, false),
            (Language::Solidity, AliasStyle::DottedSuffix, ".", true, false),
        ];

        for (language, alias_style, separator, dotted, has_builtins) in rows {
            assert_language_exhaustive(language);
            let policy = policy_for(language);
            assert_eq!(policy.module_alias_style, alias_style, "{language:?}");
            assert_eq!(policy.path_separator, separator, "{language:?}");
            assert_eq!(policy.dotted_module_paths, dotted, "{language:?}");
            assert_eq!(!policy.builtins.is_empty(), has_builtins, "{language:?}");
        }
    }

    fn assert_language_exhaustive(language: Language) {
        match language {
            Language::Python
            | Language::TypeScript
            | Language::JavaScript
            | Language::Go
            | Language::Rust
            | Language::Java
            | Language::C
            | Language::Cpp
            | Language::Ruby
            | Language::Kotlin
            | Language::Swift
            | Language::CSharp
            | Language::Scala
            | Language::Php
            | Language::Lua
            | Language::Luau
            | Language::Elixir
            | Language::Ocaml
            | Language::Solidity => {}
        }
    }

    #[test]
    fn language_policy_builtins_and_alias_smoke() {
        let python = policy_for(Language::Python);
        assert_eq!(python.module_alias_style, AliasStyle::DottedSuffix);
        assert!(!python.builtins.is_empty());

        let typescript = policy_for(Language::TypeScript);
        assert_eq!(typescript.module_alias_style, AliasStyle::None);
        assert!(typescript.builtins.is_empty());
    }

    #[test]
    fn module_uses_dotted_alias_routes_unknown_to_false() {
        assert!(module_uses_dotted_alias("python"));
        assert!(!module_uses_dotted_alias("typescript"));
        assert!(!module_uses_dotted_alias("unknown-language"));
    }
}
