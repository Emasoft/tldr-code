//! Find importers of a module (spec Section 2.2.4)
//!
//! Find all files that import a given module.
//!
//! # Features
//! - Captures line numbers
//! - Captures import statement text
//! - Supports both import and from-import styles
//! - Works with Python, TypeScript, Go

use std::collections::HashSet;
use std::path::Path;

use crate::ast::imports::get_imports;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{IgnoreSpec, ImporterInfo, ImportersReport, Language};
use crate::TldrResult;

/// Find all files that import a given module.
///
/// # Arguments
/// * `root` - Project root directory
/// * `module` - Module name to search for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(ImportersReport)` - List of files importing the module
pub fn find_importers(
    root: &Path,
    module: &str,
    language: Language,
) -> TldrResult<ImportersReport> {
    let extensions: HashSet<String> = language
        .extensions()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let tree = get_file_tree(root, Some(&extensions), true, Some(&IgnoreSpec::default()))?;
    let files = collect_files(&tree, root);

    let mut importers = Vec::new();

    for file_path in files {
        match find_import_in_file(&file_path, module, language) {
            Ok(Some(info)) => importers.push(info),
            Ok(None) => {}
            Err(e) => {
                if e.is_recoverable() {
                    // Skip files with parse errors
                    continue;
                }
            }
        }
    }

    let total = importers.len();
    Ok(ImportersReport {
        module: module.to_string(),
        importers,
        total,
    })
}

/// Check if a file imports the specified module.
///
/// `importers-ast-anchored-v1` (v0.4.2 M-035): the line and import-statement
/// text are now sourced from the AST extractor's `ImportInfo.line`. Previously
/// this function ran a text-substring scan (`find_import_line`) that surfaced
/// docstring/alias false positives and fell back to `line: 1` whenever the
/// idiomatic match failed (notably Go imports inside `import (...)` blocks).
/// The text scan is gone; the only thing read from disk is the literal text
/// of the AST-pinned line.
fn find_import_in_file(
    file_path: &Path,
    target_module: &str,
    language: Language,
) -> TldrResult<Option<ImporterInfo>> {
    let imports = get_imports(file_path, language)?;

    // Two-pass scan: prefer non-aliased imports (M-035 cluster intent).
    // Pre-fix the emitter used a text-scan that simply returned the first
    // line containing the module substring; in a file with both
    //   line 6:  using Assert = Newtonsoft.Json.Bson.Tests.XUnitAssert;  (aliased)
    //   line 7:  using Newtonsoft.Json.Bson;                              (real)
    // the alias-RHS at line 6 also lexically matches `Newtonsoft.Json.Bson`
    // (it's a sub-namespace), so the importers emitter surfaced line 6.
    // The user-intuitive answer is line 7: the unaliased `using` is the
    // direct importer; the alias-RHS is a transitive reference embedded in
    // a local binding. Iterate twice: first pass picks unaliased imports,
    // second pass falls back to aliased ones.
    for prefer_unaliased in [true, false] {
        for import in &imports {
            // CSharp alias-exclusion: a `using A = B.C;` directive should
            // NOT match a query for `A` — the alias name is a local binding,
            // not an imported module.
            if matches!(language, Language::CSharp)
                && import.alias.as_deref() == Some(target_module)
            {
                continue;
            }

            // Skip aliased imports in the first pass so an unaliased import
            // lower in the file is preferred over an aliased one higher up.
            if prefer_unaliased && import.alias.is_some() {
                continue;
            }

            let matched_module = module_matches(&import.module, target_module, language);

            // Secondary match: `from X import target_module` — when querying
            // for a named import (Python's `target` as one of `import.names`),
            // the file is still an importer of the parent module.
            let matched_from_name = import.is_from.unwrap_or(false)
                && import.names.iter().any(|n| n == target_module);

            if !matched_module && !matched_from_name {
                continue;
            }

            return Ok(Some(emit_importer(file_path, import.line)?));
        }
    }

    Ok(None)
}

/// Emit an `ImporterInfo` for a file given the AST-anchored line.
///
/// importers-ast-anchored-v1 (M-035): reads exactly one line from the file —
/// the line the AST extractor pinned via `ImportInfo.line` — and uses its
/// text as the `import_statement`. No substring scanning, no fallback to
/// line 1. If `ast_line == 0` (e.g. a defensive path where a helper failed
/// to set the line), we degrade gracefully to the first line of the file.
fn emit_importer(file_path: &Path, ast_line: u32) -> TldrResult<ImporterInfo> {
    let content = std::fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let idx = if ast_line == 0 {
        0
    } else {
        (ast_line as usize).saturating_sub(1)
    };
    let stmt = lines.get(idx).copied().unwrap_or("").trim().to_string();
    let line = if ast_line == 0 { 1 } else { ast_line };
    Ok(ImporterInfo {
        file: file_path.to_path_buf(),
        line,
        import_statement: stmt,
    })
}

/// Check if a module name matches the target
fn module_matches(import_module: &str, target: &str, language: Language) -> bool {
    match language {
        Language::Python => {
            // Exact match
            if import_module == target {
                return true;
            }
            // Submodule match: services.auth matches services
            if import_module.starts_with(&format!("{}.", target)) {
                return true;
            }
            // Target is submodule: services matches services.auth
            if target.starts_with(&format!("{}.", import_module)) {
                return true;
            }
            // Handle relative imports
            let cleaned_import = import_module.trim_start_matches('.');
            let cleaned_target = target.trim_start_matches('.');
            cleaned_import == cleaned_target
        }
        Language::TypeScript | Language::JavaScript => {
            // Normalize paths
            let normalized_import = import_module.replace('\\', "/");
            let normalized_target = target.replace('\\', "/");

            if normalized_import == normalized_target {
                return true;
            }
            // Handle ./relative paths
            let import_clean = normalized_import.trim_start_matches("./");
            let target_clean = normalized_target.trim_start_matches("./");
            import_clean == target_clean
        }
        Language::Go => {
            // Package path matching
            import_module == target || import_module.ends_with(&format!("/{}", target))
        }
        // language-specific-bugs-v1 (P14.AGG14-11): Scala uses the same
        // dotted-FQCN syntax as Java (`import cats.effect.IO`) plus a
        // family of brace-, wildcard-, and rename-based selectors. The
        // exact-match-only fallback meant a query for the package
        // `cats.effect` against a file that imports
        // `cats.effect.kernel.Async` returned 0 hits, even though the
        // file is unambiguously inside the `cats.effect` subtree.
        // Mirror Python's submodule-bidirectional rule so subpath
        // queries succeed in both directions:
        //   target = "cats.effect"            matches "cats.effect.kernel.Async"
        //   target = "cats.effect.kernel.Async" matches "cats.effect"
        //   target = "cats.effect.IO"         matches "cats.effect.IO"
        //
        // residual-bugs-v1 (P15.AGG15-3): callers also pass a bare class
        // name without the FQN package (`tldr importers Owner ...` for
        // spring-petclinic). The previous prefix-only rules failed
        // because `Owner` neither equals nor is a strict prefix/suffix
        // of `org.springframework.samples.petclinic.owner.Owner`. Add
        // a final last-segment match so a class-name query resolves
        // every FQN whose terminal segment matches. This mirrors Go's
        // `ends_with("/{}")` rule but for dotted package paths. Only
        // applied when the target itself is a single segment (no dot)
        // — an FQN target falls through the prefix rules above.
        //
        // non-judgment-call-bugs-v1 (P17.AGG17-1): the reverse-prefix
        // rule (`target.starts_with("{}.", import_module)`) was too
        // aggressive when `import_module` is a single top-level segment.
        // For example, `import cats._` extracts as module=`cats`; an
        // `importers cats.effect.IO` query would then match because
        // `cats.effect.IO` starts with `cats.`. But Scala wildcard
        // imports are *not* transitive — `import cats._` only exposes
        // `cats`'s direct members, not `cats.effect.IO`. Restrict the
        // reverse-prefix rule to multi-segment `import_module` values
        // (`cats.effect`, `cats.effect.kernel`, …) which represent
        // genuine sub-package imports. Top-level wildcards still match
        // exact target queries via the `import_module == target` rule.
        Language::Scala | Language::Kotlin | Language::Java | Language::CSharp => {
            // importers-ast-anchored-v1 (M-035): CSharp added to the dotted-FQN
            // family. `using Foo.Bar.Baz;` should match a query for
            // `Foo.Bar` (sub-namespace prefix) and a bare-class query
            // `Baz` (last-segment) — mirroring the Java/Scala rules.
            if import_module == target {
                return true;
            }
            if import_module.starts_with(&format!("{}.", target)) {
                return true;
            }
            if import_module.contains('.')
                && target.starts_with(&format!("{}.", import_module))
            {
                return true;
            }
            if !target.contains('.') && import_module.ends_with(&format!(".{}", target)) {
                return true;
            }
            false
        }
        Language::C | Language::Cpp => {
            // importers-ast-anchored-v1 (M-035): #include "../subdir/foo.h"
            // should match a query for the bare header name `foo.h`. The AST
            // extractor preserves the literal include path (`../subdir/foo.h`,
            // `subdir/foo.h`, or `foo.h`); compare the basename against the
            // target so a relative include resolves correctly. System includes
            // (`<stdio.h>`) compare via the same rule.
            if import_module == target {
                return true;
            }
            let import_basename = std::path::Path::new(import_module)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(import_module);
            let target_basename = std::path::Path::new(target)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(target);
            import_basename == target_basename
        }
        _ => import_module == target,
    }
}

/// Find the line number and text of an import statement.
///
/// importers-ast-anchored-v1 (v0.4.2 M-035): this function is no longer
/// called from production code — the importers emitter now reads the line
/// directly from `ImportInfo.line` populated by the AST extractor. The
/// function is retained for the existing unit-test coverage (which pins
/// the per-language idiom recognition); marking `#[cfg(test)]` is the
/// truthful way to express that it is exercised only by tests.
#[cfg(test)]
fn find_import_line(
    lines: &[&str],
    module: &str,
    is_from: bool,
    language: Language,
) -> (u32, String) {
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        match language {
            Language::Python => {
                if is_from {
                    if trimmed.starts_with("from ") && trimmed.contains(module) {
                        return (i as u32 + 1, trimmed.to_string());
                    }
                } else if trimmed.starts_with("import ") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            Language::TypeScript | Language::JavaScript => {
                if trimmed.contains("import") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
                if trimmed.contains("require") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            Language::Go => {
                if trimmed.contains("import") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            // non-judgment-call-bugs-v1 (P17.AGG17-1): for Scala / Kotlin
            // / Java / Rust, lines starting with `package` (Scala/Kotlin/
            // Java) or `mod`/`pub mod` (Rust) are *declarations*, not
            // imports. Previously this branch returned the first line
            // whose substring matched `module`, which falsely surfaced
            // package-declaration lines (`package cats.effect.kernel`)
            // as the import statement when an unrelated wildcard import
            // matched the query. Require the line to look like an
            // import statement (`import …` / `use …`) before reporting it.
            Language::Scala | Language::Kotlin | Language::Java => {
                if (trimmed.starts_with("import ") || trimmed.starts_with("import\t"))
                    && trimmed.contains(module)
                {
                    return (i as u32 + 1, trimmed.to_string());
                }
                // cross-cutting-and-clear-fix-bugs-v1 (P18.B8): Scala
                // brace-list imports look like
                //   `import cats.effect.tracing.{Tracing, TracingEvent}`
                // — the literal `module` string ("cats.effect.tracing.Tracing")
                // is NOT a substring. The pre-fix code fell through to
                // the (1, "import {module}") synthetic fallback, so all
                // brace-imported symbols pinned to line 1. Recognise the
                // pattern: when the trimmed line is an `import` statement
                // whose prefix matches the module's qualifier and whose
                // brace-list contains the module's last segment, return
                // the actual line number.
                if matches!(language, Language::Scala)
                    && (trimmed.starts_with("import ") || trimmed.starts_with("import\t"))
                {
                    if let Some(last_dot) = module.rfind('.') {
                        let prefix = &module[..last_dot];
                        let last_seg = &module[last_dot + 1..];
                        // Single-line brace: `import a.b.{X, Y}`
                        if trimmed.contains(prefix) && trimmed.contains('{') {
                            // Multi-line brace: line ends with `{` but no `}` —
                            // accumulate until matching `}`.
                            let has_close = trimmed.contains('}');
                            let inside_text: String = if has_close {
                                let brace_open = trimmed.find('{').unwrap_or(0);
                                let after = &trimmed[brace_open + 1..];
                                let inside_end = after.find('}').unwrap_or(after.len());
                                after[..inside_end].to_string()
                            } else {
                                let mut acc = String::new();
                                let brace_open = trimmed.find('{').unwrap_or(0);
                                acc.push_str(&trimmed[brace_open + 1..]);
                                acc.push(' ');
                                let mut k = i + 1;
                                while k < lines.len() {
                                    let l = lines[k].trim();
                                    if let Some(close) = l.find('}') {
                                        acc.push_str(&l[..close]);
                                        break;
                                    }
                                    acc.push_str(l);
                                    acc.push(' ');
                                    k += 1;
                                }
                                acc
                            };
                            for raw_sym in inside_text.split(',') {
                                let raw = raw_sym.trim();
                                // Handle rename: `X => Y` — keep lhs.
                                let lhs = raw.split("=>").next().unwrap_or(raw).trim();
                                if lhs == last_seg {
                                    return (i as u32 + 1, trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Language::Rust => {
                if (trimmed.starts_with("use ") || trimmed.starts_with("pub use "))
                    && trimmed.contains(module)
                {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            // ux-cluster-v1 (v0.4.2 VAL-UX-D5): Swift previously fell
            // through to the catch-all `_` arm below, which accepted
            // ANY line containing the module substring. In Swift code
            // where an `import` lives inside `#if <cond> … #else …
            // #endif` blocks (or simply preceded by `#if false //
            // ModuleName is not a thing yet`), the first matching
            // line was the preprocessor directive itself — not the
            // actual `import` line. Require the line to look like a
            // real Swift import line and never accept preprocessor
            // directives. Recognised import-line shapes:
            //   `import Foundation`
            //   `import struct Foo.Bar`
            //   `@testable import Foo`
            //   `@_spi(Testing) import Foo`
            //   `@_implementationOnly import Foo`
            //   `public import Foo` (Swift 5.9+ access modifier)
            Language::Swift => {
                // Reject preprocessor conditionals up front.
                if trimmed.starts_with("#if")
                    || trimmed.starts_with("#else")
                    || trimmed.starts_with("#elseif")
                    || trimmed.starts_with("#endif")
                {
                    continue;
                }
                // Must contain the module name AND be an import line.
                if !trimmed.contains(module) {
                    continue;
                }
                // Strip leading `@…` attribute clusters and any
                // `public ` / `internal ` / `private ` / `fileprivate `
                // access modifiers, then verify the remaining text
                // begins with the `import` keyword.
                let mut rest = trimmed;
                while rest.starts_with('@') {
                    // Skip the attribute (including any parenthesised
                    // argument) up to the next whitespace.
                    if let Some(paren_open) = rest.find('(') {
                        if let Some(paren_close) = rest[paren_open..].find(')') {
                            rest = rest[paren_open + paren_close + 1..].trim_start();
                            continue;
                        }
                    }
                    if let Some(space) = rest.find(char::is_whitespace) {
                        rest = rest[space..].trim_start();
                    } else {
                        rest = "";
                        break;
                    }
                }
                for modifier in ["public ", "internal ", "private ", "fileprivate "] {
                    if let Some(stripped) = rest.strip_prefix(modifier) {
                        rest = stripped.trim_start();
                    }
                }
                if rest.starts_with("import ") || rest.starts_with("import\t") {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            _ => {
                if trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
        }
    }

    // Fallback
    (1, format!("import {}", module))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_matches_python() {
        // Exact match
        assert!(module_matches(
            "services.auth",
            "services.auth",
            Language::Python
        ));

        // Submodule match
        assert!(module_matches(
            "services.auth",
            "services",
            Language::Python
        ));

        // No match
        assert!(!module_matches("utils", "services", Language::Python));

        // Relative import
        assert!(module_matches(".auth", "auth", Language::Python));
    }

    #[test]
    fn test_module_matches_typescript() {
        assert!(module_matches("./utils", "./utils", Language::TypeScript));
        assert!(module_matches("./utils", "utils", Language::TypeScript));
        assert!(module_matches("utils", "./utils", Language::TypeScript));
    }

    #[test]
    fn test_find_import_line() {
        let lines = vec![
            "\"\"\"Module docstring\"\"\"",
            "",
            "from typing import List",
            "from services.auth import authenticate",
            "",
            "def main():",
            "    pass",
        ];

        let (line, stmt) = find_import_line(&lines, "services.auth", true, Language::Python);
        assert_eq!(line, 4);
        assert!(stmt.contains("services.auth"));
    }
}
