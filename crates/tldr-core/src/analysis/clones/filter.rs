//! File discovery and filtering for clone detection.

use std::path::{Path, PathBuf};

use crate::walker::walk_project;

use super::is_generated_file;

/// Check if a file appears to be a test file.
///
/// Matches common test file naming conventions across languages:
/// - Python: test_*.py, *_test.py
/// - Go: *_test.go
/// - Rust: *_test.rs (integration tests; unit tests in same file are not filtered)
/// - Ruby: *_test.rb, *_spec.rb
/// - JavaScript/TypeScript: *.test.{ts,tsx,js,jsx}, *.spec.{ts,tsx,js,jsx}
/// - Java: *Test.java, *Tests.java, *IT.java
/// - Kotlin: *Test.kt, *Tests.kt
/// - Scala: *Spec.scala, *Test.scala
/// - C#: *Tests.cs, *Test.cs
/// - Swift: *Tests.swift, *Test.swift, *Spec.swift
/// - PHP: *Test.php
/// - Elixir: *_test.exs
/// - Directories: tests/, test/, __tests__/, spec/, testing/ (case-insensitive)
///
/// cl3-test-linkage-v1 (CL-3 / GH #35): the prior matcher lacked the TSX/JSX
/// suffixes (the literal #35 bug — colocated `Component.test.tsx` tests were
/// undercounted by `whatbreaks`) and several PascalCase conventions
/// (`*Tests.swift`, `*Test.kt`, `*Spec.scala`, `*Test.php`). Directory probes
/// are now case-insensitive on the component boundary so Swift's capital
/// `Tests/` directory registers too.
pub fn is_test_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();

    // Check test directory patterns case-insensitively, on the path-component
    // boundary so `/Tests/` and `/tests/` both register while `/contests/`
    // does not.
    let in_test_dir = path.components().any(|c| {
        c.as_os_str().to_str().is_some_and(|s| {
            s.eq_ignore_ascii_case("tests")
                || s.eq_ignore_ascii_case("test")
                || s.eq_ignore_ascii_case("__tests__")
                || s.eq_ignore_ascii_case("spec")
                || s.eq_ignore_ascii_case("specs")
                || s.eq_ignore_ascii_case("testing")
        })
    });
    if in_test_dir {
        return true;
    }

    // Check test file name patterns.
    let name = file_name.as_ref();
    name.starts_with("test_")
        // Python / Go / Rust / Ruby snake-case conventions.
        || name.ends_with("_test.py")
        || name.ends_with("_test.go")
        || name.ends_with("_test.rs")
        || name.ends_with("_test.rb")
        || name.ends_with("_spec.rb")
        // Elixir ExUnit.
        || name.ends_with("_test.exs")
        // JS/TS Jest/Mocha — including the TSX/JSX variants (the GH #35 bug).
        || name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".test.jsx")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.jsx")
        // JVM / .NET PascalCase suffixes.
        || name.ends_with("Test.java")
        || name.ends_with("Tests.java")
        || name.ends_with("IT.java")
        || name.ends_with("Test.kt")
        || name.ends_with("Tests.kt")
        || name.ends_with("Spec.scala")
        || name.ends_with("Test.scala")
        || name.ends_with("Tests.cs")
        || name.ends_with("Test.cs")
        // Swift XCTest.
        || name.ends_with("Tests.swift")
        || name.ends_with("Test.swift")
        || name.ends_with("Spec.swift")
        // PHP PHPUnit.
        || name.ends_with("Test.php")
}

/// Discover source files for clone detection.
/// Wraps walkdir with extension filter, max_files cap, test/generated exclusion.
pub fn discover_source_files(
    path: &Path,
    language: Option<&str>,
    max_files: usize,
    exclude_generated: bool,
    exclude_tests: bool,
) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for e in walk_project(path) {
        if !e.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let file_path = e.path();

        // Skip generated files if requested
        if exclude_generated && is_generated_file(file_path) {
            continue;
        }

        // Skip test files if requested
        if exclude_tests && is_test_file(file_path) {
            continue;
        }

        if is_source_file_for_clones(file_path, language) {
            files.push(file_path.to_path_buf());
            if files.len() >= max_files {
                break;
            }
        }
    }

    files
}

/// Check if a file is a source file for clone detection
fn is_source_file_for_clones(path: &Path, language: Option<&str>) -> bool {
    let ext = path.extension().and_then(|e| e.to_str());

    match (ext, language) {
        // If language specified, only match that language's extension
        (Some("py"), Some("python")) => true,
        (Some("ts" | "tsx"), Some("typescript")) => true,
        (Some("js" | "jsx"), Some("javascript")) => true,
        (Some("go"), Some("go")) => true,
        (Some("rs"), Some("rust")) => true,
        (Some("java"), Some("java")) => true,
        (Some("c" | "h"), Some("c")) => true,
        (Some("cs"), Some("csharp")) => true,
        (Some("ex" | "exs"), Some("elixir")) => true,
        (Some("lua"), Some("lua")) => true,
        (Some("ml" | "mli"), Some("ocaml")) => true,
        (Some("php"), Some("php")) => true,
        (Some("rb"), Some("ruby")) => true,
        (Some("scala"), Some("scala")) => true,
        (Some("swift"), Some("swift")) => true,
        (Some("kt" | "kts"), Some("kotlin")) => true,
        (Some("cpp" | "cc" | "cxx" | "hpp"), Some("cpp")) => true,
        (Some("luau"), Some("luau")) => true,
        // v0.5.0 SOL-015b M10 (solidity-sol015b-health-clones-smells-v1):
        // Register `.sol` so `tldr clones <dir>` includes Solidity files
        // in fragment discovery instead of silently dropping them at
        // the extension filter.
        (Some("sol"), Some("solidity")) => true,

        // If no language specified, accept common source files
        (
            Some(
                "py" | "ts" | "tsx" | "js" | "jsx" | "go" | "rs" | "java" | "c" | "h" | "cs" | "ex"
                | "exs" | "lua" | "ml" | "mli" | "php" | "rb" | "scala" | "swift" | "kt" | "kts"
                | "cpp" | "cc" | "cxx" | "hpp" | "luau" | "sol",
            ),
            None,
        ) => true,

        _ => false,
    }
}

/// Get language name from file extension
pub fn get_language_from_path(path: &Path) -> Option<&'static str> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    match ext {
        "py" => Some("python"),
        "ts" | "tsx" => Some("typescript"),
        "js" | "jsx" => Some("javascript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" => Some("cpp"),
        "cs" => Some("csharp"),
        "ex" | "exs" => Some("elixir"),
        "lua" => Some("lua"),
        "luau" => Some("luau"),
        "ml" | "mli" => Some("ocaml"),
        "php" => Some("php"),
        "rb" => Some("ruby"),
        "scala" => Some("scala"),
        "swift" => Some("swift"),
        "kt" | "kts" => Some("kotlin"),
        // v0.5.0 SOL-015b M10 (solidity-sol015b-health-clones-smells-v1):
        // `.sol` maps to "solidity" so the dominant-language resolver
        // (`resolve_dominant_language`) emits the correct top-level
        // `language` field on the clones report.
        "sol" => Some("solidity"),
        _ => None,
    }
}
