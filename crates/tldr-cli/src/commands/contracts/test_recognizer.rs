//! Per-language test framework recognizers.
//!
//! Closes phase-11 BUG-AGG-3 (HIGH): `tldr specs --from-tests` and
//! `tldr invariants --from-tests` previously hard-coded Python `test_*`
//! pytest-style discovery, so JavaScript/Java/PHP/Swift/Go/Kotlin/Scala/
//! Ruby/Elixir/Lua test directories returned `test_files_scanned = 0`
//! despite containing real test functions.
//!
//! Each recognizer answers two questions per file:
//!
//! 1. **Is this a test file?** (per the language's discovery convention)
//! 2. **How many test functions does it contain?** (counted via tree-sitter
//!    AST walks rather than text-level heuristics, so comments and string
//!    literals can't false-match.)
//!
//! Languages handled:
//!
//! | Language    | Convention                                                 |
//! |-------------|------------------------------------------------------------|
//! | Python      | `def test_*` (pytest) or methods inside `class Test*`      |
//! | JavaScript  | `it(...)` / `test(...)` calls (Mocha/Jest/Jasmine)         |
//! | TypeScript  | `it(...)` / `test(...)` calls                              |
//! | Java        | Methods annotated with `@Test`                             |
//! | Kotlin      | Methods annotated with `@Test`                             |
//! | PHP         | `public function test*` inside class whose name ends `Test`|
//! | Swift       | `func test*()` inside class extending `XCTestCase`         |
//! | Ruby        | `def test_*` (Minitest) or `it/describe` blocks (RSpec)    |
//! | Go          | Top-level `func TestXxx(t *testing.T)`                     |
//! | Scala       | `test("...")` calls (Munit/ScalaTest FunSuite)             |
//! | Elixir      | `test "..." do ... end` blocks (ExUnit)                    |
//! | Lua / Luau  | `it(...)` / `describe(...)` blocks (busted)                |
//! | Rust        | `fn` items immediately preceded by `#[test]`               |
//! | C#          | Methods with `[Test]` / `[Fact]` / `[TestMethod]`          |
//! | C / C++ /   | (No widely standard test framework — fall back to file     |
//! | OCaml       |  count when name suggests test, function count = 0; the   |
//! |             |  framework adapter can be wired later.)                    |
//!
//! For languages without a clear convention, the recognizer treats files
//! whose name contains `test` (case-insensitive) as test files but reports
//! `0` functions — strictly better than the previous behaviour where the
//! file count itself was always `0` for non-Python.

use std::path::Path;

use tldr_core::ast::ParserPool;
use tldr_core::Language;
use tree_sitter::{Node, Tree};

/// Result of inspecting a single candidate file for test functions.
#[derive(Debug, Clone, Default)]
pub struct TestFileInfo {
    /// True if this file participates in a test suite (i.e. should bump
    /// `test_files_scanned`).
    pub is_test_file: bool,
    /// Number of test functions detected by walking the AST.
    pub test_function_count: u32,
}

/// Public entry point: classify a candidate file and count its tests.
///
/// `language` is the language the caller has already detected for the
/// file (typically via `Language::from_path` in `run_specs` /
/// `collect_observations`). Returns a default zero-info value if the
/// file is not parseable in this language.
pub fn recognize(path: &Path, source: &str, language: Language) -> TestFileInfo {
    if !is_candidate_test_file(path, language) {
        return TestFileInfo::default();
    }

    // language-specific-bugs-v1 (P14.AGG14-9): for Rust, every `.rs` is
    // a path-level candidate so `tldr specs --from-tests` can cover
    // inline `#[cfg(test)] mod tests { ... }` blocks inside production
    // source files (e.g. ripgrep `crates/globset/src/lib.rs`). To keep
    // directory walks cheap, gate on a fast attribute substring check
    // before parsing — any `.rs` without any test-attribute marker
    // cannot contribute and parsing the entire file would just be
    // wasted work.
    //
    // m116-easy-mechanical-v1 (#42): the original substring `#[test]`
    // missed async test runners (`#[tokio::test]`, `#[actix_rt::test]`,
    // `#[async_std::test]`, `#[smol_potat::test]`) — every async-only
    // crate reported `test_functions_scanned = 0`. Match the broader
    // `::test]` marker as well; `rust_attribute_is_test` (the per-fn
    // predicate) already accepts `*::test` via `rsplit("::").next()`.
    if matches!(language, Language::Rust)
        && !source.contains("#[test]")
        && !source.contains("::test]")
        && !source.contains("::test(")
    {
        return TestFileInfo::default();
    }

    // Empty or whitespace-only files: nothing to count.
    if source.trim().is_empty() {
        return TestFileInfo {
            is_test_file: true,
            test_function_count: 0,
        };
    }

    let pool = ParserPool::new();
    let tree = match pool.parse(source, language).ok() {
        Some(t) => t,
        None => {
            return TestFileInfo {
                is_test_file: true,
                test_function_count: 0,
            };
        }
    };

    let count = count_test_functions(&tree, source.as_bytes(), language);

    TestFileInfo {
        is_test_file: true,
        test_function_count: count,
    }
}

/// Decide whether `path` matches the language's test-file naming convention.
///
/// Each language has its own convention; we centralise them here so
/// `run_specs` can early-skip non-tests cheaply (without parsing).
fn is_candidate_test_file(path: &Path, language: Language) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);
    let lower = file_name.to_ascii_lowercase();

    match language {
        // Python: `test_*.py` (pytest) or `*_test.py` (unittest-style).
        Language::Python => {
            file_name.starts_with("test_") && file_name.ends_with(".py")
                || file_name.ends_with("_test.py")
        }
        // JavaScript / TypeScript: Jest/Mocha conventions.
        // `*.test.js` / `*.spec.js` (and tsx/jsx variants), or any file
        // inside a directory literally named `__tests__`.
        Language::JavaScript | Language::TypeScript => {
            let in_tests_dir = path
                .components()
                .any(|c| c.as_os_str() == "__tests__" || c.as_os_str() == "test"
                    || c.as_os_str() == "tests" || c.as_os_str() == "spec");
            let has_test_marker = stem.ends_with(".test")
                || stem.ends_with(".spec")
                || stem.ends_with("_test")
                || stem.ends_with("_spec")
                || stem.ends_with("Test")
                || stem.ends_with("Spec");
            (has_test_marker || in_tests_dir)
                && (lower.ends_with(".js")
                    || lower.ends_with(".jsx")
                    || lower.ends_with(".mjs")
                    || lower.ends_with(".cjs")
                    || lower.ends_with(".ts")
                    || lower.ends_with(".tsx"))
        }
        // Java: Maven/Gradle convention — files under `src/test/java` are
        // tests, or any class whose name ends with `Test`/`Tests`.
        Language::Java => {
            if !lower.ends_with(".java") {
                return false;
            }
            stem.ends_with("Test")
                || stem.ends_with("Tests")
                || stem.ends_with("IT")
                || stem.ends_with("ITCase")
                || path.components().any(|c| c.as_os_str() == "test")
        }
        // Kotlin: same convention as Java.
        Language::Kotlin => {
            (lower.ends_with(".kt") || lower.ends_with(".kts"))
                && (stem.ends_with("Test")
                    || stem.ends_with("Tests")
                    || path.components().any(|c| c.as_os_str() == "test"))
        }
        // PHP: PHPUnit convention — class FooTest in FooTest.php; plus the
        // Symfony pattern of abstract bases ending in `TestCase`
        // (e.g. `AbstractAsciiTestCase.php`) and the Codeception convention
        // of acceptance tests ending in `Cest` (e.g. `LoginCest.php`).
        // test-recognizer-expansion-v1 (P22 M-005): the file-name gate was
        // previously `*Test|*Tests` only, dropping real-world test fixtures
        // from large frameworks at the directory-walk stage.
        Language::Php => {
            lower.ends_with(".php")
                && (stem.ends_with("Test")
                    || stem.ends_with("Tests")
                    || stem.ends_with("TestCase")
                    || stem.ends_with("TestCases")
                    || stem.ends_with("Cest"))
        }
        // Swift: XCTest convention — files named `*Tests.swift`.
        Language::Swift => {
            lower.ends_with(".swift")
                && (stem.ends_with("Tests") || stem.ends_with("Test") || stem.ends_with("Spec"))
        }
        // Ruby: Minitest `test_*.rb` / `*_test.rb`; RSpec `*_spec.rb`.
        // cluster-misc-v2 (M-029): also accept any `.rb` file whose path
        // passes through a directory literally named `test` or `tests` — the
        // same convention already applied to Java/Kotlin/JavaScript/CSharp.
        // This covers Minitest suites where test helpers are named after
        // the subject (e.g. `test/sanitizer.rb`) without a `test_` prefix.
        Language::Ruby => {
            lower.ends_with(".rb")
                && (file_name.starts_with("test_")
                    || stem.ends_with("_test")
                    || stem.ends_with("_spec")
                    || path
                        .components()
                        .any(|c| c.as_os_str() == "test" || c.as_os_str() == "tests"))
        }
        // Go: convention is `*_test.go`.
        Language::Go => lower.ends_with("_test.go"),
        // Scala: Munit / ScalaTest convention — `*Suite.scala`/`*Spec.scala`/`*Test.scala`.
        Language::Scala => {
            lower.ends_with(".scala")
                && (stem.ends_with("Test")
                    || stem.ends_with("Tests")
                    || stem.ends_with("Spec")
                    || stem.ends_with("Suite"))
        }
        // Elixir: ExUnit convention — `*_test.exs`.
        Language::Elixir => {
            (lower.ends_with(".exs") || lower.ends_with(".ex"))
                && (stem.ends_with("_test") || file_name.starts_with("test_"))
        }
        // Lua / Luau: busted convention — `*_spec.lua`/`*_test.lua`.
        Language::Lua | Language::Luau => {
            (lower.ends_with(".lua") || lower.ends_with(".luau"))
                && (stem.ends_with("_spec")
                    || stem.ends_with("_test")
                    || file_name.starts_with("test_"))
        }
        // Rust: built-in `#[test]` framework — files under `tests/` are
        // integration tests, and any source file may contain `#[cfg(test)]`
        // mod blocks. Treat any `.rs` whose path contains `test` (a tests/
        // directory or a *_test.rs filename), `bench`, OR contains a
        // `#[test]` substring as a candidate;
        // matches_test_function then filters down to actual `#[test]` items.
        //
        // language-specific-bugs-v1 (P14.AGG14-9): the path-only filter
        // missed the canonical Rust convention of inline
        // `#[cfg(test)] mod tests { ... }` blocks inside a regular
        // `lib.rs` / module file (every cargo crate has these). The
        // additional substring check at recognise-time
        // (`source.contains("#[test]")`) is cheap relative to parsing and
        // turns single-file invocations like `tldr specs --from-tests
        // crates/globset/src/lib.rs` into yielding the inline tests they
        // contain. Directory walks accept any `.rs` here and still rely on
        // `matches_test_function` for per-fn filtering.
        Language::Rust => {
            lower.ends_with(".rs")
        }
        // C#: NUnit / xUnit / MSTest — files named `*Tests.cs` or under
        // a Tests directory. matches_test_function filters down to methods
        // carrying `[Test]` / `[Fact]` / `[TestMethod]` etc.
        Language::CSharp => {
            lower.ends_with(".cs")
                && (stem.ends_with("Test")
                    || stem.ends_with("Tests")
                    || path.components().any(|c| {
                        let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                        s == "test" || s == "tests"
                    }))
        }
        // Languages without a single dominant convention. Fall back to the
        // weak heuristic of "filename contains 'test'" so directories laid
        // out as `tests/` still count their files. The function-count
        // walker still returns 0 for these — wiring grammar-specific
        // recognisers is left as TODO.
        // OCaml: dune test stanzas live under `test/` / `tests/` dirs and
        // are conventionally named `*_test.ml` / `*_tests.ml`, plus
        // ppx_expect suites under `expect-tests/`. Accept any `.ml`/`.mli`
        // whose name or path signals a test (cl7-test-frameworks-v1, CL-7).
        Language::Ocaml => {
            (lower.ends_with(".ml") || lower.ends_with(".mli"))
                && (lower.contains("test")
                    || lower.contains("spec")
                    || path.components().any(|c| {
                        let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                        s == "test" || s == "tests" || s.contains("test")
                    }))
        }
        Language::C | Language::Cpp => {
            lower.contains("test") || lower.contains("spec")
        }
        // v0.5.0 SOL-001: Solidity test convention per oracle —
        // Foundry/Forge tests live under `test/**/*.sol` and contain
        // `test*` / `fuzz*` / `invariant_*` functions. Files outside
        // `test/` directories may also be tests; we use the same lax
        // filename heuristic as C/C++ for now and refine in SOL-007.
        Language::Solidity => {
            path.components().any(|c| c.as_os_str() == "test" || c.as_os_str() == "tests")
                || lower.contains("test")
        }
    }
}

/// AST-walk a parsed test file and count test functions per language convention.
fn count_test_functions(tree: &Tree, source: &[u8], language: Language) -> u32 {
    let root = tree.root_node();
    let mut count = 0u32;
    walk_count(&root, source, language, &mut count);
    count
}

fn walk_count(node: &Node, source: &[u8], language: Language, count: &mut u32) {
    if matches_test_function(node, source, language) {
        *count += 1;
        // Don't recurse into a function body — nested calls inside a
        // matched test function shouldn't be double-counted (e.g. an
        // `it(...)` inside a `describe(...)` block both match the JS
        // recogniser; only the leaf `it` counts).
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_count(&child, source, language, count);
    }
}

/// Public wrapper around the per-language test-function predicate.
///
/// `tldr specs --from-tests` re-uses this from the generic spec extractor
/// so the same definition of "test function" used to count tests is used
/// to harvest assertions inside them.
pub fn is_test_function_node(node: &Node, source: &[u8], language: Language) -> bool {
    matches_test_function(node, source, language)
}

/// Per-language predicate: is this AST node a test function declaration?
fn matches_test_function(node: &Node, source: &[u8], language: Language) -> bool {
    match language {
        Language::Python => python_is_test_function(node, source),
        Language::JavaScript | Language::TypeScript => js_is_test_call(node, source),
        Language::Java | Language::Kotlin => jvm_has_test_annotation(node, source),
        Language::Php => php_is_test_method(node, source),
        Language::Swift => swift_is_test_method(node, source),
        Language::Ruby => ruby_is_test_def_or_block(node, source),
        Language::Go => go_is_top_level_test_function(node, source),
        Language::Scala => scala_is_test_call(node, source),
        Language::Elixir => elixir_is_test_macro(node, source),
        Language::Lua | Language::Luau => lua_is_test_call(node, source),
        Language::Rust => rust_is_test_function(node, source),
        Language::CSharp => csharp_has_test_attribute(node, source),
        // cl7-test-frameworks-v1 (CL-7): OCaml dune/ppx test conventions —
        // `let%test`, `let%test_unit`, `let%expect_test` extension-point
        // bindings, plus Alcotest `test_case "..."` registrations.
        Language::Ocaml => ocaml_is_test_binding(node, source),
        Language::C | Language::Cpp => false,
        // solidity-test-recognizer-v1 (v0.5.0 SOL-009): Foundry/Forge test
        // convention. A function is a test if it is a `function_definition`
        // whose name starts with `test`, `fuzz`, or `invariant_`. The
        // file-level filter (`is_candidate_test_file`) already gates
        // whether we even reach this predicate, so `test*` functions in
        // `src/` files won't be visited.
        //
        // Forge hooks (`setUp`, `setUpAll`, etc.) are intentionally NOT
        // matched — they don't start with `test`/`fuzz`/`invariant_`.
        Language::Solidity => solidity_is_forge_test_function(node, source),
    }
}

// -- Rust: `#[test]` attribute precedes a `fn` item ---------------------------
//
// In tree-sitter-rust, `#[test]` is parsed as an `attribute_item` that is a
// SIBLING (preceding) of the `function_item`, not a child. So at every
// `function_item` we walk back to the previous siblings collecting any
// `attribute_item` nodes; if any contains an `attribute` whose head
// identifier is `test`, this is a unit test. We also accept aliases
// commonly used in async/integration setups: `tokio::test`, `async_std::test`,
// `rstest`, `proptest`, plus the common `test_case` macro.
fn rust_is_test_function(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "function_item" {
        return false;
    }
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {
                if rust_attribute_is_test(&p, source) {
                    return true;
                }
                prev = p.prev_sibling();
            }
            "line_comment" | "block_comment" => {
                prev = p.prev_sibling();
            }
            _ => break,
        }
    }
    false
}

fn rust_attribute_is_test(attr_item: &Node, source: &[u8]) -> bool {
    // attribute_item -> [#, [, attribute(...), ]]
    let mut cursor = attr_item.walk();
    for child in attr_item.children(&mut cursor) {
        if child.kind() == "attribute" {
            // attribute can be `test`, `tokio::test`, `test_case::test_case`,
            // etc. Walk and collect the tail identifier(s).
            let text = node_text(child, source);
            // Strip any argument list `(...)` and whitespace; take the path tail.
            let head = text
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or("");
            let tail = head.rsplit("::").next().unwrap_or("");
            if matches!(
                tail,
                "test" | "tokio_test" | "async_test" | "rstest" | "test_case"
            ) {
                return true;
            }
        }
    }
    false
}

// -- C#: methods with `[Test]` / `[Fact]` / `[TestMethod]` etc. --------------
//
// tree-sitter-c-sharp uses `method_declaration` whose direct children include
// one or more `attribute_list` nodes. Each `attribute_list` contains
// `attribute` children whose first identifier names the attribute (e.g.
// "Test", "Fact", "TestMethod", "TestCase", "Theory").
fn csharp_has_test_attribute(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "method_declaration" {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute_list" {
            let mut inner = child.walk();
            for attr in child.children(&mut inner) {
                if attr.kind() == "attribute" && csharp_attribute_is_test(&attr, source) {
                    return true;
                }
            }
        }
    }
    false
}

fn csharp_attribute_is_test(attribute: &Node, source: &[u8]) -> bool {
    // Read the tail identifier of the attribute name.
    let text = node_text(*attribute, source);
    let head = text
        .split(|c: char| c == '(' || c.is_whitespace())
        .next()
        .unwrap_or("");
    let tail = head.rsplit('.').next().unwrap_or("");
    matches!(
        tail,
        "Test"
            | "TestAttribute"
            | "Fact"
            | "FactAttribute"
            | "Theory"
            | "TheoryAttribute"
            | "TestMethod"
            | "TestMethodAttribute"
            | "TestCase"
            | "TestCaseAttribute"
            | "DataTestMethod"
            | "DataTestMethodAttribute"
    )
}

// -- Python: `def test_*` -----------------------------------------------------
fn python_is_test_function(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "function_definition" {
        return false;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or_default();
    name.starts_with("test_")
}

// -- JS/TS: `it(...)` / `test(...)` -------------------------------------------
fn js_is_test_call(node: &Node, source: &[u8]) -> bool {
    // tree-sitter-typescript / -javascript both expose `call_expression`
    // with a `function` child that's an identifier for top-level calls.
    if node.kind() != "call_expression" {
        return false;
    }
    let func_node = match node.child_by_field_name("function") {
        Some(n) => n,
        None => return false,
    };
    // We only want unqualified identifiers (`it("...")`, `test("...")`),
    // not member calls like `obj.it(...)` which are unrelated.
    if func_node.kind() != "identifier" {
        return false;
    }
    let name = node_text(func_node, source);
    matches!(name.as_str(), "it" | "test" | "fit" | "xit" | "xtest")
}

// -- Java/Kotlin: methods with @Test / @ParameterizedTest / @RepeatedTest ----
//
// JUnit5 ships several annotations beyond the bare `@Test`:
//   * `@ParameterizedTest` (junit-jupiter-params)
//   * `@RepeatedTest`      (junit-jupiter-api)
//   * `@TestFactory`       (dynamic tests)
//   * `@TestTemplate`      (extension point for custom test types)
// Kotest / JUnit4 / TestNG add a few more variants that share the same
// tail identifier (`Test`). We accept any annotation whose tail
// identifier is in this set — the import path / package qualifier is
// irrelevant.
//
// test-recognizer-expansion-v1 (P22 M-005): the previous predicate hard-
// coded the tail `"Test"`, silently dropping JUnit5 parameterized/repeated
// tests at the AST count stage.
const JVM_TEST_ANNOTATIONS: &[&str] = &[
    "Test",
    "ParameterizedTest",
    "RepeatedTest",
    "TestFactory",
    "TestTemplate",
];

fn jvm_has_test_annotation(node: &Node, source: &[u8]) -> bool {
    // Java tree-sitter: `method_declaration` with a sibling `modifiers`
    // child containing `marker_annotation` / `annotation` whose name is
    // one of `JVM_TEST_ANNOTATIONS`. Kotlin (kotlin-ng):
    // `function_declaration` with a `modifiers` child containing
    // `annotation` -> `user_type` -> `type_identifier`.
    let kind = node.kind();
    if kind != "method_declaration" && kind != "function_declaration" {
        return false;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            if subtree_contains_annotation_in(&child, source, JVM_TEST_ANNOTATIONS) {
                return true;
            }
        } else if (child.kind() == "annotation" || child.kind() == "marker_annotation")
            && annotation_name_in(&child, source, JVM_TEST_ANNOTATIONS)
        {
            return true;
        }
    }
    false
}

fn subtree_contains_annotation_in(node: &Node, source: &[u8], targets: &[&str]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if (kind == "annotation" || kind == "marker_annotation")
            && annotation_name_in(&child, source, targets)
        {
            return true;
        }
        if subtree_contains_annotation_in(&child, source, targets) {
            return true;
        }
    }
    false
}

/// True if `annotation_node`'s tail identifier (after the last `.`) is in
/// `targets`. Handles fully-qualified annotations like
/// `@org.junit.jupiter.api.Test` and bare ones like `@ParameterizedTest`.
fn annotation_name_in(annotation_node: &Node, source: &[u8], targets: &[&str]) -> bool {
    let text = node_text(*annotation_node, source);
    let trimmed = text.trim_start_matches('@');
    let head = trimmed
        .split(|c: char| c == '(' || c.is_whitespace())
        .next()
        .unwrap_or("");
    let last = head.rsplit('.').next().unwrap_or("");
    targets.iter().any(|t| *t == last)
}

// -- PHP: PHPUnit `public function test*` -------------------------------------
fn php_is_test_method(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "method_declaration" {
        return false;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or_default();
    name.starts_with("test")
}

// -- Swift: `func test*()` ----------------------------------------------------
fn swift_is_test_method(node: &Node, source: &[u8]) -> bool {
    // tree-sitter-swift uses `function_declaration` (top-level) and
    // `protocol_function_declaration` (inside class body); we accept any
    // declaration whose `name` child starts with "test".
    let kind = node.kind();
    if !(kind == "function_declaration" || kind == "protocol_function_declaration") {
        return false;
    }
    // Swift grammar exposes the method name as the first `simple_identifier`
    // child after the `func` keyword. Walk children to find it.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "simple_identifier" {
            return node_text(child, source).starts_with("test");
        }
    }
    false
}

// -- Ruby: `def test_*` (Minitest) or `it/describe` blocks (RSpec) -----------
fn ruby_is_test_def_or_block(node: &Node, source: &[u8]) -> bool {
    match node.kind() {
        "method" => {
            // Minitest: `def test_<name>`.
            let name = node
                .child_by_field_name("name")
                .map(|n| node_text(n, source))
                .unwrap_or_default();
            name.starts_with("test_")
        }
        "call" => {
            // RSpec: `it "..." do ... end` / `specify "..." do ... end`.
            let method = node
                .child_by_field_name("method")
                .map(|n| node_text(n, source))
                .unwrap_or_default();
            matches!(method.as_str(), "it" | "specify")
        }
        _ => false,
    }
}

// -- Go: top-level `func TestXxx(t *testing.T)` -------------------------------
fn go_is_top_level_test_function(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "function_declaration" {
        return false;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or_default();
    if !name.starts_with("Test") {
        return false;
    }
    // Filter out `Test` exactly (no following uppercase). The Go testing
    // convention is `TestXxx` where `X` is upper.
    let after = name.strip_prefix("Test").unwrap_or("");
    let starts_upper = after.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false);
    starts_upper
}

// -- Scala: `test("...") { ... }` / `property("...") { ... }` calls -----------
fn scala_is_test_call(node: &Node, source: &[u8]) -> bool {
    // tree-sitter-scala uses `call_expression`. MUnit / ScalaTest FunSuite
    // register cases with `test("name") { ... }`; ScalaCheck integrations
    // (`munit.ScalaCheckSuite`, `org.scalatest.prop`) use
    // `property("name") { ... }`. Both shapes parse as a `call_expression`
    // whose `function` child is ITSELF a `call_expression` of the form
    // `test("name")` / `property("name")` (the trailing `{ ... }` block is
    // the outer call's argument). Accept either by reading the tail
    // identifier of the callee, descending through the inner
    // call_expression when present.
    //
    // cl7-test-frameworks-v1 (CL-7): the previous predicate only matched
    // `test`, silently dropping every ScalaCheck `property(...)` suite.
    if node.kind() != "call_expression" {
        return false;
    }
    let func_node = match node.child_by_field_name("function") {
        Some(n) => n,
        None => return false,
    };
    // `test("name") { ... }` parses as call_expression{ function:
    // call_expression{ function: identifier "test" }, arguments: block }.
    // Drill into the nested call's function identifier when present.
    let callee = if func_node.kind() == "call_expression" {
        func_node
            .child_by_field_name("function")
            .unwrap_or(func_node)
    } else {
        func_node
    };
    let name = node_text(callee, source);
    let tail = name.rsplit('.').next().unwrap_or(&name);
    matches!(tail, "test" | "property")
}

// -- OCaml: `let%test` / `let%expect_test` / Alcotest `test_case` -------------
//
// cl7-test-frameworks-v1 (CL-7): tree-sitter-ocaml parses ppx test bindings
// as a `value_definition` whose children are `let`, `%`, `attribute_id`
// (the extension name — `test`, `test_unit`, `expect_test`), and a
// `let_binding`. We recognise any value_definition carrying a test-shaped
// extension id. Alcotest suites register cases as `test_case "name" speed f`
// (an `application_expression` whose function tail is `test_case`); accept
// that shape too so `alcotest`-based suites count their cases.
fn ocaml_is_test_binding(node: &Node, source: &[u8]) -> bool {
    match node.kind() {
        "value_definition" => {
            // Look for the `%` + `attribute_id` extension marker among the
            // direct children. The attribute id names the ppx test kind.
            let mut cursor = node.walk();
            let mut saw_percent = false;
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "%" => saw_percent = true,
                    "attribute_id" if saw_percent => {
                        let id = node_text(child, source);
                        let tail = id.rsplit('.').next().unwrap_or(&id);
                        return matches!(
                            tail,
                            "test" | "test_unit" | "expect_test" | "test_module"
                        );
                    }
                    _ => {}
                }
            }
            false
        }
        // Alcotest: `test_case "desc" `Quick f` — an application whose
        // callee tail identifier is `test_case`.
        "application_expression" => {
            let func = match node.child_by_field_name("function") {
                Some(f) => f,
                None => return false,
            };
            let name = node_text(func, source);
            let tail = name.rsplit('.').next().unwrap_or(&name);
            matches!(tail, "test_case")
        }
        _ => false,
    }
}

// -- Elixir: `test "..." do ... end` ------------------------------------------
fn elixir_is_test_macro(node: &Node, source: &[u8]) -> bool {
    // tree-sitter-elixir parses macros as `call` nodes; the head is the
    // `target` child (an `identifier`), and the body is a `do_block`.
    if node.kind() != "call" {
        return false;
    }
    let target = match node.child_by_field_name("target") {
        Some(n) => n,
        None => return false,
    };
    node_text(target, source) == "test"
}

// -- Lua/Luau: `it(...)` / `describe(...)` (busted) ---------------------------
fn lua_is_test_call(node: &Node, source: &[u8]) -> bool {
    // tree-sitter-lua / -luau represent calls as `function_call`. The
    // function name lives in the `name` field (an `identifier`).
    if node.kind() != "function_call" && node.kind() != "function_call_statement" {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return matches!(node_text(child, source).as_str(), "it" | "test");
        }
    }
    false
}

// -- Solidity: Foundry/Forge `function test*`/`fuzz*`/`invariant_*` -----------
//
// solidity-test-recognizer-v1 (v0.5.0 SOL-009): Foundry/Forge test convention.
//
// Tree-sitter-solidity emits Solidity functions as `function_definition`
// nodes with a `name` field (an `identifier`). Foundry's test discovery
// picks up any function whose name starts with `test`, `fuzz`, or
// `invariant_`. Hooks like `setUp` are intentionally excluded.
//
// File-path gating (must live in `test/`, `tests/`, or have a filename
// containing `test`) is handled upstream by `is_candidate_test_file`, so
// this predicate purely filters on the function name. A `function testFoo`
// inside `src/Main.sol` therefore never reaches this code — the
// recognise() short-circuit returns `is_test_file = false` first.
//
// We deliberately do NOT (yet) check inheritance from `Test` / `forge-std`
// transitively — that's a Phase-2 refinement. The file-path heuristic is
// sufficient for v1 per the oracle research and the standard Foundry layout.
fn solidity_is_forge_test_function(node: &Node, source: &[u8]) -> bool {
    if node.kind() != "function_definition" {
        return false;
    }
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or_default();
    // Foundry conventions:
    //   - `test*`         → unit test (the default `forge test` discovery).
    //   - `fuzz*`         → property test (fuzz inputs).
    //   - `invariant_*`   → invariant test (stateful fuzzing).
    // Hooks like `setUp` / `setUpAll` / `afterInvariant` do NOT match.
    name.starts_with("test") || name.starts_with("fuzz") || name.starts_with("invariant_")
}

// -- Helpers ------------------------------------------------------------------
fn node_text(node: Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() {
        std::str::from_utf8(&source[start..end])
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    }
}

/// Detect language for a candidate test file. Returns `None` if the
/// extension isn't supported.
pub fn detect_language(path: &Path) -> Option<Language> {
    Language::from_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn python_test_function_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "test_x.py",
            "def test_one():\n    pass\n\ndef test_two():\n    pass\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Python);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }

    #[test]
    fn javascript_describe_it_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "foo.test.js",
            "describe('s', () => { it('a', () => {}); it('b', () => {}); });",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::JavaScript);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }

    #[test]
    fn java_test_annotation_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "FooTest.java",
            "import org.junit.Test;\nclass FooTest {\n  @Test public void shouldFoo() {}\n  @Test public void shouldBar() {}\n}\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Java);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }

    #[test]
    fn php_phpunit_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "FooTest.php",
            "<?php\nclass FooTest {\n  public function testBar() {}\n  public function testBaz() {}\n}\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Php);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }

    #[test]
    fn swift_xctest_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "FooTests.swift",
            "import XCTest\nclass FooTests: XCTestCase {\n  func testBar() {}\n  func testBaz() {}\n}\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Swift);
        assert!(info.is_test_file);
        assert!(info.test_function_count >= 2);
    }

    #[test]
    fn go_testing_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "foo_test.go",
            "package foo\nimport \"testing\"\nfunc TestFoo(t *testing.T) {}\nfunc TestBar(t *testing.T) {}\nfunc helper() {}\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Go);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }

    #[test]
    fn ruby_minitest_counted() {
        let tmp = tempdir().unwrap();
        let p = write(
            tmp.path(),
            "foo_test.rb",
            "class FooTest\n  def test_one; end\n  def test_two; end\nend\n",
        );
        let src = fs::read_to_string(&p).unwrap();
        let info = recognize(&p, &src, Language::Ruby);
        assert!(info.is_test_file);
        assert_eq!(info.test_function_count, 2);
    }
}
