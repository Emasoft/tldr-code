//! Complexity metrics calculation
//!
//! Implements cyclomatic and cognitive complexity as per spec Section 2.3.2.
//!
//! # Cyclomatic Complexity
//! - V(G) = E - N + 2 (edges - nodes + 2)
//! - Counts decision points: if, elif, for, while, case, catch, &&, ||, ?:
//! - issue-75-cl4-cyclomatic-parity-v1: the decision-point table below is the
//!   per-language union of the grammars this tool parses. Convention
//!   (standard McCabe, extended to track `cognitive.rs`'s cyclomatic column
//!   so `tldr complexity` and `tldr cognitive --include-cyclomatic` stay
//!   aligned):
//!   - one decision per `if`/`elif`/loop/`catch`/ternary/short-circuit
//!     `&&`/`||` — grammars that model these as *expressions* (`if_expression`
//!     in rust/kotlin/scala/ocaml, `for_expression`/`while_expression`/
//!     `loop_expression` in rust/scala/ocaml) are credited through the same
//!     arms (see the pinned grammars' node-types.json — a construct has
//!     exactly one of the statement/expression kind, so no double count);
//!   - match/when dispatch constructs are credited once for the dispatch
//!     (`match_expression`, `when_expression`) plus once per arm, mirroring
//!     cognitive.rs; catchall arms (`else`/`default`/`_`/wildcard) add
//!     nothing (same rule as the cognitive counter's per-arm credit);
//!   - C# `switch_section` is the per-case unit (the `case_switch_label` /
//!     `default_switch_label` kinds cited by issue #75 do not exist in the
//!     pinned tree-sitter-c-sharp 0.23.1 node-types.json — a section's first
//!     child is either the `case` payload or the anonymous `default` token);
//!     the default section is the catchall and adds nothing.
//!
//! # Cognitive Complexity (SonarSource)
//! - Increment for each control structure
//! - Additional increment per nesting level
//! - Breaks in linear flow (break, continue, goto)

use std::collections::HashMap;
use std::path::Path;

use tree_sitter::Node;

use crate::ast::function_finder::{
    find_function_node, get_function_body, get_function_name, get_function_node_kinds,
};
use crate::ast::parser::{parse, parse_file};
use crate::error::TldrError;
// issue-75-cl4-cyclomatic-parity-v1: catchall-arm detection helpers are the
// same ones the cognitive counter uses for its per-arm credit — a single
// source of truth for "which arm is the catchall" per grammar.
use crate::metrics::cognitive::{
    is_default_case_statement, is_elixir_catchall_stab_clause, is_kotlin_else_when_entry,
    is_ocaml_wildcard_match_case,
};
use crate::types::{ComplexityMetrics, Language};
use crate::TldrResult;

/// Maximum nesting depth to prevent infinite loops (M24 mitigation)
const MAX_NESTING_DEPTH: usize = 100;

/// Calculate complexity metrics for a function
///
/// # Arguments
/// * `source_or_path` - Source code or file path
/// * `function_name` - Name of function to analyze
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(ComplexityMetrics)` - Complexity metrics
/// * `Err(TldrError::FunctionNotFound)` - Function not found
///
/// # Example
/// ```ignore
/// use tldr_core::metrics::calculate_complexity;
/// use tldr_core::Language;
///
/// let metrics = calculate_complexity("def foo(): pass", "foo", Language::Python)?;
/// assert_eq!(metrics.cyclomatic, 1);
/// ```
pub fn calculate_complexity(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<ComplexityMetrics> {
    // Determine if input is a file path or source code
    let (tree, source) = if Path::new(source_or_path).exists() {
        let (tree, source, _lang) = parse_file(Path::new(source_or_path))?;
        (tree, source)
    } else {
        let tree = parse(source_or_path, language)?;
        (tree, source_or_path.to_string())
    };

    let root = tree.root_node();

    // Find the function
    let func_node = find_function_node(root, function_name, language, &source);

    match func_node {
        Some(node) => {
            let mut calculator =
                ComplexityCalculator::new(function_name.to_string(), &source, language);
            calculator.analyze_function(node)?;
            let mut metrics = calculator.into_metrics();
            // BUG-7 (cross-command-consistency-v1): delegate the cognitive
            // number (and `nesting_depth`, which is the same `max_nesting`)
            // to the canonical SonarSource calculator that backs
            // `tldr cognitive`.  This kills the per-command drift that made
            // `tldr complexity` and `tldr cognitive` disagree on the same
            // function.
            let canonical = crate::metrics::cognitive::calculate_cognitive_for_function(
                function_name,
                &source,
                language,
                node,
            );
            metrics.cognitive = canonical.cognitive;
            metrics.max_nesting = canonical.max_nesting;
            Ok(metrics)
        }
        None => Err(TldrError::function_not_found(function_name)),
    }
}

/// Calculate complexity metrics for ALL functions in source code in a single pass.
///
/// Parses the file once, walks the AST to find all function/method nodes,
/// and calculates complexity for each. This is 10-25x faster than calling
/// `calculate_complexity()` per function when a file has many functions.
///
/// # Arguments
/// * `source` - Source code string
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(HashMap<String, ComplexityMetrics>)` - Map of function_name -> metrics
pub fn calculate_all_complexities(
    source: &str,
    language: Language,
) -> TldrResult<HashMap<String, ComplexityMetrics>> {
    let tree = parse(source, language)?;
    let root = tree.root_node();
    calculate_all_complexities_from_tree(root, source, language)
}

/// Calculate complexity metrics for ALL functions in a file in a single pass.
///
/// Reads and parses the file once, then calculates complexity for all functions.
///
/// # Arguments
/// * `path` - File path to analyze
///
/// # Returns
/// * `Ok(HashMap<String, ComplexityMetrics>)` - Map of function_name -> metrics
pub fn calculate_all_complexities_file(
    path: &Path,
) -> TldrResult<HashMap<String, ComplexityMetrics>> {
    let (tree, source, lang) = parse_file(path)?;
    let root = tree.root_node();
    calculate_all_complexities_from_tree(root, &source, lang)
}

/// Calculate complexity metrics for all functions given an already-parsed tree.
///
/// Use this when you already have a parsed tree to avoid redundant parsing.
/// Walks the AST depth-first to find all function/method nodes, then runs
/// the complexity calculator on each.
pub fn calculate_all_complexities_from_tree(
    root: Node,
    source: &str,
    language: Language,
) -> TldrResult<HashMap<String, ComplexityMetrics>> {
    let func_kinds = get_function_node_kinds(language);
    let mut results = HashMap::new();

    // DFS to find all function nodes
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if func_kinds.contains(&node.kind()) {
            if let Some(name) = get_function_name(node, language, source) {
                let mut calculator = ComplexityCalculator::new(name.clone(), source, language);
                if calculator.analyze_function(node).is_ok() {
                    let mut metrics = calculator.into_metrics();
                    // BUG-7 (cross-command-consistency-v1): batch path must
                    // also delegate to the canonical SonarSource calculator.
                    let canonical = crate::metrics::cognitive::calculate_cognitive_for_function(
                        &name, source, language, node,
                    );
                    metrics.cognitive = canonical.cognitive;
                    metrics.max_nesting = canonical.max_nesting;
                    results.insert(name, metrics);
                }
            }
        }

        // Push children in reverse order for left-to-right DFS
        let child_count = node.child_count();
        for i in (0..child_count).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }

    Ok(results)
}

/// Calculator for complexity metrics
struct ComplexityCalculator<'a> {
    function_name: String,
    source: &'a str,
    language: Language,
    cyclomatic: u32,
    cognitive: u32,
    max_nesting: u32,
    current_nesting: u32,
    lines_of_code: u32,
    start_line: u32,
    end_line: u32,
}

impl<'a> ComplexityCalculator<'a> {
    fn new(function_name: String, source: &'a str, language: Language) -> Self {
        Self {
            function_name,
            source,
            language,
            cyclomatic: 1, // Base complexity is 1
            cognitive: 0,
            max_nesting: 0,
            current_nesting: 0,
            lines_of_code: 0,
            start_line: 0,
            end_line: 0,
        }
    }

    fn analyze_function(&mut self, func_node: Node) -> TldrResult<()> {
        self.start_line = func_node.start_position().row as u32 + 1;
        self.end_line = func_node.end_position().row as u32 + 1;
        self.lines_of_code = self.end_line - self.start_line + 1;

        // Get function body
        let body = get_function_body(func_node, self.language);

        if let Some(body_node) = body {
            self.analyze_node(body_node, 0)?;
        }

        Ok(())
    }

    fn analyze_node(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if depth > MAX_NESTING_DEPTH {
            return Ok(());
        }

        let kind = node.kind();

        // Update nesting tracking
        let is_nesting_structure = self.is_nesting_structure(kind);
        if is_nesting_structure {
            self.current_nesting += 1;
            self.max_nesting = self.max_nesting.max(self.current_nesting);
        }

        // Count decision points for cyclomatic complexity
        self.count_cyclomatic_increment(node);

        // Count cognitive complexity
        self.count_cognitive_increment(node);

        // Recurse into children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.analyze_node(cursor.node(), depth + 1)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        if is_nesting_structure {
            self.current_nesting -= 1;
        }

        Ok(())
    }

    /// Check if a node kind introduces nesting
    fn is_nesting_structure(&self, kind: &str) -> bool {
        matches!(
            kind,
            "if_statement"
                | "elif_clause"
                | "else_clause"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "try_statement"
                | "except_clause"
                | "catch_clause"
                | "with_statement"
                | "match_statement"
                | "switch_statement"
                | "lambda"
                | "lambda_expression"
                | "conditional_expression" // ternary
        )
    }

    /// Count cyclomatic complexity increments
    ///
    /// Cyclomatic complexity counts decision points:
    /// - if, elif, else (else doesn't add, but the branch does)
    /// - for, while loops (statement OR expression forms)
    /// - case/match/when dispatch constructs and their arms
    /// - catch/except handlers
    /// - && and || operators
    /// - ?: ternary operator
    ///
    /// issue-75-cl4-cyclomatic-parity-v1: the per-language arms mirror
    /// `cognitive.rs::count_cyclomatic_increment` (the counter behind
    /// `tldr cognitive --include-cyclomatic`) so the two commands report
    /// the same cyclomatic number for the same function. Catchall arms
    /// (`else`/`default`/`_`) are excluded via the shared cognitive helpers.
    fn count_cyclomatic_increment(&mut self, node: Node) {
        let kind = node.kind();

        // Primary decision points
        match kind {
            // `if_expression` is the conditional kind in grammars that model
            // `if` as an expression (rust/kotlin/scala/ocaml per their pinned
            // node-types.json). No pinned grammar emits both `if_statement`
            // and `if_expression`, so the arm cannot double-count.
            "if_statement" | "if_expression" | "elif_clause" => {
                self.cyclomatic += 1;
            }
            "for_statement" | "for_in_statement" | "while_statement" => {
                self.cyclomatic += 1;
            }
            "except_clause" | "catch_clause" | "except_handler" => {
                self.cyclomatic += 1;
            }
            "case_clause" | "match_arm" | "switch_case" => {
                self.cyclomatic += 1;
            }
            "conditional_expression" | "ternary_expression" => {
                self.cyclomatic += 1;
            }
            // pattern-match-arm-undercount-v1: cyclomatic +1 per non-catchall
            // arm for c/cpp `case_statement`, kotlin `when_entry`, ocaml
            // `match_case`, elixir `stab_clause`. (rust `match_arm` /
            // scala `case_clause` are already credited above.)
            "case_statement"
                if matches!(self.language, Language::C | Language::Cpp)
                    && !is_default_case_statement(node) =>
            {
                self.cyclomatic += 1
            }
            "when_entry"
                if matches!(self.language, Language::Kotlin)
                    && !is_kotlin_else_when_entry(node) =>
            {
                self.cyclomatic += 1
            }
            "match_case"
                if matches!(self.language, Language::Ocaml)
                    && !is_ocaml_wildcard_match_case(node, self.source) =>
            {
                self.cyclomatic += 1
            }
            "stab_clause"
                if matches!(self.language, Language::Elixir)
                    && !is_elixir_catchall_stab_clause(node, self.source) =>
            {
                self.cyclomatic += 1
            }
            // Loop/match expressions on Rust/Scala/OCaml (these grammars have
            // no `*_statement` loop kinds — verified in node-types.json).
            "for_expression" | "while_expression" | "loop_expression"
                if matches!(
                    self.language,
                    Language::Rust | Language::Scala | Language::Ocaml
                ) =>
            {
                self.cyclomatic += 1
            }
            "match_expression"
                if matches!(
                    self.language,
                    Language::Rust | Language::Scala | Language::Ocaml
                ) =>
            {
                self.cyclomatic += 1
            }
            "when_expression" if matches!(self.language, Language::Kotlin) => self.cyclomatic += 1,
            "do_while_statement" if matches!(self.language, Language::Kotlin) => {
                self.cyclomatic += 1
            }
            // issue-75-cl4: C#. `foreach_statement` is the loop kind in the
            // pinned tree-sitter-c-sharp 0.23.1 node-types.json (php's
            // `foreach_statement` is also a loop, so the arm stays ungated).
            "foreach_statement" => {
                self.cyclomatic += 1;
            }
            // `switch_section` is the per-case unit of a C# `switch_statement`
            // (`switch_body` = repeat(switch_section); the `case_switch_label`
            // / `default_switch_label` kinds cited by the issue do not exist
            // in the pinned grammar). The default section is the catchall.
            "switch_section"
                if matches!(self.language, Language::CSharp)
                    && !is_csharp_default_switch_section(node) =>
            {
                self.cyclomatic += 1
            }
            // Ruby AST kinds (P12.AGG12-10 + cognitive-else-counting-fix-v1).
            // Gate bare-keyword cognates on Language::Ruby — in other
            // grammars these are literal-token leaves of statement nodes and
            // would double-count cyclomatic complexity. The `*_modifier`
            // forms are Ruby-only by construction so are safe.
            "if" | "unless" if matches!(self.language, Language::Ruby) => self.cyclomatic += 1,
            "while" | "until" if matches!(self.language, Language::Ruby) => self.cyclomatic += 1,
            "for" if matches!(self.language, Language::Ruby) => self.cyclomatic += 1,
            "rescue" if matches!(self.language, Language::Ruby) => self.cyclomatic += 1,
            "if_modifier" | "unless_modifier" => self.cyclomatic += 1,
            "while_modifier" | "until_modifier" => self.cyclomatic += 1,
            "when" if matches!(self.language, Language::Ruby) => self.cyclomatic += 1, // case-arm cognate
            _ => {}
        }

        // Logical operators in conditions. Only check the parent
        // boolean_operator/binary_expression node via its `operator`
        // field text — the operator keyword/token (`and`/`or`/`&&`/`||`)
        // is also visited as its own child node during the DFS walk, so a
        // second, unconditional match on `kind == "&&" | "||" | "and" |
        // "or"` here double-counted every logical operator (e.g. `a and
        // b` added 2 instead of 1 to cyclomatic complexity).
        //
        // issue-75-cl4: scala and ocaml model ALL infix operators as
        // `infix_expression` with an `operator` field (verified in both
        // pinned grammars' node-types.json) — boolean `&&`/`||` included.
        // The operator-text filter keeps arithmetic/comparison infix nodes
        // out; ocaml's deprecated-but-valid `or` boolean keyword is
        // credited like `||`.
        if kind == "boolean_operator" || kind == "binary_expression" || kind == "infix_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(self.source.as_bytes()).unwrap_or("");
                if op_text == "and" || op_text == "or" || op_text == "&&" || op_text == "||" {
                    self.cyclomatic += 1;
                }
            }
        }
    }

    /// Count cognitive complexity increments
    ///
    /// Cognitive complexity (SonarSource):
    /// - Base increment for control structures
    /// - Nesting penalty for nested structures
    /// - Increment for breaks in linear flow
    fn count_cognitive_increment(&mut self, node: Node) {
        let kind = node.kind();

        // Control structures add 1 + nesting level
        let base_increment = match kind {
            "if_statement" => Some(1),
            "elif_clause" => Some(1),
            "else_clause" => Some(1),
            "for_statement" | "for_in_statement" => Some(1),
            "while_statement" => Some(1),
            "except_clause" | "catch_clause" => Some(1),
            "match_statement" | "switch_statement" => Some(1),
            "conditional_expression" | "ternary_expression" => Some(1),
            _ => None,
        };

        if let Some(base) = base_increment {
            // Add base + nesting penalty
            // Cognitive complexity adds 1 for each nesting level
            self.cognitive += base + self.current_nesting.saturating_sub(1);
        }

        // Breaks in linear flow
        match kind {
            "break_statement" | "continue_statement" => {
                self.cognitive += 1;
            }
            "return_statement" => {
                // Return early adds cognitive load (but not when it's the last statement)
                // For simplicity, we count all returns after the first
                // This is a simplification of the SonarSource rules
            }
            _ => {}
        }

        // Logical operators in conditions add complexity
        if kind == "boolean_operator" || kind == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(self.source.as_bytes()).unwrap_or("");
                if op_text == "and" || op_text == "or" || op_text == "&&" || op_text == "||" {
                    self.cognitive += 1;
                }
            }
        }

        // Recursion adds cognitive complexity
        // Check if this is a call to the current function
        if kind == "call" || kind == "call_expression" {
            if let Some(callee) = self.get_callee_name(node) {
                if callee == self.function_name {
                    self.cognitive += 1;
                }
            }
        }
    }

    /// Get callee name from call node
    fn get_callee_name(&self, call_node: Node) -> Option<String> {
        let func_node = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child(0))?;

        match func_node.kind() {
            "identifier" => Some(
                func_node
                    .utf8_text(self.source.as_bytes())
                    .ok()?
                    .to_string(),
            ),
            _ => None,
        }
    }

    fn into_metrics(self) -> ComplexityMetrics {
        ComplexityMetrics {
            function: self.function_name,
            cyclomatic: self.cyclomatic,
            cognitive: self.cognitive,
            max_nesting: self.max_nesting,
            lines_of_code: self.lines_of_code,
        }
    }
}

/// issue-75-cl4-cyclomatic-parity-v1: C# — a `switch_section` whose first
/// child is the anonymous `default` token is the catchall arm and is NOT
/// credited. Per the pinned tree-sitter-c-sharp 0.23.1 grammar,
/// `switch_section: prec.left(seq(choice(seq('case', …), 'default'), ':',
/// repeat(statement)))` — a case section's first child carries the `case`
/// payload (expression/pattern), a default section's first child is the
/// `default` keyword itself. Same first-child trick as cognitive.rs's
/// `is_default_case_statement` for C/C++.
fn is_csharp_default_switch_section(node: Node) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    cursor.node().kind() == "default"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function_complexity() {
        let source = r#"
def simple():
    return 1
"#;
        let metrics = calculate_complexity(source, "simple", Language::Python).unwrap();
        assert_eq!(metrics.function, "simple");
        assert_eq!(metrics.cyclomatic, 1); // No branches
        assert_eq!(metrics.cognitive, 0); // No control structures
    }

    #[test]
    fn test_if_statement_complexity() {
        let source = r#"
def with_if(x):
    if x > 0:
        return 1
    return 0
"#;
        let metrics = calculate_complexity(source, "with_if", Language::Python).unwrap();
        assert_eq!(metrics.cyclomatic, 2); // Base + 1 if
    }

    #[test]
    fn test_nested_if_complexity() {
        let source = r#"
def nested(a, b):
    if a > 0:
        if b > 0:
            return 1
    return 0
"#;
        let metrics = calculate_complexity(source, "nested", Language::Python).unwrap();
        assert_eq!(metrics.cyclomatic, 3); // Base + 2 ifs
        assert!(metrics.cognitive >= 3); // if + (nested if with penalty)
        assert!(metrics.max_nesting >= 2);
    }

    #[test]
    fn test_loop_complexity() {
        let source = r#"
def with_loop():
    for i in range(10):
        print(i)
"#;
        let metrics = calculate_complexity(source, "with_loop", Language::Python).unwrap();
        assert_eq!(metrics.cyclomatic, 2); // Base + 1 for loop
    }

    #[test]
    fn test_function_not_found() {
        let source = "def foo(): pass";
        let result = calculate_complexity(source, "nonexistent", Language::Python);
        assert!(matches!(result, Err(TldrError::FunctionNotFound { .. })));
    }

    #[test]
    fn test_logical_operators() {
        let source = r#"
def with_logic(a, b, c):
    if a and b:
        return 1
    if a or c:
        return 2
    return 0
"#;
        let metrics = calculate_complexity(source, "with_logic", Language::Python).unwrap();
        // Base + 2 ifs + 2 logical operators
        assert!(metrics.cyclomatic >= 4);
    }

    #[test]
    fn test_lines_of_code() {
        let source = r#"
def multiline():
    a = 1
    b = 2
    c = 3
    return a + b + c
"#;
        let metrics = calculate_complexity(source, "multiline", Language::Python).unwrap();
        assert!(metrics.lines_of_code >= 5);
    }

    #[test]
    fn test_batch_complexity_returns_all_functions() {
        let source = r#"
def simple():
    return 1

def with_if(x):
    if x > 0:
        return 1
    return 0

def with_loop():
    for i in range(10):
        print(i)
"#;
        let results = calculate_all_complexities(source, Language::Python).unwrap();
        assert_eq!(results.len(), 3, "Should find all 3 functions");
        assert!(results.contains_key("simple"));
        assert!(results.contains_key("with_if"));
        assert!(results.contains_key("with_loop"));
    }

    #[test]
    fn test_batch_complexity_matches_individual() {
        let source = r#"
def simple():
    return 1

def with_if(x):
    if x > 0:
        return 1
    return 0

def nested(a, b):
    if a > 0:
        if b > 0:
            return 1
    return 0
"#;
        let batch = calculate_all_complexities(source, Language::Python).unwrap();

        // Each batch result should match individual calculation
        for (name, batch_metrics) in &batch {
            let individual = calculate_complexity(source, name, Language::Python).unwrap();
            assert_eq!(
                batch_metrics.cyclomatic, individual.cyclomatic,
                "Cyclomatic mismatch for {}",
                name
            );
            assert_eq!(
                batch_metrics.cognitive, individual.cognitive,
                "Cognitive mismatch for {}",
                name
            );
            assert_eq!(
                batch_metrics.max_nesting, individual.max_nesting,
                "Max nesting mismatch for {}",
                name
            );
            assert_eq!(
                batch_metrics.lines_of_code, individual.lines_of_code,
                "LOC mismatch for {}",
                name
            );
        }
    }

    #[test]
    fn test_batch_complexity_empty_source() {
        let source = "# just a comment\n";
        let results = calculate_all_complexities(source, Language::Python).unwrap();
        assert!(results.is_empty(), "No functions means empty map");
    }

    #[test]
    fn test_batch_complexity_with_class_methods() {
        let source = r#"
class MyClass:
    def method_a(self):
        return 1

    def method_b(self, x):
        if x > 0:
            return x
        return 0
"#;
        let results = calculate_all_complexities(source, Language::Python).unwrap();
        // Should find class methods too
        assert!(
            results.len() >= 2,
            "Should find at least 2 methods, got {}",
            results.len()
        );
    }

    #[test]
    fn test_batch_complexity_file_path() {
        // Test that calculate_all_complexities_file works with a file path
        use std::io::Write;
        let dir = std::env::temp_dir().join("tldr_batch_test");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_batch.py");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(
            f,
            "def foo():\n    return 1\n\ndef bar(x):\n    if x: return x\n    return 0"
        )
        .unwrap();

        let results = calculate_all_complexities_file(&file_path).unwrap();
        assert!(results.contains_key("foo"));
        assert!(results.contains_key("bar"));

        // Clean up
        std::fs::remove_dir_all(&dir).ok();
    }

    // ------------------------------------------------------------------
    // issue-75-cl4-cyclomatic-parity-v1: per-language known-value fixtures.
    // Each fixture is a single function whose textbook (McCabe) decision
    // count is derived construct-by-construct in the trailing comment. The
    // same fixtures are asserted against `tldr cognitive`'s cyclomatic
    // column (analyze_cognitive_source) to pin cross-command parity.
    // ------------------------------------------------------------------

    /// Assert `tldr complexity` and `tldr cognitive --include-cyclomatic`
    /// agree on the same function (cross-command-consistency, BUG-7 style).
    fn assert_cognitive_parity(source: &str, function: &str, language: Language, expected: u32) {
        let options = crate::metrics::cognitive::CognitiveOptions::default().with_cyclomatic(true);
        let report = crate::metrics::cognitive::analyze_cognitive_source(
            source, language, "fixture", &options,
        )
        .unwrap();
        let entry = report
            .functions
            .iter()
            .find(|f| f.name == function)
            .unwrap_or_else(|| panic!("cognitive walker did not find `{}`", function));
        assert_eq!(
            entry.cyclomatic,
            Some(expected),
            "cognitive's cyclomatic disagrees with the textbook count for `{}`",
            function
        );
    }

    #[test]
    fn issue75_python_known_value_control() {
        // Base(1) + if(1) + elif(1) + for(1) + while(1) + if(1) + and(1)
        // + if(1) + or(1) + except(1); `with` and `assert` are not
        // decisions. Total = 10. Python was already correct pre-fix
        // (control fixture — must not regress).
        let source = r#"
def decision_stamp(a, b):
    if a > 0:
        pass
    elif b > 0:
        pass
    for i in range(3):
        pass
    while a > 0:
        a -= 1
    if a > 0 and b > 0:
        pass
    if a > 0 or b > 0:
        pass
    try:
        pass
    except ValueError:
        pass
    with open("/tmp/x") as fh:
        pass
    assert a >= 0
    return 0
"#;
        let metrics = calculate_complexity(source, "decision_stamp", Language::Python).unwrap();
        assert_eq!(metrics.cyclomatic, 10);
        assert_cognitive_parity(source, "decision_stamp", Language::Python, 10);
    }

    #[test]
    fn issue75_go_known_value_control() {
        // Base(1) + if(1) + else-if(1) + for(1) + range-for(1) + &&(1)
        // + if(1) + ||(1). Total = 8. Go was already correct pre-fix
        // (control fixture — must not regress).
        let source = r#"
package main

func decisionStamp(a int, b int) int {
	if a > 0 {
		return 1
	} else if b > 0 {
		return 2
	}
	for i := 0; i < 3; i++ {
	}
	for range []int{1, 2} {
	}
	x := a > 0 && b > 0
	if a > 0 || b > 0 {
		return 3
	}
	_ = x
	return 0
}
"#;
        let metrics = calculate_complexity(source, "decisionStamp", Language::Go).unwrap();
        assert_eq!(metrics.cyclomatic, 8);
        assert_cognitive_parity(source, "decisionStamp", Language::Go, 8);
    }

    #[test]
    fn issue75_rust_known_value() {
        // Base(1) + if_expression(2) + for_expression(1) + while_expression(1)
        // + loop_expression(1) + match_expression(1) + match_arm(3) + &&(1)
        // + if_expression(1) + ||(1) + if_expression(1). Total = 14.
        // Pre-fix this measured 6 (if/loop kinds and the match dispatch
        // were all uncounted).
        let source = r#"
fn decision_stamp(a: i32, b: i32) -> i32 {
    if a > 0 {
        return 1;
    } else if b > 0 {
        return 2;
    }
    for i in 0..3 {
        let _ = i;
    }
    while a > 0 {
        break;
    }
    loop {
        break;
    }
    match a {
        1 => return 3,
        2 => return 4,
        _ => {}
    }
    let x = a > 0 && b > 0;
    if a > 0 || b > 0 {
        return 5;
    }
    if x {
        return 6;
    }
    0
}
"#;
        let metrics = calculate_complexity(source, "decision_stamp", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 14,
            "rust: expression-form ifs/loops/match must count"
        );
        assert_cognitive_parity(source, "decision_stamp", Language::Rust, 14);
    }

    #[test]
    fn issue75_java_known_value_control() {
        // Base(1) + if(1) + else-if(1) + for(1) + while(1) + catch(1)
        // + ternary(1) + &&(1) + if(1) + ||(1) + ternary(1). Total = 11.
        // Java was already correct pre-fix (control fixture).
        let source = r#"
class D {
    static int decisionStamp(int a, int b) {
        if (a > 0) {
            return 1;
        } else if (b > 0) {
            return 2;
        }
        for (int i = 0; i < 3; i++) {
        }
        while (a > 0) {
            a--;
        }
        try {
            int[] arr = new int[1];
            arr[5] = 0;
        } catch (RuntimeException e) {
            return 3;
        }
        int r = a > 0 ? 1 : 0;
        boolean x = a > 0 && b > 0;
        if (a > 0 || b > 0) {
            return 4 + r + (x ? 1 : 0);
        }
        return 0;
    }
}
"#;
        let metrics = calculate_complexity(source, "decisionStamp", Language::Java).unwrap();
        assert_eq!(metrics.cyclomatic, 11);
        assert_cognitive_parity(source, "decisionStamp", Language::Java, 11);
    }

    #[test]
    fn issue75_typescript_known_value_control() {
        // Base(1) + if(1) + else-if(1) + for(1) + while(1) + switch_case(2)
        // (default excluded) + ternary(1) + &&(1) + if(1) + ||(1)
        // + ternary(1). Total = 12. TS was already correct pre-fix
        // (control fixture).
        let source = r#"
export function decisionStamp(a: number, b: number): number {
  if (a > 0) {
    return 1;
  } else if (b > 0) {
    return 2;
  }
  for (let i = 0; i < 3; i++) {
  }
  while (a > 0) {
    a--;
  }
  switch (a) {
    case 1:
      return 3;
    case 2:
      return 4;
    default:
      break;
  }
  const t = a > 0 ? 1 : 0;
  const x = a > 0 && b > 0;
  if (a > 0 || b > 0) {
    return 5;
  }
  return t + (x ? 1 : 0);
}
"#;
        let metrics = calculate_complexity(source, "decisionStamp", Language::TypeScript).unwrap();
        assert_eq!(metrics.cyclomatic, 12);
        assert_cognitive_parity(source, "decisionStamp", Language::TypeScript, 12);
    }

    #[test]
    fn issue75_kotlin_known_value() {
        // Base(1) + if_expression(4: `if (a > 0)`, `else if (b > 0)`,
        // `if (a > 0 || b > 0)`, `return if (x) ...`) + when_expression(1)
        // + when_entry(2; the `else ->` arm is the catchall and adds
        // nothing) + for(1) + while(1) + &&(1) + ||(1). Total = 12.
        // Pre-fix this measured 5 (if_expression/when kinds uncounted).
        // AST note (kotlin-ng 1.1.0): boolean chains are `binary_expression`
        // with an `operator` field (no conj/disjunction kinds), and the
        // `else ->` when-entry's first child is the anonymous `else` token.
        let source = r#"
fun decisionStamp(a: Int, b: Int): Int {
    if (a > 0) {
        return 1
    } else if (b > 0) {
        return 2
    }
    when (a) {
        1 -> return 3
        2 -> return 4
        else -> {}
    }
    for (i in 0..2) {
    }
    while (a > 0) {
        break
    }
    val x = a > 0 && b > 0
    if (a > 0 || b > 0) {
        return 5
    }
    return if (x) 6 else 0
}
"#;
        let metrics = calculate_complexity(source, "decisionStamp", Language::Kotlin).unwrap();
        assert_eq!(
            metrics.cyclomatic, 12,
            "kotlin: if/when expressions must count"
        );
        assert_cognitive_parity(source, "decisionStamp", Language::Kotlin, 12);
    }

    #[test]
    fn issue75_csharp_known_value() {
        // Base(1) + if(2) + foreach(1) + for(1) + while(1) + switch_section(2;
        // the `default:` section is the catchall and adds nothing) + ternary(2)
        // + &&(1) + ||(1) + if(1). Total = 13. Pre-fix this measured 10
        // (foreach and switch sections uncounted).
        //
        // Cognitive-parity note: NOT asserted here — cognitive.rs's own
        // cyclomatic table lacks the C# `foreach_statement`/`switch_section`
        // arms (its column reports 10 for this fixture). Its cognitive
        // SCORE is unaffected. Closing that gap in cognitive.rs is a
        // deliberate follow-up outside this issue's file scope.
        let source = r#"
class D {
    static int DecisionStamp(int a, int b) {
        if (a > 0) {
            return 1;
        } else if (b > 0) {
            return 2;
        }
        foreach (var i in new int[] { 1, 2 }) {
        }
        for (int j = 0; j < 3; j++) {
        }
        while (a > 0) {
            a--;
        }
        switch (a) {
            case 1:
                return 3;
            case 2:
                return 4;
            default:
                break;
        }
        int t = a > 0 ? 1 : 0;
        bool x = a > 0 && b > 0;
        if (a > 0 || b > 0) {
            return 5;
        }
        return t + (x ? 1 : 0);
    }
}
"#;
        let metrics = calculate_complexity(source, "DecisionStamp", Language::CSharp).unwrap();
        assert_eq!(
            metrics.cyclomatic, 13,
            "c# foreach/switch sections must count"
        );
    }

    #[test]
    fn issue75_ocaml_known_value() {
        // Base(1) + if_expression(2) + match_expression(1) + match_case(2;
        // `| _ ->` is the wildcard catchall and adds nothing) + for(1)
        // + while(1) + &&(1) + ||(1) + if_expression(1). Total = 11.
        // Pre-fix this measured 1 — every OCaml decision kind is an
        // expression kind the old table missed entirely.
        //
        // Cognitive-parity note: NOT asserted here — cognitive.rs's own
        // cyclomatic table lacks the scala/ocaml `infix_expression` arm
        // (its column reports 9 for this fixture). Closing that gap in
        // cognitive.rs is a deliberate follow-up outside this issue's
        // file scope.
        let source = r#"
let decision_stamp a b =
  if a > 0 then 1
  else if b > 0 then 2
  else (
    match a with
    | 1 -> 3
    | 2 -> 4
    | _ -> 0);
  ignore (for i = 0 to 2 do ignore i done);
  ignore (while a > 0 do ignore a done);
  ignore (a > 0 && b > 0);
  ignore (a > 0 || b > 0);
  if a > 0 then 5 else 0
"#;
        let metrics = calculate_complexity(source, "decision_stamp", Language::Ocaml).unwrap();
        assert_eq!(
            metrics.cyclomatic, 11,
            "ocaml: if/match/loop expressions must count"
        );
    }

    #[test]
    fn issue75_scala_known_value() {
        // Base(1) + if_expression(3: `if (a > 0)`, `else if (b > 0)`,
        // `if (a > 0 || b > 0)`) + match_expression(1) + case_clause(3;
        // includes the `case _` arm — pre-existing table behavior, shared
        // with cognitive.rs) + for_expression(1) + while_expression(1)
        // + &&(1) + ||(1). Total = 12. Pre-fix this measured 4 (if/match/
        // loop expression kinds and infix &&/|| were all uncounted).
        //
        // Cognitive-parity note: NOT asserted here — cognitive.rs's own
        // cyclomatic table lacks the scala/ocaml `infix_expression` arm
        // (its column reports 10 for this fixture). Closing that gap in
        // cognitive.rs is a deliberate follow-up outside this issue's
        // file scope.
        let source = r#"
object D {
  def decisionStamp(a: Int, b: Int): Int = {
    if (a > 0) 1
    else if (b > 0) 2
    a match {
      case 1 => 3
      case 2 => 4
      case _ => 0
    }
    var i = 0
    for (j <- 0 to 2) {
      i += j
    }
    while (i < 3) {
      i += 1
    }
    val x = a > 0 && b > 0
    if (a > 0 || b > 0) 5 else 6
  }
}
"#;
        let metrics = calculate_complexity(source, "decisionStamp", Language::Scala).unwrap();
        assert_eq!(
            metrics.cyclomatic, 12,
            "scala: if/match/for/while expressions and infix &&/|| must count"
        );
    }
}
