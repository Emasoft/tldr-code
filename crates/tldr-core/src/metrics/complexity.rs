//! Complexity metrics calculation
//!
//! Implements cyclomatic and cognitive complexity as per spec Section 2.3.2.
//!
//! # Cyclomatic Complexity
//! - V(G) = E - N + 2 (edges - nodes + 2)
//! - Counts decision points: if, elif, for, while, case, catch, &&, ||, ?:
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
// cl4-cyclomatic-v1 (GH #75): reuse the catchall-arm detectors from the
// canonical cognitive calculator so cyclomatic and cognitive agree on which
// match/when arms are decision points (single source of truth).
use crate::metrics::cognitive::{is_kotlin_else_when_entry, is_ocaml_wildcard_match_case};
use crate::error::TldrError;
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
        // cfg-ruby-rebuild-v1 (v0.4.2 M-102): tree-sitter-ruby emits bare
        // kinds (`if`, `while`, `until`, `for`, `case`, `begin`, `unless`)
        // for Ruby control-flow constructs. These cognates would falsely
        // match identifier / keyword tokens in other grammars (e.g. Python
        // uses `if_statement`, never bare `if`), so they are gated on
        // Language::Ruby.
        if matches!(self.language, Language::Ruby)
            && matches!(
                kind,
                "if" | "unless"
                    | "while"
                    | "until"
                    | "for"
                    | "case"
                    | "begin"
                    | "rescue"
                    | "if_modifier"
                    | "unless_modifier"
                    | "while_modifier"
                    | "until_modifier"
                    | "do_block"
            )
        {
            return true;
        }

        // solidity-metrics-v1 (v0.5.0 SOL-008): Solidity exposes do-while
        // as `do_while_statement` (same kind as Kotlin). Treat it as a
        // nesting structure so the body gets a nesting penalty in cognitive
        // (the cognitive walker re-uses this kind via its own
        // `increases_nesting`). Gating on Solidity avoids touching grammars
        // where the same kind name might collide.
        if matches!(self.language, Language::Solidity) && kind == "do_while_statement" {
            return true;
        }

        matches!(
            kind,
            "if_statement"
                | "elif_clause"
                | "else_clause"
                | "for_statement"
                | "for_in_statement"
                // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101) Java for-each.
                | "enhanced_for_statement"
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
    /// - for, while loops
    /// - case/match branches
    /// - catch/except handlers
    /// - && and || operators
    /// - ?: ternary operator
    fn count_cyclomatic_increment(&mut self, node: Node) {
        let kind = node.kind();

        // cfg-ruby-rebuild-v1 (v0.4.2 M-102): tree-sitter-ruby emits BARE
        // kinds for control-flow constructs (`if`, `elsif`, `while`, `until`,
        // `for`, `case`, `when`, `rescue`, `unless`, plus modifier forms).
        // These cognates collide with bare keyword tokens / identifier
        // text in other grammars, so they are gated on Language::Ruby.
        // Without this, every Ruby method came out as cyclomatic=1, which
        // cascaded into broken output for `complexity`, `slice`, `available`,
        // `reaching-defs`, `dead-stores`, `taint`, `chop`, `context`,
        // `health`, `hotspots`, `debt`.
        if matches!(self.language, Language::Ruby) {
            match kind {
                "if" | "elsif" | "unless" => {
                    self.cyclomatic += 1;
                }
                "while" | "until" | "for" => {
                    self.cyclomatic += 1;
                }
                "when" => {
                    // Each `when` arm is a decision point in a `case` switch.
                    self.cyclomatic += 1;
                }
                "rescue" => {
                    // Each `rescue` clause is a decision point in `begin/rescue`.
                    self.cyclomatic += 1;
                }
                "call" => {
                    // `loop do ... end` is parsed as a `call` to `Kernel#loop`
                    // with an attached `do_block`. Recognise this iteration
                    // construct as a decision point.
                    if is_ruby_loop_call(node, self.source) {
                        self.cyclomatic += 1;
                    }
                }
                _ => {}
            }
        }

        // Modifier forms (`x if cond`, `y unless cond`, `expr while cond`,
        // `expr until cond`) — these node kinds are Ruby-specific in
        // tree-sitter-ruby but the names don't collide with other grammars
        // so they can match unconditionally.
        match kind {
            "if_modifier" | "unless_modifier" => {
                self.cyclomatic += 1;
            }
            "while_modifier" | "until_modifier" => {
                self.cyclomatic += 1;
            }
            _ => {}
        }

        // Primary decision points
        match kind {
            "if_statement" | "elif_clause" => {
                self.cyclomatic += 1;
            }
            "for_statement" | "for_in_statement" | "while_statement" => {
                self.cyclomatic += 1;
            }
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101): Java's
            // `for (T x : xs) { ... }` parses as `enhanced_for_statement`,
            // a distinct kind from the classical 3-part `for_statement`.
            // Iter-2 audit `java.md` "Layer probe: CFG" showed sumEven
            // reporting cyclomatic=2 (instead of >=3 for entry+for+if).
            "enhanced_for_statement" => {
                self.cyclomatic += 1;
            }
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101): Scala,
            // Rust, OCaml and Kotlin all expose loop constructs as
            // `*_expression` rather than `*_statement`. Iter-2 audit
            // `scala.md` cell c09 showed `Loops.sum` (a plain
            // while-loop) reporting cyclomatic=1 — the back-edge is
            // emitted by the CFG but never credited in cyclomatic.
            // Mirror the cognitive.rs pattern (see
            // `cognitive::count_cyclomatic_increment` line 1163) — gate
            // on the expression-oriented languages so we don't
            // double-count token leaves in C-shaped grammars.
            "for_expression" | "while_expression" | "loop_expression"
                if matches!(
                    self.language,
                    Language::Scala | Language::Rust | Language::Ocaml | Language::Kotlin
                ) =>
            {
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
            // solidity-metrics-v1 (v0.5.0 SOL-008): Solidity has both
            // `do_while_statement` (like Kotlin) and the standard
            // `if_statement` / `for_statement` / `while_statement` /
            // `try_statement` / `catch_clause` which are already
            // credited by the generic arms above. Credit do_while here.
            "do_while_statement" if matches!(self.language, Language::Solidity) => {
                self.cyclomatic += 1;
            }

            // ---------------------------------------------------------------
            // cl4-cyclomatic-v1 (GH #75, #76): per-language decision-node
            // arms that the canonical cognitive calculator already credits
            // (see `cognitive::CognitiveCalculator::count_cyclomatic_increment`,
            // the proven-correct reference). The expression-oriented grammars
            // (Kotlin / Scala / OCaml) expose `if`/`when`/`match` as
            // `*_expression` rather than `*_statement`, so none of the generic
            // `_statement`/`_clause` arms above ever fired — branchy functions
            // collapsed to `cyclomatic = 1`. C# exposes its switch as
            // `switch_section` arms under a `switch_body` (and its for-each as
            // `foreach_statement`), neither of which had any arm here.
            // ---------------------------------------------------------------

            // Kotlin / Scala / OCaml: `if` is an expression.
            "if_expression"
                if matches!(
                    self.language,
                    Language::Kotlin | Language::Scala | Language::Ocaml
                ) =>
            {
                self.cyclomatic += 1;
            }
            // Kotlin `when (...)` dispatch: the construct itself is a decision
            // point, and each non-`else` `when_entry` adds another arm.
            "when_expression" if matches!(self.language, Language::Kotlin) => {
                self.cyclomatic += 1;
            }
            "when_entry"
                if matches!(self.language, Language::Kotlin)
                    && !is_kotlin_else_when_entry(node) =>
            {
                self.cyclomatic += 1;
            }
            // Scala / OCaml `match` dispatch. The Scala `case_clause` and
            // OCaml `match_case` arms are credited below (Scala via the
            // unconditional `case_clause` arm above; OCaml via `match_case`
            // here) — this credits the dispatch construct itself.
            "match_expression"
                if matches!(self.language, Language::Scala | Language::Ocaml) =>
            {
                self.cyclomatic += 1;
            }
            // NOTE: OCaml's `function | ...` form (node `function_expression`)
            // is deliberately NOT credited as a dispatch construct here, to
            // stay byte-for-byte in step with the canonical cognitive
            // cyclomatic (see `cognitive::count_cyclomatic_increment`, which
            // credits `match_expression` but not `function_expression`). Each
            // `function | pat -> ...` arm is still counted via the `match_case`
            // arm below, so the McCabe decision count is exact. Crediting the
            // construct too would double-count by one relative to the
            // `tldr cognitive --include-cyclomatic` reference and reintroduce
            // the cross-command drift BUG-7 closed.
            // OCaml `match_case` arms (each non-wildcard `| pat -> ...`).
            "match_case"
                if matches!(self.language, Language::Ocaml)
                    && !is_ocaml_wildcard_match_case(node, self.source) =>
            {
                self.cyclomatic += 1;
            }
            // C# `switch (...) { case ...: ... }`. Each non-`default`
            // `switch_section` is a decision arm. The `default` section is the
            // catchall and is NOT credited (mirrors the C/C++ `default`
            // convention and the cognitive catchall helpers).
            "switch_section"
                if matches!(self.language, Language::CSharp)
                    && !is_csharp_default_switch_section(node) =>
            {
                self.cyclomatic += 1;
            }
            // C# `foreach (T x in xs) { ... }` is a loop / back-edge. The
            // classical 3-part `for_statement` and `while_statement` are
            // already credited by the generic arms above; the for-each form
            // is a distinct node kind that had no arm.
            "foreach_statement" if matches!(self.language, Language::CSharp) => {
                self.cyclomatic += 1;
            }
            _ => {}
        }

        // Logical operators in conditions
        if kind == "boolean_operator" || kind == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(self.source.as_bytes()).unwrap_or("");
                if op_text == "and" || op_text == "or" || op_text == "&&" || op_text == "||" {
                    self.cyclomatic += 1;
                }
            }
        }

        // cl4-cyclomatic-v1 (GH #75): Scala spells short-circuit boolean
        // operators as an `infix_expression` whose `operator` field is an
        // `operator_identifier` node carrying the `&&` / `||` text — a node
        // shape the `boolean_operator`/`binary_expression` arm above never
        // matches. Without this, `if ((a ne null) && (b ne null))` and the
        // like contribute zero decision points on Scala. Gated on
        // Language::Scala so the `infix_expression` cognate (which some other
        // grammars reuse for arithmetic) can't double-count elsewhere.
        if matches!(self.language, Language::Scala) && kind == "infix_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(self.source.as_bytes()).unwrap_or("");
                if op_text == "&&" || op_text == "||" {
                    self.cyclomatic += 1;
                }
            }
        }

        // Also check for && and || as direct node kinds.
        // solidity-metrics-v1 (v0.5.0 SOL-008): tree-sitter-solidity exposes
        // each `binary_expression` operator as a CHILD node whose KIND is the
        // operator token itself (`&&` / `||`). Without gating, every Solidity
        // `&&`/`||` would be credited TWICE — once via the field-name check
        // above on `binary_expression`, and once again as the bare-token
        // node. Skip the bare-token credit for Solidity so the field-name
        // arm remains the single source of truth.
        if (kind == "&&" || kind == "||" || kind == "and" || kind == "or")
            && !matches!(self.language, Language::Solidity)
        {
            self.cyclomatic += 1;
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

/// cfg-ruby-rebuild-v1 (v0.4.2 M-102): Check whether a Ruby `call` node
/// represents `loop do ... end` (a `Kernel#loop` invocation with an
/// attached `do_block`).
///
/// The call must:
/// 1. Have method name `loop` (tree-sitter-ruby stores it under the
///    `method` field as an `identifier` node).
/// 2. Have an attached `do_block` or `block` (the iteration body).
///
/// Used by the cyclomatic decision counter to count `loop do` as a
/// decision point, and re-exported (`pub(crate)`) so the CFG builder
/// can dispatch to its dedicated Ruby loop handler.
pub(crate) fn is_ruby_loop_call(node: tree_sitter::Node, source: &str) -> bool {
    let method = match node.child_by_field_name("method") {
        Some(m) => m,
        None => return false,
    };
    if method.kind() != "identifier" {
        return false;
    }
    let method_name = method.utf8_text(source.as_bytes()).unwrap_or("");
    if method_name != "loop" {
        return false;
    }
    // Must have a block (the iteration body). `loop` without a block
    // is a no-op / forward reference, not a loop construct.
    node.child_by_field_name("block")
        .map(|b| matches!(b.kind(), "do_block" | "block"))
        .unwrap_or(false)
}

/// cl4-cyclomatic-v1 (GH #75): C# — a `switch_section` whose first child is
/// the `default` keyword is the catchall arm and is NOT a decision point
/// (mirrors the C/C++ `default` convention). A normal case section starts
/// with the `case` keyword.
///
/// Grammar shape (verified against tree-sitter-c-sharp):
/// ```text
/// switch_body
///   switch_section          ← `case <pattern>: ...`
///     case
///     constant_pattern | ...
///     :
///     <statements>
///   switch_section          ← `default: ...`
///     default
///     :
///     <statements>
/// ```
fn is_csharp_default_switch_section(node: tree_sitter::Node) -> bool {
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
}
