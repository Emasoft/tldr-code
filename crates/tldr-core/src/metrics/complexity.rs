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
use crate::metrics::cognitive::{
    is_default_case_statement, is_kotlin_else_when_entry, is_ocaml_wildcard_match_case,
    is_swift_default_switch_entry,
};
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

/// Calculate complexity metrics for ALL functions in a file, keyed by
/// `(name, line)` so same-name overloads do not collide.
///
/// See [`calculate_all_complexities_keyed_from_tree`]. Use this instead of
/// [`calculate_all_complexities_file`] when the caller has each function's
/// 1-indexed start line (`FunctionInfo::line_number`) available to disambiguate
/// overloads.
pub fn calculate_all_complexities_keyed_file(
    path: &Path,
) -> TldrResult<HashMap<(String, u32), ComplexityMetrics>> {
    let (tree, source, lang) = parse_file(path)?;
    let root = tree.root_node();
    calculate_all_complexities_keyed_from_tree(root, &source, lang)
}

/// Source-string convenience wrapper for
/// [`calculate_all_complexities_keyed_from_tree`]. Parses `source` once and
/// returns the `(name, line)`-keyed metrics map.
pub fn calculate_all_complexities_keyed(
    source: &str,
    language: Language,
) -> TldrResult<HashMap<(String, u32), ComplexityMetrics>> {
    let tree = parse(source, language)?;
    let root = tree.root_node();
    calculate_all_complexities_keyed_from_tree(root, source, language)
}

/// Calculate complexity metrics for all functions given an already-parsed tree.
///
/// Use this when you already have a parsed tree to avoid redundant parsing.
/// Walks the AST depth-first to find all function/method nodes, then runs
/// the complexity calculator on each.
///
/// The returned map is keyed by the BARE function name. When a file contains
/// multiple same-named functions (C++/C#/Swift overloads, Scala/OCaml
/// multi-clause defs) the entries collide and the last one walked wins. This
/// is preserved for backward compatibility with callers that only have a bare
/// name to look up by (`debt`, `maintainability`, `bugbot first_run`). Callers
/// that can supply the function's start line (`quality::complexity`,
/// `quality::smells`) should use [`calculate_all_complexities_keyed_from_tree`]
/// instead, which assigns each overload a distinct entry.
pub fn calculate_all_complexities_from_tree(
    root: Node,
    source: &str,
    language: Language,
) -> TldrResult<HashMap<String, ComplexityMetrics>> {
    // Fold the distinctly-keyed map down to bare-name keys. Iteration order of
    // a HashMap is unspecified, so to keep the historical "last function walked
    // wins" semantics deterministic we re-insert in ascending start-line order
    // (the DFS visited shallow-to-deep / top-to-bottom, so the largest line is
    // the one the old code inserted last for same-name collisions).
    let keyed = calculate_all_complexities_keyed_from_tree(root, source, language)?;
    let mut ordered: Vec<((String, u32), ComplexityMetrics)> = keyed.into_iter().collect();
    ordered.sort_by(|a, b| a.0 .1.cmp(&b.0 .1));
    let mut results = HashMap::new();
    for ((name, _line), metrics) in ordered {
        results.insert(name, metrics);
    }
    Ok(results)
}

/// Calculate complexity metrics for all functions, keyed by `(name, line)`.
///
/// Identical AST walk to [`calculate_all_complexities_from_tree`] but keys each
/// entry by `(bare_name, decl_keyword_line)` so same-name overloads do NOT
/// collide. `decl_keyword_line` is computed with the exact same normalisation
/// (`decl_keyword_line_from_node`) that the extractor uses for
/// `FunctionInfo::line_number` / `MethodInfo::line_number`, so a consumer can
/// look up an entry by `(method.name, method.line_number)` and get THAT
/// instance's metrics rather than whichever overload happened to be inserted
/// last (cluster 9 / cluster 11 root cause).
pub fn calculate_all_complexities_keyed_from_tree(
    root: Node,
    source: &str,
    language: Language,
) -> TldrResult<HashMap<(String, u32), ComplexityMetrics>> {
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
                    // fix-R2-themeA: key by (name, decl-keyword line) so that
                    // same-name overloads get distinct entries. The line MUST
                    // match the extractor's `line_number` (which routes
                    // annotation/modifier-decorated decls through
                    // `decl_keyword_line_from_node`) so consumer lookups by
                    // `(name, func.line_number)` hit the right instance.
                    let line = crate::ast::extract::decl_keyword_line_from_node(&node);
                    results.insert((name, line), metrics);
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

        // C1 GAP-1 (v0.5.0 AUDIT-FIX): an Elixir clause-head `when` guard is a
        // decision point, but it lives in the `def NAME(...) when <guard>`
        // HEAD — outside the `do_block` body that `analyze_node` walks below.
        // Credit it here from the function node so a guarded clause (even one
        // with a straight-line body) reflects the guard branch. Multi-clause
        // dispatch itself is modelled by the CLI's per-clause iteration, which
        // analyses each clause's body in isolation; this only credits the
        // guard attached to the clause head being analysed.
        if matches!(self.language, Language::Elixir)
            && elixir_head_has_when_guard(func_node, self.source)
        {
            self.cyclomatic += 1;
        }

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
        // R7 RC3 (v0.5.0 CLOSEOUT): tree-sitter-ruby emits a NAMED construct
        // node (kind `if`/`elsif`/`unless`/`when`/`while`/`until`/`for`/
        // `rescue`) that CONTAINS an UNNAMED keyword-token child of the SAME
        // kind. The recursive walker visits unnamed children, so without an
        // `is_named()` guard each construct matched TWICE (once for the named
        // construct, once for its bare keyword leaf) — every Ruby decision
        // point was double-counted (interpret_unicode 1+2=3, a 3-`when` case
        // 1+6=7). Verified via dumper that the construct is is_named()=true and
        // the keyword leaf is is_named()=false; the `call` form (`loop do`) is
        // also a named node. Gating on is_named() credits each construct once.
        if matches!(self.language, Language::Ruby) && node.is_named() {
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
            // R7 RC1 (v0.5.0 CLOSEOUT): C / C++ spell each `switch` case as a
            // named `case_statement` node (the classic `case_clause`/
            // `switch_case` arm above never matches C/C++). Each non-`default`
            // case is a decision arm; the `default` arm is the catchall and is
            // NOT a decision point. This mirrors, node-for-node, the canonical
            // cognitive counter (cognitive.rs `count_cyclomatic_increment`,
            // which already credits `case_statement`), so `tldr complexity`
            // and `tldr cognitive --include-cyclomatic` agree, and matches the
            // CFG's per-case branch convention. Fallthrough labels
            // (`case 'a': case 'A':`) each parse as their own `case_statement`
            // node and each count, per McCabe. hex_digit_to_int: 22 labels ->
            // 23; was 1.
            "case_statement"
                if matches!(self.language, Language::C | Language::Cpp)
                    && !is_default_case_statement(node) =>
            {
                self.cyclomatic += 1;
            }
            // R7 RC1 (v0.5.0 CLOSEOUT): Swift spells each `switch` arm as a
            // named `switch_entry`. A normal arm's first child is the `case`
            // keyword; the catchall arm's first child is a `default_keyword`
            // node and is NOT a decision point. A multi-pattern arm
            // (`case 2, 3:`) is a SINGLE `switch_entry` -> one decision point
            // (the switch is a single multi-way branch on those patterns),
            // consistent with the C `case_statement` treatment of distinct
            // exclusive arms. append (4 arms) -> 5; was 1.
            "switch_entry"
                if matches!(self.language, Language::Swift)
                    && !is_swift_default_switch_entry(node) =>
            {
                self.cyclomatic += 1;
            }
            // R7 RC1 (v0.5.0 CLOSEOUT): Swift `guard <cond> else { ... }` is a
            // binary decision (the else branch is taken iff the condition
            // fails), so it is a decision point exactly like an `if`. Node kind
            // `guard_statement`, verified via dumper. popMax (guard + 2 ifs)
            // -> 4; was 3 (guard contributed 0).
            "guard_statement" if matches!(self.language, Language::Swift) => {
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

            // Kotlin / Scala / OCaml / Rust: `if` is an expression.
            //
            // RC5 (v0.5.0 RC-CAMPAIGN): in tree-sitter-rust `if`, `if let` and
            // the chained `else if` all parse as `if_expression` (never the
            // C-shaped `if_statement`), so the generic `_statement` arms never
            // fired and every branchy Rust function collapsed to cyclomatic = 1.
            // The canonical cognitive cyclomatic counter
            // (`cognitive::count_cyclomatic_increment`) credits `if_expression`
            // ungated, so `tldr complexity` disagreed with
            // `tldr cognitive --include-cyclomatic` and with the CFG's own
            // E-N+2P decision count. Adding `Language::Rust` brings the McCabe
            // count back in step (rust-clap / rust-ripgrep were 1 vs cognitive
            // 4 / 9). The trailing bare `else` is an `else_clause` (not an
            // `if_expression`) and is correctly NOT counted.
            "if_expression"
                if matches!(
                    self.language,
                    Language::Kotlin | Language::Scala | Language::Ocaml | Language::Rust
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

            // ---------------------------------------------------------------
            // C1 GAP-1 (v0.5.0 AUDIT-FIX): Elixir decision points. Before this
            // arm `tldr complexity` reported a near-constant cyclomatic=1 for
            // every Elixir function regardless of branching, because
            // tree-sitter-elixir spells case/cond/with/if/unless as `call`
            // nodes (target=identifier) and their arms as `stab_clause`
            // children of a `do_block` — none of the generic `*_statement` /
            // `*_clause` / `*_expression` arms above ever matched. The
            // canonical cognitive cyclomatic counter
            // (`cognitive::count_cyclomatic_increment`) already credits the
            // same non-catchall `stab_clause` arms, so `tldr complexity` and
            // `tldr cognitive --include-cyclomatic` had drifted; this arm
            // closes that drift and additionally credits the `if`/`unless`
            // constructs (which carry no `stab_clause`). The `when` guard on a
            // clause head is credited separately in `analyze_function` (the
            // head is not part of the walked body). Node shapes verified by
            // debug-parse against tree-sitter-elixir.
            // ---------------------------------------------------------------

            // Each non-catchall `case`/`cond`/`with`-else arm is a decision
            // point. Catchall arms (`_ ->`, `cond`'s `true ->`) are excluded so
            // the McCabe count matches the canonical cognitive counter exactly.
            "stab_clause"
                if matches!(self.language, Language::Elixir)
                    && !is_elixir_catchall_stab_clause(node, self.source) =>
            {
                self.cyclomatic += 1;
            }
            // Elixir `if`/`unless` are `call` nodes (`target` identifier
            // `if`/`unless`), not `if_statement`. They carry no `stab_clause`,
            // so they must be credited as decision points here.
            "call"
                if matches!(self.language, Language::Elixir)
                    && is_elixir_if_unless_call(node, self.source) =>
            {
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

        // R7 RC2 (v0.5.0 CLOSEOUT): the redundant bare-token `&&`/`||`/`and`/
        // `or` arm that used to live here has been REMOVED. In every supported
        // grammar a short-circuit boolean operator is reachable via
        // `child_by_field_name("operator")` on the enclosing
        // `boolean_operator` (Python) / `binary_expression` (C/C++/Java/JS/TS/
        // Go/Rust/PHP/C#/Solidity) / `infix_expression` (Scala, handled in its
        // dedicated arm above), so the field-name arm at the top of this block
        // is the single source of truth. The operator ALSO appears as a bare
        // child node whose KIND is the operator token itself (`&&`/`||`), which
        // the recursive walker visits — so the old bare-token arm credited the
        // SAME operator a second time, doubling the count for every C-family
        // language (is_hex_digit: 1+2*5=11 instead of 6). The campaign's
        // SOL-008 fix had already excluded Solidity from the bare-token arm for
        // exactly this reason; removing the arm generalises that fix to all
        // grammars. Verified via a tree-sitter dumper (pinned to the workspace
        // grammar versions) that C/C++/Java/JS/TS/Go/Rust/Python/PHP/C# all
        // expose the operator on the `operator` field; Scala uses
        // `operator_identifier` (its own arm) and is unaffected.
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

/// C1 GAP-1 (v0.5.0 AUDIT-FIX): Elixir — a `stab_clause` whose `arguments`
/// child is a single identifier `_` (or the boolean `true`, the conventional
/// `cond` catchall) is the catchall arm and is NOT a decision point.
///
/// This replicates, node-for-node, the catchall detector that backs the
/// canonical cognitive cyclomatic counter (`cognitive.rs`) so the two
/// commands credit exactly the same arms. Grammar shape (verified by
/// debug-parse against tree-sitter-elixir):
/// ```text
/// stab_clause
///   [left] arguments { <pattern> }
///   [operator] ->
///   [right] body { ... }
/// ```
fn is_elixir_catchall_stab_clause(node: tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if child.kind() == "arguments" {
            // A single `identifier` child with text `_` is the catchall.
            let mut acursor = child.walk();
            if acursor.goto_first_child() {
                let inner = acursor.node();
                let text = inner.utf8_text(source.as_bytes()).unwrap_or("");
                if inner.kind() == "identifier" && text == "_" {
                    return true;
                }
                if inner.kind() == "boolean" && text == "true" {
                    // `cond` catchall is conventionally `true ->`.
                    return true;
                }
            }
            return false;
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
    false
}

/// C1 GAP-1 (v0.5.0 AUDIT-FIX): Elixir — detect whether a `call` node is an
/// `if`/`unless` construct. tree-sitter-elixir models `if cond do ... end`
/// (and `unless`) as a `call` whose first child is an `identifier` token
/// carrying the keyword (verified by debug-parse):
/// ```text
/// call
///   [target] identifier 'if'
///   arguments { <cond> }
///   do_block { ... }
/// ```
/// `case`/`cond`/`with` are intentionally NOT matched here — their arms are
/// counted via the `stab_clause` arm, mirroring the canonical cognitive
/// counter (crediting the dispatch construct too would double-count).
fn is_elixir_if_unless_call(node: tree_sitter::Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    let head = cursor.node();
    if head.kind() != "identifier" {
        return false;
    }
    matches!(
        head.utf8_text(source.as_bytes()).unwrap_or(""),
        "if" | "unless"
    )
}

/// C1 GAP-1 (v0.5.0 AUDIT-FIX): Elixir — detect a `when` guard on a clause
/// head. The `def NAME(args) when <guard>` form parses as a `binary_operator`
/// whose `operator` field is the `when` token, sitting inside the `def` call's
/// `arguments` (verified by debug-parse):
/// ```text
/// call                         ← the `def`/`defp`
///   [target] identifier 'def'
///   arguments
///     binary_operator          ← `classify(n) when n > 0`
///       [left] call            ← the clause signature
///       [operator] when 'when'
///       [right] <guard expr>
/// ```
/// The guard lives in the clause HEAD, not the `do_block` body the complexity
/// walker descends into, so it must be detected directly from the function
/// node. Scans descendants (bounded) for a `binary_operator` with a `when`
/// operator child.
fn elixir_head_has_when_guard(func_node: tree_sitter::Node, source: &str) -> bool {
    // The guard, if present, is in the `arguments` child of the `def` call.
    // Walk the immediate children to find `arguments`, then look for a
    // `binary_operator` whose `operator` field is `when`.
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() != "arguments" {
            continue;
        }
        let mut arg_cursor = child.walk();
        for arg in child.children(&mut arg_cursor) {
            if arg.kind() == "binary_operator" {
                if let Some(op) = arg.child_by_field_name("operator") {
                    if op.kind() == "when"
                        || op.utf8_text(source.as_bytes()).unwrap_or("") == "when"
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
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

    // =========================================================================
    // fix-R2-themeA: same-name overload collision in the batch metrics map.
    //
    // metrics::complexity built a HashMap<String, _> keyed by BARE name, so a
    // file with several same-named functions (C++/C#/Swift overloads,
    // Scala/OCaml multi-clause defs) collapsed to a single entry — every
    // same-named function then read the LAST one's metric. Reproduces:
    //   - cluster 11 RC10: swift cURLDescription (trivial forwarder reported
    //     with the complex overload's cyclomatic)
    //   - cluster 9 #4: csharp CalculateSize / ocaml `equal` (a 1-4 line
    //     overload reported with the long overload's lines_of_code)
    // The keyed map must give EACH overload its own (name, line) entry.
    // =========================================================================

    #[test]
    fn test_keyed_overloads_get_distinct_cyclomatic() {
        // Two C++ `area` overloads in ONE translation unit:
        //   - area(int)   : straight line  -> cyclomatic 1
        //   - area(int,int): 3 decision pts -> cyclomatic 4
        // Bare-name keying loses one of them; (name,line) keying keeps both
        // with their OWN cyclomatic.
        let source = r#"
int area(int s) {
    return s * s;
}

int area(int w, int h) {
    if (w < 0) return 0;
    if (h < 0) return 0;
    if (w == h) return w * w;
    return w * h;
}
"#;
        let keyed = calculate_all_complexities_keyed(source, Language::Cpp).unwrap();

        // Both physical overloads survive as distinct entries.
        let mut areas: Vec<(u32, u32)> = keyed
            .iter()
            .filter(|((name, _line), _m)| name == "area")
            .map(|((_name, line), m)| (*line, m.cyclomatic))
            .collect();
        areas.sort();
        assert_eq!(
            areas.len(),
            2,
            "both `area` overloads must survive distinctly, got {:?}",
            areas
        );
        // First overload (lower line) is straight-line; second is branchy.
        assert_eq!(areas[0].1, 1, "area(int) is straight-line cyclomatic 1");
        assert_eq!(
            areas[1].1, 4,
            "area(int,int) has 3 decision points -> cyclomatic 4"
        );
        // The bug was that BOTH read the same (last) value; assert they differ.
        assert_ne!(
            areas[0].1, areas[1].1,
            "overloads must NOT share the collided last-wins cyclomatic"
        );
    }

    #[test]
    fn test_keyed_overloads_get_distinct_loc() {
        // Two `compute` overloads with very different lengths. The short one
        // must NOT inherit the long one's lines_of_code (cluster 9 #4 shape).
        let source = r#"
int compute(int x) { return x; }

int compute(int a, int b) {
    int t = 0;
    t += a;
    t += b;
    t += a * b;
    t += a - b;
    return t;
}
"#;
        let keyed = calculate_all_complexities_keyed(source, Language::Cpp).unwrap();
        let mut locs: Vec<(u32, u32)> = keyed
            .iter()
            .filter(|((name, _line), _m)| name == "compute")
            .map(|((_name, line), m)| (*line, m.lines_of_code))
            .collect();
        locs.sort();
        assert_eq!(locs.len(), 2, "both `compute` overloads survive, got {:?}", locs);
        // The 1-line overload keeps ~1 LOC; the long one is clearly larger.
        assert_eq!(locs[0].1, 1, "single-line overload stays 1 LOC, got {:?}", locs);
        assert!(
            locs[1].1 >= 7,
            "multi-line overload keeps its own larger LOC, got {:?}",
            locs
        );
        assert_ne!(
            locs[0].1, locs[1].1,
            "short overload must NOT inherit the long overload's LOC"
        );
    }

    #[test]
    fn test_keyed_line_matches_extractor_line_number() {
        // The (name,line) key MUST agree with the extractor's `line_number`
        // (which is what consumers look up by). Verify the keyed map's lines
        // line up with extract_file's reported function lines for overloads.
        use crate::ast::extract_file;
        use std::io::Write;
        let dir = std::env::temp_dir().join("tldr_keyed_line_test");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("overload.cpp");
        let mut f = std::fs::File::create(&file_path).unwrap();
        write!(
            f,
            "int area(int s) {{ return s * s; }}\n\nint area(int w, int h) {{\n    if (w < 0) return 0;\n    return w * h;\n}}\n"
        )
        .unwrap();

        let keyed = calculate_all_complexities_keyed_file(&file_path).unwrap();
        let module = extract_file(&file_path, None).unwrap();

        // Every `area` FunctionInfo line must be present as a key in the map.
        let area_fns: Vec<u32> = module
            .functions
            .iter()
            .filter(|fi| fi.name == "area")
            .map(|fi| fi.line_number)
            .collect();
        assert!(
            area_fns.len() >= 2,
            "extractor should see both overloads, got {:?}",
            area_fns
        );
        for line in &area_fns {
            assert!(
                keyed.contains_key(&("area".to_string(), *line)),
                "keyed map missing (area, {}); keys present: {:?}",
                line,
                keyed.keys().collect::<Vec<_>>()
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_keyed_fold_preserves_unique_name_behavior() {
        // For unique-name files the keyed map and the legacy bare-name map must
        // carry identical metrics — guard against the re-key changing the
        // common (non-overload) case.
        let source = r#"
def alpha():
    return 1

def beta(x):
    if x > 0:
        return 1
    return 0
"#;
        let bare = calculate_all_complexities(source, Language::Python).unwrap();
        let keyed = calculate_all_complexities_keyed(source, Language::Python).unwrap();
        assert_eq!(bare.len(), keyed.len(), "no collisions => same cardinality");
        for ((name, _line), km) in &keyed {
            let bm = bare.get(name).expect("bare map has the same names");
            assert_eq!(bm.cyclomatic, km.cyclomatic, "cyclomatic parity for {}", name);
            assert_eq!(bm.lines_of_code, km.lines_of_code, "LOC parity for {}", name);
            assert_eq!(bm.cognitive, km.cognitive, "cognitive parity for {}", name);
        }
    }

    // =========================================================================
    // C1 GAP-1 (v0.5.0 AUDIT-FIX): Elixir cyclomatic decision-point counting.
    //
    // tree-sitter-elixir spells `case`/`cond`/`with`/`if`/`unless` as `call`
    // nodes (target `identifier`), NOT the `*_statement`/`*_expression`
    // cognates the generic arms in `count_cyclomatic_increment` match. The
    // dispatch arms live in a `do_block` as `stab_clause` children. Before
    // this fix `tldr complexity` reported a near-constant cyclomatic=1 for
    // every Elixir function regardless of branching, while the canonical
    // `tldr cognitive --include-cyclomatic` (cognitive.rs) already credited
    // the same `stab_clause` arms — a cross-command drift. These tests pin
    // the corrected counting on the SAME `calculate_complexity` walker that
    // backs `tldr complexity` (and, via delegation, `tldr explain`).
    // =========================================================================

    #[test]
    fn test_elixir_case_cyclomatic_gt_one() {
        // A `case` with two non-catchall arms (`1`, `2`) + a `_` catchall.
        // Each non-catchall `stab_clause` is a decision point ⇒ cyclomatic
        // must be > 1 (base 1 + 2 arms = 3). Pre-fix this was a flat 1.
        let source = r#"
defmodule M do
  def classify(x) do
    case x do
      1 -> :one
      2 -> :two
      _ -> :other
    end
  end
end
"#;
        let metrics = calculate_complexity(source, "classify", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `case` with branching must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
        // Exact McCabe count: base + 2 non-catchall arms (catchall `_` excluded).
        assert_eq!(
            metrics.cyclomatic, 3,
            "Elixir `case` [1, 2, _]: base 1 + 2 non-catchall arms = 3, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_cond_cyclomatic_gt_one() {
        // A `cond` with two real guards + the conventional `true ->` catchall.
        let source = r#"
defmodule M do
  def pick(x) do
    cond do
      x < 0 -> :neg
      x == 0 -> :zero
      true -> :pos
    end
  end
end
"#;
        let metrics = calculate_complexity(source, "pick", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `cond` with branching must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
        // base + 2 non-catchall clauses (`true ->` is the catchall, excluded).
        assert_eq!(
            metrics.cyclomatic, 3,
            "Elixir `cond` [x<0, x==0, true]: base 1 + 2 non-catchall = 3, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_with_else_cyclomatic_gt_one() {
        // `with` else-arms are also `stab_clause` children (of an `else_block`).
        let source = r#"
defmodule M do
  def run(x) do
    with {:ok, a} <- fetch(x),
         {:ok, b} <- fetch(a) do
      {:ok, b}
    else
      :error -> :failed
      other -> {:unexpected, other}
    end
  end
end
"#;
        let metrics = calculate_complexity(source, "run", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `with` else-arms must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_if_cyclomatic_gt_one() {
        // Elixir `if` is a `call` node (no `if_statement`/`stab_clause`); the
        // generic arms never matched it, so it must be credited explicitly.
        let source = r#"
defmodule M do
  def check(x) do
    if x > 10 do
      :big
    else
      :small
    end
  end
end
"#;
        let metrics = calculate_complexity(source, "check", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `if` must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_unless_cyclomatic_gt_one() {
        let source = r#"
defmodule M do
  def maybe(x) do
    unless x == 0 do
      :nonzero
    end
  end
end
"#;
        let metrics = calculate_complexity(source, "maybe", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `unless` must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_when_guard_cyclomatic_gt_one() {
        // A guarded single-clause function head: the `when` guard is a
        // decision point even though the body has no branches. The guard
        // lives in the `def` head (the function node), not the `do_block`.
        let source = r#"
defmodule M do
  def positive(x) when x > 0 do
    x * 2
  end
end
"#;
        let metrics = calculate_complexity(source, "positive", Language::Elixir).unwrap();
        assert!(
            metrics.cyclomatic > 1,
            "Elixir `when` guard must yield cyclomatic > 1, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_elixir_no_branch_stays_one() {
        // Guard against over-counting: a straight-line Elixir function with
        // no branching must stay at cyclomatic = 1.
        let source = r#"
defmodule M do
  def linear(x) do
    y = x + 1
    z = y * 2
    z
  end
end
"#;
        let metrics = calculate_complexity(source, "linear", Language::Elixir).unwrap();
        assert_eq!(
            metrics.cyclomatic, 1,
            "Straight-line Elixir function must stay cyclomatic = 1, got {}",
            metrics.cyclomatic
        );
    }

    // =====================================================================
    // R7 complexity-metrics (v0.5.0 CLOSEOUT) characterization tests.
    //
    // RC1: cyclomatic must count C/C++ `switch` cases and Swift
    //      `switch`/`guard` as decision points (was ignored -> undercount).
    // RC2: cyclomatic must NOT double-count `&&`/`||` in C-family grammars
    //      (the operator was credited via both the operator-field arm and the
    //      bare-token arm).
    // RC3: cyclomatic must not double-match Ruby bare-keyword construct nodes
    //      against their own unnamed keyword-token children.
    //
    // Node kinds verified via tree-sitter dumper pinned to the workspace
    // grammar versions (tree-sitter-c/cpp 0.23.4, ruby 0.23.1, swift 0.7.1).
    // Expected values are the McCabe decision counts, kept consistent with the
    // canonical cognitive case/arm treatment and the CFG decision-point count.
    // =====================================================================

    // -- RC1: C/C++ switch ------------------------------------------------

    #[test]
    fn test_c_switch_counts_each_case() {
        // 5 non-default cases + a default -> base 1 + 5 = 6. The default arm
        // is the catchall and is NOT a decision point.
        let source = r#"
int classify(int x) {
    switch (x) {
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    case 4: return 4;
    case 5: return 5;
    default: return 0;
    }
}
"#;
        let metrics = calculate_complexity(source, "classify", Language::C).unwrap();
        assert_eq!(
            metrics.cyclomatic, 6,
            "C switch: base 1 + 5 non-default cases = 6, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_c_switch_empty_fallthrough_labels_each_count() {
        // McCabe / cognitive convention: each `case` label is its own
        // `case_statement` node, including empty fallthrough labels.
        // 3 non-default labels (`'a'`, `'A'`, `'b'`) -> base 1 + 3 = 4.
        let source = r#"
int f(char c) {
    switch (c) {
    case 'a': case 'A': return 10;
    case 'b': return 11;
    default: return 0;
    }
}
"#;
        let metrics = calculate_complexity(source, "f", Language::C).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "C fallthrough labels each count: base 1 + 3 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_cpp_switch_counts_each_case() {
        // if + for + 3 non-default cases -> base 1 + 1 + 1 + 3 = 6.
        let source = r#"
int convert(int n) {
    if (n < 0) return -1;
    for (int i = 0; i < n; ++i) {
        switch (i) {
        case 0: return 0;
        case 1: return 1;
        case 2: return 2;
        default: return 9;
        }
    }
    return 0;
}
"#;
        let metrics = calculate_complexity(source, "convert", Language::Cpp).unwrap();
        assert_eq!(
            metrics.cyclomatic, 6,
            "C++ if+for+3 cases: base 1 +1 +1 +3 = 6, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_c_switch_only_default_stays_one() {
        // A switch with only a `default` arm has no decision point.
        let source = r#"
int f(int x) {
    switch (x) {
    default: return 0;
    }
}
"#;
        let metrics = calculate_complexity(source, "f", Language::C).unwrap();
        assert_eq!(
            metrics.cyclomatic, 1,
            "C switch with only default = base 1, got {}",
            metrics.cyclomatic
        );
    }

    // -- RC1: Swift switch + guard ---------------------------------------

    #[test]
    fn test_swift_switch_counts_each_entry() {
        // 4 switch arms, no default -> base 1 + 4 = 5.
        let source = r#"
func append(a: Bool, b: Bool) -> Int {
    switch (a, b) {
    case (true, true): return 1
    case (true, false): return 2
    case (false, true): return 3
    case (false, false): return 4
    }
}
"#;
        let metrics = calculate_complexity(source, "append", Language::Swift).unwrap();
        assert_eq!(
            metrics.cyclomatic, 5,
            "Swift 4-arm switch: base 1 + 4 = 5, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_swift_switch_default_not_counted() {
        // 2 real arms + default -> base 1 + 2 = 3.
        let source = r#"
func f(x: Int) -> Int {
    switch x {
    case 1: return 1
    case 2: return 2
    default: return 0
    }
}
"#;
        let metrics = calculate_complexity(source, "f", Language::Swift).unwrap();
        assert_eq!(
            metrics.cyclomatic, 3,
            "Swift 2-arm+default switch: base 1 + 2 = 3, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_swift_guard_counts() {
        // guard + 2 ifs -> base 1 + 1 + 2 = 4. (else adds nothing.)
        let source = r#"
func popMax(c: Int, v: Int) -> Int {
    guard c > 2 else { return 0 }
    if c == 2 {
        if v > 0 {
            return 30
        }
    } else {
        return 3
    }
    return c
}
"#;
        let metrics = calculate_complexity(source, "popMax", Language::Swift).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Swift guard + 2 ifs: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    // -- RC2: C-family &&/|| single-count --------------------------------

    #[test]
    fn test_c_logical_operators_not_double_counted() {
        // 3 `&&` + 2 `||` = 5 boolean ops -> base 1 + 5 = 6 (NOT 11).
        let source = r#"
int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}
"#;
        let metrics = calculate_complexity(source, "is_hex_digit", Language::C).unwrap();
        assert_eq!(
            metrics.cyclomatic, 6,
            "C 5 boolean ops counted once: base 1 + 5 = 6, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_cpp_logical_operators_not_double_counted() {
        let source = r#"
bool g(bool a, bool b, bool c) {
    if (a && b || c) return true;
    return false;
}
"#;
        // if + (1 && + 1 ||) -> base 1 + 1 + 2 = 4.
        let metrics = calculate_complexity(source, "g", Language::Cpp).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "C++ if + 2 boolean ops once: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_java_logical_operators_not_double_counted() {
        let source = r#"
class M {
    boolean f(boolean a, boolean b) {
        if (a && b || a) return true;
        return false;
    }
}
"#;
        let metrics = calculate_complexity(source, "f", Language::Java).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Java if + 2 boolean ops once: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_javascript_logical_operators_not_double_counted() {
        let source = r#"
function f(a, b) {
    if (a && b || a) return 1;
    return 0;
}
"#;
        let metrics = calculate_complexity(source, "f", Language::JavaScript).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "JS if + 2 boolean ops once: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    /// fix-R7 (cluster[11] RC3): JS function-expression methods assigned to a
    /// member (`res.send = function send(body){}`), to a variable
    /// (`const f = function(){}`), or via arrow (`res.json = (o) => {}`) must be
    /// found and named by the batch complexity walk. Previously the JS function
    /// kind list contained the bare `function` keyword-leaf but NOT
    /// `function_expression`, and `get_function_name` had no JS arm to recover
    /// the LHS name, so these methods were silently dropped from the map —
    /// which is why `health`/`smells`/`debt`/`diff` under-reported express-style
    /// `res.X = function(){}` modules.
    #[test]
    fn test_js_function_expression_methods_are_named_and_counted() {
        let source = r#"
res.send = function send(body) {
    if (body) { return this; }
    return this;
};
res.json = function (obj) {
    if (obj) { return this; }
    return this;
};
res.sendFile = (path) => {
    if (path) { return this; }
    return this;
};
const helper = function () {
    return 1;
};
function topLevel() {
    return 0;
}
"#;
        let map = calculate_all_complexities(source, Language::JavaScript).unwrap();

        // Named function_expression assigned to a member: keyed by the member
        // property name `send` (its own `function send` name also works).
        assert!(
            map.contains_key("send") || map.contains_key("res.send"),
            "named function_expression `res.send = function send()` must be found, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // Anonymous function_expression assigned to a member -> LHS property.
        assert!(
            map.contains_key("json") || map.contains_key("res.json"),
            "anonymous `res.json = function(){{}}` must be found via LHS name, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // Arrow assigned to a member -> LHS property.
        assert!(
            map.contains_key("sendFile") || map.contains_key("res.sendFile"),
            "arrow `res.sendFile = () => {{}}` must be found, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // function_expression bound to a const variable -> declarator name.
        assert!(
            map.contains_key("helper"),
            "`const helper = function(){{}}` must be found, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // Regression: the plain top-level declaration still found.
        assert!(
            map.contains_key("topLevel"),
            "top-level function_declaration must still be found, got keys: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        // The `send` method has a real cyclomatic > 1 (it has an `if`), proving
        // the body was actually analyzed (not a 0/empty placeholder).
        let send_key = if map.contains_key("send") { "send" } else { "res.send" };
        assert!(
            map[send_key].cyclomatic >= 2,
            "function_expression body must be analyzed (cyclomatic>=2 for the `if`), got {}",
            map[send_key].cyclomatic
        );
    }

    #[test]
    fn test_python_logical_operators_still_counted_once() {
        // Regression guard: Python `and`/`or` must STILL be credited (via the
        // operator-field arm) after the bare-token arm is removed.
        // 2 ifs + 2 ops -> base 1 + 2 + 2 = 5.
        let source = r#"
def with_logic(a, b, c):
    if a and b:
        return 1
    if a or c:
        return 2
    return 0
"#;
        let metrics = calculate_complexity(source, "with_logic", Language::Python).unwrap();
        assert_eq!(
            metrics.cyclomatic, 5,
            "Python 2 ifs + 2 boolean ops once: base 1 +2 +2 = 5, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_go_logical_operators_counted_once() {
        let source = r#"
package m
func f(a, b bool) int {
	if a && b || a {
		return 1
	}
	return 0
}
"#;
        let metrics = calculate_complexity(source, "f", Language::Go).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Go if + 2 boolean ops once: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_scala_logical_operators_unaffected() {
        // Scala uses `infix_expression` with its own dedicated arm; it must
        // remain correct (1 if + 2 ops) = base 1 + 1 + 2 = 4.
        let source = r#"
object M { def f(a: Boolean, b: Boolean): Int = { if (a && b || a) 1 else 0 } }
"#;
        let metrics = calculate_complexity(source, "f", Language::Scala).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Scala if + 2 infix boolean ops: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    // -- RC3: Ruby keyword-token double-match (cyclomatic) ---------------

    #[test]
    fn test_ruby_case_when_not_double_counted() {
        // case + 3 when -> base 1 + 3 = 4 (NOT 7). `case` itself adds 0;
        // each non-default `when` arm adds 1.
        let source = r#"
def interpret(x)
  case x
  when 1 then 1
  when 2 then 2
  when 3 then 3
  end
end
"#;
        let metrics = calculate_complexity(source, "interpret", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Ruby case/3-when counted once: base 1 + 3 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_if_else_not_double_counted() {
        // single if/else -> base 1 + 1 = 2 (NOT 3).
        let source = r#"
def interpret_unicode(x)
  if x == 1
    10
  else
    20
  end
end
"#;
        let metrics = calculate_complexity(source, "interpret_unicode", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Ruby single if/else counted once: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_if_modifier_not_double_counted() {
        // single trailing if-modifier -> base 1 + 1 = 2 (NOT 3).
        let source = r#"
def reset
  cleanup if dirty?
  mkpath
end
"#;
        let metrics = calculate_complexity(source, "reset", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Ruby if-modifier counted once: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_unless_modifier_not_double_counted() {
        // single trailing unless-modifier -> base 1 + 1 = 2 (NOT 3).
        let source = r#"
def find_similar(target)
  return [] unless defined?(SpellChecker)
  target
end
"#;
        let metrics = calculate_complexity(source, "find_similar", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Ruby unless-modifier counted once: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_elsif_chain_not_double_counted() {
        // if + 2 elsif -> base 1 + 1 + 2 = 4 (NOT 7).
        let source = r#"
def grade(x)
  if x > 90
    "a"
  elsif x > 80
    "b"
  elsif x > 70
    "c"
  end
end
"#;
        let metrics = calculate_complexity(source, "grade", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Ruby if + 2 elsif counted once: base 1 +1 +2 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_while_not_double_counted() {
        // single while -> base 1 + 1 = 2 (NOT 3).
        let source = r#"
def count_down(n)
  while n > 0
    n -= 1
  end
  n
end
"#;
        let metrics = calculate_complexity(source, "count_down", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Ruby single while counted once: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_ruby_straight_line_stays_one() {
        // Guard against over-correction: no branches -> cyclomatic 1.
        let source = r#"
def linear(x)
  y = x + 1
  z = y * 2
  z
end
"#;
        let metrics = calculate_complexity(source, "linear", Language::Ruby).unwrap();
        assert_eq!(
            metrics.cyclomatic, 1,
            "Ruby straight-line stays cyclomatic 1, got {}",
            metrics.cyclomatic
        );
    }

    // -- RC5: Rust `if` is an expression ---------------------------------
    //
    // RC5 (v0.5.0 RC-CAMPAIGN): in tree-sitter-rust `if`, `if let` and the
    // chained `else if` all parse as `if_expression` nodes (never the C-shaped
    // `if_statement`), so none of the generic `_statement` arms ever fired and
    // every branchy Rust function collapsed to cyclomatic = 1. The canonical
    // cognitive cyclomatic counter (`cognitive::count_cyclomatic_increment`,
    // which credits `if_expression` ungated) already counted these, so
    // `tldr complexity` disagreed with `tldr cognitive --include-cyclomatic`
    // and with the CFG's own E-N+2P decision count. The fix adds
    // `Language::Rust` to the existing `if_expression` decision arm.
    //
    // GENERALIZATION GATE: this asserts EVERY variant of the Rust-`if`
    // symptom class — plain `if`, `if let`, and chained `else if` — is
    // credited, plus the over-correction guard that a straight-line Rust
    // function stays at 1.

    #[test]
    fn test_rust_if_expression_counts_all_variants() {
        // base 1 + `if` (1) + `else if` (nested if_expression, 1)
        //        + `if let` (1) = 4. This is exactly the McCabe E-N+2P count
        // and matches `tldr cognitive --include-cyclomatic` (which reports 4).
        let source = r#"
fn classify(x: i32) -> i32 {
    if x < 0 {
        return -1;
    } else if x == 0 {
        return 0;
    }
    if let Some(_y) = Some(x) {
        return 1;
    }
    2
}
"#;
        let metrics = calculate_complexity(source, "classify", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Rust if + else-if + if-let: base 1 +1 +1 +1 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_rust_plain_if_counts() {
        // Variant: a single plain `if` -> base 1 + 1 = 2.
        let source = r#"
fn f(x: i32) -> i32 {
    if x > 0 {
        return 1;
    }
    0
}
"#;
        let metrics = calculate_complexity(source, "f", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Rust plain `if`: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_rust_if_let_counts() {
        // Variant: a single `if let` pattern match -> base 1 + 1 = 2.
        let source = r#"
fn f(x: Option<i32>) -> i32 {
    if let Some(v) = x {
        return v;
    }
    0
}
"#;
        let metrics = calculate_complexity(source, "f", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Rust `if let`: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_rust_else_if_chain_counts_each() {
        // Variant: a 3-deep `else if` chain. Each `else if` is its own nested
        // `if_expression`; the trailing bare `else` is an `else_clause` with a
        // block (NOT a decision point). base 1 + 3 = 4.
        let source = r#"
fn grade(x: i32) -> i32 {
    if x >= 90 {
        4
    } else if x >= 80 {
        3
    } else if x >= 70 {
        2
    } else {
        0
    }
}
"#;
        let metrics = calculate_complexity(source, "grade", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 4,
            "Rust 3 `else if` arms (trailing `else` not counted): base 1 + 3 = 4, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_rust_straight_line_stays_one() {
        // Over-correction guard: no branches -> cyclomatic 1.
        let source = r#"
fn linear(x: i32) -> i32 {
    let y = x + 1;
    let z = y * 2;
    z
}
"#;
        let metrics = calculate_complexity(source, "linear", Language::Rust).unwrap();
        assert_eq!(
            metrics.cyclomatic, 1,
            "Rust straight-line stays cyclomatic 1, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_other_expr_langs_if_unchanged_by_rust_fix() {
        // Regression guard: the existing expression-oriented languages already
        // credited via the `if_expression` arm (Kotlin / Scala / OCaml) must be
        // unchanged. A Kotlin `if` -> base 1 + 1 = 2.
        let kotlin = r#"
fun f(x: Int): Int {
    if (x > 0) {
        return 1
    }
    return 0
}
"#;
        let metrics = calculate_complexity(kotlin, "f", Language::Kotlin).unwrap();
        assert_eq!(
            metrics.cyclomatic, 2,
            "Kotlin `if` still counts after Rust fix: base 1 + 1 = 2, got {}",
            metrics.cyclomatic
        );
    }
}
