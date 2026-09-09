//! Cognitive complexity calculation module (Session 15, Phase 3)
//!
//! Implements SonarQube's cognitive complexity algorithm with threshold checking.
//!
//! # Algorithm Overview (per SonarSource whitepaper)
//!
//! Cognitive complexity increments for:
//! - Control flow structures: +1 for if, elif, for, while, catch, switch, ?:
//! - Nesting penalty: +1 per nesting level for nested control structures
//! - Logical operators: +1 for sequences of &&, ||
//! - Recursion: +1 for recursive calls
//! - Break/continue to label: +1 (not applicable in Python)
//!
//! Important deviations from cyclomatic complexity:
//! - `else` adds +0 (linear flow per SonarSource Cognitive Complexity v1.4)
//! - `else if` adds +1 total (the inner `if`, NOT +2)
//! - `elif` adds +1 (Python's distinct `elif_clause`)
//! - Nesting increases cognitive load exponentially
//!
//! # References
//! - [SonarSource Cognitive Complexity Whitepaper](https://www.sonarsource.com/docs/CognitiveComplexity.pdf)

use std::path::Path;

use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::ast::function_finder::{get_function_body, get_function_name, get_function_node_kinds};
use crate::ast::parser::{parse, parse_file};
use crate::metrics::types::{CognitiveContributor, CognitiveInfo};
use crate::types::Language;
use crate::TldrResult;

/// Maximum nesting depth to prevent infinite loops
const MAX_NESTING_DEPTH: usize = 100;

/// Default threshold for cognitive complexity warning
pub const DEFAULT_THRESHOLD: u32 = 15;

/// Default threshold for severe violations
pub const DEFAULT_HIGH_THRESHOLD: u32 = 25;

/// Result of cognitive complexity analysis for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveReport {
    /// Functions analyzed with their complexity scores
    pub functions: Vec<FunctionCognitive>,
    /// Functions that exceed the threshold
    pub violations: Vec<ViolationEntry>,
    /// Summary statistics
    pub summary: CognitiveSummary,
    /// Warnings encountered during analysis
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Cognitive complexity for a single function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCognitive {
    /// Function name
    pub name: String,
    /// File path
    pub file: String,
    /// Line number where function starts
    pub line: u32,
    /// Cognitive complexity score
    pub cognitive: u32,
    /// Cyclomatic complexity (optional, for comparison)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cyclomatic: Option<u32>,
    /// Maximum nesting depth in this function
    pub max_nesting: u32,
    /// Nesting penalty portion of the score
    pub nesting_penalty: u32,
    /// Threshold status
    pub threshold_status: ThresholdStatus,
    /// Detailed contributors (optional, when show_contributors is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contributors: Option<Vec<CognitiveContributor>>,
}

/// Threshold violation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEntry {
    /// Function name
    pub name: String,
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Cognitive complexity score
    pub cognitive: u32,
    /// Severity level
    pub severity: String,
}

/// Summary statistics for cognitive complexity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CognitiveSummary {
    /// Total number of functions analyzed
    pub total_functions: usize,
    /// Sum of all cognitive complexity scores
    pub total_cognitive: u32,
    /// Average cognitive complexity
    pub avg_cognitive: f64,
    /// Maximum cognitive complexity found
    pub max_cognitive: u32,
    /// Number of violations (exceeds threshold)
    pub violations_count: usize,
    /// Number of severe violations (exceeds high threshold)
    pub severe_violations_count: usize,
    /// Compliance rate (percentage of functions under threshold)
    pub compliance_rate: f64,
}

/// Threshold status for a function
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThresholdStatus {
    /// Below threshold
    Ok,
    /// Approaching threshold (>= 80% of threshold)
    Warning,
    /// Exceeds threshold
    Violation,
    /// Exceeds high threshold
    Severe,
}

impl ThresholdStatus {
    /// Determine status based on score and thresholds
    pub fn from_score(score: u32, threshold: u32, high_threshold: u32) -> Self {
        if score >= high_threshold {
            ThresholdStatus::Severe
        } else if score >= threshold {
            ThresholdStatus::Violation
        } else if score >= (threshold * 4 / 5) {
            // >= 80% of threshold
            ThresholdStatus::Warning
        } else {
            ThresholdStatus::Ok
        }
    }
}

/// Options for cognitive complexity analysis
#[derive(Debug, Clone, Default)]
pub struct CognitiveOptions {
    /// Filter to specific function name
    pub function_filter: Option<String>,
    /// Threshold for violations
    pub threshold: u32,
    /// High threshold for severe violations
    pub high_threshold: u32,
    /// Include contributor breakdown
    pub show_contributors: bool,
    /// Include cyclomatic comparison
    pub include_cyclomatic: bool,
    /// Maximum functions to return (0 = all)
    pub top: usize,
}

impl CognitiveOptions {
    /// Create default options with standard thresholds
    pub fn new() -> Self {
        Self {
            function_filter: None,
            threshold: DEFAULT_THRESHOLD,
            high_threshold: DEFAULT_HIGH_THRESHOLD,
            show_contributors: false,
            include_cyclomatic: false,
            top: 50,
        }
    }

    /// Set function filter
    pub fn with_function(mut self, function: Option<String>) -> Self {
        self.function_filter = function;
        self
    }

    /// Set threshold
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Set high threshold
    pub fn with_high_threshold(mut self, high_threshold: u32) -> Self {
        self.high_threshold = high_threshold;
        self
    }

    /// Enable contributor breakdown
    pub fn with_contributors(mut self, show: bool) -> Self {
        self.show_contributors = show;
        self
    }

    /// Enable cyclomatic comparison
    pub fn with_cyclomatic(mut self, include: bool) -> Self {
        self.include_cyclomatic = include;
        self
    }

    /// Set top limit
    pub fn with_top(mut self, top: usize) -> Self {
        self.top = top;
        self
    }
}

/// Analyze cognitive complexity for a file
///
/// # Arguments
/// * `path` - Path to the source file
/// * `options` - Analysis options
///
/// # Returns
/// * `Ok(CognitiveReport)` - Analysis results
/// * `Err(TldrError)` - On parse or file errors
pub fn analyze_cognitive(path: &Path, options: &CognitiveOptions) -> TldrResult<CognitiveReport> {
    // Parse the file
    let (tree, source, language) = parse_file(path)?;
    let root = tree.root_node();

    let file_path = path.to_string_lossy().to_string();

    // Find all functions
    let mut functions = find_all_functions(root, language, &source, &file_path, options)?;

    // sibling-resolver-gaps-v1 (P14.AGG14-19): the AST walker above
    // recognizes only the canonical JS function nodes
    // (`function_declaration`, `arrow_function`, `method_definition`,
    // `function`, `generator_function*`). It misses the CommonJS
    // pattern `app.X = function name() {}` because the
    // `assignment_expression` is the immediate parent of the
    // function expression — the function expression itself is a
    // `function` node, but its tree-sitter `name` field is empty when
    // the assigned function is anonymous OR it's the inner name (which
    // doesn't reflect the outer `app.X` exported binding). For
    // express's `application.js` cognitive returned only 2 functions
    // while halstead returned 19. Augment by reusing the AST extractor
    // (the same source halstead/complexity siblings rely on) to fill
    // in CommonJS-style assignments. The extractor knows the
    // `app.X = function ...` shape and emits the qualified name.
    if matches!(language, Language::JavaScript | Language::TypeScript) {
        augment_cognitive_with_extractor_functions(
            path,
            language,
            &source,
            &file_path,
            options,
            &mut functions,
        )?;
    }

    // Apply function filter if specified
    if let Some(ref filter) = options.function_filter {
        functions.retain(|f| f.name.contains(filter) || f.name == *filter);
    }

    // Sort by cognitive complexity descending
    functions.sort_by_key(|b| std::cmp::Reverse(b.cognitive));

    // Apply top limit
    if options.top > 0 && functions.len() > options.top {
        functions.truncate(options.top);
    }

    // Build violations list
    let violations: Vec<ViolationEntry> = functions
        .iter()
        .filter(|f| {
            f.threshold_status == ThresholdStatus::Violation
                || f.threshold_status == ThresholdStatus::Severe
        })
        .map(|f| ViolationEntry {
            name: f.name.clone(),
            file: f.file.clone(),
            line: f.line,
            cognitive: f.cognitive,
            severity: match f.threshold_status {
                ThresholdStatus::Severe => "severe".to_string(),
                ThresholdStatus::Violation => "violation".to_string(),
                _ => "warning".to_string(),
            },
        })
        .collect();

    // Calculate summary
    let summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    Ok(CognitiveReport {
        functions,
        violations,
        summary,
        warnings: Vec::new(),
    })
}

/// Analyze cognitive complexity from source code string
pub fn analyze_cognitive_source(
    source: &str,
    language: Language,
    file_name: &str,
    options: &CognitiveOptions,
) -> TldrResult<CognitiveReport> {
    let tree = parse(source, language)?;
    let root = tree.root_node();

    let mut functions = find_all_functions(root, language, source, file_name, options)?;

    // Apply function filter if specified
    if let Some(ref filter) = options.function_filter {
        functions.retain(|f| f.name.contains(filter) || f.name == *filter);
    }

    // Sort by cognitive complexity descending
    functions.sort_by_key(|b| std::cmp::Reverse(b.cognitive));

    // Apply top limit
    if options.top > 0 && functions.len() > options.top {
        functions.truncate(options.top);
    }

    // Build violations list
    let violations: Vec<ViolationEntry> = functions
        .iter()
        .filter(|f| {
            f.threshold_status == ThresholdStatus::Violation
                || f.threshold_status == ThresholdStatus::Severe
        })
        .map(|f| ViolationEntry {
            name: f.name.clone(),
            file: f.file.clone(),
            line: f.line,
            cognitive: f.cognitive,
            severity: match f.threshold_status {
                ThresholdStatus::Severe => "severe".to_string(),
                ThresholdStatus::Violation => "violation".to_string(),
                _ => "warning".to_string(),
            },
        })
        .collect();

    // Calculate summary
    let summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    Ok(CognitiveReport {
        functions,
        violations,
        summary,
        warnings: Vec::new(),
    })
}

/// Find all functions in the AST and calculate their cognitive complexity
fn find_all_functions(
    root: Node,
    language: Language,
    source: &str,
    file_path: &str,
    options: &CognitiveOptions,
) -> TldrResult<Vec<FunctionCognitive>> {
    let func_kinds = get_function_node_kinds(language);
    let mut functions = Vec::new();

    let mut cursor = root.walk();
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if func_kinds.contains(&node.kind()) {
            if let Some(name) = get_function_name(node, language, source) {
                let mut calculator = CognitiveCalculator::new(name.clone(), source, language);
                calculator.analyze_function(node)?;

                // Extract values before consuming calculator
                let max_nesting = calculator.max_nesting;
                let cyclomatic_val = calculator.cyclomatic;

                let info = calculator.into_info();
                let cognitive = info.score;
                let nesting_penalty = info.nesting_penalty;

                let threshold_status = ThresholdStatus::from_score(
                    cognitive,
                    options.threshold,
                    options.high_threshold,
                );

                let cyclomatic = if options.include_cyclomatic {
                    Some(cyclomatic_val)
                } else {
                    None
                };

                let contributors = if options.show_contributors {
                    info.contributors
                } else {
                    None
                };

                functions.push(FunctionCognitive {
                    name,
                    file: file_path.to_string(),
                    line: node.start_position().row as u32 + 1,
                    cognitive,
                    cyclomatic,
                    max_nesting,
                    nesting_penalty,
                    threshold_status,
                    contributors,
                });
            }
        }

        // Add children to stack
        cursor.reset(node);
        if cursor.goto_first_child() {
            loop {
                stack.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // p19-secondary-fixes-v1 (BUG-P19-03): OCaml's
    // `get_function_node_kinds` lists BOTH `value_definition` (the outer
    // wrapper) and `let_binding` (the inner definition). The walker
    // matches both and emits the same function twice with identical
    // (name, line). Dedup by (name, line) preserving first-seen entry.
    if matches!(language, Language::Ocaml) {
        let mut seen: std::collections::HashSet<(String, u32)> =
            std::collections::HashSet::new();
        functions.retain(|f| seen.insert((f.name.clone(), f.line)));
    }

    Ok(functions)
}

/// sibling-resolver-gaps-v1 (P14.AGG14-19): augment the cognitive
/// function list with any function the AST extractor sees that the
/// raw tree-sitter walker missed. Targets the JS CommonJS pattern
/// `app.X = function name(){}` (and module-level
/// `module.exports.foo = function(){}`), which `extract_file` already
/// resolves (halstead and complexity siblings rely on this). For each
/// extractor function whose name is not yet present in `functions`,
/// locate the matching node via `find_function_node` and run the
/// same cognitive calculator — preserving exact metric semantics.
fn augment_cognitive_with_extractor_functions(
    path: &Path,
    language: Language,
    source: &str,
    file_path: &str,
    options: &CognitiveOptions,
    functions: &mut Vec<FunctionCognitive>,
) -> TldrResult<()> {
    use crate::ast::function_finder::find_function_node;
    use crate::extract_file;

    let module = match extract_file(path, None) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let tree = parse(source, language)?;
    let root = tree.root_node();

    let existing: std::collections::HashSet<String> =
        functions.iter().map(|f| f.name.clone()).collect();

    let mut candidates: Vec<(String, u32)> = Vec::new();
    for f in &module.functions {
        if !existing.contains(&f.name) {
            candidates.push((f.name.clone(), f.line_number));
        }
    }
    for class in &module.classes {
        for m in &class.methods {
            if !existing.contains(&m.name) {
                candidates.push((m.name.clone(), m.line_number));
            }
        }
    }

    for (name, line) in candidates {
        let func_node = match find_function_node(root, &name, language, source) {
            Some(n) => n,
            None => continue,
        };
        let mut calculator = CognitiveCalculator::new(name.clone(), source, language);
        if calculator.analyze_function(func_node).is_err() {
            continue;
        }
        let max_nesting = calculator.max_nesting;
        let cyclomatic_val = calculator.cyclomatic;
        let info = calculator.into_info();
        let cognitive = info.score;
        let nesting_penalty = info.nesting_penalty;

        let threshold_status =
            ThresholdStatus::from_score(cognitive, options.threshold, options.high_threshold);

        let cyclomatic = if options.include_cyclomatic {
            Some(cyclomatic_val)
        } else {
            None
        };

        let contributors = if options.show_contributors {
            info.contributors
        } else {
            None
        };

        functions.push(FunctionCognitive {
            name,
            file: file_path.to_string(),
            line,
            cognitive,
            cyclomatic,
            max_nesting,
            nesting_penalty,
            threshold_status,
            contributors,
        });
    }
    Ok(())
}

/// Calculate summary statistics
fn calculate_summary(
    functions: &[FunctionCognitive],
    threshold: u32,
    high_threshold: u32,
) -> CognitiveSummary {
    if functions.is_empty() {
        return CognitiveSummary::default();
    }

    let total_cognitive: u32 = functions.iter().map(|f| f.cognitive).sum();
    let max_cognitive = functions.iter().map(|f| f.cognitive).max().unwrap_or(0);
    let avg_cognitive = total_cognitive as f64 / functions.len() as f64;

    let violations_count = functions
        .iter()
        .filter(|f| f.cognitive >= threshold)
        .count();
    let severe_violations_count = functions
        .iter()
        .filter(|f| f.cognitive >= high_threshold)
        .count();

    let compliant = functions.len() - violations_count;
    let compliance_rate = (compliant as f64 / functions.len() as f64) * 100.0;

    CognitiveSummary {
        total_functions: functions.len(),
        total_cognitive,
        avg_cognitive,
        max_cognitive,
        violations_count,
        severe_violations_count,
        compliance_rate,
    }
}

/// Result of running the canonical cognitive calculator on a single
/// function node.  Used by `tldr complexity` (cross-command-consistency-v1)
/// so it shares one implementation with `tldr cognitive`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CognitiveScore {
    /// SonarSource cognitive complexity score
    pub cognitive: u32,
    /// Maximum nesting depth observed
    pub max_nesting: u32,
    /// Nesting-penalty portion of the score
    pub nesting_penalty: u32,
}

/// Run the canonical SonarSource cognitive calculator on a single function.
///
/// BUG-7 (cross-command-consistency-v1): both `tldr complexity` and
/// `tldr cognitive` must report the same number for the same function.
/// This helper runs the cognitive calculator that powers `tldr cognitive`
/// so `tldr complexity` can delegate to it instead of carrying a second,
/// drifting implementation.
pub fn calculate_cognitive_for_function(
    function_name: &str,
    source: &str,
    language: Language,
    func_node: Node,
) -> CognitiveScore {
    let mut calc = CognitiveCalculator::new(function_name.to_string(), source, language);
    if calc.analyze_function(func_node).is_err() {
        return CognitiveScore::default();
    }
    let max_nesting = calc.max_nesting;
    let nesting_penalty = calc.nesting_penalty;
    let info = calc.into_info();
    CognitiveScore {
        cognitive: info.score,
        max_nesting,
        nesting_penalty,
    }
}

/// Calculator for cognitive complexity metrics
struct CognitiveCalculator<'a> {
    function_name: String,
    source: &'a str,
    language: Language,
    cognitive: u32,
    cyclomatic: u32,
    max_nesting: u32,
    current_nesting: u32,
    nesting_penalty: u32,
    contributors: Vec<CognitiveContributor>,
    /// Track previous logical operator to detect sequences
    prev_logical_op: Option<String>,
}

impl<'a> CognitiveCalculator<'a> {
    fn new(function_name: String, source: &'a str, language: Language) -> Self {
        Self {
            function_name,
            source,
            language,
            cognitive: 0,
            cyclomatic: 1, // Base complexity is 1
            max_nesting: 0,
            current_nesting: 0,
            nesting_penalty: 0,
            contributors: Vec::new(),
            prev_logical_op: None,
        }
    }

    fn analyze_function(&mut self, func_node: Node) -> TldrResult<()> {
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
        let line = node.start_position().row as u32 + 1;

        // Check if this is a nesting-increasing structure
        let increases_nesting = self.increases_nesting_node(node);

        if increases_nesting {
            self.current_nesting += 1;
            self.max_nesting = self.max_nesting.max(self.current_nesting);
        }

        // Calculate cognitive complexity increment
        self.count_cognitive_increment(node, line);

        // Calculate cyclomatic increment (for comparison)
        self.count_cyclomatic_increment(node);

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

        if increases_nesting {
            self.current_nesting -= 1;
        }

        // Reset logical operator tracking at statement boundaries
        if is_statement(kind) {
            self.prev_logical_op = None;
        }

        Ok(())
    }

    /// Check if a node kind increases nesting level
    fn increases_nesting(&self, kind: &str) -> bool {
        // Language-agnostic control-flow node kinds. These have the
        // `_statement` / `_clause` suffix and are unambiguous across grammars.
        let generic = matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "try_statement"
                | "with_statement"
                | "match_statement"
                | "switch_statement"
                | "switch_body"
                | "lambda"
                | "lambda_expression"
                | "catch_clause"
                | "except_clause"
                | "except_handler"
        );

        if generic {
            return true;
        }

        // cognitive-else-counting-fix-v1: Ruby tree-sitter grammar exposes
        // control-flow nodes without the `_statement` suffix used by
        // Python/JS/Java (e.g. bare `"if"`, `"while"`, `"case"`). These bare
        // keyword names ALSO appear as token-kind leaves in Python/JS/TS/C/
        // Rust trees (the literal `if` / `for` / `while` keyword inside an
        // `if_statement` / `for_statement`). Matching them unconditionally
        // double-counted every control structure in non-Ruby code. Gate the
        // Ruby cognates on `Language::Ruby` so they only fire for actual
        // Ruby ASTs.
        if matches!(self.language, Language::Ruby) {
            return matches!(
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
            );
        }

        // pattern-match-arm-undercount-v1 (P19.BUG-01 family + BUG-P19-02):
        // Rust / Scala / Kotlin / OCaml grammars expose control-flow nodes
        // as `*_expression` (rather than `*_statement`). Without this branch
        // the cognitive walker never enters those expressions as a nesting
        // step, leaving `max_nesting=0` and `nesting_penalty=0` everywhere
        // in the corpus (the dominant symptom of BUG-P19-02 on Rust).
        match self.language {
            Language::Rust => {
                if matches!(
                    kind,
                    "if_expression"
                        | "for_expression"
                        | "while_expression"
                        | "loop_expression"
                        | "match_expression"
                        | "closure_expression"
                ) {
                    return true;
                }
            }
            Language::Scala => {
                if matches!(
                    kind,
                    "if_expression"
                        | "for_expression"
                        | "while_expression"
                        | "match_expression"
                        | "try_expression"
                        | "case_block"
                ) {
                    return true;
                }
            }
            Language::Kotlin => {
                if matches!(
                    kind,
                    "if_expression"
                        | "when_expression"
                        | "try_expression"
                        | "do_while_statement"
                ) {
                    return true;
                }
            }
            Language::Ocaml => {
                if matches!(
                    kind,
                    "match_expression"
                        | "function_expression"
                        | "if_expression"
                        | "for_expression"
                        | "while_expression"
                        | "try_expression"
                ) {
                    return true;
                }
            }
            Language::Elixir => {
                // Anonymous `fn` blocks contain `stab_clause` arms and
                // dispatch like `case`/`cond`/`with`; treat as nesting.
                if matches!(kind, "anonymous_function") {
                    return true;
                }
                // `call` nodes for case/cond/with handled in node-aware
                // wrapper `increases_nesting_node`.
            }
            _ => {}
        }

        false
    }

    /// Node-aware nesting check. Wraps `increases_nesting(&str)` and adds
    /// language-specific node-shape checks that need access to the node
    /// (rather than just its kind), such as Elixir's case/cond/with
    /// dispatch calls.
    fn increases_nesting_node(&self, node: Node) -> bool {
        if self.increases_nesting(node.kind()) {
            return true;
        }
        if matches!(self.language, Language::Elixir)
            && node.kind() == "call"
            && self.is_elixir_dispatch_call(node)
        {
            return true;
        }
        false
    }

    /// Detect Elixir `case`/`cond`/`with` dispatch construct.
    ///
    /// The Elixir tree-sitter grammar models these as a `call` whose first
    /// child is an `identifier` token containing the keyword. They wrap a
    /// `do_block` whose direct children are `stab_clause` arms.
    fn is_elixir_dispatch_call(&self, node: Node) -> bool {
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return false;
        }
        let head = cursor.node();
        if head.kind() != "identifier" {
            return false;
        }
        let text = match head.utf8_text(self.source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return false,
        };
        matches!(text, "case" | "cond" | "with")
    }

    /// Count cognitive complexity increment for a node
    ///
    /// Per SonarSource algorithm:
    /// - if/elif/for/while/catch/switch/?:: +1 base + nesting level
    /// - else: +0 (linear flow, no cognitive increment)
    /// - &&/||: +1 for each sequence change
    /// - recursion: +1
    fn count_cognitive_increment(&mut self, node: Node, line: u32) {
        let kind = node.kind();

        // Per SonarSource Cognitive Complexity v1.4: `else if` adds +1, NOT
        // +2. We score the inner `if_statement` directly (which is exactly +1
        // base, no nesting penalty since the parent else_clause is treated as
        // linear flow), and score `else_clause` as +0. This produces the
        // correct +1 for `else if` without double-counting.

        // Control structures that add base increment + nesting.
        //
        // Per SonarSource Cognitive Complexity v1.4 (and the module-level
        // doc-comment): `else` is linear flow and adds +0. Only `if`, `elif`,
        // for/while/catch/switch/?: increment.
        let base_increment = match kind {
            // if adds +1 base + nesting
            "if_statement" | "if_expression" => Some((1, "if")),
            // elif adds +1 base + nesting (Python's elif_clause)
            "elif_clause" => Some((1, "elif")),
            // for/while add +1 base + nesting
            "for_statement" | "for_in_statement" => Some((1, "for")),
            "while_statement" => Some((1, "while")),
            // pattern-match-arm-undercount-v1: Rust/Scala/Kotlin/OCaml
            // expose loops as `*_expression` rather than `*_statement`.
            // Without these the loop construct itself is invisible to the
            // cognitive walker on those languages.
            "for_expression" | "while_expression" | "loop_expression"
                if matches!(
                    self.language,
                    Language::Rust | Language::Scala | Language::Ocaml
                ) =>
            {
                Some((1, "for"))
            }
            // Kotlin do-while
            "do_while_statement" if matches!(self.language, Language::Kotlin) => {
                Some((1, "while"))
            }
            // catch/except add +1 base + nesting
            "except_clause" | "catch_clause" | "except_handler" => Some((1, "catch")),
            // try_expression (scala/kotlin/ocaml) — credited so the catch
            // arms underneath get nesting; cognitive +1 matches `try`.
            "try_expression"
                if matches!(
                    self.language,
                    Language::Scala | Language::Kotlin | Language::Ocaml
                ) =>
            {
                Some((1, "try"))
            }
            // switch/match add +1 base + nesting
            "match_statement" | "switch_statement" => Some((1, "switch")),
            // pattern-match-arm-undercount-v1: Rust/Scala/OCaml/Kotlin
            // expose match/when as `*_expression`. Credit the construct
            // itself with +1 and let each non-catchall arm add +1 below.
            "match_expression"
                if matches!(
                    self.language,
                    Language::Rust | Language::Scala | Language::Ocaml
                ) =>
            {
                Some((1, "match"))
            }
            "function_expression" if matches!(self.language, Language::Ocaml) => {
                // OCaml `function | ...` form. Same dispatch as `match`.
                Some((1, "match"))
            }
            "when_expression" if matches!(self.language, Language::Kotlin) => {
                Some((1, "when"))
            }
            // ternary adds +1 (no nesting penalty per SonarQube - chains are flat)
            "conditional_expression" | "ternary_expression" => Some((1, "?:")),
            // P12.AGG12-10 + cognitive-else-counting-fix-v1: Ruby AST kinds.
            // `if`/`unless` are SonarSource "if" cognates; `while`/`until` are
            // loops; `for` is a loop; `case` is a switch; `begin` is the
            // equivalent of `try`; `rescue` is the catch clause; the
            // *_modifier suffix variants are the trailing-conditional
            // shorthand and count exactly the same as their statement form.
            //
            // CRITICAL: gate on Language::Ruby. In Python/JS/TS/C/Rust ASTs
            // the literal `if`/`for`/`while` keyword appears as a token-kind
            // child of `if_statement` / `for_statement` etc. Matching them
            // unconditionally double-counted every control structure (e.g.
            // a single `if x: ...` scored 3 instead of 1).
            "if" if matches!(self.language, Language::Ruby) => Some((1, "if")),
            "unless" if matches!(self.language, Language::Ruby) => Some((1, "if")),
            "while" | "until" if matches!(self.language, Language::Ruby) => Some((1, "while")),
            "for" if matches!(self.language, Language::Ruby) => Some((1, "for")),
            "case" if matches!(self.language, Language::Ruby) => Some((1, "switch")),
            "rescue" if matches!(self.language, Language::Ruby) => Some((1, "catch")),
            "if_modifier" => Some((1, "if")),
            "unless_modifier" => Some((1, "if")),
            "while_modifier" | "until_modifier" => Some((1, "while")),
            // pattern-match-arm-undercount-v1 (P19.BUG-01 family):
            // Per-arm credit for switch/match/when/case dispatch
            // constructs across c/cpp/rust/scala/kotlin/ocaml/elixir.
            // SonarSource v1.4 strictly credits the dispatch construct
            // once; we extend with +1 per non-catchall arm so 5-arm
            // matches in Rust/Scala/etc. surface a meaningful cognitive
            // score (the pre-fix repro showed 8-arm `parse` cog=0 on
            // Rust). Catchall arms (`_`, `default`, `else`) are excluded
            // so an `if/else` cognate inside the dispatch remains
            // linear-flow.
            "case_statement"
                if matches!(self.language, Language::C | Language::Cpp)
                    && !is_default_case_statement(node) =>
            {
                Some((1, "case"))
            }
            "match_arm"
                if matches!(self.language, Language::Rust)
                    && !is_rust_wildcard_arm(node, self.source) =>
            {
                Some((1, "arm"))
            }
            "case_clause"
                if matches!(self.language, Language::Scala)
                    && !is_scala_wildcard_arm(node, self.source) =>
            {
                Some((1, "case"))
            }
            "when_entry"
                if matches!(self.language, Language::Kotlin)
                    && !is_kotlin_else_when_entry(node) =>
            {
                Some((1, "when"))
            }
            "match_case"
                if matches!(self.language, Language::Ocaml)
                    && !is_ocaml_wildcard_match_case(node, self.source) =>
            {
                Some((1, "arm"))
            }
            "stab_clause"
                if matches!(self.language, Language::Elixir)
                    && !is_elixir_catchall_stab_clause(node, self.source) =>
            {
                Some((1, "case"))
            }
            _ => None,
        };

        if let Some((base, construct)) = base_increment {
            // Nesting penalty only applies to nested control structures.
            // The current_nesting is already incremented for this node, so we
            // use saturating_sub(1).
            // Exceptions per SonarSource spec (no nesting penalty):
            //   - ternary (?:)
            //   - `else if` — an if_statement that is a direct child of an
            //     else_clause; treated as a flat sibling of the parent if,
            //     not a nested construct.
            let is_else_if = construct == "if"
                && node
                    .parent()
                    .map(|p| p.kind() == "else_clause")
                    .unwrap_or(false);

            let nesting_increment =
                if construct != "?:" && !is_else_if && self.current_nesting > 1 {
                    self.current_nesting.saturating_sub(1)
                } else {
                    0
                };

            let total = base + nesting_increment;
            self.cognitive += total;
            self.nesting_penalty += nesting_increment;

            self.contributors.push(CognitiveContributor {
                line,
                construct: construct.to_string(),
                base_increment: base,
                nesting_increment,
                nesting_level: self.current_nesting,
            });
        }

        // Logical operators: +1 for sequence of same type, +1 when type changes
        if kind == "boolean_operator" || kind == "binary_expression" {
            if let Some(op) = self.get_logical_operator(node) {
                // Only add if different from previous or first in sequence
                let should_add = match &self.prev_logical_op {
                    None => true,              // First in sequence
                    Some(prev) => *prev != op, // Different operator
                };

                if should_add {
                    self.cognitive += 1;
                    self.contributors.push(CognitiveContributor {
                        line,
                        construct: op.clone(),
                        base_increment: 1,
                        nesting_increment: 0,
                        nesting_level: self.current_nesting,
                    });
                }

                self.prev_logical_op = Some(op);
            }
        }

        // Recursion: +1 for calling the same function
        if kind == "call" || kind == "call_expression" {
            if let Some(callee) = self.get_callee_name(node) {
                if callee == self.function_name {
                    self.cognitive += 1;
                    self.contributors.push(CognitiveContributor {
                        line,
                        construct: "recursion".to_string(),
                        base_increment: 1,
                        nesting_increment: 0,
                        nesting_level: self.current_nesting,
                    });
                }
            }
        }

        // Break/continue to label: +1 (not common in Python)
        if kind == "break_statement" || kind == "continue_statement" {
            // Check if it has a label (language specific)
            // For now, only count labeled breaks/continues
            if node.named_child_count() > 0 {
                self.cognitive += 1;
                self.contributors.push(CognitiveContributor {
                    line,
                    construct: if kind == "break_statement" {
                        "break_label"
                    } else {
                        "continue_label"
                    }
                    .to_string(),
                    base_increment: 1,
                    nesting_increment: 0,
                    nesting_level: self.current_nesting,
                });
            }
        }
    }

    /// Get logical operator from node
    fn get_logical_operator(&self, node: Node) -> Option<String> {
        if let Some(op_node) = node.child_by_field_name("operator") {
            let op_text = op_node.utf8_text(self.source.as_bytes()).ok()?;
            if matches!(op_text, "and" | "or" | "&&" | "||") {
                return Some(op_text.to_string());
            }
        }
        None
    }

    /// Count cyclomatic complexity increment (for comparison)
    fn count_cyclomatic_increment(&mut self, node: Node) {
        let kind = node.kind();

        match kind {
            "if_statement" | "if_expression" | "elif_clause" => self.cyclomatic += 1,
            "for_statement" | "for_in_statement" | "while_statement" => self.cyclomatic += 1,
            "except_clause" | "catch_clause" | "except_handler" => self.cyclomatic += 1,
            "case_clause" | "match_arm" | "switch_case" => self.cyclomatic += 1,
            "conditional_expression" | "ternary_expression" => self.cyclomatic += 1,
            // pattern-match-arm-undercount-v1: cyclomatic +1 per non-catchall
            // arm for c/cpp `case_statement`, kotlin `when_entry`, ocaml
            // `match_case`, elixir `stab_clause`. (rust `match_arm` /
            // scala `case_clause` already credited above.)
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
            // Loop/match expressions on Rust/Scala/Kotlin/OCaml.
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
            "when_expression" if matches!(self.language, Language::Kotlin) => {
                self.cyclomatic += 1
            }
            "do_while_statement" if matches!(self.language, Language::Kotlin) => {
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
            "boolean_operator" | "binary_expression"
                if self.get_logical_operator(node).is_some() => {
                    self.cyclomatic += 1;
                }
            _ => {}
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

    fn into_info(self) -> CognitiveInfo {
        CognitiveInfo {
            score: self.cognitive,
            nesting_penalty: self.nesting_penalty,
            threshold_violations: Vec::new(),
            contributors: if self.contributors.is_empty() {
                None
            } else {
                Some(self.contributors)
            },
        }
    }
}

/// Check if a node kind represents a statement
fn is_statement(kind: &str) -> bool {
    kind.ends_with("_statement") || kind.ends_with("_definition") || kind.ends_with("_declaration")
}

// pattern-match-arm-undercount-v1 (P19.BUG-01 family): helpers to detect
// catchall arms in each grammar so the cognitive walker can credit
// non-catchall arms only.

/// C / C++: a `case_statement` whose first child is the `default` keyword
/// is the catchall arm and is NOT credited.
fn is_default_case_statement(node: Node) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    cursor.node().kind() == "default"
}

/// Rust: a `match_arm` whose `match_pattern` child is a wildcard `_` is
/// the catchall arm and is NOT credited.
fn is_rust_wildcard_arm(node: Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if child.kind() == "match_pattern" {
            // A match_pattern containing a single wildcard `_` is the catchall.
            let mut pcursor = child.walk();
            if pcursor.goto_first_child() {
                let inner = pcursor.node();
                if inner.kind() == "_" {
                    return true;
                }
                let text = inner.utf8_text(source.as_bytes()).unwrap_or("");
                if text == "_" {
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

/// Scala: a `case_clause` whose pattern is a single `wildcard` is the
/// catchall arm and is NOT credited.
fn is_scala_wildcard_arm(node: Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        let kind = child.kind();
        // Skip the leading `case` keyword.
        if kind == "case" {
            if !cursor.goto_next_sibling() {
                return false;
            }
            continue;
        }
        if kind == "wildcard" {
            return true;
        }
        // The first non-`case` named child is the pattern; if it is
        // anything other than `wildcard`, this is a credited arm.
        // Every path in the loop returns or continues, so the loop itself
        // is the function's value; a trailing `false` was unreachable.
        let text = child.utf8_text(source.as_bytes()).unwrap_or("");
        return text == "_";
    }
}

/// Kotlin: a `when_entry` whose first child is the `else` token is the
/// catchall arm and is NOT credited.
fn is_kotlin_else_when_entry(node: Node) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        let kind = child.kind();
        if kind == "else" {
            return true;
        }
        // The first significant child decides; arrows / numbers / etc. mean not-else.
        if kind != "(" && kind != " " {
            return false;
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
    false
}

/// OCaml: a `match_case` whose first pattern child is a `value_pattern`
/// containing only `_` is the catchall arm and is NOT credited.
fn is_ocaml_wildcard_match_case(node: Node, source: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    let first = cursor.node();
    let kind = first.kind();
    if kind == "value_pattern" {
        let text = first.utf8_text(source.as_bytes()).unwrap_or("");
        if text == "_" {
            return true;
        }
    }
    false
}

/// Elixir: a `stab_clause` whose `arguments` child is a single
/// identifier `_` (or `true` in `cond`) is the catchall arm and is NOT
/// credited.
fn is_elixir_catchall_stab_clause(node: Node, source: &str) -> bool {
    // Locate the `arguments` child.
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

/// Merge multiple cognitive reports into one.
///
/// Combines functions from all reports, sorts by cognitive score descending,
/// applies top-N limit, rebuilds violations, and recalculates summary.
pub fn merge_cognitive_reports(
    reports: Vec<CognitiveReport>,
    options: &CognitiveOptions,
) -> CognitiveReport {
    if reports.is_empty() {
        return CognitiveReport {
            functions: vec![],
            violations: vec![],
            summary: CognitiveSummary::default(),
            warnings: vec![],
        };
    }

    // 1. Flatten all functions from all reports
    let mut functions: Vec<FunctionCognitive> = reports
        .iter()
        .flat_map(|r| r.functions.iter().cloned())
        .collect();

    // 2. Merge warnings from all reports
    let warnings: Vec<String> = reports.into_iter().flat_map(|r| r.warnings).collect();

    // 3. Sort by cognitive score descending
    functions.sort_by_key(|b| std::cmp::Reverse(b.cognitive));

    // 4. Apply top-N limit
    if options.top > 0 && functions.len() > options.top {
        functions.truncate(options.top);
    }

    // 5. Rebuild violations from the (potentially truncated) function list
    let violations: Vec<ViolationEntry> = functions
        .iter()
        .filter(|f| {
            f.threshold_status == ThresholdStatus::Violation
                || f.threshold_status == ThresholdStatus::Severe
        })
        .map(|f| ViolationEntry {
            name: f.name.clone(),
            file: f.file.clone(),
            line: f.line,
            cognitive: f.cognitive,
            severity: match f.threshold_status {
                ThresholdStatus::Severe => "severe".to_string(),
                ThresholdStatus::Violation => "violation".to_string(),
                _ => "warning".to_string(),
            },
        })
        .collect();

    // 6. Recalculate summary
    let summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    CognitiveReport {
        functions,
        violations,
        summary,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test simple function with no control flow (cognitive = 0)
    #[test]
    fn test_simple_function_zero_complexity() {
        let source = r#"
def simple_function(x, y):
    result = x + y
    return result
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "simple_function")
            .unwrap();
        assert_eq!(
            func.cognitive, 0,
            "Simple function should have cognitive = 0"
        );
    }

    /// Test single if statement (cognitive = 1)
    #[test]
    fn test_single_if() {
        let source = r#"
def check_positive(x):
    if x > 0:
        return True
    return False
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "check_positive")
            .unwrap();
        assert_eq!(func.cognitive, 1, "Single if should have cognitive = 1");
    }

    /// Test nested if (cognitive = 3: if=1 + nested_if=1+1_nesting)
    #[test]
    fn test_nested_if() {
        let source = r#"
def check_nested(x, y):
    if x > 0:
        if y > 0:
            return "both positive"
    return "not both positive"
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "check_nested")
            .unwrap();
        assert_eq!(
            func.cognitive, 3,
            "Nested if should have cognitive = 3 (1 + 1 + 1 nesting)"
        );
    }

    /// Test loop with nested condition (cognitive = 3)
    #[test]
    fn test_loop_with_nested_condition() {
        let source = r#"
def process_items(items):
    result = []
    for item in items:
        if item > 0:
            result.append(item)
    return result
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "process_items")
            .unwrap();
        assert_eq!(
            func.cognitive, 3,
            "Loop with nested if should have cognitive = 3"
        );
    }

    /// Test multiple functions are all analyzed
    #[test]
    fn test_multiple_functions() {
        let source = r#"
def simple():
    return 1

def with_if(x):
    if x:
        return x
    return 0

def with_nested(x, y):
    if x:
        if y:
            return x + y
    return 0

def complex_function(data, threshold, flag):
    result = 0
    for item in data:
        if item > threshold:
            if flag:
                while item > 0:
                    result += 1
                    item -= 1
            else:
                result -= 1
    return result
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        assert!(
            report.functions.len() >= 4,
            "Should analyze all 4 functions"
        );
    }

    /// Test threshold violations are detected
    #[test]
    fn test_threshold_violations() {
        let source = r#"
def complex_function(data, threshold, flag):
    result = 0
    for item in data:
        if item > threshold:
            if flag:
                while item > 0:
                    if result > 100:
                        result += 1
                    item -= 1
            else:
                result -= 1
        else:
            for x in range(10):
                if x > 5:
                    result += x
    return result
"#;
        let options = CognitiveOptions::new().with_threshold(5);
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        assert!(
            !report.violations.is_empty(),
            "Should detect threshold violations"
        );
    }

    /// Test that `else` adds +0 (linear flow) per SonarSource Cognitive
    /// Complexity v1.4. Only `if` and `elif` increment.
    #[test]
    fn test_else_not_counted() {
        let source = r#"
def with_else(x):
    if x > 0:
        return 1
    else:
        return -1
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "with_else")
            .unwrap();
        // if adds +1, else adds +0 (linear flow per SonarSource v1.4)
        assert_eq!(
            func.cognitive, 1,
            "else should NOT add to cognitive complexity per SonarSource v1.4"
        );
    }

    /// Test logical operators add complexity
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
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(source, Language::Python, "test.py", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "with_logic")
            .unwrap();
        // 2 ifs (each +1) + 2 logical operators (each +1) = 4
        assert!(func.cognitive >= 4, "Should count logical operators");
    }

    /// Test else-if chains don't double-count in JavaScript
    /// Per SonarSource Cognitive Complexity v1.4: `else` adds +0,
    /// `else if` adds +1 (not +2), so `if-else if-else` scores 2.
    #[test]
    fn test_else_if_no_double_count_javascript() {
        let js_code = r#"
function test(x) {
    if (x > 0) {       // +1
        return 1;
    } else if (x < 0) { // +1 (else-if: +1, NOT +2; else adds 0)
        return -1;
    } else {            // +0 (else is linear flow per SonarSource v1.4)
        return 0;
    }
}
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(js_code, Language::JavaScript, "test.js", &options).unwrap();

        let func = report.functions.iter().find(|f| f.name == "test").unwrap();
        assert_eq!(
            func.cognitive, 2,
            "if-else if-else should score 2 per SonarSource (if=+1, else-if=+1, else=+0)"
        );
    }

    /// Test else-if chains in TypeScript
    #[test]
    fn test_else_if_no_double_count_typescript() {
        let ts_code = r#"
function test(x: number): number {
    if (x > 0) {       // +1
        return 1;
    } else if (x < 0) { // +1 (NOT +2)
        return -1;
    } else {            // +0 (else is linear flow)
        return 0;
    }
}
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(ts_code, Language::TypeScript, "test.ts", &options).unwrap();

        let func = report.functions.iter().find(|f| f.name == "test").unwrap();
        assert_eq!(func.cognitive, 2, "if-else if-else should score 2");
    }

    /// Test else-if chains in Rust
    #[test]
    fn test_rust_else_if_scoring() {
        let rust_code = r#"
fn test(x: i32) -> i32 {
    if x > 0 {         // +1
        1
    } else if x < 0 {  // +1
        -1
    } else {            // +0
        0
    }
}
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(rust_code, Language::Rust, "test.rs", &options).unwrap();

        let func = report.functions.iter().find(|f| f.name == "test").unwrap();
        assert_eq!(func.cognitive, 2, "Rust if-else if-else should score 2");
    }

    /// Test Python elif still works correctly (already used elif_clause)
    #[test]
    fn test_python_elif_still_correct() {
        let py_code = r#"
def test(x):
    if x > 0:     # +1
        return 1
    elif x < 0:   # +1
        return -1
    else:          # +0 (else is linear flow per SonarSource v1.4)
        return 0
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(py_code, Language::Python, "test.py", &options).unwrap();

        let func = report.functions.iter().find(|f| f.name == "test").unwrap();
        assert_eq!(func.cognitive, 2, "Python if-elif-else should score 2");
    }

    /// Test multiple else-if chains
    #[test]
    fn test_multiple_else_if_chains() {
        let js_code = r#"
function classify(x) {
    if (x > 100) {      // +1
        return "high";
    } else if (x > 50) { // +1
        return "medium";
    } else if (x > 0) {  // +1
        return "low";
    } else {             // +0
        return "negative";
    }
}
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(js_code, Language::JavaScript, "test.js", &options).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.name == "classify")
            .unwrap();
        assert_eq!(
            func.cognitive, 3,
            "Multiple else-if should each score +1; else=0; total = 3"
        );
    }

    /// Test else-if in C language
    #[test]
    fn test_c_else_if_no_double_count() {
        let c_code = r#"
int test(int x) {
    if (x > 0) {       // +1
        return 1;
    } else if (x < 0) { // +1 (NOT +2)
        return -1;
    } else {            // +0
        return 0;
    }
}
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(c_code, Language::C, "test.c", &options).unwrap();

        let func = report.functions.iter().find(|f| f.name == "test").unwrap();
        assert_eq!(func.cognitive, 2, "C if-else if-else should score 2");
    }

    // -------------------------------------------------------------------------
    // Merge Cognitive Reports Tests
    // -------------------------------------------------------------------------

    /// Helper to create a synthetic FunctionCognitive for testing
    fn make_cognitive_function(
        name: &str,
        file: &str,
        line: u32,
        cognitive: u32,
    ) -> FunctionCognitive {
        FunctionCognitive {
            name: name.to_string(),
            file: file.to_string(),
            line,
            cognitive,
            cyclomatic: None,
            max_nesting: 0,
            nesting_penalty: 0,
            threshold_status: ThresholdStatus::from_score(
                cognitive,
                DEFAULT_THRESHOLD,
                DEFAULT_HIGH_THRESHOLD,
            ),
            contributors: None,
        }
    }

    /// Helper to create a synthetic CognitiveReport for testing
    fn make_cognitive_report(functions: Vec<FunctionCognitive>) -> CognitiveReport {
        let violations: Vec<ViolationEntry> = functions
            .iter()
            .filter(|f| f.cognitive >= DEFAULT_THRESHOLD)
            .map(|f| ViolationEntry {
                name: f.name.clone(),
                file: f.file.clone(),
                line: f.line,
                cognitive: f.cognitive,
                severity: if f.cognitive >= DEFAULT_HIGH_THRESHOLD {
                    "severe".to_string()
                } else {
                    "warning".to_string()
                },
            })
            .collect();
        let summary = calculate_summary(&functions, DEFAULT_THRESHOLD, DEFAULT_HIGH_THRESHOLD);
        CognitiveReport {
            functions,
            violations,
            summary,
            warnings: vec![],
        }
    }

    #[test]
    fn test_merge_cognitive_reports_combines_functions() {
        let report1 = make_cognitive_report(vec![
            make_cognitive_function("foo", "a.py", 1, 5),
            make_cognitive_function("bar", "a.py", 10, 20),
        ]);
        let report2 = make_cognitive_report(vec![make_cognitive_function("baz", "b.py", 1, 10)]);

        let options = CognitiveOptions::new();
        let merged = merge_cognitive_reports(vec![report1, report2], &options);

        assert_eq!(
            merged.functions.len(),
            3,
            "Merged report should contain all 3 functions from both reports"
        );

        // Verify all function names are present
        let names: Vec<&str> = merged.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"foo"), "Should contain 'foo'");
        assert!(names.contains(&"bar"), "Should contain 'bar'");
        assert!(names.contains(&"baz"), "Should contain 'baz'");
    }

    #[test]
    fn test_merge_cognitive_reports_recalculates_summary() {
        let report1 = make_cognitive_report(vec![
            make_cognitive_function("foo", "a.py", 1, 5),
            make_cognitive_function("bar", "a.py", 10, 20),
        ]);
        let report2 = make_cognitive_report(vec![make_cognitive_function("baz", "b.py", 1, 10)]);

        let options = CognitiveOptions::new();
        let merged = merge_cognitive_reports(vec![report1, report2], &options);

        // Summary should reflect all 3 functions
        assert_eq!(
            merged.summary.total_functions, 3,
            "Summary should count all 3 functions"
        );
        assert_eq!(
            merged.summary.total_cognitive, 35,
            "Total cognitive should be 5+20+10=35"
        );
        assert_eq!(
            merged.summary.max_cognitive, 20,
            "Max cognitive should be 20"
        );
    }

    #[test]
    fn test_merge_cognitive_reports_empty() {
        let options = CognitiveOptions::new();
        let merged = merge_cognitive_reports(vec![], &options);

        assert!(
            merged.functions.is_empty(),
            "Empty merge should have no functions"
        );
        assert!(
            merged.violations.is_empty(),
            "Empty merge should have no violations"
        );
        assert_eq!(
            merged.summary.total_functions, 0,
            "Empty merge should have 0 total_functions"
        );
    }
}
