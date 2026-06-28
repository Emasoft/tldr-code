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

use crate::ast::extract::decl_keyword_line_from_node;
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
    /// G-cognitive (v0.5.0 BACKLOG): set to `true` when the displayed
    /// `functions` list was truncated by `--top N`. Every statistic in this
    /// summary is ALWAYS aggregated over the full set of analyzed functions
    /// (not just the displayed top-N subset), so the numbers are invariant
    /// under `--top`; this flag merely signals that the per-function list is
    /// a prefix of the full ranking.
    #[serde(default)]
    pub truncated: bool,
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
    functions.sort_by(|a, b| b.cognitive.cmp(&a.cognitive));

    // G-cognitive (v0.5.0 BACKLOG): `--top N` is a DISPLAY limit only. Build
    // the violations list and the summary over ALL functions BEFORE
    // truncating the displayed list, so total_functions / avg_cognitive /
    // compliance_rate (and the rest of the summary) stay invariant under
    // `--top`. Truncating first made every aggregate reflect only the
    // top-N subset.
    let violations = build_violation_entries(&functions);
    let mut summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    // Apply the top limit to the displayed function list only.
    let truncated = options.top > 0 && functions.len() > options.top;
    if truncated {
        functions.truncate(options.top);
    }
    summary.truncated = truncated;

    Ok(CognitiveReport {
        functions,
        violations,
        summary,
        warnings: Vec::new(),
    })
}

/// Build the `ViolationEntry` list for a set of analyzed functions.
///
/// G-cognitive (v0.5.0 BACKLOG): factored out of the three report builders
/// (`analyze_cognitive`, `analyze_cognitive_source`, `merge_cognitive_reports`)
/// so all of them aggregate violations over the FULL function set before any
/// `--top N` display truncation is applied.
fn build_violation_entries(functions: &[FunctionCognitive]) -> Vec<ViolationEntry> {
    functions
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
        .collect()
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
    functions.sort_by(|a, b| b.cognitive.cmp(&a.cognitive));

    // G-cognitive (v0.5.0 BACKLOG): aggregate violations + summary over ALL
    // functions BEFORE applying the `--top N` display limit (see
    // `analyze_cognitive` for the rationale).
    let violations = build_violation_entries(&functions);
    let mut summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    // Apply the top limit to the displayed function list only.
    let truncated = options.top > 0 && functions.len() > options.top;
    if truncated {
        functions.truncate(options.top);
    }
    summary.truncated = truncated;

    Ok(CognitiveReport {
        functions,
        violations,
        summary,
        warnings: Vec::new(),
    })
}

/// v0.5.0 CL-10 (GH #81): return the 1-indexed decl-keyword line for a
/// function/method `node`, normalising past leading annotation/attribute/
/// modifier children for the grammars that emit them. For all other
/// languages the helper returns the bare `node.start_position()` line
/// (`decl_keyword_line_from_node` is a no-op when the first child already
/// IS the decl keyword), so the gate only changes behaviour where a real
/// drift exists.
///
/// The language gate is kept identical to
/// `ast::extractor::collect_definitions` so `cognitive` agrees with
/// `structure` / `extract` / `explain` / `slice` on the reported line.
fn decl_keyword_line_for(node: Node, language: Language) -> u32 {
    if matches!(
        language,
        Language::Java
            | Language::Solidity
            | Language::Swift
            | Language::Kotlin
            | Language::Scala
            | Language::CSharp
    ) {
        decl_keyword_line_from_node(&node)
    } else {
        node.start_position().row as u32 + 1
    }
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
                    // v0.5.0 CL-10 (GH #81): route the reported line through
                    // `decl_keyword_line_from_node` for grammars that emit
                    // leading annotation/attribute/modifier children
                    // (Java `@Override`, Swift `@inlinable`, C# `[Test]`,
                    // …). Without this the bare `node.start_position()`
                    // anchored cognitive's line to the annotation line while
                    // `extract` / `structure` reported the decl-keyword line
                    // for the SAME symbol — a cross-pipeline drift.
                    line: decl_keyword_line_for(node, language),
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

    // M-037 fix: key `existing` by (name, line) not just name, so that
    // overloaded methods sharing a name but defined at different lines are
    // each treated as distinct candidates.  Previously, once the first
    // `ReadElementAsync` (line 46) was found by the AST walker, the second
    // overload (line 58) was silently skipped here — leaving cognitive with
    // fewer functions than halstead (which uses `extract_file` and deduplicates
    // by (name, file, line) rather than by name alone).
    let existing: std::collections::HashSet<(String, u32)> =
        functions.iter().map(|f| (f.name.clone(), f.line)).collect();

    // R7 BUG[7] (v0.5.0 CLOSEOUT): `extract_file` emits a JS *named function
    // expression* (`var Foo = function Foo(){}` / `Obj.x = function Foo(){}`)
    // TWICE in `module.functions` with identical (name, line_number) — once for
    // the variable/property binding and once for the named-expression
    // identifier (verified on firebug-lite-debug.js: FirebugConsoleHandler@23054,
    // getMembers@30365, onListMouseMove@24771 each appear x2). Without a
    // self-dedup the augment loop below pushed a byte-identical
    // `FunctionCognitive` per copy (50 entries / 47 unique on that file). The
    // deeper extract double-emit is a structure-cluster defect (extract.rs); we
    // add a safe idempotent guard here keyed on (name, line) so the cognitive
    // augment is duplicate-free regardless of extractor behavior. Keying on the
    // LINE as well as the name preserves legitimate same-name overloads defined
    // at different lines. `seen` is seeded with the AST-walker output
    // (`existing`) so a candidate already produced there is never re-added.
    let mut seen: std::collections::HashSet<(String, u32)> = existing.clone();
    let mut candidates: Vec<(String, u32)> = Vec::new();
    for f in &module.functions {
        if seen.insert((f.name.clone(), f.line_number)) {
            candidates.push((f.name.clone(), f.line_number));
        }
    }
    for class in &module.classes {
        for m in &class.methods {
            if seen.insert((m.name.clone(), m.line_number)) {
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
        // Aggregated over ALL functions; callers set `truncated` after they
        // apply the `--top N` display limit (G-cognitive).
        truncated: false,
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
                // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101) Java for-each.
                | "enhanced_for_statement"
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
            // solidity-metrics-v1 (v0.5.0 SOL-008): tree-sitter-solidity
            // exposes do-while loops as `do_while_statement` (same kind as
            // Kotlin). The generic arm in `increases_nesting` covers
            // `if_statement` / `for_statement` / `while_statement` /
            // `try_statement` / `catch_clause`, so those are already
            // nesting-counted; we only need to add `do_while_statement`
            // here so the inner-of-do-while body gets a nesting penalty.
            Language::Solidity => {
                if matches!(kind, "do_while_statement") {
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
            // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): tree-sitter-c-sharp
            // spells its for-each loop `foreach_statement` (distinct from the
            // classical three-part `for_statement`), and its switch arms as
            // `switch_section` children under a `switch_body`. The generic arm
            // already credits `switch_statement` / `switch_body` for nesting,
            // but NOT `switch_section` — without it a `foreach` nested in a
            // case body sat at the same nesting level as the switch and earned
            // no SonarSource nesting penalty. Crediting `switch_section` makes
            // each case arm a nesting step, so loops/branches inside a case
            // body are correctly penalised. `foreach_statement` makes the
            // for-each body a nesting step too (mirrors `for_statement`).
            Language::CSharp => {
                if matches!(kind, "foreach_statement" | "switch_section") {
                    return true;
                }
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
        // R7 RC4 (v0.5.0 CLOSEOUT): an `else if` rung is a flat sibling of the
        // parent `if`, NOT a nested construct (SonarSource Cognitive
        // Complexity v1.4). The penalty-suppression for the rung's OWN score
        // already exists (`is_else_if` in count_cognitive_increment), but the
        // nesting tracker still climbed for each rung, so a construct
        // genuinely nested inside an else-if branch accumulated phantom depth
        // (debugCommand: max_nesting=50 / nesting_penalty=1607 for real brace
        // depth 4). Do not raise nesting for an else-if `if`. Verified via
        // dumper: in C/C++/Java/JS/TS an `else if` parses as
        // `else_clause -> if_statement`; in Rust as `else_clause ->
        // if_expression`. (Python/Ruby use distinct flat `elif_clause`/`elsif`
        // and never reach this branch.)
        if matches!(node.kind(), "if_statement" | "if_expression") && self.node_is_else_if(node) {
            return false;
        }

        // R7 RC3 (v0.5.0 CLOSEOUT): tree-sitter-ruby emits a NAMED construct
        // node (`if`/`unless`/`while`/`case`/...) that CONTAINS an UNNAMED
        // keyword-token child of the SAME kind. The recursive walker visits
        // unnamed children, so the bare keyword token would ALSO match the
        // Ruby arm in `increases_nesting` and inflate nesting (a flat
        // `return [] unless x` reported max_nesting=2 instead of 1). Only the
        // named construct node represents real nesting; suppress the climb for
        // the unnamed keyword leaf. Verified via dumper: the construct is
        // is_named()=true and the keyword leaf is_named()=false.
        if matches!(self.language, Language::Ruby) && !node.is_named() {
            return false;
        }

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

    /// R7 RC4 (v0.5.0 CLOSEOUT): detect an `else if` rung — an `if` whose
    /// direct parent is an `else_clause`. This is the same predicate the
    /// cognitive scorer already uses to zero an else-if rung's nesting penalty
    /// (`count_cognitive_increment`, the `is_else_if` local), lifted here so
    /// the nesting *tracker* agrees with the score. Applies to the brace
    /// languages whose `else if` nests structurally (C/C++/Java/JS/TS) and to
    /// Rust's `else_clause -> if_expression`.
    fn node_is_else_if(&self, node: Node) -> bool {
        node.parent()
            .map(|p| p.kind() == "else_clause")
            .unwrap_or(false)
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

        // R7 RC3 (v0.5.0 CLOSEOUT): tree-sitter-ruby emits a NAMED construct
        // node (`if`/`unless`/`when`/...) that CONTAINS an UNNAMED keyword
        // token of the SAME kind. The Ruby `base_increment` arms below match
        // on `kind` only, so the bare keyword token double-counted every Ruby
        // control structure (e.g. a flat `if/else` scored 3, not 1). Only the
        // named construct node is a real control structure; skip the unnamed
        // keyword leaf. The named operator nodes used by the `&&`/`||` and
        // recursion logic below are unaffected (they are is_named()=true).
        if matches!(self.language, Language::Ruby) && !node.is_named() {
            return;
        }

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
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101) Java for-each.
            "enhanced_for_statement" => Some((1, "for")),
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
            // Kotlin do-while; Solidity also exposes `do_while_statement`.
            // solidity-metrics-v1 (v0.5.0 SOL-008): credit Solidity do-while
            // as a +1 cognitive base + nesting penalty (matches the loop
            // construct semantics).
            "do_while_statement"
                if matches!(self.language, Language::Kotlin | Language::Solidity) =>
            {
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
            // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): C# for-each loop. The
            // generic `for_statement` arm above does not match it
            // (tree-sitter-c-sharp uses a distinct `foreach_statement` kind),
            // so a `foreach` earned zero cognitive credit. Credit it as a loop
            // (+1 base + nesting penalty), matching the SonarSource treatment
            // of `for`/`while`.
            "foreach_statement" if matches!(self.language, Language::CSharp) => {
                Some((1, "for"))
            }
            // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): each non-`default`
            // `switch_section` is a case arm. SonarSource credits the switch
            // construct once (the `switch_statement` arm above) and we extend
            // with +1 per case arm so a branchy `switch` surfaces a meaningful
            // cognitive score (mirrors the c/cpp `case_statement` and
            // rust/scala/kotlin per-arm credit). The `default` section is the
            // catchall and is NOT credited.
            "switch_section"
                if matches!(self.language, Language::CSharp)
                    && !is_csharp_default_switch_section(node) =>
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

        // R7 RC3 (v0.5.0 CLOSEOUT): skip Ruby's unnamed keyword-token children
        // so the bare `if`/`unless`/`when`/... token does not double-count the
        // construct (see count_cognitive_increment for the full rationale).
        if matches!(self.language, Language::Ruby) && !node.is_named() {
            return;
        }

        match kind {
            "if_statement" | "if_expression" | "elif_clause" => self.cyclomatic += 1,
            "for_statement" | "for_in_statement" | "while_statement" => self.cyclomatic += 1,
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101) Java for-each.
            "enhanced_for_statement" => self.cyclomatic += 1,
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
            // R7 RC1 (v0.5.0 CLOSEOUT): keep this module's `--include-cyclomatic`
            // counter byte-for-byte in step with the canonical `complexity.rs`
            // cyclomatic arms added in R7 — each non-`default` Swift
            // `switch_entry` is a decision arm and each `guard_statement` is a
            // binary decision. (cognitive SCORING of Swift switch/guard is
            // intentionally unchanged — only cyclomatic was the audited defect.)
            "switch_entry"
                if matches!(self.language, Language::Swift)
                    && !is_swift_default_switch_entry(node) =>
            {
                self.cyclomatic += 1
            }
            "guard_statement" if matches!(self.language, Language::Swift) => {
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
            // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): keep the cognitive
            // module's own cyclomatic counter (`tldr cognitive
            // --include-cyclomatic`) byte-for-byte in step with the canonical
            // `complexity.rs` arm-set added in cl4-cyclomatic-v1 — each
            // non-`default` `switch_section` and each `foreach_statement` is a
            // C# decision point / loop back-edge.
            "switch_section"
                if matches!(self.language, Language::CSharp)
                    && !is_csharp_default_switch_section(node) =>
            {
                self.cyclomatic += 1
            }
            "foreach_statement" if matches!(self.language, Language::CSharp) => {
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
            "do_while_statement"
                if matches!(self.language, Language::Kotlin | Language::Solidity) =>
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
            "boolean_operator" | "binary_expression" => {
                if self.get_logical_operator(node).is_some() {
                    self.cyclomatic += 1;
                }
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
///
/// Exposed `pub(crate)` so the canonical cyclomatic counter in
/// `complexity.rs` (R7 RC1) can reuse the exact same catchall predicate when
/// crediting C/C++ `case_statement` decision points — keeping cyclomatic and
/// cognitive in agreement on which switch arms are decision points.
pub(crate) fn is_default_case_statement(node: Node) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    cursor.node().kind() == "default"
}

/// R7 RC1 (v0.5.0 CLOSEOUT): Swift — a `switch_entry` whose leading child is a
/// `default_keyword` node is the catchall arm and is NOT a decision point
/// (mirrors the C/C++ and C# `default` conventions).
///
/// Grammar shape (verified via tree-sitter-swift 0.7.1 dumper):
/// ```text
/// switch_entry            ← `case 1: ...`
///   case                  (unnamed keyword token)
///   switch_pattern ...
/// switch_entry            ← `default: ...`
///   default_keyword       (named)
///   ...
/// ```
/// A normal arm leads with the unnamed `case` token; the catchall leads with
/// the named `default_keyword`. Exposed `pub(crate)` so both the canonical
/// cyclomatic counter (`complexity.rs`) and this module's
/// `--include-cyclomatic` counter credit the same Swift switch arms.
pub(crate) fn is_swift_default_switch_entry(node: Node) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        match cursor.node().kind() {
            "default_keyword" => return true,
            // Stop at the pattern/body so we only inspect the leading marker.
            "switch_pattern" | "statements" => return false,
            _ => {}
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
    false
}

/// C#: a `switch_section` whose first child is the `default` keyword is the
/// catchall arm and is NOT credited (mirrors the C/C++ `default` convention).
///
/// Grammar shape (verified against tree-sitter-c-sharp 0.23.1):
/// ```text
/// switch_body
///   switch_section          ← `case <pattern>: ...`
///     case
///     constant_pattern | ...
///     :
///     <statements | block>
///   switch_section          ← `default: ...`
///     default
///     :
///     <statements>
/// ```
fn is_csharp_default_switch_section(node: Node) -> bool {
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
        let text = child.utf8_text(source.as_bytes()).unwrap_or("");
        return text == "_";
    }
    false
}

/// Kotlin: a `when_entry` whose first child is the `else` token is the
/// catchall arm and is NOT credited.
///
/// cl4-cyclomatic-v1 (GH #75): exposed `pub(crate)` so the cyclomatic
/// calculator in `complexity.rs` reuses the SAME catchall-detection logic
/// (single source of truth — the cognitive walker is the proven reference).
pub(crate) fn is_kotlin_else_when_entry(node: Node) -> bool {
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
///
/// cl4-cyclomatic-v1 (GH #75): exposed `pub(crate)` so `complexity.rs`
/// reuses the SAME catchall-detection logic as the cognitive walker.
pub(crate) fn is_ocaml_wildcard_match_case(node: Node, source: &str) -> bool {
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
    functions.sort_by(|a, b| b.cognitive.cmp(&a.cognitive));

    // 4. G-cognitive (v0.5.0 BACKLOG): rebuild violations and recalculate the
    //    summary over ALL merged functions BEFORE the `--top N` display
    //    truncation, so the directory-level aggregates are invariant under
    //    `--top` (they previously reflected only the top-N subset).
    let violations = build_violation_entries(&functions);
    let mut summary = calculate_summary(&functions, options.threshold, options.high_threshold);

    // 5. Apply the top-N limit to the displayed function list only.
    let truncated = options.top > 0 && functions.len() > options.top;
    if truncated {
        functions.truncate(options.top);
    }
    summary.truncated = truncated;

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

    // =====================================================================
    // R7 complexity-metrics (v0.5.0 CLOSEOUT) characterization tests.
    //
    // RC4: `else if` ladders must NOT inflate max_nesting or the cognitive
    //      nesting penalty. Each else-if rung is a flat sibling of the parent
    //      `if` (SonarSource v1.4), so a construct genuinely nested inside an
    //      else-if branch must see only its TRUE depth.
    // RC3: Ruby control constructs (and their nesting) must not be
    //      double-counted against their own unnamed keyword-token children.
    //
    // Cross-language reference (verified live): a single flat guard `if` in
    // Python and C reports max_nesting=1; a genuinely nested if reports
    // max_nesting=2. Ruby must match (it was reporting 2 for a flat guard).
    // =====================================================================

    /// RC4: a genuinely-nested `if` inside an else-if ladder must reflect only
    /// its true depth, not the phantom depth of the else-if rungs above it.
    #[test]
    fn test_else_if_ladder_does_not_inflate_nesting() {
        let c_code = r#"
int classify(int x) {
    if (x == 1) {
        return 1;
    } else if (x == 2) {
        return 2;
    } else if (x == 3) {
        if (x > 0) {       // genuinely nested: true depth 2
            return 30;
        }
        return 3;
    } else {
        return 0;
    }
}
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(c_code, Language::C, "test.c", &options).unwrap();
        let func = report
            .functions
            .iter()
            .find(|f| f.name == "classify")
            .unwrap();
        // 4 if-rungs (base +1 each) + the nested if gains +1 nesting penalty
        // (true depth 2) => 4 + 1 = 5. Was 7 (3 phantom rungs added).
        assert_eq!(
            func.cognitive, 5,
            "else-if ladder cognitive should be 5 (4 base + 1 real nesting), got {}",
            func.cognitive
        );
        // Deepest TRUE nesting: outer ladder at level 1, nested if at level 2.
        assert_eq!(
            func.max_nesting, 2,
            "else-if ladder max_nesting should be the real depth 2, got {}",
            func.max_nesting
        );
        // Only the genuinely-nested if contributes a nesting penalty.
        assert_eq!(
            func.nesting_penalty, 1,
            "else-if ladder nesting_penalty should be 1, got {}",
            func.nesting_penalty
        );
    }

    /// RC4: flat else-if chains (no genuinely-nested constructs) keep their
    /// existing correct score AND now report a flat max_nesting of 1.
    #[test]
    fn test_flat_else_if_chain_nesting_is_one() {
        let js_code = r#"
function classify(x) {
    if (x > 100) {
        return "high";
    } else if (x > 50) {
        return "medium";
    } else if (x > 0) {
        return "low";
    } else {
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
        // Score unchanged: 3 (if + 2 else-if, each +1).
        assert_eq!(func.cognitive, 3, "flat else-if score stays 3");
        // All rungs are flat siblings -> max nesting depth 1.
        assert_eq!(
            func.max_nesting, 1,
            "flat else-if max_nesting should be 1, got {}",
            func.max_nesting
        );
        assert_eq!(
            func.nesting_penalty, 0,
            "flat else-if has no nesting penalty, got {}",
            func.nesting_penalty
        );
    }

    /// RC4: a loop nested two levels deep inside else-if branches earns the
    /// penalty for its TRUE depth, not the inflated rung depth.
    #[test]
    fn test_nested_loop_inside_else_if_true_depth() {
        let c_code = r#"
int f(int x, int n) {
    if (x == 1) {
        return 1;
    } else if (x == 2) {
        for (int i = 0; i < n; i++) {   // true depth 2
            if (i > 5) {                 // true depth 3
                return i;
            }
        }
    }
    return 0;
}
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(c_code, Language::C, "test.c", &options).unwrap();
        let func = report.functions.iter().find(|f| f.name == "f").unwrap();
        // With the else-if rung NOT bumping nesting (RC4): the for body sits at
        // true depth 2 and the inner if at true depth 3.
        //   if(x==1)      : base 1, nesting 0          -> 1
        //   else if(x==2) : base 1 (flat sibling)      -> 1
        //   for  (depth 2): base 1 + nesting 1         -> 2
        //   if(i>5)(depth3): base 1 + nesting 2        -> 3
        // total = 1 + 1 + 2 + 3 = 7. (Pre-fix the phantom else-if rung pushed
        // these deeper, inflating the score.)
        assert_eq!(
            func.cognitive, 7,
            "nested loop inside else-if cognitive should be 7, got {}",
            func.cognitive
        );
        assert_eq!(
            func.max_nesting, 3,
            "nested loop inside else-if max_nesting should be 3, got {}",
            func.max_nesting
        );
    }

    /// RC3: a flat Ruby guard (`return ... unless cond`) must report
    /// max_nesting=1 (matching Python/C flat guards), not 2.
    #[test]
    fn test_ruby_flat_unless_modifier_nesting_not_doubled() {
        let rb_code = r#"
def find_similar(target)
  return [] unless defined?(SpellChecker)
  target
end
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(rb_code, Language::Ruby, "t.rb", &options).unwrap();
        let func = report
            .functions
            .iter()
            .find(|f| f.name == "find_similar")
            .unwrap();
        assert_eq!(
            func.max_nesting, 1,
            "Ruby flat unless-modifier max_nesting should be 1 (like Python/C), got {}",
            func.max_nesting
        );
        // Cognitive: the guard is one control structure -> +1.
        assert_eq!(
            func.cognitive, 1,
            "Ruby flat unless-modifier cognitive should be 1, got {}",
            func.cognitive
        );
    }

    /// RC3: a flat Ruby `if/else` must report max_nesting=1, not 2.
    #[test]
    fn test_ruby_flat_if_else_nesting_not_doubled() {
        let rb_code = r#"
def interpret(x)
  if x == 1
    10
  else
    20
  end
end
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(rb_code, Language::Ruby, "t.rb", &options).unwrap();
        let func = report.functions.iter().find(|f| f.name == "interpret").unwrap();
        assert_eq!(
            func.max_nesting, 1,
            "Ruby flat if/else max_nesting should be 1, got {}",
            func.max_nesting
        );
    }

    /// RC3: a genuinely nested Ruby if (if inside if) reports max_nesting=2.
    #[test]
    fn test_ruby_nested_if_true_depth_two() {
        let rb_code = r#"
def nested(x, y)
  if x
    if y
      return 1
    end
  end
  0
end
"#;
        let options = CognitiveOptions::new();
        let report = analyze_cognitive_source(rb_code, Language::Ruby, "t.rb", &options).unwrap();
        let func = report.functions.iter().find(|f| f.name == "nested").unwrap();
        assert_eq!(
            func.max_nesting, 2,
            "Ruby genuinely-nested if max_nesting should be 2, got {}",
            func.max_nesting
        );
    }

    /// Cross-language anchor: Python flat guard reports max_nesting=1.
    /// Locks the reference value the Ruby fix is calibrated against.
    #[test]
    fn test_python_flat_guard_nesting_reference() {
        let py_code = r#"
def guard(x):
    if not x:
        return []
    return x
"#;
        let options = CognitiveOptions::new();
        let report =
            analyze_cognitive_source(py_code, Language::Python, "t.py", &options).unwrap();
        let func = report.functions.iter().find(|f| f.name == "guard").unwrap();
        assert_eq!(func.max_nesting, 1, "Python flat guard max_nesting is 1");
    }

    /// R7 BUG[7] (v0.5.0 CLOSEOUT): the file-based cognitive report (which runs
    /// `augment_cognitive_with_extractor_functions`) must never contain
    /// duplicate `(name, line)` entries — `extract_file` can emit a JS named
    /// function expression twice, and the augment loop must self-dedup.
    ///
    /// The extract double-emit is an interaction effect that only surfaces on
    /// large files (it is NOT minimally reproducible — see the audit), so this
    /// test cannot force the dup. It instead pins the structural invariant on a
    /// JS file rich in named function expressions: the augment dedup guarantees
    /// the report is duplicate-free regardless of extractor behavior.
    #[test]
    fn test_js_cognitive_no_duplicate_name_line_entries() {
        use std::io::Write;
        let js = r#"
var Foo = function Foo(a, b) {
    if (a && b) { return 1; }
    return 0;
};
var obj = {};
obj.handler = function handler(e) {
    if (e) { return e; }
    return null;
};
Lib.Mod.onMove = function onMove(x) {
    try { return x; } catch (err) { return 0; }
};
function plain(z) {
    return z > 0 ? 1 : 0;
}
"#;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("r7_bug7_dedup_{}.js", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(js.as_bytes()).unwrap();
        }
        let options = CognitiveOptions::new();
        let report = analyze_cognitive(&path, &options).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut seen: std::collections::HashSet<(String, u32)> =
            std::collections::HashSet::new();
        for f in &report.functions {
            assert!(
                seen.insert((f.name.clone(), f.line)),
                "duplicate (name,line) in cognitive report: {} @ {}",
                f.name,
                f.line
            );
        }
    }

    // =====================================================================
    // G-cognitive (v0.5.0 BACKLOG): `--top N` is a DISPLAY limit only.
    //
    // The whole summary (total_functions / total_cognitive / avg_cognitive /
    // max_cognitive / violations_count / severe_violations_count /
    // compliance_rate) plus the violations list MUST be invariant under
    // `--top`. The pre-fix code truncated the function vector BEFORE
    // aggregating, so every statistic reflected only the top-N subset
    // (witness: kotlin-coroutines reported total_functions=50/avg=26.46 at
    // --top 50 vs total_functions=7260/avg=0.86 at --top 0).
    //
    // Symptom class = ALL languages: this is a language-agnostic
    // post-processing bug, so the anti-treadmill gate asserts invariance
    // across a broad cross-language matrix — a single-language test is a FAIL.
    // =====================================================================

    /// Emit one trivial (`cognitive == 0`) or one deeply-nested
    /// (`cognitive == 6`) function for `lang`. Three-deep nested `if`s exceed
    /// the test thresholds (violation @ 2, severe @ 5) in every grammar.
    fn g_cognitive_make_fn(lang: Language, name: &str, complex: bool) -> String {
        match lang {
            Language::Python => {
                if complex {
                    format!("def {name}(a):\n    if a:\n        if a:\n            if a:\n                return 1\n    return 0\n\n")
                } else {
                    format!("def {name}(a):\n    return a\n\n")
                }
            }
            Language::Ruby => {
                if complex {
                    format!("def {name}(a)\n  if a\n    if a\n      if a\n        return 1\n      end\n    end\n  end\n  0\nend\n\n")
                } else {
                    format!("def {name}(a)\n  a\nend\n\n")
                }
            }
            Language::Rust => {
                if complex {
                    format!("fn {name}(a: bool) -> i32 {{\n    if a {{\n        if a {{\n            if a {{\n                return 1;\n            }}\n        }}\n    }}\n    0\n}}\n\n")
                } else {
                    format!("fn {name}(a: i32) -> i32 {{\n    a\n}}\n\n")
                }
            }
            Language::Kotlin => {
                if complex {
                    format!("fun {name}(a: Boolean): Int {{\n    if (a) {{\n        if (a) {{\n            if (a) {{\n                return 1\n            }}\n        }}\n    }}\n    return 0\n}}\n\n")
                } else {
                    format!("fun {name}(a: Int): Int {{\n    return a\n}}\n\n")
                }
            }
            Language::Go => {
                if complex {
                    format!("func {name}(a bool) int {{\n\tif a {{\n\t\tif a {{\n\t\t\tif a {{\n\t\t\t\treturn 1\n\t\t\t}}\n\t\t}}\n\t}}\n\treturn 0\n}}\n\n")
                } else {
                    format!("func {name}(a int) int {{\n\treturn a\n}}\n\n")
                }
            }
            Language::Java => {
                // Emitted inside `class C { ... }` (see g_cognitive_wrap).
                if complex {
                    format!("  int {name}(boolean a) {{\n    if (a) {{\n      if (a) {{\n        if (a) {{\n          return 1;\n        }}\n      }}\n    }}\n    return 0;\n  }}\n")
                } else {
                    format!("  int {name}(int a) {{\n    return a;\n  }}\n")
                }
            }
            Language::CSharp => {
                // Emitted inside `class C { ... }` (see g_cognitive_wrap).
                if complex {
                    format!("  int {name}(bool a) {{\n    if (a) {{\n      if (a) {{\n        if (a) {{\n          return 1;\n        }}\n      }}\n    }}\n    return 0;\n  }}\n")
                } else {
                    format!("  int {name}(int a) {{\n    return a;\n  }}\n")
                }
            }
            Language::Swift => {
                if complex {
                    format!("func {name}(a: Bool) -> Int {{\n    if a {{\n        if a {{\n            if a {{\n                return 1\n            }}\n        }}\n    }}\n    return 0\n}}\n\n")
                } else {
                    format!("func {name}(a: Int) -> Int {{\n    return a\n}}\n\n")
                }
            }
            Language::Scala => {
                // Emitted inside `object O { ... }` (see g_cognitive_wrap).
                if complex {
                    format!("  def {name}(a: Boolean): Int = {{\n    if (a) {{\n      if (a) {{\n        if (a) {{\n          return 1\n        }}\n      }}\n    }}\n    0\n  }}\n")
                } else {
                    format!("  def {name}(a: Int): Int = {{\n    a\n  }}\n")
                }
            }
            Language::Lua | Language::Luau => {
                if complex {
                    format!("function {name}(a)\n    if a then\n        if a then\n            if a then\n                return 1\n            end\n        end\n    end\n    return 0\nend\n\n")
                } else {
                    format!("function {name}(a)\n    return a\nend\n\n")
                }
            }
            Language::Elixir => {
                // Emitted inside `defmodule M do ... end` (see g_cognitive_wrap).
                // NB: this grammar's `if` does not raise cognitive; the
                // invariance still holds via total_functions (see test body).
                if complex {
                    format!("  def {name}(a) do\n    if a do\n      if a do\n        if a do\n          1\n        end\n      end\n    end\n  end\n\n")
                } else {
                    format!("  def {name}(a) do\n    a\n  end\n\n")
                }
            }
            Language::Ocaml => {
                if complex {
                    format!("let {name} a =\n  if a then\n    if a then\n      if a then 1 else 0\n    else 0\n  else 0\n\n")
                } else {
                    format!("let {name} a = a\n\n")
                }
            }
            Language::Solidity => {
                // Emitted inside `contract C {{ ... }}` (see g_cognitive_wrap).
                if complex {
                    format!("  function {name}(bool a) public pure returns (uint) {{\n    if (a) {{\n      if (a) {{\n        if (a) {{\n          return 1;\n        }}\n      }}\n    }}\n    return 0;\n  }}\n")
                } else {
                    format!("  function {name}(uint a) public pure returns (uint) {{\n    return a;\n  }}\n")
                }
            }
            // Brace-and-semicolon C-family: JavaScript, TypeScript, C, C++, PHP.
            _ => {
                let sig = match lang {
                    Language::JavaScript | Language::TypeScript => {
                        format!("function {name}(a)")
                    }
                    Language::Php => format!("function {name}($a)"),
                    _ => format!("int {name}(int a)"), // C / C++
                };
                if complex {
                    format!("{sig} {{\n    if (a) {{\n        if (a) {{\n            if (a) {{\n                return 1;\n            }}\n        }}\n    }}\n    return 0;\n}}\n\n")
                } else {
                    format!("{sig} {{\n    return a;\n}}\n\n")
                }
            }
        }
    }

    /// Wrap a concatenation of function definitions in the per-language
    /// compilation-unit shell required for the grammar to parse them.
    fn g_cognitive_wrap(lang: Language, body: &str) -> String {
        match lang {
            Language::Go => format!("package main\n\n{body}"),
            Language::Php => format!("<?php\n{body}"),
            Language::Java | Language::CSharp => format!("class C {{\n{body}}}\n"),
            Language::Scala => format!("object O {{\n{body}}}\n"),
            Language::Elixir => format!("defmodule M do\n{body}end\n"),
            Language::Solidity => format!("contract C {{\n{body}}}\n"),
            _ => body.to_string(),
        }
    }

    #[test]
    fn g_cognitive_top_n_does_not_affect_summary_stats_all_languages() {
        // Every language in the symptom class ("all"). The truncate/aggregate
        // path under test has ZERO language branching, so this matrix exercises
        // the full Language enum to prove the fix is genuinely language-agnostic.
        let langs = [
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Rust,
            Language::Go,
            Language::Java,
            Language::Kotlin,
            Language::C,
            Language::Cpp,
            Language::Ruby,
            Language::Php,
            Language::Swift,
            Language::CSharp,
            Language::Scala,
            Language::Lua,
            Language::Luau,
            Language::Elixir,
            Language::Ocaml,
            Language::Solidity,
        ];

        for lang in langs {
            // 3 trivial (cognitive 0) + 2 nested (cognitive 6) functions.
            let mut body = String::new();
            for n in ["s0", "s1", "s2"] {
                body.push_str(&g_cognitive_make_fn(lang, n, false));
            }
            for n in ["c0", "c1"] {
                body.push_str(&g_cognitive_make_fn(lang, n, true));
            }
            let source = g_cognitive_wrap(lang, &body);

            // Thresholds chosen so the trivial functions are OK and the nested
            // pair are both Severe violations.
            let full_opts = CognitiveOptions::new()
                .with_threshold(2)
                .with_high_threshold(5)
                .with_top(0);
            let top_opts = CognitiveOptions::new()
                .with_threshold(2)
                .with_high_threshold(5)
                .with_top(2);

            let full = analyze_cognitive_source(&source, lang, "g_cognitive.in", &full_opts)
                .unwrap_or_else(|e| panic!("{lang:?}: analyze (full) failed: {e}"));
            let topn = analyze_cognitive_source(&source, lang, "g_cognitive.in", &top_opts)
                .unwrap_or_else(|e| panic!("{lang:?}: analyze (top) failed: {e}"));

            // Template-breakage guard: all five functions must parse.
            assert!(
                full.summary.total_functions >= 5,
                "{lang:?}: expected >=5 functions parsed, got {}\n--- source ---\n{source}",
                full.summary.total_functions
            );

            // Non-vacuous: truncation must actually drop functions, otherwise
            // the invariance assertions below would pass even with the bug.
            assert!(
                topn.functions.len() < full.functions.len(),
                "{lang:?}: --top 2 did not truncate (full listed {}, top listed {})",
                full.functions.len(),
                topn.functions.len(),
            );
            assert!(
                topn.summary.truncated,
                "{lang:?}: summary.truncated must be true under --top 2",
            );
            assert!(
                !full.summary.truncated,
                "{lang:?}: summary.truncated must be false under --top 0",
            );

            // Non-vacuousness is UNIVERSAL via `total_functions`: under the
            // pre-fix code the truncated path reported total_functions == 2
            // while the full path reported >= 5, so the equality check below
            // fails on the bug for EVERY language regardless of scoring.
            //
            // Where the grammar actually raises cognitive (every language here
            // except Elixir's `if`-do macro), the full set additionally mixes
            // compliant + violating functions, so avg_cognitive /
            // compliance_rate / violations_count would ALSO diverge under the
            // bug — a strictly stronger witness.
            if full.summary.max_cognitive > 0 {
                assert!(
                    full.summary.violations_count >= 1
                        && full.summary.violations_count < full.summary.total_functions,
                    "{lang:?}: expected a mix of compliant + violating functions (violations={}, total={})",
                    full.summary.violations_count,
                    full.summary.total_functions,
                );
            }

            // CORE INVARIANT: every summary statistic is identical with and
            // without --top N. The pre-fix code failed total_functions /
            // avg_cognitive / compliance_rate here.
            let f = &full.summary;
            let t = &topn.summary;
            assert_eq!(
                t.total_functions, f.total_functions,
                "{lang:?}: total_functions changed under --top",
            );
            assert_eq!(
                t.total_cognitive, f.total_cognitive,
                "{lang:?}: total_cognitive changed under --top",
            );
            assert_eq!(
                t.avg_cognitive, f.avg_cognitive,
                "{lang:?}: avg_cognitive changed under --top",
            );
            assert_eq!(
                t.max_cognitive, f.max_cognitive,
                "{lang:?}: max_cognitive changed under --top",
            );
            assert_eq!(
                t.violations_count, f.violations_count,
                "{lang:?}: violations_count changed under --top",
            );
            assert_eq!(
                t.severe_violations_count, f.severe_violations_count,
                "{lang:?}: severe_violations_count changed under --top",
            );
            assert_eq!(
                t.compliance_rate, f.compliance_rate,
                "{lang:?}: compliance_rate changed under --top",
            );

            // The violations list is also aggregated over the full set.
            assert_eq!(
                topn.violations.len(),
                full.violations.len(),
                "{lang:?}: violations list length changed under --top",
            );
        }
    }
}
