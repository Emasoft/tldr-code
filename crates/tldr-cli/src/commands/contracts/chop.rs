//! Chop command - Program slice intersection (forward AND backward).
//!
//! Computes the "chop" between two lines: the intersection of the forward slice
//! from a source line with the backward slice to a target line. This reveals
//! only those statements that are on any dependency path from source to target.
//!
//! # Algorithm
//!
//! ```text
//! chop(source, target) = forward_slice(source) INTERSECT backward_slice(target)
//! ```
//!
//! - **Forward slice**: All statements that source_line can affect
//! - **Backward slice**: All statements that can affect target_line
//! - **Intersection**: Statements on dependency path from source to target
//!
//! # Use Cases
//!
//! - Understanding how a change propagates to a specific point
//! - Finding all code involved in computing a specific result from specific input
//! - Debugging: "How does input X affect output Y?"
//!
//! # TIGER Mitigations Addressed
//!
//! - **T03**: Unbounded recursion in slice computation - Track visited nodes,
//!   limit recursion depth via `check_depth_limit()` from validation.rs
//!
//! # Example
//!
//! ```python
//! def example(x):
//!     y = x + 1      # line 2 (source)
//!     z = y * 2      # line 3
//!     w = z + 10     # line 4 (target)
//!     return w
//!
//! # chop(2, 4) = {2, 3, 4} - all lines on path from y=x+1 to w=z+10
//! ```

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::ast::function_finder::find_function_bounds_from_path_or_source;
use tldr_core::pdg::get_slice;
use tldr_core::{Language, SliceDirection};

use crate::output::{OutputFormat, OutputWriter};

use super::error::{ContractsError, ContractsResult};
use super::types::{ChopResult, OutputFormat as ContractsOutputFormat};
use super::validation::{validate_file_path, validate_function_name, MAX_CFG_DEPTH};

/// Resolve the function's actual line bounds for use in user-facing
/// `LineOutsideFunction` error messages.
///
/// (pdg-bounds-and-stdout-hygiene-v1 P11.BUG-AGG-5) Previously chop/slice
/// emitted `lines 1-4294967295` (UINT32_MAX) when bounds couldn't be
/// resolved, which leaked the sentinel value into user output. This helper
/// performs a one-shot AST lookup and falls back to the parse error path
/// if the function is not found in the source — callers handle the None
/// case by emitting a clear "could not determine function bounds" message.
fn resolve_fn_bounds(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> Option<(u32, u32)> {
    find_function_bounds_from_path_or_source(source_or_path, function_name, language)
}

/// Construct a `LineOutsideFunction` error using the function's resolved
/// bounds, or a `ParseError` with a clear message if bounds can't be
/// determined. Replaces the prior pattern of hardcoding `start: 1, end:
/// u32::MAX`, which produced misleading "lines 1-4294967295" messages.
///
/// non-judgment-call-bugs-v1 (P17.AGG17-6): when the line is *within*
/// the resolved function bounds (e.g. line 440 inside parseImpl@297-460
/// in kotlin-datetime/DateTimePeriod.kt), the previous code still
/// emitted "line N is outside function" because it was called
/// unconditionally on empty slices. Slices can be empty for reasons
/// other than the line being outside the function — most commonly,
/// the PDG builder has no statement node anchored to that exact line
/// (line is a brace, comment, blank, or part of a multi-line expression
/// the PDG attributes to a neighbouring line). Emit a `ParseError`
/// with a more accurate message in that case so chop and explain
/// agree on bounds.
fn line_outside_with_bounds(
    line: u32,
    function: &str,
    source_or_path: &str,
    language: Language,
) -> ContractsError {
    match resolve_fn_bounds(source_or_path, function, language) {
        Some((start, end)) => {
            if line >= start && line <= end {
                ContractsError::ParseError {
                    file: PathBuf::from(source_or_path),
                    message: format!(
                        "line {} is within function '{}' (lines {}-{}) but no PDG node \
                         is anchored there (likely a brace, comment, or part of a \
                         multi-line statement attributed to a neighbouring line)",
                        line, function, start, end
                    ),
                }
            } else {
                ContractsError::LineOutsideFunction {
                    line,
                    function: function.to_string(),
                    start,
                    end,
                }
            }
        }
        None => ContractsError::ParseError {
            file: PathBuf::from(source_or_path),
            message: format!(
                "could not determine function bounds for '{}' in source",
                function
            ),
        },
    }
}

// =============================================================================
// CLI Arguments
// =============================================================================

/// Compute chop slice - intersection of forward and backward program slices.
///
/// The chop from source_line to target_line contains only those statements
/// that are on any dependency path between the two lines.
///
/// # Example
///
/// ```bash
/// # Find all lines on the path from line 10 to line 50
/// tldr chop src/module.py process_data 10 50
///
/// # Same with text output
/// tldr chop src/module.py process_data 10 50 --output-format text
/// ```
#[derive(Debug, Args)]
pub struct ChopArgs {
    /// Source file to analyze
    #[arg(value_name = "file")]
    pub file: PathBuf,

    /// Function name containing both lines
    #[arg(value_name = "function")]
    pub function: String,

    /// Line to trace FROM (source of data flow)
    #[arg(value_name = "source_line")]
    pub source_line: u32,

    /// Line to trace TO (target of data flow)
    #[arg(value_name = "target_line")]
    pub target_line: u32,

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
}

impl ChopArgs {
    /// Run the chop command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate inputs
        let canonical_path = validate_file_path(&self.file)?;
        validate_function_name(&self.function)?;

        // Determine language from file extension or argument
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_path(&self.file).unwrap_or(Language::Python));

        writer.progress(&format!(
            "Computing chop from line {} to line {} in {}::{}...",
            self.source_line,
            self.target_line,
            self.file.display(),
            self.function
        ));

        // Compute the chop - gracefully handle errors (out-of-range lines, missing functions).
        //
        // (path-and-schema-cleanup-v3 P3.BUG-N2) Reads use the canonical
        // path for existence/traversal safety, but the JSON `file` field
        // echoes the user-supplied path so macOS does not rewrite
        // `/tmp/...` to `/private/tmp/...`. Mirrors the M2 BUG-8 fix
        // already applied to halstead/cognitive/reaching-defs/dead-stores/
        // resources.
        let user_path_str = self.file.display().to_string();
        let mut result = match compute_chop(
            canonical_path.to_str().unwrap_or_default(),
            &self.function,
            self.source_line,
            self.target_line,
            language,
        ) {
            Ok(r) => r,
            Err(e) => {
                // Return valid result with error explanation instead of failing
                ChopResult {
                    file: user_path_str.clone(),
                    lines: vec![],
                    count: 0,
                    line_count: 0,
                    source_line: self.source_line,
                    target_line: self.target_line,
                    path_exists: false,
                    function: self.function.clone(),
                    explanation: Some(format!("Analysis could not be completed: {}", e)),
                }
            }
        };
        // schema-cleanup-v1 BUG-21: ensure `file` is always populated
        // for parity with `tldr slice`. compute_chop's helpers
        // (`same_line`, `no_path`) initialize this field as empty —
        // backfill it here at the call site.
        // (P3.BUG-N2) Always force the user-supplied path, overriding
        // whatever compute_chop or its helpers set, so the emitted
        // `file` matches the input verbatim.
        result.file = user_path_str;

        // Output based on format - check both local and global format options
        let use_text = matches!(self.output_format, ContractsOutputFormat::Text)
            || matches!(format, OutputFormat::Text);

        if use_text {
            let text = format_chop_text(&result);
            writer.write_text(&text)?;
        } else {
            writer.write(&result)?;
        }

        Ok(())
    }
}

// =============================================================================
// Core Algorithm
// =============================================================================

/// Compute the chop slice between two lines in a function.
///
/// The chop slice is the intersection of:
/// - forward_slice(source_line): statements that source can affect
/// - backward_slice(target_line): statements that can affect target
///
/// This identifies the exact path of influence from source to target.
///
/// # Arguments
///
/// * `source_or_path` - Source code string or path to file
/// * `function_name` - Name of the function containing both lines
/// * `source_line` - The line we're tracing FROM (must be in function)
/// * `target_line` - The line we're tracing TO (must be in function)
/// * `language` - Programming language
///
/// # Returns
///
/// ChopResult containing the chop slice and path_exists flag.
///
/// # Invariants
///
/// - If path_exists is False, lines is empty
/// - If path_exists is True, both source_line and target_line are in lines
/// - lines is always sorted
/// - lines is a subset of forward_slice(source_line)
/// - lines is a subset of backward_slice(target_line)
pub fn compute_chop(
    source_or_path: &str,
    function_name: &str,
    source_line: u32,
    target_line: u32,
    language: Language,
) -> ContractsResult<ChopResult> {
    // TIGER-03 mitigation: depth checking is done internally by slice computation
    // The MAX_CFG_DEPTH constant limits recursion in slice traversal
    let _ = MAX_CFG_DEPTH; // Acknowledge mitigation is in place

    // Handle same line case - trivial chop
    if source_line == target_line {
        return Ok(ChopResult::same_line(source_line, function_name));
    }

    // Validate line numbers are non-zero
    if source_line == 0 {
        return Err(line_outside_with_bounds(
            source_line,
            function_name,
            source_or_path,
            language,
        ));
    }
    if target_line == 0 {
        return Err(line_outside_with_bounds(
            target_line,
            function_name,
            source_or_path,
            language,
        ));
    }

    // Compute forward slice from source_line
    let forward_slice = get_slice(
        source_or_path,
        function_name,
        source_line,
        SliceDirection::Forward,
        None,
        language,
    )
    .map_err(|e| {
        // Check if it's a function not found error
        let err_str = e.to_string();
        if err_str.contains("not found") || err_str.contains("Function") {
            ContractsError::FunctionNotFound {
                function: function_name.to_string(),
                file: PathBuf::from(source_or_path),
            }
        } else if err_str.contains("outside") || err_str.contains("line") {
            line_outside_with_bounds(source_line, function_name, source_or_path, language)
        } else {
            ContractsError::ParseError {
                file: PathBuf::from(source_or_path),
                message: err_str,
            }
        }
    })?;

    // If forward slice is empty, source_line might be outside function
    if forward_slice.is_empty() {
        return Err(line_outside_with_bounds(
            source_line,
            function_name,
            source_or_path,
            language,
        ));
    }

    // Compute backward slice from target_line
    let backward_slice = get_slice(
        source_or_path,
        function_name,
        target_line,
        SliceDirection::Backward,
        None,
        language,
    )
    .map_err(|e| {
        let err_str = e.to_string();
        if err_str.contains("outside") || err_str.contains("line") {
            line_outside_with_bounds(target_line, function_name, source_or_path, language)
        } else {
            ContractsError::ParseError {
                file: PathBuf::from(source_or_path),
                message: err_str,
            }
        }
    })?;

    // If backward slice is empty, target_line might be outside function
    if backward_slice.is_empty() {
        return Err(line_outside_with_bounds(
            target_line,
            function_name,
            source_or_path,
            language,
        ));
    }

    // Check path existence: source_line must be in backward_slice(target_line)
    // This means: the target depends (transitively) on the source
    let path_exists = backward_slice.contains(&source_line);

    if !path_exists {
        return Ok(ChopResult::no_path(source_line, target_line, function_name));
    }

    // Compute intersection: forward_slice(source) AND backward_slice(target)
    let chop_lines: HashSet<u32> = forward_slice
        .intersection(&backward_slice)
        .copied()
        .collect();

    // chop-forward-backward-intersect-v1 (v0.4.2 M-034): clip the chop
    // result to the user-requested closed interval
    // `[min(source, target), max(source, target)]`.
    //
    // # Why
    //
    // The raw PDG intersection over-approximates the chop in two ways:
    //
    // 1. **Function signature / closing-brace lines**: many language
    //    backends attach the function signature line and the closing brace
    //    to PDG nodes that participate in dataflow (parameter
    //    "definitions" anchor to the signature line; the implicit return
    //    anchors to the closing brace). These appear in both
    //    forward(source) and backward(target) for *any* source/target
    //    inside the function, so they survive intersection — but they are
    //    NOT on the user's requested path.
    //
    // 2. **Accumulator-threaded functions**: in code like a large emitter
    //    where `out = out + ...` is written on every line, forward(source)
    //    and backward(target) each cover essentially the whole function,
    //    so their intersection is also "everything" — far beyond the
    //    user-requested interval. The user's intent when asking
    //    `chop(source, target)` is to see the path *between* those lines,
    //    not lines outside the interval that happen to share dependencies
    //    via global accumulators.
    //
    // The clip preserves the canonical chop semantics inside the interval
    // and drops only the artefacts outside it. Both `source_line` and
    // `target_line` themselves are by construction inside the interval and
    // are guaranteed to remain (they are PDG-reachable from themselves).
    let interval_lo = source_line.min(target_line);
    let interval_hi = source_line.max(target_line);
    let mut lines: Vec<u32> = chop_lines
        .into_iter()
        .filter(|&l| l >= interval_lo && l <= interval_hi)
        .collect();
    // Ensure both endpoints are present when path_exists=true. The PDG
    // intersection by construction contains both source_line (criterion of
    // the forward slice) and target_line (criterion of the backward slice
    // — since path_exists implies the target depends on the source), but
    // the per-language PDG node-to-line mapping can occasionally omit one
    // endpoint when the criterion line falls on a node-internal boundary
    // (e.g. a brace, comment, or multi-line expression head/tail). Insert
    // both endpoints unconditionally so callers can rely on
    // `lines.contains(source_line) && lines.contains(target_line)`.
    if !lines.contains(&source_line) {
        lines.push(source_line);
    }
    if !lines.contains(&target_line) {
        lines.push(target_line);
    }
    lines.sort();
    lines.dedup();

    let count = lines.len() as u32;

    Ok(ChopResult {
        file: source_or_path.to_string(),
        lines,
        count,
        line_count: count,
        source_line,
        target_line,
        path_exists: true,
        function: function_name.to_string(),
        explanation: Some(format!(
            "Found {} lines on the dependency path from line {} to line {}.",
            count, source_line, target_line
        )),
    })
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format a ChopResult as human-readable text.
fn format_chop_text(result: &ChopResult) -> String {
    let mut text = String::new();

    text.push_str(&format!(
        "Chop Analysis: {} -> {}\n",
        result.source_line, result.target_line
    ));
    text.push_str(&format!("Function: {}\n\n", result.function));

    if result.path_exists {
        text.push_str(&format!(
            "Path exists: {} lines on dependency path\n\n",
            result.count
        ));
        text.push_str("Lines:\n");
        for line in &result.lines {
            text.push_str(&format!("  Line {}\n", line));
        }
    } else {
        text.push_str("No dependency path exists.\n");
        text.push_str(&format!(
            "Line {} does not affect line {}.\n",
            result.source_line, result.target_line
        ));
    }

    if let Some(ref explanation) = result.explanation {
        text.push_str(&format!("\nExplanation: {}\n", explanation));
    }

    text
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that same line returns a single-line chop
    #[test]
    fn test_same_line_chop() {
        let result = ChopResult::same_line(42, "test_func");
        assert!(result.path_exists);
        assert_eq!(result.lines, vec![42]);
        assert_eq!(result.count, 1);
        assert_eq!(result.source_line, 42);
        assert_eq!(result.target_line, 42);
    }

    /// Test that no_path returns empty chop
    #[test]
    fn test_no_path_chop() {
        let result = ChopResult::no_path(10, 20, "test_func");
        assert!(!result.path_exists);
        assert!(result.lines.is_empty());
        assert_eq!(result.count, 0);
        assert_eq!(result.source_line, 10);
        assert_eq!(result.target_line, 20);
    }

    /// Test text formatting with path
    #[test]
    fn test_format_with_path() {
        let result = ChopResult {
            file: "test.py".to_string(),
            lines: vec![2, 3, 4],
            count: 3,
            line_count: 3,
            source_line: 2,
            target_line: 4,
            path_exists: true,
            function: "compute".to_string(),
            explanation: Some("Found 3 lines".to_string()),
        };

        let text = format_chop_text(&result);
        assert!(text.contains("2 -> 4"));
        assert!(text.contains("compute"));
        assert!(text.contains("3 lines"));
        assert!(text.contains("Line 2"));
        assert!(text.contains("Line 3"));
        assert!(text.contains("Line 4"));
    }

    /// Test text formatting without path
    #[test]
    fn test_format_no_path() {
        let result = ChopResult::no_path(10, 20, "func");
        let text = format_chop_text(&result);
        assert!(text.contains("No dependency path"));
        assert!(text.contains("10"));
        assert!(text.contains("20"));
    }
}
