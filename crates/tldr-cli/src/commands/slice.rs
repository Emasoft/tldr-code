//! Slice command - Program slicing
//!
//! Computes backward or forward program slices from a line.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use tldr_core::ast::function_finder::find_function_bounds_from_path_or_source;
use tldr_core::{get_slice_rich, Language, RichSlice, SliceDirection};

use crate::commands::daemon_router::{params_with_file_function_line, try_daemon_route};
use crate::commands::elixir_per_clause;
use crate::output::{OutputFormat, OutputWriter};

/// Compute program slice from a line
#[derive(Debug, Args)]
pub struct SliceArgs {
    /// Source file path
    pub file: PathBuf,

    /// Function name containing the line
    pub function: String,

    /// Line number to slice from
    pub line: u32,

    /// Slice direction: backward (what affects this line) or forward (what this line affects)
    #[arg(long, short = 'd', default_value = "backward")]
    pub direction: SliceDirectionArg,

    /// Variable to filter by (optional - traces all if not specified)
    #[arg(long)]
    pub variable: Option<String>,

    /// Programming language (auto-detected from file extension if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt in to the
    /// bare-name fallback for Rust / C / C++ `Class::method` inputs.
    /// See `complexity.rs::ComplexityArgs::qualified` for the full
    /// rationale.
    #[arg(long)]
    pub qualified: bool,
}

/// CLI wrapper for slice direction
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum SliceDirectionArg {
    /// Backward slice - what affects this line?
    #[default]
    Backward,
    /// Forward slice - what does this line affect?
    Forward,
}

impl From<SliceDirectionArg> for SliceDirection {
    fn from(arg: SliceDirectionArg) -> Self {
        match arg {
            SliceDirectionArg::Backward => SliceDirection::Backward,
            SliceDirectionArg::Forward => SliceDirection::Forward,
        }
    }
}

/// Rich slice line for output
#[derive(Debug, Serialize, Deserialize)]
struct SliceLine {
    line: u32,
    code: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    definitions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dep_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dep_label: Option<String>,
}

/// Edge in slice output
#[derive(Debug, Serialize, Deserialize)]
struct SliceEdgeOutput {
    from_line: u32,
    to_line: u32,
    dep_type: String,
    label: String,
}

/// Slice result output format (backward-compatible: keeps `lines` as Vec<u32>)
#[derive(Debug, Serialize, Deserialize)]
struct SliceOutput {
    file: PathBuf,
    function: String,
    criterion_line: u32,
    direction: String,
    variable: Option<String>,
    /// Bare line numbers (backward-compatible)
    lines: Vec<u32>,
    /// Rich line data with code and metadata
    #[serde(skip_serializing_if = "Vec::is_empty")]
    slice_lines: Vec<SliceLine>,
    /// Dependency edges within the slice
    #[serde(skip_serializing_if = "Vec::is_empty")]
    edges: Vec<SliceEdgeOutput>,
    line_count: usize,
    /// Diagnostic explanation when the result is empty for a known
    /// reason (e.g. criterion line is outside the function bounds).
    /// ux-and-explain-completeness-v1 (P12.AGG12-15): mirrors `chop`'s
    /// pattern so empty results are not silent.
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>,
}

/// Legacy daemon output (old format without rich data)
#[derive(Debug, Serialize, Deserialize)]
struct LegacySliceOutput {
    file: PathBuf,
    function: String,
    criterion_line: u32,
    direction: String,
    variable: Option<String>,
    lines: Vec<u32>,
    line_count: usize,
}

impl SliceArgs {
    /// Run the slice command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Determine language from file extension or argument
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_path(&self.file).unwrap_or(Language::Python));

        // m117-deferred-decisions-v1 (v0.4.2 M-118, D8): opt-in bare-name
        // canonicalisation. Default is strict-qualified (no-op).
        let function = tldr_core::ast::function_finder::resolve_qualified_function_name(
            &self.function,
            language,
            self.qualified,
        );

        let direction: SliceDirection = self.direction.into();
        let direction_str = match direction {
            SliceDirection::Backward => "backward",
            SliceDirection::Forward => "forward",
        };

        // Try daemon first for cached result (use file's parent as project root)
        let project = self.file.parent().unwrap_or(&self.file);
        if let Some(output) = try_daemon_route::<LegacySliceOutput>(
            project,
            "slice",
            params_with_file_function_line(&self.file, &function, self.line),
        ) {
            // Daemon returns legacy format -- enrich with source code if possible
            let source_lines = read_file_lines(&self.file);
            if writer.is_text() {
                let mut text = String::new();
                text.push_str(&format!(
                    "Program Slice ({} from line {})\n",
                    output.direction, output.criterion_line
                ));
                text.push_str(&format!(
                    "Function: {}::{}\n",
                    output.file.display(),
                    output.function
                ));
                if let Some(var) = &output.variable {
                    text.push_str(&format!("Variable: {}\n", var));
                }
                // P12.AGG12-15: surface OOR diagnostic in text output too.
                if output.lines.is_empty() {
                    if let Some(diag) = slice_oor_explanation(
                        self.file.to_str().unwrap_or_default(),
                        &function,
                        self.line,
                        language,
                    ) {
                        text.push_str(&format!("\n{}\n", diag));
                        writer.write_text(&text)?;
                        return Ok(());
                    }
                }
                text.push_str(&format!(
                    "\nSlice contains {} lines:\n\n",
                    output.lines.len()
                ));
                for &line_num in &output.lines {
                    let code = source_lines
                        .get((line_num as usize).wrapping_sub(1))
                        .map(|s| s.trim_end())
                        .unwrap_or("");
                    let marker = if line_num == output.criterion_line {
                        ">"
                    } else {
                        " "
                    };
                    let criterion_flag = if line_num == output.criterion_line {
                        "  <-- criterion"
                    } else {
                        ""
                    };
                    text.push_str(&format!(
                        "{} {:>5} | {}{}\n",
                        marker, line_num, code, criterion_flag
                    ));
                }
                writer.write_text(&text)?;
                return Ok(());
            } else {
                // Convert legacy to new format for JSON
                let slice_lines: Vec<SliceLine> = output
                    .lines
                    .iter()
                    .map(|&l| {
                        let code = source_lines
                            .get((l as usize).wrapping_sub(1))
                            .map(|s| s.trim_end().to_string())
                            .unwrap_or_default();
                        SliceLine {
                            line: l,
                            code,
                            definitions: Vec::new(),
                            uses: Vec::new(),
                            dep_type: None,
                            dep_label: None,
                        }
                    })
                    .collect();
                // P12.AGG12-15: same OOR diagnostic as the direct-compute
                // path, applied to the daemon's legacy output.
                let explanation = if output.lines.is_empty() {
                    slice_oor_explanation(
                        self.file.to_str().unwrap_or_default(),
                        &function,
                        self.line,
                        language,
                    )
                } else {
                    None
                };
                let rich_output = SliceOutput {
                    file: output.file,
                    function: output.function,
                    criterion_line: output.criterion_line,
                    direction: output.direction,
                    variable: output.variable,
                    line_count: output.line_count,
                    lines: output.lines,
                    slice_lines,
                    edges: Vec::new(),
                    explanation,
                };
                writer.write(&rich_output)?;
                return Ok(());
            }
        }

        // Fallback to direct compute with rich output
        writer.progress(&format!(
            "Computing {} slice for line {} in {}::{}...",
            direction_str,
            self.line,
            self.file.display(),
            function
        ));

        // Get rich slice
        let rich = get_slice_rich(
            self.file.to_str().unwrap_or_default(),
            &function,
            self.line,
            direction,
            self.variable.as_deref(),
            language,
        )?;

        // elixir-multiclause-slice-dispatch-v1 (v0.5.0 RC, CF2-S14):
        // the whole-file `get_slice_rich` above resolves a multi-clause
        // Elixir `def` to its *first* body-bearing clause (the M-E1
        // selector). When the criterion line lives inside a LATER
        // clause, that slice comes back empty and the headline would
        // wrongly report "line outside function" (validating against
        // clause #1's range) even though the correct slice exists in a
        // later clause / `per_clauses[n]`. Consult the matching clause
        // *before* concluding the line is out of range: recompute the
        // slice against the synthetic single-clause sub-source for
        // whichever body-bearing clause actually contains the line.
        let rich = if rich.nodes.is_empty() {
            elixir_clause_slice_for_line(
                &self.file,
                &function,
                self.line,
                direction,
                self.variable.as_deref(),
                language,
            )
            .unwrap_or(rich)
        } else {
            rich
        };

        // Build backward-compatible line list
        let lines: Vec<u32> = rich.nodes.iter().map(|n| n.line).collect();

        // Build rich line data
        let slice_lines: Vec<SliceLine> = rich
            .nodes
            .iter()
            .map(|n| SliceLine {
                line: n.line,
                code: n.code.clone(),
                definitions: n.definitions.clone(),
                uses: n.uses.clone(),
                dep_type: n.dep_type.clone(),
                dep_label: n.dep_label.clone(),
            })
            .collect();

        // Build edge output
        let edges: Vec<SliceEdgeOutput> = rich
            .edges
            .iter()
            .map(|e| SliceEdgeOutput {
                from_line: e.from_line,
                to_line: e.to_line,
                dep_type: e.dep_type.clone(),
                label: e.label.clone(),
            })
            .collect();

        let data_count = edges.iter().filter(|e| e.dep_type == "data").count();
        let ctrl_count = edges.iter().filter(|e| e.dep_type == "control").count();

        // ux-and-explain-completeness-v1 (P12.AGG12-15): when the slice
        // is empty, attribute it. The most common cause is the criterion
        // line being outside the resolved function bounds — mirror chop's
        // diagnostic pattern so users aren't left guessing.
        let explanation = if lines.is_empty() {
            slice_oor_explanation(
                self.file.to_str().unwrap_or_default(),
                &function,
                self.line,
                language,
            )
        } else {
            None
        };

        let output = SliceOutput {
            file: self.file.clone(),
            function: function.clone(),
            criterion_line: self.line,
            direction: direction_str.to_string(),
            variable: self.variable.clone(),
            line_count: lines.len(),
            lines,
            slice_lines,
            edges,
            explanation,
        };

        // elixir-per-clause-dfg-cfg-v1 (v0.4.2 M-031): for Elixir
        // multi-clause `def`, emit `per_clauses` alongside the legacy
        // single-clause slice. Each per-clause slice is computed on a
        // synthetic single-clause sub-source. The criterion line is
        // clamped per-clause to the clause's start_line if the
        // user-supplied criterion falls outside the clause body.
        let per_clause_array: Option<Vec<serde_json::Value>> = if writer.is_text() {
            None
        } else {
            let user_line = self.line;
            elixir_per_clause::for_each_body_bearing_clause(
                &self.file,
                &function,
                language,
                |tmp_path, clause, _offset| -> anyhow::Result<serde_json::Value> {
                    let line_for_clause = if user_line >= clause.start_line
                        && user_line <= clause.end_line
                    {
                        user_line
                    } else {
                        // Pick a sensible default line inside the clause
                        // body (start_line + 1 if available, else
                        // start_line). The synthetic source preserves
                        // original line numbering.
                        clause.start_line.saturating_add(1).min(clause.end_line)
                    };
                    let rich_sub = get_slice_rich(
                        tmp_path.to_str().unwrap_or_default(),
                        &function,
                        line_for_clause,
                        direction,
                        self.variable.as_deref(),
                        language,
                    )?;
                    let sub_lines: Vec<u32> = rich_sub.nodes.iter().map(|n| n.line).collect();
                    let sub_slice_lines: Vec<SliceLine> = rich_sub
                        .nodes
                        .iter()
                        .map(|n| SliceLine {
                            line: n.line,
                            code: n.code.clone(),
                            definitions: n.definitions.clone(),
                            uses: n.uses.clone(),
                            dep_type: n.dep_type.clone(),
                            dep_label: n.dep_label.clone(),
                        })
                        .collect();
                    let sub_edges: Vec<SliceEdgeOutput> = rich_sub
                        .edges
                        .iter()
                        .map(|e| SliceEdgeOutput {
                            from_line: e.from_line,
                            to_line: e.to_line,
                            dep_type: e.dep_type.clone(),
                            label: e.label.clone(),
                        })
                        .collect();
                    let sub_output = SliceOutput {
                        file: self.file.clone(),
                        function: function.clone(),
                        criterion_line: line_for_clause,
                        direction: direction_str.to_string(),
                        variable: self.variable.clone(),
                        line_count: sub_lines.len(),
                        lines: sub_lines,
                        slice_lines: sub_slice_lines,
                        edges: sub_edges,
                        explanation: None,
                    };
                    let v = serde_json::to_value(&sub_output)?;
                    Ok(elixir_per_clause::per_clause_entry_value(clause, v))
                },
            )?
        };

        // Output based on format
        if writer.is_text() {
            let text = format_rich_text(&output, data_count, ctrl_count);
            writer.write_text(&text)?;
        } else {
            let value = serde_json::to_value(&output)?;
            let merged = elixir_per_clause::merge_per_clauses(value, per_clause_array);
            // Mirror writer.write() formatting for JSON formats.
            match format {
                OutputFormat::Compact => {
                    writer.write_text(&serde_json::to_string(&merged)?)?;
                }
                _ => {
                    writer.write_text(&serde_json::to_string_pretty(&merged)?)?;
                }
            }
        }

        Ok(())
    }
}

/// Format rich slice as compact text for LLM consumption
fn format_rich_text(output: &SliceOutput, data_count: usize, ctrl_count: usize) -> String {
    let mut text = String::new();

    text.push_str(&format!(
        "Program Slice ({} from line {})\n",
        output.direction, output.criterion_line
    ));
    text.push_str(&format!(
        "Function: {}::{}\n",
        output.file.display(),
        output.function
    ));
    if let Some(var) = &output.variable {
        text.push_str(&format!("Variable: {}\n", var));
    }

    // P12.AGG12-15: emit the OOR diagnostic prominently when present.
    if let Some(diag) = &output.explanation {
        text.push_str(&format!("\n{}\n", diag));
        return text;
    }

    // Count non-blank lines for accurate summary
    let non_blank_count = output
        .slice_lines
        .iter()
        .filter(|sl| !sl.code.trim().is_empty())
        .count();

    // Summary line with dep counts
    if data_count > 0 || ctrl_count > 0 {
        text.push_str(&format!(
            "\nSlice contains {} lines ({} data deps, {} control deps):\n\n",
            non_blank_count, data_count, ctrl_count
        ));
    } else {
        text.push_str(&format!("\nSlice contains {} lines:\n\n", non_blank_count));
    }

    // Code lines with annotations
    // Track previous defs/uses to avoid repeating identical annotations
    // (PDG nodes span multiple lines but carry one set of defs/uses)
    let mut prev_defs: Option<&Vec<String>> = None;
    let mut prev_uses: Option<&Vec<String>> = None;

    for sl in &output.slice_lines {
        // Skip blank lines — they waste tokens and carry no insight
        if sl.code.trim().is_empty() {
            continue;
        }

        let marker = if sl.line == output.criterion_line {
            ">"
        } else {
            " "
        };

        // Only show defs/uses on the first line of each node span
        let same_as_prev = prev_defs == Some(&sl.definitions) && prev_uses == Some(&sl.uses);

        let mut annotations = Vec::new();
        if !same_as_prev {
            if !sl.definitions.is_empty() {
                annotations.push(format!("[defines: {}]", sl.definitions.join(", ")));
            }
            if !sl.uses.is_empty() {
                annotations.push(format!("[uses: {}]", sl.uses.join(", ")));
            }
        }
        if let Some(dt) = &sl.dep_type {
            if dt == "control" && !same_as_prev {
                annotations.push("ctrl".to_string());
            }
        }

        prev_defs = Some(&sl.definitions);
        prev_uses = Some(&sl.uses);

        let criterion_flag = if sl.line == output.criterion_line {
            "  <-- criterion"
        } else {
            ""
        };

        let annotation_str = if annotations.is_empty() {
            String::new()
        } else {
            format!("     {}", annotations.join(" "))
        };

        text.push_str(&format!(
            "{} {:>5} | {}{}{}\n",
            marker, sl.line, sl.code, annotation_str, criterion_flag
        ));
    }

    // Dependencies section
    if !output.edges.is_empty() {
        text.push_str("\nDependencies:\n");
        for edge in &output.edges {
            if edge.dep_type == "data" && !edge.label.is_empty() {
                text.push_str(&format!(
                    "  {}@{} <- {}@{} (data: {})\n",
                    edge.label, edge.to_line, edge.label, edge.from_line, edge.label
                ));
            } else {
                text.push_str(&format!(
                    "  {} <- {} ({})\n",
                    edge.to_line, edge.from_line, edge.dep_type
                ));
            }
        }
    }

    text
}

/// Produce a `LineOutsideFunction`-style diagnostic when slice's
/// criterion line falls outside the resolved bounds of the named
/// function. ux-and-explain-completeness-v1 (P12.AGG12-15): mirrors
/// the diagnostic emitted by `chop` so empty slices on out-of-range
/// criterion lines are not silent. Returns None when the function
/// cannot be located in source (a different failure mode that should
/// not be reported as "outside function").
fn slice_oor_explanation(
    source_or_path: &str,
    function_name: &str,
    line: u32,
    language: Language,
) -> Option<String> {
    let (start, end) =
        find_function_bounds_from_path_or_source(source_or_path, function_name, language)?;
    if line < start || line > end {
        Some(format!(
            "Analysis could not be completed: line {} is outside function '{}' (lines {}-{})",
            line, function_name, start, end
        ))
    } else {
        None
    }
}

/// elixir-multiclause-slice-dispatch-v1 (v0.5.0 RC, CF2-S14): recompute
/// a backward/forward slice for an Elixir multi-clause `def` against the
/// clause whose body actually contains `line`.
///
/// The whole-file slice resolves a multi-clause `def` to its first
/// body-bearing clause (M-E1), so a criterion line inside a *later*
/// clause yields nothing there. This helper lists the body-bearing
/// clauses, finds the one whose `start_line..=end_line` span contains
/// `line`, and re-runs the slice on that clause's synthetic
/// single-clause sub-source (which preserves original line numbers, so
/// the result needs no offset translation).
///
/// Returns `None` for non-Elixir sources, single-clause functions, when
/// no clause body contains `line` (a genuine out-of-range criterion),
/// or when the recomputed slice is still empty — leaving the caller's
/// out-of-range diagnostic intact for those cases.
fn elixir_clause_slice_for_line(
    file: &std::path::Path,
    function_name: &str,
    line: u32,
    direction: SliceDirection,
    variable: Option<&str>,
    language: Language,
) -> Option<RichSlice> {
    let clauses = elixir_per_clause::list_body_bearing_clauses(file, function_name, language)?;
    if clauses.len() <= 1 {
        return None;
    }
    // Locate the body-bearing clause whose span contains the criterion.
    // Clauses are non-overlapping, so at most one matches.
    let clause = clauses
        .iter()
        .find(|c| line >= c.start_line && line <= c.end_line)?;
    let source = elixir_per_clause::read_source(file)?;
    let (synthetic, _offset) = elixir_per_clause::build_synthetic_clause_source(&source, clause);
    let tmp = elixir_per_clause::write_temp_clause_file(&synthetic).ok()?;
    let rich = get_slice_rich(
        tmp.path().to_str()?,
        function_name,
        line,
        direction,
        variable,
        language,
    )
    .ok()?;
    drop(tmp);
    if rich.nodes.is_empty() {
        None
    } else {
        Some(rich)
    }
}

// Optional helper accessor used in tests and richtext path; matches
// `read_file_lines` location in the file.
/// Read file lines for source enrichment
fn read_file_lines(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|c| c.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Faithful inline Elixir fixture mirroring `Plug.Conn.send_resp`:
    /// a bodyless head plus three body-bearing clauses, the last with a
    /// different arity. Returns the temp file (kept alive by the caller)
    /// and the path.
    fn write_multiclause_fixture() -> tempfile::NamedTempFile {
        // 1  defmodule M do
        // 2  (blank)
        // 3    def foo(conn)                         <- bodyless head, arity 1
        // 4  (blank)
        // 5    def foo(%Conn{state: :unset}) do      <- clause #1 body, arity 1
        // 6      raise ArgumentError, "not set"
        // 7    end
        // 8  (blank)
        // 9    def foo(%Conn{adapter: {a, p}} = conn) do  <- clause #2, arity 1
        // 10     conn = run_before_send(conn, :set)
        // 11     {:ok, body, p} = a.send_resp(p, conn.status)
        // 12     %{conn | adapter: {a, p}, resp_body: body, state: :sent}
        // 13   end
        // 14 (blank)
        // 15   def foo(%Conn{} = conn, status, body) do   <- clause #3, arity 3
        // 16     conn |> resp(status, body) |> foo()
        // 17   end
        // 18 end
        let src = "defmodule M do\n\
\n\
  def foo(conn)\n\
\n\
  def foo(%Conn{state: :unset}) do\n\
    raise ArgumentError, \"not set\"\n\
  end\n\
\n\
  def foo(%Conn{adapter: {a, p}} = conn) do\n\
    conn = run_before_send(conn, :set)\n\
    {:ok, body, p} = a.send_resp(p, conn.status)\n\
    %{conn | adapter: {a, p}, resp_body: body, state: :sent}\n\
  end\n\
\n\
  def foo(%Conn{} = conn, status, body) do\n\
    conn |> resp(status, body) |> foo()\n\
  end\n\
end\n";
        let tmp = tempfile::Builder::new()
            .prefix("tldr_cf2_s14_")
            .suffix(".ex")
            .tempfile()
            .expect("create temp fixture");
        std::fs::write(tmp.path(), src).expect("write fixture");
        tmp
    }

    /// elixir-multiclause-slice-dispatch-v1 (CF2-S14): a criterion line
    /// inside a *non-first* clause of a multi-clause Elixir `def` must
    /// yield a real slice instead of a false "line outside function"
    /// diagnostic — while a genuinely out-of-range line must STILL
    /// report outside-function. Mirrors `Plug.Conn.send_resp`, where
    /// the first body-bearing clause is lines 5-7 but the requested line
    /// lives in a later clause.
    #[test]
    fn elixir_multiclause_later_clause_line_is_sliced_not_outside_function() {
        let tmp = write_multiclause_fixture();
        let path = tmp.path();
        let path_str = path.to_str().unwrap();

        // --- Line 10: inside clause #2 (lines 9-13), a LATER clause. ---
        // Precondition (the bug): the whole-file slice resolves to the
        // first body-bearing clause (lines 5-7), so line 10 produces an
        // empty slice there.
        let whole_file = get_slice_rich(
            path_str,
            "foo",
            10,
            SliceDirection::Backward,
            None,
            Language::Elixir,
        )
        .unwrap();
        assert!(
            whole_file.nodes.is_empty(),
            "precondition: whole-file slice resolves to clause #1 and is empty for a later-clause line"
        );
        // Without the fix the headline would emit this OOR diagnostic.
        assert!(
            slice_oor_explanation(path_str, "foo", 10, Language::Elixir).is_some(),
            "precondition: clause-#1-only validation flags the later-clause line as out of range"
        );

        // The fix: consult the matching clause before concluding OOR.
        let rescued = elixir_clause_slice_for_line(
            path,
            "foo",
            10,
            SliceDirection::Backward,
            None,
            Language::Elixir,
        );
        assert!(
            rescued.is_some(),
            "later-clause line 10 must yield a slice from its matching clause, not 'outside function'"
        );
        let rescued = rescued.unwrap();
        assert!(
            !rescued.nodes.is_empty(),
            "rescued slice must contain at least the criterion line"
        );
        assert!(
            rescued.nodes.iter().any(|n| n.line == 10),
            "rescued slice must include the criterion line 10"
        );

        // --- Line 16: inside clause #3 (lines 15-17), a different arity. ---
        let whole_file_3 = get_slice_rich(
            path_str,
            "foo",
            16,
            SliceDirection::Backward,
            None,
            Language::Elixir,
        )
        .unwrap();
        assert!(
            whole_file_3.nodes.is_empty(),
            "precondition: whole-file slice is empty for the arity-3 clause line too"
        );
        let rescued_3 = elixir_clause_slice_for_line(
            path,
            "foo",
            16,
            SliceDirection::Backward,
            None,
            Language::Elixir,
        );
        assert!(
            rescued_3.is_some_and(|r| r.nodes.iter().any(|n| n.line == 16)),
            "arity-3 later clause line 16 must be sliced via its matching clause"
        );

        // --- Genuine out-of-range line: must STILL report outside-function. ---
        // Line 2 is a blank line outside every clause body.
        let oor_rescue = elixir_clause_slice_for_line(
            path,
            "foo",
            2,
            SliceDirection::Backward,
            None,
            Language::Elixir,
        );
        assert!(
            oor_rescue.is_none(),
            "a genuinely out-of-range line must NOT be rescued by any clause"
        );
        assert!(
            slice_oor_explanation(path_str, "foo", 2, Language::Elixir).is_some(),
            "a genuinely out-of-range line must still report outside-function"
        );
    }
}
