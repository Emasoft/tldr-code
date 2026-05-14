//! elixir-per-clause-dfg-cfg-v1 (v0.4.2 cluster M-031)
//!
//! Per-clause iteration helper for Elixir multi-clause `def` definitions.
//!
//! ## Problem
//!
//! Elixir multi-clause `def NAME(args)` declarations resolve to a single
//! AST node via `find_function_node`. The M-E1 fix
//! (`elixir-multiclause-and-mix-v1`, commit `8f95de7`) made that selector
//! advance past bodyless heads to the first body-bearing clause — but
//! every later clause is still invisible to the 9 per-function
//! DFG/CFG/metrics commands. For `Plug.Conn.send_resp` this means 4 of
//! 5 clauses are unobservable; per-arity differences collapse (the
//! 3-arity clause at line 595 disappears entirely).
//!
//! ## Approach
//!
//! For Elixir, we list every body-bearing clause via
//! [`tldr_core::ast::function_finder::find_elixir_def_clauses`] and, for
//! each, run the requested analyzer against a synthetic single-clause
//! sub-source. Each sub-source is the parent `defmodule` shell
//! containing only that one clause; line numbers in the analyzer's JSON
//! output are translated back to the original file via an offset.
//!
//! The CLI command emits both the legacy top-level fields (computed
//! from the first body-bearing clause, exactly as today — preserves
//! backwards compatibility) AND a `per_clauses: [...]` array with one
//! entry per clause keyed by `{start_line, end_line, arity, has_body}`.
//!
//! ## Scope
//!
//! Elixir-only. Non-Elixir files and single-clause Elixir functions
//! are unchanged — `per_clauses` is omitted entirely.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::NamedTempFile;
use tldr_core::ast::function_finder::{find_elixir_def_clauses, ElixirDefClause};
use tldr_core::ast::parser::parse;
use tldr_core::Language;

/// Metadata describing one Elixir def clause discovered in the source.
///
/// Mirrors [`ElixirDefClause`] but copies the values out of the
/// tree-sitter-bound struct so callers can use them after the
/// tree-sitter tree drops.
#[derive(Debug, Clone)]
pub struct ClauseMeta {
    /// 1-based start line of the clause in the original source.
    pub start_line: u32,
    /// 1-based end line of the clause in the original source.
    pub end_line: u32,
    /// Arity of the clause (argument count).
    pub arity: usize,
    /// True if the clause has a `do_block` (a real body).
    pub has_body: bool,
}

impl From<&ElixirDefClause> for ClauseMeta {
    fn from(c: &ElixirDefClause) -> Self {
        Self {
            start_line: c.start_line,
            end_line: c.end_line,
            arity: c.arity,
            has_body: c.has_body,
        }
    }
}

/// List body-bearing Elixir def clauses for `function_name` in `file`.
///
/// Returns `None` if the file cannot be read or parsed, or if the
/// language is not Elixir. Returns an empty vec if no clause matches.
/// Bodyless heads are excluded — analyzers need a real body.
pub fn list_body_bearing_clauses(
    file: &Path,
    function_name: &str,
    language: Language,
) -> Option<Vec<ClauseMeta>> {
    if !matches!(language, Language::Elixir) {
        return None;
    }
    let source = std::fs::read_to_string(file).ok()?;
    let tree = parse(&source, language).ok()?;
    let clauses = find_elixir_def_clauses(tree.root_node(), function_name, &source);
    Some(
        clauses
            .iter()
            .filter(|c| c.has_body)
            .map(ClauseMeta::from)
            .collect(),
    )
}

/// Read the original Elixir source so callers can build per-clause
/// synthetic sub-sources without re-doing IO.
pub fn read_source(file: &Path) -> Option<String> {
    std::fs::read_to_string(file).ok()
}

/// Build a synthetic single-clause `.ex` source containing ONLY the
/// clause spanning `clause.start_line..=clause.end_line` from
/// `original_source`, wrapped in a minimal `defmodule M do ... end`
/// shell.
///
/// To preserve line-number attribution, the wrapper prepends N
/// blank-or-padding lines so that the clause's `start_line` in the
/// synthetic source equals its `start_line` in the original. Callers
/// can therefore consume analyzer line numbers verbatim — no offset
/// translation needed.
///
/// Returns the synthetic source string. The shell line count is at
/// least 1 (a `defmodule M do` line), so clauses with `start_line == 1`
/// cannot be preserved exactly; in that (impossible-in-real-Elixir)
/// case the caller will see a 1-line shift, which we surface in a
/// `synthetic_offset` field on the per-clause result.
pub fn build_synthetic_clause_source(
    original_source: &str,
    clause: &ClauseMeta,
) -> (String, u32) {
    let lines: Vec<&str> = original_source.lines().collect();
    let start_idx = (clause.start_line.saturating_sub(1)) as usize;
    let end_idx = (clause.end_line.saturating_sub(1)) as usize;
    if start_idx >= lines.len() {
        // Defensive: out-of-range clause; emit an empty defmodule shell.
        return ("defmodule M do\nend\n".to_string(), 0);
    }
    let end_idx = end_idx.min(lines.len() - 1);

    // We need a 1-line `defmodule M do` header. To keep clause line
    // numbers aligned, pad with `(clause.start_line - 2)` blank lines
    // BEFORE the header (so the header sits at `start_line - 1`, the
    // clause at `start_line`). If the clause is at line 1 (impossible
    // for a real `def` in valid Elixir), we emit no padding and accept
    // a 1-line shift; the offset is reported back to callers.
    let mut out = String::new();
    let synthetic_offset: u32 = if clause.start_line >= 2 {
        let pad_lines = (clause.start_line - 2) as usize;
        for _ in 0..pad_lines {
            out.push('\n');
        }
        out.push_str("defmodule M do\n");
        // No offset — clause sits at its original line.
        0
    } else {
        out.push_str("defmodule M do\n");
        // clause shifts down by 1 in the synthetic source.
        1
    };

    // Append the clause text verbatim.
    for line in &lines[start_idx..=end_idx] {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("end\n");
    (out, synthetic_offset)
}

/// Write a synthetic source to a temp `.ex` file and return the path
/// (held alive by the returned `NamedTempFile` to delay deletion).
pub fn write_temp_clause_file(synthetic_source: &str) -> Result<NamedTempFile> {
    let tmp = tempfile::Builder::new()
        .prefix("tldr_m031_clause_")
        .suffix(".ex")
        .tempfile()?;
    std::fs::write(tmp.path(), synthetic_source)?;
    Ok(tmp)
}

/// Convenience: run the per-clause iteration boilerplate. For each
/// body-bearing clause, build a synthetic source, write it to a temp
/// file, invoke `runner(temp_path, clause_meta, synthetic_offset)`,
/// and collect results. Returns `Ok(None)` if the file is not Elixir
/// or if there is only one (or zero) body-bearing clause — the caller
/// should then fall through to its legacy single-clause path.
pub fn for_each_body_bearing_clause<R, F>(
    file: &Path,
    function_name: &str,
    language: Language,
    mut runner: F,
) -> Result<Option<Vec<R>>>
where
    F: FnMut(&PathBuf, &ClauseMeta, u32) -> Result<R>,
{
    let Some(clauses) = list_body_bearing_clauses(file, function_name, language) else {
        return Ok(None);
    };
    if clauses.len() <= 1 {
        // Single-clause Elixir: no per-clause iteration needed; let
        // the legacy path handle it. The caller's existing
        // single-shot analyzer call already targets the (sole)
        // body-bearing clause via the M-E1 fix.
        return Ok(None);
    }
    let Some(source) = read_source(file) else {
        return Ok(None);
    };

    let mut out: Vec<R> = Vec::with_capacity(clauses.len());
    for clause in &clauses {
        let (synthetic, offset) = build_synthetic_clause_source(&source, clause);
        let tmp = write_temp_clause_file(&synthetic)?;
        let tmp_path = tmp.path().to_path_buf();
        let r = runner(&tmp_path, clause, offset)?;
        out.push(r);
        drop(tmp);
    }
    Ok(Some(out))
}

/// Merge an optional `per_clauses` array into an analyzer's top-level
/// JSON object. If `per_clauses` is `None`, returns `top_level`
/// unchanged. If `top_level` is not a JSON object, wraps it in
/// `{ "result": <top_level>, "per_clauses": [...] }` (defensive
/// fallback — every command in this cluster emits objects).
pub fn merge_per_clauses(
    top_level: serde_json::Value,
    per_clauses: Option<Vec<serde_json::Value>>,
) -> serde_json::Value {
    let Some(arr) = per_clauses else {
        return top_level;
    };
    match top_level {
        serde_json::Value::Object(mut map) => {
            map.insert(
                "per_clauses".to_string(),
                serde_json::Value::Array(arr),
            );
            serde_json::Value::Object(map)
        }
        other => {
            let mut map = serde_json::Map::new();
            map.insert("result".to_string(), other);
            map.insert(
                "per_clauses".to_string(),
                serde_json::Value::Array(arr),
            );
            serde_json::Value::Object(map)
        }
    }
}

/// Build a `per_clauses` JSON array entry for one clause + analyzer
/// output. Used by commands that emit a flat JSON object — the entry
/// flattens the analyzer result alongside `{start_line, end_line,
/// arity, has_body}` so callers can dump it under
/// `per_clauses: [...]`.
pub fn per_clause_entry_value(
    clause: &ClauseMeta,
    analyzer_output: serde_json::Value,
) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    entry.insert(
        "start_line".to_string(),
        serde_json::Value::from(clause.start_line),
    );
    entry.insert(
        "end_line".to_string(),
        serde_json::Value::from(clause.end_line),
    );
    entry.insert(
        "arity".to_string(),
        serde_json::Value::from(clause.arity as u64),
    );
    entry.insert(
        "has_body".to_string(),
        serde_json::Value::from(clause.has_body),
    );
    entry.insert("result".to_string(), analyzer_output);
    serde_json::Value::Object(entry)
}

/// Decide if the requested function should be treated as a
/// multi-clause Elixir function (and thus needs `per_clauses` emission).
/// Returns the clause list if so, `None` otherwise.
pub fn elixir_multi_clause_or_none(
    file: &Path,
    function_name: &str,
    language: Language,
) -> Option<Vec<ClauseMeta>> {
    let clauses = list_body_bearing_clauses(file, function_name, language)?;
    if clauses.len() <= 1 {
        None
    } else {
        Some(clauses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_preserves_line_numbers_when_clause_starts_after_line_1() {
        let src = "defmodule M do\n  def foo(1) do\n    1\n  end\n  def foo(x) do\n    x + 1\n  end\nend\n";
        // Both clauses start at line 2 and line 5 respectively.
        let c1 = ClauseMeta {
            start_line: 2,
            end_line: 4,
            arity: 1,
            has_body: true,
        };
        let (syn1, off1) = build_synthetic_clause_source(src, &c1);
        assert_eq!(off1, 0, "clause at line 2 must have zero offset");
        // The clause text should start at line 2 in the synthetic source.
        let syn1_lines: Vec<&str> = syn1.lines().collect();
        assert!(syn1_lines[1].contains("defmodule M do") || syn1_lines[0].is_empty());
        // Find the clause line and verify it's at the expected position.
        let clause_line_idx = syn1_lines
            .iter()
            .position(|l| l.contains("def foo(1) do"))
            .expect("synthetic must contain the clause text");
        // clause_line_idx is 0-based; line number is clause_line_idx + 1.
        assert_eq!(
            (clause_line_idx + 1) as u32,
            c1.start_line,
            "synthetic clause must sit at the same line number as original"
        );

        let c2 = ClauseMeta {
            start_line: 5,
            end_line: 7,
            arity: 1,
            has_body: true,
        };
        let (syn2, off2) = build_synthetic_clause_source(src, &c2);
        assert_eq!(off2, 0);
        let syn2_lines: Vec<&str> = syn2.lines().collect();
        let clause2_line_idx = syn2_lines
            .iter()
            .position(|l| l.contains("def foo(x) do"))
            .expect("synthetic must contain clause 2 text");
        assert_eq!((clause2_line_idx + 1) as u32, c2.start_line);
    }
}
