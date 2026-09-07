//! TRDD-O66FM8TN — the MCP `tldr_dead` tool must report unreadable source
//! files, not drop them.
//!
//! Dead-code analysis is whole-program: a function whose only caller lives in
//! a file the scan couldn't decode is reported dead when it isn't. Before the
//! fix, `handle_dead` called `get_code_structure` only to harvest function
//! names and threw away `structure.warnings` / `structure.files_skipped`, so
//! the JSON response gave no sign that 5 of the 8 fixture files were excluded.
//!
//! Fixtures: `design/reproducers/TRDD-BKALIK1B/` — 3 readable Python files
//! (control.py, good.py, late_nul.py) and 5 files the scanner cannot decode
//! (bad.py, nobom.py, u16be.py, u32be.py, u32le.py).
//!
//! The assertion is on the WARNING TEXT naming each skipped file, never on
//! mere absence from the results — absence is exactly what the bug produced
//! too (a `files_skipped` reader must not accept "I don't see it" as proof).

use serde_json::json;
use tldr_mcp::tools::callgraph::handle_dead;

const UNREADABLE: &[&str] = &["bad.py", "nobom.py", "u16be.py", "u32be.py", "u32le.py"];
const READABLE: &[&str] = &["control.py", "good.py", "late_nul.py"];

#[test]
fn dead_reports_every_unreadable_file_by_name_in_warnings() {
    let result = handle_dead(json!({
        "path": "../../design/reproducers/TRDD-BKALIK1B",
        "language": "python",
    }));

    assert_ne!(result.is_error, Some(true), "handle_dead returned an error");
    let text = &result.content.first().expect("content item").text;
    let report: serde_json::Value = serde_json::from_str(text).expect("valid JSON report");

    assert_eq!(
        report["filesSkipped"].as_u64().or_else(|| report["files_skipped"].as_u64()),
        Some(UNREADABLE.len() as u64),
        "report: {text}"
    );

    let warnings = report["warnings"]
        .as_array()
        .expect("warnings array present")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    for name in UNREADABLE {
        assert!(
            warnings.iter().any(|w| w.contains(name)),
            "expected a warning naming {name}, got: {warnings:?}"
        );
    }
    for name in READABLE {
        assert!(
            !warnings.iter().any(|w| w.contains(name)),
            "readable file {name} must not appear in warnings, got: {warnings:?}"
        );
    }
}
