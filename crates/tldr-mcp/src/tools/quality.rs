//! Quality tools: context, change_impact, smells, maintainability, diagnostics, health, todo, diff, debt
//!
//! These tools provide code quality analysis and metrics.

use crate::protocol::ToolsCallResult;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tldr_core::callgraph::{confidence_tier, ResolutionRung};
use tldr_core::{ContextCallEdge, ContextEdgeProvenance, RelevantContext};

use super::{
    callgraph, get_optional_bool, get_optional_int, get_optional_string, get_optional_string_array,
    get_required_string, parse_min_confidence_arg, to_path, MinConfidence,
};

#[derive(Serialize)]
struct ContextOutput<'a> {
    schema: &'static str,
    #[serde(flatten)]
    context: &'a RelevantContext,
    unresolved: Vec<callgraph::UnresolvedOutput>,
}

/// Handle tldr_context tool call
pub fn handle_context(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let entry_point = match get_required_string(&args, "entry_point") {
        Ok(e) => e,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let depth = get_optional_int(&args, "depth").unwrap_or(2) as usize;
    let include_docstrings = get_optional_bool(&args, "include_docstrings").unwrap_or(false);
    let min_confidence = match parse_min_confidence_arg(&args) {
        Ok(tier) => tier,
        Err(e) => return ToolsCallResult::error(e),
    };

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = match language.parse::<tldr_core::Language>() {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    match tldr_core::get_relevant_context(
        &path,
        &entry_point,
        depth,
        lang,
        include_docstrings,
        None,
    ) {
        Ok(mut context) => {
            annotate_context_edges(&mut context, &path, lang, min_confidence);
            let unresolved = callgraph::unresolved_v2(&path, lang);
            let output = ContextOutput {
                schema: "context.v2",
                context: &context,
                unresolved,
            };
            match serde_json::to_string_pretty(&output) {
                Ok(json) => ToolsCallResult::text(json),
                Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
            }
        }
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

fn annotate_context_edges(
    context: &mut RelevantContext,
    project: &Path,
    language: tldr_core::Language,
    min_confidence: MinConfidence,
) {
    let Ok(graph) = tldr_core::build_project_call_graph(project, language, None, true) else {
        return;
    };
    let mut graph_edges: Vec<_> = graph.edges().cloned().collect();
    graph_edges.sort_by(|a, b| {
        a.src_file
            .cmp(&b.src_file)
            .then_with(|| a.src_func.cmp(&b.src_func))
            .then_with(|| a.call_line.cmp(&b.call_line))
            .then_with(|| a.dst_file.cmp(&b.dst_file))
            .then_with(|| a.dst_func.cmp(&b.dst_func))
    });

    let mut lines = HashMap::new();
    for func in &context.functions {
        lines.insert((func.file.clone(), func.name.clone()), func.line);
    }

    for func in context.functions.iter_mut() {
        func.call_edges.clear();
        for edge in &graph_edges {
            let rung = graph
                .edge_rung(edge)
                .unwrap_or(ResolutionRung::LocalFunction);
            if !min_confidence.includes_optional_rung(Some(rung)) {
                continue;
            }
            if context_node_matches(&func.file, &func.name, &edge.src_file, &edge.src_func) {
                func.call_edges.push(ContextCallEdge {
                    dst_file: edge.dst_file.clone(),
                    dst_func: edge.dst_func.clone(),
                    dst_line: lookup_context_line(&lines, &edge.dst_file, &edge.dst_func),
                    call_line: edge.call_line,
                    confidence: confidence_tier(rung).as_str().to_string(),
                    provenance: ContextEdgeProvenance {
                        rung: rung.id().to_string(),
                        mechanism: rung.mechanism().to_string(),
                    },
                });
            }
            if func.confidence.is_none()
                && func.name != context.entry_point
                && context_node_matches(&func.file, &func.name, &edge.dst_file, &edge.dst_func)
            {
                func.confidence = Some(confidence_tier(rung).as_str().to_string());
                func.provenance = Some(ContextEdgeProvenance {
                    rung: rung.id().to_string(),
                    mechanism: rung.mechanism().to_string(),
                });
            }
        }
        func.call_edges.sort_by(|a, b| {
            a.dst_file
                .cmp(&b.dst_file)
                .then_with(|| a.dst_func.cmp(&b.dst_func))
                .then_with(|| a.call_line.cmp(&b.call_line))
        });
        func.call_edges.dedup_by(|a, b| {
            a.dst_file == b.dst_file
                && a.dst_func == b.dst_func
                && a.call_line == b.call_line
                && a.provenance.rung == b.provenance.rung
        });
    }

    if min_confidence != MinConfidence::T2 {
        let entry = context.entry_point.clone();
        context.functions.retain(|func| {
            func.name == entry
                || func
                    .provenance
                    .as_ref()
                    .and_then(|p| rung_from_id(&p.rung))
                    .is_some_and(|rung| min_confidence.includes_rung(rung))
        });
    }
}

fn lookup_context_line(lines: &HashMap<(PathBuf, String), u32>, file: &Path, func: &str) -> u32 {
    for ((known_file, known_func), line) in lines {
        if context_node_matches(known_file, known_func, file, func) {
            return *line;
        }
    }
    0
}

fn context_path_matches(a: &Path, b: &Path) -> bool {
    a == b || a.ends_with(b) || b.ends_with(a)
}

fn context_node_matches(
    context_file: &Path,
    context_name: &str,
    edge_file: &Path,
    edge_name: &str,
) -> bool {
    context_path_matches(context_file, edge_file)
        && (context_name == edge_name
            || context_name == last_segment(edge_name)
            || last_segment(context_name) == edge_name
            || last_segment(context_name) == last_segment(edge_name))
}

fn last_segment(name: &str) -> &str {
    name.rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn rung_from_id(id: &str) -> Option<ResolutionRung> {
    match id {
        "constructor_method" => Some(ResolutionRung::ConstructorMethod),
        "constructor_class_fallback" => Some(ResolutionRung::ConstructorClassFallback),
        "local_function" => Some(ResolutionRung::LocalFunction),
        "local_method" => Some(ResolutionRung::LocalMethod),
        "import_map_exact" => Some(ResolutionRung::ImportMapExact),
        "import_map_alias" => Some(ResolutionRung::ImportMapAlias),
        "reexport_trace" => Some(ResolutionRung::ReExportTrace),
        "ref_import" => Some(ResolutionRung::RefImport),
        "ref_local" => Some(ResolutionRung::RefLocal),
        "global_free_function" => Some(ResolutionRung::GlobalFreeFunction),
        "static_qualified" => Some(ResolutionRung::StaticQualified),
        "method_in_class" => Some(ResolutionRung::MethodInClass),
        "method_in_base" => Some(ResolutionRung::MethodInBase),
        "cpp_out_of_line_method" => Some(ResolutionRung::CppOutOfLineMethod),
        "php_magic_call" => Some(ResolutionRung::PhpMagicCall),
        "receiver_type" => Some(ResolutionRung::ReceiverType),
        "self_receiver" => Some(ResolutionRung::SelfReceiver),
        "module_import_receiver" => Some(ResolutionRung::ModuleImportReceiver),
        "import_map_receiver" => Some(ResolutionRung::ImportMapReceiver),
        "local_qualified_receiver" => Some(ResolutionRung::LocalQualifiedReceiver),
        "ocaml_module_receiver" => Some(ResolutionRung::OcamlModuleReceiver),
        "capitalized_receiver_guess" => Some(ResolutionRung::CapitalizedReceiverGuess),
        "local_fuzzy_match" => Some(ResolutionRung::LocalFuzzyMatch),
        "global_fuzzy_match" => Some(ResolutionRung::GlobalFuzzyMatch),
        "type_aware_fallback" => Some(ResolutionRung::TypeAwareFallback),
        "super_dispatch" => Some(ResolutionRung::SuperDispatch),
        "reference_enrichment" => Some(ResolutionRung::ReferenceEnrichment),
        _ => None,
    }
}

/// Handle tldr_change_impact tool call
pub fn handle_change_impact(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let changed_files = get_optional_string_array(&args, "changed_files");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = match language.parse::<tldr_core::Language>() {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let changed: Option<Vec<std::path::PathBuf>> =
        changed_files.map(|files| files.into_iter().map(|f| to_path(&f)).collect());

    match tldr_core::change_impact(&path, changed.as_deref(), lang) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_smells tool call
pub fn handle_smells(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let threshold_str =
        get_optional_string(&args, "threshold").unwrap_or_else(|| "default".to_string());
    let smell_type_str = get_optional_string(&args, "smell_type");
    let suggest = get_optional_bool(&args, "suggest").unwrap_or(false);

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let threshold = match threshold_str.to_lowercase().as_str() {
        "strict" => tldr_core::ThresholdPreset::Strict,
        "relaxed" => tldr_core::ThresholdPreset::Relaxed,
        _ => tldr_core::ThresholdPreset::Default,
    };

    let smell_type = smell_type_str.and_then(|s| match s.as_str() {
        "GodClass" => Some(tldr_core::SmellType::GodClass),
        "LongMethod" => Some(tldr_core::SmellType::LongMethod),
        "LongParameterList" => Some(tldr_core::SmellType::LongParameterList),
        "FeatureEnvy" => Some(tldr_core::SmellType::FeatureEnvy),
        "DataClumps" => Some(tldr_core::SmellType::DataClumps),
        _ => None,
    });

    match tldr_core::detect_smells(&path, threshold, smell_type, suggest) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_maintainability tool call
pub fn handle_maintainability(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let include_halstead = get_optional_bool(&args, "include_halstead").unwrap_or(false);
    let language = get_optional_string(&args, "language");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = language.and_then(|l| l.parse::<tldr_core::Language>().ok());

    match tldr_core::maintainability_index(&path, include_halstead, lang) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_diagnostics tool call
pub fn handle_diagnostics(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let _language = get_optional_string(&args, "language");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    // Diagnostics requires external tools (pyright, ruff, etc.)
    // For now, return a placeholder response indicating it needs external tooling
    ToolsCallResult::text(serde_json::json!({
        "status": "not_implemented",
        "message": "Diagnostics requires external tools (pyright, ruff). Run these directly for now.",
        "path": path.display().to_string()
    }).to_string())
}

/// Handle tldr_diff tool call
pub fn handle_diff(args: Value) -> ToolsCallResult {
    let old = match get_required_string(&args, "old") {
        Ok(o) => o,
        Err(e) => return ToolsCallResult::error(e),
    };

    let new = match get_required_string(&args, "new") {
        Ok(n) => n,
        Err(e) => return ToolsCallResult::error(e),
    };

    let _language = get_optional_string(&args, "language");

    let old_path = to_path(&old);
    let new_path = to_path(&new);

    if !old_path.exists() {
        return ToolsCallResult::error(format!("Old path not found: {}", old_path.display()));
    }
    if !new_path.exists() {
        return ToolsCallResult::error(format!("New path not found: {}", new_path.display()));
    }

    // Semantic diff is complex - return placeholder for now
    ToolsCallResult::text(
        serde_json::json!({
            "status": "not_implemented",
            "message": "Semantic diff is planned for future implementation",
            "old": old,
            "new": new
        })
        .to_string(),
    )
}

/// Handle tldr_debt tool call
pub fn handle_debt(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let _language = get_optional_string(&args, "language");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    // Technical debt estimation combines multiple metrics
    // For now, return placeholder
    ToolsCallResult::text(
        serde_json::json!({
            "status": "not_implemented",
            "message": "Technical debt estimation is planned for future implementation",
            "path": path.display().to_string()
        })
        .to_string(),
    )
}

/// Handle tldr_health tool call (composite)
pub fn handle_health(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let _language = get_optional_string(&args, "language");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    // Health dashboard combines smells, maintainability, and complexity
    // Run maintainability as a quick health indicator
    match tldr_core::maintainability_index(&path, false, None) {
        Ok(mi_report) => {
            match tldr_core::detect_smells(&path, tldr_core::ThresholdPreset::Default, None, false)
            {
                Ok(smells_report) => {
                    let health_score = if mi_report.summary.average_mi >= 80.0
                        && smells_report.summary.total_smells == 0
                    {
                        "excellent"
                    } else if mi_report.summary.average_mi >= 60.0
                        && smells_report.summary.total_smells < 5
                    {
                        "good"
                    } else if mi_report.summary.average_mi >= 40.0
                        && smells_report.summary.total_smells < 10
                    {
                        "fair"
                    } else {
                        "needs_attention"
                    };

                    ToolsCallResult::text(
                        serde_json::json!({
                            "health_score": health_score,
                            "maintainability": {
                                "average_mi": mi_report.summary.average_mi,
                                "min_mi": mi_report.summary.min_mi,
                                "max_mi": mi_report.summary.max_mi,
                                "files_analyzed": mi_report.summary.files_analyzed
                            },
                            "smells": {
                                "total": smells_report.summary.total_smells,
                                "files_with_smells": smells_report.smells.len()
                            }
                        })
                        .to_string(),
                    )
                }
                Err(e) => ToolsCallResult::error(format!("Error analyzing smells: {}", e)),
            }
        }
        Err(e) => ToolsCallResult::error(format!("Error calculating maintainability: {}", e)),
    }
}

/// Handle tldr_todo tool call (composite)
pub fn handle_todo(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let _language = get_optional_string(&args, "language");

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    // Generate action items from analysis
    let mut todos = Vec::new();

    // Check for code smells
    if let Ok(smells_report) =
        tldr_core::detect_smells(&path, tldr_core::ThresholdPreset::Default, None, true)
    {
        for smell in smells_report.smells.iter().take(10) {
            todos.push(serde_json::json!({
                "category": "smell",
                "priority": "medium",
                "file": smell.file.display().to_string(),
                "line": smell.line,
                "description": smell.reason,
                "suggestion": smell.suggestion
            }));
        }
    }

    // Check for secrets
    if let Ok(secrets_report) = tldr_core::scan_secrets(&path, 4.5, false, None) {
        for secret in secrets_report.findings.iter().take(5) {
            todos.push(serde_json::json!({
                "category": "security",
                "priority": "high",
                "file": secret.file.display().to_string(),
                "line": secret.line,
                "description": format!("Potential secret found: {}", secret.pattern),
                "suggestion": "Remove hardcoded secret and use environment variables"
            }));
        }
    }

    ToolsCallResult::text(
        serde_json::json!({
            "total_items": todos.len(),
            "action_items": todos
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_handle_context_missing_args() {
        let result = handle_context(json!({}));
        assert!(result.is_error == Some(true));
    }

    #[test]
    fn test_handle_smells_path_not_found() {
        let result = handle_smells(json!({"path": "/nonexistent/path"}));
        assert!(result.is_error == Some(true));
        assert!(result.content[0].text.contains("Path not found"));
    }

    #[test]
    fn test_handle_maintainability_missing_path() {
        let result = handle_maintainability(json!({}));
        assert!(result.is_error == Some(true));
    }
}
