//! Call graph tools: calls, impact, dead, importers, arch
//!
//! These tools provide cross-file analysis of function calls and dependencies.

use crate::protocol::ToolsCallResult;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use tldr_core::analysis::impact::{
    exclude_approximate_callers_from_report, impact_analysis_with_ast_fallback_options,
    populate_caller_tree_lines,
};
use tldr_core::callgraph::cross_file_types::CallType;
use tldr_core::callgraph::{
    build_project_call_graph_v2, confidence_tier, BuildConfig, CallGraphIR,
};
use tldr_core::types::{DeadCodeReport, ImpactReport};

use super::{
    get_optional_bool, get_optional_int, get_optional_string, get_optional_string_array,
    get_required_string, parse_min_confidence_arg, to_path, MinConfidence,
};

#[derive(Debug, Serialize)]
struct CallGraphOutput {
    schema: &'static str,
    root: PathBuf,
    language: tldr_core::Language,
    nodes: Vec<String>,
    edges: Vec<EdgeOutput>,
    unresolved: Vec<UnresolvedOutput>,
    truncated: bool,
    total_edges: usize,
    shown_edges: usize,
}

#[derive(Debug, Serialize)]
struct EdgeOutput {
    src_file: PathBuf,
    src_func: String,
    src_line: u32,
    call_line: Option<u32>,
    dst_file: PathBuf,
    dst_func: String,
    dst_line: u32,
    call_type: CallType,
    confidence: String,
    provenance: EdgeProvenance,
    staleness: EdgeStaleness,
}

#[derive(Debug, Serialize)]
struct EdgeProvenance {
    rung: String,
    mechanism: String,
}

#[derive(Debug, Serialize)]
struct EdgeStaleness {
    src_hash: String,
    generated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct UnresolvedOutput {
    caller_file: PathBuf,
    caller_func: String,
    target: String,
    line: Option<u32>,
    reason: String,
}

#[derive(Serialize)]
struct ImpactOutput<'a> {
    schema: &'static str,
    #[serde(flatten)]
    report: &'a ImpactReport,
}

#[derive(Serialize)]
struct DeadOutput<'a> {
    schema: &'static str,
    #[serde(flatten)]
    report: &'a DeadCodeReport,
}

/// Handle tldr_calls tool call
pub fn handle_calls(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
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
    let min_confidence = match parse_min_confidence_arg(&args) {
        Ok(tier) => tier,
        Err(e) => return ToolsCallResult::error(e),
    };

    let config = BuildConfig {
        language: lang.as_str().to_string(),
        respect_ignore: true,
        use_type_resolution: true,
        ..Default::default()
    };
    match build_project_call_graph_v2(&path, config) {
        Ok(ir) => {
            let output = calls_v2_output(&path, lang, &ir, min_confidence);
            serialize_text(&output)
        }
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_impact tool call
pub fn handle_impact(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let function = match get_required_string(&args, "function") {
        Ok(f) => f,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let depth = get_optional_int(&args, "depth").unwrap_or(3) as usize;
    let file_filter = get_optional_string(&args, "file");
    let approximate = get_optional_bool(&args, "approximate").unwrap_or(false);

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = match language.parse::<tldr_core::Language>() {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    // First build the call graph
    let call_graph = match tldr_core::build_project_call_graph(&path, lang, None, true) {
        Ok(cg) => cg,
        Err(e) => return ToolsCallResult::error(format!("Error building call graph: {}", e)),
    };

    let file_path = file_filter.map(|f| to_path(&f));

    match impact_analysis_with_ast_fallback_options(
        &call_graph,
        &function,
        depth,
        file_path.as_deref(),
        &path,
        lang,
        approximate,
    ) {
        Ok(mut report) => {
            tldr_core::enrich_impact_with_references(&mut report, &path, &function, lang);
            if !approximate {
                exclude_approximate_callers_from_report(&mut report);
            }
            populate_caller_tree_lines(&mut report, &path, lang);
            if !approximate {
                exclude_approximate_callers_from_report(&mut report);
            }
            serialize_text(&ImpactOutput {
                schema: "impact.v2",
                report: &report,
            })
        }
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_dead tool call
pub fn handle_dead(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    let entry_points = get_optional_string_array(&args, "entry_points");
    let approximate = get_optional_bool(&args, "approximate").unwrap_or(false);

    let path = to_path(&path);
    if !path.exists() {
        return ToolsCallResult::error(format!("Path not found: {}", path.display()));
    }

    let lang = match language.parse::<tldr_core::Language>() {
        Ok(l) => l,
        Err(e) => return ToolsCallResult::error(e),
    };

    // Build call graph first
    let call_graph = match tldr_core::build_project_call_graph(&path, lang, None, true) {
        Ok(cg) => cg,
        Err(e) => return ToolsCallResult::error(format!("Error building call graph: {}", e)),
    };

    // Get all functions from structure
    let all_functions = match tldr_core::get_code_structure(&path, lang, 0, None) {
        Ok(structure) => {
            let mut funcs = Vec::new();
            for file in structure.files {
                for func_name in file.functions {
                    funcs.push(tldr_core::FunctionRef::new(file.path.clone(), func_name));
                }
            }
            funcs
        }
        Err(e) => return ToolsCallResult::error(format!("Error getting structure: {}", e)),
    };

    let entry_refs: Option<Vec<String>> = entry_points;

    match tldr_core::dead_code_analysis(&call_graph, &all_functions, entry_refs.as_deref()) {
        Ok(mut report) => {
            if approximate {
                promote_possibly_dead(&mut report);
            }
            serialize_text(&DeadOutput {
                schema: "dead.v2",
                report: &report,
            })
        }
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

/// Handle tldr_importers tool call
pub fn handle_importers(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let module = match get_required_string(&args, "module") {
        Ok(m) => m,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
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

    match tldr_core::find_importers(&path, &module, lang) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

fn serialize_text<T: Serialize>(value: &T) -> ToolsCallResult {
    match serde_json::to_string_pretty(value) {
        Ok(json) => ToolsCallResult::text(json),
        Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
    }
}

fn calls_v2_output(
    root: &Path,
    language: tldr_core::Language,
    ir: &CallGraphIR,
    min_confidence: MinConfidence,
) -> CallGraphOutput {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let definition_lines = definition_line_index(ir);
    let generated_at = chrono::Utc::now().date_naive().to_string();
    let mut source_hashes: HashMap<PathBuf, String> = HashMap::new();
    let mut edges = Vec::new();

    for edge in &ir.edges {
        if !min_confidence.includes_rung(edge.rung) {
            continue;
        }
        let src_file = relative_to_root(&edge.src_file, &canonical_root);
        let dst_file = relative_to_root(&edge.dst_file, &canonical_root);
        let src_hash = source_hashes
            .entry(edge.src_file.clone())
            .or_insert_with(|| sha256_file_hex(&canonical_root, &edge.src_file))
            .clone();
        edges.push(EdgeOutput {
            src_file,
            src_func: edge.src_func.clone(),
            src_line: definition_lines
                .get(&(edge.src_file.clone(), edge.src_func.clone()))
                .copied()
                .unwrap_or(0),
            call_line: edge.call_line,
            dst_file,
            dst_func: edge.dst_func.clone(),
            dst_line: definition_lines
                .get(&(edge.dst_file.clone(), edge.dst_func.clone()))
                .copied()
                .unwrap_or(0),
            call_type: edge.call_type,
            confidence: confidence_tier(edge.rung).as_str().to_string(),
            provenance: EdgeProvenance {
                rung: edge.rung.id().to_string(),
                mechanism: edge.rung.mechanism().to_string(),
            },
            staleness: EdgeStaleness {
                src_hash,
                generated_at: generated_at.clone(),
            },
        });
    }

    edges.sort_by(|a, b| {
        a.src_file
            .cmp(&b.src_file)
            .then_with(|| a.src_func.cmp(&b.src_func))
            .then_with(|| a.call_line.cmp(&b.call_line))
            .then_with(|| a.dst_file.cmp(&b.dst_file))
            .then_with(|| a.dst_func.cmp(&b.dst_func))
    });
    let total_edges = edges.len();

    let mut unresolved: Vec<UnresolvedOutput> = ir
        .unresolved
        .iter()
        .map(|call| UnresolvedOutput {
            caller_file: relative_to_root(&call.caller_file, &canonical_root),
            caller_func: call.caller_func.clone(),
            target: call.target.clone(),
            line: call.line,
            reason: call.reason.clone(),
        })
        .collect();
    unresolved.sort_by(|a, b| {
        a.caller_file
            .cmp(&b.caller_file)
            .then_with(|| a.caller_func.cmp(&b.caller_func))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.target.cmp(&b.target))
    });

    let mut node_set = BTreeSet::new();
    for edge in &edges {
        node_set.insert(format!("{}:{}", edge.src_file.display(), edge.src_func));
        node_set.insert(format!("{}:{}", edge.dst_file.display(), edge.dst_func));
    }
    for (file_path, file_ir) in &ir.files {
        let rel = relative_to_root(file_path, &canonical_root);
        for func in &file_ir.funcs {
            let qualified = if let Some(class_name) = &func.class_name {
                format!("{}.{}", class_name, func.name)
            } else {
                func.name.clone()
            };
            node_set.insert(format!("{}:{}", rel.display(), qualified));
        }
    }

    CallGraphOutput {
        schema: "calls.v2",
        root: root.to_path_buf(),
        language,
        nodes: node_set.into_iter().collect(),
        edges,
        unresolved,
        truncated: false,
        total_edges,
        shown_edges: total_edges,
    }
}

pub(crate) fn unresolved_v2(root: &Path, language: tldr_core::Language) -> Vec<UnresolvedOutput> {
    let config = BuildConfig {
        language: language.as_str().to_string(),
        respect_ignore: true,
        use_type_resolution: true,
        ..Default::default()
    };
    let Ok(ir) = build_project_call_graph_v2(root, config) else {
        return Vec::new();
    };
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut unresolved: Vec<UnresolvedOutput> = ir
        .unresolved
        .iter()
        .map(|call| UnresolvedOutput {
            caller_file: relative_to_root(&call.caller_file, &canonical_root),
            caller_func: call.caller_func.clone(),
            target: call.target.clone(),
            line: call.line,
            reason: call.reason.clone(),
        })
        .collect();
    unresolved.sort_by(|a, b| {
        a.caller_file
            .cmp(&b.caller_file)
            .then_with(|| a.caller_func.cmp(&b.caller_func))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.target.cmp(&b.target))
    });
    unresolved
}

fn definition_line_index(ir: &CallGraphIR) -> HashMap<(PathBuf, String), u32> {
    let mut lines = HashMap::new();
    for (file_path, file_ir) in &ir.files {
        for func in &file_ir.funcs {
            lines
                .entry((file_path.clone(), func.name.clone()))
                .or_insert(func.line);
            if let Some(class_name) = &func.class_name {
                lines
                    .entry((file_path.clone(), format!("{}.{}", class_name, func.name)))
                    .or_insert(func.line);
            }
        }
    }
    lines
}

fn relative_to_root(path: &Path, root: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn sha256_file_hex(root: &Path, file: &Path) -> String {
    let path = if file.is_absolute() {
        file.to_path_buf()
    } else {
        root.join(file)
    };
    let bytes = fs::read(path).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn promote_possibly_dead(report: &mut DeadCodeReport) {
    let promoted = std::mem::take(&mut report.possibly_dead);
    for function in promoted {
        report
            .by_file
            .entry(function.file.clone())
            .or_default()
            .push(function.name.clone());
        report.dead_functions.push(function);
    }
    report.total_dead = report.dead_functions.len();
    report.total_possibly_dead = 0;
    report.dead_percentage = if report.total_functions == 0 {
        0.0
    } else {
        (report.total_dead as f64 / report.total_functions as f64) * 100.0
    };
}

/// Handle tldr_arch tool call
pub fn handle_arch(args: Value) -> ToolsCallResult {
    let path = match get_required_string(&args, "path") {
        Ok(p) => p,
        Err(e) => return ToolsCallResult::error(e),
    };

    let language = match get_required_string(&args, "language") {
        Ok(l) => l,
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

    // Build call graph first
    let call_graph = match tldr_core::build_project_call_graph(&path, lang, None, true) {
        Ok(cg) => cg,
        Err(e) => return ToolsCallResult::error(format!("Error building call graph: {}", e)),
    };

    match tldr_core::architecture_analysis(&call_graph) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => ToolsCallResult::text(json),
            Err(e) => ToolsCallResult::error(format!("Serialization error: {}", e)),
        },
        Err(e) => ToolsCallResult::error(format!("Error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_handle_calls_missing_args() {
        let result = handle_calls(json!({}));
        assert!(result.is_error == Some(true));
    }

    #[test]
    fn test_handle_impact_missing_function() {
        let result = handle_impact(json!({"path": ".", "language": "python"}));
        assert!(result.is_error == Some(true));
        assert!(result.content[0].text.contains("Missing required argument"));
    }

    #[test]
    fn test_handle_dead_missing_language() {
        let result = handle_dead(json!({"path": "."}));
        assert!(result.is_error == Some(true));
    }
}
