//! Call Graph Layer (L2) handlers: calls, impact, dead, importers, arch
//!
//! These handlers provide cross-file call graph analysis, impact analysis,
//! dead code detection, importer tracking, and architecture inference.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Deserialize;

use crate::server::{DaemonResponse, HandlerError};
use crate::state::DaemonState;

use tldr_core::{
    architecture_analysis, build_project_call_graph, dead_code_analysis, find_importers,
    impact_analysis, ArchitectureReport, DeadCodeReport, FunctionRef, ImpactReport,
    ImportersReport, Language, ProjectCallGraph,
};

// =============================================================================
// Calls Handler
// =============================================================================

/// Calls request parameters
#[derive(Debug, Deserialize)]
pub struct CallsRequest {
    pub language: String,
}

/// Calls handler - builds cross-file call graph
pub async fn calls(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<CallsRequest>,
) -> Result<Json<DaemonResponse<CallsResponse>>, HandlerError> {
    state.touch();

    let language: Language = request
        .language
        .parse()
        .map_err(|e: String| HandlerError(axum::http::StatusCode::BAD_REQUEST, e))?;

    // Use cached call graph or build new one (M12)
    let project = state.project().clone();
    let graph = state
        .get_or_build_call_graph(language, || async move {
            // Run in blocking context (M10)
            tokio::task::spawn_blocking(move || {
                build_project_call_graph(&project, language, None, true)
                    // why: a swallowed build error was cached as an empty graph forever
                    // (get_or_build_call_graph caches the closure's return value), so a
                    // parse/IO failure silently looked like "project has no calls" on every
                    // future request. Log it so the failure is at least observable.
                    .unwrap_or_else(|e| {
                        tracing::error!("build_project_call_graph failed: {e}");
                        ProjectCallGraph::new()
                    })
            })
            .await
            .unwrap_or_else(|_| ProjectCallGraph::new())
        })
        .await;

    let response = CallsResponse {
        edge_count: graph.edge_count(),
        edges: graph.edges().cloned().collect(),
    };

    Ok(Json(DaemonResponse::ok(response)))
}

/// Response for calls endpoint
#[derive(Debug, serde::Serialize)]
pub struct CallsResponse {
    pub edge_count: usize,
    pub edges: Vec<tldr_core::CallEdge>,
}

// =============================================================================
// Impact Handler
// =============================================================================

/// Impact request parameters
#[derive(Debug, Deserialize)]
pub struct ImpactRequest {
    pub func: String,
    #[serde(default = "default_depth")]
    pub depth: usize,
    #[serde(default)]
    pub file: Option<String>,
    pub language: String,
}

fn default_depth() -> usize {
    3
}

/// Impact handler - finds all callers of a function
pub async fn impact(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<ImpactRequest>,
) -> Result<Json<DaemonResponse<ImpactReport>>, HandlerError> {
    state.touch();

    let language: Language = request
        .language
        .parse()
        .map_err(|e: String| HandlerError(axum::http::StatusCode::BAD_REQUEST, e))?;

    let project = state.project().clone();
    let func = request.func.clone();
    let depth = request.depth;
    let target_file = request.file.map(PathBuf::from);

    // Get or build call graph
    let graph = state
        .get_or_build_call_graph(language, || async move {
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                build_project_call_graph(&project, language, None, true)
                    // why: a swallowed build error was cached as an empty graph forever
                    // (get_or_build_call_graph caches the closure's return value), so a
                    // parse/IO failure silently looked like "project has no calls" on every
                    // future request. Log it so the failure is at least observable.
                    .unwrap_or_else(|e| {
                        tracing::error!("build_project_call_graph failed: {e}");
                        ProjectCallGraph::new()
                    })
            })
            .await
            .unwrap_or_else(|_| ProjectCallGraph::new())
        })
        .await;

    // Run impact analysis
    let result = impact_analysis(&graph, &func, depth, target_file.as_deref())
        .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DaemonResponse::ok(result)))
}

// =============================================================================
// Dead Handler
// =============================================================================

/// Dead code request parameters
#[derive(Debug, Deserialize)]
pub struct DeadRequest {
    pub language: String,
    #[serde(default)]
    pub entry_points: Option<Vec<String>>,
}

/// Dead handler - finds unreachable functions
pub async fn dead(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<DeadRequest>,
) -> Result<Json<DaemonResponse<DeadCodeReport>>, HandlerError> {
    state.touch();

    let language: Language = request
        .language
        .parse()
        .map_err(|e: String| HandlerError(axum::http::StatusCode::BAD_REQUEST, e))?;

    let project = state.project().clone();
    let entry_points = request.entry_points;

    // TRDD-O66FM8TN: dead-code analysis needs the skipped-file list, and
    // only the raw CallGraphIR carries it (`build_project_call_graph`'s
    // ProjectCallGraph wrapper drops `warnings` entirely in
    // `project_graph_from_ir` — tldr-core/src/callgraph/builder.rs). So
    // build the IR directly here instead of going through the shared,
    // cached ProjectCallGraph used by `calls` — that cache cannot carry
    // warnings because ProjectCallGraph has no field for them.
    // The bypass is NOT only a caching difference — do not "optimize" it away.
    // This path builds with `use_type_resolution = true` and, when
    // `WorkspaceConfig::discover` finds roots, with those workspace roots. The
    // cached path (`calls`/`impact`/`arch`) calls `build_project_call_graph`
    // and passes neither. On a multi-root workspace the two produce DIFFERENT
    // edge sets, and this one sees more. Moving `dead` back onto the shared
    // cache without reproducing both settings would silently lose edges and
    // resurrect the dead-code false positives TRDD-O66FM8TN exists to kill —
    // a correctness regression wearing a performance change's clothes.
    // ponytail: the cost is that `dead` rebuilds the graph every request. If
    // that ever matters, cache a (graph, warnings) pair built with THIS
    // config; do not reuse the `calls` cache.
    let build_root = project.clone();
    let ir = tokio::task::spawn_blocking(move || {
        let mut config = tldr_core::callgraph::BuildConfig {
            language: language.as_str().to_string(),
            respect_ignore: true,
            ..Default::default()
        };
        config.use_type_resolution = true;
        if let Some(ws) = tldr_core::WorkspaceConfig::discover(&build_root) {
            if !ws.roots.is_empty() {
                config.use_workspace_config = true;
                config.workspace_roots = ws.roots;
            }
        }
        tldr_core::callgraph::build_project_call_graph_v2(&build_root, config)
    })
    .await
    .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let graph = tldr_core::callgraph::builder::project_graph_from_ir_ref(&ir);

    // Collect all functions (this should come from structure extraction)
    // For now, collect from call graph edges
    let all_functions: Vec<FunctionRef> = graph
        .edges()
        .flat_map(|e| {
            vec![
                FunctionRef::new(e.src_file.clone(), &e.src_func),
                FunctionRef::new(e.dst_file.clone(), &e.dst_func),
            ]
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let mut result = dead_code_analysis(&graph, &all_functions, entry_points.as_deref())
        .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    result.files_skipped = ir.warnings.len();
    result.warnings = ir.warnings;

    Ok(Json(DaemonResponse::ok(result)))
}

// =============================================================================
// Importers Handler
// =============================================================================

/// Importers request parameters
#[derive(Debug, Deserialize)]
pub struct ImportersRequest {
    pub module: String,
    pub language: String,
}

/// Importers handler - finds all files importing a module
pub async fn importers(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<ImportersRequest>,
) -> Result<Json<DaemonResponse<ImportersReport>>, HandlerError> {
    state.touch();

    let language: Language = request
        .language
        .parse()
        .map_err(|e: String| HandlerError(axum::http::StatusCode::BAD_REQUEST, e))?;

    let project = state.project().clone();
    let module = request.module;

    // Run in blocking context (M10)
    let result = tokio::task::spawn_blocking(move || find_importers(&project, &module, language))
        .await
        .map_err(|e| {
            HandlerError(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Task join error: {}", e),
            )
        })?
        .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DaemonResponse::ok(result)))
}

// =============================================================================
// Arch Handler
// =============================================================================

/// Arch request parameters
#[derive(Debug, Deserialize)]
pub struct ArchRequest {
    pub language: String,
}

/// Arch handler - analyzes codebase architecture
pub async fn arch(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<ArchRequest>,
) -> Result<Json<DaemonResponse<ArchitectureReport>>, HandlerError> {
    state.touch();

    let language: Language = request
        .language
        .parse()
        .map_err(|e: String| HandlerError(axum::http::StatusCode::BAD_REQUEST, e))?;

    let project = state.project().clone();

    // Get or build call graph
    let graph = state
        .get_or_build_call_graph(language, || async {
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                build_project_call_graph(&project, language, None, true)
                    // why: a swallowed build error was cached as an empty graph forever
                    // (get_or_build_call_graph caches the closure's return value), so a
                    // parse/IO failure silently looked like "project has no calls" on every
                    // future request. Log it so the failure is at least observable.
                    .unwrap_or_else(|e| {
                        tracing::error!("build_project_call_graph failed: {e}");
                        ProjectCallGraph::new()
                    })
            })
            .await
            .unwrap_or_else(|_| ProjectCallGraph::new())
        })
        .await;

    let result = architecture_analysis(&graph)
        .map_err(|e| HandlerError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DaemonResponse::ok(result)))
}
