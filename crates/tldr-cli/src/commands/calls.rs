//! Calls command - Build call graph
//!
//! Builds and displays the cross-file call graph for a project.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use tldr_core::callgraph::cross_file_types::CallType;
use tldr_core::callgraph::{build_project_call_graph_v2, BuildConfig};
use tldr_core::Language;

use crate::commands::daemon_router::{params_with_path_lang, try_daemon_route};
use crate::output::{format_calls_dot, DotCallEdge, OutputFormat, OutputWriter};

/// Build and display cross-file call graph
#[derive(Debug, Args)]
pub struct CallsArgs {
    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detected if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Respect .gitignore and .tldrignore patterns
    #[arg(long, default_value = "true")]
    pub respect_ignore: bool,

    /// Maximum items (edges) to include in output (default: 200)
    #[arg(long, default_value_t = DEFAULT_CALLS_MAX_ITEMS)]
    pub max_items: usize,
}

/// Default edge truncation limit shared with the daemon's Calls handler.
///
/// Matches the clap `default_value` of `CallsArgs::max_items`; the daemon
/// builds the cached payload with the same limit so a warm cache slot is
/// exactly the slot a default `tldr calls` request reads.
pub(crate) const DEFAULT_CALLS_MAX_ITEMS: usize = 200;

/// Call graph output format
///
/// med-low-schema-cleanup-v1 (N12): the redundant `edge_count` and
/// `node_count` keys were removed. `total_edges` + `shown_edges` +
/// `truncated` is the single canonical pair (mirrors what `references`
/// and `dead` use); `node_count` was always equal to `nodes.len()` so
/// consumers can derive it locally.
///
/// daemon-calls-payload-v1: `pub(crate)` because the IPC daemon's Calls
/// handler serializes THIS type as its cached payload. Pre-fix the daemon
/// serialized the raw `ProjectCallGraph` (`{"edges": [...]}`), which never
/// deserialized into `CallGraphOutput` — `try_daemon_route` always returned
/// `None` and `tldr calls` silently fell back to direct compute, making the
/// daemon cache useless for the calls command.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CallGraphOutput {
    pub(crate) root: PathBuf,
    /// Resolved language. `None` (serialized as JSON `null`) when the
    /// caller passed no `--lang` flag and `Language::from_directory`
    /// found no analyzable files (e.g. the path is an empty directory).
    ///
    /// schema-cleanup-v2 (P2.BUG-10): pre-fix the type was `Language`
    /// and the `unwrap_or(Language::Python)` autodetect fallback caused
    /// an empty directory to be reported as `language: "python"` —
    /// silently picking a default that misrepresented the input. Now
    /// the field is `Option<Language>` and the autodetect failure
    /// surfaces as JSON `null`, which downstream consumers can branch
    /// on without parsing English error strings.
    pub(crate) language: Option<Language>,
    pub(crate) nodes: Vec<String>,
    pub(crate) edges: Vec<EdgeOutput>,
    /// Whether the output was truncated due to max_items limit
    ///
    /// (path-and-schema-cleanup-v3 P3.BUG-N5) Always emitted — including
    /// when `false` — so schema consumers do not need to handle the
    /// absent-key case. Previously elided via `skip_serializing_if`, but
    /// downstream tooling (and `references`, `dead`, `dice`, etc.) all
    /// treat `truncated` as a stable boolean key.
    #[serde(default)]
    pub(crate) truncated: bool,
    /// Total number of edges before truncation
    pub(crate) total_edges: usize,
    /// Number of edges shown after truncation
    pub(crate) shown_edges: usize,
    /// Number of source files the builder could not read and dropped.
    ///
    /// TRDD-O66FM8TN: a dropped file means missing edges, so the graph is
    /// confidently incomplete unless the omission is in the output.
    /// `#[serde(default)]` keeps cached daemon payloads deserializable.
    #[serde(default)]
    pub(crate) files_skipped: usize,
    /// One `Skipped <path>: <reason>` line per dropped file.
    #[serde(default)]
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EdgeOutput {
    pub(crate) src_file: PathBuf,
    pub(crate) src_func: String,
    pub(crate) dst_file: PathBuf,
    pub(crate) dst_func: String,
    pub(crate) call_type: CallType,
}

impl CallGraphOutput {
    /// Build the call-graph output from the v2 IR.
    ///
    /// daemon-calls-payload-v1: shared between the CLI's direct-compute path
    /// and the IPC daemon's Calls handler so the cached daemon payload is the
    /// SAME shape direct compute prints (the round-trip through
    /// `try_daemon_route::<CallGraphOutput>` is then lossless by
    /// construction). Path normalization, the edge sort/truncation and the
    /// node derivation from the FINAL edge list plus every defined function
    /// all mirror the direct path exactly.
    pub(crate) fn from_ir(
        ir: &tldr_core::callgraph::cross_file_types::CallGraphIR,
        strip_root: &Path,
        display_root: &Path,
        language: Option<Language>,
        max_items: usize,
    ) -> Self {
        let edges: Vec<EdgeOutput> = ir
            .edges
            .iter()
            .map(|e| {
                let src = e.src_file.strip_prefix(strip_root).unwrap_or(&e.src_file);
                let dst = e.dst_file.strip_prefix(strip_root).unwrap_or(&e.dst_file);
                EdgeOutput {
                    src_file: src.to_path_buf(),
                    src_func: e.src_func.clone(),
                    dst_file: dst.to_path_buf(),
                    dst_func: e.dst_func.clone(),
                    call_type: e.call_type,
                }
            })
            .collect();

        // Sort and truncate edges by max_items
        let total_edges = edges.len();
        let truncated = total_edges > max_items;
        let mut edges = edges;
        if edges.len() > max_items {
            // Sort by source file + function as a simple importance metric
            edges.sort_by(|a, b| {
                let a_key = format!("{}:{}", a.src_file.display(), a.src_func);
                let b_key = format!("{}:{}", b.src_file.display(), b.src_func);
                a_key.cmp(&b_key)
            });
            edges.truncate(max_items);
        }
        let shown_edges = edges.len();

        // Build unique node set from the FINAL edge list AND from every
        // defined function in the project (phase-12 audit BUG-AGG12-4: an
        // edges-only derivation under-reported languages whose external
        // calls do not resolve to in-project targets).
        let mut node_set = std::collections::BTreeSet::new();
        for edge in &edges {
            node_set.insert(format!("{}:{}", edge.src_file.display(), edge.src_func));
            node_set.insert(format!("{}:{}", edge.dst_file.display(), edge.dst_func));
        }
        for (file_path, file_ir) in &ir.files {
            // FileIR paths are already normalized to forward-slash
            // relative form; strip the canonicalized root just in case
            // the FileIR happens to be absolute (defensive).
            let rel = file_path.strip_prefix(strip_root).unwrap_or(file_path);
            for func in &file_ir.funcs {
                let qualified = if let Some(class) = &func.class_name {
                    format!("{}.{}", class, func.name)
                } else {
                    func.name.clone()
                };
                node_set.insert(format!("{}:{}", rel.display(), qualified));
            }
        }
        let nodes: Vec<String> = node_set.into_iter().collect();

        Self {
            root: display_root.to_path_buf(),
            language,
            nodes,
            edges,
            truncated,
            total_edges,
            shown_edges,
            files_skipped: ir.warnings.len(),
            warnings: ir.warnings.clone(),
        }
    }
}

impl CallsArgs {
    /// Run the calls command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists BEFORE language detection / progress banner
        // (lang-detect-default-v1)
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // Determine language. schema-cleanup-v2 (P2.BUG-10): when the
        // caller did not pass `--lang` AND `Language::from_directory`
        // detects nothing (e.g. empty directory), preserve the absence
        // as `None` rather than silently falling back to Python — that
        // fallback caused empty-dir scans to be reported as
        // `language: "python"` with zero edges, which misrepresented
        // the input. The build path below treats `None` as Python for
        // call-graph construction (the call-graph builder requires a
        // language) but the JSON `language` field reflects the actual
        // detection result.
        let detected_language = self.lang.or_else(|| Language::from_directory(&self.path));
        let language = detected_language.unwrap_or(Language::Python);

        // Try daemon first for cached result.
        //
        // issue-83-daemon-language-v1: thread the detected language into
        // the daemon request so the daemon builds the graph with the same
        // language the direct-compute path uses. Without it the daemon
        // resolved `None` to Python and returned an empty (0-edge) graph
        // for non-Python projects.
        // daemon-calls-payload-v1: thread `--max-items` so the daemon builds
        // the cached payload with the same truncation the direct path would
        // apply; a missing key means the daemon falls back to the shared
        // default.
        let mut params = params_with_path_lang(&self.path, Some(language.as_str()));
        if let serde_json::Value::Object(ref mut map) = params {
            map.insert("max_items".to_string(), serde_json::json!(self.max_items));
        }
        if let Some(output) = try_daemon_route::<CallGraphOutput>(&self.path, "calls", params) {
            // Output based on format
            if writer.is_text() {
                let mut text = String::new();
                let lang_label = output
                    .language
                    .map(|l| l.as_str().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                text.push_str(&format!(
                    "Call Graph for {} ({})\n",
                    output.root.display(),
                    lang_label,
                ));
                text.push_str(&format!("Edges: {}\n", output.total_edges));
                push_skipped_files(&mut text, &output);
                text.push('\n');

                for edge in &output.edges {
                    text.push_str(&format!(
                        "{}:{} -> {}:{}\n",
                        edge.src_file.display(),
                        edge.src_func,
                        edge.dst_file.display(),
                        edge.dst_func
                    ));
                }

                writer.write_text(&text)?;
                return Ok(());
            } else if writer.is_dot() {
                // surface-gaps-v1 (BUG-19): DOT support for the daemon path.
                let srcs: Vec<String> = output
                    .edges
                    .iter()
                    .map(|e| format!("{}:{}", e.src_file.display(), e.src_func))
                    .collect();
                let dsts: Vec<String> = output
                    .edges
                    .iter()
                    .map(|e| format!("{}:{}", e.dst_file.display(), e.dst_func))
                    .collect();
                let labels: Vec<String> = output
                    .edges
                    .iter()
                    .map(|e| format!("{:?}", e.call_type))
                    .collect();
                let dot_edges: Vec<DotCallEdge<'_>> = (0..output.edges.len())
                    .map(|i| DotCallEdge {
                        src: srcs[i].as_str(),
                        dst: dsts[i].as_str(),
                        label: Some(labels[i].as_str()),
                    })
                    .collect();
                let dot = format_calls_dot(&dot_edges);
                writer.write_text(&dot)?;
                return Ok(());
            } else {
                writer.write(&output)?;
                return Ok(());
            }
        }

        // Fallback to direct compute
        writer.progress(&format!(
            "Building call graph for {} ({:?})...",
            self.path.display(),
            language
        ));

        // Build call graph (V2 canonical)
        let config = BuildConfig {
            language: language.as_str().to_string(),
            respect_ignore: self.respect_ignore,
            use_type_resolution: true,
            ..Default::default()
        };
        let ir = build_project_call_graph_v2(&self.path, config)?;
        // daemon-calls-payload-v1: the output construction lives in ONE place
        // shared with the IPC daemon's Calls handler, so daemon-mode and
        // direct-compute payloads are identical by construction instead of by
        // two copies of the same normalization code drifting apart.
        let root = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());
        let output =
            CallGraphOutput::from_ir(&ir, &root, &self.path, detected_language, self.max_items);

        // Output based on format
        if writer.is_dot() {
            // surface-gaps-v1 (BUG-19): direct-compute DOT path.
            let srcs: Vec<String> = output
                .edges
                .iter()
                .map(|e| format!("{}:{}", e.src_file.display(), e.src_func))
                .collect();
            let dsts: Vec<String> = output
                .edges
                .iter()
                .map(|e| format!("{}:{}", e.dst_file.display(), e.dst_func))
                .collect();
            let labels: Vec<String> = output
                .edges
                .iter()
                .map(|e| format!("{:?}", e.call_type))
                .collect();
            let dot_edges: Vec<DotCallEdge<'_>> = (0..output.edges.len())
                .map(|i| DotCallEdge {
                    src: srcs[i].as_str(),
                    dst: dsts[i].as_str(),
                    label: Some(labels[i].as_str()),
                })
                .collect();
            let dot = format_calls_dot(&dot_edges);
            writer.write_text(&dot)?;
            return Ok(());
        }
        if writer.is_text() {
            let mut text = String::new();
            let lang_label = detected_language
                .map(|l| l.as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            text.push_str(&format!(
                "Call Graph for {} ({})\n",
                self.path.display(),
                lang_label,
            ));
            text.push_str(&format!("Edges: {}\n", output.total_edges));
            push_skipped_files(&mut text, &output);
            text.push('\n');

            for edge in &output.edges {
                text.push_str(&format!(
                    "{}:{} -> {}:{}\n",
                    edge.src_file.display(),
                    edge.src_func,
                    edge.dst_file.display(),
                    edge.dst_func
                ));
            }

            writer.write_text(&text)?;
        } else {
            writer.write(&output)?;
        }

        Ok(())
    }
}

/// TRDD-O66FM8TN: name every dropped file next to the edge count, because
/// the edge count was computed without it.
fn push_skipped_files(text: &mut String, output: &CallGraphOutput) {
    if output.warnings.is_empty() {
        return;
    }
    text.push_str(&format!(
        "Files skipped: {} (edges exclude them)\n",
        output.files_skipped
    ));
    for warning in &output.warnings {
        text.push_str(&format!("  {}\n", warning));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::daemon::types::{DaemonCommand, DaemonConfig, DaemonResponse};
    use crate::commands::daemon::TLDRDaemon;
    use tempfile::TempDir;

    /// daemon-calls-payload-v1: the IPC daemon's Calls payload must
    /// deserialize into `CallGraphOutput` — this is the exact conversion
    /// `try_daemon_route::<CallGraphOutput>` performs on the IPC response.
    /// Pre-fix the daemon cached/serialized the raw compat `ProjectCallGraph`
    /// (`{"edges": [...]}`), which failed here on the missing required
    /// fields, so `tldr calls` never used the daemon cache.
    #[tokio::test]
    async fn daemon_calls_payload_deserializes_into_call_graph_output() {
        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("main.py"),
            "from utils import helper\n\n\ndef main():\n    helper()\n",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("utils.py"),
            "def helper():\n    return 'help'\n",
        )
        .unwrap();

        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), DaemonConfig::default());
        let response = daemon
            .handle_command(DaemonCommand::Calls {
                path: None,
                language: Some(Language::Python),
                max_items: None,
            })
            .await;

        let value = match response {
            DaemonResponse::Result(value) => value,
            DaemonResponse::Error { error, .. } => {
                panic!("daemon Calls errored on a valid project: {error}")
            }
            other => panic!("expected Result, got {other:?}"),
        };

        let output: CallGraphOutput = serde_json::from_value(value)
            .expect("daemon Calls payload must decode into CallGraphOutput");
        assert!(output.total_edges >= 1, "fixture must produce an edge");
        assert_eq!(output.total_edges, output.shown_edges);
        assert!(!output.truncated);
        let main_edge = output
            .edges
            .iter()
            .find(|e| e.src_func == "main" && e.dst_func == "helper")
            .expect("the main -> helper edge must be in the payload");
        assert!(main_edge.src_file.ends_with("main.py"));
        assert!(main_edge.dst_file.ends_with("utils.py"));
    }

    /// The truncation limit the CLI threads through the request is honored by
    /// the daemon's payload build (same sort/truncate/node derivation as the
    /// direct path).
    #[tokio::test]
    async fn daemon_calls_payload_honors_max_items() {
        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("main.py"),
            "from utils import helper\n\n\ndef main():\n    helper()\n",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("utils.py"),
            "def helper():\n    return 'help'\n",
        )
        .unwrap();

        let daemon = TLDRDaemon::new(temp.path().to_path_buf(), DaemonConfig::default());
        let response = daemon
            .handle_command(DaemonCommand::Calls {
                path: None,
                language: Some(Language::Python),
                max_items: Some(0),
            })
            .await;
        let value = match response {
            DaemonResponse::Result(value) => value,
            other => panic!("expected Result, got {other:?}"),
        };

        let output: CallGraphOutput =
            serde_json::from_value(value).expect("payload decodes with max_items = 0");
        assert_eq!(output.edges.len(), 0, "max_items 0 truncates everything");
        assert!(output.truncated, "truncated must be flagged");
        assert!(
            output.total_edges >= 1,
            "total_edges still reports the untruncated count"
        );
        assert_eq!(output.shown_edges, 0);
    }
}
