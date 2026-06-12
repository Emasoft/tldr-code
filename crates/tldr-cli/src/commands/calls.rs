//! Calls command - Build call graph
//!
//! Builds and displays the cross-file call graph for a project.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use tldr_core::callgraph::cross_file_types::CallType;
use tldr_core::callgraph::{build_project_call_graph_v2, BuildConfig};
use tldr_core::Language;

use crate::commands::daemon_router::{params_with_path, try_daemon_route};
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

    /// Maximum edges to include in **text/DOT** output (default: 200).
    ///
    /// calls-edge-limit-v1 (v0.4.2 M-003): this cap applies ONLY to the
    /// text and DOT renderers — they are pretty-print surfaces and dumping
    /// thousands of edges into a terminal is hostile. `--format json` always
    /// emits the full edge set regardless of `--max-items`; downstream
    /// tooling that consumes the JSON wants the complete graph, and silent
    /// truncation there was a real bug (M-003) where shown_edges plateaued
    /// at 200 even when total_edges was thousands.
    ///
    /// `--limit` is a short alias kept for ergonomic parity with other
    /// CLIs that use that flag name.
    #[arg(long, alias = "limit", default_value = "200")]
    pub max_items: usize,
}

/// Call graph output format
///
/// med-low-schema-cleanup-v1 (N12): the redundant `edge_count` and
/// `node_count` keys were removed. `total_edges` + `shown_edges` +
/// `truncated` is the single canonical pair (mirrors what `references`
/// and `dead` use); `node_count` was always equal to `nodes.len()` so
/// consumers can derive it locally.
#[derive(Debug, Serialize, Deserialize)]
struct CallGraphOutput {
    root: PathBuf,
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
    language: Option<Language>,
    nodes: Vec<String>,
    edges: Vec<EdgeOutput>,
    /// Whether the output was truncated due to max_items limit
    ///
    /// (path-and-schema-cleanup-v3 P3.BUG-N5) Always emitted — including
    /// when `false` — so schema consumers do not need to handle the
    /// absent-key case. Previously elided via `skip_serializing_if`, but
    /// downstream tooling (and `references`, `dead`, `dice`, etc.) all
    /// treat `truncated` as a stable boolean key.
    #[serde(default)]
    truncated: bool,
    /// Total number of edges before truncation
    total_edges: usize,
    /// Number of edges shown after truncation
    shown_edges: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct EdgeOutput {
    src_file: PathBuf,
    src_func: String,
    dst_file: PathBuf,
    dst_func: String,
    call_type: CallType,
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
        let detected_language = self
            .lang
            .or_else(|| Language::from_directory(&self.path));
        let language = detected_language.unwrap_or(Language::Python);

        // cl15-polyglot-v1 (v0.5.0 CL-15): determine the set of languages to
        // analyze. When the user did NOT pin `--lang`, analyze EVERY detected
        // language under the tree and merge the per-language call graphs — the
        // dominant-language pick above is only used as the reported
        // `language` label, never as a filter that drops the rest. When the
        // user DID pin `--lang`, restrict to that one language but emit a
        // clear stderr WARNING naming the dropped languages + file counts.
        let scan_languages: Vec<Language> = if self.lang.is_some() {
            if self.path.is_dir() {
                crate::commands::polyglot::warn_if_languages_dropped(&self.path, language);
            }
            vec![language]
        } else if self.path.is_dir() {
            let mut langs = crate::commands::polyglot::detected_language_list(&self.path);
            if langs.is_empty() {
                langs.push(language);
            }
            langs
        } else {
            vec![language]
        };

        // Try daemon first for cached result
        if let Some(output) = try_daemon_route::<CallGraphOutput>(
            &self.path,
            "calls",
            params_with_path(Some(&self.path)),
        ) {
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
                text.push_str(&format!("Edges: {}\n\n", output.total_edges));

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

        // Bypass compat layer - output ir.edges directly with normalized paths
        let root = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());

        // cl15-polyglot-v1 (v0.5.0 CL-15): build one call graph per detected
        // language and merge. The V2 builder filters to a single language's
        // `scan_extensions()` family, so a polyglot tree needs one pass per
        // language; we accumulate edges and the per-language function
        // inventory (defined funcs as nodes) into a single combined graph.
        let mut edges: Vec<EdgeOutput> = Vec::new();
        let mut defined_nodes: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for scan_lang in &scan_languages {
            let config = BuildConfig {
                language: scan_lang.as_str().to_string(),
                respect_ignore: self.respect_ignore,
                use_type_resolution: true,
                ..Default::default()
            };
            let ir = build_project_call_graph_v2(&self.path, config)?;
            for e in &ir.edges {
                let src = e.src_file.strip_prefix(&root).unwrap_or(&e.src_file);
                let dst = e.dst_file.strip_prefix(&root).unwrap_or(&e.dst_file);
                edges.push(EdgeOutput {
                    src_file: src.to_path_buf(),
                    src_func: e.src_func.clone(),
                    dst_file: dst.to_path_buf(),
                    dst_func: e.dst_func.clone(),
                    call_type: e.call_type,
                });
            }
            // Include every defined function as a graph node (zero-out-degree
            // where appropriate) so the call graph exposes both call
            // relationships AND the function inventory per language.
            for (file_path, file_ir) in &ir.files {
                let rel = file_path.strip_prefix(&root).unwrap_or(file_path);
                for func in &file_ir.funcs {
                    let qualified = if let Some(class) = &func.class_name {
                        format!("{}.{}", class, func.name)
                    } else {
                        func.name.clone()
                    };
                    defined_nodes.insert(format!("{}:{}", rel.display(), qualified));
                }
            }
        }

        // calls-edge-limit-v1 (v0.4.2 M-003): the prior implementation
        // truncated `edges` UNCONDITIONALLY at `--max-items` (default 200)
        // before serialization, which silently capped JSON consumers at
        // 200 even when total_edges was thousands (kotlin 2570, swift
        // 7110, lua 2964, elixir 676, typescript 440, csharp 207). The
        // cap was a pretty-print heuristic that leaked into the data API.
        //
        // Fix: sort once (stable order makes the truncated text view
        // deterministic), keep ALL edges in `CallGraphOutput`, and only
        // narrow the slice when rendering text/DOT. JSON gets the full
        // graph; truncated=false and shown_edges==total_edges there.
        edges.sort_by(|a, b| {
            let a_key = format!("{}:{}", a.src_file.display(), a.src_func);
            let b_key = format!("{}:{}", b.src_file.display(), b.src_func);
            a_key.cmp(&b_key)
        });
        let total_edges = edges.len();

        // Build unique node set from ALL edges AND from every
        // defined function in the project. The original derivation was
        // edges-only, which under-reported the call graph for files like
        // OCaml functor bodies (`module Make (V) = struct ... end`)
        // whose let-bindings make external calls (`Format.fprintf`, …)
        // that don't resolve to in-project targets. Phase-12 audit
        // (BUG-AGG12-4) caught dag.ml reporting nodes=2 even though
        // `tldr structure dag.ml` finds 19 functions. Including defined
        // funcs as graph nodes (zero-out-degree where appropriate) gives
        // every language a faithful node count: the call graph now
        // exposes both call relationships AND the function inventory.
        let mut node_set = std::collections::BTreeSet::new();
        for edge in &edges {
            node_set.insert(format!("{}:{}", edge.src_file.display(), edge.src_func));
            node_set.insert(format!("{}:{}", edge.dst_file.display(), edge.dst_func));
        }
        // cl15-polyglot-v1: the per-language defined-function inventory was
        // accumulated above across every scanned language. Merge it in so
        // every language's functions appear as nodes (zero-out-degree where
        // appropriate), matching the single-language behaviour per-language.
        node_set.extend(defined_nodes);
        let nodes: Vec<String> = node_set.into_iter().collect();

        // calls-edge-limit-v1: JSON gets the full edge set, so for the
        // serialized `CallGraphOutput` shown_edges==total_edges and
        // truncated is always false. Text/DOT renderers below derive
        // their own truncated slice from `output.edges` (still the full
        // set on the struct — the cap is a presentation concern).
        let output = CallGraphOutput {
            root: self.path.clone(),
            language: detected_language,
            nodes,
            edges,
            truncated: false,
            total_edges,
            shown_edges: total_edges,
        };

        // Text/DOT presentation cap: clamp to --max-items and warn on
        // stderr when truncation fires so terminal users don't silently
        // get a partial picture. JSON consumers bypass this branch
        // entirely (writer.write(&output) below) and get the full graph.
        let text_dot_limit = self.max_items;
        let text_dot_truncated = output.edges.len() > text_dot_limit;
        let visible_edges_len = output.edges.len().min(text_dot_limit);

        // Output based on format
        if writer.is_dot() {
            // surface-gaps-v1 (BUG-19): direct-compute DOT path.
            // calls-edge-limit-v1: honor --max-items here (pretty-print
            // surface) by slicing to `visible_edges_len`.
            let srcs: Vec<String> = output
                .edges
                .iter()
                .take(visible_edges_len)
                .map(|e| format!("{}:{}", e.src_file.display(), e.src_func))
                .collect();
            let dsts: Vec<String> = output
                .edges
                .iter()
                .take(visible_edges_len)
                .map(|e| format!("{}:{}", e.dst_file.display(), e.dst_func))
                .collect();
            let labels: Vec<String> = output
                .edges
                .iter()
                .take(visible_edges_len)
                .map(|e| format!("{:?}", e.call_type))
                .collect();
            let dot_edges: Vec<DotCallEdge<'_>> = (0..visible_edges_len)
                .map(|i| DotCallEdge {
                    src: srcs[i].as_str(),
                    dst: dsts[i].as_str(),
                    label: Some(labels[i].as_str()),
                })
                .collect();
            let dot = format_calls_dot(&dot_edges);
            writer.write_text(&dot)?;
            if text_dot_truncated {
                eprintln!(
                    "warning: DOT output truncated to {} of {} edges (use --max-items / --limit to raise, or --format json for the full graph)",
                    visible_edges_len, total_edges
                );
            }
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
            text.push_str(&format!("Edges: {}\n\n", output.total_edges));

            for edge in output.edges.iter().take(visible_edges_len) {
                text.push_str(&format!(
                    "{}:{} -> {}:{}\n",
                    edge.src_file.display(),
                    edge.src_func,
                    edge.dst_file.display(),
                    edge.dst_func
                ));
            }

            writer.write_text(&text)?;
            if text_dot_truncated {
                eprintln!(
                    "warning: text output truncated to {} of {} edges (use --max-items / --limit to raise, or --format json for the full graph)",
                    visible_edges_len, total_edges
                );
            }
        } else {
            writer.write(&output)?;
        }

        Ok(())
    }
}
