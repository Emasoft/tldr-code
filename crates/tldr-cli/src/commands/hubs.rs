//! Hubs command - Detect high-centrality hub functions
//!
//! Identifies "hub" functions that are change amplifiers - modifications to them
//! affect many other parts of the codebase. Uses graph centrality algorithms
//! to quantify risk.
//!
//! # Algorithms
//!
//! - `in_degree`: How many functions call this one (dependencies)
//! - `out_degree`: How many functions this one calls (complexity)
//! - `pagerank`: Recursive importance based on caller importance
//! - `betweenness`: How often this lies on shortest paths (bottleneck)
//!
//! # Premortem Mitigations
//! - T14: CLI registration follows existing pattern
//! - T16: Small graph (<10 nodes) messaging
//! - T18: Text formatting follows spec style guide

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};

use tldr_core::analysis::hubs::{
    compute_hub_report_with_lines, enumerate_function_lines, HubAlgorithm,
};
use tldr_core::callgraph::{build_forward_graph, build_reverse_graph, collect_nodes};
use tldr_core::{build_project_call_graph, Language};

use crate::output::{format_hubs_dot, format_hubs_text, OutputFormat, OutputWriter};
use crate::path_validation::require_directory;

/// Algorithm selection for CLI (mirrors HubAlgorithm)
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum AlgorithmArg {
    /// All algorithms: in_degree, out_degree, pagerank, betweenness
    #[default]
    All,
    /// In-degree only (fast)
    Indegree,
    /// Out-degree only (fast)
    Outdegree,
    /// PageRank only
    Pagerank,
    /// Betweenness only (slow for large graphs)
    Betweenness,
}

impl From<AlgorithmArg> for HubAlgorithm {
    fn from(arg: AlgorithmArg) -> Self {
        match arg {
            AlgorithmArg::All => HubAlgorithm::All,
            AlgorithmArg::Indegree => HubAlgorithm::InDegree,
            AlgorithmArg::Outdegree => HubAlgorithm::OutDegree,
            AlgorithmArg::Pagerank => HubAlgorithm::PageRank,
            AlgorithmArg::Betweenness => HubAlgorithm::Betweenness,
        }
    }
}

/// Detect hub functions using centrality analysis
#[derive(Debug, Args)]
pub struct HubsArgs {
    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Number of top hubs to return
    #[arg(long, default_value = "10")]
    pub top: usize,

    /// Centrality algorithm to use
    #[arg(long, value_enum, default_value = "all")]
    pub algorithm: AlgorithmArg,

    /// Minimum composite score threshold (0.0-1.0)
    #[arg(long)]
    pub threshold: Option<f64>,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,
}

impl HubsArgs {
    /// Run the hubs command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists AND is a directory.
        // cli-error-clarity-v2 (P2.BUG-4): when given a regular file we used
        // to print "Path not found" (false). Use the shared helper so the
        // error explains the user mistake clearly.
        require_directory(&self.path, "hubs")?;

        // Validate threshold if provided
        if let Some(thresh) = self.threshold {
            if !(0.0..=1.0).contains(&thresh) {
                anyhow::bail!("Threshold must be between 0.0 and 1.0, got {}", thresh);
            }
        }

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&self.path).unwrap_or(Language::Python));

        // cl15-polyglot-v1 (v0.5.0 CL-15): determine the set of languages to
        // analyze. When the user did NOT pin `--lang`, build a MERGED call
        // graph across EVERY detected language so hub centrality reflects the
        // whole polyglot tree, not just the dominant language. When the user
        // DID pin `--lang`, restrict to that language but emit a clear stderr
        // WARNING naming the dropped languages + file counts.
        let scan_languages: Vec<Language> = if self.lang.is_some() {
            crate::commands::polyglot::warn_if_languages_dropped(&self.path, language);
            vec![language]
        } else {
            let mut langs = crate::commands::polyglot::detected_language_list(&self.path);
            if langs.is_empty() {
                langs.push(language);
            }
            langs
        };

        writer.progress(&format!(
            "Building call graph for {} ({} language(s))...",
            self.path.display(),
            scan_languages.len()
        ));

        // Build ONE merged call graph that unions every detected language's
        // edges, and merge each language's function-line lookup. The per-
        // language V2 builder filters to that language's extension family, so
        // the polyglot tree needs one pass per language.
        let mut graph = tldr_core::types::ProjectCallGraph::new();
        let mut function_lines = std::collections::HashMap::new();
        for scan_lang in &scan_languages {
            let g = build_project_call_graph(&self.path, *scan_lang, None, true)?;
            for edge in g.edges() {
                graph.add_edge(edge.clone());
            }
            // hubs-line-population-v1: enumerate function definition lines so
            // the hub report identifies each function by its real AST line
            // instead of the legacy `0` placeholder produced by the
            // call-graph builder. Merge across languages — each language's
            // files use disjoint relative paths so there are no key clashes.
            function_lines.extend(enumerate_function_lines(&self.path, *scan_lang));
        }

        writer.progress("Computing hub centrality metrics...");

        // Build graph representations
        let forward = build_forward_graph(&graph);
        let reverse = build_reverse_graph(&graph);
        let nodes = collect_nodes(&graph);

        // Compute hub report
        let report = compute_hub_report_with_lines(
            &nodes,
            &forward,
            &reverse,
            self.algorithm.into(),
            self.top,
            self.threshold,
            Some(&function_lines),
        );

        // Output based on format
        if writer.is_text() {
            let text = format_hubs_text(&report);
            writer.write_text(&text)?;
        } else if writer.is_dot() {
            // surface-gaps-v1 (BUG-19): hubs DOT — node-only graph of top
            // hubs labeled with their composite scores.
            let dot = format_hubs_dot(&report);
            writer.write_text(&dot)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}
