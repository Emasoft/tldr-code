//! Whatbreaks command - unified impact analysis wrapper
//!
//! Auto-detects target type (function/file/module) and runs appropriate
//! sub-analyses to answer: "What breaks if I change X?"
//!
//! # Sub-Analyses by Target Type
//!
//! - **Function**: Runs `impact` analysis to find callers
//! - **File**: Runs `importers` + `change-impact` analysis
//! - **Module**: Runs `importers` analysis
//!
//! # Premortem Mitigations
//! - T14: CLI registration follows existing pattern
//! - T15: --type flag for disambiguation
//! - T18: Text formatting follows spec style guide

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, ValueEnum};

use tldr_core::analysis::whatbreaks::{whatbreaks_analysis, TargetType, WhatbreaksOptions};
use tldr_core::Language;

use crate::commands::remaining::explain::explain_project_root_marker;
use crate::output::{format_whatbreaks_text, OutputFormat, OutputWriter};
use crate::path_validation::require_directory;

/// Target type selection for CLI (T15 mitigation)
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TargetTypeArg {
    /// Function name - run impact analysis
    Function,
    /// File path - run importers + change-impact
    File,
    /// Module name - run importers
    Module,
}

impl From<TargetTypeArg> for TargetType {
    fn from(arg: TargetTypeArg) -> Self {
        match arg {
            TargetTypeArg::Function => TargetType::Function,
            TargetTypeArg::File => TargetType::File,
            TargetTypeArg::Module => TargetType::Module,
        }
    }
}

/// Analyze what breaks if a target is changed
///
/// Automatically detects whether target is a function, file, or module
/// and runs appropriate sub-analyses.
#[derive(Debug, Args)]
pub struct WhatbreaksArgs {
    /// Target to analyze (function name, file path, or module name)
    pub target: String,

    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Force target type (overrides auto-detection)
    #[arg(long = "type", short = 't', value_enum)]
    pub target_type: Option<TargetTypeArg>,

    /// Maximum depth for impact/caller traversal
    #[arg(long, short = 'd', default_value = "3")]
    pub depth: usize,

    /// Skip slow analyses (diff-impact)
    #[arg(long)]
    pub quick: bool,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,
}

impl WhatbreaksArgs {
    /// Run the whatbreaks command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate path exists AND is a directory.
        // cli-error-clarity-v2 (P2.BUG-4).
        require_directory(&self.path, "whatbreaks")?;

        writer.progress(&format!(
            "Analyzing what breaks if '{}' changes...",
            self.target
        ));

        // doc-target-whatbreaks-v1: when the target names an EXISTING FILE,
        // scope the analysis walk to that file's PROJECT ROOT (the marker
        // walk-up `explain`/`impact` use) instead of blindly walking the
        // `path` argument (default CWD). A file target on a big repo
        // previously walked the whole CWD tree — >60 s before first output —
        // even though everything whatbreaks needs (importers of the module,
        // change impact, the call graph) is bounded by the project the file
        // belongs to. No marker in any ancestor → legacy behavior: walk the
        // given `path` argument, so marker-less projects are unchanged.
        let analysis_root = self.analysis_root();

        // Build options
        let options = WhatbreaksOptions {
            depth: self.depth,
            quick: self.quick,
            language: self.lang,
            force_type: self.target_type.map(|t| t.into()),
        };

        // Run analysis
        let report = whatbreaks_analysis(&self.target, &analysis_root, &options)?;

        writer.progress(&format!(
            "Target type: {} ({})",
            report.target_type, report.detection_reason
        ));

        // Output based on format
        if writer.is_text() {
            let text = format_whatbreaks_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }

    /// doc-target-whatbreaks-v1: the directory the analysis walks.
    ///
    /// When `target` resolves to an EXISTING FILE (absolute, or relative to
    /// the `path` argument), the walk is scoped to that file's marker-based
    /// project root (`explain_project_root_marker`, the same detection
    /// `explain`/`impact` use). When no project marker exists in any ancestor
    /// — or the target is not an existing file (function/module names) — the
    /// legacy `path` argument is kept, so pre-fix behavior is byte-identical
    /// for those cases.
    fn analysis_root(&self) -> PathBuf {
        let target_path = if Path::new(&self.target).is_absolute() {
            PathBuf::from(&self.target)
        } else {
            self.path.join(&self.target)
        };
        if target_path.is_file() {
            if let Some(root) = explain_project_root_marker(&target_path) {
                return root;
            }
        }
        self.path.clone()
    }
}
