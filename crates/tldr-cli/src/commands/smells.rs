//! Smells command - Detect code smells
//!
//! Identifies common code smells like God Class, Long Method, etc.
//! Auto-routes through daemon when available for ~35x speedup.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::{
    analyze_smells_aggregated_with_walker_opts, detect_smells_with_walker_opts, Language,
    SmellType, SmellsReport, SmellsWalkerOpts, ThresholdPreset,
};

use crate::commands::daemon_router::{params_for_smells, try_daemon_route};
use crate::output::{format_smells_text, OutputFormat, OutputWriter};

/// Detect code smells
#[derive(Debug, Args)]
pub struct SmellsArgs {
    /// Path to analyze (file or directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language to filter by (auto-detected if omitted)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Threshold preset
    #[arg(long, short = 't', default_value = "default")]
    pub threshold: ThresholdPresetArg,

    /// Filter by smell type
    #[arg(long, short = 's')]
    pub smell_type: Option<SmellTypeArg>,

    /// Include suggestions for fixing
    #[arg(long)]
    pub suggest: bool,

    /// Deep analysis: aggregate findings from cohesion, coupling, dead code,
    /// similarity, and cognitive complexity analyzers in addition to the
    /// standard smell detectors
    #[arg(long)]
    pub deep: bool,

    /// Walk vendored/build dirs (node_modules, target, dist, etc.) that would normally be skipped.
    #[arg(long)]
    pub no_default_ignore: bool,

    /// Limit the scan to specific files (repeatable; EXACT-PATH-ONLY, no glob expansion).
    /// Each entry is validated via `validate_file_path` (rejects path traversal /
    /// non-existent files). When set, the path argument becomes a project-root
    /// anchor for output ordering only and the walker is bypassed. Implies
    /// `--include-tests` (caller picked the list).
    #[arg(long)]
    pub files: Vec<PathBuf>,

    /// Include findings from test files. Default: test-file findings are excluded
    /// (PR-review default). Implicit `true` when `--files` is non-empty.
    #[arg(long)]
    pub include_tests: bool,
}

/// CLI wrapper for threshold preset
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ThresholdPresetArg {
    /// Strict thresholds for high-quality codebases
    Strict,
    /// Default thresholds (recommended)
    #[default]
    Default,
    /// Relaxed thresholds for legacy code
    Relaxed,
}

impl From<ThresholdPresetArg> for ThresholdPreset {
    fn from(arg: ThresholdPresetArg) -> Self {
        match arg {
            ThresholdPresetArg::Strict => ThresholdPreset::Strict,
            ThresholdPresetArg::Default => ThresholdPreset::Default,
            ThresholdPresetArg::Relaxed => ThresholdPreset::Relaxed,
        }
    }
}

/// CLI wrapper for smell type
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SmellTypeArg {
    /// God Class (>20 methods or >500 LOC)
    GodClass,
    /// Long Method (>50 LOC or cyclomatic >10)
    LongMethod,
    /// Long Parameter List (>5 parameters)
    LongParameterList,
    /// Feature Envy
    FeatureEnvy,
    /// Data Clumps
    DataClumps,
    /// Low Cohesion (LCOM4 >= 2) -- requires --deep
    LowCohesion,
    /// Tight Coupling (score >= 0.6) -- requires --deep
    TightCoupling,
    /// Dead Code (unreachable functions) -- requires --deep
    DeadCode,
    /// Code Clone (similar functions) -- requires --deep
    CodeClone,
    /// High Cognitive Complexity (>= 15) -- requires --deep
    HighCognitiveComplexity,
    /// Deep Nesting (nesting depth >= 5)
    DeepNesting,
    /// Data Class (many fields, few/no methods)
    DataClass,
    /// Lazy Element (class with only 1 method and 0-1 fields)
    LazyElement,
    /// Message Chain (long method call chains > 3)
    MessageChain,
    /// Primitive Obsession (many primitive-typed parameters)
    PrimitiveObsession,
    /// Middle Man (>60% delegation) -- requires --deep
    MiddleMan,
    /// Refused Bequest (<33% inherited usage) -- requires --deep
    RefusedBequest,
    /// Inappropriate Intimacy (bidirectional coupling) -- requires --deep
    InappropriateIntimacy,
}

impl From<SmellTypeArg> for SmellType {
    fn from(arg: SmellTypeArg) -> Self {
        match arg {
            SmellTypeArg::GodClass => SmellType::GodClass,
            SmellTypeArg::LongMethod => SmellType::LongMethod,
            SmellTypeArg::LongParameterList => SmellType::LongParameterList,
            SmellTypeArg::FeatureEnvy => SmellType::FeatureEnvy,
            SmellTypeArg::DataClumps => SmellType::DataClumps,
            SmellTypeArg::LowCohesion => SmellType::LowCohesion,
            SmellTypeArg::TightCoupling => SmellType::TightCoupling,
            SmellTypeArg::DeadCode => SmellType::DeadCode,
            SmellTypeArg::CodeClone => SmellType::CodeClone,
            SmellTypeArg::HighCognitiveComplexity => SmellType::HighCognitiveComplexity,
            SmellTypeArg::DeepNesting => SmellType::DeepNesting,
            SmellTypeArg::DataClass => SmellType::DataClass,
            SmellTypeArg::LazyElement => SmellType::LazyElement,
            SmellTypeArg::MessageChain => SmellType::MessageChain,
            SmellTypeArg::PrimitiveObsession => SmellType::PrimitiveObsession,
            SmellTypeArg::MiddleMan => SmellType::MiddleMan,
            SmellTypeArg::RefusedBequest => SmellType::RefusedBequest,
            SmellTypeArg::InappropriateIntimacy => SmellType::InappropriateIntimacy,
        }
    }
}

impl SmellsArgs {
    /// Run the smells command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // BUG-11: validate path exists BEFORE any analysis. Without this
        // check, a missing path silently slipped through: `is_dir()` returned
        // false, the file branch ran with no files to scan, and the command
        // returned exit 0 with empty results. Now: missing path => exit 1
        // (matches `health`, `structure`, `deps`, `vuln`).
        if !self.path.exists() {
            anyhow::bail!("Path not found: {}", self.path.display());
        }

        // v0.2.3 (#1.D): when `--files` is non-empty, the caller explicitly named
        // each path. Trust them and force `include_tests=true` so user-listed
        // test files are not silently filtered.
        let include_tests = self.include_tests || !self.files.is_empty();

        // v0.2.3 (#1.D): each `--files` entry MUST go through the CORE
        // validator (`tldr_core::validation::validate_file_path`) — same one
        // the daemon uses. We pass the smells `path` argument as the project
        // root so path-traversal attempts (`/etc/passwd`, `../../etc/...`)
        // produce a hard error rather than a silent skip. Failures bubble up
        // as a CLI error (non-zero exit), NOT a silent skip.
        let project_root = if self.path.is_dir() {
            // Try to canonicalize the path (so traversal checks work). Fall
            // back to the literal path on canonicalize error (e.g. tmpdir
            // shenanigans on macOS where /var -> /private/var).
            dunce::canonicalize(&self.path).unwrap_or_else(|_| self.path.clone())
        } else {
            // For file paths, use the parent dir (or "." if none).
            self.path
                .parent()
                .map(|p| dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."))
        };
        let mut validated_files: Vec<PathBuf> = Vec::with_capacity(self.files.len());
        for f in &self.files {
            let f_str = f.to_str().ok_or_else(|| {
                anyhow::anyhow!("--files entry contains non-UTF8 bytes: {:?}", f)
            })?;
            let canonical =
                tldr_core::validation::validate_file_path(f_str, Some(&project_root))
                    .map_err(|e| anyhow::anyhow!("--files {}: {}", f.display(), e))?;
            validated_files.push(canonical);
        }

        // Try daemon first for cached result
        if let Some(report) = try_daemon_route::<SmellsReport>(
            &self.path,
            "smells",
            params_for_smells(Some(&self.path), &validated_files, include_tests),
        ) {
            // Output based on format
            if writer.is_text() {
                let text = format_smells_text(&report);
                writer.write_text(&text)?;
                return Ok(());
            } else {
                writer.write(&report)?;
                return Ok(());
            }
        }

        // determinism-and-stderr-hygiene-v1 (BUG-18): the M14
        // (med-cleanup-bundle-v1) deep-only-smells hint used to be
        // unconditionally written to stderr via `eprintln!`, which
        // broke the JSON-mode contract (`tldr smells <path> 2>err >
        // out.json` always produced a non-empty stderr stream).
        //
        // Relocate the same advisory into `SmellsReport.warnings` so
        // BOTH JSON consumers (introspectable via `report.warnings[]`)
        // AND text consumers (rendered to stdout by the text
        // formatter — see `format_smells_text`) still see it. Skip
        // injection when `--quiet`, when the user asked for a single
        // smell type via `--smell-type` (warning would be misleading),
        // or when `--deep` is set (the analyzers ARE running).
        // why: the original condition suppressed the warning whenever
        // `--smell-type` was set, on the theory that a per-type warning would
        // be "misleading" -- but that suppressed it in exactly the one case
        // where it is guaranteed useful: requesting a deep-only smell type
        // without `--deep` always yields zero results, and the user got no
        // explanation at all (a silent empty report). Detect that specific
        // case and still warn; only suppress for non-deep-only types.
        let requested_is_deep_only = matches!(
            self.smell_type,
            Some(
                SmellTypeArg::LowCohesion
                    | SmellTypeArg::TightCoupling
                    | SmellTypeArg::DeadCode
                    | SmellTypeArg::CodeClone
                    | SmellTypeArg::HighCognitiveComplexity
                    | SmellTypeArg::MiddleMan
                    | SmellTypeArg::RefusedBequest
                    | SmellTypeArg::InappropriateIntimacy
            )
        );
        let deep_only_warning: Option<String> = if self.deep || quiet {
            None
        } else if requested_is_deep_only {
            Some(
                "Note: the requested smell type requires --deep flag and yields no results without it.".to_string(),
            )
        } else if self.smell_type.is_none() {
            const DEEP_ONLY_SMELLS: &[&str] = &[
                "low_cohesion",
                "tight_coupling",
                "dead_code",
                "code_clone",
                "high_cognitive_complexity",
                "middle_man",
                "refused_bequest",
                "inappropriate_intimacy",
            ];
            Some(format!(
                "Note: {} smell analyzers require --deep flag. Run with --deep for: {}",
                DEEP_ONLY_SMELLS.len(),
                DEEP_ONLY_SMELLS.join(", ")
            ))
        } else {
            None
        };

        // Fallback to direct compute
        writer.progress(&format!(
            "Scanning for code smells in {}{}...",
            self.path.display(),
            if self.deep { " (deep analysis)" } else { "" }
        ));

        // Detect smells - use aggregated analysis when --deep is set
        let walker_opts = SmellsWalkerOpts {
            no_default_ignore: self.no_default_ignore,
            lang: self.lang,
            files: validated_files,
            include_tests,
        };
        let mut report = if self.deep {
            analyze_smells_aggregated_with_walker_opts(
                &self.path,
                self.threshold.into(),
                self.smell_type.map(|s| s.into()),
                self.suggest,
                walker_opts,
            )?
        } else {
            detect_smells_with_walker_opts(
                &self.path,
                self.threshold.into(),
                self.smell_type.map(|s| s.into()),
                self.suggest,
                walker_opts,
            )?
        };

        if let Some(msg) = deep_only_warning {
            report.warnings.push(msg);
        }

        // Output based on format
        if writer.is_text() {
            let text = format_smells_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}
