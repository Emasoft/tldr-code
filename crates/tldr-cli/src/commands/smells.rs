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
        if let Some(mut report) = try_daemon_route::<SmellsReport>(
            &self.path,
            "smells",
            params_for_smells(Some(&self.path), &validated_files, include_tests),
        ) {
            // cross-cmd-path-shape-v1 (v0.4.2 bug-A5): both the daemon
            // payload and the direct-compute path canonicalise file
            // paths via `dunce::canonicalize` (crates/tldr-core/src/
            // quality/smells.rs:494-498), so on macOS the user's
            // `/tmp/...` input is mirrored as `/private/tmp/...` in
            // every `smells[].file` and `by_file` key. Echo the user's
            // verbatim input shape in output (M3 pattern).
            restore_smells_path_shape(&mut report, &self.path);
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
        let deep_only_warning: Option<String> =
            (!self.deep && !quiet && self.smell_type.is_none()).then(|| {
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
                format!(
                    "Note: {} smell analyzers require --deep flag. Run with --deep for: {}",
                    DEEP_ONLY_SMELLS.len(),
                    DEEP_ONLY_SMELLS.join(", ")
                )
            });

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

        // cross-cmd-path-shape-v1 (v0.4.2 bug-A5): direct-compute path
        // also runs `smell.file` through `dunce::canonicalize` (see
        // crates/tldr-core/src/quality/smells.rs:494-498). Substitute
        // the user's verbatim input shape back into every emitted
        // path.
        restore_smells_path_shape(&mut report, &self.path);

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

/// cross-cmd-path-shape-v1 (v0.4.2 bug-A5): re-assert the user's input
/// path shape on every path emitted in a `SmellsReport`.
///
/// The core analyzer canonicalises file paths via `dunce::canonicalize`
/// (crates/tldr-core/src/quality/smells.rs:494-498) for stable
/// dedup/sort semantics, but the canonical form leaks the macOS
/// `/private/tmp` resolution into output. The CLI restores the user's
/// verbatim input shape after the core analysis returns, mirroring the
/// M3 (`5f6009e scala-path-canonical-v1`) and P15-B precedent:
/// canonicalise for internal filter/match only, echo user input
/// verbatim in output.
///
/// The substitution rule is a prefix rewrite: every emitted path whose
/// canonical form starts with the canonical user-input root is
/// rewritten to the user-input root + the same suffix. Paths that do
/// not share the canonical prefix (e.g. cross-class smells with the
/// sentinel `<cross-class>` path) are left untouched.
fn restore_smells_path_shape(report: &mut SmellsReport, user_root: &std::path::Path) {
    let canon_user_root = dunce::canonicalize(user_root).ok();
    let rewrite = |p: &std::path::Path| -> Option<std::path::PathBuf> {
        // If `p` already starts with the user's input root verbatim,
        // there's nothing to do.
        if p.starts_with(user_root) {
            return None;
        }
        // If `p` starts with the canonical form of the user's input
        // root (`/private/tmp/...` when user typed `/tmp/...`),
        // rewrite the prefix back to the user's input.
        if let Some(canon) = canon_user_root.as_ref() {
            if let Ok(suffix) = p.strip_prefix(canon) {
                if user_root.as_os_str().is_empty() {
                    return Some(suffix.to_path_buf());
                }
                return Some(user_root.join(suffix));
            }
        }
        None
    };

    for smell in report.smells.iter_mut() {
        if let Some(new_path) = rewrite(&smell.file) {
            smell.file = new_path;
        }
    }
    // Rebuild `by_file` so the keys agree with `smells[].file` after
    // rewriting. HashMap key rewrite in-place is awkward; build a new
    // map.
    let mut new_by_file: std::collections::HashMap<PathBuf, Vec<tldr_core::SmellFinding>> =
        std::collections::HashMap::with_capacity(report.by_file.len());
    for (key, mut findings) in report.by_file.drain() {
        let new_key = rewrite(&key).unwrap_or(key);
        for f in findings.iter_mut() {
            if let Some(np) = rewrite(&f.file) {
                f.file = np;
            }
        }
        new_by_file.entry(new_key).or_default().extend(findings);
    }
    report.by_file = new_by_file;
}
