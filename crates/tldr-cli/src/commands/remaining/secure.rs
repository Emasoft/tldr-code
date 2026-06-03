//! Secure Command - Security Analysis Dashboard
//!
//! Aggregates security sub-analyses (taint, resources, bounds, contracts,
//! behavioral, mutability) into a severity-sorted security report.
//!
//! # Sub-analyses
//!
//! - `taint`: Detect data flow from untrusted sources to sensitive sinks
//! - `resources`: Detect resource leaks (files, connections)
//! - `bounds`: Detect potential buffer overflows and bounds issues
//! - `contracts`: Analyze pre/postconditions (full mode only)
//! - `behavioral`: Analyze exception handling and state transitions (full mode only)
//! - `mutability`: Detect mutable parameter issues (full mode only)
//!
//! # Quick Mode
//!
//! Quick mode (`--quick`) runs only the fast analyses:
//! - taint, resources, bounds
//!
//! Full mode adds:
//! - contracts, behavioral, mutability
//!
//! # Example
//!
//! ```bash
//! # Analyze a file
//! tldr secure src/app.py
//!
//! # Quick mode (faster)
//! tldr secure src/app.py --quick
//!
//! # Show detail for sub-analysis
//! tldr secure src/app.py --detail taint
//!
//! # Text output
//! tldr secure src/app.py -f text
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Args;
use colored::Colorize;
use serde_json::Value;
use tldr_core::fs::{read_to_string_tolerant, ReadOutcome};
use tldr_core::walker::ProjectWalker;
use tldr_core::Language;
use tree_sitter::Node;

use crate::output::OutputFormat;

use super::ast_cache::AstCache;
use super::error::{RemainingError, RemainingResult};
use super::types::{SecureFinding, SecureReport, SecureSummary};

// =============================================================================
// Security Analysis Types
// =============================================================================

/// Security sub-analysis types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAnalysis {
    Taint,
    Resources,
    Bounds,
    Contracts,
    Behavioral,
    Mutability,
}

impl SecurityAnalysis {
    /// Get the analysis name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Taint => "taint",
            Self::Resources => "resources",
            Self::Bounds => "bounds",
            Self::Contracts => "contracts",
            Self::Behavioral => "behavioral",
            Self::Mutability => "mutability",
        }
    }
}

/// Quick mode analyses (fast)
pub const QUICK_ANALYSES: &[SecurityAnalysis] = &[
    SecurityAnalysis::Taint,
    SecurityAnalysis::Resources,
    SecurityAnalysis::Bounds,
];

/// Full mode analyses (all)
pub const FULL_ANALYSES: &[SecurityAnalysis] = &[
    SecurityAnalysis::Taint,
    SecurityAnalysis::Resources,
    SecurityAnalysis::Bounds,
    SecurityAnalysis::Contracts,
    SecurityAnalysis::Behavioral,
    SecurityAnalysis::Mutability,
];

// =============================================================================
// CLI Arguments
// =============================================================================

/// Security analysis dashboard aggregating multiple security checks
#[derive(Debug, Args, Clone)]
pub struct SecureArgs {
    /// File path or directory to analyze
    pub path: PathBuf,

    /// Programming language to filter by (auto-detected if omitted)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Show details for specific sub-analysis
    #[arg(long)]
    pub detail: Option<String>,

    /// Run quick mode (taint, resources, bounds only)
    #[arg(long)]
    pub quick: bool,

    /// Write output to file instead of stdout
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Walk vendored/build dirs (node_modules, target, dist, etc.) that would normally be skipped.
    #[arg(long)]
    pub no_default_ignore: bool,

    /// Include findings on test files. Mirrors `tldr vuln --include-tests`
    /// (M-X3 `js-test-file-suppression-v1`). Default: `false` — findings
    /// emitted from JS/TS test files (paths under `test/`, `tests/`,
    /// `__tests__/`, or filenames ending in `.test.{js,ts,jsx,tsx}`,
    /// `.spec.{js,ts,jsx,tsx}`, or `.e2e.{js,ts}`) and Rust test files
    /// (paths under `/tests/` or filenames ending in `_test.rs` /
    /// `tests.rs`) are suppressed because they exercise sink behavior on
    /// synthetic inputs and pollute production-codebase scans. Pass
    /// `--include-tests` to restore them. Mirrors the `--include-smells`
    /// precedent (opt-in for noisy categories).
    #[arg(long)]
    pub include_tests: bool,
}

impl SecureArgs {
    /// Run the secure command with CLI-provided format
    pub fn run(&self, format: OutputFormat) -> anyhow::Result<()> {
        run(self.clone(), format)
    }
}

// =============================================================================
// Implementation
// =============================================================================

/// Run the secure analysis
pub fn run(args: SecureArgs, format: OutputFormat) -> anyhow::Result<()> {
    let start = Instant::now();

    // Validate path exists
    if !args.path.exists() {
        return Err(RemainingError::file_not_found(&args.path).into());
    }

    // Create report
    let mut report = SecureReport::new(args.path.display().to_string());

    // Initialize AST cache for shared parsing
    let mut cache = AstCache::default();

    // Determine which analyses to run
    let analyses = if args.quick {
        QUICK_ANALYSES
    } else {
        FULL_ANALYSES
    };

    // VULN-SECURE-AUTODETECT-PARITY-V1 (M-AA5): mirror `tldr vuln`'s
    // language-resolution path so secure agrees with vuln on autodetect.
    //
    // Pre-fix: `tldr secure /tmp/repos/express` (no `--lang`) reported
    // `summary.taint_count: 0` while `tldr vuln /tmp/repos/express`
    // reported `findings: 1`. The discrepancy traced to secure's
    // `collect_files` lacking the autodetect step: with `lang = None`,
    // `is_supported_secure_file` matches only `py | rs`, so a JS-only
    // tree (express) silently produced an empty file set.
    //
    // M-Z10 (`secure-test-file-suppression-v1`) made vuln+secure agree
    // when `--lang` is EXPLICIT by mirroring the test-file suppression
    // mask. M-AA5 closes the symmetric gap on the autodetect path:
    //
    //   1. If `--lang L` provided, honor it as-is.
    //   2. Else, autodetect via `Language::from_directory` (M-AA1
    //      `autodetect-dominant-language-v1` made this strict
    //      extension-majority + manifest-priority).
    //   3. If the detected language lies outside the natively-analyzed
    //      set, error with `AutodetectUnsupported` (exit 2) — same
    //      contract as vuln. This points the user at an explicit
    //      `--lang` flag.
    //
    // The natively-analyzed set is canonical-pipeline-driven and lives
    // in `vuln::is_natively_analyzed` (Python, Rust, TypeScript,
    // JavaScript per M-Y3). Reusing it here keeps secure↔vuln gate
    // semantics in lock-step: if vuln autodetect-rejects a tree, secure
    // does too, with the same message.
    let effective_lang: Option<Language> = match args.lang {
        Some(l) => Some(l),
        None => {
            let detected = if args.path.is_dir() {
                Language::from_directory(&args.path)
            } else {
                Language::from_path(&args.path)
            };
            if let Some(l) = detected {
                if !super::vuln::is_natively_analyzed(l) {
                    return Err(RemainingError::autodetect_unsupported(format!(
                        "secure: taint analysis for {lang} is not yet supported by autodetect; \
                         pass --lang {lang} explicitly to scan this file (the canonical taint \
                         pipeline supports it). Autodetect-by-extension currently routes only \
                         --lang python, --lang rust, --lang typescript, and --lang javascript; \
                         other languages require an explicit --lang flag.",
                        lang = l.as_str()
                    ))
                    .into());
                }
            }
            detected
        }
    };

    // Collect files to analyze (autodetected language drives the
    // extension filter when --lang is omitted).
    let candidate_files = collect_files(&args.path, effective_lang, args.no_default_ignore)?;

    // SECURE-UTF8-TOLERANCE-V1: pre-filter for UTF-8 validity ONCE up front.
    // The 6 sub-analyses (taint, resources, bounds, contracts, behavioral,
    // mutability) each re-iterate the same files, so doing the read here
    // (a) dedupes warnings (1 message per bad file, not 6) and
    // (b) avoids each analysis having to know about the tolerance policy.
    // The Luau parser-test corpus (`tests/conformance/literals.luau`,
    // `pm.luau`, `sort.luau`) intentionally embeds raw 0xFF/0xFE bytes —
    // pre-fix `tldr secure --lang luau /tmp/repos/luau-luau` aborted with
    // `Error: stream did not contain valid UTF-8` on the first such file.
    let (files, warnings, files_skipped) = partition_utf8_clean(&candidate_files);

    // Run sub-analyses and collect findings
    let mut all_findings = Vec::new();
    let mut sub_results: HashMap<String, Value> = HashMap::new();

    for analysis in analyses {
        let (findings, raw_result) = run_security_analysis(*analysis, &files, &mut cache)?;

        // Collect findings
        all_findings.extend(findings);

        // Store raw result if requested
        if args.detail.as_deref() == Some(analysis.name()) {
            sub_results.insert(analysis.name().to_string(), raw_result);
        }
    }

    // SECURE-TEST-FILE-SUPPRESSION-V1 (M-Z10): mirror the test-file
    // suppression policy from `tldr vuln` (M-X3
    // `js-test-file-suppression-v1`). See `apply_test_file_suppression`.
    if !args.include_tests {
        apply_test_file_suppression(&mut all_findings);
    }

    // Sort findings by severity (critical first)
    all_findings.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));

    // WRAPPER-CROSS-CONSISTENCY-V1 (BUG-15, BUG-16): compute the summary
    // counters from the FINAL `findings` array via category group-by,
    // post-aggregation and post-sort. The previous implementation set
    // `taint_count = findings.len()` inside the per-analysis update where
    // `analyze_taint` on Rust files returns `category="unsafe_block"`
    // findings — so `taint_count` ghosted to N while the findings array
    // had zero `category=="taint"` entries (BUG-16). Group-by on the
    // canonical findings array makes the summary match the array by
    // construction.
    report.summary = compute_summary_from_findings(&all_findings);

    report.findings = all_findings;
    report.sub_results = sub_results;
    report.total_elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    // SECURE-UTF8-TOLERANCE-V1: surface skipped files in the report.
    report.files_skipped = files_skipped;
    report.warnings = warnings;

    // Output
    let output_str = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Compact => serde_json::to_string(&report)?,
        OutputFormat::Text => format_text_report(&report),
        OutputFormat::Sarif | OutputFormat::Dot => {
            // SARIF/DOT not fully supported for secure, fall back to JSON
            serde_json::to_string_pretty(&report)?
        }
    };

    // Write output
    if let Some(output_path) = &args.output {
        fs::write(output_path, &output_str)?;
    } else {
        println!("{}", output_str);
    }

    Ok(())
}

/// Collect supported files to analyze.
fn collect_files(
    path: &Path,
    lang: Option<Language>,
    no_default_ignore: bool,
) -> RemainingResult<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        if is_supported_secure_file(path, lang) {
            files.push(path.to_path_buf());
        }
    } else if path.is_dir() {
        // Walk directory and collect supported source files.
        let mut walker = ProjectWalker::new(path).max_depth(10);
        if no_default_ignore {
            walker = walker.no_default_ignore();
        }
        for entry in walker.iter() {
            let p = entry.path();
            if p.is_file() && is_supported_secure_file(p, lang) {
                files.push(p.to_path_buf());
            }
        }
    }

    // Return empty vec if no files found (like vuln.rs does)
    // The report will show 0 files scanned with no findings

    Ok(files)
}

/// Check whether `path` is a source file the secure analyzer should scan.
///
/// With `lang = Some(L)`, only matches that language's extensions. With
/// `lang = None`, preserves the historical behavior of `py | rs` (the
/// languages the sub-analyzers natively support).
fn is_supported_secure_file(path: &std::path::Path, lang: Option<Language>) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return false,
    };
    match lang {
        Some(Language::TypeScript) => matches!(ext, "ts" | "tsx"),
        Some(Language::JavaScript) => matches!(ext, "js" | "mjs" | "cjs" | "jsx"),
        Some(Language::Python) => ext == "py",
        Some(Language::Rust) => ext == "rs",
        Some(Language::Go) => ext == "go",
        Some(Language::Java) => ext == "java",
        Some(Language::C) => matches!(ext, "c" | "h"),
        Some(Language::Cpp) => matches!(ext, "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx"),
        Some(Language::CSharp) => ext == "cs",
        Some(Language::Ruby) => ext == "rb",
        Some(Language::Php) => ext == "php",
        Some(Language::Kotlin) => matches!(ext, "kt" | "kts"),
        Some(Language::Swift) => ext == "swift",
        Some(Language::Scala) => ext == "scala",
        Some(Language::Elixir) => matches!(ext, "ex" | "exs"),
        Some(Language::Lua) => ext == "lua",
        Some(Language::Luau) => ext == "luau",
        Some(Language::Ocaml) => matches!(ext, "ml" | "mli"),
        // v0.5.0 SOL-001 Solidity foundation: file is accepted; full
        // security analyzer (Top-5 detector suite per oracle) lands in
        // SOL-005. Until then, the entry-point returns no findings.
        Some(Language::Solidity) => ext == "sol",
        None => matches!(ext, "py" | "rs"),
    }
}

fn is_rust_file(path: &std::path::Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()), Some("rs"))
}

// `is_rust_test_file` was originally defined locally here; M-Z10
// (`secure-test-file-suppression-v1`) consolidated it with vuln.rs by
// promoting `vuln::is_rust_test_file` to `pub(super)` and reusing it
// here. See `super::vuln::is_rust_test_file`. The behavior is identical
// to the previous local impl (path component `/tests/` or filename
// suffix `_test.rs` / `tests.rs`).

/// Partition the candidate file set into clean (kept) and skipped files.
///
/// Two-stage filter:
///
/// 1. **Oversize / auto-gen pre-filter** (SECURE-FASTPATH-V1, M-Z8):
///    defer to `tldr_core::fs::oversize::check_size` before reading the
///    file. The 6 sub-analyses each iterate this file set and read the
///    full content into memory; without a cap, a 2.3 MB
///    `dom.generated.d.ts` (TypeScript DOM-gen baselines) dominates
///    the wall clock — pre-fix `tldr secure --lang typescript
///    /tmp/repos/ts-dom-gen` ran 154 s, dwarfing the rest of the
///    repo's ~20 ms. Mirrors the policy applied in
///    `vuln.rs::analyze_file` (covered by M-Y3
///    `typescript-large-file-perf-v1`) and `api_check.rs::analyze_file`
///    (covered by M-Z4 `fastpath-extend-non-vuln-v1`); central policy
///    in `tldr_core::fs::oversize` enforces the 10 MB source-file cap
///    and the 512 KB cap for `.d.ts` / `.min.js` / `.bundle.*`
///    auto-generated artefacts.
///
/// 2. **UTF-8 tolerance** (SECURE-UTF8-TOLERANCE-V1, M-X5): pre-fix,
///    `run_security_analysis` called `fs::read_to_string(file)?` which
///    propagates the `Err(io::Error("stream did not contain valid
///    UTF-8"))` returned by `String::from_utf8` for files like
///    `tests/conformance/literals.luau` in the upstream luau-luau
///    repo. That `?` aborted the entire scan on the first such file,
///    so `tldr secure --lang luau /tmp/repos/luau-luau` failed with
///    `Error: IO error: stream did not contain valid UTF-8` and
///    exited 1, even though 111/114 files were perfectly scannable.
///    Mirrors the policy already in
///    `crates/tldr-core/src/surface/luau.rs`: skip with a structured
///    warning, continue.
///
/// Both oversize and non-UTF-8 skips are counted under the returned
/// `files_skipped` counter and surfaced via a structured warning.
/// Genuine I/O errors (file vanished mid-scan) drop the file with a
/// warning but are NOT counted as a skip — the `secure` walk is
/// best-effort and one transient failure should not lose the rest.
fn partition_utf8_clean(candidates: &[PathBuf]) -> (Vec<PathBuf>, Vec<String>, u32) {
    use tldr_core::fs::oversize::{check_size, format_oversize_warning, SizeCheck};

    let mut clean: Vec<PathBuf> = Vec::with_capacity(candidates.len());
    let mut warnings: Vec<String> = Vec::new();
    let mut skipped: u32 = 0;
    for file in candidates {
        // SECURE-FASTPATH-V1 (M-Z8): apply oversize cap BEFORE the read.
        // `read_to_string_tolerant` reads the full file into memory, so
        // a 2.3 MB `dom.generated.d.ts` would otherwise be loaded six
        // times (once per sub-analysis read) and parsed once into a
        // tree-sitter AST per analysis. The check_size stat call is
        // O(1) and returns SizeCheck::Unknown for missing files
        // (which then falls through to the existing read path and is
        // handled there).
        match check_size(file) {
            SizeCheck::Oversize {
                size_bytes,
                max_bytes,
                is_autogen,
            } => {
                skipped += 1;
                warnings.push(format_oversize_warning(
                    file,
                    size_bytes,
                    max_bytes,
                    is_autogen,
                ));
                continue;
            }
            // WithinLimit | Unknown: proceed to the UTF-8 read below.
            _ => {}
        }

        match read_to_string_tolerant(file) {
            Ok(ReadOutcome::Ok(_)) => clean.push(file.clone()),
            Ok(ReadOutcome::NonUtf8 { byte_offset }) => {
                skipped += 1;
                warnings.push(format!(
                    "Skipped {}: invalid UTF-8 at byte {}",
                    file.display(),
                    byte_offset
                ));
            }
            Err(e) => {
                // Genuine I/O failure (permissions, vanished, etc.).
                // Drop the file with a warning rather than aborting the
                // whole scan. This is NOT counted under `files_skipped`,
                // which is reserved for the UTF-8-tolerance policy and
                // the oversize policy.
                warnings.push(format!(
                    "Skipped {}: I/O error: {}",
                    file.display(),
                    e
                ));
            }
        }
    }
    (clean, warnings, skipped)
}

/// Run a specific security analysis on files
fn run_security_analysis(
    analysis: SecurityAnalysis,
    files: &[PathBuf],
    cache: &mut AstCache,
) -> RemainingResult<(Vec<SecureFinding>, Value)> {
    let mut findings = Vec::new();

    for file in files {
        // SECURE-UTF8-TOLERANCE-V1 (defense-in-depth): the file set was
        // pre-filtered by `partition_utf8_clean` in `run`, so a clean
        // read is the expected path. We still use the tolerant reader
        // here so that a TOCTOU race (file replaced with non-UTF-8
        // content between the partition pass and the analysis pass)
        // skips the file instead of aborting the scan. No warning is
        // emitted here — the partition pass owns warning emission to
        // avoid duplicate messages across the 6 sub-analyses.
        let source = match read_to_string_tolerant(file)? {
            ReadOutcome::Ok(s) => s,
            ReadOutcome::NonUtf8 { .. } => continue,
        };

        // Get or parse the AST
        let tree = cache.get_or_parse(file, &source)?;

        // Run analysis
        let file_findings = match analysis {
            SecurityAnalysis::Taint => analyze_taint(tree.root_node(), &source, file),
            SecurityAnalysis::Resources => analyze_resources(tree.root_node(), &source, file),
            SecurityAnalysis::Bounds => analyze_bounds(tree.root_node(), &source, file),
            SecurityAnalysis::Contracts => analyze_contracts(tree.root_node(), &source, file),
            SecurityAnalysis::Behavioral => analyze_behavioral(tree.root_node(), &source, file),
            SecurityAnalysis::Mutability => analyze_mutability(tree.root_node(), &source, file),
        };

        findings.extend(file_findings);
    }

    // Create raw result
    let raw_result = serde_json::to_value(&findings).unwrap_or(Value::Array(vec![]));

    Ok((findings, raw_result))
}

/// SECURE-TEST-FILE-SUPPRESSION-V1 (M-Z10): in-place suppression of
/// findings emitted from test files. Mirrors the post-analysis filter
/// applied in `vuln.rs::VulnArgs::run` for `--include-tests`, restoring
/// vuln↔secure parity (`tldr secure`'s taint findings count must match
/// `tldr vuln`'s finding count on the same path).
///
/// Pre-fix on `/tmp/repos/express`:
/// * `tldr vuln --lang javascript .` → 1 finding (index.js:21; the
///   `test/app.engine.js:9` finding masked by M-X3 `is_js_test_file`).
/// * `tldr secure --lang javascript . | jq '[.findings[]|select(.category=="taint")]'`
///   → 2 findings (index.js + test/app.engine.js — secure ran the
///   canonical taint pipeline but never applied the M-X3 mask, so the
///   `test/app.engine.js` finding leaked through).
///
/// Reuses `super::vuln::is_js_test_file` (M-X3 helper: JS/TS path
/// components + test-style filename suffixes, with a `/fixtures/`
/// exemption that keeps `vuln_migration_v1` GREEN) and
/// `super::vuln::is_rust_test_file` (Rust `/tests/` + `_test.rs` /
/// `tests.rs` suffix). The Rust mask was already applied INSIDE
/// `analyze_rust_bounds` for unwrap-style smell findings; this filter
/// adds the symmetric mask for taint-class findings.
///
/// Runs BEFORE `compute_summary_from_findings` so the summary reflects
/// the suppressed view (matches the WRAPPER-CROSS-CONSISTENCY-V1
/// invariant: summary derives from the final findings array).
fn apply_test_file_suppression(findings: &mut Vec<SecureFinding>) {
    findings.retain(|f| {
        let p = std::path::Path::new(&f.file);
        // Fixture exemption: paths under a `fixtures/` directory must
        // NOT be suppressed even when their ancestors include `tests/`
        // (e.g. `crates/tldr-cli/tests/fixtures/vuln_migration_v1/...`).
        // `is_js_test_file` already bakes this exemption in; we apply
        // the same gate to the Rust predicate (which doesn't, since on
        // the vuln side Rust file collection happens before the
        // post-analysis filter and the fixture suite is JS/TS-only).
        // Without this gate, finding-level Rust suppression would drop
        // legitimate fixture findings on hypothetical Rust fixtures.
        let in_fixtures =
            f.file.contains("/fixtures/") || f.file.contains("\\fixtures\\");
        if in_fixtures {
            return true;
        }
        !super::vuln::is_js_test_file(p) && !super::vuln::is_rust_test_file(p)
    });
}

/// Compute the summary by category group-by over the FINAL findings array.
///
/// WRAPPER-CROSS-CONSISTENCY-V1 (BUG-15, BUG-16): every `*_count` field
/// derives from `findings[].category`, so the schema invariant
/// `taint_count + leak_count + bounds_warnings + behavioral_count +
///  unsafe_blocks + raw_pointer_ops + unwrap_calls + todo_markers +
///  missing_contracts + mutable_params == findings.len()`
/// holds by construction. `taint_critical` is a severity refinement of
/// `taint_count` (subset, not its own category) and is excluded from the
/// invariant.
///
/// Categories emitted by sub-analyzers (must remain in sync with the
/// `analyze_*` functions below):
/// - taint analysis: `taint` (Python/JS/etc.) | `unsafe_block` (Rust)
/// - resource analysis: `resource_leak` (Python) | `raw_pointer` (Rust)
/// - bounds analysis: `bounds` (Python) | `unwrap`, `todo_marker` (Rust)
/// - behavioral analysis: `behavioral`
/// - contracts analysis: `missing_contract` (placeholder, currently unused)
/// - mutability analysis: `mutable_param` (placeholder, currently unused)
fn compute_summary_from_findings(findings: &[SecureFinding]) -> SecureSummary {
    let count_cat = |cat: &str| findings.iter().filter(|f| f.category == cat).count() as u32;

    SecureSummary {
        taint_count: count_cat("taint"),
        taint_critical: findings
            .iter()
            .filter(|f| f.category == "taint" && f.severity == "critical")
            .count() as u32,
        leak_count: count_cat("resource_leak"),
        bounds_warnings: count_cat("bounds"),
        behavioral_count: count_cat("behavioral"),
        missing_contracts: count_cat("missing_contract"),
        mutable_params: count_cat("mutable_param"),
        unsafe_blocks: count_cat("unsafe_block"),
        raw_pointer_ops: count_cat("raw_pointer"),
        unwrap_calls: count_cat("unwrap"),
        todo_markers: count_cat("todo_marker"),
    }
}

/// Get severity order (lower = more severe)
fn severity_order(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

// =============================================================================
// Taint Analysis
// =============================================================================

/// Analyze taint flows in a file.
///
/// SECURE-TAINT-AGGREGATOR-V1: For non-Rust files this routes through the
/// canonical `tldr_core::security::vuln::scan_vulnerabilities` pipeline —
/// the same pipeline `tldr vuln` uses — so `secure.summary.taint_count`
/// agrees with `tldr vuln`'s finding count.
///
/// RUST-SECURE-TAINT-AGGREGATOR-V2: For Rust files this now mirrors
/// `tldr vuln`'s dual dispatch from `rust-vuln-taint-pipeline-v1`:
/// canonical pipeline + line scanner with overlap dedup. The
/// canonical findings AND the line-scanner SqlInjection /
/// CommandInjection findings (the only line-scanner emissions that are
/// taint-class — UnsafeCode/MemorySafety/Panic are smell-class and not
/// counted under `summary.taint_count`) are emitted with
/// `category = "taint"`. Unsafe-block findings retain
/// `category = "unsafe_block"` (counted separately by
/// `summary.unsafe_blocks`). Pre-V2, secure dropped ALL canonical Rust
/// taint findings — `tldr vuln --lang rust file.rs` reported N>0
/// findings while `tldr secure --lang rust file.rs` reported 0
/// (BUG-17, surfaced by the 17-lang sweep).
///
/// The legacy substring-based `TAINT_SINKS` matcher (which produced 0
/// findings on real flows because it could not see source-to-sink
/// relationships) remains retired.
fn analyze_taint(_root: Node, source: &str, file: &Path) -> Vec<SecureFinding> {
    let (mut findings, canonical_lines) = canonical_taint_findings_with_index(file);
    if is_rust_file(file) {
        findings.extend(rust_line_scanner_taint_findings(
            file,
            source,
            &canonical_lines,
        ));
        findings.extend(analyze_rust_unsafe_blocks(source, file));
    }
    findings
}

/// Run the Rust line scanner from `vuln.rs` and project ONLY its
/// taint-class findings (SqlInjection, CommandInjection) onto
/// `SecureFinding`s with `category = "taint"`. Non-taint smell-class
/// emissions (UnsafeCode, MemorySafety, Panic) are dropped here — they
/// are surfaced by the dedicated `analyze_rust_unsafe_blocks` /
/// `analyze_rust_raw_pointers` / `analyze_rust_bounds` paths under
/// their own categories.
///
/// `canonical_index` carries the `(line, core_VulnType)` tuples the
/// canonical pipeline already produced for this file. SqlInjection /
/// CommandInjection line-scanner findings whose `(line, vuln_type)` is
/// already in the canonical index are dropped — same dedup predicate as
/// `vuln.rs::dedupe_overlap`. This keeps secure↔vuln per-file counts
/// equal: vuln applies the same dedup, so secure must too, otherwise
/// secure would over-count when both layers report the same finding.
///
/// RUST-SECURE-TAINT-AGGREGATOR-V2: closes the
/// `sql_injection_format_keyword_positive.rs` parity gap — the
/// canonical Rust pipeline does not produce a SqlInjection finding for
/// `format!("SELECT … {}", x)` (no real source-to-sink), but the line
/// scanner does (per `rust-format-sql-fp-narrowing-v1`). For
/// secure↔vuln directory-level parity, secure must include this.
fn rust_line_scanner_taint_findings(
    file: &Path,
    source: &str,
    canonical_index: &[(u32, tldr_core::security::vuln::VulnType)],
) -> Vec<SecureFinding> {
    use crate::commands::remaining::types::VulnType;

    super::vuln::analyze_rust_file(file, source)
        .into_iter()
        .filter(|f| {
            matches!(
                f.vuln_type,
                VulnType::SqlInjection | VulnType::CommandInjection
            )
        })
        .filter(|f| {
            // Mirrors `vuln.rs::dedupe_overlap`: drop line-scanner finding
            // if canonical already covers `(line, vuln_type)`.
            let core_ty = match f.vuln_type {
                VulnType::SqlInjection => tldr_core::security::vuln::VulnType::SqlInjection,
                VulnType::CommandInjection => {
                    tldr_core::security::vuln::VulnType::CommandInjection
                }
                _ => return true,
            };
            !canonical_index
                .iter()
                .any(|(line, ty)| *line == f.line && *ty == core_ty)
        })
        .map(|f| {
            let severity = match f.severity {
                crate::commands::remaining::types::Severity::Critical => "critical",
                crate::commands::remaining::types::Severity::High => "high",
                crate::commands::remaining::types::Severity::Medium => "medium",
                crate::commands::remaining::types::Severity::Low => "low",
                _ => "medium",
            };
            let description = format!("{:?}: {}", f.vuln_type, f.description);
            SecureFinding::new("taint", severity, description).with_location(f.file, f.line)
        })
        .collect()
}

/// Run the canonical `scan_vulnerabilities` pipeline on a single file and
/// project the resulting `VulnFinding`s onto `SecureFinding`s with
/// `category = "taint"`. Returns both the projected findings AND the
/// set of `(line, core_VulnType)` tuples covered by canonical — used by
/// the Rust line-scanner path to dedupe overlap (SqlInjection,
/// CommandInjection on the same line). Mirrors
/// `vuln.rs::dedupe_overlap`.
///
/// Runs for ALL extensions including `.rs`
/// (RUST-SECURE-TAINT-AGGREGATOR-V2 — mirrors `tldr vuln`'s
/// canonical-for-all-languages dispatch from
/// `rust-vuln-taint-pipeline-v1`).
fn canonical_taint_findings_with_index(
    file: &Path,
) -> (
    Vec<SecureFinding>,
    Vec<(u32, tldr_core::security::vuln::VulnType)>,
) {
    let report = match tldr_core::security::vuln::scan_vulnerabilities(file, None, None) {
        Ok(r) => r,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let index: Vec<(u32, tldr_core::security::vuln::VulnType)> = report
        .findings
        .iter()
        .map(|f| (f.sink.line, f.vuln_type))
        .collect();

    let findings = report
        .findings
        .into_iter()
        .map(|f| {
            let severity = match f.severity.to_uppercase().as_str() {
                "CRITICAL" => "critical",
                "HIGH" => "high",
                "MEDIUM" => "medium",
                "LOW" => "low",
                _ => "medium",
            };
            let description = format!(
                "{:?}: {} with unsanitized input from {}",
                f.vuln_type, f.sink.sink_type, f.source.source_type
            );
            SecureFinding::new("taint", severity, description)
                .with_location(f.file.display().to_string(), f.sink.line)
        })
        .collect();

    (findings, index)
}

// =============================================================================
// Resource Analysis
// =============================================================================

/// Known resource creators
const RESOURCE_CREATORS: &[&str] = &["open", "socket", "connect", "cursor", "urlopen"];

/// Analyze resource leaks in a file
fn analyze_resources(root: Node, source: &str, file: &Path) -> Vec<SecureFinding> {
    if is_rust_file(file) {
        return analyze_rust_raw_pointers(source, file);
    }

    let mut findings = Vec::new();
    let source_bytes = source.as_bytes();

    // Find resource assignments outside of `with` statements
    find_leaked_resources(root, source_bytes, file, &mut findings);

    findings
}

fn find_leaked_resources(
    node: Node,
    source: &[u8],
    file: &Path,
    findings: &mut Vec<SecureFinding>,
) {
    // Check if this is an assignment with a resource creator
    if node.kind() == "assignment" {
        if let Some(right) = node.child_by_field_name("right") {
            if right.kind() == "call" {
                if let Some(func) = right.child_by_field_name("function") {
                    let func_text = node_text(func, source);
                    let func_name = func_text.split('.').next_back().unwrap_or(func_text);

                    if RESOURCE_CREATORS.contains(&func_name) {
                        // Check if this is inside a with statement
                        if !is_inside_with(node) {
                            findings.push(
                                SecureFinding::new(
                                    "resource_leak",
                                    "high",
                                    format!(
                                        "Resource '{}' opened without context manager - may leak",
                                        func_name
                                    ),
                                )
                                .with_location(
                                    file.display().to_string(),
                                    node.start_position().row as u32 + 1,
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    // Recurse
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_leaked_resources(child, source, file, findings);
        }
    }
}

fn is_inside_with(node: Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "with_statement" {
            return true;
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Bounds Analysis
// =============================================================================

/// Analyze bounds/overflow issues in a file
fn analyze_bounds(_root: Node, source: &str, file: &Path) -> Vec<SecureFinding> {
    if is_rust_file(file) {
        return analyze_rust_bounds(source, file);
    }

    // Placeholder for Python bounds analysis.
    Vec::new()
}

// =============================================================================
// Contracts Analysis
// =============================================================================

/// Analyze missing contracts in a file
fn analyze_contracts(_root: Node, _source: &str, _file: &Path) -> Vec<SecureFinding> {
    // Placeholder - would check for functions without type hints, docstrings, or assertions
    Vec::new()
}

// =============================================================================
// Behavioral Analysis
// =============================================================================

/// Analyze behavioral issues (exception handling, state) in a file
fn analyze_behavioral(root: Node, source: &str, file: &Path) -> Vec<SecureFinding> {
    let mut findings = Vec::new();
    let source_bytes = source.as_bytes();

    // Find bare except clauses
    find_bare_except(root, source_bytes, file, &mut findings);

    findings
}

fn find_bare_except(node: Node, source: &[u8], file: &Path, findings: &mut Vec<SecureFinding>) {
    // Check for except clauses without exception type
    if node.kind() == "except_clause" {
        let has_type = node.children(&mut node.walk()).any(|c| {
            c.kind() == "as_pattern"
                || (c.kind() == "identifier" && node_text(c, source) != "Exception")
        });

        if !has_type {
            let text = node_text(node, source);
            if text.starts_with("except:") || text.starts_with("except :") {
                findings.push(
                    SecureFinding::new(
                        "behavioral",
                        "medium",
                        "Bare except clause catches all exceptions including KeyboardInterrupt",
                    )
                    .with_location(
                        file.display().to_string(),
                        node.start_position().row as u32 + 1,
                    ),
                );
            }
        }
    }

    // Recurse
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_bare_except(child, source, file, findings);
        }
    }
}

// =============================================================================
// Mutability Analysis
// =============================================================================

/// Analyze mutability issues in a file
fn analyze_mutability(_root: Node, _source: &str, _file: &Path) -> Vec<SecureFinding> {
    // Placeholder - would check for mutable default arguments, etc.
    Vec::new()
}

// =============================================================================
// Utilities
// =============================================================================

fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn analyze_rust_unsafe_blocks(source: &str, file: &Path) -> Vec<SecureFinding> {
    let mut findings = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains("unsafe {") || trimmed.starts_with("unsafe{") {
            findings.push(
                SecureFinding::new(
                    "unsafe_block",
                    "high",
                    "unsafe block detected; verify invariants and safety rationale",
                )
                .with_location(file.display().to_string(), (idx + 1) as u32),
            );
        }
    }
    findings
}

fn analyze_rust_raw_pointers(source: &str, file: &Path) -> Vec<SecureFinding> {
    let mut findings = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains("std::ptr::")
            || trimmed.contains("core::ptr::")
            || trimmed.contains("ptr::read(")
            || trimmed.contains("ptr::write(")
        {
            findings.push(
                SecureFinding::new(
                    "raw_pointer",
                    "high",
                    "raw pointer operation detected; audit aliasing, lifetime, and bounds assumptions",
                )
                .with_location(file.display().to_string(), (idx + 1) as u32),
            );
        }
    }
    findings
}

fn analyze_rust_bounds(source: &str, file: &Path) -> Vec<SecureFinding> {
    let mut findings = Vec::new();
    let skip_test_only = super::vuln::is_rust_test_file(file);

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        if !skip_test_only && trimmed.contains(".unwrap()") {
            findings.push(
                SecureFinding::new(
                    "unwrap",
                    "medium",
                    "unwrap() call in non-test code may panic at runtime",
                )
                .with_location(file.display().to_string(), (idx + 1) as u32),
            );
        }

        if !skip_test_only && (trimmed.contains("todo!(") || trimmed.contains("unimplemented!(")) {
            findings.push(
                SecureFinding::new(
                    "todo_marker",
                    "low",
                    "todo!/unimplemented! marker found in non-test Rust code",
                )
                .with_location(file.display().to_string(), (idx + 1) as u32),
            );
        }
    }

    findings
}

// =============================================================================
// Text Output
// =============================================================================

fn format_text_report(report: &SecureReport) -> String {
    let mut output = String::new();

    output.push_str(&"=".repeat(60));
    output.push('\n');
    output.push_str(&format!(
        "{}\n",
        "SECURE - Security Analysis Dashboard".bold()
    ));
    output.push_str(&"=".repeat(60));
    output.push_str("\n\n");
    output.push_str(&format!("Path: {}\n\n", report.path));

    if report.findings.is_empty() {
        output.push_str(&format!("{}\n", "No security issues found.".green()));
    } else {
        output.push_str(&format!(
            "{}\n",
            "Severity | Category       | Description".bold()
        ));
        output.push_str(&format!("{}\n", "-".repeat(60)));

        for finding in &report.findings {
            let severity_colored = match finding.severity.as_str() {
                "critical" => finding.severity.red().bold().to_string(),
                "high" => finding.severity.red().to_string(),
                "medium" => finding.severity.yellow().to_string(),
                "low" => finding.severity.blue().to_string(),
                _ => finding.severity.clone(),
            };
            output.push_str(&format!(
                "{:>8} | {:<14} | {}\n",
                severity_colored, finding.category, finding.description
            ));
            if !finding.file.is_empty() {
                output.push_str(&format!(
                    "         |                | {}:{}\n",
                    finding.file, finding.line
                ));
            }
        }
    }

    output.push('\n');
    output.push_str(&format!("{}\n", "Summary:".bold()));
    output.push_str(&format!(
        "  Taint issues:      {} ({} critical)\n",
        report.summary.taint_count, report.summary.taint_critical
    ));
    output.push_str(&format!(
        "  Resource leaks:    {}\n",
        report.summary.leak_count
    ));
    output.push_str(&format!(
        "  Bounds warnings:   {}\n",
        report.summary.bounds_warnings
    ));
    output.push_str(&format!(
        "  Behavioral:        {}\n",
        report.summary.behavioral_count
    ));
    output.push_str(&format!(
        "  Missing contracts: {}\n",
        report.summary.missing_contracts
    ));
    output.push_str(&format!(
        "  Mutable params:    {}\n",
        report.summary.mutable_params
    ));
    output.push_str(&format!(
        "  Unsafe blocks:     {}\n",
        report.summary.unsafe_blocks
    ));
    output.push_str(&format!(
        "  Raw pointer ops:   {}\n",
        report.summary.raw_pointer_ops
    ));
    output.push_str(&format!(
        "  Unwrap calls:      {}\n",
        report.summary.unwrap_calls
    ));
    output.push_str(&format!(
        "  Todo markers:      {}\n",
        report.summary.todo_markers
    ));
    output.push('\n');
    output.push_str(&format!("Elapsed: {:.2}ms\n", report.total_elapsed_ms));

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tree_sitter::Parser;

    fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_secure_args_default() {
        // Test that default values are set correctly
        let args = SecureArgs {
            path: PathBuf::from("test.py"),
            lang: None,
            detail: None,
            quick: false,
            output: None,
            no_default_ignore: false,
            include_tests: false,
        };
        assert!(!args.quick);
        assert!(!args.include_tests);
    }

    #[test]
    fn test_severity_order() {
        assert!(severity_order("critical") < severity_order("high"));
        assert!(severity_order("high") < severity_order("medium"));
        assert!(severity_order("medium") < severity_order("low"));
        assert!(severity_order("low") < severity_order("info"));
    }

    #[test]
    fn test_taint_analysis_finds_sql_injection() {
        // SECURE-TAINT-AGGREGATOR-V1: routes through canonical
        // `scan_vulnerabilities` which requires a real source-to-sink
        // flow (not just a literal f-string in a sink). This fixture
        // models a Flask request → cursor.execute flow that the
        // canonical taint engine reports.
        let temp = TempDir::new().unwrap();
        let source = r#"
from flask import request
import sqlite3

def query():
    user_input = request.args.get("name")
    conn = sqlite3.connect("db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"#;
        let path = create_test_file(&temp, "vuln.py", source);

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let findings = analyze_taint(tree.root_node(), source, &path);
        assert!(
            !findings.is_empty(),
            "Should detect SQL injection from request.args -> cursor.execute"
        );
        assert!(findings.iter().all(|f| f.category == "taint"));
    }

    /// SECURE-TAINT-AGGREGATOR-V1: secure↔vuln aggregation parity guard.
    ///
    /// The canonical `scan_vulnerabilities` pipeline is the single
    /// source of truth for taint findings. `tldr secure` MUST surface
    /// the same finding count as `tldr vuln` on the same path —
    /// previously secure ran a substring-only matcher that missed
    /// every real source-to-sink flow and reported `taint_count: 0`
    /// while `vuln` reported N>0 on the same file.
    #[test]
    fn test_secure_taint_count_matches_vuln_findings() {
        let temp = TempDir::new().unwrap();
        // Fixture with a real Flask-style taint flow: HTTP param ->
        // subprocess.call (CommandInjection) and HTTP param ->
        // cursor.execute (SqlInjection-via-string-concat).
        let source = r#"
from flask import request
import subprocess
import sqlite3

def cmd():
    user = request.args.get("user")
    subprocess.call("echo " + user, shell=True)

def sql():
    name = request.args.get("name")
    conn = sqlite3.connect("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + name + "'")
"#;
        let path = create_test_file(&temp, "flow.py", source);

        // Canonical pipeline (same call path tldr vuln uses).
        let vuln_report =
            tldr_core::security::vuln::scan_vulnerabilities(&path, None, None).unwrap();
        let vuln_count = vuln_report.findings.len();
        assert!(
            vuln_count > 0,
            "Fixture must produce >=1 canonical finding (got 0 - fixture is wrong)"
        );

        // secure's taint analysis on the same file.
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let secure_findings = analyze_taint(tree.root_node(), source, &path);

        assert_eq!(
            secure_findings.len(),
            vuln_count,
            "secure taint findings must match vuln finding count exactly \
             (secure={}, vuln={}). secure uses canonical scan_vulnerabilities \
             pipeline.",
            secure_findings.len(),
            vuln_count
        );
        assert!(secure_findings.iter().all(|f| f.category == "taint"));
    }

    /// RUST-SECURE-TAINT-AGGREGATOR-V2: Rust-specific secure↔vuln aggregation
    /// parity guard. Pre-V2, `analyze_taint` short-circuited on `.rs` files
    /// to ONLY the unsafe-block line scanner, dropping every canonical
    /// taint finding. `tldr vuln --lang rust file.rs` reported N>0
    /// CommandInjection/SqlInjection findings while `tldr secure --lang rust
    /// file.rs` reported `taint_count: 0`. Surfaced by the v0.2.x 17-language
    /// sweep — Rust was the only language failing
    /// `secure.taint_count == vuln.findings.length` parity (16/17 passed).
    ///
    /// Post-V2: secure.taint_count (category="taint") MUST equal
    /// vuln.findings.length on Rust. Unsafe-block findings are still
    /// emitted but counted under summary.unsafe_blocks, not taint_count.
    #[test]
    fn test_secure_taint_count_matches_vuln_rust() {
        let temp = TempDir::new().unwrap();
        // Real source-to-sink command-injection flow in Rust: env input
        // (untrusted source) flowing into Command::new(...).arg(...).output()
        // (sink). Mirrors `command_injection_positive.rs` from
        // `vuln_migration_v1` fixtures.
        let source = r#"
use std::env;
use std::process::Command;

fn run() {
    let user = env::var("USER_INPUT").unwrap();
    let output = Command::new("sh").arg("-c").arg(&user).output();
    let _ = output;
}
"#;
        let path = create_test_file(&temp, "cmd_inj.rs", source);

        // Canonical pipeline (same call path tldr vuln uses).
        let vuln_report =
            tldr_core::security::vuln::scan_vulnerabilities(&path, None, None).unwrap();
        let vuln_count = vuln_report.findings.len();
        assert!(
            vuln_count > 0,
            "Fixture must produce >=1 canonical Rust finding (got 0 - fixture is wrong)"
        );

        // secure's taint analysis on the same Rust file.
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let secure_findings = analyze_taint(tree.root_node(), source, &path);

        // Filter to category="taint" — that's what summary.taint_count counts.
        // (analyze_taint may also include category="unsafe_block" findings
        // for Rust, which feed summary.unsafe_blocks, not taint_count.)
        let taint_findings: Vec<_> = secure_findings
            .iter()
            .filter(|f| f.category == "taint")
            .collect();

        assert_eq!(
            taint_findings.len(),
            vuln_count,
            "secure taint findings (category=\"taint\") must match vuln \
             finding count exactly on Rust (secure_taint={}, vuln={}). \
             RUST-SECURE-TAINT-AGGREGATOR-V2 routes Rust through the \
             canonical scan_vulnerabilities pipeline, same as tldr vuln.",
            taint_findings.len(),
            vuln_count
        );
    }

    #[test]
    fn test_resource_analysis_finds_leak() {
        let source = r#"
def read_file():
    f = open("test.txt")
    data = f.read()
    return data
"#;

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let findings = analyze_resources(tree.root_node(), source, &PathBuf::from("test.py"));
        assert!(!findings.is_empty(), "Should detect resource leak");
    }

    #[test]
    fn test_resource_analysis_no_leak_with_context() {
        let source = r#"
def read_file():
    with open("test.txt") as f:
        data = f.read()
    return data
"#;

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let findings = analyze_resources(tree.root_node(), source, &PathBuf::from("test.py"));
        assert!(
            findings.is_empty(),
            "Should not detect leak with context manager"
        );
    }

    #[test]
    fn test_collect_files_includes_rust() {
        let temp = TempDir::new().unwrap();
        create_test_file(&temp, "sample.py", "print('ok')");
        create_test_file(&temp, "lib.rs", "fn main() {}");
        create_test_file(&temp, "notes.txt", "ignore");

        let files = collect_files(temp.path(), None, false).unwrap();
        assert!(files.iter().any(|f| f.ends_with("sample.py")));
        assert!(files.iter().any(|f| f.ends_with("lib.rs")));
        assert!(!files.iter().any(|f| f.ends_with("notes.txt")));
    }

    #[test]
    fn test_rust_secure_metrics_detected() {
        let source = r#"
use std::ptr;

fn risky(user: &str) {
    unsafe { ptr::write(user.as_ptr() as *mut u8, b'x'); }
    let _v = Some(user).unwrap();
    todo!("finish hardening");
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = PathBuf::from("src/lib.rs");

        let taint_findings = analyze_taint(tree.root_node(), source, &file);
        let resource_findings = analyze_resources(tree.root_node(), source, &file);
        let bounds_findings = analyze_bounds(tree.root_node(), source, &file);

        assert!(!taint_findings.is_empty(), "Should count unsafe blocks");
        assert!(
            !resource_findings.is_empty(),
            "Should count raw pointer ops"
        );
        assert!(
            bounds_findings.iter().any(|f| f.category == "unwrap"),
            "Should count unwrap calls"
        );
        assert!(
            bounds_findings.iter().any(|f| f.category == "todo_marker"),
            "Should count todo markers"
        );
    }

    /// SECURE-FASTPATH-V1 (M-Z8): the file partition step must drop
    /// oversize / auto-generated files BEFORE the per-analysis
    /// `read_to_string_tolerant` loop, mirroring the policy applied
    /// by `vuln.rs::analyze_file` (M-Y3) and `api_check.rs::analyze_file`
    /// (M-Z4). Pre-fix, `tldr secure --lang typescript /tmp/repos/ts-dom-gen`
    /// ran 154 s because the 2.3 MB `dom.generated.d.ts` was read 6
    /// times (once per sub-analysis) and parsed 6 times into a
    /// tree-sitter AST. The fastpath skips it on the FIRST stat call.
    ///
    /// Test fixture: a synthetic `.d.ts` file padded over the 512 KB
    /// auto-gen cap (`MAX_AUTOGEN_FILE_SIZE_BYTES`). Asserts:
    /// 1. The file is dropped from the kept set.
    /// 2. `files_skipped` is incremented.
    /// 3. The warning carries the documented oversize shape so
    ///    consumers can distinguish oversize from UTF-8 skips.
    #[test]
    fn test_secure_skips_oversize_files() {
        use tldr_core::fs::oversize::MAX_AUTOGEN_FILE_SIZE_BYTES;

        let temp = TempDir::new().unwrap();

        // Padded content that exceeds the auto-gen cap. Use a `.d.ts`
        // suffix so the auto-gen 512 KB cap applies (rather than the
        // 10 MB source-file cap, which would force a many-MB fixture).
        let mut padded = String::with_capacity(MAX_AUTOGEN_FILE_SIZE_BYTES as usize + 1024);
        padded.push_str("export type Generated = {\n");
        // A line that is harmless but heavy enough to cross the cap.
        let line = "  member_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx: string;\n";
        while (padded.len() as u64) < MAX_AUTOGEN_FILE_SIZE_BYTES + 1024 {
            padded.push_str(line);
        }
        padded.push_str("};\n");
        let big = create_test_file(&temp, "dom.generated.d.ts", &padded);

        // Sanity: confirm we actually exceeded the cap (otherwise the
        // test would be a no-op false-positive).
        let size = std::fs::metadata(&big).unwrap().len();
        assert!(
            size > MAX_AUTOGEN_FILE_SIZE_BYTES,
            "fixture must exceed auto-gen cap (size={}, cap={})",
            size,
            MAX_AUTOGEN_FILE_SIZE_BYTES
        );

        // Also include a small, in-policy `.ts` file so we can verify
        // the partition continues past the oversize skip rather than
        // short-circuiting.
        let small = create_test_file(
            &temp,
            "ok.ts",
            "export function f(x: string): string { return x; }\n",
        );

        let (kept, warnings, files_skipped) =
            partition_utf8_clean(&[big.clone(), small.clone()]);

        // 1. Oversize file is dropped from the kept set.
        assert!(
            !kept.iter().any(|p| p == &big),
            "oversize .d.ts must be dropped from kept set: kept={:?}",
            kept
        );
        // The small in-policy file is preserved.
        assert!(
            kept.iter().any(|p| p == &small),
            "small in-policy .ts must be preserved: kept={:?}",
            kept
        );

        // 2. files_skipped reflects the oversize drop.
        assert_eq!(
            files_skipped, 1,
            "files_skipped must count the oversize drop (got {})",
            files_skipped
        );

        // 3. Warning carries the documented oversize shape, distinct
        //    from the UTF-8 "invalid UTF-8 at byte" shape.
        let oversize_warning = warnings
            .iter()
            .find(|w| w.contains("dom.generated.d.ts"))
            .expect("must emit a warning for the oversize file");
        assert!(
            oversize_warning.contains("exceeds")
                && oversize_warning.contains("cap for")
                && oversize_warning.contains("auto-generated/minified files"),
            "oversize warning must use the format_oversize_warning shape \
             (got: {})",
            oversize_warning
        );
    }

    // =========================================================================
    // SECURE-TEST-FILE-SUPPRESSION-V1 (M-Z10) — vuln/secure parity tests
    // =========================================================================

    /// Build a SecureReport JSON file by running `secure::run` against a
    /// temp directory containing the supplied files. Returns the parsed
    /// JSON value for assertion.
    fn run_secure_to_json(
        path: &Path,
        lang: Language,
        include_tests: bool,
    ) -> serde_json::Value {
        let temp_out = TempDir::new().unwrap();
        let out_path = temp_out.path().join("report.json");
        let args = SecureArgs {
            path: path.to_path_buf(),
            lang: Some(lang),
            detail: None,
            // Quick mode: only run taint/resources/bounds, sufficient for
            // the suppression assertion and faster.
            quick: true,
            output: Some(out_path.clone()),
            no_default_ignore: false,
            include_tests,
        };
        run(args, OutputFormat::Json).expect("secure::run should succeed");
        let raw = fs::read_to_string(&out_path).expect("report file must exist");
        serde_json::from_str(&raw).expect("report must be valid JSON")
    }

    /// SECURE-TEST-FILE-SUPPRESSION-V1: default scan must suppress
    /// findings emitted from JS/TS test files, mirroring `tldr vuln`'s
    /// M-X3 mask. Without this, vuln/secure parity breaks: vuln=1
    /// finding (source-only), secure.taint=2 findings (source + test).
    #[test]
    fn test_secure_default_suppresses_js_test_files() {
        let temp = TempDir::new().unwrap();

        // Source file with a real source-to-sink reflected-XSS flow
        // (req.query -> res.send). Same shape as the
        // `vuln_migration_v1/javascript/xss_positive.js` fixture, which
        // the canonical taint engine is known to report on.
        let source_js = r#"export function handler(req, res, db) {
    const name = req.query.name;
    res.send("<h1>" + name + "</h1>");
}
"#;
        // Test file with the SAME flow shape, placed under `test/` so
        // it matches `is_js_test_file`. The canonical taint engine
        // emits a finding here too; without the suppression filter
        // this would inflate `secure.taint` past `vuln.findings`.
        let test_js = r#"export function handler(req, res, db) {
    const input = req.query.q;
    res.send("<p>" + input + "</p>");
}
"#;

        // Layout:
        //   <temp>/src/index.js   (source — must produce a finding)
        //   <temp>/test/app.test.js  (test — must be suppressed)
        let src_dir = temp.path().join("src");
        let test_dir = temp.path().join("test");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&test_dir).unwrap();
        let src_path = src_dir.join("index.js");
        let test_path = test_dir.join("app.test.js");
        fs::write(&src_path, source_js).unwrap();
        fs::write(&test_path, test_js).unwrap();

        let report = run_secure_to_json(temp.path(), Language::JavaScript, false);

        // Pull out taint findings — the suppression target.
        let findings = report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .filter(|f| f["category"].as_str() == Some("taint"))
            .collect::<Vec<_>>();

        // Pre-fix: at least one finding from the test file leaked
        // through. Post-fix: every taint finding's `file` MUST be the
        // source file (test/app.test.js suppressed entirely). Assert
        // by looking at unique file paths to be tolerant of canonical
        // engine emitting multiple findings per flow.
        assert!(
            !findings.is_empty(),
            "fixture must produce at least one taint finding (got 0 — fixture is wrong)"
        );
        let unique_files: std::collections::HashSet<&str> = findings
            .iter()
            .filter_map(|f| f["file"].as_str())
            .collect();
        assert_eq!(
            unique_files.len(),
            1,
            "default scan must suppress test-file findings — expected exactly 1 \
             unique file (the source), got {:?}",
            unique_files
        );
        let kept_file = unique_files.iter().next().unwrap();
        assert!(
            kept_file.ends_with("index.js"),
            "kept finding must come from the source file, got {:?}",
            kept_file
        );
        assert!(
            !kept_file.contains("/test/"),
            "kept finding must not come from a test path, got {:?}",
            kept_file
        );
        assert!(
            !findings
                .iter()
                .any(|f| f["file"].as_str().unwrap_or("").contains("/test/")),
            "no finding may originate from a test/ path; got: {:?}",
            findings.iter().map(|f| f["file"].clone()).collect::<Vec<_>>()
        );
    }

    /// SECURE-TEST-FILE-SUPPRESSION-V1: `--include-tests` must restore
    /// the legacy emission set, surfacing findings from BOTH source and
    /// test files. Mirrors `tldr vuln --include-tests` semantics.
    #[test]
    fn test_secure_include_tests_emits_test_findings() {
        let temp = TempDir::new().unwrap();

        let source_js = r#"export function handler(req, res, db) {
    const name = req.query.name;
    res.send("<h1>" + name + "</h1>");
}
"#;
        let test_js = r#"export function handler(req, res, db) {
    const input = req.query.q;
    res.send("<p>" + input + "</p>");
}
"#;

        let src_dir = temp.path().join("src");
        let test_dir = temp.path().join("test");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(src_dir.join("index.js"), source_js).unwrap();
        fs::write(test_dir.join("app.test.js"), test_js).unwrap();

        let report = run_secure_to_json(temp.path(), Language::JavaScript, true);

        let findings = report["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .filter(|f| f["category"].as_str() == Some("taint"))
            .collect::<Vec<_>>();

        // With --include-tests BOTH source and test findings surface.
        // Use unique-file-set semantics for tolerance to canonical-
        // engine multi-emission per flow.
        let unique_files: std::collections::HashSet<&str> = findings
            .iter()
            .filter_map(|f| f["file"].as_str())
            .collect();
        assert_eq!(
            unique_files.len(),
            2,
            "--include-tests must restore test-file emissions — expected 2 \
             unique files (source + test), got {:?}",
            unique_files
        );
        assert!(
            unique_files.iter().any(|f| f.ends_with("index.js")),
            "must include source-file finding: {:?}",
            unique_files
        );
        assert!(
            unique_files.iter().any(|f| f.contains("/test/") && f.ends_with(".test.js")),
            "must include test-file finding when --include-tests: {:?}",
            unique_files
        );
    }

    /// Direct unit test for the in-place helper. Independent of the
    /// `run()` pipeline so a regression in suppression semantics is
    /// caught at the predicate-application boundary.
    #[test]
    fn test_apply_test_file_suppression_filters_js_and_rust_test_paths() {
        let mk = |file: &str| SecureFinding::new("taint", "high", "x").with_location(file, 1);

        let mut findings = vec![
            mk("/abs/src/index.js"),                   // keep
            mk("/abs/test/app.test.js"),               // drop (js test path)
            mk("/abs/lib/foo.spec.ts"),                // drop (js spec suffix)
            mk("/abs/__tests__/x.tsx"),                // drop (js __tests__)
            mk("/abs/crates/foo/tests/it.rs"),         // drop (rust /tests/)
            mk("/abs/crates/foo/src/lib.rs"),          // keep
            mk("/abs/crates/foo/src/foo_test.rs"),     // drop (rust _test.rs)
            // Fixture exemption — must NOT be dropped (vuln_migration_v1
            // suite depends on this exemption being preserved).
            mk("/abs/crates/tldr-cli/tests/fixtures/vuln_migration_v1/javascript/x.js"),
        ];

        apply_test_file_suppression(&mut findings);

        let kept: Vec<_> = findings.iter().map(|f| f.file.clone()).collect();
        // Expected kept: 2 source files (index.js, lib.rs) + 1 fixture =
        // 3. The 5 dropped: app.test.js, foo.spec.ts, x.tsx, it.rs,
        // foo_test.rs.
        assert_eq!(
            kept.len(),
            3,
            "expected 3 kept (2 source + 1 fixture), got {:?}",
            kept
        );
        assert!(kept.iter().any(|f| f.ends_with("/src/index.js")));
        assert!(kept.iter().any(|f| f.ends_with("/src/lib.rs")));
        assert!(kept.iter().any(|f| f.contains("/fixtures/")));
        // Negative assertions — none of the dropped paths should remain.
        assert!(!kept.iter().any(|f| f.ends_with("/app.test.js")));
        assert!(!kept.iter().any(|f| f.ends_with("/foo.spec.ts")));
        assert!(!kept.iter().any(|f| f.ends_with("/__tests__/x.tsx")));
        assert!(!kept.iter().any(|f| f.ends_with("/tests/it.rs")));
        assert!(!kept.iter().any(|f| f.ends_with("/foo_test.rs")));
    }
}
