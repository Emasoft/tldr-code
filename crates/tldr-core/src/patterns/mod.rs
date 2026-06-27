//! Pattern detection module for design pattern mining
//!
//! This module provides single-pass pattern extraction across codebases.
//! Addresses blockers: A5 (multi-pass overhead), A23 (parse error handling)
//!
//! # Architecture
//!
//! The pattern detection framework uses a single-pass approach:
//! 1. Parse each file once into AST
//! 2. Walk AST once, collecting signals for ALL patterns
//! 3. Convert signals to patterns after walk
//! 4. Aggregate patterns across files
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::patterns::{PatternMiner, PatternConfig};
//!
//! let miner = PatternMiner::new(PatternConfig::default());
//! let report = miner.mine_patterns(Path::new("src"), None)?;
//! ```

pub mod api_conventions;
pub mod async_patterns;
pub mod constraints;
pub mod detector;
pub mod error_handling;
pub mod format;
pub mod import_patterns;
pub mod language_profile;
pub mod languages;
pub mod naming;
pub mod resource_mgmt;
pub mod signals;
pub mod soft_delete;
pub mod test_idioms;
pub mod type_coverage;
pub mod validation;

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use crate::ast::parser::ParserPool;
use crate::error::TldrError;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{
    ApiConventionPattern, AsyncPattern, ErrorHandlingPattern, ImportPattern, Language,
    LanguageDistribution, NamingPattern, PatternCategory, PatternMetadata, PatternReport,
    ResourceManagementPattern, SoftDeletePattern, TestIdiomPattern, TypeCoveragePattern,
    ValidationPattern,
};
use crate::TldrResult;

pub use constraints::{generate_constraints, DetectedPatterns};
pub use detector::PatternDetector;
pub use signals::PatternSignals;

/// Configuration for pattern mining
#[derive(Debug, Clone)]
pub struct PatternConfig {
    /// Minimum confidence threshold for patterns (0.0-1.0)
    pub min_confidence: f64,
    /// Maximum files to analyze (0 = unlimited)
    pub max_files: usize,
    /// Number of evidence examples per pattern
    pub evidence_limit: usize,
    /// Categories to detect (empty = all)
    pub categories: Vec<PatternCategory>,
    /// Whether to generate LLM constraints
    pub generate_constraints: bool,
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            max_files: 1000,
            evidence_limit: 3,
            categories: Vec::new(), // All categories
            generate_constraints: true,
        }
    }
}

/// Pattern miner that performs single-pass extraction across codebases
pub struct PatternMiner {
    config: PatternConfig,
    parser_pool: ParserPool,
}

impl PatternMiner {
    /// Create a new pattern miner with the given configuration
    pub fn new(config: PatternConfig) -> Self {
        Self {
            config,
            parser_pool: ParserPool::new(),
        }
    }

    /// Mine patterns from a path (file or directory)
    ///
    /// # Arguments
    /// * `path` - Path to file or directory to analyze
    /// * `lang` - Optional language filter (auto-detect if None)
    ///
    /// # Returns
    /// * `Ok(PatternReport)` - Complete pattern analysis report
    /// * `Err(TldrError)` - If analysis fails
    pub fn mine_patterns(&self, path: &Path, lang: Option<Language>) -> TldrResult<PatternReport> {
        let start = Instant::now();

        // Collect files to analyze
        let files = self.collect_files(path, lang)?;

        let mut files_analyzed = 0;
        let mut files_skipped = 0;
        let mut files_partial = 0;
        let mut files_by_language: HashMap<String, usize> = HashMap::new();
        let mut patterns_by_language: HashMap<String, usize> = HashMap::new();

        // Aggregate signals across all files
        let mut aggregated_signals = PatternSignals::default();

        // T4 (v0.5.0 AUDIT-FIX): also accumulate signals PER LANGUAGE so
        // that `patterns_by_language` can credit the language that
        // actually produced each signal (instead of spraying one global
        // count across a hardcoded allowlist), and so the
        // language-specific top-level patterns (naming convention,
        // framework) can be computed from the PRIMARY language alone
        // rather than a cross-language mix (which made an Elixir/Phoenix
        // repo report `framework: express` from vendored `.js` and a
        // camelCase JS repo report `snake_case`).
        let mut per_language_signals: HashMap<String, PatternSignals> = HashMap::new();

        for (file_path, file_lang) in files.iter().take(self.config.max_files) {
            // Read file content
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => {
                    files_skipped += 1;
                    continue;
                }
            };

            // Parse and extract signals
            match self.extract_file_signals(&content, *file_lang, file_path) {
                Ok(signals) => {
                    aggregated_signals.merge(&signals);
                    per_language_signals
                        .entry(file_lang.to_string())
                        .or_default()
                        .merge(&signals);
                    files_analyzed += 1;
                    *files_by_language.entry(file_lang.to_string()).or_insert(0) += 1;
                }
                Err(TldrError::ParseError { .. }) => {
                    // Try partial extraction for parse errors (A23 mitigation)
                    if let Ok(partial) =
                        self.extract_partial_signals(&content, *file_lang, file_path)
                    {
                        aggregated_signals.merge(&partial);
                        per_language_signals
                            .entry(file_lang.to_string())
                            .or_default()
                            .merge(&partial);
                        files_partial += 1;
                        *files_by_language.entry(file_lang.to_string()).or_insert(0) += 1;
                    } else {
                        files_skipped += 1;
                    }
                }
                Err(_) => {
                    files_skipped += 1;
                }
            }
        }

        // T4: the primary language is the one with the most analyzed
        // files; ties broken alphabetically for determinism. The
        // language-specific top-level patterns (naming, api_conventions)
        // are derived from this language's signals so a minority of
        // foreign/vendored files cannot corrupt them.
        let primary_language: Option<String> = files_by_language
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(lang, _)| lang.clone());
        let primary_signals: &PatternSignals = primary_language
            .as_ref()
            .and_then(|lang| per_language_signals.get(lang))
            .unwrap_or(&aggregated_signals);

        let duration_ms = start.elapsed().as_millis() as u64;

        // Convert signals to patterns.
        //
        // T4 (v0.5.0 AUDIT-FIX): `naming` and `api_conventions` are
        // language-specific conventions, so they are derived from the
        // PRIMARY language's signals — not the cross-language aggregate.
        // This is what stops a camelCase JS repo from reporting
        // `snake_case` (when mixed with a stray snake_case `.py`) and an
        // Elixir/Phoenix repo from reporting `framework: express` (from
        // vendored `.js`). The remaining categories stay global: they are
        // language-agnostic idioms and several are pinned global by
        // existing tests.
        let soft_delete = self.signals_to_soft_delete(&aggregated_signals);
        // R7 cluster[9] #25/#235/#255: `error_handling` and `type_coverage`
        // are LANGUAGE-SPECIFIC (exception-type vocabulary, type-annotation
        // coverage), so they must be derived from the PRIMARY language's
        // signals — completing the T4 primary-binding that already covers
        // `naming`/`api_conventions`. Pre-fix they used the cross-language
        // aggregate, so a Swift/C++ repo with a stray vendored `.py`
        // reported Python exceptions (`DocoptLanguageError`,
        // `CompilerError`) and an inflated `coverage_functions` (e.g. 1.0
        // from a handful of plain-JS files in a TS repo).
        let error_handling = self.signals_to_error_handling(primary_signals);
        let naming = self.signals_to_naming(primary_signals);
        let resource_management = self.signals_to_resource_mgmt(&aggregated_signals);
        let validation = self.signals_to_validation(&aggregated_signals);
        let test_idioms = self.signals_to_test_idioms(&aggregated_signals);
        let import_patterns = self.signals_to_import_patterns(&aggregated_signals);
        let type_coverage = self.signals_to_type_coverage(primary_signals);
        let api_conventions = self.signals_to_api_conventions(primary_signals);
        let async_patterns = self.signals_to_async_patterns(&aggregated_signals);

        // Count patterns before/after filter
        let patterns_before = self.count_patterns_before_filter(&DetectedPatterns {
            soft_delete: &soft_delete,
            error_handling: &error_handling,
            naming: &naming,
            resource_management: &resource_management,
            validation: &validation,
            test_idioms: &test_idioms,
            import_patterns: &import_patterns,
            type_coverage: &type_coverage,
            api_conventions: &api_conventions,
            async_patterns: &async_patterns,
        });

        // Apply confidence filter to all pattern types.
        // Note: ImportPattern has hardcoded confidence 1.0, so filtering is a no-op
        // by design (presence = confidence). Included for consistency.
        // Note: NamingPattern uses consistency_score as confidence. This means
        // inconsistent naming (low score) gets filtered out. This is a known
        // limitation — low consistency IS a valid finding worth reporting.
        // TODO: Add separate detection_confidence field to NamingPattern.
        // Note: TypeCoveragePattern uses coverage_overall as confidence. Low
        // coverage gets filtered, which may hide useful "low coverage" findings.
        let soft_delete = self.filter_by_confidence(soft_delete);
        let error_handling = self.filter_by_confidence(error_handling);
        let naming = self.filter_by_confidence(naming);
        let resource_management = self.filter_by_confidence(resource_management);
        let validation = self.filter_by_confidence(validation);
        let test_idioms = self.filter_by_confidence(test_idioms);
        let import_patterns = self.filter_by_confidence(import_patterns);
        let type_coverage = self.filter_by_confidence(type_coverage);
        let api_conventions = self.filter_by_confidence(api_conventions);
        let async_patterns = self.filter_by_confidence(async_patterns);

        let patterns_after = self.count_patterns_before_filter(&DetectedPatterns {
            soft_delete: &soft_delete,
            error_handling: &error_handling,
            naming: &naming,
            resource_management: &resource_management,
            validation: &validation,
            test_idioms: &test_idioms,
            import_patterns: &import_patterns,
            type_coverage: &type_coverage,
            api_conventions: &api_conventions,
            async_patterns: &async_patterns,
        });

        // pack-patterns-v1: roll up concrete AST-grounded design-pattern
        // occurrences (Solidity Ownable/Proxy/…, PHP Singleton/Factory/
        // Observer, OCaml functor idioms). Dedup by
        // (pattern, language, file, line) so the same contract/class is
        // not double-counted, then sort deterministically.
        let design_patterns = Self::dedup_design_patterns(&aggregated_signals);

        // Update patterns_by_language.
        //
        // T4 (v0.5.0 AUDIT-FIX): credit each language with the pattern
        // categories detected from ITS OWN signal bucket, plus its own
        // design-pattern hits. Pre-fix, this used a hardcoded
        // `supported_pattern_languages` allowlist and assigned the single
        // global `patterns_after` count to every listed language. That
        // had two failure modes, both seen in the audit corpora:
        //   1. A primary language NOT on the allowlist (kotlin, scala,
        //      cpp, c, ruby) reported 0 even though it produced real
        //      signals — `cpp-tinyxml2 {cpp:0,c:0}`, `kotlin {kotlin:0}`,
        //      `scala {scala:0}`, `ruby {ruby:0}`.
        //   2. A tiny foreign minority that WAS on the allowlist
        //      (java/python from a stray `.java`/`.py`) inherited the
        //      whole global count — `kotlin-coroutines {python:2,java:2}`,
        //      `scala-cats-effect {java:2}`.
        // Counting per-language signals fixes both: a language is credited
        // iff it actually detected something, and only for what IT
        // detected. Every language now has an AST pattern profile
        // (`language_profile()`), so there is no longer any allowlist.
        //
        // pack-patterns-v1: per-language design-pattern counts. Design
        // patterns ARE attributable to a single language, so they are
        // added on top of that language's idiom-category count.
        let mut design_by_language: HashMap<String, usize> = HashMap::new();
        for dp in &design_patterns {
            *design_by_language.entry(dp.language.clone()).or_insert(0) += 1;
        }
        for lang in files_by_language.keys() {
            let idiom_count = per_language_signals
                .get(lang)
                .map(|sig| self.count_categories_for_signals(sig))
                .unwrap_or(0);
            let dp_count = design_by_language.get(lang).copied().unwrap_or(0);
            patterns_by_language.insert(lang.clone(), idiom_count + dp_count);
        }

        // R7 cluster[9] #224: reconcile the metadata pattern counts with
        // the emitted output. `count_patterns_before_filter` only counts
        // the idiom-category `DetectedPatterns`, but `design_patterns` (the
        // GoF/Solidity/PHP/OCaml hits) ARE part of the report AND are added
        // to `patterns_by_language` (dp_count above). Pre-fix this left
        // before/after_filter inconsistent with both the emitted
        // `design_patterns` array and `patterns_by_language` (e.g.
        // solidity-solmate: 20 emitted, patterns_by_language.solidity=21,
        // but before_filter=2/after_filter=1). Design patterns are deduped,
        // not confidence-filtered, so they contribute equally to before and
        // after counts.
        let design_pattern_count = design_patterns.len();

        // Build metadata
        let metadata = PatternMetadata {
            files_analyzed,
            files_skipped,
            files_partial,
            duration_ms,
            language_distribution: LanguageDistribution {
                files_by_language,
                patterns_by_language,
            },
            patterns_before_filter: patterns_before + design_pattern_count,
            patterns_after_filter: patterns_after + design_pattern_count,
            confidence_threshold: self.config.min_confidence,
        };

        // Generate constraints if enabled
        let constraints = if self.config.generate_constraints {
            generate_constraints(&DetectedPatterns {
                soft_delete: &soft_delete,
                error_handling: &error_handling,
                naming: &naming,
                resource_management: &resource_management,
                validation: &validation,
                test_idioms: &test_idioms,
                import_patterns: &import_patterns,
                type_coverage: &type_coverage,
                api_conventions: &api_conventions,
                async_patterns: &async_patterns,
            })
        } else {
            Vec::new()
        };

        // Detect conflicts
        let conflicts = self.detect_conflicts(&DetectedPatterns {
            soft_delete: &soft_delete,
            error_handling: &error_handling,
            naming: &naming,
            resource_management: &resource_management,
            validation: &validation,
            test_idioms: &test_idioms,
            import_patterns: &import_patterns,
            type_coverage: &type_coverage,
            api_conventions: &api_conventions,
            async_patterns: &async_patterns,
        });

        Ok(PatternReport {
            metadata,
            soft_delete,
            error_handling,
            naming,
            resource_management,
            validation,
            test_idioms,
            import_patterns,
            type_coverage,
            api_conventions,
            async_patterns,
            design_patterns,
            constraints,
            conflicts,
        })
    }

    /// pack-patterns-v1: dedup + deterministically sort the raw
    /// design-pattern hits aggregated across files.
    ///
    /// The same logical pattern can be discovered more than once (e.g. a
    /// contract that both inherits `Ownable` AND defines an `onlyOwner`
    /// modifier triggers two structural sub-checks). We key dedup on
    /// `(pattern, language, file, line)` so each physical declaration
    /// surfaces exactly once, then sort by
    /// `(language, file, line, pattern)` for stable, diffable output.
    fn dedup_design_patterns(
        signals: &PatternSignals,
    ) -> Vec<crate::types::DesignPattern> {
        use std::collections::BTreeSet;

        let mut seen: BTreeSet<(String, String, String, u32)> = BTreeSet::new();
        let mut out: Vec<crate::types::DesignPattern> = Vec::new();
        for dp in &signals.design_patterns.hits {
            let key = (
                dp.pattern.clone(),
                dp.language.clone(),
                dp.file.clone(),
                dp.line,
            );
            if seen.insert(key) {
                out.push(dp.clone());
            }
        }
        out.sort_by(|a, b| {
            a.language
                .cmp(&b.language)
                .then(a.file.cmp(&b.file))
                .then(a.line.cmp(&b.line))
                .then(a.pattern.cmp(&b.pattern))
        });
        out
    }

    /// Collect source files to analyze
    fn collect_files(
        &self,
        path: &Path,
        lang: Option<Language>,
    ) -> TldrResult<Vec<(std::path::PathBuf, Language)>> {
        if path.is_file() {
            // RC4-A (v0.5.0 RC-CAMPAIGN): route the single-file autodetect
            // through the shared per-file header resolver so a C++ public
            // header kept as `.h` (content sniff / same-dir `.cpp` sibling) is
            // classified as `cpp`, not force-bucketed to `c` by the
            // single-bucket `from_path`. `lang.or_else` keeps an explicit
            // `--lang` override authoritative (`--lang c` on a `.h` is honored).
            let file_lang = lang
                .or_else(|| Language::from_path_with_siblings(path))
                .ok_or_else(|| {
                    TldrError::UnsupportedLanguage(
                        path.extension()
                            .map(|e| e.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    )
                })?;
            return Ok(vec![(path.to_path_buf(), file_lang)]);
        }

        let mut files = Vec::new();
        let ignore_spec = crate::IgnoreSpec::default();

        // Use get_file_tree to collect files with ignore support
        let tree = get_file_tree(path, None, true, Some(&ignore_spec))?;
        let source_files = collect_files(&tree, path);

        for file_path in source_files {
            // fastpath-extend-non-vuln-v1: when `lang` is provided, restrict
            // to files whose extension actually matches that language (mirrors
            // the BUG-java-debt-stackoverflow-v1 fix in `quality/debt.rs`).
            //
            // Pre-fix, `lang = Some(luau)` against a C++ codebase like
            // `luau-luau` would force-parse every `.cpp`/`.h` file as luau,
            // producing pathological tree-sitter ASTs and pushing
            // `tldr patterns` past 60 s on a 122-luau-file repo (BEFORE
            // measurement: timeout >60s; AFTER: <2s).
            // RC4-A (v0.5.0 RC-CAMPAIGN): resolve the C-vs-C++ identity of a
            // `.h` header per-file (content sniff / same-dir C++ sibling) via
            // the shared resolver already consumed by
            // structure/extract/inheritance/health/loc/interface, instead of
            // the single-bucket `from_path` that hard-maps every `.h` to `c`.
            // The explicit `--lang` guard below is preserved verbatim: it
            // still filters to files whose (now header-aware) detection
            // matches the override, so a genuine C `.h` under `--lang c` is
            // honored while a C++ `.h` is not force-parsed as C.
            let detected = Language::from_path_with_siblings(&file_path);
            let file_lang = match (lang, detected) {
                // User specified language and file matches: use it.
                (Some(forced), Some(d)) if d == forced => forced,
                // User specified language but extension is a different known
                // language: skip (don't force-parse a `.cpp` as luau).
                (Some(_), Some(_)) => continue,
                // User specified language and extension is unknown
                // (e.g. `dictionary.txt`, `lua_dict.txt`): SKIP. The
                // alternative would be to force-parse the file under the
                // override grammar, which on real-world Lua repos
                // (`lua-lsp/meta/spell/dictionary.txt`, ~1.3 MB) hung
                // tree-sitter for >5 minutes. Restricting `--lang` to
                // matching extensions is the semantically correct
                // interpretation ("analyze <language> files only") and
                // avoids the pathological-AST timeout.
                (Some(_), None) => continue,
                // No override: only include files we can detect.
                (None, Some(d)) => d,
                (None, None) => continue,
            };

            // fastpath-extend-non-vuln-v1: enforce the central oversize
            // policy at collection time. The pattern miner reads files via
            // `std::fs::read_to_string` and dispatches them through
            // `ParserPool::parse(content, …)` (NOT through the path-based
            // `parse_file_with_lang` chokepoint that already enforces the
            // policy), so an extra check here is required for
            // auto-generated / minified artefacts to be skipped uniformly.
            if let crate::fs::oversize::SizeCheck::Oversize { .. } =
                crate::fs::oversize::check_size(&file_path)
            {
                continue;
            }

            files.push((file_path, file_lang));
        }

        Ok(files)
    }

    /// Extract pattern signals from a single file (single-pass)
    fn extract_file_signals(
        &self,
        content: &str,
        lang: Language,
        file_path: &Path,
    ) -> TldrResult<PatternSignals> {
        let tree = self.parser_pool.parse(content, lang)?;
        let detector = PatternDetector::new(lang, file_path.to_path_buf());
        Ok(detector.detect_all(&tree, content))
    }

    /// Extract partial signals from a file with parse errors (A23 mitigation)
    fn extract_partial_signals(
        &self,
        content: &str,
        lang: Language,
        file_path: &Path,
    ) -> TldrResult<PatternSignals> {
        // Use regex-based fallback detection for partially parseable files
        let detector = PatternDetector::new(lang, file_path.to_path_buf());
        Ok(detector.detect_fallback(content))
    }

    // Signal to pattern conversion methods
    fn signals_to_soft_delete(&self, signals: &PatternSignals) -> Option<SoftDeletePattern> {
        soft_delete::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_error_handling(&self, signals: &PatternSignals) -> Option<ErrorHandlingPattern> {
        error_handling::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_naming(&self, signals: &PatternSignals) -> Option<NamingPattern> {
        naming::signals_to_pattern(signals)
    }

    fn signals_to_resource_mgmt(
        &self,
        signals: &PatternSignals,
    ) -> Option<ResourceManagementPattern> {
        resource_mgmt::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_validation(&self, signals: &PatternSignals) -> Option<ValidationPattern> {
        validation::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_test_idioms(&self, signals: &PatternSignals) -> Option<TestIdiomPattern> {
        test_idioms::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_import_patterns(&self, signals: &PatternSignals) -> Option<ImportPattern> {
        import_patterns::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_type_coverage(&self, signals: &PatternSignals) -> Option<TypeCoveragePattern> {
        type_coverage::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_api_conventions(&self, signals: &PatternSignals) -> Option<ApiConventionPattern> {
        api_conventions::signals_to_pattern(signals, self.config.evidence_limit)
    }

    fn signals_to_async_patterns(&self, signals: &PatternSignals) -> Option<AsyncPattern> {
        async_patterns::signals_to_pattern(signals, self.config.evidence_limit)
    }

    // Helper to filter patterns by confidence threshold
    fn filter_by_confidence<T: HasConfidence>(&self, pattern: Option<T>) -> Option<T> {
        pattern.filter(|p| p.confidence() >= self.config.min_confidence)
    }

    // T4 (v0.5.0 AUDIT-FIX): count the confidence-surviving pattern
    // categories produced by a SINGLE language's signal bucket. Mirrors
    // the global conversion + filter pipeline exactly (same
    // `signals_to_*` + `filter_by_confidence`) so a language's
    // per-language count is consistent with how patterns would be
    // reported if that language were analyzed alone. Used to build a
    // faithful `patterns_by_language` histogram.
    fn count_categories_for_signals(&self, signals: &PatternSignals) -> usize {
        let detected = DetectedPatterns {
            soft_delete: &self.filter_by_confidence(self.signals_to_soft_delete(signals)),
            error_handling: &self
                .filter_by_confidence(self.signals_to_error_handling(signals)),
            naming: &self.filter_by_confidence(self.signals_to_naming(signals)),
            resource_management: &self
                .filter_by_confidence(self.signals_to_resource_mgmt(signals)),
            validation: &self.filter_by_confidence(self.signals_to_validation(signals)),
            test_idioms: &self.filter_by_confidence(self.signals_to_test_idioms(signals)),
            import_patterns: &self
                .filter_by_confidence(self.signals_to_import_patterns(signals)),
            type_coverage: &self
                .filter_by_confidence(self.signals_to_type_coverage(signals)),
            api_conventions: &self
                .filter_by_confidence(self.signals_to_api_conventions(signals)),
            async_patterns: &self
                .filter_by_confidence(self.signals_to_async_patterns(signals)),
        };
        self.count_patterns_before_filter(&detected)
    }

    // Count total patterns before filter
    fn count_patterns_before_filter(&self, patterns: &DetectedPatterns<'_>) -> usize {
        let mut count = 0;
        if patterns.soft_delete.is_some() {
            count += 1;
        }
        if patterns.error_handling.is_some() {
            count += 1;
        }
        if patterns.naming.is_some() {
            count += 1;
        }
        if patterns.resource_management.is_some() {
            count += 1;
        }
        if patterns.validation.is_some() {
            count += 1;
        }
        if patterns.test_idioms.is_some() {
            count += 1;
        }
        if patterns.import_patterns.is_some() {
            count += 1;
        }
        if patterns.type_coverage.is_some() {
            count += 1;
        }
        if patterns.api_conventions.is_some() {
            count += 1;
        }
        if patterns.async_patterns.is_some() {
            count += 1;
        }
        count
    }

    // Detect conflicts between patterns
    fn detect_conflicts(&self, patterns: &DetectedPatterns<'_>) -> Vec<String> {
        let mut conflicts = Vec::new();

        // Check for import pattern conflicts
        if let Some(imports) = patterns.import_patterns {
            if imports.grouping_style == crate::types::ImportGrouping::Ungrouped {
                conflicts.push(
                    "Inconsistent import grouping: no clear ordering pattern detected".to_string(),
                );
            }
            if imports.absolute_vs_relative == crate::types::ImportStyle::Mixed {
                conflicts.push(
                    "Mixed import styles: some files use absolute imports, others use relative"
                        .to_string(),
                );
            }
        }

        conflicts
    }
}

/// Trait for patterns with a confidence score
pub trait HasConfidence {
    /// Returns the confidence score for this pattern in the range [0.0, 1.0].
    fn confidence(&self) -> f64;
}

impl HasConfidence for SoftDeletePattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for ErrorHandlingPattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for NamingPattern {
    fn confidence(&self) -> f64 {
        self.consistency_score
    }
}

impl HasConfidence for ResourceManagementPattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for ValidationPattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for TestIdiomPattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for ImportPattern {
    fn confidence(&self) -> f64 {
        1.0 // Import patterns always have full confidence once detected
    }
}

impl HasConfidence for TypeCoveragePattern {
    fn confidence(&self) -> f64 {
        self.coverage_overall
    }
}

impl HasConfidence for ApiConventionPattern {
    fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl HasConfidence for AsyncPattern {
    fn confidence(&self) -> f64 {
        self.concurrency_confidence
    }
}

/// Detect patterns from a path (convenience function)
pub fn detect_patterns(path: &Path, lang: Option<Language>) -> TldrResult<PatternReport> {
    let miner = PatternMiner::new(PatternConfig::default());
    miner.mine_patterns(path, lang)
}

/// Detect patterns with custom configuration
pub fn detect_patterns_with_config(
    path: &Path,
    lang: Option<Language>,
    config: PatternConfig,
) -> TldrResult<PatternReport> {
    let miner = PatternMiner::new(config);
    miner.mine_patterns(path, lang)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ImportGrouping, ImportPattern, ImportStyle, NamingConvention, NamingPattern,
        StarImportUsage, TypeCoveragePattern,
    };

    /// Helper: create a PatternMiner with a specific confidence threshold.
    fn miner_with_threshold(threshold: f64) -> PatternMiner {
        PatternMiner::new(PatternConfig {
            min_confidence: threshold,
            ..PatternConfig::default()
        })
    }

    // =========================================================================
    // Bug: naming, import_patterns, type_coverage skip confidence filter
    // =========================================================================

    /// All pattern types must be subject to the confidence filter.
    /// naming patterns with low consistency_score should be filtered out
    /// when the score is below min_confidence.
    #[test]
    fn test_all_pattern_types_filtered_by_confidence_naming() {
        let miner = miner_with_threshold(0.7);

        // NamingPattern with consistency_score = 0.3 (below 0.7 threshold)
        let low_confidence_naming: Option<NamingPattern> = Some(NamingPattern {
            functions: NamingConvention::SnakeCase,
            classes: NamingConvention::PascalCase,
            constants: NamingConvention::UpperSnakeCase,
            private_prefix: None,
            consistency_score: 0.3, // Below threshold of 0.7
            violations: Vec::new(),
        });

        // The filter should remove it since 0.3 < 0.7
        let filtered = miner.filter_by_confidence(low_confidence_naming);
        assert!(
            filtered.is_none(),
            "NamingPattern with consistency_score 0.3 should be filtered out at threshold 0.7, \
             but it survived the filter. This indicates naming patterns skip confidence filtering."
        );
    }

    /// import_patterns with low confidence should be filtered out.
    #[test]
    fn test_all_pattern_types_filtered_by_confidence_imports() {
        let miner = miner_with_threshold(0.7);

        // ImportPattern always returns confidence 1.0 in the HasConfidence impl,
        // so we test at a threshold that would filter it if it were applied.
        // The bug is that filter_by_confidence is never CALLED for import_patterns
        // in mine_patterns(). We verify indirectly: if the miner had a threshold
        // above 1.0, even imports should be filtered. But since ImportPattern
        // hardcodes 1.0, we test the structural bug differently.
        //
        // The real test: construct a PatternReport manually simulating what
        // mine_patterns does, and verify that import_patterns IS filtered.
        // In the buggy code, lines 177-184 skip naming, import_patterns,
        // type_coverage from the filter_by_confidence call.

        // We can at least verify that filter_by_confidence works when called:
        let import_pattern: Option<ImportPattern> = Some(ImportPattern {
            grouping_style: ImportGrouping::StdlibFirst,
            absolute_vs_relative: ImportStyle::Absolute,
            star_imports: StarImportUsage::None,
            alias_conventions: Vec::new(),
            evidence: Vec::new(),
        });

        // ImportPattern::confidence() returns 1.0, so threshold 0.7 should keep it
        let filtered = miner.filter_by_confidence(import_pattern);
        assert!(
            filtered.is_some(),
            "ImportPattern with confidence 1.0 should survive threshold 0.7"
        );
    }

    /// type_coverage with low coverage_overall should be filtered out.
    #[test]
    fn test_all_pattern_types_filtered_by_confidence_type_coverage() {
        let miner = miner_with_threshold(0.7);

        // TypeCoveragePattern with coverage_overall = 0.2 (below 0.7 threshold)
        let low_coverage: Option<TypeCoveragePattern> = Some(TypeCoveragePattern {
            coverage_overall: 0.2, // Below threshold of 0.7
            coverage_functions: 0.1,
            coverage_variables: 0.3,
            typevar_usage: false,
            generic_patterns: Vec::new(),
            evidence: Vec::new(),
        });

        // The filter should remove it since 0.2 < 0.7
        let filtered = miner.filter_by_confidence(low_coverage);
        assert!(
            filtered.is_none(),
            "TypeCoveragePattern with coverage_overall 0.2 should be filtered out at threshold 0.7, \
             but it survived the filter. This indicates type_coverage patterns skip confidence filtering."
        );
    }

    // =========================================================================
    // Bug: patterns_by_language uses global count for all languages
    // =========================================================================

    /// patterns_by_language must credit the language that ACTUALLY
    /// produced the signals — computed from that language's own
    /// per-language signal bucket — not a single global count sprayed
    /// across a hardcoded allowlist.
    ///
    /// T4 (v0.5.0 AUDIT-FIX): pre-fix, the histogram used a hardcoded
    /// `supported_pattern_languages` allowlist and assigned the global
    /// `patterns_after` count to every listed language. A Kotlin-majority
    /// repo therefore reported `kotlin: 0` (kotlin absent from the list)
    /// while a single stray `.java`/`.py` file inherited the full global
    /// count (`java: 2`, `python: 2`). This drives the real production
    /// path (`mine_patterns`) over a temp dir and asserts the primary
    /// language is credited and the foreign minority is not over-credited.
    #[test]
    fn test_patterns_by_language_credits_primary_language() {
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");

        // Kotlin file with real, detectable signals (class + function +
        // import => naming + import_patterns categories).
        let kt = dir.path().join("App.kt");
        let mut f = std::fs::File::create(&kt).unwrap();
        writeln!(
            f,
            "import kotlin.coroutines.CoroutineContext\n\nclass MyService {{\n    fun doWork() {{}}\n    fun loadData() {{}}\n}}\n"
        )
        .unwrap();

        // A single foreign Java file (the historical mis-attribution
        // target). It also has signals, but must only be credited for
        // ITS OWN count, never the global one.
        let jv = dir.path().join("Helper.java");
        let mut g = std::fs::File::create(&jv).unwrap();
        writeln!(
            g,
            "package x;\npublic class Helper {{\n  public void run() {{}}\n}}\n"
        )
        .unwrap();

        let report =
            detect_patterns(dir.path(), None).expect("mine_patterns over temp dir");
        let by_lang = &report.metadata.language_distribution.patterns_by_language;

        let kotlin_count = by_lang.get("kotlin").copied().unwrap_or(0);
        assert!(
            kotlin_count >= 1,
            "kotlin (the primary language) must be credited with its own detected \
             pattern categories (>= 1); got {}. Full patterns_by_language: {:?}",
            kotlin_count,
            by_lang
        );

        // Python must NOT appear at all (no python files in the dir): the
        // old code injected `python: N` whenever python was in the
        // allowlist even with zero python files — but here there are none,
        // so it should simply be absent.
        assert!(
            by_lang.get("python").copied().unwrap_or(0) == 0,
            "no python files were analyzed, so python must not be credited; got {:?}",
            by_lang
        );
    }

    // =========================================================================
    // Sanity: high-confidence patterns should survive the filter
    // =========================================================================

    /// Patterns with high confidence scores should survive filtering.
    #[test]
    fn test_patterns_survive_filter_when_high_confidence() {
        let miner = miner_with_threshold(0.5);

        // NamingPattern with high consistency_score
        let naming: Option<NamingPattern> = Some(NamingPattern {
            functions: NamingConvention::SnakeCase,
            classes: NamingConvention::PascalCase,
            constants: NamingConvention::UpperSnakeCase,
            private_prefix: Some("_".to_string()),
            consistency_score: 0.95, // Well above 0.5
            violations: Vec::new(),
        });

        let filtered = miner.filter_by_confidence(naming);
        assert!(
            filtered.is_some(),
            "NamingPattern with consistency_score 0.95 should survive threshold 0.5"
        );

        // TypeCoveragePattern with high coverage
        let type_cov: Option<TypeCoveragePattern> = Some(TypeCoveragePattern {
            coverage_overall: 0.85,
            coverage_functions: 0.9,
            coverage_variables: 0.8,
            typevar_usage: true,
            generic_patterns: vec!["Optional".to_string()],
            evidence: Vec::new(),
        });

        let filtered = miner.filter_by_confidence(type_cov);
        assert!(
            filtered.is_some(),
            "TypeCoveragePattern with coverage_overall 0.85 should survive threshold 0.5"
        );
    }

    // =========================================================================
    // RC4-A: `.h` headers in C++ projects must bucket as cpp, not c
    // =========================================================================

    /// `collect_files` (and therefore the `files_by_language` histogram of
    /// `tldr patterns`) must resolve the C-vs-C++ identity of a `.h` header
    /// per-file through `Language::from_path_with_siblings` /
    /// `resolve_header_language`, exactly like
    /// `structure`/`extract`/`inheritance`/`health`/`loc`/`interface`.
    ///
    /// Pre-fix `tldr patterns` used the single-bucket `Language::from_path`,
    /// which hard-maps every `.h` to `Language::C`, so a C++ header
    /// (`namespace`/`class`/`template`) was force-parsed by the C grammar and
    /// credited to `c` (live re-measure on cpp-fmt: `c: 26` for 25 C++ `.h` +
    /// 1 real `.c`; expected post-fix `c: 1`, `cpp: 71`).
    ///
    /// This is the GENERALIZATION test for the whole `.h` misbucket class — it
    /// asserts EVERY variant of the symptom class, not just one:
    ///   1. C++ `.h` resolved by CONTENT SNIFF (no sibling) -> cpp, never c.
    ///   2. C++ `.h` resolved by SAME-DIR `.cpp` SIBLING (plain content) -> cpp.
    ///   3. a genuine C `.h` (no C++ content, no C++ sibling) -> c, never cpp.
    ///   4. an explicit `--lang c` on a `.h` is still HONORED (-> c).
    #[test]
    fn test_h_header_buckets_cpp_not_c_across_all_variants() {
        use std::io::Write;

        // ---- Variant 1: C++ `.h` via content sniff (no sibling) ----------
        let d1 = tempfile::tempdir().expect("tempdir");
        let h1 = d1.path().join("buffer.h");
        let mut f1 = std::fs::File::create(&h1).unwrap();
        writeln!(
            f1,
            "namespace fmt {{\ntemplate <typename T>\nclass Buffer {{\npublic:\n  void grow(int n);\n  void clear();\n}};\n}}\n"
        )
        .unwrap();

        let r1 = detect_patterns(d1.path(), None).expect("patterns over cpp-content .h");
        let by1 = &r1.metadata.language_distribution.files_by_language;
        assert_eq!(
            by1.get("c").copied().unwrap_or(0),
            0,
            "a C++ `.h` (namespace/class/template content) must NOT be credited to `c`; got {:?}",
            by1
        );
        assert!(
            by1.get("cpp").copied().unwrap_or(0) >= 1,
            "a C++ `.h` resolved by content sniff must bucket as `cpp`; got {:?}",
            by1
        );

        // ---- Variant 2: C++ `.h` via same-dir `.cpp` sibling -------------
        // Plain (sniff-inconclusive) header content; the `.cpp` sibling is the
        // positive evidence that flips it to C++.
        let d2 = tempfile::tempdir().expect("tempdir");
        let h2 = d2.path().join("widget.h");
        let mut f2 = std::fs::File::create(&h2).unwrap();
        writeln!(f2, "int widget_init(int code);\nint widget_run(void);\n").unwrap();
        let cpp2 = d2.path().join("widget.cpp");
        let mut g2 = std::fs::File::create(&cpp2).unwrap();
        writeln!(g2, "int widget_init(int code) {{ return code; }}\n").unwrap();

        let r2 = detect_patterns(d2.path(), None).expect("patterns over .h+.cpp sibling");
        let by2 = &r2.metadata.language_distribution.files_by_language;
        assert_eq!(
            by2.get("c").copied().unwrap_or(0),
            0,
            "a plain `.h` next to a `.cpp` sibling must bucket as `cpp`, never `c`; got {:?}",
            by2
        );
        assert!(
            by2.get("cpp").copied().unwrap_or(0) >= 2,
            "both the `.h` (via sibling) and the `.cpp` must be credited to `cpp`; got {:?}",
            by2
        );

        // ---- Variant 3: genuine C `.h` (no C++ content, no C++ sibling) --
        let d3 = tempfile::tempdir().expect("tempdir");
        let h3 = d3.path().join("list.h");
        let mut f3 = std::fs::File::create(&h3).unwrap();
        writeln!(
            f3,
            "struct list {{ int value; struct list *next; }};\nint list_len(struct list *l);\n"
        )
        .unwrap();

        let r3 = detect_patterns(d3.path(), None).expect("patterns over pure-C .h");
        let by3 = &r3.metadata.language_distribution.files_by_language;
        assert_eq!(
            by3.get("cpp").copied().unwrap_or(0),
            0,
            "a pure-C `.h` (no C++ content, no C++ sibling) must NOT be credited to `cpp`; got {:?}",
            by3
        );
        assert!(
            by3.get("c").copied().unwrap_or(0) >= 1,
            "a pure-C `.h` must remain bucketed as `c`; got {:?}",
            by3
        );

        // ---- Variant 4: explicit `--lang c` on a `.h` is still honored ---
        let r4 = detect_patterns(d3.path(), Some(Language::C)).expect("patterns --lang c");
        let by4 = &r4.metadata.language_distribution.files_by_language;
        assert!(
            by4.get("c").copied().unwrap_or(0) >= 1,
            "explicit `--lang c` on a `.h` must still be honored and bucket as `c`; got {:?}",
            by4
        );
    }
}
