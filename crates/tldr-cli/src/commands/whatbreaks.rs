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

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, ValueEnum};

use tldr_core::analysis::whatbreaks::{whatbreaks_analysis, TargetType, WhatbreaksOptions};
use tldr_core::Language;

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

        // cl15-polyglot-v1 (v0.5.0 CL-15): when the user pins `--lang` on a
        // polyglot tree, the non-matching languages are dropped from the
        // underlying call-graph/import analysis. Emit a clear stderr WARNING
        // naming them so the restriction is never silent. (Full multi-language
        // merging for whatbreaks is driven by the core
        // `whatbreaks_analysis` language resolution — see deferred note in the
        // CL-15 report.)
        if self.lang.is_some() {
            let resolved = self
                .lang
                .unwrap_or_else(|| Language::from_directory(&self.path).unwrap_or(Language::Python));
            crate::commands::polyglot::warn_if_languages_dropped(&self.path, resolved);
        }

        writer.progress(&format!(
            "Analyzing what breaks if '{}' changes...",
            self.target
        ));

        // Build options
        let options = WhatbreaksOptions {
            depth: self.depth,
            quick: self.quick,
            language: self.lang,
            force_type: self.target_type.map(|t| t.into()),
        };

        // Run analysis
        let report = whatbreaks_analysis(&self.target, &self.path, &options)?;

        // c3-whatbreaks-struct-type-v1 (v0.5.0 AUDIT-FIX, C3 gap-b): the core
        // `detect_target_type` only knows File / Module / Function, so a bare
        // TYPE name (a struct/enum/trait/class/interface) falls through to the
        // Function default — `tldr whatbreaks GlobSet` wrongly reports
        // `target_type=function`. Resolve the true kind from the AST/structure
        // (NOT a textual guess): when the user did not force a type, the core
        // did not already classify it as File/Module, and the project structure
        // shows the target is a TYPE definition (and not also a function/method
        // of the same name), relabel the emitted classification to `type`.
        //
        // The core `TargetType` enum has no `Type` variant and lives outside
        // this command's edit scope, so the relabel is applied at the EMISSION
        // boundary: the JSON value's `target_type`/`detection_reason` fields and
        // the text header are rewritten here. The underlying sub-analyses
        // (importers / references-based callers) still run and remain useful.
        let type_label: Option<String> = if self.target_type.is_none()
            && matches!(report.target_type, TargetType::Function)
        {
            detect_target_type_kind(&self.target, &self.path, self.lang)
        } else {
            None
        };

        let effective_type_str = type_label
            .clone()
            .unwrap_or_else(|| report.target_type.to_string());

        writer.progress(&format!(
            "Target type: {} ({})",
            effective_type_str, report.detection_reason
        ));

        // Output based on format
        if writer.is_text() {
            let mut text = format_whatbreaks_text(&report);
            if let Some(kind) = &type_label {
                text = relabel_whatbreaks_text_header(&text, &self.target, kind);
            }
            writer.write_text(&text)?;
        } else if let Some(kind) = &type_label {
            // Re-serialize so the `target_type` field reflects the AST-resolved
            // kind without mutating the core enum.
            let mut value = serde_json::to_value(&report)
                .map_err(|e| anyhow::anyhow!("serialize whatbreaks report: {e}"))?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "target_type".to_string(),
                    serde_json::Value::String(kind.clone()),
                );
                obj.insert(
                    "detection_reason".to_string(),
                    serde_json::Value::String(format!(
                        "Target '{}' is a {} definition (resolved from AST/structure)",
                        self.target, kind
                    )),
                );
            }
            writer.write(&value)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

/// c3-whatbreaks-struct-type-v1 (v0.5.0 AUDIT-FIX, C3 gap-b): resolve whether
/// the bare `target` names a TYPE (struct / enum / trait / class / interface /
/// union / protocol / typealias / record / object) in the project, using the
/// AST-backed code structure — NOT a textual heuristic.
///
/// Returns the canonical kind string (`"struct"`, `"enum"`, ... or the generic
/// `"type"`) when the target is a type definition AND is not ALSO defined as a
/// function/method of the same name (so a genuine function that merely shares a
/// name with a type is never relabelled). Returns `None` otherwise.
fn detect_target_type_kind(
    target: &str,
    project: &std::path::Path,
    lang: Option<Language>,
) -> Option<String> {
    use tldr_core::types::IgnoreSpec;
    use tldr_core::{get_code_structure, get_polyglot_code_structure};

    // Type kinds emitted by the AST extractors across languages.
    fn is_type_kind(kind: &str) -> bool {
        matches!(
            kind,
            "struct"
                | "enum"
                | "trait"
                | "class"
                | "interface"
                | "union"
                | "protocol"
                | "typealias"
                | "type"
                | "record"
                | "object"
                | "annotation"
        )
    }

    let structure = match lang {
        Some(l) => {
            get_code_structure(project, l, usize::MAX, Some(&IgnoreSpec::default())).ok()?
        }
        None => {
            // Auto-detect: prefer the polyglot structure so a type in ANY
            // detected language is found, mirroring the analysis path.
            match get_polyglot_code_structure(project, usize::MAX, Some(&IgnoreSpec::default())) {
                Ok(s) => s,
                Err(_) => {
                    let l = Language::from_directory(project).unwrap_or(Language::Python);
                    get_code_structure(project, l, usize::MAX, Some(&IgnoreSpec::default())).ok()?
                }
            }
        }
    };

    let mut found_kind: Option<String> = None;
    let mut found_callable = false;
    for file in &structure.files {
        for def in &file.definitions {
            if def.name != target {
                continue;
            }
            if def.kind == "function" || def.kind == "method" {
                found_callable = true;
            } else if is_type_kind(&def.kind) && found_kind.is_none() {
                found_kind = Some(def.kind.clone());
            }
        }
    }

    // Only relabel when the target is a type AND not also a callable of the
    // same name (avoid hiding a real function behind a same-named type).
    match found_kind {
        Some(kind) if !found_callable => Some(kind),
        _ => None,
    }
}

/// Rewrite the `What Breaks: <target> (function)` header line emitted by
/// [`format_whatbreaks_text`] so the parenthesised kind reflects the
/// AST-resolved type kind. Only the header line's first `function` token is
/// rewritten; the rest of the formatted body is preserved verbatim.
fn relabel_whatbreaks_text_header(text: &str, target: &str, kind: &str) -> String {
    // `format_whatbreaks_text` colourises the type word, so the header may be
    // `... (\x1b[33mfunction\x1b[0m)` on a TTY or plain `... (function)` when
    // piped. In BOTH forms the literal word `function` appears exactly once on
    // the header line (the target name is rendered separately), so replacing
    // the first `function` occurrence on that line is robust to ANSI wrapping.
    let _ = target;
    let (header, rest) = match text.split_once('\n') {
        Some((h, r)) => (h, Some(r)),
        None => (text, None),
    };
    let new_header = header.replacen("function", kind, 1);
    match rest {
        Some(r) => format!("{}\n{}", new_header, r),
        None => new_header,
    }
}
