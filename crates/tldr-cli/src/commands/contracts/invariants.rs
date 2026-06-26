//! Invariants command - Daikon-lite invariant inference from test traces.
//!
//! Infers likely invariants from analyzing test files for function call patterns.
//! This is a simplified static analysis approach that extracts invariants from
//! observed argument patterns in test assertions.
//!
//! # TIGER/ELEPHANT Mitigations Addressed
//! - TIGER-06: Test path sanitization -> validate_file_path checks
//! - E08: Parse test files before analysis -> tree-sitter validation
//! - E12: Consistent ordering -> sort test functions alphabetically
//!
//! # Invariant Types
//!
//! | Kind | Detection Rule | Example |
//! |------|---------------|---------|
//! | Type | All values same type | `x: int` |
//! | NonNull | No None values observed | `x is not None` |
//! | NonNegative | All numeric values >= 0 | `x >= 0` |
//! | Positive | All numeric values > 0 | `x > 0` |
//! | Range | Track min/max observed | `0 <= x <= 100` |
//! | Relation | p1 < p2 for all observations | `start < end` |
//!
//! # Simplified Implementation Note
//!
//! This implementation uses static analysis of test files to infer invariants,
//! rather than actual runtime tracing. It parses function calls from test
//! assertions and infers invariants from the argument patterns observed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use tldr_core::walker::walk_project;
use tldr_core::Language;
use tree_sitter::{Node, Parser};
use tree_sitter_python::LANGUAGE as PYTHON_LANGUAGE;

use crate::output::{OutputFormat, OutputWriter};

use super::error::{ContractsError, ContractsResult};
use super::types::{
    Confidence, FunctionInvariants, Invariant, InvariantKind, InvariantsReport, InvariantsSummary,
    OutputFormat as ContractsOutputFormat,
};
use super::validation::read_file_safe;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum depth for AST traversal (TIGER-08 mitigation)
const MAX_AST_DEPTH: usize = 100;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Infer invariants from test execution traces (Daikon-lite).
///
/// Analyzes test files to extract function call patterns and infers
/// likely invariants such as type constraints, numeric bounds, and
/// ordering relations between parameters.
///
/// # Example
///
/// ```bash
/// tldr invariants src/module.py --from-tests tests/
/// tldr invariants src/math.py --from-tests tests/test_math.py --min-obs 5
/// tldr invariants src/api.py --from-tests tests/ --function process_data
/// ```
#[derive(Debug, Args)]
pub struct InvariantsArgs {
    /// Source file containing functions to analyze
    pub file: PathBuf,

    /// Test file or directory for tracing
    #[arg(long = "from-tests", short = 't')]
    pub from_tests: PathBuf,

    /// Output format (json or text). Prefer global --format/-f flag.
    #[arg(
        long = "output-format",
        short = 'o',
        hide = true,
        default_value = "json"
    )]
    pub output_format: ContractsOutputFormat,

    /// Filter to specific function
    #[arg(long)]
    pub function: Option<String>,

    /// Minimum observations required to report an invariant
    #[arg(long, default_value = "1")]
    pub min_obs: u32,

    /// Language override (auto-detected if not specified).
    ///
    /// MUST stay typed as `Option<Language>` to match the global
    /// `--lang` / `-l` flag declared on `Cli` in `main.rs`. clap stores the
    /// value once under the long-name key; if the local arg's type diverges
    /// from the global type, accessing `lang` triggers a type-id downcast
    /// panic in `clap_builder::parser::error::Error`. (P11.BUG-AGG-2)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,
}

impl InvariantsArgs {
    /// Run the invariants command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate source file exists
        if !self.file.exists() {
            return Err(ContractsError::FileNotFound {
                path: self.file.clone(),
            }
            .into());
        }

        // Validate test path exists
        if !self.from_tests.exists() {
            return Err(ContractsError::TestPathNotFound {
                path: self.from_tests.clone(),
            }
            .into());
        }

        writer.progress(&format!(
            "Inferring invariants for {} from {}...",
            self.file.display(),
            self.from_tests.display()
        ));

        // Run inference
        let report = run_invariants(
            &self.file,
            &self.from_tests,
            self.function.as_deref(),
            self.min_obs,
        )?;

        // Output based on format
        let use_text = matches!(self.output_format, ContractsOutputFormat::Text)
            || matches!(format, OutputFormat::Text);

        if use_text {
            let text = format_invariants_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        Ok(())
    }
}

// =============================================================================
// Core Analysis Functions
// =============================================================================

/// Observation of a function call from a test
#[derive(Debug, Clone)]
struct Observation {
    /// Function name being called
    function_name: String,
    /// Argument values as JSON
    args: Vec<ObservedValue>,
    /// Expected return value (if available from assertion)
    return_value: Option<ObservedValue>,
}

/// An observed value from a test
#[derive(Debug, Clone)]
enum ObservedValue {
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
    None,
    List(Vec<ObservedValue>),
    Other(String), // Unparseable value represented as string
}

impl ObservedValue {
    fn type_name(&self) -> &'static str {
        match self {
            ObservedValue::Int(_) => "int",
            ObservedValue::Float(_) => "float",
            ObservedValue::String(s) => {
                let _ = s.len();
                "str"
            }
            ObservedValue::Bool(b) => {
                let _ = *b;
                "bool"
            }
            ObservedValue::None => "NoneType",
            ObservedValue::List(items) => {
                let _ = items.len();
                "list"
            }
            ObservedValue::Other(text) => {
                let _ = text.len();
                "unknown"
            }
        }
    }

    fn is_none(&self) -> bool {
        matches!(self, ObservedValue::None)
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            ObservedValue::Int(i) => Some(*i as f64),
            ObservedValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Language-aware display type name for a `Type` invariant.
    ///
    /// T2 (v0.5.0 AUDIT-FIX): `type_name()` returns the *category* key used for
    /// "all values share a type" comparison (and stays Python-flavoured because
    /// the comparison is internal). For the user-facing invariant EXPRESSION we
    /// render the type in the SOURCE language's own vocabulary, so a Kotlin /
    /// Java / TypeScript / OCaml invariant never shows Python's `str` / `int` /
    /// `NoneType`.
    ///
    /// Returns `None` when the observed value has no reportable type:
    ///   * `Other` (unparseable) — for ALL languages (matches the existing
    ///     `first_type != "unknown"` guard).
    ///   * `None` (the null sentinel) — declined for every NON-Python language
    ///     (an all-`None` column is a nullability fact, not a type fact, and
    ///     Python's `NoneType` spelling is exactly what we must not leak). For
    ///     Python we PRESERVE the historical `result: NoneType` emission
    ///     byte-for-byte.
    fn lang_type_name(&self, lang: Language) -> Option<&'static str> {
        // The `Other` element is "unparseable" — never report a type for it
        // (matches the existing `first_type != "unknown"` guard).
        if matches!(self, ObservedValue::Other(_)) {
            return None;
        }
        // The null sentinel: keep Python's historical `NoneType`; decline for
        // every other language so no Python idiom leaks.
        if matches!(self, ObservedValue::None) {
            return if matches!(lang, Language::Python) {
                Some("NoneType")
            } else {
                None
            };
        }
        Some(lang_type_word(lang, self))
    }
}

/// T2 (v0.5.0 AUDIT-FIX): map a concrete `ObservedValue` to the SOURCE
/// language's spelling of its type. Python is preserved EXACTLY
/// (`int`/`float`/`str`/`bool`/`list`) so the existing Python invariant tests
/// and output stay byte-identical. Every other language uses its own canonical
/// type names rather than leaking Python idioms.
fn lang_type_word(lang: Language, v: &ObservedValue) -> &'static str {
    use ObservedValue as V;
    match lang {
        // Preserve Python's exact vocabulary.
        Language::Python => match v {
            V::Int(_) => "int",
            V::Float(_) => "float",
            V::String(_) => "str",
            V::Bool(_) => "bool",
            V::List(_) => "list",
            V::None | V::Other(_) => "unknown",
        },
        // C-family / JVM: Int/Double/String/Boolean/List.
        Language::Kotlin => match v {
            V::Int(_) => "Int",
            V::Float(_) => "Double",
            V::String(_) => "String",
            V::Bool(_) => "Boolean",
            V::List(_) => "List",
            V::None | V::Other(_) => "Any",
        },
        Language::Java => match v {
            V::Int(_) => "int",
            V::Float(_) => "double",
            V::String(_) => "String",
            V::Bool(_) => "boolean",
            V::List(_) => "List",
            V::None | V::Other(_) => "Object",
        },
        Language::Scala => match v {
            V::Int(_) => "Int",
            V::Float(_) => "Double",
            V::String(_) => "String",
            V::Bool(_) => "Boolean",
            V::List(_) => "List",
            V::None | V::Other(_) => "Any",
        },
        Language::CSharp => match v {
            V::Int(_) => "int",
            V::Float(_) => "double",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "List",
            V::None | V::Other(_) => "object",
        },
        Language::Swift => match v {
            V::Int(_) => "Int",
            V::Float(_) => "Double",
            V::String(_) => "String",
            V::Bool(_) => "Bool",
            V::List(_) => "Array",
            V::None | V::Other(_) => "Any",
        },
        // TypeScript / JavaScript: number/string/boolean (TS structural names).
        Language::TypeScript | Language::JavaScript => match v {
            V::Int(_) | V::Float(_) => "number",
            V::String(_) => "string",
            V::Bool(_) => "boolean",
            V::List(_) => "Array",
            V::None | V::Other(_) => "unknown",
        },
        // Go: int/float64/string/bool/slice.
        Language::Go => match v {
            V::Int(_) => "int",
            V::Float(_) => "float64",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "slice",
            V::None | V::Other(_) => "any",
        },
        // Rust: i64/f64/&str/bool/Vec.
        Language::Rust => match v {
            V::Int(_) => "i64",
            V::Float(_) => "f64",
            V::String(_) => "&str",
            V::Bool(_) => "bool",
            V::List(_) => "Vec",
            V::None | V::Other(_) => "_",
        },
        // OCaml: int/float/string/bool/list.
        Language::Ocaml => match v {
            V::Int(_) => "int",
            V::Float(_) => "float",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "list",
            V::None | V::Other(_) => "_",
        },
        // Ruby: Integer/Float/String/bool/Array.
        Language::Ruby => match v {
            V::Int(_) => "Integer",
            V::Float(_) => "Float",
            V::String(_) => "String",
            V::Bool(_) => "Boolean",
            V::List(_) => "Array",
            V::None | V::Other(_) => "Object",
        },
        // PHP: int/float/string/bool/array.
        Language::Php => match v {
            V::Int(_) => "int",
            V::Float(_) => "float",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "array",
            V::None | V::Other(_) => "mixed",
        },
        // Lua / Luau: number/string/boolean/table.
        Language::Lua | Language::Luau => match v {
            V::Int(_) | V::Float(_) => "number",
            V::String(_) => "string",
            V::Bool(_) => "boolean",
            V::List(_) => "table",
            V::None | V::Other(_) => "any",
        },
        // Elixir: integer/float/binary/boolean/list.
        Language::Elixir => match v {
            V::Int(_) => "integer",
            V::Float(_) => "float",
            V::String(_) => "binary",
            V::Bool(_) => "boolean",
            V::List(_) => "list",
            V::None | V::Other(_) => "any",
        },
        // Solidity: uint256/string/bool/array (no float type in Solidity).
        Language::Solidity => match v {
            V::Int(_) => "uint256",
            V::Float(_) => "uint256",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "array",
            V::None | V::Other(_) => "bytes",
        },
        // C / C++: int/double/string/bool (best-effort; std types).
        Language::C | Language::Cpp => match v {
            V::Int(_) => "int",
            V::Float(_) => "double",
            V::String(_) => "string",
            V::Bool(_) => "bool",
            V::List(_) => "vector",
            V::None | V::Other(_) => "auto",
        },
    }
}

/// T2 (v0.5.0 AUDIT-FIX): the SOURCE language's "this value is present / not
/// null" expression for a NonNull invariant. Python keeps `x is not None`
/// EXACTLY (regression-preserving). Null-bearing languages use `x != null`;
/// Option/Maybe languages (Rust / OCaml / Swift) express presence in their own
/// idiom; languages where a recorded literal can never be a null sentinel
/// still report presence in their own words. Returns `Some(expression)` for
/// every language — the NonNull FACT is language-neutral, only its SPELLING
/// differs.
fn non_null_expression(lang: Language, variable: &str) -> String {
    match lang {
        Language::Python => format!("{variable} is not None"),
        // `null`-bearing languages.
        Language::Java
        | Language::Kotlin
        | Language::Scala
        | Language::CSharp
        | Language::TypeScript
        | Language::JavaScript
        | Language::Lua
        | Language::Luau
        | Language::Php
        | Language::C
        | Language::Cpp
        | Language::Go
        | Language::Solidity => format!("{variable} != null"),
        // Option / Maybe languages: presence is "is Some" / "is not None"
        // expressed structurally. Swift uses `!= nil`.
        Language::Swift => format!("{variable} != nil"),
        Language::Rust | Language::Ocaml => format!("{variable} is Some"),
        // Elixir: absence is `nil`.
        Language::Elixir => format!("{variable} != nil"),
        // Ruby: absence is `nil`.
        Language::Ruby => format!("{variable} != nil"),
    }
}

/// Run invariant inference on source file using test observations.
///
/// Note: `_source_path` is currently unused in this simplified static analysis
/// implementation. It is kept in the API for future runtime tracing support.
pub fn run_invariants(
    source_path: &Path,
    test_path: &Path,
    function_filter: Option<&str>,
    min_obs: u32,
) -> ContractsResult<InvariantsReport> {
    // T2 (v0.5.0 AUDIT-FIX): the invariant type/optionality vocabulary is
    // rendered in the SOURCE language's own idiom. Detect it from the analyzed
    // source file; fall back to Python so the historical default (and the
    // pytest-only test corpus) keeps its exact `int`/`str`/`is not None`
    // spelling when detection is unavailable.
    let detected_lang = super::test_recognizer::detect_language(source_path);
    let source_lang = detected_lang.unwrap_or(Language::Python);

    // fix-R3-rc4 (RC4): the `<FILE>` positional now SCOPES the report. Build the
    // set of bare names actually DECLARED in `source_path` — the defined-symbol
    // namespace the engine never computed — so the test-derived observation
    // buckets can be intersected against it below (the FILE used to be purely
    // decorative, making the output invariant under the positional).
    //
    // `None` means the file's symbols are UNKNOWN (language undetectable,
    // unreadable, or unparseable); in that case we deliberately fall back to the
    // historical unfiltered behaviour rather than silently emptying every report
    // — distinguishing "parse failed" from the genuine "parsed, zero defs"
    // (`Some(empty)`) case.
    let defined: Option<HashSet<String>> = match detected_lang {
        Some(lang) => super::symbols::defined_symbols_for_file(source_path, lang),
        None => None,
    };

    // Collect observations from test files (Python only — observations
    // are extracted via the existing pytest-aware AST walker).
    let observations = collect_observations(test_path, function_filter)?;

    // verification-pipeline-completeness-v1 (P11.BUG-AGG-3): also run
    // the per-language test-file recogniser so the report's summary
    // reflects test files / functions even for non-Python trees. The
    // recogniser is shared with `tldr specs` (see contracts::test_recognizer).
    let (test_files_scanned, test_functions_scanned) = scan_test_recognizer(test_path);

    // Group observations by function
    let mut by_function: HashMap<String, Vec<Observation>> = HashMap::new();
    for obs in observations {
        by_function
            .entry(obs.function_name.clone())
            .or_default()
            .push(obs);
    }

    // Infer invariants for each function
    let mut functions = Vec::new();
    let mut total_observations = 0u32;
    let mut total_invariants = 0u32;
    let mut by_kind: HashMap<String, u32> = HashMap::new();

    for (func_name, obs_list) in by_function.iter() {
        // fix-R3-rc4 (RC4): scope to symbols DECLARED in the analyzed FILE.
        // Drop any observed call whose bare name is not declared there. Under
        // the conventional per-file definition this correctly excludes
        // constructors of other types, inherited members, and framework /
        // extension methods — none are declared in this file. When `defined`
        // is `None` (symbols unknown) the filter is skipped entirely so the
        // report falls back to the unfiltered set. Dropped names do not count
        // toward the summary totals, so the summary now also discriminates on
        // the FILE positional.
        if let Some(ref defined) = defined {
            if !defined.contains(func_name) {
                continue;
            }
        }

        let obs_count = obs_list.len() as u32;
        total_observations += obs_count;

        if obs_count < min_obs {
            continue;
        }

        let (preconditions, postconditions) =
            infer_invariants_for_function(obs_list, source_lang);

        // Filter by min_obs
        let preconditions: Vec<_> = preconditions
            .into_iter()
            .filter(|inv| inv.observations >= min_obs)
            .collect();
        let postconditions: Vec<_> = postconditions
            .into_iter()
            .filter(|inv| inv.observations >= min_obs)
            .collect();

        // Count by kind
        for inv in preconditions.iter().chain(postconditions.iter()) {
            let kind_str = inv.kind.to_string();
            *by_kind.entry(kind_str).or_default() += 1;
            total_invariants += 1;
        }

        functions.push(FunctionInvariants {
            function_name: func_name.clone(),
            preconditions,
            postconditions,
            observation_count: obs_count,
        });
    }

    // Sort functions alphabetically for consistent output (E12)
    functions.sort_by(|a, b| a.function_name.cmp(&b.function_name));

    Ok(InvariantsReport {
        functions,
        summary: InvariantsSummary {
            total_observations,
            total_invariants,
            by_kind,
            test_files_scanned,
            test_functions_scanned,
        },
    })
}

/// Walk the test path (file or directory) and tally per-language test
/// files / functions via the shared recogniser. Used to populate the
/// `InvariantsSummary` counts (P11.BUG-AGG-3).
fn scan_test_recognizer(test_path: &Path) -> (u32, u32) {
    use super::test_recognizer;

    let mut files = 0u32;
    let mut functions = 0u32;

    let mut tally = |path: &Path| {
        let language = match test_recognizer::detect_language(path) {
            Some(l) => l,
            None => return,
        };
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let info = test_recognizer::recognize(path, &source, language);
        if info.is_test_file {
            files += 1;
            functions += info.test_function_count;
        }
    };

    if test_path.is_file() {
        tally(test_path);
    } else {
        for entry in
            walk_project(test_path).filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        {
            tally(entry.path());
        }
    }

    (files, functions)
}

/// Collect observations from test files.
fn collect_observations(
    test_path: &Path,
    function_filter: Option<&str>,
) -> ContractsResult<Vec<Observation>> {
    let mut observations = Vec::new();

    if test_path.is_file() {
        if is_python_test_file(test_path) {
            let file_obs = extract_observations_from_file(test_path, function_filter)?;
            observations.extend(file_obs);
        } else {
            observations.extend(collect_generic_observations(test_path, function_filter));
        }
    } else {
        // Directory: scan every file. Python `test_*.py` keeps the full
        // pytest-aware AST walker; every other language is routed through
        // the shared multi-framework spec extractor (cl7-test-frameworks-v1),
        // so Jest/XCTest/RSpec/MUnit/dune suites yield observations too.
        for entry in walk_project(test_path)
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        {
            let path = entry.path();

            if is_python_test_file(path) {
                match extract_observations_from_file(path, function_filter) {
                    Ok(file_obs) => observations.extend(file_obs),
                    Err(_) => continue, // Skip files that fail to parse
                }
            } else {
                observations.extend(collect_generic_observations(path, function_filter));
            }
        }
    }

    Ok(observations)
}

/// True when `path` is a Python pytest-style file the legacy observation
/// walker should handle directly.
fn is_python_test_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    (file_name.starts_with("test_") && file_name.ends_with(".py"))
        || file_name.ends_with("_test.py")
}

/// cl7-test-frameworks-v1 (CL-7): derive invariant observations for
/// non-Python test files by reusing the shared, multi-framework spec
/// extractor (`specs::run_specs`). Every input/output spec it recovers from
/// a Jest/XCTest/RSpec/MUnit/dune assertion becomes an `Observation` whose
/// args are the recorded inputs and whose return value is the asserted
/// output — exactly the precondition/postcondition mapping the pytest path
/// produces. Files that aren't recognised as tests yield nothing.
fn collect_generic_observations(
    path: &Path,
    function_filter: Option<&str>,
) -> Vec<Observation> {
    let report = match super::specs::run_specs(path, function_filter) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut observations = Vec::new();
    for func in report.functions {
        if let Some(filter) = function_filter {
            if func.function_name != filter {
                continue;
            }
        }
        for io in func.input_output_specs {
            let args = io
                .inputs
                .iter()
                .map(observed_value_from_json)
                .collect::<Vec<_>>();
            let return_value = Some(observed_value_from_json(&io.output));
            observations.push(Observation {
                function_name: io.function,
                args,
                return_value,
            });
        }
        // Property specs (truthy/null/etc.) carry no concrete argument
        // values, but they still pin down a function-under-test. Record an
        // arg-less observation so non-null / type invariants can form from
        // the asserted output shape where available.
        for prop in func.property_specs {
            let return_value = match prop.property_type.as_str() {
                "null" => Some(ObservedValue::None),
                "truthy" => Some(ObservedValue::Bool(true)),
                "falsy" => Some(ObservedValue::Bool(false)),
                _ => None,
            };
            observations.push(Observation {
                function_name: prop.function,
                args: Vec::new(),
                return_value,
            });
        }
    }
    observations
}

/// Convert a `serde_json::Value` (as produced by the spec extractor) into the
/// invariants engine's `ObservedValue` lattice element.
fn observed_value_from_json(v: &serde_json::Value) -> ObservedValue {
    match v {
        serde_json::Value::Null => ObservedValue::None,
        serde_json::Value::Bool(b) => ObservedValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ObservedValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                ObservedValue::Float(f)
            } else {
                ObservedValue::Other(n.to_string())
            }
        }
        serde_json::Value::String(s) => ObservedValue::String(s.clone()),
        serde_json::Value::Array(items) => {
            ObservedValue::List(items.iter().map(observed_value_from_json).collect())
        }
        serde_json::Value::Object(_) => ObservedValue::Other(v.to_string()),
    }
}

/// Extract observations from a single test file.
fn extract_observations_from_file(
    path: &Path,
    function_filter: Option<&str>,
) -> ContractsResult<Vec<Observation>> {
    let source = read_file_safe(path)?;

    let mut parser = Parser::new();
    parser
        .set_language(&PYTHON_LANGUAGE.into())
        .map_err(|e| ContractsError::ParseError {
            file: path.to_path_buf(),
            message: e.to_string(),
        })?;

    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| ContractsError::ParseError {
            file: path.to_path_buf(),
            message: "Failed to parse file".to_string(),
        })?;

    let root = tree.root_node();
    // Note: AST depth checking is done during recursive traversal via MAX_AST_DEPTH guard

    let mut observations = Vec::new();
    let mut current_test_function = String::new();

    // Walk the AST looking for test functions and assertions
    extract_observations_recursive(
        &root,
        &source,
        &mut observations,
        &mut current_test_function,
        function_filter,
        0,
    );

    Ok(observations)
}

/// Recursively extract observations from AST nodes.
fn extract_observations_recursive(
    node: &Node,
    source: &str,
    observations: &mut Vec<Observation>,
    current_test_function: &mut String,
    function_filter: Option<&str>,
    depth: usize,
) {
    if depth > MAX_AST_DEPTH {
        return;
    }

    match node.kind() {
        "function_definition" => {
            // Check if this is a test function
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = node_text(name_node, source);
                if name.starts_with("test_") {
                    *current_test_function = name;
                }
            }
        }
        "assert_statement" => {
            // Extract observations from assert statements
            if !current_test_function.is_empty() {
                if let Some(obs) = extract_observation_from_assert(node, source, function_filter) {
                    observations.push(obs);
                }
            }
        }
        "call" => {
            // Also look at standalone calls in test functions
            if !current_test_function.is_empty() {
                if let Some(obs) = extract_observation_from_call(node, source, function_filter) {
                    observations.push(obs);
                }
            }
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_observations_recursive(
            &child,
            source,
            observations,
            current_test_function,
            function_filter,
            depth + 1,
        );
    }
}

/// Extract an observation from an assert statement.
fn extract_observation_from_assert(
    node: &Node,
    source: &str,
    function_filter: Option<&str>,
) -> Option<Observation> {
    // Look for patterns like: assert func(args) == expected
    // or: assert func(args)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "comparison_operator" {
            // assert func(args) == expected
            if let Some(call_node) = find_call_in_subtree(&child) {
                return extract_observation_from_call_with_expected(
                    &call_node,
                    &child,
                    source,
                    function_filter,
                );
            }
        } else if child.kind() == "call" {
            // assert func(args)
            return extract_observation_from_call(&child, source, function_filter);
        }
    }
    None
}

/// Find a call node in a subtree.
fn find_call_in_subtree<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "call" {
        return Some(*node);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(call) = find_call_in_subtree(&child) {
            return Some(call);
        }
    }
    None
}

/// Extract observation from a call node with expected value.
fn extract_observation_from_call_with_expected(
    call_node: &Node,
    comparison_node: &Node,
    source: &str,
    function_filter: Option<&str>,
) -> Option<Observation> {
    let function_name = extract_function_name(call_node, source)?;

    // Apply function filter
    if let Some(filter) = function_filter {
        if function_name != filter {
            return None;
        }
    }

    let args = extract_call_arguments(call_node, source);
    let return_value = extract_expected_value(comparison_node, call_node, source);

    Some(Observation {
        function_name,
        args,
        return_value,
    })
}

/// Extract observation from a call node.
fn extract_observation_from_call(
    call_node: &Node,
    source: &str,
    function_filter: Option<&str>,
) -> Option<Observation> {
    let function_name = extract_function_name(call_node, source)?;

    // Apply function filter
    if let Some(filter) = function_filter {
        if function_name != filter {
            return None;
        }
    }

    let args = extract_call_arguments(call_node, source);

    Some(Observation {
        function_name,
        args,
        return_value: None,
    })
}

/// Extract function name from a call node.
fn extract_function_name(call_node: &Node, source: &str) -> Option<String> {
    let func_node = call_node.child_by_field_name("function")?;

    let name = match func_node.kind() {
        "identifier" => Some(node_text(func_node, source)),
        "attribute" => {
            // For method calls like obj.method(), extract just the method name
            func_node
                .child_by_field_name("attribute")
                .map(|n| node_text(n, source))
        }
        _ => None,
    }?;

    // RC5 (Step 4): Python invariants path parity. This walk does NOT flow
    // through `run_specs`, so it needs its own builtin gate: drop Python
    // builtins and common str/dict method tails (`repr`, `sorted`, `encode`,
    // `decode`, `lower`, `get`, …) so they are never attributed as the
    // function-under-test. Shares the single static table in `specs`.
    if super::specs::is_language_builtin(&name, Language::Python) {
        return None;
    }

    Some(name)
}

/// Extract arguments from a call node.
fn extract_call_arguments(call_node: &Node, source: &str) -> Vec<ObservedValue> {
    let mut args = Vec::new();

    if let Some(args_node) = call_node.child_by_field_name("arguments") {
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                // Skip keyword arguments for now
                if child.kind() != "keyword_argument" {
                    args.push(parse_value(&child, source));
                }
            }
        }
    }

    args
}

/// Extract expected value from a comparison expression.
fn extract_expected_value(
    comparison_node: &Node,
    call_node: &Node,
    source: &str,
) -> Option<ObservedValue> {
    // Find the value that's being compared to (not the call itself)
    let mut cursor = comparison_node.walk();
    for child in comparison_node.children(&mut cursor) {
        // Skip the call node and operators
        if child.id() != call_node.id()
            && child.kind() != "=="
            && child.kind() != "!="
            && child.kind() != "comparison_operator"
        {
            return Some(parse_value(&child, source));
        }
    }
    None
}

/// Parse a value from an AST node.
fn parse_value(node: &Node, source: &str) -> ObservedValue {
    let text = node_text(*node, source);

    match node.kind() {
        "integer" => text
            .parse::<i64>()
            .map(ObservedValue::Int)
            .unwrap_or(ObservedValue::Other(text)),
        "float" => text
            .parse::<f64>()
            .map(ObservedValue::Float)
            .unwrap_or(ObservedValue::Other(text)),
        "string" | "concatenated_string" => {
            // Remove quotes
            let trimmed = text
                .trim_start_matches(['"', '\''])
                .trim_end_matches(['"', '\'']);
            ObservedValue::String(trimmed.to_string())
        }
        "true" => ObservedValue::Bool(true),
        "false" => ObservedValue::Bool(false),
        "none" => ObservedValue::None,
        "list" => {
            let mut items = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() != "[" && child.kind() != "]" && child.kind() != "," {
                    items.push(parse_value(&child, source));
                }
            }
            ObservedValue::List(items)
        }
        "unary_operator" => {
            // Handle negative numbers like -5
            if text.starts_with('-') {
                if let Ok(i) = text.parse::<i64>() {
                    return ObservedValue::Int(i);
                }
                if let Ok(f) = text.parse::<f64>() {
                    return ObservedValue::Float(f);
                }
            }
            ObservedValue::Other(text)
        }
        _ => ObservedValue::Other(text),
    }
}

/// Get text content of an AST node.
fn node_text(node: Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

// =============================================================================
// Invariant Inference
// =============================================================================

/// Infer invariants from a list of observations for a function.
///
/// `lang` is the SOURCE language of the function under analysis; it drives the
/// language-aware type / optionality vocabulary so non-Python functions never
/// emit Python idioms (`str` / `NoneType` / `is not None`).
fn infer_invariants_for_function(
    observations: &[Observation],
    lang: Language,
) -> (Vec<Invariant>, Vec<Invariant>) {
    let n = observations.len() as u32;
    if n == 0 {
        return (Vec::new(), Vec::new());
    }

    let confidence = confidence_from_observations(n);
    let mut preconditions = Vec::new();
    let mut postconditions = Vec::new();

    // Collect all argument positions
    let max_args = observations.iter().map(|o| o.args.len()).max().unwrap_or(0);

    // Infer invariants for each argument position
    for arg_idx in 0..max_args {
        let values: Vec<_> = observations
            .iter()
            .filter_map(|o| o.args.get(arg_idx))
            .collect();

        if values.is_empty() {
            continue;
        }

        let param_name = format!("arg{}", arg_idx);

        // Type invariant
        if let Some(inv) = infer_type_invariant(&param_name, &values, n, confidence, lang) {
            preconditions.push(inv);
        }

        // Non-null invariant
        if let Some(inv) = infer_non_null_invariant(&param_name, &values, n, confidence, lang) {
            preconditions.push(inv);
        }

        // Numeric invariants
        let numeric_values: Vec<f64> = values.iter().filter_map(|v| v.as_f64()).collect();
        if !numeric_values.is_empty() && numeric_values.len() == values.len() {
            // Non-negative
            if let Some(inv) =
                infer_non_negative_invariant(&param_name, &numeric_values, n, confidence)
            {
                preconditions.push(inv);
            }

            // Positive
            if let Some(inv) = infer_positive_invariant(&param_name, &numeric_values, n, confidence)
            {
                preconditions.push(inv);
            }

            // Range
            if let Some(inv) = infer_range_invariant(&param_name, &numeric_values, n, confidence) {
                preconditions.push(inv);
            }
        }
    }

    // Infer ordering relations between arguments
    for i in 0..max_args {
        for j in (i + 1)..max_args {
            if let Some(inv) = infer_relation_invariant(observations, i, j, n, confidence) {
                preconditions.push(inv);
            }
        }
    }

    // Infer postconditions from return values
    let return_values: Vec<_> = observations
        .iter()
        .filter_map(|o| o.return_value.as_ref())
        .collect();

    if !return_values.is_empty() {
        // Type invariant for result
        if let Some(inv) = infer_type_invariant("result", &return_values, n, confidence, lang) {
            postconditions.push(inv);
        }

        // Non-null invariant for result
        if let Some(inv) = infer_non_null_invariant("result", &return_values, n, confidence, lang) {
            postconditions.push(inv);
        }

        // Numeric invariants for result
        let numeric_results: Vec<f64> = return_values.iter().filter_map(|v| v.as_f64()).collect();
        if !numeric_results.is_empty() && numeric_results.len() == return_values.len() {
            if let Some(inv) =
                infer_non_negative_invariant("result", &numeric_results, n, confidence)
            {
                postconditions.push(inv);
            }
            if let Some(inv) = infer_positive_invariant("result", &numeric_results, n, confidence) {
                postconditions.push(inv);
            }
            if let Some(inv) = infer_range_invariant("result", &numeric_results, n, confidence) {
                postconditions.push(inv);
            }
        }
    }

    (preconditions, postconditions)
}

/// Determine confidence level based on observation count.
fn confidence_from_observations(n: u32) -> Confidence {
    if n >= 10 {
        Confidence::High
    } else if n >= 5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

/// Infer type invariant if all values have the same type.
///
/// `lang` renders the type name in the SOURCE language's vocabulary
/// (T2 v0.5.0 AUDIT-FIX): Python keeps `int`/`str`/… ; Kotlin uses
/// `Int`/`String`/… ; etc. The internal "all values share a type" comparison
/// still uses the language-neutral category key (`type_name`), so the
/// detection logic is unchanged — only the displayed expression is localized.
fn infer_type_invariant(
    variable: &str,
    values: &[&ObservedValue],
    obs_count: u32,
    confidence: Confidence,
    lang: Language,
) -> Option<Invariant> {
    if values.is_empty() {
        return None;
    }

    // Category equality is language-neutral (unchanged detection logic).
    let first_type = values[0].type_name();
    if !(values.iter().all(|v| v.type_name() == first_type) && first_type != "unknown") {
        return None;
    }

    // Localize the displayed type to the source language. If the lattice
    // element has no reportable type in this language, decline.
    let type_word = values[0].lang_type_name(lang)?;
    Some(Invariant {
        variable: variable.to_string(),
        kind: InvariantKind::Type,
        expression: format!("{}: {}", variable, type_word),
        confidence,
        observations: obs_count,
        counterexample_count: 0,
    })
}

/// Infer non-null invariant if no values are None.
///
/// `lang` renders the optionality expression in the SOURCE language's idiom
/// (T2 v0.5.0 AUDIT-FIX): Python `x is not None`; null-bearing languages
/// `x != null`; Swift/Ruby/Elixir `x != nil`; Rust/OCaml `x is Some`.
fn infer_non_null_invariant(
    variable: &str,
    values: &[&ObservedValue],
    obs_count: u32,
    confidence: Confidence,
    lang: Language,
) -> Option<Invariant> {
    if values.is_empty() {
        return None;
    }

    if values.iter().all(|v| !v.is_none()) {
        Some(Invariant {
            variable: variable.to_string(),
            kind: InvariantKind::NonNull,
            expression: non_null_expression(lang, variable),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        })
    } else {
        None
    }
}

/// Infer non-negative invariant if all numeric values >= 0.
fn infer_non_negative_invariant(
    variable: &str,
    values: &[f64],
    obs_count: u32,
    confidence: Confidence,
) -> Option<Invariant> {
    if values.is_empty() {
        return None;
    }

    // Don't emit non_negative if all values are positive (positive is stronger)
    if values.iter().all(|v| *v >= 0.0) && values.contains(&0.0) {
        Some(Invariant {
            variable: variable.to_string(),
            kind: InvariantKind::NonNegative,
            expression: format!("{} >= 0", variable),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        })
    } else {
        None
    }
}

/// Infer positive invariant if all numeric values > 0.
fn infer_positive_invariant(
    variable: &str,
    values: &[f64],
    obs_count: u32,
    confidence: Confidence,
) -> Option<Invariant> {
    if values.is_empty() {
        return None;
    }

    if values.iter().all(|v| *v > 0.0) {
        Some(Invariant {
            variable: variable.to_string(),
            kind: InvariantKind::Positive,
            expression: format!("{} > 0", variable),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        })
    } else {
        None
    }
}

/// Infer range invariant from min/max values.
fn infer_range_invariant(
    variable: &str,
    values: &[f64],
    obs_count: u32,
    confidence: Confidence,
) -> Option<Invariant> {
    if values.is_empty() {
        return None;
    }

    let min_val = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // Only report range if min != max (otherwise it's a constant)
    if min_val < max_val {
        Some(Invariant {
            variable: variable.to_string(),
            kind: InvariantKind::Range,
            expression: format!("{} <= {} <= {}", min_val, variable, max_val),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        })
    } else {
        None
    }
}

/// Infer ordering relation between two arguments.
fn infer_relation_invariant(
    observations: &[Observation],
    idx1: usize,
    idx2: usize,
    obs_count: u32,
    confidence: Confidence,
) -> Option<Invariant> {
    let pairs: Vec<(f64, f64)> = observations
        .iter()
        .filter_map(|o| {
            let v1 = o.args.get(idx1)?.as_f64()?;
            let v2 = o.args.get(idx2)?.as_f64()?;
            Some((v1, v2))
        })
        .collect();

    if pairs.is_empty() {
        return None;
    }

    let param1 = format!("arg{}", idx1);
    let param2 = format!("arg{}", idx2);

    // Check various relations
    if pairs.iter().all(|(v1, v2)| v1 < v2) {
        return Some(Invariant {
            variable: format!("{},{}", param1, param2),
            kind: InvariantKind::Relation,
            expression: format!("{} < {}", param1, param2),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        });
    }

    if pairs.iter().all(|(v1, v2)| v1 <= v2) {
        return Some(Invariant {
            variable: format!("{},{}", param1, param2),
            kind: InvariantKind::Relation,
            expression: format!("{} <= {}", param1, param2),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        });
    }

    if pairs.iter().all(|(v1, v2)| v1 > v2) {
        return Some(Invariant {
            variable: format!("{},{}", param1, param2),
            kind: InvariantKind::Relation,
            expression: format!("{} > {}", param1, param2),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        });
    }

    if pairs.iter().all(|(v1, v2)| v1 >= v2) {
        return Some(Invariant {
            variable: format!("{},{}", param1, param2),
            kind: InvariantKind::Relation,
            expression: format!("{} >= {}", param1, param2),
            confidence,
            observations: obs_count,
            counterexample_count: 0,
        });
    }

    None
}

// =============================================================================
// Text Formatting
// =============================================================================

/// Format invariants report as human-readable text.
pub fn format_invariants_text(report: &InvariantsReport) -> String {
    let mut lines = Vec::new();

    for fi in &report.functions {
        lines.push(format!(
            "Function: {} ({} observations)",
            fi.function_name, fi.observation_count
        ));

        if !fi.preconditions.is_empty() {
            for inv in &fi.preconditions {
                lines.push(format!(
                    "  Requires: {} [{}]",
                    inv.expression, inv.confidence
                ));
            }
        }

        if !fi.postconditions.is_empty() {
            for inv in &fi.postconditions {
                lines.push(format!(
                    "  Ensures: {} [{}]",
                    inv.expression, inv.confidence
                ));
            }
        }

        if fi.preconditions.is_empty() && fi.postconditions.is_empty() {
            lines.push("  (no invariants inferred)".to_string());
        }

        lines.push(String::new());
    }

    // Summary
    lines.push(format!(
        "Summary: {} observations, {} invariants",
        report.summary.total_observations, report.summary.total_invariants
    ));

    if !report.summary.by_kind.is_empty() {
        let kinds: Vec<_> = report
            .summary
            .by_kind
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect();
        lines.push(format!("By kind: {}", kinds.join(", ")));
    }

    lines.join("\n")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_files(temp: &TempDir, source: &str, test: &str) -> (PathBuf, PathBuf) {
        let src_path = temp.path().join("src.py");
        let test_path = temp.path().join("test_src.py");
        fs::write(&src_path, source).unwrap();
        fs::write(&test_path, test).unwrap();
        (src_path, test_path)
    }

    #[test]
    fn test_invariants_type_inference() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def compute(x, y): return x + y",
            r#"
from src import compute

def test_compute_ints():
    assert compute(1, 2) == 3
    assert compute(5, 10) == 15
    assert compute(0, 0) == 0
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        assert!(!report.functions.is_empty());
        let func = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute");
        assert!(func.is_some());

        let func = func.unwrap();
        // Should have type invariants
        let type_invs: Vec<_> = func
            .preconditions
            .iter()
            .filter(|i| i.kind == InvariantKind::Type)
            .collect();
        assert!(!type_invs.is_empty(), "Should detect type invariants");
    }

    #[test]
    fn test_invariants_non_null() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def process(data): return data.strip()",
            r#"
from src import process

def test_process_strings():
    assert process("hello") == "hello"
    assert process("  world  ") == "world"
    assert process("test") == "test"
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        // Should detect non-null for string argument
        let func = report
            .functions
            .iter()
            .find(|f| f.function_name == "process");
        assert!(func.is_some());

        let func = func.unwrap();
        let non_null_invs: Vec<_> = func
            .preconditions
            .iter()
            .filter(|i| i.kind == InvariantKind::NonNull)
            .collect();
        assert!(
            !non_null_invs.is_empty(),
            "Should detect non-null invariant"
        );
    }

    #[test]
    fn test_invariants_numeric_bounds() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def square(x): return x * x",
            r#"
from src import square

def test_square_positive():
    assert square(1) == 1
    assert square(2) == 4
    assert square(3) == 9
    assert square(10) == 100
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.function_name == "square");
        assert!(func.is_some());

        let func = func.unwrap();
        // Should detect positive invariant (all values > 0)
        let positive_invs: Vec<_> = func
            .preconditions
            .iter()
            .filter(|i| i.kind == InvariantKind::Positive)
            .collect();
        assert!(
            !positive_invs.is_empty(),
            "Should detect positive invariant"
        );
    }

    #[test]
    fn test_invariants_ordering_relations() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def bounded_compute(start, end): return end - start",
            r#"
from src import bounded_compute

def test_bounded_compute():
    assert bounded_compute(0, 10) == 10
    assert bounded_compute(5, 15) == 10
    assert bounded_compute(100, 200) == 100
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.function_name == "bounded_compute");
        assert!(func.is_some());

        let func = func.unwrap();
        // Should detect arg0 < arg1 relation
        let relation_invs: Vec<_> = func
            .preconditions
            .iter()
            .filter(|i| i.kind == InvariantKind::Relation)
            .collect();
        assert!(!relation_invs.is_empty(), "Should detect ordering relation");
    }

    #[test]
    fn test_invariants_confidence_scoring() {
        let temp = TempDir::new().unwrap();
        let src_path = temp.path().join("func.py");
        let test_path = temp.path().join("test_func.py");

        fs::write(&src_path, "def identity(x): return x").unwrap();

        // Many observations = high confidence
        let mut test_code = String::from("from func import identity\n\n");
        for i in 0..15 {
            test_code.push_str(&format!(
                "def test_identity_{}(): assert identity({}) == {}\n",
                i, i, i
            ));
        }
        fs::write(&test_path, test_code).unwrap();

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        let func = report
            .functions
            .iter()
            .find(|f| f.function_name == "identity");
        assert!(func.is_some());

        let func = func.unwrap();
        assert!(func.observation_count >= 10);

        // With 15+ observations, confidence should be High
        for inv in &func.preconditions {
            assert_eq!(
                inv.confidence,
                Confidence::High,
                "Should have high confidence with 15 observations"
            );
        }
    }

    #[test]
    fn test_invariants_min_obs_filter() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def add(a, b): return a + b",
            r#"
from src import add

def test_add(): assert add(1, 2) == 3
"#,
        );

        // With min_obs=5, single observation should be filtered out
        let report = run_invariants(&src_path, &test_path, None, 5).unwrap();

        // Should have no functions reported (or functions with empty invariants)
        for func in &report.functions {
            assert!(
                func.preconditions.is_empty(),
                "Should filter out invariants with < 5 observations"
            );
        }
    }

    #[test]
    fn test_invariants_json_output() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def add(a, b): return a + b",
            r#"
from src import add

def test_add():
    assert add(1, 2) == 3
    assert add(2, 3) == 5
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        // Should serialize to JSON without error
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("functions"));
        assert!(json.contains("summary"));
    }

    #[test]
    fn test_invariants_text_output() {
        let temp = TempDir::new().unwrap();
        let (src_path, test_path) = create_test_files(
            &temp,
            "def add(a, b): return a + b",
            r#"
from src import add

def test_add():
    assert add(1, 2) == 3
"#,
        );

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();
        let text = format_invariants_text(&report);

        assert!(text.contains("Function:"));
        assert!(text.contains("observations"));
    }

    // ====================================================================
    // FEATURE TESTS — T2 (v0.5.0 AUDIT-FIX): language-aware invariant
    // type/optionality vocabulary. Non-Python source functions must NOT
    // emit Python idioms (`is not None`, `NoneType`, `: str`).
    // ====================================================================

    /// Kotlin source: invariants inferred from a Kotlin test must use Kotlin
    /// type/optionality vocabulary, never Python's `is not None` / `NoneType`
    /// / `str`. (kotlin-datetime regressed with `arg0: str` / `arg0 is not
    /// None` / `result: str`.)
    #[test]
    fn kotlin_invariants_no_python_idioms() {
        let temp = TempDir::new().unwrap();
        let src_path = temp.path().join("Calc.kt");
        let test_path = temp.path().join("CalcTest.kt");
        fs::write(
            &src_path,
            "class Calc {\n  fun describe(x: Int): String = x.toString()\n}\n",
        )
        .unwrap();
        fs::write(
            &test_path,
            "import kotlin.test.Test\nimport kotlin.test.assertEquals\n\
             class CalcTest {\n\
             \t@Test fun a() { assertEquals(\"1\", describe(1)) }\n\
             \t@Test fun b() { assertEquals(\"2\", describe(2)) }\n\
             }\n",
        )
        .unwrap();

        let report = run_invariants(&src_path, &test_path, None, 1).unwrap();

        let exprs: Vec<String> = report
            .functions
            .iter()
            .flat_map(|f| f.preconditions.iter().chain(f.postconditions.iter()))
            .map(|i| i.expression.clone())
            .collect();

        for e in &exprs {
            assert!(
                !e.contains("is not None"),
                "Kotlin invariant must not emit Python `is not None`: {e:?}"
            );
            assert!(
                !e.contains("NoneType"),
                "Kotlin invariant must not emit Python `NoneType`: {e:?}"
            );
            assert!(
                !(e.contains(": str") || e.contains(": int") || e.contains(": float")),
                "Kotlin invariant must not emit Python type names: {e:?}"
            );
        }
    }

    /// Direct unit on the vocabulary: a non-Python (Kotlin) language emits its
    /// own type name for a string observation and its own optionality
    /// expression — never the Python idioms.
    #[test]
    fn non_python_type_vocab_is_language_aware() {
        let vals = [ObservedValue::String("x".to_string())];
        let refs: Vec<&ObservedValue> = vals.iter().collect();

        // Python keeps `str` (regression guard: do not change Python).
        let py = infer_type_invariant("arg0", &refs, 1, Confidence::Low, Language::Python)
            .expect("python type inv");
        assert_eq!(py.expression, "arg0: str");

        // Kotlin uses its own type name, not `str`.
        let kt = infer_type_invariant("arg0", &refs, 1, Confidence::Low, Language::Kotlin)
            .expect("kotlin type inv");
        assert!(
            !kt.expression.contains(": str"),
            "kotlin type vocab must not be Python `str`: {:?}",
            kt.expression
        );
        assert_eq!(kt.expression, "arg0: String");

        // Non-null: Python `is not None`; Kotlin `!= null`.
        let py_nn = infer_non_null_invariant("arg0", &refs, 1, Confidence::Low, Language::Python)
            .expect("python nn");
        assert_eq!(py_nn.expression, "arg0 is not None");
        let kt_nn = infer_non_null_invariant("arg0", &refs, 1, Confidence::Low, Language::Kotlin)
            .expect("kotlin nn");
        assert!(
            !kt_nn.expression.contains("is not None"),
            "kotlin non-null must not be Python idiom: {:?}",
            kt_nn.expression
        );
        assert_eq!(kt_nn.expression, "arg0 != null");
    }

    /// R7 (invariants-specs cluster) item 2 — "invariant type/null vocabulary
    /// remaining non-Python leaks": exhaustively assert that for EVERY
    /// non-Python language the type and non-null/optionality vocabulary never
    /// emits a Python idiom (`str`/`int`/`float`/`bool`/`list`/`NoneType` as a
    /// reported type, or `is not None`). Python itself is the regression anchor
    /// and is asserted to KEEP its historical spelling.
    #[test]
    fn all_non_python_langs_emit_no_python_vocab_leak() {
        // Every supported language EXCEPT Python.
        let non_python = [
            Language::Kotlin,
            Language::Java,
            Language::Scala,
            Language::CSharp,
            Language::Swift,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go,
            Language::Rust,
            Language::Ocaml,
            Language::Ruby,
            Language::Php,
            Language::Lua,
            Language::Luau,
            Language::Elixir,
            Language::Solidity,
            Language::C,
            Language::Cpp,
        ];

        // Python-EXCLUSIVE type token. NOTE: `int`/`float`/`bool` are
        // deliberately NOT flagged — they are the genuine native spelling for
        // several C-family / ML languages (Java/Go/C#/C/C++/OCaml `int`,
        // Elixir/OCaml `float`). The Python-exclusive type token is `str`
        // (others use String/string/&str/binary); `NoneType` / `is not None`
        // are the Python null idioms the T2 work eliminated. The type token is
        // compared EXACTLY (split on `": "`) so `str` is not confused with
        // `string` (Go/PHP/C#/TS) or `&str` (Rust, a deliberate Rust spelling).
        let python_str_token = "str";

        // Exercise each lattice element so every `lang_type_word` arm is hit.
        let samples = [
            ObservedValue::Int(1),
            ObservedValue::Float(1.5),
            ObservedValue::String("x".to_string()),
            ObservedValue::Bool(true),
            ObservedValue::List(vec![ObservedValue::Int(1)]),
        ];

        for lang in non_python {
            for sample in &samples {
                let vals = [sample];
                let refs: Vec<&ObservedValue> = vals.iter().copied().collect();

                if let Some(ti) =
                    infer_type_invariant("arg0", &refs, 3, Confidence::Low, lang)
                {
                    // The rendered form is `arg0: <type>`. Compare the type
                    // token EXACTLY so `str` is distinguished from the
                    // legitimate `string` / `&str` spellings.
                    let type_token = ti.expression.rsplit(": ").next().unwrap_or("");
                    assert_ne!(
                        type_token, python_str_token,
                        "{lang:?} type invariant leaked Python `str` token: {:?}",
                        ti.expression
                    );
                    assert!(
                        !ti.expression.contains("NoneType"),
                        "{lang:?} type invariant leaked Python `NoneType`: {:?}",
                        ti.expression
                    );
                }

                if let Some(nn) =
                    infer_non_null_invariant("arg0", &refs, 3, Confidence::Low, lang)
                {
                    assert!(
                        !nn.expression.contains("is not None"),
                        "{lang:?} non-null invariant leaked Python `is not None`: {:?}",
                        nn.expression
                    );
                }
            }
        }

        // Python regression anchor: it KEEPS its historical spelling.
        let vals = [ObservedValue::String("x".to_string())];
        let refs: Vec<&ObservedValue> = vals.iter().collect();
        let py_t = infer_type_invariant("arg0", &refs, 3, Confidence::Low, Language::Python)
            .expect("python type inv");
        assert_eq!(py_t.expression, "arg0: str");
        let py_nn = infer_non_null_invariant("arg0", &refs, 3, Confidence::Low, Language::Python)
            .expect("python nn inv");
        assert_eq!(py_nn.expression, "arg0 is not None");
    }

    // ========================================================================
    // fix-R3-rc4 (RC4): the `<FILE>` positional must SCOPE the reported
    // functions to the symbols DECLARED in that file, instead of echoing every
    // call name observed across the whole test tree. These characterization
    // tests pin the real ground-truth scoping (not merely non-emptiness).
    // ========================================================================

    /// Build a `src_a.py` / `src_b.py` pair and a `tests/` dir whose assertions
    /// observe BOTH `alpha` and `beta`. Returns the temp dir (kept alive) plus
    /// the two source paths and the test directory.
    fn scope_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = TempDir::new().unwrap();
        let src_a = temp.path().join("src_a.py");
        let src_b = temp.path().join("src_b.py");
        fs::write(&src_a, "def alpha(x):\n    return x\n").unwrap();
        fs::write(&src_b, "def beta(x):\n    return x\n").unwrap();
        let tests = temp.path().join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("test_both.py"),
            r#"
from src_a import alpha
from src_b import beta

def test_alpha():
    assert alpha(1) == 1
    assert alpha(2) == 2

def test_beta():
    assert beta(1) == 1
    assert beta(2) == 2
"#,
        )
        .unwrap();
        (temp, src_a, src_b, tests)
    }

    fn invariant_names(source: &Path, tests: &Path) -> Vec<String> {
        let report = run_invariants(source, tests, None, 1).unwrap();
        let mut names: Vec<String> = report
            .functions
            .iter()
            .map(|f| f.function_name.clone())
            .collect();
        names.sort();
        names
    }

    /// Test 1 (the core bug) — the positional now DISCRIMINATES. Scoping to
    /// `src_a.py` reports `alpha` and NOT `beta`; scoping to `src_b.py` reports
    /// `beta` and NOT `alpha`; the two reports DIFFER. Before the fix both
    /// files emit the identical observed-everywhere list.
    #[test]
    fn invariants_file_positional_scopes_to_declared_symbols() {
        let (_temp, src_a, src_b, tests) = scope_fixture();

        let a = invariant_names(&src_a, &tests);
        let b = invariant_names(&src_b, &tests);

        assert!(
            a.contains(&"alpha".to_string()),
            "src_a.py declares alpha, so it must be reported: {a:?}"
        );
        assert!(
            !a.contains(&"beta".to_string()),
            "beta is NOT declared in src_a.py and must be excluded: {a:?}"
        );
        assert!(
            b.contains(&"beta".to_string()),
            "src_b.py declares beta, so it must be reported: {b:?}"
        );
        assert!(
            !b.contains(&"alpha".to_string()),
            "alpha is NOT declared in src_b.py and must be excluded: {b:?}"
        );
        assert_ne!(a, b, "the FILE positional must change the reported set");
    }

    /// Test 2 (Q2) — names observed in the test tree but NOT declared in the
    /// scoped file (helper functions, builtins, would-be framework/inherited
    /// calls) are dropped. The report is EXACTLY the declared symbol, which is
    /// airtight: `helper` is definitely observed (`assert helper(3) == 3`), so
    /// without scoping the set could not equal `{compute}`.
    #[test]
    fn invariants_drops_names_not_declared_in_file() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("calc.py");
        fs::write(&src, "def compute(x):\n    return x\n").unwrap();
        let tests = temp.path().join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("test_calc.py"),
            r#"
from calc import compute

def test_compute():
    assert compute(1) == 1
    assert compute(2) == 2
    assert helper(3) == 3
    assert str(compute(1)) == "1"
"#,
        )
        .unwrap();

        let names = invariant_names(&src, &tests);
        assert_eq!(
            names,
            vec!["compute".to_string()],
            "only the symbol declared in calc.py survives scoping: {names:?}"
        );
    }

    /// Test 3 (Q2) — empty-but-correct. A file whose declared symbols are
    /// disjoint from every observed call yields an EMPTY function list (the
    /// documented intended outcome under strict declared-in-file scoping), not
    /// a crash and not the unfiltered list.
    #[test]
    fn invariants_empty_when_no_observed_name_declared_in_file() {
        let temp = TempDir::new().unwrap();
        // `unrelated.py` declares only `unrelated`, which the tests never call.
        let src = temp.path().join("unrelated.py");
        fs::write(&src, "def unrelated():\n    return 0\n").unwrap();
        let tests = temp.path().join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("test_x.py"),
            "\ndef test_x():\n    assert compute(1) == 1\n    assert compute(2) == 2\n",
        )
        .unwrap();

        let report = run_invariants(&src, &tests, None, 1).unwrap();
        assert!(
            report.functions.is_empty(),
            "no observed call is declared in unrelated.py -> empty report: {:?}",
            report
                .functions
                .iter()
                .map(|f| f.function_name.clone())
                .collect::<Vec<_>>()
        );
    }

    /// Test 4 — parse-failure / unreadable fallback. A `.py` file containing
    /// invalid UTF-8 is still detected as Python by extension, but its declared
    /// symbols are UNKNOWN (read fails). The report must FALL BACK to unfiltered
    /// rather than silently empty everything, so a parser gap can never erase a
    /// report.
    #[test]
    fn invariants_falls_back_to_unfiltered_when_file_unreadable() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("broken.py");
        fs::write(&src, [0xff, 0xfe, 0x00, 0x80, 0x81]).unwrap();
        let tests = temp.path().join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("test_x.py"),
            "\ndef test_x():\n    assert compute(1) == 1\n    assert compute(2) == 2\n",
        )
        .unwrap();

        let names = invariant_names(&src, &tests);
        assert!(
            names.contains(&"compute".to_string()),
            "an unreadable FILE must fall back to unfiltered (compute retained): {names:?}"
        );
    }

    /// Test 5 — same-name KNOWN LIMITATION. Scoping matches by UNQUALIFIED
    /// name: a file declaring `read` keeps every observed `read` call even
    /// where the canonical (receiver-type-qualified) key would distinguish two
    /// classes. This pins the accepted bare-name imprecision so a future
    /// signature-keyed fix has a target.
    #[test]
    fn invariants_bare_name_match_keeps_same_named_symbol_known_limitation() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("reader.py");
        fs::write(&src, "def read(x):\n    return x\n").unwrap();
        let tests = temp.path().join("tests");
        fs::create_dir_all(&tests).unwrap();
        fs::write(
            tests.join("test_read.py"),
            "\ndef test_read():\n    assert read(1) == 1\n    assert read(2) == 2\n",
        )
        .unwrap();

        let names = invariant_names(&src, &tests);
        assert!(
            names.contains(&"read".to_string()),
            "bare-name match keeps `read` declared in reader.py: {names:?}"
        );
    }
}
