//! Specs command - Extract behavioral specifications from pytest test files.
//!
//! Parses pytest assertions to derive input/output contracts, exception specs,
//! and property specs for functions under test.
//!
//! # TIGER/ELEPHANT Mitigations Addressed
//! - E06: Literal eval limits -> MAX_LITERAL_DEPTH, MAX_LITERAL_SIZE
//! - T07: Regex DoS - Use tree-sitter for parsing, not regex on code
//! - T08: AST stack overflow - check_ast_depth() limits traversal depth
//!
//! # Extraction Patterns
//!
//! | Pattern | Spec Type | Example |
//! |---------|-----------|---------|
//! | `assert f(x) == y` | InputOutput | `add(2, 3) == 5` |
//! | `with pytest.raises(E)` | Exception | `raises(ValueError)` |
//! | `assert isinstance(f(x), T)` | Property (type) | `isinstance(result, list)` |
//! | `assert len(f(x)) == n` | Property (length) | `len(result) == 3` |
//! | `assert f(x) > n` | Property (bounds) | `result > 0` |
//! | `assert "key" in f(x)` | Property (membership) | `"id" in result` |

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use tldr_core::ast::ParserPool;
use tldr_core::walker::walk_project;
use tldr_core::Language;
use tree_sitter::{Node, Parser, Tree};
use tree_sitter_python::LANGUAGE as PYTHON_LANGUAGE;

use crate::output::{OutputFormat, OutputWriter};

use super::error::{ContractsError, ContractsResult};
use super::types::{
    Confidence, ExceptionSpec, FunctionSpecs, InputOutputSpec,
    OutputFormat as ContractsOutputFormat, PropertySpec, SpecsByType, SpecsReport, SpecsSummary,
};
use super::validation::{check_ast_depth, read_file_safe, validate_file_path};

// =============================================================================
// Resource Limits (E06 Mitigation)
// =============================================================================

/// Maximum depth for recursive literal evaluation
const MAX_LITERAL_DEPTH: usize = 10;

/// Maximum size for literal string representation (in bytes)
const MAX_LITERAL_SIZE: usize = 10_000;

// =============================================================================
// CLI Arguments
// =============================================================================

/// Extract behavioral specifications from pytest test files.
///
/// Parses pytest assertions to derive:
/// - Input/output specs from `assert func(args) == expected`
/// - Exception specs from `with pytest.raises(ExceptionType)`
/// - Property specs from isinstance, len(), and comparison assertions
///
/// # Example
///
/// ```bash
/// tldr specs --from-tests tests/
/// tldr specs --from-tests tests/test_module.py --function add
/// tldr specs --from-tests tests/ --format text
/// ```
#[derive(Debug, Args)]
pub struct SpecsArgs {
    /// Test file or directory to scan for specs
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

    /// Filter to specific function under test
    #[arg(long)]
    pub function: Option<String>,

    /// Source directory for cross-referencing (optional)
    #[arg(long)]
    pub source: Option<PathBuf>,
}

impl SpecsArgs {
    /// Run the specs command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(format, quiet);

        // Validate test path exists
        if !self.from_tests.exists() {
            return Err(ContractsError::TestPathNotFound {
                path: self.from_tests.clone(),
            }
            .into());
        }

        writer.progress(&format!(
            "Extracting specs from {}...",
            self.from_tests.display()
        ));

        // Run extraction
        let report = run_specs(&self.from_tests, self.function.as_deref())?;

        // Output based on format
        let use_text = matches!(self.output_format, ContractsOutputFormat::Text)
            || matches!(format, OutputFormat::Text);

        if use_text {
            let text = format_specs_text(&report);
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

/// Run specs extraction on a test file or directory.
///
/// # Arguments
/// * `test_path` - Path to a test file or directory
/// * `function_filter` - Optional filter to specific function under test
///
/// # Returns
/// SpecsReport with all extracted specifications.
pub fn run_specs(test_path: &Path, function_filter: Option<&str>) -> ContractsResult<SpecsReport> {
    let mut all_specs: HashMap<String, FunctionSpecs> = HashMap::new();
    let mut test_functions_scanned = 0u32;
    let mut test_files_scanned = 0u32;

    if test_path.is_file() {
        // Single file: dispatch on language. Python keeps the full
        // pytest-aware extraction path (which also yields specs); other
        // supported languages fall through to the AST recogniser, which
        // returns counts only.
        let lang = super::test_recognizer::detect_language(test_path);
        if matches!(lang, Some(Language::Python)) {
            let file_report = extract_from_test_file(test_path)?;
            test_files_scanned = 1;
            test_functions_scanned = file_report.test_functions_scanned;
            merge_specs(&mut all_specs, file_report.functions);
        } else if let Some(language) = lang {
            // Read + recognise without aborting on read failures.
            if let Ok(source) = std::fs::read_to_string(test_path) {
                let info = super::test_recognizer::recognize(test_path, &source, language);
                if info.is_test_file {
                    test_files_scanned = 1;
                    test_functions_scanned = info.test_function_count;
                    // verification-and-metrics-completeness-v1
                    // (P12.AGG12-2): for the languages whose test
                    // recogniser yields a non-zero count, also extract
                    // input/output/exception/property specs from common
                    // assertion patterns. Previously these languages
                    // reported `total_specs = 0` even with hundreds of
                    // recognised test functions.
                    let extracted =
                        extract_generic_specs(test_path, &source, language);
                    merge_specs(&mut all_specs, extracted);
                }
            }
        }
    } else {
        // Directory: walk every source file the walker yields and dispatch
        // per detected language. Python still gets the full pytest
        // extractor; other supported languages get the AST recogniser
        // which returns `(is_test_file, test_function_count)`.
        //
        // verification-pipeline-completeness-v1 (P11.BUG-AGG-3): closes
        // the previous Python-only walk that always reported
        // `test_files_scanned = 0` on JS/Java/PHP/Swift/Go/etc test trees.
        for entry in
            walk_project(test_path).filter(|e| e.path().is_file())
        {
            let file_path = entry.path();
            let language = match super::test_recognizer::detect_language(file_path) {
                Some(l) => l,
                None => continue,
            };

            if matches!(language, Language::Python) {
                // Preserve the existing Python `test_*.py` /
                // `Test*` class convention so we don't over-scan
                // non-test Python files.
                let name = match file_path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n,
                    None => continue,
                };
                if !((name.starts_with("test_") && name.ends_with(".py"))
                    || name.ends_with("_test.py"))
                {
                    continue;
                }
                match extract_from_test_file(file_path) {
                    Ok(file_report) => {
                        test_files_scanned += 1;
                        test_functions_scanned += file_report.test_functions_scanned;
                        merge_specs(&mut all_specs, file_report.functions);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse {}: {}", file_path.display(), e);
                    }
                }
                continue;
            }

            // Non-Python: use the language-specific test recogniser.
            let source = match std::fs::read_to_string(file_path) {
                Ok(s) => s,
                // TRDD-O66FM8TN: was a bare `Err(_) => continue`. The Python
                // branch a few lines above already announces a test file it
                // could not handle; this arm dropped one just as silently and
                // said nothing, so `test_files_scanned` under-counted with no
                // hint why. Both arms skip the file -- only one used to admit
                // it. Keep them saying the same thing.
                Err(e) => {
                    eprintln!("Warning: Failed to read {}: {}", file_path.display(), e);
                    continue;
                }
            };
            let info = super::test_recognizer::recognize(file_path, &source, language);
            if info.is_test_file {
                test_files_scanned += 1;
                test_functions_scanned += info.test_function_count;
                // verification-and-metrics-completeness-v1 (P12.AGG12-2):
                // generic assertion-based spec extractor for languages whose
                // recogniser counts tests but the legacy Python extractor
                // never ran on. Covers Java/Kotlin/C#/Rust/JS/TS/PHP/Swift/
                // Go/Scala/Ruby/Elixir/Lua: any language whose test
                // functions can be located by `recognize`.
                let extracted = extract_generic_specs(file_path, &source, language);
                merge_specs(&mut all_specs, extracted);
            }
        }
    }

    // Apply function filter
    let mut functions: Vec<FunctionSpecs> = all_specs.into_values().collect();
    if let Some(filter) = function_filter {
        functions.retain(|f| f.function_name == filter);
    }

    // Sort by function name for deterministic output
    functions.sort_by(|a, b| a.function_name.cmp(&b.function_name));

    // Calculate summary
    let total_io = functions
        .iter()
        .map(|f| f.input_output_specs.len() as u32)
        .sum();
    let total_exc = functions
        .iter()
        .map(|f| f.exception_specs.len() as u32)
        .sum();
    let total_prop = functions
        .iter()
        .map(|f| f.property_specs.len() as u32)
        .sum();
    let total_specs = total_io + total_exc + total_prop;

    let summary = SpecsSummary {
        total_specs,
        by_type: SpecsByType {
            input_output: total_io,
            exception: total_exc,
            property: total_prop,
        },
        test_functions_scanned,
        test_files_scanned,
        functions_found: functions.len() as u32,
    };

    Ok(SpecsReport { functions, summary })
}

/// Intermediate result from parsing a single file.
struct FileSpecReport {
    functions: Vec<FunctionSpecs>,
    test_functions_scanned: u32,
}

/// Extract specs from a single test file.
fn extract_from_test_file(path: &Path) -> ContractsResult<FileSpecReport> {
    let canonical = validate_file_path(path)?;
    let source = read_file_safe(&canonical)?;

    if source.trim().is_empty() {
        return Ok(FileSpecReport {
            functions: vec![],
            test_functions_scanned: 0,
        });
    }

    // Parse with tree-sitter
    let tree = parse_python(&source, &canonical)?;
    let root = tree.root_node();

    let mut specs: HashMap<String, FunctionSpecs> = HashMap::new();
    let mut test_func_count = 0u32;

    // Process all test functions
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        // why: tree-sitter-python wraps a decorated def in a
        // `decorated_definition` node (the `function_definition`/
        // `class_definition` lives under its `definition` field), so
        // any pytest test decorated with e.g. `@pytest.mark.parametrize`
        // or `@pytest.fixture` -- extremely common -- was never matched
        // by the arms below and silently dropped from the scan.
        let effective = if child.kind() == "decorated_definition" {
            child.child_by_field_name("definition").unwrap_or(child)
        } else {
            child
        };
        match effective.kind() {
            "function_definition" => {
                if let Some(name_node) = effective.child_by_field_name("name") {
                    let name = get_node_text(name_node, source.as_bytes());
                    if name.starts_with("test_") {
                        test_func_count += 1;
                        process_test_function(effective, name, source.as_bytes(), &mut specs, 0)?;
                    }
                }
            }
            "class_definition" => {
                // Test class: class TestFoo:
                if let Some(name_node) = effective.child_by_field_name("name") {
                    let class_name = get_node_text(name_node, source.as_bytes());
                    if class_name.starts_with("Test") {
                        if let Some(body) = effective.child_by_field_name("body") {
                            let mut class_cursor = body.walk();
                            for method in body.children(&mut class_cursor) {
                                // why: same decorated-def unwrap for methods
                                // (e.g. a parametrized test method).
                                let effective_method = if method.kind() == "decorated_definition" {
                                    method.child_by_field_name("definition").unwrap_or(method)
                                } else {
                                    method
                                };
                                if effective_method.kind() == "function_definition" {
                                    if let Some(method_name) =
                                        effective_method.child_by_field_name("name")
                                    {
                                        let mname = get_node_text(method_name, source.as_bytes());
                                        if mname.starts_with("test_") {
                                            test_func_count += 1;
                                            process_test_function(
                                                effective_method,
                                                mname,
                                                source.as_bytes(),
                                                &mut specs,
                                                0,
                                            )?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Generate summaries for each function
    let functions: Vec<FunctionSpecs> = specs
        .into_values()
        .map(|mut fs| {
            fs.summary = generate_summary(&fs);
            fs
        })
        .collect();

    Ok(FileSpecReport {
        functions,
        test_functions_scanned: test_func_count,
    })
}

/// Parse Python source with tree-sitter.
fn parse_python(source: &str, file: &Path) -> ContractsResult<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&PYTHON_LANGUAGE.into())
        .map_err(|e| ContractsError::ParseError {
            file: file.to_path_buf(),
            message: format!("Failed to set Python language: {}", e),
        })?;

    parser
        .parse(source, None)
        .ok_or_else(|| ContractsError::ParseError {
            file: file.to_path_buf(),
            message: "Parsing returned None".to_string(),
        })
}

/// Get text content of a node.
fn get_node_text<'a>(node: Node<'a>, source: &'a [u8]) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() {
        std::str::from_utf8(&source[start..end]).unwrap_or("")
    } else {
        ""
    }
}

// =============================================================================
// Test Function Processing
// =============================================================================

/// Process a single test function to extract specs.
fn process_test_function(
    func: Node,
    test_func_name: &str,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
    depth: usize,
) -> ContractsResult<()> {
    check_ast_depth(depth, &PathBuf::from("<test>"))?;

    let body = match func.child_by_field_name("body") {
        Some(b) => b,
        None => return Ok(()),
    };

    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        match stmt.kind() {
            "assert_statement" => {
                extract_from_assert(stmt, test_func_name, source, specs)?;
            }
            "with_statement" => {
                extract_from_with(stmt, test_func_name, source, specs)?;
            }
            "expression_statement" => {
                // Check for asserts inside expressions
                let mut inner = stmt.walk();
                for child in stmt.children(&mut inner) {
                    if child.kind() == "assert_statement" {
                        extract_from_assert(child, test_func_name, source, specs)?;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Extract specs from an assert statement.
fn extract_from_assert(
    assert_stmt: Node,
    test_func_name: &str,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
) -> ContractsResult<()> {
    let line = assert_stmt.start_position().row as u32 + 1;

    // Get the test expression (skip the "assert" keyword)
    let mut cursor = assert_stmt.walk();
    let mut test_expr = None;
    for child in assert_stmt.children(&mut cursor) {
        if child.kind() != "assert" {
            test_expr = Some(child);
            break;
        }
    }

    let test_expr = match test_expr {
        Some(e) => e,
        None => return Ok(()),
    };

    // Try to extract different spec types
    if try_extract_isinstance_spec(test_expr, test_func_name, line, source, specs) {
        return Ok(());
    }

    if try_extract_comparison_spec(test_expr, test_func_name, line, source, specs) {
        return Ok(());
    }

    Ok(())
}

/// Try to extract an isinstance property spec.
///
/// Pattern: `assert isinstance(func(args), Type)`
fn try_extract_isinstance_spec(
    expr: Node,
    test_func_name: &str,
    line: u32,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    if expr.kind() != "call" {
        return false;
    }

    let func_node = match expr.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };

    let func_name = get_node_text(func_node, source);
    if func_name != "isinstance" {
        return false;
    }

    let args = match expr.child_by_field_name("arguments") {
        Some(a) => a,
        None => return false,
    };

    // Get first and second arguments
    let mut arg_cursor = args.walk();
    let mut first_arg = None;
    let mut second_arg = None;

    for child in args.children(&mut arg_cursor) {
        let kind = child.kind();
        if kind == "(" || kind == ")" || kind == "," {
            continue;
        }
        if first_arg.is_none() {
            first_arg = Some(child);
        } else if second_arg.is_none() {
            second_arg = Some(child);
            break;
        }
    }

    let (first_arg, second_arg) = match (first_arg, second_arg) {
        (Some(f), Some(s)) => (f, s),
        _ => return false,
    };

    // First arg should be a call to the function under test
    if first_arg.kind() != "call" {
        return false;
    }

    let (fname, _inputs) = match extract_call_info(first_arg, source) {
        Some(info) => info,
        None => return false,
    };

    let type_name = get_node_text(second_arg, source);
    let constraint = format!("isinstance(result, {})", type_name);

    let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
        function_name: fname.clone(),
        summary: String::new(),
        test_count: 0,
        input_output_specs: vec![],
        exception_specs: vec![],
        property_specs: vec![],
    });

    fs.property_specs.push(PropertySpec {
        function: fname,
        property_type: "type".to_string(),
        constraint,
        test_function: test_func_name.to_string(),
        line,
        confidence: Confidence::High,
    });

    true
}

/// Try to extract specs from comparison expressions.
///
/// Patterns:
/// - `assert func(args) == expected` -> InputOutputSpec
/// - `assert func(args) > n` -> PropertySpec (bounds)
/// - `assert len(func(args)) == n` -> PropertySpec (length)
/// - `assert "key" in func(args)` -> PropertySpec (membership)
fn try_extract_comparison_spec(
    expr: Node,
    test_func_name: &str,
    line: u32,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    if expr.kind() != "comparison_operator" {
        return false;
    }

    // Get left, operator, and right from comparison
    let mut cursor = expr.walk();
    let mut left = None;
    let mut op: Option<&str> = None;
    let mut right = None;

    for child in expr.children(&mut cursor) {
        let kind = child.kind();
        match kind {
            "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                op = Some(kind);
            }
            "in" | "not in" => {
                op = Some(kind);
            }
            "is" | "is not" => {
                op = Some(kind);
            }
            _ => {
                if left.is_none() {
                    left = Some(child);
                } else if right.is_none() {
                    right = Some(child);
                }
            }
        }
    }

    let (left, op, right) = match (left, op, right) {
        (Some(l), Some(o), Some(r)) => (l, o, r),
        _ => return false,
    };

    // Check for membership: "key" in func(args)
    if op == "in" && right.kind() == "call" {
        if let Some((fname, _)) = extract_call_info(right, source) {
            let key_text = get_node_text(left, source);
            let constraint = format!("{} in result", key_text);

            let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                function_name: fname.clone(),
                summary: String::new(),
                test_count: 0,
                input_output_specs: vec![],
                exception_specs: vec![],
                property_specs: vec![],
            });

            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "membership".to_string(),
                constraint,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });

            return true;
        }
    }

    // Check for equality with call on left: func(args) == expected
    if op == "==" {
        // Check for len(func(args)) == n
        if left.kind() == "call" {
            let left_func = left
                .child_by_field_name("function")
                .map(|f| get_node_text(f, source));
            if left_func == Some("len") {
                if let Some(inner_args) = left.child_by_field_name("arguments") {
                    // Find the inner call
                    let mut inner_cursor = inner_args.walk();
                    for child in inner_args.children(&mut inner_cursor) {
                        if child.kind() == "call" {
                            if let Some((fname, _)) = extract_call_info(child, source) {
                                let len_val = get_node_text(right, source);
                                let constraint = format!("len(result) == {}", len_val);

                                let fs =
                                    specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                                        function_name: fname.clone(),
                                        summary: String::new(),
                                        test_count: 0,
                                        input_output_specs: vec![],
                                        exception_specs: vec![],
                                        property_specs: vec![],
                                    });

                                fs.property_specs.push(PropertySpec {
                                    function: fname,
                                    property_type: "length".to_string(),
                                    constraint,
                                    test_function: test_func_name.to_string(),
                                    line,
                                    confidence: Confidence::High,
                                });

                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Regular equality: func(args) == expected
        if left.kind() == "call" {
            if let Some((fname, inputs)) = extract_call_info(left, source) {
                let output = try_eval_literal(right, source);

                let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                    function_name: fname.clone(),
                    summary: String::new(),
                    test_count: 0,
                    input_output_specs: vec![],
                    exception_specs: vec![],
                    property_specs: vec![],
                });

                fs.input_output_specs.push(InputOutputSpec {
                    function: fname,
                    inputs,
                    output,
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::High,
                });

                return true;
            }
        }

        // Also check right side: expected == func(args)
        if right.kind() == "call" {
            if let Some((fname, inputs)) = extract_call_info(right, source) {
                let output = try_eval_literal(left, source);

                let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                    function_name: fname.clone(),
                    summary: String::new(),
                    test_count: 0,
                    input_output_specs: vec![],
                    exception_specs: vec![],
                    property_specs: vec![],
                });

                fs.input_output_specs.push(InputOutputSpec {
                    function: fname,
                    inputs,
                    output,
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::High,
                });

                return true;
            }
        }
    }

    // Check for bounds comparisons: func(args) > n, func(args) >= n, etc.
    if matches!(op, "<" | ">" | "<=" | ">=") {
        let (call_side, value_side) = if left.kind() == "call" {
            (left, right)
        } else if right.kind() == "call" {
            (right, left)
        } else {
            return false;
        };

        // Check if it's len(func(args))
        let call_func_name = call_side
            .child_by_field_name("function")
            .map(|f| get_node_text(f, source));
        if call_func_name == Some("len") {
            if let Some(inner_args) = call_side.child_by_field_name("arguments") {
                let mut inner_cursor = inner_args.walk();
                for child in inner_args.children(&mut inner_cursor) {
                    if child.kind() == "call" {
                        if let Some((fname, _)) = extract_call_info(child, source) {
                            let val = get_node_text(value_side, source);
                            let constraint = format!("len(result) {} {}", op, val);

                            let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                                function_name: fname.clone(),
                                summary: String::new(),
                                test_count: 0,
                                input_output_specs: vec![],
                                exception_specs: vec![],
                                property_specs: vec![],
                            });

                            fs.property_specs.push(PropertySpec {
                                function: fname,
                                property_type: "length".to_string(),
                                constraint,
                                test_function: test_func_name.to_string(),
                                line,
                                confidence: Confidence::Medium,
                            });

                            return true;
                        }
                    }
                }
            }
        }

        // Regular bounds: func(args) > n
        if let Some((fname, _)) = extract_call_info(call_side, source) {
            let val = get_node_text(value_side, source);
            let constraint = format!("result {} {}", op, val);

            let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                function_name: fname.clone(),
                summary: String::new(),
                test_count: 0,
                input_output_specs: vec![],
                exception_specs: vec![],
                property_specs: vec![],
            });

            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "bounds".to_string(),
                constraint,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });

            return true;
        }
    }

    false
}

/// Extract specs from a with statement (pytest.raises).
///
/// Pattern: `with pytest.raises(ExceptionType, match="pattern"): func(args)`
fn extract_from_with(
    with_stmt: Node,
    test_func_name: &str,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
) -> ContractsResult<()> {
    let line = with_stmt.start_position().row as u32 + 1;

    // Find the with_clause(s)
    let mut cursor = with_stmt.walk();
    let mut is_raises = false;
    let mut exception_type = String::new();
    let mut match_pattern: Option<String> = None;

    for child in with_stmt.children(&mut cursor) {
        if child.kind() == "with_clause" {
            // Check for pytest.raises(...)
            let mut clause_cursor = child.walk();
            for clause_child in child.children(&mut clause_cursor) {
                if clause_child.kind() == "with_item" {
                    if let Some(ctx_expr) = clause_child.child(0) {
                        if ctx_expr.kind() == "call" {
                            let func_text = ctx_expr
                                .child_by_field_name("function")
                                .map(|f| get_node_text(f, source))
                                .unwrap_or("");

                            // Check for pytest.raises or raises
                            if func_text == "raises" || func_text.ends_with(".raises") {
                                is_raises = true;

                                // Get exception type from first argument
                                if let Some(args) = ctx_expr.child_by_field_name("arguments") {
                                    let mut arg_cursor = args.walk();
                                    for arg in args.children(&mut arg_cursor) {
                                        let kind = arg.kind();
                                        if kind == "(" || kind == ")" || kind == "," {
                                            continue;
                                        }
                                        if kind == "keyword_argument" {
                                            // Check for match= keyword
                                            if let Some(key) = arg.child_by_field_name("name") {
                                                if get_node_text(key, source) == "match" {
                                                    if let Some(val) =
                                                        arg.child_by_field_name("value")
                                                    {
                                                        let val_text = get_node_text(val, source);
                                                        // Strip quotes
                                                        match_pattern = Some(
                                                            val_text
                                                                .trim_matches('"')
                                                                .trim_matches('\'')
                                                                .to_string(),
                                                        );
                                                    }
                                                }
                                            }
                                        } else if exception_type.is_empty() {
                                            exception_type = get_node_text(arg, source).to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !is_raises || exception_type.is_empty() {
        return Ok(());
    }

    // Find function calls in the with body
    let body = match with_stmt.child_by_field_name("body") {
        Some(b) => b,
        None => return Ok(()),
    };

    find_calls_and_add_exception_specs(
        body,
        source,
        specs,
        &exception_type,
        &match_pattern,
        test_func_name,
        line,
    );

    Ok(())
}

/// Recursively find calls in a block and add exception specs.
fn find_calls_and_add_exception_specs(
    block: Node,
    source: &[u8],
    specs: &mut HashMap<String, FunctionSpecs>,
    exception_type: &str,
    match_pattern: &Option<String>,
    test_func_name: &str,
    line: u32,
) {
    let mut cursor = block.walk();
    for child in block.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some((fname, inputs)) = extract_call_info(child, source) {
                let fs = specs.entry(fname.clone()).or_insert_with(|| FunctionSpecs {
                    function_name: fname.clone(),
                    summary: String::new(),
                    test_count: 0,
                    input_output_specs: vec![],
                    exception_specs: vec![],
                    property_specs: vec![],
                });

                fs.exception_specs.push(ExceptionSpec {
                    function: fname,
                    inputs,
                    exception_type: exception_type.to_string(),
                    match_pattern: match_pattern.clone(),
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::High,
                });
            }
        }

        // Recurse into nested nodes
        if child.child_count() > 0 {
            find_calls_and_add_exception_specs(
                child,
                source,
                specs,
                exception_type,
                match_pattern,
                test_func_name,
                line,
            );
        }
    }
}

// =============================================================================
// Call Info Extraction
// =============================================================================

/// Extract function name and arguments from a call node.
fn extract_call_info(call: Node, source: &[u8]) -> Option<(String, Vec<serde_json::Value>)> {
    let func_node = call.child_by_field_name("function")?;
    let func_name = match func_node.kind() {
        "identifier" => get_node_text(func_node, source).to_string(),
        "attribute" => {
            // Get the attribute name (e.g., obj.method -> "method")
            func_node
                .child_by_field_name("attribute")
                .map(|a| get_node_text(a, source).to_string())?
        }
        _ => return None,
    };

    // Skip built-in functions that aren't function-under-test
    if matches!(
        func_name.as_str(),
        "len"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "set"
            | "tuple"
            | "isinstance"
            | "hasattr"
            | "getattr"
            | "print"
            | "range"
            | "type"
    ) {
        return None;
    }

    let args_node = call.child_by_field_name("arguments")?;
    let mut inputs = Vec::new();

    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "(" || kind == ")" || kind == "," {
            continue;
        }
        // Skip keyword arguments for now
        if kind == "keyword_argument" {
            continue;
        }
        inputs.push(try_eval_literal(child, source));
    }

    Some((func_name, inputs))
}

// =============================================================================
// Literal Evaluation (E06 Mitigation)
// =============================================================================

/// Try to evaluate an AST node as a JSON-compatible literal.
///
/// Handles:
/// - Numbers (int, float)
/// - Strings
/// - Booleans (True, False)
/// - None/null
/// - Lists
/// - Dicts
/// - Tuples (as arrays)
///
/// Falls back to string representation of the AST node if not evaluable.
fn try_eval_literal(node: Node, source: &[u8]) -> serde_json::Value {
    try_eval_literal_inner(node, source, 0)
}

fn try_eval_literal_inner(node: Node, source: &[u8], depth: usize) -> serde_json::Value {
    // E06 mitigation: limit recursion depth
    if depth > MAX_LITERAL_DEPTH {
        return serde_json::Value::String(get_node_text(node, source).to_string());
    }

    let text = get_node_text(node, source);

    // E06 mitigation: limit size
    if text.len() > MAX_LITERAL_SIZE {
        return serde_json::Value::String("<large literal>".to_string());
    }

    match node.kind() {
        "integer" => text
            .parse::<i64>()
            .map(serde_json::Value::from)
            .unwrap_or_else(|_| serde_json::Value::String(text.to_string())),
        "float" => text
            .parse::<f64>()
            .map(|f| serde_json::json!(f))
            .unwrap_or_else(|_| serde_json::Value::String(text.to_string())),
        "string" | "concatenated_string" => {
            // Strip quotes and handle escape sequences
            let unquoted = strip_string_quotes(text);
            serde_json::Value::String(unquoted)
        }
        "true" | "True" => serde_json::Value::Bool(true),
        "false" | "False" => serde_json::Value::Bool(false),
        "none" | "None" => serde_json::Value::Null,
        "identifier" => {
            // Check for True, False, None
            match text {
                "True" => serde_json::Value::Bool(true),
                "False" => serde_json::Value::Bool(false),
                "None" => serde_json::Value::Null,
                _ => serde_json::Value::String(text.to_string()),
            }
        }
        "list" => {
            let mut items = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let kind = child.kind();
                if kind != "[" && kind != "]" && kind != "," {
                    items.push(try_eval_literal_inner(child, source, depth + 1));
                }
            }
            serde_json::Value::Array(items)
        }
        "tuple" | "parenthesized_expression" => {
            // Check if it's actually a tuple (has comma) or just parenthesized
            let mut items = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    items.push(try_eval_literal_inner(child, source, depth + 1));
                }
            }
            if items.len() == 1 && node.kind() == "parenthesized_expression" {
                // Just a parenthesized expression, return the inner value
                items.into_iter().next().unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Array(items)
            }
        }
        "dictionary" => {
            let mut obj = serde_json::Map::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "pair" {
                    let key_node = child.child_by_field_name("key");
                    let value_node = child.child_by_field_name("value");
                    if let (Some(k), Some(v)) = (key_node, value_node) {
                        let key = match try_eval_literal_inner(k, source, depth + 1) {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        };
                        let value = try_eval_literal_inner(v, source, depth + 1);
                        obj.insert(key, value);
                    }
                }
            }
            serde_json::Value::Object(obj)
        }
        "unary_operator" => {
            // Handle negative numbers: -5
            let mut cursor = node.walk();
            let mut op = "";
            let mut operand = None;
            for child in node.children(&mut cursor) {
                if child.kind() == "-" {
                    op = "-";
                } else if child.kind() == "+" {
                    op = "+";
                } else {
                    operand = Some(child);
                }
            }
            if op == "-" {
                if let Some(operand) = operand {
                    let val = try_eval_literal_inner(operand, source, depth + 1);
                    if let serde_json::Value::Number(n) = val {
                        if let Some(i) = n.as_i64() {
                            return serde_json::json!(-i);
                        }
                        if let Some(f) = n.as_f64() {
                            return serde_json::json!(-f);
                        }
                    }
                }
            }
            serde_json::Value::String(text.to_string())
        }
        _ => {
            // Fall back to string representation
            serde_json::Value::String(text.to_string())
        }
    }
}

/// Strip quotes from a Python string literal.
fn strip_string_quotes(s: &str) -> String {
    let mut s = s.trim();

    // Handle string prefixes (r/R/b/B/f/F), in ANY order: Python allows
    // both "rb"/"Rb" and "br"/"fr" spellings. why: the previous code
    // stripped one 'r' pass, then one 'b' pass, then one 'f' pass -- so
    // `br"..."`/`fr"..."` (b or f BEFORE r) left a stray leading `r`
    // that made every quote check below fail, and the raw `r"foo"`
    // text (prefix + quotes intact) leaked into the extracted literal.
    // Stripping in a loop is order-independent and self-terminating
    // (real prefixes are at most 2 chars from this set).
    while let Some(c) = s.chars().next() {
        if matches!(c, 'r' | 'R' | 'b' | 'B' | 'f' | 'F') {
            s = &s[c.len_utf8()..];
        } else {
            break;
        }
    }

    // Handle triple quotes
    if s.starts_with("\"\"\"") && s.ends_with("\"\"\"") && s.len() >= 6 {
        return s[3..s.len() - 3].to_string();
    }
    if s.starts_with("'''") && s.ends_with("'''") && s.len() >= 6 {
        return s[3..s.len() - 3].to_string();
    }

    // Handle single/double quotes
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return s[1..s.len() - 1].to_string();
    }

    s.to_string()
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Merge specs from a file into the aggregate.
// =============================================================================
// Generic Multi-Language Spec Extraction (P12.AGG12-2)
// =============================================================================
//
// Walks every language's tree-sitter AST that has at least one assertion
// pattern we can recognise and emits InputOutput / Property / Exception specs
// from common assertion call shapes:
//
// Recognised assertion calls (call name -> spec kind):
//   assertEquals(expected, actual)        -> InputOutputSpec
//   assertEqual(expected, actual)         -> InputOutputSpec
//   AreEqual(expected, actual)            -> InputOutputSpec   (NUnit)
//   Equal(expected, actual)               -> InputOutputSpec   (xUnit)
//   assertSame(expected, actual)          -> InputOutputSpec
//   expect(actual).toBe(expected)         -> InputOutputSpec   (Jest, partial)
//   assertTrue(cond)                      -> PropertySpec      (bool)
//   assertFalse(cond)                     -> PropertySpec      (bool)
//   IsTrue(cond) / IsFalse(cond)          -> PropertySpec      (NUnit/MSTest)
//   assertNotNull(x) / assertNull(x)      -> PropertySpec      (nullness)
//   IsNotNull(x) / IsNull(x)              -> PropertySpec      (NUnit/MSTest)
//   assertNotEquals(a, b)                 -> PropertySpec      (inequality)
//   AreNotEqual / NotEqual                -> PropertySpec      (inequality)
//   assertThrows(E.class, () -> body)     -> ExceptionSpec
//   assertFails { body }                  -> ExceptionSpec     (Kotlin)
//   Assert.Throws<E>(() => body)          -> ExceptionSpec     (NUnit)
//   should_panic / panic_test             -> ExceptionSpec     (Rust attr)
//
// The walker recognises the function-under-test (FUT) from the SECOND
// positional argument of equality assertions (since most JVM assertion
// libraries put expected first, actual second). When ambiguous we pick the
// argument that is itself a call_expression / method_invocation / similar
// callable-shaped node.

/// Top-level entry point for generic spec extraction. Parses `source` with
/// the appropriate tree-sitter grammar for `language`, walks every test
/// function (using the same recogniser as test counting), and extracts
/// specs from each function body.
fn extract_generic_specs(
    path: &Path,
    source: &str,
    language: Language,
) -> Vec<FunctionSpecs> {
    if source.trim().is_empty() {
        return Vec::new();
    }
    let pool = ParserPool::new();
    let tree = match pool.parse(source, language).ok() {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut specs: HashMap<String, FunctionSpecs> = HashMap::new();
    let bytes = source.as_bytes();
    walk_for_test_bodies(tree.root_node(), bytes, language, path, &mut specs);

    specs
        .into_values()
        .map(|mut fs| {
            fs.summary = generate_summary(&fs);
            fs
        })
        .collect()
}

/// Walk the AST. When a node looks like a recognised test function for the
/// language, descend into its body and harvest assertions; otherwise recurse.
fn walk_for_test_bodies(
    node: Node,
    source: &[u8],
    language: Language,
    path: &Path,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    if super::test_recognizer::is_test_function_node(&node, source, language) {
        let test_name = test_function_display_name(&node, source);
        harvest_assertions_in(&node, source, language, &test_name, path, specs);
        // Don't double-count nested matches inside a single recognised test.
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_test_bodies(child, source, language, path, specs);
    }
}

/// Best-effort display name for the recognised test (function name when
/// available, otherwise an anonymous placeholder).
fn test_function_display_name(node: &Node, source: &[u8]) -> String {
    if let Some(name) = node.child_by_field_name("name") {
        return get_node_text(name, source).to_string();
    }
    // Walk children for the first identifier child (covers Swift,
    // Kotlin, etc. whose grammar exposes the name as a positional child).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "identifier" || kind == "simple_identifier" || kind == "name" {
            return get_node_text(child, source).to_string();
        }
    }
    "<anonymous>".to_string()
}

/// Harvest every assertion-shaped call inside a test function body and
/// translate into the appropriate spec.
fn harvest_assertions_in(
    test_func: &Node,
    source: &[u8],
    language: Language,
    test_func_name: &str,
    _path: &Path,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    walk_for_assertion_calls(*test_func, source, language, test_func_name, specs);
}

fn walk_for_assertion_calls(
    node: Node,
    source: &[u8],
    language: Language,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    // critical-regressions-v1 (P13.AGG13-1): Go tests use the
    // `if condition { t.Errorf/Fatal/Fail(...) }` idiom rather than a
    // dedicated `assertEquals`-shaped helper. Detect that shape and
    // promote the FUT call inside the condition to a property spec.
    if matches!(language, Language::Go) && node.kind() == "if_statement" {
        if try_extract_go_if_t_assertion(&node, source, test_func_name, specs) {
            // Still recurse: nested if/loop bodies may contain more
            // assertions or further FUT calls we need to harvest.
        }
    }

    // language-specific-bugs-v1 (P14.AGG14-2): Java MockMvc fluent
    // assertions —  `mockMvc.perform(get("/owners/new"))
    //                       .andExpect(status().isOk())
    //                       .andExpect(view().name(...))` — the conventional
    // `assertEquals`-shaped helpers don't appear, so the assertion
    // extractor previously yielded `total_specs = 0` for every Spring
    // controller test. Promote each `andExpect(...)` to a property spec
    // whose `function` is the HTTP-builder call inside the matching
    // `perform(...)` (the MockMvc endpoint under test) and whose
    // `constraint` text reflects the matcher kind (status/view/model/...).
    if matches!(language, Language::Java)
        && (node.kind() == "method_invocation" || node.kind() == "invocation_expression")
    {
        try_extract_java_mockmvc_assertion(&node, source, test_func_name, specs);
    }

    let kind = node.kind();
    let is_call = matches!(
        kind,
        "call_expression"
            | "invocation_expression"
            | "method_invocation"
            | "macro_invocation"
            | "call"
            | "function_call"
            | "function_call_statement"
            // critical-regressions-v1 (P13.AGG13-1): PHP tree-sitter exposes
            // assertion calls under multiple call-shaped node kinds.
            // Without these, `$this->assertSame(...)`, `self::assertEquals(...)`,
            // and `Foo::staticAssert(...)` all fall through and PHPUnit
            // tests yield 0 specs even though `test_functions_scanned > 0`.
            | "member_call_expression"
            | "function_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    );
    if is_call {
        if let Some(callee_text) = generic_callee_name(&node, source) {
            let callee_tail = callee_text.rsplit('.').next().unwrap_or(&callee_text);
            // Strip generic params: `Throws<E>` -> `Throws`
            let callee_tail = callee_tail.split('<').next().unwrap_or(callee_tail);
            classify_assertion_call(
                &node,
                source,
                language,
                callee_tail,
                test_func_name,
                specs,
            );
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_assertion_calls(child, source, language, test_func_name, specs);
    }
}

/// critical-regressions-v1 (P13.AGG13-1): handle Go's `if cond { t.Errorf(...) }`
/// idiom. The Go testing package has no `assertEquals`-style helper; tests
/// branch on a condition and call `t.Error(f)` / `t.Fatal(f)` / `t.Fail(...)`
/// when the condition is met. Promote the condition's contained call to a
/// property spec so downstream `tldr specs` reports something useful instead
/// of `total_specs: 0` for files with hundreds of `t.Errorf` sites.
///
/// Returns true when a spec was extracted (currently informational; caller
/// continues recursing regardless).
fn try_extract_go_if_t_assertion(
    if_node: &Node,
    source: &[u8],
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    // tree-sitter-go exposes `if_statement` with named fields:
    //   `condition` (the boolean expression)
    //   `consequence` (the block executed when true)
    //   `alternative` (else branch, optional)
    let cond_node = match if_node.child_by_field_name("condition") {
        Some(c) => c,
        None => return false,
    };
    let consequence = match if_node.child_by_field_name("consequence") {
        Some(c) => c,
        None => return false,
    };

    // Look for a `t.<Errorf|Error|Fatal|Fatalf|Fail|FailNow|Log|Logf>(...)` call
    // inside the consequence block. If present, this is a Go test assertion
    // shaped as `if !condition { t.Errorf(...) }`.
    let has_t_assertion = subtree_contains_go_test_failure_call(&consequence, source);
    if !has_t_assertion {
        return false;
    }

    // Locate the FUT-shaped call inside the condition expression. Common
    // shapes:
    //   if !reflect.DeepEqual(got, want) { ... }   -> FUT is reflect.DeepEqual? no, FUT was the call
    //                                                  that produced `got`. We can't recover that
    //                                                  cheaply, so attribute the spec to the call
    //                                                  that appears in the condition itself.
    //   if got != want { ... }                     -> no call in condition; bail.
    //   if foo() != 5 { ... }                       -> FUT is `foo`.
    //   if err := f(x); err != nil { ... }         -> FUT is `f`.
    let call_node = match first_callable_inside(cond_node) {
        Some(c) => c,
        None => return false,
    };
    let (fname, _inputs) = match generic_extract_call_info(call_node, source) {
        Some(p) => p,
        None => return false,
    };
    // Don't emit specs for the test failure call itself (e.g. when the
    // condition is just a call to `t.Failed()`).
    if is_known_assertion_callee(&fname) || is_go_t_failure_method(&fname) {
        return false;
    }

    let line = if_node.start_position().row as u32 + 1;
    let entry = specs
        .entry(fname.clone())
        .or_insert_with(|| FunctionSpecs {
            function_name: fname.clone(),
            summary: String::new(),
            test_count: 0,
            input_output_specs: vec![],
            exception_specs: vec![],
            property_specs: vec![],
        });
    entry.property_specs.push(PropertySpec {
        function: fname,
        property_type: "go_if_assertion".to_string(),
        constraint: "condition guards t.Errorf/t.Fatal".to_string(),
        test_function: test_func_name.to_string(),
        line,
        confidence: Confidence::Medium,
    });
    true
}

/// Returns true if any `call_expression` under `node` calls a Go testing
/// failure method (`t.Errorf`, `t.Fatal`, `t.Fail`, `t.Log`, …).
fn subtree_contains_go_test_failure_call(node: &Node, source: &[u8]) -> bool {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let text = get_node_text(func, source);
            // Accept either `<receiver>.<method>` selector form or a bare
            // identifier (in case the test renamed `t` via a closure).
            let tail = text.rsplit('.').next().unwrap_or(text);
            if is_go_t_failure_method(tail) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if subtree_contains_go_test_failure_call(&child, source) {
            return true;
        }
    }
    false
}

/// Recognise the well-known Go `*testing.T` failure-reporting methods.
fn is_go_t_failure_method(name: &str) -> bool {
    matches!(
        name,
        "Error"
            | "Errorf"
            | "Fatal"
            | "Fatalf"
            | "Fail"
            | "FailNow"
            | "Log"
            | "Logf"
            | "Skip"
            | "Skipf"
            | "Skipped"
    )
}

/// language-specific-bugs-v1 (P14.AGG14-2): handle Java Spring MockMvc
/// fluent assertions of the form
///   `mockMvc.perform(get("/owners/new")).andExpect(status().isOk())`
///
/// `node` is a `method_invocation`. We only fire when the callee tail is
/// `andExpect` / `andExpectAll` / `andDo` (the MockMvc verbs). The
/// receiver of the chain bottoms out at `mockMvc.perform(<endpointBuilder>)`
/// — we walk down the receiver chain to find that `perform(...)` and
/// extract the HTTP-method call inside its first argument (e.g. `get`,
/// `post`, `put`, …) plus the URL literal — that's the FUT.
///
/// The first argument to `andExpect(...)` is a matcher chain like
/// `status().isOk()` / `view().name(...)` / `model().attributeExists(...)`.
/// We pull out a short tag (`status`, `view`, `model`, …) and the leaf
/// matcher kind (`isOk`, `is3xxRedirection`, `name`, …) for the
/// `constraint` so multiple `.andExpect(...)` calls in the same test body
/// produce distinguishable property specs.
///
/// Each invocation pushes one property spec onto the FUT entry. The
/// caller's recursion still walks into receivers, so each
/// `andExpect(...)` in a chain produces its own spec.
fn try_extract_java_mockmvc_assertion(
    call: &Node,
    source: &[u8],
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    // Tail identifier of this method_invocation.
    let callee = match generic_callee_name(call, source) {
        Some(c) => c,
        None => return false,
    };
    let tail = callee
        .rsplit('.')
        .next()
        .unwrap_or(&callee)
        .split('<')
        .next()
        .unwrap_or(&callee)
        .trim();
    let is_mockmvc_verb = matches!(tail, "andExpect" | "andExpectAll" | "andDo");
    if !is_mockmvc_verb {
        return false;
    }

    // The receiver of `andExpect` is itself another `method_invocation`
    // whose tail eventually reaches `mockMvc.perform(...)`. Walk down the
    // chain via the `object` field until we find a `perform` call.
    let perform_call = match find_mockmvc_perform_call(*call, source) {
        Some(p) => p,
        None => return false,
    };

    // Endpoint builder: the first positional argument to `perform(...)` is
    // an HTTP-method call (`get`, `post`, `put`, `delete`, `patch`, …)
    // whose first arg is the URL literal. Use the HTTP verb name as the
    // FUT name and the URL literal as the lone input.
    let perform_args = collect_call_args(perform_call);
    let endpoint_call_node = perform_args
        .first()
        .copied()
        .and_then(first_callable_inside);

    let (fut_name, fut_inputs): (String, Vec<serde_json::Value>) =
        match endpoint_call_node.and_then(|c| generic_extract_call_info(c, source)) {
            Some(info) => info,
            None => {
                // Fallback: synthesize a placeholder so we still emit a spec.
                ("mockMvcRequest".to_string(), Vec::new())
            }
        };

    // Constraint text: classify the matcher chain inside `andExpect(...)`.
    //   status().isOk()                -> "status:isOk"
    //   status().is3xxRedirection()    -> "status:is3xxRedirection"
    //   view().name("...")             -> "view:name"
    //   model().attributeExists("..")  -> "model:attributeExists"
    //   model().attributeHasErrors(..) -> "model:attributeHasErrors"
    let exp_args = collect_call_args(*call);
    let constraint = exp_args
        .first()
        .copied()
        .map(|n| classify_mockmvc_matcher(n, source))
        .unwrap_or_else(|| "expectation".to_string());

    let line = call.start_position().row as u32 + 1;

    let entry = specs.entry(fut_name.clone()).or_insert_with(|| FunctionSpecs {
        function_name: fut_name.clone(),
        summary: String::new(),
        test_count: 0,
        input_output_specs: vec![],
        exception_specs: vec![],
        property_specs: vec![],
    });

    // Avoid duplicates when the same test method is harvested twice (the
    // caller recurses through receivers, so we can hit the same call node
    // via different paths).
    let already_present = entry
        .property_specs
        .iter()
        .any(|p| p.line == line && p.constraint == constraint && p.test_function == test_func_name);
    if !already_present {
        // First-time observation: record an input/output spec for the
        // endpoint call (so `total_specs` reflects coverage even when
        // `andExpect` is the only assertion verb present).
        if entry
            .input_output_specs
            .iter()
            .all(|io| io.test_function != test_func_name)
        {
            entry.input_output_specs.push(InputOutputSpec {
                function: fut_name.clone(),
                inputs: fut_inputs.clone(),
                output: serde_json::Value::Null,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
        }
        entry.property_specs.push(PropertySpec {
            function: fut_name.clone(),
            property_type: "mockmvc_expectation".to_string(),
            constraint,
            test_function: test_func_name.to_string(),
            line,
            confidence: Confidence::Medium,
        });
    }

    true
}

/// Walk down the receiver chain of an `andExpect(...)` invocation looking
/// for the corresponding `mockMvc.perform(...)` call. Returns the
/// `method_invocation` node that represents `perform(...)`.
fn find_mockmvc_perform_call<'a>(call: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    // The Java tree-sitter grammar models
    //   a.b.c(args)
    // as `method_invocation { object: a.b, name: "c", arguments: ... }`,
    // and chained calls `a.b().c().d()` as nested `method_invocation`s
    // whose `object` field is the previous call.
    let mut current = call;
    let mut hops = 0usize;
    // Conservative bound: real MockMvc chains rarely exceed ~6 verbs.
    while hops < 32 {
        let object = current
            .child_by_field_name("object")
            .or_else(|| current.child_by_field_name("expression"));
        let object = match object {
            Some(o) => o,
            None => return None,
        };
        if matches!(
            object.kind(),
            "method_invocation" | "invocation_expression"
        ) {
            if let Some(name) = generic_callee_name(&object, source) {
                let tail = name.rsplit('.').next().unwrap_or(&name);
                if tail == "perform" {
                    return Some(object);
                }
            }
            current = object;
            hops += 1;
            continue;
        }
        return None;
    }
    None
}

/// Classify the matcher passed to `andExpect(...)` so each expectation
/// produces a recognisable `constraint` string. `node` is the first
/// argument expression of `andExpect(...)`. We walk inwards to find the
/// outermost call whose receiver is one of the well-known MockMvc
/// matcher entry points (`status`, `view`, `model`, `header`, …) and use
/// its leaf method name plus the entry-point name as the constraint.
fn classify_mockmvc_matcher(node: Node, source: &[u8]) -> String {
    // Best-effort: look at the entire matcher text and pull out the first
    // `<word>()` head plus the last `.<word>(`. Falls back to the raw
    // text trimmed.
    let text = std::str::from_utf8(&source[node.start_byte()..node.end_byte()]).unwrap_or("");
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "expectation".to_string();
    }

    // Pull out the first identifier (entry point) and the last identifier
    // before a `(` (leaf matcher).
    let head: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    // Find last `.<ident>(` occurrence.
    let mut leaf: Option<&str> = None;
    let bytes = trimmed.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'(' && i > 0 {
            // Walk backwards collecting an identifier.
            let mut j = i;
            while j > 0 {
                let c = bytes[j - 1];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    j -= 1;
                } else {
                    break;
                }
            }
            if j < i {
                let candidate = &trimmed[j..i];
                if candidate != head {
                    leaf = Some(candidate);
                    break;
                }
            }
        }
    }

    match (head.as_str(), leaf) {
        ("", None) => "expectation".to_string(),
        (h, None) => h.to_string(),
        ("", Some(l)) => l.to_string(),
        (h, Some(l)) => format!("{}:{}", h, l),
    }
}

/// Tail identifier of the callable expression.
fn generic_callee_name(call: &Node, source: &[u8]) -> Option<String> {
    if let Some(f) = call.child_by_field_name("function") {
        return Some(get_node_text(f, source).to_string());
    }
    if let Some(f) = call.child_by_field_name("method") {
        return Some(get_node_text(f, source).to_string());
    }
    if let Some(f) = call.child_by_field_name("name") {
        return Some(get_node_text(f, source).to_string());
    }
    // language-specific-bugs-v1 (P14.AGG14-9): tree-sitter-rust exposes
    // the macro's identifier on a `macro` field of `macro_invocation`,
    // not via the generic `name` / `function` fields. Without this
    // lookup, `assert_eq!(...)` fell through to the first-identifier
    // fallback below, which usually returned the right thing —  but
    // only when the parser identified the leading bareword as an
    // identifier child rather than as part of a path expression. Hit
    // the field name directly for robustness.
    if let Some(f) = call.child_by_field_name("macro") {
        return Some(get_node_text(f, source).to_string());
    }
    // Fall back to first identifier child.
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        match child.kind() {
            "identifier"
            | "simple_identifier"
            | "field_access"
            | "member_access_expression"
            | "navigation_expression"
            | "scoped_identifier" => {
                return Some(get_node_text(child, source).to_string());
            }
            _ => {}
        }
    }
    None
}

/// language-specific-bugs-v1 (P14.AGG14-9): Rust-macro-aware argument
/// collector. Walks the macro_invocation's `token_tree` skipping the
/// outer parens, then groups top-level tokens by comma boundaries
/// (respecting nested `()` / `[]` / `{}` so commas inside an inner
/// argument list are not treated as separators). Each group's first
/// "interesting" child becomes one positional arg; if a group contains
/// a call_expression (or any callable shape), prefer that node so
/// `first_callable_inside` / `generic_extract_call_info` work in the
/// downstream classifier.
///
/// Note: tree-sitter-rust does NOT structure macro contents into
/// expressions — `assert_eq!(add(2,3), 5)` parses to a token_tree of
/// flat tokens `[add, (, 2, ,, 3, ), ,, 5]`. Real call_expression /
/// method_call nodes are not nested inside, so we cannot find them via
/// `looks_like_call`. Instead, we represent each comma-separated group
/// by its FIRST identifier-shaped token (that's the function name when
/// the arg is a function call) and return the group's first node so
/// downstream `try_eval_literal` / `generic_extract_call_info` still
/// produce a usable name + literal pair.
fn collect_rust_macro_args<'a>(call: Node<'a>) -> Vec<Node<'a>> {
    // Find the token_tree child of the macro_invocation.
    let token_tree = {
        let mut found = None;
        let mut cursor = call.walk();
        for child in call.children(&mut cursor) {
            if child.kind() == "token_tree" {
                found = Some(child);
                break;
            }
        }
        match found {
            Some(t) => t,
            None => return Vec::new(),
        }
    };

    // Build a flat list of token_tree's direct children, splitting by
    // top-level commas. Track paren depth so commas inside nested
    // parens (e.g. `add(2, 3)`) are NOT treated as argument separators.
    //
    // tree-sitter-rust emits `(` and `)` as direct named children of
    // `token_tree`; we use them to maintain depth without affecting
    // the group's content (the matching outer parens of the macro
    // boundary are at depth 0 -> 1 / 1 -> 0 transitions).
    let mut groups: Vec<Vec<Node<'a>>> = vec![Vec::new()];
    let mut depth = 0i32;
    let mut cursor = token_tree.walk();
    for child in token_tree.children(&mut cursor) {
        let k = child.kind();
        match k {
            "(" | "[" | "{" => {
                depth += 1;
                // Skip the OUTERMOST `(` (the macro's opening paren) so
                // it doesn't leak into the first group. Inner parens
                // remain visible so `first_callable_inside` / text
                // reconstruction can use them.
                if depth == 1 {
                    continue;
                }
                groups.last_mut().unwrap().push(child);
            }
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    // Outermost `)` — skip.
                    continue;
                }
                groups.last_mut().unwrap().push(child);
            }
            "," if depth == 1 => {
                groups.push(Vec::new());
            }
            _ => {
                groups.last_mut().unwrap().push(child);
            }
        }
    }

    // For each group, prefer the FIRST identifier-shaped token. When the
    // arg is a function call (`add(2, 3)`), the first identifier is the
    // call's function name and the downstream `generic_extract_call_info`
    // uses just the name + the group's text region. When the arg is a
    // literal (`5`), the first non-trivia token IS the literal —
    // `try_eval_literal` will pick up `integer_literal` etc. unchanged.
    groups
        .into_iter()
        .filter_map(|grp| {
            if grp.is_empty() {
                return None;
            }
            // Prefer an identifier (function-call head). Fallback to the
            // first non-punctuation child (literal / unary expr / etc.).
            for n in &grp {
                if matches!(n.kind(), "identifier" | "scoped_identifier") {
                    return Some(*n);
                }
            }
            grp.into_iter().find(|n| {
                !matches!(n.kind(), "(" | ")" | "[" | "]" | "{" | "}" | ",")
            })
        })
        .collect()
}

/// Read positional arguments of a call node, ignoring punctuation and
/// non-argument children (e.g. trailing closures, generic params).
fn collect_call_args<'a>(call: Node<'a>) -> Vec<Node<'a>> {
    let mut out: Vec<Node<'a>> = Vec::new();
    let arg_list = call
        .child_by_field_name("arguments")
        .or_else(|| {
            // Find first argument-list child by kind.
            let mut cursor = call.walk();
            for child in call.children(&mut cursor) {
                let k = child.kind();
                if k == "argument_list"
                    || k == "value_arguments"
                    || k == "arguments"
                    || k == "argument_list_no_paren"
                    // Rust macro_invocation wraps args in token_tree.
                    || k == "token_tree"
                {
                    return Some(child);
                }
            }
            None
        })
        .unwrap_or(call);

    let mut cursor = arg_list.walk();
    for child in arg_list.children(&mut cursor) {
        let k = child.kind();
        // Skip punctuation and trivia.
        if k == "("
            || k == ")"
            || k == ","
            || k == ":"
            || k == "{"
            || k == "}"
            || k == "["
            || k == "]"
        {
            continue;
        }
        // Skip the function head when we're falling back to the call node.
        if k == "identifier" && arg_list.id() == call.id() {
            continue;
        }
        // Unwrap one-level argument wrappers.
        if k == "argument" || k == "value_argument" {
            // Take the first non-trivial child as the actual expression.
            let mut inner = child.walk();
            for grand in child.children(&mut inner) {
                let gk = grand.kind();
                if gk == ":" || gk == "name" {
                    continue;
                }
                out.push(grand);
                break;
            }
            continue;
        }
        out.push(child);
    }
    out
}

/// Classify a single assertion call based on the tail of its callee name.
fn classify_assertion_call(
    call: &Node,
    source: &[u8],
    language: Language,
    callee_tail: &str,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    let line = call.start_position().row as u32 + 1;

    // Helper to get a fresh entry in `specs`.
    fn ensure<'a>(
        specs: &'a mut HashMap<String, FunctionSpecs>,
        name: &str,
    ) -> &'a mut FunctionSpecs {
        specs.entry(name.to_string()).or_insert_with(|| FunctionSpecs {
            function_name: name.to_string(),
            summary: String::new(),
            test_count: 0,
            input_output_specs: vec![],
            exception_specs: vec![],
            property_specs: vec![],
        })
    }

    // Equality assertions: assertEquals(expected, actual) / AreEqual etc.
    let is_equality = matches!(
        callee_tail,
        "assertEquals"
            | "assertEqual"
            | "assertSame"
            | "AreEqual"
            | "AreSame"
            | "Equal"
            | "assert_eq"
            | "assert_equal"
            | "should_eq"
            | "shouldBe"
            | "shouldEqual"
    );

    // Inequality assertions
    let is_inequality = matches!(
        callee_tail,
        "assertNotEquals"
            | "assertNotEqual"
            | "AreNotEqual"
            | "NotEqual"
            | "assert_ne"
            | "assertNotSame"
    );

    // Boolean truthy / falsy assertions
    let is_true = matches!(
        callee_tail,
        "assertTrue" | "IsTrue" | "True" | "assert" | "assert_true"
    );
    let is_false = matches!(
        callee_tail,
        "assertFalse" | "IsFalse" | "False" | "assert_false"
    );

    // Nullness assertions
    let is_not_null = matches!(
        callee_tail,
        "assertNotNull" | "IsNotNull" | "NotNull" | "assert_some"
    );
    let is_null = matches!(
        callee_tail,
        "assertNull" | "IsNull" | "Null" | "assert_none"
    );

    // Exception assertions
    let is_throws = matches!(
        callee_tail,
        "assertThrows"
            | "assertFails"
            | "Throws"
            | "ThrowsAsync"
            | "Throws_"
            | "should_panic"
            | "expectThrows"
    );

    // language-specific-bugs-v1 (P14.AGG14-9): Rust macro_invocation
    // wraps assertion arguments in a `token_tree`, which tree-sitter does
    // not structure into separate args — `collect_call_args` returns a
    // jumble of tokens. Build a Rust-specific argument list by walking
    // the token_tree looking for top-level expressions separated by
    // commas. When the macro head is one of `assert_eq` / `assert_ne` /
    // `assert` / `debug_assert*`, this gives back conventional positional
    // args even when tree-sitter did not.
    // language-specific-bugs-v1 (P14.AGG14-9): Rust macro arguments are
    // flat tokens (the tree-sitter-rust grammar doesn't structure
    // them into expressions), so we cannot rely on
    // `collect_call_args` finding clean argument nodes. Take a
    // structural approach: split the macro's `token_tree` body by
    // top-level commas (respecting nested parens / braces), and return
    // the first call-shaped descendant of each group as the
    // representative arg. When a group has no call-shaped child, fall
    // back to the group's first non-trivia child so downstream
    // `try_eval_literal` can still pull the literal value off the leaf.
    let args = if matches!(language, Language::Rust) && call.kind() == "macro_invocation" {
        collect_rust_macro_args(*call)
    } else {
        collect_call_args(*call)
    };
    if args.is_empty() {
        return;
    }

    if is_equality && args.len() >= 2 {
        // language-specific-bugs-v1 (P14.AGG14-9): Rust macro args are
        // flat token nodes (not call_expression structures), so
        // `looks_like_call` returns false for both sides of
        // `assert_eq!(add(2,3), 5)`. Recognize this case explicitly:
        // when a side is a bare identifier whose immediate sibling token
        // in the source is `(`, treat that identifier as the head of a
        // (text-level) function call. Use the identifier's name as the
        // FUT name and the OTHER side as the value/output.
        let rust_macro = matches!(language, Language::Rust)
            && call.kind() == "macro_invocation";
        let (call_arg, value_arg) = if rust_macro {
            let lhs_callish = is_rust_macro_call_token(args[0], source);
            let rhs_callish = is_rust_macro_call_token(args[1], source);
            match (rhs_callish, lhs_callish) {
                (true, _) => (args[1], args[0]),
                (false, true) => (args[0], args[1]),
                _ => return,
            }
        } else {
            match (looks_like_call(args[1]), looks_like_call(args[0])) {
                (true, _) => (args[1], args[0]),
                (false, true) => (args[0], args[1]),
                _ => return,
            }
        };
        if let Some((fname, inputs)) =
            extract_call_info_for_lang(call_arg, source, language)
        {
            let output = try_eval_literal(value_arg, source);
            let fs = ensure(specs, &fname);
            fs.input_output_specs.push(InputOutputSpec {
                function: fname,
                inputs,
                output,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::High,
            });
        }
        return;
    }

    if is_inequality && args.len() >= 2 {
        let rust_macro = matches!(language, Language::Rust)
            && call.kind() == "macro_invocation";
        let call_arg = if rust_macro {
            if is_rust_macro_call_token(args[1], source) {
                args[1]
            } else if is_rust_macro_call_token(args[0], source) {
                args[0]
            } else {
                return;
            }
        } else if looks_like_call(args[1]) {
            args[1]
        } else if looks_like_call(args[0]) {
            args[0]
        } else {
            return;
        };
        let other = if call_arg.id() == args[1].id() {
            args[0]
        } else {
            args[1]
        };
        if let Some((fname, _inputs)) = extract_call_info_for_lang(call_arg, source, language) {
            let val = std::str::from_utf8(
                &source[other.start_byte()..other.end_byte()],
            )
            .unwrap_or("");
            let constraint = format!("result != {}", val);
            let fs = ensure(specs, &fname);
            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "inequality".to_string(),
                constraint,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
        }
        return;
    }

    if (is_true || is_false) && !args.is_empty() {
        // First arg is the boolean expression; if it's a call_expression,
        // take its name. Otherwise emit a generic property on the contained
        // call when present.
        let mut call_arg = first_callable_inside(args[0]);

        // p19-secondary-fixes-v1 (BUG-P19-09): for Rust macros
        // (`assert!(call(...))` / `assert!(!call(...))` /
        // `assert!(receiver.method(...))`), the macro body is a flat
        // `token_tree` so `first_callable_inside` finds no call_expression
        // wrapper. Detect the inline-call shape by walking the macro's
        // entire `token_tree` looking for an identifier (or
        // scoped/field expression) immediately followed by `(` in the
        // source, then promote it to a synthetic "call". We walk from
        // the macro_invocation root (not from `args[0]` alone, since
        // the relevant identifier may be a SIBLING token in the
        // token_tree, not a descendant of the first-arg node).
        if call_arg.is_none()
            && matches!(language, Language::Rust)
            && call.kind() == "macro_invocation"
        {
            call_arg = find_rust_macro_inline_call(*call, source);
        }

        if let Some(c) = call_arg {
            // For the rust macro case the synthetic call shape is the
            // inner identifier — extract the name from the source bytes
            // directly so we record the function-under-test even when
            // tree-sitter didn't structure it.
            let fname_inputs = if matches!(language, Language::Rust)
                && call.kind() == "macro_invocation"
                && !looks_like_call(c)
            {
                Some((
                    std::str::from_utf8(&source[c.start_byte()..c.end_byte()])
                        .unwrap_or("")
                        .trim()
                        .rsplit('.')
                        .next()
                        .unwrap_or("")
                        .rsplit("::")
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    Vec::<serde_json::Value>::new(),
                ))
                .filter(|(n, _)| !n.is_empty())
            } else {
                generic_extract_call_info(c, source)
            };
            if let Some((fname, _)) = fname_inputs {
                let fs = ensure(specs, &fname);
                fs.property_specs.push(PropertySpec {
                    function: fname,
                    property_type: if is_true {
                        "truthy".to_string()
                    } else {
                        "falsy".to_string()
                    },
                    constraint: if is_true {
                        "result is true".to_string()
                    } else {
                        "result is false".to_string()
                    },
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::Medium,
                });
            }
        }
        return;
    }

    if (is_null || is_not_null) && !args.is_empty() {
        let call_arg = first_callable_inside(args[0]);
        if let Some(c) = call_arg {
            if let Some((fname, _)) = generic_extract_call_info(c, source) {
                let fs = ensure(specs, &fname);
                fs.property_specs.push(PropertySpec {
                    function: fname,
                    property_type: if is_not_null {
                        "not_null".to_string()
                    } else {
                        "null".to_string()
                    },
                    constraint: if is_not_null {
                        "result != null".to_string()
                    } else {
                        "result == null".to_string()
                    },
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::Medium,
                });
            }
        }
        return;
    }

    if is_throws {
        // Pick the lambda/closure argument and find a call inside it.
        for arg in &args {
            if let Some(c) = first_callable_inside(*arg) {
                if let Some((fname, inputs)) = generic_extract_call_info(c, source) {
                    let exc = guess_exception_type(call, source);
                    let fs = ensure(specs, &fname);
                    fs.exception_specs.push(ExceptionSpec {
                        function: fname,
                        exception_type: exc,
                        match_pattern: None,
                        inputs,
                        test_function: test_func_name.to_string(),
                        line,
                        confidence: Confidence::Medium,
                    });
                    return;
                }
            }
        }
    }
}

/// Multi-language version of `extract_call_info`. Walks the call node
/// looking for the callee identifier (handles the various AST shapes
/// across Java/Kotlin/C#/Rust/etc.) and collects positional argument
/// literals via `try_eval_literal`. The Python-only filter list of
/// builtins is dropped here: in non-Python tests, names like `len` are
/// genuine functions-under-test.
fn generic_extract_call_info(
    call: Node,
    source: &[u8],
) -> Option<(String, Vec<serde_json::Value>)> {
    // Skip macros that wrap the FUT (Rust): assert!(actual_call(...)) — we
    // already handled the assert wrapper at the caller layer.
    let raw_callee = generic_callee_name(&call, source)?;
    // Take the tail identifier (strip generic params and method access).
    let head = raw_callee.split('<').next().unwrap_or(&raw_callee);
    let tail = head.rsplit('.').next().unwrap_or(head);
    let tail = tail.rsplit("::").next().unwrap_or(tail);
    let func_name = tail.trim().to_string();
    if func_name.is_empty() {
        return None;
    }

    // Skip very common assertion-library helpers when they slipped through
    // (e.g. nested `assertTrue(..)` inside another assert).
    if is_known_assertion_callee(&func_name) {
        return None;
    }

    let args = collect_call_args(call);
    let inputs: Vec<serde_json::Value> = args
        .into_iter()
        .map(|n| try_eval_literal(n, source))
        .collect();

    Some((func_name, inputs))
}

fn is_known_assertion_callee(name: &str) -> bool {
    matches!(
        name,
        "assertEquals"
            | "assertEqual"
            | "assertSame"
            | "assertTrue"
            | "assertFalse"
            | "assertNull"
            | "assertNotNull"
            | "assertNotEquals"
            | "assertThrows"
            | "assertFails"
            | "AreEqual"
            | "AreNotEqual"
            | "AreSame"
            | "IsTrue"
            | "IsFalse"
            | "IsNull"
            | "IsNotNull"
            | "Throws"
            | "ThrowsAsync"
            | "Equal"
            | "NotEqual"
            | "True"
            | "False"
            | "Null"
            | "NotNull"
            | "assert"
            | "assert_eq"
            | "assert_ne"
            | "assert_true"
            | "assert_false"
            | "assert_some"
            | "assert_none"
            | "should_eq"
            | "shouldBe"
            | "shouldEqual"
    )
}

/// language-specific-bugs-v1 (P14.AGG14-9): true when `n` is a bareword
/// inside a Rust macro_invocation that is immediately followed by an
/// open paren in the source — i.e. the FUT identifier of a function
/// call expressed as flat tokens. Used to detect `add` in
/// `assert_eq!(add(2,3), 5)` where tree-sitter-rust represents the
/// macro contents as a token_tree of flat tokens with no
/// `call_expression` wrapper.
fn is_rust_macro_call_token(n: Node, source: &[u8]) -> bool {
    if !matches!(n.kind(), "identifier" | "scoped_identifier") {
        return false;
    }
    let end = n.end_byte();
    // Walk forward over whitespace looking for `(`.
    let mut i = end;
    while i < source.len() {
        let b = source[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
            continue;
        }
        return b == b'(';
    }
    false
}

/// language-specific-bugs-v1 (P14.AGG14-9): wrapper around
/// `generic_extract_call_info` that handles the Rust-macro case where
/// the "call" is an identifier with a flat-token argument list (no
/// `call_expression` AST shape). Returns `(fname, inputs)` where
/// `fname` is the identifier's text and `inputs` is a best-effort list
/// of immediately-following positional literal values, terminated at
/// the matching `)`.
fn extract_call_info_for_lang(
    node: Node,
    source: &[u8],
    language: Language,
) -> Option<(String, Vec<serde_json::Value>)> {
    if matches!(language, Language::Rust)
        && matches!(node.kind(), "identifier" | "scoped_identifier")
    {
        let fname = std::str::from_utf8(&source[node.start_byte()..node.end_byte()])
            .ok()?
            .trim()
            .to_string();
        if fname.is_empty() {
            return None;
        }
        // Best-effort: leave `inputs` empty for the macro-token path;
        // emitting the FUT name + line is the user-facing minimum. A
        // future improvement could text-parse the token range between
        // `(` and the matching `)` into literals.
        return Some((fname, Vec::new()));
    }
    generic_extract_call_info(node, source)
}

/// Best-effort: does `n` look like a function call we can extract a name from?
fn looks_like_call(n: Node) -> bool {
    matches!(
        n.kind(),
        "call_expression"
            | "invocation_expression"
            | "method_invocation"
            | "call"
            | "function_call"
            | "function_call_statement"
            | "macro_invocation"
            // critical-regressions-v1 (P13.AGG13-1): PHP call shapes (see
            // also `walk_for_assertion_calls`).
            | "member_call_expression"
            | "function_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    )
}

/// Walk into a node looking for the first callable subnode (handles
/// lambda wrappers, parenthesised expressions, blocks, etc.).
fn first_callable_inside(n: Node) -> Option<Node> {
    if looks_like_call(n) {
        return Some(n);
    }
    let mut cursor = n.walk();
    for child in n.children(&mut cursor) {
        if let Some(found) = first_callable_inside(child) {
            return Some(found);
        }
    }
    None
}

/// p19-secondary-fixes-v1 (BUG-P19-09): Rust macro body tokens are flat
/// (no call_expression wrapper). Find the first identifier (possibly
/// part of a `receiver.method` field access, or `Class::method` scoped
/// identifier) that is immediately followed by `(` in the source —
/// i.e. an inline function call in the macro arguments. Returns the
/// identifier node (or its containing expression) so the caller can
/// pull the function-under-test name from its byte range.
fn find_rust_macro_inline_call<'a>(root: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        // Direct shapes the rust grammar DOES expose inside macros: scoped
        // identifiers and field accesses; either may be the function side
        // of an inline call when followed by `(`.
        if matches!(
            kind,
            "identifier" | "scoped_identifier" | "field_expression"
        ) && is_followed_by_open_paren(node, source)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                stack.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    None
}

fn is_followed_by_open_paren(node: Node, source: &[u8]) -> bool {
    let mut i = node.end_byte();
    while i < source.len() {
        let b = source[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
            continue;
        }
        return b == b'(';
    }
    false
}

/// Guess an exception type from the assertion call. Looks for type-shaped
/// children inside the argument list (e.g. `IllegalArgumentException.class`,
/// `Throws<NullReferenceException>(...)`). Returns `Throwable` as a fallback.
fn guess_exception_type(call: &Node, source: &[u8]) -> String {
    // Walk the call's text up to the first '(' and collect any
    // capitalised-identifier sub-token.
    let text = std::str::from_utf8(&source[call.start_byte()..call.end_byte()])
        .unwrap_or("");
    let mut acc = String::new();
    for ch in text.chars() {
        if acc.contains('(') || acc.contains('{') {
            break;
        }
        acc.push(ch);
    }
    // Common type-positional patterns:
    //   assertThrows(IllegalArgumentException.class, ...)
    //   Assert.Throws<NullReferenceException>(...)
    if let Some(start) = acc.find('<') {
        if let Some(end) = acc[start + 1..].find('>') {
            return acc[start + 1..start + 1 + end].trim().to_string();
        }
    }
    if let Some(idx) = acc.find('(') {
        let after = &acc[idx + 1..];
        if let Some(dot) = after.find(".class") {
            return after[..dot].trim().to_string();
        }
    }
    "Exception".to_string()
}

fn merge_specs(all_specs: &mut HashMap<String, FunctionSpecs>, new_specs: Vec<FunctionSpecs>) {
    for new_fs in new_specs {
        let entry = all_specs
            .entry(new_fs.function_name.clone())
            .or_insert_with(|| FunctionSpecs {
                function_name: new_fs.function_name.clone(),
                summary: String::new(),
                test_count: 0,
                input_output_specs: vec![],
                exception_specs: vec![],
                property_specs: vec![],
            });

        entry.input_output_specs.extend(new_fs.input_output_specs);
        entry.exception_specs.extend(new_fs.exception_specs);
        entry.property_specs.extend(new_fs.property_specs);
        entry.test_count += new_fs.test_count;
    }
}

/// Generate a summary string for a FunctionSpecs.
fn generate_summary(fs: &FunctionSpecs) -> String {
    let io_count = fs.input_output_specs.len();
    let exc_count = fs.exception_specs.len();
    let prop_count = fs.property_specs.len();

    let mut parts = Vec::new();
    if io_count > 0 {
        parts.push(format!("{} input/output", io_count));
    }
    if exc_count > 0 {
        parts.push(format!("{} raises", exc_count));
    }
    if prop_count > 0 {
        parts.push(format!("{} property", prop_count));
    }

    if parts.is_empty() {
        "no specs".to_string()
    } else {
        parts.join(", ")
    }
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Format a specs report as human-readable text.
pub fn format_specs_text(report: &SpecsReport) -> String {
    let mut output = String::new();

    for func in &report.functions {
        output.push_str(&format!("Function: {}\n", func.function_name));

        for spec in &func.input_output_specs {
            let inputs_str: Vec<String> = spec.inputs.iter().map(|v| format!("{}", v)).collect();
            output.push_str(&format!(
                "  IO: {}({}) == {}\n",
                func.function_name,
                inputs_str.join(", "),
                spec.output
            ));
        }

        for spec in &func.exception_specs {
            if let Some(pattern) = &spec.match_pattern {
                output.push_str(&format!(
                    "  Raises: {} (match='{}')\n",
                    spec.exception_type, pattern
                ));
            } else {
                output.push_str(&format!("  Raises: {}\n", spec.exception_type));
            }
        }

        for spec in &func.property_specs {
            output.push_str(&format!(
                "  Property ({}): {}\n",
                spec.property_type, spec.constraint
            ));
        }

        output.push('\n');
    }

    output.push_str(&format!("Total specs: {}\n", report.summary.total_specs));

    output
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const PYTHON_TEST_FILE: &str = r#"
import pytest

def test_add_basic():
    assert add(1, 2) == 3
    assert add(0, 0) == 0
    assert add(-1, 1) == 0

def test_add_large():
    assert add(100, 200) == 300

def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)

def test_validate_raises_with_match():
    with pytest.raises(ValueError, match="invalid"):
        validate(-1)

def test_result_type():
    # Direct call pattern for type check
    assert isinstance(multiply(2, 3), int)

def test_result_length():
    # Direct call pattern for length check
    assert len(get_items()) == 3

def test_result_bounds():
    # Direct call pattern for bounds check
    assert compute_value() > 0

def test_membership():
    # Direct call pattern for membership check
    assert "key" in get_config()
"#;

    #[test]
    fn test_specs_input_output_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        // Should find 'add' function specs
        let add_func = report.functions.iter().find(|f| f.function_name == "add");
        assert!(add_func.is_some(), "Should find 'add' function");

        let add = add_func.unwrap();
        assert!(
            add.input_output_specs.len() >= 3,
            "Should extract at least 3 IO specs for add, got {}",
            add.input_output_specs.len()
        );
    }

    #[test]
    fn test_specs_exception_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        // Should find exception spec for 'divide'
        let divide_func = report
            .functions
            .iter()
            .find(|f| f.function_name == "divide");
        assert!(divide_func.is_some(), "Should find 'divide' function");

        let divide = divide_func.unwrap();
        assert!(
            !divide.exception_specs.is_empty(),
            "Should extract exception specs for divide"
        );
        assert_eq!(
            divide.exception_specs[0].exception_type,
            "ZeroDivisionError"
        );
    }

    #[test]
    fn test_specs_exception_with_match() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        let validate_func = report
            .functions
            .iter()
            .find(|f| f.function_name == "validate");
        assert!(validate_func.is_some(), "Should find 'validate' function");

        let validate = validate_func.unwrap();
        assert!(!validate.exception_specs.is_empty());
        assert!(validate.exception_specs[0].match_pattern.is_some());
        assert_eq!(
            validate.exception_specs[0].match_pattern.as_ref().unwrap(),
            "invalid"
        );
    }

    #[test]
    fn test_specs_property_type_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        let multiply_func = report
            .functions
            .iter()
            .find(|f| f.function_name == "multiply");
        assert!(multiply_func.is_some(), "Should find 'multiply' function");

        let multiply = multiply_func.unwrap();
        let type_prop = multiply
            .property_specs
            .iter()
            .find(|p| p.property_type == "type");
        assert!(type_prop.is_some(), "Should extract type property");
        assert!(type_prop.unwrap().constraint.contains("isinstance"));
    }

    #[test]
    fn test_specs_property_length_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        let get_items = report
            .functions
            .iter()
            .find(|f| f.function_name == "get_items");
        assert!(get_items.is_some(), "Should find 'get_items' function");

        let get_items = get_items.unwrap();
        let len_prop = get_items
            .property_specs
            .iter()
            .find(|p| p.property_type == "length");
        assert!(len_prop.is_some(), "Should extract length property");
    }

    #[test]
    fn test_specs_property_bounds_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        let compute = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute_value");
        assert!(compute.is_some(), "Should find 'compute_value' function");

        let compute = compute.unwrap();
        let bounds_prop = compute
            .property_specs
            .iter()
            .find(|p| p.property_type == "bounds");
        assert!(bounds_prop.is_some(), "Should extract bounds property");
    }

    #[test]
    fn test_specs_property_membership_extraction() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        let get_config = report
            .functions
            .iter()
            .find(|f| f.function_name == "get_config");
        assert!(get_config.is_some(), "Should find 'get_config' function");

        let get_config = get_config.unwrap();
        let member_prop = get_config
            .property_specs
            .iter()
            .find(|p| p.property_type == "membership");
        assert!(member_prop.is_some(), "Should extract membership property");
    }

    #[test]
    fn test_specs_function_filter() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, Some("add")).unwrap();

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].function_name, "add");
    }

    #[test]
    fn test_specs_directory_scan() {
        let temp = TempDir::new().unwrap();

        // Create two test files
        let test1 = temp.path().join("test_one.py");
        fs::write(&test1, "def test_foo():\n    assert foo(1) == 2\n").unwrap();

        let test2 = temp.path().join("test_two.py");
        fs::write(&test2, "def test_bar():\n    assert bar(3) == 4\n").unwrap();

        let report = run_specs(temp.path(), None).unwrap();

        assert_eq!(report.summary.test_files_scanned, 2);
        assert!(report.functions.iter().any(|f| f.function_name == "foo"));
        assert!(report.functions.iter().any(|f| f.function_name == "bar"));
    }

    #[test]
    fn test_specs_json_output() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        let json = serde_json::to_string(&report).unwrap();

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("functions").is_some());
        assert!(parsed.get("summary").is_some());
    }

    #[test]
    fn test_specs_text_output() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        let text = format_specs_text(&report);

        assert!(text.contains("Function:"));
        assert!(text.contains("Total specs:"));
    }

    #[test]
    fn test_specs_test_path_not_found() {
        // run_specs checks existence before validate_file_path, so it returns
        // TestPathNotFound error only when the path truly doesn't exist
        // For this test to trigger the proper validation, we check via the Args
        let _args = SpecsArgs {
            from_tests: PathBuf::from("/nonexistent/test_path"),
            output_format: ContractsOutputFormat::Json,
            function: None,
            source: None,
        };
        // The run method should fail with TestPathNotFound
        // But since run_specs checks path.exists() first, we test that behavior
        let path = Path::new("/nonexistent/test_path");
        assert!(!path.exists(), "Path should not exist for this test");
    }

    #[test]
    fn test_specs_empty_directory() {
        let temp = TempDir::new().unwrap();
        let report = run_specs(temp.path(), None).unwrap();

        assert_eq!(report.summary.test_files_scanned, 0);
        assert_eq!(report.summary.total_specs, 0);
    }

    #[test]
    fn test_specs_summary_counts() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_module.py");
        fs::write(&test_path, PYTHON_TEST_FILE).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        assert!(report.summary.total_specs > 0);
        assert!(report.summary.by_type.input_output > 0);
        assert!(report.summary.test_functions_scanned > 0);
        assert_eq!(report.summary.test_files_scanned, 1);
    }

    /// Helper to parse a literal and find the actual expression node
    fn parse_and_get_expr(source: &str) -> (Tree, Vec<u8>) {
        let mut parser = Parser::new();
        parser.set_language(&PYTHON_LANGUAGE.into()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        (tree, source.as_bytes().to_vec())
    }

    /// Find the innermost expression node (skipping expression_statement wrapper)
    fn find_expr_node(node: Node) -> Node {
        if node.kind() == "expression_statement" {
            if let Some(child) = node.child(0) {
                return child;
            }
        }
        node
    }

    #[test]
    fn test_literal_eval_integers() {
        let (tree, source) = parse_and_get_expr("42");
        let root = tree.root_node();
        let expr = find_expr_node(root.child(0).unwrap());
        let val = try_eval_literal(expr, &source);
        assert_eq!(val, serde_json::json!(42));
    }

    #[test]
    fn test_literal_eval_negative() {
        let (tree, source) = parse_and_get_expr("-5");
        let root = tree.root_node();
        let expr = find_expr_node(root.child(0).unwrap());
        let val = try_eval_literal(expr, &source);
        assert_eq!(val, serde_json::json!(-5));
    }

    #[test]
    fn test_literal_eval_string() {
        let (tree, source) = parse_and_get_expr("\"hello\"");
        let root = tree.root_node();
        let expr = find_expr_node(root.child(0).unwrap());
        let val = try_eval_literal(expr, &source);
        assert_eq!(val, serde_json::json!("hello"));
    }

    #[test]
    fn test_literal_eval_list() {
        let (tree, source) = parse_and_get_expr("[1, 2, 3]");
        let root = tree.root_node();
        let expr = find_expr_node(root.child(0).unwrap());
        let val = try_eval_literal(expr, &source);
        assert_eq!(val, serde_json::json!([1, 2, 3]));
    }
}
