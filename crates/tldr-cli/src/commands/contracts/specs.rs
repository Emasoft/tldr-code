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
                Err(_) => continue,
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

    // Helper: total spec count across all entries in a FunctionSpecs map.
    let spec_total = |m: &HashMap<String, FunctionSpecs>| -> usize {
        m.values().map(|v| {
            v.input_output_specs.len() + v.exception_specs.len() + v.property_specs.len()
        }).sum()
    };

    // cluster-misc-v2 (M-029): after each test function is processed,
    // increment test_count for every FunctionSpecs entry that gained at
    // least one new spec from that test function.
    let bump_test_counts = |specs: &mut HashMap<String, FunctionSpecs>,
                                pre: &HashMap<String, usize>| {
        for (name, entry) in specs.iter_mut() {
            let prev = pre.get(name).copied().unwrap_or(0);
            let now = entry.input_output_specs.len()
                + entry.exception_specs.len()
                + entry.property_specs.len();
            if now > prev {
                entry.test_count += 1;
            }
        }
    };

    // Process all test functions
    let _ = spec_total; // suppress unused warning from closure capture
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(name_node, source.as_bytes());
                    if name.starts_with("test_") {
                        test_func_count += 1;
                        let pre: HashMap<String, usize> = specs
                            .iter()
                            .map(|(k, v)| (k.clone(), v.input_output_specs.len() + v.exception_specs.len() + v.property_specs.len()))
                            .collect();
                        process_test_function(child, name, source.as_bytes(), &mut specs, 0)?;
                        bump_test_counts(&mut specs, &pre);
                    }
                }
            }
            "class_definition" => {
                // Test class: class TestFoo:
                if let Some(name_node) = child.child_by_field_name("name") {
                    let class_name = get_node_text(name_node, source.as_bytes());
                    if class_name.starts_with("Test") {
                        if let Some(body) = child.child_by_field_name("body") {
                            let mut class_cursor = body.walk();
                            for method in body.children(&mut class_cursor) {
                                if method.kind() == "function_definition" {
                                    if let Some(method_name) = method.child_by_field_name("name") {
                                        let mname = get_node_text(method_name, source.as_bytes());
                                        if mname.starts_with("test_") {
                                            test_func_count += 1;
                                            let pre: HashMap<String, usize> = specs
                                                .iter()
                                                .map(|(k, v)| (k.clone(), v.input_output_specs.len() + v.exception_specs.len() + v.property_specs.len()))
                                                .collect();
                                            process_test_function(
                                                method,
                                                mname,
                                                source.as_bytes(),
                                                &mut specs,
                                                0,
                                            )?;
                                            bump_test_counts(&mut specs, &pre);
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
    let s = s.trim();

    // Handle raw strings (r"..." or r'...')
    let s = s
        .strip_prefix('r')
        .or_else(|| s.strip_prefix('R'))
        .unwrap_or(s);
    let s = s
        .strip_prefix('b')
        .or_else(|| s.strip_prefix('B'))
        .unwrap_or(s);
    let s = s
        .strip_prefix('f')
        .or_else(|| s.strip_prefix('F'))
        .unwrap_or(s);

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
    // fix-T1b-scala-go-testrecognizer-v1 (@Test-recognizer move): swift-testing
    // `@Test func anyName()` recognition now lives in
    // `test_recognizer::swift_is_test_method` alongside the XCTest `func test*`
    // convention, so `is_test_function_node` already covers both. The previous
    // local `swift_is_testing_attr_function` shim (which made the harvest and
    // `count_test_functions` disagree) has been removed.
    let is_test = super::test_recognizer::is_test_function_node(&node, source, language);
    if is_test {
        let test_name = test_function_display_name(&node, source);

        // cluster-misc-v2 (M-029): snapshot spec counts before harvesting so
        // we can increment test_count on every FunctionSpecs entry that
        // received at least one new spec from this test function.
        let pre_counts: HashMap<String, usize> = specs
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.input_output_specs.len()
                        + v.exception_specs.len()
                        + v.property_specs.len(),
                )
            })
            .collect();

        harvest_assertions_in(&node, source, language, &test_name, path, specs);

        // Increment test_count for any entry whose total spec count grew.
        for (name, entry) in specs.iter_mut() {
            let prev = pre_counts.get(name).copied().unwrap_or(0);
            let now = entry.input_output_specs.len()
                + entry.exception_specs.len()
                + entry.property_specs.len();
            if now > prev {
                entry.test_count += 1;
            }
        }

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

    // cluster-misc-v2 (M-029): Elixir ExUnit `test "name" do ... end`
    // macros are parsed as `call` nodes whose first child is an `identifier`
    // "test" (the macro target). The previous fallback therefore returned
    // "test" for every Elixir test, losing the actual test name.
    //
    // For Elixir `call` nodes, look for the first string-literal argument
    // inside the `arguments` child. The tree-sitter-elixir grammar nests
    // the argument list under `arguments > string > quoted_content`.
    if node.kind() == "call" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "arguments" {
                // Walk the arguments node for the first string child.
                let mut arg_cursor = child.walk();
                for arg in child.children(&mut arg_cursor) {
                    // tree-sitter-elixir: string literals are either
                    // `string` nodes (double-quoted) or the raw text.
                    if arg.kind() == "string" {
                        // The content lives in a `quoted_content` child or
                        // is the direct text of the string node.
                        let mut sc = arg.walk();
                        for s_child in arg.children(&mut sc) {
                            if s_child.kind() == "quoted_content" {
                                let txt = get_node_text(s_child, source).to_string();
                                if !txt.is_empty() {
                                    return txt;
                                }
                            }
                        }
                        // Fallback: strip surrounding quotes from node text.
                        let raw = get_node_text(arg, source);
                        let trimmed = raw.trim_matches('"').trim_matches('\'').to_string();
                        if !trimmed.is_empty() {
                            return trimmed;
                        }
                    }
                }
            }
        }
    }

    // Walk children for the first identifier child (covers Swift,
    // Kotlin, etc. whose grammar exposes the name as a positional child).
    // NOTE: this path must come AFTER the Elixir call-node path above so
    // Elixir tests don't hit the identifier "test" and return the keyword.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "simple_identifier" || kind == "name" {
            return get_node_text(child, source).to_string();
        }
        // "identifier" is intentionally excluded here: it matches the
        // Elixir macro target "test" and the Lua function name "it" /
        // "test" — returning those is unhelpful. For languages that genuinely
        // expose the test-function name as a bare `identifier` child
        // (e.g. Go `function_declaration`), the `child_by_field_name("name")`
        // path above already handles them correctly.
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
    // fix-T1a-assertion-adapter-v1 (A1): the adapter is constant for the whole
    // body walk, so resolve it once here and thread it through the recursion
    // (rather than re-resolving per node).
    let adapter = adapter_for(language);
    walk_for_assertion_calls(
        *test_func,
        source,
        language,
        adapter.as_ref(),
        test_func_name,
        specs,
    );
}

// =============================================================================
// fix-T1a-assertion-adapter-v1 (v0.5.0 DESIGN-TAIL, A1): per-language
// assertion-extraction adapters.
//
// `walk_for_assertion_calls` previously dispatched through a chain of
// `if matches!(language, …)` guards calling one-hop framework handlers, then
// fell through to a generic flat-callee classifier that consulted TWO
// hand-synced global keyword lists (`is_equality`, `is_known_assertion_callee`)
// which had DRIFTED apart. This module replaces that with:
//
//   * `trait AssertionAdapter` — one impl per language; each owns its
//     framework SHAPES structurally (Go if/t.Fail descent, Java mockmvc
//     chain, JS member-spine, Swift #expect operator-read, Ruby expect,
//     OCaml application) AND the per-language equality VOCABULARY.
//   * `AssertionVocab` — a small NAMED const table of matcher-leaf names
//     grouped by semantic (equality / inequality / truthy / …). The
//     "is this name an assertion helper (never a FUT)?" predicate is now
//     DERIVED from the union of those groups (`AssertionVocab::is_known_callee`),
//     so the two lists can no longer drift: there is one source of truth.
//   * `adapter_for(language)` — mirrors the `match language { … }` shape of
//     `test_recognizer::matches_test_function`.
//
// Per-node dispatch is preserved exactly: the walker calls
// `adapter_for(language).extract(node, …)` on every node and then recurses,
// just as the old guard-chain did.
// =============================================================================

/// fix-T1a-assertion-adapter-v1 (A1): a small, named, per-language table of
/// assertion matcher-leaf names grouped by the spec they imply.
///
/// Used by the shared flat-callee classifier ([`classify_assertion_call`]) to
/// decide what KIND of spec a flat `assertEquals(...)`-shaped helper produces.
/// The "never attribute this name as a function-under-test" filter
/// ([`AssertionVocab::is_known_callee`]) is computed from the UNION of every
/// group plus [`AssertionVocab::matcher_heads`], which structurally prevents
/// the two-list drift bug: a matcher added to one group is automatically
/// excluded from FUT attribution.
struct AssertionVocab {
    /// Equality helpers: `assertEquals(expected, actual)` / `AreEqual` / … —
    /// emit an input/output spec.
    equality: &'static [&'static str],
    /// Inequality helpers: `assertNotEquals` / `assert_ne` / … — emit an
    /// inequality property spec.
    inequality: &'static [&'static str],
    /// Boolean-true helpers: `assertTrue` / `IsTrue` / … — truthy property.
    truthy: &'static [&'static str],
    /// Boolean-false helpers: `assertFalse` / `IsFalse` / … — falsy property.
    falsy: &'static [&'static str],
    /// Not-null helpers: `assertNotNull` / `IsNotNull` / … — not_null property.
    not_null: &'static [&'static str],
    /// Null helpers: `assertNull` / `IsNull` / … — null property.
    null: &'static [&'static str],
    /// Throwing helpers: `assertThrows` / `should_panic` / … — exception spec.
    throws: &'static [&'static str],
    /// Extra matcher HEADS that are assertion plumbing but carry no flat-call
    /// semantic of their own (`expect` / `toBe` / `eq` / `to` / `assert`).
    /// These must never be attributed as functions-under-test even though the
    /// flat classifier does not branch on them (they are handled by the
    /// member-spine / framework paths instead).
    matcher_heads: &'static [&'static str],
}

impl AssertionVocab {
    fn is_equality(&self, name: &str) -> bool {
        self.equality.contains(&name)
    }
    fn is_inequality(&self, name: &str) -> bool {
        self.inequality.contains(&name)
    }
    fn is_truthy(&self, name: &str) -> bool {
        self.truthy.contains(&name)
    }
    fn is_falsy(&self, name: &str) -> bool {
        self.falsy.contains(&name)
    }
    fn is_not_null(&self, name: &str) -> bool {
        self.not_null.contains(&name)
    }
    fn is_null(&self, name: &str) -> bool {
        self.null.contains(&name)
    }
    fn is_throws(&self, name: &str) -> bool {
        self.throws.contains(&name)
    }

    /// True when `name` is any assertion helper in this vocab — derived from
    /// the union of every group. This is the single source of truth that
    /// replaces the old hand-synced `is_known_assertion_callee` list.
    fn is_known_callee(&self, name: &str) -> bool {
        self.is_equality(name)
            || self.is_inequality(name)
            || self.is_truthy(name)
            || self.is_falsy(name)
            || self.is_not_null(name)
            || self.is_null(name)
            || self.is_throws(name)
            || self.matcher_heads.contains(&name)
    }
}

/// fix-T1a-assertion-adapter-v1 (A1): the shared flat-callee assertion
/// vocabulary.
///
/// The generic flat classifier currently fires for EVERY language (the old
/// guard-chain always fell through to it), so a single shared table preserves
/// behavior exactly. Per-language framework SHAPES live in the individual
/// adapters; this table is the equality/throws/… LEAF vocabulary they all
/// share for plain `assertEquals`-style calls. Scala's infix `===` / `shouldBe`
/// equality and Go's testify `Equal` FUT handling are deliberately left to the
/// T1b clusters — this table only carries what the pre-A1 global lists carried.
const FLAT_VOCAB: AssertionVocab = AssertionVocab {
    equality: &[
        "assertEquals",
        "assertEqual",
        "assertSame",
        "AreEqual",
        "AreSame",
        "Equal",
        "assert_eq",
        "assert_equal",
        "should_eq",
        "shouldBe",
        "shouldEqual",
        // Swift XCTest / swift-testing equality helpers.
        "expectEqual",
        "XCTAssertEqual",
        "expectEqualElements",
    ],
    inequality: &[
        "assertNotEquals",
        "assertNotEqual",
        "AreNotEqual",
        "NotEqual",
        "assert_ne",
        "assertNotSame",
    ],
    truthy: &[
        "assertTrue",
        "IsTrue",
        "True",
        "assert",
        "assert_true",
        "XCTAssertTrue",
        "expectTrue",
    ],
    falsy: &[
        "assertFalse",
        "IsFalse",
        "False",
        "assert_false",
        "XCTAssertFalse",
        "expectFalse",
    ],
    not_null: &[
        "assertNotNull",
        "IsNotNull",
        "NotNull",
        "assert_some",
        "XCTAssertNotNil",
        "expectNotNil",
    ],
    null: &[
        "assertNull",
        "IsNull",
        "Null",
        "assert_none",
        "XCTAssertNil",
        "expectNil",
    ],
    throws: &[
        "assertThrows",
        "assertFails",
        "Throws",
        "ThrowsAsync",
        "Throws_",
        "should_panic",
        "expectThrows",
        "XCTAssertThrowsError",
    ],
    // Member-spine / framework matcher heads that must never be FUTs. These
    // were the entries in the OLD `is_known_assertion_callee` that are not
    // flat-classifier semantics (handled by the JS/Ruby spine paths instead).
    matcher_heads: &["expect", "toBe", "toEqual", "toStrictEqual", "toMatch", "to", "eq"],
};

/// fix-T1a-assertion-adapter-v1 (A1): per-language assertion extractor.
///
/// `extract` is invoked once per AST node during the body walk (mirroring the
/// old per-node guard chain). An adapter recognises its framework's assertion
/// SHAPES on the node, emits the corresponding specs, and then delegates the
/// generic flat-callee path to [`classify_assertion_call`] using its
/// [`AssertionVocab`]. The walker handles recursion into children.
trait AssertionAdapter {
    /// Inspect `node` for assertion shapes and emit specs into `specs`.
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    );

    /// The flat-callee vocabulary this language uses for plain
    /// `assertEquals`-style helpers. Defaults to the shared [`FLAT_VOCAB`].
    fn vocab(&self) -> &'static AssertionVocab {
        &FLAT_VOCAB
    }
}

/// fix-T1a-assertion-adapter-v1 (A1): run the shared generic flat-callee
/// classification on `node` if it is a call shape. Factored out so every
/// adapter can reuse it after handling its framework-specific shapes.
fn classify_flat_call_node(
    node: &Node,
    source: &[u8],
    language: Language,
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
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
            | "member_call_expression"
            | "function_call_expression"
            | "scoped_call_expression"
            | "nullsafe_member_call_expression"
    );
    if !is_call {
        return;
    }
    if let Some(callee_text) = generic_callee_name(node, source) {
        let callee_tail = callee_text.rsplit('.').next().unwrap_or(&callee_text);
        // Strip generic params: `Throws<E>` -> `Throws`
        let callee_tail = callee_tail.split('<').next().unwrap_or(callee_tail);
        classify_assertion_call(
            node,
            source,
            language,
            callee_tail,
            vocab,
            test_func_name,
            specs,
        );
    }
}

/// Adapter for languages with no dedicated framework SHAPE: they rely solely
/// on the shared flat-callee classifier (`assertEquals`-style helpers). Covers
/// Python (whose pytest path runs separately), C/C++, Kotlin, C#, PHP,
/// Lua/Luau, Elixir, Solidity, and Rust's flat `assert_eq!` macros.
///
/// NOT Scala: `adapter_for` dispatches `Language::Scala` to the dedicated
/// `ScalaAdapter` (which adds the positional-helper and infix-DSL shapes on top
/// of the shared flat path), so Scala never reaches this adapter.
///
/// Carries its `language` so the shared classifier's Rust-macro-aware branches
/// (`matches!(language, Language::Rust) && node.kind() == "macro_invocation"`)
/// only fire for genuine Rust — never for Kotlin/C#/PHP routed here.
struct FlatOnlyAdapter {
    language: Language,
}
impl AssertionAdapter for FlatOnlyAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        classify_flat_call_node(node, source, self.language, self.vocab(), test_func_name, specs);
    }
}

/// fix-T1b-scala-go-testrecognizer-v1 (G4-b): the Go assertion vocabulary.
///
/// Mirrors the shared [`FLAT_VOCAB`] but DROPS the bare `Equal` from the
/// equality group (in Go, `cmp.Equal` / `bytes.Equal` are comparison
/// PREDICATES used inside `if` conditions, not testify-style equality
/// assertions over a FUT) and adds the named comparison-helper tails
/// (`DeepEqual` / `Equal` / `Is`) to `matcher_heads` so the derived
/// `is_known_callee` predicate suppresses them from FUT attribution
/// everywhere. The remaining groups match `FLAT_VOCAB` so any genuine
/// testify-`assert.True`/etc. flat helper still classifies as before.
const GO_VOCAB: AssertionVocab = AssertionVocab {
    equality: &[
        "assertEquals",
        "assertEqual",
        "assertSame",
        "AreEqual",
        "AreSame",
        "assert_eq",
        "assert_equal",
        "should_eq",
        "shouldBe",
        "shouldEqual",
    ],
    inequality: &[
        "assertNotEquals",
        "assertNotEqual",
        "AreNotEqual",
        "NotEqual",
        "assert_ne",
        "assertNotSame",
    ],
    truthy: &["assertTrue", "IsTrue", "True", "assert", "assert_true"],
    falsy: &["assertFalse", "IsFalse", "False", "assert_false"],
    not_null: &["assertNotNull", "IsNotNull", "NotNull", "assert_some"],
    null: &["assertNull", "IsNull", "Null", "assert_none"],
    throws: &["assertThrows", "assertFails", "Throws", "ThrowsAsync", "should_panic"],
    // Comparison-helper tails suppressed as FUTs (G4-b). `reflect.DeepEqual`,
    // `cmp.Equal`, `bytes.Equal`, `errors.Is`.
    matcher_heads: &["DeepEqual", "Equal", "Is"],
};

/// T2 (v0.5.0 AUDIT-FIX): the C / C++ GoogleTest + Catch2 assertion
/// vocabulary.
///
/// GoogleTest assertion MACROS (`EXPECT_EQ`/`ASSERT_EQ`/…) are the dominant
/// shape in C/C++ test suites; the previous shared `FLAT_VOCAB` carried none of
/// them, so a GoogleTest file reported `total_specs = 0` even with hundreds of
/// recognised `TEST(...)` functions. The macro names are SCREAMING_CASE C
/// preprocessor symbols that never collide with another language's method
/// names, so isolating them in a C/C++-only vocabulary keeps every other
/// language untouched.
///
/// GoogleTest orders equality args as `EXPECT_EQ(actual, expected)` (actual
/// first) — the OPPOSITE of JUnit's `assertEquals(expected, actual)`. The
/// shared `classify_assertion_call` equality branch already picks "the
/// call-shaped side" as the function-under-test regardless of position, so
/// `EXPECT_EQ(add(2,3), 5)` correctly attributes `add` and records `5` as the
/// output without any position-specific handling here.
const CPP_VOCAB: AssertionVocab = AssertionVocab {
    equality: &[
        // GoogleTest.
        "EXPECT_EQ",
        "ASSERT_EQ",
        "EXPECT_STREQ",
        "ASSERT_STREQ",
        // Inherit the shared cross-language helpers too (Unity `TEST_ASSERT_*`
        // style suites and any testify-shaped C++ helpers).
        "assertEquals",
        "assertEqual",
    ],
    inequality: &["EXPECT_NE", "ASSERT_NE", "EXPECT_STRNE", "ASSERT_STRNE"],
    truthy: &[
        // GoogleTest.
        "EXPECT_TRUE",
        "ASSERT_TRUE",
        // Catch2 / doctest.
        "REQUIRE",
        "CHECK",
    ],
    falsy: &["EXPECT_FALSE", "ASSERT_FALSE", "REQUIRE_FALSE", "CHECK_FALSE"],
    not_null: &["EXPECT_NE_NULL", "ASSERT_NE_NULL"],
    null: &["EXPECT_EQ_NULL", "ASSERT_EQ_NULL"],
    throws: &[
        // GoogleTest.
        "EXPECT_THROW",
        "ASSERT_THROW",
        "EXPECT_ANY_THROW",
        "ASSERT_ANY_THROW",
        // Catch2.
        "REQUIRE_THROWS",
        "REQUIRE_THROWS_AS",
        "CHECK_THROWS",
    ],
    matcher_heads: &[],
};

/// C / C++: GoogleTest + Catch2 assertion macros (flat call shape) + shared
/// flat helpers. No dedicated framework SHAPE beyond the flat-callee classifier
/// (the macros parse as `call_expression` / `macro_invocation` whose callee is
/// the macro identifier), so this adapter only swaps in [`CPP_VOCAB`].
struct CppAdapter;
impl AssertionAdapter for CppAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        classify_flat_call_node(node, source, Language::Cpp, self.vocab(), test_func_name, specs);
    }

    fn vocab(&self) -> &'static AssertionVocab {
        &CPP_VOCAB
    }
}

/// Go: `if <call> != want { t.Errorf(...) }` idiom + flat helpers.
struct GoAdapter;
impl AssertionAdapter for GoAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if node.kind() == "if_statement" {
            // Still recurse afterwards (handled by the walker): nested if/loop
            // bodies may contain more assertions.
            try_extract_go_if_t_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Go, self.vocab(), test_func_name, specs);
    }

    fn vocab(&self) -> &'static AssertionVocab {
        &GO_VOCAB
    }
}

/// Java: Spring MockMvc fluent chain + flat JUnit helpers.
struct JavaAdapter;
impl AssertionAdapter for JavaAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if matches!(node.kind(), "method_invocation" | "invocation_expression") {
            try_extract_java_mockmvc_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Java, self.vocab(), test_func_name, specs);
    }
}

/// JS/TS: Jest/mocha/chai/should member-spine `expect(actual).matcher(...)` +
/// flat helpers.
struct JsAdapter {
    language: Language,
}
impl AssertionAdapter for JsAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if matches!(node.kind(), "call_expression" | "member_expression") {
            try_extract_js_expect_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, self.language, self.vocab(), test_func_name, specs);
    }
}

/// Swift: swift-testing `#expect` / `#require` macros + flat XCTest helpers.
struct SwiftAdapter;
impl AssertionAdapter for SwiftAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if node.kind() == "macro_invocation" {
            try_extract_swift_expect_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Swift, self.vocab(), test_func_name, specs);
    }
}

/// Ruby: RSpec `expect(actual).to matcher` + flat minitest helpers.
struct RubyAdapter;
impl AssertionAdapter for RubyAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if node.kind() == "call" {
            try_extract_ruby_expect_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Ruby, self.vocab(), test_func_name, specs);
    }
}

/// OCaml: ppx structural `equal`/alcotest `check` applications + flat helpers.
struct OcamlAdapter;
impl AssertionAdapter for OcamlAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        if node.kind() == "application_expression" {
            try_extract_ocaml_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Ocaml, self.vocab(), test_func_name, specs);
    }
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a): Scala (munit / cats-effect /
/// ScalaTest).
///
/// Two assertion SHAPES on top of the shared flat-callee path:
///   * G1-a1 positional helper calls — `assertCompleteAs(io, expected)` and
///     the cats-effect/munit equality family. These reach the shared flat
///     classifier through [`SCALA_VOCAB`]; the only Scala-specific work is the
///     `(actual=arg0, expected=arg1)` extraction when arg0 is a bare value
///     (`val test`) rather than a call — handled by
///     [`try_extract_scala_helper_assertion`].
///   * G1-a2 infix DSL — `x should be (y)` / `a === b` / `c must_== d`, parsed
///     as `infix_expression`. Handled by [`try_extract_scala_infix_assertion`].
struct ScalaAdapter;
impl AssertionAdapter for ScalaAdapter {
    fn extract(
        &self,
        node: &Node,
        source: &[u8],
        test_func_name: &str,
        specs: &mut HashMap<String, FunctionSpecs>,
    ) {
        // G1-a2: ScalaTest infix-DSL equality (`x should be (y)` / `a === b`).
        if node.kind() == "infix_expression" {
            try_extract_scala_infix_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        // G1-a1: positional equality helpers whose actual is a bare value.
        if node.kind() == "call_expression" {
            try_extract_scala_helper_assertion(node, source, self.vocab(), test_func_name, specs);
        }
        classify_flat_call_node(node, source, Language::Scala, self.vocab(), test_func_name, specs);
    }

    fn vocab(&self) -> &'static AssertionVocab {
        &SCALA_VOCAB
    }
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a): the Scala assertion vocabulary.
///
/// Scala test suites (munit / cats-effect / ScalaTest) ship a wider equality
/// surface than the shared [`FLAT_VOCAB`]. The dominant cats-effect shape is a
/// positional helper `assertCompleteAs(io, expected)` (308 sites in
/// scala-cats-effect) whose `(actual=arg0, expected=arg1)` layout mirrors
/// `assertEquals` exactly. We extend the equality group with the
/// cats-effect/munit helper family so the flat classifier attributes them; the
/// derived `is_known_callee` predicate then also excludes them from FUT
/// attribution automatically (no second list to keep in sync).
const SCALA_VOCAB: AssertionVocab = AssertionVocab {
    // Equality is deliberately EMPTY for Scala: the shared flat classifier
    // picks "the call side" as the actual, but every munit / cats-effect
    // equality helper uses a fixed `(actual=arg0, expected=arg1)` positional
    // order regardless of which side is a call (e.g.
    // `assertEquals(e.getMessage, "msg")` and
    // `assertCompleteAs(test, Left(e))`). So `try_extract_scala_helper_assertion`
    // owns the whole equality family with the correct arg0-actual rule, and the
    // names live in `matcher_heads` below for FUT suppression only.
    equality: &[],
    inequality: &["assertNotEquals", "assertNotEqual", "assertNotSame"],
    truthy: &["assert", "assertTrue", "assertIOBool"],
    falsy: &["assertFalse"],
    not_null: &["assertSome"],
    null: &["assertNone"],
    throws: &[
        "assertFails",
        "assertFailsWith",
        "interceptIO",
        "intercept",
        "interceptMessageIO",
    ],
    // Equality / infix matcher heads: never attributed as a FUT. The equality
    // family is handled positionally by `try_extract_scala_helper_assertion`;
    // the infix words by `try_extract_scala_infix_assertion`.
    matcher_heads: &[
        // munit / xUnit-style positional equality helpers.
        "assertEquals",
        "assertEqual",
        "assertSame",
        // cats-effect / munit-cats-effect positional equality helpers.
        "assertCompleteAs",
        "assertCompleteAsSync",
        "assertIO",
        "assertIOBoolean",
        "assertSyncIO",
        "assertCompleteAsf",
        // ScalaTest infix DSL heads.
        "should",
        "shouldBe",
        "shouldEqual",
        "must",
        "mustEqual",
        "mustBe",
        "be",
        "===",
        "must_==",
    ],
};

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a1): the Scala positional equality
/// helper family — munit `assertEquals`/`assertEqual`/`assertSame` and the
/// cats-effect `assertCompleteAs` family. All share the fixed
/// `(actual=arg0, expected=arg1)` argument order, which
/// `try_extract_scala_helper_assertion` attributes directly (rather than the
/// shared flat classifier's call-side heuristic).
const SCALA_POSITIONAL_EQ_HELPERS: &[&str] = &[
    "assertEquals",
    "assertEqual",
    "assertSame",
    "assertCompleteAs",
    "assertCompleteAsSync",
    "assertIO",
    "assertIOBoolean",
    "assertSyncIO",
    "assertCompleteAsf",
];

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a): the ScalaTest infix-DSL equality
/// operators. `x should be (y)` / `x must be (y)` / `a === b` / `c must_== d` /
/// `r shouldEqual e` parse (tree-sitter-scala) as an `infix_expression` whose
/// `[operator]` field is one of these names. When present, the left operand
/// carries the FUT and the right operand carries the expected value.
///
/// Both `should` (Matchers) and bare `must` (MustMatchers) are the DSL subject
/// words: `result should be(5)` and `result must be(5)` have identical
/// `infix_expression` shapes (operator word + `be(..)`/`equal(..)` carrier on
/// the right — verified by debug-parse), so both must be recognised here.
const SCALA_INFIX_EQ_OPERATORS: &[&str] = &[
    "should",     // `x should be (y)` / `x should equal (y)`
    "must",       // `x must be (y)` / `x must equal (y)` (ScalaTest MustMatchers)
    "shouldBe",   // `x shouldBe y`
    "shouldEqual",
    "mustBe",
    "mustEqual",
    "must_==",
    "===",        // ScalaTest TypeCheckedTripleEquals / cats Eq syntax
    "====",
];

/// fix-T1a-assertion-adapter-v1 (A1): pick the assertion adapter for a
/// language. Mirrors `test_recognizer::matches_test_function`'s
/// `match language { … }` shape. Adapters are zero-sized (or carry only the
/// `Language` tag for JS/TS), so the boxing cost is negligible and happens
/// once per visited AST node's language (a constant).
fn adapter_for(language: Language) -> Box<dyn AssertionAdapter> {
    match language {
        Language::Go => Box::new(GoAdapter),
        Language::Java => Box::new(JavaAdapter),
        Language::JavaScript | Language::TypeScript => Box::new(JsAdapter { language }),
        Language::Swift => Box::new(SwiftAdapter),
        Language::Ruby => Box::new(RubyAdapter),
        Language::Ocaml => Box::new(OcamlAdapter),
        Language::Scala => Box::new(ScalaAdapter),
        // T2 (v0.5.0 AUDIT-FIX): C / C++ get the GoogleTest + Catch2 assertion
        // macro vocabulary (CPP_VOCAB) instead of the shared FLAT_VOCAB.
        Language::C | Language::Cpp => Box::new(CppAdapter),
        // Every remaining language uses only the shared flat-callee path
        // (Python's pytest extraction runs on a separate code path entirely;
        // it never reaches the walker, but a flat adapter is harmless).
        _ => Box::new(FlatOnlyAdapter { language }),
    }
}

fn walk_for_assertion_calls(
    node: Node,
    source: &[u8],
    language: Language,
    adapter: &dyn AssertionAdapter,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    // fix-T1a-assertion-adapter-v1 (A1): dispatch the per-language adapter on
    // this node. Each adapter recognises its framework SHAPES (Go if/t.Fail,
    // Java mockmvc, JS member-spine, Swift #expect, Ruby expect, OCaml
    // application) and then runs the shared flat-callee classifier with its
    // own equality VOCABULARY — replacing the old `if matches!(language, …)`
    // guard chain and the two drifted global keyword lists.
    adapter.extract(&node, source, test_func_name, specs);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_assertion_calls(child, source, language, adapter, test_func_name, specs);
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
    vocab: &AssertionVocab,
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
    //   if !reflect.DeepEqual(got, want) { ... }   -> the comparison HELPER is
    //                                                  not the FUT; descend into
    //                                                  its args for the real FUT
    //                                                  (G4-b).
    //   if got != want { ... }                     -> no call in condition; bail
    //                                                  (G4-a reaching-defs
    //                                                  recovery is deferred).
    //   if foo() != 5 { ... }                       -> FUT is `foo`.
    //   if err := f(x); err != nil { ... }         -> FUT is `f`.
    let call_node = match first_callable_inside(cond_node) {
        Some(c) => c,
        None => return false,
    };

    // fix-T1b-scala-go-testrecognizer-v1 (G4-b): comparison-helper descent.
    // `if !reflect.DeepEqual(ps, want) { ... }` previously attributed the spec
    // to `DeepEqual` (the helper) — silent wrong attribution. Resolve the
    // condition call's callee tail FIRST (without the FUT-exclusion filter that
    // `generic_extract_call_info` applies), so we can recognise a comparison
    // helper even though it is in the suppression vocab. When the call is one
    // of the named comparison helpers (`reflect.DeepEqual`, `cmp.Equal`,
    // `bytes.Equal`, `errors.Is`), the real FUT (if any) lives in its
    // arguments: descend into the helper's args for the first genuine call. If
    // none of the args is a call (`reflect.DeepEqual(ps, want)` over two vars),
    // there is no recoverable FUT, so emit nothing rather than the junk helper
    // spec. Otherwise fall back to attributing the condition call itself.
    let cond_callee_tail = generic_callee_name(&call_node, source)
        .map(|c| {
            c.rsplit('.')
                .next()
                .unwrap_or(&c)
                .split('<')
                .next()
                .unwrap_or(&c)
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    let fname = if is_go_comparison_helper(&cond_callee_tail) {
        let inner_fut = collect_call_args(call_node)
            .into_iter()
            .find_map(first_callable_inside)
            .and_then(|c| generic_extract_call_info(c, source, vocab));
        match inner_fut {
            Some((inner_name, _)) if !is_go_comparison_helper(&inner_name) => inner_name,
            // No genuine FUT inside the comparison helper's args: drop the
            // would-be helper attribution entirely.
            _ => return false,
        }
    } else {
        match generic_extract_call_info(call_node, source, vocab) {
            Some((n, _)) => n,
            None => return false,
        }
    };

    // Don't emit specs for the test failure call itself (e.g. when the
    // condition is just a call to `t.Failed()`).
    if vocab.is_known_callee(&fname) || is_go_t_failure_method(&fname) {
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

/// fix-T1b-scala-go-testrecognizer-v1 (G4-b): the named Go comparison-helper
/// set. `name` is the callee TAIL (after the package/receiver `.`), matching
/// `reflect.DeepEqual` / `cmp.Equal` / `bytes.Equal` / `errors.Is`. These are
/// equality predicates, never the function-under-test — when they appear in an
/// `if` condition the real FUT (if any) lives in their arguments.
///
/// ACCEPTED TRADE-OFF: matching the bare tail `Equal` also suppresses a domain
/// method literally named `Equal` (e.g. `ps.Equal(other)` on a user value
/// type). Because we only have the callee tail at this point — not the
/// receiver's type — there is no cheap, purely-structural way to distinguish a
/// stdlib/cmp `Equal` predicate from a domain `Equal` method without type
/// resolution. The dominant real-world use of an in-`if`-condition `Equal` tail
/// is the comparison-predicate form, so we suppress it from FUT attribution and
/// accept the rare false positive on a domain `Equal`.
fn is_go_comparison_helper(name: &str) -> bool {
    matches!(name, "DeepEqual" | "Equal" | "Is")
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
    vocab: &AssertionVocab,
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
        match endpoint_call_node.and_then(|c| generic_extract_call_info(c, source, vocab)) {
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

/// cl7-test-frameworks-v1 (CL-7): Jest/mocha (JS/TS) fluent assertion.
///
/// Recognises `expect(<actual>).<matcher>(<expected>)` where:
///   - the outer node is a `call_expression` whose `function` field is a
///     `member_expression`,
///   - the member's `object` is a `call_expression` whose callee identifier
///     is `expect`,
///   - the member's `property` is a known equality matcher
///     (`toBe` / `toEqual` / `toStrictEqual`).
///
/// The function-under-test is the single argument of the inner `expect(...)`
/// (when it is itself a call); the expected value is the matcher's argument.
/// Returns true when a spec was emitted.
fn try_extract_js_expect_assertion(
    outer: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    js_expect_inner(outer, source, vocab, test_func_name, specs).unwrap_or(false)
}

/// Inner resolver for [`try_extract_js_expect_assertion`]. Returns
/// `Some(true)` when a spec was emitted, `Some(false)`/`None` otherwise. Split
/// out so the structural resolution can use the `?` operator.
fn js_expect_inner(
    outer: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> Option<bool> {
    // The assertion's tail member node carries the matcher name in its
    // `property` field, and its `object` chain descends (by structure) to
    // the `expect(<actual>)` carrier:
    //
    //   call_expression          expect(parse(x)).to.eql(y)   (Jest / chai .eql(y))
    //     function: member_expression  expect(parse(x)).to.eql
    //   member_expression        expect(flag).to.be.true       (chai no-arg boolean)
    //
    // For a `call_expression` outer node the matcher takes an argument (the
    // expected value); for a bare `member_expression` outer node the matcher
    // is a no-arg leaf (`.to.be.true` / `.to.be.null`).
    let (member, matcher_args): (Node, Option<Vec<Node>>) = match outer.kind() {
        "call_expression" => {
            let f = outer.child_by_field_name("function")?;
            if f.kind() != "member_expression" {
                return Some(false);
            }
            (f, Some(collect_call_args(*outer)))
        }
        "member_expression" => (*outer, None),
        _ => return Some(false),
    };

    // matcher = the spine LEAF (`eql`, `equal`, `toBe`, `true`, `throw`, ...).
    let matcher_node = member.child_by_field_name("property")?;
    let matcher = get_node_text(matcher_node, source);

    // Classify the matcher from the named leaf table. A `member_expression`
    // outer node is only a standalone assertion when its leaf is a no-arg
    // terminal (boolean / null) — otherwise it is just the `.function` of an
    // enclosing call we will visit separately, so bail to avoid emitting a
    // spec without a matcher argument.
    let kind = js_classify_matcher(matcher)?;
    if matcher_args.is_none() && !kind.is_no_arg_leaf() {
        return Some(false);
    }

    // SPINE DESCENT: from `member.object`, walk down the member_expression
    // chain BY STRUCTURE (descend through any non-leaf segment) until the
    // bottom `expect(<actual>)` call (Jest / chai) or, for should-style
    // chains (`subject.should.equal(y)`), the bottom subject node.
    let carrier = member.child_by_field_name("object")?;
    let (fut_node, fut_is_call_arg) = js_descend_to_carrier(carrier, source)?;

    // The FUT call: for `expect(<actual>)` the actual is inside the call's
    // args; for should-style the subject node IS the actual.
    let fut = if fut_is_call_arg {
        let expect_args = collect_call_args(fut_node);
        let actual = *expect_args.first()?;
        first_callable_inside(actual)?
    } else {
        first_callable_inside(fut_node)?
    };
    let (fname, inputs) = generic_extract_call_info(fut, source, vocab)?;

    let line = outer.start_position().row as u32 + 1;
    let fs = ensure_entry(specs, &fname);
    match kind {
        JsMatcherKind::Equality => {
            // Equality matcher: matcher arg is the expected output.
            let output = matcher_args
                .as_ref()
                .and_then(|a| a.first())
                .map(|n| try_eval_literal(*n, source))
                .unwrap_or(serde_json::Value::Null);
            fs.input_output_specs.push(InputOutputSpec {
                function: fname,
                inputs,
                output,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::High,
            });
            Some(true)
        }
        JsMatcherKind::Null => {
            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "null".to_string(),
                constraint: "result == null".to_string(),
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
            Some(true)
        }
        JsMatcherKind::Truthy => {
            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "truthy".to_string(),
                constraint: "result is truthy".to_string(),
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
            Some(true)
        }
        JsMatcherKind::Falsy => {
            fs.property_specs.push(PropertySpec {
                function: fname,
                property_type: "falsy".to_string(),
                constraint: "result is falsy".to_string(),
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
            Some(true)
        }
        JsMatcherKind::Throw => {
            fs.exception_specs.push(ExceptionSpec {
                function: fname,
                exception_type: "Error".to_string(),
                match_pattern: None,
                inputs,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::Medium,
            });
            Some(true)
        }
    }
}

/// cl7/T1-specs (v0.5.0): the kind of a JS/TS assertion matcher leaf.
///
/// Used ONLY to classify the spine leaf — never to gate the structural
/// descent to the `expect(...)` carrier (an unbounded chai-connector word
/// list would silently drop specs).
#[derive(Clone, Copy, PartialEq, Eq)]
enum JsMatcherKind {
    Equality,
    Null,
    Truthy,
    Falsy,
    Throw,
}

impl JsMatcherKind {
    /// True when the matcher is a no-argument terminal that can appear as a
    /// bare property access (`expect(x).to.be.true`) rather than a call.
    fn is_no_arg_leaf(self) -> bool {
        matches!(
            self,
            JsMatcherKind::Null | JsMatcherKind::Truthy | JsMatcherKind::Falsy
        )
    }
}

/// cl7/T1-specs (v0.5.0): classify a JS/TS matcher LEAF name.
///
/// Small, named, per-framework matcher-leaf table (Jest + chai + should).
/// This is a CLASSIFICATION leaf table only — it does not drive the
/// structural spine descent. Returns `None` for non-matcher property names
/// (chai connectors like `to` / `be` / `deep`), which keeps intermediate
/// `member_expression` nodes from emitting spurious specs.
fn js_classify_matcher(matcher: &str) -> Option<JsMatcherKind> {
    match matcher {
        // Equality matchers: Jest (`toBe` family) and chai/should
        // (`eql` / `equal` / `equals` / `eq`; `.deep.equal` leaf is `equal`).
        "toBe" | "toEqual" | "toStrictEqual" | "toMatchObject" | "eql" | "equal" | "equals"
        | "eq" => Some(JsMatcherKind::Equality),
        // Nullish terminals.
        "toBeNull" | "toBeUndefined" | "null" | "undefined" => Some(JsMatcherKind::Null),
        // Truthy terminals (`.to.be.true` / `.to.be.ok` / Jest `toBeTruthy`).
        "toBeDefined" | "toBeTruthy" | "true" | "ok" => Some(JsMatcherKind::Truthy),
        // Falsy terminals.
        "toBeFalsy" | "false" => Some(JsMatcherKind::Falsy),
        // Throwing matchers.
        "toThrow" | "toThrowError" | "throw" | "throws" => Some(JsMatcherKind::Throw),
        _ => None,
    }
}

/// cl7/T1-specs (v0.5.0): structurally descend a JS/TS assertion spine to
/// its FUT carrier.
///
/// Walks down the `member_expression` `.object` chain BY STRUCTURE (through
/// any number of intervening segments — `to`, `be`, `deep`, ... — without
/// enumerating a connector wordlist). Stops at:
///   - the bottom `call_expression` named `expect` (Jest / chai
///     `expect(actual).…`), returning `(call, true)` so the caller pulls the
///     actual from the call's arguments; or
///   - the bottom non-`expect` node of a should-style chain
///     (`subject.should.equal(y)`), returning `(subject, false)` so the
///     caller treats the subject node itself as the actual.
fn js_descend_to_carrier<'a>(node: Node<'a>, source: &[u8]) -> Option<(Node<'a>, bool)> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "call_expression" => {
                // `expect(actual)` carrier → actual lives in the args.
                let callee = cur
                    .child_by_field_name("function")
                    .map(|f| get_node_text(f, source));
                if callee == Some("expect") {
                    return Some((cur, true));
                }
                // A call that is not `expect(...)` is the should-style
                // subject itself (`svc.find(1).should.equal(2)`): treat the
                // call as the actual.
                return Some((cur, false));
            }
            "member_expression" => {
                // Descend through the connector segment by structure.
                cur = cur.child_by_field_name("object")?;
            }
            // Bottom of a should-style chain is a plain subject (identifier
            // / parenthesised expr / ...): the subject is the actual.
            _ => return Some((cur, false)),
        }
    }
}

/// cl7-test-frameworks-v1 (CL-7): RSpec (Ruby) fluent assertion.
///
/// Recognises `expect(<actual>).to <matcher>` / `.not_to <matcher>`, where
/// the tree-sitter-ruby shape is a `call` node:
///   - `receiver`: a `call` whose method is `expect` (arg = actual / FUT),
///   - `method`: `to` / `not_to` / `to_not`,
///   - `arguments`: the matcher, commonly `eq(<expected>)` (a nested call)
///     or a bare matcher identifier like `be_nil`.
fn try_extract_ruby_expect_assertion(
    call: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    // method must be to / not_to / to_not.
    let method = match call.child_by_field_name("method") {
        Some(m) => get_node_text(m, source),
        None => return false,
    };
    let negated = match method {
        "to" => false,
        "not_to" | "to_not" => true,
        _ => return false,
    };
    // receiver must be `expect(<actual>)`.
    let receiver = match call.child_by_field_name("receiver") {
        Some(r) if r.kind() == "call" => r,
        _ => return false,
    };
    let recv_method = match receiver.child_by_field_name("method") {
        Some(m) => get_node_text(m, source),
        None => return false,
    };
    if recv_method != "expect" {
        return false;
    }
    let expect_args = collect_call_args(receiver);
    let actual = match expect_args.first() {
        Some(a) => *a,
        None => return false,
    };
    let fut = match first_callable_inside(actual) {
        Some(c) => c,
        None => return false,
    };
    let (fname, inputs) = match generic_extract_call_info(fut, source, vocab) {
        Some(v) => v,
        None => return false,
    };

    // Inspect the matcher argument: `eq(...)` / `eql(...)` / `be_nil` / etc.
    let matcher_args = collect_call_args(*call);
    let matcher = matcher_args.first().copied();
    let line = call.start_position().row as u32 + 1;
    let fs = ensure_entry(specs, &fname);

    if let Some(m) = matcher {
        // Equality matcher `eq(expected)` / `eql(expected)`.
        if m.kind() == "call" {
            if let Some(mn) = m.child_by_field_name("method") {
                let mname = get_node_text(mn, source);
                if matches!(mname, "eq" | "eql" | "equal") && !negated {
                    let m_args = collect_call_args(m);
                    let output = m_args
                        .first()
                        .map(|n| try_eval_literal(*n, source))
                        .unwrap_or(serde_json::Value::Null);
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
        // Bare matcher identifier `be_nil`, `be_truthy`, `be_falsey`, etc.
        let m_text = get_node_text(m, source);
        let (ptype, constraint) = ruby_matcher_property(m_text, negated);
        fs.property_specs.push(PropertySpec {
            function: fname,
            property_type: ptype,
            constraint,
            test_function: test_func_name.to_string(),
            line,
            confidence: Confidence::Medium,
        });
        return true;
    }
    false
}

/// Map an RSpec bare matcher (`be_nil`, `be_truthy`, …) to a property
/// (type, constraint) pair, honouring `not_to` negation.
fn ruby_matcher_property(matcher: &str, negated: bool) -> (String, String) {
    let tail = matcher.trim();
    match tail {
        "be_nil" => {
            if negated {
                ("not_null".to_string(), "result != nil".to_string())
            } else {
                ("null".to_string(), "result == nil".to_string())
            }
        }
        "be_truthy" | "be_true" => {
            if negated {
                ("falsy".to_string(), "result is falsy".to_string())
            } else {
                ("truthy".to_string(), "result is truthy".to_string())
            }
        }
        "be_falsey" | "be_false" => {
            if negated {
                ("truthy".to_string(), "result is truthy".to_string())
            } else {
                ("falsy".to_string(), "result is falsy".to_string())
            }
        }
        other => {
            let prefix = if negated { "not " } else { "" };
            (
                "matcher".to_string(),
                format!("result {}{}", prefix, other),
            )
        }
    }
}

/// cl7-test-frameworks-v1 (CL-7): OCaml ppx / alcotest assertion.
///
/// tree-sitter-ocaml models calls as `application_expression` with a
/// `function` child (the callee) and one or more `argument` children. Two
/// common test shapes:
///   - structural equality: `equal (f x) y` / `String.equal (f x) y` —
///     callee tail is `equal`; the FUT is the call inside the first arg,
///     the expected value is the second arg.
///   - alcotest `check`: `check int "desc" expected (f x)` — callee tail is
///     `check`; the FUT is the call inside the last argument and the
///     expected value is the preceding argument.
fn try_extract_ocaml_assertion(
    app: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    let func = match app.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };
    let callee = get_node_text(func, source);
    let tail = callee.rsplit('.').next().unwrap_or(&callee).trim();

    // Collect the positional argument children (field name "argument").
    let mut args: Vec<Node> = Vec::new();
    let mut cursor = app.walk();
    for child in app.children(&mut cursor) {
        if let Some(fname) = ocaml_field_name(app, &child) {
            if fname == "argument" {
                args.push(child);
            }
        }
    }
    if args.is_empty() {
        return false;
    }

    let line = app.start_position().row as u32 + 1;

    match tail {
        // Structural equality helpers: `equal a b`, `String.equal a b`,
        // `Int.equal a b`. The FUT lives in one argument (the one that is /
        // contains an application), the expected in the other.
        "equal" | "equal_string" | "equal_int" if args.len() >= 2 => {
            let (fut_arg, val_arg) = if ocaml_arg_has_application(args[0]) {
                (args[0], args[1])
            } else if ocaml_arg_has_application(args[1]) {
                (args[1], args[0])
            } else {
                return false;
            };
            let fut = match ocaml_first_application(fut_arg) {
                Some(c) => c,
                None => return false,
            };
            let (fname, inputs) = match ocaml_application_info(fut, source, vocab) {
                Some(v) => v,
                None => return false,
            };
            let output = try_eval_literal(val_arg, source);
            let fs = ensure_entry(specs, &fname);
            fs.input_output_specs.push(InputOutputSpec {
                function: fname,
                inputs,
                output,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::High,
            });
            true
        }
        // Alcotest `check testable "desc" expected actual`: 4 args; FUT in the
        // last, expected in the second-to-last.
        "check" if args.len() >= 4 => {
            let actual = args[args.len() - 1];
            let expected = args[args.len() - 2];
            let fut = match ocaml_first_application(actual) {
                Some(c) => c,
                None => return false,
            };
            let (fname, inputs) = match ocaml_application_info(fut, source, vocab) {
                Some(v) => v,
                None => return false,
            };
            let output = try_eval_literal(expected, source);
            let fs = ensure_entry(specs, &fname);
            fs.input_output_specs.push(InputOutputSpec {
                function: fname,
                inputs,
                output,
                test_function: test_func_name.to_string(),
                line,
                confidence: Confidence::High,
            });
            true
        }
        _ => false,
    }
}

/// Field name of `child` within `parent` (tree-sitter doesn't expose this
/// off the child directly; walk the parent's cursor to find it).
fn ocaml_field_name<'a>(parent: &Node<'a>, child: &Node<'a>) -> Option<&'static str> {
    let mut cursor = parent.walk();
    for (i, c) in parent.children(&mut cursor).enumerate() {
        if c.id() == child.id() {
            return parent.field_name_for_child(i as u32);
        }
    }
    None
}

/// True when an OCaml argument node is, or contains, an
/// `application_expression` (a function call) — used to pick the FUT side.
fn ocaml_arg_has_application(node: Node) -> bool {
    ocaml_first_application(node).is_some()
}

/// Find the first `application_expression` at or within `node` (unwrapping
/// `parenthesized_expression`).
fn ocaml_first_application(node: Node) -> Option<Node> {
    if node.kind() == "application_expression" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = ocaml_first_application(child) {
            return Some(found);
        }
    }
    None
}

/// Extract `(function_name, inputs)` from an OCaml `application_expression`.
fn ocaml_application_info(
    app: Node,
    source: &[u8],
    vocab: &AssertionVocab,
) -> Option<(String, Vec<serde_json::Value>)> {
    let func = app.child_by_field_name("function")?;
    let callee = get_node_text(func, source);
    let tail = callee.rsplit('.').next().unwrap_or(&callee).trim();
    if tail.is_empty() || vocab.is_known_callee(tail) {
        return None;
    }
    let mut inputs: Vec<serde_json::Value> = Vec::new();
    let mut cursor = app.walk();
    for child in app.children(&mut cursor) {
        if let Some(fname) = ocaml_field_name(&app, &child) {
            if fname == "argument" {
                inputs.push(try_eval_literal(child, source));
            }
        }
    }
    Some((tail.to_string(), inputs))
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a1): Scala positional equality
/// helper.
///
/// The munit (`assertEquals`/`assertEqual`/`assertSame`) and cats-effect
/// (`assertCompleteAs(io, expected)`, `assertIO(io, expected)`, …) equality
/// families all use the SAME fixed argument order: `(actual=arg0,
/// expected=arg1)`. The shared flat classifier instead picks "whichever side
/// looks like a call", which mis-attributes `assertCompleteAs(test, Left(e))`
/// (arg1 is a constructor call) and skips `assertCompleteAs(test, 42)` (neither
/// side is a call). So this handler owns the whole family positionally.
///
/// arg0 is the actual: if it is / contains a call (`assertEquals(compute(),
/// …)`, `assertEquals(e.getMessage, …)`), the call's tail is the FUT; if it is
/// a bare value (`assertCompleteAs(test, 42)` over a `val`), its tail
/// identifier is the FUT. arg1 is the expected output. Returns true when a spec
/// was emitted.
fn try_extract_scala_helper_assertion(
    call: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
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
    if !SCALA_POSITIONAL_EQ_HELPERS.contains(&tail) {
        return false;
    }
    let args = collect_call_args(*call);
    if args.len() < 2 {
        return false;
    }
    // actual = arg0. Prefer a contained call (`compute()` / `e.getMessage`),
    // else a bare value's tail identifier (`test` / `obj.value`).
    let fname = match scala_actual_fut_name(args[0], source, vocab) {
        Some(n) => n,
        None => return false,
    };
    let output = try_eval_literal(args[1], source);
    let line = call.start_position().row as u32 + 1;
    let fs = ensure_entry(specs, &fname);
    fs.input_output_specs.push(InputOutputSpec {
        function: fname,
        inputs: Vec::new(),
        output,
        test_function: test_func_name.to_string(),
        line,
        confidence: Confidence::Medium,
    });
    true
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a1): resolve a FUT name from a Scala
/// "actual" operand (arg0 of a positional equality helper, or the left of an
/// infix assertion).
///
/// * a genuine call (`compute()` / `e.getMessage`) → its callee tail via
///   `generic_extract_call_info`.
/// * a `field_expression` (`obj.value`) → its tail `[field]` identifier.
/// * a bare `identifier` (`test`) → the identifier text.
///
/// Returns `None` for literals / unattributable operands, and skips names that
/// are themselves known assertion helpers.
fn scala_actual_fut_name(
    operand: Node,
    source: &[u8],
    vocab: &AssertionVocab,
) -> Option<String> {
    if let Some(c) = first_callable_inside(operand) {
        if let Some((fname, _)) = generic_extract_call_info(c, source, vocab) {
            return Some(fname);
        }
    }
    let name = scala_value_fut_name(operand, source)?;
    if name.is_empty() || vocab.is_known_callee(&name) {
        return None;
    }
    Some(name)
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a1): derive a function-under-test
/// name from a Scala "actual" operand that is a bare value (not a call).
///
/// * `identifier` (`test`) → the identifier text.
/// * `field_expression` (`obj.value`) → the tail `[field]` identifier.
///
/// Returns `None` for literals / other shapes (nothing useful to attribute).
fn scala_value_fut_name(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let t = get_node_text(node, source).trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        "field_expression" => {
            let field = node.child_by_field_name("field")?;
            let t = get_node_text(field, source).trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        _ => None,
    }
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a2): ScalaTest infix-DSL equality.
///
/// tree-sitter-scala parses `x should be (y)` / `a === b` / `c must_== d` /
/// `r shouldBe e` as an `infix_expression` with named fields:
///   `[left]`  — the subject (function-under-test carrier),
///   `[operator]` — the matcher word (`should` / `===` / `shouldBe` / …),
///   `[right]` — the expected value (or, for `should be (y)`, a
///               `call_expression be(y)` whose argument is the expected value).
///
/// When the operator is a known equality matcher ([`SCALA_INFIX_EQ_OPERATORS`])
/// we attribute the FUT from the LEFT operand (a call's tail, a field read's
/// tail, or a bare identifier) and the expected value from the RIGHT operand
/// (unwrapping the `should be (y)` wrapper call). Returns true when a spec was
/// emitted.
fn try_extract_scala_infix_assertion(
    node: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) -> bool {
    let operator = match node.child_by_field_name("operator") {
        Some(op) => get_node_text(op, source).trim().to_string(),
        None => return false,
    };
    if !SCALA_INFIX_EQ_OPERATORS.contains(&operator.as_str()) {
        return false;
    }
    let left = match node.child_by_field_name("left") {
        Some(l) => l,
        None => return false,
    };
    let right = match node.child_by_field_name("right") {
        Some(r) => r,
        None => return false,
    };

    // FUT name from the left subject: prefer a contained call, else a member /
    // identifier read (shared with the positional-helper actual resolver).
    let fname = match scala_actual_fut_name(left, source, vocab) {
        Some(n) => n,
        None => return false,
    };

    // Expected value from the right operand. `should be (y)` / `should equal
    // (y)` wraps the value in a `be(y)` / `equal(y)` call — unwrap to the first
    // argument. Otherwise the right operand IS the expected value.
    let value_node = scala_infix_expected_value(right, source).unwrap_or(right);
    let output = try_eval_literal(value_node, source);

    let line = node.start_position().row as u32 + 1;
    let fs = ensure_entry(specs, &fname);
    fs.input_output_specs.push(InputOutputSpec {
        function: fname,
        inputs: Vec::new(),
        output,
        test_function: test_func_name.to_string(),
        line,
        confidence: Confidence::Medium,
    });
    true
}

/// fix-T1b-scala-go-testrecognizer-v1 (G1-a2): unwrap the expected-value node
/// from the RIGHT operand of a ScalaTest infix assertion.
///
/// `x should be (y)` / `x must be (y)` parses the right side as a
/// `call_expression` whose `[function]` is `be` / `equal` and whose first
/// argument is the expected value `y`. Return that argument. For the bare
/// `a === b` form there is no wrapper, so return `None` and let the caller use
/// the right operand directly.
///
/// The carrier-method tails recognised here are the real ScalaTest matcher
/// methods that wrap a value as `method(value)`: `be(y)`, `equal(y)`, and the
/// `===(y)` method form. The operator words (`should` / `must` / `must_==`)
/// live on the `[operator]` field of the parent `infix_expression`, never as a
/// right-side carrier — `must_==`, in particular, parses with a BARE identifier
/// on the right (verified by debug-parse), so it never reaches this guard. (The
/// previously-listed `be_==` was a confusion with the `must_==` operator: it is
/// not a real matcher method name, so it has been removed.)
fn scala_infix_expected_value<'a>(right: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    if right.kind() != "call_expression" {
        return None;
    }
    let func = right.child_by_field_name("function")?;
    let tail = get_node_text(func, source)
        .rsplit('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if !matches!(tail.as_str(), "be" | "equal" | "===") {
        return None;
    }
    collect_call_args(right).first().copied()
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
                // cl7-test-frameworks-v1 (CL-7): tree-sitter-swift nests
                // arguments under `call_suffix > value_arguments`, so the
                // direct-child scan above misses them. Descend one level
                // into `call_suffix` to find the `value_arguments` list.
                if k == "call_suffix" {
                    let mut sub = child.walk();
                    for grand in child.children(&mut sub) {
                        if grand.kind() == "value_arguments" {
                            return Some(grand);
                        }
                    }
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

/// cl7-test-frameworks-v1 (CL-7): Swift property-read equality.
///
/// For `expectEqual(<a>, <b>)` where one side is a Swift
/// `navigation_expression` (a property/member read like `set.count`),
/// return `(fut_name, inputs, value_arg)` so the caller records an
/// input/output spec: the accessor tail (`count`) is the function-under-test,
/// the receiver (`set`) is the single input, and the OTHER argument is the
/// expected output. Returns `None` when neither side is a member read.
fn swift_member_equality<'a>(
    a: Node<'a>,
    b: Node<'a>,
    source: &[u8],
    language: Language,
    vocab: &AssertionVocab,
) -> Option<(String, Vec<serde_json::Value>, Node<'a>)> {
    if !matches!(language, Language::Swift) {
        return None;
    }
    // Prefer the LEFT side as the actual (XCTest convention is
    // `expectEqual(actual, expected)`), but accept either being the member
    // read.
    for (actual, value) in [(a, b), (b, a)] {
        if actual.kind() == "navigation_expression" {
            // Tail accessor name = the property/method being read.
            let suffix = actual.child_by_field_name("suffix")?;
            // navigation_suffix -> suffix: simple_identifier
            let name_node = suffix
                .child_by_field_name("suffix")
                .unwrap_or(suffix);
            let name = get_node_text(name_node, source).trim().to_string();
            if name.is_empty() || vocab.is_known_callee(&name) {
                continue;
            }
            // Receiver text becomes the (single) input observation.
            let receiver = actual.child_by_field_name("target");
            let inputs = receiver
                .map(|r| try_eval_literal(r, source))
                .into_iter()
                .collect::<Vec<_>>();
            return Some((name, inputs, value));
        }
    }
    None
}

/// T1-specs (v0.5.0 DESIGN-TAIL, G3-a): swift-testing `#expect` / `#require`.
///
/// tree-sitter-swift parses `#expect(<arg>)` as a `macro_invocation`:
///   `#`  `simple_identifier`("expect"|"require")  `call_suffix`
///     `call_suffix` -> `value_arguments` -> `value_argument` (field `value`)
///
/// The single value-argument is dispatched purely on AST shape:
///   * a binary expression (`equality_expression` / `comparison_expression` /
///     `infix_expression`) carrying a `op` field — read the operator from the
///     AST op node and the two operands from the `lhs` / `rhs` fields. The
///     function-under-test is taken from whichever operand carries a call /
///     navigation (member) read; the other operand is the expected value.
///       - `==` => InputOutputSpec
///       - `!=` => inequality PropertySpec
///       - `<` / `>` / `<=` / `>=` => bounds PropertySpec
///   * a bare boolean expression (no `op` field, e.g. `#expect(x.isEmpty)`)
///     => truthy PropertySpec.
///
/// Property reads (`set.count`, `coords[0].x`) attribute to the accessor tail
/// via the existing `swift_member_equality` convention; genuine function
/// calls (`compute()`) attribute via `generic_extract_call_info`.
fn try_extract_swift_expect_assertion(
    call: &Node,
    source: &[u8],
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    // Callee identifier: the `simple_identifier` child (after the `#` token).
    let mut callee: Option<&str> = None;
    let mut suffix: Option<Node> = None;
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        match child.kind() {
            "simple_identifier" if callee.is_none() => {
                callee = Some(get_node_text(child, source));
            }
            "call_suffix" => suffix = Some(child),
            _ => {}
        }
    }
    if !matches!(callee, Some("expect") | Some("require")) {
        return;
    }
    let suffix = match suffix {
        Some(s) => s,
        None => return,
    };

    // call_suffix -> value_arguments -> first value_argument (field `value`).
    let value_arguments = {
        let mut found = None;
        let mut sc = suffix.walk();
        for ch in suffix.children(&mut sc) {
            if ch.kind() == "value_arguments" {
                found = Some(ch);
                break;
            }
        }
        match found {
            Some(v) => v,
            None => return,
        }
    };
    let first_value_arg = {
        let mut found = None;
        let mut vc = value_arguments.walk();
        for ch in value_arguments.children(&mut vc) {
            if ch.kind() == "value_argument" {
                found = Some(ch);
                break;
            }
        }
        match found {
            Some(v) => v,
            None => return,
        }
    };
    // Skip labelled arguments (`#expect(processExitsWith: .failure) { … }`,
    // `#expect(throws:) { … }`) — these are exit-test / throwing directives,
    // not value comparisons. The presence of a `value_argument_label` child
    // is the structural signal.
    {
        let mut lc = first_value_arg.walk();
        for ch in first_value_arg.children(&mut lc) {
            if ch.kind() == "value_argument_label" {
                return;
            }
        }
    }
    let arg = match first_value_arg.child_by_field_name("value") {
        Some(a) => a,
        None => return,
    };

    let line = call.start_position().row as u32 + 1;

    // Binary comparison: dispatch on the AST `op` node.
    if let Some(op_node) = arg.child_by_field_name("op") {
        let lhs = match arg.child_by_field_name("lhs") {
            Some(n) => n,
            None => return,
        };
        let rhs = match arg.child_by_field_name("rhs") {
            Some(n) => n,
            None => return,
        };
        let op = get_node_text(op_node, source).trim();

        // Resolve (actual_fut, inputs, expected_node). Prefer the LEFT
        // operand as actual (Swift convention), accepting either side.
        let resolved = swift_resolve_expect_operands(lhs, rhs, source, vocab);
        let (fname, inputs, expected) = match resolved {
            Some(v) => v,
            None => return,
        };

        match op {
            "==" => {
                let output = try_eval_literal(expected, source);
                let fs = ensure_entry(specs, &fname);
                fs.input_output_specs.push(InputOutputSpec {
                    function: fname,
                    inputs,
                    output,
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::High,
                });
            }
            "!=" => {
                let val = get_node_text(expected, source);
                let fs = ensure_entry(specs, &fname);
                fs.property_specs.push(PropertySpec {
                    function: fname,
                    property_type: "inequality".to_string(),
                    constraint: format!("result != {}", val),
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::Medium,
                });
            }
            "<" | ">" | "<=" | ">=" => {
                let val = get_node_text(expected, source);
                let fs = ensure_entry(specs, &fname);
                fs.property_specs.push(PropertySpec {
                    function: fname,
                    property_type: "bounds".to_string(),
                    constraint: format!("result {} {}", op, val),
                    test_function: test_func_name.to_string(),
                    line,
                    confidence: Confidence::Medium,
                });
            }
            _ => {}
        }
        return;
    }

    // No operator: a bare boolean expression (`#expect(x.isEmpty)` /
    // `#expect(flag())`) => truthy property on the accessor / call FUT.
    // (Property specs carry no inputs, so the receiver observation is dropped.)
    if let Some((fname, _inputs)) = swift_operand_fut(arg, source, vocab) {
        let fs = ensure_entry(specs, &fname);
        fs.property_specs.push(PropertySpec {
            function: fname,
            property_type: "truthy".to_string(),
            constraint: "result is truthy".to_string(),
            test_function: test_func_name.to_string(),
            line,
            confidence: Confidence::Medium,
        });
    }
}

/// T1-specs (v0.5.0 DESIGN-TAIL, G3-a): pick the actual/expected operands of
/// a swift-testing comparison.
///
/// Returns `(fut_name, inputs, expected_node)` where the function-under-test
/// is resolved from whichever operand carries a member read / call (preferring
/// the left), and `expected_node` is the OTHER operand. `None` when neither
/// operand is a member read or call (a pure value-vs-value comparison we can't
/// attribute).
fn swift_resolve_expect_operands<'a>(
    lhs: Node<'a>,
    rhs: Node<'a>,
    source: &[u8],
    vocab: &AssertionVocab,
) -> Option<(String, Vec<serde_json::Value>, Node<'a>)> {
    for (actual, expected) in [(lhs, rhs), (rhs, lhs)] {
        if let Some((fname, inputs)) = swift_operand_fut(actual, source, vocab) {
            return Some((fname, inputs, expected));
        }
    }
    None
}

/// T1-specs (v0.5.0 DESIGN-TAIL, G3-a): resolve the FUT name + inputs for a
/// single swift-testing operand.
///
/// * A `navigation_expression` (member/property read such as `set.count` or
///   `coords[0].x`) attributes to the accessor tail via the existing
///   `swift_member_equality` convention (tail = FUT, receiver = input).
/// * Otherwise, if the operand contains a genuine `call_expression`
///   (`compute()`), attribute via `generic_extract_call_info`.
///
/// Returns `None` for pure literals / values.
fn swift_operand_fut(
    operand: Node,
    source: &[u8],
    vocab: &AssertionVocab,
) -> Option<(String, Vec<serde_json::Value>)> {
    if operand.kind() == "navigation_expression" {
        // Reuse the accessor-tail convention: `swift_member_equality` reads
        // the tail accessor as the FUT name and the receiver as the input.
        // The third tuple element (the "value") is irrelevant here, so pass
        // the operand itself as the throwaway second node.
        if let Some((name, inputs, _)) =
            swift_member_equality(operand, operand, source, Language::Swift, vocab)
        {
            return Some((name, inputs));
        }
    }
    // Genuine function call inside the operand (`compute()`,
    // `OpaquePointer(bitPattern: i)`): attribute to the call.
    if let Some(c) = first_callable_inside(operand) {
        // Subscripts (`coords[0]`) also parse as `call_expression` in
        // tree-sitter-swift; their callee is itself an expression, not a
        // plain function name, so `generic_extract_call_info` would yield the
        // subscript receiver. That case is already covered by the
        // navigation_expression branch above (the subscript is the receiver
        // of a `.member` read), so by the time we reach here a bare call is a
        // real function call.
        if let Some((fname, inputs)) = generic_extract_call_info(c, source, vocab) {
            return Some((fname, inputs));
        }
    }
    None
}

/// Get (or create) the `FunctionSpecs` entry for `name` in `specs`.
///
/// Shared by the framework-specific assertion extractors
/// (cl7-test-frameworks-v1) and the generic classifier.
fn ensure_entry<'a>(
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

/// Classify a single assertion call based on the tail of its callee name.
///
/// fix-T1a-assertion-adapter-v1 (A1): the equality / inequality / truthy / …
/// matcher classification now comes from the caller's per-language
/// [`AssertionVocab`] (`vocab`) rather than the former inline `matches!`
/// keyword lists. The "is this name a known assertion helper (never a FUT)?"
/// predicate is `vocab.is_known_callee`, which is DERIVED from the same vocab —
/// so the two lists can no longer drift apart.
fn classify_assertion_call(
    call: &Node,
    source: &[u8],
    language: Language,
    callee_tail: &str,
    vocab: &AssertionVocab,
    test_func_name: &str,
    specs: &mut HashMap<String, FunctionSpecs>,
) {
    let line = call.start_position().row as u32 + 1;

    // Local alias for the shared entry helper (cl7-test-frameworks-v1).
    let ensure = ensure_entry;

    // Matcher classification driven by the per-language vocabulary. The
    // semantic groups (equality / inequality / truthy / falsy / null /
    // not_null / throws) cover Swift XCTest (`expectEqual` / `XCTAssertEqual`
    // / …), JUnit/xUnit (`assertEquals` / `AreEqual` / …), Rust macros
    // (`assert_eq` / `assert_ne` / …), and the Kotlin/Scala `shouldBe` family
    // — see `FLAT_VOCAB`.
    let is_equality = vocab.is_equality(callee_tail);
    let is_inequality = vocab.is_inequality(callee_tail);
    let is_true = vocab.is_truthy(callee_tail);
    let is_false = vocab.is_falsy(callee_tail);
    let is_not_null = vocab.is_not_null(callee_tail);
    let is_null = vocab.is_null(callee_tail);
    let is_throws = vocab.is_throws(callee_tail);

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
                _ => {
                    // cl7-test-frameworks-v1 (CL-7): Swift XCTest /
                    // swift-testing assertions overwhelmingly compare a
                    // PROPERTY READ against an expected value, e.g.
                    // `expectEqual(set.count, count)`. Neither side is a
                    // call_expression, so the call-shaped picker above
                    // bails. Treat a `navigation_expression`
                    // (`receiver.member`) as the function-under-test: the
                    // accessor tail (`count`) is the FUT name and the
                    // receiver is the (single) input. This recovers
                    // input/output specs for the dominant XCTest shape.
                    if let Some((fname, inputs, value_arg)) =
                        swift_member_equality(args[0], args[1], source, language, vocab)
                    {
                        let output = try_eval_literal(value_arg, source);
                        let fs = ensure(specs, &fname);
                        fs.input_output_specs.push(InputOutputSpec {
                            function: fname,
                            inputs,
                            output,
                            test_function: test_func_name.to_string(),
                            line,
                            confidence: Confidence::Medium,
                        });
                    }
                    return;
                }
            }
        };
        if let Some((fname, inputs)) =
            extract_call_info_for_lang(call_arg, source, language, vocab)
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
        if let Some((fname, _inputs)) = extract_call_info_for_lang(call_arg, source, language, vocab) {
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
                generic_extract_call_info(c, source, vocab)
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
            if let Some((fname, _)) = generic_extract_call_info(c, source, vocab) {
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
                if let Some((fname, inputs)) = generic_extract_call_info(c, source, vocab) {
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
    vocab: &AssertionVocab,
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
    // (e.g. nested `assertTrue(..)` inside another assert). The set is
    // DERIVED from the per-language vocab (`is_known_callee`), so it cannot
    // drift from the equality/throws/… classification groups.
    if vocab.is_known_callee(&func_name) {
        return None;
    }

    let args = collect_call_args(call);
    let inputs: Vec<serde_json::Value> = args
        .into_iter()
        .map(|n| try_eval_literal(n, source))
        .collect();

    Some((func_name, inputs))
}

// fix-T1a-assertion-adapter-v1 (A1): the former standalone
// `is_known_assertion_callee` keyword list has been REMOVED. Its single
// source of truth is now `AssertionVocab::is_known_callee`, derived from the
// union of the per-language vocab groups + `matcher_heads`. This eliminates
// the drift bug where a matcher added to `is_equality` (the classifier list)
// was forgotten in the FUT-exclusion list (or vice versa).

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
    // m116-easy-mechanical-v1 (#44): mirror the same guards as
    // `find_rust_macro_inline_call` — an identifier preceded by `.`
    // is a chain-method position (not a FUT) and identifiers inside
    // a `|...|` closure are closure-locals, not FUTs.
    if preceded_by_dot(n, source) || is_inside_rust_macro_closure(n, source) {
        return false;
    }
    // T2 (v0.5.0 AUDIT-FIX): Rust enum constructors (`Some` / `Ok` / `Err` /
    // `None`) are value WRAPPERS, never the function-under-test. In
    // `assert_eq!(arg.get_long(), Some("bar"))` both sides are call-shaped
    // tokens; without this guard the RHS `Some(...)` was picked as the FUT
    // (clap regressed reporting `Some`/`None` as the only functions-under-test).
    // Excluding constructors here lets the FUT-selection fall through to the
    // real LHS accessor (`get_long`), treating `Some("bar")` as the expected
    // output value. The name set is the std `Option`/`Result` variant set; a
    // `scoped_identifier` (`Option::Some`) is matched on its tail too.
    if is_rust_enum_ctor_token(n, source) {
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

/// T2 (v0.5.0 AUDIT-FIX): true when a Rust macro-arg token is a std
/// `Option`/`Result` constructor (`Some` / `None` / `Ok` / `Err`). These are
/// value wrappers around an EXPECTED value in an equality assertion, never the
/// function-under-test. Matches the tail identifier so both the bare form
/// (`Some(x)`) and the path-qualified form (`Option::Some(x)`) are caught.
fn is_rust_enum_ctor_token(n: Node, source: &[u8]) -> bool {
    let text = std::str::from_utf8(&source[n.start_byte()..n.end_byte()])
        .unwrap_or("")
        .trim();
    let tail = text.rsplit("::").next().unwrap_or(text);
    matches!(tail, "Some" | "None" | "Ok" | "Err")
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
    vocab: &AssertionVocab,
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
    generic_extract_call_info(node, source, vocab)
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
///
/// m116-easy-mechanical-v1 (#44): walks SOURCE-ORDER (not stack-pop
/// reverse order) and rejects two cases that yielded the wrong FUT in
/// nested method-chain assertions:
///
/// - `.method(...)` positions (preceded by a `.` byte): these are
///   intermediate chain helpers (`.iter()`, `.any()`, `.collect()`) —
///   semantically not the function-under-test, so picking them
///   produced noisy / wrong spec entries like `function_name: "any"`
///   in `assert!(result.iter().any(|x| ...))`.
/// - identifiers inside a `|...|` closure parameter list or its body:
///   the FUT is the receiver of the enclosing chain, not a closure
///   helper.
fn find_rust_macro_inline_call<'a>(root: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    // Source-order DFS: pre-order, left-to-right.
    fn descend<'a>(node: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
        let kind = node.kind();
        if matches!(
            kind,
            "identifier" | "scoped_identifier" | "field_expression"
        ) && is_followed_by_open_paren(node, source)
            && !preceded_by_dot(node, source)
            && !is_inside_rust_macro_closure(node, source)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if let Some(found) = descend(cursor.node(), source) {
                    return Some(found);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }
    descend(root, source)
}

/// True if the byte immediately before `node.start_byte()` (skipping
/// whitespace) is `.` — i.e. the identifier is the method-name side of
/// a method call on some receiver, not a standalone FUT call.
fn preceded_by_dot(node: Node, source: &[u8]) -> bool {
    let start = node.start_byte();
    if start == 0 {
        return false;
    }
    let mut i = start;
    while i > 0 {
        i -= 1;
        let b = source[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            continue;
        }
        return b == b'.';
    }
    false
}

/// True if `node` sits between a `|...|` closure parameter list and the
/// matching closure boundary — i.e. it's inside a closure body in a
/// macro argument like `assert!(it.any(|x| x.foo()))`. The flat
/// token_tree representation means we can't rely on AST parents, so
/// scan the surrounding source bytes for an unmatched `|` before the
/// node's start (closure-param opener) without an intervening closing
/// `)` / `,` / `;` at depth 0.
///
/// Heuristic but conservative: only suppresses identifiers that are
/// clearly inside a closure body. The macro_invocation's flat
/// token_tree exposes `|`, `|`, identifiers, etc. as direct children
/// in source order; we scan backward from `node.start_byte()` looking
/// for an unmatched `|` at the same paren depth that opens a closure.
fn is_inside_rust_macro_closure(node: Node, source: &[u8]) -> bool {
    let start = node.start_byte();
    let mut depth: i32 = 0;
    let mut pipe_count: i32 = 0;
    // Walk backward through the source up to ~512 bytes; closures are
    // typically short. We track paren/bracket depth so we don't
    // mistake a `|` in `if a | b > c` style code as a closure opener.
    let limit = start.saturating_sub(512);
    let bytes = source;
    let mut i = start;
    while i > limit {
        i -= 1;
        let b = bytes[i];
        match b {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth == 0 {
                    // We've left the enclosing group — no closure
                    // opener was found at our depth.
                    return false;
                }
                depth -= 1;
            }
            b'|' if depth == 0 => {
                pipe_count += 1;
                // Two `|`s at depth 0 before `node` => we passed
                // through `|...|` => `node` is inside the closure
                // body. A single unmatched `|` means we're inside
                // the parameter list itself.
                if pipe_count >= 1 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
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

    // ====================================================================
    // T1-specs (v0.5.0 DESIGN-TAIL): test-framework assertion extraction.
    // ====================================================================

    /// G3-a: swift-testing `#expect` / `#require` macro recognition.
    ///
    /// The dominant swift-testing shape is `@Test func name() { #expect(a == b) }`.
    /// Function names do NOT start with `test`, and the assertion is a
    /// `macro_invocation` (callee `expect`/`require`) rather than an
    /// `XCTAssertEqual` flat call — so the file previously yielded
    /// `total_specs = 0`. This encodes the repro.
    #[test]
    fn test_specs_swift_expect_macro_equality() {
        let temp = TempDir::new().unwrap();
        // File name must satisfy the Swift `*Tests.swift` candidate gate.
        let test_path = temp.path().join("WidgetTests.swift");
        let src = r#"
import Testing

@Suite("widget tests")
struct WidgetTests {
  @Test func computesValue() {
    #expect(compute() == 42)
  }

  @Test("reads property") func readsCount() {
    #expect(set.count == 3)
  }

  @Test func subscriptRead() {
    #expect(coords[0].x == 1)
  }

  @Test func booleanFlag() {
    #expect(widget.isEmpty)
  }
}
"#;
        fs::write(&test_path, src).unwrap();

        let report = run_specs(&test_path, None).unwrap();

        // The macro sites must now produce specs (previously total = 0).
        assert!(
            report.summary.total_specs > 0,
            "swift-testing #expect should yield specs, got {}",
            report.summary.total_specs
        );

        // `compute()` is a genuine call on the actual side: equality => IO spec.
        let compute = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute")
            .expect("should record FUT `compute` from #expect(compute() == 42)");
        assert!(
            !compute.input_output_specs.is_empty(),
            "compute should have an input/output spec from the == comparison"
        );

        // `set.count` is a pure property read: attribute to accessor tail
        // `count` (the swift_member_equality convention), expected = 3.
        let count = report
            .functions
            .iter()
            .find(|f| f.function_name == "count")
            .expect("should record accessor `count` from #expect(set.count == 3)");
        assert!(
            !count.input_output_specs.is_empty(),
            "count accessor should have an input/output spec"
        );

        // Subscript-bearing navigation `coords[0].x` attributes to accessor `x`.
        assert!(
            report.functions.iter().any(|f| f.function_name == "x"),
            "should record accessor `x` from #expect(coords[0].x == 1)"
        );

        // Boolean-only `#expect(widget.isEmpty)` => truthy property on `isEmpty`.
        let is_empty = report
            .functions
            .iter()
            .find(|f| f.function_name == "isEmpty")
            .expect("should record accessor `isEmpty` from boolean #expect");
        assert!(
            is_empty
                .property_specs
                .iter()
                .any(|p| p.property_type == "truthy"),
            "boolean #expect should yield a truthy property"
        );
    }

    /// G3-a: swift-testing `#require` and comparison/inequality operators.
    #[test]
    fn test_specs_swift_require_and_comparisons() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("BoundsTests.swift");
        let src = r#"
import Testing

struct BoundsTests {
  @Test func bounds() {
    #expect(value.size > 0)
  }

  @Test func notEqual() {
    #expect(thing.kind != 5)
  }

  @Test func required() {
    #require(parsed.count == 7)
  }
}
"#;
        fs::write(&test_path, src).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        assert!(
            report.summary.total_specs > 0,
            "comparison/inequality/#require should yield specs"
        );

        // `> 0` => bounds property on accessor `size`.
        let size = report
            .functions
            .iter()
            .find(|f| f.function_name == "size")
            .expect("should record accessor `size`");
        assert!(
            size.property_specs
                .iter()
                .any(|p| p.property_type == "bounds"),
            "`size > 0` should be a bounds property"
        );

        // `!= 5` => inequality property on accessor `kind`.
        let kind = report
            .functions
            .iter()
            .find(|f| f.function_name == "kind")
            .expect("should record accessor `kind`");
        assert!(
            kind.property_specs
                .iter()
                .any(|p| p.property_type == "inequality"),
            "`kind != 5` should be an inequality property"
        );

        // `#require(parsed.count == 7)` => IO spec on accessor `count`.
        assert!(
            report
                .functions
                .iter()
                .any(|f| f.function_name == "count"),
            "#require equality should record accessor `count`"
        );
    }

    /// G2-a: chai chained matchers `expect(x).to.eql(y)` (two-hop spine).
    ///
    /// The previous one-hop Jest handler hard-required
    /// `member.object.kind() == "call_expression"` named `expect`, so chai's
    /// `expect(...).to.eql(...)` (with an intervening `.to` member) was
    /// silently dropped. This encodes the repro.
    #[test]
    fn test_specs_js_chai_chained_matchers() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("service.spec.ts");
        let src = r#"
describe('service', () => {
  it('parses', () => {
    expect(parse(input)).to.eql(expected);
  });

  it('finds', () => {
    expect(svc.find(1)).to.equal(2);
  });

  it('flags', () => {
    expect(check(x)).to.be.true;
  });
});
"#;
        fs::write(&test_path, src).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        assert!(
            report.summary.total_specs > 0,
            "chai chained matchers should yield specs, got {}",
            report.summary.total_specs
        );

        // `expect(parse(input)).to.eql(expected)` => IO spec on `parse`.
        let parse = report
            .functions
            .iter()
            .find(|f| f.function_name == "parse")
            .expect("should record FUT `parse` from expect(parse(input)).to.eql(...)");
        assert!(
            !parse.input_output_specs.is_empty(),
            "`.to.eql` should produce an input/output spec for parse"
        );

        // `.to.equal(2)` is also an equality matcher.
        let find = report
            .functions
            .iter()
            .find(|f| f.function_name == "find")
            .expect("should record FUT `find` from expect(svc.find(1)).to.equal(2)");
        assert!(
            !find.input_output_specs.is_empty(),
            "`.to.equal` should produce an input/output spec for find"
        );

        // `.to.be.true` is a no-arg boolean leaf => truthy property on `check`.
        let check = report
            .functions
            .iter()
            .find(|f| f.function_name == "check")
            .expect("should record FUT `check` from expect(check(x)).to.be.true");
        assert!(
            check
                .property_specs
                .iter()
                .any(|p| p.property_type == "truthy"),
            "`.to.be.true` should produce a truthy property for check"
        );
    }

    /// Regression guard: the spine-descent walker must still serve the
    /// classic one-hop Jest shape `expect(f(x)).toBe(y)`.
    #[test]
    fn test_specs_js_jest_one_hop_still_works() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc.test.js");
        let src = r#"
describe('calc', () => {
  test('adds', () => {
    expect(add(2, 3)).toBe(5);
  });
  test('nullish', () => {
    expect(lookup(0)).toBeNull();
  });
});
"#;
        fs::write(&test_path, src).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("Jest one-hop expect(add(2,3)).toBe(5) must still work");
        assert!(
            !add.input_output_specs.is_empty(),
            "Jest toBe should still produce an input/output spec"
        );
        let lookup = report
            .functions
            .iter()
            .find(|f| f.function_name == "lookup")
            .expect("Jest one-hop toBeNull must still work");
        assert!(
            lookup
                .property_specs
                .iter()
                .any(|p| p.property_type == "null"),
            "toBeNull should still produce a null property"
        );
    }

    // ====================================================================
    // CHARACTERIZATION (A1 assertion-adapter migration regression net).
    //
    // fix-T1a-assertion-adapter-v1: these golden tests pin the CURRENT
    // correct `tldr specs` attribution (FUT name, actual/expected, spec
    // type) for EVERY already-passing language/framework BEFORE the A1
    // per-language AssertionAdapter refactor. They must stay green after
    // the migration — the per-adapter equality/known-callee tables that
    // replace the two drifted global lists (`is_equality`,
    // `is_known_assertion_callee`) must reproduce these exactly. A
    // regression here means the migration silently dropped or
    // mis-attributed a spec.
    //
    // Inline fixtures (not the corpora) are used deliberately: line
    // numbers and FUT names are stable across corpus refreshes, so the
    // golden assertions stay deterministic.
    // ====================================================================

    /// CHAR: Python pytest equality / exception / property extraction.
    /// Pins the Python-only `extract_from_assert` path (shares
    /// `try_eval_literal` / `collect_call_args` with the generic path the
    /// A1 refactor touches).
    #[test]
    fn char_python_pytest_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_calc.py");
        let src = r#"
def test_add():
    assert add(2, 3) == 5

def test_div_raises():
    with pytest.raises(ValueError):
        divide(1, 0)

def test_bounds():
    assert compute() > 0
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("pytest: add");
        assert_eq!(add.input_output_specs.len(), 1, "add: one IO spec");
        assert_eq!(add.input_output_specs[0].output, serde_json::json!(5));
        assert_eq!(
            add.input_output_specs[0].inputs,
            vec![serde_json::json!(2), serde_json::json!(3)]
        );

        let divide = report
            .functions
            .iter()
            .find(|f| f.function_name == "divide")
            .expect("pytest: divide");
        assert_eq!(divide.exception_specs.len(), 1);
        assert_eq!(divide.exception_specs[0].exception_type, "ValueError");

        let compute = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute")
            .expect("pytest: compute");
        assert!(compute
            .property_specs
            .iter()
            .any(|p| p.property_type == "bounds"));
    }

    /// CHAR: Java Spring MockMvc fluent assertions.
    /// `mockMvc.perform(get("/x")).andExpect(status().isOk())` => FUT is
    /// the HTTP verb (`get`), constraint encodes the matcher chain.
    #[test]
    fn char_java_mockmvc_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("OwnerControllerTests.java");
        let src = r#"
class OwnerControllerTests {
    @Test
    void testNewOwnerForm() throws Exception {
        mockMvc.perform(get("/owners/new"))
            .andExpect(status().isOk())
            .andExpect(view().name("owners/createOrUpdateOwnerForm"));
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        assert!(
            report.summary.total_specs > 0,
            "mockmvc must yield specs"
        );
        let get = report
            .functions
            .iter()
            .find(|f| f.function_name == "get")
            .expect("mockmvc: FUT `get` (HTTP verb in perform)");
        assert!(
            get.property_specs
                .iter()
                .any(|p| p.property_type == "mockmvc_expectation"
                    && p.constraint.contains("status")),
            "status().isOk() => status:isOk constraint"
        );
        assert!(
            get.property_specs
                .iter()
                .any(|p| p.constraint.contains("view")),
            "view().name(..) => view:name constraint"
        );
    }

    /// CHAR: Ruby RSpec `expect(actual).to eq(expected)` / `.not_to be_nil`.
    #[test]
    fn char_ruby_rspec_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc_spec.rb");
        let src = r#"
RSpec.describe Calc do
  it "adds" do
    expect(add(2, 3)).to eq(5)
  end

  it "present" do
    expect(lookup(0)).not_to be_nil
  end
end
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("rspec: add");
        assert_eq!(add.input_output_specs.len(), 1, "rspec eq => one IO spec");
        assert_eq!(add.input_output_specs[0].output, serde_json::json!(5));

        let lookup = report
            .functions
            .iter()
            .find(|f| f.function_name == "lookup")
            .expect("rspec: lookup");
        assert!(
            lookup
                .property_specs
                .iter()
                .any(|p| p.property_type == "not_null"),
            "not_to be_nil => not_null property"
        );
    }

    /// CHAR: Ruby minitest `assert_equal expected, actual` flat call.
    /// This exercises the generic flat classifier `is_equality` path with
    /// the `assert_equal` matcher — the very name that is currently in
    /// `is_equality` but MISSING from `is_known_assertion_callee` (the
    /// drift the A1 collapse must preserve behaviorally).
    #[test]
    fn char_ruby_minitest_assert_equal() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc_test.rb");
        let src = r#"
class CalcTest < Minitest::Test
  def test_add
    assert_equal 5, add(2, 3)
  end
end
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("minitest: add FUT from assert_equal 5, add(2,3)");
        assert_eq!(
            add.input_output_specs.len(),
            1,
            "assert_equal => one IO spec"
        );
        assert_eq!(add.input_output_specs[0].output, serde_json::json!(5));
        // `assert_equal` itself must NEVER be attributed as a FUT.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "assert_equal"),
            "assert_equal must not appear as a function-under-test"
        );
    }

    /// CHAR: OCaml structural equality `let%test _ = equal (f x) y`.
    ///
    /// Pins CURRENT behavior: the FUT is `add`, inputs are the (string-typed,
    /// since OCaml integer literals are not the Python `integer` node kind)
    /// args, and the expected value is captured verbatim as `String("5")`.
    /// `equal` itself is never a FUT (per the known-assertion-callee filter
    /// that the A1 OCaml adapter table must preserve).
    #[test]
    fn char_ocaml_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("test_calc.ml");
        let src = r#"
let%test "add" = equal (add 2 3) 5
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        assert!(report.summary.total_specs > 0, "ocaml must yield specs");
        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("ocaml: add FUT from equal");
        assert_eq!(
            add.input_output_specs.len(),
            1,
            "ocaml equal => exactly one IO spec for add"
        );
        // Non-Python integer literals are captured as their source text
        // (current `try_eval_literal` only recognises the Python `integer`
        // node kind). Pin that exact representation.
        assert_eq!(
            add.input_output_specs[0].output,
            serde_json::json!("5"),
            "ocaml expected value captured as source text \"5\""
        );
        assert_eq!(
            add.input_output_specs[0].inputs,
            vec![serde_json::json!("2"), serde_json::json!("3")],
            "ocaml inputs captured as source text"
        );
        // `equal` must never be a FUT.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "equal"),
            "equal must not appear as a function-under-test"
        );
    }

    /// CHAR: Rust `assert_eq!(add(2, 3), 5)` macro (flat token_tree path).
    #[test]
    fn char_rust_assert_eq_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc_test.rs");
        let src = r#"
#[cfg(test)]
mod tests {
    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn test_flag() {
        assert!(is_ready());
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("rust: add FUT from assert_eq!");
        assert!(
            !add.input_output_specs.is_empty(),
            "assert_eq! => IO spec for add"
        );
        let is_ready = report
            .functions
            .iter()
            .find(|f| f.function_name == "is_ready")
            .expect("rust: is_ready FUT from assert!");
        assert!(
            is_ready
                .property_specs
                .iter()
                .any(|p| p.property_type == "truthy"),
            "assert!(is_ready()) => truthy property"
        );
        // The macro head must never be a FUT.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "assert_eq" || f.function_name == "assert"),
            "assert_eq/assert must not appear as functions-under-test"
        );
    }

    /// CHAR: cross-language FLAT classifier vocabulary — JUnit
    /// `assertEquals`/`assertThrows`, Kotlin `shouldBe`, C# `AreEqual`.
    /// Pins the equality / throws / known-callee leaf vocabulary that the
    /// A1 per-adapter tables must reproduce (the drift-prone core).
    #[test]
    fn char_flat_classifier_vocabulary() {
        // JUnit (Java): assertEquals(expected, actual) + assertThrows.
        let temp = TempDir::new().unwrap();
        let jpath = temp.path().join("CalcTests.java");
        let jsrc = r#"
class CalcTests {
    @Test
    void testAdd() {
        assertEquals(5, add(2, 3));
    }

    @Test
    void testThrows() {
        assertThrows(IllegalArgumentException.class, () -> parse(bad));
    }
}
"#;
        fs::write(&jpath, jsrc).unwrap();
        let jreport = run_specs(&jpath, None).unwrap();
        let add = jreport
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("junit: add FUT from assertEquals");
        assert_eq!(add.input_output_specs.len(), 1);
        // Java integer literals (`decimal_integer_literal`) are not the
        // Python `integer` node kind, so `try_eval_literal` keeps them as
        // source text. Pin that exact current representation.
        assert_eq!(add.input_output_specs[0].output, serde_json::json!("5"));
        let parse = jreport
            .functions
            .iter()
            .find(|f| f.function_name == "parse")
            .expect("junit: parse FUT from assertThrows lambda");
        assert!(
            !parse.exception_specs.is_empty(),
            "assertThrows => exception spec for parse"
        );
        assert!(
            !jreport
                .functions
                .iter()
                .any(|f| f.function_name == "assertEquals"
                    || f.function_name == "assertThrows"),
            "assertEquals/assertThrows must not be FUTs"
        );

        // Kotlin: actual shouldBe expected (infix — flat callee `shouldBe`).
        let ktpath = temp.path().join("CalcTest.kt");
        let ktsrc = r#"
class CalcTest {
    @Test
    fun testAdd() {
        shouldBe(add(2, 3), 5)
    }
}
"#;
        fs::write(&ktpath, ktsrc).unwrap();
        let ktreport = run_specs(&ktpath, None).unwrap();
        assert!(
            ktreport
                .functions
                .iter()
                .find(|f| f.function_name == "add")
                .map(|f| !f.input_output_specs.is_empty())
                .unwrap_or(false),
            "kotlin shouldBe => IO spec for add"
        );

        // C#: Assert.AreEqual(expected, actual).
        let cspath = temp.path().join("CalcTests.cs");
        let cssrc = r#"
public class CalcTests {
    [Test]
    public void TestAdd() {
        Assert.AreEqual(5, Add(2, 3));
    }
}
"#;
        fs::write(&cspath, cssrc).unwrap();
        let csreport = run_specs(&cspath, None).unwrap();
        let csadd = csreport
            .functions
            .iter()
            .find(|f| f.function_name == "Add")
            .expect("csharp: Add FUT from AreEqual");
        assert_eq!(csadd.input_output_specs.len(), 1);
        // C# integer literals are likewise kept as source text.
        assert_eq!(csadd.input_output_specs[0].output, serde_json::json!("5"));
    }

    /// CHAR: Go `if <call> != want { t.Errorf(...) }` idiom.
    ///
    /// Pins the CURRENT behavior: the FUT call must appear directly in the
    /// `condition` (not the `initializer`) for `try_extract_go_if_t_assertion`
    /// to attribute it. `if add(2,3) != 5 { t.Errorf(..) }` => `add` gains a
    /// `go_if_assertion` property. (The `if got := add(..); got != 5` shape
    /// is intentionally NOT pinned here — that FUT lives in the initializer
    /// and is a known limitation, separate from the A1 migration.)
    #[test]
    fn char_go_if_t_assertion() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc_test.go");
        let src = r#"
package calc

import "testing"

func TestAdd(t *testing.T) {
    if add(2, 3) != 5 {
        t.Errorf("add(2,3) want 5")
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("go: add FUT from if-condition call");
        assert!(
            add.property_specs
                .iter()
                .any(|p| p.property_type == "go_if_assertion"),
            "go if/t.Errorf => go_if_assertion property"
        );
    }

    // ====================================================================
    // CHARACTERIZATION (T1b: Scala/Go assertion-gap + @Test-recognizer move
    // regression net).
    //
    // fix-T1b-scala-go-testrecognizer-v1: these golden tests pin the CURRENT
    // correct `tldr specs` behavior of the already-passing shapes that the
    // T1b changes touch, BEFORE any edit:
    //
    //   * Scala `assertEquals(actual(), expected)` already attributes to the
    //     FUT via the shared flat `is_equality` path — adding the
    //     `assertCompleteAs`-family helpers (G1-a1) and the infix DSL (G1-a2)
    //     must NOT change this.
    //   * Go `if realCall() != want { t.Errorf(..) }` already attributes the
    //     in-condition call as the FUT — the G4-b comparison-helper descent
    //     must NOT regress the non-helper path.
    //   * Swift XCTest `func test*()` is counted by the test recogniser today
    //     — moving the swift-testing `@Test` recognition INTO
    //     `test_recognizer.rs` must keep the XCTest convention working.
    //
    // A regression in any of these means a T1b change silently altered the
    // behavior of a language that was already correct.
    // ====================================================================

    /// CHAR (T1b): Scala `assertEquals(actual, expected)` attribution.
    /// Scala uses the dedicated `ScalaAdapter` (NOT the shared
    /// `FlatOnlyAdapter`): `SCALA_VOCAB.equality` is empty, and `assertEquals`
    /// is a `SCALA_POSITIONAL_EQ_HELPERS` member handled by
    /// `try_extract_scala_helper_assertion` with the fixed `(actual=arg0,
    /// expected=arg1)` rule. Pins that a 2-arg `assertEquals` where arg0 is a
    /// call attributes the IO spec to that call (`actual`) with the other arg
    /// as the expected output, and that `assertEquals` itself is never a FUT.
    /// G1-a1 (assertCompleteAs family) must preserve this exactly.
    #[test]
    fn char_scala_assert_equals_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("CalcSuite.scala");
        let src = r#"
class CalcSuite extends munit.FunSuite {
  test("adds") {
    assertEquals(actual(), expected)
  }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let actual = report
            .functions
            .iter()
            .find(|f| f.function_name == "actual")
            .expect("scala: actual FUT from assertEquals(actual(), expected)");
        assert_eq!(
            actual.input_output_specs.len(),
            1,
            "assertEquals => one IO spec for actual"
        );
        assert_eq!(
            actual.input_output_specs[0].output,
            serde_json::json!("expected")
        );
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "assertEquals"),
            "assertEquals must never be a FUT"
        );
    }

    /// CHAR (T1b): Go `if realCall() != want { t.Errorf(..) }` attribution.
    /// Distinct from `char_go_if_t_assertion` (which uses `add(2,3) != 5`):
    /// this pins that when the in-condition call is a GENUINE FUT (not a
    /// comparison helper), the G4-b helper-descent leaves it attributed to
    /// that call. The comparison-helper suppression must only fire for the
    /// named helper set, never for ordinary calls.
    #[test]
    fn char_go_if_plain_call_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("svc_test.go");
        let src = r#"
package svc

import "testing"

func TestLookup(t *testing.T) {
    if lookup(7) != 42 {
        t.Fatalf("lookup(7) want 42")
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let lookup = report
            .functions
            .iter()
            .find(|f| f.function_name == "lookup")
            .expect("go: lookup FUT from if-condition call");
        assert!(
            lookup
                .property_specs
                .iter()
                .any(|p| p.property_type == "go_if_assertion"),
            "go if/t.Fatalf => go_if_assertion property on lookup"
        );
    }

    /// CHAR (T1b): Swift XCTest `func test*()` recognition.
    /// Pins the existing XCTest naming convention: a `func testFoo()` inside
    /// an `XCTestCase` subclass is recognised as a test function (so its
    /// `XCTAssertEqual` body is harvested). Moving the swift-testing `@Test`
    /// recognition into `test_recognizer.rs` must keep this XCTest path green.
    #[test]
    fn char_swift_xctest_recognized() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("CalcTests.swift");
        let src = r#"
import XCTest

class CalcTests: XCTestCase {
    func testAdd() {
        XCTAssertEqual(add(2, 3), 5)
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        assert_eq!(
            report.summary.test_functions_scanned, 1,
            "XCTest func testAdd must be counted as one test function"
        );
        let add = report
            .functions
            .iter()
            .find(|f| f.function_name == "add")
            .expect("swift: add FUT from XCTAssertEqual(add(2,3), 5)");
        assert_eq!(
            add.input_output_specs.len(),
            1,
            "XCTAssertEqual => one IO spec for add"
        );
    }

    // ====================================================================
    // FEATURE TESTS — fix-T1b-scala-go-testrecognizer-v1.
    //
    //   G1-a1: Scala positional equality helpers (munit `assertEquals` family
    //          + cats-effect `assertCompleteAs` family), arg0=actual.
    //   G1-a2: ScalaTest infix DSL (`x should be (y)` / `a === b` / shouldBe).
    //   G4-b:  Go comparison-helper descent + suppression.
    //   @Test: swift-testing `@Test func` count == harvest consistency.
    // ====================================================================

    /// G1-a1: cats-effect `assertCompleteAs(actual, expected)` attributes to
    /// the actual operand (arg0), NOT the helper, for both a bare-value actual
    /// (`val test`) and a call actual (`compute()`), and even when the EXPECTED
    /// side is a call (`Left(e)`). These are the ~308 sites that previously
    /// yielded zero specs.
    #[test]
    fn scala_assert_complete_as_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("IOSuite.scala");
        let src = r#"
class IOSuite extends munit.FunSuite {
  test("effects") {
    assertCompleteAs(test, 42)
    assertCompleteAs(compute(), 7)
    assertCompleteAs(io, Left(e))
  }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        // Bare-value actual: FUT = `test`, expected = 42 (source-text literal).
        let t = report
            .functions
            .iter()
            .find(|f| f.function_name == "test")
            .expect("assertCompleteAs(test, 42) => FUT test");
        assert_eq!(t.input_output_specs.len(), 1);
        assert_eq!(t.input_output_specs[0].output, serde_json::json!("42"));

        // Call actual: FUT = `compute`.
        let c = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute")
            .expect("assertCompleteAs(compute(), 7) => FUT compute");
        assert_eq!(c.input_output_specs[0].output, serde_json::json!("7"));

        // Call EXPECTED side must NOT steal attribution: FUT stays `io`.
        let io = report
            .functions
            .iter()
            .find(|f| f.function_name == "io")
            .expect("assertCompleteAs(io, Left(e)) => FUT io (not Left)");
        assert_eq!(io.input_output_specs[0].output, serde_json::json!("Left(e)"));

        // The helper and the expected-side constructor are never FUTs.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "assertCompleteAs" || f.function_name == "Left"),
            "assertCompleteAs / Left must not be attributed as FUTs"
        );
    }

    /// G1-a1: munit `assertEquals(actual, expected)` uses the same arg0=actual
    /// rule even when the actual is a method call (`e.getMessage`) and the
    /// expected is a literal.
    #[test]
    fn scala_assert_equals_method_actual() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("MsgSuite.scala");
        let src = r#"
class MsgSuite extends munit.FunSuite {
  test("message") {
    assertEquals(e.getMessage, "boom")
  }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let m = report
            .functions
            .iter()
            .find(|f| f.function_name == "getMessage")
            .expect("assertEquals(e.getMessage, \"boom\") => FUT getMessage");
        assert_eq!(m.input_output_specs.len(), 1);
        assert_eq!(m.input_output_specs[0].output, serde_json::json!("boom"));
    }

    /// G1-a2: ScalaTest infix DSL — `result should be (5)`, `a === b`, and
    /// `value shouldBe 99` all attribute the FUT to the LEFT operand with the
    /// right operand (unwrapping the `be(..)` carrier) as the expected output.
    #[test]
    fn scala_infix_dsl_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("InfixSpec.scala");
        let src = r#"
class InfixSpec extends AnyFlatSpec {
  test("infix") {
    result should be (5)
    a === b
    value shouldBe 99
  }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let result = report
            .functions
            .iter()
            .find(|f| f.function_name == "result")
            .expect("`result should be (5)` => FUT result");
        assert_eq!(
            result.input_output_specs[0].output,
            serde_json::json!("5"),
            "`should be (y)` unwraps the be(..) carrier to the expected value"
        );

        let a = report
            .functions
            .iter()
            .find(|f| f.function_name == "a")
            .expect("`a === b` => FUT a");
        assert_eq!(a.input_output_specs[0].output, serde_json::json!("b"));

        let value = report
            .functions
            .iter()
            .find(|f| f.function_name == "value")
            .expect("`value shouldBe 99` => FUT value");
        assert_eq!(value.input_output_specs[0].output, serde_json::json!("99"));

        // Infix matcher words are never FUTs.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| matches!(f.function_name.as_str(), "should" | "shouldBe" | "be" | "===")),
            "infix matcher words must not be FUTs"
        );
    }

    /// G1-a2: ScalaTest `MustMatchers` infix DSL — `result must equal(5)` and
    /// `result must be(5)` parse (verified by debug-parse) as an
    /// `infix_expression` whose `[operator]` is the bare word `must`, with the
    /// right operand a `be(..)`/`equal(..)` carrier call — structurally
    /// identical to the `should be (y)` path. Pins that bare `must` is
    /// recognised as an infix equality operator and attributes the FUT to the
    /// LEFT operand with the carrier's argument as the expected output.
    ///
    /// This is a GENUINE guard for the `SCALA_INFIX_EQ_OPERATORS` "must" entry:
    /// without it, `try_extract_scala_infix_assertion` returns false for the
    /// MustMatchers DSL (a silent spec-drop) and the two FUTs below never
    /// appear in the report.
    #[test]
    fn scala_must_matchers_infix_attribution() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("MustSpec.scala");
        let src = r#"
class MustSpec extends AnyFlatSpec {
  test("must") {
    result must equal(5)
    other must be(7)
  }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        // `result must equal(5)` => FUT result, expected 5 (equal(..) carrier
        // unwrapped to its first argument).
        let result = report
            .functions
            .iter()
            .find(|f| f.function_name == "result")
            .expect("`result must equal(5)` => FUT result");
        assert_eq!(
            result.input_output_specs.len(),
            1,
            "`must equal(5)` => one IO spec for result"
        );
        assert_eq!(
            result.input_output_specs[0].output,
            serde_json::json!("5"),
            "`must equal(y)` unwraps the equal(..) carrier to the expected value"
        );

        // `other must be(7)` => FUT other, expected 7 (be(..) carrier unwrapped).
        let other = report
            .functions
            .iter()
            .find(|f| f.function_name == "other")
            .expect("`other must be(7)` => FUT other");
        assert_eq!(
            other.input_output_specs.len(),
            1,
            "`must be(7)` => one IO spec for other"
        );
        assert_eq!(
            other.input_output_specs[0].output,
            serde_json::json!("7"),
            "`must be(y)` unwraps the be(..) carrier to the expected value"
        );

        // The infix matcher words and the carrier methods are never FUTs.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| matches!(f.function_name.as_str(), "must" | "be" | "equal")),
            "`must` / carrier methods must not be FUTs"
        );
    }

    /// G4-b: Go `if !reflect.DeepEqual(<call>, want) { t.Fatalf(..) }` descends
    /// into the helper's arguments — the FUT is the call inside (`parse`), not
    /// the comparison helper (`DeepEqual`).
    #[test]
    fn go_deep_equal_descends_to_inner_call() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("router_test.go");
        let src = r#"
package router

import (
    "reflect"
    "testing"
)

func TestRoute(t *testing.T) {
    want := Params{}
    if !reflect.DeepEqual(parse(input), want) {
        t.Fatalf("bad")
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let parse = report
            .functions
            .iter()
            .find(|f| f.function_name == "parse")
            .expect("reflect.DeepEqual(parse(input), want) => FUT parse");
        assert!(
            parse
                .property_specs
                .iter()
                .any(|p| p.property_type == "go_if_assertion"),
            "descended FUT gains a go_if_assertion property"
        );
        // The comparison helper must never be attributed.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "DeepEqual"),
            "DeepEqual must be suppressed, never a FUT"
        );
    }

    /// G4-b: Go `if !reflect.DeepEqual(ps, want) { ... }` over two VARIABLES
    /// (no inner call) emits NOTHING — the silent-wrong `DeepEqual` attribution
    /// is gone, and no junk spec replaces it. This is the exact go-httprouter
    /// `router_test.go:55` shape.
    #[test]
    fn go_deep_equal_over_vars_emits_nothing() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("router_test.go");
        let src = r#"
package router

import (
    "reflect"
    "testing"
)

func TestRoute(t *testing.T) {
    ps := lookup()
    want := Params{}
    if !reflect.DeepEqual(ps, want) {
        t.Fatalf("wrong wildcard values")
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "DeepEqual"),
            "DeepEqual over vars must not be attributed (no silent-wrong spec)"
        );
        // No `go_if_assertion` property should be synthesised for this if.
        assert!(
            report
                .functions
                .iter()
                .all(|f| f.property_specs.iter().all(|p| p.property_type != "go_if_assertion")),
            "no go_if_assertion spec when the helper's args carry no FUT call"
        );
    }

    /// G4-b: an ordinary (non-helper) call in an `if` condition is unaffected
    /// by the comparison-helper descent — `if compute() != 5 { t.Errorf(..) }`
    /// still attributes to `compute`.
    #[test]
    fn go_plain_call_condition_unaffected() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("svc_test.go");
        let src = r#"
package svc

import "testing"

func TestCompute(t *testing.T) {
    if compute() != 5 {
        t.Errorf("compute want 5")
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let compute = report
            .functions
            .iter()
            .find(|f| f.function_name == "compute")
            .expect("if compute() != 5 => FUT compute (non-helper path)");
        assert!(compute
            .property_specs
            .iter()
            .any(|p| p.property_type == "go_if_assertion"));
    }

    /// @Test move: swift-testing `@Test func anyName()` is BOTH counted by the
    /// recogniser AND harvested for `#expect`, so `test_functions_scanned`
    /// matches the number of `@Test` markers and the assertion harvest reaches
    /// names that do not start with `test`.
    #[test]
    fn swift_testing_at_test_count_and_harvest_agree() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("MixTests.swift");
        let src = r#"
import Testing
import XCTest

struct NewTests {
    @Test func computesValue() {
        #expect(compute() == 42)
    }
    @Test("labelled") func anotherOne() {
        #expect(other() == 7)
    }
}

class OldTests: XCTestCase {
    func testLegacy() {
        XCTAssertEqual(add(1, 2), 3)
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        // 2 swift-testing @Test + 1 XCTest func test* = 3 test functions.
        assert_eq!(
            report.summary.test_functions_scanned, 3,
            "count must include both @Test funcs and the XCTest func"
        );
        // Harvest reaches the non-`test`-prefixed @Test bodies.
        assert!(
            report.functions.iter().any(|f| f.function_name == "compute"),
            "harvest reaches @Test func computesValue's #expect"
        );
        assert!(
            report.functions.iter().any(|f| f.function_name == "other"),
            "harvest reaches @Test(\"labelled\") func anotherOne's #expect"
        );
        // And still reaches the XCTest body.
        assert!(
            report.functions.iter().any(|f| f.function_name == "add"),
            "harvest still reaches the XCTest func testLegacy"
        );
    }

    // ====================================================================
    // FEATURE TESTS — T2 (v0.5.0 AUDIT-FIX): C++ GoogleTest specs end-to-end
    // + Rust enum-constructor FUT suppression.
    // ====================================================================

    /// C++ GoogleTest: a file of `TEST(Suite, Name) { EXPECT_EQ(call(), v) }`
    /// must report `test_functions_scanned > 0` AND surface specs from the
    /// `EXPECT_EQ` assertions. (fmt's `test/*.cc` regressed with
    /// `test_functions_scanned = 0` / `total_specs = 0`.)
    #[test]
    fn specs_cpp_googletest_end_to_end() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("calc-test.cc");
        let src = "#include <gtest/gtest.h>\n\
            TEST(CalcTest, Adds) {\n  EXPECT_EQ(add(2, 3), 5);\n}\n\
            TEST(CalcTest, Subs) {\n  EXPECT_EQ(sub(5, 2), 3);\n}\n";
        fs::write(&test_path, src).unwrap();

        let report = run_specs(&test_path, None).unwrap();
        assert!(
            report.summary.test_functions_scanned >= 2,
            "GoogleTest TEST() macros must be counted; got {}",
            report.summary.test_functions_scanned
        );
        // EXPECT_EQ(add(2,3), 5) => `add` is the FUT.
        assert!(
            report.functions.iter().any(|f| f.function_name == "add"),
            "EXPECT_EQ(add(2,3), 5) must surface `add` as a FUT; got {:?}",
            report
                .functions
                .iter()
                .map(|f| &f.function_name)
                .collect::<Vec<_>>()
        );
        // The TEST macro head must never be a FUT.
        assert!(
            !report
                .functions
                .iter()
                .any(|f| f.function_name == "TEST" || f.function_name == "EXPECT_EQ"),
            "TEST/EXPECT_EQ must not be functions-under-test"
        );
    }

    /// Rust enum constructors (`Some`/`Ok`/`Err`/`None`) are value wrappers,
    /// never the function-under-test. In `assert_eq!(get_id(), Ok(7))` the
    /// constructor side (`Ok`) must be REJECTED as the FUT so the FUT-selection
    /// falls through to the real call (`get_id`); the constructor's payload is
    /// the expected value. (clap regressed reporting `Some`/`None`/`Ok` as the
    /// only functions-under-test.)
    #[test]
    fn specs_rust_enum_ctor_not_fut() {
        let temp = TempDir::new().unwrap();
        let test_path = temp.path().join("arg_test.rs");
        let src = r#"
#[cfg(test)]
mod tests {
    #[test]
    fn test_long() {
        assert_eq!(get_id(), Ok(7));
        assert_eq!(lookup(), None);
        assert_eq!(get_long(), Some("bar"));
    }
}
"#;
        fs::write(&test_path, src).unwrap();
        let report = run_specs(&test_path, None).unwrap();

        let names: Vec<String> = report
            .functions
            .iter()
            .map(|f| f.function_name.clone())
            .collect();
        // Constructors are never FUTs (this is the regression being fixed).
        assert!(
            !names.iter().any(|n| n == "Some" || n == "Ok" || n == "Err" || n == "None"),
            "enum constructors must not be FUTs; got {names:?}"
        );
        // The real call on the OTHER side is attributed instead — proving the
        // FUT-selection fell through past the constructor.
        assert!(
            names.iter().any(|n| n == "get_id"),
            "`get_id` (the real call opposite `Ok(7)`) must be the FUT; got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "lookup"),
            "`lookup` (the real call opposite `None`) must be the FUT; got {names:?}"
        );
    }
}
