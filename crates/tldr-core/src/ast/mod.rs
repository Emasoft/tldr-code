//! AST extraction and parsing for TLDR
//!
//! This module provides tree-sitter based code parsing and structure extraction.
//! It implements the core Layer 1 (AST) functionality:
//!
//! - `parser` - Tree-sitter parser pool for efficient parsing
//! - `extractor` - Extract code structure (functions, classes, imports)
//! - `extract` - Full module extraction with call graph
//! - `imports` - Language-specific import parsing

pub mod count;
pub mod cpp_macro;
pub mod entity;
pub mod extract;
pub mod extractor;
pub mod function_finder;
pub mod imports;
pub mod parser;

pub use count::{count_functions_canonical, count_functions_canonical_from_modules};
pub use extract::{extract_file, extract_file_with_lang, extract_from_tree, extract_function_params};
pub use extractor::{detect_project_languages, get_code_structure, get_polyglot_code_structure};
pub use imports::get_imports;
pub use parser::ParserPool;
