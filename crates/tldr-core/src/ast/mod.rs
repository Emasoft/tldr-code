//! AST extraction and parsing for TLDR
//!
//! This module provides tree-sitter based code parsing and structure extraction.
//! It implements the core Layer 1 (AST) functionality:
//!
//! - `parser` - Tree-sitter parser pool for efficient parsing
//! - `extractor` - Extract code structure (functions, classes, imports)
//! - `extract` - Full module extraction with call graph
//! - `elements` - Element extraction for data/config formats (JSON/YAML/TOML/Bash)
//! - `imports` - Language-specific import parsing

//! - `jsonl` - JSONL/NDJSON row streaming (one JSON document per row)
//! - `logs` - native log-entry scanning for `.log` files (NO tree-sitter
//!   grammar exists for logs; this scanner is the only consumer)
//! - `ooxml` - OOXML containers (.docx/.xlsx/.pptx): in-memory unzip +
//!   the XML element walker over the container's XML parts
//! - `doclinks` - document link extraction: markdown/html/xml hyperlinks
//!   as ImportInfo entries (doclinks-v1)

pub mod count;
pub mod doclinks;
pub mod elements;
pub mod extract;
pub mod extractor;
pub mod function_finder;
pub mod imports;
pub mod jsonl;
pub mod logs;
pub mod ooxml;
pub mod parser;

pub use count::{count_functions_canonical, count_functions_canonical_from_modules};
pub use doclinks::extract_doc_links;
pub use elements::extract_elements;
pub use extract::{extract_file, extract_file_with_lang, extract_from_tree};
pub use extractor::get_code_structure;
pub use imports::get_imports;
pub use jsonl::{
    first_row_tree, is_jsonl_path, stream_jsonl, JsonlStreamReport, JsonlStreamSummary,
};
pub use logs::{is_log_path, parse_log_file, stream_log_entries, LogEntry};
pub use ooxml::{extract_ooxml, is_ooxml_path, OoxmlKind};
pub use parser::ParserPool;
