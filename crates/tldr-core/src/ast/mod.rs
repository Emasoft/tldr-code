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
//! - `toc` - heuristic table-of-contents scanning for `.txt`/`.text` files
//!   (NO tree-sitter grammar exists for prose; the Log no-grammar precedent)
//! - `csvscan` - native RFC 4180 record scanning for `.csv`/`.tsv` files
//!   (the only CSV grammar crate on crates.io is unbuildable — cc build-dep
//!   conflict with ts 0.25 + ts-0.20-era exports with no bridge LanguageFns;
//!   the Log/Text no-grammar precedent)
//! - `sqlscan` - native SQL schema-outline scanning for `.sql`/`.ddl` files
//!   (crates.io only publishes tree-sitter-sql 0.0.2, dead since 2021 — the
//!   Log/Text/CSV no-grammar precedent; statement-splitter + DDL kind table)
//! - `ooxml` - OOXML containers (.docx/.xlsx/.pptx): in-memory unzip +
//!   the XML element walker over the container's XML parts
//! - `doclinks` - document link extraction: markdown/html/xml hyperlinks
//!   as ImportInfo entries (doclinks-v1)

pub mod count;
pub mod csvscan;
pub mod doclinks;
pub mod dotfiles;
pub mod elements;
pub mod extract;
pub mod extractor;
pub mod function_finder;
pub mod imports;
pub mod jsonl;
pub mod logs;
pub mod ooxml;
pub mod parser;
pub mod sqlscan;
pub mod toc;
pub mod yaml_chunk;

pub use count::{count_functions_canonical, count_functions_canonical_from_modules};
pub use csvscan::{
    delimiter_for, is_csv_path, is_tsv_path, parse_csv_file, stream_csv_records, CsvField,
    CsvRecord,
};
pub use doclinks::extract_doc_links;
pub use dotfiles::{is_env_path, is_ignore_path, parse_env_file, parse_ignore_file};
pub use elements::extract_elements;
pub use extract::{extract_file, extract_file_with_lang, extract_from_tree};
pub use extractor::{extract_definition_entries, get_code_structure, DefinitionEntry};
pub use imports::get_imports;
pub use jsonl::{
    first_row_tree, is_jsonl_path, stream_jsonl, JsonlStreamReport, JsonlStreamSummary,
};
pub use logs::{is_log_path, parse_log_file, stream_log_entries, LogEntry};
pub use ooxml::{extract_ooxml, is_ooxml_path, OoxmlKind};
pub use parser::ParserPool;
pub use sqlscan::{extract_sql_refs, is_sql_path, parse_sql_schema};
pub use toc::{is_text_path, parse_text_file, scan_toc};
