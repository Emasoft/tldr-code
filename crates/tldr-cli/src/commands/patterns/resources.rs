//! Resources Command - Resource Lifecycle Analysis
//!
//! Analyzes resource lifecycle to detect leaks, double-close, and use-after-close issues.
//!
//! # Analysis Types
//!
//! - R1: Resource detection - Identify resources requiring close
//! - R2: Close verification - All-paths leak detection
//! - R3: Double-close detection - Closing resources twice
//! - R4: Use-after-close - Using closed resources
//! - R6: Context manager suggestions - Suggest `with` statement
//! - R7: Leak path enumeration - Detailed paths to leaks
//! - R9: Constraint generation - LLM-ready constraints
//!
//! # TIGER Mitigations
//!
//! - T04: MAX_PATHS=1000 with early termination for path enumeration
//!
//! # Example
//!
//! ```bash
//! # Analyze a single file
//! tldr resources src/db.py
//!
//! # Analyze specific function
//! tldr resources src/db.py query
//!
//! # Check all issues
//! tldr resources src/db.py --check-all
//!
//! # Show leak paths
//! tldr resources src/db.py --show-paths
//! ```

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use tree_sitter::{Node, Parser};

use tldr_core::ast::ParserPool;
use tldr_core::types::Language;

use super::error::{PatternsError, PatternsResult};
use super::types::{
    ContextSuggestion, DoubleCloseInfo, LeakInfo, OutputFormat, ResourceConstraint, ResourceInfo,
    ResourceReport, ResourceSummary, UseAfterCloseInfo,
};
use super::validation::{read_file_safe, validate_file_path, validate_file_path_in_project};
use crate::output::OutputFormat as GlobalOutputFormat;

// =============================================================================
// TIGER-04: Path Enumeration Limit
// =============================================================================

/// Maximum paths to enumerate before early termination (TIGER-04).
pub const MAX_PATHS: usize = 1000;

// =============================================================================
// Resource Detection Constants (Multi-Language)
// =============================================================================

/// Resource pattern for a specific language: (creator_function, resource_type, closer_functions)
struct LangResourcePatterns {
    /// Functions that create resources requiring cleanup
    creators: &'static [(&'static str, &'static str)], // (func_name, resource_type)
    /// Methods/functions that release resources
    closers: &'static [&'static str],
    /// Function node kinds for this language in tree-sitter
    function_kinds: &'static [&'static str],
    /// Name field for function nodes (usually "name")
    name_field: &'static str,
    /// Body node kind ("block" for Python, "statement_block" for TS, etc.)
    body_kinds: &'static [&'static str],
    /// Assignment node kinds
    assignment_kinds: &'static [&'static str],
    /// Return statement kinds
    return_kinds: &'static [&'static str],
    /// If statement kinds
    if_kinds: &'static [&'static str],
    /// Loop statement kinds
    loop_kinds: &'static [&'static str],
    /// Try statement kinds
    try_kinds: &'static [&'static str],
    /// Context manager / RAII / defer kinds
    cleanup_block_kinds: &'static [&'static str],
}

fn get_resource_patterns(lang: Language) -> LangResourcePatterns {
    match lang {
        Language::Python => LangResourcePatterns {
            creators: &[
                ("open", "file"),
                ("socket", "socket"),
                ("create_connection", "socket"),
                ("connect", "connection"),
                ("cursor", "cursor"),
                ("urlopen", "url_connection"),
                ("request", "http_connection"),
                ("popen", "process"),
                ("Popen", "process"),
                ("Lock", "lock"),
                ("RLock", "lock"),
                ("Semaphore", "semaphore"),
                ("Event", "event"),
                ("Condition", "condition"),
            ],
            closers: &[
                "close",
                "shutdown",
                "disconnect",
                "release",
                "dispose",
                "cleanup",
                "terminate",
                "__exit__",
            ],
            function_kinds: &["function_definition"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["assignment"],
            return_kinds: &["return_statement", "raise_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement", "while_statement"],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &["with_statement"],
        },
        Language::Go => LangResourcePatterns {
            creators: &[
                ("Open", "file"),
                ("Create", "file"),
                ("OpenFile", "file"),
                ("NewFile", "file"),
                ("Dial", "connection"),
                ("DialTCP", "connection"),
                ("DialUDP", "connection"),
                ("DialTimeout", "connection"),
                ("Listen", "listener"),
                ("ListenTCP", "listener"),
                ("ListenAndServe", "server"),
                ("NewReader", "reader"),
                ("NewWriter", "writer"),
                ("NewScanner", "scanner"),
                ("Get", "http_response"),
                ("Post", "http_response"),
                ("NewRequest", "http_request"),
                ("Connect", "connection"),
                ("NewClient", "client"),
                ("Pipe", "pipe"),
                ("TempFile", "file"),
            ],
            closers: &["Close", "Shutdown", "Stop", "Release", "Flush"],
            function_kinds: &["function_declaration", "method_declaration"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["short_var_declaration", "assignment_statement"],
            return_kinds: &["return_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement"],
            try_kinds: &[],
            cleanup_block_kinds: &["defer_statement"],
        },
        Language::Rust => LangResourcePatterns {
            // G2-O1: Rust acquisition is matched by the module-qualified
            // `acquisition_symbols(Language::Rust)` allowlist (AST-extracted
            // callee path + spine descent), NOT this flat list. The bare
            // `new` creator was DROPPED entirely — `String::new` / `Vec::new`
            // are not resources. This list is retained only for the legacy
            // `closers`-style struct shape; it is not consulted for matching.
            creators: &[],
            closers: &["drop", "close", "shutdown", "flush", "sync_all"],
            function_kinds: &["function_item"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["let_declaration"],
            return_kinds: &["return_expression"],
            if_kinds: &["if_expression"],
            loop_kinds: &["for_expression", "while_expression", "loop_expression"],
            try_kinds: &[],
            cleanup_block_kinds: &[],
        },
        Language::Java => LangResourcePatterns {
            creators: &[
                ("FileInputStream", "file_stream"),
                ("FileOutputStream", "file_stream"),
                ("FileReader", "reader"),
                ("FileWriter", "writer"),
                ("BufferedReader", "reader"),
                ("BufferedWriter", "writer"),
                ("InputStreamReader", "reader"),
                ("OutputStreamWriter", "writer"),
                ("PrintWriter", "writer"),
                ("Scanner", "scanner"),
                ("Socket", "socket"),
                ("ServerSocket", "server_socket"),
                ("Connection", "connection"),
                ("getConnection", "connection"),
                ("prepareStatement", "statement"),
                ("createStatement", "statement"),
                ("openConnection", "connection"),
                ("newInputStream", "stream"),
                ("newOutputStream", "stream"),
                ("RandomAccessFile", "file"),
            ],
            closers: &[
                "close",
                "shutdown",
                "disconnect",
                "dispose",
                "release",
                "flush",
            ],
            function_kinds: &["method_declaration", "constructor_declaration"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["local_variable_declaration"],
            return_kinds: &["return_statement", "throw_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &[
                "for_statement",
                "enhanced_for_statement",
                "while_statement",
                "do_statement",
            ],
            try_kinds: &["try_statement", "try_with_resources_statement"],
            cleanup_block_kinds: &["try_with_resources_statement"],
        },
        Language::TypeScript | Language::JavaScript => LangResourcePatterns {
            creators: &[
                ("open", "file"),
                ("openSync", "file"),
                ("createReadStream", "stream"),
                ("createWriteStream", "stream"),
                ("createServer", "server"),
                ("connect", "connection"),
                ("createConnection", "connection"),
                ("fetch", "response"),
                ("request", "request"),
                ("get", "request"),
                ("post", "request"),
                ("WebSocket", "websocket"),
                ("createPool", "pool"),
                ("getConnection", "connection"),
            ],
            closers: &[
                "close",
                "end",
                "destroy",
                "disconnect",
                "release",
                "abort",
                "unref",
            ],
            function_kinds: &[
                "function_declaration",
                "arrow_function",
                "method_definition",
                "function",
            ],
            name_field: "name",
            body_kinds: &["statement_block"],
            assignment_kinds: &[
                "variable_declaration",
                "lexical_declaration",
                "assignment_expression",
            ],
            return_kinds: &["return_statement", "throw_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &[
                "for_statement",
                "for_in_statement",
                "while_statement",
                "do_statement",
            ],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &[],
        },
        Language::C => LangResourcePatterns {
            creators: &[
                ("fopen", "file"),
                ("fdopen", "file"),
                ("tmpfile", "file"),
                ("open", "file_descriptor"),
                ("creat", "file_descriptor"),
                ("socket", "socket"),
                ("accept", "socket"),
                ("malloc", "memory"),
                ("calloc", "memory"),
                ("realloc", "memory"),
                ("strdup", "memory"),
                ("mmap", "memory_map"),
                ("opendir", "directory"),
                ("popen", "process"),
                ("dlopen", "dynamic_lib"),
                ("CreateFile", "file_handle"),
            ],
            closers: &[
                "fclose",
                "close",
                "free",
                "munmap",
                "closedir",
                "pclose",
                "dlclose",
                "shutdown",
                "CloseHandle",
            ],
            function_kinds: &["function_definition"],
            name_field: "declarator",
            body_kinds: &["compound_statement"],
            assignment_kinds: &["declaration", "assignment_expression"],
            return_kinds: &["return_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement", "while_statement", "do_statement"],
            try_kinds: &[],
            cleanup_block_kinds: &[],
        },
        Language::Cpp => LangResourcePatterns {
            creators: &[
                ("fopen", "file"),
                ("open", "file_descriptor"),
                ("socket", "socket"),
                ("malloc", "memory"),
                ("calloc", "memory"),
                ("realloc", "memory"),
                ("new", "heap_object"),
                ("make_unique", "unique_ptr"),
                ("make_shared", "shared_ptr"),
                ("ifstream", "file_stream"),
                ("ofstream", "file_stream"),
                ("fstream", "file_stream"),
                ("CreateFile", "file_handle"),
                ("connect", "connection"),
            ],
            closers: &[
                "fclose",
                "close",
                "free",
                "delete",
                "shutdown",
                "release",
                "CloseHandle",
                "destroy",
            ],
            function_kinds: &["function_definition"],
            name_field: "declarator",
            body_kinds: &["compound_statement"],
            assignment_kinds: &["declaration", "assignment_expression"],
            return_kinds: &["return_statement", "throw_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &[
                "for_statement",
                "while_statement",
                "do_statement",
                "for_range_loop",
            ],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &[],
        },
        Language::Ruby => LangResourcePatterns {
            // G2-O1: Ruby acquisition is matched by the module-qualified
            // `acquisition_symbols(Language::Ruby)` allowlist against an
            // AST-extracted (receiver, method) tuple, NOT this flat list. The
            // old `ends_with(".open")` match here made arbitrary `Foo.open`
            // false-positive; the qualified tuple `(File, open)` does not.
            creators: &[],
            closers: &["close", "shutdown", "disconnect", "release"],
            function_kinds: &["method", "singleton_method"],
            name_field: "name",
            body_kinds: &["body_statement"],
            assignment_kinds: &["assignment"],
            return_kinds: &["return", "raise"],
            if_kinds: &["if", "unless"],
            loop_kinds: &["for", "while", "until"],
            try_kinds: &["begin"],
            cleanup_block_kinds: &["do_block"],
        },
        Language::CSharp => LangResourcePatterns {
            creators: &[
                ("FileStream", "file_stream"),
                ("StreamReader", "reader"),
                ("StreamWriter", "writer"),
                ("File.Open", "file"),
                ("File.OpenRead", "file"),
                ("File.OpenWrite", "file"),
                ("SqlConnection", "connection"),
                ("HttpClient", "http_client"),
                ("TcpClient", "tcp_client"),
                ("Socket", "socket"),
            ],
            closers: &["Close", "Dispose", "Shutdown", "Release", "Flush"],
            function_kinds: &["method_declaration", "constructor_declaration"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["local_declaration_statement", "assignment_expression"],
            return_kinds: &["return_statement", "throw_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &[
                "for_statement",
                "foreach_statement",
                "while_statement",
                "do_statement",
            ],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &["using_statement"],
        },
        Language::Php => LangResourcePatterns {
            creators: &[
                ("fopen", "file"),
                ("tmpfile", "file"),
                ("fsockopen", "socket"),
                ("pfsockopen", "socket"),
                ("curl_init", "curl"),
                ("mysqli_connect", "connection"),
                ("PDO", "connection"),
                ("popen", "process"),
                ("opendir", "directory"),
            ],
            closers: &[
                "fclose",
                "curl_close",
                "mysqli_close",
                "pclose",
                "closedir",
                "close",
            ],
            function_kinds: &["function_definition", "method_declaration"],
            name_field: "name",
            body_kinds: &["compound_statement"],
            assignment_kinds: &["assignment_expression"],
            return_kinds: &["return_statement", "throw_expression"],
            if_kinds: &["if_statement"],
            loop_kinds: &[
                "for_statement",
                "foreach_statement",
                "while_statement",
                "do_statement",
            ],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &[],
        },
        Language::Elixir => LangResourcePatterns {
            // G2-O1: acquisition matched by `acquisition_symbols(Elixir)`
            // against an AST `(receiver, method)` tuple (`File.open`,
            // `:gen_tcp.connect`); this flat list is no longer consulted for
            // matching. (T2b wires the Elixir assignment arm + fn-name.)
            creators: &[
                ("open", "file"),
                ("open!", "file"),
                ("connect", "connection"),
                ("start_link", "process"),
                ("start", "process"),
            ],
            closers: &["close", "stop", "disconnect"],
            function_kinds: &["call"], // Elixir uses `def` as a macro call
            name_field: "target",
            body_kinds: &["do_block"],
            // T2b: Elixir `=` is emitted as `binary_operator` by the current
            // tree-sitter-elixir grammar (verified by debug-parse on scalar,
            // `{:ok, x}` tuple, `with`, `case`, pipeline and chained `a = b =`
            // forms — every one is a `binary_operator` with an `[operator] =`).
            // We ALSO list `match_operator` because the rest of the codebase
            // treats it as Elixir's `=` kind (security/ast_utils.rs Elixir
            // assignment_kinds, dfg/extractor.rs's Elixir match arm), and older
            // grammar revisions name the node that way; keeping both makes the
            // assignment dispatch (`assignment_kinds.contains(&kind)`) robust to
            // a grammar bump without changing behavior on 0.3.x.
            assignment_kinds: &["binary_operator", "match_operator"], // = operator
            return_kinds: &[],
            if_kinds: &["call"],   // if is a macro
            loop_kinds: &["call"], // for/Enum.each are calls
            try_kinds: &["call"],  // try is a macro
            cleanup_block_kinds: &[],
        },
        Language::Scala => LangResourcePatterns {
            creators: &[
                ("Source", "source"),
                ("fromFile", "source"),
                ("FileInputStream", "stream"),
                ("FileOutputStream", "stream"),
                ("BufferedSource", "source"),
                ("getConnection", "connection"),
            ],
            closers: &["close", "shutdown", "disconnect", "dispose"],
            function_kinds: &["function_definition"],
            name_field: "name",
            body_kinds: &["block"],
            assignment_kinds: &["val_definition", "var_definition"],
            return_kinds: &["return_expression"],
            if_kinds: &["if_expression"],
            loop_kinds: &["for_expression", "while_expression"],
            try_kinds: &["try_expression"],
            cleanup_block_kinds: &[],
        },
        Language::Kotlin => LangResourcePatterns {
            creators: &[
                ("FileInputStream", "file_stream"),
                ("FileOutputStream", "file_stream"),
                ("FileReader", "reader"),
                ("FileWriter", "writer"),
                ("BufferedReader", "reader"),
                ("BufferedWriter", "writer"),
                ("InputStreamReader", "reader"),
                ("OutputStreamWriter", "writer"),
                ("PrintWriter", "writer"),
                ("Scanner", "scanner"),
                ("Socket", "socket"),
                ("ServerSocket", "server_socket"),
                ("getConnection", "connection"),
                ("openConnection", "connection"),
                ("File", "file"),
                ("RandomAccessFile", "file"),
            ],
            closers: &["close", "shutdown", "dispose", "use"],
            function_kinds: &["function_declaration"],
            name_field: "name",
            body_kinds: &["function_body"],
            assignment_kinds: &["property_declaration", "assignment"],
            return_kinds: &["jump_expression"],
            if_kinds: &["if_expression"],
            loop_kinds: &["for_statement", "while_statement"],
            try_kinds: &["try_expression"],
            cleanup_block_kinds: &["call_expression"], // .use { } block
        },
        Language::Swift => LangResourcePatterns {
            creators: &[
                ("FileHandle", "file_handle"),
                ("OutputStream", "stream"),
                ("InputStream", "stream"),
                ("URLSession", "session"),
                ("FileManager", "file_manager"),
                ("fopen", "file"),
                ("open", "file"),
                ("Socket", "socket"),
                ("NWConnection", "connection"),
            ],
            closers: &[
                "closeFile",
                "close",
                "shutdown",
                "invalidateAndCancel",
                "cancel",
            ],
            function_kinds: &["function_declaration"],
            name_field: "name",
            body_kinds: &["function_body"],
            assignment_kinds: &["property_declaration", "directly_assignable_expression"],
            return_kinds: &["control_transfer_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement", "while_statement"],
            try_kinds: &["do_statement"], // do { } catch { }
            cleanup_block_kinds: &[],     // defer detected differently
        },
        Language::Ocaml => LangResourcePatterns {
            // G2-O1: acquisition matched by `acquisition_symbols(Ocaml)`
            // against an AST-flattened value_path (`open_in`,
            // `Stdlib.open_out`, `Unix.openfile`); this flat list is no longer
            // consulted for matching (the old `application` arm checked the
            // wrong node kind and the raw first-word substring was a footgun).
            creators: &[
                ("open_in", "input_channel"),
                ("open_out", "output_channel"),
                ("open_in_bin", "input_channel"),
                ("open_out_bin", "output_channel"),
                ("Unix.openfile", "file_descriptor"),
                ("Unix.socket", "socket"),
                ("open_connection", "connection"),
                ("connect", "connection"),
            ],
            closers: &[
                "close_in",
                "close_out",
                "close_in_noerr",
                "close_out_noerr",
                "Unix.close",
                "close_connection",
            ],
            function_kinds: &["let_binding", "value_definition"],
            name_field: "pattern",
            body_kinds: &["let_expression", "sequence_expression"],
            assignment_kinds: &["let_binding"],
            return_kinds: &[],
            if_kinds: &["if_expression"],
            loop_kinds: &["for_expression", "while_expression"],
            try_kinds: &["try_expression"],
            cleanup_block_kinds: &[],
        },
        Language::Lua | Language::Luau => LangResourcePatterns {
            creators: &[
                ("io.open", "file"),
                ("io.lines", "file"),
                ("io.popen", "process"),
                ("io.tmpfile", "file"),
                ("socket.tcp", "socket"),
                ("socket.udp", "socket"),
                ("socket.connect", "connection"),
                ("open", "file"),
            ],
            closers: &["close"],
            function_kinds: &["function_declaration", "function_definition"],
            name_field: "name",
            body_kinds: &["body"],
            assignment_kinds: &["assignment_statement", "variable_declaration"],
            return_kinds: &["return_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement", "for_in_statement", "while_statement"],
            try_kinds: &[],
            cleanup_block_kinds: &[],
        },
        // v0.5.0 SOL-001: Solidity has no traditional file/socket
        // resources — the EVM is a sandboxed VM. However the locked-
        // ether vulnerability class IS a resource-leak shape (ether
        // accepted via payable but never returned). Real adapter
        // lands in SOL-005 with the vuln detector suite. Until then,
        // an empty pattern set is safe: the resource-leak scanner
        // will simply find no creators and report nothing.
        Language::Solidity => LangResourcePatterns {
            creators: &[],
            closers: &[],
            function_kinds: &[
                "function_definition",
                "constructor_definition",
                "fallback_function_definition",
                "receive_function_definition",
            ],
            name_field: "name",
            body_kinds: &["function_body"],
            assignment_kinds: &["assignment_expression", "variable_declaration_statement"],
            return_kinds: &["return_statement", "revert_statement"],
            if_kinds: &["if_statement"],
            loop_kinds: &["for_statement", "while_statement", "do_while_statement"],
            try_kinds: &["try_statement"],
            cleanup_block_kinds: &[],
        },
    }
}

/// Legacy constant for backward compatibility with tests
pub const RESOURCE_CREATORS: &[&str] = &[
    "open",
    "socket",
    "create_connection",
    "connect",
    "cursor",
    "urlopen",
    "request",
    "popen",
    "Popen",
    "Lock",
    "RLock",
    "Semaphore",
    "Event",
    "Condition",
    "contextlib.closing",
];

/// Legacy constant for backward compatibility with tests
pub const RESOURCE_CLOSERS: &[&str] = &[
    "close",
    "shutdown",
    "disconnect",
    "release",
    "dispose",
    "cleanup",
    "terminate",
    "__exit__",
];

/// Legacy resource type map for backward compatibility with Python detection
const RESOURCE_TYPE_MAP: &[(&str, &str)] = &[
    ("open", "file"),
    ("socket", "socket"),
    ("create_connection", "socket"),
    ("connect", "connection"),
    ("cursor", "cursor"),
    ("urlopen", "url_connection"),
    ("request", "http_connection"),
    ("popen", "process"),
    ("Popen", "process"),
    ("Lock", "lock"),
    ("RLock", "lock"),
    ("Semaphore", "semaphore"),
    ("Event", "event"),
    ("Condition", "condition"),
];

// =============================================================================
// CLI Arguments
// =============================================================================

/// Analyze resource lifecycle to detect leaks, double-close, and use-after-close.
#[derive(Debug, Args, Clone)]
pub struct ResourcesArgs {
    /// Source file to analyze
    pub file: PathBuf,

    /// Function to analyze (optional; analyze all if omitted)
    pub function: Option<String>,

    /// Language filter (auto-detected if omitted)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    /// Run leak detection (R2) - enabled by default
    #[arg(long, default_value = "true")]
    pub check_leaks: bool,

    /// Run double-close detection (R3)
    #[arg(long)]
    pub check_double_close: bool,

    /// Run use-after-close detection (R4)
    #[arg(long)]
    pub check_use_after_close: bool,

    /// Run all checks (R2, R3, R4)
    #[arg(long)]
    pub check_all: bool,

    /// Suggest context manager usage (R6)
    #[arg(long)]
    pub suggest_context: bool,

    /// Show detailed leak paths (R7)
    #[arg(long)]
    pub show_paths: bool,

    /// Generate LLM constraints (R9)
    #[arg(long)]
    pub constraints: bool,

    /// Output summary statistics only
    #[arg(long)]
    pub summary: bool,

    /// Output format (json or text). Prefer global --format/-f flag.
    #[arg(
        long = "output",
        short = 'o',
        hide = true,
        default_value = "json",
        value_enum
    )]
    pub output_format: OutputFormat,

    /// Project root for path validation (optional)
    #[arg(long)]
    pub project_root: Option<PathBuf>,
}

impl ResourcesArgs {
    /// Run the resources analysis command
    pub fn run(&self, global_format: GlobalOutputFormat) -> anyhow::Result<()> {
        run(self.clone(), global_format)
    }
}

// =============================================================================
// Basic Block and Simplified CFG
// =============================================================================

/// A basic block in the simplified control flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique block identifier
    pub id: usize,
    /// Statement nodes in this block (start_byte, end_byte, kind, text)
    pub stmts: Vec<(usize, usize, String, String)>,
    /// Line numbers of statements
    pub lines: Vec<u32>,
    /// Predecessor block IDs
    pub preds: Vec<usize>,
    /// Successor block IDs
    pub succs: Vec<usize>,
    /// Whether this is an entry block
    pub is_entry: bool,
    /// Whether this is an exit block (return/raise/implicit)
    pub is_exit: bool,
    /// Exception handler block IDs (for try blocks)
    pub exception_handlers: Vec<usize>,
}

impl BasicBlock {
    fn new(id: usize) -> Self {
        Self {
            id,
            stmts: Vec::new(),
            lines: Vec::new(),
            preds: Vec::new(),
            succs: Vec::new(),
            is_entry: false,
            is_exit: false,
            exception_handlers: Vec::new(),
        }
    }
}

/// Simplified control flow graph for resource analysis.
#[derive(Debug)]
pub struct SimpleCfg {
    /// Mapping from block ID to BasicBlock
    pub blocks: HashMap<usize, BasicBlock>,
    /// ID of the entry block
    pub entry_block: usize,
    /// IDs of all exit blocks
    pub exit_blocks: Vec<usize>,
    /// Next available block ID
    next_id: usize,
}

impl SimpleCfg {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            entry_block: 0,
            exit_blocks: Vec::new(),
            next_id: 0,
        }
    }

    fn new_block(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.blocks.insert(id, BasicBlock::new(id));
        id
    }

    fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(block) = self.blocks.get_mut(&from) {
            if !block.succs.contains(&to) {
                block.succs.push(to);
            }
        }
        if let Some(block) = self.blocks.get_mut(&to) {
            if !block.preds.contains(&from) {
                block.preds.push(from);
            }
        }
    }

    fn mark_exit(&mut self, id: usize) {
        if let Some(block) = self.blocks.get_mut(&id) {
            block.is_exit = true;
        }
        if !self.exit_blocks.contains(&id) {
            self.exit_blocks.push(id);
        }
    }
}

// =============================================================================
// CFG Builder
// =============================================================================

/// Build a simplified CFG from a function AST.
pub fn build_cfg(func_node: Node, source: &[u8]) -> SimpleCfg {
    let mut cfg = SimpleCfg::new();
    let entry_id = cfg.new_block();
    cfg.entry_block = entry_id;

    if let Some(block) = cfg.blocks.get_mut(&entry_id) {
        block.is_entry = true;
    }

    // Find the function body
    let body = func_node
        .children(&mut func_node.walk())
        .find(|n| n.kind() == "block");

    if let Some(body_node) = body {
        let exit_id = process_statements(&mut cfg, body_node, source, entry_id);
        if let Some(exit) = exit_id {
            // Mark implicit exit if we have a non-exit block at the end
            if !cfg.blocks.get(&exit).is_none_or(|b| b.is_exit) {
                cfg.mark_exit(exit);
            }
        }
    } else {
        // Empty function
        cfg.mark_exit(entry_id);
    }

    cfg
}

fn process_statements(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    mut current: usize,
) -> Option<usize> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // Simple statements - add to current block
            "expression_statement"
            | "assignment"
            | "augmented_assignment"
            | "return_statement"
            | "pass_statement"
            | "break_statement"
            | "continue_statement"
            | "raise_statement"
            | "assert_statement"
            | "global_statement"
            | "nonlocal_statement"
            | "import_statement"
            | "import_from_statement"
            | "delete_statement" => {
                let text = node_text(child, source).to_string();
                let line = child.start_position().row as u32 + 1;
                if let Some(block) = cfg.blocks.get_mut(&current) {
                    block.stmts.push((
                        child.start_byte(),
                        child.end_byte(),
                        child.kind().to_string(),
                        text,
                    ));
                    block.lines.push(line);
                }

                // Handle exit statements
                if child.kind() == "return_statement" || child.kind() == "raise_statement" {
                    cfg.mark_exit(current);
                    return None; // No more statements can be executed
                }
            }

            // If statement - creates branches
            "if_statement" => {
                current = process_if_statement(cfg, child, source, current)?;
            }

            // For/while loops
            "for_statement" | "while_statement" => {
                current = process_loop(cfg, child, source, current)?;
            }

            // Try statement
            "try_statement" => {
                current = process_try(cfg, child, source, current)?;
            }

            // With statement (context manager)
            "with_statement" => {
                current = process_with(cfg, child, source, current)?;
            }

            _ => {
                // Unknown or compound statement - add as is
                let text = node_text(child, source).to_string();
                let line = child.start_position().row as u32 + 1;
                if let Some(block) = cfg.blocks.get_mut(&current) {
                    block.stmts.push((
                        child.start_byte(),
                        child.end_byte(),
                        child.kind().to_string(),
                        text,
                    ));
                    block.lines.push(line);
                }
            }
        }
    }

    Some(current)
}

fn process_if_statement(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    current: usize,
) -> Option<usize> {
    // Add the condition to current block
    if let Some(cond) = node.child_by_field_name("condition") {
        let text = node_text(cond, source).to_string();
        let line = cond.start_position().row as u32 + 1;
        if let Some(block) = cfg.blocks.get_mut(&current) {
            block.stmts.push((
                cond.start_byte(),
                cond.end_byte(),
                "condition".to_string(),
                text,
            ));
            block.lines.push(line);
        }
    }

    // Create blocks for true branch
    let true_block = cfg.new_block();
    cfg.add_edge(current, true_block);

    // Find consequence block
    let mut cursor = node.walk();
    let consequence = node.children(&mut cursor).find(|n| n.kind() == "block");
    let true_exit = if let Some(body) = consequence {
        process_statements(cfg, body, source, true_block)
    } else {
        Some(true_block)
    };

    // Find alternative (else/elif)
    let mut cursor = node.walk();
    let alternative = node
        .children(&mut cursor)
        .find(|n| n.kind() == "else_clause" || n.kind() == "elif_clause");

    let false_exit = if let Some(alt) = alternative {
        let false_block = cfg.new_block();
        cfg.add_edge(current, false_block);

        // Find the block within else/elif
        if let Some(alt_body) = alt.children(&mut alt.walk()).find(|n| n.kind() == "block") {
            process_statements(cfg, alt_body, source, false_block)
        } else {
            Some(false_block)
        }
    } else {
        // No else clause - false branch goes to next block
        None
    };

    // Create merge block
    let merge = cfg.new_block();

    if let Some(te) = true_exit {
        cfg.add_edge(te, merge);
    }
    if let Some(fe) = false_exit {
        cfg.add_edge(fe, merge);
    }
    if alternative.is_none() {
        // If no else, false path goes directly from current to merge
        cfg.add_edge(current, merge);
    }

    Some(merge)
}

fn process_loop(cfg: &mut SimpleCfg, node: Node, source: &[u8], current: usize) -> Option<usize> {
    // Create header block
    let header = cfg.new_block();
    cfg.add_edge(current, header);

    // Add loop condition to header
    if let Some(cond) = node.child_by_field_name("condition") {
        let text = node_text(cond, source).to_string();
        let line = cond.start_position().row as u32 + 1;
        if let Some(block) = cfg.blocks.get_mut(&header) {
            block.stmts.push((
                cond.start_byte(),
                cond.end_byte(),
                "loop_condition".to_string(),
                text,
            ));
            block.lines.push(line);
        }
    }

    // Create body block
    let body_block = cfg.new_block();
    cfg.add_edge(header, body_block);

    // Process body
    let body = node
        .children(&mut node.walk())
        .find(|n| n.kind() == "block");
    let body_exit = if let Some(body_node) = body {
        process_statements(cfg, body_node, source, body_block)
    } else {
        Some(body_block)
    };

    // Back edge from body to header
    if let Some(be) = body_exit {
        cfg.add_edge(be, header);
    }

    // Exit block
    let exit = cfg.new_block();
    cfg.add_edge(header, exit); // Loop can exit when condition is false

    Some(exit)
}

fn process_try(cfg: &mut SimpleCfg, node: Node, source: &[u8], current: usize) -> Option<usize> {
    // Create try block
    let try_block = cfg.new_block();
    cfg.add_edge(current, try_block);

    // Find and process try body
    let try_body = node
        .children(&mut node.walk())
        .find(|n| n.kind() == "block");
    let try_exit = if let Some(body) = try_body {
        process_statements(cfg, body, source, try_block)
    } else {
        Some(try_block)
    };

    // Find except handlers
    let mut cursor = node.walk();
    let mut handler_exits = Vec::new();
    for child in node.children(&mut cursor) {
        if child.kind() == "except_clause" {
            let handler_block = cfg.new_block();
            // Exception edge from try block
            cfg.add_edge(try_block, handler_block);
            if let Some(block) = cfg.blocks.get_mut(&try_block) {
                block.exception_handlers.push(handler_block);
            }

            // Process handler body
            if let Some(handler_body) = child
                .children(&mut child.walk())
                .find(|n| n.kind() == "block")
            {
                if let Some(exit) = process_statements(cfg, handler_body, source, handler_block) {
                    handler_exits.push(exit);
                }
            } else {
                handler_exits.push(handler_block);
            }
        }
    }

    // Find finally clause
    let finally_clause = node
        .children(&mut node.walk())
        .find(|n| n.kind() == "finally_clause");

    // Create merge block
    let merge = cfg.new_block();

    if let Some(te) = try_exit {
        if let Some(finally) = finally_clause {
            // Process finally
            let finally_block = cfg.new_block();
            cfg.add_edge(te, finally_block);
            if let Some(finally_body) = finally
                .children(&mut finally.walk())
                .find(|n| n.kind() == "block")
            {
                if let Some(exit) = process_statements(cfg, finally_body, source, finally_block) {
                    cfg.add_edge(exit, merge);
                }
            } else {
                cfg.add_edge(finally_block, merge);
            }
        } else {
            cfg.add_edge(te, merge);
        }
    }

    for he in handler_exits {
        cfg.add_edge(he, merge);
    }

    Some(merge)
}

fn process_with(cfg: &mut SimpleCfg, node: Node, source: &[u8], current: usize) -> Option<usize> {
    // Add with statement to current block (marks context manager entry)
    let text = node_text(node, source).to_string();
    let line = node.start_position().row as u32 + 1;
    if let Some(block) = cfg.blocks.get_mut(&current) {
        block.stmts.push((
            node.start_byte(),
            node.end_byte(),
            "with_statement".to_string(),
            text,
        ));
        block.lines.push(line);
    }

    // Process the with body
    let body = node
        .children(&mut node.walk())
        .find(|n| n.kind() == "block");
    if let Some(body_node) = body {
        process_statements(cfg, body_node, source, current)
    } else {
        Some(current)
    }
}

// =============================================================================
// Resource Detection
// =============================================================================

/// Detected resource information during analysis.
#[derive(Debug, Clone)]
struct DetectedResource {
    /// Variable name holding the resource
    name: String,
    /// Type of resource
    resource_type: String,
    /// Line where resource was created
    line: u32,
    /// Whether it's inside a context manager (with statement)
    in_context_manager: bool,
}

// =============================================================================
// AGG17-7 (resources-ast-gate-v1): TS/JS ambiguous-name AST gate
// =============================================================================
//
// Variable names that are too generic in TS/JS — without an AST cleanup-context
// match they routinely false-positive on Map.get / Array.find / object lookups
// (e.g. `const event = events.get(id)`, `const data = config.data`). For these
// names we require a confirming cleanup-method call on the same variable inside
// the function body before flagging it as a managed resource.
const TS_JS_AMBIGUOUS_NAMES: &[&str] = &["event", "request", "response", "data"];

/// (js-resources-and-dead-fps-v1 F1) Resource-creator aliases whose name alone
/// is too generic to confirm an HTTP/network handle. `get` / `post` map to
/// the TS/JS creator entries `("get","request")` / `("post","request")` but
/// also legitimately appear as Map/Object/Cache lookups (`this.get('view')`,
/// `cache.get(name)`, `config.post(...)`). For these creators we ALSO require
/// a confirming cleanup-method call on the LHS variable inside the same
/// function body, regardless of the LHS variable's name (the AGG17-7 gate
/// was LHS-name-driven; this extension is creator-driven).
///
/// High-precision creators (`fetch`, `createServer`, `createConnection`,
/// `createReadStream`, `createWriteStream`, `open`, `openSync`, `WebSocket`,
/// `createPool`) are NOT in this list — their name alone is a strong hint.
const TS_JS_AMBIGUOUS_CREATORS: &[&str] =
    &["get", "post", "request", "connect", "getConnection"];

/// Cleanup-style methods whose presence on `<var>.<method>(...)` confirms that
/// `var` is a real resource handle (rather than a Map lookup or plain object).
const TS_JS_CLEANUP_METHODS: &[&str] = &[
    "close",
    "destroy",
    "end",
    "abort",
    "disconnect",
    "release",
    "unref",
    "removeListener",
    "removeAllListeners",
    "removeEventListener",
    "unsubscribe",
    "cancel",
];

/// Walk a TS/JS function body and collect variable names that have a
/// cleanup-style method invoked on them (e.g. `event.close()` →
/// `{"event"}`). Used by the ambiguous-name AST gate.
fn collect_ts_js_cleanup_vars(func_node: Node, source: &[u8]) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    fn visit(node: Node, source: &[u8], out: &mut HashSet<String>) {
        // Look for call_expression whose function is a member_expression
        // ending in one of TS_JS_CLEANUP_METHODS, with object = identifier.
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "member_expression" {
                    let object = func.child_by_field_name("object");
                    let property = func.child_by_field_name("property");
                    if let (Some(obj), Some(prop)) = (object, property) {
                        if obj.kind() == "identifier" {
                            let prop_text = node_text(prop, source);
                            if TS_JS_CLEANUP_METHODS.contains(&prop_text) {
                                out.insert(node_text(obj, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child, source, out);
        }
    }
    visit(func_node, source, &mut out);
    out
}

/// Resource detector for finding must-close resources.
pub struct ResourceDetector {
    resources: Vec<DetectedResource>,
    context_manager_vars: HashSet<String>,
    /// AGG17-7: TS/JS variables observed to receive a cleanup-method call
    /// (`<var>.close()`, `.destroy()`, `.removeListener()`, etc.). Used to gate
    /// ambiguous-name resource flagging — see `TS_JS_AMBIGUOUS_NAMES`.
    ts_js_cleanup_vars: HashSet<String>,
    lang: Language,
}

impl ResourceDetector {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            context_manager_vars: HashSet::new(),
            ts_js_cleanup_vars: HashSet::new(),
            lang: Language::Python,
        }
    }

    pub fn with_language(lang: Language) -> Self {
        Self {
            resources: Vec::new(),
            context_manager_vars: HashSet::new(),
            ts_js_cleanup_vars: HashSet::new(),
            lang,
        }
    }

    /// AGG17-7: For TS/JS, return true if `var_name` is in the ambiguous set
    /// AND has no cleanup-method call observed in the current function — i.e.
    /// it should be SKIPPED rather than flagged as a resource.
    fn ts_js_should_skip_ambiguous(&self, var_name: &str) -> bool {
        if !matches!(self.lang, Language::TypeScript | Language::JavaScript) {
            return false;
        }
        if !TS_JS_AMBIGUOUS_NAMES.contains(&var_name) {
            return false;
        }
        !self.ts_js_cleanup_vars.contains(var_name)
    }

    /// (js-resources-and-dead-fps-v1 F1) TS/JS-only secondary gate keyed on
    /// the RHS creator alias rather than the LHS variable name. When the
    /// matched creator is in `TS_JS_AMBIGUOUS_CREATORS` and the LHS variable
    /// has no observed cleanup-method call, skip flagging the resource.
    fn ts_js_should_skip_ambiguous_creator(
        &self,
        var_name: &str,
        creator: &str,
    ) -> bool {
        if !matches!(self.lang, Language::TypeScript | Language::JavaScript) {
            return false;
        }
        if !TS_JS_AMBIGUOUS_CREATORS.contains(&creator) {
            return false;
        }
        !self.ts_js_cleanup_vars.contains(var_name)
    }

    /// Detect resources in a function (legacy Python-only).
    pub fn detect(&mut self, func_node: Node, source: &[u8]) -> Vec<ResourceInfo> {
        self.resources.clear();
        self.context_manager_vars.clear();
        self.visit_node(func_node, source, false);

        self.resources
            .iter()
            .map(|r| ResourceInfo {
                name: r.name.clone(),
                resource_type: r.resource_type.clone(),
                line: r.line,
                closed: r.in_context_manager,
            })
            .collect()
    }

    /// Detect resources using language-specific patterns.
    pub fn detect_with_patterns(&mut self, func_node: Node, source: &[u8]) -> Vec<ResourceInfo> {
        let patterns = get_resource_patterns(self.lang);
        self.resources.clear();
        self.context_manager_vars.clear();
        self.ts_js_cleanup_vars.clear();
        // AGG17-7: precompute cleanup-method receivers for TS/JS so we can
        // gate the ambiguous-name set (event/request/response/data).
        if matches!(self.lang, Language::TypeScript | Language::JavaScript) {
            self.ts_js_cleanup_vars = collect_ts_js_cleanup_vars(func_node, source);
        }
        self.visit_node_multilang(func_node, source, false, &patterns);

        self.resources
            .iter()
            .map(|r| ResourceInfo {
                name: r.name.clone(),
                resource_type: r.resource_type.clone(),
                line: r.line,
                closed: r.in_context_manager,
            })
            .collect()
    }

    fn visit_node(&mut self, node: Node, source: &[u8], in_with: bool) {
        match node.kind() {
            "with_statement" => {
                // Process with_items - they're direct children of with_statement
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "with_item" {
                        self.visit_with_item(child, source);
                    } else if child.kind() == "with_clause" {
                        // Some Python versions use with_clause wrapper
                        let mut inner_cursor = child.walk();
                        for item in child.children(&mut inner_cursor) {
                            if item.kind() == "with_item" {
                                self.visit_with_item(item, source);
                            }
                        }
                    }
                }
                // Recurse into body with context manager flag
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit_node(child, source, true);
                }
            }
            "assignment" => {
                self.check_assignment(node, source, in_with);
            }
            _ => {
                // Recurse
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit_node(child, source, in_with);
                }
            }
        }
    }

    fn visit_with_item(&mut self, node: Node, source: &[u8]) {
        // with_item structure in tree-sitter-python:
        //   with_item
        //     as_pattern
        //       call (the expression, e.g., open(path))
        //       as_pattern_target
        //         identifier (the variable name, e.g., f)
        //
        // OR (for with expression without 'as'):
        //   with_item
        //     call (the expression only)

        // First check for as_pattern (with ... as var)
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "as_pattern" {
                let mut as_cursor = child.walk();
                let mut call_node: Option<Node> = None;
                let mut target_node: Option<Node> = None;

                for as_child in child.children(&mut as_cursor) {
                    if as_child.kind() == "call" {
                        call_node = Some(as_child);
                    } else if as_child.kind() == "as_pattern_target" {
                        // as_pattern_target contains the identifier
                        if let Some(ident) = as_child.child(0) {
                            if ident.kind() == "identifier" {
                                target_node = Some(ident);
                            }
                        }
                    }
                }

                if let (Some(call), Some(target)) = (call_node, target_node) {
                    let var_name = node_text(target, source).to_string();
                    self.context_manager_vars.insert(var_name.clone());

                    if let Some(resource_type) = self.get_resource_type_from_call(call, source) {
                        self.resources.push(DetectedResource {
                            name: var_name,
                            resource_type,
                            line: node.start_position().row as u32 + 1,
                            in_context_manager: true,
                        });
                    }
                }
            }
        }

        // Also try field names for older tree-sitter versions
        if let Some(target) = node.child_by_field_name("alias") {
            let var_name = node_text(target, source).to_string();
            if !self.context_manager_vars.contains(&var_name) {
                self.context_manager_vars.insert(var_name.clone());

                if let Some(value) = node.child_by_field_name("value") {
                    if let Some(resource_type) = self.get_resource_type_from_call(value, source) {
                        self.resources.push(DetectedResource {
                            name: var_name,
                            resource_type,
                            line: node.start_position().row as u32 + 1,
                            in_context_manager: true,
                        });
                    }
                }
            }
        }
    }

    fn check_assignment(&mut self, node: Node, source: &[u8], in_with: bool) {
        // f = open(...)
        if let Some(left) = node.child_by_field_name("left") {
            if let Some(right) = node.child_by_field_name("right") {
                let var_name = node_text(left, source).to_string();

                if let Some(resource_type) = self.get_resource_type_from_call(right, source) {
                    let in_context = in_with || self.context_manager_vars.contains(&var_name);
                    self.resources.push(DetectedResource {
                        name: var_name,
                        resource_type,
                        line: node.start_position().row as u32 + 1,
                        in_context_manager: in_context,
                    });
                }
            }
        }
    }

    fn get_resource_type_from_call(&self, node: Node, source: &[u8]) -> Option<String> {
        if node.kind() != "call" {
            return None;
        }

        // Get function name
        let func = node.child_by_field_name("function")?;
        let func_text = node_text(func, source);

        // Extract just the function name from attribute access (e.g., "sqlite3.connect" -> "connect")
        let func_name = func_text.split('.').next_back().unwrap_or(func_text);

        // Check if it's a resource creator
        for &creator in RESOURCE_CREATORS {
            if func_name == creator {
                // Find the resource type from the type map
                for &(name, rtype) in RESOURCE_TYPE_MAP {
                    if func_name == name {
                        return Some(rtype.to_string());
                    }
                }
                // Default to the function name as type
                return Some(func_name.to_string());
            }
        }

        None
    }

    // =========================================================================
    // Multi-language methods
    // =========================================================================

    fn visit_node_multilang(
        &mut self,
        node: Node,
        source: &[u8],
        in_cleanup: bool,
        patterns: &LangResourcePatterns,
    ) {
        let kind = node.kind();

        // Check for cleanup block kinds (with, defer, using, try-with-resources)
        if patterns.cleanup_block_kinds.contains(&kind) {
            match self.lang {
                Language::Python => {
                    // Python with_statement: check for with_item children
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "with_item" {
                            self.visit_with_item(child, source);
                        } else if child.kind() == "with_clause" {
                            let mut inner_cursor = child.walk();
                            for item in child.children(&mut inner_cursor) {
                                if item.kind() == "with_item" {
                                    self.visit_with_item(item, source);
                                }
                            }
                        }
                    }
                    // Recurse into body with cleanup flag
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.visit_node_multilang(child, source, true, patterns);
                    }
                    return;
                }
                Language::Go => {
                    // Go defer: mark any resource in the defer as cleanup-managed
                    // We just recurse with in_cleanup=true
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.visit_node_multilang(child, source, true, patterns);
                    }
                    return;
                }
                Language::CSharp => {
                    // C# using statement: resources are auto-disposed
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.visit_node_multilang(child, source, true, patterns);
                    }
                    return;
                }
                Language::Java => {
                    // Java try-with-resources: resources in the resource spec are auto-closed
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.visit_node_multilang(child, source, true, patterns);
                    }
                    return;
                }
                _ => {}
            }
        }

        // Check for assignment kinds
        if patterns.assignment_kinds.contains(&kind) {
            self.check_assignment_multilang(node, source, in_cleanup, patterns);
        }

        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit_node_multilang(child, source, in_cleanup, patterns);
        }
    }

    fn check_assignment_multilang(
        &mut self,
        node: Node,
        source: &[u8],
        in_cleanup: bool,
        patterns: &LangResourcePatterns,
    ) {
        match self.lang {
            Language::Python => {
                // f = open(...)
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(right) = node.child_by_field_name("right") {
                        let var_name = node_text(left, source).to_string();
                        if let Some(resource_type) =
                            self.get_resource_type_from_call_multilang(right, source, patterns)
                        {
                            let in_context =
                                in_cleanup || self.context_manager_vars.contains(&var_name);
                            self.resources.push(DetectedResource {
                                name: var_name,
                                resource_type,
                                line: node.start_position().row as u32 + 1,
                                in_context_manager: in_context,
                            });
                        }
                    }
                }
            }
            Language::Go => {
                // Go: f, err := os.Open(...) or f := os.Open(...)
                // short_var_declaration has left and right fields
                // assignment_statement has left and right fields
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(right) = node.child_by_field_name("right") {
                        // left might be an expression_list with multiple identifiers
                        let var_name = if left.kind() == "expression_list" {
                            // Take first identifier
                            left.child(0).map(|c| node_text(c, source).to_string())
                        } else {
                            Some(node_text(left, source).to_string())
                        };
                        if let Some(var_name) = var_name {
                            if var_name != "_" && var_name != "err" {
                                // Check right side - may be expression_list too
                                let call_node = if right.kind() == "expression_list" {
                                    right.child(0)
                                } else {
                                    Some(right)
                                };
                                if let Some(call_node) = call_node {
                                    if let Some(resource_type) = self
                                        .get_resource_type_from_call_multilang(
                                            call_node, source, patterns,
                                        )
                                    {
                                        self.resources.push(DetectedResource {
                                            name: var_name,
                                            resource_type,
                                            line: node.start_position().row as u32 + 1,
                                            in_context_manager: in_cleanup,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Language::Rust => {
                // let f = File::open(...)?;
                // let_declaration has pattern and value fields
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if let Some(value) = node.child_by_field_name("value") {
                        let var_name = node_text(pattern, source).to_string();
                        if let Some(resource_type) =
                            self.get_resource_type_from_call_multilang(value, source, patterns)
                        {
                            // G4-O2: Rust is RAII so a handle that stays local
                            // is auto-dropped → treat as closed. But when the
                            // handle ESCAPES the function scope (returned,
                            // stored into a field, or `mem::forget`'d) AND no
                            // explicit drop/close is applied to it, RAII no
                            // longer guarantees cleanup on this path — so it is
                            // reportable as a leak (closed=false). This replaces
                            // the old unconditional `in_context_manager: true`
                            // that made Rust incapable of ever reporting a leak.
                            // (CFG-precise drop reachability is G4-O1, deferred.)
                            let escapes = rust_handle_escapes(node, &var_name, source)
                                && !rust_handle_explicitly_closed(node, &var_name, source, patterns);
                            self.resources.push(DetectedResource {
                                name: var_name,
                                resource_type,
                                line: node.start_position().row as u32 + 1,
                                in_context_manager: !escapes,
                            });
                        }
                    }
                }
            }
            Language::Java | Language::CSharp => {
                // Type var = new Resource(...);
                // local_variable_declaration contains declarator children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Some(value) = child.child_by_field_name("value") {
                                let var_name = node_text(name_node, source).to_string();
                                if let Some(resource_type) = self
                                    .get_resource_type_from_call_multilang(value, source, patterns)
                                {
                                    self.resources.push(DetectedResource {
                                        name: var_name,
                                        resource_type,
                                        line: node.start_position().row as u32 + 1,
                                        in_context_manager: in_cleanup,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Language::TypeScript | Language::JavaScript => {
                // const f = fs.open(...); or let f = ...
                // variable_declaration / lexical_declaration contain variable_declarator children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Some(value) = child.child_by_field_name("value") {
                                let var_name = node_text(name_node, source).to_string();
                                if let Some(resource_type) = self
                                    .get_resource_type_from_call_multilang(value, source, patterns)
                                {
                                    // AGG17-7: ambiguous TS/JS names need a
                                    // confirming cleanup-method call to be flagged.
                                    if self.ts_js_should_skip_ambiguous(&var_name) {
                                        continue;
                                    }
                                    // js-resources-and-dead-fps-v1 F1: also
                                    // skip when the *creator alias* is in the
                                    // ambiguous-creator set (get/post/request/
                                    // connect/getConnection) and no cleanup-
                                    // method call was observed on `var_name`.
                                    if let Some(creator) =
                                        self.ts_js_creator_alias(value, source, patterns)
                                    {
                                        if self.ts_js_should_skip_ambiguous_creator(
                                            &var_name, &creator,
                                        ) {
                                            continue;
                                        }
                                    }
                                    self.resources.push(DetectedResource {
                                        name: var_name,
                                        resource_type,
                                        line: node.start_position().row as u32 + 1,
                                        in_context_manager: in_cleanup,
                                    });
                                }
                            }
                        }
                    }
                }
                // Also handle assignment_expression: f = open(...)
                if node.kind() == "assignment_expression" {
                    if let Some(left) = node.child_by_field_name("left") {
                        if let Some(right) = node.child_by_field_name("right") {
                            let var_name = node_text(left, source).to_string();
                            if let Some(resource_type) =
                                self.get_resource_type_from_call_multilang(right, source, patterns)
                            {
                                // AGG17-7: ambiguous TS/JS names need a
                                // confirming cleanup-method call to be flagged.
                                if self.ts_js_should_skip_ambiguous(&var_name) {
                                    return;
                                }
                                // js-resources-and-dead-fps-v1 F1: also skip
                                // when the *creator alias* is in the
                                // ambiguous-creator set.
                                if let Some(creator) =
                                    self.ts_js_creator_alias(right, source, patterns)
                                {
                                    if self.ts_js_should_skip_ambiguous_creator(
                                        &var_name, &creator,
                                    ) {
                                        return;
                                    }
                                }
                                self.resources.push(DetectedResource {
                                    name: var_name,
                                    resource_type,
                                    line: node.start_position().row as u32 + 1,
                                    in_context_manager: in_cleanup,
                                });
                            }
                        }
                    }
                }
            }
            Language::C | Language::Cpp => {
                // FILE *f = fopen(...); or void *p = malloc(...);
                // declaration contains init_declarator children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "init_declarator" {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            if let Some(value) = child.child_by_field_name("value") {
                                // declarator might be a pointer_declarator wrapping an identifier
                                let var_name = extract_c_declarator_name(declarator, source);
                                if let Some(var_name) = var_name {
                                    if let Some(resource_type) = self
                                        .get_resource_type_from_call_multilang(
                                            value, source, patterns,
                                        )
                                    {
                                        self.resources.push(DetectedResource {
                                            name: var_name,
                                            resource_type,
                                            line: node.start_position().row as u32 + 1,
                                            in_context_manager: in_cleanup,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                // Also handle assignment_expression
                if node.kind() == "assignment_expression" {
                    if let Some(left) = node.child_by_field_name("left") {
                        if let Some(right) = node.child_by_field_name("right") {
                            let var_name = node_text(left, source).to_string();
                            if let Some(resource_type) =
                                self.get_resource_type_from_call_multilang(right, source, patterns)
                            {
                                self.resources.push(DetectedResource {
                                    name: var_name,
                                    resource_type,
                                    line: node.start_position().row as u32 + 1,
                                    in_context_manager: in_cleanup,
                                });
                            }
                        }
                    }
                }
            }
            Language::Kotlin => {
                // Kotlin: val reader = BufferedReader(FileReader(path))
                // property_declaration has variable_declaration children with name/value
                // or assignment has left/right
                if node.kind() == "property_declaration" {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "variable_declaration" {
                            if let Some(name_node) =
                                child.child_by_field_name("name").or_else(|| child.child(0))
                            {
                                let var_name = node_text(name_node, source).to_string();
                                // The initializer/value is a sibling after the '='
                                // In Kotlin tree-sitter, the value/expression follows the property_declaration's delegation_specifier or directly
                                // Check remaining children for call expressions
                                let mut inner_cursor = node.walk();
                                for sibling in node.children(&mut inner_cursor) {
                                    if let Some(resource_type) = self
                                        .get_resource_type_from_call_multilang(
                                            sibling, source, patterns,
                                        )
                                    {
                                        self.resources.push(DetectedResource {
                                            name: var_name.clone(),
                                            resource_type,
                                            line: node.start_position().row as u32 + 1,
                                            in_context_manager: in_cleanup,
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else if node.kind() == "assignment" {
                    if let Some(left) = node.child_by_field_name("left").or_else(|| node.child(0)) {
                        if let Some(right) = node.child_by_field_name("right") {
                            let var_name = node_text(left, source).to_string();
                            if let Some(resource_type) =
                                self.get_resource_type_from_call_multilang(right, source, patterns)
                            {
                                self.resources.push(DetectedResource {
                                    name: var_name,
                                    resource_type,
                                    line: node.start_position().row as u32 + 1,
                                    in_context_manager: in_cleanup,
                                });
                            }
                        }
                    }
                }
            }
            Language::Swift => {
                // Swift: let handle = FileHandle(forReadingAtPath: path)!
                // property_declaration has pattern (name) and value (expression)
                if node.kind() == "property_declaration"
                    || node.kind() == "directly_assignable_expression"
                {
                    if let Some(pattern) = node
                        .child_by_field_name("pattern")
                        .or_else(|| node.child_by_field_name("name"))
                    {
                        let var_name = node_text(pattern, source).to_string();
                        // Check all children for call expressions (value may be force-unwrapped, etc.)
                        let mut cursor = node.walk();
                        for child in node.children(&mut cursor) {
                            if let Some(resource_type) =
                                self.get_resource_type_from_call_multilang(child, source, patterns)
                            {
                                self.resources.push(DetectedResource {
                                    name: var_name.clone(),
                                    resource_type,
                                    line: node.start_position().row as u32 + 1,
                                    in_context_manager: in_cleanup,
                                });
                                break;
                            }
                        }
                    }
                }
            }
            Language::Ocaml => {
                // OCaml: let ic = open_in path in ...
                // let_binding has pattern (value_name) and body (application / expression)
                if node.kind() == "let_binding" {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        let var_name = node_text(pattern, source).to_string();
                        // Check body for resource creation
                        if let Some(body) = node.child_by_field_name("body") {
                            if let Some(resource_type) =
                                self.get_resource_type_from_call_multilang(body, source, patterns)
                            {
                                self.resources.push(DetectedResource {
                                    name: var_name,
                                    resource_type,
                                    line: node.start_position().row as u32 + 1,
                                    in_context_manager: in_cleanup,
                                });
                            }
                        }
                    }
                }
            }
            Language::Elixir => {
                // G3-O1: Elixir `=` is a `binary_operator` with `[operator] =`,
                // `[left]` pattern, `[right]` value (verified by debug-parse on
                // tree-sitter-elixir 0.3.x). The generic `_` arm below would
                // bind the WHOLE LHS as text — for `{:ok, file} = File.open(p)`
                // that yields the bogus name `{:ok, file}`. Here we structurally
                // bind the inner identifier of the LHS pattern (scalar
                // `identifier`, or the first `identifier` inside a `{:ok, file}`
                // `tuple`) and resolve the RHS via the module-qualified
                // acquisition matcher (G2-O1 allowlist).
                //
                // T2b: accept BOTH `binary_operator` and `match_operator`. The
                // rest of the codebase (security/ast_utils.rs, dfg/extractor.rs)
                // treats `match_operator` as Elixir's `=` kind, and older
                // grammar revisions name the `=` node that way. Both shapes use
                // the SAME `[operator]`/`[left]`/`[right]` fields, so the
                // structural extraction below is identical for either kind.
                if !matches!(node.kind(), "binary_operator" | "match_operator") {
                    return;
                }
                // Confirm the operator is `=` structurally (never text-split).
                let is_eq = node
                    .child_by_field_name("operator")
                    .map(|op| op.kind() == "=")
                    .unwrap_or(false);
                if !is_eq {
                    return;
                }
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return;
                };
                if let Some(var_name) = elixir_bind_name(left, source) {
                    if let Some(resource_type) =
                        self.get_resource_type_from_call_multilang(right, source, patterns)
                    {
                        self.resources.push(DetectedResource {
                            name: var_name,
                            resource_type,
                            line: node.start_position().row as u32 + 1,
                            in_context_manager: in_cleanup,
                        });
                    }
                }
            }
            Language::Lua | Language::Luau => {
                // fix-C5-2 (v0.5.0 AUDIT-FIX): tree-sitter-lua 0.2.0 does NOT
                // expose `values`/`variables`/`right`/`left`/`name` fields on
                // its assignment nodes (verified by debug-parse). The real
                // shapes are:
                //   local f = io.open(p)
                //     variable_declaration
                //       └ assignment_statement
                //           ├ variable_list     (unnamed child, holds idents)
                //           ├ "="
                //           └ expression_list   (unnamed child, holds the call)
                //   f = io.open(p)              (bare, no `local`)
                //     assignment_statement      (same children as above)
                //
                // We act ONLY on `assignment_statement` here and treat
                // `variable_declaration` as a pass-through (its sole
                // meaningful child is the inner `assignment_statement`, which
                // the recursion reaches). This avoids double-counting the
                // `local` form, while still catching the bare form.
                if node.kind() != "assignment_statement" {
                    return;
                }

                // Locate the `variable_list` and `expression_list` children by
                // kind (no field names available). Use indexed access so no
                // TreeCursor borrow outlives the returned `Node`.
                let mut var_list: Option<Node> = None;
                let mut expr_list: Option<Node> = None;
                for i in 0..node.child_count() {
                    let Some(child) = node.child(i) else { continue };
                    match child.kind() {
                        "variable_list" | "identifier_list" if var_list.is_none() => {
                            var_list = Some(child);
                        }
                        "expression_list" if expr_list.is_none() => {
                            expr_list = Some(child);
                        }
                        _ => {}
                    }
                }

                // First identifier on the LHS is the resource variable name.
                let var_name = var_list.and_then(|vl| {
                    (0..vl.child_count())
                        .filter_map(|i| vl.child(i))
                        .find(|n| matches!(n.kind(), "identifier" | "dot_index_expression"))
                        .map(|n| node_text(n, source).to_string())
                });

                // First expression on the RHS is the acquisition call,
                // unwrapped through any `assert(...)` / `pcall(...)` wrapper.
                let call_node = expr_list
                    .and_then(|el| {
                        (0..el.child_count())
                            .filter_map(|i| el.child(i))
                            .find(|n| !matches!(n.kind(), "," | "(" | ")"))
                    })
                    .map(|n| unwrap_lua_acquisition_call(n, source));

                if let (Some(var_name), Some(call_node)) = (var_name, call_node) {
                    if let Some(resource_type) =
                        self.get_resource_type_from_call_multilang(call_node, source, patterns)
                    {
                        self.resources.push(DetectedResource {
                            name: var_name,
                            resource_type,
                            line: node.start_position().row as u32 + 1,
                            in_context_manager: in_cleanup,
                        });
                    }
                }
            }
            _ => {
                // Generic fallback: try left/right fields
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(right) = node.child_by_field_name("right") {
                        let var_name = node_text(left, source).to_string();
                        if let Some(resource_type) =
                            self.get_resource_type_from_call_multilang(right, source, patterns)
                        {
                            self.resources.push(DetectedResource {
                                name: var_name,
                                resource_type,
                                line: node.start_position().row as u32 + 1,
                                in_context_manager: in_cleanup,
                            });
                        }
                    }
                }
            }
        }
    }

    /// (js-resources-and-dead-fps-v1 F1) For TS/JS only: return the matched
    /// creator-alias string (e.g. `"get"`, `"createServer"`) without the
    /// resource type, by re-running just the creator-name match against the
    /// language patterns. Used by the ambiguous-creator gate. Returns `None`
    /// when the language is not TS/JS, the call shape is not extractable, or
    /// the call doesn't match any known TS/JS creator alias.
    fn ts_js_creator_alias(
        &self,
        node: Node,
        source: &[u8],
        patterns: &LangResourcePatterns,
    ) -> Option<String> {
        if !matches!(self.lang, Language::TypeScript | Language::JavaScript) {
            return None;
        }
        let func_name = extract_call_name(node, source)?;
        for &(creator, _rtype) in patterns.creators {
            if func_name == creator
                || func_name.ends_with(&format!("::{}", creator))
                || func_name.ends_with(&format!(".{}", creator))
            {
                return Some(creator.to_string());
            }
        }
        None
    }

    /// Multi-language resource type detection from call expressions.
    fn get_resource_type_from_call_multilang(
        &self,
        node: Node,
        source: &[u8],
        patterns: &LangResourcePatterns,
    ) -> Option<String> {
        // G2-O1 + G1-O1: Rust/Ruby/OCaml/Elixir use the module-qualified
        // acquisition matcher against an AST-extracted callee path (with chain
        // descent), NOT the flat single-name creators loop. This is what
        // suppresses the old `Foo.open` (Ruby `ends_with(".open")`) and
        // `String::new` (bare-`new`) false positives, and what lets
        // `File::open(path).unwrap()` be detected via spine descent. We return
        // here unconditionally for these languages so the legacy substring
        // fallbacks below never fire for them.
        if uses_qualified_acquisition(self.lang) {
            return qualified_creator_type(node, source, self.lang);
        }

        // Extract the function/method name from the call
        let func_name = extract_call_name(node, source)?;

        // Check against language-specific creator patterns
        for &(creator, rtype) in patterns.creators {
            if func_name == creator
                || func_name.ends_with(&format!("::{}", creator))
                || func_name.ends_with(&format!(".{}", creator))
            {
                return Some(rtype.to_string());
            }
        }

        // For C/C++: also check for new/malloc at the call level
        if matches!(self.lang, Language::C | Language::Cpp) {
            if node.kind() == "call_expression" {
                // fix-R7 (cluster[11] RC2): match the creator by EXACT callee
                // name (extracted from the AST `function` child), not by a
                // raw-text prefix. `node_text(node).starts_with("fopen")`
                // wrongly matched `fopen_s(&fp, ...)` (a Win32 wrapper whose
                // result is an `errno_t`, not a FILE*), flagging the int return
                // var as a leaked file. `extract_call_name` already pulls the
                // bare callee identifier (`fopen_s` vs `fopen`), so equality is
                // both correct and AST-driven.
                if let Some(callee) = extract_call_name(node, source) {
                    for &(creator, rtype) in patterns.creators {
                        if callee == creator {
                            return Some(rtype.to_string());
                        }
                    }
                }
            }
            // Check for `new` expressions in C++
            if node.kind() == "new_expression" {
                return Some("heap_object".to_string());
            }
        }

        // For Kotlin: check for constructor calls like BufferedReader(FileReader(path))
        if matches!(self.lang, Language::Kotlin) {
            // Kotlin constructors look like function calls in tree-sitter
            let text = node_text(node, source);
            for &(creator, rtype) in patterns.creators {
                if text.starts_with(creator) {
                    return Some(rtype.to_string());
                }
            }
        }

        // For Swift: check for constructor calls like FileHandle(forReadingAtPath: path)
        if matches!(self.lang, Language::Swift) {
            let text = node_text(node, source);
            for &(creator, rtype) in patterns.creators {
                if text.starts_with(creator) {
                    return Some(rtype.to_string());
                }
            }
            // Also check force-unwrap: FileHandle(...)!
            if node.kind() == "force_unwrap_expression" || node.kind() == "try_expression" {
                if let Some(child) = node.child(0) {
                    return self.get_resource_type_from_call_multilang(child, source, patterns);
                }
            }
        }

        // NOTE: OCaml/Elixir acquisition is handled structurally by the
        // module-qualified matcher above (early return) — the old
        // `application` (wrong node kind) + raw-text first-word substring
        // fallbacks were removed in G2-O1.

        // For Lua/Luau: check for method calls like io.open(path, "r")
        if matches!(self.lang, Language::Lua | Language::Luau) {
            let text = node_text(node, source);
            for &(creator, rtype) in patterns.creators {
                if text.starts_with(creator) {
                    return Some(rtype.to_string());
                }
            }
        }

        // For Java/C#: check for `new ClassName(...)` constructor calls
        if matches!(self.lang, Language::Java | Language::CSharp)
            && node.kind() == "object_creation_expression"
        {
            // Get the type name
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_name = node_text(type_node, source);
                for &(creator, rtype) in patterns.creators {
                    if type_name == creator || type_name.contains(creator) {
                        return Some(rtype.to_string());
                    }
                }
            }
        }

        None
    }
}

impl Default for ResourceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Leak Detection (TIGER-04)
// =============================================================================

/// Leak detector using CFG path analysis.
pub struct LeakDetector {
    /// Maximum paths to enumerate (TIGER-04)
    max_paths: usize,
    /// Paths enumerated so far
    paths_enumerated: usize,
    /// Whether we hit the limit
    hit_limit: bool,
    /// Language being analyzed — selects the close-call extractor shape.
    lang: Language,
    /// fix-R7 (cluster[11] RC1): per-variable set of CFG block ids that close
    /// the variable. Populated by [`LeakDetector::index_closes`] before path
    /// analysis; consulted by [`LeakDetector::path_has_close`].
    close_blocks: HashMap<String, HashSet<usize>>,
}

impl LeakDetector {
    pub fn new() -> Self {
        Self {
            max_paths: MAX_PATHS,
            paths_enumerated: 0,
            hit_limit: false,
            lang: Language::Python,
            close_blocks: HashMap::new(),
        }
    }

    /// Construct a leak detector bound to a specific language so the close-call
    /// extractor (`extract_close_call`) uses the right AST shape.
    pub fn with_language(lang: Language) -> Self {
        Self {
            max_paths: MAX_PATHS,
            paths_enumerated: 0,
            hit_limit: false,
            lang,
            close_blocks: HashMap::new(),
        }
    }

    /// Detect potential leaks using CFG path analysis.
    ///
    /// `func_node` is the analyzed function's AST root. It is walked once to
    /// index every close call (`fclose(fp)`, `fp.close()`, …) onto the CFG
    /// block that contains it (fix-R7 cluster[11] RC1) and to detect handles
    /// whose ownership is transferred out of the function (returned / stored),
    /// which are not leaks.
    pub fn detect(
        &mut self,
        cfg: &SimpleCfg,
        resources: &[ResourceInfo],
        source: &[u8],
        func_node: Node,
        show_paths: bool,
    ) -> Vec<LeakInfo> {
        let mut leaks = Vec::new();
        self.paths_enumerated = 0;
        self.hit_limit = false;

        // fix-R7 (cluster[11] RC1): index close calls -> CFG blocks BEFORE path
        // analysis so `path_has_close` is a real per-path membership check
        // instead of the old hardcoded `false`.
        self.index_closes(cfg, func_node, source);

        for resource in resources {
            // Skip resources in context managers / RAII / try-with-resources.
            if resource.closed {
                continue;
            }

            // fix-R7 (cluster[11] RC1): a handle whose ownership is transferred
            // out of the function (C/C++ `return fp;`) is the CALLER's
            // responsibility, not a leak here.
            if resource_ownership_transferred(func_node, &resource.name, source, self.lang) {
                continue;
            }

            // fix-R7 (cluster[11] RC1): lines that exit the function on the
            // resource's OWN acquisition-failure guard (`if ((fp=fopen())==NULL)
            // return;`, `fd=open(); if (fd==-1) return;`). On such a path the
            // resource was NOT successfully acquired, so the absence of a close
            // is correct, not a leak. Without this the very common C idiom
            // "acquire in/with an error check, early-return on failure"
            // false-positives (c-redis util.c `dir`/`fd`/`dir_fd`).
            let failure_exit_lines =
                acquisition_failure_exit_lines(func_node, &resource.name, source, self.lang);

            // Find all paths from resource creation to exits
            let paths = self.enumerate_paths(cfg, resource, source);

            // Check if any path lacks a close
            for path in &paths {
                if self.path_has_close(path, &resource.name) {
                    continue;
                }
                // Skip acquisition-failure paths: the terminal block carries an
                // error-guard exit on this resource (resource is NULL/invalid).
                if self.path_exits_on_acquisition_failure(cfg, path, &failure_exit_lines) {
                    continue;
                }
                leaks.push(LeakInfo {
                    resource: resource.name.clone(),
                    line: resource.line,
                    paths: if show_paths {
                        Some(vec![self.format_path(path)])
                    } else {
                        None
                    },
                });
                break; // One leak path is enough per resource
            }
        }

        leaks
    }

    /// Detect potential leaks using CFG path analysis (multi-language).
    /// Same logic as `detect` since the CFG is already language-aware.
    pub fn detect_multilang(
        &mut self,
        cfg: &SimpleCfg,
        resources: &[ResourceInfo],
        source: &[u8],
        func_node: Node,
        show_paths: bool,
    ) -> Vec<LeakInfo> {
        self.detect(cfg, resources, source, func_node, show_paths)
    }

    /// fix-R7 (cluster[11] RC1): walk the function body for close calls and
    /// record, per resource variable, the set of CFG block ids that close it.
    ///
    /// A close is recognized by [`extract_close_call`] (the same extractor the
    /// double-close / use-after-close detectors use) filtered by the language's
    /// `closers` set, so this is AST-driven and consistent across the resource
    /// analyses. The close-call's source line is mapped to its enclosing block
    /// via the block's `lines` membership.
    fn index_closes(&mut self, cfg: &SimpleCfg, func_node: Node, source: &[u8]) {
        self.close_blocks.clear();
        let patterns = get_resource_patterns(self.lang);
        // Collect (var, close_line) pairs.
        let mut close_lines: Vec<(String, u32)> = Vec::new();
        collect_close_lines(func_node, source, self.lang, &patterns, &mut close_lines);

        // Map each close line onto the block(s) whose `lines` contain it.
        for (var, line) in close_lines {
            for (block_id, block) in &cfg.blocks {
                if block.lines.contains(&line) {
                    self.close_blocks.entry(var.clone()).or_default().insert(*block_id);
                }
            }
        }
    }

    /// Enumerate paths from resource creation to exits (TIGER-04: with limit).
    fn enumerate_paths(
        &mut self,
        cfg: &SimpleCfg,
        resource: &ResourceInfo,
        _source: &[u8],
    ) -> Vec<Vec<usize>> {
        let mut paths = Vec::new();

        // Find which block contains the resource creation
        let start_block = self.find_block_with_line(cfg, resource.line);
        if start_block.is_none() {
            return paths;
        }
        let start = start_block.unwrap();

        // DFS to find all paths to exit blocks
        for &exit_id in &cfg.exit_blocks {
            if self.hit_limit {
                break;
            }
            self.find_paths_dfs(cfg, start, exit_id, &mut Vec::new(), &mut paths);
        }

        paths
    }

    fn find_block_with_line(&self, cfg: &SimpleCfg, line: u32) -> Option<usize> {
        for (id, block) in &cfg.blocks {
            if block.lines.contains(&line) {
                return Some(*id);
            }
        }
        // Default to entry block if not found
        Some(cfg.entry_block)
    }

    fn find_paths_dfs(
        &mut self,
        cfg: &SimpleCfg,
        current: usize,
        target: usize,
        current_path: &mut Vec<usize>,
        paths: &mut Vec<Vec<usize>>,
    ) {
        // TIGER-04: Check path limit
        if self.paths_enumerated >= self.max_paths {
            self.hit_limit = true;
            return;
        }

        // Cycle detection
        if current_path.contains(&current) {
            return;
        }

        current_path.push(current);

        if current == target {
            paths.push(current_path.clone());
            self.paths_enumerated += 1;
        } else if let Some(block) = cfg.blocks.get(&current) {
            for &succ in &block.succs {
                self.find_paths_dfs(cfg, succ, target, current_path, paths);
                if self.hit_limit {
                    break;
                }
            }
        }

        current_path.pop();
    }

    /// fix-R7 (cluster[11] RC1): a path closes the resource iff ANY block on the
    /// path is one of the blocks that close `resource_name` (precomputed by
    /// [`LeakDetector::index_closes`]). Previously this was a hardcoded `false`,
    /// so every path was considered close-free and every non-context-managed
    /// resource was reported as a leak.
    ///
    /// The check is per-PATH (not per-function): a resource closed only on one
    /// branch still leaks on the branch that omits the close, because that
    /// path's blocks do not intersect the close-block set.
    fn path_has_close(&self, path: &[usize], resource_name: &str) -> bool {
        let Some(blocks) = self.close_blocks.get(resource_name) else {
            return false;
        };
        path.iter().any(|b| blocks.contains(b))
    }

    /// fix-R7 (cluster[11] RC1): true when this path exits through the
    /// resource's acquisition-FAILURE guard (the resource is NULL/invalid on
    /// this path, so no close is expected and it is not a leak).
    ///
    /// A path's terminal block is its last block; we check whether that block
    /// contains any of the precomputed `failure_exit_lines` (return/exit
    /// statements inside an error-guard `if` on this resource).
    fn path_exits_on_acquisition_failure(
        &self,
        cfg: &SimpleCfg,
        path: &[usize],
        failure_exit_lines: &HashSet<u32>,
    ) -> bool {
        if failure_exit_lines.is_empty() {
            return false;
        }
        let Some(&last) = path.last() else {
            return false;
        };
        let Some(block) = cfg.blocks.get(&last) else {
            return false;
        };
        block.lines.iter().any(|l| failure_exit_lines.contains(l))
    }

    fn format_path(&self, path: &[usize]) -> String {
        path.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

impl Default for LeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Double-Close Detection
// =============================================================================

/// Double-close detector.
pub struct DoubleCloseDetector {
    lang: Language,
}

impl DoubleCloseDetector {
    pub fn new() -> Self {
        Self {
            lang: Language::Python,
        }
    }

    pub fn with_language(lang: Language) -> Self {
        Self { lang }
    }

    /// Detect double-close issues (legacy Python).
    pub fn detect(&self, func_node: Node, source: &[u8]) -> Vec<DoubleCloseInfo> {
        let mut issues = Vec::new();
        let mut close_sites: HashMap<String, Vec<u32>> = HashMap::new();

        self.find_closes(func_node, source, &mut close_sites);

        for (resource, lines) in close_sites {
            if lines.len() > 1 {
                issues.push(DoubleCloseInfo {
                    resource,
                    first_close: lines[0],
                    second_close: lines[1],
                });
            }
        }

        issues
    }

    /// Detect double-close issues with multi-language support.
    pub fn detect_multilang(&self, func_node: Node, source: &[u8]) -> Vec<DoubleCloseInfo> {
        let mut issues = Vec::new();
        let mut close_sites: HashMap<String, Vec<u32>> = HashMap::new();
        let patterns = get_resource_patterns(self.lang);

        self.find_closes_multilang(func_node, source, &mut close_sites, &patterns);

        for (resource, lines) in close_sites {
            if lines.len() > 1 {
                issues.push(DoubleCloseInfo {
                    resource,
                    first_close: lines[0],
                    second_close: lines[1],
                });
            }
        }

        issues
    }

    fn find_closes(&self, node: Node, source: &[u8], closes: &mut HashMap<String, Vec<u32>>) {
        if node.kind() == "call" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "attribute" {
                    if let Some(attr) = func.child_by_field_name("attribute") {
                        let method = node_text(attr, source);
                        if RESOURCE_CLOSERS.contains(&method) {
                            if let Some(obj) = func.child_by_field_name("object") {
                                let var_name = node_text(obj, source).to_string();
                                let line = node.start_position().row as u32 + 1;
                                closes.entry(var_name).or_default().push(line);
                            }
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_closes(child, source, closes);
        }
    }

    fn find_closes_multilang(
        &self,
        node: Node,
        source: &[u8],
        closes: &mut HashMap<String, Vec<u32>>,
        patterns: &LangResourcePatterns,
    ) {
        let kind = node.kind();
        // Check for method call patterns: obj.close(), obj.Close(), fclose(obj), etc.
        if kind == "call"
            || kind == "call_expression"
            || kind == "method_invocation"
            || kind == "invocation_expression"
        {
            if let Some((var_name, method)) = extract_close_call(node, source, self.lang) {
                if patterns.closers.contains(&method.as_str()) {
                    let line = node.start_position().row as u32 + 1;
                    closes.entry(var_name).or_default().push(line);
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_closes_multilang(child, source, closes, patterns);
        }
    }
}

impl Default for DoubleCloseDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Use-After-Close Detection
// =============================================================================

/// Use-after-close detector.
pub struct UseAfterCloseDetector {
    lang: Language,
}

impl UseAfterCloseDetector {
    pub fn new() -> Self {
        Self {
            lang: Language::Python,
        }
    }

    pub fn with_language(lang: Language) -> Self {
        Self { lang }
    }

    /// Detect use-after-close issues (legacy Python).
    pub fn detect(&self, func_node: Node, source: &[u8]) -> Vec<UseAfterCloseInfo> {
        let mut issues = Vec::new();
        let mut close_lines: HashMap<String, u32> = HashMap::new();
        let mut uses_after_close: Vec<(String, u32, u32)> = Vec::new();

        self.analyze(func_node, source, &mut close_lines, &mut uses_after_close);

        for (resource, close_line, use_line) in uses_after_close {
            issues.push(UseAfterCloseInfo {
                resource,
                close_line,
                use_line,
            });
        }

        issues
    }

    /// Detect use-after-close issues with multi-language support.
    pub fn detect_multilang(&self, func_node: Node, source: &[u8]) -> Vec<UseAfterCloseInfo> {
        let mut issues = Vec::new();
        let mut close_lines: HashMap<String, u32> = HashMap::new();
        let mut uses_after_close: Vec<(String, u32, u32)> = Vec::new();
        let patterns = get_resource_patterns(self.lang);

        self.analyze_multilang(
            func_node,
            source,
            &mut close_lines,
            &mut uses_after_close,
            &patterns,
        );

        for (resource, close_line, use_line) in uses_after_close {
            issues.push(UseAfterCloseInfo {
                resource,
                close_line,
                use_line,
            });
        }

        issues
    }

    fn analyze(
        &self,
        node: Node,
        source: &[u8],
        close_lines: &mut HashMap<String, u32>,
        uses_after: &mut Vec<(String, u32, u32)>,
    ) {
        let line = node.start_position().row as u32 + 1;

        if node.kind() == "call" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "attribute" {
                    if let Some(attr) = func.child_by_field_name("attribute") {
                        let method = node_text(attr, source);
                        if RESOURCE_CLOSERS.contains(&method) {
                            if let Some(obj) = func.child_by_field_name("object") {
                                let var_name = node_text(obj, source).to_string();
                                close_lines.insert(var_name, line);
                            }
                        } else if let Some(obj) = func.child_by_field_name("object") {
                            let var_name = node_text(obj, source).to_string();
                            if let Some(&close_line) = close_lines.get(&var_name) {
                                if line > close_line {
                                    uses_after.push((var_name, close_line, line));
                                }
                            }
                        }
                    }
                }
            }
        }

        if node.kind() == "attribute" {
            if let Some(obj) = node.child_by_field_name("object") {
                if obj.kind() == "identifier" {
                    let var_name = node_text(obj, source).to_string();
                    if let Some(&close_line) = close_lines.get(&var_name) {
                        if line > close_line {
                            uses_after.push((var_name, close_line, line));
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.analyze(child, source, close_lines, uses_after);
        }
    }

    fn analyze_multilang(
        &self,
        node: Node,
        source: &[u8],
        close_lines: &mut HashMap<String, u32>,
        uses_after: &mut Vec<(String, u32, u32)>,
        patterns: &LangResourcePatterns,
    ) {
        let line = node.start_position().row as u32 + 1;
        let kind = node.kind();

        // Check for close calls
        if kind == "call"
            || kind == "call_expression"
            || kind == "method_invocation"
            || kind == "invocation_expression"
        {
            if let Some((var_name, method)) = extract_close_call(node, source, self.lang) {
                if patterns.closers.contains(&method.as_str()) {
                    close_lines.insert(var_name, line);
                } else {
                    // Non-close method call on a variable - check if it's been closed
                    // Try to extract the object name
                    if let Some((obj_name, _)) = extract_close_call(node, source, self.lang) {
                        if let Some(&close_line) = close_lines.get(&obj_name) {
                            if line > close_line {
                                uses_after.push((obj_name, close_line, line));
                            }
                        }
                    }
                }
            }
        }

        // Check for member access on closed resources
        if kind == "attribute"
            || kind == "member_expression"
            || kind == "field_expression"
            || kind == "selector_expression"
        {
            if let Some(obj) = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("operand"))
                .or_else(|| node.child(0))
            {
                if obj.kind() == "identifier" {
                    let var_name = node_text(obj, source).to_string();
                    if let Some(&close_line) = close_lines.get(&var_name) {
                        if line > close_line {
                            uses_after.push((var_name, close_line, line));
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.analyze_multilang(child, source, close_lines, uses_after, patterns);
        }
    }
}

impl Default for UseAfterCloseDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Context Manager Suggestions
// =============================================================================

/// Suggest context manager usage for resources.
pub fn suggest_context_manager(resources: &[ResourceInfo]) -> Vec<ContextSuggestion> {
    resources
        .iter()
        .filter(|r| !r.closed) // Only suggest for non-context-managed resources
        .map(|r| {
            let suggestion = match r.resource_type.as_str() {
                "file" => format!("with open(...) as {}:", r.name),
                "connection" => format!("with connect(...) as {}:", r.name),
                "cursor" => format!("with connection.cursor() as {}:", r.name),
                "socket" => format!("with socket.socket(...) as {}:", r.name),
                _ => format!("with {} as {}:", r.resource_type, r.name),
            };
            ContextSuggestion {
                resource: r.name.clone(),
                suggestion,
            }
        })
        .collect()
}

/// Suggest cleanup patterns using language-appropriate idioms.
pub fn suggest_context_manager_multilang(
    resources: &[ResourceInfo],
    lang: Language,
) -> Vec<ContextSuggestion> {
    resources
        .iter()
        .filter(|r| !r.closed)
        .map(|r| {
            let suggestion = match lang {
                Language::Python => match r.resource_type.as_str() {
                    "file" => format!("with open(...) as {}:", r.name),
                    "connection" => format!("with connect(...) as {}:", r.name),
                    "cursor" => format!("with connection.cursor() as {}:", r.name),
                    "socket" => format!("with socket.socket(...) as {}:", r.name),
                    _ => format!("with {} as {}:", r.resource_type, r.name),
                },
                Language::Go => format!("defer {}.Close()", r.name),
                Language::Rust => format!("// {}: Drop trait handles cleanup automatically. Consider wrapping in a scope block.", r.name),
                Language::Java => match r.resource_type.as_str() {
                    "file_stream" | "reader" | "writer" | "scanner" | "stream" =>
                        format!("try ({} {} = ...) {{ ... }}", r.resource_type, r.name),
                    "connection" | "statement" =>
                        format!("try ({} {} = ...) {{ ... }}", r.resource_type, r.name),
                    _ => format!("try ({} {} = ...) {{ ... }}", r.resource_type, r.name),
                },
                Language::CSharp => format!("using (var {} = ...) {{ ... }}", r.name),
                Language::TypeScript | Language::JavaScript =>
                    format!("try {{ ... }} finally {{ {}.close(); }}", r.name),
                Language::C => match r.resource_type.as_str() {
                    "file" => format!("// Ensure fclose({}) on all paths", r.name),
                    "memory" => format!("// Ensure free({}) on all paths", r.name),
                    _ => format!("// Ensure cleanup of {} on all paths", r.name),
                },
                Language::Cpp => match r.resource_type.as_str() {
                    "heap_object" => format!("// Use std::unique_ptr or std::shared_ptr instead of raw new for {}", r.name),
                    "memory" => format!("// Use RAII wrapper or smart pointer for {}", r.name),
                    _ => format!("// Consider RAII wrapper for {}", r.name),
                },
                Language::Ruby => format!("File.open(...) do |{}| ... end", r.name),
                Language::Php => format!("// Ensure {}() cleanup in finally block", r.name),
                Language::Kotlin => format!("{}.use {{ {} -> ... }}", r.name, r.name),
                Language::Swift => format!("defer {{ {}.closeFile() }}", r.name),
                Language::Ocaml => format!("Fun.protect ~finally:(fun () -> close_in {}) (fun () -> ...)", r.name),
                Language::Lua | Language::Luau => format!("// Ensure {}:close() is called, consider pcall for cleanup", r.name),
                _ => format!("// Ensure {} is properly closed/released", r.name),
            };
            ContextSuggestion {
                resource: r.name.clone(),
                suggestion,
            }
        })
        .collect()
}

// =============================================================================
// Constraint Generation
// =============================================================================

/// Generate LLM-ready constraints from resource analysis.
pub fn generate_constraints(
    file: &str,
    function: Option<&str>,
    resources: &[ResourceInfo],
    leaks: &[LeakInfo],
    double_closes: &[DoubleCloseInfo],
    use_after_closes: &[UseAfterCloseInfo],
) -> Vec<ResourceConstraint> {
    let mut constraints = Vec::new();
    let context = function.unwrap_or("module").to_string();

    // Generate constraints for leaks
    for leak in leaks {
        constraints.push(ResourceConstraint {
            rule: format!(
                "Resource '{}' opened at line {} must be closed on all control flow paths",
                leak.resource, leak.line
            ),
            context: format!("{} in {}", context, file),
            confidence: 0.9,
        });
    }

    // Generate constraints for double-closes
    for dc in double_closes {
        constraints.push(ResourceConstraint {
            rule: format!(
                "Resource '{}' must not be closed twice (lines {} and {})",
                dc.resource, dc.first_close, dc.second_close
            ),
            context: format!("{} in {}", context, file),
            confidence: 0.95,
        });
    }

    // Generate constraints for use-after-close
    for uac in use_after_closes {
        constraints.push(ResourceConstraint {
            rule: format!(
                "Resource '{}' must not be used at line {} after being closed at line {}",
                uac.resource, uac.use_line, uac.close_line
            ),
            context: format!("{} in {}", context, file),
            confidence: 0.95,
        });
    }

    // General resource usage patterns
    for resource in resources {
        if !resource.closed {
            constraints.push(ResourceConstraint {
                rule: format!(
                    "Resource '{}' ({}) should use context manager pattern (with statement)",
                    resource.name, resource.resource_type
                ),
                context: format!("{} in {}", context, file),
                confidence: 0.85,
            });
        }
    }

    constraints
}

// =============================================================================
// Output Formatting
// =============================================================================

/// Format resources report as human-readable text.
pub fn format_resources_text(report: &ResourceReport) -> String {
    let mut lines = Vec::new();

    lines.push(format!("Resource Analysis: {}", report.file));
    lines.push(format!("Language: {}", report.language));
    if let Some(ref func) = report.function {
        lines.push(format!("Function: {}", func));
    }
    lines.push(String::new());

    // Resources
    lines.push(format!("Resources detected: {}", report.resources.len()));
    for r in &report.resources {
        let status = if r.closed { "closed" } else { "open" };
        lines.push(format!(
            "  - {}: {} at line {} [{}]",
            r.name, r.resource_type, r.line, status
        ));
    }
    lines.push(String::new());

    // Leaks
    if !report.leaks.is_empty() {
        lines.push(format!("Leaks found: {}", report.leaks.len()));
        for leak in &report.leaks {
            lines.push(format!("  - {} at line {}", leak.resource, leak.line));
            if let Some(ref paths) = leak.paths {
                for path in paths {
                    lines.push(format!("    Path: {}", path));
                }
            }
        }
    } else {
        lines.push("Leaks found: 0".to_string());
    }

    // Double closes
    if !report.double_closes.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "Double-close errors: {}",
            report.double_closes.len()
        ));
        for dc in &report.double_closes {
            lines.push(format!(
                "  - {}: first close at {}, second close at {}",
                dc.resource, dc.first_close, dc.second_close
            ));
        }
    }

    // Use after close
    if !report.use_after_closes.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "Use-after-close errors: {}",
            report.use_after_closes.len()
        ));
        for uac in &report.use_after_closes {
            lines.push(format!(
                "  - {}: closed at {}, used at {}",
                uac.resource, uac.close_line, uac.use_line
            ));
        }
    }

    // Suggestions
    if !report.suggestions.is_empty() {
        lines.push(String::new());
        lines.push(format!("Suggestions: {}", report.suggestions.len()));
        for s in &report.suggestions {
            lines.push(format!("  - {}: {}", s.resource, s.suggestion));
        }
    }

    // Constraints
    if !report.constraints.is_empty() {
        lines.push(String::new());
        lines.push(format!("Constraints: {}", report.constraints.len()));
        for c in &report.constraints {
            lines.push(format!("  - {} (confidence: {:.2})", c.rule, c.confidence));
        }
    }

    // Summary
    lines.push(String::new());
    lines.push("Summary:".to_string());
    lines.push(format!(
        "  resources_detected: {}",
        report.summary.resources_detected
    ));
    lines.push(format!("  leaks_found: {}", report.summary.leaks_found));
    lines.push(format!(
        "  double_closes_found: {}",
        report.summary.double_closes_found
    ));
    lines.push(format!(
        "  use_after_closes_found: {}",
        report.summary.use_after_closes_found
    ));
    lines.push(String::new());
    lines.push(format!(
        "Analysis completed in {}ms",
        report.analysis_time_ms
    ));

    lines.join("\n")
}

// =============================================================================
// Helper Functions
// =============================================================================

fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.start_byte()..node.end_byte()]).unwrap_or("")
}

/// fix-C5-2 (v0.5.0 AUDIT-FIX): peel `assert(...)` / `pcall(...)` /
/// parenthesised wrappers off a Lua RHS expression so the inner resource
/// acquisition call (`io.open(...)`) is what the creator matcher sees.
///
/// Lua idiom `local f = assert(io.open(uri, "r"))` (lua-lsp analyze.lua:679)
/// nests the real `io.open` `function_call` inside an `assert` `function_call`.
/// tree-sitter-lua models `assert(io.open(...))` as:
///   function_call
///     ├ identifier "assert"
///     └ arguments
///         ├ "("
///         ├ function_call         ← the io.open call we want
///         └ ")"
/// We descend while the node is a `function_call` whose callee is the bare
/// identifier `assert` or `pcall` (and only when it wraps a single inner
/// call), and through `parenthesized_expression` wrappers. Any other node is
/// returned unchanged. The descent is bounded to avoid pathological nesting.
fn unwrap_lua_acquisition_call<'a>(node: Node<'a>, source: &[u8]) -> Node<'a> {
    let mut current = node;
    for _ in 0..8 {
        match current.kind() {
            "parenthesized_expression" => {
                // Unwrap `(expr)` to its single inner expression. Indexed
                // access avoids a TreeCursor borrow outliving the node.
                let inner = (0..current.child_count())
                    .filter_map(|i| current.child(i))
                    .find(|n| !matches!(n.kind(), "(" | ")"));
                match inner {
                    Some(n) => current = n,
                    None => return current,
                }
            }
            "function_call" => {
                // Only unwrap the well-known guard wrappers `assert`/`pcall`.
                let callee = current.child(0);
                let is_guard = callee
                    .map(|c| {
                        c.kind() == "identifier"
                            && matches!(node_text(c, source), "assert" | "pcall")
                    })
                    .unwrap_or(false);
                if !is_guard {
                    return current;
                }
                // Find the single inner call inside the `arguments` node.
                let args = (0..current.child_count())
                    .filter_map(|i| current.child(i))
                    .find(|n| n.kind() == "arguments");
                let Some(args) = args else { return current };
                let inner_call = (0..args.child_count())
                    .filter_map(|i| args.child(i))
                    .find(|n| matches!(n.kind(), "function_call" | "parenthesized_expression"));
                match inner_call {
                    Some(n) => current = n,
                    // assert wrapping a non-call (e.g. `assert(x)`) — leave as
                    // is; the creator matcher will simply not match.
                    None => return current,
                }
            }
            _ => return current,
        }
    }
    current
}

/// Extract the function/method name from a call expression node.
/// Works across languages by checking various call node structures.
fn extract_call_name(node: Node, source: &[u8]) -> Option<String> {
    // Handle different call expression kinds across languages
    match node.kind() {
        // Python, JS/TS, Java, C#, Ruby, PHP
        "call" | "call_expression" | "method_invocation" | "invocation_expression" => {
            if let Some(func) = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.child_by_field_name("method"))
            {
                let func_text = node_text(func, source);
                // Extract just the function name from attribute/member access
                let func_name = func_text
                    .split('.')
                    .next_back()
                    .unwrap_or(func_text)
                    .rsplit("::")
                    .next()
                    .unwrap_or(func_text);
                return Some(func_name.to_string());
            }
            // For C/C++ call_expression, first child is the function
            if let Some(first_child) = node.child(0) {
                let text = node_text(first_child, source);
                let name = text
                    .split('.')
                    .next_back()
                    .unwrap_or(text)
                    .rsplit("::")
                    .next()
                    .unwrap_or(text);
                return Some(name.to_string());
            }
        }
        // Go: selector_expression.arguments
        "composite_literal" => {
            // Go: Type{} literal
        }
        // fix-C5-2 (v0.5.0 AUDIT-FIX): Lua/Luau `function_call`. tree-sitter-lua
        // models a call as `function_call` whose FIRST child is the callee —
        // either a bare `identifier` (`open(p)`) or a `dot_index_expression`
        // (`io.open`) / `method_index_expression` (`obj:method`). Without this
        // arm `extract_call_name` returned `None` for every Lua call, which
        // short-circuited `get_resource_type_from_call_multilang` (via `?`)
        // before its Lua `starts_with` matcher could run — so io.open was
        // never detected. We return the FULL dotted callee text (e.g.
        // `io.open`) so the qualified Lua creator entries (`io.open`,
        // `io.lines`) match exactly via the standard creator loop.
        "function_call" => {
            if let Some(callee) = node.child(0) {
                let text = node_text(callee, source);
                return Some(text.to_string());
            }
        }
        _ => {}
    }

    // G1-O2: no TEXT fallback. When the node is not a recognized call/
    // application kind we return None — the call name must come from the
    // AST structure, never from splitting source text on '('. (The
    // module-qualified acquisition matcher in `qualified_creator_type`
    // handles Rust/Ruby/OCaml/Elixir structurally.)
    None
}

// =============================================================================
// G2-O1 / G1-O1: Module-qualified acquisition matcher (Rust/Ruby/OCaml/Elixir)
//
// `pure node.kind()` cannot distinguish `File::open` (acquisition) from
// `Regex::new` (not). The ONE irreducible non-AST element is a curated,
// per-language SEMANTIC allowlist of acquisition symbols. Crucially it is
// matched against an AST-EXTRACTED fully-qualified callee path
// (`qualified_callee`, structural node.kind()/field-driven), never against a
// source substring — so `Foo.open` (Ruby) and `String::new` (Rust) no longer
// false-match the way the old `ends_with(".open")` / bare-`new` table did.
// =============================================================================

/// An acquisition symbol: `(receiver, method, resource_type)`.
///
/// `receiver` is matched against the LAST segment of the AST-extracted
/// receiver path (e.g. `File` for `std::fs::File::open`, `Stdlib` for
/// `Stdlib.open_out`). An empty `receiver` (`""`) means the callee is an
/// unqualified/built-in acquisition function (e.g. OCaml `open_in`, or a
/// known Rust acquisition *method* such as `.lock()` invoked on a receiver
/// whose path we do not resolve).
type AcqSymbol = (&'static str, &'static str, &'static str);

/// Curated per-language acquisition-symbol allowlist (G2-O1). Note: the bare
/// Rust `new` creator is intentionally ABSENT — `String::new` / `Vec::new` /
/// `BufReader::new` are not resource acquisitions and must never match.
fn acquisition_symbols(lang: Language) -> &'static [AcqSymbol] {
    match lang {
        Language::Rust => &[
            // std file / fs
            ("File", "open", "file"),
            ("File", "create", "file"),
            ("OpenOptions", "open", "file"),
            // networking
            ("TcpStream", "connect", "connection"),
            ("TcpListener", "bind", "listener"),
            ("UdpSocket", "bind", "socket"),
            ("UnixStream", "connect", "connection"),
            ("UnixListener", "bind", "listener"),
            // Sync guards: `.lock()` / `.try_lock()` on a Mutex/RwLock return
            // an RAII guard. These are the ONLY empty-receiver (bare-method)
            // acquisitions — keyed with an empty receiver and matched on the
            // method name alone, since the receiver is a runtime value whose
            // type we cannot resolve from the AST. The spine-eligibility guard
            // still requires a *known* acquisition method here (never a bare
            // `new`/`clone`). We deliberately EXCLUDE common method names like
            // `read`/`write`/`spawn` to avoid false-positives on ordinary
            // `x.read()` / `buf.write()` calls — those acquisitions are only
            // recognized when module-qualified (e.g. `TcpStream::connect`).
            ("", "lock", "mutex_guard"),
            ("", "try_lock", "mutex_guard"),
        ],
        Language::Ruby => &[
            ("File", "open", "file"),
            ("IO", "open", "file"),
            ("TCPSocket", "open", "socket"),
            ("TCPSocket", "new", "socket"),
            ("UNIXSocket", "open", "socket"),
            ("UNIXSocket", "new", "socket"),
            ("TCPServer", "open", "listener"),
            ("TCPServer", "new", "listener"),
            ("HTTP", "start", "connection"),
            ("Tempfile", "open", "file"),
            ("Tempfile", "new", "file"),
            ("PStore", "new", "store"),
        ],
        Language::Ocaml => &[
            ("", "open_in", "input_channel"),
            ("", "open_out", "output_channel"),
            ("", "open_in_bin", "input_channel"),
            ("", "open_out_bin", "output_channel"),
            ("Stdlib", "open_in", "input_channel"),
            ("Stdlib", "open_out", "output_channel"),
            ("Stdlib", "open_in_bin", "input_channel"),
            ("Stdlib", "open_out_bin", "output_channel"),
            ("Unix", "openfile", "file_descriptor"),
            ("Unix", "socket", "socket"),
            ("Unix", "open_connection", "connection"),
        ],
        Language::Elixir => &[
            ("File", "open", "file"),
            ("File", "open!", "file"),
            (":gen_tcp", "connect", "connection"),
            (":gen_tcp", "listen", "listener"),
            (":gen_udp", "open", "socket"),
            (":file", "open", "file"),
        ],
        _ => &[],
    }
}

/// True for languages whose resource acquisition is matched via the
/// module-qualified allowlist rather than the flat single-name creators loop.
fn uses_qualified_acquisition(lang: Language) -> bool {
    matches!(
        lang,
        Language::Rust | Language::Ruby | Language::Ocaml | Language::Elixir
    )
}

/// Flatten a Rust `scoped_identifier` (`std::fs::File::open`) into its segment
/// list. Pure structural: walks the nested `path`/`name` fields.
fn flatten_rust_scoped(node: Node, source: &[u8], out: &mut Vec<String>) {
    if node.kind() == "scoped_identifier" {
        if let Some(path) = node.child_by_field_name("path") {
            flatten_rust_scoped(path, source, out);
        }
        if let Some(name) = node.child_by_field_name("name") {
            out.push(node_text(name, source).to_string());
        }
    } else if node.kind() == "identifier" {
        out.push(node_text(node, source).to_string());
    }
}

/// Flatten an OCaml `value_path` (`Stdlib.open_out`) into `(receiver_segments,
/// value_name)`. Structural: `module_path` children + trailing `value_name`.
fn flatten_ocaml_value_path(node: Node, source: &[u8]) -> Option<(Vec<String>, String)> {
    if node.kind() != "value_path" {
        // bare `open_in` parses as value_path > value_name, but a lone
        // value_name may also appear directly.
        if node.kind() == "value_name" {
            return Some((Vec::new(), node_text(node, source).to_string()));
        }
        return None;
    }
    let mut segs: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "module_path" => {
                // module_path may itself nest; collect module_name leaves.
                let mut mc = child.walk();
                for m in child.children(&mut mc) {
                    if m.kind() == "module_name" {
                        segs.push(node_text(m, source).to_string());
                    } else if m.kind() == "module_path" {
                        let mut mmc = m.walk();
                        for mm in m.children(&mut mmc) {
                            if mm.kind() == "module_name" {
                                segs.push(node_text(mm, source).to_string());
                            }
                        }
                    }
                }
            }
            "value_name" => name = Some(node_text(child, source).to_string()),
            _ => {}
        }
    }
    name.map(|n| (segs, n))
}

/// Extract the fully-qualified callee of a single call/application node as
/// `(receiver_path_segments, method_name)`. Pure structural — driven by
/// node.kind()/field names per grammar, never by splitting source text. The
/// receiver segments are EMPTY for an unqualified callee and for a method call
/// whose receiver is an arbitrary value expression (e.g. `x.lock()`).
///
/// Returns None when `node` is not a recognized call shape for `lang`.
fn qualified_callee(node: Node, source: &[u8], lang: Language) -> Option<(Vec<String>, String)> {
    match lang {
        Language::Rust => {
            if node.kind() != "call_expression" {
                return None;
            }
            let func = node.child_by_field_name("function")?;
            match func.kind() {
                "scoped_identifier" => {
                    let mut segs = Vec::new();
                    flatten_rust_scoped(func, source, &mut segs);
                    let name = segs.pop()?;
                    Some((segs, name))
                }
                "identifier" => Some((Vec::new(), node_text(func, source).to_string())),
                "field_expression" => {
                    // method call `recv.method(...)`: receiver path is a value
                    // expression we don't resolve to a module path.
                    let field = func.child_by_field_name("field")?;
                    Some((Vec::new(), node_text(field, source).to_string()))
                }
                _ => None,
            }
        }
        Language::Ruby => {
            if node.kind() != "call" {
                return None;
            }
            let method = node.child_by_field_name("method")?;
            let method_name = node_text(method, source).to_string();
            // receiver: constant (`File`) or scope_resolution (`Net::HTTP`).
            if let Some(recv) = node.child_by_field_name("receiver") {
                match recv.kind() {
                    "constant" => Some((vec![node_text(recv, source).to_string()], method_name)),
                    "scope_resolution" => {
                        let mut segs: Vec<String> = Vec::new();
                        // scope_resolution: (scope)? :: name — collect constant
                        // leaves structurally.
                        collect_ruby_scope_segments(recv, source, &mut segs);
                        Some((segs, method_name))
                    }
                    // receiver is itself a call / variable / self → not a
                    // module-qualified acquisition.
                    _ => Some((Vec::new(), method_name)),
                }
            } else {
                Some((Vec::new(), method_name))
            }
        }
        Language::Ocaml => {
            if node.kind() != "application_expression" {
                return None;
            }
            let func = node.child_by_field_name("function")?;
            flatten_ocaml_value_path(func, source)
        }
        Language::Elixir => {
            if node.kind() != "call" {
                return None;
            }
            let target = node.child_by_field_name("target")?;
            if target.kind() != "dot" {
                return None;
            }
            let left = target.child_by_field_name("left")?;
            let right = target.child_by_field_name("right")?;
            // left = alias (`File`) or atom (`:gen_tcp`); right = identifier.
            let recv = match left.kind() {
                "alias" | "atom" => node_text(left, source).to_string(),
                _ => return Some((Vec::new(), node_text(right, source).to_string())),
            };
            Some((vec![recv], node_text(right, source).to_string()))
        }
        _ => None,
    }
}

/// Collect the constant segments of a Ruby `scope_resolution` node
/// (`Net::HTTP` → ["Net", "HTTP"]). Structural walk over `scope`/`name`.
fn collect_ruby_scope_segments(node: Node, source: &[u8], out: &mut Vec<String>) {
    if node.kind() == "scope_resolution" {
        if let Some(scope) = node.child_by_field_name("scope") {
            collect_ruby_scope_segments(scope, source, out);
        }
        if let Some(name) = node.child_by_field_name("name") {
            out.push(node_text(name, source).to_string());
        }
    } else if node.kind() == "constant" {
        out.push(node_text(node, source).to_string());
    }
}

/// G3-O1: structurally bind the variable name from an Elixir `=` LHS pattern.
///
/// Handles the two acquisition-binding shapes seen in real code:
///   * a bare scalar `identifier`  (`file = File.open!(p)`)
///   * an `{:ok, file}` ok-tuple   (`{:ok, file} = File.open(p)`)
///
/// For the tuple we return the FIRST `identifier` child (the bound variable),
/// skipping the `:ok`/`:error` `atom` tag — a pure node.kind() walk, never a
/// text split of the tuple. Returns None for shapes we do not bind (e.g. a
/// pin `^x`, a nested destructure, or a non-identifier LHS).
fn elixir_bind_name(left: Node, source: &[u8]) -> Option<String> {
    match left.kind() {
        "identifier" => Some(node_text(left, source).to_string()),
        "tuple" => {
            let mut cursor = left.walk();
            for child in left.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return Some(node_text(child, source).to_string());
                }
            }
            None
        }
        _ => None,
    }
}

/// G4-O2: the enclosing function `block` of a Rust `let_declaration` (ascend
/// `parent()` to the nearest `function_item`/closure body). Returns None when
/// no enclosing block is found (e.g. a `let` at item position).
fn rust_enclosing_block(decl: Node) -> Option<Node> {
    let mut cur = decl.parent();
    while let Some(n) = cur {
        if n.kind() == "function_item" {
            return n.child_by_field_name("body");
        }
        // closures / async blocks: stop at the first enclosing `block` whose
        // parent is a closure_expression / async_block.
        if n.kind() == "closure_expression" {
            return n.child_by_field_name("body");
        }
        cur = n.parent();
    }
    None
}

/// G4-O2: true when the Rust handle `var_name` (bound at `decl`) ESCAPES its
/// owning function scope on at least one path. Escape sites (all structural,
/// node.kind()/field-driven — never text matching the source):
///   * returned: a `return_expression` whose value is `var_name`, OR the
///     block's tail expression is the bare `identifier var_name`;
///   * stored into a field: `assignment_expression` whose `left` is a
///     `field_expression` and whose `right` is the bare `identifier var_name`;
///   * `mem::forget(var_name)` / `forget(var_name)` (Drop suppressed).
///
/// A handle used only locally (e.g. as a method receiver `var.read()`) does
/// NOT escape, so RAII cleanup stands.
fn rust_handle_escapes(decl: Node, var_name: &str, source: &[u8]) -> bool {
    let Some(block) = rust_enclosing_block(decl) else {
        return false;
    };
    // tail-expression return: last named child of the block that is the bare
    // identifier `var_name`.
    if let Some(tail) = block.named_child(block.named_child_count().saturating_sub(1)) {
        if tail.kind() == "identifier" && node_text(tail, source) == var_name {
            return true;
        }
    }
    rust_escape_in_subtree(block, var_name, source)
}

/// Recursive structural scan for a Rust escape site of `var_name` (see
/// `rust_handle_escapes`).
fn rust_escape_in_subtree(node: Node, var_name: &str, source: &[u8]) -> bool {
    if rust_node_is_escape_site(node, var_name, source) {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if rust_escape_in_subtree(child, var_name, source) {
            return true;
        }
    }
    false
}

/// True when THIS Rust node is itself an escape site for `var_name` (not its
/// descendants — the caller recurses). Structural per node.kind()/field.
fn rust_node_is_escape_site(node: Node, var_name: &str, source: &[u8]) -> bool {
    match node.kind() {
        // `return <handle>;` — bare handle identifier as the returned value.
        "return_expression" => node
            .named_child(0)
            .map(|val| val.kind() == "identifier" && node_text(val, source) == var_name)
            .unwrap_or(false),
        // `<field_expr> = <handle>;` moves ownership into a field.
        "assignment_expression" => {
            match (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                (Some(left), Some(right)) => {
                    left.kind() == "field_expression"
                        && right.kind() == "identifier"
                        && node_text(right, source) == var_name
                }
                _ => false,
            }
        }
        // `mem::forget(handle)` / `std::mem::forget(handle)` / `forget(handle)`.
        "call_expression" => {
            rust_call_is_forget(node, source) && rust_call_has_ident_arg(node, var_name, source)
        }
        _ => false,
    }
}

/// G4-O2: true when a Rust `call_expression`'s callee is `forget` —
/// last path segment of the callee is `forget` (`mem::forget`,
/// `std::mem::forget`, or a bare imported `forget`). Structural: reads the
/// `function` field's scoped/identifier shape, never a source substring.
fn rust_call_is_forget(call: Node, source: &[u8]) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let last = match func.kind() {
        "identifier" => node_text(func, source).to_string(),
        "scoped_identifier" => {
            let mut segs = Vec::new();
            flatten_rust_scoped(func, source, &mut segs);
            match segs.pop() {
                Some(s) => s,
                None => return false,
            }
        }
        _ => return false,
    };
    last == "forget"
}

/// G4-O2: true when a Rust `call_expression`'s argument list contains the bare
/// `identifier var_name`. Structural walk over the `arguments` node.
fn rust_call_has_ident_arg(call: Node, var_name: &str, source: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() == "identifier" && node_text(arg, source) == var_name {
            return true;
        }
    }
    false
}

/// G4-O2: true when the Rust handle `var_name` is EXPLICITLY closed/dropped in
/// its enclosing function body — `drop(var_name)` or a closer method call
/// `var_name.close()` / `.shutdown()` / etc. (from the per-language `closers`
/// list). When present, the escape is cleaned up before/along the path, so we
/// do NOT report a leak. (A full CFG path-sensitive version is G4-O1.)
fn rust_handle_explicitly_closed(
    decl: Node,
    var_name: &str,
    source: &[u8],
    patterns: &LangResourcePatterns,
) -> bool {
    let Some(block) = rust_enclosing_block(decl) else {
        return false;
    };
    rust_close_in_subtree(block, var_name, source, patterns)
}

/// Recursive structural scan for an explicit `drop(var)` / `var.closer()` site.
fn rust_close_in_subtree(
    node: Node,
    var_name: &str,
    source: &[u8],
    patterns: &LangResourcePatterns,
) -> bool {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            // `drop(var)` — bare/scoped callee whose last segment is `drop`.
            let drop_callee = match func.kind() {
                "identifier" => node_text(func, source) == "drop",
                "scoped_identifier" => {
                    let mut segs = Vec::new();
                    flatten_rust_scoped(func, source, &mut segs);
                    segs.last().map(|s| s.as_str()) == Some("drop")
                }
                _ => false,
            };
            if drop_callee && rust_call_has_ident_arg(node, var_name, source) {
                return true;
            }
            // `var.close()` / `var.shutdown()` — method call on the handle
            // whose method name is a known closer.
            if func.kind() == "field_expression" {
                if let (Some(recv), Some(field)) = (
                    func.child_by_field_name("value"),
                    func.child_by_field_name("field"),
                ) {
                    if recv.kind() == "identifier"
                        && node_text(recv, source) == var_name
                        && patterns.closers.contains(&node_text(field, source))
                    {
                        return true;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if rust_close_in_subtree(child, var_name, source, patterns) {
            return true;
        }
    }
    false
}

/// Match an AST-extracted `(receiver_segments, method)` against the curated
/// acquisition allowlist for `lang`. Returns the resource type on a hit.
///
/// SPINE-ELIGIBILITY (G1-O1 guard): a callee with an empty receiver path may
/// match ONLY a known acquisition *method* (an allowlist entry whose receiver
/// is `""`). A module-qualified callee matches when its receiver path's LAST
/// segment equals the entry receiver and the method matches. This is what
/// makes a bare single-segment `new`/`clone` on a chain spine NEVER match.
fn match_acquisition(
    receiver_segments: &[String],
    method: &str,
    lang: Language,
) -> Option<String> {
    for &(want_recv, want_method, rtype) in acquisition_symbols(lang) {
        if want_method != method {
            continue;
        }
        if want_recv.is_empty() {
            // unqualified / known-method entry: only match when the extracted
            // callee is itself unqualified (no resolved module path).
            if receiver_segments.is_empty() {
                return Some(rtype.to_string());
            }
        } else if receiver_segments.last().map(|s| s.as_str()) == Some(want_recv) {
            return Some(rtype.to_string());
        }
    }
    None
}

/// G2-O1 + G1-O1: resolve the resource type of a value node for a
/// qualified-acquisition language by descending the call/postfix SPINE and
/// matching each callee against the acquisition allowlist.
///
/// The spine follows `function`/`receiver`/value fields ONLY (never argument
/// nodes): `File::open(path).unwrap()` exposes `File::open`; `File::open(p)?`
/// unwraps the `try_expression`. Each spine callee is matched via
/// `match_acquisition`, so a bare `new`/`unwrap`/`clone` on the spine is
/// rejected by the spine-eligibility guard.
fn qualified_creator_type(node: Node, source: &[u8], lang: Language) -> Option<String> {
    // 1. direct callee at this node.
    if let Some((segs, method)) = qualified_callee(node, source, lang) {
        if let Some(rt) = match_acquisition(&segs, &method, lang) {
            return Some(rt);
        }
    }
    // 2. descend the spine into the receiver chain / postfix wrappers.
    match lang {
        Language::Rust => match node.kind() {
            // postfix `?`: child(0) is the inner expression.
            "try_expression" => {
                let inner = node.child(0)?;
                qualified_creator_type(inner, source, lang)
            }
            // `recv.method(...)` and `File::open(p).unwrap()`: the function
            // field's value (for a field_expression) is the receiver chain.
            "call_expression" => {
                let func = node.child_by_field_name("function")?;
                if func.kind() == "field_expression" {
                    let recv = func.child_by_field_name("value")?;
                    return qualified_creator_type(recv, source, lang);
                }
                None
            }
            // reference/await-style wrappers occasionally seen on a spine.
            "reference_expression" | "await_expression" | "unary_expression" => {
                let inner = node.child(node.child_count().saturating_sub(1))?;
                qualified_creator_type(inner, source, lang)
            }
            _ => None,
        },
        Language::Ruby => {
            // `Foo.new.open` etc.: descend the receiver chain. Receiver is a
            // call when chained.
            if node.kind() == "call" {
                if let Some(recv) = node.child_by_field_name("receiver") {
                    if recv.kind() == "call" {
                        return qualified_creator_type(recv, source, lang);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// fix-R7 (cluster[11] RC1): collect `(resource_var, close_line)` pairs by
/// walking `node` for close calls.
///
/// Recognizes a close exactly as the double-close / use-after-close detectors
/// do: an AST call whose `(var, method)` (from [`extract_close_call`]) has
/// `method` in the language's `closers` set. The 1-indexed source line of the
/// call is recorded so the caller can map it onto a CFG block.
fn collect_close_lines(
    node: Node,
    source: &[u8],
    lang: Language,
    patterns: &LangResourcePatterns,
    out: &mut Vec<(String, u32)>,
) {
    let kind = node.kind();
    if kind == "call"
        || kind == "call_expression"
        || kind == "method_invocation"
        || kind == "invocation_expression"
        || kind == "function_call"
    {
        if let Some((var_name, method)) = extract_close_call(node, source, lang) {
            if patterns.closers.contains(&method.as_str()) {
                let line = node.start_position().row as u32 + 1;
                out.push((var_name, line));
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_close_lines(child, source, lang, patterns, out);
    }
}

/// fix-R7 (cluster[11] RC1): true when ownership of `var_name` is transferred
/// out of the function so it is NOT a leak here.
///
/// The common C/C++ pattern is `return fp;` (a factory that hands the open
/// handle to its caller — e.g. tinyxml2 `XMLDocument::LoadFile`). We detect a
/// `return`-kind statement whose returned expression is (or contains, after a
/// cast/parenthesization) the bare identifier `var_name`. Languages with RAII /
/// GC ownership do not need this (their handles are marked closed via
/// `in_context_manager`/escape analysis already), so we scope it to C/C++.
fn resource_ownership_transferred(
    func_node: Node,
    var_name: &str,
    source: &[u8],
    lang: Language,
) -> bool {
    if !matches!(lang, Language::C | Language::Cpp) {
        return false;
    }
    return_transfers_var(func_node, var_name, source)
}

/// fix-R7 (cluster[11] RC1): collect the source lines that exit the function on
/// `var_name`'s acquisition-FAILURE guard.
///
/// The C idiom `if ((fp = fopen(..)) == NULL) return -1;` (and `fd = open();
/// if (fd == -1) return -1;`, `if (!p) return;`) means the early-return branch
/// is taken ONLY when acquisition FAILED — the resource is NULL/invalid there,
/// so the missing close on that path is correct, not a leak. We find `if`
/// statements whose condition is an error-test referencing `var_name`
/// (`== NULL`, `== 0`, `== -1`, `< 0`, or `!var`) and whose consequence
/// contains an exit (`return`/`goto`/`break`/`continue`) that does NOT itself
/// close the resource, and record those exit lines. The leak walk then skips
/// any path whose terminal block is one of these failure exits.
///
/// Scoped to C/C++ (the idiom + the false-positive class are C/C++); other
/// languages mark acquisition via `in_context_manager`/RAII already.
fn acquisition_failure_exit_lines(
    func_node: Node,
    var_name: &str,
    source: &[u8],
    lang: Language,
) -> HashSet<u32> {
    let mut out = HashSet::new();
    if !matches!(lang, Language::C | Language::Cpp) {
        return out;
    }
    let patterns = get_resource_patterns(lang);
    collect_acquisition_failure_exits(func_node, var_name, source, &patterns, &mut out);
    out
}

fn collect_acquisition_failure_exits(
    node: Node,
    var_name: &str,
    source: &[u8],
    patterns: &LangResourcePatterns,
    out: &mut HashSet<u32>,
) {
    if node.kind() == "if_statement" {
        if let Some(cond) = node.child_by_field_name("condition") {
            if condition_is_error_guard_on(cond, var_name, source) {
                // The consequence is the then-branch. Collect exit statement
                // lines that do not close the resource.
                if let Some(cons) = node.child_by_field_name("consequence") {
                    collect_exit_lines_without_close(cons, var_name, source, patterns, out);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_acquisition_failure_exits(child, var_name, source, patterns, out);
    }
}

/// True when `cond` is an error/null test that references `var_name`:
/// `var == NULL|0|-1`, `var < 0`, `!var`, or the same with `var` assigned
/// inside the condition (`(var = acquire()) == NULL`). Structural per AST.
fn condition_is_error_guard_on(cond: Node, var_name: &str, source: &[u8]) -> bool {
    match cond.kind() {
        "parenthesized_expression" => cond
            .named_child(0)
            .map(|c| condition_is_error_guard_on(c, var_name, source))
            .unwrap_or(false),
        // `!var`
        "unary_expression" => {
            let op_is_not = cond
                .child_by_field_name("operator")
                .map(|o| node_text(o, source) == "!")
                .unwrap_or(false);
            op_is_not
                && cond
                    .child_by_field_name("argument")
                    .map(|a| expr_references_var(a, var_name, source))
                    .unwrap_or(false)
        }
        // `var == NULL`, `var == -1`, `var < 0`, `(var = acquire()) == NULL`
        "binary_expression" => {
            let op = cond
                .child_by_field_name("operator")
                .map(|o| node_text(o, source))
                .unwrap_or_default();
            if !matches!(op, "==" | "<" | "<=" | "!=") {
                return false;
            }
            let left = cond.child_by_field_name("left");
            let right = cond.child_by_field_name("right");
            // One side references the var (directly or via the assignment), the
            // other is an error sentinel (NULL / 0 / negative literal).
            let var_side = left
                .map(|l| expr_references_var(l, var_name, source))
                .unwrap_or(false)
                || right
                    .map(|r| expr_references_var(r, var_name, source))
                    .unwrap_or(false);
            let sentinel_side = left
                .map(|l| is_error_sentinel(l, source))
                .unwrap_or(false)
                || right.map(|r| is_error_sentinel(r, source)).unwrap_or(false);
            var_side && sentinel_side
        }
        _ => false,
    }
}

/// True when `node`'s subtree references the identifier `var_name` (as a bare
/// identifier or as the LHS of an inner assignment `var = acquire()`).
fn expr_references_var(node: Node, var_name: &str, source: &[u8]) -> bool {
    match node.kind() {
        "identifier" => node_text(node, source) == var_name,
        "parenthesized_expression" | "assignment_expression" => {
            let mut cursor = node.walk();
            let children: Vec<Node> = node.children(&mut cursor).collect();
            children
                .into_iter()
                .any(|c| expr_references_var(c, var_name, source))
        }
        _ => false,
    }
}

/// True when `node` is an error sentinel: `NULL`, `0`, or a negative literal.
fn is_error_sentinel(node: Node, source: &[u8]) -> bool {
    match node.kind() {
        "null" => true,
        "number_literal" => {
            let t = node_text(node, source);
            t == "0" || t.starts_with('-')
        }
        "unary_expression" => {
            // `-1`
            node.child_by_field_name("operator")
                .map(|o| node_text(o, source) == "-")
                .unwrap_or(false)
        }
        _ => false,
    }
}

/// Collect lines of exit statements (`return`/`goto`/`break`/`continue`) within
/// `node` that do NOT close `var_name`. A `return`-after-close is fine (handled
/// by the close index); here we want the failure exits that skip the close.
fn collect_exit_lines_without_close(
    node: Node,
    var_name: &str,
    source: &[u8],
    patterns: &LangResourcePatterns,
    out: &mut HashSet<u32>,
) {
    let kind = node.kind();
    if matches!(
        kind,
        "return_statement" | "goto_statement" | "break_statement" | "continue_statement"
    ) {
        // If this exit's enclosing branch already closed the resource the close
        // index covers it; we only need to mark the exit line so its CFG block
        // (the failure-branch terminal) is recognized. Record the exit line.
        let line = node.start_position().row as u32 + 1;
        out.insert(line);
        return;
    }
    // Do not descend into a nested closing call's siblings unnecessarily, but a
    // simple full descent is correct and cheap for a guard body.
    let _ = (var_name, patterns);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_exit_lines_without_close(child, var_name, source, patterns, out);
    }
}

/// Recursively scan for a C/C++ `return_statement` that returns `var_name`.
fn return_transfers_var(node: Node, var_name: &str, source: &[u8]) -> bool {
    if node.kind() == "return_statement" {
        // The returned expression is the first named child. Accept a bare
        // identifier, or an identifier nested under a cast/parenthesized
        // expression (`return (FILE*)fp;`).
        if let Some(expr) = node.named_child(0) {
            if identifier_subtree_matches(expr, var_name, source) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if return_transfers_var(child, var_name, source) {
            return true;
        }
    }
    false
}

/// True when `node` IS the bare identifier `var_name`, or is a cast /
/// parenthesized / unary wrapper whose sole identifier operand is `var_name`.
/// Deliberately conservative: a `return f(fp);` (call, not a transfer of `fp`
/// itself) does NOT match because the identifier is an argument of a call node,
/// which we do not unwrap.
fn identifier_subtree_matches(node: Node, var_name: &str, source: &[u8]) -> bool {
    match node.kind() {
        "identifier" => node_text(node, source) == var_name,
        "cast_expression" | "parenthesized_expression" | "pointer_expression" => node
            .named_child(node.named_child_count().saturating_sub(1))
            .map(|c| identifier_subtree_matches(c, var_name, source))
            .unwrap_or(false),
        _ => false,
    }
}

/// Extract the variable name from a C/C++ declarator (handles pointer_declarator, etc.)
fn extract_c_declarator_name(declarator: Node, source: &[u8]) -> Option<String> {
    match declarator.kind() {
        "identifier" => Some(node_text(declarator, source).to_string()),
        "pointer_declarator" => {
            // *foo -> get the identifier inside
            let mut cursor = declarator.walk();
            for child in declarator.children(&mut cursor) {
                if child.kind() == "identifier" {
                    return Some(node_text(child, source).to_string());
                }
                if child.kind() == "pointer_declarator" {
                    return extract_c_declarator_name(child, source);
                }
            }
            None
        }
        _ => Some(node_text(declarator, source).to_string()),
    }
}

/// Extract (object_name, method_name) from a close call like `f.close()` or `fclose(fp)`.
fn extract_close_call(node: Node, source: &[u8], lang: Language) -> Option<(String, String)> {
    match lang {
        Language::Python
        | Language::Ruby
        | Language::Java
        | Language::CSharp
        | Language::TypeScript
        | Language::JavaScript
        | Language::Scala
        | Language::Kotlin
        | Language::Swift => {
            // obj.method() pattern
            if let Some(func) = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("method"))
                .or_else(|| node.child_by_field_name("name"))
            {
                // Check for attribute/member access: obj.close()
                if func.kind() == "attribute"
                    || func.kind() == "member_expression"
                    || func.kind() == "selector_expression"
                    || func.kind() == "field_access"
                {
                    let obj = func.child_by_field_name("object").or_else(|| func.child(0));
                    let attr = func
                        .child_by_field_name("attribute")
                        .or_else(|| func.child_by_field_name("field"))
                        .or_else(|| func.child_by_field_name("name"));

                    if let (Some(obj), Some(attr)) = (obj, attr) {
                        let var_name = node_text(obj, source).to_string();
                        let method = node_text(attr, source).to_string();
                        return Some((var_name, method));
                    }
                }
            }
            None
        }
        Language::Go => {
            // Go: obj.Close() - selector_expression
            if let Some(func) = node.child_by_field_name("function") {
                if func.kind() == "selector_expression" {
                    if let Some(operand) = func.child_by_field_name("operand") {
                        if let Some(field) = func.child_by_field_name("field") {
                            let var_name = node_text(operand, source).to_string();
                            let method = node_text(field, source).to_string();
                            return Some((var_name, method));
                        }
                    }
                }
            }
            None
        }
        Language::C | Language::Cpp => {
            // C: fclose(fp) - the variable is the first argument
            if let Some(func) = node
                .child_by_field_name("function")
                .or_else(|| node.child(0))
            {
                let func_name = node_text(func, source).to_string();
                // Get first argument
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(first_arg) = args.child(1) {
                        // child(0) is usually '('
                        let var_name = node_text(first_arg, source).to_string();
                        return Some((var_name, func_name));
                    }
                }
            }
            None
        }
        _ => {
            // Generic: try obj.method() pattern
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(obj) = func.child_by_field_name("object").or_else(|| func.child(0)) {
                    if let Some(attr) = func.child_by_field_name("attribute") {
                        let var_name = node_text(obj, source).to_string();
                        let method = node_text(attr, source).to_string();
                        return Some((var_name, method));
                    }
                }
            }
            None
        }
    }
}

// =============================================================================
// Multi-language CFG Builder
// =============================================================================

/// Build a simplified CFG from a function AST, using language-specific patterns.
pub fn build_cfg_multilang(func_node: Node, source: &[u8], lang: Language) -> SimpleCfg {
    let patterns = get_resource_patterns(lang);
    let mut cfg = SimpleCfg::new();
    let entry_id = cfg.new_block();
    cfg.entry_block = entry_id;

    if let Some(block) = cfg.blocks.get_mut(&entry_id) {
        block.is_entry = true;
    }

    // Find the function body - try all known body kinds
    let body = func_node
        .children(&mut func_node.walk())
        .find(|n| patterns.body_kinds.contains(&n.kind()));

    if let Some(body_node) = body {
        let exit_id =
            process_statements_multilang(&mut cfg, body_node, source, entry_id, &patterns);
        if let Some(exit) = exit_id {
            if !cfg.blocks.get(&exit).is_none_or(|b| b.is_exit) {
                cfg.mark_exit(exit);
            }
        }
    } else {
        // Empty function or body not found - try processing children directly
        cfg.mark_exit(entry_id);
    }

    cfg
}

fn process_statements_multilang(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    mut current: usize,
    patterns: &LangResourcePatterns,
) -> Option<usize> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();

        if patterns.return_kinds.contains(&kind) {
            // Return/raise/throw statement
            let text = node_text(child, source).to_string();
            let line = child.start_position().row as u32 + 1;
            if let Some(block) = cfg.blocks.get_mut(&current) {
                block
                    .stmts
                    .push((child.start_byte(), child.end_byte(), kind.to_string(), text));
                block.lines.push(line);
            }
            cfg.mark_exit(current);
            return None;
        } else if patterns.if_kinds.contains(&kind) {
            // If statement - creates branches
            current = process_if_multilang(cfg, child, source, current, patterns)?;
        } else if patterns.loop_kinds.contains(&kind) {
            // Loop statement
            current = process_loop_multilang(cfg, child, source, current, patterns)?;
        } else if patterns.try_kinds.contains(&kind) {
            // Try/catch statement
            current = process_try_multilang(cfg, child, source, current, patterns)?;
        } else if patterns.cleanup_block_kinds.contains(&kind) {
            // Context manager / defer / using
            current = process_cleanup_block_multilang(cfg, child, source, current, patterns)?;
        } else {
            // Regular statement
            let text = node_text(child, source).to_string();
            let line = child.start_position().row as u32 + 1;
            if let Some(block) = cfg.blocks.get_mut(&current) {
                block
                    .stmts
                    .push((child.start_byte(), child.end_byte(), kind.to_string(), text));
                block.lines.push(line);
            }
        }
    }
    Some(current)
}

fn process_if_multilang(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    current: usize,
    patterns: &LangResourcePatterns,
) -> Option<usize> {
    // Add condition to current block
    if let Some(cond) = node.child_by_field_name("condition") {
        let text = node_text(cond, source).to_string();
        let line = cond.start_position().row as u32 + 1;
        if let Some(block) = cfg.blocks.get_mut(&current) {
            block.stmts.push((
                cond.start_byte(),
                cond.end_byte(),
                "condition".to_string(),
                text,
            ));
            block.lines.push(line);
        }
    }

    let true_block = cfg.new_block();
    cfg.add_edge(current, true_block);

    // Find the body block
    let mut cursor = node.walk();
    let consequence = node
        .children(&mut cursor)
        .find(|n| patterns.body_kinds.contains(&n.kind()));
    let true_exit = if let Some(body) = consequence {
        process_statements_multilang(cfg, body, source, true_block, patterns)
    } else {
        Some(true_block)
    };

    // Find alternative (else/elif)
    let mut cursor = node.walk();
    let alternative = node
        .children(&mut cursor)
        .find(|n| n.kind() == "else_clause" || n.kind() == "elif_clause" || n.kind() == "else");

    let false_exit = if let Some(alt) = alternative {
        let false_block = cfg.new_block();
        cfg.add_edge(current, false_block);
        let alt_body = alt
            .children(&mut alt.walk())
            .find(|n| patterns.body_kinds.contains(&n.kind()));
        if let Some(alt_body) = alt_body {
            process_statements_multilang(cfg, alt_body, source, false_block, patterns)
        } else {
            Some(false_block)
        }
    } else {
        None
    };

    let merge = cfg.new_block();
    if let Some(te) = true_exit {
        cfg.add_edge(te, merge);
    }
    if let Some(fe) = false_exit {
        cfg.add_edge(fe, merge);
    }
    if alternative.is_none() {
        cfg.add_edge(current, merge);
    }

    Some(merge)
}

fn process_loop_multilang(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    current: usize,
    patterns: &LangResourcePatterns,
) -> Option<usize> {
    let header = cfg.new_block();
    cfg.add_edge(current, header);

    if let Some(cond) = node.child_by_field_name("condition") {
        let text = node_text(cond, source).to_string();
        let line = cond.start_position().row as u32 + 1;
        if let Some(block) = cfg.blocks.get_mut(&header) {
            block.stmts.push((
                cond.start_byte(),
                cond.end_byte(),
                "loop_condition".to_string(),
                text,
            ));
            block.lines.push(line);
        }
    }

    let body_block = cfg.new_block();
    cfg.add_edge(header, body_block);

    let body = node
        .children(&mut node.walk())
        .find(|n| patterns.body_kinds.contains(&n.kind()));
    let body_exit = if let Some(body_node) = body {
        process_statements_multilang(cfg, body_node, source, body_block, patterns)
    } else {
        Some(body_block)
    };

    if let Some(be) = body_exit {
        cfg.add_edge(be, header);
    }

    let exit = cfg.new_block();
    cfg.add_edge(header, exit);
    Some(exit)
}

fn process_try_multilang(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    current: usize,
    patterns: &LangResourcePatterns,
) -> Option<usize> {
    let try_block = cfg.new_block();
    cfg.add_edge(current, try_block);

    let try_body = node
        .children(&mut node.walk())
        .find(|n| patterns.body_kinds.contains(&n.kind()));
    let try_exit = if let Some(body) = try_body {
        process_statements_multilang(cfg, body, source, try_block, patterns)
    } else {
        Some(try_block)
    };

    let mut cursor = node.walk();
    let mut handler_exits = Vec::new();
    for child in node.children(&mut cursor) {
        let ck = child.kind();
        if ck == "except_clause" || ck == "catch_clause" || ck == "rescue" {
            let handler_block = cfg.new_block();
            cfg.add_edge(try_block, handler_block);
            if let Some(block) = cfg.blocks.get_mut(&try_block) {
                block.exception_handlers.push(handler_block);
            }
            let handler_body = child
                .children(&mut child.walk())
                .find(|n| patterns.body_kinds.contains(&n.kind()));
            if let Some(hb) = handler_body {
                if let Some(exit) =
                    process_statements_multilang(cfg, hb, source, handler_block, patterns)
                {
                    handler_exits.push(exit);
                }
            } else {
                handler_exits.push(handler_block);
            }
        }
    }

    let finally_clause = node
        .children(&mut node.walk())
        .find(|n| n.kind() == "finally_clause" || n.kind() == "finally");

    let merge = cfg.new_block();
    if let Some(te) = try_exit {
        if let Some(finally) = finally_clause {
            let finally_block = cfg.new_block();
            cfg.add_edge(te, finally_block);
            let finally_body = finally
                .children(&mut finally.walk())
                .find(|n| patterns.body_kinds.contains(&n.kind()));
            if let Some(fb) = finally_body {
                if let Some(exit) =
                    process_statements_multilang(cfg, fb, source, finally_block, patterns)
                {
                    cfg.add_edge(exit, merge);
                }
            } else {
                cfg.add_edge(finally_block, merge);
            }
        } else {
            cfg.add_edge(te, merge);
        }
    }
    for he in handler_exits {
        cfg.add_edge(he, merge);
    }

    Some(merge)
}

fn process_cleanup_block_multilang(
    cfg: &mut SimpleCfg,
    node: Node,
    source: &[u8],
    current: usize,
    patterns: &LangResourcePatterns,
) -> Option<usize> {
    let text = node_text(node, source).to_string();
    let line = node.start_position().row as u32 + 1;
    if let Some(block) = cfg.blocks.get_mut(&current) {
        block.stmts.push((
            node.start_byte(),
            node.end_byte(),
            node.kind().to_string(),
            text,
        ));
        block.lines.push(line);
    }

    let body = node
        .children(&mut node.walk())
        .find(|n| patterns.body_kinds.contains(&n.kind()));
    if let Some(body_node) = body {
        process_statements_multilang(cfg, body_node, source, current, patterns)
    } else {
        Some(current)
    }
}

#[cfg(test)]
fn get_python_parser() -> PatternsResult<Parser> {
    get_parser_for_language(Language::Python)
}

/// Create a tree-sitter parser for the given language.
fn get_parser_for_language(lang: Language) -> PatternsResult<Parser> {
    let mut parser = Parser::new();
    let ts_lang =
        ParserPool::get_ts_language(lang).ok_or_else(|| PatternsError::UnsupportedLanguage {
            language: lang.as_str().to_string(),
        })?;
    parser
        .set_language(&ts_lang)
        .map_err(|e| PatternsError::ParseError {
            file: PathBuf::from("<internal>"),
            message: format!("Failed to set {} language: {}", lang.as_str(), e),
        })?;
    Ok(parser)
}

/// Get the function name from a node, handling language-specific declarator patterns.
/// For C/C++, the name is nested inside a `function_declarator` child of the `declarator` field.
/// For OCaml, value_definition wraps let_binding which has the pattern field.
fn get_function_name_from_node(
    node: Node,
    source: &[u8],
    patterns: &LangResourcePatterns,
) -> Option<String> {
    // OCaml: value_definition wraps let_binding(s)
    if node.kind() == "value_definition" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    return Some(node_text(pattern, source).to_string());
                }
            }
        }
        return None;
    }

    // First try the standard name field
    if let Some(name_node) = node.child_by_field_name(patterns.name_field) {
        // For C/C++, the "declarator" field contains a function_declarator
        // which itself has a "declarator" field containing the actual identifier
        if name_node.kind() == "function_declarator" {
            if let Some(inner) = name_node.child_by_field_name("declarator") {
                return Some(node_text(inner, source).to_string());
            }
        }
        // For pointer_declarator -> function_declarator pattern
        if name_node.kind() == "pointer_declarator" {
            let mut cursor = name_node.walk();
            for child in name_node.children(&mut cursor) {
                if child.kind() == "function_declarator" {
                    if let Some(inner) = child.child_by_field_name("declarator") {
                        return Some(node_text(inner, source).to_string());
                    }
                }
            }
        }
        return Some(node_text(name_node, source).to_string());
    }
    None
}

#[cfg(test)]
fn find_function_node<'a>(
    tree: &'a tree_sitter::Tree,
    function_name: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    let root = tree.root_node();
    // Use Python patterns as default for backward compatibility
    let patterns = get_resource_patterns(Language::Python);
    find_function_recursive(root, function_name, source, &patterns)
}

fn find_function_node_multilang<'a>(
    tree: &'a tree_sitter::Tree,
    function_name: &str,
    source: &[u8],
    lang: Language,
) -> Option<Node<'a>> {
    let root = tree.root_node();
    let patterns = get_resource_patterns(lang);
    find_function_recursive(root, function_name, source, &patterns)
}

fn find_function_recursive<'a>(
    node: Node<'a>,
    function_name: &str,
    source: &[u8],
    patterns: &LangResourcePatterns,
) -> Option<Node<'a>> {
    let kind = node.kind();
    if patterns.function_kinds.contains(&kind) {
        if let Some(name) = get_function_name_from_node(node, source, patterns) {
            if name == function_name {
                return Some(node);
            }
        }
    }

    // Check for arrow functions in variable declarations (TS/JS pattern):
    // lexical_declaration / variable_declaration -> variable_declarator -> name + value(arrow_function)
    if matches!(kind, "lexical_declaration" | "variable_declaration") {
        let mut decl_cursor = node.walk();
        for child in node.children(&mut decl_cursor) {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let var_name = name_node.utf8_text(source).unwrap_or("");
                    if var_name == function_name {
                        if let Some(value_node) = child.child_by_field_name("value") {
                            if matches!(
                                value_node.kind(),
                                "arrow_function"
                                    | "function"
                                    | "function_expression"
                                    | "generator_function"
                            ) {
                                return Some(value_node);
                            }
                        }
                    }
                }
            }
        }
    }

    // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS function-expression
    // assignments — CommonJS / prototype patterns.
    //   app.use = function() {}
    //   Foo.prototype.bar = function() {}
    //   handler = () => {}
    // Mirrors the same case explain.rs handles in P12.AGG12-7. The callee
    // function body lives on the right-hand side of an assignment_expression
    // whose left-hand side is either an identifier or a member_expression.
    if kind == "assignment_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let target_name = match left.kind() {
                "identifier" => Some(left.utf8_text(source).unwrap_or("").to_string()),
                "member_expression" => left
                    .child_by_field_name("property")
                    .map(|p| p.utf8_text(source).unwrap_or("").to_string()),
                _ => None,
            };
            if let Some(name) = target_name {
                if name == function_name
                    && matches!(
                        right.kind(),
                        "arrow_function"
                            | "function"
                            | "function_expression"
                            | "generator_function"
                    )
                {
                    return Some(right);
                }
            }
        }
    }

    // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS object literal pair —
    //   { foo: function() {} } / { foo: () => {} }
    // The function body is the value of a `pair` whose key is an identifier
    // matching function_name.
    if kind == "pair" {
        if let (Some(key), Some(value)) = (
            node.child_by_field_name("key"),
            node.child_by_field_name("value"),
        ) {
            let key_name = match key.kind() {
                "property_identifier" | "identifier" => {
                    key.utf8_text(source).unwrap_or("").to_string()
                }
                "string" => key
                    .utf8_text(source)
                    .unwrap_or("")
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                    .to_string(),
                _ => String::new(),
            };
            if key_name == function_name
                && matches!(
                    value.kind(),
                    "arrow_function"
                        | "function"
                        | "function_expression"
                        | "generator_function"
                )
            {
                return Some(value);
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_function_recursive(child, function_name, source, patterns) {
            return Some(found);
        }
    }

    None
}

fn find_all_functions_multilang<'a>(
    tree: &'a tree_sitter::Tree,
    source: &[u8],
    lang: Language,
) -> Vec<(String, Node<'a>)> {
    let mut functions = Vec::new();
    let patterns = get_resource_patterns(lang);
    collect_functions(tree.root_node(), source, &mut functions, &patterns);
    functions
}

fn collect_functions<'a>(
    node: Node<'a>,
    source: &[u8],
    functions: &mut Vec<(String, Node<'a>)>,
    patterns: &LangResourcePatterns,
) {
    let kind = node.kind();
    if patterns.function_kinds.contains(&kind) {
        if let Some(name) = get_function_name_from_node(node, source, patterns) {
            functions.push((name, node));
        }
    }

    // Check for arrow functions in variable declarations (TS/JS pattern):
    // lexical_declaration / variable_declaration -> variable_declarator -> name + value(arrow_function)
    if matches!(kind, "lexical_declaration" | "variable_declaration") {
        let mut decl_cursor = node.walk();
        for child in node.children(&mut decl_cursor) {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Some(value_node) = child.child_by_field_name("value") {
                        if matches!(
                            value_node.kind(),
                            "arrow_function"
                                | "function"
                                | "function_expression"
                                | "generator_function"
                        ) {
                            let var_name = name_node.utf8_text(source).unwrap_or("").to_string();
                            functions.push((var_name, value_node));
                        }
                    }
                }
            }
        }
    }

    // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS function-expression
    // assignments — `app.foo = function(){}` and bare `handler = () => {}`.
    if kind == "assignment_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if matches!(
                right.kind(),
                "arrow_function" | "function" | "function_expression" | "generator_function"
            ) {
                let target_name = match left.kind() {
                    "identifier" => Some(left.utf8_text(source).unwrap_or("").to_string()),
                    "member_expression" => left
                        .child_by_field_name("property")
                        .map(|p| p.utf8_text(source).unwrap_or("").to_string()),
                    _ => None,
                };
                if let Some(name) = target_name {
                    if !name.is_empty() {
                        functions.push((name, right));
                    }
                }
            }
        }
    }

    // language-adapter-fixes-v1 (P13.AGG13-3): JS/TS object literal pair —
    //   { foo: function() {} } / { foo: () => {} }
    if kind == "pair" {
        if let (Some(key), Some(value)) = (
            node.child_by_field_name("key"),
            node.child_by_field_name("value"),
        ) {
            if matches!(
                value.kind(),
                "arrow_function" | "function" | "function_expression" | "generator_function"
            ) {
                let key_name = match key.kind() {
                    "property_identifier" | "identifier" => {
                        key.utf8_text(source).unwrap_or("").to_string()
                    }
                    "string" => key
                        .utf8_text(source)
                        .unwrap_or("")
                        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                        .to_string(),
                    _ => String::new(),
                };
                if !key_name.is_empty() {
                    functions.push((key_name, value));
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, functions, patterns);
    }
}

// =============================================================================
// Main Analysis Function
// =============================================================================

fn analyze_function_with_lang(
    func_node: Node,
    source: &[u8],
    args: &ResourcesArgs,
    lang: Language,
) -> (
    Vec<ResourceInfo>,
    Vec<LeakInfo>,
    Vec<DoubleCloseInfo>,
    Vec<UseAfterCloseInfo>,
) {
    let check_leaks = args.check_leaks || args.check_all;
    let check_double_close = args.check_double_close || args.check_all;
    let check_use_after_close = args.check_use_after_close || args.check_all;
    // Detect resources
    let mut detector = ResourceDetector::with_language(lang);
    let resources = detector.detect_with_patterns(func_node, source);

    // Detect leaks
    let leaks = if check_leaks {
        let cfg = build_cfg_multilang(func_node, source, lang);
        let mut leak_detector = LeakDetector::with_language(lang);
        leak_detector.detect_multilang(&cfg, &resources, source, func_node, args.show_paths)
    } else {
        Vec::new()
    };

    // Detect double-close
    let double_closes = if check_double_close {
        let detector = DoubleCloseDetector::with_language(lang);
        detector.detect_multilang(func_node, source)
    } else {
        Vec::new()
    };

    // Detect use-after-close
    let use_after_closes = if check_use_after_close {
        let detector = UseAfterCloseDetector::with_language(lang);
        detector.detect_multilang(func_node, source)
    } else {
        Vec::new()
    };

    (resources, leaks, double_closes, use_after_closes)
}

// =============================================================================
// Entry Point
// =============================================================================

/// Run the resources analysis command.
pub fn run(args: ResourcesArgs, global_format: GlobalOutputFormat) -> anyhow::Result<()> {
    let start_time = Instant::now();

    // Validate path.
    //
    // BUG-8 (cross-command-consistency-v1): keep the user-supplied path for
    // the emitted `file` field.  `validate_file_path[_in_project]` still runs
    // for existence/traversal checks but its canonicalised return is used
    // only for IO; the output report uses `args.file` so it matches what the
    // caller typed (no `/private/tmp/...` rewrite on macOS).
    let path = if let Some(ref root) = args.project_root {
        validate_file_path_in_project(&args.file, root)?
    } else {
        validate_file_path(&args.file)?
    };

    // Read file
    let source = read_file_safe(&path)?;
    let source_bytes = source.as_bytes();

    // Detect language (multi-language support)
    let lang: Language = match args.lang {
        Some(l) => l,
        None => Language::from_path(&path).ok_or_else(|| {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_string();
            PatternsError::UnsupportedLanguage { language: ext }
        })?,
    };

    // Parse file with language-appropriate parser
    let mut parser = get_parser_for_language(lang)?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| PatternsError::ParseError {
            file: path.clone(),
            message: format!("Failed to parse {} file", lang.as_str()),
        })?;

    // Collect results
    let mut all_resources = Vec::new();
    let mut all_leaks = Vec::new();
    let mut all_double_closes = Vec::new();
    let mut all_use_after_closes = Vec::new();

    if let Some(ref func_name) = args.function {
        // Analyze specific function.
        //
        // rust-per-fn-qualified-name-v1 (v0.4.2 cluster M-013): the
        // resources command uses its own ad-hoc `find_function_node_multilang`
        // resolver (it predates `tldr_core::ast::function_finder::find_function_node`)
        // and that local resolver does NOT understand Rust `Type::method`
        // qualified names. The call-graph commands already accept this
        // shape; rather than duplicate the class-scope resolver here we
        // fall back to the bare last segment when the qualified form
        // fails — sharing the same canonical normaliser exposed by
        // `qualified_name_fallback_bare`.
        let func_node = find_function_node_multilang(&tree, func_name, source_bytes, lang)
            .or_else(|| {
                tldr_core::ast::function_finder::qualified_name_fallback_bare(func_name, lang)
                    .and_then(|bare| {
                        find_function_node_multilang(&tree, &bare, source_bytes, lang)
                    })
            });
        if let Some(func_node) = func_node {
            let (resources, leaks, double_closes, use_after_closes) =
                analyze_function_with_lang(func_node, source_bytes, &args, lang);
            all_resources = resources;
            all_leaks = leaks;
            all_double_closes = double_closes;
            all_use_after_closes = use_after_closes;
        } else {
            return Err(PatternsError::FunctionNotFound {
                function: func_name.clone(),
                file: path.clone(),
            }
            .into());
        }
    } else {
        // Analyze all functions
        let functions = find_all_functions_multilang(&tree, source_bytes, lang);
        for (_name, func_node) in functions {
            let (resources, leaks, double_closes, use_after_closes) =
                analyze_function_with_lang(func_node, source_bytes, &args, lang);
            all_resources.extend(resources);
            all_leaks.extend(leaks);
            all_double_closes.extend(double_closes);
            all_use_after_closes.extend(use_after_closes);
        }
    }

    // Generate suggestions
    let suggestions = if args.suggest_context {
        suggest_context_manager_multilang(&all_resources, lang)
    } else {
        Vec::new()
    };

    // Generate constraints
    let constraints = if args.constraints {
        generate_constraints(
            path.to_str().unwrap_or(""),
            args.function.as_deref(),
            &all_resources,
            &all_leaks,
            &all_double_closes,
            &all_use_after_closes,
        )
    } else {
        Vec::new()
    };

    // Build summary
    let summary = ResourceSummary {
        resources_detected: all_resources.len() as u32,
        leaks_found: all_leaks.len() as u32,
        double_closes_found: all_double_closes.len() as u32,
        use_after_closes_found: all_use_after_closes.len() as u32,
    };

    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    // Build report.
    //
    // BUG-8 (cross-command-consistency-v1): emit the user-supplied path
    // (`args.file`) instead of the canonicalised `path`, so the `file`
    // field in the JSON matches what the caller typed.
    let report = ResourceReport {
        file: args.file.to_string_lossy().to_string(),
        language: lang.as_str().to_string(),
        function: args.function.clone(),
        resources: all_resources,
        leaks: all_leaks,
        double_closes: all_double_closes,
        use_after_closes: all_use_after_closes,
        suggestions,
        constraints,
        summary,
        analysis_time_ms: elapsed_ms,
    };

    // Output: global -f flag takes priority over hidden --output-format
    let use_text = matches!(global_format, GlobalOutputFormat::Text)
        || matches!(args.output_format, OutputFormat::Text);

    // elixir-per-clause-dfg-cfg-v1 (v0.4.2 M-031): emit per-clause
    // resources analysis for Elixir multi-clause defs when a function
    // is targeted. Each clause runs on a synthetic single-clause
    // sub-source. The legacy top-level report stays populated (it
    // mirrors the first body-bearing clause via the M-E1 selector).
    let per_clause_array: Option<Vec<serde_json::Value>> = if use_text {
        None
    } else if let Some(ref func_name) = args.function {
        let function_name_outer = func_name.clone();
        let function_name = func_name.clone();
        let parent_args = args.clone();
        crate::commands::elixir_per_clause::for_each_body_bearing_clause(
            &args.file,
            &function_name_outer,
            lang,
            move |tmp_path, clause, _offset| -> anyhow::Result<serde_json::Value> {
                let sub_source = read_file_safe(tmp_path)?;
                let sub_bytes = sub_source.as_bytes();
                let mut sub_parser = get_parser_for_language(lang)?;
                let sub_tree =
                    sub_parser
                        .parse(&sub_source, None)
                        .ok_or_else(|| PatternsError::ParseError {
                            file: tmp_path.clone(),
                            message: format!("Failed to parse synthetic {} clause", lang.as_str()),
                        })?;
                let sub_func_node =
                    find_function_node_multilang(&sub_tree, &function_name, sub_bytes, lang)
                        .or_else(|| {
                            tldr_core::ast::function_finder::qualified_name_fallback_bare(
                                &function_name,
                                lang,
                            )
                            .and_then(|bare| {
                                find_function_node_multilang(&sub_tree, &bare, sub_bytes, lang)
                            })
                        });
                let (sub_resources, sub_leaks, sub_double_closes, sub_use_after_closes) =
                    if let Some(node) = sub_func_node {
                        analyze_function_with_lang(node, sub_bytes, &parent_args, lang)
                    } else {
                        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
                    };
                let sub_summary = ResourceSummary {
                    resources_detected: sub_resources.len() as u32,
                    leaks_found: sub_leaks.len() as u32,
                    double_closes_found: sub_double_closes.len() as u32,
                    use_after_closes_found: sub_use_after_closes.len() as u32,
                };
                let sub_report = ResourceReport {
                    file: parent_args.file.to_string_lossy().to_string(),
                    language: lang.as_str().to_string(),
                    function: Some(function_name.clone()),
                    resources: sub_resources,
                    leaks: sub_leaks,
                    double_closes: sub_double_closes,
                    use_after_closes: sub_use_after_closes,
                    suggestions: Vec::new(),
                    constraints: Vec::new(),
                    summary: sub_summary,
                    analysis_time_ms: 0,
                };
                let v = serde_json::to_value(&sub_report)?;
                Ok(crate::commands::elixir_per_clause::per_clause_entry_value(clause, v))
            },
        )?
    } else {
        None
    };

    let output = if use_text {
        format_resources_text(&report)
    } else {
        let value = serde_json::to_value(&report)?;
        let merged =
            crate::commands::elixir_per_clause::merge_per_clauses(value, per_clause_array);
        serde_json::to_string_pretty(&merged)?
    };

    println!("{}", output);

    // Exit code 3 if issues found
    let has_issues = report.summary.leaks_found > 0
        || report.summary.double_closes_found > 0
        || report.summary.use_after_closes_found > 0;

    if has_issues {
        std::process::exit(3);
    }

    Ok(())
}

// =============================================================================
// L2 Integration API
// =============================================================================

/// Aggregated resource analysis results for L2 consumption.
///
/// Each finding is paired with the function name where it was detected.
/// This avoids requiring callers to handle tree-sitter nodes directly.
pub struct ResourceAnalysisResults {
    /// Detected leaks: `(function_name, LeakInfo)`.
    pub leaks: Vec<(String, LeakInfo)>,
    /// Detected double-close issues: `(function_name, DoubleCloseInfo)`.
    pub double_closes: Vec<(String, DoubleCloseInfo)>,
    /// Detected use-after-close issues: `(function_name, UseAfterCloseInfo)`.
    pub use_after_closes: Vec<(String, UseAfterCloseInfo)>,
}

/// Analyze source code for resource lifecycle issues.
///
/// Parses the source with tree-sitter for the given language, finds all function
/// nodes, and runs the full resource analysis (leak, double-close, use-after-close)
/// on each function.
///
/// This is the primary entry point for L2 finding extractors that need resource
/// analysis without constructing `ResourcesArgs` or tree-sitter nodes themselves.
///
/// # Arguments
/// * `source` - Source code to analyze
/// * `lang` - Programming language for parsing
///
/// # Returns
/// `ResourceAnalysisResults` with all detected issues, or an error if parsing fails.
pub fn analyze_source_for_resource_issues(
    source: &str,
    lang: Language,
) -> PatternsResult<ResourceAnalysisResults> {
    let source_bytes = source.as_bytes();

    // Parse source with tree-sitter
    let mut parser = get_parser_for_language(lang)?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| PatternsError::ParseError {
            file: PathBuf::from("<in-memory>"),
            message: format!(
                "Failed to parse {} source for resource analysis",
                lang.as_str()
            ),
        })?;

    // Build args with all checks enabled
    let args = ResourcesArgs {
        file: PathBuf::from("<in-memory>"),
        function: None,
        lang: Some(lang),
        check_leaks: true,
        check_double_close: true,
        check_use_after_close: true,
        check_all: true,
        suggest_context: false,
        show_paths: false,
        constraints: false,
        summary: false,
        output_format: OutputFormat::Json,
        project_root: None,
    };

    let mut all_leaks = Vec::new();
    let mut all_double_closes = Vec::new();
    let mut all_use_after_closes = Vec::new();

    // Find all functions and analyze each
    let functions = find_all_functions_multilang(&tree, source_bytes, lang);
    for (func_name, func_node) in functions {
        let (_resources, leaks, double_closes, use_after_closes) =
            analyze_function_with_lang(func_node, source_bytes, &args, lang);

        for leak in leaks {
            all_leaks.push((func_name.clone(), leak));
        }
        for dc in double_closes {
            all_double_closes.push((func_name.clone(), dc));
        }
        for uac in use_after_closes {
            all_use_after_closes.push((func_name.clone(), uac));
        }
    }

    Ok(ResourceAnalysisResults {
        leaks: all_leaks,
        double_closes: all_double_closes,
        use_after_closes: all_use_after_closes,
    })
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LEAKY_FUNCTION: &str = r#"
def leaky_function(path):
    f = open(path)
    if some_condition():
        return None
    content = f.read()
    f.close()
    return content
"#;

    const TEST_SAFE_WITH_CONTEXT: &str = r#"
def safe_with_context(path):
    with open(path) as f:
        return f.read()
"#;

    const TEST_DOUBLE_CLOSE: &str = r#"
def double_close(path):
    f = open(path)
    content = f.read()
    f.close()
    f.close()
    return content
"#;

    const TEST_USE_AFTER_CLOSE: &str = r#"
def use_after_close(path):
    f = open(path)
    f.close()
    content = f.read()
    return content
"#;

    #[test]
    fn test_resource_creators_constant() {
        assert!(RESOURCE_CREATORS.contains(&"open"));
        assert!(RESOURCE_CREATORS.contains(&"socket"));
        assert!(RESOURCE_CREATORS.contains(&"connect"));
        assert!(RESOURCE_CREATORS.contains(&"cursor"));
    }

    #[test]
    fn test_resource_closers_constant() {
        assert!(RESOURCE_CLOSERS.contains(&"close"));
        assert!(RESOURCE_CLOSERS.contains(&"shutdown"));
        assert!(RESOURCE_CLOSERS.contains(&"disconnect"));
    }

    #[test]
    fn test_max_paths_constant() {
        assert_eq!(MAX_PATHS, 1000);
    }

    #[test]
    fn test_resource_detector_finds_open() {
        let mut parser = get_python_parser().unwrap();
        let tree = parser.parse(TEST_LEAKY_FUNCTION, None).unwrap();
        let source = TEST_LEAKY_FUNCTION.as_bytes();

        let func_node = find_function_node(&tree, "leaky_function", source).unwrap();
        let mut detector = ResourceDetector::new();
        let resources = detector.detect(func_node, source);

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "f");
        assert_eq!(resources[0].resource_type, "file");
        assert!(!resources[0].closed);
    }

    #[test]
    fn test_resource_detector_context_manager() {
        let mut parser = get_python_parser().unwrap();
        let tree = parser.parse(TEST_SAFE_WITH_CONTEXT, None).unwrap();
        let source = TEST_SAFE_WITH_CONTEXT.as_bytes();

        let func_node = find_function_node(&tree, "safe_with_context", source).unwrap();
        let mut detector = ResourceDetector::new();
        let resources = detector.detect(func_node, source);

        assert_eq!(resources.len(), 1);
        assert!(
            resources[0].closed,
            "Context manager resource should be marked as closed"
        );
    }

    #[test]
    fn test_double_close_detector() {
        let mut parser = get_python_parser().unwrap();
        let tree = parser.parse(TEST_DOUBLE_CLOSE, None).unwrap();
        let source = TEST_DOUBLE_CLOSE.as_bytes();

        let func_node = find_function_node(&tree, "double_close", source).unwrap();
        let detector = DoubleCloseDetector::new();
        let issues = detector.detect(func_node, source);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].resource, "f");
    }

    #[test]
    fn test_use_after_close_detector() {
        let mut parser = get_python_parser().unwrap();
        let tree = parser.parse(TEST_USE_AFTER_CLOSE, None).unwrap();
        let source = TEST_USE_AFTER_CLOSE.as_bytes();

        let func_node = find_function_node(&tree, "use_after_close", source).unwrap();
        let detector = UseAfterCloseDetector::new();
        let issues = detector.detect(func_node, source);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].resource, "f");
    }

    #[test]
    fn test_suggest_context_manager() {
        let resources = vec![ResourceInfo {
            name: "f".to_string(),
            resource_type: "file".to_string(),
            line: 2,
            closed: false,
        }];

        let suggestions = suggest_context_manager(&resources);
        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].suggestion.contains("with open"));
    }

    #[test]
    fn test_generate_constraints_for_leak() {
        let resources = vec![ResourceInfo {
            name: "f".to_string(),
            resource_type: "file".to_string(),
            line: 2,
            closed: false,
        }];
        let leaks = vec![LeakInfo {
            resource: "f".to_string(),
            line: 2,
            paths: None,
        }];

        let constraints =
            generate_constraints("test.py", Some("test_func"), &resources, &leaks, &[], &[]);

        assert!(!constraints.is_empty());
        assert!(constraints[0].rule.contains("must be closed"));
    }

    #[test]
    fn test_leak_detector_path_limit() {
        let detector = LeakDetector::new();
        assert_eq!(detector.max_paths, MAX_PATHS);
    }

    #[test]
    fn test_cfg_builder_basic() {
        let mut parser = get_python_parser().unwrap();
        let source = r#"
def simple():
    x = 1
    return x
"#;
        let tree = parser.parse(source, None).unwrap();
        let func_node = find_function_node(&tree, "simple", source.as_bytes()).unwrap();
        let cfg = build_cfg(func_node, source.as_bytes());

        assert!(!cfg.blocks.is_empty());
        assert!(!cfg.exit_blocks.is_empty());
    }

    #[test]
    fn test_cfg_builder_with_if() {
        let mut parser = get_python_parser().unwrap();
        let source = r#"
def with_if(x):
    if x > 0:
        return x
    return -x
"#;
        let tree = parser.parse(source, None).unwrap();
        let func_node = find_function_node(&tree, "with_if", source.as_bytes()).unwrap();
        let cfg = build_cfg(func_node, source.as_bytes());

        // Should have multiple blocks for the branching
        assert!(cfg.blocks.len() > 1);
    }

    #[test]
    fn test_format_resources_text() {
        let report = ResourceReport {
            file: "test.py".to_string(),
            language: "python".to_string(),
            function: Some("test".to_string()),
            resources: vec![ResourceInfo {
                name: "f".to_string(),
                resource_type: "file".to_string(),
                line: 2,
                closed: false,
            }],
            leaks: vec![],
            double_closes: vec![],
            use_after_closes: vec![],
            suggestions: vec![],
            constraints: vec![],
            summary: ResourceSummary::default(),
            analysis_time_ms: 10,
        };

        let text = format_resources_text(&report);
        assert!(text.contains("Resource Analysis: test.py"));
        assert!(text.contains("Function: test"));
        assert!(text.contains("file"));
    }

    #[test]
    fn test_find_ts_arrow_function_resources() {
        let ts_source = r#"
const getDuration = (start: Date, end: Date): number => {
    const conn = createConnection();
    const result = end.getTime() - start.getTime();
    conn.close();
    return result;
};

function regularFunc(x: number): number {
    return x * 2;
}
"#;
        let tree = tldr_core::ast::parser::parse(ts_source, Language::TypeScript).unwrap();
        let source_bytes = ts_source.as_bytes();

        // Regular function should be found
        let regular =
            find_function_node_multilang(&tree, "regularFunc", source_bytes, Language::TypeScript);
        assert!(regular.is_some(), "Should find regular TS function");

        // Arrow function assigned to const should also be found
        let arrow =
            find_function_node_multilang(&tree, "getDuration", source_bytes, Language::TypeScript);
        assert!(
            arrow.is_some(),
            "Should find TS arrow function 'getDuration'"
        );
    }

    #[test]
    fn test_resources_args_lang_flag() {
        // Verify ResourcesArgs has a lang field of type Option<Language> (not language: String)
        let args = ResourcesArgs {
            file: PathBuf::from("src/db.go"),
            function: None,
            lang: Some(Language::Go),
            check_leaks: true,
            check_double_close: false,
            check_use_after_close: false,
            check_all: false,
            suggest_context: false,
            show_paths: false,
            constraints: false,
            summary: false,
            output_format: OutputFormat::Json,
            project_root: None,
        };
        assert_eq!(args.lang, Some(Language::Go));

        // Also test None case (auto-detect)
        let args_auto = ResourcesArgs {
            file: PathBuf::from("src/db.py"),
            function: None,
            lang: None,
            check_leaks: true,
            check_double_close: false,
            check_use_after_close: false,
            check_all: false,
            suggest_context: false,
            show_paths: false,
            constraints: false,
            summary: false,
            output_format: OutputFormat::Json,
            project_root: None,
        };
        assert_eq!(args_auto.lang, None);
    }

    // =========================================================================
    // CHARACTERIZATION TESTS (T2a-resource-acquisition)
    //
    // These pin the CURRENT, CORRECT resource-acquisition behavior of the
    // already-working languages (Python / Go / TS / JS / C++). They form the
    // regression net for the acquisition-core rewrite (extract_call_name
    // G1-O2, qualified-creator matcher G2-O1, chain descent G1-O1). They must
    // stay GREEN before and after the rewrite.
    // =========================================================================

    /// Helper: detect (name, resource_type) pairs for a function via the real
    /// multilang detection path (parse → find function → detect_with_patterns).
    fn char_detect(src: &str, func: &str, lang: Language) -> Vec<(String, String)> {
        let tree = tldr_core::ast::parser::parse(src, lang).unwrap();
        let bytes = src.as_bytes();
        let fnode = find_function_node_multilang(&tree, func, bytes, lang)
            .unwrap_or_else(|| panic!("function `{func}` not found for {lang:?}"));
        let mut d = ResourceDetector::with_language(lang);
        d.detect_with_patterns(fnode, bytes)
            .into_iter()
            .map(|r| (r.name, r.resource_type))
            .collect()
    }

    #[test]
    fn char_python_open_file() {
        let src = r#"
def read(path):
    f = open(path)
    return f.read()
"#;
        let got = char_detect(src, "read", Language::Python);
        assert_eq!(got, vec![("f".to_string(), "file".to_string())]);
    }

    // =====================================================================
    // fix-C5-2 (v0.5.0 AUDIT-FIX): Lua resource acquisition via io.open /
    // io.lines. Mirrors the design-tail rust/ruby/ocaml/elixir work above.
    // Reproduces lua-lsp `analyze.lua` (io.open at lines 527/679/701).
    // =====================================================================

    /// RED→GREEN: `local f = io.open(p)` must be detected as a `file`
    /// resource named `f`. tree-sitter-lua models this as
    /// `variable_declaration` → `assignment_statement` →
    /// `variable_list`/`expression_list` (no `values`/`variables` fields), so
    /// the old field-name lookup found nothing.
    #[test]
    fn char_lua_io_open_local_detected() {
        let src = "function read(p)\n  local f = io.open(p)\n  return f:read(\"*a\")\nend\n";
        let got = char_detect(src, "read", Language::Lua);
        assert!(
            got.iter().any(|(n, t)| n == "f" && t == "file"),
            "Lua `local f = io.open(p)` must be detected as file `f`: got {got:?}"
        );
    }

    /// RED→GREEN: `local f = assert(io.open(uri, "r"))` — io.open wrapped in
    /// `assert(...)`. The acquisition call is nested inside the assert call,
    /// so detection must descend through the wrapper. Mirrors
    /// lua-lsp analyze.lua:679 `local f = assert(io.open(...))`.
    #[test]
    fn char_lua_io_open_wrapped_in_assert_detected() {
        let src = "function read(uri)\n  local f = assert(io.open(uri, \"r\"))\n  return f:read(\"*a\")\nend\n";
        let got = char_detect(src, "read", Language::Lua);
        assert!(
            got.iter().any(|(n, t)| n == "f" && t == "file"),
            "Lua `local f = assert(io.open(...))` must be detected as file `f`: got {got:?}"
        );
    }

    /// RED→GREEN: a bare (non-`local`) assignment `f = io.open(p)` produces a
    /// top-level `assignment_statement` and must also be detected.
    #[test]
    fn char_lua_io_open_bare_assignment_detected() {
        let src = "function read(p)\n  f = io.open(p, \"w\")\n  return f\nend\n";
        let got = char_detect(src, "read", Language::Lua);
        assert!(
            got.iter().any(|(n, t)| n == "f" && t == "file"),
            "Lua bare `f = io.open(p)` must be detected as file `f`: got {got:?}"
        );
    }

    /// RED→GREEN: `io.lines` is also a file-resource acquisition.
    #[test]
    fn char_lua_io_lines_detected() {
        let src = "function read(p)\n  local it = io.lines(p)\n  return it\nend\n";
        let got = char_detect(src, "read", Language::Lua);
        assert!(
            got.iter().any(|(n, t)| n == "it" && t == "file"),
            "Lua `local it = io.lines(p)` must be detected as file `it`: got {got:?}"
        );
    }

    /// Guard: the single `local f = io.open(p)` must be detected EXACTLY once
    /// (the dispatch fires on both `variable_declaration` and the nested
    /// `assignment_statement`; we must not double-count).
    #[test]
    fn char_lua_io_open_no_double_count() {
        let src = "function read(p)\n  local f = io.open(p)\n  return f\nend\n";
        let got = char_detect(src, "read", Language::Lua);
        let f_count = got.iter().filter(|(n, t)| n == "f" && t == "file").count();
        assert_eq!(
            f_count, 1,
            "Lua `local f = io.open(p)` must be detected exactly once: got {got:?}"
        );
    }

    #[test]
    fn char_go_os_open_file() {
        let src = r#"
func read() {
    f, err := os.Open("x")
    defer f.Close()
}
"#;
        let got = char_detect(src, "read", Language::Go);
        assert_eq!(got, vec![("f".to_string(), "file".to_string())]);
    }

    #[test]
    fn char_go_net_dial_connection() {
        let src = r#"
func dial() {
    conn, err := net.Dial("tcp", "x")
    defer conn.Close()
}
"#;
        let got = char_detect(src, "dial", Language::Go);
        assert_eq!(got, vec![("conn".to_string(), "connection".to_string())]);
    }

    #[test]
    fn char_ts_high_precision_name_flagged() {
        // High-precision LHS name `server` from createServer is flagged
        // regardless of cleanup (AGG17-7 gate only narrows ambiguous names).
        let src = r#"
function start() {
    const server = http.createServer();
}
"#;
        let got = char_detect(src, "start", Language::TypeScript);
        assert!(
            got.iter().any(|(n, _)| n == "server"),
            "server must be flagged: got {got:?}"
        );
    }

    #[test]
    fn char_ts_ambiguous_name_without_cleanup_skipped() {
        // AGG17-7: ambiguous name `data` from `.get(...)` with no cleanup
        // call is skipped.
        let src = r#"
function readConfig(config) {
    const data = config.get("api_key");
    return data;
}
"#;
        let got = char_detect(src, "readConfig", Language::TypeScript);
        assert!(
            !got.iter().any(|(n, _)| n == "data"),
            "ambiguous `data` w/o cleanup must NOT be flagged: got {got:?}"
        );
    }

    #[test]
    fn char_ts_ambiguous_name_with_cleanup_flagged() {
        // AGG17-7: ambiguous `request` WITH a `request.abort()` cleanup call
        // is still flagged.
        let src = r#"
function makeRequest() {
    const request = http.request({});
    request.abort();
}
"#;
        let got = char_detect(src, "makeRequest", Language::TypeScript);
        assert!(
            got.iter().any(|(n, _)| n == "request"),
            "ambiguous `request` WITH cleanup must be flagged: got {got:?}"
        );
    }

    #[test]
    fn char_cpp_fopen_file() {
        let src = r#"
void read() {
    FILE *fp = fopen("x", "r");
}
"#;
        let got = char_detect(src, "read", Language::Cpp);
        assert_eq!(got, vec![("fp".to_string(), "file".to_string())]);
    }

    /// fix-R7 (cluster[11] RC2): `fopen_s` must NOT match the `fopen` creator.
    /// The C/C++ creator match used `node_text(node).starts_with(creator)`, so
    /// `fopen_s( &fp, ... )` (whose result `err` is an `errno_t` int, not a
    /// FILE*) was misdetected as a `file` resource named `err`. Matching must be
    /// exact callee-name equality via the AST `function` child.
    /// Reproduces cpp-tinyxml2 `err`@2322.
    #[test]
    fn char_cpp_fopen_s_does_not_misdetect_errno_var() {
        let src = r#"
void open(const char* path, const char* mode) {
    FILE* fp = 0;
    errno_t err = fopen_s(&fp, path, mode);
}
"#;
        let got = char_detect(src, "open", Language::Cpp);
        assert!(
            !got.iter().any(|(n, _)| n == "err"),
            "errno_t `err` from fopen_s must NOT be flagged as a file resource: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC2): regression guard — the genuine `fopen` creator
    /// still matches exactly after switching from prefix to exact equality.
    #[test]
    fn char_c_fopen_exact_still_detected() {
        let src = "void read(const char* p) {\n    FILE* fp = fopen(p, \"r\");\n}\n";
        let got = char_detect(src, "read", Language::C);
        assert!(
            got.iter().any(|(n, t)| n == "fp" && t == "file"),
            "exact `fopen` must still be detected as file `fp`: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): a C file that IS closed on every path must NOT
    /// be reported as a leak. `LeakDetector::path_has_close` was a hardcoded
    /// `false`, so EVERY non-context-managed C/C++ resource was flagged leaked
    /// regardless of an explicit `fclose`. Reproduces c-redis util.c `fp`@963
    /// (closed at `if (fp) fclose(fp);`).
    #[test]
    fn char_c_fclose_on_all_paths_is_not_leak() {
        let src = "\
void seed() {
    FILE *fp = fopen(\"/dev/urandom\", \"r\");
    if (fp) fclose(fp);
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            !got.contains(&"fp".to_string()),
            "C `fp` closed via `fclose(fp)` must NOT leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): a C file that is opened but NEVER closed on
    /// some path MUST still be reported as a leak (the real-leak direction —
    /// the fix must not blanket-suppress leaks).
    #[test]
    fn char_c_no_close_still_leaks() {
        let src = "\
void read(const char* p) {
    FILE *fp = fopen(p, \"r\");
    return;
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            got.contains(&"fp".to_string()),
            "C `fp` never closed must still leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): a C/C++ function that RETURNS the handle
    /// transfers ownership to the caller and must NOT be reported as a leak.
    /// Reproduces cpp-tinyxml2 `fp`@2327 (`return fp;`@2329).
    #[test]
    fn char_cpp_returned_handle_is_not_leak() {
        let src = "\
FILE* openfile(const char* path, const char* mode) {
    FILE* fp = fopen(path, mode);
    return fp;
}
";
        let got = char_leak_names(src, Language::Cpp);
        assert!(
            !got.contains(&"fp".to_string()),
            "C++ returned handle `fp` (ownership transfer) must NOT leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): regression guard — Python non-managed open
    /// must STILL leak (the shared `detect` path must keep working for the
    /// in-context-manager=false case in languages that already worked).
    #[test]
    fn char_python_open_still_leaks_after_rc1() {
        let src = "def read(path):\n    f = open(path)\n    return f.read()\n";
        let got = char_leak_names(src, Language::Python);
        assert!(
            got.contains(&"f".to_string()),
            "Python non-managed open must still leak `f`: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): a C resource acquired INSIDE an error-guard
    /// `if` whose failure branch early-returns must NOT leak — on that branch
    /// the resource is NULL (acquisition failed). Reproduces c-redis util.c
    /// `dir`@1132 (`if ((dir = opendir(dname)) == NULL) return -1;` then
    /// `closedir(dir)` on every other path).
    #[test]
    fn char_c_acquire_in_if_cond_failure_return_not_leak() {
        let src = "\
int dirRemove(char *dname) {
    void *dir;
    if ((dir = opendir(dname)) == NULL) {
        return -1;
    }
    while (readdir(dir) != NULL) {
        if (something()) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            !got.contains(&"dir".to_string()),
            "`dir` acquired in if-cond + closed on all real paths must NOT leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): the `fd = open(); if (fd == -1) return;` error
    /// sentinel form (open returns -1 on failure) must also be recognized as an
    /// acquisition-failure guard. Reproduces c-redis util.c `fd`@1141 /
    /// `dir_fd`@1207. The fd is then closed via `close(fd)` on real paths.
    #[test]
    fn char_c_fd_error_sentinel_guard_not_leak() {
        let src = "\
int sync_dir(char *name) {
    int fd = open(name, 0);
    if (fd == -1) {
        return -1;
    }
    if (fsync(fd) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            !got.contains(&"fd".to_string()),
            "`fd` with `== -1` failure guard + close on real paths must NOT leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): the acquisition-failure suppression must be
    /// SCOPED — a resource acquired with an error guard but then NEVER closed on
    /// a SUCCESS path must STILL leak (do not blanket-suppress).
    #[test]
    fn char_c_acquire_guard_but_no_close_on_success_still_leaks() {
        let src = "\
int bad(char *name) {
    int fd = open(name, 0);
    if (fd == -1) {
        return -1;
    }
    use_fd(fd);
    return 0;
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            got.contains(&"fd".to_string()),
            "`fd` valid but never closed on the success path must STILL leak: got {got:?}"
        );
    }

    /// fix-R7 (cluster[11] RC1): a C resource closed on ONE branch but leaked on
    /// another (`if (cond) fclose(fp);` with no else) MUST be reported — the
    /// per-path check must find the close-free path.
    #[test]
    fn char_c_close_on_one_branch_only_leaks() {
        let src = "\
void maybe(const char* p, int cond) {
    FILE *fp = fopen(p, \"r\");
    if (cond) {
        fclose(fp);
    }
}
";
        let got = char_leak_names(src, Language::C);
        assert!(
            got.contains(&"fp".to_string()),
            "C `fp` closed only on one branch must leak (close-free path exists): got {got:?}"
        );
    }

    // =========================================================================
    // FIX-BEHAVIOR TESTS (T2a-resource-acquisition)
    //
    // Assert the CORRECTED module-qualified acquisition behavior:
    //   G2-O1  — `String::new()` / `Vec::new()` / arbitrary `Foo.open` are no
    //            longer flagged; only curated qualified symbols are.
    //   G1-O1  — `File::open(path).unwrap()` / `File::open(path)?` /
    //            `TcpStream::connect(addr).unwrap()` ARE detected via spine
    //            descent.
    //   G1-O2  — `extract_call_name` has no source-text `split('(')` fallback.
    // =========================================================================

    /// Find the first descendant node of a given kind (DFS).
    fn first_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = first_of_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn fix_rust_string_new_not_a_resource() {
        let src = r#"
fn good() {
    let s = String::new();
    let v = Vec::new();
    let b = BufReader::new(file);
}
"#;
        let got = char_detect(src, "good", Language::Rust);
        assert!(
            got.is_empty(),
            "G2-O1: String::new/Vec::new/BufReader::new must NOT be resources; got {got:?}"
        );
    }

    #[test]
    fn fix_rust_file_open_unwrap_detected_via_spine() {
        let src = r#"
fn good() {
    let f = File::open(path).unwrap();
}
"#;
        let got = char_detect(src, "good", Language::Rust);
        assert_eq!(
            got,
            vec![("f".to_string(), "file".to_string())],
            "G1-O1: File::open(path).unwrap() must be detected via spine descent"
        );
    }

    #[test]
    fn fix_rust_file_open_try_detected() {
        let src = r#"
fn good() {
    let g = File::open(path)?;
}
"#;
        let got = char_detect(src, "good", Language::Rust);
        assert_eq!(
            got,
            vec![("g".to_string(), "file".to_string())],
            "G1-O1: File::open(path)? (try_expression) must be detected"
        );
    }

    #[test]
    fn fix_rust_tcpstream_connect_unwrap_detected() {
        let src = r#"
fn good() {
    let c = TcpStream::connect(addr).unwrap();
}
"#;
        let got = char_detect(src, "good", Language::Rust);
        assert_eq!(
            got,
            vec![("c".to_string(), "connection".to_string())],
            "G1-O1: TcpStream::connect(addr).unwrap() must be detected"
        );
    }

    #[test]
    fn fix_rust_qualified_file_open_detected() {
        let src = r#"
fn good() {
    let f = std::fs::File::open(path).unwrap();
}
"#;
        let got = char_detect(src, "good", Language::Rust);
        assert_eq!(
            got,
            vec![("f".to_string(), "file".to_string())],
            "fully-qualified std::fs::File::open must match on last segment File"
        );
    }

    #[test]
    fn fix_ruby_file_open_detected_foo_open_not() {
        let src = "def good\n  f = File.open(\"x\")\n  z = Foo.open(\"y\")\n  arr = Array.new\nend\n";
        let got = char_detect(src, "good", Language::Ruby);
        assert!(
            got.contains(&("f".to_string(), "file".to_string())),
            "Ruby File.open must be detected: got {got:?}"
        );
        assert!(
            !got.iter().any(|(n, _)| n == "z"),
            "G2-O1: arbitrary Foo.open must NOT false-positive: got {got:?}"
        );
        assert!(
            !got.iter().any(|(n, _)| n == "arr"),
            "G2-O1: Array.new must NOT false-positive: got {got:?}"
        );
    }

    #[test]
    fn fix_ruby_chained_new_open_not_flagged() {
        // `SomeBuilder.new.open` — receiver of `.open` is a call, not a
        // module-qualified constant, so it must not match (File, open).
        let src = "def good\n  s = SomeBuilder.new.open\nend\n";
        let got = char_detect(src, "good", Language::Ruby);
        assert!(
            got.is_empty(),
            "Ruby SomeBuilder.new.open must NOT be flagged: got {got:?}"
        );
    }

    // --- OCaml/Elixir: matcher-level (their end-to-end fn-finding is T2b). ---

    #[test]
    fn fix_ocaml_open_in_and_qualified_detected() {
        let detector = ResourceDetector::with_language(Language::Ocaml);
        let patterns = get_resource_patterns(Language::Ocaml);

        let src = "let _ = open_in \"x\"";
        let tree = tldr_core::ast::parser::parse(src, Language::Ocaml).unwrap();
        let app = first_of_kind(tree.root_node(), "application_expression").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(app, src.as_bytes(), &patterns),
            Some("input_channel".to_string()),
            "OCaml bare open_in must match"
        );

        let src2 = "let _ = Stdlib.open_out \"y\"";
        let tree2 = tldr_core::ast::parser::parse(src2, Language::Ocaml).unwrap();
        let app2 = first_of_kind(tree2.root_node(), "application_expression").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(app2, src2.as_bytes(), &patterns),
            Some("output_channel".to_string()),
            "OCaml Stdlib.open_out must match"
        );

        // Non-acquisition application must NOT match.
        let src3 = "let _ = List.length lst";
        let tree3 = tldr_core::ast::parser::parse(src3, Language::Ocaml).unwrap();
        let app3 = first_of_kind(tree3.root_node(), "application_expression").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(app3, src3.as_bytes(), &patterns),
            None,
            "OCaml List.length must NOT match"
        );
    }

    #[test]
    fn fix_elixir_file_open_and_gen_tcp_detected() {
        let detector = ResourceDetector::with_language(Language::Elixir);
        let patterns = get_resource_patterns(Language::Elixir);

        let src = "File.open(\"x\")";
        let tree = tldr_core::ast::parser::parse(src, Language::Elixir).unwrap();
        let call = first_of_kind(tree.root_node(), "call").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(call, src.as_bytes(), &patterns),
            Some("file".to_string()),
            "Elixir File.open must match"
        );

        let src2 = ":gen_tcp.connect(host, port, [])";
        let tree2 = tldr_core::ast::parser::parse(src2, Language::Elixir).unwrap();
        let call2 = first_of_kind(tree2.root_node(), "call").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(call2, src2.as_bytes(), &patterns),
            Some("connection".to_string()),
            "Elixir :gen_tcp.connect must match"
        );

        // Map.new() must NOT match (bare new dropped).
        let src3 = "Map.new()";
        let tree3 = tldr_core::ast::parser::parse(src3, Language::Elixir).unwrap();
        let call3 = first_of_kind(tree3.root_node(), "call").unwrap();
        assert_eq!(
            detector.get_resource_type_from_call_multilang(call3, src3.as_bytes(), &patterns),
            None,
            "Elixir Map.new() must NOT match"
        );
    }

    // =========================================================================
    // CHARACTERIZATION TESTS (T2b-resource-ocaml-elixir-release)
    //
    // Pin the CURRENT, CORRECT end-to-end resource behavior that T2b must NOT
    // regress: the OCaml `let ic = open_in` acquisition arm (already wired by
    // T2a's qualified matcher + the `let_binding` `body` field), the working
    // Elixir scalar-LHS `file = File.open!(p)` binding, and the existing
    // already-green languages' detection/leak shape. These run GREEN on the
    // pre-T2b tree and stay green afterwards (regression net for the Elixir
    // tuple-LHS arm + the Rust RAII-escape leak flip).
    // =========================================================================

    /// Helper: end-to-end `(name, resource_type, closed)` triples through the
    /// REAL command path (`find_all_functions_multilang` over every function,
    /// then `detect_with_patterns`), deduped by `(name, type, closed, line)`.
    /// This mirrors what `tldr resources <file>` actually reports and so is the
    /// honest regression pin for the per-language acquisition arms — including
    /// Elixir, whose `def` body lives under the outer macro `call` node that
    /// the single-function resolver does not select.
    fn char_detect_closed(src: &str, lang: Language) -> Vec<(String, String, bool)> {
        let tree = tldr_core::ast::parser::parse(src, lang).unwrap();
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut seen: HashSet<(String, String, bool, u32)> = HashSet::new();
        for (_name, fnode) in find_all_functions_multilang(&tree, bytes, lang) {
            let mut d = ResourceDetector::with_language(lang);
            for r in d.detect_with_patterns(fnode, bytes) {
                let key = (r.name.clone(), r.resource_type.clone(), r.closed, r.line);
                if seen.insert(key) {
                    out.push((r.name, r.resource_type, r.closed));
                }
            }
        }
        out
    }

    /// Helper: end-to-end leak resource names through the full real path
    /// (`find_all_functions_multilang` + `analyze_function_with_lang` with
    /// leak checking). Dedups repeated leak entries by resource name.
    fn char_leak_names(src: &str, lang: Language) -> Vec<String> {
        let tree = tldr_core::ast::parser::parse(src, lang).unwrap();
        let bytes = src.as_bytes();
        let args = ResourcesArgs {
            file: PathBuf::from("<in-memory>"),
            function: None,
            lang: Some(lang),
            check_leaks: true,
            check_double_close: false,
            check_use_after_close: false,
            check_all: false,
            suggest_context: false,
            show_paths: false,
            constraints: false,
            summary: false,
            output_format: OutputFormat::Json,
            project_root: None,
        };
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for (_name, fnode) in find_all_functions_multilang(&tree, bytes, lang) {
            let (_res, leaks, _dc, _uac) = analyze_function_with_lang(fnode, bytes, &args, lang);
            for l in leaks {
                if seen.insert(l.resource.clone()) {
                    out.push(l.resource);
                }
            }
        }
        out
    }

    #[test]
    fn char_ocaml_open_in_end_to_end_detected() {
        // T2a already wires OCaml acquisition end-to-end (qualified matcher +
        // the `let_binding` `body` field). Pin that `ic` is detected as an
        // input_channel through the real detection path so the T2b OCaml work
        // (and the release flip) cannot silently regress it.
        let src = "let read p =\n  let ic = open_in p in\n  input_line ic\n";
        let got = char_detect_closed(src, Language::Ocaml);
        assert!(
            got.iter()
                .any(|(n, t, _)| n == "ic" && t == "input_channel"),
            "OCaml `let ic = open_in p` must be detected end-to-end: got {got:?}"
        );
    }

    #[test]
    fn char_ocaml_qualified_open_out_end_to_end_detected() {
        let src = "let write p =\n  let oc = Stdlib.open_out p in\n  output_string oc \"x\"\n";
        let got = char_detect_closed(src, Language::Ocaml);
        assert!(
            got.iter()
                .any(|(n, t, _)| n == "oc" && t == "output_channel"),
            "OCaml `let oc = Stdlib.open_out p` must be detected end-to-end: got {got:?}"
        );
    }

    #[test]
    fn char_elixir_scalar_bind_file_open_detected() {
        // The scalar-LHS Elixir binding already works via the generic arm
        // (LHS is a plain identifier). Pin it: name `file`, type `file`.
        let src = "def simple(p) do\n  file = File.open!(p)\n  file\nend\n";
        let got = char_detect_closed(src, Language::Elixir);
        assert!(
            got.iter().any(|(n, t, _)| n == "file" && t == "file"),
            "Elixir `file = File.open!(p)` must be detected as `file`: got {got:?}"
        );
    }

    #[test]
    fn char_python_leak_reported_end_to_end() {
        // Pin the already-green Python leak shape through the full CFG +
        // LeakDetector path: a non-context-managed `open` leaks.
        let src = "def read(path):\n    f = open(path)\n    return f.read()\n";
        let got = char_leak_names(src, Language::Python);
        assert!(
            got.contains(&"f".to_string()),
            "Python non-managed open must leak `f`: got {got:?}"
        );
    }

    // =========================================================================
    // FIX-BEHAVIOR TESTS (T2b-resource-ocaml-elixir-release)
    //
    //   G3-O1 (Elixir) — `{:ok, file} = File.open(p)` binds the *inner*
    //                     `file` identifier (not the whole `{:ok, file}` tuple
    //                     text) by structurally walking the tuple LHS.
    //   G4-O2 (Rust)   — a Rust handle that ESCAPES its scope (returned /
    //                     stored into a field / mem::forget'd) is reported
    //                     leaked; a plain RAII-dropped handle is NOT.
    // =========================================================================

    #[test]
    fn fix_elixir_assignment_kinds_include_match_operator() {
        // T2b: the Elixir assignment DISPATCH gate is
        // `patterns.assignment_kinds.contains(&node.kind())` (see
        // `visit_node_multilang` -> `check_assignment_multilang`). The rest of
        // the codebase treats `match_operator` as Elixir's `=` kind
        // (security/ast_utils.rs Elixir assignment_kinds; dfg/extractor.rs's
        // Elixir match arm) and older grammar revisions name the `=` node that
        // way. If `match_operator` is dropped from this table, a
        // `match_operator` `=` node would be SILENTLY skipped (never reach the
        // Elixir acquisition arm) — zero detection without an error. Guard the
        // production table directly so that regression cannot slip through.
        let patterns = get_resource_patterns(Language::Elixir);
        assert!(
            patterns.assignment_kinds.contains(&"match_operator"),
            "Elixir assignment_kinds must include `match_operator` so a \
             match_operator `=` node reaches the acquisition arm: got {:?}",
            patterns.assignment_kinds
        );
        // The current grammar (tree-sitter-elixir 0.3.x) emits `=` as
        // `binary_operator`; keep that wired too so 0.3.x detection is unchanged.
        assert!(
            patterns.assignment_kinds.contains(&"binary_operator"),
            "Elixir assignment_kinds must still include `binary_operator`: got {:?}",
            patterns.assignment_kinds
        );
    }

    #[test]
    fn fix_elixir_match_operator_assignment_acquisition_detected() {
        // T2b: end-to-end guard that an Elixir `=` acquisition is detected
        // through the REAL command path. Whatever node kind the grammar emits
        // for `=` (`binary_operator` on 0.3.x, `match_operator` on revisions
        // that name it so), the production assignment dispatch + Elixir arm must
        // bind the handle and resolve the qualified acquisition. We assert the
        // node kind we actually observe is one the production table accepts, so
        // this test stays an honest guard of the dispatch wiring even if a
        // grammar bump flips the kind from `binary_operator` to `match_operator`.
        let src = "def open_conn(host, port) do\n  conn = :gen_tcp.connect(host, port, [])\n  conn\nend\n";
        let tree = tldr_core::ast::parser::parse(src, Language::Elixir).unwrap();
        let patterns = get_resource_patterns(Language::Elixir);

        // Locate the `=` assignment node and confirm its kind is wired in the
        // production dispatch table (the gate that routes it to the Elixir arm).
        let assign = first_assignment_with_eq(tree.root_node(), src.as_bytes())
            .expect("expected an Elixir `=` assignment node");
        assert!(
            patterns.assignment_kinds.contains(&assign.kind()),
            "the `=` node kind `{}` must be in the production assignment_kinds \
             so it reaches the Elixir acquisition arm: got {:?}",
            assign.kind(),
            patterns.assignment_kinds
        );

        // Drive the production detection and confirm the connection handle is
        // bound (proving the Elixir arm extracts LHS/RHS for this `=` kind).
        let got = char_detect_closed(src, Language::Elixir);
        assert!(
            got.iter()
                .any(|(n, t, _)| n == "conn" && t == "connection"),
            "Elixir `conn = :gen_tcp.connect(...)` must be detected as a \
             connection handle through the production path: got {got:?}"
        );
    }

    /// Test helper: depth-first find the first Elixir `=` assignment node
    /// (`binary_operator`/`match_operator` whose `[operator]` child is `=`).
    /// Pure node.kind()/field walk — no text matching of source structure.
    fn first_assignment_with_eq<'t>(node: Node<'t>, _source: &[u8]) -> Option<Node<'t>> {
        if matches!(node.kind(), "binary_operator" | "match_operator")
            && node
                .child_by_field_name("operator")
                .map(|op| op.kind() == "=")
                .unwrap_or(false)
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = first_assignment_with_eq(child, _source) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn fix_elixir_tuple_bind_extracts_inner_identifier() {
        // G3-O1: `{:ok, file} = File.open(p)` must bind `file`, never the
        // raw tuple text `{:ok, file}`.
        let src = "def read(p) do\n  {:ok, file} = File.open(p)\n  IO.read(file, :all)\nend\n";
        let got = char_detect_closed(src, Language::Elixir);
        assert!(
            got.iter().any(|(n, t, _)| n == "file" && t == "file"),
            "Elixir tuple-LHS must bind inner `file`: got {got:?}"
        );
        assert!(
            !got.iter().any(|(n, _, _)| n.contains('{') || n.contains(':')),
            "Elixir tuple-LHS must NOT bind the raw `{{:ok, file}}` tuple text: got {got:?}"
        );
    }

    #[test]
    fn fix_elixir_scalar_bind_still_extracts_identifier() {
        // Regression guard: the scalar binding stays correct after the
        // tuple-aware arm is added.
        let src = "def simple(p) do\n  file = File.open!(p)\n  file\nend\n";
        let got = char_detect_closed(src, Language::Elixir);
        assert!(
            got.iter().any(|(n, t, _)| n == "file" && t == "file"),
            "Elixir scalar bind must still produce `file`: got {got:?}"
        );
    }

    #[test]
    fn fix_rust_returned_handle_can_leak() {
        // G4-O2: a File handle that is RETURNED from the function escapes the
        // scope; with no drop/close on that path it must be reportable as a
        // leak (Rust is no longer hard-coded closed).
        let src = "fn open_it(path: &str) -> File {\n    let f = File::open(path).unwrap();\n    f\n}\n";
        let got = char_leak_names(src, Language::Rust);
        assert!(
            got.contains(&"f".to_string()),
            "G4-O2: a returned Rust handle must be reportable as leaked: got {got:?}"
        );
    }

    #[test]
    fn fix_rust_mem_forget_handle_can_leak() {
        // G4-O2: `mem::forget(f)` suppresses Drop — the handle leaks.
        let src = "fn leaky(path: &str) {\n    let f = File::open(path).unwrap();\n    std::mem::forget(f);\n}\n";
        let got = char_leak_names(src, Language::Rust);
        assert!(
            got.contains(&"f".to_string()),
            "G4-O2: a mem::forget'd Rust handle must be reportable as leaked: got {got:?}"
        );
    }

    #[test]
    fn fix_rust_field_stored_handle_can_leak() {
        // G4-O2: storing the handle into a struct field (`self.f = f;`) moves
        // ownership out of the local scope — escape, so reportable.
        let src = "fn store(&mut self, path: &str) {\n    let f = File::open(path).unwrap();\n    self.f = f;\n}\n";
        let got = char_leak_names(src, Language::Rust);
        assert!(
            got.contains(&"f".to_string()),
            "G4-O2: a field-stored Rust handle must be reportable as leaked: got {got:?}"
        );
    }

    #[test]
    fn fix_rust_local_dropped_handle_not_leaked() {
        // G4-O2 must NOT regress the RAII default: a handle that stays local
        // (never escapes) is auto-dropped → NOT a leak.
        let src = "fn read_local(path: &str) {\n    let f = File::open(path).unwrap();\n    let _ = f.metadata();\n}\n";
        let got = char_leak_names(src, Language::Rust);
        assert!(
            !got.contains(&"f".to_string()),
            "G4-O2: a purely-local RAII handle must NOT be flagged as leaked: got {got:?}"
        );
    }
}
