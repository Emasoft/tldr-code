//! Foundational types for Builder V2 call graph construction.
//!
//! This is the leaf module in the builder_v2 dependency graph -- it has no
//! dependencies on other new modules (scanner, var_types, module_path, imports,
//! resolution). Contains config, error, diagnostics, index types, and parser
//! utilities.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tree_sitter::{Parser, Tree};

use super::cross_file_types::CallGraphIR;

// =============================================================================
// Python Built-in Types (Phase 2: Parity Fix)
// =============================================================================

/// Python built-in types to skip when resolving cross-file calls.
/// These are not actual cross-file dependencies and inflate edge counts.
pub(crate) const PYTHON_BUILTINS: &[&str] = &[
    // Exceptions
    "Exception",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AttributeError",
    "RuntimeError",
    "StopIteration",
    "OSError",
    "FileNotFoundError",
    "ImportError",
    "ModuleNotFoundError",
    // Built-in types
    "int",
    "str",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "bytes",
    "bytearray",
    "frozenset",
    "object",
    "type",
    // Built-in functions that look like constructors
    "super",
    "classmethod",
    "staticmethod",
    "property",
    "range",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sorted",
    "reversed",
    "len",
    "print",
    "open",
    "iter",
    "next",
    "isinstance",
    "issubclass",
    "getattr",
    "setattr",
    "hasattr",
    "delattr",
];

// =============================================================================
// BuildConfig (Spec Section 14.3)
// =============================================================================

/// Configuration for call graph building.
///
/// # Defaults
/// - `language`: Empty string (must be set by caller)
/// - `use_workspace_config`: false
/// - `workspace_roots`: empty
/// - `use_type_resolution`: false
/// - `respect_ignore`: true (respect .tldrignore patterns)
/// - `parallelism`: 0 (auto-detect based on CPU cores)
/// - `verbose`: false
#[derive(Clone, Debug)]
pub struct BuildConfig {
    /// Language to analyze (e.g., "python", "typescript")
    pub language: String,

    /// Enable workspace config filtering (monorepo support)
    pub use_workspace_config: bool,

    /// Workspace roots to include when workspace filtering is enabled.
    /// Paths are relative to project root unless absolute.
    pub workspace_roots: Vec<PathBuf>,

    /// Enable type-aware method resolution
    pub use_type_resolution: bool,

    /// Respect .tldrignore patterns
    pub respect_ignore: bool,

    /// Maximum parallel threads (0 = auto-detect)
    pub parallelism: usize,

    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            language: String::new(),
            use_workspace_config: false,
            workspace_roots: Vec::new(),
            use_type_resolution: false,
            respect_ignore: true,
            parallelism: 0, // Auto-detect
            verbose: false,
        }
    }
}

// =============================================================================
// BuildError (Spec Section 14.10)
// =============================================================================

/// Errors during call graph building.
#[derive(Debug, Error)]
pub enum BuildError {
    /// Project root directory not found
    #[error("Project root not found: {0}")]
    RootNotFound(PathBuf),

    /// Requested language is not supported
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),

    /// Error reading or parsing workspace configuration
    #[error("Workspace config error: {0}")]
    WorkspaceConfig(String),

    /// I/O error during file operations
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error parsing a source file
    #[error("Parse error in {file}: {message}")]
    ParseError {
        /// Path to the file that failed to parse
        file: PathBuf,
        /// Description of the parse error
        message: String,
    },

    /// Error in thread pool operations
    #[error("Thread pool error: {0}")]
    ThreadPool(String),

    /// Feature not enabled at compile time (M3.7 mitigation)
    ///
    /// Returned when `use_experimental=true` is passed to `build_call_graph`
    /// but the `experimental_callgraph` feature is not enabled.
    #[error("Feature not enabled: {feature}. {message}")]
    FeatureNotEnabled {
        /// The feature that was requested but not enabled
        feature: String,
        /// Instructions or additional context
        message: String,
    },
}

// =============================================================================
// BuildResult and BuildDiagnostics (Mitigation M2.1)
// =============================================================================

/// Result of a call graph build operation.
///
/// Contains both the built graph and any diagnostics (warnings, errors)
/// collected during the build process.
#[derive(Debug)]
pub struct BuildResult {
    /// The constructed call graph IR
    pub graph: CallGraphIR,

    /// Diagnostics collected during build
    pub diagnostics: BuildDiagnostics,
}

/// Diagnostics collected during call graph building.
///
/// Implements error aggregation per Mitigation M2.1:
/// "Implement error aggregation with configurable strategy.
/// Return both the graph AND a list of warnings/errors."
#[derive(Debug, Default)]
pub struct BuildDiagnostics {
    /// Files that failed to parse
    pub parse_errors: Vec<ParseDiagnostic>,

    /// Warnings during import/call resolution
    pub resolution_warnings: Vec<ResolutionWarning>,

    /// Files that were skipped (with reason)
    pub skipped_files: Vec<(PathBuf, SkipReason)>,
}

impl BuildDiagnostics {
    /// Create empty diagnostics
    pub fn new() -> Self {
        Self::default()
    }

    /// Sort diagnostics for deterministic output.
    ///
    /// Per Mitigation M2.12: "Sort diagnostics by file path and line number
    /// before returning" to ensure deterministic output regardless of
    /// parallel execution order.
    pub fn sort(&mut self) {
        self.parse_errors.sort();
        self.resolution_warnings.sort();
        self.skipped_files.sort_by(|a, b| a.0.cmp(&b.0));
    }

    /// Check if there are any errors (not just warnings)
    pub fn has_errors(&self) -> bool {
        !self.parse_errors.is_empty()
    }

    /// Total number of diagnostic messages
    pub fn count(&self) -> usize {
        self.parse_errors.len() + self.resolution_warnings.len() + self.skipped_files.len()
    }
}

/// Diagnostic for a parse error in a specific file.
#[derive(Debug, Clone)]
pub struct ParseDiagnostic {
    /// Path to the file that failed
    pub file: PathBuf,

    /// Line number where error occurred (0 if unknown)
    pub line: u32,

    /// Error message
    pub message: String,
}

// Implement Ord for deterministic sorting (M2.12)
impl PartialEq for ParseDiagnostic {
    fn eq(&self, other: &Self) -> bool {
        self.file == other.file && self.line == other.line && self.message == other.message
    }
}

impl Eq for ParseDiagnostic {}

impl PartialOrd for ParseDiagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParseDiagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.file
            .cmp(&other.file)
            .then(self.line.cmp(&other.line))
            .then(self.message.cmp(&other.message))
    }
}

/// Warning during import or call resolution.
#[derive(Debug, Clone)]
pub struct ResolutionWarning {
    /// Path to the file where warning occurred
    pub file: PathBuf,

    /// Line number (0 if unknown)
    pub line: u32,

    /// The import or call that couldn't be resolved
    pub target: String,

    /// Reason for the warning
    pub reason: String,
}

// Implement Ord for deterministic sorting (M2.12)
impl PartialEq for ResolutionWarning {
    fn eq(&self, other: &Self) -> bool {
        self.file == other.file
            && self.line == other.line
            && self.target == other.target
            && self.reason == other.reason
    }
}

impl Eq for ResolutionWarning {}

impl PartialOrd for ResolutionWarning {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResolutionWarning {
    fn cmp(&self, other: &Self) -> Ordering {
        self.file
            .cmp(&other.file)
            .then(self.line.cmp(&other.line))
            .then(self.target.cmp(&other.target))
            .then(self.reason.cmp(&other.reason))
    }
}

/// Reason why a file was skipped during processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// File encoding could not be determined
    EncodingError,

    /// File matched ignore pattern
    Ignored,

    /// File is outside workspace scope
    OutOfScope,

    /// File is a symlink that would cause a cycle
    SymlinkCycle,

    /// Other reason with description
    Other(String),
}

// =============================================================================
// Phase 14c: Index Types (Spec Section 14.4 Steps 3-4)
// =============================================================================

/// Entry in the function index.
///
/// Stores metadata about a function definition for cross-file resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncEntry {
    /// Path to the file containing this function (relative to project root).
    pub file_path: PathBuf,

    /// Line number where the function is defined (1-indexed).
    pub line: u32,

    /// End line of the function (1-indexed).
    pub end_line: u32,

    /// Whether this function is a method of a class.
    pub is_method: bool,

    /// Containing class name if `is_method` is true.
    pub class_name: Option<String>,
}

impl FuncEntry {
    /// Creates a new FuncEntry for a standalone function.
    pub fn function(file_path: PathBuf, line: u32, end_line: u32) -> Self {
        Self {
            file_path,
            line,
            end_line,
            is_method: false,
            class_name: None,
        }
    }

    /// Creates a new FuncEntry for a method.
    pub fn method(file_path: PathBuf, line: u32, end_line: u32, class_name: String) -> Self {
        Self {
            file_path,
            line,
            end_line,
            is_method: true,
            class_name: Some(class_name),
        }
    }
}

/// fix-R7 (cluster[11]): a path is "test" when any of its components is a
/// conventional test directory name. Mirrors `resolution::is_test_path` and
/// `context::builder::is_test_path` so the ClassIndex prefer-production tiebreak
/// matches the rest of the call-graph resolver. Used ONLY as a tiebreak (never
/// to exclude), so a test-only class is still resolvable when it is the sole
/// definition.
fn path_is_test(p: &Path) -> bool {
    p.components().any(|c| {
        // Case-insensitive: Swift/Java/Kotlin conventionally capitalise the
        // directory (`Tests/`, `Test/`), unlike Python/JS (`tests/`).
        let lc = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            lc.as_str(),
            "tests" | "test" | "__tests__" | "spec" | "specs" | "testing"
        )
    })
}

/// Entry in the class index.
///
/// Stores metadata about a class definition for cross-file resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEntry {
    /// Path to the file containing this class (relative to project root).
    pub file_path: PathBuf,

    /// Line number where the class is defined (1-indexed).
    pub line: u32,

    /// End line of the class (1-indexed).
    pub end_line: u32,

    /// Method names defined in this class.
    pub methods: Vec<String>,

    /// Base class names (for inheritance tracking).
    pub bases: Vec<String>,
}

impl ClassEntry {
    /// Creates a new ClassEntry.
    pub fn new(
        file_path: PathBuf,
        line: u32,
        end_line: u32,
        methods: Vec<String>,
        bases: Vec<String>,
    ) -> Self {
        Self {
            file_path,
            line,
            end_line,
            methods,
            bases,
        }
    }
}

/// Function index for O(1) lookup of function definitions.
///
/// Maps (module_path, func_name) to FuncEntry for quick cross-file resolution.
///
/// # Thread Safety
///
/// This type is not `Sync` - it's built in parallel but only accessed
/// after the build is complete.
///
/// # Example
/// ```rust,ignore
/// let index = FuncIndex::new();
/// index.insert("mymodule", "process", entry);
/// if let Some(entry) = index.get("mymodule", "process") {
///     println!("Found {} at line {}", entry.file_path.display(), entry.line);
/// }
/// ```
#[derive(Debug, Default)]
pub struct FuncIndex {
    /// Maps (module_path, func_name) -> all entries sharing that key.
    ///
    /// A single (module, name) key can legitimately map to MULTIPLE entries:
    /// when several classes in the same module each define a method of the
    /// same bare name (e.g. `Animal.speak`, `Robot.speak`, `Plant.speak` all
    /// indexed under `("x", "speak")`), every one must survive. Storing a
    /// `Vec` (rather than overwriting) is what lets `find_by_name` report the
    /// true cardinality so the decline-on-ambiguity guards in `resolution`
    /// (which require exactly one candidate) can fire correctly instead of
    /// binding an order-dependent survivor.
    entries: HashMap<(String, String), Vec<FuncEntry>>,

    /// Secondary name index: `func_name` -> every `(module, func_name)` key in
    /// `entries` whose name component equals `func_name`.
    ///
    /// fix-W5-callgraph-blowup-v1: name-keyed lookups
    /// ([`find_by_name`](Self::find_by_name) and the receiver/fuzzy/type
    /// fallbacks in `resolution`) previously scanned the *entire* `entries`
    /// map (one `HashMap<(module,name), _>` linear pass per call-site). On a
    /// project with `M` distinct keys and `N` call-sites that is `O(N*M)` —
    /// quadratic — and it never terminated on large bundled files (js-lodash)
    /// or large multi-repo roots. This index lets `find_by_name` resolve in
    /// `O(k)` where `k` is the number of keys sharing the name, restoring
    /// sub-quadratic resolution while preserving the *exact* set and ordering
    /// guarantees the ambiguity guards depend on.
    ///
    /// Invariant: `by_name[name]` lists every key `(m, name)` present in
    /// `entries`, and only those. Maintained on every `insert`/`merge`.
    by_name: HashMap<String, Vec<(String, String)>>,
}

impl FuncIndex {
    /// Creates a new empty function index.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Creates a function index with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            by_name: HashMap::with_capacity(capacity),
        }
    }

    /// Inserts a function entry under `(module, func_name)`.
    ///
    /// Multiple distinct entries may share a key (see the type doc). Inserts
    /// are deduplicated by `(file_path, line, class_name)` so that the same
    /// definition reached via more than one module alias (e.g. the full and
    /// simple module spellings) does not inflate the candidate count and
    /// spuriously trip the ambiguity guards.
    pub fn insert(
        &mut self,
        module: impl Into<String>,
        func_name: impl Into<String>,
        entry: FuncEntry,
    ) {
        let module = module.into();
        let func_name = func_name.into();
        let key = (module, func_name);
        match self.entries.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(mut occ) => {
                // Key already present (so already registered in `by_name`);
                // just append the new entry if it is not a dedup-duplicate.
                let vec = occ.get_mut();
                if !vec.iter().any(|e| {
                    e.file_path == entry.file_path
                        && e.line == entry.line
                        && e.class_name == entry.class_name
                }) {
                    vec.push(entry);
                }
            }
            std::collections::hash_map::Entry::Vacant(vac) => {
                // First entry for this key: register the key under its name so
                // `find_by_name` can reach it in O(k) without scanning `entries`.
                self.by_name
                    .entry(key.1.clone())
                    .or_default()
                    .push(key.clone());
                vac.insert(vec![entry]);
            }
        }
    }

    /// Looks up a function by module and name.
    ///
    /// Returns the first entry stored under the key. When a key holds several
    /// distinct same-name methods, callers that need to reason about
    /// ambiguity must use [`find_by_name`](Self::find_by_name) (or
    /// [`get_all`](Self::get_all)) instead — `get` preserves the historical
    /// single-result API for the common, unique-key lookups.
    pub fn get(&self, module: &str, func_name: &str) -> Option<&FuncEntry> {
        self.entries
            .get(&(module.to_string(), func_name.to_string()))
            .and_then(|v| v.first())
    }

    /// Returns all entries stored under `(module, func_name)`.
    pub fn get_all(&self, module: &str, func_name: &str) -> &[FuncEntry] {
        self.entries
            .get(&(module.to_string(), func_name.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the total number of entries in the index (summed across all
    /// keys, so colliding same-name methods each count).
    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Returns true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.values().all(|v| v.is_empty())
    }

    /// Merges another FuncIndex into this one.
    ///
    /// Used to combine results from parallel processing. Entries are appended
    /// per key (with the same `(file_path, line, class_name)` dedup as
    /// [`insert`](Self::insert)) so same-name methods from different shards
    /// all survive.
    pub fn merge(&mut self, other: FuncIndex) {
        for ((module, name), entries) in other.entries {
            for entry in entries {
                self.insert(module.clone(), name.clone(), entry);
            }
        }
    }

    /// Returns an iterator over all entries.
    ///
    /// Each `((module, name), entry)` pair is yielded once; keys holding
    /// several same-name methods produce one item per entry.
    pub fn iter(&self) -> impl Iterator<Item = ((&str, &str), &FuncEntry)> {
        self.entries.iter().flat_map(|((m, f), entries)| {
            entries.iter().map(move |e| ((m.as_str(), f.as_str()), e))
        })
    }

    /// Finds all entries matching a given function name across all modules.
    /// Used for fallback resolution when the module/receiver cannot be determined.
    ///
    /// fix-W5-callgraph-blowup-v1: resolves via the `by_name` secondary index
    /// in `O(k)` (k = keys sharing this name) instead of the previous
    /// full-`entries` linear scan, which made every receiver/fuzzy/fallback
    /// resolution `O(M)` in the total key count and the whole call-graph build
    /// `O(N*M)` (quadratic) on large inputs. The yielded set and order are
    /// identical to the old scan for any given index contents (every entry
    /// under a `(module, func_name)` key whose name component equals
    /// `func_name`), so resolution semantics and the ambiguity guards are
    /// unchanged.
    pub fn find_by_name<'a>(
        &'a self,
        func_name: &'a str,
    ) -> impl Iterator<Item = &'a FuncEntry> + 'a {
        self.by_name
            .get(func_name)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .filter_map(move |key| self.entries.get(key))
            .flat_map(|entries| entries.iter())
    }

    /// Iterates `((module, func_name), entry)` tuples for one `func_name`.
    ///
    /// fix-W5-callgraph-blowup-v1: the index-backed counterpart to filtering
    /// [`iter`](Self::iter) by name. Callers in `resolution` that need the
    /// owning module/key alongside the entry (and previously paid an `O(M)`
    /// `iter().filter(name == ...)` scan per call-site) use this to stay
    /// `O(k)`. Yields exactly the same `((module, name), entry)` items the
    /// filtered full scan produced for the same name.
    pub fn iter_by_name<'a>(
        &'a self,
        func_name: &'a str,
    ) -> impl Iterator<Item = ((&'a str, &'a str), &'a FuncEntry)> + 'a {
        self.by_name
            .get(func_name)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .filter_map(move |key| {
                self.entries
                    .get(key)
                    .map(|entries| ((key.0.as_str(), key.1.as_str()), entries))
            })
            .flat_map(|((m, f), entries)| entries.iter().map(move |e| ((m, f), e)))
    }

    /// Convert to path map for TypeAwareCallResolver compatibility.
    ///
    /// The path map is single-valued per `(module, name)` key; when several
    /// entries share a key the first one's path is used (the resolver only
    /// needs a representative file for type-table seeding).
    pub fn to_path_map(&self) -> std::collections::HashMap<(String, String), std::path::PathBuf> {
        self.entries
            .iter()
            .filter_map(|((m, f), entries)| {
                entries
                    .first()
                    .map(|e| ((m.clone(), f.clone()), e.file_path.clone()))
            })
            .collect()
    }
}

/// Class index for O(1) lookup of class definitions.
///
/// Maps class_name to ClassEntry for quick cross-file resolution.
///
/// # Example
/// ```rust,ignore
/// let index = ClassIndex::new();
/// index.insert("User", entry);
/// if let Some(entry) = index.get("User") {
///     println!("Found User at line {}", entry.line);
/// }
/// ```
#[derive(Debug, Default)]
pub struct ClassIndex {
    /// Maps class_name -> ClassEntry
    entries: HashMap<String, ClassEntry>,
}

impl ClassIndex {
    /// Creates a new empty class index.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Creates a class index with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
        }
    }

    /// Inserts a class entry.
    ///
    /// fix-R7 (cluster[11], Swift research-needed): `ClassIndex` is
    /// single-valued, so when a class name is defined in more than one file the
    /// surviving entry decides where `calls`/`hubs`/`impact` etc. resolve it.
    /// Plain `HashMap::insert` was last-write-wins (order-dependent), which made
    /// `Session` (production `Source/Core/Session.swift` + `extension Session`
    /// in `Tests/...`) resolve to a TEST file. We apply the same prefer-
    /// production tiebreak the FuncIndex resolver uses: a production definition
    /// is never overwritten by a colliding test-file definition. A test-only
    /// class is still stored (the rule is a tiebreak among collisions, not an
    /// exclusion). Distinct definitions that are both production keep the
    /// last-write-wins behaviour (genuine collision the index cannot
    /// disambiguate without module scope — see the design-fork doc).
    pub fn insert(&mut self, class_name: impl Into<String>, entry: ClassEntry) {
        let class_name = class_name.into();
        if let Some(existing) = self.entries.get(&class_name) {
            let existing_is_test = path_is_test(&existing.file_path);
            let new_is_test = path_is_test(&entry.file_path);
            // Keep the existing PRODUCTION def when the incoming one is a test
            // def — do not let a test file clobber the canonical definition.
            if !existing_is_test && new_is_test {
                return;
            }
        }
        self.entries.insert(class_name, entry);
    }

    /// Looks up a class by name.
    pub fn get(&self, class_name: &str) -> Option<&ClassEntry> {
        self.entries.get(class_name)
    }

    /// Looks up a mutable class entry by name.
    pub fn get_mut(&mut self, class_name: &str) -> Option<&mut ClassEntry> {
        self.entries.get_mut(class_name)
    }

    /// Returns the number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merges another ClassIndex into this one.
    ///
    /// Used to combine results from parallel processing. fix-R7 (cluster[11]):
    /// routes every merged entry through [`ClassIndex::insert`] so the
    /// prefer-production tiebreak applies to cross-shard collisions too (a
    /// test-file shard merged after a production shard must not clobber the
    /// canonical def). Previously `HashMap::extend` was last-write-wins and
    /// shard-order-dependent.
    pub fn merge(&mut self, other: ClassIndex) {
        for (name, entry) in other.entries {
            self.insert(name, entry);
        }
    }

    /// Returns an iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ClassEntry)> {
        self.entries.iter().map(|(n, e)| (n.as_str(), e))
    }

    /// Convert to path map for TypeAwareCallResolver compatibility.
    /// Note: ClassIndex uses single-key (class_name), but TypeAwareCallResolver expects (module, class).
    /// We use ("", class_name) as the key since we don't track module per class.
    pub fn to_path_map(&self) -> std::collections::HashMap<(String, String), std::path::PathBuf> {
        self.entries
            .iter()
            .map(|(name, e)| (("".to_string(), name.clone()), e.file_path.clone()))
            .collect()
    }
}

// =============================================================================
// Utility Functions (FM-1 and FM-2 mitigations)
// =============================================================================

/// Capitalizes the first character of a string.
/// Used for Java/Kotlin/C# convention: variable "owner" -> class "Owner".
pub(crate) fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

// =============================================================================
// Thread-Local Parsers (Mitigation M1.4)
// =============================================================================

// NOTE: Tree-sitter Parser is !Send, so we cannot share it across threads.
// The get_thread_local_parser function creates a new parser per call,
// which is safe for parallel execution via rayon. Each thread gets its own
// parser instance on the stack.
//
// For future optimization, we could use thread_local! to cache parsers
// per language per thread, but the current approach is correct and simpler.

/// Gets or creates a thread-local parser for the specified language.
///
/// Per Mitigation M1.4: Tree-sitter Parser is !Send, so we use thread_local!
/// to ensure each thread has its own parser instance.
pub(crate) fn get_thread_local_parser(language: &str) -> Result<Parser, BuildError> {
    let mut parser = Parser::new();

    let ts_language = match language.to_lowercase().as_str() {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "typescript" | "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "javascript" | "js" => tree_sitter_typescript::LANGUAGE_TSX.into(), // JS/JSX via TSX grammar
        "go" => tree_sitter_go::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "scala" => tree_sitter_scala::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "lua" => tree_sitter_lua::LANGUAGE.into(),
        "luau" => tree_sitter_luau::LANGUAGE.into(),
        "elixir" => tree_sitter_elixir::LANGUAGE.into(),
        "ocaml" => tree_sitter_ocaml::LANGUAGE_OCAML.into(),
        // v0.5.0 SOL-001: Solidity foundation. Adapter-level callgraph
        // builder lands in SOL-003+; parser dispatch is enabled now so
        // downstream code can parse `.sol` files without panicking.
        "solidity" => tree_sitter_solidity::LANGUAGE.into(),
        _ => return Err(BuildError::UnsupportedLanguage(language.to_string())),
    };

    parser
        .set_language(&ts_language)
        .map_err(|e| BuildError::ParseError {
            file: PathBuf::new(),
            message: format!("Failed to set language {}: {}", language, e),
        })?;

    Ok(parser)
}

/// Parse source code and return the tree.
///
/// Uses thread-local parser storage per M1.4 mitigation.
pub(crate) fn parse_source(source: &str, language: &str) -> Result<Tree, BuildError> {
    let mut parser = get_thread_local_parser(language)?;

    parser
        .parse(source, None)
        .ok_or_else(|| BuildError::ParseError {
            file: PathBuf::new(),
            message: "Parser returned None".to_string(),
        })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_config_defaults() {
        let config = BuildConfig::default();

        assert!(config.language.is_empty());
        assert!(!config.use_workspace_config);
        assert!(config.workspace_roots.is_empty());
        assert!(!config.use_type_resolution);
        assert!(config.respect_ignore);
        assert_eq!(config.parallelism, 0);
        assert!(!config.verbose);
    }

    /// fix-R7 (cluster[11], Swift research-needed): when a class name is defined
    /// in BOTH a production file and a test file, `ClassIndex` (single-valued)
    /// must keep the PRODUCTION definition regardless of insertion order. The
    /// pre-fix `HashMap::insert` was last-write-wins, so `Session` (defined in
    /// `Source/Core/Session.swift` and `extension Session` in
    /// `Tests/WebSocketTests.swift`) resolved to the test file in `hubs`/`calls`
    /// depending on shard ordering. This is the same "prefer non-test"
    /// disambiguation already applied to FuncIndex.
    #[test]
    fn class_index_prefers_production_over_test_regardless_of_order() {
        let src = ClassEntry::new(
            PathBuf::from("Source/Core/Session.swift"),
            30,
            200,
            vec!["request".to_string()],
            vec![],
        );
        let test = ClassEntry::new(
            PathBuf::from("Tests/WebSocketTests.swift"),
            10,
            50,
            vec!["request".to_string()],
            vec![],
        );

        // Order A: production first, then test inserted later (the order that
        // previously let the test file overwrite the canonical def).
        let mut idx_a = ClassIndex::new();
        idx_a.insert("Session", src.clone());
        idx_a.insert("Session", test.clone());
        assert_eq!(
            idx_a.get("Session").map(|e| e.file_path.clone()),
            Some(PathBuf::from("Source/Core/Session.swift")),
            "production def must win when a later test def collides"
        );

        // Order B: test first, then production.
        let mut idx_b = ClassIndex::new();
        idx_b.insert("Session", test.clone());
        idx_b.insert("Session", src.clone());
        assert_eq!(
            idx_b.get("Session").map(|e| e.file_path.clone()),
            Some(PathBuf::from("Source/Core/Session.swift")),
            "production def must win when inserted after a test def"
        );
    }

    /// fix-R7 (cluster[11], Swift): a test-only class (no production definition)
    /// must STILL be resolvable — the prefer-production rule is a tiebreak, not
    /// an exclusion (regression guard for the bounded fix).
    #[test]
    fn class_index_keeps_test_only_class() {
        let test = ClassEntry::new(
            PathBuf::from("Tests/HelperTests.swift"),
            5,
            20,
            vec!["help".to_string()],
            vec![],
        );
        let mut idx = ClassIndex::new();
        idx.insert("TestOnlyHelper", test);
        assert_eq!(
            idx.get("TestOnlyHelper").map(|e| e.file_path.clone()),
            Some(PathBuf::from("Tests/HelperTests.swift")),
            "a test-only class must remain resolvable when it is the sole def"
        );
    }

    /// fix-R7 (cluster[11], Swift): `ClassIndex::merge` (used to combine parallel
    /// shards) must apply the same prefer-production tiebreak; a test-file shard
    /// merged on top of a production shard must not clobber the production def.
    #[test]
    fn class_index_merge_prefers_production() {
        let mut prod_shard = ClassIndex::new();
        prod_shard.insert(
            "Session",
            ClassEntry::new(PathBuf::from("Source/Session.swift"), 1, 9, vec![], vec![]),
        );
        let mut test_shard = ClassIndex::new();
        test_shard.insert(
            "Session",
            ClassEntry::new(PathBuf::from("Tests/SessionTests.swift"), 1, 9, vec![], vec![]),
        );

        prod_shard.merge(test_shard);
        assert_eq!(
            prod_shard.get("Session").map(|e| e.file_path.clone()),
            Some(PathBuf::from("Source/Session.swift")),
            "merge must keep the production def over a test def"
        );
    }

    #[test]
    fn test_build_error_display() {
        let err = BuildError::RootNotFound(PathBuf::from("/foo/bar"));
        assert!(err.to_string().contains("/foo/bar"));

        let err = BuildError::UnsupportedLanguage("brainfuck".to_string());
        assert!(err.to_string().contains("brainfuck"));
    }

    #[test]
    fn test_build_diagnostics_sort() {
        let mut diag = BuildDiagnostics::new();

        diag.parse_errors.push(ParseDiagnostic {
            file: PathBuf::from("z.py"),
            line: 10,
            message: "error".to_string(),
        });
        diag.parse_errors.push(ParseDiagnostic {
            file: PathBuf::from("a.py"),
            line: 5,
            message: "error".to_string(),
        });

        diag.sort();

        assert_eq!(diag.parse_errors[0].file, PathBuf::from("a.py"));
        assert_eq!(diag.parse_errors[1].file, PathBuf::from("z.py"));
    }

    /// Test: BuildDiagnostics methods
    #[test]
    fn test_build_diagnostics_methods() {
        let mut diag = BuildDiagnostics::new();

        assert!(!diag.has_errors());
        assert_eq!(diag.count(), 0);

        diag.parse_errors.push(ParseDiagnostic {
            file: PathBuf::from("test.py"),
            line: 1,
            message: "test error".to_string(),
        });

        assert!(diag.has_errors());
        assert_eq!(diag.count(), 1);

        diag.resolution_warnings.push(ResolutionWarning {
            file: PathBuf::from("test.py"),
            line: 2,
            target: "some_import".to_string(),
            reason: "not found".to_string(),
        });

        assert_eq!(diag.count(), 2);
    }

    /// Test: SkipReason variants exist
    #[test]
    fn test_skip_reason_variants() {
        let reasons = vec![
            SkipReason::EncodingError,
            SkipReason::Ignored,
            SkipReason::OutOfScope,
            SkipReason::SymlinkCycle,
            SkipReason::Other("custom reason".to_string()),
        ];

        for reason in reasons {
            // Just verify they can be created and compared
            assert_eq!(reason.clone(), reason);
        }
    }

    // ========================================================================
    // fix-W5-callgraph-blowup-v1: FuncIndex name-lookup must be index-backed.
    // ========================================================================

    /// Reference implementation of the OLD `find_by_name`: a full linear scan
    /// over every `(module, name)` key. Used only to prove the indexed
    /// `find_by_name` returns the *identical* set of entries (semantics are
    /// preserved exactly), independent of the speed assertion below.
    fn reference_find_by_name<'a>(idx: &'a FuncIndex, name: &str) -> Vec<&'a FuncEntry> {
        let mut out: Vec<&FuncEntry> = Vec::new();
        for ((_m, f), entry) in idx.iter() {
            if f == name {
                out.push(entry);
            }
        }
        out
    }

    /// Char test (W5): `find_by_name` / `iter_by_name` resolve in O(k), not by
    /// scanning the whole index.
    ///
    /// Pre-fix, `find_by_name` did `entries.iter().filter(name == ...)` — an
    /// O(M) pass over every distinct `(module, name)` key on *each* call. The
    /// production resolver calls it (and the two name-filtered `iter()` scans
    /// it replaced) once per call-site, so a project with M funcs and N
    /// call-sites cost O(N*M) and never terminated on large bundled inputs
    /// (js-lodash) or large multi-repo roots (the `/tmp`-rooted coupling pair).
    ///
    /// This builds a large index (M distinct names across many modules) and
    /// performs N name-lookups. On the old O(N*M) scan this is ~N*M HashMap
    /// key-comparisons (tens-to-hundreds of millions in a debug build, taking
    /// many seconds); the index-backed lookup is O(N*k) and finishes in
    /// milliseconds. The generous wall bound fails on the quadratic code and
    /// passes with orders-of-magnitude margin on the fix. A correctness
    /// assertion against `reference_find_by_name` locks the resolved set so the
    /// speedup cannot come from dropping or reordering candidates.
    #[test]
    fn func_index_find_by_name_is_sub_quadratic() {
        use std::time::Instant;

        // M distinct function names spread across many modules => a large
        // `entries` map. `modules * names_per_module` distinct keys.
        let modules = 200usize;
        let names_per_module = 50usize; // 10_000 distinct keys
        let total_names = modules * names_per_module;

        let mut idx = FuncIndex::with_capacity(total_names);
        for m in 0..modules {
            let module = format!("mod_{m}");
            for n in 0..names_per_module {
                let name = format!("fn_{m}_{n}");
                idx.insert(
                    module.clone(),
                    name.clone(),
                    FuncEntry::function(PathBuf::from(format!("{module}.py")), n as u32 + 1, 0),
                );
            }
        }
        // Seed a handful of ambiguous same-name methods across modules so the
        // O(k) path returns multiple entries (k > 1) and cardinality is real.
        for m in 0..modules {
            idx.insert(
                format!("mod_{m}"),
                "shared".to_string(),
                FuncEntry::method(
                    PathBuf::from(format!("mod_{m}.py")),
                    900,
                    910,
                    format!("Class{m}"),
                ),
            );
        }

        // Correctness: indexed lookup == reference linear scan, for both a
        // unique name and the ambiguous shared name.
        let unique = "fn_137_42";
        let mut got: Vec<_> = idx.find_by_name(unique).collect();
        let mut want = reference_find_by_name(&idx, unique);
        got.sort_by_key(|e| (e.file_path.clone(), e.line));
        want.sort_by_key(|e| (e.file_path.clone(), e.line));
        assert_eq!(got, want, "find_by_name must match the full-scan reference");
        assert_eq!(got.len(), 1, "unique name must have exactly one entry");

        let shared_count = idx.find_by_name("shared").count();
        assert_eq!(
            shared_count, modules,
            "ambiguous shared method must surface every definer (cardinality preserved)"
        );

        // iter_by_name must agree with find_by_name on entries (key-scoped).
        let via_iter: Vec<_> = idx.iter_by_name(unique).map(|(_k, e)| e).collect();
        assert_eq!(via_iter, idx.find_by_name(unique).collect::<Vec<_>>());

        // A name absent from the index costs O(1), not O(M).
        assert_eq!(idx.find_by_name("does_not_exist").count(), 0);

        // Speed: N name-lookups (mix of hits and misses) must finish well
        // under budget. Old O(N*M): N * 10_000 key-compares. New O(N*k): tiny.
        let lookups = 40_000usize;
        let start = Instant::now();
        let mut sink = 0usize;
        for i in 0..lookups {
            let m = i % modules;
            let n = i % names_per_module;
            // Real hits...
            sink += idx.find_by_name(&format!("fn_{m}_{n}")).count();
            // ...plus the ambiguous name and a guaranteed miss.
            sink += idx.find_by_name("shared").count();
            sink += idx.find_by_name("absent_xyz").count();
        }
        let elapsed = start.elapsed();
        assert!(sink > 0, "lookups must do real work");
        assert!(
            elapsed.as_secs() < 5,
            "find_by_name over {total_names} keys x {lookups} lookups took {elapsed:?}; \
             a full-index scan per lookup (the pre-fix O(N*M) behavior) blows this \
             generous 5s bound, the O(k) index does not"
        );
    }
}
