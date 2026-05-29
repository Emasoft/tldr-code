//! Import Resolver for resolving Python import statements.
//!
//! This module provides the `ImportResolver` struct which resolves import statements
//! to their target files and names within a project.
//!
//! # Overview
//!
//! The `ImportResolver` is designed for:
//! - Resolving absolute imports (`from pkg.module import Name`)
//! - Resolving relative imports (`from . import types`, `from ..utils import helper`)
//! - Expanding wildcard imports (`from pkg import *`)
//! - Tracking TYPE_CHECKING imports
//! - LRU caching for repeated resolutions
//!
//! # Example
//!
//! ```rust,ignore
//! use tldr_core::callgraph::import_resolver::ImportResolver;
//! use tldr_core::callgraph::module_index::ModuleIndex;
//! use tldr_core::callgraph::cross_file_types::ImportDef;
//! use std::path::Path;
//!
//! let index = ModuleIndex::build(Path::new("src"), "python")?;
//! let mut resolver = ImportResolver::new(&index, 10000);
//!
//! let import_def = ImportDef::from_import("pkg.module", vec!["Name".to_string()]);
//! let resolved = resolver.resolve(&import_def, Path::new("main.py"));
//!
//! assert!(!resolved.is_empty());
//! ```
//!
//! # Spec Reference
//!
//! See `migration/spec/callgraph-spec.md` Section 5 for the full behavioral specification.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lru::LruCache;

use super::cross_file_types::{ImportDef, ImportKind, ResolvedImport};
use super::module_index::ModuleIndex;

// =============================================================================
// Cache Key for LRU Cache
// =============================================================================

/// Cache key for resolved imports.
///
/// Uses (module, sorted names, current_file) as the key for deterministic hashing.
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
struct CacheKey {
    /// Module being imported
    module: String,
    /// Imported names (sorted for deterministic hashing)
    names: Vec<String>,
    /// File containing the import statement
    current_file: PathBuf,
    /// Relative import level (0 for absolute)
    level: u8,
}

impl CacheKey {
    fn new(import: &ImportDef, current_file: &Path) -> Self {
        let mut names = import.names.clone();
        names.sort(); // Sort for deterministic hashing
        Self {
            module: import.module.clone(),
            names,
            current_file: current_file.to_path_buf(),
            level: import.level,
        }
    }
}

// =============================================================================
// Cache Statistics
// =============================================================================

/// Statistics about cache usage.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Current number of entries in the cache
    pub entries: usize,
    /// Maximum capacity of the cache
    pub capacity: usize,
}

impl CacheStats {
    /// Returns the hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

// =============================================================================
// Import Resolver
// =============================================================================

/// Default cache size for import resolution.
pub const DEFAULT_CACHE_SIZE: usize = 10_000;

/// Import resolver with LRU caching.
///
/// Resolves import statements to their target files and names within a project.
/// Uses an LRU cache to avoid repeated resolution of the same imports.
pub struct ImportResolver<'a> {
    /// Reference to the module index for lookups
    index: &'a ModuleIndex,
    /// LRU cache for resolved imports
    cache: LruCache<CacheKey, Arc<Vec<ResolvedImport>>>,
    /// Cache for parsed __all__ per module (wildcard expansion)
    all_cache: HashMap<PathBuf, Arc<Vec<String>>>,
    /// Number of cache hits
    cache_hits: u64,
    /// Number of cache misses
    cache_misses: u64,
}

impl<'a> ImportResolver<'a> {
    /// Creates a new ImportResolver with the given cache size.
    ///
    /// # Arguments
    ///
    /// * `index` - Reference to the ModuleIndex for module lookups
    /// * `cache_size` - Maximum number of cached resolutions
    pub fn new(index: &'a ModuleIndex, cache_size: usize) -> Self {
        let cache_size = cache_size.max(1); // Ensure at least 1
        Self {
            index,
            cache: LruCache::new(NonZeroUsize::new(cache_size).unwrap()),
            all_cache: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Creates a new ImportResolver with the default cache size.
    pub fn with_default_cache(index: &'a ModuleIndex) -> Self {
        Self::new(index, DEFAULT_CACHE_SIZE)
    }

    /// Resolve an import statement.
    ///
    /// Returns resolved imports for each name in the import.
    /// Results are cached for repeated lookups.
    ///
    /// # Arguments
    ///
    /// * `import` - The import definition to resolve
    /// * `current_file` - The file containing the import statement
    ///
    /// # Returns
    ///
    /// A vector of resolved imports. Empty if the module is external.
    ///
    /// # Behavior
    ///
    /// 1. Check cache for previous resolution
    /// 2. Handle relative imports (`level > 0`) via `resolve_relative()`
    /// 3. Check if project module via `is_project_module()`
    /// 4. Handle wildcards by expanding `__all__`
    /// 5. Create ResolvedImport for each name
    pub fn resolve(&mut self, import: &ImportDef, current_file: &Path) -> Vec<ResolvedImport> {
        let cache_key = CacheKey::new(import, current_file);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            self.cache_hits += 1;
            return Arc::clone(cached).as_ref().clone();
        }

        self.cache_misses += 1;

        // Perform resolution
        let resolved = self.resolve_uncached(import, current_file);

        // Cache the result
        let cached = Arc::new(resolved.clone());
        self.cache.put(cache_key, cached);

        resolved
    }

    /// Internal resolution without caching.
    fn resolve_uncached(&mut self, import: &ImportDef, current_file: &Path) -> Vec<ResolvedImport> {
        let language = self.index.language();
        // Determine the actual module to resolve
        let resolved_module = if import.level > 0 {
            // Relative import - resolve the module path first
            match language {
                "python" => match self.resolve_relative(import, current_file) {
                    Some(m) => m,
                    None => {
                        // Relative import beyond root - return empty
                        return vec![];
                    }
                },
                "ruby" | "php" | "lua" | "luau" => {
                    if let Some(m) = self.resolve_file_relative(import, current_file) {
                        m
                    } else {
                        return vec![];
                    }
                }
                _ => match self.resolve_relative(import, current_file) {
                    Some(m) => m,
                    None => {
                        // Relative import beyond root - return empty
                        return vec![];
                    }
                },
            }
        } else {
            // Absolute import — normalize JS/TS extension variants
            // TS projects often import "./foo.js" when the actual file is "foo.ts"
            let module = &import.module;
            let stripped = module
                .strip_suffix(".js")
                .or_else(|| module.strip_suffix(".jsx"))
                .or_else(|| module.strip_suffix(".ts"))
                .or_else(|| module.strip_suffix(".tsx"))
                .or_else(|| module.strip_suffix(".mjs"))
                .or_else(|| module.strip_suffix(".cjs"))
                .or_else(|| module.strip_suffix(".rb"))
                .or_else(|| module.strip_suffix(".php"))
                .or_else(|| module.strip_suffix(".lua"))
                .or_else(|| module.strip_suffix(".luau"));

            let base = match stripped {
                Some(base) => base.to_string(),
                None => module.clone(),
            };

            // Resolve JS/TS/Go relative paths (./foo, ../bar) to project-relative module names
            if base.starts_with("./") || base.starts_with("../") {
                match language {
                    "typescript" | "javascript" | "go" => {
                        match self.resolve_js_relative_path(&base, current_file) {
                            Some(resolved) => resolved,
                            None => base,
                        }
                    }
                    "ruby" | "php" | "lua" | "luau" | "c" | "cpp" => self
                        .resolve_file_path_import(&base, current_file)
                        .unwrap_or(base),
                    _ => base,
                }
            } else {
                // Luau script-based requires (script.Parent.Module)
                if language == "luau" {
                    if let Some(resolved) = self.resolve_luau_script_path(&base, current_file) {
                        resolved
                    } else {
                        base
                    }
                } else if matches!(language, "ruby" | "php" | "lua" | "c" | "cpp")
                    && looks_like_file_path(&base)
                {
                    self.resolve_file_path_import(&base, current_file)
                        .unwrap_or(base)
                } else {
                    base
                }
            }
        };

        // Check if this is a project module
        if !self.index.is_project_module(&resolved_module) {
            // External module - return empty
            return vec![];
        }

        // Look up the file path
        let module_file = match self.index.lookup(&resolved_module) {
            Some(path) => path.to_path_buf(),
            None => {
                // Module not found in index
                return vec![];
            }
        };

        // Determine import kind
        let kind = self.classify_import(import);

        // Handle wildcard imports
        if import.is_wildcard() {
            return self.resolve_wildcard(import, &resolved_module, &module_file);
        }

        // Build resolved imports for each name
        let mut results = Vec::with_capacity(import.names.len());

        if import.is_from {
            // from X import Y, Z
            for name in &import.names {
                // Python: "from pkg import submod" resolves to submodule if it exists.
                if language == "python" {
                    let candidate = if resolved_module.is_empty() {
                        name.clone()
                    } else {
                        format!("{}.{}", resolved_module, name)
                    };
                    if self.index.is_project_module(&candidate) {
                        if let Some(candidate_file) = self.index.lookup(&candidate) {
                            let mut original = import.clone();
                            original.resolved_module = Some(candidate.clone());
                            let resolved = ResolvedImport {
                                original,
                                resolved_file: Some(candidate_file.to_path_buf()),
                                resolved_name: Some(name.clone()),
                                is_external: false,
                                confidence: self.compute_confidence(kind),
                            };
                            results.push(resolved);
                            continue;
                        }
                    }
                }

                let mut original = import.clone();
                original.resolved_module = Some(resolved_module.clone());
                let resolved = ResolvedImport {
                    original,
                    resolved_file: Some(module_file.clone()),
                    resolved_name: Some(name.clone()),
                    is_external: false,
                    confidence: self.compute_confidence(kind),
                };
                results.push(resolved);
            }
        } else {
            // import X or import X as Y
            let mut original = import.clone();
            original.resolved_module = Some(resolved_module.clone());
            let resolved = ResolvedImport {
                original,
                resolved_file: Some(module_file.clone()),
                resolved_name: Some(resolved_module.clone()),
                is_external: false,
                confidence: self.compute_confidence(kind),
            };
            results.push(resolved);
        }

        results
    }

    /// Resolve a JS/TS/Go-style relative path (`./foo`, `../bar`) to a module name.
    ///
    /// TypeScript/JavaScript imports use filesystem-relative paths like `./errors`
    /// or `../utils/helpers`. These need to be resolved relative to the importing
    /// file's directory and then mapped to the module names stored in ModuleIndex.
    ///
    /// # Arguments
    ///
    /// * `module` - The import path after extension stripping (e.g., `./errors`, `../utils/helpers`)
    /// * `current_file` - Absolute path of the file containing the import
    ///
    /// # Returns
    ///
    /// The resolved module name as stored in ModuleIndex, or `None` if resolution fails.
    fn resolve_js_relative_path(&self, module: &str, current_file: &Path) -> Option<String> {
        let project_root = self.index.project_root();
        let language = self.index.language();

        // Canonicalize current_file to match the canonicalized project_root
        // (on macOS, /tmp -> /private/tmp, /var -> /private/var)
        let canonical_file =
            dunce::canonicalize(current_file).unwrap_or_else(|_| current_file.to_path_buf());

        // Get the relative path of current_file from project root
        let rel_current = canonical_file.strip_prefix(project_root).ok()?;
        let from_dir = rel_current
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();

        let resolved = if let Some(rest) = module.strip_prefix("./") {
            // Handle ./ prefix: resolve relative to importing file's directory
            if from_dir.is_empty() {
                rest.to_string()
            } else {
                format!("{}/{}", from_dir, rest)
            }
        } else if module.starts_with("../") {
            // Handle ../ prefix: navigate up directories
            let parts: Vec<&str> = if from_dir.is_empty() {
                vec![]
            } else {
                from_dir.split('/').collect()
            };
            let mut dir_parts = parts;
            let import_segments: Vec<&str> = module.split('/').collect();
            let mut remaining = &import_segments[..];

            while !remaining.is_empty() && remaining[0] == ".." {
                remaining = &remaining[1..];
                if dir_parts.is_empty() {
                    // Trying to navigate above project root
                    return None;
                }
                dir_parts.pop();
            }

            let rest: Vec<&str> = remaining.to_vec();
            let mut all_parts = dir_parts;
            all_parts.extend(rest);
            all_parts.join("/")
        } else {
            // Not a relative path - should not reach here
            return None;
        };

        // TypeScript modules in ModuleIndex are stored with "./" prefix (e.g., "./v4/core/errors")
        // Go modules are stored without prefix (e.g., "pkg", "utils")
        match language {
            "typescript" | "javascript" => Some(format!("./{}", resolved)),
            "go" => Some(resolved),
            _ => Some(format!("./{}", resolved)),
        }
    }

    /// Resolve a file-path style import relative to the current file or project root.
    ///
    /// Supports languages where imports are file paths (Ruby/PHP/Lua/Luau/C/C++).
    fn resolve_file_path_import(&self, module: &str, current_file: &Path) -> Option<String> {
        let language = self.index.language();
        let module_path = module.trim_start_matches("./");

        let mut candidates = Vec::new();
        if let Some(dir) = current_file.parent() {
            candidates.extend(self.file_candidates_for_module(dir, module_path, language));
        }
        let root = self.index.project_root();
        candidates.extend(self.file_candidates_for_module(root, module_path, language));

        for candidate in candidates {
            if let Some(resolved) = self.index.reverse_lookup(&candidate) {
                return Some(resolved.to_string());
            }
        }

        None
    }

    /// Resolve relative imports for file-path languages using level semantics.
    fn resolve_file_relative(&self, import: &ImportDef, current_file: &Path) -> Option<String> {
        let mut module = import.module.clone();
        if import.level > 1 && !module.starts_with("../") {
            let prefix = "../".repeat((import.level - 1) as usize);
            module = format!("{}{}", prefix, module);
        }
        self.resolve_file_path_import(&module, current_file)
    }

    /// Resolve Luau script-based require paths (script.Parent.Module).
    fn resolve_luau_script_path(&self, module: &str, current_file: &Path) -> Option<String> {
        if !module.starts_with("script") {
            return None;
        }

        let mut parts = module.split('.').collect::<Vec<_>>();
        if parts.is_empty() || parts[0] != "script" {
            return None;
        }
        parts.remove(0);

        let mut base_dir = current_file.parent()?;
        while !parts.is_empty() && parts[0] == "Parent" {
            base_dir = base_dir.parent()?;
            parts.remove(0);
        }
        if parts.is_empty() {
            return None;
        }

        let rel = parts.join("/");
        let language = self.index.language();
        let candidates = self.file_candidates_for_module(base_dir, &rel, language);
        for candidate in candidates {
            if let Some(resolved) = self.index.reverse_lookup(&candidate) {
                return Some(resolved.to_string());
            }
        }

        None
    }

    fn file_candidates_for_module(
        &self,
        base_dir: &Path,
        module: &str,
        language: &str,
    ) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let module_path = Path::new(module);
        if module_path.extension().is_some() {
            candidates.push(base_dir.join(module_path));
            return candidates;
        }

        for ext in language_extensions(language) {
            candidates.push(base_dir.join(module_path).with_extension(ext));
        }

        candidates
    }

    /// Resolve a relative import (Python-specific).
    ///
    /// Implements PEP 328 semantics:
    /// - `from . import X` → current package
    /// - `from .. import X` → parent package
    /// - `from ...pkg import X` → grandparent.pkg
    ///
    /// # Arguments
    ///
    /// * `import` - The import definition (must have `level > 0`)
    /// * `current_file` - The file containing the import
    ///
    /// # Returns
    ///
    /// The absolute module path, or `None` if the relative import goes beyond root.
    pub fn resolve_relative(&self, import: &ImportDef, current_file: &Path) -> Option<String> {
        if import.level == 0 {
            // Not a relative import
            return Some(import.module.clone());
        }

        // Get the module path of the current file
        let current_module = self.index.reverse_lookup(current_file)?;

        // Determine if we're in a package (__init__.py) or a module
        let is_init = current_file
            .file_name()
            .map(|n| n == "__init__.py")
            .unwrap_or(false);

        // Parse the current module into parts
        let parts: Vec<&str> = current_module.split('.').collect();

        // For __init__.py, the module IS the package
        // For other files, the package is parent of the module
        let package_depth = if is_init {
            parts.len()
        } else {
            parts.len() - 1
        };

        // Calculate how many levels to go up
        // level=1 means current package, level=2 means parent, etc.
        let levels_up = import.level as usize - 1;

        if levels_up > package_depth {
            // Trying to go above root
            return None;
        }

        // Build the base module path
        let base_parts = &parts[..package_depth - levels_up];

        // Combine with the import module
        let mut result_parts: Vec<&str> = base_parts.to_vec();

        // Add the imported module parts if any
        if !import.module.is_empty() {
            for part in import.module.split('.') {
                result_parts.push(part);
            }
        }

        // For "from . import X" where X is a name (not module), we need the package
        // But for "from .subpkg import X" we need pkg.subpkg
        if result_parts.is_empty() {
            return None;
        }

        Some(result_parts.join("."))
    }

    /// Resolve a wildcard import by expanding __all__.
    fn resolve_wildcard(
        &mut self,
        import: &ImportDef,
        _resolved_module: &str,
        module_file: &Path,
    ) -> Vec<ResolvedImport> {
        // Get or parse __all__ for this module
        let names = self.expand_wildcard(module_file);

        // Build resolved imports for each name
        names
            .iter()
            .map(|name| {
                let mut modified_import = import.clone();
                modified_import.names = vec![name.clone()];

                ResolvedImport {
                    original: modified_import,
                    resolved_file: Some(module_file.to_path_buf()),
                    resolved_name: Some(name.clone()),
                    is_external: false,
                    confidence: 0.4, // Lower confidence for wildcard expansion
                }
            })
            .collect()
    }

    /// Expand a wildcard import by parsing __all__ from the module.
    ///
    /// Results are cached per module to avoid repeated parsing.
    fn expand_wildcard(&mut self, module_file: &Path) -> Arc<Vec<String>> {
        // Check cache
        if let Some(cached) = self.all_cache.get(module_file) {
            return Arc::clone(cached);
        }

        // Parse __all__ from the file
        let names = self.parse_all(module_file);
        let cached = Arc::new(names);
        self.all_cache
            .insert(module_file.to_path_buf(), Arc::clone(&cached));

        cached
    }

    /// Parse __all__ from a Python file.
    ///
    /// Looks for patterns like:
    /// - `__all__ = ['Foo', 'Bar']`
    /// - `__all__ = ["Foo", "Bar"]`
    /// - Multi-line:
    ///   ```ignore
    ///   __all__ = [
    ///       'Foo',
    ///       'Bar',
    ///   ]
    ///   ```
    ///
    /// infra-tail-issues-v1 (#58, v0.4.2 M-108): pre-fix this parser
    /// required `[` and `]` on the same trimmed line, so a multi-line
    /// `__all__` literal — the canonical Python convention when
    /// exporting more than a handful of names — produced an empty
    /// list and the wildcard import resolver dropped every name. The
    /// `interface` AST-based parser already handled this correctly,
    /// causing cross-pipeline drift. The new implementation extracts
    /// the full bracket span (single- or multi-line) and uses the
    /// shared `extract_dunder_all_names` helper that
    /// `parse_dunder_all` also relies on.
    fn parse_all(&self, module_file: &Path) -> Vec<String> {
        // Read the file
        let content = match std::fs::read_to_string(module_file) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        extract_dunder_all_names_vec(&content)
    }

    /// Classify an import into its kind.
    fn classify_import(&self, import: &ImportDef) -> ImportKind {
        if import.is_type_checking {
            ImportKind::TypeOnly
        } else if import.is_wildcard() {
            ImportKind::Wildcard
        } else if import.level > 0 {
            ImportKind::Relative
        } else {
            ImportKind::Absolute
        }
    }

    /// Compute confidence based on import kind.
    fn compute_confidence(&self, kind: ImportKind) -> f32 {
        match kind {
            ImportKind::Absolute => 1.0,
            ImportKind::Relative => 0.9,
            ImportKind::TypeOnly => 1.0,
            ImportKind::Wildcard => 0.4,
        }
    }

    /// Clear the resolution cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.all_cache.clear();
        self.cache_hits = 0;
        self.cache_misses = 0;
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            hits: self.cache_hits,
            misses: self.cache_misses,
            entries: self.cache.len(),
            capacity: self.cache.cap().get(),
        }
    }

    /// Get reference to the underlying module index.
    pub fn module_index(&self) -> &ModuleIndex {
        self.index
    }
}

// =============================================================================
// Re-Export Tracer
// =============================================================================

/// Maximum default depth for re-export tracing.
pub const DEFAULT_MAX_DEPTH: usize = 10;

/// Result of tracing a re-export.
#[derive(Debug, Clone, PartialEq)]
pub struct TracedReExport {
    /// File where the definition is located
    pub definition_file: PathBuf,
    /// Qualified name in the definition file
    pub qualified_name: String,
    /// Number of hops in the re-export chain
    pub depth: usize,
}

/// Re-export tracer for following re-export chains.
///
/// When a name is imported from a package, it may be re-exported from
/// another module. This tracer follows the chain to find the original
/// definition.
pub struct ReExportTracer<'a> {
    /// Reference to the module index
    index: &'a ModuleIndex,
    /// Memoization cache for traced re-exports
    cache: HashMap<(String, String), Option<TracedReExport>>,
    /// Cache hit count
    cache_hits: usize,
    /// Cache miss count
    cache_misses: usize,
}

impl<'a> ReExportTracer<'a> {
    /// Creates a new ReExportTracer.
    pub fn new(index: &'a ModuleIndex) -> Self {
        Self {
            index,
            cache: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Trace a re-export to its original definition.
    ///
    /// # Arguments
    ///
    /// * `module_path` - Module to start from
    /// * `name` - Name to trace
    /// * `max_depth` - Maximum chain depth (default 10)
    ///
    /// # Returns
    ///
    /// The traced re-export, or `None` if:
    /// - Module is not in project
    /// - Circular re-export detected
    /// - Max depth exceeded
    /// - Name not found
    pub fn trace(
        &mut self,
        module_path: &str,
        name: &str,
        max_depth: usize,
    ) -> Option<TracedReExport> {
        // Check cache
        let cache_key = (module_path.to_string(), name.to_string());
        if let Some(cached) = self.cache.get(&cache_key) {
            self.cache_hits += 1;
            return cached.clone();
        }
        self.cache_misses += 1;

        // Trace with cycle detection
        let mut visited = std::collections::HashSet::new();
        let result = self.trace_internal(module_path, name, max_depth, &mut visited);

        // Cache the result
        self.cache.insert(cache_key, result.clone());

        result
    }

    /// Internal trace with cycle detection.
    fn trace_internal(
        &self,
        module_path: &str,
        name: &str,
        max_depth: usize,
        visited: &mut std::collections::HashSet<(String, String)>,
    ) -> Option<TracedReExport> {
        // Check for cycle
        let key = (module_path.to_string(), name.to_string());
        if visited.contains(&key) {
            // Circular re-export detected
            return None;
        }

        // Check depth
        if visited.len() >= max_depth {
            // Max depth exceeded
            return None;
        }

        // Mark as visited
        visited.insert(key);

        // Look up the module file
        let module_file = self.index.lookup(module_path)?;

        // Check if this is a package (__init__.py)
        let is_package = module_file
            .file_name()
            .map(|n| n == "__init__.py")
            .unwrap_or(false);

        if !is_package {
            // Not a package - name is defined here (or doesn't exist)
            return Some(TracedReExport {
                definition_file: module_file.to_path_buf(),
                qualified_name: name.to_string(),
                depth: visited.len(),
            });
        }

        // Parse __init__.py for re-exports
        let reexports = self.parse_init_reexports(module_file);

        // Check if name is re-exported
        if let Some((source_module, source_name)) = reexports.get(name) {
            // Recursively trace
            return self.trace_internal(source_module, source_name, max_depth, visited);
        }

        // Check if name is defined locally in __init__.py
        if self.is_defined_locally(module_file, name) {
            return Some(TracedReExport {
                definition_file: module_file.to_path_buf(),
                qualified_name: name.to_string(),
                depth: visited.len(),
            });
        }

        // Name not found
        None
    }

    /// Parse __init__.py for re-export patterns.
    ///
    /// Looks for patterns like:
    /// - `from .module import Name`
    /// - `from .module import Name as Alias`
    fn parse_init_reexports(&self, init_file: &Path) -> HashMap<String, (String, String)> {
        let mut reexports = HashMap::new();

        let content = match std::fs::read_to_string(init_file) {
            Ok(c) => c,
            Err(_) => return reexports,
        };
        let export_filter = parse_dunder_all(&content);

        // Get the package module path
        let package_module = match self.index.reverse_lookup(init_file) {
            Some(m) => m.to_string(),
            None => return reexports,
        };

        // Simple parsing for "from .X import Y" patterns
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("from ") {
                continue;
            }

            // Parse "from .X import Y" or "from .X import Y as Z"
            if let Some(import_pos) = trimmed.find(" import ") {
                let from_part = &trimmed[5..import_pos].trim();
                let import_part = &trimmed[import_pos + 8..].trim();

                // Handle relative imports
                if from_part.starts_with('.') {
                    let dots = from_part.chars().take_while(|c| *c == '.').count();
                    let module_rest = from_part[dots..].trim();

                    // Compute base module by walking up for leading dots.
                    let base_module = if dots <= 1 {
                        package_module.clone()
                    } else {
                        let mut parts: Vec<&str> = package_module.split('.').collect();
                        let levels_up = dots - 1;
                        if parts.len() >= levels_up {
                            parts.truncate(parts.len() - levels_up);
                        }
                        parts.join(".")
                    };

                    // Parse imported names
                    for item in import_part.split(',') {
                        let item = item.trim();

                        // Handle "Name as Alias"
                        let (original_name, alias) = if let Some(as_pos) = item.find(" as ") {
                            let original = item[..as_pos].trim();
                            let alias = item[as_pos + 4..].trim();
                            (original, alias)
                        } else {
                            (item, item)
                        };

                        let source_module = if module_rest.is_empty() {
                            // from . import Foo  (or from .. import Foo)
                            // If Foo is a submodule, point to that module; otherwise treat as symbol in base module.
                            let candidate = if base_module.is_empty() {
                                original_name.to_string()
                            } else {
                                format!("{}.{}", base_module, original_name)
                            };
                            if self.index.is_project_module(&candidate) {
                                candidate
                            } else {
                                base_module.clone()
                            }
                        } else if base_module.is_empty() {
                            module_rest.to_string()
                        } else {
                            format!("{}.{}", base_module, module_rest)
                        };

                        if !export_filter.is_empty() && !export_filter.contains(alias) {
                            continue;
                        }
                        // Map alias -> (source_module, original_name)
                        reexports.insert(
                            alias.to_string(),
                            (source_module.clone(), original_name.to_string()),
                        );
                    }
                }
            }
        }

        reexports
    }

    /// Check if a name is defined locally in a file.
    ///
    /// Looks for class and function definitions.
    fn is_defined_locally(&self, file: &Path, name: &str) -> bool {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Simple check for class or function definitions
        let class_pattern = format!("class {}:", name);
        let class_pattern2 = format!("class {}(", name);
        let def_pattern = format!("def {}(", name);
        let assign_pattern = format!("{} =", name);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(&class_pattern)
                || trimmed.starts_with(&class_pattern2)
                || trimmed.starts_with(&def_pattern)
                || trimmed.starts_with(&assign_pattern)
            {
                return true;
            }
        }

        false
    }

    /// Clear the trace cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_hits = 0;
        self.cache_misses = 0;
    }

    /// Get cache statistics (hits, misses).
    ///
    /// Returns a tuple of (cache_hits, cache_misses).
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache_hits, self.cache_misses)
    }
}

fn parse_dunder_all(content: &str) -> HashSet<String> {
    // infra-tail-issues-v1 (#58, v0.4.2 M-108): rewritten to use the
    // shared multi-line extractor. Pre-fix this scanned line-by-line
    // and required `[` and `]` to coexist on the same trimmed line, so
    // a multi-line `__all__` literal silently produced an empty
    // export set, which made the re-export tracer (`parse_init_reexports`)
    // drop every `from .X import Y` name that should have been
    // filtered through `__all__`.
    extract_dunder_all_names_vec(content).into_iter().collect()
}

/// Extract names declared in a Python `__all__` assignment, supporting
/// both single-line (`__all__ = ['a', 'b']`) and multi-line
/// (`__all__ = [\n    'a',\n    'b',\n]`) literals using either `[]`
/// or `()` as the container.
///
/// Returns a Vec to preserve declaration order (callers that need a
/// set wrap via `.into_iter().collect()`).
///
/// Algorithm:
///   1. Find the start of an `__all__` assignment via a textual scan.
///   2. Locate the opening bracket (`[` or `(`) at or after the `=`.
///   3. Walk forward keeping a bracket-depth counter, ignoring
///      brackets inside string literals (single or double quoted,
///      including escapes).
///   4. Split the captured span on `,` and strip surrounding quotes.
///
/// This is a deliberately tolerant text parser (not an AST walker) so
/// it works without pulling tree-sitter into the resolver. It matches
/// the textual heuristics already used elsewhere in this module for
/// `from .X import Y` parsing (`parse_init_reexports` L897), keeping
/// the layer architecture consistent.
fn extract_dunder_all_names_vec(content: &str) -> Vec<String> {
    let bytes = content.as_bytes();
    let mut search_start = 0usize;
    let mut names: Vec<String> = Vec::new();

    loop {
        let rest = match content.get(search_start..) {
            Some(r) => r,
            None => break,
        };
        let rel = match rest.find("__all__") {
            Some(idx) => idx,
            None => break,
        };
        let dunder_at = search_start + rel;

        // Cheap sanity: __all__ must start at line head (modulo
        // whitespace) — avoid matching the substring inside a comment
        // or string. Walk back to the previous newline.
        let line_start = content[..dunder_at]
            .rfind('\n')
            .map(|nl| nl + 1)
            .unwrap_or(0);
        let prefix = &content[line_start..dunder_at];
        if !prefix.chars().all(|c| c.is_whitespace()) {
            search_start = dunder_at + "__all__".len();
            continue;
        }

        // Find `=` after `__all__`.
        let after_dunder = dunder_at + "__all__".len();
        let eq_rel = match content[after_dunder..].find('=') {
            Some(idx) => idx,
            None => break,
        };
        let eq_at = after_dunder + eq_rel;

        // Find opening bracket `[` or `(` after `=`.
        let mut open_at: Option<usize> = None;
        let mut open_kind: u8 = 0;
        for (i, &b) in bytes.iter().enumerate().skip(eq_at + 1) {
            match b {
                b' ' | b'\t' | b'\r' | b'\n' => continue,
                b'[' => {
                    open_at = Some(i);
                    open_kind = b'[';
                    break;
                }
                b'(' => {
                    open_at = Some(i);
                    open_kind = b'(';
                    break;
                }
                _ => break,
            }
        }
        let open_at = match open_at {
            Some(p) => p,
            None => {
                search_start = eq_at + 1;
                continue;
            }
        };
        let close_kind = if open_kind == b'[' { b']' } else { b')' };

        // Bracket-balanced walk to find the matching close, ignoring
        // brackets inside string literals.
        let mut close_at: Option<usize> = None;
        let mut depth: i32 = 1;
        let mut i = open_at + 1;
        let mut in_str: Option<u8> = None;
        let mut escape = false;
        while i < bytes.len() {
            let b = bytes[i];
            if let Some(quote) = in_str {
                if escape {
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == quote {
                    in_str = None;
                }
            } else {
                match b {
                    b'"' | b'\'' => in_str = Some(b),
                    b'#' => {
                        // Skip rest-of-line comment.
                        while i < bytes.len() && bytes[i] != b'\n' {
                            i += 1;
                        }
                        continue;
                    }
                    b'[' | b'(' => depth += 1,
                    b']' | b')' => {
                        if b == close_kind {
                            depth -= 1;
                            if depth == 0 {
                                close_at = Some(i);
                                break;
                            }
                        } else {
                            depth -= 1;
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        let close_at = match close_at {
            Some(p) => p,
            None => break,
        };

        // Extract names inside the bracket span.
        let inner = &content[open_at + 1..close_at];
        for item in split_dunder_all_items(inner) {
            let name = item
                .trim()
                .trim_matches(|c: char| c == '"' || c == '\'')
                .trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                names.push(name.to_string());
            }
        }

        // Stop after the first match — the resolver expects the FIRST
        // top-level __all__ to define the public surface.
        return names;
    }
    names
}

/// Split a `__all__` body on top-level commas, respecting string
/// literals so a comma inside `"foo, bar"` does not produce an
/// erroneous split.
fn split_dunder_all_items(inner: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let bytes = inner.as_bytes();
    let mut start = 0usize;
    let mut in_str: Option<u8> = None;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b',' => {
                    items.push(&inner[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
    }
    if start < bytes.len() {
        items.push(&inner[start..]);
    }
    items
}

fn looks_like_file_path(module: &str) -> bool {
    module.contains('/')
        || module.contains('\\')
        || module.ends_with(".h")
        || module.ends_with(".hpp")
}

fn language_extensions(language: &str) -> &'static [&'static str] {
    match language {
        "ruby" => &["rb"],
        "php" => &["php"],
        "lua" => &["lua"],
        "luau" => &["luau", "lua"],
        "c" => &["c", "h"],
        "cpp" => &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "h"],
        _ => &[],
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_project() -> (TempDir, ModuleIndex) {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a simple package structure:
        // pkg/__init__.py
        // pkg/module.py
        // pkg/sub/__init__.py
        // pkg/sub/impl.py
        // main.py

        std::fs::create_dir_all(root.join("pkg/sub")).unwrap();

        std::fs::write(
            root.join("pkg/__init__.py"),
            "from .module import MyClass\n__all__ = ['MyClass']\n",
        )
        .unwrap();

        std::fs::write(
            root.join("pkg/module.py"),
            "class MyClass:\n    pass\n\ndef helper():\n    pass\n",
        )
        .unwrap();

        std::fs::write(
            root.join("pkg/sub/__init__.py"),
            "from .impl import SubClass\n",
        )
        .unwrap();

        std::fs::write(root.join("pkg/sub/impl.py"), "class SubClass:\n    pass\n").unwrap();

        std::fs::write(
            root.join("main.py"),
            "from pkg import MyClass\nfrom pkg.module import helper\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "python").unwrap();

        (temp, index)
    }

    #[test]
    fn test_resolve_absolute_import() {
        let (_temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("pkg.module", vec!["MyClass".to_string()]);
        let resolved = resolver.resolve(&import, Path::new("main.py"));

        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].is_external);
        assert_eq!(resolved[0].resolved_name, Some("MyClass".to_string()));
    }

    #[test]
    fn test_resolve_relative_import() {
        let (temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        // from . import module (from pkg/module.py)
        let import = ImportDef::relative_import("module", vec!["MyClass".to_string()], 1);
        let current_file = temp.path().join("pkg/__init__.py");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].is_external);
    }

    #[test]
    fn test_resolve_relative_import_level_2() {
        let (temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        // from ..module import MyClass (from pkg/sub/impl.py)
        let import = ImportDef::relative_import("module", vec!["MyClass".to_string()], 2);
        let current_file = temp.path().join("pkg/sub/impl.py");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].is_external);
    }

    #[test]
    fn test_resolve_external_module() {
        let (_temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::simple_import("os");
        let resolved = resolver.resolve(&import, Path::new("main.py"));

        assert!(resolved.is_empty()); // External modules return empty
    }

    #[test]
    fn test_resolve_wildcard() {
        let (temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        // from pkg import *
        let import = ImportDef::wildcard_import("pkg");
        let current_file = temp.path().join("main.py");
        let resolved = resolver.resolve(&import, &current_file);

        // Should expand to names in __all__
        let names: Vec<_> = resolved
            .iter()
            .filter_map(|r| r.resolved_name.as_ref())
            .collect();
        assert!(names.contains(&&"MyClass".to_string()));
    }

    #[test]
    fn test_cache_hit() {
        let (_temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("pkg.module", vec!["MyClass".to_string()]);

        // First call
        let _ = resolver.resolve(&import, Path::new("main.py"));
        assert_eq!(resolver.cache_stats().hits, 0);
        assert_eq!(resolver.cache_stats().misses, 1);

        // Second call - should hit cache
        let _ = resolver.resolve(&import, Path::new("main.py"));
        assert_eq!(resolver.cache_stats().hits, 1);
        assert_eq!(resolver.cache_stats().misses, 1);
    }

    #[test]
    fn test_resolve_relative_module_basic() {
        let (temp, index) = create_test_project();
        let resolver = ImportResolver::new(&index, 100);

        // from . import module (from pkg/__init__.py)
        let import = ImportDef::relative_import("module", vec![], 1);
        let current_file = temp.path().join("pkg/__init__.py");
        let result = resolver.resolve_relative(&import, &current_file);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), "pkg.module");
    }

    #[test]
    fn test_resolve_relative_beyond_root() {
        let (temp, index) = create_test_project();
        let resolver = ImportResolver::new(&index, 100);

        // from ..... import X (way too many levels)
        let import = ImportDef::relative_import("X", vec![], 10);
        let current_file = temp.path().join("pkg/module.py");
        let result = resolver.resolve_relative(&import, &current_file);

        assert!(result.is_none());
    }

    #[test]
    fn test_reexport_tracer_single() {
        let (_temp, index) = create_test_project();
        let mut tracer = ReExportTracer::new(&index);

        // pkg re-exports MyClass from pkg.module
        let result = tracer.trace("pkg", "MyClass", 10);

        assert!(result.is_some());
        let traced = result.unwrap();
        assert!(traced.definition_file.ends_with("module.py"));
        assert_eq!(traced.qualified_name, "MyClass");
    }

    #[test]
    fn test_reexport_tracer_defined_in_init() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a package where the class is defined in __init__.py
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        std::fs::write(
            root.join("pkg/__init__.py"),
            "class LocalClass:\n    pass\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "python").unwrap();
        let mut tracer = ReExportTracer::new(&index);

        let result = tracer.trace("pkg", "LocalClass", 10);

        assert!(result.is_some());
        let traced = result.unwrap();
        assert!(traced.definition_file.ends_with("__init__.py"));
    }

    #[test]
    fn test_reexport_tracer_not_found() {
        let (_temp, index) = create_test_project();
        let mut tracer = ReExportTracer::new(&index);

        let result = tracer.trace("pkg", "NonExistent", 10);

        assert!(result.is_none());
    }

    #[test]
    fn test_reexport_tracer_external() {
        let (_temp, index) = create_test_project();
        let mut tracer = ReExportTracer::new(&index);

        let result = tracer.trace("os", "path", 10);

        assert!(result.is_none()); // External module not in project
    }

    #[test]
    fn test_reexport_tracer_chain() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a chain: pkg re-exports from pkg.sub, which re-exports from pkg.sub.impl
        // pkg/__init__.py: from .sub import DeepClass
        // pkg/sub/__init__.py: from .impl import DeepClass
        // pkg/sub/impl.py: class DeepClass: ...
        std::fs::create_dir_all(root.join("pkg/sub")).unwrap();

        std::fs::write(root.join("pkg/__init__.py"), "from .sub import DeepClass\n").unwrap();

        std::fs::write(
            root.join("pkg/sub/__init__.py"),
            "from .impl import DeepClass\n",
        )
        .unwrap();

        std::fs::write(root.join("pkg/sub/impl.py"), "class DeepClass:\n    pass\n").unwrap();

        let index = ModuleIndex::build(root, "python").unwrap();
        let mut tracer = ReExportTracer::new(&index);

        let result = tracer.trace("pkg", "DeepClass", 10);

        assert!(result.is_some());
        let traced = result.unwrap();
        assert!(traced.definition_file.ends_with("impl.py"));
        assert_eq!(traced.qualified_name, "DeepClass");
        assert!(traced.depth >= 2); // At least 2 hops
    }

    #[test]
    fn test_reexport_tracer_circular() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a circular re-export using packages (not modules):
        // pkg/a/__init__.py: from ..b import X
        // pkg/b/__init__.py: from ..a import X
        std::fs::create_dir_all(root.join("pkg/a")).unwrap();
        std::fs::create_dir_all(root.join("pkg/b")).unwrap();

        std::fs::write(root.join("pkg/__init__.py"), "").unwrap();

        std::fs::write(root.join("pkg/a/__init__.py"), "from ..b import X\n").unwrap();

        std::fs::write(root.join("pkg/b/__init__.py"), "from ..a import X\n").unwrap();

        let index = ModuleIndex::build(root, "python").unwrap();
        let mut tracer = ReExportTracer::new(&index);

        // Tracing X from pkg.a should detect the circular dependency
        let result = tracer.trace("pkg.a", "X", 10);

        // Circular re-export should return None
        assert!(result.is_none());
    }

    #[test]
    fn test_reexport_tracer_max_depth_exceeded() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a chain of 5 re-exports: pkg -> a -> b -> c -> d -> e (impl)
        // With max_depth=3, it should fail
        std::fs::create_dir_all(root.join("pkg/a/b/c/d/e")).unwrap();

        std::fs::write(root.join("pkg/__init__.py"), "from .a import X\n").unwrap();
        std::fs::write(root.join("pkg/a/__init__.py"), "from .b import X\n").unwrap();
        std::fs::write(root.join("pkg/a/b/__init__.py"), "from .c import X\n").unwrap();
        std::fs::write(root.join("pkg/a/b/c/__init__.py"), "from .d import X\n").unwrap();
        std::fs::write(root.join("pkg/a/b/c/d/__init__.py"), "from .e import X\n").unwrap();
        std::fs::write(
            root.join("pkg/a/b/c/d/e/__init__.py"),
            "class X:\n    pass\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "python").unwrap();

        // With max_depth=3, should fail (need fresh tracer to avoid cache)
        let mut tracer1 = ReExportTracer::new(&index);
        let result = tracer1.trace("pkg", "X", 3);
        assert!(result.is_none());

        // With max_depth=10, should succeed (fresh tracer to avoid cached failure)
        let mut tracer2 = ReExportTracer::new(&index);
        let result = tracer2.trace("pkg", "X", 10);
        assert!(result.is_some());
        let traced = result.unwrap();
        assert!(traced.definition_file.ends_with("__init__.py"));
        assert_eq!(traced.qualified_name, "X");
    }

    #[test]
    fn test_reexport_tracer_cache_stats() {
        let (_temp, index) = create_test_project();
        let mut tracer = ReExportTracer::new(&index);

        // Initial stats should be 0
        let (hits, misses) = tracer.cache_stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 0);

        // First trace - cache miss
        let _ = tracer.trace("pkg", "MyClass", 10);
        let (hits, misses) = tracer.cache_stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 1);

        // Second trace same key - cache hit
        let _ = tracer.trace("pkg", "MyClass", 10);
        let (hits, misses) = tracer.cache_stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    // =========================================================================
    // TypeScript relative path resolution tests
    // =========================================================================

    fn create_ts_test_project() -> (TempDir, ModuleIndex) {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a TypeScript project structure:
        // v4/core/errors.ts
        // v4/core/parse.ts
        // v4/core/schemas.ts
        // v4/core/index.ts
        // utils/helpers.ts
        // utils/format.ts
        // main.ts

        std::fs::create_dir_all(root.join("v4/core")).unwrap();
        std::fs::create_dir_all(root.join("utils")).unwrap();

        std::fs::write(
            root.join("v4/core/errors.ts"),
            "export class ZodError {}\nexport function formatError() {}\n",
        )
        .unwrap();

        std::fs::write(
            root.join("v4/core/parse.ts"),
            "import { ZodError } from './errors';\nexport function parse() {}\n",
        )
        .unwrap();

        std::fs::write(
            root.join("v4/core/schemas.ts"),
            "import { parse } from './parse';\nimport { formatError } from './errors';\n",
        )
        .unwrap();

        std::fs::write(
            root.join("v4/core/index.ts"),
            "export { ZodError } from './errors';\nexport { parse } from './parse';\n",
        )
        .unwrap();

        std::fs::write(
            root.join("utils/helpers.ts"),
            "export function helper() {}\n",
        )
        .unwrap();

        std::fs::write(
            root.join("utils/format.ts"),
            "import { helper } from './helpers';\nexport function format() {}\n",
        )
        .unwrap();

        std::fs::write(
            root.join("main.ts"),
            "import { ZodError } from './v4/core/errors';\nimport { helper } from './utils/helpers';\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "typescript").unwrap();
        (temp, index)
    }

    #[test]
    fn test_resolve_ts_dot_slash_import_same_directory() {
        // from './errors' in v4/core/parse.ts should resolve to ./v4/core/errors
        let (temp, index) = create_ts_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("./errors", vec!["ZodError".to_string()]);
        let current_file = temp.path().join("v4/core/parse.ts");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ./errors from v4/core/parse.ts"
        );
        assert!(!resolved[0].is_external);
        assert_eq!(resolved[0].resolved_name, Some("ZodError".to_string()));
    }

    #[test]
    fn test_resolve_ts_dot_slash_import_from_root() {
        // from './v4/core/errors' in main.ts should resolve to ./v4/core/errors
        let (temp, index) = create_ts_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("./v4/core/errors", vec!["ZodError".to_string()]);
        let current_file = temp.path().join("main.ts");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ./v4/core/errors from main.ts"
        );
        assert!(!resolved[0].is_external);
    }

    #[test]
    fn test_resolve_ts_dot_dot_slash_import() {
        // from '../errors' in a hypothetical deeper dir should resolve correctly
        // Use: v4/core/parse.ts imports from '../core/errors' -- but this is unusual.
        // Better: create a file that does import { helper } from '../utils/helpers'
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        std::fs::create_dir_all(root.join("src/sub")).unwrap();
        std::fs::create_dir_all(root.join("src/utils")).unwrap();

        std::fs::write(
            root.join("src/utils/helpers.ts"),
            "export function help() {}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/sub/consumer.ts"),
            "import { help } from '../utils/helpers';\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "typescript").unwrap();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("../utils/helpers", vec!["help".to_string()]);
        let current_file = root.join("src/sub/consumer.ts");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ../utils/helpers from src/sub/consumer.ts"
        );
        assert!(!resolved[0].is_external);
        assert_eq!(resolved[0].resolved_name, Some("help".to_string()));
    }

    #[test]
    fn test_resolve_ts_dot_slash_with_js_extension() {
        // TS often imports './errors.js' but actual file is errors.ts
        let (temp, index) = create_ts_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("./errors.js", vec!["ZodError".to_string()]);
        let current_file = temp.path().join("v4/core/parse.ts");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ./errors.js from v4/core/parse.ts (strip .js)"
        );
        assert!(!resolved[0].is_external);
    }

    #[test]
    fn test_resolve_ts_preserves_python_behavior() {
        // Python imports should not be affected by TS relative path resolution
        let (_temp, index) = create_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("pkg.module", vec!["MyClass".to_string()]);
        let resolved = resolver.resolve(&import, Path::new("main.py"));

        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].is_external);
        assert_eq!(resolved[0].resolved_name, Some("MyClass".to_string()));
    }

    #[test]
    fn test_resolve_ts_multiple_dot_dot_levels() {
        // ../../X resolution
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        std::fs::create_dir_all(root.join("a/b/c")).unwrap();
        std::fs::write(root.join("a/target.ts"), "export function target() {}\n").unwrap();
        std::fs::write(
            root.join("a/b/c/deep.ts"),
            "import { target } from '../../target';\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "typescript").unwrap();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("../../target", vec!["target".to_string()]);
        let current_file = root.join("a/b/c/deep.ts");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ../../target from a/b/c/deep.ts"
        );
        assert!(!resolved[0].is_external);
    }

    #[test]
    fn test_resolve_ts_bare_module_not_affected() {
        // Non-relative imports (bare modules like 'react') should not be affected
        let (temp, index) = create_ts_test_project();
        let mut resolver = ImportResolver::new(&index, 100);

        let import = ImportDef::from_import("react", vec!["useState".to_string()]);
        let current_file = temp.path().join("main.ts");
        let resolved = resolver.resolve(&import, &current_file);

        // 'react' is external, should return empty
        assert!(
            resolved.is_empty(),
            "Bare module 'react' should be external"
        );
    }

    // =========================================================================
    // Go relative path resolution tests
    // =========================================================================

    #[test]
    fn test_resolve_go_dot_slash_import() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Go project:
        // cmd/main.go (package main, imports ./pkg)
        // pkg/handler.go (package pkg)
        // pkg/utils/helpers.go (package utils)
        std::fs::create_dir_all(root.join("cmd")).unwrap();
        std::fs::create_dir_all(root.join("pkg/utils")).unwrap();

        std::fs::write(root.join("cmd/main.go"), "package main\nimport \"./pkg\"\n").unwrap();
        std::fs::write(
            root.join("pkg/handler.go"),
            "package pkg\nimport \"./utils\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("pkg/utils/helpers.go"),
            "package utils\nfunc Help() {}\n",
        )
        .unwrap();

        let index = ModuleIndex::build(root, "go").unwrap();

        // Go stores modules as directory paths without ./ prefix
        assert!(
            index.lookup("cmd").is_some(),
            "Go should index 'cmd' module"
        );
        assert!(
            index.lookup("pkg").is_some(),
            "Go should index 'pkg' module"
        );
        assert!(
            index.lookup("pkg/utils").is_some(),
            "Go should index 'pkg/utils' module"
        );

        let mut resolver = ImportResolver::new(&index, 100);

        // Go import: "./utils" from pkg/handler.go means pkg/utils
        let import = ImportDef::from_import("./utils", vec!["Help".to_string()]);
        let current_file = root.join("pkg/handler.go");
        let resolved = resolver.resolve(&import, &current_file);

        assert_eq!(
            resolved.len(),
            1,
            "Should resolve ./utils from pkg/handler.go to pkg/utils"
        );
        assert!(!resolved[0].is_external);
    }
}
