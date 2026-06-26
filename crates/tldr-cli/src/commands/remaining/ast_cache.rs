//! AST Cache for efficient multi-analysis
//!
//! Provides a caching layer for parsed ASTs to prevent redundant parsing
//! when running multiple sub-analyses on the same file (TIGER-03 mitigation).
//!
//! # Usage
//!
//! ```ignore
//! let mut cache = AstCache::new(100);
//! let tree = cache.get_or_parse(&path, &source)?;
//! // Tree is cached for subsequent calls
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tree_sitter::Tree;

use tldr_core::Language;

use super::error::{RemainingError, RemainingResult};

/// Maximum cache size (number of ASTs to cache)
pub const MAX_CACHE_SIZE: usize = 100;

/// Cache key combining path and modification time
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AstCacheKey {
    pub path: PathBuf,
    pub mtime: Option<SystemTime>,
}

impl AstCacheKey {
    /// Create a new cache key
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Self { path, mtime }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// AST cache with LRU eviction
pub struct AstCache {
    /// Cached trees indexed by path/mtime key
    cache: HashMap<PathBuf, (Option<SystemTime>, Tree)>,
    /// Maximum number of entries
    capacity: usize,
    /// Access order for LRU (most recent last)
    access_order: Vec<PathBuf>,
    /// Statistics
    stats: CacheStats,
}

impl AstCache {
    /// Create a new cache with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: HashMap::new(),
            capacity,
            access_order: Vec::new(),
            stats: CacheStats::default(),
        }
    }

    /// Get or parse a file, caching the result.
    ///
    /// `lang` is the language the caller has already resolved (e.g. honoring
    /// an explicit `--lang` flag). When `None`, the language is detected from
    /// the file extension. This is threaded all the way to the parse so that
    /// every AST-walk runs on a correctly-parsed tree (RC7: the previous
    /// extension-only dispatch defaulted every non-`.rs` file to the Python
    /// grammar, producing misparses for TS/JS/Go/Java/etc.).
    pub fn get_or_parse(
        &mut self,
        path: &Path,
        source: &str,
        lang: Option<Language>,
    ) -> RemainingResult<&Tree> {
        let key = AstCacheKey::new(path);

        // Check if we have a valid cached entry
        if let Some((cached_mtime, _)) = self.cache.get(path) {
            if *cached_mtime == key.mtime {
                self.stats.hits += 1;
                self.update_access_order(path);
                return Ok(&self.cache.get(path).unwrap().1);
            }
        }

        self.stats.misses += 1;

        // Parse the file through the canonical, dialect-aware parser pool.
        let tree = self.parse_source(source, path, lang)?;

        // Evict if at capacity
        while self.cache.len() >= self.capacity {
            self.evict_lru();
        }

        // Insert into cache
        self.cache.insert(path.to_path_buf(), (key.mtime, tree));
        self.access_order.push(path.to_path_buf());

        Ok(&self.cache.get(path).unwrap().1)
    }

    /// Parse source code through the canonical parser pool.
    ///
    /// The language is taken from the caller's hint when present, otherwise
    /// detected from the file path. This delegates to the same
    /// dialect-aware (`TSX`/`JSX`) `parse_with_path` path used by
    /// `tldr resources`/`parse_file`, so `secure`'s AST walks see real
    /// per-grammar node-kinds instead of a Python-default misparse.
    fn parse_source(
        &self,
        source: &str,
        path: &Path,
        lang: Option<Language>,
    ) -> RemainingResult<Tree> {
        let lang = lang
            .or_else(|| Language::from_path(path))
            .ok_or_else(|| RemainingError::parse_error(path, "unsupported language"))?;
        tldr_core::ast::parser::parse_with_path(source, lang, Some(path))
            .map_err(|e| RemainingError::parse_error(path, e.to_string()))
    }

    /// Update access order for LRU
    fn update_access_order(&mut self, path: &Path) {
        if let Some(pos) = self.access_order.iter().position(|p| p == path) {
            self.access_order.remove(pos);
        }
        self.access_order.push(path.to_path_buf());
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        if let Some(path) = self.access_order.first().cloned() {
            self.cache.remove(&path);
            self.access_order.remove(0);
            self.stats.evictions += 1;
        }
    }

    /// Invalidate a specific path
    pub fn invalidate(&mut self, path: &Path) {
        self.cache.remove(path);
        self.access_order.retain(|p| p != path);
    }

    /// Clear the entire cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.access_order.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get current cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for AstCache {
    fn default() -> Self {
        Self::new(MAX_CACHE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_cache_hit() {
        let temp = TempDir::new().unwrap();
        let path = create_test_file(&temp, "test.py", "def foo(): pass");
        let source = fs::read_to_string(&path).unwrap();

        let mut cache = AstCache::new(10);

        // First access - miss
        let _ = cache.get_or_parse(&path, &source, None).unwrap();
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);

        // Second access - hit
        let _ = cache.get_or_parse(&path, &source, None).unwrap();
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_cache_invalidation() {
        let temp = TempDir::new().unwrap();
        let path = create_test_file(&temp, "test.py", "def foo(): pass");
        let source = fs::read_to_string(&path).unwrap();

        let mut cache = AstCache::new(10);

        let _ = cache.get_or_parse(&path, &source, None).unwrap();
        assert_eq!(cache.len(), 1);

        cache.invalidate(&path);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_eviction() {
        let temp = TempDir::new().unwrap();

        let mut cache = AstCache::new(2);

        for i in 0..3 {
            let path = create_test_file(&temp, &format!("test{}.py", i), "def foo(): pass");
            let source = fs::read_to_string(&path).unwrap();
            let _ = cache.get_or_parse(&path, &source, None).unwrap();
        }

        // Should have evicted one entry
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_cache_parses_rust_source() {
        let temp = TempDir::new().unwrap();
        let path = create_test_file(&temp, "lib.rs", "fn main() { println!(\"ok\"); }");
        let source = fs::read_to_string(&path).unwrap();

        let mut cache = AstCache::new(10);
        let tree = cache.get_or_parse(&path, &source, None).unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    /// Count `ERROR` nodes anywhere in the tree (parse-health probe).
    fn count_error_nodes(node: tree_sitter::Node) -> usize {
        let mut count = if node.is_error() { 1 } else { 0 };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            count += count_error_nodes(child);
        }
        count
    }

    /// Does any node in the tree have the given kind?
    fn tree_has_kind(node: tree_sitter::Node, kind: &str) -> bool {
        if node.kind() == kind {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if tree_has_kind(child, kind) {
                return true;
            }
        }
        false
    }

    /// RC7 root-cause guard: a `.ts` snippet parsed with an explicit
    /// TypeScript hint must produce a real TS tree — exposing TS node-kinds
    /// (`call_expression`/`member_expression`) and containing NONE of the
    /// Python node-kinds (`assignment`/`call`) that the old Python-default
    /// dispatch manufactured via error recovery. Locks the dispatch against
    /// silently regressing to a fixed grammar.
    #[test]
    fn test_cache_dispatches_typescript_not_python() {
        let temp = TempDir::new().unwrap();
        let path = create_test_file(
            &temp,
            "x.ts",
            "function f(db){\n  let cur = db.cursor();\n}\n",
        );
        let source = fs::read_to_string(&path).unwrap();

        let mut cache = AstCache::new(10);
        let tree = cache
            .get_or_parse(&path, &source, Some(Language::TypeScript))
            .unwrap();
        let root = tree.root_node();

        // Real TS grammar exposes call_expression / member_expression.
        assert!(
            tree_has_kind(root, "call_expression"),
            "expected TS call_expression in correctly-parsed tree"
        );
        assert!(
            tree_has_kind(root, "member_expression"),
            "expected TS member_expression in correctly-parsed tree"
        );
        // Python node-kinds must NOT appear — their presence is the misparse
        // signature that drove the resource_leak false positive.
        assert!(
            !tree_has_kind(root, "assignment"),
            "Python 'assignment' kind leaked into TS parse (misparse regression)"
        );
        // A clean TS parse of this snippet has no ERROR nodes.
        assert_eq!(
            count_error_nodes(root),
            0,
            "TS snippet should parse without ERROR nodes"
        );
    }
}
