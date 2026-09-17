//! BM25 keyword search implementation
//!
//! Implements BM25 (Best Matching 25) ranking algorithm for code search.
//! Uses code-aware tokenization for camelCase/snake_case splitting.
//!
//! # BM25 Formula
//! ```text
//! score(D, Q) = sum(IDF(qi) * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * |D|/avgdl)))
//! ```
//!
//! Where:
//! - tf: term frequency in document
//! - IDF: inverse document frequency
//! - k1: term frequency saturation parameter (default 1.5)
//! - b: document length normalization parameter (default 0.75)
//! - avgdl: average document length

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use super::tokenizer::Tokenizer;
use crate::fs::tree::DEFAULT_SKIP_DIRS;
use crate::types::Language;
use crate::TldrResult;

/// BM25 search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bm25Result {
    /// File path
    pub file_path: PathBuf,
    /// BM25 relevance score
    pub score: f64,
    /// Start line of the matching region
    pub line_start: u32,
    /// End line of the matching region
    pub line_end: u32,
    /// Snippet of matching content
    pub snippet: String,
    /// Terms that matched in this document
    pub matched_terms: Vec<String>,
    /// search-exact-token-v1 (issue #9): how this snippet window matched
    /// the query terms:
    /// - `"exact"`     — at least one matched term occurs as a whole token
    ///   inside the window (per the same tokenizer that built the index)
    /// - `"substring"` — matched terms occur only inside larger words
    ///   (`"addresses"` contains `"dres"`)
    /// - `"fuzzy"`     — reserved for sub-token similarity (unused today)
    ///
    /// Empty (and omitted from JSON) for paths that do not classify their
    /// matches (regex, hybrid RRF fusion).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub match_type: String,
}

/// Document in the BM25 index
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Document {
    /// Document ID (file path)
    id: String,
    /// Term frequencies
    term_freqs: HashMap<String, u32>,
    /// Total number of tokens
    length: usize,
    /// Original content for snippet extraction
    content: String,
}

/// BM25 search index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bm25Index {
    /// k1 parameter: term frequency saturation (default 1.5)
    k1: f64,
    /// b parameter: document length normalization (default 0.75)
    b: f64,
    /// All indexed documents
    documents: Vec<Document>,
    /// Document frequency for each term (how many docs contain term)
    doc_freqs: HashMap<String, usize>,
    /// Average document length
    avg_doc_length: f64,
    /// Running sum of all document lengths (integer to avoid float drift).
    /// INVARIANT: Must be recalculated if documents are ever removed.
    total_doc_length: usize,
    /// Tokenizer instance
    tokenizer: Tokenizer,
}

impl Default for Bm25Index {
    fn default() -> Self {
        Self::new(1.5, 0.75)
    }
}

impl Bm25Index {
    /// Create a new BM25 index with specified parameters
    ///
    /// # Arguments
    /// * `k1` - Term frequency saturation (default 1.5, higher = more weight to term frequency)
    /// * `b` - Document length normalization (default 0.75, 0 = no normalization, 1 = full normalization)
    pub fn new(k1: f64, b: f64) -> Self {
        Self {
            k1,
            b,
            documents: Vec::new(),
            doc_freqs: HashMap::new(),
            avg_doc_length: 0.0,
            total_doc_length: 0,
            tokenizer: Tokenizer::new(),
        }
    }

    /// Add a document to the index
    ///
    /// # Arguments
    /// * `doc_id` - Unique identifier for the document (typically file path)
    /// * `content` - Text content to index
    pub fn add_document(&mut self, doc_id: &str, content: &str) {
        let tokens = self.tokenizer.tokenize(content);
        let length = tokens.len();

        // Count term frequencies
        let mut term_freqs: HashMap<String, u32> = HashMap::new();
        let mut unique_terms: HashSet<String> = HashSet::new();

        for token in &tokens {
            *term_freqs.entry(token.clone()).or_insert(0) += 1;
            unique_terms.insert(token.clone());
        }

        // Update document frequencies
        for term in unique_terms {
            *self.doc_freqs.entry(term).or_insert(0) += 1;
        }

        // Add document
        self.documents.push(Document {
            id: doc_id.to_string(),
            term_freqs,
            length,
            content: content.to_string(),
        });

        // Update average document length in O(1) instead of O(n)
        self.total_doc_length += length;
        self.avg_doc_length = self.total_doc_length as f64 / self.documents.len() as f64;
    }

    /// Search the index for relevant documents
    ///
    /// # Arguments
    /// * `query` - Search query string
    /// * `top_k` - Maximum number of results to return
    ///
    /// # Returns
    /// Vector of search results sorted by relevance score (descending)
    ///
    /// # Coverage penalty (analysis-precision-v1, BUG-20)
    ///
    /// Plain BM25 scores documents purely by per-term contribution: a query
    /// `nonexistent_term_xyz_789` (4 query tokens after camel/snake split:
    /// `nonexistent`, `term`, `xyz`, `789`) that matches a single rare token
    /// (`xyz`) in one document still ranks that document close to a
    /// hypothetical "all four matched" maximum, because the IDF of a single
    /// rare term dominates the per-document sum.
    ///
    /// To prevent a single-token sub-match from masquerading as a near-perfect
    /// hit, we apply a coverage penalty: when fewer than half of the query
    /// tokens matched a document, multiply that document's BM25 score by the
    /// coverage ratio (`matched / total`). The threshold is set at 0.5 so that
    /// documents matching the majority of the query are not penalized — only
    /// thin matches are discounted. The penalty is *multiplicative*, so a
    /// 1-of-4 match (coverage 0.25) keeps 25% of its original score; a 3-of-4
    /// match (coverage 0.75) is left untouched.
    pub fn search(&self, query: &str, top_k: usize) -> Vec<Bm25Result> {
        let query_tokens = self.tokenizer.tokenize(query);

        if query_tokens.is_empty() || self.documents.is_empty() {
            return Vec::new();
        }

        let n = self.documents.len() as f64;

        // Total *unique* query tokens — duplicates in the user query should not
        // inflate the denominator of the coverage ratio. matched_terms below
        // is also unique-per-document by construction (one append per term).
        // We preserve insertion order (deterministic output) while deduping.
        let unique_query_tokens: Vec<String> = {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            let mut out: Vec<String> = Vec::with_capacity(query_tokens.len());
            for t in &query_tokens {
                if seen.insert(t.as_str()) {
                    out.push(t.clone());
                }
            }
            out
        };
        let total_query_terms = unique_query_tokens.len() as f64;

        // analysis-precision-v1: penalty kicks in when coverage < this ratio.
        // 0.5 = half of query tokens must match to avoid the penalty.
        const COVERAGE_THRESHOLD: f64 = 0.5;

        // Score each document
        let mut scores: Vec<(usize, f64, Vec<String>)> = Vec::new();

        for (doc_idx, doc) in self.documents.iter().enumerate() {
            let mut score = 0.0;
            let mut matched_terms = Vec::new();

            for term in &unique_query_tokens {
                let tf = *doc.term_freqs.get(term).unwrap_or(&0) as f64;

                if tf > 0.0 {
                    matched_terms.push(term.clone());

                    // IDF calculation
                    let df = *self.doc_freqs.get(term).unwrap_or(&0) as f64;
                    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

                    // BM25 score component
                    let doc_len = doc.length as f64;
                    let numerator = tf * (self.k1 + 1.0);
                    let denominator =
                        tf + self.k1 * (1.0 - self.b + self.b * doc_len / self.avg_doc_length);

                    score += idf * (numerator / denominator);
                }
            }

            if score > 0.0 {
                // Apply coverage penalty (analysis-precision-v1, BUG-20).
                let coverage_ratio = if total_query_terms > 0.0 {
                    matched_terms.len() as f64 / total_query_terms
                } else {
                    1.0
                };
                if coverage_ratio < COVERAGE_THRESHOLD {
                    score *= coverage_ratio;
                }
                scores.push((doc_idx, score, matched_terms));
            }
        }

        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // search-exact-token-v1 (issue #9): expand every matched document
        // into one result per match window instead of collapsing the whole
        // file into a single snippet. Previously `search` returned at most
        // one window per document and picked it with first-max *substring*
        // containment, so a decoy line whose larger word merely contains the
        // token ("addresses" ⊃ "dres") hijacked the window from the real
        // whole-token occurrences further down (issue #9 repro: one hit at
        // lines 1-3 while the real occurrences at 979-980 were never
        // returned).
        let mut results: Vec<Bm25Result> = Vec::new();
        for (idx, score, matched_terms) in scores {
            let doc = &self.documents[idx];
            for (line_start, line_end, snippet, match_type) in
                extract_match_windows(&self.tokenizer, &doc.content, &matched_terms)
            {
                results.push(Bm25Result {
                    file_path: PathBuf::from(&doc.id),
                    score,
                    line_start,
                    line_end,
                    snippet,
                    matched_terms: matched_terms.clone(),
                    match_type,
                });
            }
        }

        // search-exact-token-v1 (issue #9): whole-token windows rank above
        // substring-only windows regardless of document score — all windows
        // of a document share the document's BM25 score, so without this
        // explicit tier a substring-only window could sit above an exact
        // window of an equally-scored document. The stable sort keeps the
        // document-score order (and, within a document, ascending line
        // order) intact inside each tier.
        results.sort_by(|a, b| {
            match_type_rank(&b.match_type)
                .cmp(&match_type_rank(&a.match_type))
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        results.truncate(top_k);
        results
    }

    /// Build an index from all code files in a project directory
    ///
    /// # Arguments
    /// * `root` - Root directory to index
    /// * `language` - Language to filter by (only index files of this language)
    pub fn from_project(root: &Path, language: Language) -> TldrResult<Self> {
        let mut index = Self::default();
        let extensions: HashSet<&str> = language.extensions().iter().copied().collect();

        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                // VAL-018: never reject the WalkDir root (depth 0). The
                // user-supplied root may legitimately have a leading dot
                // (e.g. `.tmpXXXXXX` from tempfile, or any path under a
                // hidden parent). Filtering by depth 0 keeps the
                // hidden-skip semantics for descendants while not
                // silently producing 0 results when the project root
                // itself starts with `.`.
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                // Skip hidden and default skip directories below the root.
                if name.starts_with('.') && name != "." {
                    return false;
                }
                if e.file_type().is_dir() && DEFAULT_SKIP_DIRS.contains(&name.as_ref()) {
                    return false;
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip directories
            if entry.file_type().is_dir() {
                continue;
            }

            // Check extension
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e));

            if let Some(ext) = &ext {
                if !extensions.contains(ext.as_str()) {
                    continue;
                }
            } else {
                continue;
            }

            // Read and index file
            if let Ok(content) = fs::read_to_string(path) {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                index.add_document(&relative, &content);
            }
        }

        Ok(index)
    }

    /// Get the number of documents in the index
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

/// search-exact-token-v1 (issue #9): maximum gap (in lines) between two
/// match lines for them to share one snippet window. 2 keeps adjacent and
/// near-adjacent occurrences (e.g. `const dres = fetch(...)` followed by
/// `console.log(dres.status);`) in a single card while splitting disjoint
/// clusters into separate cards.
const WINDOW_MERGE_GAP: usize = 2;

/// search-exact-token-v1 (issue #9): context lines kept before/after the
/// match cluster inside a snippet window.
const WINDOW_CONTEXT_LINES: usize = 1;

/// Ranking priority of a `Bm25Result::match_type` label (issue #9).
/// Exact whole-token windows outrank substring-only windows, which
/// outrank unclassified results.
fn match_type_rank(match_type: &str) -> u8 {
    match match_type {
        "exact" => 2,
        "substring" => 1,
        _ => 0,
    }
}

/// Split one matched document into one snippet window per cluster of match
/// lines (issue #9).
///
/// A line "matches" when it contains at least one of the BM25-matched terms:
/// * as a whole token under the same tokenizer that built the index
///   (`Tokenizer::tokenize(line)` contains the term) — labeled `"exact"`;
/// * otherwise only as a bare substring inside a larger word
///   (`"addresses"` contains `"dres"`) — labeled `"substring"`.
///
/// Guarantees:
/// * every line containing a matched term as a whole token belongs to some
///   emitted window — there is no per-file cap beyond the caller's explicit
///   `top_k`;
/// * whole-token windows are produced even when a substring-only decoy line
///   appears earlier in the file (the old first-max substring window pick
///   let such decoys hijack the single snippet, issue #9);
/// * substring-only windows are emitted ONLY when the document has no
///   whole-token window at all, keeping fuzzy noise out of results that
///   already contain exact hits.
///
/// Returns `(line_start, line_end, snippet, match_type)` tuples where
/// `line_start`/`line_end` are the 1-indexed inclusive bounds of the
/// MATCHED-CORE lines (the lines that actually contain a matched term) and
/// `snippet` keeps `WINDOW_CONTEXT_LINES` of surrounding context. Keeping
/// context out of the reported bounds matters downstream: the enrichment
/// stage maps these bounds to their enclosing function, and a context line
/// that merely starts an unrelated function must not hijack a top-level
/// match (issue #9 follow-up). Windows are ordered by ascending line number.
fn extract_match_windows(
    tokenizer: &Tokenizer,
    content: &str,
    matched_terms: &[String],
) -> Vec<(u32, u32, String, String)> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || matched_terms.is_empty() {
        return Vec::new();
    }

    // Classify each line once: a whole-token match beats a bare substring.
    let mut exact_lines: Vec<usize> = Vec::new();
    let mut substring_lines: Vec<usize> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let line_lower = line.to_lowercase();
        if !matched_terms
            .iter()
            .any(|t| line_lower.contains(t.as_str()))
        {
            continue;
        }
        let line_tokens = tokenizer.tokenize(line);
        let has_whole_token = matched_terms
            .iter()
            .any(|t| line_tokens.iter().any(|tok| tok == t));
        if has_whole_token {
            exact_lines.push(idx);
        } else {
            substring_lines.push(idx);
        }
    }

    // Whole-token windows win; substring-only windows are a fallback.
    let (match_lines, label) = if !exact_lines.is_empty() {
        (exact_lines, "exact")
    } else {
        (substring_lines, "substring")
    };
    if match_lines.is_empty() {
        return Vec::new();
    }

    // Group match lines into clusters at most WINDOW_MERGE_GAP lines apart.
    let mut clusters: Vec<(usize, usize)> = Vec::new(); // inclusive 0-based bounds
    let mut cluster_start = match_lines[0];
    let mut cluster_end = match_lines[0];
    for &idx in &match_lines[1..] {
        if idx - cluster_end <= WINDOW_MERGE_GAP {
            cluster_end = idx;
        } else {
            clusters.push((cluster_start, cluster_end));
            cluster_start = idx;
            cluster_end = idx;
        }
    }
    clusters.push((cluster_start, cluster_end));

    clusters
        .into_iter()
        .map(|(first, last)| {
            let start = first.saturating_sub(WINDOW_CONTEXT_LINES);
            let end = (last + WINDOW_CONTEXT_LINES + 1).min(lines.len());
            let snippet = lines[start..end].join("\n");
            (
                (first + 1) as u32,
                (last + 1) as u32,
                snippet,
                label.to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bm25_add_document() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "def process_data items");
        index.add_document("file2", "class DataProcessor");

        assert_eq!(index.document_count(), 2);
    }

    #[test]
    fn test_bm25_search_basic() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process data items data data");
        index.add_document("file2", "process something else");

        let results = index.search("data", 10);
        assert!(!results.is_empty());
        // file1 should rank higher (more occurrences of "data")
        assert_eq!(results[0].file_path, PathBuf::from("file1"));
    }

    #[test]
    fn test_bm25_returns_scores() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process data");

        let results = index.search("data", 10);
        assert!(!results.is_empty());
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn test_bm25_returns_matched_terms() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process user data");

        let results = index.search("process data", 10);
        assert!(!results.is_empty());
        assert!(results[0].matched_terms.contains(&"process".to_string()));
        assert!(results[0].matched_terms.contains(&"data".to_string()));
    }

    #[test]
    fn test_bm25_respects_top_k() {
        let mut index = Bm25Index::new(1.5, 0.75);
        for i in 0..10 {
            index.add_document(&format!("file{}", i), "process data");
        }

        let results = index.search("data", 5);
        assert!(results.len() <= 5);
    }

    #[test]
    fn test_bm25_tokenizes_camel_case() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "processData ItemProcessor");

        let results = index.search("process", 10);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_bm25_tokenizes_snake_case() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process_data item_processor");

        let results = index.search("process", 10);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_bm25_case_insensitive() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "PROCESS_DATA");

        let results = index.search("process", 10);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_bm25_empty_query() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process data");

        let results = index.search("", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_bm25_no_match() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process data");

        let results = index.search("nonexistent", 10);
        assert!(results.is_empty());
    }

    /// Regression test for issue #8 — BM25 search must match a
    /// single-letter PascalCase prefix identifier (`IService`) regardless
    /// of the query's case. Pre-fix the tokenizer split `IService` into
    /// `["I", "Service"]` then dropped `"I"` (min_length=2), so the
    /// canonical `iservice` token was never indexed and the query found
    /// zero matches.
    #[test]
    fn test_bm25_single_letter_pascal_prefix_match() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "interface IService { method(): void; }");

        let lower_results = index.search("iservice", 10);
        assert!(
            !lower_results.is_empty(),
            "BM25 search for 'iservice' against IService-containing fixture must return >= 1 result; got 0 results"
        );

        let upper_results = index.search("IService", 10);
        assert!(
            !upper_results.is_empty(),
            "BM25 search for 'IService' against IService-containing fixture must return >= 1 result; got 0 results"
        );
    }

    /// analysis-precision-v1, BUG-20: a 4-token query that only matches a
    /// single rare token in a single document must NOT score near the
    /// hypothetical 4-of-4 maximum. The coverage penalty multiplies the
    /// BM25 sum by `matched_terms.len() / total_query_terms` whenever
    /// coverage < 0.5.
    ///
    /// Before the fix: `nonexistent_term_xyz_789` (tokens: nonexistent,
    /// term, xyz, 789) against a corpus containing only `xyz` in one doc
    /// scored ~0.92 (close to BM25 max). After the fix the same hit gets
    /// multiplied by 1/4 = 0.25, dropping well below 0.5.
    #[test]
    fn test_search_low_coverage_score_discounted() {
        let mut index = Bm25Index::new(1.5, 0.75);
        // 5 unrelated documents to give "xyz" a real IDF weight.
        index.add_document("file1", "client.get(base_url=\"http://xyz.other.test\")");
        index.add_document("file2", "fn main() { println!(\"hello world\"); }");
        index.add_document("file3", "let total = compute_sum(items);");
        index.add_document("file4", "import os; from pathlib import Path");
        index.add_document("file5", "struct Config { timeout: u64 }");

        let results = index.search("nonexistent_term_xyz_789", 10);

        // Only file1 contains a matching token (`xyz`). 1-of-4 coverage = 0.25.
        // Top result must exist (we still want to surface a hit) but its
        // score must be heavily discounted (< 0.5 — the test's hard ceiling).
        assert_eq!(
            results.len(),
            1,
            "expected exactly 1 sub-match, got {}",
            results.len()
        );
        assert_eq!(results[0].matched_terms, vec!["xyz".to_string()]);
        assert!(
            results[0].score < 0.5,
            "low-coverage BM25 score must be < 0.5 (BUG-20 coverage penalty); got {}",
            results[0].score
        );
    }

    /// Companion test: a query whose tokens ALL match must NOT be penalized.
    /// Coverage = 1.0, so the score equals plain BM25.
    #[test]
    fn test_search_full_coverage_score_unchanged() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document("file1", "process user data items");
        index.add_document("file2", "render html template");
        index.add_document("file3", "compile rust code");

        // 2-token query, both tokens in file1 → coverage = 1.0, no penalty.
        let results = index.search("process data", 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].matched_terms.len(), 2);
        // Score should be the un-penalized BM25 sum (well above the
        // 0.5 ceiling that low-coverage hits get clamped under).
        assert!(
            results[0].score > 0.5,
            "full-coverage match must keep BM25 score (no penalty); got {}",
            results[0].score
        );
    }

    /// search-exact-token-v1 (issue #9): a whole-token occurrence far below
    /// a substring-only decoy line must still surface in its own window,
    /// and the decoy ("addresses" ⊃ "dres") must neither hijack the window
    /// nor appear in the results at all. This is the engine-level shape of
    /// the issue #9 repro.
    #[test]
    fn test_search_exact_window_beats_substring_decoy() {
        let mut index = Bm25Index::new(1.5, 0.75);
        let mut lines: Vec<String> = Vec::new();
        lines.push("// rescanClicks state: addresses stale UI flags.".to_string());
        for i in 0..40 {
            lines.push(format!("function filler_{}(alpha) {{ return alpha; }}", i));
        }
        lines.push("const dres = fetch('/api/data');".to_string());
        lines.push("console.log(dres.status);".to_string());
        index.add_document("app.js", &lines.join("\n"));

        // 1-based lines of the real occurrences (last two lines).
        let real_line_1 = (lines.len() - 1) as u32;
        let real_line_2 = lines.len() as u32;

        let results = index.search("dres", 10);

        assert!(
            !results.is_empty(),
            "exact-token occurrences must be returned; got 0 results"
        );
        for result in &results {
            assert_eq!(
                result.match_type, "exact",
                "substring-only decoy must not surface once exact hits exist: {result:?}"
            );
            assert!(
                result.line_start <= real_line_1 && result.line_end >= real_line_2,
                "window must cover the real occurrences at {real_line_1}-{real_line_2}; got {:?}",
                (result.line_start, result.line_end)
            );
            assert!(
                result.snippet.contains("dres"),
                "snippet must reference the searched token; got {result:?}"
            );
        }
    }

    /// search-exact-token-v1 (issue #9): two disjoint whole-token clusters
    /// in one file each surface as their own window (multi-window recall —
    /// the old engine collapsed the file into a single snippet).
    #[test]
    fn test_search_disjoint_exact_clusters_each_surface() {
        let mut index = Bm25Index::new(1.5, 0.75);
        let mut lines: Vec<String> = Vec::new();
        lines.push("const dres = fetch('/api/data');".to_string());
        lines.push("console.log(dres.status);".to_string());
        // Filler until the second cluster's first line sits at 304 (1-based).
        while lines.len() + 1 < 304 {
            lines.push(format!(
                "function filler_{}(alpha) {{ return alpha; }}",
                lines.len()
            ));
        }
        // `dresRetry` tokenizes to ["dres", "retry"], so both lines are
        // whole-token "dres" occurrences.
        lines.push("const dresRetry = revalidate(dres);".to_string());
        lines.push("console.log(dresRetry.status);".to_string());
        index.add_document("two_clusters.js", &lines.join("\n"));

        let results = index.search("dres", 10);

        assert!(
            results.iter().any(|r| r.line_start <= 1 && r.line_end >= 2),
            "cluster 1 (lines 1-2) must be covered; got {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.line_start <= 304 && r.line_end >= 305),
            "cluster 2 (lines 304-305, the whole-token dresRetry lines) must be covered; got {results:?}"
        );
        assert!(
            results.iter().all(|r| r.match_type == "exact"),
            "all windows must be exact whole-token matches; got {results:?}"
        );
    }

    /// search-exact-token-v1 (issue #9): window extraction unit checks —
    /// clustering with context, disjoint cluster splitting, and the
    /// substring fallback label for documents with no whole-token
    /// occurrence (defensive path).
    #[test]
    fn test_extract_match_windows_clustering_and_labels() {
        let tokenizer = Tokenizer::new();
        let terms = ["dres".to_string()];

        // One cluster (lines 1-2) + a substring-only decoy (line 8) that
        // must be dropped because a whole-token window exists.
        let content = "const dres = fetch();\nconsole.log(dres.status);\nfiller\n\nfiller\n\nfiller\naddresses stale UI\n";
        let windows = extract_match_windows(&tokenizer, content, &terms);
        assert_eq!(windows.len(), 1, "decoy must be dropped; got {windows:?}");
        assert_eq!(windows[0].0, 1, "1-indexed matched-core window start");
        // Matched-core bounds (not context-inclusive): the enrichment stage
        // maps these bounds to their enclosing function, so a context line
        // must never widen a top-level match into an unrelated function.
        // Context still appears inside `snippet` (see the contains check).
        assert_eq!(windows[0].1, 2, "1-indexed matched-core window end");
        assert_eq!(windows[0].3, "exact");
        assert!(windows[0].2.contains("const dres"));

        // Disjoint clusters (gap > WINDOW_MERGE_GAP) split into two windows.
        let content = "const dres = 1;\na\nb\nc\ncall(dres);\n";
        let windows = extract_match_windows(&tokenizer, content, &terms);
        assert_eq!(
            windows.len(),
            2,
            "disjoint clusters must split; got {windows:?}"
        );
        assert_eq!((windows[0].0, windows[0].1), (1, 1));
        assert_eq!((windows[1].0, windows[1].1), (5, 5));

        // No whole-token occurrence anywhere → substring fallback label.
        let content = "addresses and more addresses\n";
        let windows = extract_match_windows(&tokenizer, content, &terms);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].3, "substring");
        assert_eq!((windows[0].0, windows[0].1), (1, 1));
    }

    /// Regression test for issue #84 — a document containing
    /// `OAuth2Provider` must be findable by a BM25 query for `oauth`.
    /// Pre-fix the tokenizer produced `["oauth2", "provider"]` for
    /// `OAuth2Provider`, so the query term `oauth` never matched any indexed
    /// term and the search returned zero results (in BM25 mode and,
    /// transitively, in Hybrid mode which intersects the BM25 list).
    #[test]
    fn test_bm25_oauth2_provider_found_via_oauth_query() {
        let mut index = Bm25Index::new(1.5, 0.75);
        index.add_document(
            "oauth.rs",
            "pub struct OAuth2Provider {\n    pub client_id: String,\n}",
        );

        let results = index.search("oauth", 10);
        assert!(
            !results.is_empty(),
            "BM25 search for 'oauth' must find the OAuth2Provider document; got 0 results"
        );
        assert_eq!(results[0].file_path, PathBuf::from("oauth.rs"));
        assert!(
            results[0].matched_terms.contains(&"oauth".to_string()),
            "matched terms must include 'oauth'; got {:?}",
            results[0].matched_terms
        );

        // The full identifier and its subtokens must be findable too.
        for query in ["OAuth2Provider", "oauth2provider", "provider", "oauth"] {
            let results = index.search(query, 10);
            assert!(
                !results.is_empty(),
                "BM25 search for '{query}' must find the OAuth2Provider document"
            );
        }
    }
}
