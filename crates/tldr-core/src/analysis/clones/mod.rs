//! Clone detection module -- tree-sitter fragment extraction,
//! two-phase hash detection, and correct line numbers.

// All type definitions and utility functions
mod types;
pub use types::*;

// Submodules
pub mod detect;
pub mod extract;
pub mod filter;
pub mod tokenize;

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

// Re-export is_test_file from filter
pub use filter::is_test_file;

use detect::PairKey;
use extract::extract_fragments_from_file;
use filter::{discover_source_files, get_language_from_path};
use tokenize::tokenize_file_v2;

/// schema-cleanup-v2 (P2.BUG-7): pick the dominant language string
/// across the discovered files. Tally the per-extension language label
/// from `get_language_from_path` and return the most-frequent one. Ties
/// resolve by the first language encountered (deterministic ordering on
/// the input slice — `discover_source_files` already returns files in
/// directory-walk order).
///
/// Returns the literal `"auto"` only when no file has a recognised
/// extension (degenerate case — `discover_source_files` should have
/// rejected those via `is_source_file_for_clones`, so this branch is
/// effectively unreachable in production).
fn resolve_dominant_language(files: &[std::path::PathBuf]) -> String {
    use std::collections::HashMap;
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let mut order: Vec<&'static str> = Vec::new();
    for f in files {
        if let Some(lang) = get_language_from_path(f) {
            if !counts.contains_key(lang) {
                order.push(lang);
            }
            *counts.entry(lang).or_insert(0) += 1;
        }
    }
    // Pick the language with the highest count; on ties, the first
    // language seen (insertion order) wins.
    let mut best: Option<&'static str> = None;
    let mut best_count: usize = 0;
    for lang in &order {
        let c = counts[lang];
        if c > best_count {
            best_count = c;
            best = Some(lang);
        }
    }
    best.map(|s| s.to_string())
        .unwrap_or_else(|| "auto".to_string())
}

/// Detect code clones in a directory using the v2 pipeline.
///
/// Pipeline:
/// 1. Discover source files
/// 2. Tokenize each file
/// 3. Extract fragments per file (tree-sitter function boundaries)
/// 4. Detect Type-1/Type-2 clones (hash buckets)
/// 5. Detect Type-3 clones (inverted index)
/// 6. Assemble ClonesReport
pub fn detect_clones(path: &Path, options: &ClonesOptions) -> anyhow::Result<ClonesReport> {
    let start = Instant::now();

    // Step 1: Discover files
    let files = discover_source_files(
        path,
        options.language.as_deref(),
        options.max_files,
        options.exclude_generated,
        options.exclude_tests,
    );

    if files.is_empty() {
        return Ok(empty_report(path, options, &start));
    }

    // schema-cleanup-v2 (P2.BUG-7): resolve the report's `language` field
    // to the actual analyzed language string rather than the literal
    // `"auto"` placeholder. Pre-fix the field always echoed `"auto"` (or
    // the user's `--lang` flag verbatim), making it impossible for
    // consumers to programmatically tell what the autodetector actually
    // picked. Now we either honor the explicit `options.language` or
    // derive a single dominant language string from the discovered files
    // via `get_language_from_path` majority count. Falls back to `"auto"`
    // only when no file in `files` has a recognised extension (degenerate
    // case — `discover_source_files` should have rejected those files via
    // `is_source_file_for_clones`).
    let resolved_language = options
        .language
        .clone()
        .unwrap_or_else(|| resolve_dominant_language(&files));

    // Step 2: Tokenize files
    let file_tokens: Vec<tokenize::FileTokens> = files
        .iter()
        .filter_map(|f| tokenize_file_v2(f).ok())
        .collect();

    if file_tokens.is_empty() {
        return Ok(empty_report(path, options, &start));
    }

    // Step 3: Extract fragments
    let mut all_fragments: Vec<extract::FragmentData> = Vec::new();
    for (idx, ft) in file_tokens.iter().enumerate() {
        let frags = extract_fragments_from_file(
            ft,
            idx,
            options.min_tokens,
            options.min_lines,
            options.normalization,
        );
        all_fragments.extend(frags);
    }

    let total_tokens: usize = file_tokens.iter().map(|ft| ft.raw_tokens.len()).sum();

    if all_fragments.is_empty() {
        return Ok(ClonesReport {
            root: path.to_path_buf(),
            language: resolved_language.clone(),
            clone_pairs: vec![],
            clone_classes: vec![],
            stats: CloneStats {
                files_analyzed: file_tokens.len(),
                total_tokens,
                clones_found: 0,
                type1_count: 0,
                type2_count: 0,
                type3_count: 0,
                class_count: None,
                detection_time_ms: start.elapsed().as_millis() as u64,
            },
            config: CloneConfig {
                min_tokens: options.min_tokens,
                min_lines: options.min_lines,
                similarity_threshold: options.threshold,
                normalization: options.normalization,
                type_filter: options.type_filter,
            },
        });
    }

    // Step 4: Type-1 and Type-2 detection
    let mut found_pairs: HashSet<PairKey> = HashSet::new();
    let mut clone_pairs = detect::detect_type1_type2(&all_fragments, options, &mut found_pairs);

    // Step 5: Type-3 detection (if type_filter allows and not at max_clones)
    let should_detect_type3 = clone_pairs.len() < options.max_clones
        && options.type_filter.is_none_or(|t| t == CloneType::Type3);

    if should_detect_type3 {
        let type3_pairs = detect::detect_type3(&all_fragments, options, &mut found_pairs);
        clone_pairs.extend(type3_pairs);
    }

    // determinism-and-stderr-hygiene-v1 (BUG-2): both `detect_type1_type2`
    // and `detect_type3` walk `HashMap<u64, Vec<usize>>` /
    // `HashMap<usize, usize>` buckets via `.values()` / `.iter()`, whose
    // iteration order is non-deterministic across runs (DefaultHasher
    // seeds per-process). The same set of pairs is found, but the order
    // of `clone_pairs[]` shuffles across invocations, so two runs of
    // `tldr clones <repo>` produce byte-different stdout — breaking
    // CI byte-diff gates and any downstream tooling that hashes the
    // report. Sort here, BEFORE id assignment, so IDs are also stable.
    // Tiebreaker chain matches `ClonePair::canonical()` ordering
    // (`fragment1.file → fragment1.start_line → fragment2.file →
    // fragment2.start_line`) plus `clone_type` and `similarity` to
    // produce a total order over the bag.
    clone_pairs.sort_by(|a, b| {
        a.fragment1
            .file
            .cmp(&b.fragment1.file)
            .then_with(|| a.fragment1.start_line.cmp(&b.fragment1.start_line))
            .then_with(|| a.fragment1.end_line.cmp(&b.fragment1.end_line))
            .then_with(|| a.fragment2.file.cmp(&b.fragment2.file))
            .then_with(|| a.fragment2.start_line.cmp(&b.fragment2.start_line))
            .then_with(|| a.fragment2.end_line.cmp(&b.fragment2.end_line))
            .then_with(|| (a.clone_type as u8).cmp(&(b.clone_type as u8)))
            .then_with(|| {
                b.similarity
                    .partial_cmp(&a.similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    // Assign sequential 1-indexed IDs
    for (i, pair) in clone_pairs.iter_mut().enumerate() {
        pair.id = i + 1;
    }

    // Compute statistics
    let type1_count = clone_pairs
        .iter()
        .filter(|p| p.clone_type == CloneType::Type1)
        .count();
    let type2_count = clone_pairs
        .iter()
        .filter(|p| p.clone_type == CloneType::Type2)
        .count();
    let type3_count = clone_pairs
        .iter()
        .filter(|p| p.clone_type == CloneType::Type3)
        .count();

    let (clone_classes, class_count) = if options.show_classes {
        let classes = compute_clone_classes_v2(&clone_pairs);
        let count = classes.len();
        (classes, Some(count))
    } else {
        (vec![], None)
    };

    Ok(ClonesReport {
        root: path.to_path_buf(),
        language: resolved_language,
        clone_pairs,
        clone_classes,
        stats: CloneStats {
            files_analyzed: file_tokens.len(),
            total_tokens,
            clones_found: type1_count + type2_count + type3_count,
            type1_count,
            type2_count,
            type3_count,
            class_count,
            detection_time_ms: start.elapsed().as_millis() as u64,
        },
        config: CloneConfig {
            min_tokens: options.min_tokens,
            min_lines: options.min_lines,
            similarity_threshold: options.threshold,
            normalization: options.normalization,
            type_filter: options.type_filter,
        },
    })
}

/// Compute clone classes from pairs using Union-Find (for show_classes=true).
fn compute_clone_classes_v2(pairs: &[ClonePair]) -> Vec<CloneClass> {
    use std::collections::HashMap;

    if pairs.is_empty() {
        return vec![];
    }

    // Map fragments to indices
    let mut fragment_map: HashMap<CloneFragment, usize> = HashMap::new();
    let mut fragments: Vec<CloneFragment> = Vec::new();

    for pair in pairs {
        if !fragment_map.contains_key(&pair.fragment1) {
            fragment_map.insert(pair.fragment1.clone(), fragments.len());
            fragments.push(pair.fragment1.clone());
        }
        if !fragment_map.contains_key(&pair.fragment2) {
            fragment_map.insert(pair.fragment2.clone(), fragments.len());
            fragments.push(pair.fragment2.clone());
        }
    }

    // Build Union-Find
    let mut uf = UnionFind::new(fragments.len());
    let mut pair_similarities: HashMap<(usize, usize), (f64, CloneType)> = HashMap::new();

    for pair in pairs {
        let idx1 = fragment_map[&pair.fragment1];
        let idx2 = fragment_map[&pair.fragment2];
        uf.union(idx1, idx2);
        pair_similarities.insert(
            (idx1.min(idx2), idx1.max(idx2)),
            (pair.similarity, pair.clone_type),
        );
    }

    // Extract components.
    //
    // fix-fix-clones-det-v1 (v0.5.0 FIX-CLONES-DET): `UnionFind::components()`
    // returns a `HashMap<usize, Vec<usize>>`, and the prior code walked it
    // via `for (_root, member_indices) in components`, assigning the
    // sequential `class_id` in DefaultHasher iteration order (randomized
    // per-process). That made `clone_classes[]` order — and every class
    // `id` — non-deterministic run-to-run, so `tldr clones --show-classes`
    // emitted byte-different JSON on identical input, breaking CI byte-diff
    // gates and any downstream consumer that hashes the report.
    //
    // We now impose a deterministic TOTAL ORDER at this emission boundary
    // while preserving clone-detection semantics (same set of classes, same
    // membership — only the order changes):
    //   1. members within each class are sorted by
    //      (file path, start_line, length=end_line-start_line),
    //   2. the dominant-type tally tie-breaks deterministically
    //      (highest count, then lowest `CloneType` ordinal) rather than
    //      relying on `HashMap`-order `max_by_key`,
    //   3. the classes themselves are sorted by their first member's
    //      (file path, start_line, length), then size, then dominant type,
    //   4. `id` is assigned sequentially AFTER the sort, so ids are stable.
    let components = uf.components();

    // Stable per-member sort key: (file, start_line, length).
    fn member_key(f: &CloneFragment) -> (std::path::PathBuf, usize, usize) {
        (
            f.file.clone(),
            f.start_line,
            f.end_line.saturating_sub(f.start_line),
        )
    }

    let mut classes: Vec<CloneClass> = Vec::new();

    for (_root, member_indices) in components {
        if member_indices.len() < 2 {
            continue;
        }

        // Compute aggregate stats over the member set BEFORE reordering the
        // exported fragments (stats are order-independent, but we keep the
        // pairwise walk over `member_indices` so the `pair_similarities`
        // keys still match).
        let mut total_sim = 0.0f64;
        let mut count = 0usize;
        let mut type_counts: HashMap<CloneType, usize> = HashMap::new();

        for i in 0..member_indices.len() {
            for j in (i + 1)..member_indices.len() {
                let key = (
                    member_indices[i].min(member_indices[j]),
                    member_indices[i].max(member_indices[j]),
                );
                if let Some(&(sim, ct)) = pair_similarities.get(&key) {
                    total_sim += sim;
                    count += 1;
                    *type_counts.entry(ct).or_insert(0) += 1;
                }
            }
        }

        let avg_similarity = if count > 0 {
            total_sim / count as f64
        } else {
            1.0
        };

        // Deterministic dominant type: highest count wins; ties broken by
        // the lowest `CloneType` ordinal (Type1 < Type2 < Type3) so the
        // result no longer depends on `HashMap` iteration order.
        let dominant_type = type_counts
            .iter()
            .max_by(|a, b| {
                a.1.cmp(b.1)
                    .then_with(|| (*b.0 as u8).cmp(&(*a.0 as u8)))
            })
            .map(|(t, _)| *t)
            .unwrap_or(CloneType::Type1);

        // Members sorted into the deterministic total order.
        let mut class_fragments: Vec<CloneFragment> = member_indices
            .iter()
            .map(|&i| fragments[i].clone())
            .collect();
        class_fragments.sort_by(|a, b| member_key(a).cmp(&member_key(b)));

        classes.push(CloneClass {
            id: 0, // assigned after the class-level sort below
            clone_type: dominant_type,
            avg_similarity,
            size: class_fragments.len(),
            fragments: class_fragments,
        });
    }

    // Impose a deterministic total order over the classes themselves. The
    // primary key is the first (already-sorted) member's
    // (file, start_line, length); a class always has >= 2 members here, so
    // `fragments[0]` exists. Remaining keys (size, dominant type) only
    // matter for the degenerate case of two classes sharing a first member,
    // which cannot happen (a fragment belongs to exactly one class) but are
    // kept for a fully-defined total order.
    classes.sort_by(|a, b| {
        let ka = member_key(&a.fragments[0]);
        let kb = member_key(&b.fragments[0]);
        ka.cmp(&kb)
            .then_with(|| a.size.cmp(&b.size))
            .then_with(|| (a.clone_type as u8).cmp(&(b.clone_type as u8)))
    });

    // Assign sequential 1-indexed ids AFTER sorting so ids are stable.
    for (i, class) in classes.iter_mut().enumerate() {
        class.id = i + 1;
    }

    classes
}

/// Create an empty report for edge cases (no files, etc.)
fn empty_report(path: &Path, options: &ClonesOptions, start: &Instant) -> ClonesReport {
    ClonesReport {
        root: path.to_path_buf(),
        language: options
            .language
            .clone()
            .unwrap_or_else(|| "auto".to_string()),
        clone_pairs: vec![],
        clone_classes: vec![],
        stats: CloneStats {
            files_analyzed: 0,
            total_tokens: 0,
            clones_found: 0,
            type1_count: 0,
            type2_count: 0,
            type3_count: 0,
            class_count: None,
            detection_time_ms: start.elapsed().as_millis() as u64,
        },
        config: CloneConfig {
            min_tokens: options.min_tokens,
            min_lines: options.min_lines,
            similarity_threshold: options.threshold,
            normalization: options.normalization,
            type_filter: options.type_filter,
        },
    }
}
