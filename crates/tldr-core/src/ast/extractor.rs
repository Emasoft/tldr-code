//! Code structure extraction (spec Section 2.1.2)
//!
//! Extracts functions, classes, methods, and imports from source files.

use std::collections::HashSet;
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{CodeStructure, DefinitionInfo, FileStructure, IgnoreSpec, Language, MethodInfo};
use crate::TldrResult;

use super::extract::{decl_keyword_line_from_node, is_upper_case_name};
use super::imports::extract_imports_from_tree;
use super::parser::parse_file;

/// Extract code structure from all files in a directory.
///
/// # Arguments
/// * `root` - Root directory to scan
/// * `language` - Programming language to extract
/// * `max_results` - Maximum number of files (0 = unlimited)
/// * `ignore_spec` - Optional ignore patterns
///
/// # Edge Cases (per spec)
/// - Syntax error in file: Skip file, continue with others
/// - Binary file: Skip silently
/// - Encoding error: UTF-8 lossy fallback
/// - Empty file: Include with empty lists
pub fn get_code_structure(
    root: &Path,
    language: Language,
    max_results: usize,
    ignore_spec: Option<&IgnoreSpec>,
) -> TldrResult<CodeStructure> {
    // typescript-large-file-perf-v1: oversize files are surfaced as
    // a warning + a non-zero `files_skipped` counter on the result,
    // never a hard error. The single-file path returns an empty
    // `files` vec with `files_skipped = 1`; the dir-walk path
    // accumulates them as it iterates.
    let mut warnings: Vec<String> = Vec::new();
    let mut files_skipped: u32 = 0;

    // Handle single file case: extract structure directly
    if root.is_file() {
        let parent = root.parent().unwrap_or(root);
        match extract_file_structure(root, parent, language) {
            Ok(mut structure) => {
                // scala-path-canonical-v1 (v0.4.1 bug-C): in single-file
                // mode, `extract_file_structure` runs with
                // `root = file` and `parent = file.parent()`, so the
                // internal `strip_prefix(parent)` collapses
                // `files[0].path` to the basename (`ExitCode.scala`)
                // and the user loses their input path shape
                // (`/tmp/repos/.../ExitCode.scala`). Per the P15-B
                // precedent (`6a3288a context-relative-and-ts-colon-v1`),
                // preserve the user's input path shape verbatim in
                // output. The dir-walk branch (further below) still
                // emits paths relative to the scan root, which is the
                // user's input there too — so the user-input-shape
                // invariant holds across both branches.
                structure.path = root.to_path_buf();
                return Ok(CodeStructure {
                    root: root.to_path_buf(),
                    language: Some(language),
                    files: vec![structure],
                    files_skipped: 0,
                    warnings: Vec::new(),
                });
            }
            Err(crate::error::TldrError::FileTooLarge {
                path,
                size_mb: _,
                max_mb: _,
            }) => {
                files_skipped += 1;
                // Re-stat the file so the warning uses the same
                // KB/MB-aware formatter as the rest of the policy
                // (`fs::oversize::format_oversize_warning`). The
                // `size_mb` / `max_mb` fields on `FileTooLarge` are
                // pre-rounded to MB and would render the 512 KB
                // cap as "1MB" — confusing for users.
                let (size_bytes, max_bytes) =
                    match crate::fs::oversize::check_size(&path) {
                        crate::fs::oversize::SizeCheck::Oversize {
                            size_bytes,
                            max_bytes,
                            ..
                        } => (size_bytes, max_bytes),
                        // Fallback: file vanished between the
                        // failed parse and the warning emission.
                        // Use the rounded fields from the error.
                        _ => (0, 0),
                    };
                warnings.push(crate::fs::oversize::format_oversize_warning(
                    &path,
                    size_bytes,
                    max_bytes,
                    crate::fs::oversize::is_autogen_file(&path),
                ));
                return Ok(CodeStructure {
                    root: root.to_path_buf(),
                    language: Some(language),
                    files: Vec::new(),
                    files_skipped,
                    warnings,
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    // Get file tree filtered by language extensions.
    //
    // language-coverage-fixes-v1 (P4.BUG-N1, P4.BUG-N5): use
    // `scan_extensions()` instead of `extensions()` so:
    //   - C++ scans include `.h` (`tinyxml2.h` next to `tinyxml2.cpp`).
    //   - JS/TS scans include the sibling family (`.tsx` files in mixed
    //     React/Node directories are no longer silently dropped).
    //
    // The downstream parser (`parse_with_path`) routes `.tsx`/`.jsx` to
    // the TSX grammar dialect and `.h` is parsed by the C++ grammar when
    // `language == Language::Cpp` (a strict superset of C decls).
    let extensions: HashSet<String> = language
        .scan_extensions()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let tree = get_file_tree(root, Some(&extensions), true, ignore_spec)?;
    let files = collect_files(&tree, root);

    let mut file_structures = Vec::new();

    for file_path in files {
        // Apply max_results limit
        if max_results > 0 && file_structures.len() >= max_results {
            break;
        }

        // Try to extract structure, skip on error (per spec edge case handling)
        match extract_file_structure(&file_path, root, language) {
            Ok(structure) => file_structures.push(structure),
            Err(crate::error::TldrError::FileTooLarge {
                path,
                size_mb,
                max_mb,
            }) => {
                // typescript-large-file-perf-v1: structured skip
                // surfaced via `files_skipped` + `warnings`, mirrors
                // the M-X5/M-Y2 UTF-8-tolerance pattern.
                files_skipped += 1;
                warnings.push(format!(
                    "Skipped {}: {}MB exceeds {}MB cap for {}",
                    path.display(),
                    size_mb,
                    max_mb,
                    if crate::fs::oversize::is_autogen_file(&path) {
                        "auto-generated/minified files"
                    } else {
                        "source files"
                    }
                ));
            }
            Err(e) => {
                // Log error but continue - recoverable errors per spec
                if e.is_recoverable() {
                    eprintln!("Warning: Skipping {} - {}", file_path.display(), e);
                } else {
                    return Err(e);
                }
            }
        }
    }

    // med-low-schema-cleanup-v1 (N7): when a directory walk yielded zero
    // source files, emit `language: null` and a warning instead of
    // silently defaulting to the requested language. This avoids the
    // misleading shape `{"language":"python","files":[]}` for an empty
    // directory: the user has no way to tell whether the directory is
    // genuinely empty or whether the autodetector picked the wrong
    // language. Mirrors the M-X5/M-Y2/M-Z8 warnings pattern.
    let (out_language, out_warnings) = if file_structures.is_empty() && files_skipped == 0 {
        let mut w = warnings.clone();
        w.push("No source files found in directory".to_string());
        (None, w)
    } else {
        (Some(language), warnings)
    };

    Ok(CodeStructure {
        root: root.to_path_buf(),
        language: out_language,
        files: file_structures,
        files_skipped,
        warnings: out_warnings,
    })
}

/// reg-health-regression-v1 (v0.5.0 REG-HEALTH): enumerate every language
/// that has at least one source file under `root`, grouped by
/// [`Language::from_path`], in a deterministic order.
///
/// This is the single source-of-truth for "which languages live in this
/// tree", shared by the polyglot `structure` directory path and by
/// `health`'s `classes_analyzed` / `functions_analyzed` canonicalisation so
/// the two surfaces agree (the M-016 invariant).
///
/// The walk goes through [`crate::walker::walk_project`] — the same walk the
/// dominant-language [`Language::from_directory`] autodetector uses — so the
/// file inventory is consistent across commands. The result is sorted by the
/// `Debug`-rendered enum variant name; `Language` does not derive `Ord`, but
/// its `Debug` repr is stable per-build, so language order is reproducible.
pub fn detect_project_languages(root: &Path) -> Vec<Language> {
    use std::collections::HashSet;

    let mut seen: HashSet<Language> = HashSet::new();
    let mut langs: Vec<Language> = Vec::new();
    for entry in crate::walker::walk_project(root) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(lang) = Language::from_path(p) {
            if seen.insert(lang) {
                langs.push(lang);
            }
        }
    }
    langs.sort_by_key(|l| format!("{:?}", l));
    langs
}

/// b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3):
/// inverse of `PRIMARY_FAMILY_SHARE_DEN` — a detected language is part of the
/// "primary family" when its file count is at least
/// `dominant_count / PRIMARY_FAMILY_SHARE_DEN` (i.e. ≥ 20% of the dominant
/// language's file count).
///
/// Tuning rationale (file-count shares observed on the v0.5.0 corpora):
///   - `java-retrofit`: Java 306 (85%), JavaScript 34 (9%), Kotlin 16 (4%),
///     TypeScript 1 — only Java clears 306/5 = 61; the 34-file generated-docs
///     JavaScript bundle (and the rest of the tail) is excluded, killing the
///     211 MB blow-up.
///   - `scala-zio`: Scala 895 (96%), JavaScript 26, … → Scala only.
///   - `typescript-nest`: TypeScript 1673 (97%), JavaScript 51 → TypeScript only.
///   - The CL-15 balanced fixture (1 Python / 1 Go / 1 TypeScript): dominant
///     count is 1, threshold is 1/5 → 0, so EVERY language (each ≥ 1) is kept —
///     the CL-15 "analyze all languages in a balanced tree" contract holds.
const PRIMARY_FAMILY_SHARE_DEN: usize = 5;

/// b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3): from
/// the full set of detected languages under `root`, return
/// `(kept, dropped)` where `kept` is the primary language family (the dominant
/// language plus every language whose file count is ≥ 20% of the dominant's)
/// and `dropped` is everything else.
///
/// `all_langs` is the deterministically-ordered output of
/// [`detect_project_languages`]; both returned vectors preserve that ordering so
/// the merged structure (which echoes "the first scanned language") stays
/// reproducible. The dominant language is always in `kept`. A single-language
/// tree returns `(all_langs, [])` unchanged.
///
/// Walks the tree ONCE to count files per language (the same
/// `walk_project` + `from_path` inventory `detect_project_languages` uses, so
/// the counts are consistent with detection).
fn select_primary_language_family(
    root: &Path,
    all_langs: &[Language],
) -> (Vec<Language>, Vec<Language>) {
    use std::collections::HashMap;

    // Nothing to scope when there is only one language.
    if all_langs.len() <= 1 {
        return (all_langs.to_vec(), Vec::new());
    }

    let mut counts: HashMap<Language, usize> = HashMap::new();
    for entry in crate::walker::walk_project(root) {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Some(lang) = Language::from_path(p) {
            *counts.entry(lang).or_insert(0) += 1;
        }
    }

    let dominant_count = counts.values().copied().max().unwrap_or(0);
    if dominant_count == 0 {
        return (all_langs.to_vec(), Vec::new());
    }

    // Integer threshold: ≥ dominant_count / PRIMARY_FAMILY_SHARE_DEN. The
    // dominant language itself always clears this (count == dominant_count).
    let threshold = dominant_count / PRIMARY_FAMILY_SHARE_DEN;

    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for &lang in all_langs {
        let c = counts.get(&lang).copied().unwrap_or(0);
        if c >= threshold {
            kept.push(lang);
        } else {
            dropped.push(lang);
        }
    }

    // Safety: never return an empty kept set (would regress to "no source
    // found" on a non-empty tree). If the gate somehow excluded everything,
    // fall back to analyzing all languages.
    if kept.is_empty() {
        return (all_langs.to_vec(), Vec::new());
    }

    (kept, dropped)
}

/// reg-health-regression-v1 (v0.5.0 REG-HEALTH): multi-language structure
/// extraction for a directory.
///
/// `structure` and `health` both became polyglot in v0.5.0 (CL-15): a
/// mixed-language tree is no longer silently reduced to its dominant
/// language. This helper centralises the merge so the two commands count
/// classes/functions identically (the M-016 `health == structure`
/// invariant).
///
/// # Algorithm
///
/// 1. [`detect_project_languages`] enumerates every language present.
/// 2. [`get_code_structure`] runs once per language. Each per-language scan
///    widens to its `scan_extensions()` family — so the C++ scan picks up
///    `.h` headers, but so does the C scan, meaning a header next to C++
///    sources is parsed by BOTH grammars and would be counted twice.
/// 3. **Deduplication by path**: each physical file is kept exactly once,
///    under the language [`Language::from_path_with_siblings`] assigns it
///    (the sibling-aware owner — a `.h` next to `.cpp` belongs to C++, not
///    C). When the owning language is not among the scanned set, the entry
///    with the richer parse (most definitions) wins. This removes the C/C++
///    `.h` double-count that otherwise inflated `structure`'s class total
///    above `health`'s single-grammar count.
///
/// The merged `language` field reports the DOMINANT autodetected language
/// ([`Language::from_directory`]) for schema parity with the single-language
/// path. An empty / source-free tree yields `language: None` and a
/// `"No source files found in directory"` warning (the N7 contract), never a
/// silent default fallback.
pub fn get_polyglot_code_structure(
    root: &Path,
    max_results: usize,
    ignore_spec: Option<&IgnoreSpec>,
) -> TldrResult<CodeStructure> {
    use std::collections::HashMap;

    let all_langs = detect_project_languages(root);

    // Empty tree → null language + N7 warning. Do NOT default to a
    // language (reg-health-regression-v1: CL-15 leaked a Python fallback).
    if all_langs.is_empty() {
        return Ok(CodeStructure {
            root: root.to_path_buf(),
            language: None,
            files: Vec::new(),
            files_skipped: 0,
            warnings: vec!["No source files found in directory".to_string()],
        });
    }

    // b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3):
    // scope the polyglot scan to the PRIMARY language family.
    //
    // CL-15 made a directory scan analyze EVERY detected language and merge the
    // results — the right call for a genuinely balanced multi-language tree. But
    // real repos are typically ~one dominant language (85–100% of source files)
    // plus a long tail of minority-language files that are almost always
    // generated/vendored *documentation-site* assets. The `java-retrofit`
    // corpus is the pathological case: 306 `.java` source files plus a 754 KB
    // minified dokka `website/public/.../main.js` bundle (committed, not
    // gitignored, and not named `*.min.js` so the oversize cap does not catch
    // it). The minority JavaScript pass reads that bundle and emits ~211 MB of
    // structure for a Java project.
    //
    // `select_primary_language_family` keeps a language only when its file count
    // is a meaningful SHARE of the dominant language's count (see the constant
    // there). A balanced tree (CL-15's 1-Python/1-Go/1-TypeScript fixture) keeps
    // every language because each is 100% of the dominant; a 306-vs-34 tree
    // drops the 34-file docs minority. Dropped languages are returned in
    // `dropped` so the caller can WARN about them — the CL-15 "never silently
    // drop source" principle is preserved (the warning channel changes, the
    // silence does not return).
    let (langs, dropped) = select_primary_language_family(root, &all_langs);

    // Per-path winning entry. `from_path_with_siblings` names the owning
    // language; we keep the scan whose language matches it. When no scan
    // matches the owner (rare), keep the parse with the most definitions.
    struct Winner {
        owned: bool,
        defs: usize,
        file: FileStructure,
    }
    let mut by_path: HashMap<std::path::PathBuf, Winner> = HashMap::new();
    let mut order: Vec<std::path::PathBuf> = Vec::new();

    let mut files_skipped: u32 = 0;
    let mut warnings: Vec<String> = Vec::new();

    for lang in &langs {
        let s = get_code_structure(root, *lang, max_results, ignore_spec)?;
        files_skipped = files_skipped.saturating_add(s.files_skipped);
        for w in s.warnings {
            // Drop the per-language "No source files found" noise — the
            // merged result is non-empty by construction here.
            if w == "No source files found in directory" {
                continue;
            }
            warnings.push(w);
        }
        for file in s.files {
            // `file.path` is relative to `root` (see `extract_file_structure`).
            // Resolve ownership against the ABSOLUTE path so the sibling scan
            // in `from_path_with_siblings` can see neighbouring `.cpp` files
            // (a root-level `tinyxml2.h` has an empty parent otherwise, which
            // would mis-assign it to C and defeat the dedup).
            let abs_path = if file.path.is_absolute() {
                file.path.clone()
            } else {
                root.join(&file.path)
            };
            let owner = Language::from_path_with_siblings(&abs_path);
            let owned = owner == Some(*lang);
            let defs = file.definitions.len();
            match by_path.get_mut(&file.path) {
                None => {
                    order.push(file.path.clone());
                    by_path.insert(
                        file.path.clone(),
                        Winner {
                            owned,
                            defs,
                            file,
                        },
                    );
                }
                Some(existing) => {
                    // Prefer the owning-language scan; tie-break on the
                    // richer parse (most definitions). This deterministically
                    // keeps the C++ scan of a `.h` over the C scan.
                    let replace = match (existing.owned, owned) {
                        (false, true) => true,
                        (true, false) => false,
                        _ => defs > existing.defs,
                    };
                    if replace {
                        existing.owned = owned;
                        existing.defs = defs;
                        existing.file = file;
                    }
                }
            }
        }
    }

    let merged_files: Vec<FileStructure> =
        order.into_iter().filter_map(|p| by_path.remove(&p).map(|w| w.file)).collect();

    warnings.push(format!(
        "polyglot scan: analyzed {} language(s): {}",
        langs.len(),
        langs
            .iter()
            .map(|l| format!("{:?}", l))
            .collect::<Vec<_>>()
            .join(", ")
    ));

    // b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3):
    // never silently drop a minority language. When the primary-family gate
    // excluded languages, name them (and how to recover them) in the warnings
    // so the restriction is visible on every surface that echoes
    // `CodeStructure::warnings`. The CLI additionally mirrors this to stderr.
    if !dropped.is_empty() {
        warnings.push(format!(
            "polyglot scan: scoped to the primary language family — dropped {} minority \
             language(s): {}. Pass --lang to analyze one of them explicitly.",
            dropped.len(),
            dropped
                .iter()
                .map(|l| format!("{:?}", l))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Dominant autodetected language for schema parity; fall back to the
    // first scanned language only when `from_directory` can't decide on a
    // tree we already know is non-empty.
    let dominant = Language::from_directory(root).or_else(|| langs.first().copied());

    Ok(CodeStructure {
        root: root.to_path_buf(),
        language: dominant,
        files: merged_files,
        files_skipped,
        warnings,
    })
}

/// Extract structure from a single file
fn extract_file_structure(
    path: &Path,
    root: &Path,
    language: Language,
) -> TldrResult<FileStructure> {
    // p19-secondary-fixes-v1 (BUG-P19-05 + BUG-P19-08): honor the caller-
    // supplied `language` over path-extension detection. Otherwise
    // `tldr structure tinyxml2.h --lang cpp` re-detects `.h` as C and the
    // resulting C-parsed tree misses all the C++ classes (the cpp class
    // extractor walks a tree built by the C grammar, which has different
    // node kinds — `class_specifier` is cpp-only, so the cpp extractor
    // returned ~0 classes).
    let (tree, source, _) = crate::ast::parser::parse_file_with_lang(path, Some(language))?;

    let relative_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

    // canonical-function-enumerator-v1: derive `functions` and `methods` from
    // the canonical `extract_file` enumerator so that
    // `sum(files[].functions) + sum(files[].methods)` agrees with
    // `health.summary.functions_analyzed` and `dead.total_functions` on the
    // same input. Class names still come from the legacy AST walk because
    // structure historically emits them as bare strings.
    let module_info =
        super::extract::extract_from_tree(&tree, &source, language, path, Some(root))?;
    let functions: Vec<String> = module_info
        .functions
        .iter()
        .map(|f| f.name.clone())
        .collect();
    let methods: Vec<String> = module_info
        .classes
        .iter()
        .flat_map(|c| c.methods.iter().map(|m| m.name.clone()))
        .collect();

    let classes = match language {
        // W2-lua-structure (v0.5.0 AUDIT-FIX): Lua/Luau have no native `class`
        // node, so the legacy `extract_classes` codemap walk returns nothing.
        // The canonical table-class names now come from
        // `extract::extract_classes_detailed` (already computed above as
        // `module_info.classes`) — surface them here so `structure`'s
        // `classes[]` axis agrees with `extract` for the table-class idiom
        // (`local M = {}` + `function M.x()` / `function M:y()`).
        Language::Lua | Language::Luau => {
            module_info.classes.iter().map(|c| c.name.clone()).collect()
        }
        _ => extract_classes(&tree, &source, language),
    };
    let imports = extract_imports_from_tree(&tree, &source, language)?;
    let definitions = extract_definitions(&tree, &source, language);

    // schema-unification-v1 BUG-21: derive `method_infos` from `definitions`
    // (which already carry line + signature for kind="method" entries) so
    // overloaded methods with the same name remain distinguishable to JSON
    // consumers. Order is preserved from `definitions` (source order); we do
    // NOT attempt to align indices with the legacy `methods: Vec<String>`
    // field — they are independent views.
    let method_infos: Vec<MethodInfo> = definitions
        .iter()
        .filter(|d| d.kind == "method")
        .map(|d| MethodInfo {
            name: d.name.clone(),
            signature: d.signature.clone(),
            line: d.line_start,
            line_end: d.line_end,
        })
        .collect();

    Ok(FileStructure {
        path: relative_path,
        functions,
        classes,
        methods,
        method_infos,
        imports,
        definitions,
    })
}

/// Extract function names from a syntax tree
pub fn extract_functions(tree: &Tree, source: &str, language: Language) -> Vec<String> {
    let mut functions = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Python => extract_python_functions(&root, source, &mut functions, false),
        Language::TypeScript | Language::JavaScript => {
            extract_ts_functions(&root, source, &mut functions, false)
        }
        Language::Go => extract_go_functions(&root, source, &mut functions),
        Language::Rust => extract_rust_functions(&root, source, &mut functions),
        Language::Java => extract_java_functions(&root, source, &mut functions, false),
        Language::C => extract_c_functions(&root, source, &mut functions),
        Language::Cpp => extract_cpp_functions(&root, source, &mut functions),
        Language::Ruby => extract_ruby_functions(&root, source, &mut functions, false),
        Language::Scala => extract_scala_functions(&root, source, &mut functions),
        Language::Kotlin => extract_kotlin_functions(&root, source, &mut functions, false),
        Language::Ocaml => extract_ocaml_functions(&root, source, &mut functions),
        Language::Php => extract_php_functions(&root, source, &mut functions, false),
        Language::Swift => extract_swift_functions(&root, source, &mut functions),
        Language::CSharp => {} // C# has no free functions
        Language::Elixir => extract_elixir_functions(&root, source, &mut functions),
        Language::Lua => extract_lua_functions(&root, source, &mut functions),
        Language::Luau => extract_luau_functions(&root, source, &mut functions),
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1): free-function
        // names at file scope. Contract/interface/library members are
        // emitted by `extract_methods` instead.
        Language::Solidity => extract_solidity_functions(&root, source, &mut functions, false),
    }

    functions
}

/// Extract class names from a syntax tree
pub fn extract_classes(tree: &Tree, source: &str, language: Language) -> Vec<String> {
    let mut classes = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Python => extract_python_classes(&root, source, &mut classes),
        Language::TypeScript | Language::JavaScript => {
            extract_ts_classes(&root, source, &mut classes)
        }
        Language::Go => extract_go_structs(&root, source, &mut classes),
        Language::Rust => extract_rust_structs(&root, source, &mut classes),
        Language::Java => extract_java_classes(&root, source, &mut classes),
        Language::C => extract_c_structs(&root, source, &mut classes),
        Language::Cpp => {
            // cl4-interface-v1 (IT3-cpp per-file classes leak, GH #78) —
            // supersedes the M-106 enum-into-classes behaviour (Issue #46).
            // `enum_specifier` is NOT a class/struct: C++ enums are a
            // distinct definition kind. The M-106 fix folded enum names into
            // the per-file `classes[]` string projection, which leaked enum
            // names (e.g. tinyxml2's `Mode` / `XMLError`) into `structure`'s
            // `files[].classes`. Enums remain fully reported via the separate
            // `definitions[]` projection (kind="enum", emitted by
            // `extract_definitions` → `classify_definition_node`), so dropping
            // them from `classes[]` loses no information — it only stops the
            // class axis from advertising types that are not classes.
            // `extract_cpp_classes` handles `class_specifier` /
            // `struct_specifier` (and the macro-misparse `function_definition`
            // shape) only — disjoint from `enum_specifier`.
            extract_cpp_classes(&root, source, &mut classes);
        }
        Language::Ruby => extract_ruby_classes(&root, source, &mut classes),
        Language::Scala => extract_scala_classes(&root, source, &mut classes),
        Language::Kotlin => extract_kotlin_classes(&root, source, &mut classes),
        Language::Php => extract_php_classes(&root, source, &mut classes),
        Language::Swift => extract_swift_classes(&root, source, &mut classes),
        Language::CSharp => extract_csharp_classes(&root, source, &mut classes),
        Language::Elixir => extract_elixir_classes(&root, source, &mut classes),
        Language::Lua => {}  // Lua has no native classes
        Language::Luau => {} // Luau has no native classes
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1): treat
        // contract/interface/library declarations as the "class" axis.
        // Differentiation between the three kinds is preserved in
        // `collect_definitions` / `extract_classes_detailed`.
        Language::Solidity => extract_solidity_classes(&root, source, &mut classes),
        _ => {}
    }

    classes
}

/// Extract method names (methods inside classes) from a syntax tree
pub fn extract_methods(tree: &Tree, source: &str, language: Language) -> Vec<String> {
    let mut methods = Vec::new();
    let root = tree.root_node();

    match language {
        Language::Python => extract_python_functions(&root, source, &mut methods, true),
        Language::TypeScript | Language::JavaScript => {
            extract_ts_functions(&root, source, &mut methods, true)
        }
        Language::Go => {} // Go methods are extracted as functions with receivers
        Language::Rust => extract_rust_impl_methods(&root, source, &mut methods),
        Language::Java => extract_java_functions(&root, source, &mut methods, true),
        Language::C => {} // C has no methods
        Language::Cpp => extract_cpp_methods(&root, source, &mut methods),
        Language::Ruby => extract_ruby_functions(&root, source, &mut methods, true),
        Language::Scala => extract_scala_methods(&root, source, &mut methods),
        Language::Kotlin => extract_kotlin_functions(&root, source, &mut methods, true),
        Language::Php => extract_php_functions(&root, source, &mut methods, true),
        Language::Swift => extract_swift_methods(&root, source, &mut methods),
        Language::CSharp => extract_csharp_methods(&root, source, &mut methods),
        Language::Elixir => {} // Elixir has no methods (modules are not OOP classes)
        Language::Lua => {}    // Lua has no methods
        Language::Luau => {}   // Luau has no methods
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1): methods are
        // `function_definition` / `constructor_definition` /
        // `fallback_receive_definition` nodes whose ancestor chain
        // includes a `contract_body` (i.e. contract/interface/library
        // members).
        Language::Solidity => extract_solidity_functions(&root, source, &mut methods, true),
        _ => {}
    }

    methods
}

// =============================================================================
// Python extraction
// =============================================================================

fn extract_python_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Check if inside a class
                let is_method = is_inside_class(&child);

                if methods_only == is_method {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "class_definition" => {
                // Recurse into class body for methods
                if let Some(body) = child.child_by_field_name("body") {
                    extract_python_functions(&body, source, functions, methods_only);
                }
            }
            _ => {
                // Recurse into other nodes
                extract_python_functions(&child, source, functions, methods_only);
            }
        }
    }
}

fn extract_python_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "class_definition" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                classes.push(name);
            }
        }
        extract_python_classes(&child, source, classes);
    }
}

// =============================================================================
// TypeScript/JavaScript extraction
// =============================================================================

fn extract_ts_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration"
            | "function"
            | "generator_function_declaration"
            | "generator_function" => {
                if !methods_only {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "function_expression" => {
                // Named function expression: const x = function name() {}
                // Use variable name if inside a variable_declarator, else the function's own name
                if !methods_only {
                    let mut extracted = false;
                    if let Some(parent) = child.parent() {
                        if parent.kind() == "variable_declarator" {
                            if let Some(name_node) = parent.child_by_field_name("name") {
                                let name = get_node_text(&name_node, source);
                                functions.push(name);
                                extracted = true;
                            }
                        }
                    }
                    if !extracted {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = get_node_text(&name_node, source);
                            functions.push(name);
                        }
                    }
                }
            }
            "method_definition" | "method_signature" | "abstract_method_signature" => {
                // VAL-001: `method_signature` covers interface methods and
                // abstract class signatures in some grammar versions;
                // `abstract_method_signature` covers `abstract foo(): void;`
                // inside `abstract class` bodies in tree-sitter-typescript.
                // Both expose the name via the "name" field (property_identifier).
                if methods_only {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "arrow_function" => {
                // Arrow functions assigned to variables
                if !methods_only {
                    if let Some(parent) = child.parent() {
                        if parent.kind() == "variable_declarator" {
                            if let Some(name_node) = parent.child_by_field_name("name") {
                                let name = get_node_text(&name_node, source);
                                functions.push(name);
                            }
                        }
                    }
                }
            }
            "class_declaration" | "class" => {
                // Recurse into class body for methods
                if let Some(body) = child.child_by_field_name("body") {
                    extract_ts_functions(&body, source, functions, methods_only);
                }
            }
            _ => {
                extract_ts_functions(&child, source, functions, methods_only);
            }
        }
    }
}

fn extract_ts_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration" || child.kind() == "class" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                classes.push(name);
            }
        }
        extract_ts_classes(&child, source, classes);
    }
}

// =============================================================================
// Go extraction
// =============================================================================

fn extract_go_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_declaration" || child.kind() == "method_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                functions.push(name);
            }
        }
        extract_go_functions(&child, source, functions);
    }
}

/// Extract Go struct types as classes.
/// Go uses `type_declaration` containing `type_spec` with a `struct_type` body.
fn extract_go_structs(node: &Node, source: &str, structs: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "type_declaration" {
            // type_declaration contains one or more type_spec children
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "type_spec" {
                    // Check if it's a struct type (has struct_type child)
                    let mut has_struct = false;
                    let mut type_name = None;
                    let mut spec_cursor = inner.walk();
                    for spec_child in inner.children(&mut spec_cursor) {
                        if spec_child.kind() == "type_identifier" {
                            type_name = Some(get_node_text(&spec_child, source));
                        }
                        if spec_child.kind() == "struct_type"
                            || spec_child.kind() == "interface_type"
                        {
                            has_struct = true;
                        }
                    }
                    if has_struct {
                        if let Some(name) = type_name {
                            structs.push(name);
                        }
                    }
                }
            }
        }
        extract_go_structs(&child, source, structs);
    }
}

// =============================================================================
// Rust extraction
// =============================================================================

fn extract_rust_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_item" {
            // Only top-level functions (not inside impl blocks)
            if !is_inside_impl(&child) {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    functions.push(name);
                }
            }
        }
        extract_rust_functions(&child, source, functions);
    }
}

fn extract_rust_structs(node: &Node, source: &str, structs: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "struct_item"
            || child.kind() == "enum_item"
            || child.kind() == "trait_item"
        {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                structs.push(name);
            }
        }
        extract_rust_structs(&child, source, structs);
    }
}

fn extract_rust_impl_methods(node: &Node, source: &str, methods: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "impl_item" {
            // Get methods from impl block
            if let Some(body) = child.child_by_field_name("body") {
                let mut body_cursor = body.walk();
                for item in body.children(&mut body_cursor) {
                    if item.kind() == "function_item" {
                        if let Some(name_node) = item.child_by_field_name("name") {
                            let name = get_node_text(&name_node, source);
                            methods.push(name);
                        }
                    }
                }
            }
        } else if child.kind() == "trait_item" {
            // Get methods from trait definition (declaration_list body)
            let mut trait_cursor = child.walk();
            for trait_child in child.children(&mut trait_cursor) {
                if trait_child.kind() == "declaration_list" {
                    let mut body_cursor = trait_child.walk();
                    for item in trait_child.children(&mut body_cursor) {
                        if item.kind() == "function_item"
                            || item.kind() == "function_signature_item"
                        {
                            if let Some(name_node) = item.child_by_field_name("name") {
                                let name = get_node_text(&name_node, source);
                                methods.push(name);
                            }
                        }
                    }
                }
            }
        }
        extract_rust_impl_methods(&child, source, methods);
    }
}

/// rust-impl-qualifier-v1 (VAL-RUST-QUAL): emit `Type::method` qualified
/// names for every method defined inside a Rust `impl <Type> { ... }` or
/// `impl <Trait> for <Type> { ... }` block, plus `Trait::method` for
/// methods declared inside `trait <Trait> { ... }` bodies.
///
/// This is the qualifier-aware counterpart to [`extract_rust_impl_methods`]
/// which only emits bare method names. Used by the impact / whatbreaks
/// AST-fallback path (`find_function_in_ast`) so a user-typed
/// `Glob::parse` resolves only to the `parse` method that actually lives
/// inside `impl Glob { ... }` — pre-fix the bare-name extraction matched
/// every same-named `parse` across the corpus regardless of impl type.
///
/// Scope: handles the canonical
///   * `impl <Type>` → `Type::method`
///   * `impl <Trait> for <Type>` → `Type::method` (the type, not the trait)
///   * `impl<T> <Type><...>` (generic type) → `Type::method`
///   * `impl some::module::Type` (scoped type) → `Type::method`
///   * `trait <Trait>` → `Trait::method`
///
/// The fully-qualified disambiguator form `<MyType as Trait>::method` is
/// deferred — those would need separate UFCS handling.
pub fn extract_rust_impl_methods_qualified(
    tree: &Tree,
    source: &str,
    out: &mut Vec<String>,
) {
    fn walk(node: &Node, source: &str, out: &mut Vec<String>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "impl_item" {
                let type_name = rust_impl_type_name(&child, source);
                if let Some(body) = child.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for item in body.children(&mut body_cursor) {
                        if item.kind() == "function_item" {
                            if let Some(name_node) = item.child_by_field_name("name") {
                                let method = get_node_text(&name_node, source);
                                if let Some(ref ty) = type_name {
                                    out.push(format!("{ty}::{method}"));
                                } else {
                                    // Couldn't resolve the impl type — emit bare so
                                    // the candidate doesn't disappear entirely.
                                    out.push(method);
                                }
                            }
                        }
                    }
                }
            } else if child.kind() == "trait_item" {
                let trait_name = child
                    .child_by_field_name("name")
                    .map(|n| get_node_text(&n, source));
                let mut trait_cursor = child.walk();
                for trait_child in child.children(&mut trait_cursor) {
                    if trait_child.kind() == "declaration_list" {
                        let mut body_cursor = trait_child.walk();
                        for item in trait_child.children(&mut body_cursor) {
                            if item.kind() == "function_item"
                                || item.kind() == "function_signature_item"
                            {
                                if let Some(name_node) =
                                    item.child_by_field_name("name")
                                {
                                    let method = get_node_text(&name_node, source);
                                    if let Some(ref tr) = trait_name {
                                        out.push(format!("{tr}::{method}"));
                                    } else {
                                        out.push(method);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            walk(&child, source, out);
        }
    }

    walk(&tree.root_node(), source, out);
}

/// Extract the target type name from a Rust `impl_item` node.
///
/// Handles:
///   * `impl Foo { ... }` -> "Foo"
///   * `impl Trait for Foo { ... }` -> "Foo" (the type, not the trait)
///   * `impl<T> Foo<T> { ... }` -> "Foo" (strips generic params)
///   * `impl some::module::Type { ... }` -> "Type" (last segment)
///
/// Mirrors the private `get_impl_type_name` helper in
/// `crate::ast::extract` — duplicated here to keep this extractor
/// self-contained.
fn rust_impl_type_name(impl_node: &Node, source: &str) -> Option<String> {
    let type_node = impl_node.child_by_field_name("type")?;

    match type_node.kind() {
        "type_identifier" => Some(get_node_text(&type_node, source)),
        "generic_type" => type_node
            .child_by_field_name("type")
            .map(|n| get_node_text(&n, source)),
        "scoped_type_identifier" => type_node
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source)),
        _ => {
            let text = get_node_text(&type_node, source);
            let name = text.split('<').next().unwrap_or(&text).trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        }
    }
}

// =============================================================================
// Java extraction
// =============================================================================

fn extract_java_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "method_declaration" => {
                let is_in_class = is_inside_class(&child);
                if methods_only == is_in_class {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "constructor_declaration" => {
                // Constructors are always inside a class, so they are methods
                if methods_only {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            _ => {}
        }
        extract_java_functions(&child, source, functions, methods_only);
    }
}

fn extract_java_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration" || child.kind() == "interface_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                classes.push(name);
            }
        }
        extract_java_classes(&child, source, classes);
    }
}

// =============================================================================
// C extraction
// =============================================================================

fn extract_c_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_definition" {
            // Get the declarator which contains the function name
            if let Some(declarator) = child.child_by_field_name("declarator") {
                if let Some(name) = extract_c_function_name(&declarator, source) {
                    functions.push(name);
                }
            }
        }
        extract_c_functions(&child, source, functions);
    }
}

/// Extract function name from a C declarator node
/// Handles: function_declarator, pointer_declarator wrapping function_declarator
fn extract_c_function_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "function_declarator" => {
            // Direct function declarator - get the declarator field which is the identifier
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if declarator.kind() == "identifier" {
                    return Some(get_node_text(&declarator, source));
                } else if declarator.kind() == "parenthesized_declarator" {
                    // Handle (*func_ptr)(args) style
                    return extract_c_function_name(&declarator, source);
                }
            }
        }
        "pointer_declarator" => {
            // int *foo() - recurse into the declarator
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_c_function_name(&declarator, source);
            }
        }
        "identifier" => {
            return Some(get_node_text(node, source));
        }
        _ => {
            // Try children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = extract_c_function_name(&child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn extract_c_structs(node: &Node, source: &str, structs: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "struct_specifier" | "enum_specifier" => {
                // Named struct/enum: struct Foo { ... }
                // Require a body field so we don't emit bare parameter type
                // references (`void foo(struct Bar *b)`) or forward
                // declarations (`struct Bar;`) as struct definitions.
                if child.child_by_field_name("body").is_some() {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        structs.push(name);
                    }
                }
            }
            "type_definition" => {
                // typedef struct { ... } Name;
                // The type_definition contains a struct_specifier (anonymous) and a type_identifier
                let mut has_struct_or_enum = false;
                let mut typedef_name = None;
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    // Only count as a new struct/enum definition when the
                    // inner specifier actually has a body. `typedef struct
                    // Existing OtherName;` references an existing type and
                    // must not register `OtherName` as a new struct.
                    if (inner.kind() == "struct_specifier" || inner.kind() == "enum_specifier")
                        && inner.child_by_field_name("body").is_some()
                    {
                        has_struct_or_enum = true;
                    }
                    if inner.kind() == "type_identifier" {
                        typedef_name = Some(get_node_text(&inner, source));
                    }
                }
                if has_struct_or_enum {
                    if let Some(name) = typedef_name {
                        structs.push(name);
                    }
                }
            }
            _ => {}
        }
        extract_c_structs(&child, source, structs);
    }
}

// =============================================================================
// C++ extraction
// =============================================================================

fn extract_cpp_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    let source_bytes = source.as_bytes();

    for child in node.children(&mut cursor) {
        if child.kind() == "function_definition" {
            // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): a
            // `function_definition` that is actually a macro-decorated
            // class header (`class TINYXML2_LIB XMLDocument {…}`) is a
            // class, not a free function. Skip — methods inside are
            // emitted via `extract_cpp_classes` / `extract_cpp_methods`.
            if super::cpp_macro::is_macro_decorated_class(&child, source_bytes) {
                continue;
            }
            // Only count as free function if NOT inside a class/struct body
            if !is_inside_cpp_class(&child) {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if let Some(name) = extract_cpp_function_name(&declarator, source) {
                        functions.push(name);
                    }
                }
            }
        }
        extract_cpp_functions(&child, source, functions);
    }
}

/// Extract function name from a C++ declarator node
/// Handles: function_declarator, qualified_identifier, reference_declarator
fn extract_cpp_function_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "function_declarator" => {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_cpp_function_name(&declarator, source);
            }
        }
        "qualified_identifier" | "scoped_identifier" => {
            // namespace::function - get the name part
            if let Some(name) = node.child_by_field_name("name") {
                return Some(get_node_text(&name, source));
            }
            // Fallback: get full qualified name
            return Some(get_node_text(node, source));
        }
        "pointer_declarator" | "reference_declarator" => {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_cpp_function_name(&declarator, source);
            }
        }
        "identifier" | "field_identifier" | "destructor_name" => {
            return Some(get_node_text(node, source));
        }
        "operator_name" => {
            // operator+ etc.
            return Some(get_node_text(node, source));
        }
        _ => {
            // Try children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = extract_cpp_function_name(&child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn extract_cpp_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            // p19-secondary-fixes-v1 (BUG-P19-05): the `structure` cpp
            // extractor previously emitted `enum_specifier` as a class. Fix
            // is enum-vs-class separation. Enums are now captured in
            // `extract_c_structs` (which is also used for cpp file-level
            // structs/enums). Only emit real classes/structs here.
            "class_specifier" | "struct_specifier" => {
                // Require a `body` field before emitting the class. A forward
                // declaration `class XMLDocument;` parses as a `class_specifier`
                // WITH a name but NO body; emitting it duplicated every class
                // that also has a real definition later in the header (tinyxml2
                // reported 27 entries / 19 unique — the 8 forward decls doubled).
                // C's `extract_c_structs` already gates on body; mirror it here.
                // (A type reference like `friend class Foo;` / `class Foo* p;`
                // is likewise bodyless and correctly skipped.)
                if child.child_by_field_name("body").is_some() {
                    if let Some(name) = extract_cpp_class_name(&child, source) {
                        classes.push(name);
                        // Recurse INTO the body to pick up nested classes.
                        if let Some(body) = child.child_by_field_name("body") {
                            extract_cpp_classes(&body, source, classes);
                        }
                        continue;
                    }
                }
            }
            // p19-secondary-fixes-v1 (BUG-P19-05 + BUG-P19-08): tree-sitter-cpp
            // misparses `class MACRO Name { ... };` as a `function_definition`
            // whose `type` field is a `class_specifier` for `class MACRO`
            // and whose `declarator` is the real class name. Recover that
            // here so the dominant style in tinyxml2.h / Boost / Folly
            // surfaces real classes in `structure` output (the `interface`
            // command already handles this via the inheritance extractor —
            // BUG-P19-08 is the resulting class-count drift between the
            // two pipelines).
            "function_definition" | "declaration" => {
                if let Some(name) = extract_cpp_macro_misparse_class_name(&child, source) {
                    classes.push(name);
                    // p19-secondary-fixes-v1 (BUG-P19-05): recurse into the
                    // misparsed body so inner classes (e.g. `class DynArray`
                    // nested under tinyxml2's `class TINYXML2_LIB StrPair`)
                    // are emitted too. Use the function_definition's body
                    // (compound_statement) or the child class_specifier's
                    // body, whichever is present.
                    if let Some(body) = child.child_by_field_name("body") {
                        extract_cpp_classes(&body, source, classes);
                    } else {
                        // Fallback: scan children for a `compound_statement`.
                        let mut bcursor = child.walk();
                        for c in child.children(&mut bcursor) {
                            if c.kind() == "compound_statement"
                                || c.kind() == "field_declaration_list"
                            {
                                extract_cpp_classes(&c, source, classes);
                                break;
                            }
                        }
                    }
                    continue;
                }
            }
            _ => {}
        }
        extract_cpp_classes(&child, source, classes);
    }
}

/// Pull the class name from a `class_specifier` / `struct_specifier` node.
/// Falls back to the first `type_identifier` child if `name` field is
/// missing (the canonical tree-sitter-cpp shape varies by grammar
/// version).
fn extract_cpp_class_name(node: &Node, source: &str) -> Option<String> {
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = get_node_text(&name_node, source);
        if !name.is_empty() {
            return Some(name);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
            let name = get_node_text(&child, source);
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Recover the real class name from the tree-sitter-cpp misparse of
/// `class MACRO Name { ... };` as `function_definition` / `declaration`
/// with the macro consumed by an inner `class_specifier` and the real
/// name as the `declarator` identifier. Returns `None` for real
/// function definitions / variable declarations.
fn extract_cpp_macro_misparse_class_name(node: &Node, source: &str) -> Option<String> {
    let type_node = node.child_by_field_name("type")?;
    if type_node.kind() != "class_specifier" && type_node.kind() != "struct_specifier" {
        return None;
    }
    let declarator = node.child_by_field_name("declarator")?;
    if declarator.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&declarator, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Extract C++ methods: function_definition nodes inside class/struct bodies.
/// Only counts methods with actual bodies (function_definition), not forward
/// declarations or `= default`/`= delete` stubs.
fn extract_cpp_methods(node: &Node, source: &str, methods: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_specifier" | "struct_specifier" => {
                // Look inside the class/struct body (field_declaration_list)
                if let Some(body) = child.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for body_child in body.children(&mut body_cursor) {
                        if body_child.kind() == "function_definition" {
                            // Skip `= default` and `= delete` methods (no real body)
                            if cpp_has_default_or_delete(&body_child) {
                                continue;
                            }
                            // Inline method definition with body: void greet() { ... }
                            if let Some(declarator) = body_child.child_by_field_name("declarator") {
                                if let Some(name) = extract_cpp_function_name(&declarator, source) {
                                    methods.push(name);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        extract_cpp_methods(&child, source, methods);
    }
}

/// Check if a C++ function_definition has `= default` or `= delete` (no real body)
fn cpp_has_default_or_delete(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "default_method_clause" || child.kind() == "delete_method_clause" {
            return true;
        }
    }
    false
}

/// Check if a C++ node is inside a class or struct specifier body
fn is_inside_cpp_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_specifier" | "struct_specifier" => return true,
            "field_declaration_list" => {
                // field_declaration_list is the body of a class/struct
                if let Some(grandparent) = parent.parent() {
                    if matches!(grandparent.kind(), "class_specifier" | "struct_specifier") {
                        return true;
                    }
                }
            }
            "translation_unit" => return false, // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Ruby extraction
// =============================================================================

/// Extract Ruby functions/methods from AST
/// Ruby uses `method` nodes for both top-level functions and class methods.
/// `methods_only` = false: top-level methods only
/// `methods_only` = true: methods inside classes/modules only
fn extract_ruby_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "method" => {
                // Check if this method is inside a class or module
                let is_method = is_inside_ruby_class_or_module(&child);

                if methods_only == is_method {
                    // Get the method name from the identifier child
                    let mut method_cursor = child.walk();
                    for method_child in child.children(&mut method_cursor) {
                        if method_child.kind() == "identifier" {
                            let name = get_node_text(&method_child, source);
                            functions.push(name);
                            break;
                        }
                    }
                }
            }
            "singleton_method" => {
                // def self.method_name or def object.method_name
                // These are class methods (module functions)
                if methods_only {
                    let mut method_cursor = child.walk();
                    for method_child in child.children(&mut method_cursor) {
                        // The name is the second identifier (after "self" or object)
                        if method_child.kind() == "identifier" {
                            let name = get_node_text(&method_child, source);
                            // Skip "self" - we want the method name
                            if name != "self" {
                                functions.push(name);
                                break;
                            }
                        }
                    }
                }
            }
            "class" | "module" => {
                // Recurse into class/module body for methods.
                // In Ruby's tree-sitter grammar, `child_by_field_name("body")`
                // returns the `body_statement` node. We must use only ONE
                // recursion path to avoid double-counting methods.
                let body_found = child.child_by_field_name("body");
                if let Some(body) = body_found {
                    extract_ruby_functions(&body, source, functions, methods_only);
                } else {
                    // Fallback: iterate children for body_statement
                    let mut class_cursor = child.walk();
                    for class_child in child.children(&mut class_cursor) {
                        if class_child.kind() == "body_statement" {
                            extract_ruby_functions(&class_child, source, functions, methods_only);
                        }
                    }
                }
            }
            _ => {
                // Recurse into other nodes
                extract_ruby_functions(&child, source, functions, methods_only);
            }
        }
    }
}

/// Extract Ruby class and module names
fn extract_ruby_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class" | "module" => {
                // Get the class/module name from the constant child
                let mut class_cursor = child.walk();
                for class_child in child.children(&mut class_cursor) {
                    if class_child.kind() == "constant" || class_child.kind() == "scope_resolution"
                    {
                        let name = get_node_text(&class_child, source);
                        classes.push(name);
                        break;
                    }
                }
            }
            _ => {}
        }
        // Recurse to find nested classes/modules
        extract_ruby_classes(&child, source, classes);
    }
}

/// Check if a Ruby node is inside a class or module definition
fn is_inside_ruby_class_or_module(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class" | "module" | "body_statement" => {
                // body_statement alone isn't enough - check if its parent is class/module
                if parent.kind() == "body_statement" {
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "class" || grandparent.kind() == "module" {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }
            "program" => return false, // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Scala extraction
// =============================================================================

/// Extract Scala top-level functions (def inside object, or standalone)
/// Scala uses: function_definition for def foo(...) = ...
fn extract_scala_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Only top-level functions (in objects or at package level)
                // Skip methods inside class/trait definitions
                if !is_inside_scala_class_or_trait(&child) {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "object_definition" => {
                // Recurse into object body for functions
                if let Some(body) = child.child_by_field_name("body") {
                    extract_scala_functions(&body, source, functions);
                }
            }
            "template_body" => {
                // Recurse into template body
                extract_scala_functions(&child, source, functions);
            }
            _ => {
                // Recurse into other nodes
                extract_scala_functions(&child, source, functions);
            }
        }
    }
}

/// Extract Scala class and trait names (not objects -- objects are singletons, not classes)
fn extract_scala_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_definition" | "trait_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    classes.push(name);
                }
            }
            _ => {}
        }
        // Recurse to find nested classes
        extract_scala_classes(&child, source, classes);
    }
}

/// Extract Scala methods (functions inside class/trait)
fn extract_scala_methods(node: &Node, source: &str, methods: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Only methods inside class/trait definitions
                if is_inside_scala_class_or_trait(&child) {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        methods.push(name);
                    }
                }
            }
            "class_definition" | "trait_definition" => {
                // Recurse into class/trait body for methods
                if let Some(body) = child.child_by_field_name("body") {
                    extract_scala_methods(&body, source, methods);
                }
            }
            "template_body" => {
                // Recurse into template body
                extract_scala_methods(&child, source, methods);
            }
            _ => {
                // Recurse into other nodes
                extract_scala_methods(&child, source, methods);
            }
        }
    }
}

/// Check if a Scala node is inside a class or trait definition (but not object)
fn is_inside_scala_class_or_trait(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_definition" | "trait_definition" => return true,
            "object_definition" => return false, // Object methods are considered functions
            "compilation_unit" => return false,  // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Kotlin extraction
// =============================================================================

/// Extract Kotlin functions/methods from AST
/// Kotlin uses `function_declaration` for both top-level functions and class methods.
/// `methods_only` = false: top-level functions only (not inside class/object/interface)
/// `methods_only` = true: methods inside class/object/interface only
fn extract_kotlin_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // Check if inside a class, object, or interface
                let is_method = is_inside_kotlin_class_or_object(&child);

                if methods_only == is_method {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "class_declaration" | "object_declaration" | "companion_object" => {
                // Recurse into class/object/companion body for methods
                let mut class_cursor = child.walk();
                for class_child in child.children(&mut class_cursor) {
                    if class_child.kind() == "class_body" {
                        extract_kotlin_functions(&class_child, source, functions, methods_only);
                    }
                }
            }
            _ => {
                extract_kotlin_functions(&child, source, functions, methods_only);
            }
        }
    }
}

/// Extract Kotlin class, object, and interface names
fn extract_kotlin_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "object_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    classes.push(name);
                }
            }
            _ => {}
        }
        extract_kotlin_classes(&child, source, classes);
    }
}

/// Check if a Kotlin node is inside a class, object, or interface definition
fn is_inside_kotlin_class_or_object(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_declaration" | "object_declaration" | "companion_object" => return true,
            "class_body" => {
                // class_body is a container -- check if its parent is a class-like node
                if let Some(grandparent) = parent.parent() {
                    if matches!(
                        grandparent.kind(),
                        "class_declaration" | "object_declaration" | "companion_object"
                    ) {
                        return true;
                    }
                }
            }
            "source_file" => return false, // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Solidity extraction (v0.5.0 SOL-004 — solidity-ast-extractor-v1)
//
// Wire the structure/definition/cohesion fast-path. SOL-003 already
// owns `extract.rs` (detailed FunctionInfo/ClassInfo/EventInfo/ErrorInfo
// shapes); this layer surfaces *names only* for the lightweight
// `tldr structure` / `tldr definition` / `tldr cohesion` consumers.
//
// Modeled on the Kotlin template (per oracle research):
//   `extract_kotlin_functions` ↔ `extract_solidity_functions`
//   `extract_kotlin_classes`   ↔ `extract_solidity_classes`
//   `is_inside_kotlin_class_or_object` ↔ `is_inside_solidity_contract`
//
// Solidity AST shape (per tree-sitter-solidity 1.2.13 node-types.json):
//   - `source_file` root
//   - `contract_declaration` / `interface_declaration` /
//     `library_declaration` — own a `body` field of kind `contract_body`
//   - `function_definition` / `constructor_definition` /
//     `fallback_receive_definition` / `modifier_definition` /
//     `event_definition` / `error_declaration` /
//     `struct_declaration` / `enum_declaration` —
//     emitted both at file scope and as direct children of `contract_body`.
//   - `function_definition` carries a `name` field. The
//     `constructor_definition` / `fallback_receive_definition` nodes
//     have no `name` field — we synthesize `constructor` / `fallback`
//     / `receive` keyword strings to match the SOL-003 extract layer.
// =============================================================================

/// Extract Solidity function/method names from AST.
///
/// `methods_only = false`: free functions only (NOT inside any contract /
/// interface / library body).
/// `methods_only = true`: members only (must be inside a contract /
/// interface / library body).
/// v0.5.0 SOL-CONV-R1-5 (V11): collect Solidity contract / interface /
/// library member function names (i.e., `methods_only=true`). The
/// general `extract_functions` entrypoint passes `methods_only=false`
/// because the public API focuses on free functions; the verify
/// aggregator needs the full surface so its per-function contract /
/// NatSpec extraction covers contract members too.
pub fn extract_solidity_methods_for_verify(tree: &tree_sitter::Tree, source: &str) -> Vec<String> {
    let mut functions = Vec::new();
    extract_solidity_functions(&tree.root_node(), source, &mut functions, true);
    functions
}

fn extract_solidity_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                let is_method = is_inside_solidity_contract(&child);
                if methods_only == is_method {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        functions.push(get_node_text(&name_node, source));
                    }
                }
            }
            "constructor_definition" => {
                // Constructors are always inside a contract body.
                if methods_only {
                    functions.push("constructor".to_string());
                }
            }
            "fallback_receive_definition" => {
                // Fallback/receive are always inside a contract body.
                if methods_only {
                    functions.push(solidity_fallback_receive_keyword(&child, source));
                }
            }
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration" => {
                // Recurse into the contract body so its members are
                // discovered when `methods_only == true`.
                if let Some(body) = child.child_by_field_name("body") {
                    extract_solidity_functions(&body, source, functions, methods_only);
                }
            }
            _ => {
                extract_solidity_functions(&child, source, functions, methods_only);
            }
        }
    }
}

/// Extract Solidity contract / interface / library names.
fn extract_solidity_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    classes.push(get_node_text(&name_node, source));
                }
            }
            _ => {}
        }
        extract_solidity_classes(&child, source, classes);
    }
}

/// Return `true` if `node` has an ancestor `contract_declaration` /
/// `interface_declaration` / `library_declaration` (or their
/// `contract_body` container). Used to distinguish free functions from
/// contract members. Modeled on `is_inside_kotlin_class_or_object`.
fn is_inside_solidity_contract(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "contract_declaration"
            | "interface_declaration"
            | "library_declaration"
            | "contract_body" => return true,
            "source_file" => return false, // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

/// Find the `fallback` / `receive` keyword token under a
/// `fallback_receive_definition` node. Falls back to `"fallback"` when
/// the grammar emits no distinguishable keyword (defensive).
fn solidity_fallback_receive_keyword(node: &Node, source: &str) -> String {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "fallback" || kind == "receive" {
            return kind.to_string();
        }
        let txt = get_node_text(&child, source);
        if txt == "fallback" || txt == "receive" {
            return txt;
        }
    }
    "fallback".to_string()
}

// =============================================================================
// OCaml extraction
// =============================================================================

/// Extract OCaml function names from AST.
/// OCaml functions are `value_definition` nodes containing `let_binding` children
/// that have `parameter` children (distinguishing functions from value bindings).
/// The function name is in the `pattern` field of the `let_binding`.
fn extract_ocaml_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        if child.kind() == "value_definition" {
            // m114-adapter-tail-v1 (v0.4.2 M-114): skip `let_expression`-
            // parented `value_definition` nodes — those are the
            // tree-sitter-ocaml wrapper for inner `let ... in body`
            // bindings, NOT module-level definitions. Without this guard
            // the recursive walk leaked let-in locals as top-level
            // functions (mirrors the fix in
            // `extract_ocaml_functions_detailed`).
            let is_let_in = child
                .parent()
                .map(|p| p.kind() == "let_expression")
                .unwrap_or(false);
            if !is_let_in {
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "let_binding" {
                        // Only extract if it has parameters (i.e., is a function, not a value binding)
                        if ocaml_binding_has_params_simple(&inner) {
                            if let Some(pattern_node) = inner.child_by_field_name("pattern") {
                                let name = get_node_text(&pattern_node, source);
                                // Skip anonymous bindings like `let () = ...`
                                if name != "()" && !name.is_empty() {
                                    functions.push(name);
                                }
                            }
                        }
                    }
                }
            }
        }
        extract_ocaml_functions(&child, source, functions);
    }
}

/// Check if an OCaml let_binding has parameter children (i.e., is a function definition).
fn ocaml_binding_has_params_simple(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameter" {
            return true;
        }
    }
    false
}

/// Return true when an OCaml `value_definition` node binds a FUNCTION (either a
/// parameterised `let f x = ...` or a point-free `let f = function | ...` /
/// `let f = fun x -> ...`). A `value_definition` may wrap several `let_binding`
/// children (`let a = .. and b = ..`); it counts as a function if ANY binding
/// is function-shaped. Mirrors `ocaml_binding_has_params` in `extract.rs` so the
/// `structure` and `extract` pipelines agree on OCaml function classification.
fn ocaml_value_definition_is_function(node: &Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "let_binding" {
            let mut inner = child.walk();
            for binding_child in child.children(&mut inner) {
                match binding_child.kind() {
                    "parameter" => return true,
                    "function_expression" | "fun_expression" => return true,
                    _ => {}
                }
            }
        }
    }
    false
}

// =============================================================================
// PHP extraction
// =============================================================================

/// Extract PHP functions/methods from AST
/// PHP uses `function_definition` for standalone functions and `method_declaration` for class methods.
/// `methods_only` = false: top-level functions only
/// `methods_only` = true: methods inside classes only
fn extract_php_functions(
    node: &Node,
    source: &str,
    functions: &mut Vec<String>,
    methods_only: bool,
) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                // Standalone function: function hello() {}
                // Check if inside a class
                let is_method = is_inside_php_class(&child);

                if methods_only == is_method {
                    // Get the function name
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "method_declaration" => {
                // Class method: public function greet() {}
                if methods_only {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        functions.push(name);
                    }
                }
            }
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                // Recurse into class/interface/trait body for methods.
                // In PHP's tree-sitter grammar, the body field IS the declaration_list.
                // Only recurse via one path to avoid double-counting.
                if let Some(body) = child.child_by_field_name("body") {
                    extract_php_functions(&body, source, functions, methods_only);
                } else {
                    // Fallback: look for declaration_list directly
                    let mut class_cursor = child.walk();
                    for class_child in child.children(&mut class_cursor) {
                        if class_child.kind() == "declaration_list" {
                            extract_php_functions(&class_child, source, functions, methods_only);
                        }
                    }
                }
            }
            _ => {
                // Recurse into other nodes
                extract_php_functions(&child, source, functions, methods_only);
            }
        }
    }
}

/// Extract PHP class, interface, and trait names
fn extract_php_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                // Get the class/interface/trait name
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    classes.push(name);
                }
            }
            _ => {}
        }
        // Recurse to find nested classes (though PHP doesn't support truly nested classes,
        // we still recurse for completeness)
        extract_php_classes(&child, source, classes);
    }
}

/// Check if a PHP node is inside a class, interface, or trait definition
fn is_inside_php_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "declaration_list" => {
                // declaration_list alone isn't enough - check if its parent is a class type
                if parent.kind() == "declaration_list" {
                    if let Some(grandparent) = parent.parent() {
                        if matches!(
                            grandparent.kind(),
                            "class_declaration" | "interface_declaration" | "trait_declaration"
                        ) {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }
            "program" => return false, // Top-level
            _ => {}
        }
        current = parent.parent();
    }
    false
}

// =============================================================================
// Swift extraction (stubs - pending full implementation)
// =============================================================================

fn extract_swift_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declaration" && !is_inside_class(&child) {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                functions.push(name);
            }
        }
        extract_swift_functions(&child, source, functions);
    }
}

fn extract_swift_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_declaration" || child.kind() == "protocol_declaration" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = get_node_text(&name_node, source);
                classes.push(name);
            }
        }
        extract_swift_classes(&child, source, classes);
    }
}

fn extract_swift_methods(node: &Node, source: &str, methods: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if is_inside_class(&child) {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = get_node_text(&name_node, source);
                        methods.push(name);
                    }
                }
            }
            "init_declaration" => {
                // Swift init() constructors inside classes
                if is_inside_class(&child) {
                    methods.push("init".to_string());
                }
            }
            _ => {}
        }
        extract_swift_methods(&child, source, methods);
    }
}

// =============================================================================
// C# extraction (stubs - pending full implementation)
// =============================================================================

fn extract_csharp_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "interface_declaration" | "struct_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    classes.push(name);
                }
            }
            _ => {}
        }
        extract_csharp_classes(&child, source, classes);
    }
}

fn extract_csharp_methods(node: &Node, source: &str, methods: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    methods.push(name);
                }
            }
            "constructor_declaration" => {
                // C# constructors: public Animal(string name) { }
                // The constructor name is an identifier child (same as the class name)
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    methods.push(name);
                } else {
                    // Fallback: find the first identifier child
                    let mut inner_cursor = child.walk();
                    for inner in child.children(&mut inner_cursor) {
                        if inner.kind() == "identifier" {
                            let name = get_node_text(&inner, source);
                            methods.push(name);
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
        extract_csharp_methods(&child, source, methods);
    }
}

// =============================================================================
// Elixir extraction (stubs - pending full implementation)
// =============================================================================

fn extract_elixir_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            // def/defp/defmacro/defmacrop in Elixir are all `call` nodes.
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "identifier" {
                    let text = get_node_text(&inner, source);
                    if text == "def"
                        || text == "defp"
                        || text == "defmacro"
                        || text == "defmacrop"
                    {
                        // Next sibling holds the name; it may be an `arguments`
                        // wrapper, a bare `call`, OR a `binary_operator` for a
                        // guarded clause (`def f(x) when guard`).
                        if let Some(args) = inner.next_sibling() {
                            if let Some(fname) =
                                elixir_def_name_from_args(&args, source)
                            {
                                if !fname.is_empty() && !functions.contains(&fname) {
                                    functions.push(fname);
                                }
                            }
                        }
                    }
                }
            }
        }
        extract_elixir_functions(&child, source, functions);
    }
}

/// Resolve the function/macro name from the argument node following an Elixir
/// `def`/`defp`/`defmacro`/`defmacrop` keyword. Handles the three first-arg
/// shapes the tree-sitter-elixir grammar produces:
///   * `arguments` wrapper or bare `call` — `def f(x)` (name = inner call's
///     first child, or the bare identifier).
///   * `binary_operator` — a guarded clause `def f(x) when guard`; descend to
///     the inner `call` (LHS of `when`) and take its name.
fn elixir_def_name_from_args(args: &Node, source: &str) -> Option<String> {
    // A guarded head: `f(x) when guard` is a binary_operator whose left side
    // is the real `call`.
    if args.kind() == "binary_operator" {
        let mut c = args.walk();
        for child in args.children(&mut c) {
            if child.kind() == "call" {
                if let Some(name_node) = child.child(0) {
                    return Some(get_node_text(&name_node, source));
                }
            }
        }
        return None;
    }

    // `arguments` wrapper or a bare `call`.
    let name_node = args.child(0)?;
    match name_node.kind() {
        "call" => {
            // `f(x)` — name is the call's first child.
            if let Some(n) = name_node.child(0) {
                Some(get_node_text(&n, source))
            } else {
                Some(get_node_text(&name_node, source))
            }
        }
        "identifier" => Some(get_node_text(&name_node, source)),
        // Guarded head nested directly under `arguments`.
        "binary_operator" => elixir_def_name_from_args(&name_node, source),
        _ => None,
    }
}

fn extract_elixir_classes(node: &Node, source: &str, classes: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            let mut inner_cursor = child.walk();
            for inner in child.children(&mut inner_cursor) {
                if inner.kind() == "identifier" {
                    let text = get_node_text(&inner, source);
                    if text == "defmodule" {
                        if let Some(args) = inner.next_sibling() {
                            if let Some(name_node) = args.child(0) {
                                let name = get_node_text(&name_node, source);
                                classes.push(name);
                            }
                        }
                    }
                }
            }
        }
        extract_elixir_classes(&child, source, classes);
    }
}

// =============================================================================
// Lua extraction (stubs - pending full implementation)
// =============================================================================

fn extract_lua_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                // Handles: function foo(), local function foo(),
                //          function Table.method(), function Table:method()
                if let Some(name) = extract_lua_function_name(&child, source) {
                    functions.push(name);
                }
                // Don't recurse into function_declaration children (no nested functions to find)
                continue;
            }
            "variable_declaration" => {
                // Handles: local foo = function() end
                // Structure: variable_declaration > [local] assignment_statement >
                //   variable_list > identifier + expression_list > function_definition
                extract_lua_variable_function(&child, source, functions);
                // Don't recurse -- we already looked inside via extract_lua_variable_function
                continue;
            }
            "assignment_statement" => {
                // Handles: foo = function() end (without local, at top level)
                extract_lua_assignment_function(&child, source, functions);
                continue;
            }
            _ => {}
        }
        extract_lua_functions(&child, source, functions);
    }
}

/// Extract function name from a Lua function_declaration node.
/// Handles: identifier (simple name), dot_index_expression (Table.method),
/// method_index_expression (Table:method)
fn extract_lua_function_name(node: &Node, source: &str) -> Option<String> {
    // Try field name first
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = get_node_text(&name_node, source);
        return Some(name);
    }
    // Fallback: iterate children for identifier/dot_index_expression/method_index_expression
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let name = get_node_text(&child, source);
                // Skip keywords
                if name != "function" && name != "local" && name != "end" {
                    return Some(name);
                }
            }
            "dot_index_expression" | "method_index_expression" => {
                // Table.method or Table:method -- extract the last identifier (method name)
                if let Some(field) = child.child_by_field_name("field") {
                    return Some(get_node_text(&field, source));
                }
                // Fallback: get the last identifier child
                let mut inner_cursor = child.walk();
                let mut last_ident = None;
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "identifier" {
                        last_ident = Some(get_node_text(&inner, source));
                    }
                }
                return last_ident;
            }
            _ => {}
        }
    }
    None
}

/// Extract function from a variable_declaration like: local foo = function() end
fn extract_lua_variable_function(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "assignment_statement" {
            extract_lua_assignment_function(&child, source, functions);
        }
    }
}

/// Extract function from an assignment_statement if RHS is function_definition
fn extract_lua_assignment_function(node: &Node, source: &str, functions: &mut Vec<String>) {
    // Check if the expression_list contains a function_definition
    let mut has_function_def = false;
    let mut inner_cursor = node.walk();
    for inner in node.children(&mut inner_cursor) {
        if inner.kind() == "expression_list" {
            let mut expr_cursor = inner.walk();
            for expr in inner.children(&mut expr_cursor) {
                if expr.kind() == "function_definition" {
                    has_function_def = true;
                    break;
                }
            }
        }
    }
    if !has_function_def {
        return;
    }
    // Get the variable name from variable_list. The LHS may be:
    //   - `identifier`                 -> `foo = function() end`
    //   - `dot_index_expression`       -> `M.foo = function() end`
    //   - `method_index_expression`    -> `M:foo = function() end`
    //   - `bracket_index_expression`   -> `t["k"] = function() end`
    // The latter three (`*_index_expression`) are `variable` supertypes and
    // appear as direct children of `variable_list`. Each must yield a name so
    // the definition is visible to `structure` (and downstream `dead`,
    // `explain`, `impact`). We emit the full qualified text for index forms so
    // distinct keys remain distinct (e.g. the 11
    // `method_handlers["textDocument/..."]` handlers).
    let mut inner_cursor2 = node.walk();
    for inner in node.children(&mut inner_cursor2) {
        if inner.kind() == "variable_list" {
            if let Some(name_node) = inner.child(0) {
                match name_node.kind() {
                    "identifier" | "dot_index_expression" | "method_index_expression"
                    | "bracket_index_expression" => {
                        functions.push(get_node_text(&name_node, source));
                        return;
                    }
                    _ => {}
                }
            }
        }
    }
}

// =============================================================================
// Luau extraction (stubs - pending full implementation)
// =============================================================================

fn extract_luau_functions(node: &Node, source: &str, functions: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" | "local_function" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source);
                    functions.push(name);
                }
            }
            _ => {}
        }
        extract_luau_functions(&child, source, functions);
    }
}

// =============================================================================
// Definition extraction (DefinitionInfo population)
// =============================================================================

/// Extract all definitions (functions, classes, structs, methods) from a syntax tree
/// as `DefinitionInfo` entries with line ranges and signatures.
///
/// This walks the tree-sitter AST recursively and classifies nodes as function-like
/// or class-like, mirroring the logic in `search/enriched.rs::classify_node`.
/// Detect whether a Ruby `class` AST node is a unit-test fixture.
///
/// m114-adapter-tail-v1 (v0.4.2 M-114): pattern-matches the superclass
/// chain against the canonical minitest / test-unit / activesupport
/// base classes. Returns `true` when the superclass name (either a
/// bare `constant` like `Test`, or a `scope_resolution` like
/// `Minitest::Test`) matches one of the known endings.
///
/// Matched bases (case-sensitive, suffix match on the rightmost
/// `::`-segment so namespaced aliases such as `MyApp::Test::TestCase`
/// still resolve):
/// * `Minitest::Test`, `Minitest::Spec`
/// * `Test::Unit::TestCase`
/// * `ActiveSupport::TestCase`
///
/// NOT matched: arbitrary RSpec `describe` blocks (those are call
/// expressions, not class nodes — handled at the discovery layer if
/// needed; outside the scope of this fix).
fn ruby_class_is_test(class_node: &Node, source: &str) -> bool {
    let superclass = match class_node.child_by_field_name("superclass") {
        Some(s) => s,
        None => return false,
    };
    // Walk children of the `superclass` node and pick the first
    // `constant` / `scope_resolution` child (the punctuation `<` is a
    // sibling and is intentionally skipped).
    let mut cursor = superclass.walk();
    for child in superclass.children(&mut cursor) {
        match child.kind() {
            "constant" | "scope_resolution" => {
                let text = match child.utf8_text(source.as_bytes()) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                return ruby_is_test_base_name(text);
            }
            _ => {}
        }
    }
    false
}

/// Whether `name` matches one of the canonical Ruby unit-test base
/// classes. Suffix-matches on the rightmost `::`-segment so
/// re-aliased forms (e.g. `MyProj::Minitest::Test`) still flag.
fn ruby_is_test_base_name(name: &str) -> bool {
    // Exact matches against the fully-qualified canonical names.
    const EXACT: &[&str] = &[
        "Minitest::Test",
        "Minitest::Spec",
        "MiniTest::Test",      // legacy camelCase
        "MiniTest::Unit::TestCase",
        "Test::Unit::TestCase",
        "ActiveSupport::TestCase",
    ];
    for b in EXACT {
        if name == *b {
            return true;
        }
    }
    // Suffix match: trailing `::Minitest::Test` etc.
    for b in EXACT {
        let suffix = format!("::{}", b);
        if name.ends_with(&suffix) {
            return true;
        }
    }
    false
}

fn extract_definitions(tree: &Tree, source: &str, language: Language) -> Vec<DefinitionInfo> {
    let mut definitions = Vec::new();
    let root = tree.root_node();
    collect_definitions(root, source, language, &mut definitions);
    definitions
}

/// Recursively collect definition nodes from a tree-sitter AST.
fn collect_definitions(
    node: Node,
    source: &str,
    language: Language,
    definitions: &mut Vec<DefinitionInfo>,
) {
    let kind = node.kind();

    // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): cpp macro-
    // decorated class recovery. tree-sitter-cpp misparses
    // `class MACRO Name : public Base { ... };` as a `function_definition`
    // whose children are `class_specifier(class MACRO)` +
    // `identifier(Name)` + (optional) `ERROR(': public Base')` +
    // `compound_statement(body)`. Without recovery,
    //   - `classify_definition_node("function_definition") = (true, false)`
    //     emits the symbol as `kind:"function"` with name `Name`
    //     (the declarator identifier).
    //   - the inner bodyless `class_specifier` is then emitted as
    //     `kind:"class"` with name = the MACRO (from `child_by_field_name("name")`).
    // The dual emission produces the iter-2 audit's L-1 drift: same line
    // reports `XMLDocument` as function AND `TINYXML2_LIB` as class.
    // Recover both pieces here.
    if matches!(language, Language::Cpp | Language::C) && kind == "function_definition" {
        if let Some(class_name) =
            super::cpp_macro::macro_decorated_class_name(&node, source.as_bytes())
        {
            let line_start = node.start_position().row as u32 + 1;
            let line_end = node.end_position().row as u32 + 1;
            let signature = extract_def_signature(node, source);
            definitions.push(DefinitionInfo {
                name: class_name,
                kind: "class".to_string(),
                line_start,
                line_end,
                signature,
                is_test: false,
            });
            // Recurse INTO children so methods inside the body and any
            // nested classes are still collected, but skip the bodyless
            // inner `class_specifier` shell whose `name` field carries
            // the MACRO identifier (would otherwise emit a phantom
            // `kind:"class"` for the macro). See `extract_cpp_classes_detailed`
            // (`ast/extract.rs`) for the mirroring suppression.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let is_macro_shell = matches!(
                    child.kind(),
                    "class_specifier" | "struct_specifier"
                ) && child.child_by_field_name("body").is_none();
                if is_macro_shell {
                    continue;
                }
                collect_definitions(child, source, language, definitions);
            }
            return;
        }
    }

    // Elixir: def/defp/defmodule are macro calls parsed as "call" nodes.
    // Handle them specially before the generic path.
    if language == Language::Elixir && kind == "call" {
        if let Some(def_info) = try_elixir_call_definition(node, source) {
            definitions.push(def_info);
        }
    }

    // Lua: function-valued assignments are NOT `function_declaration` nodes,
    // so they are invisible to `classify_definition_node`. Detect
    //   `t.x = function() end`   (dot_index_expression LHS)
    //   `t["k"] = function() end`(bracket_index_expression LHS)
    //   `t:m = function() end`   (method_index_expression LHS)
    //   `local f = function()`   (variable_declaration wrapping the above)
    //   `f = function() end`     (identifier LHS)
    // and emit them as `kind:"function"` definitions so `structure` (and the
    // `definitions[]`-derived `functions[]` projection, plus downstream
    // `explain` / `impact` / `dead`) see them. Without this, the 11
    // `method_handlers["textDocument/..."]` LSP handlers were dropped
    // (gaps IT3-lua-01 / IT3-lua-03 / IT3-lua-04). We push and then return,
    // because the function body is recursed into explicitly below so nested
    // definitions are still collected (and the `function_definition` RHS is
    // NOT itself a named definition to double-emit).
    if matches!(language, Language::Lua) {
        if let Some((def_info, body)) = try_lua_function_assignment_definition(node, source) {
            definitions.push(def_info);
            if let Some(body) = body {
                collect_definitions(body, source, language, definitions);
            }
            return;
        }
    }

    // Constants: detect const/static/UPPER_CASE assignments across languages.
    // cross-cutting-and-clear-fix-bugs-v1 (P18.Pattern-B): track whether
    // this node was already emitted as a constant. If so, suppress the
    // field emission below — Java's `private static final String FOO = ...;`
    // is BOTH a constant (by `static final` + UPPER_CASE) AND a field
    // (by structural class-scope position), and the previous code emitted
    // it twice with different `kind` values.
    let mut emitted_as_constant = false;
    if let Some(const_def) = try_constant_definition(node, source, language) {
        definitions.push(const_def);
        emitted_as_constant = true;
    }

    let (is_func, is_class) = classify_definition_node(kind, language);

    // VAL-001: In C, `struct_specifier` / `enum_specifier` without a `body`
    // field is a bare type reference (parameter type like `struct sockaddr *a`,
    // forward declaration, or sizeof expression) — NOT a definition. Guard
    // here rather than in classify_definition_node because classify takes a
    // `&str` kind without access to node fields.
    let is_bodyless_c_specifier = is_class
        && matches!(kind, "struct_specifier" | "enum_specifier")
        && node.child_by_field_name("body").is_none();

    // OCaml `value_definition` is classified is_func unconditionally, but the
    // generic walk also descends into `let ... in body` expressions whose inner
    // bindings are ALSO `value_definition` nodes parented by `let_expression`.
    // Without a guard those let-in locals leaked into `definitions[]` /
    // `method_infos[]` as if they were top-level functions (dune's util.ml
    // surfaced `contexts`/`internal_path`/`context_exn`/`prog`/`scheduler`),
    // and plain value bindings (`let all = [...]`) were emitted as functions
    // too. Mirror the dedicated `extract_ocaml_functions` predicate: skip a
    // `value_definition` that is let-in-parented OR whose binding is not
    // function-shaped. OCaml-gated so no other grammar is affected.
    let is_non_function_ocaml_value = matches!(language, Language::Ocaml)
        && kind == "value_definition"
        && (node
            .parent()
            .map(|p| p.kind() == "let_expression")
            .unwrap_or(false)
            || !ocaml_value_definition_is_function(&node));

    if (is_func || is_class) && !is_bodyless_c_specifier && !is_non_function_ocaml_value {
        if let Some(name) = get_definition_node_name(node, source) {
            // m002-java-cross-pipeline-drift-v1 (v0.4.2 M-109): For Java
            // function/class/method/constructor/interface/enum/record
            // declarations, route through `decl_keyword_line_from_node`
            // so the line we surface here matches the line emitted by
            // `extract` / `explain` / `slice` (which already adopted the
            // helper). Without this, `structure` / `interface` /
            // `contracts` / `verify` / `definition` / `cohesion` reported
            // the line of a leading `@Annotation` / `modifiers` child
            // while the other pipelines reported the decl-keyword line
            // for the SAME symbol — a cross-pipeline drift.
            //
            // Originally gated on `Language::Java` (M-109) then widened to
            // Solidity (SOL-004). v0.5.0 CL-10 (GH #81): the gate ALSO has
            // to cover every grammar whose declaration node emits leading
            // annotation/attribute/modifier children that shift the bare
            // `node.start_position()` line off the decl keyword. The shared
            // `decl_keyword_line_from_node` helper already recognises those
            // child kinds (`attribute`/`attributes`/`modifier` for Swift,
            // `modifiers`/`annotation` for Java, the Kotlin `*_modifier`
            // family, and Scala `annotations`) — so the only thing missing
            // was the LANGUAGE GATE here. Swift `@inlinable` /
            // `@discardableResult` / `@available(...)`-decorated methods were
            // reporting the attribute line in `structure` / `interface` /
            // `contracts` / `verify` / `definition` / `cohesion` while
            // `extract` / `explain` / `slice` reported the `func` keyword
            // line for the SAME symbol.
            //
            // Languages WITHOUT leading-annotation grammar shapes (Rust,
            // Python — handled via `decorated_definition` parent — Go, C,
            // C++, JS/TS, …) place the decl keyword as the first child, so
            // `decl_keyword_line_from_node` returns the same line as
            // `node.start_position()` for them; routing them through the
            // helper is a no-op. We still gate explicitly so the behaviour
            // is intentional and the test `m002_java_cross_pipeline_v1`
            // (which pins Rust/Python/Go to the bare start line) keeps
            // passing.
            let line_start = if matches!(
                language,
                Language::Java
                    | Language::Solidity
                    | Language::Swift
                    | Language::Kotlin
                    | Language::Scala
                    | Language::CSharp
            ) {
                decl_keyword_line_from_node(&node)
            } else {
                node.start_position().row as u32 + 1 // 1-indexed
            };
            let line_end = node.end_position().row as u32 + 1;

            // Extract signature. RC2-META Stage 1: function-axis declarations
            // (methods/functions/constructors) render from the HEADER span via
            // the shared resolver so an inline body block no longer leaks into
            // the signature (`m(): void {} }` -> `m(): void`). Class-axis
            // declarations keep the legacy first-line slice (their body brace
            // `class Foo {` is intentionally retained — no churn).
            let signature = if is_func && !is_class {
                crate::ast::entity::signature_from_header(node, source)
            } else {
                extract_def_signature(node, source)
            };

            let entry_kind = if is_class {
                match kind {
                    "struct_item" | "struct_definition" | "struct_specifier" => "struct",
                    // cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #46.
                    // Tag cpp `enum class Foo` / `enum Foo` as kind="enum"
                    // (consistent with Rust `enum_item`).
                    "enum_specifier" | "enum_item" => "enum",
                    "trait_item" => "trait",
                    "interface_declaration" => "interface",
                    "module" => "module",
                    // b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0
                    // AUDIT-FIX, B3): Scala-specific container/type kinds. These
                    // node kinds are only reached as class-LIKE for Scala (the
                    // language gate in `classify_definition_node` sets
                    // `is_class` for them only when `language == Scala`), so
                    // they cannot collide with another grammar that happens to
                    // reuse a name. `type_definition` is the Scala type ALIAS —
                    // it is emitted with kind:"type", NOT "class". (OCaml's
                    // `type_definition` never reaches this switch with a name,
                    // so it is unaffected.)
                    "type_definition" if matches!(language, Language::Scala) => "type",
                    "object_definition" => "object",
                    "trait_definition" => "trait",
                    "enum_definition" => "enum",
                    // v0.5.0 SOL-004 (solidity-ast-extractor-v1):
                    // Solidity-specific class-axis kinds.
                    "contract_declaration" => "contract",
                    "library_declaration" => "library",
                    "struct_declaration" => "struct",
                    "enum_declaration" => "enum",
                    _ => "class",
                }
            } else {
                // v0.5.0 SOL-004: Solidity-specific function-axis kinds.
                // `modifier_definition` / `event_definition` /
                // `error_declaration` are surfaced as first-class
                // definition kinds so downstream commands can find
                // them by name without a Solidity-specific accessor.
                match kind {
                    "modifier_definition" => "modifier",
                    "event_definition" => "event",
                    "error_declaration" => "error",
                    "constructor_definition" | "fallback_receive_definition" => "method",
                    _ => {
                        // Check if inside a class/impl => method
                        if is_inside_class_or_impl(&node, language) {
                            "method"
                        } else if is_go_method_with_receiver(&node, language) {
                            // cross-language-extraction-v2 P2.BUG-1:
                            // Go methods are declared with a receiver
                            // (`func (r *T) Foo()`), not lexically
                            // inside a class/struct body. Detect via
                            // the tree-sitter `method_declaration` node
                            // kind which is only emitted when a
                            // receiver is present (regular functions
                            // emit `function_declaration`).
                            "method"
                        } else if is_lua_table_qualified_function(&node, language) {
                            // W2-lua-structure (v0.5.0 AUDIT-FIX): a Lua/Luau
                            // `function T.m()` / `function T:m()` is a member of
                            // table-class `T` — same structural signal Go uses
                            // (a receiver-qualified declaration). Classify it as
                            // `kind:"method"` so `structure`'s `method_infos[]`
                            // (filtered by kind=="method") surfaces it and the
                            // `functions[]` projection (kind=="function") drops
                            // it — agreeing with the canonical
                            // `extract_classes_detailed` grouping that moved
                            // these out of module `functions` and into the
                            // table-class's `methods`.
                            "method"
                        } else {
                            "function"
                        }
                    }
                }
            };

            // m114-adapter-tail-v1 (v0.4.2 M-114): tag Ruby class
            // definitions whose superclass is a known unit-test base
            // class (`Minitest::Test`, `Minitest::Spec`,
            // `Test::Unit::TestCase`, `ActiveSupport::TestCase`) with
            // `is_test = true`. The audit corpus
            // (`/tmp/repos/ruby-rubocop/spec/**`) is dense with these
            // and downstream tooling (`dead`, `surface`, change-impact)
            // wants to skip non-test code paths.
            let is_test = entry_kind == "class"
                && language == Language::Ruby
                && ruby_class_is_test(&node, source);

            definitions.push(DefinitionInfo {
                name,
                kind: entry_kind.to_string(),
                line_start,
                line_end,
                signature,
                is_test,
            });
        }
    }

    // VAL-004: Class-scope field/property declarations emit with kind="field".
    // cross-cutting-and-clear-fix-bugs-v1 (P18.Pattern-B): skip if the
    // same node was already emitted as a constant (Java
    // `private static final FOO = ...`).
    if !emitted_as_constant {
        if let Some(field_defs) = try_field_definition(node, source, language) {
            definitions.extend(field_defs);
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_definitions(child, source, language, definitions);
    }
}

/// Try to classify a Lua `assignment_statement` whose right-hand side is a
/// `function_definition` as a `kind:"function"` definition.
///
/// In tree-sitter-lua a function value bound to a table slot or variable is an
/// `assignment_statement` (optionally wrapped in a `variable_declaration` for
/// `local`), NOT a `function_declaration`. The LHS `variable_list` holds one of
/// the `variable` supertypes:
///   - `identifier`               -> `f = function() end`            -> name `f`
///   - `dot_index_expression`     -> `t.x = function() end`          -> name `t.x`
///   - `method_index_expression`  -> `t:m = function() end`          -> name `t:m`
///   - `bracket_index_expression` -> `t["k"] = function() end`       -> name `t["k"]`
///
/// The qualified text is used as the name so distinct table slots (e.g. the 11
/// `method_handlers["textDocument/..."]` LSP handlers) remain distinguishable.
///
/// Returns `(DefinitionInfo, Option<body_block_node>)` so the caller can recurse
/// into the function body for nested definitions.
fn try_lua_function_assignment_definition<'a>(
    node: Node<'a>,
    source: &str,
) -> Option<(DefinitionInfo, Option<Node<'a>>)> {
    if node.kind() != "assignment_statement" {
        return None;
    }

    // Locate the variable_list (LHS) and the function_definition RHS.
    let mut var_node: Option<Node> = None;
    let mut func_def: Option<Node> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "variable_list" => {
                var_node = child.child(0);
            }
            "expression_list" => {
                let mut inner = child.walk();
                for expr in child.children(&mut inner) {
                    if expr.kind() == "function_definition" {
                        func_def = Some(expr);
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    let var_node = var_node?;
    let func_def = func_def?;

    // The LHS must be a nameable `variable` supertype. Use the full qualified
    // text directly from the AST node span.
    let name = match var_node.kind() {
        "identifier"
        | "dot_index_expression"
        | "method_index_expression"
        | "bracket_index_expression" => get_node_text(&var_node, source),
        _ => return None,
    };
    if name.is_empty() {
        return None;
    }

    let line_start = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;
    let signature = extract_def_signature(node, source);

    // Recurse into the function body (block) for nested definitions.
    let body = {
        let mut b = None;
        let mut fc = func_def.walk();
        for part in func_def.children(&mut fc) {
            if part.kind() == "block" {
                b = Some(part);
                break;
            }
        }
        b
    };

    Some((
        DefinitionInfo {
            name,
            kind: "function".to_string(),
            line_start,
            line_end,
            signature,
            is_test: false,
        },
        body,
    ))
}

/// Try to classify a tree-sitter node as a constant definition.
///
/// Returns `Some(DefinitionInfo)` with `kind: "constant"` if the node represents a
/// module-level constant. Uses explicit `const`/`static`/`final` keywords for languages
/// that have them, and UPPER_CASE naming convention for Python/JS/TS/Ruby/C/C++.
fn try_constant_definition(node: Node, source: &str, language: Language) -> Option<DefinitionInfo> {
    let kind = node.kind();

    match language {
        Language::Python => {
            // UPPER_CASE = value (at module level: expression_statement → assignment)
            if kind != "expression_statement" {
                return None;
            }
            let inner = node.child(0)?;
            if inner.kind() != "assignment" {
                return None;
            }
            let left = inner.child_by_field_name("left")?;
            if left.kind() != "identifier" {
                return None;
            }
            let name = get_node_text(&left, source);
            if !is_upper_case_name(&name) {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::Rust => {
            // const_item: `const NAME: Type = value;`
            // static_item: `static NAME: Type = value;`
            if kind != "const_item" && kind != "static_item" {
                return None;
            }
            let name = node
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))?;
            Some(make_constant_def(node, name, source))
        }

        Language::Go => {
            // const_spec inside const_declaration (individual constant in a group)
            if kind != "const_spec" {
                return None;
            }
            let name = node
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))?;
            Some(make_constant_def(node, name, source))
        }

        Language::TypeScript | Language::JavaScript => {
            // `const UPPER_CASE = ...` (also found inside `export const ...` via recursion)
            if kind != "lexical_declaration" {
                return None;
            }
            let decl_text = get_node_text(&node, source);
            if !decl_text.starts_with("const ") {
                return None;
            }
            let mut cursor = node.walk();
            let declarator = node
                .children(&mut cursor)
                .find(|c| c.kind() == "variable_declarator")?;
            let name = declarator
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))?;
            if !is_upper_case_name(&name) {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::C | Language::Cpp => {
            match kind {
                "preproc_def" => {
                    // #define UPPER_CASE value
                    let mut cursor = node.walk();
                    let ident = node
                        .children(&mut cursor)
                        .find(|c| c.kind() == "identifier")?;
                    let name = get_node_text(&ident, source);
                    if !is_upper_case_name(&name) {
                        return None;
                    }
                    Some(make_constant_def(node, name, source))
                }
                "declaration" => {
                    // const/constexpr TYPE UPPER_CASE = value;
                    let mut cursor = node.walk();
                    let has_const = node.children(&mut cursor).any(|c| {
                        if c.kind() != "type_qualifier" {
                            return false;
                        }
                        let text = get_node_text(&c, source);
                        text == "const" || (language == Language::Cpp && text == "constexpr")
                    });
                    if !has_const {
                        return None;
                    }
                    let mut cursor2 = node.walk();
                    let init_decl = node
                        .children(&mut cursor2)
                        .find(|c| c.kind() == "init_declarator")?;
                    let decl = init_decl.child_by_field_name("declarator")?;
                    let name = get_node_text(&decl, source);
                    if !is_upper_case_name(&name) {
                        return None;
                    }
                    Some(make_constant_def(node, name, source))
                }
                _ => None,
            }
        }

        Language::Ruby => {
            // CONSTANT = value (LHS is a `constant` node in tree-sitter-ruby)
            if kind != "assignment" {
                return None;
            }
            let mut cursor = node.walk();
            let const_node = node
                .children(&mut cursor)
                .find(|c| c.kind() == "constant")?;
            let name = get_node_text(&const_node, source);
            Some(make_constant_def(node, name, source))
        }

        Language::Java => {
            // static final fields: `public static final TYPE NAME = value;`
            if kind != "field_declaration" {
                return None;
            }
            let mut cursor = node.walk();
            let modifiers = node
                .children(&mut cursor)
                .find(|c| c.kind() == "modifiers")?;
            let mod_text = get_node_text(&modifiers, source);
            if !mod_text.contains("static") || !mod_text.contains("final") {
                return None;
            }
            let mut cursor2 = node.walk();
            let declarator = node
                .children(&mut cursor2)
                .find(|c| c.kind() == "variable_declarator")?;
            let name = declarator
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))?;
            // m002-java-cross-pipeline-drift-v1 (v0.4.2 M-109): Java
            // static-final constants resolve to `field_declaration` nodes,
            // which the extract pipeline anchors to the bare node start
            // line (the leading `@Deprecated` annotation row). Keep the
            // same behavior here so structure↔extract parity for
            // constants is preserved. Aligning to the decl-keyword line
            // requires a coordinated update on the extract side.
            Some(make_constant_def(node, name, source))
        }

        Language::Kotlin => {
            // top-level val/const val declarations
            // tree-sitter-kotlin-ng: property_declaration
            if kind != "property_declaration" {
                return None;
            }
            let text = get_node_text(&node, source);
            if !text.starts_with("val ") && !text.starts_with("const val ") {
                return None;
            }
            // Only UPPER_CASE or const val
            let mut cursor = node.walk();
            let var_decl = node
                .children(&mut cursor)
                .find(|c| c.kind() == "variable_declaration")?;
            let name_node = if let Some(n) = var_decl.child_by_field_name("name") {
                Some(n)
            } else {
                let mut vc = var_decl.walk();
                let found = var_decl
                    .children(&mut vc)
                    .find(|c| c.kind() == "simple_identifier" || c.kind() == "identifier");
                found
            };
            let name = name_node.map(|n| get_node_text(&n, source))?;
            if !text.starts_with("const val ") && !is_upper_case_name(&name) {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::Swift => {
            // `let` declarations at module level
            if kind != "property_declaration" {
                return None;
            }
            // VAL-004: class-scope `let`/`var` are fields, not module
            // constants — skip to avoid emitting duplicate definitions.
            if let Some(parent) = node.parent() {
                if matches!(
                    parent.kind(),
                    "class_body" | "enum_body" | "protocol_body" | "struct_body"
                ) {
                    return None;
                }
            }
            let text = get_node_text(&node, source);
            if !text.starts_with("let ") {
                return None;
            }
            let name_node = if let Some(n) = node.child_by_field_name("name") {
                Some(n)
            } else {
                let mut cursor = node.walk();
                let found = node.children(&mut cursor).find(|c| {
                    c.kind() == "pattern"
                        || c.kind() == "simple_identifier"
                        || c.kind() == "identifier"
                });
                found
            };
            let name_node = name_node?;
            let name = get_node_text(&name_node, source);
            // Skip if name looks like a destructuring pattern
            if name.contains('(') || name.contains('{') {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::CSharp => {
            // const fields: `public const TYPE NAME = value;`
            if kind != "field_declaration" {
                return None;
            }
            let mut cursor = node.walk();
            let has_const = node
                .children(&mut cursor)
                .any(|c| c.kind() == "modifier" && get_node_text(&c, source) == "const");
            if !has_const {
                return None;
            }
            let mut cursor2 = node.walk();
            let var_decl = node
                .children(&mut cursor2)
                .find(|c| c.kind() == "variable_declaration")?;
            let mut cursor3 = var_decl.walk();
            let declarator = var_decl
                .children(&mut cursor3)
                .find(|c| c.kind() == "variable_declarator")?;
            let name = declarator
                .child_by_field_name("name")
                .or_else(|| declarator.child(0))
                .map(|n| get_node_text(&n, source))?;
            Some(make_constant_def(node, name, source))
        }

        Language::Scala => {
            // val UPPER_CASE = value
            if kind != "val_definition" {
                return None;
            }
            let name_node = if let Some(n) = node.child_by_field_name("pattern") {
                Some(n)
            } else {
                let mut cursor = node.walk();
                let found = node
                    .children(&mut cursor)
                    .find(|c| c.kind() == "identifier");
                found
            };
            let name_node = name_node?;
            let name = get_node_text(&name_node, source);
            if !is_upper_case_name(&name) {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::Php => {
            // const NAME = value; or define('NAME', value);
            if kind != "const_declaration" {
                return None;
            }
            let mut cursor = node.walk();
            let element = node
                .children(&mut cursor)
                .find(|c| c.kind() == "const_element")?;
            let name = element
                .child_by_field_name("name")
                .or_else(|| element.child(0))
                .map(|n| get_node_text(&n, source))?;
            Some(make_constant_def(node, name, source))
        }

        Language::Elixir => {
            // @module_attribute: `@attr value`
            if kind != "unary_operator" {
                return None;
            }
            let text = get_node_text(&node, source);
            if !text.starts_with('@') {
                return None;
            }
            let mut cursor = node.walk();
            let ident = node
                .children(&mut cursor)
                .find(|c| c.kind() == "identifier")?;
            let name = format!("@{}", get_node_text(&ident, source));
            // Skip common non-constant attributes
            if name == "@doc" || name == "@moduledoc" || name == "@spec" || name == "@type" {
                return None;
            }
            Some(make_constant_def(node, name, source))
        }

        Language::Lua | Language::Luau | Language::Ocaml => None,
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1):
        // `constant_variable_declaration` (file scope or contract scope).
        // The grammar always exposes a `name` field; the SOL-003 extract
        // layer already emits these as FieldInfo with is_constant=true.
        // Here we surface them in the lightweight DefinitionInfo channel
        // as `kind:"constant"` so `tldr structure` / `tldr definition`
        // can list them by name.
        Language::Solidity => {
            if kind != "constant_variable_declaration" {
                return None;
            }
            let name = node
                .child_by_field_name("name")
                .map(|n| get_node_text(&n, source))?;
            Some(make_constant_def(node, name, source))
        }
    }
}

/// Build a `DefinitionInfo` with `kind: "constant"` from a node and its name.
/// Uses the full node span for `line_start`/`line_end` and the first line for `signature`.
fn make_constant_def(node: Node, name: String, source: &str) -> DefinitionInfo {
    let line_start = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;
    let sig_start = node.start_byte();
    let signature = source[sig_start..]
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    DefinitionInfo {
        name,
        kind: "constant".to_string(),
        line_start,
        line_end,
        signature,
        is_test: false,
    }
}

/// VAL-004: Try to classify a tree-sitter node as a class-scope field /
/// property declaration. Returns one `DefinitionInfo` per declared name so
/// that a single Java statement like `int x, y;` emits two field entries.
///
/// Only emits when the node is a direct child of a class-like body (class,
/// interface, enum, struct, protocol, actor body depending on language).
/// Top-level Kotlin `val/var` parses as `property_declaration` too but must
/// NOT be emitted — the parent check prevents that.
fn try_field_definition(
    node: Node,
    source: &str,
    language: Language,
) -> Option<Vec<DefinitionInfo>> {
    let kind = node.kind();

    // Per-language kind gating.
    let kind_matches = match language {
        Language::Java => matches!(kind, "field_declaration"),
        Language::Kotlin => matches!(kind, "property_declaration"),
        Language::Swift => matches!(kind, "property_declaration"),
        Language::TypeScript | Language::JavaScript => {
            matches!(kind, "public_field_definition" | "field_definition")
        }
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1): Solidity
        // contract-scope `state_variable_declaration` becomes a
        // `kind:"field"` entry — mirroring the SOL-003 extract layer
        // which puts them in `ClassInfo.fields`. The parent gate below
        // (must be `contract_body`) ensures file-scope variables —
        // which the grammar parses as `constant_variable_declaration`
        // and which are surfaced via `try_constant_definition` — don't
        // double-emit here.
        Language::Solidity => matches!(kind, "state_variable_declaration"),
        _ => false,
    };
    if !kind_matches {
        return None;
    }

    // Must sit directly inside a class-like body. This excludes top-level
    // declarations (e.g. Kotlin `val topLevelX = 1` under `source_file`).
    let parent = node.parent()?;
    let parent_kind = parent.kind();
    let parent_is_class_body = matches!(
        parent_kind,
        "class_body"           // Java, Kotlin, TS, Swift
            | "interface_body" // Java
            | "enum_body"      // Java / Swift
            | "annotation_type_body" // Java
            | "protocol_body"  // Swift
            | "struct_body" // (reserved)
            | "contract_body" // v0.5.0 SOL-004 (Solidity)
    );
    if !parent_is_class_body {
        return None;
    }

    // Extract names.
    let mut defs: Vec<DefinitionInfo> = Vec::new();
    // m002-java-cross-pipeline-drift-v1 (v0.4.2 M-109): NOTE — we
    // intentionally do NOT route Java field declarations through
    // `decl_keyword_line_from_node` here. The `extract` pipeline's Java
    // field extractor (`extract_java_class_fields` in `ast::extract`)
    // also uses the bare `node.start_position()` row, so both pipelines
    // currently agree on the annotation line for annotated Java fields
    // (`@Column private String x;` → both report line of `@Column`).
    // Aligning structure to the decl-keyword line here would NEWLY drift
    // from extract — making the bug worse for fields. The M-109 scope
    // (per Phase-22 iter-2 audit) is class/interface/method/constructor,
    // which are handled in `collect_definitions` above. Realigning Java
    // fields is a separate change that must update extract in lockstep.
    let line_start = node.start_position().row as u32 + 1;
    let line_end = node.end_position().row as u32 + 1;
    let signature = extract_def_signature(node, source);

    match language {
        Language::Java => {
            // field_declaration → variable_declarator+ → identifier ("name" field)
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    let name_opt = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
                        .or_else(|| {
                            let mut c2 = child.walk();
                            for inner in child.children(&mut c2) {
                                if inner.kind() == "identifier" {
                                    return inner
                                        .utf8_text(source.as_bytes())
                                        .ok()
                                        .map(|s| s.to_string());
                                }
                            }
                            None
                        });
                    if let Some(name) = name_opt {
                        defs.push(DefinitionInfo {
                            name,
                            kind: "field".to_string(),
                            line_start,
                            line_end,
                            signature: signature.clone(),
                            is_test: false,
                        });
                    }
                }
            }
        }
        Language::Kotlin => {
            // property_declaration → variable_declaration → identifier
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declaration" {
                    let mut c2 = child.walk();
                    for inner in child.children(&mut c2) {
                        if inner.kind() == "identifier" {
                            if let Ok(name) = inner.utf8_text(source.as_bytes()) {
                                defs.push(DefinitionInfo {
                                    name: name.to_string(),
                                    kind: "field".to_string(),
                                    line_start,
                                    line_end,
                                    signature: signature.clone(),
                                    is_test: false,
                                });
                            }
                            break;
                        }
                    }
                }
            }
        }
        Language::Swift => {
            // property_declaration → pattern → simple_identifier
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "pattern" {
                    let mut c2 = child.walk();
                    for inner in child.children(&mut c2) {
                        if inner.kind() == "simple_identifier" {
                            if let Ok(name) = inner.utf8_text(source.as_bytes()) {
                                defs.push(DefinitionInfo {
                                    name: name.to_string(),
                                    kind: "field".to_string(),
                                    line_start,
                                    line_end,
                                    signature: signature.clone(),
                                    is_test: false,
                                });
                            }
                            break;
                        }
                    }
                }
            }
        }
        Language::TypeScript | Language::JavaScript => {
            // public_field_definition / field_definition: property_identifier
            // is either the "name" field or an inline child.
            let name_opt = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok().map(|s| s.to_string()))
                .or_else(|| {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "property_identifier"
                            || child.kind() == "private_property_identifier"
                        {
                            return child
                                .utf8_text(source.as_bytes())
                                .ok()
                                .map(|s| s.to_string());
                        }
                    }
                    None
                });
            if let Some(name) = name_opt {
                defs.push(DefinitionInfo {
                    name,
                    kind: "field".to_string(),
                    line_start,
                    line_end,
                    signature,
                    is_test: false,
                });
            }
        }
        // v0.5.0 SOL-004 (solidity-ast-extractor-v1): Solidity
        // `state_variable_declaration` always exposes a `name` field
        // (per tree-sitter-solidity 1.2.13 grammar — verified against
        // src/node-types.json).
        Language::Solidity => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source.as_bytes()) {
                    defs.push(DefinitionInfo {
                        name: name.to_string(),
                        kind: "field".to_string(),
                        line_start,
                        line_end,
                        signature,
                        is_test: false,
                    });
                }
            }
        }
        _ => {}
    }

    if defs.is_empty() {
        None
    } else {
        Some(defs)
    }
}

/// Try to extract a definition from an Elixir `call` node.
/// In Elixir, `def`/`defp`/`defmodule` are macro calls that tree-sitter parses as `call` nodes.
fn try_elixir_call_definition(node: Node, source: &str) -> Option<DefinitionInfo> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "identifier" {
            continue;
        }
        let keyword = child.utf8_text(source.as_bytes()).ok()?;
        let args = child.next_sibling()?;

        match keyword {
            "def" | "defp" | "defmacro" | "defmacrop" => {
                let first_arg = args.child(0)?;
                // Resolve the defined name across the three first-arg shapes:
                //   * `call` — `def process(data)` (name = call.child(0)).
                //   * `binary_operator` — `def fn(x) when guard` (the first arg
                //     is the `when` operator; descend to its inner `call` and
                //     take that call's name). Without this the whole
                //     `fn(x) when guard` text was used as the name (#51).
                //   * bare identifier — `def f` with no args.
                let name = if first_arg.kind() == "call" {
                    first_arg.child(0)?.utf8_text(source.as_bytes()).ok()?
                } else if first_arg.kind() == "binary_operator" {
                    // Guarded clause: find the inner `call` (the LHS of `when`).
                    let mut gc = first_arg.walk();
                    let inner_call = first_arg
                        .children(&mut gc)
                        .find(|c| c.kind() == "call");
                    if let Some(call) = inner_call {
                        call.child(0)?.utf8_text(source.as_bytes()).ok()?
                    } else {
                        first_arg.utf8_text(source.as_bytes()).ok()?
                    }
                } else {
                    first_arg.utf8_text(source.as_bytes()).ok()?
                };
                let line_start = node.start_position().row as u32 + 1;
                let line_end = node.end_position().row as u32 + 1;
                let signature = extract_def_signature(node, source);
                // elixir-method-infos-v1: def/defp/defmacro/defmacrop inside a
                // `defmodule … do … end` block are emitted with kind="method" so
                // the `method_infos` view (filtered by kind=="method") is
                // populated for Elixir, mirroring how Ruby methods inside
                // `module`/`class` blocks are classified. Top-level
                // def/defmacro (rare but legal in scripts) remain "function".
                // defmacro/defmacrop were previously dropped entirely (#57),
                // hiding the whole DSL surface of Phoenix/Plug routers.
                let kind_str = if is_inside_elixir_defmodule(&node, source) {
                    "method"
                } else {
                    "function"
                };
                return Some(DefinitionInfo {
                    name: name.to_string(),
                    kind: kind_str.to_string(),
                    line_start,
                    line_end,
                    signature,
                    is_test: false,
                });
            }
            "defmodule" => {
                let first_arg = args.child(0)?;
                let name = first_arg.utf8_text(source.as_bytes()).ok()?;
                let line_start = node.start_position().row as u32 + 1;
                let line_end = node.end_position().row as u32 + 1;
                let signature = extract_def_signature(node, source);
                return Some(DefinitionInfo {
                    name: name.to_string(),
                    kind: "module".to_string(),
                    line_start,
                    line_end,
                    signature,
                    is_test: false,
                });
            }
            _ => {}
        }
    }
    None
}

/// elixir-method-infos-v1: Returns true if `node` (an Elixir def/defp `call`
/// node) has an ancestor `call` whose first identifier child is `defmodule`.
/// Walks parents only — does not recurse into siblings — so cost is O(depth).
fn is_inside_elixir_defmodule(node: &Node, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "call" {
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if child.kind() == "identifier" {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        if text == "defmodule" {
                            return true;
                        }
                    }
                    // Only the first identifier child is the keyword; stop.
                    break;
                }
            }
        }
        current = parent.parent();
    }
    false
}

/// Classify a tree-sitter node kind as function-like or class-like.
/// Mirrors `search/enriched.rs::classify_node`.
fn classify_definition_node(kind: &str, language: Language) -> (bool, bool) {
    let mut is_func = matches!(
        kind,
        "function_definition"
            | "function_declaration"
            | "function_item"     // Rust
            | "method_definition"
            | "method_signature"           // TS: interface methods & abstract class signature (VAL-001)
            | "abstract_method_signature"  // TS: `abstract foo(): void;` inside abstract class (VAL-001)
            | "method_declaration"
            | "method"            // Ruby
            | "singleton_method"  // Ruby class methods
            | "arrow_function"
            | "function_expression"
            | "function"           // JS/TS
            | "func_literal"       // Go
            | "function_type"
            | "value_definition"   // OCaml top-level let binding (functions and values)
            | "init_declaration"   // Swift init constructor (VAL-002)
            | "constructor_declaration" // Java / C# constructor (VAL-003)
    );

    let mut is_class = matches!(
        kind,
        "class_definition"
            | "class_declaration"
            | "abstract_class_declaration"  // TS: `abstract class Foo {}` (VAL-001)
            | "class_specifier"   // C++
            | "class"             // Ruby
            | "module"            // Ruby
            | "struct_item"        // Rust
            | "struct_definition"  // C/C++
            | "struct_specifier"   // C
            | "enum_specifier"     // C/C++ — cpp-python-ast-issues-v1 #46
            | "enum_item"          // Rust
            | "trait_item"         // Rust
            | "type_spec"          // Go struct
            | "interface_declaration"
            | "module_definition"  // OCaml module definition
            | "companion_object" // Kotlin companion object (name: "Companion" by convention)
    );

    // b3-structure-polyglot-bound-scala-classify-v1 (v0.5.0 AUDIT-FIX, B3):
    // `type_definition` is a node kind SHARED by tree-sitter-ocaml and
    // tree-sitter-scala but with DIFFERENT semantics, so it must be
    // language-gated rather than living in the unconditional `is_class` list
    // above (where it was commented "OCaml type definition"):
    //
    //   - OCaml `type t = ...` IS a type/class-defining construct. The shared
    //     `get_definition_node_name` returns `None` for it (the name lives in a
    //     nested `type_binding > type_constructor`, not a `name` field), so on
    //     HEAD an OCaml `type_definition` is classified `is_class` but then
    //     dropped from `definitions[]` for lack of a name — a de-facto no-op.
    //     We preserve that EXACT behaviour by keeping OCaml's `type_definition`
    //     in the class-classified set.
    //
    //   - Scala `type X = ...` is a TYPE ALIAS, not a class. tree-sitter-scala
    //     exposes a `name` field on it, so the unconditional rule mislabeled it
    //     `kind:"class"`. It must surface as `kind:"type"` (handled in the
    //     entry-kind mapping below). We still flag it class-LIKE here only so
    //     the `(is_func || is_class)` emission gate lets it through; the
    //     entry-kind switch refines the reported kind to "type".
    //
    //   - Scala's idiomatic containers `object` / `trait` / `enum` are NOT in
    //     the shared list, so they were dropped from `definitions[]` entirely.
    //     Add them here (Scala-gated) so they surface with their own kinds.
    match language {
        Language::Swift => {
            // A Swift `function_type` node is a CLOSURE TYPE ANNOTATION
            // (`(Int) -> Void`), never a function DEFINITION. It appears inside
            // closure-typed property/parameter type annotations (e.g.
            // Alamofire's `var httpResponseHandler: (...) -> Void`). Because the
            // grammar exposes the return type under a `[name]` field
            // (`-> Void` => name="Void"), the generic collector emitted a
            // phantom `Void` "method" for every closure type (#238: 16 phantoms
            // in DataRequest.swift). `function_type` stays in the base is_func
            // list for other grammars (Go etc.) where it is unreported; here it
            // is gated OFF so Swift closure types are not mistaken for methods.
            // Real Swift methods are `function_declaration` and init is
            // `init_declaration` — both unaffected.
            if kind == "function_type" {
                is_func = false;
            }
        }
        Language::Ocaml => {
            if kind == "type_definition" {
                is_class = true;
            }
        }
        Language::Scala => {
            if matches!(
                kind,
                "type_definition"
                    | "object_definition"
                    | "trait_definition"
                    | "enum_definition"
            ) {
                is_class = true;
            }
        }
        _ => {}
    }

    // v0.5.0 SOL-004 (solidity-ast-extractor-v1): Solidity-specific
    // node kinds. Gated on the language so that other grammars that
    // happen to reuse the names (`struct_declaration` / `enum_declaration`
    // exist in the C# grammar too, and are handled by the dedicated
    // C# extractors at the `extract_classes` layer) are not affected.
    if matches!(language, Language::Solidity) {
        // Functions: free functions + members + ctors + fallback/receive
        // + modifiers (modifiers are callable-shaped — a name + params +
        // body — and `tldr structure` / `tldr definition` want them in
        // the same listing as functions so taint / impact / dead-code
        // can find them by name).
        if matches!(
            kind,
            "constructor_definition"
                | "fallback_receive_definition"
                | "modifier_definition"
                | "event_definition"
                | "error_declaration"
        ) {
            is_func = true;
        }
        // Classes: contract / library (interface already in the shared
        // is_class list above). Plus struct/enum declarations which are
        // type-defining and surface as `kind:"struct"` / `kind:"enum"`
        // in `collect_definitions` (the entry_kind mapping below).
        if matches!(
            kind,
            "contract_declaration"
                | "library_declaration"
                | "struct_declaration"
                | "enum_declaration"
        ) {
            is_class = true;
        }
    }

    (is_func, is_class)
}

/// Extract the name from a function/class definition node.
/// Mirrors `search/enriched.rs::get_definition_name`.
fn get_definition_node_name(node: Node, source: &str) -> Option<String> {
    // Swift `init_declaration` has no `name` field — the node starts with the
    // literal token `init`. Mirror `extract_swift_methods` which also emits
    // the literal string "init".
    if node.kind() == "init_declaration" {
        return Some("init".to_string());
    }

    // Most languages use a "name" field
    if let Some(name_node) = node.child_by_field_name("name") {
        let text = name_node.utf8_text(source.as_bytes()).ok()?;
        return Some(text.to_string());
    }

    // Java `constructor_declaration` may not expose a `name` field in all
    // grammar versions — fall back to the first identifier child (same
    // fallback as `extract_csharp_methods`).
    if node.kind() == "constructor_declaration" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                let text = child.utf8_text(source.as_bytes()).ok()?;
                return Some(text.to_string());
            }
        }
    }

    // C/C++ function_definition uses "declarator" instead of "name"
    if node.kind() == "function_definition" {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            return extract_name_from_declarator(declarator, source);
        }
    }

    // For arrow functions assigned to variables, check parent
    if node.kind() == "arrow_function" || node.kind() == "function_expression" {
        if let Some(parent) = node.parent() {
            if parent.kind() == "variable_declarator" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    let text = name_node.utf8_text(source.as_bytes()).ok()?;
                    return Some(text.to_string());
                }
            }
        }
    }

    // OCaml: value_definition contains a let_binding child with a "pattern" field.
    // The pattern field holds the function/value name (e.g. `let top_level x = ...`
    // has pattern="top_level"). Skip anonymous bindings:
    //   - `let () = ...` (unit pattern, used for top-level imperative blocks)
    //   - `let _ = ...` (wildcard pattern, used to discard expression results
    //     inside function bodies — these are NOT named definitions, and they
    //     surface as duplicate "_" entries when a function body uses
    //     `let _ = expr in ...` chains. VAL-018: filter at extraction time
    //     so structure/diff/callgraph all see consistent function names).
    if node.kind() == "value_definition" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                if let Some(pattern_node) = child.child_by_field_name("pattern") {
                    let text = pattern_node.utf8_text(source.as_bytes()).ok()?;
                    if text != "()" && text != "_" && !text.is_empty() {
                        return Some(text.to_string());
                    }
                }
            }
        }
        return None;
    }

    // Kotlin: companion_object has no identifier child; use "Companion" by convention.
    if node.kind() == "companion_object" {
        return Some("Companion".to_string());
    }

    // v0.5.0 SOL-004 (solidity-ast-extractor-v1): Solidity
    // `constructor_definition` and `fallback_receive_definition` have no
    // `name` field. Mirror the SOL-003 extract layer:
    //   - `constructor_definition` → name = "constructor"
    //   - `fallback_receive_definition` → name = "fallback" / "receive"
    //     based on the keyword token that opens the node.
    if node.kind() == "constructor_definition" {
        return Some("constructor".to_string());
    }
    if node.kind() == "fallback_receive_definition" {
        return Some(solidity_fallback_receive_keyword(&node, source));
    }

    None
}

/// Extract a function name from a C/C++ declarator chain.
/// Handles function_declarator, pointer_declarator, reference_declarator, etc.
fn extract_name_from_declarator(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "destructor_name" => Some(get_node_text(&node, source)),
        "function_declarator" | "pointer_declarator" | "reference_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            extract_name_from_declarator(inner, source)
        }
        "qualified_identifier" | "scoped_identifier" => {
            if let Some(name) = node.child_by_field_name("name") {
                return Some(get_node_text(&name, source));
            }
            Some(get_node_text(&node, source))
        }
        _ => {
            // Fallback: try children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = extract_name_from_declarator(child, source) {
                    return Some(name);
                }
            }
            None
        }
    }
}

/// Check if a node is a Go method declaration (a function with a receiver).
///
/// In tree-sitter-go, `method_declaration` is emitted only when a receiver is
/// present (`func (r *Receiver) Foo()`); plain `func Foo()` emits
/// `function_declaration`. Go methods are NOT lexically nested inside a
/// struct body, so `is_inside_class_or_impl` returns false for them — this
/// helper covers the gap so they are classified as `kind: "method"` and surface
/// in `FileStructure::method_infos`.
///
/// Closes cross-language-extraction-v2 P2.BUG-1 (Go side).
fn is_go_method_with_receiver(node: &Node, language: Language) -> bool {
    matches!(language, Language::Go) && node.kind() == "method_declaration"
}

/// W2-lua-structure (v0.5.0 AUDIT-FIX): true for a Lua/Luau
/// `function_declaration` whose `name` field is table-qualified
/// (`dot_index_expression` => `function T.m`, `method_index_expression` =>
/// `function T:m`). Such a declaration is a member of table-class `T`, so it is
/// classified `kind:"method"` — the structure-path analogue of the receiver
/// grouping performed by `extract::extract_classes_detailed`. A bare
/// `function foo()` (name kind `identifier`) is NOT table-qualified and stays a
/// `function`.
fn is_lua_table_qualified_function(node: &Node, language: Language) -> bool {
    matches!(language, Language::Lua | Language::Luau)
        && node.kind() == "function_declaration"
        && node
            .child_by_field_name("name")
            .map(|name| {
                matches!(
                    name.kind(),
                    "dot_index_expression" | "method_index_expression"
                )
            })
            .unwrap_or(false)
}

/// Check if a node is inside a class/struct body or impl block.
///
/// The `language` parameter is used to disambiguate node kinds that are shared
/// across tree-sitter grammars but have different semantics. For example,
/// `"module"` is the root node in tree-sitter-python (not a class scope) but
/// represents a Ruby module definition (a class scope) in tree-sitter-ruby.
fn is_inside_class_or_impl(node: &Node, language: Language) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        let kind = parent.kind();
        // "module" is a class-scope node in Ruby but the root node in Python.
        // Only treat it as a class scope when the language is Ruby.
        let module_is_class = !matches!(language, Language::Python);
        if matches!(
            kind,
            "class_definition"
                | "class_declaration"
                | "abstract_class_declaration"  // TS (VAL-001)
                | "class_specifier"   // C++
                | "class"             // Ruby
                | "class_body"
                | "impl_item"
                | "struct_item"
                | "trait_item"
                | "interface_declaration"  // TS/Java/C# (VAL-001)
                | "interface_body"         // TS body wrapper (VAL-001)
                | "companion_object"  // Kotlin
                | "object_declaration" // Kotlin
                // v0.5.0 SOL-004 (solidity-ast-extractor-v1): Solidity
                // contract / library declarations and their
                // `contract_body` container are class-scope. Methods
                // (function_definition / constructor_definition /
                // fallback_receive_definition) inside them must classify
                // as `kind:"method"` to mirror the SOL-003 extract layer.
                | "contract_declaration"
                | "library_declaration"
                | "contract_body"
        ) || (kind == "module" && module_is_class)
        // Ruby module
        {
            return true;
        }
        // m040-cpp-macro-class-cross-pipeline-v1 (v0.4.2 M-110): cpp
        // macro-decorated class bodies live in a `compound_statement`
        // child of a `function_definition` (the tree-sitter-cpp
        // misparse `class TINYXML2_LIB Name { ... }`). The intervening
        // shapes are not in the canonical class-scope list above, so
        // `is_inside_class_or_impl` would miss them and classify
        // member methods as `kind:"function"`. Recognise the misparse
        // parent purely from AST structure (no source bytes needed)
        // so inner methods are tagged `kind:"method"` — matching the
        // class entry emitted by `collect_definitions` at the misparse
        // node.
        if matches!(language, Language::Cpp | Language::C)
            && super::cpp_macro::is_macro_decorated_class_node(&parent)
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// Extract the actual definition signature from a tree-sitter node,
/// skipping doc comments, attributes, and decorators.
/// Mirrors `search/enriched.rs::extract_definition_signature`.
fn extract_def_signature(node: Node, source: &str) -> String {
    // Strategy: find the first child node that isn't a comment or attribute,
    // then use its start position as the beginning of the actual definition.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let ckind = child.kind();
        // Skip doc comments and attributes/decorators
        if ckind == "line_comment"
            || ckind == "block_comment"
            || ckind == "comment"
            || ckind == "attribute_item"    // Rust #[...]
            || ckind == "attribute"         // Rust #[...]
            || ckind == "decorator"         // Python @decorator
            || ckind == "decorator_list"
        // Python
        {
            continue;
        }
        // Found the first non-comment child -- extract its line as signature
        let start_byte = child.start_byte();
        let line_from_start = &source[start_byte..];
        let sig = line_from_start
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !sig.is_empty() {
            return sig;
        }
    }

    // Fallback: find the first non-comment line in the node's text
    let node_text = &source[node.start_byte()..node.end_byte()];
    for line in node_text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty()
            && !trimmed.starts_with("///")
            && !trimmed.starts_with("//!")
            && !trimmed.starts_with("//")
            && !trimmed.starts_with("/*")
            && !trimmed.starts_with("*")
            && !trimmed.starts_with("#[")
            && !trimmed.starts_with("@")
            && !trimmed.starts_with("#")
        {
            return trimmed.to_string();
        }
    }

    // Last resort: use the first line
    source[node.start_byte()..]
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

// =============================================================================
// Helper functions
// =============================================================================

/// Get text content of a node
fn get_node_text(node: &Node, source: &str) -> String {
    source[node.byte_range()].to_string()
}

/// Check if a node is inside a class definition
fn is_inside_class(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "class_definition" | "class_declaration" | "class" | "class_body" => return true,
            _ => current = parent.parent(),
        }
    }
    false
}

/// Check if a node is inside an impl block or trait definition (Rust)
fn is_inside_impl(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "impl_item" || parent.kind() == "trait_item" {
            return true;
        }
        current = parent.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    /// RC2-META Stage 2 fourth-table guard: `classify_definition_node` (the
    /// `(is_func, is_class)` table that drives `structure`) must AGREE with the
    /// canonical `entity::classify_node` on every definition node across the
    /// verified fixture languages. This locks the local table so it can never
    /// drift to an answer the shared classifier disagrees with. (Membership is
    /// preserved byte-identically in Stage 2; broadening to classify_node's full
    /// union is the per-language Stage 3 migration.)
    #[test]
    fn classify_definition_node_agrees_with_classify_node_on_fixtures() {
        use crate::ast::entity::classify_node;

        fn walk(node: Node, language: Language, source: &str) {
            let kind = node.kind();
            // Elixir def/defp are `call` nodes resolved structurally elsewhere;
            // classify_definition_node deliberately abstains on them.
            if !(language == Language::Elixir && kind == "call") {
                let (is_func, is_class) = classify_definition_node(kind, language);
                if let Some(ek) = classify_node(node, language, source) {
                    // Where classify_definition_node ALSO recognises this kind on
                    // an axis, the axis must agree with the canonical classifier.
                    // EXCEPTION: classify_node is the RICHER answer for an OCaml
                    // `value_definition` / `let_binding` — it structurally refines
                    // a non-function binding to `Value`, exactly as
                    // `collect_definitions` does via the separate
                    // `is_non_function_ocaml_value` guard. So a legacy `is_func`
                    // table row paired with a canonical `Value` is the intended
                    // richer classification, not a disagreement.
                    let is_ocaml_value_refinement = matches!(ek, crate::ast::entity::EntityKind::Value);
                    if is_func && !is_ocaml_value_refinement {
                        assert!(
                            ek.is_function_axis(),
                            "{language:?} {kind:?}: classify_definition_node=func but classify_node={ek:?}"
                        );
                    }
                    if is_class {
                        assert!(
                            ek.is_class_axis(),
                            "{language:?} {kind:?}: classify_definition_node=class but classify_node={ek:?}"
                        );
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk(child, language, source);
            }
        }

        let fixtures = [
            (
                Language::TypeScript,
                "abstract class A { m(): void {} }\ninterface I {}\ntype T = number;\nenum E { X }\nfunction f() {}\n",
            ),
            (
                Language::Scala,
                "class C {}\nobject O {}\ntrait T {}\ntype X = Int\ndef g(): Int = 1\n",
            ),
            (
                Language::Ocaml,
                "let f = fun x -> x\nlet x = 1\nmodule M = struct end\n",
            ),
            (
                Language::Elixir,
                "defmodule M do\n  def bar(x) do x end\n  defmacro foo(x) do x end\nend\n",
            ),
        ];
        for (lang, src) in fixtures {
            let tree = parse(src, lang).unwrap();
            walk(tree.root_node(), lang, src);
        }
    }

    #[test]
    fn test_extract_python_functions() {
        let source = r#"
def foo():
    pass

def bar(x):
    return x

class MyClass:
    def method(self):
        pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let functions = extract_functions(&tree, source, Language::Python);

        assert!(functions.contains(&"foo".to_string()));
        assert!(functions.contains(&"bar".to_string()));
        // method should not be in functions (it's a method)
        assert!(!functions.contains(&"method".to_string()));
    }

    #[test]
    fn test_extract_python_classes() {
        let source = r#"
class MyClass:
    pass

class AnotherClass:
    def method(self):
        pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let classes = extract_classes(&tree, source, Language::Python);

        assert!(classes.contains(&"MyClass".to_string()));
        assert!(classes.contains(&"AnotherClass".to_string()));
    }

    #[test]
    fn test_extract_python_methods() {
        let source = r#"
class MyClass:
    def method1(self):
        pass

    def method2(self, x):
        return x
"#;
        let tree = parse(source, Language::Python).unwrap();
        let methods = extract_methods(&tree, source, Language::Python);

        assert!(methods.contains(&"method1".to_string()));
        assert!(methods.contains(&"method2".to_string()));
    }

    #[test]
    fn test_extract_typescript_functions() {
        let source = r#"
function foo() {}

const bar = () => {};

class MyClass {
    method() {}
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let functions = extract_functions(&tree, source, Language::TypeScript);

        assert!(functions.contains(&"foo".to_string()));
        // Arrow function detection depends on variable declarator
    }

    #[test]
    fn test_extract_go_functions() {
        let source = r#"
package main

func foo() {}

func (r *Receiver) bar() {}
"#;
        let tree = parse(source, Language::Go).unwrap();
        let functions = extract_functions(&tree, source, Language::Go);

        assert!(functions.contains(&"foo".to_string()));
        assert!(functions.contains(&"bar".to_string()));
    }

    #[test]
    fn test_extract_c_functions() {
        let source = r#"
void hello(void) {
}

int main(int argc, char** argv) {
    return 0;
}

static void helper(int x) {
}
"#;
        let tree = parse(source, Language::C).unwrap();
        let functions = extract_functions(&tree, source, Language::C);

        assert!(
            functions.contains(&"hello".to_string()),
            "Should find hello function"
        );
        assert!(
            functions.contains(&"main".to_string()),
            "Should find main function"
        );
        assert!(
            functions.contains(&"helper".to_string()),
            "Should find helper function"
        );
    }

    #[test]
    fn test_extract_c_structs() {
        let source = r#"
struct Point {
    int x;
    int y;
};

enum Color {
    RED,
    GREEN,
    BLUE
};
"#;
        let tree = parse(source, Language::C).unwrap();
        let classes = extract_classes(&tree, source, Language::C);

        assert!(
            classes.contains(&"Point".to_string()),
            "Should find Point struct"
        );
        assert!(
            classes.contains(&"Color".to_string()),
            "Should find Color enum"
        );
    }

    #[test]
    fn test_extract_c_structs_requires_body_val_001() {
        // VAL-001: extract_c_structs must only emit struct/enum specifiers
        // that have a `body` field. Bare parameter type references
        // (`struct Bar *b`), forward declarations (`struct Bar;`), and
        // typedef aliases of existing structs must NOT be emitted.
        let source = r#"
struct Foo { int x; };
void use_bar(struct Bar *b);
struct Forward;
typedef struct { int y; } Anon;
typedef struct Existing OtherName;
enum E { A };
enum F;
void use_enum(enum G *e);
"#;
        let tree = parse(source, Language::C).unwrap();
        let classes = extract_classes(&tree, source, Language::C);

        let expected: std::collections::HashSet<String> =
            ["Foo", "Anon", "E"].iter().map(|s| s.to_string()).collect();
        let got: std::collections::HashSet<String> = classes.iter().cloned().collect();

        assert_eq!(
            got, expected,
            "VAL-001: extract_c_structs must only emit bodied struct/enum \
             definitions. Expected {:?}, got {:?}",
            expected, got
        );

        // Explicit negative assertions for clarity.
        for forbidden in ["Bar", "Forward", "Existing", "OtherName", "F", "G"] {
            assert!(
                !classes.contains(&forbidden.to_string()),
                "VAL-001: must NOT emit `{}` (no body / alias / param type), \
                 got classes = {:?}",
                forbidden,
                classes
            );
        }
    }

    #[test]
    fn test_extract_cpp_functions() {
        let source = r#"
void hello() {
}

int main() {
    return 0;
}

namespace greeting {
    void greet(const std::string& name) {
    }
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let functions = extract_functions(&tree, source, Language::Cpp);

        assert!(
            functions.contains(&"hello".to_string()),
            "Should find hello function"
        );
        assert!(
            functions.contains(&"main".to_string()),
            "Should find main function"
        );
        // Namespace functions should also be found
        assert!(
            functions.contains(&"greet".to_string()),
            "Should find greet function"
        );
    }

    #[test]
    fn test_extract_cpp_classes() {
        let source = r#"
class Greeter {
public:
    void greet();
};

struct Point {
    int x, y;
};
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let classes = extract_classes(&tree, source, Language::Cpp);

        assert!(
            classes.contains(&"Greeter".to_string()),
            "Should find Greeter class"
        );
        assert!(
            classes.contains(&"Point".to_string()),
            "Should find Point struct"
        );
    }

    #[test]
    fn test_extract_ruby_functions() {
        let source = r##"
def top_level_function
  puts "I'm a function"
end

def another_function(x)
  x * 2
end

class MyClass
  def method_in_class
    puts "method"
  end
end
"##;
        let tree = parse(source, Language::Ruby).unwrap();
        let functions = extract_functions(&tree, source, Language::Ruby);

        assert!(
            functions.contains(&"top_level_function".to_string()),
            "Should find top_level_function"
        );
        assert!(
            functions.contains(&"another_function".to_string()),
            "Should find another_function"
        );
        // Method inside class should NOT be in functions
        assert!(
            !functions.contains(&"method_in_class".to_string()),
            "Should not find method_in_class in functions"
        );
    }

    #[test]
    fn test_extract_ruby_methods() {
        let source = r##"
def top_level_function
  puts "I'm a function"
end

class MyClass
  def initialize(name)
    @name = name
  end

  def greet
    puts "Hello"
  end
end

module MyModule
  def module_method
    puts "module method"
  end
end
"##;
        let tree = parse(source, Language::Ruby).unwrap();
        let methods = extract_methods(&tree, source, Language::Ruby);

        // Methods inside class should be found
        assert!(
            methods.contains(&"initialize".to_string()),
            "Should find initialize method"
        );
        assert!(
            methods.contains(&"greet".to_string()),
            "Should find greet method"
        );
        assert!(
            methods.contains(&"module_method".to_string()),
            "Should find module_method"
        );
        // Top-level function should NOT be in methods
        assert!(
            !methods.contains(&"top_level_function".to_string()),
            "Should not find top_level_function in methods"
        );
    }

    #[test]
    fn test_extract_ruby_classes() {
        let source = r##"
class MyClass
  def initialize
  end
end

class AnotherClass < BaseClass
  def method
  end
end

module MyModule
  class NestedClass
  end
end
"##;
        let tree = parse(source, Language::Ruby).unwrap();
        let classes = extract_classes(&tree, source, Language::Ruby);

        assert!(
            classes.contains(&"MyClass".to_string()),
            "Should find MyClass"
        );
        assert!(
            classes.contains(&"AnotherClass".to_string()),
            "Should find AnotherClass"
        );
        assert!(
            classes.contains(&"MyModule".to_string()),
            "Should find MyModule"
        );
        assert!(
            classes.contains(&"NestedClass".to_string()),
            "Should find NestedClass"
        );
    }

    #[test]
    fn test_extract_kotlin_functions() {
        let source = r#"
fun topLevel() {
    println("hello")
}

fun anotherTopLevel(x: Int): Int {
    return x * 2
}

class MyClass {
    fun classMethod() {}
}
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let functions = extract_functions(&tree, source, Language::Kotlin);

        assert!(
            functions.contains(&"topLevel".to_string()),
            "Should find topLevel function"
        );
        assert!(
            functions.contains(&"anotherTopLevel".to_string()),
            "Should find anotherTopLevel function"
        );
        // Methods inside classes should NOT be in top-level functions
        assert!(
            !functions.contains(&"classMethod".to_string()),
            "Should not find classMethod in functions"
        );
    }

    #[test]
    fn test_extract_kotlin_methods() {
        let source = r#"
fun topLevel() {}

class MyClass {
    fun method1() {}
    fun method2(x: Int): String { return x.toString() }
}

object Singleton {
    fun singletonMethod() {}
}
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let methods = extract_methods(&tree, source, Language::Kotlin);

        assert!(
            methods.contains(&"method1".to_string()),
            "Should find method1"
        );
        assert!(
            methods.contains(&"method2".to_string()),
            "Should find method2"
        );
        // Top-level functions should NOT be in methods
        assert!(
            !methods.contains(&"topLevel".to_string()),
            "Should not find topLevel in methods"
        );
    }

    #[test]
    fn test_extract_kotlin_classes() {
        let source = r#"
class HttpClient(val engine: Engine) {
    fun config() {}
}

object Singleton {
    fun method() {}
}

interface MyInterface {
    fun abstractMethod()
}
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let classes = extract_classes(&tree, source, Language::Kotlin);

        assert!(
            classes.contains(&"HttpClient".to_string()),
            "Should find HttpClient class"
        );
        assert!(
            classes.contains(&"Singleton".to_string()),
            "Should find Singleton object"
        );
        assert!(
            classes.contains(&"MyInterface".to_string()),
            "Should find MyInterface interface"
        );
    }

    #[test]
    fn test_extract_ocaml_functions() {
        let source = r#"
let greet name =
  Printf.printf "Hello, %s!\n" name

let add x y = x + y

let value = 42

let rec factorial n =
  if n <= 1 then 1
  else n * factorial (n - 1)

let () = greet "world"
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let functions = extract_functions(&tree, source, Language::Ocaml);

        assert!(
            functions.contains(&"greet".to_string()),
            "Should find greet function"
        );
        assert!(
            functions.contains(&"add".to_string()),
            "Should find add function"
        );
        assert!(
            functions.contains(&"factorial".to_string()),
            "Should find factorial function"
        );
        // 'value' has no parameters, it is a value binding not a function
        assert!(
            !functions.contains(&"value".to_string()),
            "Should not find value binding as function"
        );
        // let () = ... is not a named function
        assert!(
            !functions.contains(&"()".to_string()),
            "Should not find anonymous let () binding"
        );
    }

    // =========================================================================
    // Rust extraction tests -- traits, impl blocks, and struct/enum
    // =========================================================================

    #[test]
    fn test_extract_rust_classes_includes_traits() {
        let source = r#"
pub struct Config {
    pub name: String,
}

pub enum Color {
    Red,
    Green,
    Blue,
}

pub trait Serialize {
    fn serialize(&self) -> String;
}

trait Deserialize {
    fn deserialize(input: &str) -> Self;
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let classes = extract_classes(&tree, source, Language::Rust);

        assert!(
            classes.contains(&"Config".to_string()),
            "Should find Config struct"
        );
        assert!(
            classes.contains(&"Color".to_string()),
            "Should find Color enum"
        );
        assert!(
            classes.contains(&"Serialize".to_string()),
            "Should find Serialize trait"
        );
        assert!(
            classes.contains(&"Deserialize".to_string()),
            "Should find Deserialize trait"
        );
    }

    #[test]
    fn test_extract_rust_functions_excludes_trait_methods() {
        let source = r#"
pub fn top_level() -> bool {
    true
}

pub trait Visitor {
    fn visit_bool(&self, v: bool) {}
    fn visit_i32(&self, v: i32) {}
}

impl Config {
    pub fn new() -> Self {
        Config {}
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let functions = extract_functions(&tree, source, Language::Rust);

        assert!(
            functions.contains(&"top_level".to_string()),
            "Should find top_level function"
        );
        // Trait methods should NOT appear as top-level functions
        assert!(
            !functions.contains(&"visit_bool".to_string()),
            "Trait method visit_bool should not be a top-level function"
        );
        assert!(
            !functions.contains(&"visit_i32".to_string()),
            "Trait method visit_i32 should not be a top-level function"
        );
        // impl methods should NOT appear as top-level functions
        assert!(
            !functions.contains(&"new".to_string()),
            "Impl method new should not be a top-level function"
        );
    }

    #[test]
    fn test_extract_rust_methods_includes_trait_methods() {
        let source = r#"
pub trait Visitor {
    fn visit_bool(&self, v: bool) {}
    fn visit_i32(&self, v: i32) {}
}

impl Config {
    pub fn new() -> Self {
        Config {}
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}

fn top_level() {}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let methods = extract_methods(&tree, source, Language::Rust);

        // Trait default methods should be in methods
        assert!(
            methods.contains(&"visit_bool".to_string()),
            "Should find visit_bool trait method"
        );
        assert!(
            methods.contains(&"visit_i32".to_string()),
            "Should find visit_i32 trait method"
        );
        // Impl methods should be in methods
        assert!(
            methods.contains(&"new".to_string()),
            "Should find new impl method"
        );
        assert!(
            methods.contains(&"name".to_string()),
            "Should find name impl method"
        );
        // Top-level functions should NOT be in methods
        assert!(
            !methods.contains(&"top_level".to_string()),
            "top_level should not be in methods"
        );
    }

    // =========================================================================
    // Fixture-based extraction accuracy tests (18 languages)
    // =========================================================================
    //
    // Each test reads a fixture file, parses it, and asserts the expected
    // counts for functions, classes, and methods. These document the current
    // extraction coverage and identify gaps for unimplemented languages.

    /// Helper: run all three extractors on a source string for a given language
    /// and return (functions, classes, methods) counts.
    fn extract_counts(source: &str, lang: Language) -> (usize, usize, usize) {
        let tree = parse(source, lang).expect("parsing should succeed");
        let functions = extract_functions(&tree, source, lang);
        let classes = extract_classes(&tree, source, lang);
        let methods = extract_methods(&tree, source, lang);
        (functions.len(), classes.len(), methods.len())
    }

    #[test]
    fn test_extractor_python() {
        let source = include_str!("../../tests/fixtures/extractor/test_python.py");
        let (f, c, m) = extract_counts(source, Language::Python);
        assert_eq!(f, 3, "Python: expected 3 functions, got {}", f);
        assert_eq!(c, 2, "Python: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "Python: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_go() {
        let source = include_str!("../../tests/fixtures/extractor/test_go.go");
        let (f, c, m) = extract_counts(source, Language::Go);
        assert_eq!(f, 4, "Go: expected 4 functions, got {}", f);
        assert_eq!(c, 2, "Go: expected 2 structs, got {}", c);
        assert_eq!(m, 0, "Go: expected 0 methods, got {}", m);
    }

    #[test]
    fn test_extractor_rust() {
        let source = include_str!("../../tests/fixtures/extractor/test_rust.rs");
        let (f, c, m) = extract_counts(source, Language::Rust);
        assert_eq!(f, 3, "Rust: expected 3 functions, got {}", f);
        assert_eq!(c, 2, "Rust: expected 2 structs, got {}", c);
        assert_eq!(m, 4, "Rust: expected 4 methods, got {}", m);
    }

    #[test]
    fn test_extractor_java() {
        let source = include_str!("../../tests/fixtures/extractor/test_java.java");
        let (f, c, m) = extract_counts(source, Language::Java);
        assert_eq!(f, 0, "Java: expected 0 functions, got {}", f);
        assert_eq!(c, 3, "Java: expected 3 classes, got {}", c);
        assert_eq!(m, 6, "Java: expected 6 methods, got {}", m);
    }

    #[test]
    fn test_extractor_c() {
        let source = include_str!("../../tests/fixtures/extractor/test_c.c");
        let (f, c, m) = extract_counts(source, Language::C);
        assert_eq!(f, 4, "C: expected 4 functions, got {}", f);
        assert_eq!(c, 2, "C: expected 2 structs, got {}", c);
        assert_eq!(m, 0, "C: expected 0 methods, got {}", m);
    }

    #[test]
    fn test_extractor_cpp() {
        let source = include_str!("../../tests/fixtures/extractor/test_cpp.cpp");
        let (f, c, m) = extract_counts(source, Language::Cpp);
        assert_eq!(f, 2, "C++: expected 2 functions, got {}", f);
        assert_eq!(c, 2, "C++: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "C++: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_typescript() {
        let source = include_str!("../../tests/fixtures/extractor/test_typescript.ts");
        let (f, c, m) = extract_counts(source, Language::TypeScript);
        assert_eq!(f, 3, "TypeScript: expected 3 functions, got {}", f);
        assert_eq!(c, 2, "TypeScript: expected 2 classes, got {}", c);
        assert_eq!(m, 4, "TypeScript: expected 4 methods, got {}", m);
    }

    #[test]
    fn test_extractor_javascript() {
        let source = include_str!("../../tests/fixtures/extractor/test_javascript.js");
        // Note: JS uses the TypeScript parser in this crate
        let (f, c, m) = extract_counts(source, Language::JavaScript);
        assert_eq!(f, 5, "JavaScript: expected 5 functions, got {}", f);
        assert_eq!(c, 2, "JavaScript: expected 2 classes, got {}", c);
        assert_eq!(m, 4, "JavaScript: expected 4 methods, got {}", m);
    }

    #[test]
    fn test_extractor_ruby() {
        let source = include_str!("../../tests/fixtures/extractor/test_ruby.rb");
        let (f, c, m) = extract_counts(source, Language::Ruby);
        assert_eq!(f, 2, "Ruby: expected 2 functions, got {}", f);
        assert_eq!(c, 2, "Ruby: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "Ruby: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_php() {
        let source = include_str!("../../tests/fixtures/extractor/test_php.php");
        let (f, c, m) = extract_counts(source, Language::Php);
        assert_eq!(f, 2, "PHP: expected 2 functions, got {}", f);
        assert_eq!(c, 2, "PHP: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "PHP: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_kotlin() {
        let source = include_str!("../../tests/fixtures/extractor/test_kotlin.kt");
        let (f, c, m) = extract_counts(source, Language::Kotlin);
        assert_eq!(f, 2, "Kotlin: expected 2 functions, got {}", f);
        assert_eq!(c, 2, "Kotlin: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "Kotlin: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_swift() {
        let source = include_str!("../../tests/fixtures/extractor/test_swift.swift");
        let (f, c, m) = extract_counts(source, Language::Swift);
        assert_eq!(f, 3, "Swift: expected 3 functions, got {}", f);
        assert_eq!(c, 2, "Swift: expected 2 classes, got {}", c);
        assert_eq!(m, 5, "Swift: expected 5 methods, got {}", m);
    }

    #[test]
    fn test_extractor_csharp() {
        let source = include_str!("../../tests/fixtures/extractor/test_csharp.cs");
        let (f, c, m) = extract_counts(source, Language::CSharp);
        assert_eq!(f, 0, "C#: expected 0 functions, got {}", f);
        assert_eq!(c, 3, "C#: expected 3 classes, got {}", c);
        assert_eq!(
            m, 7,
            "C#: expected 7 methods (including constructors), got {}",
            m
        );
    }

    #[test]
    fn test_extractor_scala() {
        let source = include_str!("../../tests/fixtures/extractor/test_scala.scala");
        let (f, c, m) = extract_counts(source, Language::Scala);
        assert_eq!(f, 2, "Scala: expected 2 functions, got {}", f);
        assert_eq!(c, 2, "Scala: expected 2 classes, got {}", c);
        assert_eq!(m, 4, "Scala: expected 4 methods, got {}", m);
    }

    #[test]
    fn test_extractor_ocaml() {
        let source = include_str!("../../tests/fixtures/extractor/test_ocaml.ml");
        let (f, c, m) = extract_counts(source, Language::Ocaml);
        assert_eq!(f, 3, "OCaml: expected 3 functions, got {}", f);
        assert_eq!(c, 0, "OCaml: expected 0 classes, got {}", c);
        assert_eq!(m, 0, "OCaml: expected 0 methods, got {}", m);
    }

    #[test]
    fn test_extractor_elixir() {
        let source = include_str!("../../tests/fixtures/extractor/test_elixir.ex");
        let (f, c, m) = extract_counts(source, Language::Elixir);
        assert_eq!(f, 3, "Elixir: expected 3 functions, got {}", f);
        assert_eq!(c, 1, "Elixir: expected 1 class (module), got {}", c);
        assert_eq!(m, 0, "Elixir: expected 0 methods, got {}", m);
    }

    #[test]
    fn test_extractor_lua() {
        let source = include_str!("../../tests/fixtures/extractor/test_lua.lua");
        let (f, c, m) = extract_counts(source, Language::Lua);
        assert_eq!(f, 5, "Lua: expected 5 functions, got {}", f);
        assert_eq!(c, 0, "Lua: expected 0 classes, got {}", c);
        assert_eq!(m, 0, "Lua: expected 0 methods, got {}", m);
    }

    #[test]
    fn test_extractor_luau() {
        let source = include_str!("../../tests/fixtures/extractor/test_luau.luau");
        let (f, c, m) = extract_counts(source, Language::Luau);
        assert_eq!(f, 3, "Luau: expected 3 functions, got {}", f);
        assert_eq!(c, 0, "Luau: expected 0 classes, got {}", c);
        assert_eq!(m, 0, "Luau: expected 0 methods, got {}", m);
    }

    // ── constant definitions ──────────────────────────────────────────────

    fn get_constants(source: &str, language: Language) -> Vec<DefinitionInfo> {
        let tree = parse(source, language).unwrap();
        let defs = extract_definitions(&tree, source, language);
        defs.into_iter().filter(|d| d.kind == "constant").collect()
    }

    #[test]
    fn test_python_constant_definitions() {
        let source = "MAX_RETRIES = 3\n\nEXTERNAL_FUNCTIONS = {\n    \"foo\": bar,\n    \"baz\": qux,\n}\n\nlower_case = 42\n";
        let consts = get_constants(source, Language::Python);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_RETRIES");
        assert_eq!(consts[0].line_start, 1);
        assert_eq!(consts[0].line_end, 1);
        assert_eq!(consts[0].signature, "MAX_RETRIES = 3");
        assert_eq!(consts[1].name, "EXTERNAL_FUNCTIONS");
        assert_eq!(consts[1].line_start, 3);
        assert_eq!(consts[1].line_end, 6);
        assert_eq!(consts[1].signature, "EXTERNAL_FUNCTIONS = {");
    }

    #[test]
    fn test_rust_constant_definitions() {
        let source =
            "const MAX_SIZE: usize = 100;\npub static GLOBAL: &str = \"hello\";\nlet x = 5;\n";
        let consts = get_constants(source, Language::Rust);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_SIZE");
        assert_eq!(consts[0].kind, "constant");
        assert_eq!(consts[1].name, "GLOBAL");
    }

    #[test]
    fn test_go_constant_definitions() {
        let source = "package main\n\nconst MaxRetries = 3\n\nconst (\n\tA = 1\n\tB = 2\n)\n";
        let consts = get_constants(source, Language::Go);
        assert_eq!(consts.len(), 3);
        let names: Vec<&str> = consts.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"MaxRetries"));
        assert!(names.contains(&"A"));
        assert!(names.contains(&"B"));
    }

    #[test]
    fn test_typescript_constant_definitions() {
        let source = "const MAX_RETRIES = 3;\nexport const API_URL = \"https://example.com\";\nconst lower = 42;\n";
        let consts = get_constants(source, Language::TypeScript);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_RETRIES");
        assert_eq!(consts[1].name, "API_URL");
    }

    #[test]
    fn test_javascript_multiline_constant() {
        let source = "const EXTERNAL_FUNCTIONS = {\n  foo: 1,\n  bar: 2,\n};\n";
        let consts = get_constants(source, Language::JavaScript);
        assert_eq!(consts.len(), 1);
        assert_eq!(consts[0].name, "EXTERNAL_FUNCTIONS");
        assert_eq!(consts[0].line_start, 1);
        assert_eq!(consts[0].line_end, 4);
        assert_eq!(consts[0].signature, "const EXTERNAL_FUNCTIONS = {");
    }

    #[test]
    fn test_c_constant_definitions() {
        let source = "#define MAX_SIZE 100\nconst int BUFFER_LEN = 256;\nint x = 5;\n";
        let consts = get_constants(source, Language::C);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_SIZE");
        assert_eq!(consts[1].name, "BUFFER_LEN");
    }

    #[test]
    fn test_java_constant_definitions() {
        let source = "class Config {\n    public static final int MAX_RETRIES = 3;\n    public static final String API_URL = \"https://example.com\";\n    private int x = 5;\n}\n";
        let consts = get_constants(source, Language::Java);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_RETRIES");
        assert_eq!(consts[1].name, "API_URL");
    }

    #[test]
    fn test_ruby_constant_definitions() {
        let source = "MAX_RETRIES = 3\nAPI_URL = \"https://example.com\"\nlower = 42\n";
        let consts = get_constants(source, Language::Ruby);
        assert_eq!(consts.len(), 2);
        assert_eq!(consts[0].name, "MAX_RETRIES");
        assert_eq!(consts[1].name, "API_URL");
    }

    // ── Bug fix: Python top-level def must be "function" not "method" ─────

    #[test]
    fn test_python_toplevel_function_kind_is_function() {
        let source = r#"
def top_level():
    pass

class MyClass:
    def method(self):
        pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let defs = extract_definitions(&tree, source, Language::Python);
        let top_level = defs.iter().find(|d| d.name == "top_level");
        assert!(top_level.is_some(), "top_level definition not found");
        assert_eq!(
            top_level.unwrap().kind,
            "function",
            "top-level Python def must have kind 'function', not 'method'"
        );
        let method = defs.iter().find(|d| d.name == "method");
        assert!(method.is_some(), "method definition not found");
        assert_eq!(
            method.unwrap().kind,
            "method",
            "Python def inside class must have kind 'method'"
        );
    }

    // ── Bug fix: OCaml definitions array must be populated ────────────────

    #[test]
    fn test_ocaml_definitions_non_empty() {
        let source = r#"
let top_level x = x * 2

let another_func x y = x + y

let rec factorial n =
  if n <= 1 then 1
  else n * factorial (n - 1)

let () =
  let result = factorial 5 in
  Printf.printf "%d\n" result
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let defs = extract_definitions(&tree, source, Language::Ocaml);
        assert!(
            !defs.is_empty(),
            "OCaml definitions array must be non-empty; got 0"
        );
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"top_level"),
            "OCaml: expected 'top_level' in definitions, got {:?}",
            names
        );
        assert!(
            names.contains(&"another_func"),
            "OCaml: expected 'another_func' in definitions, got {:?}",
            names
        );
        assert!(
            names.contains(&"factorial"),
            "OCaml: expected 'factorial' in definitions, got {:?}",
            names
        );
        // Anonymous entry-point let () = ... must not appear
        assert!(
            !names.contains(&"()"),
            "OCaml: '()' binding must not appear in definitions"
        );
    }

    // ── Bug fix: Kotlin companion object must produce a named definition ──

    #[test]
    fn test_kotlin_companion_object_definition() {
        let source = r#"
class Animal(val name: String) {
    fun speak(): String = "..."

    companion object {
        fun create(name: String): Animal = Animal(name)
    }
}
"#;
        let tree = parse(source, Language::Kotlin).unwrap();
        let defs = extract_definitions(&tree, source, Language::Kotlin);
        let companion = defs.iter().find(|d| d.name == "Companion");
        assert!(
            companion.is_some(),
            "Kotlin: companion object must produce a 'Companion' definition; definitions: {:?}",
            defs.iter().map(|d| (&d.name, &d.kind)).collect::<Vec<_>>()
        );
        assert_eq!(
            companion.unwrap().kind,
            "class",
            "Kotlin companion object kind must be 'class'"
        );
    }

    // ── Bug fix: C struct_specifier without body must not enter definitions ──

    #[test]
    fn test_c_struct_ref_not_emitted_as_definition_val_001() {
        // VAL-001: In C, `struct sockaddr *addr` in a parameter list parses as a
        // `struct_specifier` with a `name` field but NO `body`. It is a type
        // reference, not a definition, and must not appear in definitions[].
        let source = r#"
int open_connection(struct sockaddr *addr, struct sockaddr_in *sin) {
    return 0;
}
"#;
        let tree = parse(source, Language::C).unwrap();
        let defs = extract_definitions(&tree, source, Language::C);
        let names: Vec<String> = defs.iter().map(|d| d.name.clone()).collect();

        assert!(
            names.contains(&"open_connection".to_string()),
            "VAL-001: open_connection must be in definitions; got {:?}",
            names
        );
        assert!(
            !names.contains(&"sockaddr".to_string()),
            "VAL-001: bare struct_specifier `struct sockaddr` (no body) \
             must NOT appear in definitions; got {:?}",
            names
        );
        assert!(
            !names.contains(&"sockaddr_in".to_string()),
            "VAL-001: bare struct_specifier `struct sockaddr_in` (no body) \
             must NOT appear in definitions; got {:?}",
            names
        );
    }

    // ── Bug fix: Swift init_declaration must appear in definitions as method ──

    #[test]
    fn test_swift_init_emitted_as_method_definition_val_002() {
        // VAL-002: Swift `init` inside a class must appear in definitions[]
        // with kind="method". `extract_swift_methods` already handles this for
        // the methods[] array; definitions[] must be consistent.
        let source = r#"
class Foo {
    var x: Int = 0
    init(x: Int) { self.x = x }
    func bar() {}
}
"#;
        let tree = parse(source, Language::Swift).unwrap();
        let defs = extract_definitions(&tree, source, Language::Swift);
        let named: Vec<(String, String)> = defs
            .iter()
            .map(|d| (d.name.clone(), d.kind.clone()))
            .collect();

        let init = defs.iter().find(|d| d.name == "init");
        assert!(
            init.is_some(),
            "VAL-002: Swift init must be in definitions; got {:?}",
            named
        );
        assert_eq!(
            init.unwrap().kind,
            "method",
            "VAL-002: Swift init inside class must have kind='method'; got {:?}",
            named
        );
    }

    // ── Bug fix: Java constructor_declaration must appear as method ─────

    #[test]
    fn test_java_constructor_emitted_as_method_definition_val_003() {
        // VAL-003: Java `public Store()` constructor must appear in
        // definitions[] with kind="method" (mirroring C# / existing methods).
        let source = r#"
public class Store {
    public Store() {}
    public void get() {}
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let defs = extract_definitions(&tree, source, Language::Java);
        let named: Vec<(String, String)> = defs
            .iter()
            .map(|d| (d.name.clone(), d.kind.clone()))
            .collect();

        let ctor = defs
            .iter()
            .find(|d| d.name == "Store" && d.kind == "method");
        assert!(
            ctor.is_some(),
            "VAL-003: Java constructor `Store` must be in definitions with \
             kind='method'; got {:?}",
            named
        );
        // Regular method still present
        assert!(
            defs.iter().any(|d| d.name == "get" && d.kind == "method"),
            "VAL-003: Java method `get` must remain in definitions; got {:?}",
            named
        );
    }

    // ── Bug fix: Class-scope fields must appear in definitions as kind=field ──

    #[test]
    fn test_class_fields_emitted_as_definitions_val_004() {
        // VAL-004: Class-scope field/property declarations must appear in
        // definitions[] with kind="field". Covers Java, Kotlin, Swift, TS.
        //
        // Guard: Kotlin top-level `val/var` parses as property_declaration
        // too, but must NOT be emitted as a field because it is not inside a
        // class_body.

        // Java
        {
            let source = r#"
public class Store {
    private int count = 0;
    public String name;
    int x, y;
    public void get() {}
}
"#;
            let tree = parse(source, Language::Java).unwrap();
            let defs = extract_definitions(&tree, source, Language::Java);
            let fields: Vec<String> = defs
                .iter()
                .filter(|d| d.kind == "field")
                .map(|d| d.name.clone())
                .collect();
            for expected in ["count", "name", "x", "y"] {
                assert!(
                    fields.contains(&expected.to_string()),
                    "VAL-004 (Java): field `{}` must appear in definitions; \
                     got fields={:?}, all defs={:?}",
                    expected,
                    fields,
                    defs.iter().map(|d| (&d.name, &d.kind)).collect::<Vec<_>>()
                );
            }
        }

        // Kotlin: class-scope val/var must be fields; top-level must NOT.
        {
            let source = r#"
class Foo {
    val x: Int = 0
    var y: String = "hi"
    fun bar() {}
}

val topLevelX = 1
"#;
            let tree = parse(source, Language::Kotlin).unwrap();
            let defs = extract_definitions(&tree, source, Language::Kotlin);
            let fields: Vec<String> = defs
                .iter()
                .filter(|d| d.kind == "field")
                .map(|d| d.name.clone())
                .collect();
            assert!(
                fields.contains(&"x".to_string()),
                "VAL-004 (Kotlin): class-scope `val x` must be a field; \
                 got fields={:?}",
                fields
            );
            assert!(
                fields.contains(&"y".to_string()),
                "VAL-004 (Kotlin): class-scope `var y` must be a field; \
                 got fields={:?}",
                fields
            );
            assert!(
                !fields.contains(&"topLevelX".to_string()),
                "VAL-004 (Kotlin): top-level `val topLevelX` must NOT be a \
                 field (only class-scope properties are fields); got \
                 fields={:?}",
                fields
            );
        }

        // Swift
        {
            let source = r#"
class Foo {
    var x: Int = 0
    let y: String = "hi"
    func bar() {}
}
"#;
            let tree = parse(source, Language::Swift).unwrap();
            let defs = extract_definitions(&tree, source, Language::Swift);
            let fields: Vec<String> = defs
                .iter()
                .filter(|d| d.kind == "field")
                .map(|d| d.name.clone())
                .collect();
            for expected in ["x", "y"] {
                assert!(
                    fields.contains(&expected.to_string()),
                    "VAL-004 (Swift): class-scope property `{}` must be a \
                     field; got fields={:?}",
                    expected,
                    fields
                );
            }
        }

        // TypeScript
        {
            let source = r#"
class Foo {
    public count: number = 0;
    name: string = "hi";
    bar() {}
}
"#;
            let tree = parse(source, Language::TypeScript).unwrap();
            let defs = extract_definitions(&tree, source, Language::TypeScript);
            let fields: Vec<String> = defs
                .iter()
                .filter(|d| d.kind == "field")
                .map(|d| d.name.clone())
                .collect();
            for expected in ["count", "name"] {
                assert!(
                    fields.contains(&expected.to_string()),
                    "VAL-004 (TypeScript): class field `{}` must be in \
                     definitions; got fields={:?}",
                    expected,
                    fields
                );
            }
        }
    }

    /// VAL-001: TypeScript signature-only methods (abstract class methods
    /// and interface methods) must appear in both `definitions[]` (kind=method)
    /// and `methods[]`. Previously `classify_definition_node` only matched
    /// `method_definition`, so `method_signature` / `abstract_method_signature`
    /// nodes were silently dropped.
    #[test]
    fn test_typescript_abstract_and_interface_methods_emitted_val_001() {
        let source = r#"
export abstract class Repo<T> {
  abstract save(item: T): Promise<void>;
  find(id: string): T | null { return null; }
}
interface IFace {
  greet(name: string): void;
  defaulted(): number;
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();

        // === definitions[] assertions ===
        let defs = extract_definitions(&tree, source, Language::TypeScript);
        let by_name: std::collections::BTreeMap<String, String> = defs
            .iter()
            .map(|d| (d.name.clone(), d.kind.clone()))
            .collect();

        assert_eq!(
            by_name.get("Repo").map(String::as_str),
            Some("class"),
            "VAL-001: `Repo` must be kind=class; got defs={:?}",
            defs
        );
        assert_eq!(
            by_name.get("IFace").map(String::as_str),
            Some("interface"),
            "VAL-001: `IFace` must be kind=interface; got defs={:?}",
            defs
        );
        for expected in ["save", "find", "greet", "defaulted"] {
            assert_eq!(
                by_name.get(expected).map(String::as_str),
                Some("method"),
                "VAL-001: `{}` must appear in definitions with kind=method; got defs={:?}",
                expected,
                defs
            );
        }

        // === methods[] assertions ===
        let methods = extract_methods(&tree, source, Language::TypeScript);
        for expected in ["save", "find", "greet", "defaulted"] {
            assert!(
                methods.contains(&expected.to_string()),
                "VAL-001: `{}` must appear in methods[]; got methods={:?}",
                expected,
                methods
            );
        }
    }

    /// (fix-R7-cl2-cpp-forward-dup-v1) A C++ forward declaration `class X;`
    /// (no body) must NOT be emitted as a class. With the real definition
    /// present too, the previous no-body-check pushed BOTH, duplicating the
    /// class (tinyxml2: 27 entries / 19 unique). Each defined class must appear
    /// exactly once and the forward-only decl must not double it.
    #[test]
    fn test_cpp_forward_declaration_not_duplicated() {
        let source = r#"
class XMLDocument;
class XMLElement;

class XMLDocument {
public:
    void parse();
};

class XMLElement {
public:
    void name();
};
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let classes = extract_classes(&tree, source, Language::Cpp);
        let doc_count = classes.iter().filter(|c| *c == "XMLDocument").count();
        let elem_count = classes.iter().filter(|c| *c == "XMLElement").count();
        assert_eq!(
            doc_count, 1,
            "XMLDocument must appear exactly once (forward decl must not double it), got {:?}",
            classes
        );
        assert_eq!(
            elem_count, 1,
            "XMLElement must appear exactly once, got {:?}",
            classes
        );
    }

    /// (fix-R7-cl2-cpp-forward-dup-v1) A pure forward declaration with NO real
    /// definition in the same TU must not surface as a class at all.
    #[test]
    fn test_cpp_pure_forward_declaration_excluded() {
        let source = "class OnlyForward;\nstruct AlsoForward;\n";
        let tree = parse(source, Language::Cpp).unwrap();
        let classes = extract_classes(&tree, source, Language::Cpp);
        assert!(
            !classes.contains(&"OnlyForward".to_string()),
            "pure forward decl `class OnlyForward;` must be excluded, got {:?}",
            classes
        );
        assert!(
            !classes.contains(&"AlsoForward".to_string()),
            "pure forward decl `struct AlsoForward;` must be excluded, got {:?}",
            classes
        );
    }

    /// (fix-R7-cl2-elixir-macro-v1) Elixir `defmacro`/`defmacrop` were dropped
    /// (only def/defp handled) — hiding the entire DSL surface of Phoenix/Plug
    /// routers. They must surface as definitions, AND a `when`-guarded clause
    /// must resolve to the bare function name (not the full `f(x) when g` text).
    #[test]
    fn test_elixir_defmacro_and_guard_definitions() {
        let source = r#"
defmodule Router do
  defmacro resources(path, controller) do
    path
  end

  defmacrop helper(x) do
    x
  end

  def match(conn) when is_map(conn) do
    conn
  end
end
"#;
        let tree = parse(source, Language::Elixir).unwrap();
        let defs = extract_definitions(&tree, source, Language::Elixir);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"resources"),
            "defmacro `resources` must be a definition, got {:?}",
            names
        );
        assert!(
            names.contains(&"helper"),
            "defmacrop `helper` must be a definition, got {:?}",
            names
        );
        // The guarded clause name must be the bare `match`, never the guard text.
        assert!(
            names.contains(&"match"),
            "guarded `def match(conn) when ...` must resolve to `match`, got {:?}",
            names
        );
        assert!(
            !names.iter().any(|n| n.contains("when")),
            "no definition name may contain the guard text `when`, got {:?}",
            names
        );

        // extract_functions (the Vec<String> path) must agree.
        let funcs = extract_functions(&tree, source, Language::Elixir);
        assert!(
            funcs.contains(&"resources".to_string()),
            "extract_functions must include defmacro `resources`, got {:?}",
            funcs
        );
        assert!(
            funcs.contains(&"match".to_string()),
            "extract_functions must include guarded `match`, got {:?}",
            funcs
        );
    }

    /// (fix-R7-cl2-ocaml-nested-letin-v1) The generic definition collector
    /// marked every OCaml `value_definition` as a function, including inner
    /// `let ... in` bindings, so nested let-in helpers leaked as top-level
    /// functions (dune util.ml). Only true top-level functions must surface.
    #[test]
    fn test_ocaml_nested_let_in_not_top_level() {
        let source = r#"
let check_path contexts =
  let contexts =
    let internal_path () = 1 in
    internal_path ()
  in
  contexts

let setup () =
  let scheduler = 5 in
  scheduler
"#;
        let tree = parse(source, Language::Ocaml).unwrap();
        let defs = extract_definitions(&tree, source, Language::Ocaml);
        let func_names: Vec<&str> = defs
            .iter()
            .filter(|d| d.kind == "function")
            .map(|d| d.name.as_str())
            .collect();
        // Top-level functions present.
        assert!(
            func_names.contains(&"check_path"),
            "top-level `check_path` must be a function, got {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"setup"),
            "top-level `setup` must be a function, got {:?}",
            func_names
        );
        // Nested let-in bindings must NOT leak as top-level functions.
        for leaked in ["contexts", "internal_path", "scheduler"] {
            assert!(
                !func_names.contains(&leaked),
                "nested let-in `{}` must NOT be a top-level function, got {:?}",
                leaked,
                func_names
            );
        }
    }

    /// (fix-R7-cl2-ocaml-nested-letin-v1) A point-free top-level function
    /// `let code = function | ...` must still surface in the generic collector
    /// (was at risk from the function-shape gate added for the nested fix).
    #[test]
    fn test_ocaml_pointfree_top_level_function_kept() {
        let source = "let all = [ 1; 2 ]\nlet code = function\n  | 0 -> 1\n  | _ -> 2\n";
        let tree = parse(source, Language::Ocaml).unwrap();
        let defs = extract_definitions(&tree, source, Language::Ocaml);
        let func_names: Vec<&str> = defs
            .iter()
            .filter(|d| d.kind == "function")
            .map(|d| d.name.as_str())
            .collect();
        assert!(
            func_names.contains(&"code"),
            "point-free top-level `let code = function` must be a function, got {:?}",
            func_names
        );
    }

    /// (fix-R7-cl2-swift-void-phantom-v1) A Swift closure-typed property
    /// `var h: (Int) -> Void` contains a `function_type` annotation whose return
    /// type is exposed under a `name` field — the generic collector emitted a
    /// phantom `Void` method for each. No definition named `Void` may appear,
    /// and real methods/init must remain.
    #[test]
    fn test_swift_closure_property_no_void_phantom() {
        let source = r#"
final class DataRequest {
    var httpResponseHandler: (queue: DispatchQueue, handler: (HTTPURLResponse) -> Void) -> Void)?

    var didComplete: (@Sendable () -> Void)?

    init(id: Int) {
    }

    func realMethod(x: Int) -> String {
        return "x"
    }
}
"#;
        let tree = parse(source, Language::Swift).unwrap();
        let defs = extract_definitions(&tree, source, Language::Swift);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(
            !names.contains(&"Void"),
            "closure-type return `-> Void` must NOT emit a phantom `Void` definition, got {:?}",
            names
        );
        // Real method and init must still be present.
        assert!(
            names.contains(&"realMethod"),
            "real method `realMethod` must remain, got {:?}",
            names
        );
        assert!(
            names.contains(&"init"),
            "`init` must remain, got {:?}",
            names
        );
    }
}
