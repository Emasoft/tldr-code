//! Find importers of a module (spec Section 2.2.4)
//!
//! Find all files that import a given module.
//!
//! # Features
//! - Captures line numbers
//! - Captures import statement text
//! - Supports both import and from-import styles
//! - Works with Python, TypeScript, Go

use std::collections::HashSet;
use std::path::Path;

use crate::ast::imports::get_imports;
use crate::fs::tree::{collect_files, get_file_tree};
use crate::types::{IgnoreSpec, ImporterInfo, ImportersReport, Language};
use crate::TldrResult;

/// Find all files that import a given module.
///
/// # Arguments
/// * `root` - Project root directory
/// * `module` - Module name to search for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(ImportersReport)` - List of files importing the module
pub fn find_importers(
    root: &Path,
    module: &str,
    language: Language,
) -> TldrResult<ImportersReport> {
    // RC1 (v0.5.0 R7 cluster[10]): walk with `scan_extensions()` so C++
    // `.h` headers are included — a header-only importer (`scan.h`
    // `#include`ing `format-inl.h`) was previously invisible because
    // `extensions()` omits `.h` for Cpp. C and all non-Cpp/JS-TS langs are
    // unaffected (their `scan_extensions()` equals `extensions()`).
    let extensions: HashSet<String> = language
        .scan_extensions()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let tree = get_file_tree(root, Some(&extensions), true, Some(&IgnoreSpec::default()))?;
    let files = collect_files(&tree, root);

    let mut importers = Vec::new();

    for file_path in files {
        match find_import_in_file(&file_path, module, language) {
            Ok(Some(info)) => importers.push(info),
            Ok(None) => {}
            Err(e) => {
                if e.is_recoverable() {
                    // Skip files with parse errors
                    continue;
                }
            }
        }
    }

    let total = importers.len();
    Ok(ImportersReport {
        module: module.to_string(),
        importers,
        total,
    })
}

/// Check if a file imports the specified module.
///
/// `importers-ast-anchored-v1` (v0.4.2 M-035): the line and import-statement
/// text are now sourced from the AST extractor's `ImportInfo.line`. Previously
/// this function ran a text-substring scan (`find_import_line`) that surfaced
/// docstring/alias false positives and fell back to `line: 1` whenever the
/// idiomatic match failed (notably Go imports inside `import (...)` blocks).
/// The text scan is gone; the only thing read from disk is the literal text
/// of the AST-pinned line.
fn find_import_in_file(
    file_path: &Path,
    target_module: &str,
    language: Language,
) -> TldrResult<Option<ImporterInfo>> {
    let imports = get_imports(file_path, language)?;

    // Two-pass scan: prefer non-aliased imports (M-035 cluster intent).
    // Pre-fix the emitter used a text-scan that simply returned the first
    // line containing the module substring; in a file with both
    //   line 6:  using Assert = Newtonsoft.Json.Bson.Tests.XUnitAssert;  (aliased)
    //   line 7:  using Newtonsoft.Json.Bson;                              (real)
    // the alias-RHS at line 6 also lexically matches `Newtonsoft.Json.Bson`
    // (it's a sub-namespace), so the importers emitter surfaced line 6.
    // The user-intuitive answer is line 7: the unaliased `using` is the
    // direct importer; the alias-RHS is a transitive reference embedded in
    // a local binding. Iterate twice: first pass picks unaliased imports,
    // second pass falls back to aliased ones.
    for prefer_unaliased in [true, false] {
        for import in &imports {
            // CSharp alias-exclusion: a `using A = B.C;` directive should
            // NOT match a query for `A` — the alias name is a local binding,
            // not an imported module.
            if matches!(language, Language::CSharp)
                && import.alias.as_deref() == Some(target_module)
            {
                continue;
            }

            // Skip aliased imports in the first pass so an unaliased import
            // lower in the file is preferred over an aliased one higher up.
            if prefer_unaliased && import.alias.is_some() {
                continue;
            }

            // elixir-importers-kind-gate-v1 (#52): "importer" = a directive that
            // brings the target's functions/macros into lexical scope. Only
            // `import` and `use` qualify; `alias` (name-only) and `require`
            // (macro-availability) do NOT. The extractor projects the directive
            // keyword into the ImportInfo tuple:
            //   import : is_from=Some(true),  names=["*"], alias=None
            //   use    : is_from=Some(true),  names=["*"], alias=None   (byte-identical to import)
            //   alias  : is_from=Some(false), names=[],    alias=Some(_)
            //   require: is_from=Some(false), names=[],    alias=None
            // so `is_from == Some(true)` exactly selects {import, use} and drops
            // {alias, require}.
            if matches!(language, Language::Elixir) && import.is_from != Some(true) {
                continue;
            }

            let matched_module = module_matches(&import.module, target_module, language);

            // Secondary match: `from X import target_module` — when querying
            // for a named import (Python's `target` as one of `import.names`),
            // the file is still an importer of the parent module.
            let matched_from_name = import.is_from.unwrap_or(false)
                && import.names.iter().any(|n| n == target_module);

            // importers-named-symbol-v1 (v0.5.0 T1 AUDIT-FIX): match a queried
            // symbol against the import's NAMED bindings for languages whose
            // import directive carries the symbol separately from the module
            // path — e.g. Solidity `import {ERC20} from "../tokens/ERC20.sol"`
            // captures `module = "../tokens/ERC20.sol"`, `names = ["ERC20"]`.
            // Pre-fix `importers ERC20` returned 0 because the module path
            // (`../tokens/ERC20.sol`) never matched the bare symbol query and
            // the `names` list was only consulted for Python `is_from`. We
            // accept a `names` hit when the query is a single-segment symbol
            // (no path / dotted FQN separators), which is exactly the
            // named-symbol-query shape and cannot be confused with a
            // module-path query.
            let query_is_symbol = !target_module.contains(['/', '\\', '.'])
                && !target_module.is_empty();
            let matched_named_symbol = query_is_symbol
                && import.names.iter().any(|n| n == target_module);

            if !matched_module && !matched_from_name && !matched_named_symbol {
                continue;
            }

            return Ok(Some(emit_importer(file_path, import.line)?));
        }
    }

    Ok(None)
}

/// Emit an `ImporterInfo` for a file given the AST-anchored line.
///
/// importers-ast-anchored-v1 (M-035): reads exactly one line from the file —
/// the line the AST extractor pinned via `ImportInfo.line` — and uses its
/// text as the `import_statement`. No substring scanning, no fallback to
/// line 1. If `ast_line == 0` (e.g. a defensive path where a helper failed
/// to set the line), we degrade gracefully to the first line of the file.
fn emit_importer(file_path: &Path, ast_line: u32) -> TldrResult<ImporterInfo> {
    let content = std::fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let idx = if ast_line == 0 {
        0
    } else {
        (ast_line as usize).saturating_sub(1)
    };
    let stmt = lines.get(idx).copied().unwrap_or("").trim().to_string();
    let line = if ast_line == 0 { 1 } else { ast_line };
    Ok(ImporterInfo {
        file: file_path.to_path_buf(),
        line,
        import_statement: stmt,
    })
}

/// Check if a module name matches the target
fn module_matches(import_module: &str, target: &str, language: Language) -> bool {
    match language {
        Language::Python => {
            // Exact match
            if import_module == target {
                return true;
            }
            // Submodule match (FORWARD): a query for the PARENT package
            // `services` matches a more-specific import `services.auth` — the
            // file that imports `services.auth` is an importer of `services`.
            if import_module.starts_with(&format!("{}.", target)) {
                return true;
            }
            // python-importers-submodule-granularity-v1 (v0.5.0 T1 AUDIT-FIX):
            // the REVERSE-prefix rule (a query for the more-specific submodule
            // `flask.helpers` matching a bare parent import `flask`) is WRONG
            // for Python. `from flask import Flask` imports the package
            // `flask`; it does NOT import `flask.helpers`. Pre-fix this rule
            // made `importers flask.helpers` return all 44 `from flask import …`
            // sites (wrong granularity). A more-specific submodule query must
            // only match imports of that submodule (or deeper), handled by the
            // exact + forward-prefix rules above. The reverse rule is removed.
            //
            // Handle relative imports (`.auth` queried as `auth`).
            let cleaned_import = import_module.trim_start_matches('.');
            let cleaned_target = target.trim_start_matches('.');
            cleaned_import == cleaned_target
        }
        Language::TypeScript | Language::JavaScript => {
            // Normalize paths
            let normalized_import = import_module.replace('\\', "/");
            let normalized_target = target.replace('\\', "/");

            if normalized_import == normalized_target {
                return true;
            }
            // Handle ./relative paths
            let import_clean = normalized_import.trim_start_matches("./");
            let target_clean = normalized_target.trim_start_matches("./");
            if import_clean == target_clean {
                return true;
            }
            // RC5 (v0.5.0 R7 cluster[10], #242): canonicalize relative
            // specifiers so `./scanner` (queried) matches a file that imports
            // the SAME leaf via a different relative depth (`../../scanner`).
            // The TS/JS arm previously did only exact + `./`-trim and never
            // resolved `../` prefixes, so equivalent relative spellings of the
            // same target missed. `path_module_matches` (already used by
            // Solidity/Lua/Ruby) strips leading `../`/`./` and does
            // segment-anchored suffix + leaf matching. Strip a trailing
            // module extension first so `../scanner.ts` matches `./scanner`,
            // mirroring how `index_ts_js_module` registers extension-less keys.
            fn strip_ts_ext(s: &str) -> &str {
                for ext in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs"] {
                    if let Some(stripped) = s.strip_suffix(ext) {
                        return stripped;
                    }
                }
                s
            }
            path_module_matches(strip_ts_ext(&normalized_import), strip_ts_ext(&normalized_target))
        }
        Language::Go => {
            // Package path matching
            import_module == target || import_module.ends_with(&format!("/{}", target))
        }
        // language-specific-bugs-v1 (P14.AGG14-11): Scala uses the same
        // dotted-FQCN syntax as Java (`import cats.effect.IO`) plus a
        // family of brace-, wildcard-, and rename-based selectors. The
        // exact-match-only fallback meant a query for the package
        // `cats.effect` against a file that imports
        // `cats.effect.kernel.Async` returned 0 hits, even though the
        // file is unambiguously inside the `cats.effect` subtree.
        // Mirror Python's submodule-bidirectional rule so subpath
        // queries succeed in both directions:
        //   target = "cats.effect"            matches "cats.effect.kernel.Async"
        //   target = "cats.effect.kernel.Async" matches "cats.effect"
        //   target = "cats.effect.IO"         matches "cats.effect.IO"
        //
        // residual-bugs-v1 (P15.AGG15-3): callers also pass a bare class
        // name without the FQN package (`tldr importers Owner ...` for
        // spring-petclinic). The previous prefix-only rules failed
        // because `Owner` neither equals nor is a strict prefix/suffix
        // of `org.springframework.samples.petclinic.owner.Owner`. Add
        // a final last-segment match so a class-name query resolves
        // every FQN whose terminal segment matches. This mirrors Go's
        // `ends_with("/{}")` rule but for dotted package paths. Only
        // applied when the target itself is a single segment (no dot)
        // — an FQN target falls through the prefix rules above.
        //
        // non-judgment-call-bugs-v1 (P17.AGG17-1): the reverse-prefix
        // rule (`target.starts_with("{}.", import_module)`) was too
        // aggressive when `import_module` is a single top-level segment.
        // For example, `import cats._` extracts as module=`cats`; an
        // `importers cats.effect.IO` query would then match because
        // `cats.effect.IO` starts with `cats.`. But Scala wildcard
        // imports are *not* transitive — `import cats._` only exposes
        // `cats`'s direct members, not `cats.effect.IO`. Restrict the
        // reverse-prefix rule to multi-segment `import_module` values
        // (`cats.effect`, `cats.effect.kernel`, …) which represent
        // genuine sub-package imports. Top-level wildcards still match
        // exact target queries via the `import_module == target` rule.
        Language::Scala | Language::Kotlin | Language::Java | Language::CSharp => {
            // importers-ast-anchored-v1 (M-035): CSharp added to the dotted-FQN
            // family. `using Foo.Bar.Baz;` should match a query for
            // `Foo.Bar` (sub-namespace prefix) and a bare-class query
            // `Baz` (last-segment) — mirroring the Java/Scala rules.
            if import_module == target {
                return true;
            }
            // FORWARD-prefix: a query for the PARENT package `Foo.Bar` matches
            // a more-specific import `Foo.Bar.Baz` (the file importing the
            // child is an importer of the parent subtree).
            if import_module.starts_with(&format!("{}.", target)) {
                return true;
            }
            // RC4 (v0.5.0 R7 cluster[10], #34): the REVERSE-prefix rule
            // (`target.starts_with("{import_module}.")`) is REMOVED. A query
            // for a CHILD sub-namespace `Newtonsoft.Json.Bson.Utilities` must
            // NOT match a file that only imports the PARENT namespace
            // `using Newtonsoft.Json.Bson;` — importing the parent does not
            // import the more-specific child type. This mirrors the Python fix
            // (the reverse rule was likewise removed there). Exact +
            // forward-prefix + bare-last-segment remain and cover every
            // legitimate case (incl. the residual-bugs scala cats.effect and
            // petclinic Owner queries).
            if !target.contains('.') && import_module.ends_with(&format!(".{}", target)) {
                return true;
            }
            false
        }
        Language::C | Language::Cpp => {
            // importers-ast-anchored-v1 (M-035): #include "../subdir/foo.h"
            // should match a query for the bare header name `foo.h`. The AST
            // extractor preserves the literal include path (`../subdir/foo.h`,
            // `subdir/foo.h`, or `foo.h`); compare the basename against the
            // target so a relative include resolves correctly. System includes
            // (`<stdio.h>`) compare via the same rule.
            if import_module == target {
                return true;
            }
            let import_basename = std::path::Path::new(import_module)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(import_module);
            let target_basename = std::path::Path::new(target)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(target);
            import_basename == target_basename
        }
        // cl9-importers-v1 (GH #79, v0.5.0 CL-9): PHP `use` directives
        // capture the FQ namespace the AST extractor pinned, e.g.
        // `Symfony\Component\Console\Command\Command`. The catch-all
        // `_ => import_module == target` arm only matched the full FQ
        // string, so a query for the class basename `Command` returned
        // zero importers even though the project imports it everywhere.
        //
        // PHP namespaces are `\`-separated. Mirror the spellings that
        // `index_php_module` registers in the deps resolver:
        //   * full FQ namespace verbatim (`A\B\Command`)
        //   * a sub-namespace suffix query (`B\Command` → `A\B\Command`)
        //   * the bare class basename (`Command`)
        // plus the reverse direction (FQ target matched by a shorter
        // captured module), so the rule is symmetric like Python's.
        Language::Php => {
            if import_module == target {
                return true;
            }
            // Normalise both sides on `\` and compare last segments /
            // suffixes. A leading `\` (fully-qualified absolute form,
            // `\App\Foo`) is cosmetic for matching purposes.
            let import_norm = import_module.trim_start_matches('\\');
            let target_norm = target.trim_start_matches('\\');
            if import_norm == target_norm {
                return true;
            }
            // Suffix match: target is a trailing namespace segment-run of
            // the captured module. `B\Command` matches `A\B\Command`;
            // `Command` matches `A\B\Command`.
            if import_norm.ends_with(&format!("\\{}", target_norm)) {
                return true;
            }
            // Reverse suffix: the captured module is a trailing run of a
            // longer FQ target query (`A\B` matches a query for
            // `Root\A\B`). Mirrors Python's bidirectional submodule rule.
            if target_norm.ends_with(&format!("\\{}", import_norm)) {
                return true;
            }
            false
        }
        // cl9-importers-v1 (GH #79, v0.5.0 CL-9): Solidity `import`
        // directives capture the literal source path string the AST
        // extractor pinned, e.g. `../utils/Context.sol` or
        // `@openzeppelin/contracts/utils/Context.sol`. The exact-match-
        // only fallback meant a query for the file basename `Context.sol`
        // (or a relative spelling) returned zero importers.
        //
        // Solidity import paths are filesystem-relative `/`-separated
        // strings. Mirror the spellings `index_solidity_module` /
        // `resolve_solidity_import` accept in the deps resolver:
        //   * the path verbatim (`../utils/Context.sol`)
        //   * a trailing-path-segment suffix (`utils/Context.sol`)
        //   * the bare leaf filename (`Context.sol`)
        // Relative-prefix noise (`./`, `../`) is stripped from both sides
        // before the suffix/leaf comparison so `./Context.sol`,
        // `../utils/Context.sol`, and `Context.sol` all resolve.
        Language::Solidity => path_module_matches(import_module, target),
        // cl9-importers-v1 (GH #79, v0.5.0 CL-9): Lua/Luau `require()`
        // calls capture either a dotted module path (`foo.bar`) or a
        // filesystem-relative path (`./foo/bar`, `../foo/bar`). The
        // exact-match-only fallback missed a basename / sub-path query.
        // Mirror `index_lua_module`: normalise the dotted form to slashes
        // and compare leaf names / suffixes. A `.lua`/`.luau` extension on
        // either side is stripped so `foo/bar`, `foo.bar`, and `bar` all
        // resolve to the same module.
        Language::Lua | Language::Luau => {
            if import_module == target {
                return true;
            }
            // Lua's idiom maps dot-separated module paths to filesystem
            // `/`-separated paths (`require("foo.bar")` ⇒ `foo/bar.lua`),
            // so canonicalise dots to slashes on both sides first.
            let import_norm = import_module.replace('.', "/");
            let target_norm = target.replace('.', "/");
            if import_norm == target_norm {
                return true;
            }
            path_module_matches(&import_norm, &target_norm)
        }
        // cl9-importers-v1 (GH #79, v0.5.0 CL-9): Ruby `require` /
        // `require_relative` calls capture the literal path string the AST
        // extractor pinned, e.g. `rubocop/server`, `../../lsp/server`, or
        // `rubocop/cop/util`. The exact-match-only fallback meant a query
        // for the basename `server` returned zero importers.
        //
        // Ruby require paths are `/`-separated. Mirror the spellings
        // `index_ruby_module` registers (full path, `lib/`/`app/`-stripped
        // path, bare leaf name): match on path suffix or leaf basename,
        // with leading `./`/`../` relative noise stripped from both sides.
        Language::Ruby => path_module_matches(import_module, target),
        // elixir-importers-kind-gate-v1 (#52): Elixir modules are dotted
        // PascalCase atoms and the extractor captures the full `Plug.Conn`, so
        // exact equality is correct today. This explicit arm replaces the
        // catch-all fall-through so the language's dotted-module semantics are
        // intentional and host any future submodule rule (mirroring Python/
        // Scala). The behavioral fix for #52 is the `is_from` kind-gate in
        // `find_import_in_file`; this arm is its documentation-as-code companion.
        Language::Elixir => import_module == target,
        _ => import_module == target,
    }
}

/// Match a captured filesystem-style module path against a target query,
/// tolerating relative-path noise and basename / sub-path spellings.
///
/// cl9-importers-v1 (GH #79, v0.5.0 CL-9). Used by the Solidity, Ruby and
/// Lua/Luau arms of [`module_matches`]. The captured `import_module` is the
/// literal path the AST extractor pinned (`../utils/Context.sol`,
/// `rubocop/server`, `foo/bar`); `target` is the user's query, which may be
/// the full path, a trailing sub-path, or the bare leaf filename.
///
/// A match succeeds when, after stripping leading `./` and `../` segments
/// and any trailing path separators from both sides:
///   * the normalised paths are equal, OR
///   * one is a trailing path-segment-run suffix of the other (so
///     `utils/Context.sol` and `Context.sol` both match
///     `../utils/Context.sol`), OR
///   * the bare leaf segments are equal (basename query).
///
/// The suffix comparison is segment-anchored (it requires a `/` boundary or
/// full-string equality) so a query for `text.sol` does NOT spuriously match
/// `Context.sol` — only `Context.sol` matches `Context.sol`.
fn path_module_matches(import_module: &str, target: &str) -> bool {
    if import_module == target {
        return true;
    }

    // Strip leading relative-path segments (`./`, `../`, repeated) and any
    // trailing slash. The relative prefix is positional noise — the module
    // identity lives in the trailing path segments.
    fn strip_relative(s: &str) -> &str {
        let mut rest = s.trim_end_matches('/');
        loop {
            if let Some(r) = rest.strip_prefix("../") {
                rest = r;
            } else if let Some(r) = rest.strip_prefix("./") {
                rest = r;
            } else {
                break;
            }
        }
        rest
    }

    let import_norm = strip_relative(import_module);
    let target_norm = strip_relative(target);

    if import_norm == target_norm {
        return true;
    }

    // Segment-anchored suffix match in both directions. `ends_with` alone is
    // too loose (`Context.sol` would match `ERC2771Context.sol`); requiring a
    // preceding `/` (or full equality, handled above) keeps it segment-clean.
    if import_norm.ends_with(&format!("/{}", target_norm))
        || target_norm.ends_with(&format!("/{}", import_norm))
    {
        return true;
    }

    // Bare leaf-name (basename) match: only when one side is a *single*
    // path segment (no `/`). This is the basename-query case
    // (`Context.sol`, `server`). We deliberately do NOT leaf-match two
    // multi-segment paths against each other — a query for
    // `other/Context.sol` must NOT match an import of `utils/Context.sol`
    // (different files); that case is already covered by the
    // segment-anchored suffix rules above.
    let import_is_leaf = !import_norm.contains('/');
    let target_is_leaf = !target_norm.contains('/');
    if target_is_leaf {
        let import_leaf = import_norm.rsplit('/').next().unwrap_or(import_norm);
        return import_leaf == target_norm;
    }
    if import_is_leaf {
        let target_leaf = target_norm.rsplit('/').next().unwrap_or(target_norm);
        return target_leaf == import_norm;
    }
    false
}

/// Find the line number and text of an import statement.
///
/// importers-ast-anchored-v1 (v0.4.2 M-035): this function is no longer
/// called from production code — the importers emitter now reads the line
/// directly from `ImportInfo.line` populated by the AST extractor. The
/// function is retained for the existing unit-test coverage (which pins
/// the per-language idiom recognition); marking `#[cfg(test)]` is the
/// truthful way to express that it is exercised only by tests.
#[cfg(test)]
fn find_import_line(
    lines: &[&str],
    module: &str,
    is_from: bool,
    language: Language,
) -> (u32, String) {
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        match language {
            Language::Python => {
                if is_from {
                    if trimmed.starts_with("from ") && trimmed.contains(module) {
                        return (i as u32 + 1, trimmed.to_string());
                    }
                } else if trimmed.starts_with("import ") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            Language::TypeScript | Language::JavaScript => {
                if trimmed.contains("import") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
                if trimmed.contains("require") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            Language::Go => {
                if trimmed.contains("import") && trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            // non-judgment-call-bugs-v1 (P17.AGG17-1): for Scala / Kotlin
            // / Java / Rust, lines starting with `package` (Scala/Kotlin/
            // Java) or `mod`/`pub mod` (Rust) are *declarations*, not
            // imports. Previously this branch returned the first line
            // whose substring matched `module`, which falsely surfaced
            // package-declaration lines (`package cats.effect.kernel`)
            // as the import statement when an unrelated wildcard import
            // matched the query. Require the line to look like an
            // import statement (`import …` / `use …`) before reporting it.
            Language::Scala | Language::Kotlin | Language::Java => {
                if (trimmed.starts_with("import ") || trimmed.starts_with("import\t"))
                    && trimmed.contains(module)
                {
                    return (i as u32 + 1, trimmed.to_string());
                }
                // cross-cutting-and-clear-fix-bugs-v1 (P18.B8): Scala
                // brace-list imports look like
                //   `import cats.effect.tracing.{Tracing, TracingEvent}`
                // — the literal `module` string ("cats.effect.tracing.Tracing")
                // is NOT a substring. The pre-fix code fell through to
                // the (1, "import {module}") synthetic fallback, so all
                // brace-imported symbols pinned to line 1. Recognise the
                // pattern: when the trimmed line is an `import` statement
                // whose prefix matches the module's qualifier and whose
                // brace-list contains the module's last segment, return
                // the actual line number.
                if matches!(language, Language::Scala)
                    && (trimmed.starts_with("import ") || trimmed.starts_with("import\t"))
                {
                    if let Some(last_dot) = module.rfind('.') {
                        let prefix = &module[..last_dot];
                        let last_seg = &module[last_dot + 1..];
                        // Single-line brace: `import a.b.{X, Y}`
                        if trimmed.contains(prefix) && trimmed.contains('{') {
                            // Multi-line brace: line ends with `{` but no `}` —
                            // accumulate until matching `}`.
                            let has_close = trimmed.contains('}');
                            let inside_text: String = if has_close {
                                let brace_open = trimmed.find('{').unwrap_or(0);
                                let after = &trimmed[brace_open + 1..];
                                let inside_end = after.find('}').unwrap_or(after.len());
                                after[..inside_end].to_string()
                            } else {
                                let mut acc = String::new();
                                let brace_open = trimmed.find('{').unwrap_or(0);
                                acc.push_str(&trimmed[brace_open + 1..]);
                                acc.push(' ');
                                let mut k = i + 1;
                                while k < lines.len() {
                                    let l = lines[k].trim();
                                    if let Some(close) = l.find('}') {
                                        acc.push_str(&l[..close]);
                                        break;
                                    }
                                    acc.push_str(l);
                                    acc.push(' ');
                                    k += 1;
                                }
                                acc
                            };
                            for raw_sym in inside_text.split(',') {
                                let raw = raw_sym.trim();
                                // Handle rename: `X => Y` — keep lhs.
                                let lhs = raw.split("=>").next().unwrap_or(raw).trim();
                                if lhs == last_seg {
                                    return (i as u32 + 1, trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Language::Rust => {
                if (trimmed.starts_with("use ") || trimmed.starts_with("pub use "))
                    && trimmed.contains(module)
                {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            // ux-cluster-v1 (v0.4.2 VAL-UX-D5): Swift previously fell
            // through to the catch-all `_` arm below, which accepted
            // ANY line containing the module substring. In Swift code
            // where an `import` lives inside `#if <cond> … #else …
            // #endif` blocks (or simply preceded by `#if false //
            // ModuleName is not a thing yet`), the first matching
            // line was the preprocessor directive itself — not the
            // actual `import` line. Require the line to look like a
            // real Swift import line and never accept preprocessor
            // directives. Recognised import-line shapes:
            //   `import Foundation`
            //   `import struct Foo.Bar`
            //   `@testable import Foo`
            //   `@_spi(Testing) import Foo`
            //   `@_implementationOnly import Foo`
            //   `public import Foo` (Swift 5.9+ access modifier)
            Language::Swift => {
                // Reject preprocessor conditionals up front.
                if trimmed.starts_with("#if")
                    || trimmed.starts_with("#else")
                    || trimmed.starts_with("#elseif")
                    || trimmed.starts_with("#endif")
                {
                    continue;
                }
                // Must contain the module name AND be an import line.
                if !trimmed.contains(module) {
                    continue;
                }
                // Strip leading `@…` attribute clusters and any
                // `public ` / `internal ` / `private ` / `fileprivate `
                // access modifiers, then verify the remaining text
                // begins with the `import` keyword.
                let mut rest = trimmed;
                while rest.starts_with('@') {
                    // Skip the attribute (including any parenthesised
                    // argument) up to the next whitespace.
                    if let Some(paren_open) = rest.find('(') {
                        if let Some(paren_close) = rest[paren_open..].find(')') {
                            rest = rest[paren_open + paren_close + 1..].trim_start();
                            continue;
                        }
                    }
                    if let Some(space) = rest.find(char::is_whitespace) {
                        rest = rest[space..].trim_start();
                    } else {
                        rest = "";
                        break;
                    }
                }
                for modifier in ["public ", "internal ", "private ", "fileprivate "] {
                    if let Some(stripped) = rest.strip_prefix(modifier) {
                        rest = stripped.trim_start();
                    }
                }
                if rest.starts_with("import ") || rest.starts_with("import\t") {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
            _ => {
                if trimmed.contains(module) {
                    return (i as u32 + 1, trimmed.to_string());
                }
            }
        }
    }

    // Fallback
    (1, format!("import {}", module))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_matches_python() {
        // Exact match
        assert!(module_matches(
            "services.auth",
            "services.auth",
            Language::Python
        ));

        // Submodule match
        assert!(module_matches(
            "services.auth",
            "services",
            Language::Python
        ));

        // No match
        assert!(!module_matches("utils", "services", Language::Python));

        // Relative import
        assert!(module_matches(".auth", "auth", Language::Python));
    }

    #[test]
    fn test_module_matches_typescript() {
        assert!(module_matches("./utils", "./utils", Language::TypeScript));
        assert!(module_matches("./utils", "utils", Language::TypeScript));
        assert!(module_matches("utils", "./utils", Language::TypeScript));
    }

    #[test]
    fn test_find_import_line() {
        let lines = vec![
            "\"\"\"Module docstring\"\"\"",
            "",
            "from typing import List",
            "from services.auth import authenticate",
            "",
            "def main():",
            "    pass",
        ];

        let (line, stmt) = find_import_line(&lines, "services.auth", true, Language::Python);
        assert_eq!(line, 4);
        assert!(stmt.contains("services.auth"));
    }

    // =========================================================================
    // importers-granularity-and-named-symbol-v1 (v0.5.0 T1 AUDIT-FIX)
    // =========================================================================

    use tempfile::TempDir;

    fn write_at(root: &std::path::Path, rel: &str, content: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    /// python-importers-submodule-granularity-v1: a query for the more-specific
    /// submodule `flask.helpers` must NOT return files that only import the
    /// parent package (`from flask import Flask`). RED before fix: the
    /// reverse-prefix rule matched `flask` for a `flask.helpers` query.
    #[test]
    fn test_python_importers_submodule_query_excludes_parent_only_importers() {
        // import_module = "flask" (from `from flask import Flask`)
        // target        = "flask.helpers"
        // Must NOT match: importing the parent package is not importing the
        // specific submodule.
        assert!(
            !module_matches("flask", "flask.helpers", Language::Python),
            "querying a submodule must not match a parent-package import"
        );

        // A file that imports flask.helpers directly DOES match the query.
        assert!(
            module_matches("flask.helpers", "flask.helpers", Language::Python),
            "exact submodule import must match"
        );
        // And `from flask.helpers import url_for` (module captured as
        // flask.helpers) matches too.
        assert!(
            module_matches("flask.helpers.deep", "flask.helpers", Language::Python),
            "deeper submodule of the queried one should still match"
        );
    }

    /// Regression guard: the FORWARD submodule rule (query a PARENT package,
    /// match a specific import) must still work — querying `services` returns
    /// files importing `services.auth`. This is the intended behavior and must
    /// not be broken by the granularity fix above.
    #[test]
    fn test_python_importers_parent_query_still_matches_submodule_imports() {
        assert!(
            module_matches("services.auth", "services", Language::Python),
            "parent-package query must still match submodule imports"
        );
    }

    /// solidity-importers-named-symbol-v1: `tldr importers ERC20` over a repo
    /// whose files do `import {ERC20} from "../tokens/ERC20.sol"` must find
    /// those files. RED before fix: importers only matched `names` for Python
    /// `is_from`, so the named Solidity symbol was ignored and the path
    /// (`../tokens/ERC20.sol`) did not match the bare query `ERC20`.
    #[test]
    fn test_solidity_importers_named_symbol() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(
            root,
            "src/tokens/ERC20.sol",
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract ERC20 {}\n",
        );
        write_at(
            root,
            "src/utils/SafeTransferLib.sol",
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\nimport {ERC20} from \"../tokens/ERC20.sol\";\ncontract SafeTransferLib {}\n",
        );

        let report = find_importers(root, "ERC20", Language::Solidity).unwrap();
        assert!(
            report.total >= 1,
            "named-symbol import of ERC20 not found: total={}",
            report.total
        );
        assert!(
            report
                .importers
                .iter()
                .any(|i| i.file.ends_with("SafeTransferLib.sol")),
            "expected SafeTransferLib.sol among importers: {:?}",
            report.importers
        );
    }

    // =========================================================================
    // R7 cluster[10] deps-graph fixes (v0.5.0 CLOSEOUT)
    // =========================================================================

    /// RC4 (#34): importers reverse-prefix over-attribution for dotted-FQN
    /// langs. A query for a CHILD sub-namespace `A.B.C` must NOT match a file
    /// that imports the PARENT namespace `A.B`. `using Newtonsoft.Json.Bson;`
    /// must not be returned for `importers Newtonsoft.Json.Bson.Utilities`.
    /// RED before fix: the `target.starts_with("{import_module}.")` reverse
    /// rule matched the parent import. Mirrors the Python fix.
    #[test]
    fn test_csharp_importers_child_query_excludes_parent_namespace_import() {
        for lang in [
            Language::CSharp,
            Language::Java,
            Language::Scala,
            Language::Kotlin,
        ] {
            // import_module = parent namespace; target = deeper child.
            assert!(
                !module_matches("Newtonsoft.Json.Bson", "Newtonsoft.Json.Bson.Utilities", lang),
                "{lang:?}: a child-namespace query must NOT match a parent-namespace import"
            );
            // Exact + forward-prefix + last-segment must still hold.
            assert!(
                module_matches(
                    "Newtonsoft.Json.Bson.Utilities",
                    "Newtonsoft.Json.Bson.Utilities",
                    lang
                ),
                "{lang:?}: exact import must match"
            );
            assert!(
                module_matches("Newtonsoft.Json.Bson.Utilities", "Newtonsoft.Json.Bson", lang),
                "{lang:?}: parent-package query must still match a deeper import (forward)"
            );
            assert!(
                module_matches("Newtonsoft.Json.Bson.Utilities", "Utilities", lang),
                "{lang:?}: bare last-segment query must still match"
            );
        }
    }

    /// RC5 (#242): TS/JS relative-specifier under-resolution. A query for
    /// `./scanner` must match a file that imports the SAME target file via a
    /// different relative spelling `../../scanner`. RED before fix: the TS arm
    /// did only exact + `./`-trim and never canonicalized relative paths.
    #[test]
    fn test_typescript_importers_relative_specifier_canonicalization() {
        for lang in [Language::TypeScript, Language::JavaScript] {
            // Same leaf file, different relative depth.
            assert!(
                module_matches("../../scanner", "./scanner", lang),
                "{lang:?}: ../../scanner and ./scanner refer to the same leaf and must match"
            );
            assert!(
                module_matches("../scanner", "scanner", lang),
                "{lang:?}: bare-leaf query must match a relative import of that leaf"
            );
            // A trailing extension on one side should not block the match.
            assert!(
                module_matches("../../scanner.ts", "./scanner", lang),
                "{lang:?}: extension on import side must still match a bare query"
            );
            // Two DIFFERENT leaf files must NOT match (no over-match).
            assert!(
                !module_matches("../../other", "./scanner", lang),
                "{lang:?}: different leaf files must not match"
            );
        }
    }

    /// lua-importers-require-symbol-v1: `tldr importers Type` over a Luau repo
    /// whose files do `local Type = require(script.Parent.Type)` must find
    /// those files (guards the require-path reconstruction path stays wired).
    #[test]
    fn test_luau_importers_require_module() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_at(root, "src/Type.luau", "local Type = {}\nreturn Type\n");
        write_at(
            root,
            "src/createElement.luau",
            "local Type = require(script.Parent.Type)\nreturn function() return Type end\n",
        );

        let report = find_importers(root, "Type", Language::Luau).unwrap();
        assert!(
            report.total >= 1,
            "require(script.Parent.Type) importer not found: total={}",
            report.total
        );
    }

    /// RC1 (#28): C++ `.h` headers must participate in the importers walk so a
    /// query for `widget.h` finds a `.h` file that `#include`s it. RED before
    /// fix: `find_importers` used `language.extensions()` (no `.h` for Cpp), so
    /// header-only importers (e.g. `scan.h` including `format-inl.h`) were
    /// invisible.
    #[test]
    fn test_cpp_importers_includes_header_files() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // A C++ translation unit and TWO headers — one of which is included
        // only by the other header (header-to-header include).
        write_at(root, "src/widget.cpp", "#include \"widget.h\"\nint w() { return 1; }\n");
        write_at(root, "src/widget.h", "#pragma once\nint w();\n");
        write_at(
            root,
            "src/scan.h",
            "#pragma once\n#include \"widget.h\"\nint s();\n",
        );

        let report = find_importers(root, "widget.h", Language::Cpp).unwrap();
        // Both widget.cpp and scan.h include widget.h.
        assert!(
            report
                .importers
                .iter()
                .any(|i| i.file.ends_with("scan.h")),
            "header-to-header include scan.h->widget.h must be found: {:?}",
            report.importers
        );
        assert!(
            report.total >= 2,
            "expected >=2 importers of widget.h (widget.cpp + scan.h), got {}",
            report.total
        );
    }
}
