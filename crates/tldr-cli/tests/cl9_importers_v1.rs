//! cl9-importers-v1: `module_matches` exact-match fallback fix (GH #79, v0.5.0 CL-9).
//!
//! Pre-fix, `module_matches` in `crates/tldr-core/src/analysis/importers.rs`
//! routed PHP, Ruby, Solidity and Lua/Luau through the catch-all `_ =>`
//! arm, which did a literal `import_module == target` string comparison.
//! That meant a user query for a *basename* (or a relative/sloppy spelling
//! of an import path) returned zero importers even when the project is
//! littered with imports of that module:
//!
//!   * **PHP** — `use Symfony\Component\Console\Command\Command;` was only
//!     matchable by the full FQ namespace. A query for the class basename
//!     `Command` returned 0 importers (the FQ string never equals `Command`).
//!
//!   * **Solidity** — `import {Context} from "../utils/Context.sol";`
//!     captures the literal relative path `../utils/Context.sol` as the
//!     module. A query for the file basename `Context.sol` returned 0.
//!
//!   * **Ruby** — `require_relative 'rubocop/server'` (and other path
//!     spellings ending in `/server`) captures the full path. A query for
//!     the basename `server` returned 0.
//!
//! Fix shape: AST-anchored extractors already populate `ImportInfo.module`
//! with the language-native spelling (PHP FQ namespace, Solidity path,
//! Ruby require path). The fix adds per-language arms to `module_matches`
//! that normalise the captured module + target so a basename / relative /
//! suffix query resolves — mirroring the path-resolution conventions
//! already used by the `deps` resolver (`index_php_module`,
//! `index_ruby_module`, `index_solidity_module`, `index_lua_module`).
//!
//! These tests run against the real corpora under `/tmp/tldr_corpora` and
//! compute the ground-truth importer set independently (by walking the
//! corpus the same way the AST extractor would), so the assertions stay
//! exact even if the pinned corpus is refreshed.

use assert_cmd::Command;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Run `tldr importers <module> <path> --lang <lang> -q -f json` and return
/// the parsed JSON envelope. Returns `None` if the corpus directory does not
/// exist (so the suite degrades to a skip rather than a hard failure on a
/// machine without the corpora checked out).
fn run_importers(module: &str, path: &Path, lang: &str) -> Option<Value> {
    if !path.exists() {
        eprintln!("SKIP: corpus {} not present", path.display());
        return None;
    }
    let out = Command::cargo_bin("tldr")
        .expect("tldr binary")
        .args([
            "importers",
            module,
            path.to_str().unwrap(),
            "--lang",
            lang,
            // `-m 0` = unlimited. The default `--limit 50` truncates the
            // importer list to the first 50 files, which would make the
            // ground-truth equality assertions below flaky on a corpus with
            // more than 50 importers (symfony-console has 93 `\Command`
            // importers). We want the complete set.
            "-m",
            "0",
            "-q",
            "-f",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    Some(serde_json::from_slice(&out).expect("importers output is JSON"))
}

/// Collect the set of files (canonicalised) reported as importers.
fn importer_files(v: &Value) -> BTreeSet<PathBuf> {
    v["importers"]
        .as_array()
        .expect("importers array")
        .iter()
        .map(|imp| {
            let f = imp["file"].as_str().expect("file is string");
            std::fs::canonicalize(f).unwrap_or_else(|_| PathBuf::from(f))
        })
        .collect()
}

/// Walk `root` for files with `ext`, returning every file whose text contains
/// at least one line matched by `pred` applied to the import-path string the
/// AST extractor would capture. `extract` pulls the raw import-path strings
/// out of a file's text (mirroring what the per-language extractor captures);
/// `pred` decides whether a captured path matches the basename query.
fn ground_truth<E, P>(root: &Path, ext: &str, extract: E, pred: P) -> BTreeSet<PathBuf>
where
    E: Fn(&str) -> Vec<String>,
    P: Fn(&str) -> bool,
{
    let mut out = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some(ext) {
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    if extract(&txt).iter().any(|m| pred(m)) {
                        out.insert(std::fs::canonicalize(&p).unwrap_or(p));
                    }
                }
            }
        }
    }
    out
}

fn corpus(name: &str) -> PathBuf {
    PathBuf::from("/tmp/tldr_corpora").join(name)
}

/// Basename of a `/`-separated path.
fn slash_base(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Basename of a `\`-separated PHP namespace.
fn backslash_base(s: &str) -> &str {
    s.trim_start_matches('\\').rsplit('\\').next().unwrap_or(s)
}

// =============================================================================
// PHP: FQ namespace basename query (use App\Foo\Command  → query "Command")
// =============================================================================
#[test]
fn php_fq_namespace_basename_matches() {
    let root = corpus("php-symfony-console");
    let Some(v) = run_importers("Command", &root, "php") else {
        return;
    };
    let got = importer_files(&v);

    // Ground truth: any `use ...\Command;` (basename == Command) where the
    // module is a multi-segment FQ namespace.
    let expected = ground_truth(
        &root,
        "php",
        |txt| {
            let mut mods = Vec::new();
            for line in txt.lines() {
                let t = line.trim();
                let rest = t
                    .strip_prefix("use function ")
                    .or_else(|| t.strip_prefix("use const "))
                    .or_else(|| t.strip_prefix("use "));
                let Some(rest) = rest else { continue };
                let Some(clause) = rest.split(';').next() else {
                    continue;
                };
                // Skip grouped imports `App\{A, B}` — the simple count below
                // only needs single-clause `use` lines to be a strong test.
                if clause.contains('{') {
                    continue;
                }
                // strip alias
                let module = clause
                    .split(" as ")
                    .next()
                    .unwrap_or(clause)
                    .trim()
                    .to_string();
                mods.push(module);
            }
            mods
        },
        |module| backslash_base(module) == "Command" && module.contains('\\'),
    );

    assert!(
        !expected.is_empty(),
        "ground-truth sanity: symfony-console should have many `use ...\\Command;` files"
    );
    assert_eq!(
        got, expected,
        "PHP basename query `Command` should report exactly the files importing \
         a FQ namespace ending in `\\Command`. got {} files, expected {}.",
        got.len(),
        expected.len()
    );
}

// =============================================================================
// Solidity: relative-path import, basename query (import "../utils/Context.sol"
//           → query "Context.sol")
// =============================================================================
#[test]
fn solidity_relative_import_basename_matches() {
    let root = corpus("solidity-openzeppelin");
    let Some(v) = run_importers("Context.sol", &root, "solidity") else {
        return;
    };
    let got = importer_files(&v);

    let expected = ground_truth(
        &root,
        "sol",
        |txt| {
            // Pull the quoted source path out of each `import ... "<path>";`.
            let mut mods = Vec::new();
            for line in txt.lines() {
                let t = line.trim();
                if !t.starts_with("import") {
                    continue;
                }
                // The path is the first double-quoted string on the line.
                if let Some(start) = t.find('"') {
                    if let Some(end) = t[start + 1..].find('"') {
                        mods.push(t[start + 1..start + 1 + end].to_string());
                    }
                }
            }
            mods
        },
        |module| slash_base(module) == "Context.sol",
    );

    assert!(
        !expected.is_empty(),
        "ground-truth sanity: openzeppelin should import Context.sol in many files"
    );
    assert_eq!(
        got, expected,
        "Solidity basename query `Context.sol` should report exactly the files \
         whose relative import path ends in `/Context.sol`. got {} files, expected {}.",
        got.len(),
        expected.len()
    );
}

// =============================================================================
// Ruby: require_relative path, basename query (require_relative 'rubocop/server'
//        and other `.../server` spellings → query "server")
// =============================================================================
#[test]
fn ruby_require_relative_basename_matches() {
    let root = corpus("ruby-rubocop");
    let Some(v) = run_importers("server", &root, "ruby") else {
        return;
    };
    let got = importer_files(&v);

    let expected = ground_truth(
        &root,
        "rb",
        |txt| {
            let mut mods = Vec::new();
            for line in txt.lines() {
                let t = line.trim();
                let rest = t
                    .strip_prefix("require_relative ")
                    .or_else(|| t.strip_prefix("require "));
                let Some(rest) = rest else { continue };
                // The path is the first single- or double-quoted string.
                let rest = rest.trim();
                let (q, body) = if let Some(b) = rest.strip_prefix('\'') {
                    ('\'', b)
                } else if let Some(b) = rest.strip_prefix('"') {
                    ('"', b)
                } else {
                    continue;
                };
                if let Some(end) = body.find(q) {
                    mods.push(body[..end].to_string());
                }
            }
            mods
        },
        // basename == "server" AND the module is a multi-segment path (so the
        // basename rule, not exact match, is what resolves it).
        |module| slash_base(module) == "server" && module.contains('/'),
    );

    assert!(
        !expected.is_empty(),
        "ground-truth sanity: rubocop should `require_relative '.../server'` in several files"
    );
    assert_eq!(
        got, expected,
        "Ruby basename query `server` should report exactly the files whose \
         require path ends in `/server`. got {} files, expected {}.",
        got.len(),
        expected.len()
    );
}

// =============================================================================
// Regression guard: a basename query must NOT collapse onto exact-match
// semantics. Querying the exact FQ / full path must STILL work.
// =============================================================================
#[test]
fn php_exact_fq_query_still_matches() {
    let root = corpus("php-symfony-console");
    let Some(v) = run_importers("Symfony\\Component\\Console\\Command\\Command", &root, "php")
    else {
        return;
    };
    let got = importer_files(&v);
    assert!(
        !got.is_empty(),
        "exact FQ query must keep working after the basename rule is added"
    );
}
