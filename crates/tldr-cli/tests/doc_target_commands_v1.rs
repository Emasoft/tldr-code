//! doc-target-commands-v1 — `importers` / `whatbreaks` on FILE targets,
//! end to end.
//!
//! Pins the doc-target language-resolution and path-derivation fixes for the
//! two commands that turn a FILE-shaped target into an importers query:
//!
//! 1. **importers without `--lang`** (doc-target-importers-v1,
//!    commands/importers.rs): the module string may itself name an existing
//!    file — documents do (`tldr importers b.md <root>`). The language now
//!    resolves per-file through the shared `resolve_target_language`
//!    (doc language → doc language; code language → code language), falling
//!    back to the legacy directory autodetect (Python last resort) for module
//!    strings that are not files. Before, `Language::from_directory` skipped
//!    every doc format, a doc-only project fell through to Python, and the
//!    command silently reported `total: 0`.
//! 2. **whatbreaks File targets** (doc-target-whatbreaks-v1,
//!    analysis/whatbreaks.rs): language resolves from the TARGET file;
//!    `derive_module_name` works on the PROJECT-ROOT-RELATIVE path (absolute
//!    and relative spellings of the same file produce the SAME module string —
//!    the old code split raw absolute paths on `/` into `.tmp.…` garbage);
//!    doc languages keep the root-relative path WITH extension (`b.md`,
//!    `docs/x.md`) because documents reference each other by path; code
//!    languages keep the legacy dotted-module derivation
//!    (`src/service.py` → `src.service`). Detection also accepts doc
//!    extensions for not-yet-on-disk targets.
//! 3. **Scoped walks** (commands/whatbreaks.rs): a target that names an
//!    existing file scopes the analysis to the file's marker-based project
//!    root (`explain_project_root_marker`, the walk `explain`/`impact` use)
//!    instead of blindly walking the CWD — a file target run from a big
//!    repository walked everything (>60 s before first output).
//!
//! No daemon is started; every command takes the direct-compute path.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(p: impl AsRef<Path>, body: &str) {
    let p = p.as_ref();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(p, body).expect("write fixture");
}

/// Doc-ONLY project: `a.md` links `b.md` (line 3), no code files, no project
/// marker — `Language::from_directory` has no project-language signal here at
/// all, so any doc-target hit below can only come from per-file resolution.
fn build_doc_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(root.join("a.md"), "# A\n\n[B](b.md)\n");
    write(root.join("b.md"), "# B\n\nbody\n");
    dir
}

/// Same doc project plus a minimal `package.json` root marker so the
/// marker-based project-root walk (whatbreaks scoping) resolves to the
/// fixture root.
fn build_marked_doc_project() -> TempDir {
    let dir = build_doc_project();
    write(
        dir.path().join("package.json"),
        r#"{ "name": "fixture", "private": true }"#,
    );
    dir
}

/// Python project used for the code-language regression pins: flat
/// `service.py`, nested `src/service.py`, and `a.py` importing both —
/// the importers query for each derived module string must find it.
fn build_python_project() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    write(root.join("service.py"), "def run():\n    return 1\n");
    write(root.join("src/service.py"), "def run():\n    return 2\n");
    write(
        root.join("a.py"),
        "import service\nimport src.service\n\n\ndef main():\n    return service.run()\n",
    );
    dir
}

fn run_json(args: &[&str], cwd: &Path) -> (Option<i32>, Value) {
    let output = tldr_cmd()
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("run tldr {args:?}: {e}"));
    let code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout of {args:?} is not JSON ({e}): {stdout:?}"));
    (code, json)
}

/// The repository root (cwd for the scoping probe): `crates/tldr-cli/../..`.
fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
}

// =============================================================================
// (1) importers — doc file target, NO --lang
// =============================================================================

/// `tldr importers b.md <root>` with NO `--lang` on a doc-only project finds
/// the linker: the module string names an existing file, the language
/// resolves to Markdown per-file, and the doc path-matching arm runs. Line +
/// statement are the doclinks-v1 fields, pinned here in the no-`--lang` form.
#[test]
fn importers_doc_file_without_lang_finds_linker() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "importers",
            "b.md",
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["module"], "b.md");
    assert_eq!(json["total"], 1, "a.md links b.md: {json}");

    let importers = json["importers"].as_array().unwrap();
    assert!(importers[0]["file"].as_str().unwrap().ends_with("a.md"));
    assert_eq!(importers[0]["line"], 3, "the [B](b.md) line");
    assert!(importers[0]["import_statement"]
        .as_str()
        .unwrap()
        .contains("b.md"));
}

/// The ABSOLUTE spelling of the same doc file resolves the language from the
/// FILE (the progress banner prints the resolved language): the language is
/// Markdown, not the legacy Python fall-through. The module string itself
/// stays the user's verbatim query — the importers command is a module-string
/// query, and an absolute path is not a relative doc-link spelling, so the
/// report is an honest zero (the RELATIVE form above is the matchable
/// spelling; whatbreaks owns file-target derivation).
#[test]
fn importers_absolute_doc_file_resolves_markdown_language() {
    let dir = build_doc_project();
    let root = dir.path();
    let absolute = root.join("b.md");

    let output = tldr_cmd()
        .args([
            "importers",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "text",
        ])
        .current_dir(root)
        .output()
        .expect("run tldr importers");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("(Markdown)"),
        "language must resolve from the file, banner: {stderr}"
    );

    let (code, json) = run_json(
        &[
            "importers",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        json["module"],
        absolute.to_str().unwrap(),
        "module string verbatim"
    );
    assert_eq!(
        json["total"], 0,
        "absolute spelling is not a relative doc link: {json}"
    );
}

// =============================================================================
// (2) whatbreaks — doc file target, NO --lang
// =============================================================================

/// `tldr whatbreaks <root>/b.md <root>` with NO `--lang` reports importer
/// count 1 (a.md). Before the fix the language fell through to Python (doc
/// formats are not project-language signals) and the count was silently 0.
#[test]
fn whatbreaks_doc_file_without_lang_counts_importer() {
    let dir = build_doc_project();
    let root = dir.path();
    let target = root.join("b.md");

    let (code, json) = run_json(
        &[
            "whatbreaks",
            target.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["target_type"], "file");
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");

    let importers = &json["sub_results"]["importers"];
    assert_eq!(importers["success"], true);
    assert_eq!(
        importers["data"]["module"], "b.md",
        "doc module = root-relative path"
    );
    assert_eq!(importers["data"]["count"], 1);
    assert!(importers["data"]["importers"][0]["file"]
        .as_str()
        .unwrap()
        .ends_with("a.md"));
}

/// A RELATIVE doc target combined with an ABSOLUTE root argument works even
/// when CWD is somewhere else entirely (the repo root): the target resolves
/// against the path argument, not the process CWD.
#[test]
fn whatbreaks_relative_doc_target_with_absolute_root_works() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "whatbreaks",
            "b.md",
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        repo_root(),
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["target_type"], "file");
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");
    assert_eq!(json["sub_results"]["importers"]["data"]["module"], "b.md");
}

/// `--lang` keeps first priority in the resolution order (regression control
/// for the doclinks-v1 behavior on the whatbreaks surface).
#[test]
fn whatbreaks_doc_file_lang_override_still_wins() {
    let dir = build_doc_project();
    let root = dir.path();
    let target = root.join("b.md");

    let (code, json) = run_json(
        &[
            "whatbreaks",
            target.to_str().unwrap(),
            root.to_str().unwrap(),
            "--lang",
            "markdown",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");
}

/// A doc target that does NOT exist yet is still detected as File via its
/// doc extension (previously it fell through the `.`-check to the
/// qualified-name heuristic and became Function).
#[test]
fn whatbreaks_detects_nonexistent_doc_target_as_file() {
    let dir = build_doc_project();
    let root = dir.path();

    let (code, json) = run_json(
        &[
            "whatbreaks",
            "newdoc.md",
            root.to_str().unwrap(),
            "--quick",
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["target_type"], "file", "{json}");
    assert!(
        json["detection_reason"]
            .as_str()
            .unwrap()
            .contains("file extension"),
        "extension-based detection: {json}"
    );
}

// =============================================================================
// (3) whatbreaks — scoped walk (file target ⇒ marker-based project root)
// =============================================================================

/// A file target scopes the walk to its marker-based project root: run from
/// the (huge) repository root with the DEFAULT path argument (`.`), the
/// analysis must still bound itself to the fixture project (marker found) and
/// find a.md — the pre-fix run walked the entire CWD tree with Python and
/// reported 0 after >60 s.
#[test]
fn whatbreaks_file_target_scopes_walk_to_project_root() {
    let dir = build_marked_doc_project();
    let root = dir.path();
    let target = root.join("b.md");

    let (code, json) = run_json(
        &["whatbreaks", target.to_str().unwrap(), "-f", "json", "-q"],
        repo_root(),
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["target_type"], "file");
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");
    assert!(
        json["sub_results"]["importers"]["data"]["importers"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with("a.md")
    );

    // The report's project path IS the marker root (canonicalized).
    let reported = Path::new(json["path"].as_str().unwrap());
    assert_eq!(
        reported.canonicalize().unwrap(),
        root.canonicalize().unwrap(),
        "analysis scoped to the target's project root: {json}"
    );
}

// =============================================================================
// (4) code-language regression pins
// =============================================================================

/// whatbreaks on a CODE file, no `--lang`: the ABSOLUTE target derives the
/// same dotted module as its root-relative spelling (`service`), and the
/// importers sub-result finds a.py. The pre-fix derivation split the raw
/// absolute path on `/` into the leading-dot garbage `.tmp.…service` and
/// found nothing.
#[test]
fn whatbreaks_absolute_code_file_matches_relative_derivation() {
    let dir = build_python_project();
    let root = dir.path();
    let absolute = root.join("service.py");

    let (code, json) = run_json(
        &[
            "whatbreaks",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["target_type"], "file");
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");
    assert_eq!(
        json["sub_results"]["importers"]["data"]["module"],
        "service"
    );
    assert!(
        json["sub_results"]["importers"]["data"]["importers"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with("a.py")
    );

    // The root-relative spelling of the same file: identical derivation.
    let (_, rel_json) = run_json(
        &[
            "whatbreaks",
            "service.py",
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(
        rel_json["sub_results"]["importers"]["data"]["module"],
        "service"
    );
    assert_eq!(
        rel_json["summary"]["importer_count"],
        json["summary"]["importer_count"]
    );
}

/// Nested code file with an ABSOLUTE target, no `--lang`: module derivation
/// is the root-relative dotted path (`src.service`), unchanged from the
/// relative behavior, and the importers query still finds the dotted import.
#[test]
fn whatbreaks_nested_code_file_derives_dotted_module() {
    let dir = build_python_project();
    let root = dir.path();
    let absolute = root.join("src").join("service.py");

    let (code, json) = run_json(
        &[
            "whatbreaks",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["summary"]["importer_count"], 1, "{json}");
    assert_eq!(
        json["sub_results"]["importers"]["data"]["module"],
        "src.service"
    );
    assert!(
        json["sub_results"]["importers"]["data"]["importers"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with("a.py")
    );
}

/// importers with a module string that is NOT a file keeps the legacy
/// resolution untouched: `service` resolves through the directory autodetect
/// (Python) and finds a.py; `std::collections::HashMap` is an honest
/// zero-result, exit 0 — the language resolution must never turn a
/// non-file module string into an error or a wrong-language scan.
#[test]
fn importers_non_file_module_strings_still_legacy() {
    let dir = build_python_project();
    let root = dir.path();
    let root_arg = root.to_str().unwrap();

    let (code, json) = run_json(
        &["importers", "service", root_arg, "-f", "json", "-q"],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        json["total"], 1,
        "legacy directory autodetect (Python): {json}"
    );
    assert!(json["importers"][0]["file"]
        .as_str()
        .unwrap()
        .ends_with("a.py"));

    let (code, json) = run_json(
        &[
            "importers",
            "std::collections::HashMap",
            root_arg,
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        json["total"], 0,
        "not a file → legacy Python scan, honest zero: {json}"
    );
}

/// importers with an absolute CODE file in the module slot: the language
/// resolves per-file (Python — code language → use it, visible in the
/// progress banner; identical to the legacy directory autodetect here) and
/// the command stays a well-formed module-string query (exit 0, module string
/// preserved, honest zero). No crash, no language misresolution.
#[test]
fn importers_absolute_code_file_resolves_python_language() {
    let dir = build_python_project();
    let root = dir.path();
    let absolute = root.join("service.py");

    let output = tldr_cmd()
        .args([
            "importers",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "text",
        ])
        .current_dir(root)
        .output()
        .expect("run tldr importers");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("(Python)"),
        "code language from the file, banner: {stderr}"
    );

    let (code, json) = run_json(
        &[
            "importers",
            absolute.to_str().unwrap(),
            root.to_str().unwrap(),
            "-f",
            "json",
            "-q",
        ],
        root,
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["module"], absolute.to_str().unwrap(), "{json}");
    assert_eq!(json["total"], 0);
}
