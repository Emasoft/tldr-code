//! dotfiles-v1 — `.env`-family and ignore-file semantics, end to end.
//!
//! `.env` files and `.gitignore`-family files are plain text with NO
//! tree-sitter grammar worth running — their structure IS the line. Before
//! this batch they were invisible or mislabeled:
//!
//! - `.env` is extensionless → sniffed Text, but the TOC scanner's heading
//!   rules are meaningless for `KEY=value` lines (a lone `DATABASE_URL=…`
//!   emits nothing; an ALL-CAPS VALUE line emits a fake heading).
//! - `.gitignore` ditto: glob patterns are not heading-shaped prose.
//!
//! Now `ast::dotfiles` owns their structure: `parse_env_file` emits
//! `kind: "env"` per non-comment `KEY=` line (optional `export ` prefix
//! stripped, name = KEY, signature = the value truncated to 80 chars) and
//! `parse_ignore_file` emits `kind: "pattern"` per non-comment non-empty
//! line (name = the pattern text, signature empty). The extractor's Text
//! early-return routes them there BEFORE the TOC scan.
//!
//! Pinned here through the CLI, one probe per surface:
//!
//! 1. `tldr structure <root>/.env` — `env` kinds with KEY names, values as
//!    signatures, comments/blanks/prose inert; `dev.env` (suffix family) and
//!    `.env.local` (prefix family) behave identically.
//! 2. `tldr imports <root>/.env` — Text resolution + the Text path scanner:
//!    path-shaped VALUES surface as reference edges (the scanner is owned by
//!    `ast::doclinks` and deliberately NOT duplicated by the dotfiles
//!    module — this pins the wiring, not the scanner).
//! 3. `tldr structure <root>/.gitignore` — `pattern` kinds named by the
//!    pattern text, comments/blanks inert.
//! 4. `.bashrc` regression — a SHEBANG `.bashrc` still resolves to Bash
//!    (sniff ladder outranks the file-name checks: the dotfiles dispatch
//!    only runs inside the Text branch) and keeps its `source` edge.
//!
//! No daemon is started; every command takes the direct-compute path.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;

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

fn parse(stdout: &[u8]) -> Value {
    serde_json::from_slice(stdout).expect("valid JSON on stdout")
}

/// Run a JSON command and return the parsed envelope.
fn run_json(args: &[&str]) -> Value {
    let output = tldr_cmd()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run tldr {args:?}: {e}"));
    assert_eq!(
        output.status.code(),
        Some(0),
        "tldr {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse(&output.stdout)
}

fn defs_of(json: &Value) -> Vec<(String, String, String)> {
    json["files"][0]["definitions"]
        .as_array()
        .expect("definitions array")
        .iter()
        .map(|d| {
            (
                d["kind"].as_str().unwrap_or_default().to_string(),
                d["name"].as_str().unwrap_or_default().to_string(),
                d["signature"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

// =============================================================================
// (1) .env — kind "env" per KEY= line, value in the signature
// =============================================================================

#[test]
fn structure_on_env_file_reports_env_definitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        root.join(".env"),
        concat!(
            "# database\n",
            "DATABASE_URL=postgres://localhost/app\n",
            "\n",
            "PORT=8080\n",
            "export EDITOR=vim\n",
            "THIS LINE HAS NO EQUALS\n",
            "SPACED KEY=ignored\n",
        ),
    );

    let json = run_json(&[
        "structure",
        root.join(".env").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);

    assert_eq!(
        json["language"], "text",
        "an extensionless .env file sniffs to Text: {json}"
    );
    let defs = defs_of(&json);
    assert_eq!(
        defs,
        vec![
            (
                "env".to_string(),
                "DATABASE_URL".to_string(),
                "postgres://localhost/app".to_string()
            ),
            ("env".to_string(), "PORT".to_string(), "8080".to_string()),
            ("env".to_string(), "EDITOR".to_string(), "vim".to_string()),
        ],
        "comments/blanks stay inert, `export ` strips, prose lines never emit: {defs:?}"
    );
}

/// The two non-`.env` spellings of the env family: the `.env.` PREFIX family
/// and the `*.env` SUFFIX family.
#[test]
fn env_family_prefix_and_suffix_files_get_env_definitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root.join(".env.local"), "LOCAL_FLAG=1\n");
    write(root.join("dev.env"), "DEV_FLAG=2\n");

    let local = run_json(&[
        "structure",
        root.join(".env.local").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(
        defs_of(&local),
        vec![("env".to_string(), "LOCAL_FLAG".to_string(), "1".to_string())],
        ".env.local (prefix family): {local}"
    );

    let dev = run_json(&[
        "structure",
        root.join("dev.env").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(
        defs_of(&dev),
        vec![("env".to_string(), "DEV_FLAG".to_string(), "2".to_string())],
        "dev.env (suffix family): {dev}"
    );
}

// =============================================================================
// (2) .env imports — Text resolution + the path scanner's value edges
// =============================================================================

#[test]
fn imports_on_env_file_resolves_text_and_surfaces_path_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        root.join(".env"),
        concat!(
            "CONFIG_PATH=config/settings.yml\n",
            "API_KEY=supersecretvalue\n",
        ),
    );

    let json = run_json(&[
        "imports",
        root.join(".env").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);

    assert_eq!(
        json["language"], "text",
        "the env file resolves through the Text branch: {json}"
    );
    let imports = json["imports"].as_array().unwrap();
    assert!(
        imports.iter().any(|i| i["module"]
            .as_str()
            .is_some_and(|m| m.contains("config/settings.yml"))),
        "the path-shaped VALUE must surface as a reference edge \
         (the doclinks scanner owns this surface): {imports:?}"
    );
    assert!(
        !imports.iter().any(|i| i["module"]
            .as_str()
            .is_some_and(|m| m.contains("supersecretvalue"))),
        "a bare-word value is not a path and never emits: {imports:?}"
    );
}

// =============================================================================
// (3) .gitignore — kind "pattern" per non-comment line
// =============================================================================

#[test]
fn structure_on_gitignore_reports_pattern_definitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        root.join(".gitignore"),
        concat!(
            "# build output\n",
            "target/\n",
            "*.log\n",
            "\n",
            "!keep/this\n",
            "  node_modules/  \n",
        ),
    );

    let json = run_json(&[
        "structure",
        root.join(".gitignore").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);

    assert_eq!(
        json["language"], "text",
        "an extensionless .gitignore sniffs to Text: {json}"
    );
    let defs = defs_of(&json);
    assert_eq!(
        defs,
        vec![
            ("pattern".to_string(), "target/".to_string(), String::new()),
            ("pattern".to_string(), "*.log".to_string(), String::new()),
            (
                "pattern".to_string(),
                "!keep/this".to_string(),
                String::new()
            ),
            (
                "pattern".to_string(),
                "node_modules/".to_string(),
                String::new()
            ),
        ],
        "comments/blanks inert; the pattern text IS the name (trimmed); signature empty: {defs:?}"
    );
}

/// The closed ignore set: `.dockerignore` behaves identically; a non-member
/// (`rates.txt`, plain prose text) keeps the TOC heuristic.
#[test]
fn ignore_family_members_get_patterns_while_other_text_keeps_toc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root.join(".dockerignore"), "Dockerfile\n*.tmp\n");
    write(root.join("rates.txt"), "IMPORTANT RATES\n\nplain prose\n");

    let docker = run_json(&[
        "structure",
        root.join(".dockerignore").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);
    let docker_defs = defs_of(&docker);
    assert_eq!(
        docker_defs,
        vec![
            (
                "pattern".to_string(),
                "Dockerfile".to_string(),
                String::new()
            ),
            ("pattern".to_string(), "*.tmp".to_string(), String::new()),
        ],
        ".dockerignore is a closed-set member: {docker_defs:?}"
    );

    let rates = run_json(&[
        "structure",
        root.join("rates.txt").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);
    let rates_defs = defs_of(&rates);
    assert!(
        rates_defs
            .iter()
            .any(|(kind, name, _)| kind == "heading" && name == "IMPORTANT RATES"),
        "a non-member text file keeps the TOC heuristic: {rates_defs:?}"
    );
    assert!(
        rates_defs.iter().all(|(kind, ..)| kind != "pattern"),
        "rates.txt is NOT an ignore file: {rates_defs:?}"
    );
}

// =============================================================================
// (4) .bashrc regression — the sniff ladder outranks the file-name checks
// =============================================================================

/// A shebang `.bashrc` resolves to BASH (not env/dotfile dispatch — the
/// dotfiles scanners only run inside the Text branch) and keeps its `source`
/// import edge. The `.bashrc` name contains neither an env nor an ignore
/// marker, but this pins the dispatch ORDER: content sniffing decides before
/// any text-path special casing.
#[test]
fn bashrc_with_shebang_still_resolves_bash_with_source_edge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root.join(".bashrc"), "#!/bin/bash\nsource ./lib/env.sh\n");

    let json = run_json(&[
        "imports",
        root.join(".bashrc").to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);

    assert_eq!(
        json["language"], "bash",
        "shebang sniffing must resolve .bashrc to Bash: {json}"
    );
    let imports = json["imports"].as_array().unwrap();
    assert!(
        imports
            .iter()
            .any(|i| i["module"] == "./lib/env.sh" && i["alias"] == "source"),
        "the `source` edge must survive: {imports:?}"
    );
}
