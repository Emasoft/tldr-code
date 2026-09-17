//! references-doc-languages-v1 — `tldr references <symbol> <path> --lang
//! <doc-language>` must search doc/native files.
//!
//! Before this suite existed, `is_source_file` (tldr-core
//! `analysis/references.rs`) enumerated ONLY the 18 code languages in its
//! per-language arms: every doc/native filter (markdown, text, csv, json,
//! …) fell into the `_ => false` arm, so `--lang markdown` silently
//! searched ZERO files while the SAME query without `--lang` found the
//! matches. The filter is now enumerated across all 31 variants — a doc
//! filter accepts exactly the files DETECTED as that format — and unknown
//! filter strings stay strict (`false`), so a filter can never silently
//! degrade into "search everything".

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn tldr_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("tldr"))
}

fn write(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).expect("write fixture");
    path
}

/// The verified probe shape: two `.md` files, the word declared in one and
/// referenced in the other — `--lang markdown` must search BOTH files.
#[test]
fn lang_markdown_finds_word_across_md_files() {
    let dir = TempDir::new().expect("tempdir");
    write(&dir, "guide.md", "# Guide\n\nSee the widget below.\n");
    write(&dir, "notes.md", "The widget is referenced in guide.md.\n");

    let json = references_json(&dir, "widget", &["--lang", "markdown"]);

    assert_eq!(
        json["stats"]["files_searched"], 2,
        "--lang markdown must search the two .md files: {json}"
    );
    assert_eq!(
        json["total_references"], 2,
        "the word in prose is a 0.5-confidence reference in each file: {json}"
    );
    let files = ref_files(&json);
    assert!(
        files.contains(&"notes.md".to_string()) && files.contains(&"guide.md".to_string()),
        "references must span both .md files: {files:?}"
    );
}

/// `--lang text` searches `.txt` files.
#[test]
fn lang_text_finds_word_in_txt_files() {
    let dir = TempDir::new().expect("tempdir");
    write(
        &dir,
        "readme.txt",
        "Release notes describe the widget behavior in detail.\n",
    );

    let json = references_json(&dir, "widget", &["--lang", "text"]);

    assert_eq!(json["stats"]["files_searched"], 1, "{json}");
    assert_eq!(json["total_references"], 1, "{json}");
}

/// `--lang csv` searches `.csv` data files.
#[test]
fn lang_csv_finds_word_in_csv_files() {
    let dir = TempDir::new().expect("tempdir");
    write(&dir, "data.csv", "item,qty\nwidget,2\ngadget,5\n");

    let json = references_json(&dir, "widget", &["--lang", "csv"]);

    assert_eq!(json["stats"]["files_searched"], 1, "{json}");
    assert_eq!(json["total_references"], 1, "{json}");
}

/// The filter stays a filter: a doc language must NOT match files of
/// ANOTHER format, and unrecognized extensions stay unsearchable.
#[test]
fn lang_filter_is_strict_across_formats() {
    let dir = TempDir::new().expect("tempdir");
    write(&dir, "guide.md", "The widget ships today.\n");
    write(&dir, "readme.txt", "The widget ships today.\n");
    write(&dir, "data.csv", "item,qty\nwidget,2\n");
    write(&dir, "blob.xyz", "The widget ships today.\n");

    // markdown → only the .md file.
    let json = references_json(&dir, "widget", &["--lang", "markdown"]);
    assert_eq!(json["stats"]["files_searched"], 1, "{json}");
    let files = ref_files(&json);
    assert!(
        files.iter().all(|f| f.ends_with(".md")),
        "markdown filter must only hit .md files: {files:?}"
    );

    // text → only the .txt file.
    let json = references_json(&dir, "widget", &["--lang", "text"]);
    assert_eq!(json["stats"]["files_searched"], 1, "{json}");
    let files = ref_files(&json);
    assert!(
        files.iter().all(|f| f.ends_with(".txt")),
        "text filter must only hit .txt files: {files:?}"
    );

    // csv → only the .csv file.
    let json = references_json(&dir, "widget", &["--lang", "csv"]);
    assert_eq!(json["stats"]["files_searched"], 1, "{json}");

    // Unrecognized extension: never a source file, for any filter…
    let json = references_json(&dir, "widget", &["--lang", "markdown"]);
    let files = ref_files(&json);
    assert!(
        !files.iter().any(|f| f.ends_with(".xyz")),
        "unrecognized extensions must stay unsearchable: {files:?}"
    );

    // …and for a CODE filter too (negative control for the same predicate).
    let json = references_json(&dir, "widget", &["--lang", "python"]);
    assert_eq!(
        json["stats"]["files_searched"], 0,
        "no python files exist in this fixture: {json}"
    );
}

/// Regression control: the no-filter path already searched doc files and
/// must keep doing so (the pre-fix bug was ONLY in the filtered path).
#[test]
fn no_filter_path_still_searches_markdown() {
    let dir = TempDir::new().expect("tempdir");
    write(&dir, "guide.md", "# Guide\n\nSee the widget below.\n");
    write(&dir, "notes.md", "The widget is referenced in guide.md.\n");

    let json = references_json(&dir, "widget", &[]);

    assert_eq!(json["stats"]["files_searched"], 2, "{json}");
    assert_eq!(json["total_references"], 2, "{json}");
}

// -- harness -----------------------------------------------------------------

fn references_json(dir: &TempDir, symbol: &str, extra: &[&str]) -> Value {
    let output = tldr_cmd()
        .args([
            "references",
            symbol,
            dir.path().to_str().expect("utf-8 path"),
            "--format",
            "json",
            "--quiet",
        ])
        .args(extra)
        .output()
        .expect("run tldr references");
    assert!(
        output.status.success(),
        "tldr references {symbol} failed: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse references JSON from stdout")
}

fn ref_files(json: &Value) -> Vec<String> {
    json["references"]
        .as_array()
        .expect("references array")
        .iter()
        .map(|r| {
            Path::new(r["file"].as_str().expect("file is a string"))
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .to_string()
        })
        .collect()
}
