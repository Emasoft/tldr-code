//! cl11-implements-v1 (CL-11 / GH #82)
//!
//! Inheritance collapses `implements` into `extends` because the per-language
//! TypeScript and PHP walkers never populate `base_kinds`. With `base_kinds`
//! absent, `InheritanceNode::base_kind_at(i)` defaults every base to
//! `InheritanceKind::Extends`, so an `implements Interface` edge is reported
//! with `kind: "extends"` — the same as a real `extends SuperClass` edge.
//!
//! Fix (AST-driven): in `inheritance/typescript.rs` and `inheritance/php.rs`,
//! tag the AST clause nodes by their kind:
//!   - TS  `extends_clause`   -> InheritanceKind::Extends
//!   - TS  `implements_clause`-> InheritanceKind::Implements
//!   - PHP `base_clause`      -> InheritanceKind::Extends
//!   - PHP `class_interface_clause` -> InheritanceKind::Implements
//! and populate the parallel `base_kinds` vector so each edge carries the
//! distinct kind through to the JSON `edges[].kind` field.
//!
//! Assertions: a class that BOTH `extends` a superclass AND `implements`
//! interface(s) must produce DISTINCT edge kinds — the superclass edge is
//! `extends`, the interface edges are `implements`. Verified on synthetic
//! fixtures (precise) and on the real corpora (proves it works on real code).

/// True when `p` exists AND contains at least one non-`.git` regular file
/// (or is itself a regular file). Corpus dirs may be present as empty
/// skeletons (git clone with no working tree) where `Path::exists()` is
/// `true` but analysis sees 0 files; these tests must skip in that case.
#[allow(dead_code)]
fn corpus_ready<P: AsRef<std::path::Path>>(p: P) -> bool {
    fn walk(p: &std::path::Path, depth: usize) -> bool {
        if depth > 8 { return false; }
        let Ok(rd) = std::fs::read_dir(p) else { return false; };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") { continue; }
            match entry.file_type() {
                Ok(ft) if ft.is_file() => return true,
                Ok(ft) if ft.is_dir() => { if walk(&path, depth + 1) { return true; } }
                _ => {}
            }
        }
        false
    }
    let root = p.as_ref();
    if root.is_file() { return true; }
    root.exists() && walk(root, 0)
}


use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn run_tldr(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("tldr"));
    let output = cmd.args(args).output().expect("tldr binary missing");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn parse_json(stdout: &str) -> Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("Failed to parse JSON: {}\nstdout:\n{}", e, stdout))
}

fn edge_kind<'a>(edges: &'a [Value], child: &str, parent: &str) -> &'a str {
    edges
        .iter()
        .find(|e| e["child"] == child && e["parent"] == parent)
        .unwrap_or_else(|| panic!("missing {}->{} edge in {:#?}", child, parent, edges))["kind"]
        .as_str()
        .expect("edge kind is a string")
}

/// TypeScript: a class that `extends Base implements I1, I2` must emit one
/// `extends` edge (to Base) and two `implements` edges (to I1, I2). Before the
/// fix, all three collapse to `extends`.
#[test]
fn test_typescript_extends_and_implements_distinct_kinds() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("svc.ts"),
        r#"
class Base {}

interface OnModuleInit {
    onModuleInit(): void;
}

interface OnModuleDestroy {
    onModuleDestroy(): void;
}

class Service extends Base implements OnModuleInit, OnModuleDestroy {
    onModuleInit(): void {}
    onModuleDestroy(): void {}
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "typescript",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    assert_eq!(
        edge_kind(edges, "Service", "Base"),
        "extends",
        "extends clause must be kind=extends"
    );
    assert_eq!(
        edge_kind(edges, "Service", "OnModuleInit"),
        "implements",
        "implements clause must be kind=implements, not collapsed to extends"
    );
    assert_eq!(
        edge_kind(edges, "Service", "OnModuleDestroy"),
        "implements",
        "second implements clause must also be kind=implements"
    );
}

/// PHP: a class that `extends Base implements I1, I2` must emit one `extends`
/// edge (to Base) and two `implements` edges (to the interfaces).
#[test]
fn test_php_extends_and_implements_distinct_kinds() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("cmd.php"),
        r#"<?php
class Base {}
interface Stringable {}
interface Countable {}

class Command extends Base implements Stringable, Countable {
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "php",
        "--format",
        "json",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    assert_eq!(
        edge_kind(edges, "Command", "Base"),
        "extends",
        "base_clause must be kind=extends"
    );
    assert_eq!(
        edge_kind(edges, "Command", "Stringable"),
        "implements",
        "class_interface_clause must be kind=implements, not collapsed to extends"
    );
    assert_eq!(
        edge_kind(edges, "Command", "Countable"),
        "implements",
        "second interface must also be kind=implements"
    );
}

/// Real corpus: typescript-nest must produce at least one `implements` edge.
/// Before the fix every TS edge is `extends`, so this is 0 and fails.
#[test]
fn test_typescript_nest_corpus_has_implements_edges() {
    let corpus = Path::new("/tmp/tldr_corpora/typescript-nest");
    if !corpus_ready(&corpus) {
        eprintln!("skipping: corpus {} not present", corpus.display());
        return;
    }

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "typescript",
        "--format",
        "json",
        corpus.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed on corpus: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    let implements_count = edges.iter().filter(|e| e["kind"] == "implements").count();
    let extends_count = edges.iter().filter(|e| e["kind"] == "extends").count();
    assert!(
        implements_count > 0,
        "typescript-nest must yield implements edges (got {} implements, {} extends) — \
         interface implementations are being collapsed into extends",
        implements_count,
        extends_count
    );
}

/// Real corpus: php-symfony-console must produce at least one `implements`
/// edge. Symfony's Console component has many `class X implements Y` classes.
#[test]
fn test_php_symfony_console_corpus_has_implements_edges() {
    let corpus = Path::new("/tmp/tldr_corpora/php-symfony-console");
    if !corpus_ready(&corpus) {
        eprintln!("skipping: corpus {} not present", corpus.display());
        return;
    }

    let (code, stdout, stderr) = run_tldr(&[
        "inheritance",
        "--lang",
        "php",
        "--format",
        "json",
        corpus.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "inheritance failed on corpus: {}", stderr);

    let v = parse_json(&stdout);
    let edges = v["edges"].as_array().expect("edges array");

    let implements_count = edges.iter().filter(|e| e["kind"] == "implements").count();
    let extends_count = edges.iter().filter(|e| e["kind"] == "extends").count();
    assert!(
        implements_count > 0,
        "php-symfony-console must yield implements edges (got {} implements, {} extends) — \
         interface implementations are being collapsed into extends",
        implements_count,
        extends_count
    );
}
