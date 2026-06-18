//! Regression tests for CL-8 (gaps IT3-go-01, IT3-java-01).
//!
//! The Go and Java surface extractors previously derived the package /
//! module path from the *directory basename* of the resolved target rather
//! than the AST `package_clause` (Go) / `package_declaration` (Java) node.
//!
//! Symptoms on the real corpora:
//!   - go-httprouter  -> package "go-httprouter", APIs "go-httprouter.CleanPath"
//!     (the on-disk directory is `go-httprouter`, but the AST package is
//!     `package httprouter`).
//!   - java-petclinic -> module "java-petclinic.org.springframework..."
//!     (the directory basename `java-petclinic` was unconditionally prefixed
//!     onto the real `package org.springframework.samples.petclinic;` decl,
//!     producing a bogus dotted path; for a default-package file the resolver
//!     could even concat a literal "." segment).
//!
//! These tests assert the package / module now comes from the AST package
//! declaration node. They use synthetic temp-dir fixtures (so the suite is
//! hermetic) plus, when present, the real iter-3b corpora.

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


use std::fs;
use std::path::Path;

use tldr_core::surface::extract_api_surface;

fn write(dir: &Path, rel: &str, source: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, source).unwrap();
}

// ---------------------------------------------------------------------------
// Go: package must come from `package_clause`, not the directory basename.
// ---------------------------------------------------------------------------

#[test]
fn go_package_from_ast_clause_not_dir_basename() {
    let tmp = tempfile::TempDir::new().unwrap();
    // Directory basename intentionally differs from the AST package name.
    let pkg_dir = tmp.path().join("go-httprouter");
    write(
        &pkg_dir,
        "router.go",
        "package httprouter\n\nfunc CleanPath(p string) string { return p }\n",
    );

    let surface =
        extract_api_surface(pkg_dir.to_str().unwrap(), Some("go"), false, None, None).unwrap();

    // Package field reflects the AST `package httprouter` clause.
    assert_eq!(
        surface.package, "httprouter",
        "Go surface.package must come from package_clause, got {:?}",
        surface.package
    );

    let clean = surface
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with("CleanPath"))
        .expect("CleanPath should be in the surface");

    assert_eq!(
        clean.qualified_name, "httprouter.CleanPath",
        "qualified_name must use the AST package, got {:?}",
        clean.qualified_name
    );
    assert_eq!(clean.module, "httprouter");
    assert!(
        !clean.qualified_name.contains("go-httprouter"),
        "directory basename must not leak into qualified_name: {:?}",
        clean.qualified_name
    );
}

// ---------------------------------------------------------------------------
// Java: module must come from `package_declaration`, not dir basename + concat.
// ---------------------------------------------------------------------------

#[test]
fn java_module_from_ast_package_declaration() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("java-petclinic");
    write(
        &root,
        "src/main/java/org/springframework/samples/petclinic/owner/Owner.java",
        "package org.springframework.samples.petclinic.owner;\n\npublic class Owner {}\n",
    );

    let surface =
        extract_api_surface(root.to_str().unwrap(), Some("java"), false, None, None).unwrap();

    let owner = surface
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with(".Owner"))
        .expect("Owner class should be in the surface");

    assert_eq!(
        owner.module, "org.springframework.samples.petclinic.owner",
        "Java module must be exactly the AST package_declaration, got {:?}",
        owner.module
    );
    assert_eq!(
        owner.qualified_name,
        "org.springframework.samples.petclinic.owner.Owner"
    );
    assert!(
        !owner.qualified_name.contains("java-petclinic"),
        "directory basename must not be prefixed onto the package: {:?}",
        owner.qualified_name
    );
    // Guard against the unvalidated '.' concat: no doubled/leading dots.
    assert!(
        !owner.qualified_name.contains(".."),
        "qualified_name must not contain empty '.' segments: {:?}",
        owner.qualified_name
    );
}

#[test]
fn java_default_package_no_dotted_garbage() {
    // A file with NO package declaration (default package). The previous code
    // could concat a literal "." or the dir basename. The module must be a
    // clean single segment with no empty '.' fragments.
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("rootpkg");
    write(&root, "Widget.java", "public class Widget {}\n");

    let surface =
        extract_api_surface(root.to_str().unwrap(), Some("java"), false, None, None).unwrap();

    let widget = surface
        .apis
        .iter()
        .find(|a| a.qualified_name.ends_with("Widget"))
        .expect("Widget class should be in the surface");

    assert!(
        !widget.qualified_name.contains(".."),
        "default-package qualified_name must not contain empty '.' segments: {:?}",
        widget.qualified_name
    );
    assert!(
        !widget.qualified_name.starts_with('.'),
        "default-package qualified_name must not start with '.': {:?}",
        widget.qualified_name
    );
    assert_eq!(widget.qualified_name, "Widget");
}

// ---------------------------------------------------------------------------
// Real corpora (iter-3b repro). Skipped automatically when absent.
// ---------------------------------------------------------------------------

#[test]
fn go_httprouter_corpus_uses_ast_package() {
    let corpus = Path::new("/tmp/tldr_corpora/go-httprouter");
    if !corpus_ready(corpus) {
        eprintln!("skipping: {} not present", corpus.display());
        return;
    }

    let surface =
        extract_api_surface(corpus.to_str().unwrap(), Some("go"), false, None, None).unwrap();

    assert_eq!(
        surface.package, "httprouter",
        "go-httprouter corpus package must be the AST `package httprouter`, got {:?}",
        surface.package
    );
    assert!(
        surface
            .apis
            .iter()
            .all(|a| !a.qualified_name.contains("go-httprouter")),
        "no API may carry the directory basename `go-httprouter`"
    );
    assert!(
        surface
            .apis
            .iter()
            .any(|a| a.qualified_name == "httprouter.CleanPath"),
        "httprouter.CleanPath must be present with the AST package"
    );
}

#[test]
fn java_petclinic_corpus_uses_ast_package() {
    let corpus = Path::new("/tmp/tldr_corpora/java-petclinic");
    if !corpus_ready(corpus) {
        eprintln!("skipping: {} not present", corpus.display());
        return;
    }

    let surface =
        extract_api_surface(corpus.to_str().unwrap(), Some("java"), false, None, None).unwrap();

    assert!(
        surface
            .apis
            .iter()
            .all(|a| !a.qualified_name.contains("java-petclinic")),
        "no API may carry the directory basename `java-petclinic`"
    );
    assert!(
        surface.apis.iter().all(|a| !a.qualified_name.contains("..")),
        "no API qualified_name may contain empty '.' segments"
    );
    // Owner lives in package org.springframework.samples.petclinic.owner.
    assert!(
        surface.apis.iter().any(|a| a.module
            == "org.springframework.samples.petclinic.owner"
            && a.qualified_name == "org.springframework.samples.petclinic.owner.Owner"),
        "Owner must be qualified by its AST package_declaration"
    );
}
