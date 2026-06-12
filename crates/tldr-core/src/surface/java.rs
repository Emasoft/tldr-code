//! Java-specific API surface extraction.
//!
//! Java surfaces only `public` declarations by default. When `include_private`
//! is set, package-private, protected, and private members are also returned.

use std::path::{Path, PathBuf};

use tree_sitter::{Node, Tree};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::{ClassInfo, Language};
use crate::TldrResult;

use super::language_profile::strip_layout_segments;
use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public Java API surface for a resolved package.
pub fn extract_java_api_surface(
    resolved: &ResolvedPackage,
    include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();

    for file_path in find_java_files(&resolved.root_dir) {
        apis.extend(extract_from_java_file(
            &file_path,
            &resolved.root_dir,
            &resolved.package_name,
            include_private,
        )?);
    }

    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: resolved.package_name.clone(),
        language: "java".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

fn find_java_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return dir
            .extension()
            .and_then(|ext| ext.to_str())
            .filter(|ext| *ext == "java")
            .map(|_| vec![dir.to_path_buf()])
            .unwrap_or_default();
    }

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        files.extend(find_java_files(&path));
                    }
                }
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("java") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn extract_from_java_file(
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
    include_private: bool,
) -> TldrResult<Vec<ApiEntry>> {
    let source = std::fs::read_to_string(file_path).map_err(|e| {
        crate::error::TldrError::parse_error(
            file_path.to_path_buf(),
            None,
            format!("Cannot read: {}", e),
        )
    })?;

    let tree = parse(&source, Language::Java)?;
    let module_info = extract_from_tree(&tree, &source, Language::Java, file_path, Some(root_dir))?;
    let module_path = compute_java_module_path(&tree, &source, file_path, root_dir, package_name);
    let relative_path = file_path
        .strip_prefix(root_dir)
        .unwrap_or(file_path)
        .to_path_buf();

    let mut apis = Vec::new();

    for class in &module_info.classes {
        if !include_private && !is_java_public_at_line(&source, class.line_number as usize) {
            continue;
        }

        let qualified_name = join_module(&module_path, &class.name);
        let kind = determine_java_kind(class, &source);
        let is_interface = kind == ApiKind::Interface;

        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind,
            module: module_path.clone(),
            signature: None,
            docstring: class.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_java_type_example(&class.name, kind)),
            triggers: extract_triggers(&class.name, class.docstring.as_deref()),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: class.line_number as usize,
                column: None,
            }),
        });

        for method in &class.methods {
            // Interface methods are implicitly public in Java — no modifier
            // needed. Bypass the per-method visibility check when the enclosing
            // type is an interface. Mirrors rust_lang.rs:L174-L180 trait pattern.
            if !include_private
                && !is_interface
                && !is_java_public_at_line(&source, method.line_number as usize)
            {
                continue;
            }

            let params = convert_java_params(&method.params);
            let return_type = method.return_type.clone();
            let kind = if line_contains_word(&source, method.line_number as usize, "static") {
                ApiKind::StaticMethod
            } else {
                ApiKind::Method
            };

            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, method.name),
                kind,
                module: module_path.clone(),
                signature: Some(Signature {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    is_async: false,
                    is_generator: false,
                }),
                docstring: method.docstring.clone().map(|doc| truncate_docstring(&doc)),
                example: Some(generate_java_method_example(
                    &class.name,
                    &method.name,
                    &params,
                )),
                triggers: extract_triggers(&method.name, method.docstring.as_deref()),
                is_property: false,
                return_type,
                location: Some(Location {
                    file: relative_path.clone(),
                    line: method.line_number as usize,
                    column: None,
                }),
            });
        }

        for field in &class.fields {
            let is_public = field.visibility.as_deref() == Some("public");
            if !include_private && !is_public {
                continue;
            }

            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, field.name),
                kind: if field.is_constant {
                    ApiKind::Constant
                } else {
                    ApiKind::Property
                },
                module: module_path.clone(),
                signature: None,
                docstring: None,
                example: Some(format!("{}.{}", class.name, field.name)),
                triggers: extract_triggers(&field.name, None),
                is_property: !field.is_constant,
                return_type: field.field_type.clone(),
                location: Some(Location {
                    file: relative_path.clone(),
                    line: field.line_number as usize,
                    column: None,
                }),
            });
        }
    }

    Ok(apis)
}

/// Compute the Java module (package) path for a source file.
///
/// AST-driven: the authoritative module path is the file's `package
/// declaration` node (e.g. `package org.springframework.samples.petclinic;`).
/// The on-disk directory basename of the resolved target (e.g. `java-petclinic`)
/// is NOT part of the package and must never be prefixed onto it — doing so
/// produced bogus dotted paths like `java-petclinic.org.springframework...`
/// and, for default-package files, an unvalidated leading `.` (CL-8 /
/// IT3-java-01).
///
/// When the file declares no package (the default package), the module path is
/// derived from the directory layout with build-layout segments
/// (`src/main/java`, ...) stripped. If that yields nothing, the file lives in
/// the default package and the module is empty — never a literal `.` or the
/// directory basename.
fn compute_java_module_path(
    tree: &Tree,
    source: &str,
    file_path: &Path,
    root_dir: &Path,
    _package_name: &str,
) -> String {
    // Primary source of truth: the AST package declaration.
    if let Some(pkg) = extract_java_package_declaration(tree, source) {
        return pkg;
    }

    // Default package: reconstruct from directory layout (layout segments
    // stripped), without prefixing the resolver-derived directory basename.
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parts: Vec<String> = parent
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect();
    let parts = strip_layout_segments(Language::Java, Path::new(&parts.join("/")));

    parts.join(".")
}

/// Join a (possibly empty) Java module path with a member name without
/// emitting a leading or doubled `.`. For the default package (`module` is
/// empty) this returns the bare member name (`"Widget"`), never `".Widget"`.
fn join_module(module: &str, name: &str) -> String {
    if module.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", module, name)
    }
}

/// Extract the fully-qualified package name from a Java parse tree.
///
/// AST-driven: locates the top-level `package_declaration` node and reads its
/// dotted name child. tree-sitter-java represents the name as a
/// `scoped_identifier` (multi-segment, e.g. `a.b.c`) or a bare `identifier`
/// (single segment); leading `annotation` / `marker_annotation` children are
/// ignored. Returns `None` for a default-package file (no declaration).
fn extract_java_package_declaration(tree: &Tree, source: &str) -> Option<String> {
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_declaration" {
            return java_package_name_text(&child, source);
        }
    }
    None
}

/// Read the dotted package name from a `package_declaration` node.
fn java_package_name_text(decl: &Node, source: &str) -> Option<String> {
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if matches!(child.kind(), "scoped_identifier" | "identifier") {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                let name = text.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

fn is_java_public_at_line(source: &str, line_number: usize) -> bool {
    line_contains_word(source, line_number, "public")
}

fn line_contains_word(source: &str, line_number: usize, word: &str) -> bool {
    source
        .lines()
        .nth(line_number.saturating_sub(1))
        .map(|line| {
            line.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|part| part == word)
        })
        .unwrap_or(false)
}

fn determine_java_kind(class: &ClassInfo, source: &str) -> ApiKind {
    let line = source
        .lines()
        .nth(class.line_number.saturating_sub(1) as usize)
        .unwrap_or("");

    if line.contains(" interface ") || line.trim_start().starts_with("interface ") {
        ApiKind::Interface
    } else if line.contains(" enum ") || line.trim_start().starts_with("enum ") {
        ApiKind::Enum
    } else {
        ApiKind::Class
    }
}

fn convert_java_params(raw_params: &[String]) -> Vec<Param> {
    raw_params
        .iter()
        .filter(|param| !param.is_empty())
        .map(|param| Param {
            name: param.clone(),
            type_annotation: None,
            default: None,
            is_variadic: false,
            is_keyword: false,
        })
        .collect()
}

fn truncate_docstring(doc: &str) -> String {
    let first_para = doc.split("\n\n").next().unwrap_or(doc);
    let cleaned = first_para
        .replace("/**", "")
        .replace("*/", "")
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim())
        .collect::<Vec<_>>()
        .join(" ");

    if cleaned.len() <= 200 {
        cleaned
    } else {
        format!(
            "{}...",
            crate::util::truncate_at_char_boundary(&cleaned, 197)
        )
    }
}

fn generate_java_type_example(name: &str, kind: ApiKind) -> String {
    match kind {
        ApiKind::Interface => format!("{} value = null;", name),
        ApiKind::Enum => format!("{} value = {}.values()[0];", name, name),
        _ => format!("{} value = new {}();", name, name),
    }
}

fn generate_java_method_example(class_name: &str, method_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|param| param.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!("new {}().{}({})", class_name, method_name, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, rel: &str, source: &str) {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, source).unwrap();
    }

    #[test]
    fn test_truncate_docstring_handles_unicode_char_boundaries() {
        // 67 × 3-byte char (U+2500) = 201 bytes. Pre-fix: panic at
        // `&cleaned[..197]` (197 % 3 = 2 → mid-codepoint). Post-fix: snap
        // down to the largest char-boundary <= 197 (= 195 bytes = 65 chars).
        let doc = "─".repeat(67);
        let truncated = truncate_docstring(&doc);
        assert!(truncated.ends_with("..."));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert_eq!(truncated, format!("{}...", "─".repeat(65)));
    }

    #[test]
    fn test_find_java_files_recurses() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/java/com/example/App.java",
            "public class App {}",
        );
        write_file(
            &dir,
            "src/test/java/com/example/AppTest.java",
            "class AppTest {}",
        );

        let files = find_java_files(dir.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_java_surface_filters_package_private_members() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/java/com/example/Greeter.java",
            r#"
public class Greeter {
    public static final String VERSION = "1";
    String hidden = "no";

    public String hello(String name) {
        return name;
    }

    String secret(String token) {
        return token;
    }
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_java_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(names.iter().any(|name| name.ends_with("Greeter")));
        assert!(names.iter().any(|name| name.ends_with("Greeter.hello")));
        assert!(names.iter().any(|name| name.ends_with("Greeter.VERSION")));
        assert!(!names.iter().any(|name| name.ends_with("Greeter.secret")));
        assert!(!names.iter().any(|name| name.ends_with("Greeter.hidden")));
    }

    #[test]
    fn test_extract_java_surface_includes_non_public_when_requested() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/java/com/example/Helper.java",
            r#"
class Helper {
    String value() {
        return "ok";
    }
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_java_api_surface(&resolved, true, None).unwrap();
        assert!(surface
            .apis
            .iter()
            .any(|api| api.qualified_name.ends_with("Helper.value")));
    }

    #[test]
    fn test_compute_java_module_path_uses_ast_package_declaration() {
        // The module path is the file's AST `package` declaration verbatim —
        // independent of the on-disk directory layout and of the resolver's
        // package_name (CL-8 / IT3-java-01). Neither the directory basename
        // nor build-layout segments may appear.
        let root = Path::new("/repo");
        let file = Path::new("/repo/module-a/src/main/java/com/example/http/Client.java");
        let source = "package com.example.http;\n\npublic class Client {}\n";
        let tree = parse(source, Language::Java).unwrap();

        assert_eq!(
            compute_java_module_path(&tree, source, file, root, "example_pkg"),
            "com.example.http"
        );
    }

    #[test]
    fn test_compute_java_module_path_default_package_has_no_dir_prefix() {
        // A file with no package declaration (default package) must not be
        // qualified by the resolver-derived directory basename, and must never
        // produce a leading or doubled `.` (CL-8 / IT3-java-01).
        let root = Path::new("/repo/java-petclinic");
        let file = Path::new("/repo/java-petclinic/Widget.java");
        let source = "public class Widget {}\n";
        let tree = parse(source, Language::Java).unwrap();

        let module = compute_java_module_path(&tree, source, file, root, "java-petclinic");
        assert!(
            module.is_empty(),
            "default-package module must be empty, got {:?}",
            module
        );
        assert!(!module.starts_with('.'));
        assert!(!module.contains(".."));
    }

    #[test]
    fn test_extract_java_surface_interface_methods_are_public_by_default() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/java/com/example/IService.java",
            r#"
public interface IService {
    void execute();
    String getName();
    int compute(int x);
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        // include_private = false — without the fix, interface methods are filtered out.
        let surface = extract_java_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.iter().any(|n| n.ends_with("IService")),
            "Interface type should be in surface: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.ends_with("IService.execute")),
            "execute should be in surface: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.ends_with("IService.getName")),
            "getName should be in surface: {:?}",
            names
        );
        assert!(
            names.iter().any(|n| n.ends_with("IService.compute")),
            "compute should be in surface: {:?}",
            names
        );
    }
}
