//! Kotlin-specific API surface extraction.
//!
//! Kotlin declarations are public by default. `private` and `internal`
//! declarations are excluded unless `include_private` is set.

use std::path::{Path, PathBuf};

use tree_sitter::{Node, Tree};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::{ClassInfo, Language};
use crate::TldrResult;

use super::language_profile::strip_layout_segments;
use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public Kotlin API surface for a resolved package.
pub fn extract_kotlin_api_surface(
    resolved: &ResolvedPackage,
    include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();
    // Surface-level package is the AST `package_header` of the resolved
    // source(s), NOT the resolver-derived `package_name` (which is the file
    // stem for a single-file target, e.g. `JobSupport`). Take the first file's
    // declared package; fall back to the resolver name only when no file
    // declares one (default package).
    let mut surface_package: Option<String> = None;

    for file_path in find_kotlin_files(&resolved.root_dir) {
        let (file_apis, file_package) = extract_from_kotlin_file(
            &file_path,
            &resolved.root_dir,
            &resolved.package_name,
            include_private,
        )?;
        if surface_package.is_none() {
            surface_package = file_package;
        }
        apis.extend(file_apis);
    }

    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: surface_package.unwrap_or_else(|| resolved.package_name.clone()),
        language: "kotlin".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

fn find_kotlin_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return dir
            .extension()
            .and_then(|ext| ext.to_str())
            .filter(|ext| *ext == "kt" || *ext == "kts")
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
                        files.extend(find_kotlin_files(&path));
                    }
                }
            } else if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("kt" | "kts")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn extract_from_kotlin_file(
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
    include_private: bool,
) -> TldrResult<(Vec<ApiEntry>, Option<String>)> {
    let source = std::fs::read_to_string(file_path).map_err(|e| {
        crate::error::TldrError::parse_error(
            file_path.to_path_buf(),
            None,
            format!("Cannot read: {}", e),
        )
    })?;

    let tree = parse(&source, Language::Kotlin)?;
    let module_info =
        extract_from_tree(&tree, &source, Language::Kotlin, file_path, Some(root_dir))?;
    let ast_package = extract_kotlin_package_declaration(&tree, &source);
    let module_path =
        compute_kotlin_module_path(ast_package.as_deref(), file_path, root_dir, package_name);
    let relative_path = super::resolve::location_relative_path(file_path, root_dir);

    let mut apis = Vec::new();

    for func in &module_info.functions {
        if !include_private && is_kotlin_hidden_at_line(&source, func.line_number as usize) {
            continue;
        }

        let params = convert_kotlin_params(&func.params);
        let return_type = func.return_type.clone();
        apis.push(ApiEntry {
            qualified_name: format!("{}.{}", module_path, func.name),
            kind: ApiKind::Function,
            module: module_path.clone(),
            signature: Some(Signature {
                params: params.clone(),
                return_type: return_type.clone(),
                is_async: func.is_async,
                is_generator: false,
            }),
            docstring: func.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_kotlin_call_example(
                &module_path,
                &func.name,
                &params,
            )),
            triggers: extract_triggers(&func.name, func.docstring.as_deref()),
            is_property: false,
            return_type,
            location: Some(Location {
                file: relative_path.clone(),
                line: func.line_number as usize,
                column: None,
            }),
        });
    }

    for class in &module_info.classes {
        if !include_private && is_kotlin_hidden_at_line(&source, class.line_number as usize) {
            continue;
        }

        let class_name = effective_kotlin_class_name(class, &source);
        if class_name.is_empty() {
            continue;
        }
        let qualified_name = format!("{}.{}", module_path, class_name);
        let kind = determine_kotlin_kind(class, &source);

        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind,
            module: module_path.clone(),
            signature: None,
            docstring: class.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_kotlin_type_example(&class_name, kind)),
            triggers: extract_triggers(&class_name, class.docstring.as_deref()),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: class.line_number as usize,
                column: None,
            }),
        });

        for method in &class.methods {
            // RC2-2-visibility-ts-kotlin-swift: gate class members on the
            // AST-derived `visibility` (`modifiers > visibility_modifier`)
            // instead of a source-line scan. The old line check only matched
            // `private `/`internal `, so `protected` members leaked into the
            // public surface.
            if !include_private && kotlin_visibility_is_hidden(method.visibility.as_deref()) {
                continue;
            }

            let params = convert_kotlin_params(&method.params);
            let return_type = method.return_type.clone();
            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, method.name),
                kind: ApiKind::Method,
                module: module_path.clone(),
                signature: Some(Signature {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    is_async: method.is_async,
                    is_generator: false,
                }),
                docstring: method.docstring.clone().map(|doc| truncate_docstring(&doc)),
                example: Some(generate_kotlin_method_example(
                    &class_name,
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
    }

    for constant in &module_info.constants {
        if !include_private && is_kotlin_hidden_at_line(&source, constant.line_number as usize) {
            continue;
        }

        apis.push(ApiEntry {
            qualified_name: format!("{}.{}", module_path, constant.name),
            kind: ApiKind::Constant,
            module: module_path.clone(),
            signature: None,
            docstring: None,
            example: Some(format!("{}.{}", module_path, constant.name)),
            triggers: extract_triggers(&constant.name, None),
            is_property: false,
            return_type: constant.field_type.clone(),
            location: Some(Location {
                file: relative_path.clone(),
                line: constant.line_number as usize,
                column: None,
            }),
        });
    }

    Ok((apis, ast_package))
}

fn compute_kotlin_module_path(
    ast_package: Option<&str>,
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> String {
    // Primary source of truth: the AST `package_header` declaration. This is
    // the real fully-qualified package (e.g. `kotlinx.coroutines`), independent
    // of the on-disk filename. The resolver sets `package_name` to the file stem
    // for single-file targets, so qualifying by it embedded the filename
    // (`JobSupport.JobSupport`); reading the declared package fixes that.
    if let Some(pkg) = ast_package {
        if !pkg.is_empty() {
            return pkg.to_string();
        }
    }

    // No declared package (default package): reconstruct from the directory
    // layout (build-layout segments stripped), qualified by the resolver name.
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parts: Vec<String> = parent
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect();
    let parts = strip_layout_segments(Language::Kotlin, Path::new(&parts.join("/")));

    if parts.is_empty() {
        package_name.to_string()
    } else {
        format!("{}.{}", package_name, parts.join("."))
    }
}

/// Extract the fully-qualified package name from a Kotlin parse tree.
///
/// AST-driven: locates the top-level `package_header` node and reads its dotted
/// name child. tree-sitter-kotlin-ng represents the name as a
/// `qualified_identifier` (one-or-more `identifier` segments joined by `.`);
/// a bare `identifier` is accepted for grammar-version robustness. Returns
/// `None` for a default-package file (no `package` declaration).
fn extract_kotlin_package_declaration(tree: &Tree, source: &str) -> Option<String> {
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_header" {
            return kotlin_package_name_text(&child, source);
        }
    }
    None
}

/// Read the dotted package name from a `package_header` node.
fn kotlin_package_name_text(header: &Node, source: &str) -> Option<String> {
    let mut cursor = header.walk();
    for child in header.children(&mut cursor) {
        if matches!(child.kind(), "qualified_identifier" | "identifier") {
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

/// RC2-2-visibility-ts-kotlin-swift: a Kotlin class member is hidden from the
/// public surface when its AST-derived visibility is `private`, `protected`, or
/// `internal`. Kotlin's implicit default is `public`, so `None` (no modifier)
/// and an explicit `public` both surface. Reads the `modifiers >
/// visibility_modifier` keyword captured by the extractor instead of the
/// brittle source-line scan that missed `protected`.
fn kotlin_visibility_is_hidden(visibility: Option<&str>) -> bool {
    matches!(visibility, Some("private" | "protected" | "internal"))
}

fn is_kotlin_hidden_at_line(source: &str, line_number: usize) -> bool {
    source
        .lines()
        .nth(line_number.saturating_sub(1))
        .map(|line| line.contains("private ") || line.contains("internal "))
        .unwrap_or(false)
}

fn determine_kotlin_kind(class: &ClassInfo, source: &str) -> ApiKind {
    let line = source
        .lines()
        .nth(class.line_number.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim_start();

    if line.starts_with("interface ") || line.contains(" interface ") {
        ApiKind::Interface
    } else if line.starts_with("enum class ") || line.contains(" enum class ") {
        ApiKind::Enum
    } else {
        ApiKind::Class
    }
}

fn effective_kotlin_class_name(class: &ClassInfo, source: &str) -> String {
    if !class.name.is_empty() {
        return class.name.clone();
    }

    let line = source
        .lines()
        .nth(class.line_number.saturating_sub(1) as usize)
        .unwrap_or("");
    let tokens: Vec<&str> = line
        .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect();

    for idx in 0..tokens.len() {
        match tokens[idx] {
            "class" | "object" | "interface" => {
                if let Some(name) = tokens.get(idx + 1) {
                    return (*name).to_string();
                }
            }
            "enum" => {
                if tokens.get(idx + 1) == Some(&"class") {
                    if let Some(name) = tokens.get(idx + 2) {
                        return (*name).to_string();
                    }
                }
            }
            _ => {}
        }
    }

    String::new()
}

fn convert_kotlin_params(raw_params: &[String]) -> Vec<Param> {
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

fn generate_kotlin_call_example(module_path: &str, func_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|param| param.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}.{}({})", module_path, func_name, args)
}

fn generate_kotlin_type_example(name: &str, kind: ApiKind) -> String {
    match kind {
        ApiKind::Interface => format!("val value: {} = TODO()", name),
        _ => format!("val value = {}()", name),
    }
}

fn generate_kotlin_method_example(class_name: &str, method_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|param| param.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}.{}({})",
        class_name.replace('.', "").to_lowercase(),
        method_name,
        args
    )
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
    fn test_find_kotlin_files_recurses() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "src/main/kotlin/App.kt", "class App");
        write_file(&dir, "build.gradle.kts", "plugins {}");

        let files = find_kotlin_files(dir.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_kotlin_surface_filters_private_and_internal() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/kotlin/com/example/App.kt",
            r#"
const val VERSION = "1"
private const val HIDDEN = "no"

fun greet(name: String): String = name
internal fun debug(name: String): String = name

class Greeter {
    fun hello(name: String): String = name
    private fun secret(token: String): String = token
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_kotlin_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(names.iter().any(|name| name.ends_with(".greet")));
        assert!(names.iter().any(|name| name.ends_with("Greeter.hello")));
        assert!(names.iter().any(|name| name.ends_with(".VERSION")));
        assert!(!names.iter().any(|name| name.ends_with(".debug")));
        assert!(!names.iter().any(|name| name.ends_with("Greeter.secret")));
        assert!(!names.iter().any(|name| name.ends_with(".HIDDEN")));
    }

    /// RC2-2-visibility-ts-kotlin-swift: the line-based hidden check only
    /// matched `private `/`internal `, so `protected` class methods leaked into
    /// the public surface. Reading the AST-derived `visibility` field treats
    /// private + protected + internal as hidden while keeping implicit-public.
    #[test]
    fn test_extract_kotlin_surface_excludes_protected_methods_rc2_2() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/kotlin/com/example/App.kt",
            r#"
open class Greeter {
    fun hello(name: String): String = name
    protected fun guarded(token: String): String = token
    private fun secret(token: String): String = token
    internal fun debug(token: String): String = token
}
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_kotlin_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.iter().any(|name| name.ends_with("Greeter.hello")),
            "implicit-public method must surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.ends_with("Greeter.guarded")),
            "protected method must NOT leak into surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.ends_with("Greeter.secret")),
            "private method must NOT leak into surface, got {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.ends_with("Greeter.debug")),
            "internal method must NOT leak into surface, got {names:?}"
        );
    }

    #[test]
    fn test_extract_kotlin_surface_includes_internal_when_requested() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/main/kotlin/com/example/App.kt",
            r#"
internal fun debug(name: String): String = name
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_kotlin_api_surface(&resolved, true, None).unwrap();
        assert!(surface
            .apis
            .iter()
            .any(|api| api.qualified_name.ends_with(".debug")));
    }

    #[test]
    fn test_compute_kotlin_module_path_strips_nested_common_main_kotlin_prefix() {
        // Default-package fallback (ast_package == None): reconstruct from the
        // directory layout, build-layout segments stripped.
        let root = Path::new("/repo");
        let file = Path::new("/repo/sdk/src/commonMain/kotlin/com/example/core/Client.kt");

        assert_eq!(
            compute_kotlin_module_path(None, file, root, "example_pkg"),
            "example_pkg.sdk.com.example.core"
        );
    }

    #[test]
    fn test_compute_kotlin_module_path_strips_nested_jvm_main_kotlin_prefix() {
        // Default-package fallback (ast_package == None): reconstruct from the
        // directory layout, build-layout segments stripped.
        let root = Path::new("/repo");
        let file = Path::new("/repo/runtime/src/jvmMain/kotlin/com/example/io/Streams.kt");

        assert_eq!(
            compute_kotlin_module_path(None, file, root, "example_pkg"),
            "example_pkg.runtime.com.example.io"
        );
    }

    #[test]
    fn test_compute_kotlin_module_path_uses_ast_package_header() {
        // When the file declares a `package`, the module path is that declared
        // package verbatim — independent of the on-disk directory layout and of
        // the resolver-derived `package_name` (the file stem for single-file
        // targets). This is the CF2-S6 root-cause assertion: the package segment
        // must equal the `package_header` value, never the filename.
        let root = Path::new("/repo");
        let file = Path::new("/repo/JobSupport.kt");

        assert_eq!(
            compute_kotlin_module_path(Some("kotlinx.coroutines"), file, root, "JobSupport"),
            "kotlinx.coroutines"
        );
    }

    /// CF2-S6: `tldr surface` on a single-file Kotlin target derived the package
    /// from the FILENAME (resolver sets `package_name` = file stem), producing
    /// doubled / wrong fully-qualified names like `JobSupport.JobSupport`. The
    /// fix reads the AST `package_header` node so the package segment of every
    /// qualified name (and the surface-level `package`) equals the declared
    /// package (`kotlinx.coroutines`), never the filename.
    ///
    /// Generalization: asserts the AST-driven `package_header` extraction across
    /// representative single-segment, multi-segment, and default-package Kotlin
    /// inputs — the full symptom class for this slice (language: kotlin).
    #[test]
    fn test_extract_kotlin_surface_package_from_ast_header_not_filename() {
        // Multi-segment package, single-file target named after the type. The
        // resolver passes `JobSupport` (file stem) as package_name; the surface
        // must instead expose `kotlinx.coroutines`.
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "JobSupport.kt",
            r#"package kotlinx.coroutines

class JobSupport {
    fun start(): Boolean = true
}
"#,
        );
        let file = dir.path().join("JobSupport.kt");
        let resolved = ResolvedPackage {
            root_dir: file.clone(),
            package_name: "JobSupport".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_kotlin_api_surface(&resolved, false, None).unwrap();
        assert_eq!(
            surface.package, "kotlinx.coroutines",
            "surface package must be the package_header, not the filename, got {:?}",
            surface.package
        );
        let class = surface
            .apis
            .iter()
            .find(|api| api.qualified_name.ends_with(".JobSupport"))
            .expect("JobSupport class must surface");
        assert_eq!(
            class.qualified_name, "kotlinx.coroutines.JobSupport",
            "qualified name must be package_header-qualified, not filename-doubled"
        );
        assert!(
            surface
                .apis
                .iter()
                .any(|api| api.qualified_name == "kotlinx.coroutines.JobSupport.start"),
            "method qualified name must use the package_header segment, got {:?}",
            surface
                .apis
                .iter()
                .map(|a| a.qualified_name.as_str())
                .collect::<Vec<_>>()
        );
        // Hard anti-regression: the filename must never appear as a package
        // segment of any qualified name.
        for api in &surface.apis {
            assert!(
                !api.qualified_name.starts_with("JobSupport."),
                "filename leaked into package segment: {}",
                api.qualified_name
            );
        }

        // Single-segment package (`package foo`) — the `qualified_identifier`
        // wraps a lone segment; must still be read verbatim.
        let dir2 = TempDir::new().unwrap();
        write_file(&dir2, "Widget.kt", "package widgets\n\nclass Widget\n");
        let file2 = dir2.path().join("Widget.kt");
        let resolved2 = ResolvedPackage {
            root_dir: file2.clone(),
            package_name: "Widget".to_string(),
            is_pure_source: true,
            public_names: None,
        };
        let surface2 = extract_kotlin_api_surface(&resolved2, false, None).unwrap();
        assert_eq!(surface2.package, "widgets");
        assert!(surface2
            .apis
            .iter()
            .any(|api| api.qualified_name == "widgets.Widget"));

        // Default package (no `package` declaration): fall back to the resolver
        // name; the AST path must not crash or invent a package.
        let dir3 = TempDir::new().unwrap();
        write_file(&dir3, "Loose.kt", "class Loose\n");
        let file3 = dir3.path().join("Loose.kt");
        let resolved3 = ResolvedPackage {
            root_dir: file3.clone(),
            package_name: "Loose".to_string(),
            is_pure_source: true,
            public_names: None,
        };
        let surface3 = extract_kotlin_api_surface(&resolved3, false, None).unwrap();
        assert_eq!(surface3.package, "Loose");
        assert!(surface3
            .apis
            .iter()
            .any(|api| api.qualified_name == "Loose.Loose"));
    }
}
