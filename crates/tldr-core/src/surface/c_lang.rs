//! C-specific API surface extraction.
//!
//! When headers are present, the public C surface is derived from function
//! declarations in header files. If no headers are present, we fall back to
//! function definitions in `.c` files.
//!
//! Header extraction (`extract_from_c_headers`) uses an AST walk over
//! tree-sitter-c's parse tree: only `declaration` nodes whose declarator
//! is a `function_declarator`, and `function_definition` nodes, qualify
//! as surface entries. This is the m112-surface-garbage-cleanup-v1 fix
//! (Wave 17e / M-112): the previous line-based prototype guesser parsed
//! block-comment continuation lines (`Copyright`, ALL-CAPS legalese) and
//! GCC `__attribute__` directives as functions, and inline-macro-call
//! lines (`SDS_HDR(8, s)->len`) leaked macro identifiers as APIs.

use std::path::{Path, PathBuf};

use tree_sitter::Node;

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::Language;
use crate::TldrResult;

use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public C API surface for a resolved package.
pub fn extract_c_api_surface(
    resolved: &ResolvedPackage,
    _include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let (headers, sources) = find_c_files(&resolved.root_dir);
    let mut apis = if !headers.is_empty() {
        extract_from_c_headers(&headers, &resolved.root_dir, &resolved.package_name)?
    } else {
        let mut collected = Vec::new();
        for file_path in sources {
            collected.extend(extract_from_c_source_file(
                &file_path,
                &resolved.root_dir,
                &resolved.package_name,
            )?);
        }
        collected
    };

    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: resolved.package_name.clone(),
        language: "c".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

fn find_c_files(dir: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut headers = Vec::new();
    let mut sources = Vec::new();

    if dir.is_file() {
        match dir.extension().and_then(|ext| ext.to_str()) {
            Some("h") => headers.push(dir.to_path_buf()),
            Some("c") => sources.push(dir.to_path_buf()),
            _ => {}
        }
        return (headers, sources);
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        let (sub_headers, sub_sources) = find_c_files(&path);
                        headers.extend(sub_headers);
                        sources.extend(sub_sources);
                    }
                }
            } else {
                match path.extension().and_then(|ext| ext.to_str()) {
                    Some("h") => headers.push(path),
                    Some("c") => sources.push(path),
                    _ => {}
                }
            }
        }
    }

    headers.sort();
    sources.sort();
    (headers, sources)
}

fn extract_from_c_headers(
    files: &[PathBuf],
    root_dir: &Path,
    package_name: &str,
) -> TldrResult<Vec<ApiEntry>> {
    let mut apis = Vec::new();

    for file_path in files {
        let source = std::fs::read_to_string(file_path).map_err(|e| {
            crate::error::TldrError::parse_error(
                file_path.to_path_buf(),
                None,
                format!("Cannot read: {}", e),
            )
        })?;

        let module_path = compute_module_path(file_path, root_dir, package_name);
        let relative_path = super::resolve::location_relative_path(file_path, root_dir);

        let tree = parse(&source, Language::C)?;
        let root = tree.root_node();
        collect_c_header_apis(
            &root,
            source.as_bytes(),
            &module_path,
            &relative_path,
            &mut apis,
        );
    }

    Ok(apis)
}

/// AST walk over a C header parse tree (`m112-surface-garbage-cleanup-v1`).
///
/// Only emits surface entries for:
///   - `function_definition` nodes (inline functions in headers — `static
///     inline T foo(...) { ... }`),
///   - `declaration` nodes whose declarator (possibly wrapped in a
///     `pointer_declarator`) is a `function_declarator` (function
///     prototypes — `T foo(...);`).
///
/// Everything else — block comments, GCC `__attribute__` directives,
/// `#define` / `#include` preprocessor lines, `struct` / `enum` / `union`
/// / `typedef` declarations, macro-call expressions inside inline function
/// bodies — is skipped because tree-sitter-c does not classify those as
/// `function_definition` or function-shaped `declaration` nodes.
fn collect_c_header_apis(
    node: &Node,
    source: &[u8],
    module_path: &str,
    relative_path: &Path,
    apis: &mut Vec<ApiEntry>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(entry) =
                build_c_api_entry(node, source, module_path, relative_path)
            {
                apis.push(entry);
            }
            // Don't recurse into function bodies — nested functions are
            // a GNU extension and are not part of any public C surface.
            return;
        }
        "declaration" => {
            // A `declaration` carries a function prototype only when its
            // declarator (after unwrapping any pointer wrapper) is a
            // `function_declarator`. Plain `int x;` declarations and
            // `struct __attribute__((__packed__)) sdshdr5 {...};` shapes
            // do NOT match this guard.
            if declaration_is_function_prototype(node) {
                if let Some(entry) =
                    build_c_api_entry(node, source, module_path, relative_path)
                {
                    apis.push(entry);
                }
                // Don't recurse — children carry only declarator/type pieces.
                return;
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_c_header_apis(&child, source, module_path, relative_path, apis);
    }
}

/// Returns `true` when a `declaration` node carries a function
/// prototype (declarator is a `function_declarator`, possibly wrapped in
/// a `pointer_declarator`). Skips object declarations, `typedef`s,
/// `struct`/`enum`/`union` definitions, and attribute-only lines.
fn declaration_is_function_prototype(node: &Node) -> bool {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return false;
    };
    contains_function_declarator(&declarator)
}

fn contains_function_declarator(node: &Node) -> bool {
    if node.kind() == "function_declarator" {
        return true;
    }
    // Unwrap one level of `pointer_declarator` (e.g. `int *foo(...)`).
    if let Some(inner) = node.child_by_field_name("declarator") {
        return contains_function_declarator(&inner);
    }
    false
}

fn build_c_api_entry(
    node: &Node,
    source: &[u8],
    module_path: &str,
    relative_path: &Path,
) -> Option<ApiEntry> {
    let declarator = node.child_by_field_name("declarator")?;
    let func_decl = unwrap_function_declarator(&declarator)?;
    let name_node = func_decl.child_by_field_name("declarator")?;
    let name = c_declarator_name(&name_node, source)?;
    if name.is_empty() {
        return None;
    }

    let params = c_param_names(&func_decl, source);
    // The declaration's `type` field carries only the base type (e.g. `void`,
    // `sds`); any pointer indirection lives in the declarator chain. Re-attach
    // those `*`s so `void *f(...)` reports `void *`, not a stripped `void`.
    let pointer_depth = return_pointer_depth(&declarator);
    let return_type = node
        .child_by_field_name("type")
        .and_then(|n| n.utf8_text(source).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|base| {
            if pointer_depth > 0 {
                format!("{} {}", base, "*".repeat(pointer_depth))
            } else {
                base
            }
        });

    let params_vec: Vec<Param> = params
        .into_iter()
        .map(|name| Param {
            name,
            type_annotation: None,
            default: None,
            is_variadic: false,
            is_keyword: false,
        })
        .collect();

    let line = node.start_position().row + 1;

    Some(ApiEntry {
        qualified_name: format!("{}.{}", module_path, name),
        kind: ApiKind::Function,
        module: module_path.to_string(),
        signature: Some(Signature {
            params: params_vec.clone(),
            return_type: return_type.clone(),
            is_async: false,
            is_generator: false,
        }),
        docstring: None,
        example: Some(format!(
            "{}({})",
            name,
            params_vec
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        triggers: extract_triggers(&name, None),
        is_property: false,
        return_type,
        location: Some(Location {
            file: relative_path.to_path_buf(),
            line,
            column: None,
        }),
    })
}

fn unwrap_function_declarator<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    match node.kind() {
        "function_declarator" => Some(*node),
        // `pointer_declarator { declarator: function_declarator { ... } }`
        _ => node
            .child_by_field_name("declarator")
            .and_then(|inner| unwrap_function_declarator(&inner)),
    }
}

/// Count the pointer-indirection depth of a function's return type by walking
/// the declarator chain from the outer declarator down to the
/// `function_declarator`. Each `pointer_declarator` wrapper contributes one
/// `*` (e.g. `void *f(...)` -> 1, `sds **g(...)` -> 2). The declaration's
/// `type` field omits these stars, so they must be re-attached for the
/// surface return type to be faithful.
fn return_pointer_depth(node: &Node) -> usize {
    match node.kind() {
        "function_declarator" => 0,
        "pointer_declarator" => node
            .child_by_field_name("declarator")
            .map(|inner| 1 + return_pointer_depth(&inner))
            .unwrap_or(0),
        _ => node
            .child_by_field_name("declarator")
            .map(|inner| return_pointer_depth(&inner))
            .unwrap_or(0),
    }
}

fn c_declarator_name(node: &Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(|s| s.to_string()),
        "pointer_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|inner| c_declarator_name(&inner, source)),
        // Some C grammars emit `field_identifier` for nested cases; harmless to handle.
        "field_identifier" => node.utf8_text(source).ok().map(|s| s.to_string()),
        _ => {
            // Fallback: scan children for an identifier.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = c_declarator_name(&child, source) {
                    return Some(name);
                }
            }
            None
        }
    }
}

fn c_param_names(func_decl: &Node, source: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(params) = func_decl.child_by_field_name("parameters") else {
        return out;
    };
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            if let Some(decl) = child.child_by_field_name("declarator") {
                if let Some(name) = c_declarator_name(&decl, source) {
                    if !name.is_empty() {
                        out.push(name);
                    }
                }
            }
        }
    }
    out
}

fn extract_from_c_source_file(
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> TldrResult<Vec<ApiEntry>> {
    let source = std::fs::read_to_string(file_path).map_err(|e| {
        crate::error::TldrError::parse_error(
            file_path.to_path_buf(),
            None,
            format!("Cannot read: {}", e),
        )
    })?;

    let tree = parse(&source, Language::C)?;
    let module_info = extract_from_tree(&tree, &source, Language::C, file_path, Some(root_dir))?;
    let module_path = compute_module_path(file_path, root_dir, package_name);
    let relative_path = super::resolve::location_relative_path(file_path, root_dir);

    let mut apis = Vec::new();
    for func in module_info.functions {
        let params = func
            .params
            .into_iter()
            .map(|param| Param {
                name: param,
                type_annotation: None,
                default: None,
                is_variadic: false,
                is_keyword: false,
            })
            .collect::<Vec<_>>();

        apis.push(ApiEntry {
            qualified_name: format!("{}.{}", module_path, func.name),
            kind: ApiKind::Function,
            module: module_path.clone(),
            signature: Some(Signature {
                params: params.clone(),
                return_type: func.return_type.clone(),
                is_async: false,
                is_generator: false,
            }),
            docstring: func.docstring,
            example: Some(format!(
                "{}({})",
                func.name,
                params
                    .iter()
                    .map(|p| p.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            triggers: extract_triggers(&func.name, None),
            is_property: false,
            return_type: func.return_type,
            location: Some(Location {
                file: relative_path.clone(),
                line: func.line_number as usize,
                column: None,
            }),
        });
    }

    Ok(apis)
}

fn compute_module_path(file_path: &Path, root_dir: &Path, package_name: &str) -> String {
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parts: Vec<String> = parent
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect();
    if parts.is_empty() {
        package_name.to_string()
    } else {
        format!("{}.{}", package_name, parts.join("."))
    }
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
    fn test_headers_define_c_surface() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "include/api.h", "int add(int a, int b);\n");
        write_file(&dir, "src/api.c", "int hidden(int x) { return x; }\n");

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_c_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();
        assert!(names.iter().any(|name| name.ends_with(".add")));
        assert!(!names.iter().any(|name| name.ends_with(".hidden")));
    }

    #[test]
    fn test_c_pointer_return_types_preserved_in_surface() {
        // A3d-surface-c-pointer: header-derived surface entries for
        // pointer-returning C functions must keep their pointer return type
        // (the `*`s) AND their parameters. Anti-treadmill generalization gate
        // for the C symptom class: single `*`, double `**`, void pointer, and
        // typedef-base pointer (`sds`), plus a non-pointer control.
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "include/api.h",
            concat!(
                "void *alloc_ptr(unsigned long size);\n",
                "char *make_buf(int size, const char *name);\n",
                "sds *split_one(const char *line, int *argc);\n",
                "sds **split_two(const char *line, int n);\n",
                "int plain(int x);\n",
            ),
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_c_api_surface(&resolved, false, None).unwrap();
        let find = |suffix: &str| {
            surface
                .apis
                .iter()
                .find(|a| a.qualified_name.ends_with(suffix))
                .unwrap_or_else(|| panic!("missing {suffix}: {:?}", surface.apis))
        };
        let param_names = |entry: &ApiEntry| -> Vec<String> {
            entry
                .signature
                .as_ref()
                .map(|s| s.params.iter().map(|p| p.name.clone()).collect())
                .unwrap_or_default()
        };

        let alloc = find(".alloc_ptr");
        assert_eq!(alloc.return_type.as_deref(), Some("void *"));
        assert_eq!(param_names(alloc), vec!["size"]);

        let make_buf = find(".make_buf");
        assert_eq!(make_buf.return_type.as_deref(), Some("char *"));
        assert_eq!(param_names(make_buf), vec!["size", "name"]);

        let one = find(".split_one");
        assert_eq!(one.return_type.as_deref(), Some("sds *"));
        assert_eq!(param_names(one), vec!["line", "argc"]);

        // Double pointer return.
        let two = find(".split_two");
        assert_eq!(two.return_type.as_deref(), Some("sds **"));
        assert_eq!(param_names(two), vec!["line", "n"]);

        // Non-pointer control is unchanged.
        let plain = find(".plain");
        assert_eq!(plain.return_type.as_deref(), Some("int"));
        assert_eq!(param_names(plain), vec!["x"]);
    }

    #[test]
    fn test_c_falls_back_to_source_when_no_headers() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "src/api.c",
            "int add(int a, int b) { return a + b; }\n",
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_c_api_surface(&resolved, false, None).unwrap();
        assert!(surface
            .apis
            .iter()
            .any(|api| api.qualified_name.ends_with(".add")));
    }
}
