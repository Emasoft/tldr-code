//! Lua-specific API surface extraction.
//!
//! Lua surfaces functions that are exported through a returned module table or
//! through keys in a returned table literal.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::fs::{read_to_string_tolerant, ReadOutcome};
use crate::types::Language;
use crate::TldrResult;

use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public Lua API surface for a resolved package.
pub fn extract_lua_api_surface(
    resolved: &ResolvedPackage,
    _include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut files_skipped: usize = 0;

    for file_path in find_lua_files(&resolved.root_dir) {
        if let Some(entries) = extract_from_lua_file(
            &file_path,
            &resolved.root_dir,
            &resolved.package_name,
            &mut warnings,
            &mut files_skipped,
        )? {
            apis.extend(entries);
        }
    }

    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: resolved.package_name.clone(),
        language: "lua".to_string(),
        total,
        apis,
        files_skipped,
        warnings,
    })
}

fn find_lua_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return dir
            .extension()
            .and_then(|ext| ext.to_str())
            .filter(|ext| *ext == "lua")
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
                        files.extend(find_lua_files(&path));
                    }
                }
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("lua") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn extract_from_lua_file(
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
    warnings: &mut Vec<String>,
    files_skipped: &mut usize,
) -> TldrResult<Option<Vec<ApiEntry>>> {
    let source = match read_to_string_tolerant(file_path).map_err(|e| {
        crate::error::TldrError::parse_error(
            file_path.to_path_buf(),
            None,
            format!("Cannot read: {}", e),
        )
    })? {
        ReadOutcome::Ok(s) => s,
        ReadOutcome::NonUtf8 { byte_offset } => {
            *files_skipped += 1;
            warnings.push(format!(
                "Skipped {}: invalid UTF-8 at byte {}",
                file_path.display(),
                byte_offset
            ));
            return Ok(None);
        }
    };

    let tree = parse(&source, Language::Lua)?;
    let module_info = extract_from_tree(&tree, &source, Language::Lua, file_path, Some(root_dir))?;
    let module_path = compute_module_path(file_path, root_dir, package_name);
    let relative_path = super::resolve::location_relative_path(file_path, root_dir);

    let exported_table = returned_module_table(&source);
    let returned_keys = returned_table_keys(&source);
    let mut apis = Vec::new();

    // W2-lua-structure (v0.5.0 AUDIT-FIX): table-qualified declarations
    // (`function M.hello()` / `function M:greet()`) are now grouped into
    // `module_info.classes[].methods` by the AST extractor and intentionally
    // EXCLUDED from `module_info.functions` (no double counting). The surface
    // walk recovers the exported name from the source line via
    // `parse_table_export`, which still works for a method because its
    // `line_number` points at the `function M.<name>(...)` line. So feed the
    // grouped class methods through the same export logic as plain functions.
    let candidate_functions: Vec<crate::types::FunctionInfo> = module_info
        .functions
        .into_iter()
        .chain(
            module_info
                .classes
                .into_iter()
                .flat_map(|class| class.methods),
        )
        .collect();

    // Map every module-local function name to its (params, def_line) so the
    // AST returned-table resolver can resolve identifier-alias fields
    // (`md5 = md5`) back to the function they re-export.
    let local_funcs: HashMap<String, (Vec<String>, usize)> = candidate_functions
        .iter()
        .map(|f| {
            (
                f.name.clone(),
                (f.params.clone(), f.line_number as usize),
            )
        })
        .collect();

    for func in candidate_functions {
        let line = source
            .lines()
            .nth(func.line_number.saturating_sub(1) as usize)
            .unwrap_or("")
            .trim();

        let export_name = if let Some(table_name) = exported_table.as_deref() {
            parse_table_export(line, table_name)
        } else {
            None
        }
        .or_else(|| returned_keys.get(&func.name).cloned());

        if let Some(export_name) = export_name {
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
                qualified_name: format!("{}.{}", module_path, export_name),
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
                    export_name,
                    params
                        .iter()
                        .map(|p| p.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                triggers: extract_triggers(&export_name, None),
                is_property: false,
                return_type: func.return_type,
                location: Some(Location {
                    file: relative_path.clone(),
                    line: func.line_number as usize,
                    column: None,
                }),
            });
        }
    }

    // AST recovery for the literal-bound accumulator (`local M = { … } … return
    // M`) and the multi-line `return { … }` literal — function-valued fields the
    // line-based heuristics above never surfaced. Additive: only fields not
    // already emitted are appended, so the existing single-line path is intact.
    let already: std::collections::HashSet<String> =
        apis.iter().map(|a| a.qualified_name.clone()).collect();
    for export in returned_table_function_exports(tree.root_node(), &source, &local_funcs) {
        let qualified_name = format!("{}.{}", module_path, export.name);
        if already.contains(&qualified_name) {
            continue;
        }
        let params: Vec<Param> = export
            .params
            .iter()
            .map(|name| Param {
                name: name.clone(),
                type_annotation: None,
                default: None,
                is_variadic: name == "...",
                is_keyword: false,
            })
            .collect();
        apis.push(ApiEntry {
            qualified_name,
            kind: ApiKind::Function,
            module: module_path.clone(),
            signature: Some(Signature {
                params: params.clone(),
                return_type: None,
                is_async: false,
                is_generator: false,
            }),
            docstring: None,
            example: Some(format!(
                "{}({})",
                export.name,
                params
                    .iter()
                    .map(|p| p.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            triggers: extract_triggers(&export.name, None),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: export.line,
                column: None,
            }),
        });
    }

    Ok(Some(apis))
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

fn returned_module_table(source: &str) -> Option<String> {
    source.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("return ")
            .map(str::trim)
            .filter(|rest| {
                !rest.contains('{') && rest.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
            })
            .map(|name| name.to_string())
    })
}

fn returned_table_keys(source: &str) -> HashMap<String, String> {
    let mut exports = HashMap::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(body) = trimmed
            .strip_prefix("return {")
            .and_then(|s| s.strip_suffix('}'))
        {
            for item in body.split(',') {
                let part = item.trim();
                if let Some((key, value)) = part.split_once('=') {
                    let export_key = key.trim().to_string();
                    let local_name = value.trim().trim_start_matches("M.").to_string();
                    exports.insert(local_name, export_key);
                }
            }
        }
    }
    exports
}

fn parse_table_export(line: &str, table_name: &str) -> Option<String> {
    for separator in [".", ":"] {
        let needle = format!("{table_name}{separator}");
        if let Some(rest) = line.split(&needle).nth(1) {
            let name = rest
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                .next()
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

// =============================================================================
// AST-driven returned-table literal resolution (shared by lua.rs and luau.rs)
//
// The line-based `returned_table_keys` / `parse_table_export` heuristics above
// only recognize a SINGLE-LINE `return { k = v }` and a `function M.x(...)`
// member declaration. They miss two real module idioms whose exports are
// otherwise invisible to `surface`:
//
//   1. a MULTI-LINE inline literal       `return {\n  a = a,\n  b = fn,\n}`
//   2. the literal-bound accumulator     `local M = { a = a, b = fn } … return M`
//
// In both, the function-valued fields are either inline anonymous
// `function_definition`s (never named, so absent from `module_info.functions`)
// or identifier aliases to module-local functions. This AST resolver recovers
// them directly from the returned `table_constructor`, so they surface for both
// Lua and Luau (the constructor/field grammar is byte-identical across the two).
// =============================================================================

/// A function-valued field recovered from a module's returned table literal.
pub(super) struct LiteralExport {
    /// Exported key (the table field name).
    pub name: String,
    /// Parameter names of the resolved function.
    pub params: Vec<String>,
    /// 1-based definition line (inline def site or the aliased function's site).
    pub line: usize,
}

/// AST-resolve the function-valued fields of a Lua/Luau module's returned table
/// literal. `local_funcs` maps a module-local function name to its
/// `(param_names, def_line)` so identifier-alias fields (`md5 = md5`) resolve to
/// the function they point at. Returns an empty vec for dynamic / non-literal
/// module tails (the caller keeps its existing behaviour unchanged).
pub(super) fn returned_table_function_exports(
    root: tree_sitter::Node,
    source: &str,
    local_funcs: &HashMap<String, (Vec<String>, usize)>,
) -> Vec<LiteralExport> {
    let table = match returned_module_literal(root, source) {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor = table.walk();
    for field in table.children(&mut cursor) {
        if field.kind() != "field" {
            continue;
        }
        // Only identifier keys are stable export names (`[expr] =` computed keys
        // and bare positional entries are skipped).
        let key = match field.child_by_field_name("name") {
            Some(k) if k.kind() == "identifier" => k,
            _ => continue,
        };
        let name = source[key.byte_range()].trim().to_string();
        if name.is_empty() || !seen.insert(name.clone()) {
            continue;
        }
        let value = match field.child_by_field_name("value") {
            Some(v) => v,
            None => continue,
        };
        match value.kind() {
            // Inline anonymous function: `key = function(...) … end`.
            "function_definition" | "function_definition_statement" => {
                let params = value
                    .child_by_field_name("parameters")
                    .map(|p| lua_param_names(p, source))
                    .unwrap_or_default();
                out.push(LiteralExport {
                    name,
                    params,
                    line: value.start_position().row + 1,
                });
            }
            // Alias to a module-local function: `key = localFn`.
            "identifier" => {
                let target = source[value.byte_range()].trim();
                if let Some((params, line)) = local_funcs.get(target) {
                    out.push(LiteralExport {
                        name,
                        params: params.clone(),
                        line: *line,
                    });
                }
            }
            // Non-function values (constants, dotted refs, tables) are not part
            // of the callable API surface — skip.
            _ => {}
        }
    }
    out
}

/// Resolve the `table_constructor` a module ultimately returns: either the
/// inline `return { … }` literal, the `local M = { … }` that a `return M`
/// names, or the table wrapped by `return setmetatable(M, mt)`.
fn returned_module_literal<'a>(root: tree_sitter::Node<'a>, source: &str) -> Option<tree_sitter::Node<'a>> {
    let mut ret = None;
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "return_statement" {
            ret = Some(child);
        }
    }
    let ret = ret?;
    let expr_list = {
        let mut c = ret.walk();
        let found = ret.children(&mut c).find(|n| n.kind() == "expression_list");
        found
    }?;
    let tail = {
        let mut last = None;
        let mut c = expr_list.walk();
        for n in expr_list.children(&mut c) {
            if n.is_named() {
                last = Some(n);
            }
        }
        last
    }?;
    resolve_returned_table(tail, root, source)
}

fn resolve_returned_table<'a>(
    tail: tree_sitter::Node<'a>,
    root: tree_sitter::Node<'a>,
    source: &str,
) -> Option<tree_sitter::Node<'a>> {
    match tail.kind() {
        "table_constructor" => Some(tail),
        "identifier" | "variable" => {
            let name = source[tail.byte_range()].trim();
            local_table_literal(root, source, name)
        }
        "function_call" => {
            let callee = {
                let mut c = tail.walk();
                let found = tail.children(&mut c).find(|n| n.is_named());
                found
            }?;
            if source[callee.byte_range()].trim() != "setmetatable" {
                return None;
            }
            let args = {
                let mut c = tail.walk();
                let found = tail.children(&mut c).find(|n| n.kind() == "arguments");
                found
            }?;
            let first = {
                let mut c = args.walk();
                let found = args.children(&mut c).find(|n| n.is_named());
                found
            }?;
            resolve_returned_table(first, root, source)
        }
        _ => None,
    }
}

/// Find the `table_constructor` literal bound to `local <name> = { … }`.
fn local_table_literal<'a>(
    node: tree_sitter::Node<'a>,
    source: &str,
    name: &str,
) -> Option<tree_sitter::Node<'a>> {
    if node.kind() == "variable_declaration" {
        let mut c = node.walk();
        for child in node.children(&mut c) {
            if child.kind() != "assignment_statement" {
                continue;
            }
            let (mut var_list, mut expr_list) = (None, None);
            let mut ac = child.walk();
            for sub in child.children(&mut ac) {
                match sub.kind() {
                    "variable_list" => var_list = Some(sub),
                    "expression_list" => expr_list = Some(sub),
                    _ => {}
                }
            }
            if let (Some(vl), Some(el)) = (var_list, expr_list) {
                let targets: Vec<_> = {
                    let mut vc = vl.walk();
                    vl.children(&mut vc).filter(|n| n.is_named()).collect()
                };
                let values: Vec<_> = {
                    let mut ec = el.walk();
                    el.children(&mut ec).filter(|n| n.is_named()).collect()
                };
                for (i, target) in targets.iter().enumerate() {
                    if matches!(target.kind(), "identifier" | "variable")
                        && source[target.byte_range()].trim() == name
                    {
                        if let Some(value) = values.get(i) {
                            if value.kind() == "table_constructor" {
                                return Some(*value);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = local_table_literal(child, source, name) {
            return Some(found);
        }
    }
    None
}

/// Collect parameter names from a `parameters` node, handling both untyped Lua
/// params (`(a, b)` → bare `identifier` children) and typed Luau params
/// (`(a: number)` → `parameter` wrappers whose first `identifier` is the name),
/// plus a trailing vararg `...`.
fn lua_param_names(params: tree_sitter::Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" => out.push(source[child.byte_range()].trim().to_string()),
            "parameter" => {
                let mut pc = child.walk();
                let id = child.children(&mut pc).find(|n| n.kind() == "identifier");
                if let Some(id) = id {
                    out.push(source[id.byte_range()].trim().to_string());
                }
            }
            "vararg_expression" | "spread" | "..." => out.push("...".to_string()),
            _ => {}
        }
    }
    out
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
    fn test_extract_lua_surface_from_module_table() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "lua/app.lua",
            r#"
local M = {}

function M.hello(name)
  return name
end

local function hidden(name)
  return name
end

return M
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_lua_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();
        assert!(names.iter().any(|name| name.ends_with(".hello")));
        assert!(!names.iter().any(|name| name.ends_with(".hidden")));
    }

    #[test]
    fn test_extract_lua_surface_from_return_table_literal() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "lua/app.lua",
            r#"
local function greet(name)
  return name
end

return { greet = greet }
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_lua_api_surface(&resolved, false, None).unwrap();
        assert!(surface
            .apis
            .iter()
            .any(|api| api.qualified_name.ends_with(".greet")));
    }

    /// fix-PW1-A3b: the literal-bound accumulator (`local M = { … } … return M`)
    /// and a MULTI-LINE inline `return { … }` literal both surface their
    /// function-valued fields — inline anonymous functions AND identifier
    /// aliases to module-local functions. Pre-fix the line-based heuristics
    /// returned 0 APIs for both shapes.
    #[test]
    fn test_extract_lua_surface_literal_bound_accumulator() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "lua/hash.lua",
            r#"
local function md5(message)
  return message
end

local sha = {
  md5 = md5,
  sha256 = function(message)
    return message
  end,
  VERSION = "1.0",
}

return sha
"#,
        );

        let resolved = ResolvedPackage {
            root_dir: dir.path().to_path_buf(),
            package_name: "example".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_lua_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();
        // inline anonymous function field
        assert!(
            names.iter().any(|n| n.ends_with(".sha256")),
            "inline function field `sha256` must surface; got {names:?}"
        );
        // identifier-alias field resolved to a module-local function
        assert!(
            names.iter().any(|n| n.ends_with(".md5")),
            "alias field `md5` must surface; got {names:?}"
        );
        // each function field appears exactly once (no double-emit)
        assert_eq!(
            names.iter().filter(|n| n.ends_with(".sha256")).count(),
            1,
            "sha256 must not be double-counted"
        );
    }
}
