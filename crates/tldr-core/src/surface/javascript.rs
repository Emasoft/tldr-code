//! JavaScript-specific API surface extraction.
//!
//! Extracts the complete public API surface from a JavaScript package by:
//! 1. Reading `node_modules/<pkg>/package.json` to find the `"main"` field
//! 2. Parsing `.js` / `.mjs` files with tree-sitter (shares the TS parser)
//! 3. Extracting every `export function`, `export class`, `export const`,
//!    `module.exports`, and `exports.X = ...` as a public API entry
//! 4. Parsing JSDoc `@param` and `@returns` tags for type information
//! 5. Detecting CommonJS and ES6 export patterns
//!
//! JavaScript reuses the TypeScript tree-sitter grammar and the same
//! `extract_from_tree` path in `ast/extract.rs`, since the JavaScript
//! language variant already dispatches to the TS extractor.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::{ClassInfo, Language};
use crate::TldrResult;

use super::language_profile::{is_noise_dir, is_noise_file, strip_layout_segments};
use super::resolve::public_entry_files_for_resolved_package;
use super::sort_apis_by_static_preference;
use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the complete API surface from a JavaScript package.
///
/// # Arguments
/// * `resolved` - The resolved package with root directory and metadata
/// * `include_private` - Whether to include non-exported APIs
/// * `limit` - Optional maximum number of APIs to extract
///
/// # Returns
/// * `ApiSurface` with all extracted API entries
pub fn extract_javascript_api_surface(
    resolved: &ResolvedPackage,
    include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();

    // Find all JavaScript source files, falling back to TS-backed sources when
    // a JS package is authored in TypeScript.
    let js_files = find_javascript_surface_files(&resolved.root_dir);

    // Extract from each file
    for file_path in &js_files {
        let file_apis = extract_from_javascript_file(
            file_path,
            &resolved.root_dir,
            &resolved.package_name,
            include_private,
        )?;
        apis.extend(file_apis);
    }

    let mut local_alias_apis = synthesize_js_local_export_aliases(
        &apis,
        &js_files,
        &resolved.root_dir,
        &resolved.package_name,
    );
    apis.append(&mut local_alias_apis);

    let mut alias_apis = synthesize_js_reexport_aliases(
        &apis,
        &js_files,
        &resolved.root_dir,
        &resolved.package_name,
    );
    apis.append(&mut alias_apis);

    if !resolved.is_pure_source {
        let public_entry_files =
            public_entry_files_for_resolved_package(&resolved.root_dir, Language::JavaScript);
        if !public_entry_files.is_empty() {
            apis.retain(|api| {
                api.location
                    .as_ref()
                    .is_some_and(|location| public_entry_files.contains(&location.file))
            });
        }
    }

    sort_apis_by_static_preference(&mut apis, "javascript");

    // Apply limit if specified
    if let Some(max) = limit {
        apis.truncate(max);
    }

    let total = apis.len();
    Ok(ApiSurface {
        package: resolved.package_name.clone(),
        language: "javascript".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

/// Extract API entries from a single JavaScript file.
fn extract_from_javascript_file(
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

    let parse_language = javascript_parse_language(file_path);
    let tree = parse(&source, parse_language)?;
    let module_info = extract_from_tree(&tree, &source, parse_language, file_path, Some(root_dir))?;

    let module_path = compute_js_module_path(file_path, root_dir, package_name);
    let relative_path = super::resolve::location_relative_path(file_path, root_dir);
    let flow_type_exports = collect_flow_type_exports(&source);

    let mut apis = Vec::new();

    // Extract top-level functions
    for func in &module_info.functions {
        if !include_private && !is_exported(&source, func.line_number as usize) {
            continue;
        }

        let qualified_name = format!("{}.{}", module_path, func.name);
        let params = convert_js_params(&func.params, &source, func.line_number as usize);
        let return_type = func
            .return_type
            .clone()
            .or_else(|| extract_jsdoc_return_type(&source, func.line_number as usize));

        let signature = Some(Signature {
            params: params.clone(),
            return_type: return_type.clone(),
            is_async: func.is_async,
            is_generator: false,
        });

        let example =
            generate_js_function_example(&module_path, &func.name, &params, return_type.as_deref());
        let triggers = extract_triggers(&func.name, func.docstring.as_deref());

        apis.push(ApiEntry {
            qualified_name,
            kind: ApiKind::Function,
            module: module_path.clone(),
            signature,
            docstring: func.docstring.clone().map(|d| truncate_docstring(&d)),
            example,
            triggers,
            is_property: false,
            return_type,
            location: Some(Location {
                file: relative_path.clone(),
                line: func.line_number as usize,
                column: None,
            }),
        });
    }

    // Extract classes with their methods
    for class in &module_info.classes {
        if flow_type_exports.contains(&class.name) {
            continue;
        }
        if !include_private && !is_exported(&source, class.line_number as usize) {
            continue;
        }

        let kind = determine_js_class_kind(class, &source);
        let qualified_name = format!("{}.{}", module_path, class.name);
        let triggers = extract_triggers(&class.name, class.docstring.as_deref());

        // Add the class itself
        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind,
            module: module_path.clone(),
            signature: None,
            docstring: class.docstring.clone().map(|d| truncate_docstring(&d)),
            example: generate_js_class_example(&module_path, &class.name),
            triggers: triggers.clone(),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: class.line_number as usize,
                column: None,
            }),
        });

        // Extract methods from the class
        for method in &class.methods {
            let method_qualified = format!("{}.{}", qualified_name, method.name);
            let is_static_method = is_static_declaration(&source, method.line_number as usize);
            let method_kind = if is_static_method {
                ApiKind::StaticMethod
            } else {
                ApiKind::Method
            };
            let params = convert_js_params(&method.params, &source, method.line_number as usize);
            let return_type = method
                .return_type
                .clone()
                .or_else(|| extract_jsdoc_return_type(&source, method.line_number as usize));

            let signature = Some(Signature {
                params: params.clone(),
                return_type: return_type.clone(),
                is_async: method.is_async,
                is_generator: false,
            });

            let method_triggers = extract_triggers(&method.name, method.docstring.as_deref());

            apis.push(ApiEntry {
                qualified_name: method_qualified,
                kind: method_kind,
                module: module_path.clone(),
                signature,
                docstring: method.docstring.clone().map(|d| truncate_docstring(&d)),
                example: None,
                triggers: method_triggers,
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

    // Extract constants from module_info
    for constant in &module_info.constants {
        if !include_private && !is_exported(&source, constant.line_number as usize) {
            continue;
        }

        let qualified_name = format!("{}.{}", module_path, constant.name);
        let triggers = extract_triggers(&constant.name, None);

        apis.push(ApiEntry {
            qualified_name,
            kind: ApiKind::Constant,
            module: module_path.clone(),
            signature: None,
            docstring: None,
            example: Some(format!("{}.{}", module_path, constant.name)),
            triggers,
            is_property: false,
            return_type: constant.field_type.clone(),
            location: Some(Location {
                file: relative_path.clone(),
                line: constant.line_number as usize,
                column: None,
            }),
        });
    }

    synthesize_commonjs_exports(&source, &mut apis, &module_path, &relative_path);

    // ESM default-export surface (CF2-S5): object-literal members
    // (`export default { a() {}, b }`, axios `lib/utils.js`) and the
    // decorated-instance idiom (`export default axios; axios.get = …`, axios
    // `lib/axios.js`). Both attach the module's whole public API to the default
    // export — invisible to the CommonJS/`export`-keyword scans above, so
    // `surface` reported zero APIs for these ESM modules.
    append_js_default_export_apis(
        tree.root_node(),
        &source,
        &module_info,
        &mut apis,
        &module_path,
        &relative_path,
    );

    // CF3-S5b: UMD/IIFE factory-return module exports (lodash `lodash.js`). The
    // whole library is wrapped in `;(function(){ … }.call(this))` and its public
    // surface is decorated onto the object an inner factory returns, then bound
    // via `<moduleRef>.exports = <id>`. None of the scans above descend into the
    // IIFE, so this resolver recovers those members (gated on module-reference
    // binding provenance to avoid false positives).
    append_js_umd_factory_apis(
        tree.root_node(),
        &source,
        &mut apis,
        &module_path,
        &relative_path,
    );

    // CFr-RW3: plain CommonJS decorated-instance exports (express
    // `lib/response.js`: `module.exports = res; res.status = …; res.send = …`).
    // The bound id is an `Object.create(...)` instance — not a top-level
    // function/class — so none of the scans above mint its ~22 decorated
    // methods. This resolver recovers them, gated on the literal `module.exports`
    // sink so a non-module `<x>.exports = bar` mints nothing.
    append_js_commonjs_instance_apis(
        tree.root_node(),
        &source,
        &mut apis,
        &module_path,
        &relative_path,
    );

    Ok(apis)
}

/// A member resolved from a module's `export default` (CF2-S5). `is_function`
/// is `true` only for directly function-valued members (method / arrow / fn
/// expression); identifier/shorthand members are upgraded to functions by the
/// caller when they name a known top-level function.
struct JsDefaultMember {
    name: String,
    params: Vec<String>,
    line: usize,
    is_function: bool,
}

/// Append the `export default` surface members to `apis`, deduped by qualified
/// name. Function-valued members (and identifier members that resolve to a
/// top-level function) become [`ApiKind::Function`]; everything else is a
/// [`ApiKind::Constant`] property of the default export. Shared with the
/// TypeScript frontend (`surface/typescript.rs`) — JS and TS use the same
/// tree-sitter grammar for `export default` object/instance idioms.
pub(super) fn append_js_default_export_apis(
    root: tree_sitter::Node,
    source: &str,
    module_info: &crate::types::ModuleInfo,
    apis: &mut Vec<ApiEntry>,
    module_path: &str,
    relative_path: &Path,
) {
    let members = collect_js_default_export_members(root, source);
    if members.is_empty() {
        return;
    }
    let fn_names: HashSet<&str> = module_info
        .functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let mut seen: HashSet<String> = apis.iter().map(|a| a.qualified_name.clone()).collect();

    for member in members {
        let qualified_name = format!("{}.{}", module_path, member.name);
        if !seen.insert(qualified_name.clone()) {
            continue;
        }
        let is_fn = member.is_function || fn_names.contains(member.name.as_str());
        let location = Some(Location {
            file: relative_path.to_path_buf(),
            line: member.line,
            column: None,
        });
        if is_fn {
            let params: Vec<Param> = member
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
            let example = generate_js_function_example(module_path, &member.name, &params, None);
            apis.push(ApiEntry {
                qualified_name,
                kind: ApiKind::Function,
                module: module_path.to_string(),
                signature: Some(Signature {
                    params,
                    return_type: None,
                    is_async: false,
                    is_generator: false,
                }),
                docstring: None,
                example,
                triggers: extract_triggers(&member.name, None),
                is_property: false,
                return_type: None,
                location,
            });
        } else {
            apis.push(ApiEntry {
                qualified_name,
                kind: ApiKind::Constant,
                module: module_path.to_string(),
                signature: None,
                docstring: None,
                example: Some(format!("{}.{}", module_path, member.name)),
                triggers: extract_triggers(&member.name, None),
                is_property: true,
                return_type: None,
                location,
            });
        }
    }
}

/// AST-resolve the members an ES module exposes through its `export default`.
/// Two idioms are recognized (both leave `apis` empty otherwise):
///   * object literal — `export default { a() {}, b: () => …, c }`
///   * decorated instance — `export default inst; inst.x = …; inst.y = …`
fn collect_js_default_export_members(root: tree_sitter::Node, source: &str) -> Vec<JsDefaultMember> {
    let mut default_value: Option<tree_sitter::Node> = None;
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "export_statement" && js_export_statement_is_default(child) {
            if let Some(v) = child.child_by_field_name("value") {
                default_value = Some(v);
            }
        }
    }
    let value = match default_value {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    match value.kind() {
        "object" => collect_js_object_literal_members(value, source, &mut out, &mut seen),
        "identifier" => {
            let inst = source[value.byte_range()].trim().to_string();
            collect_js_instance_member_assignments(root, source, &inst, &mut out, &mut seen);
        }
        _ => {}
    }
    out
}

/// True when an `export_statement` is `export default …` (carries a `default`
/// token child).
fn js_export_statement_is_default(node: tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    let is_default = node.children(&mut cursor).any(|c| c.kind() == "default");
    is_default
}

/// Expand an `export default { … }` object literal: `method_definition` and
/// function-valued `pair`s become functions; other `pair`s and
/// `shorthand_property_identifier`s become (potential) properties.
fn collect_js_object_literal_members(
    object: tree_sitter::Node,
    source: &str,
    out: &mut Vec<JsDefaultMember>,
    seen: &mut HashSet<String>,
) {
    let mut cursor = object.walk();
    for member in object.children(&mut cursor) {
        match member.kind() {
            "method_definition" => {
                let Some(name_node) = member.child_by_field_name("name") else {
                    continue;
                };
                let name = source[name_node.byte_range()].trim().to_string();
                if name.is_empty() || !seen.insert(name.clone()) {
                    continue;
                }
                out.push(JsDefaultMember {
                    name,
                    params: js_default_param_names(member, source),
                    line: member.start_position().row + 1,
                    is_function: true,
                });
            }
            "pair" => {
                let Some(key) = member.child_by_field_name("key") else {
                    continue;
                };
                let name = match key.kind() {
                    "property_identifier" => source[key.byte_range()].trim().to_string(),
                    "string" => source[key.byte_range()]
                        .trim_matches(|c| c == '"' || c == '\'')
                        .to_string(),
                    _ => continue,
                };
                if name.is_empty() || !seen.insert(name.clone()) {
                    continue;
                }
                let value = member.child_by_field_name("value");
                let is_function = value.map(js_is_function_value).unwrap_or(false);
                let params = value
                    .filter(|_| is_function)
                    .map(|v| js_default_param_names(v, source))
                    .unwrap_or_default();
                out.push(JsDefaultMember {
                    name,
                    params,
                    line: member.start_position().row + 1,
                    is_function,
                });
            }
            "shorthand_property_identifier" => {
                let name = source[member.byte_range()].trim().to_string();
                if name.is_empty() || !seen.insert(name.clone()) {
                    continue;
                }
                out.push(JsDefaultMember {
                    name,
                    params: Vec::new(),
                    line: member.start_position().row + 1,
                    is_function: false,
                });
            }
            _ => {}
        }
    }
}

/// Collect top-level `inst.member = <value>` assignments that decorate a
/// default-exported instance (`export default axios; axios.get = …`).
fn collect_js_instance_member_assignments(
    root: tree_sitter::Node,
    source: &str,
    inst: &str,
    out: &mut Vec<JsDefaultMember>,
    seen: &mut HashSet<String>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "expression_statement" {
            continue;
        }
        let Some(assign) = child.child(0) else {
            continue;
        };
        if assign.kind() != "assignment_expression" {
            continue;
        }
        let (Some(lhs), Some(rhs)) = (
            assign.child_by_field_name("left"),
            assign.child_by_field_name("right"),
        ) else {
            continue;
        };
        if lhs.kind() != "member_expression" {
            continue;
        }
        let (Some(obj), Some(prop)) = (
            lhs.child_by_field_name("object"),
            lhs.child_by_field_name("property"),
        ) else {
            continue;
        };
        // Only `inst.member` (a plain instance property), not nested member
        // chains like `inst.proto.x` or `Other.member`.
        if obj.kind() != "identifier" || source[obj.byte_range()].trim() != inst {
            continue;
        }
        if prop.kind() != "property_identifier" {
            continue;
        }
        let name = source[prop.byte_range()].trim().to_string();
        if name.is_empty() || !seen.insert(name.clone()) {
            continue;
        }
        let is_function = js_is_function_value(rhs);
        out.push(JsDefaultMember {
            name,
            params: if is_function {
                js_default_param_names(rhs, source)
            } else {
                Vec::new()
            },
            line: assign.start_position().row + 1,
            is_function,
        });
    }
}

// =============================================================================
// CF3-S5b: UMD / IIFE factory-return module-export resolution (lodash idiom)
// =============================================================================

/// Append the UMD/IIFE factory-return module-export surface of a whole-library
/// JS bundle (e.g. lodash `lodash.js`). See [`append_js_default_export_apis`]
/// for the ESM/CommonJS idioms; this handles the harder case where the entire
/// module is wrapped in `;(function(){ … }.call(this))`, its public surface is
/// decorated onto the object an inner factory `return`s, and that object is
/// bound to CommonJS via `<moduleRef>.exports = <id>`.
///
/// False-positive guard: a `<alias>.exports = <id>` assignment is treated as a
/// module-export sink only when `<alias>` is *provably* a module reference —
/// the literal `module`, or a local whose initializer structurally tests
/// `typeof module`/`typeof exports`. Binding-provenance, not a name allowlist.
fn append_js_umd_factory_apis(
    root: tree_sitter::Node,
    source: &str,
    apis: &mut Vec<ApiEntry>,
    module_path: &str,
    relative_path: &Path,
) {
    let body = match find_js_umd_iife_body(root) {
        Some(b) => b,
        None => return,
    };
    let module_refs = collect_js_umd_module_refs(body, source);
    let export_ids = collect_js_umd_sink_ids(body, source, &module_refs);
    if export_ids.is_empty() {
        return;
    }

    let mut seen: HashSet<String> = apis.iter().map(|a| a.qualified_name.clone()).collect();
    for export_id in export_ids {
        for member in resolve_js_umd_members(body, source, &export_id) {
            let qualified_name = format!("{}.{}", module_path, member.name);
            if !seen.insert(qualified_name.clone()) {
                continue;
            }
            let location = Some(Location {
                file: relative_path.to_path_buf(),
                line: member.line,
                column: None,
            });
            if member.is_function {
                let params: Vec<Param> = member
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
                let example =
                    generate_js_function_example(module_path, &member.name, &params, None);
                apis.push(ApiEntry {
                    qualified_name,
                    kind: ApiKind::Function,
                    module: module_path.to_string(),
                    signature: Some(Signature {
                        params,
                        return_type: None,
                        is_async: false,
                        is_generator: false,
                    }),
                    docstring: None,
                    example,
                    triggers: extract_triggers(&member.name, None),
                    is_property: false,
                    return_type: None,
                    location,
                });
            } else {
                apis.push(ApiEntry {
                    qualified_name,
                    kind: ApiKind::Constant,
                    module: module_path.to_string(),
                    signature: None,
                    docstring: None,
                    example: Some(format!("{}.{}", module_path, member.name)),
                    triggers: extract_triggers(&member.name, None),
                    is_property: true,
                    return_type: None,
                    location,
                });
            }
        }
    }
}

// =============================================================================
// CFr-RW3: plain CommonJS decorated-instance module-export resolution
// (express `lib/response.js`: `module.exports = res; res.status = …`).
// =============================================================================

/// Append the surface members a CommonJS module exposes by binding an identifier
/// to `module.exports` and then decorating it (`module.exports = res; res.x = …;
/// res.y = …`). Unlike the UMD resolver this sink is at the module top level, and
/// unlike `synthesize_commonjs_exports` the bound id need not be a top-level
/// function/class — it is typically a plain `Object.create(...)` instance whose
/// whole public API arrives via later member assignments.
///
/// Module-provenance gate (R2): the sink must be the literal `module.exports`
/// (object identifier `module`, property `exports`); a non-module
/// `<x>.exports = bar` is not a module-export sink and mints nothing.
fn append_js_commonjs_instance_apis(
    root: tree_sitter::Node,
    source: &str,
    apis: &mut Vec<ApiEntry>,
    module_path: &str,
    relative_path: &Path,
) {
    let export_ids = collect_js_commonjs_export_ids(root, source);
    if export_ids.is_empty() {
        return;
    }
    let mut seen: HashSet<String> = apis.iter().map(|a| a.qualified_name.clone()).collect();
    for export_id in export_ids {
        let mut members = Vec::new();
        let mut member_seen = HashSet::new();
        // Reuse the UMD decorated-member collector: it recursively resolves
        // `<export_id>.<member> = <value>` (including chained `a = b = fn`) and
        // classifies each value as function or property.
        js_collect_decorated_members(
            root,
            source,
            &export_id,
            root,
            &mut members,
            &mut member_seen,
        );
        for member in members {
            let qualified_name = format!("{}.{}", module_path, member.name);
            if !seen.insert(qualified_name) {
                continue;
            }
            push_js_resolved_member(&member, apis, module_path, relative_path);
        }
    }
}

/// Identifiers bound to a top-level `module.exports = <id>` sink, also handling
/// the chained alias form `exports = module.exports = <id>`.
fn collect_js_commonjs_export_ids(root: tree_sitter::Node, source: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "expression_statement" {
            continue;
        }
        if let Some(expr) = child.named_child(0) {
            js_collect_commonjs_export_id(expr, source, &mut ids);
        }
    }
    ids
}

/// Walk an assignment (and any chained right-hand assignment) for a
/// `module.exports = <identifier>` binding, pushing each bound id.
fn js_collect_commonjs_export_id(node: tree_sitter::Node, source: &str, ids: &mut Vec<String>) {
    if node.kind() != "assignment_expression" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if js_is_module_exports_target(left, source) && right.kind() == "identifier" {
        let id = source[right.byte_range()].trim().to_string();
        if !id.is_empty() && !ids.contains(&id) {
            ids.push(id);
        }
    }
    // Chained alias: `exports = module.exports = <id>` nests right-associatively.
    if right.kind() == "assignment_expression" {
        js_collect_commonjs_export_id(right, source, ids);
    }
}

/// True when `node` is the literal `module.exports` member target — the
/// provenance gate distinguishing a module-export sink from a non-module
/// `<x>.exports = …` assignment.
fn js_is_module_exports_target(node: tree_sitter::Node, source: &str) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let (Some(obj), Some(prop)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
    ) else {
        return false;
    };
    obj.kind() == "identifier"
        && source[obj.byte_range()].trim() == "module"
        && prop.kind() == "property_identifier"
        && source[prop.byte_range()].trim() == "exports"
}

/// Push a resolved [`JsDefaultMember`] onto `apis` as a function or property API
/// entry, mirroring the `export default` / UMD member shaping.
fn push_js_resolved_member(
    member: &JsDefaultMember,
    apis: &mut Vec<ApiEntry>,
    module_path: &str,
    relative_path: &Path,
) {
    let qualified_name = format!("{}.{}", module_path, member.name);
    let location = Some(Location {
        file: relative_path.to_path_buf(),
        line: member.line,
        column: None,
    });
    if member.is_function {
        let params: Vec<Param> = member
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
        let example = generate_js_function_example(module_path, &member.name, &params, None);
        apis.push(ApiEntry {
            qualified_name,
            kind: ApiKind::Function,
            module: module_path.to_string(),
            signature: Some(Signature {
                params,
                return_type: None,
                is_async: false,
                is_generator: false,
            }),
            docstring: None,
            example,
            triggers: extract_triggers(&member.name, None),
            is_property: false,
            return_type: None,
            location,
        });
    } else {
        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind: ApiKind::Constant,
            module: module_path.to_string(),
            signature: None,
            docstring: None,
            example: Some(qualified_name),
            triggers: extract_triggers(&member.name, None),
            is_property: true,
            return_type: None,
            location,
        });
    }
}

/// Unwrap nested `parenthesized_expression` wrappers to the innermost named node.
fn js_unwrap_parens(node: tree_sitter::Node) -> tree_sitter::Node {
    let mut n = node;
    while n.kind() == "parenthesized_expression" {
        let mut next = None;
        {
            let mut cursor = n.walk();
            for ch in n.children(&mut cursor) {
                if ch.is_named() {
                    next = Some(ch);
                    break;
                }
            }
        }
        match next {
            Some(ch) => n = ch,
            None => break,
        }
    }
    n
}

/// Locate the body of a top-level immediately-invoked function expression.
fn find_js_umd_iife_body(root: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "expression_statement" {
            continue;
        }
        let mut inner = child.walk();
        for expr in child.children(&mut inner) {
            if !expr.is_named() {
                continue;
            }
            if let Some(body) = js_iife_function_body(expr) {
                return Some(body);
            }
        }
    }
    None
}

/// Return the invoked function's body for an IIFE call (direct, parenthesized,
/// or `.call`/`.apply`).
fn js_iife_function_body(expr: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let call = js_unwrap_parens(expr);
    if call.kind() != "call_expression" {
        return None;
    }
    let callee = js_unwrap_parens(call.child_by_field_name("function")?);
    let fn_node = if js_is_function_value(callee) {
        callee
    } else if callee.kind() == "member_expression" {
        let obj = js_unwrap_parens(callee.child_by_field_name("object")?);
        if js_is_function_value(obj) {
            obj
        } else {
            return None;
        }
    } else {
        return None;
    };
    fn_node.child_by_field_name("body")
}

/// Identifiers bound to a module-detection initializer in the IIFE body's direct
/// statements — the provable CommonJS module references gating the export sink.
fn collect_js_umd_module_refs(body: tree_sitter::Node, source: &str) -> HashSet<String> {
    let mut refs = HashSet::new();
    let mut cursor = body.walk();
    for stmt in body.children(&mut cursor) {
        if !matches!(stmt.kind(), "variable_declaration" | "lexical_declaration") {
            continue;
        }
        let mut dc = stmt.walk();
        for decl in stmt.children(&mut dc) {
            if decl.kind() != "variable_declarator" {
                continue;
            }
            if let (Some(name), Some(value)) = (
                decl.child_by_field_name("name"),
                decl.child_by_field_name("value"),
            ) {
                if name.kind() == "identifier" && js_init_tests_module_global(value, source) {
                    refs.insert(source[name.byte_range()].trim().to_string());
                }
            }
        }
    }
    refs
}

/// True when `node`'s expression tree contains a `typeof module`/`typeof
/// exports` test, not descending into nested function scopes.
fn js_init_tests_module_global(node: tree_sitter::Node, source: &str) -> bool {
    if matches!(
        node.kind(),
        "function_expression" | "arrow_function" | "function" | "generator_function"
    ) {
        return false;
    }
    if node.kind() == "unary_expression" {
        let mut has_typeof = false;
        let mut cursor = node.walk();
        for ch in node.children(&mut cursor) {
            if ch.kind() == "typeof" {
                has_typeof = true;
            }
        }
        if has_typeof {
            if let Some(arg) = node.child_by_field_name("argument") {
                if arg.kind() == "identifier" {
                    let t = source[arg.byte_range()].trim();
                    if t == "module" || t == "exports" {
                        return true;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        if js_init_tests_module_global(ch, source) {
            return true;
        }
    }
    false
}

/// Scan the IIFE top-level scope (skipping nested function bodies) for module
/// export sinks `<moduleRef>.exports = <id>` and return each `<id>`.
fn collect_js_umd_sink_ids(
    body: tree_sitter::Node,
    source: &str,
    module_refs: &HashSet<String>,
) -> Vec<String> {
    let mut ids = Vec::new();
    js_walk_umd_sinks(body, source, module_refs, &mut ids);
    ids
}

fn js_walk_umd_sinks(
    node: tree_sitter::Node,
    source: &str,
    module_refs: &HashSet<String>,
    ids: &mut Vec<String>,
) {
    if matches!(
        node.kind(),
        "function_expression" | "arrow_function" | "function" | "generator_function"
    ) {
        return;
    }
    if node.kind() == "assignment_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if right.kind() == "identifier" && left.kind() == "member_expression" {
                if let (Some(obj), Some(prop)) = (
                    left.child_by_field_name("object"),
                    left.child_by_field_name("property"),
                ) {
                    if obj.kind() == "identifier"
                        && prop.kind() == "property_identifier"
                        && &source[prop.byte_range()] == "exports"
                    {
                        let obj_name = source[obj.byte_range()].trim();
                        if obj_name == "module" || module_refs.contains(obj_name) {
                            let id = source[right.byte_range()].trim().to_string();
                            if !ids.contains(&id) {
                                ids.push(id);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        js_walk_umd_sinks(ch, source, module_refs, ids);
    }
}

/// Resolve the exported object id to the members decorated onto it (factory
/// return object, decorated instance, or object literal).
fn resolve_js_umd_members(
    body: tree_sitter::Node,
    source: &str,
    export_id: &str,
) -> Vec<JsDefaultMember> {
    let init = match js_find_var_init(body, source, export_id) {
        Some(i) => js_unwrap_parens(i),
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    match init.kind() {
        "call_expression" => {
            let callee = match init.child_by_field_name("function") {
                Some(c) => c,
                None => return Vec::new(),
            };
            if callee.kind() != "identifier" {
                return Vec::new();
            }
            let factory_name = source[callee.byte_range()].trim();
            let factory = match js_find_function_node(body, source, factory_name) {
                Some(f) => f,
                None => return Vec::new(),
            };
            let factory_body = match factory.child_by_field_name("body") {
                Some(b) => b,
                None => return Vec::new(),
            };
            let ret = match js_find_factory_return_ident(factory_body, source) {
                Some(r) => r,
                None => return Vec::new(),
            };
            js_collect_decorated_members(
                factory_body,
                source,
                &ret,
                factory_body,
                &mut out,
                &mut seen,
            );
        }
        "identifier" => {
            let obj = source[init.byte_range()].trim().to_string();
            js_collect_decorated_members(body, source, &obj, body, &mut out, &mut seen);
        }
        _ => {}
    }
    out
}

/// Find the initializer value of `var <name> = <value>` anywhere in `scope`.
fn js_find_var_init<'a>(
    scope: tree_sitter::Node<'a>,
    source: &str,
    name: &str,
) -> Option<tree_sitter::Node<'a>> {
    if scope.kind() == "variable_declarator" {
        if let (Some(nm), Some(val)) = (
            scope.child_by_field_name("name"),
            scope.child_by_field_name("value"),
        ) {
            if nm.kind() == "identifier" && source[nm.byte_range()].trim() == name {
                return Some(val);
            }
        }
    }
    let mut cursor = scope.walk();
    for ch in scope.children(&mut cursor) {
        if let Some(found) = js_find_var_init(ch, source, name) {
            return Some(found);
        }
    }
    None
}

/// Find the function node (declaration / `var f = function|arrow`) named `name`.
fn js_find_function_node<'a>(
    scope: tree_sitter::Node<'a>,
    source: &str,
    name: &str,
) -> Option<tree_sitter::Node<'a>> {
    if scope.kind() == "function_declaration" || scope.kind() == "generator_function_declaration" {
        if let Some(nm) = scope.child_by_field_name("name") {
            if source[nm.byte_range()].trim() == name {
                return Some(scope);
            }
        }
    }
    if scope.kind() == "variable_declarator" {
        if let (Some(nm), Some(val)) = (
            scope.child_by_field_name("name"),
            scope.child_by_field_name("value"),
        ) {
            if nm.kind() == "identifier" && source[nm.byte_range()].trim() == name {
                let val = js_unwrap_parens(val);
                if js_is_function_value(val) {
                    return Some(val);
                }
            }
        }
    }
    let mut cursor = scope.walk();
    for ch in scope.children(&mut cursor) {
        if let Some(found) = js_find_function_node(ch, source, name) {
            return Some(found);
        }
    }
    None
}

/// Identifier a factory body `return`s, ignoring nested function scopes.
fn js_find_factory_return_ident(body: tree_sitter::Node, source: &str) -> Option<String> {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        match child.kind() {
            "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function" => continue,
            "return_statement" => {
                let mut rc = child.walk();
                for rchild in child.children(&mut rc) {
                    if rchild.kind() == "identifier" {
                        return Some(source[rchild.byte_range()].trim().to_string());
                    }
                }
            }
            _ => {
                if let Some(found) = js_find_factory_return_ident(child, source) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Collect `<obj_name>.<member> = <value>` assignments within `scope`,
/// classifying each value as a function (direct or an identifier naming a
/// function in `lookup_scope`) or a plain property.
fn js_collect_decorated_members(
    scope: tree_sitter::Node,
    source: &str,
    obj_name: &str,
    lookup_scope: tree_sitter::Node,
    out: &mut Vec<JsDefaultMember>,
    seen: &mut HashSet<String>,
) {
    if scope.kind() == "assignment_expression" {
        if let (Some(left), Some(right)) = (
            scope.child_by_field_name("left"),
            scope.child_by_field_name("right"),
        ) {
            if left.kind() == "member_expression" {
                if let (Some(obj), Some(prop)) = (
                    left.child_by_field_name("object"),
                    left.child_by_field_name("property"),
                ) {
                    if obj.kind() == "identifier"
                        && source[obj.byte_range()].trim() == obj_name
                        && prop.kind() == "property_identifier"
                    {
                        let name = source[prop.byte_range()].trim().to_string();
                        if !name.is_empty() && seen.insert(name.clone()) {
                            let (is_function, params) =
                                js_classify_umd_member(right, source, lookup_scope);
                            out.push(JsDefaultMember {
                                name,
                                params,
                                line: scope.start_position().row + 1,
                                is_function,
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cursor = scope.walk();
    for ch in scope.children(&mut cursor) {
        js_collect_decorated_members(ch, source, obj_name, lookup_scope, out, seen);
    }
}

/// Classify a decorated-member RHS value, returning `(is_function, params)`.
fn js_classify_umd_member(
    value: tree_sitter::Node,
    source: &str,
    lookup_scope: tree_sitter::Node,
) -> (bool, Vec<String>) {
    if js_is_function_value(value) {
        return (true, js_default_param_names(value, source));
    }
    if value.kind() == "identifier" {
        let name = source[value.byte_range()].trim();
        if let Some(fnode) = js_find_function_node(lookup_scope, source, name) {
            return (true, js_default_param_names(fnode, source));
        }
    }
    (false, Vec::new())
}

/// True when a node is a JS/TS function value (function expression, arrow, or
/// generator).
fn js_is_function_value(node: tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "arrow_function" | "function" | "generator_function"
    )
}

/// Collect parameter binding names from a function/arrow node — the
/// parenthesized `parameters` list or the parenthesis-free single arrow
/// `parameter` (`x => …`).
fn js_default_param_names(fn_node: tree_sitter::Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(params) = fn_node.child_by_field_name("parameters") {
        let mut c = params.walk();
        for child in params.children(&mut c) {
            if child.is_named() {
                if let Some(name) = js_pattern_identifier(child, source) {
                    names.push(name);
                }
            }
        }
    } else if let Some(p) = fn_node.child_by_field_name("parameter") {
        if let Some(name) = js_pattern_identifier(p, source) {
            names.push(name);
        }
    }
    names
}

/// Leftmost binding identifier of a parameter pattern node (handles destructured
/// `{ a }` / `[ b ]` / defaulted `c = 1` patterns by descending to the first
/// `identifier`).
fn js_pattern_identifier(node: tree_sitter::Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(source[node.byte_range()].trim().to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = js_pattern_identifier(child, source) {
            return Some(found);
        }
    }
    None
}

fn javascript_parse_language(file_path: &Path) -> Language {
    match file_path.extension().and_then(|ext| ext.to_str()) {
        Some("ts" | "tsx") => Language::TypeScript,
        _ => Language::JavaScript,
    }
}

fn collect_flow_type_exports(source: &str) -> HashSet<String> {
    let mut names = HashSet::new();

    for line in source.lines() {
        let trimmed = strip_js_line_comment(line).trim();
        for prefix in ["export type ", "export interface ", "type ", "interface "] {
            let Some(rest) = trimmed.strip_prefix(prefix) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }

    names
}

#[derive(Debug)]
enum JsReexport {
    Named {
        from_module: String,
        original: String,
        exported_as: String,
        line: usize,
    },
    All {
        from_module: String,
        line: usize,
    },
}

#[derive(Debug)]
struct JsImportBinding {
    local_name: String,
    imported_name: Option<String>,
    from_module: String,
}

fn synthesize_js_local_export_aliases(
    apis: &[ApiEntry],
    js_files: &[PathBuf],
    root_dir: &Path,
    package_name: &str,
) -> Vec<ApiEntry> {
    let mut aliases = Vec::new();
    let mut seen_names: HashSet<String> =
        apis.iter().map(|api| api.qualified_name.clone()).collect();

    for file_path in js_files {
        let Ok(source) = std::fs::read_to_string(file_path) else {
            continue;
        };
        let import_bindings = parse_js_import_bindings(&source, file_path, root_dir, package_name);
        if import_bindings.is_empty() {
            continue;
        }

        let module_path = compute_js_module_path(file_path, root_dir, package_name);
        let relative_path = super::resolve::location_relative_path(file_path, root_dir);

        for (statement, line) in collect_js_export_statements(&source) {
            let trimmed = statement.trim();
            let Some(specifiers) = trimmed
                .strip_prefix("export {")
                .or_else(|| trimmed.strip_prefix("export{"))
            else {
                continue;
            };
            let Some((specifiers, rest)) = specifiers.split_once('}') else {
                continue;
            };
            if rest.contains("from ") {
                continue;
            }

            for specifier in specifiers.split(',') {
                let specifier = specifier.trim();
                if specifier.is_empty() {
                    continue;
                }

                let (local_name, exported_as) = specifier
                    .split_once(" as ")
                    .map_or((specifier, specifier), |(left, right)| {
                        (left.trim(), right.trim())
                    });
                let Some(binding) = import_bindings
                    .iter()
                    .find(|binding| binding.local_name == local_name)
                else {
                    continue;
                };

                let original = binding.imported_name.as_deref().unwrap_or(local_name);
                let appended = append_js_alias_family(
                    &mut aliases,
                    &mut seen_names,
                    apis,
                    &binding.from_module,
                    original,
                    exported_as,
                    &module_path,
                    &relative_path,
                    line,
                );
                if !appended {
                    let placeholder = synthesize_js_imported_runtime_placeholder(
                        &module_path,
                        original,
                        exported_as,
                        &relative_path,
                        line,
                    );
                    if seen_names.insert(placeholder.qualified_name.clone()) {
                        aliases.push(placeholder);
                    }
                }
            }
        }
    }

    aliases.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    aliases
}

fn synthesize_js_reexport_aliases(
    apis: &[ApiEntry],
    js_files: &[PathBuf],
    root_dir: &Path,
    package_name: &str,
) -> Vec<ApiEntry> {
    let mut aliases = Vec::new();
    let mut seen_names: HashSet<String> =
        apis.iter().map(|api| api.qualified_name.clone()).collect();

    for file_path in js_files {
        if compute_js_module_path(file_path, root_dir, package_name) != package_name {
            continue;
        }

        let Ok(source) = std::fs::read_to_string(file_path) else {
            continue;
        };
        let relative_path = super::resolve::location_relative_path(file_path, root_dir);

        for reexport in parse_js_reexports(&source, file_path, root_dir, package_name) {
            match reexport {
                JsReexport::Named {
                    from_module,
                    original,
                    exported_as,
                    line,
                } => {
                    append_js_alias_family(
                        &mut aliases,
                        &mut seen_names,
                        apis,
                        &from_module,
                        &original,
                        &exported_as,
                        package_name,
                        &relative_path,
                        line,
                    );
                }
                JsReexport::All { from_module, line } => {
                    for symbol in top_level_js_symbols(apis, &from_module) {
                        append_js_alias_family(
                            &mut aliases,
                            &mut seen_names,
                            apis,
                            &from_module,
                            &symbol,
                            &symbol,
                            package_name,
                            &relative_path,
                            line,
                        );
                    }
                }
            }
        }

        for from_module in
            parse_js_commonjs_entrypoint_forwarders(&source, file_path, root_dir, package_name)
        {
            append_js_module_forward_aliases(
                &mut aliases,
                &mut seen_names,
                apis,
                &from_module,
                package_name,
                &relative_path,
            );
        }
    }

    aliases.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    aliases
}

fn parse_js_reexports(
    source: &str,
    entrypoint_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> Vec<JsReexport> {
    let mut reexports = Vec::new();
    let export_statements = collect_js_export_statements(source);

    for (statement, line) in export_statements {
        let trimmed = statement.trim();
        if trimmed.starts_with("export * from ") {
            if let Some(from_module) = parse_js_reexport_target(
                trimmed,
                "export * from ",
                entrypoint_path,
                root_dir,
                package_name,
            ) {
                reexports.push(JsReexport::All { from_module, line });
            }
            continue;
        }

        if let Some(specifiers) = trimmed
            .strip_prefix("export {")
            .or_else(|| trimmed.strip_prefix("export{"))
        {
            let Some((specifiers, rest)) = specifiers.split_once('}') else {
                continue;
            };
            let Some(from_module) = parse_js_reexport_target(
                rest.trim(),
                "from ",
                entrypoint_path,
                root_dir,
                package_name,
            ) else {
                continue;
            };

            for specifier in specifiers.split(',') {
                let specifier = specifier.trim();
                if specifier.is_empty() {
                    continue;
                }

                let (original, exported_as) = specifier
                    .split_once(" as ")
                    .map_or((specifier, specifier), |(left, right)| {
                        (left.trim(), right.trim())
                    });
                if original.is_empty() || exported_as.is_empty() {
                    continue;
                }

                reexports.push(JsReexport::Named {
                    from_module: from_module.clone(),
                    original: original.to_string(),
                    exported_as: exported_as.to_string(),
                    line,
                });
            }
        }
    }

    reexports
}

fn collect_js_export_statements(source: &str) -> Vec<(String, usize)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut statements = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let trimmed = strip_js_line_comment(lines[index]).trim().to_string();
        if !(trimmed.starts_with("export * from ")
            || trimmed.starts_with("export {")
            || trimmed.starts_with("export{"))
        {
            index += 1;
            continue;
        }

        let start_line = index + 1;
        let mut statement = trimmed;
        index += 1;

        while index < lines.len()
            && !(statement.contains(" from ")
                || statement.contains(" from'")
                || statement.contains(" from\""))
        {
            let next = strip_js_line_comment(lines[index]).trim();
            if !next.is_empty() {
                if !statement.is_empty() {
                    statement.push(' ');
                }
                statement.push_str(next);
            }
            index += 1;
        }

        while index < lines.len() && !statement.contains('}') {
            let next = strip_js_line_comment(lines[index]).trim();
            if !next.is_empty() {
                if !statement.is_empty() {
                    statement.push(' ');
                }
                statement.push_str(next);
            }
            index += 1;
        }

        statements.push((statement, start_line));
    }

    statements
}

fn collect_js_import_statements(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut statements = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let trimmed = strip_js_line_comment(lines[index]).trim().to_string();
        if !trimmed.starts_with("import ") {
            index += 1;
            continue;
        }

        let mut statement = trimmed;
        index += 1;

        while index < lines.len()
            && !(statement.contains(" from ")
                || statement.contains(" from'")
                || statement.contains(" from\"")
                || statement.ends_with(';'))
        {
            let next = strip_js_line_comment(lines[index]).trim();
            if !next.is_empty() {
                if !statement.is_empty() {
                    statement.push(' ');
                }
                statement.push_str(next);
            }
            index += 1;
        }

        statements.push(statement);
    }

    statements
}

fn parse_js_import_bindings(
    source: &str,
    file_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> Vec<JsImportBinding> {
    let mut bindings = Vec::new();

    for statement in collect_js_import_statements(source) {
        let trimmed = statement.trim().trim_end_matches(';').trim();
        let Some((imports, rest)) = trimmed
            .strip_prefix("import ")
            .and_then(|body| body.split_once(" from "))
        else {
            continue;
        };
        let specifier = rest.trim().trim_matches('"').trim_matches('\'');
        let Some(from_module) =
            resolve_js_reexport_module(file_path, root_dir, package_name, specifier)
        else {
            continue;
        };

        let imports = imports.trim();
        if let Some(named) = imports
            .strip_prefix('{')
            .and_then(|body| body.strip_suffix('}'))
        {
            for item in named.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let (imported_name, local_name) = item
                    .split_once(" as ")
                    .map_or((item, item), |(left, right)| (left.trim(), right.trim()));
                if imported_name.is_empty() || local_name.is_empty() {
                    continue;
                }
                bindings.push(JsImportBinding {
                    local_name: local_name.to_string(),
                    imported_name: Some(imported_name.to_string()),
                    from_module: from_module.clone(),
                });
            }
            continue;
        }

        if let Some(namespace) = imports.strip_prefix("* as ") {
            let local_name = namespace.trim();
            if !local_name.is_empty() {
                bindings.push(JsImportBinding {
                    local_name: local_name.to_string(),
                    imported_name: None,
                    from_module: from_module.clone(),
                });
            }
            continue;
        }

        let local_name = imports.trim();
        if !local_name.is_empty() {
            bindings.push(JsImportBinding {
                local_name: local_name.to_string(),
                imported_name: Some("default".to_string()),
                from_module,
            });
        }
    }

    bindings
}

fn parse_js_reexport_target(
    statement: &str,
    prefix: &str,
    entrypoint_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> Option<String> {
    let rest = statement.strip_prefix(prefix)?.trim();
    let specifier = rest
        .trim_end_matches(';')
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    resolve_js_reexport_module(entrypoint_path, root_dir, package_name, specifier)
}

fn parse_js_commonjs_entrypoint_forwarders(
    source: &str,
    entrypoint_path: &Path,
    root_dir: &Path,
    package_name: &str,
) -> Vec<String> {
    let mut modules = Vec::new();

    for line in source.lines() {
        let trimmed = strip_js_line_comment(line)
            .trim()
            .trim_end_matches(';')
            .trim();
        let rhs = trimmed
            .strip_prefix("module.exports = ")
            .or_else(|| trimmed.strip_prefix("exports = module.exports = "));

        let Some(rhs) = rhs else {
            continue;
        };

        if let Some(specifier) = parse_local_require_target(rhs) {
            if let Some(from_module) =
                resolve_js_reexport_module(entrypoint_path, root_dir, package_name, &specifier)
            {
                modules.push(from_module);
            }
        }
    }

    modules.sort();
    modules.dedup();
    modules
}

fn resolve_js_reexport_module(
    entrypoint_path: &Path,
    root_dir: &Path,
    package_name: &str,
    specifier: &str,
) -> Option<String> {
    if !specifier.starts_with('.') {
        return None;
    }

    let base_dir = entrypoint_path.parent().unwrap_or(root_dir);
    let target = resolve_existing_js_reexport_path(base_dir, specifier)
        .unwrap_or_else(|| normalize_js_reexport_path(&base_dir.join(specifier)));
    Some(compute_js_module_path(&target, root_dir, package_name))
}

fn normalize_js_reexport_path(path: &Path) -> PathBuf {
    path.components()
        .fold(PathBuf::new(), |mut normalized, component| {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
            normalized
        })
}

fn resolve_existing_js_reexport_path(base_dir: &Path, specifier: &str) -> Option<PathBuf> {
    let base = normalize_js_reexport_path(&base_dir.join(specifier));
    let mut candidates = vec![
        base.clone(),
        base.with_extension("js"),
        base.with_extension("mjs"),
        base.with_extension("cjs"),
    ];
    candidates.push(base.join("index.js"));
    candidates.push(base.join("index.mjs"));
    candidates.push(base.join("index.cjs"));
    candidates.into_iter().find(|candidate| candidate.exists())
}

fn top_level_js_symbols(apis: &[ApiEntry], from_module: &str) -> Vec<String> {
    let prefix = format!("{from_module}.");
    let mut symbols: Vec<String> = apis
        .iter()
        .filter_map(|api| {
            api.qualified_name
                .strip_prefix(&prefix)
                .and_then(|suffix| suffix.split('.').next())
                .filter(|segment| !segment.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect();
    symbols.sort();
    symbols.dedup();
    symbols
}

#[allow(clippy::too_many_arguments)]
fn append_js_alias_family(
    aliases: &mut Vec<ApiEntry>,
    seen_names: &mut HashSet<String>,
    apis: &[ApiEntry],
    from_module: &str,
    original: &str,
    exported_as: &str,
    package_name: &str,
    entrypoint_relative_path: &Path,
    line: usize,
) -> bool {
    let from_prefix = format!("{from_module}.{original}");
    let to_prefix = format!("{package_name}.{exported_as}");
    let mut appended = false;

    for api in apis.iter().filter(|candidate| {
        candidate.qualified_name == from_prefix
            || candidate
                .qualified_name
                .starts_with(&format!("{from_prefix}."))
    }) {
        let aliased_name = api.qualified_name.replacen(&from_prefix, &to_prefix, 1);
        if !seen_names.insert(aliased_name.clone()) {
            continue;
        }

        let mut alias = api.clone();
        alias.qualified_name = aliased_name;
        alias.module = package_name.to_string();
        alias.example = alias
            .example
            .as_ref()
            .map(|example| example.replacen(from_module, package_name, 1));
        alias.location = Some(Location {
            file: entrypoint_relative_path.to_path_buf(),
            line,
            column: None,
        });
        aliases.push(alias);
        appended = true;
    }

    appended
}

fn append_js_module_forward_aliases(
    aliases: &mut Vec<ApiEntry>,
    seen_names: &mut HashSet<String>,
    apis: &[ApiEntry],
    from_module: &str,
    package_name: &str,
    entrypoint_relative_path: &Path,
) {
    for api in apis.iter().filter(|candidate| {
        candidate.qualified_name == from_module
            || candidate
                .qualified_name
                .starts_with(&format!("{from_module}."))
    }) {
        let aliased_name = if api.qualified_name == from_module {
            package_name.to_string()
        } else {
            api.qualified_name
                .replacen(&format!("{from_module}."), &format!("{package_name}."), 1)
        };

        if !seen_names.insert(aliased_name.clone()) {
            continue;
        }

        let mut alias = api.clone();
        alias.qualified_name = aliased_name;
        alias.module = package_name.to_string();
        alias.example =
            rewrite_js_alias_example(alias.example.as_deref(), from_module, package_name);
        alias.location = Some(Location {
            file: entrypoint_relative_path.to_path_buf(),
            line: 1,
            column: None,
        });
        aliases.push(alias);
    }
}

fn synthesize_commonjs_exports(
    source: &str,
    apis: &mut Vec<ApiEntry>,
    module_path: &str,
    relative_path: &Path,
) {
    let mut seen: HashSet<String> = apis.iter().map(|api| api.qualified_name.clone()).collect();

    for (index, line) in source.lines().enumerate() {
        let trimmed = strip_js_line_comment(line)
            .trim()
            .trim_end_matches(';')
            .trim();
        let line_number = index + 1;

        if let Some(rhs) = trimmed
            .strip_prefix("exports = module.exports = ")
            .or_else(|| trimmed.strip_prefix("module.exports = "))
        {
            let rhs = rhs.trim();
            if let Some(identifier) = parse_export_rhs_identifier(rhs) {
                if let Some(api) = find_top_level_js_api(apis, module_path, &identifier) {
                    let alias = clone_js_api_alias(
                        api,
                        module_path.to_string(),
                        module_path.to_string(),
                        relative_path,
                        line_number,
                    );
                    if seen.insert(alias.qualified_name.clone()) {
                        apis.push(alias);
                    }
                }
            }
        }

        if let Some((export_name, rhs)) = parse_js_named_commonjs_export(trimmed) {
            let qualified_name = format!("{module_path}.{export_name}");
            if seen.contains(&qualified_name) {
                continue;
            }

            let alias = if let Some(identifier) = parse_export_rhs_identifier(rhs) {
                find_top_level_js_api(apis, module_path, &identifier).map(|api| {
                    clone_js_api_alias(
                        api,
                        qualified_name.clone(),
                        module_path.to_string(),
                        relative_path,
                        line_number,
                    )
                })
            } else {
                None
            };

            let api = alias.unwrap_or_else(|| {
                synthesize_js_named_export_placeholder(
                    module_path,
                    export_name,
                    rhs,
                    relative_path,
                    line_number,
                )
            });

            if seen.insert(api.qualified_name.clone()) {
                apis.push(api);
            }
        }
    }
}

fn parse_js_named_commonjs_export(statement: &str) -> Option<(&str, &str)> {
    let rest = statement
        .strip_prefix("exports.")
        .or_else(|| statement.strip_prefix("module.exports."))?;
    let (lhs, rhs) = rest.split_once('=')?;
    let export_name = lhs.trim();
    if export_name.is_empty()
        || export_name.contains('.')
        || !export_name
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '$')
    {
        return None;
    }
    Some((export_name, rhs.trim()))
}

fn parse_export_rhs_identifier(rhs: &str) -> Option<String> {
    if rhs.starts_with("require(") || rhs.contains('(') || rhs.contains('{') || rhs.contains('[') {
        return None;
    }

    let candidate = rhs.trim();
    if candidate.is_empty()
        || candidate.contains('.')
        || candidate.contains(' ')
        || !candidate
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '$')
    {
        return None;
    }

    Some(candidate.to_string())
}

fn parse_local_require_target(rhs: &str) -> Option<String> {
    let require_call = rhs.strip_prefix("require(")?.trim();
    let require_call = require_call.strip_suffix(')')?.trim();
    let specifier = require_call.trim_matches('"').trim_matches('\'');
    specifier.starts_with('.').then(|| specifier.to_string())
}

fn find_top_level_js_api<'a>(
    apis: &'a [ApiEntry],
    module_path: &str,
    name: &str,
) -> Option<&'a ApiEntry> {
    let qualified_name = format!("{module_path}.{name}");
    apis.iter().find(|api| api.qualified_name == qualified_name)
}

fn clone_js_api_alias(
    api: &ApiEntry,
    qualified_name: String,
    module: String,
    relative_path: &Path,
    line_number: usize,
) -> ApiEntry {
    let mut alias = api.clone();
    alias.qualified_name = qualified_name.clone();
    alias.module = module.clone();
    alias.example =
        rewrite_js_alias_example(alias.example.as_deref(), &api.module, &qualified_name);
    alias.location = Some(Location {
        file: relative_path.to_path_buf(),
        line: line_number,
        column: None,
    });
    if qualified_name == module && alias.kind == ApiKind::Function {
        alias.example = alias.signature.as_ref().map(|signature| {
            let args: Vec<String> = signature
                .params
                .iter()
                .map(|param| js_example_for_type(param.type_annotation.as_deref()))
                .collect();
            format!("const result = {}({});", module, args.join(", "))
        });
    }
    alias
}

fn rewrite_js_alias_example(
    example: Option<&str>,
    from_prefix: &str,
    to_prefix: &str,
) -> Option<String> {
    example.map(|value| value.replacen(from_prefix, to_prefix, 1))
}

fn synthesize_js_named_export_placeholder(
    module_path: &str,
    export_name: &str,
    rhs: &str,
    relative_path: &Path,
    line_number: usize,
) -> ApiEntry {
    let kind = if export_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_uppercase())
    {
        ApiKind::Class
    } else if rhs.contains("require(") || rhs.contains('.') {
        ApiKind::Function
    } else {
        ApiKind::Constant
    };

    ApiEntry {
        qualified_name: format!("{module_path}.{export_name}"),
        kind,
        module: module_path.to_string(),
        signature: None,
        docstring: None,
        example: Some(format!("{}.{}", module_path, export_name)),
        triggers: extract_triggers(export_name, None),
        is_property: true,
        return_type: None,
        location: Some(Location {
            file: relative_path.to_path_buf(),
            line: line_number,
            column: None,
        }),
    }
}

fn synthesize_js_imported_runtime_placeholder(
    module_path: &str,
    original: &str,
    exported_as: &str,
    relative_path: &Path,
    line_number: usize,
) -> ApiEntry {
    let kind = if original.chars().all(|ch| !ch.is_lowercase() || ch == '_') {
        ApiKind::Constant
    } else if exported_as
        .chars()
        .next()
        .is_some_and(|ch| ch.is_uppercase())
    {
        ApiKind::Class
    } else {
        ApiKind::Function
    };

    let example = match kind {
        ApiKind::Function => Some(format!("const result = {}.{}();", module_path, exported_as)),
        ApiKind::Class => generate_js_class_example(module_path, exported_as),
        _ => Some(format!("{}.{}", module_path, exported_as)),
    };

    ApiEntry {
        qualified_name: format!("{}.{}", module_path, exported_as),
        kind,
        module: module_path.to_string(),
        signature: None,
        docstring: None,
        example,
        triggers: extract_triggers(exported_as, None),
        is_property: matches!(kind, ApiKind::Constant | ApiKind::Property),
        return_type: None,
        location: Some(Location {
            file: relative_path.to_path_buf(),
            line: line_number,
            column: None,
        }),
    }
}

fn strip_js_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(before, _)| before)
}

// ============================================================================
// Helper functions
// ============================================================================

/// Compute module path from a JavaScript file path relative to the root.
///
/// Examples:
/// - `src/index.js` in package "express" -> "express"
/// - `src/router.js` in package "express" -> "express.router"
/// - `lib/utils.mjs` in package "mylib" -> "mylib.utils"
fn compute_js_module_path(file_path: &Path, root_dir: &Path, package_name: &str) -> String {
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let stem = relative.with_extension("");
    let stem_str = stem.to_string_lossy();
    let stem_path: &str = stem_str.as_ref();

    let filtered = strip_layout_segments(Language::JavaScript, Path::new(stem_path));

    if filtered.is_empty() {
        package_name.to_string()
    } else {
        format!("{}.{}", package_name, filtered.join("."))
    }
}

/// Check if a declaration at a given line is exported (ES6 or CommonJS).
///
/// Looks for:
/// - `export function ...` / `export class ...` / `export const ...`
/// - `export default ...`
/// - `module.exports = ...`
/// - `exports.X = ...`
fn is_exported(source: &str, line_number: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    if line_number == 0 || line_number > lines.len() {
        return false;
    }

    let line = lines[line_number - 1].trim();

    // ES6 exports
    if line.starts_with("export ")
        || line.starts_with("export{")
        || line.starts_with("export default")
    {
        return true;
    }

    // CommonJS: module.exports at top level
    if line.starts_with("module.exports") || line.starts_with("exports.") {
        return true;
    }

    // Check if the function/class name appears in a later module.exports or exports.X line
    // This handles the pattern: function foo() { ... } \n module.exports = { foo };
    // For this we scan the entire source for CommonJS export references
    if let Some(name) = extract_name_from_line(line) {
        for src_line in source.lines() {
            let trimmed = src_line.trim();
            if (trimmed.starts_with("module.exports")
                || trimmed.starts_with("exports =")
                || trimmed.starts_with("exports="))
                && trimmed.contains(&name)
            {
                return true;
            }
            if trimmed.starts_with("exports.") && trimmed.contains(&name) {
                return true;
            }
        }
    }

    false
}

/// Extract a function or class name from a declaration line.
fn extract_name_from_line(line: &str) -> Option<String> {
    let trimmed = line
        .trim()
        .trim_start_matches("export ")
        .trim_start_matches("default ")
        .trim_start_matches("async ");

    if trimmed.starts_with("function ") || trimmed.starts_with("function*(") {
        let rest = trimmed
            .trim_start_matches("function")
            .trim_start_matches('*')
            .trim();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }

    if trimmed.starts_with("class ") {
        let rest = trimmed.trim_start_matches("class").trim();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }

    if trimmed.starts_with("const ") || trimmed.starts_with("let ") || trimmed.starts_with("var ") {
        let rest = trimmed.split_once(' ').map(|x| x.1).unwrap_or("");
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }

    None
}

/// Determine the kind of a JavaScript class definition.
fn determine_js_class_kind(_class: &ClassInfo, _source: &str) -> ApiKind {
    // JavaScript only has classes (no interfaces, enums, or type aliases)
    ApiKind::Class
}

/// Check if a line declares a static member.
fn is_static_declaration(source: &str, line_number: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    if line_number == 0 || line_number > lines.len() {
        return false;
    }
    let line = lines[line_number - 1].trim();
    line.starts_with("static ") || line.contains(" static ")
}

/// Convert function parameters from `Vec<String>` to API surface Params.
///
/// Also enriches with JSDoc type annotations if available.
fn convert_js_params(raw_params: &[String], source: &str, line_number: usize) -> Vec<Param> {
    let jsdoc_params = extract_jsdoc_params(source, line_number);

    raw_params
        .iter()
        .filter(|p| {
            let trimmed = p.trim();
            // Skip `this` parameter
            trimmed != "this" && !trimmed.starts_with("this:")
        })
        .map(|p| {
            let p = p.trim();

            // Check for variadic (...rest)
            let is_variadic = p.starts_with("...");
            let p = if is_variadic { &p[3..] } else { p };

            // Split on '=' for defaults
            let (param_part, default) = if let Some(eq_idx) = p.find('=') {
                let lhs = p[..eq_idx].trim();
                let rhs = p[eq_idx + 1..].trim().to_string();
                (lhs, Some(rhs))
            } else {
                (p, None)
            };

            // Split on ':' for type annotation (rare in JS, but possible)
            let (name, type_annotation) = if let Some(colon_idx) = param_part.find(':') {
                let n = param_part[..colon_idx].trim();
                let t = param_part[colon_idx + 1..].trim();
                (n.to_string(), Some(t.to_string()))
            } else {
                (param_part.trim().to_string(), None)
            };

            // Enrich with JSDoc type if no inline type
            let final_type = type_annotation.or_else(|| {
                jsdoc_params
                    .iter()
                    .find(|(n, _)| n == &name)
                    .map(|(_, t)| t.clone())
            });

            Param {
                name,
                type_annotation: final_type,
                default,
                is_variadic,
                is_keyword: false,
            }
        })
        .collect()
}

/// Extract JSDoc `@param` annotations from the comment block preceding a line.
///
/// Returns a list of (param_name, type_annotation) pairs.
fn extract_jsdoc_params(source: &str, line_number: usize) -> Vec<(String, String)> {
    let lines: Vec<&str> = source.lines().collect();
    if line_number == 0 || line_number > lines.len() {
        return Vec::new();
    }

    // Walk backwards from the line to find the JSDoc block
    let mut params = Vec::new();
    let start_idx = line_number.saturating_sub(1);

    // Collect the JSDoc comment block
    let mut jsdoc_lines = Vec::new();
    let mut found_end = false;

    for i in (0..start_idx).rev() {
        let trimmed = lines[i].trim();
        if trimmed.ends_with("*/") {
            found_end = true;
            jsdoc_lines.push(trimmed.to_string());
        } else if found_end {
            jsdoc_lines.push(trimmed.to_string());
            if trimmed.starts_with("/**") || trimmed.starts_with("/*") {
                break;
            }
        } else if trimmed.is_empty() {
            continue;
        } else {
            // Non-empty, non-comment line -- stop searching
            break;
        }
    }

    // Reverse to get lines in source order (we collected bottom-up)
    jsdoc_lines.reverse();

    // Parse @param tags from collected lines
    for line in &jsdoc_lines {
        let trimmed = line.trim().trim_start_matches('*').trim();
        if let Some(rest) = trimmed.strip_prefix("@param") {
            let rest = rest.trim();
            // @param {Type} name - description
            if rest.starts_with('{') {
                if let Some(close) = rest.find('}') {
                    let type_str = rest[1..close].trim().to_string();
                    let after = rest[close + 1..].trim();
                    let name: String = after
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        params.push((name, type_str));
                    }
                }
            } else {
                // @param name - description (no type)
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    params.push((name, "any".to_string()));
                }
            }
        }
    }

    params
}

/// Extract JSDoc `@returns` / `@return` type annotation.
fn extract_jsdoc_return_type(source: &str, line_number: usize) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    if line_number == 0 || line_number > lines.len() {
        return None;
    }

    let start_idx = line_number.saturating_sub(1);
    let mut found_end = false;

    for i in (0..start_idx).rev() {
        let trimmed = lines[i].trim();
        if trimmed.ends_with("*/") {
            found_end = true;
        }
        if found_end {
            let clean = trimmed.trim_start_matches('*').trim();
            if let Some(rest) = clean
                .strip_prefix("@returns")
                .or_else(|| clean.strip_prefix("@return"))
            {
                let rest = rest.trim();
                if rest.starts_with('{') {
                    if let Some(close) = rest.find('}') {
                        return Some(rest[1..close].trim().to_string());
                    }
                }
            }
            if trimmed.starts_with("/**") || trimmed.starts_with("/*") {
                break;
            }
        } else if trimmed.is_empty() {
            continue;
        } else {
            break;
        }
    }

    None
}

/// Generate an example usage string for a JavaScript function.
fn generate_js_function_example(
    module: &str,
    name: &str,
    params: &[Param],
    _return_type: Option<&str>,
) -> Option<String> {
    let args: Vec<String> = params
        .iter()
        .map(|p| js_example_for_type(p.type_annotation.as_deref()))
        .collect();
    Some(format!(
        "const result = {}.{}({});",
        module,
        name,
        args.join(", ")
    ))
}

/// Generate an example usage string for a JavaScript class.
fn generate_js_class_example(module: &str, class_name: &str) -> Option<String> {
    let var = class_name.to_lowercase();
    Some(format!("const {} = new {}.{}();", var, module, class_name))
}

/// Generate an example argument from a type annotation (JSDoc or inline).
fn js_example_for_type(type_ann: Option<&str>) -> String {
    match type_ann {
        Some("string") | Some("String") => "\"example\"".to_string(),
        Some("number") | Some("Number") => "42".to_string(),
        Some("boolean") | Some("Boolean") => "true".to_string(),
        Some(t) if t.starts_with("Array") || t.ends_with("[]") => "[]".to_string(),
        Some("object") | Some("Object") => "{}".to_string(),
        Some("null") => "null".to_string(),
        Some("undefined") | Some("void") => "undefined".to_string(),
        Some(t) if t.starts_with("Promise") => "Promise.resolve()".to_string(),
        Some(t) if t.contains('|') => {
            // Union type: use the first option
            let first = t.split('|').next().unwrap_or("").trim();
            js_example_for_type(Some(first))
        }
        Some("any") | Some("*") | None => "undefined".to_string(),
        _ => "undefined".to_string(),
    }
}

/// Truncate a docstring to the first paragraph, max ~200 characters.
fn truncate_docstring(doc: &str) -> String {
    let stripped = doc
        .trim()
        .trim_start_matches("/**")
        .trim_start_matches("/*")
        .trim_end_matches("*/")
        .trim_start_matches("///")
        .trim_start_matches("//")
        .trim();

    let first_para = stripped.split("\n\n").next().unwrap_or(stripped);
    let cleaned: String = first_para
        .lines()
        .map(|l| l.trim().trim_start_matches('*').trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<&str>>()
        .join(" ");

    if cleaned.len() > 200 {
        format!(
            "{}...",
            crate::util::truncate_at_char_boundary(&cleaned, 197)
        )
    } else {
        cleaned
    }
}

/// Walk a directory recursively to find all JavaScript source files.
///
/// Returns paths sorted for deterministic output.
/// Finds `*.js` and `*.mjs` files, excluding `node_modules`, test dirs, etc.
pub fn find_javascript_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return root
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| {
                n.ends_with(".js")
                    || n.ends_with(".jsx")
                    || n.ends_with(".mjs")
                    || n.ends_with(".cjs")
            })
            .map(|_| vec![root.to_path_buf()])
            .unwrap_or_default();
    }
    let mut files = Vec::new();
    find_js_files_recursive(root, &mut files);
    files.sort();
    files
}

fn find_javascript_surface_files(root: &Path) -> Vec<PathBuf> {
    let js_files = find_javascript_files(root);
    if !js_files.is_empty() {
        return js_files;
    }

    let mut files = Vec::new();
    find_ts_backed_js_files_recursive(root, &mut files);
    files.sort();
    files
}

/// Recursive helper for finding JavaScript files.
fn find_js_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !dir_name.starts_with('.') && !is_noise_dir(Language::JavaScript, dir_name) {
                find_js_files_recursive(&path, files);
            }
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Include .js and .mjs files, exclude .min.js and test files
            if (name.ends_with(".js") || name.ends_with(".mjs"))
                && !name.ends_with(".min.js")
                && !is_noise_file(Language::JavaScript, name)
            {
                files.push(path);
            }
        }
    }
}

fn find_ts_backed_js_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !dir_name.starts_with('.') && !is_noise_dir(Language::JavaScript, dir_name) {
                find_ts_backed_js_files_recursive(&path, files);
            }
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("ts" | "tsx")
            ) && !is_noise_file(Language::JavaScript, name)
            {
                files.push(path);
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Module wiring validation ----

    #[test]
    fn test_javascript_surface_module_wired() {
        // Confirm the module exists and core extraction function is callable
        let resolved = ResolvedPackage {
            root_dir: std::env::temp_dir().join("tldr_test_js_surface_wired_nonexistent"),
            package_name: "testpkg".to_string(),
            is_pure_source: true,
            public_names: None,
        };
        // Should return an empty surface (no files found) rather than error
        let surface = extract_javascript_api_surface(&resolved, false, None);
        assert!(surface.is_ok());
        let s = surface.unwrap();
        assert_eq!(s.language, "javascript");
        assert_eq!(s.package, "testpkg");
        assert_eq!(s.total, 0);
    }

    // ---- CFr-RW3: CommonJS decorated-instance module exports ----

    /// Generalization test (anti-treadmill). Asserts BOTH the NEW sibling case
    /// (`module.exports = res; res.x = fn` decorated-instance CommonJS, express
    /// `lib/response.js`) is now resolved AND the R2 provenance guards still hold:
    /// a non-module `<x>.exports = bar` mints nothing, and the UMD/IIFE
    /// factory-return idiom (lodash) is still resolved. Fails on pre-fix source
    /// (decorated-instance members dropped → total 0).
    #[test]
    fn test_commonjs_decorated_instance_module_exports_members() {
        use std::fs;
        let tmp = std::env::temp_dir().join("tldr_cfr_rw3_commonjs_decorated");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("lib")).unwrap();

        let member_names = |apis: &[ApiEntry]| -> HashSet<String> {
            apis.iter()
                .filter_map(|a| a.qualified_name.rsplit('.').next().map(str::to_string))
                .collect()
        };

        // (a) SIBLING — decorated-instance CommonJS. `res` is a plain
        // `Object.create(...)` instance (not a top-level fn/class), decorated
        // with methods incl. a chained `res.contentType = res.type = fn`.
        let response = "var http = require('http');\n\
var res = Object.create(http.ServerResponse.prototype);\n\
module.exports = res;\n\
res.status = function status(code) { this.statusCode = code; return this; };\n\
res.send = function send(body) { return this; };\n\
res.contentType =\n\
res.type = function contentType(type) { return this; };\n\
res.get = function(field) { return this.getHeader(field); };\n";
        let resp_path = tmp.join("lib/response.js");
        fs::write(&resp_path, response).unwrap();
        let apis = extract_from_javascript_file(&resp_path, &tmp, "express", false).unwrap();
        let names = member_names(&apis);
        for m in ["status", "send", "contentType", "type", "get"] {
            assert!(
                names.contains(m),
                "decorated-instance member `{m}` missing from surface: {names:?}"
            );
        }
        // The bound id itself is NOT a member.
        assert!(
            !names.contains("res"),
            "module-bound id `res` must not be minted as a member: {names:?}"
        );

        // (b) GUARD — non-module `<x>.exports = bar`. `foo` is a plain object,
        // not `module`, so its decorations must NOT be minted as surface.
        let nonmod = "var foo = {};\n\
foo.exports = bar;\n\
foo.hidden = function hidden() {};\n\
foo.secret = function secret() {};\n";
        let nonmod_path = tmp.join("lib/nonmod.js");
        fs::write(&nonmod_path, nonmod).unwrap();
        let nm_apis = extract_from_javascript_file(&nonmod_path, &tmp, "pkg", false).unwrap();
        let nm_names = member_names(&nm_apis);
        assert!(
            !nm_names.contains("hidden") && !nm_names.contains("secret"),
            "non-module `foo.exports = bar` must not mint foo.* members: {nm_names:?}"
        );

        // (c) ORIGINAL/R2 — UMD/IIFE factory-return (lodash) still resolves via
        // the module-reference-provenance path, and the new top-level resolver
        // (gated on literal `module.exports`) does not interfere.
        let umd = ";(function() {\n\
  var freeExports = typeof exports == 'object' && exports;\n\
  function runInContext() {\n\
    function lodash() {}\n\
    lodash.map = function map(arr, fn) {};\n\
    lodash.filter = function filter(arr, fn) {};\n\
    return lodash;\n\
  }\n\
  var _ = runInContext();\n\
  freeExports.exports = _;\n\
}.call(this));\n";
        let umd_path = tmp.join("lodash.js");
        fs::write(&umd_path, umd).unwrap();
        let umd_apis = extract_from_javascript_file(&umd_path, &tmp, "lodash", false).unwrap();
        let umd_names = member_names(&umd_apis);
        for m in ["map", "filter"] {
            assert!(
                umd_names.contains(m),
                "UMD factory-return member `{m}` regressed: {umd_names:?}"
            );
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    // ---- compute_js_module_path ----

    #[test]
    fn test_compute_js_module_path_index() {
        let root = Path::new("/pkg");
        let file = Path::new("/pkg/index.js");
        assert_eq!(compute_js_module_path(file, root, "express"), "express");
    }

    #[test]
    fn test_compute_js_module_path_submodule() {
        let root = Path::new("/pkg");
        let file = Path::new("/pkg/router.js");
        assert_eq!(
            compute_js_module_path(file, root, "express"),
            "express.router"
        );
    }

    #[test]
    fn test_compute_js_module_path_src_dir() {
        let root = Path::new("/pkg");
        let file = Path::new("/pkg/src/utils.js");
        assert_eq!(compute_js_module_path(file, root, "mylib"), "mylib.utils");
    }

    #[test]
    fn test_compute_js_module_path_lib_dir() {
        let root = Path::new("/pkg");
        let file = Path::new("/pkg/lib/helpers.mjs");
        assert_eq!(compute_js_module_path(file, root, "mylib"), "mylib.helpers");
    }

    // ---- is_exported ----

    #[test]
    fn test_is_exported_es6_export() {
        let source = "function internal() {}\nexport function publicFn() {}\n";
        assert!(!is_exported(source, 1));
        assert!(is_exported(source, 2));
    }

    #[test]
    fn test_is_exported_export_default() {
        let source = "export default function main() {}\n";
        assert!(is_exported(source, 1));
    }

    #[test]
    fn test_is_exported_commonjs_module_exports() {
        let source = "function helper() {}\nmodule.exports = { helper };\n";
        assert!(is_exported(source, 1)); // helper is referenced in module.exports
        assert!(is_exported(source, 2)); // module.exports line itself
    }

    #[test]
    fn test_is_exported_commonjs_exports_dot() {
        let source = "function foo() {}\nexports.foo = foo;\n";
        assert!(is_exported(source, 1)); // foo referenced in exports.foo
    }

    #[test]
    fn test_is_not_exported_private() {
        let source = "function _internal() {}\nconst localVar = 42;\n";
        assert!(!is_exported(source, 1));
        assert!(!is_exported(source, 2));
    }

    // ---- JSDoc parsing ----

    #[test]
    fn test_extract_jsdoc_params() {
        let source = "/**\n * @param {string} name - The name\n * @param {number} age - The age\n */\nfunction greet(name, age) {}\n";
        let params = extract_jsdoc_params(source, 5);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "name");
        assert_eq!(params[0].1, "string");
        assert_eq!(params[1].0, "age");
        assert_eq!(params[1].1, "number");
    }

    #[test]
    fn test_extract_jsdoc_return_type() {
        let source = "/**\n * @returns {string} The greeting\n */\nfunction greet() {}\n";
        let ret = extract_jsdoc_return_type(source, 4);
        assert_eq!(ret, Some("string".to_string()));
    }

    #[test]
    fn test_extract_jsdoc_return_type_none() {
        let source = "function greet() {}\n";
        let ret = extract_jsdoc_return_type(source, 1);
        assert_eq!(ret, None);
    }

    // ---- Example generation ----

    #[test]
    fn test_js_example_for_type() {
        assert_eq!(js_example_for_type(Some("string")), "\"example\"");
        assert_eq!(js_example_for_type(Some("number")), "42");
        assert_eq!(js_example_for_type(Some("boolean")), "true");
        assert_eq!(js_example_for_type(Some("Array<number>")), "[]");
        assert_eq!(js_example_for_type(Some("object")), "{}");
        assert_eq!(js_example_for_type(None), "undefined");
    }

    #[test]
    fn test_truncate_docstring_short() {
        assert_eq!(truncate_docstring("Hello world"), "Hello world");
    }

    #[test]
    fn test_truncate_docstring_jsdoc() {
        let doc = "/** Parse the input data.\n * Returns a result. */";
        let result = truncate_docstring(doc);
        assert!(result.contains("Parse the input data"));
    }

    #[test]
    fn test_truncate_docstring_long() {
        let long = "a".repeat(300);
        let result = truncate_docstring(&long);
        assert!(result.len() <= 200 + 3); // 200 + "..."
        assert!(result.ends_with("..."));
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

    // ---- File discovery ----

    #[test]
    fn test_find_javascript_files() {
        let tmp = std::env::temp_dir().join("tldr_test_js_files");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("index.js"), "export const x = 1;").unwrap();
        std::fs::write(tmp.join("utils.mjs"), "export function f() {}").unwrap();
        std::fs::write(tmp.join("readme.md"), "# Docs").unwrap();
        std::fs::write(tmp.join("bundle.min.js"), "minified code").unwrap();

        let files = find_javascript_files(&tmp);
        assert_eq!(files.len(), 2, "Should find 2 JS files, got: {:?}", files);
        assert!(files.iter().any(|p| p.ends_with("index.js")));
        assert!(files.iter().any(|p| p.ends_with("utils.mjs")));
        assert!(!files.iter().any(|p| p.ends_with("bundle.min.js")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_javascript_files_excludes_test_files() {
        let tmp = std::env::temp_dir().join("tldr_test_js_files_exclude_tests");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("app.js"), "export const x = 1;").unwrap();
        std::fs::write(tmp.join("app.test.js"), "test('x', () => {});").unwrap();
        std::fs::write(tmp.join("app.spec.js"), "describe('x', () => {});").unwrap();

        let files = find_javascript_files(&tmp);
        assert_eq!(files.len(), 1, "Should find only app.js, got: {:?}", files);
        assert!(files[0].ends_with("app.js"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_javascript_files_excludes_noise_directories() {
        let tmp = std::env::temp_dir().join("tldr_test_js_files_exclude_noise_dirs");
        let _ = std::fs::remove_dir_all(&tmp);

        for dir in [
            "src",
            "examples",
            "docs",
            "bench",
            "benchmarks",
            "fixtures",
            "spec",
        ] {
            std::fs::create_dir_all(tmp.join(dir)).unwrap();
        }

        std::fs::write(tmp.join("src").join("index.js"), "export const live = 1;").unwrap();
        std::fs::write(
            tmp.join("examples").join("demo.js"),
            "export const example = 1;",
        )
        .unwrap();
        std::fs::write(tmp.join("docs").join("config.js"), "export const docs = 1;").unwrap();
        std::fs::write(tmp.join("bench").join("perf.js"), "export const bench = 1;").unwrap();
        std::fs::write(
            tmp.join("benchmarks").join("perf.js"),
            "export const bench = 1;",
        )
        .unwrap();
        std::fs::write(
            tmp.join("fixtures").join("sample.js"),
            "export const fixture = 1;",
        )
        .unwrap();
        std::fs::write(tmp.join("spec").join("api.js"), "export const spec = 1;").unwrap();

        let files = find_javascript_files(&tmp);
        assert_eq!(files, vec![tmp.join("src").join("index.js")]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_javascript_files_excludes_bench_and_fixture_files() {
        let tmp = std::env::temp_dir().join("tldr_test_js_files_exclude_noise_files");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        std::fs::write(tmp.join("index.js"), "export const live = 1;").unwrap();
        std::fs::write(tmp.join("api.bench.js"), "export const bench = 1;").unwrap();
        std::fs::write(tmp.join("api.benchmark.mjs"), "export const benchmark = 1;").unwrap();
        std::fs::write(tmp.join("api.fixture.js"), "export const fixture = 1;").unwrap();

        let files = find_javascript_files(&tmp);
        assert_eq!(files, vec![tmp.join("index.js")]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- Integration: extract from JS source ----

    #[test]
    fn test_extract_javascript_api_surface_with_limit() {
        let tmp = std::env::temp_dir().join("tldr_test_js_surface_limit");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(
            tmp.join("index.js"),
            "export function a() {}\nexport function b() {}\nexport function c() {}\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "testpkg".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, Some(2));
        assert!(surface.is_ok());
        let s = surface.unwrap();
        assert!(s.apis.len() <= 2, "Limit should cap at 2 APIs");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// CF2-S5: ESM `export default` surface idioms — the decorated-instance form
    /// (`export default axios; axios.get = …`, axios `lib/axios.js`) and the
    /// object-literal form (`export default { … }`, axios `lib/utils.js`). Both
    /// attached the module's whole public API to the default export and were
    /// invisible to the CommonJS/`export`-keyword scans (surface total 0).
    #[test]
    fn test_extract_javascript_surface_esm_default_export_members() {
        let tmp = std::env::temp_dir().join("tldr_test_js_surface_esm_default");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Decorated-instance idiom.
        std::fs::write(
            tmp.join("index.js"),
            r#"const client = createInstance();
client.get = function get(url) { return url; };
client.post = (url) => url;
client.VERSION = "1.0";
export default client;
"#,
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "mypkg".to_string(),
            is_pure_source: true,
            public_names: None,
        };
        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|a| a.qualified_name.as_str())
            .collect();
        assert!(
            names.contains(&"mypkg.get") && names.contains(&"mypkg.post"),
            "decorated-instance function members must surface; got {names:?}"
        );
        assert!(
            surface
                .apis
                .iter()
                .any(|a| a.qualified_name == "mypkg.get" && a.kind == ApiKind::Function),
            "`get` must be a Function; got {:?}",
            surface.apis
        );

        // Object-literal idiom (shorthand reference upgraded to a function).
        std::fs::write(
            tmp.join("index.js"),
            r#"function helper(a) { return a; }
export default {
  helper,
  build: function build(x) { return x; },
  run: () => 2,
  version: 42,
};
"#,
        )
        .unwrap();
        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|a| a.qualified_name.as_str())
            .collect();
        for want in ["mypkg.helper", "mypkg.build", "mypkg.run", "mypkg.version"] {
            assert!(
                names.contains(&want),
                "object-default member `{want}` must surface; got {names:?}"
            );
        }
        assert!(
            surface
                .apis
                .iter()
                .any(|a| a.qualified_name == "mypkg.helper" && a.kind == ApiKind::Function),
            "shorthand member `helper` naming a top-level function must be a Function"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_api_surface_es6_exports() {
        let tmp = std::env::temp_dir().join("tldr_test_js_surface_es6");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(
            tmp.join("index.js"),
            r#"/**
 * @param {string} name - The name
 * @returns {string} The greeting
 */
export function greet(name) {
    return "Hello, " + name;
}

function internal() {
    return 42;
}

export class Server {
    constructor(port) {
        this.port = port;
    }

    start() {
        console.log("Starting on port " + this.port);
    }
}

export const VERSION = "1.0.0";
"#,
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "mypkg".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        assert_eq!(surface.language, "javascript");
        assert_eq!(surface.package, "mypkg");

        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|a| a.qualified_name.as_str())
            .collect();
        assert!(
            names.contains(&"mypkg.greet"),
            "Should contain exported function greet, got: {:?}",
            names
        );
        assert!(
            !names.iter().any(|n| n.contains("internal")),
            "Should NOT contain non-exported function internal, got: {:?}",
            names
        );
        assert!(
            names.contains(&"mypkg.Server"),
            "Should contain exported class Server, got: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_named_reexport_surfaces_package_alias() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_named_reexport_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("foo.js"),
            "export function greet(name) { return name; }\n",
        )
        .unwrap();
        std::fs::write(tmp.join("index.js"), "export { greet } from './foo.js';\n").unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "pkg".to_string(),
            is_pure_source: false,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"pkg.greet"),
            "should surface package-facing alias pkg.greet, got: {:?}",
            names
        );
        assert!(
            !names.contains(&"pkg.foo.greet"),
            "package-facing surface should prune deep module symbol pkg.foo.greet, got: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_multiline_reexport_surfaces_package_aliases() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_multiline_reexport_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(
            tmp.join("src").join("client.js"),
            "export function createThing() { return 1; }\nexport function useThing() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("index.js"),
            "export {\n  createThing,\n  useThing, // package-facing hook\n} from './src/client';\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "pkg".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"pkg.createThing"),
            "missing root alias: {:?}",
            names
        );
        assert!(
            names.contains(&"pkg.useThing"),
            "missing root alias: {:?}",
            names
        );
        assert!(
            !names
                .iter()
                .any(|name| name == &"pkg.src.client.createThing"),
            "deep module alias should be pruned: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_react_style_imported_runtime_reexports_materialize() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_react_runtime_reexports_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(
            tmp.join("index.js"),
            "export type ElementType = React$ElementType;\nexport {\n  createElement,\n  useState,\n  Fragment,\n} from './src/ReactClient';\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("src").join("ReactClient.js"),
            "import { createElement } from './jsx/ReactJSXElement';\nimport { useState } from './ReactHooks';\nimport { REACT_FRAGMENT_TYPE } from './ReactSymbols';\nexport {\n  createElement,\n  useState,\n  REACT_FRAGMENT_TYPE as Fragment,\n};\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "react".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"react.createElement"),
            "missing createElement runtime export: {:?}",
            names
        );
        assert!(
            names.contains(&"react.useState"),
            "missing useState runtime export: {:?}",
            names
        );
        assert!(
            names.contains(&"react.Fragment"),
            "missing Fragment runtime export: {:?}",
            names
        );
        assert!(
            !names.iter().any(|name| name.contains("ElementType")),
            "flow type noise should not surface as runtime API: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_commonjs_forwarded_entrypoint_surfaces_package_api() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_commonjs_forward_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("lib")).unwrap();
        std::fs::write(
            tmp.join("index.js"),
            "module.exports = require('./lib/express');\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("lib").join("express.js"),
            "function createApplication() {\n  return {};\n}\nexports = module.exports = createApplication;\nexports.Router = Router;\nexports.json = bodyParser.json;\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "express".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"express"),
            "missing callable root export: {:?}",
            names
        );
        assert!(
            names.contains(&"express.Router"),
            "missing forwarded Router export: {:?}",
            names
        );
        assert!(
            names.contains(&"express.json"),
            "missing forwarded json export: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_surface_keeps_manifest_exported_subpaths_only() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_manifest_exports_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("package.json"),
            r#"{
                "name": "pkg",
                "exports": {
                    ".": "./index.js",
                    "./runtime": "./runtime.js"
                }
            }"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("index.js"),
            "export function rootApi() { return 1; }\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("runtime.js"),
            "export function runtimeApi() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("internal.js"),
            "export function internalApi() { return 3; }\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "pkg".to_string(),
            is_pure_source: false,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"pkg.rootApi"),
            "missing root export: {:?}",
            names
        );
        assert!(
            names.iter().any(|name| name.contains("runtimeApi")),
            "missing exported subpath API: {:?}",
            names
        );
        assert!(
            !names.iter().any(|name| name.contains("internalApi")),
            "internal module should be pruned from package-facing surface: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_surface_falls_back_to_ts_backed_sources() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_ts_fallback_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(
            tmp.join("package.json"),
            r#"{
                "name": "mitt-like",
                "source": "src/index.ts",
                "typings": "index.d.ts"
            }"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("src").join("index.ts"),
            "export function emit<T>(type: string, event: T): void {}\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.join("src"),
            package_name: "mitt-like".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"mitt-like.emit"),
            "should extract package-facing API from TS-backed JS source, got: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_surface_ignores_flow_type_exports_as_runtime_classes() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_flow_type_exports_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("index.js"),
            r#"
export type ElementType = string;
export type Node = mixed;

export function createElement(type, props) {
  return { type, props };
}
"#,
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "react-like".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(names.contains(&"react-like.createElement"));
        assert!(!names.contains(&"react-like.ElementType"));
        assert!(!names.contains(&"react-like.Node"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_javascript_local_export_aliases_materialize_runtime_bindings() {
        let tmp = std::env::temp_dir().join(format!(
            "tldr_js_local_export_aliases_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(
            tmp.join("src").join("ReactHooks.js"),
            "export function useState(value) { return [value, () => {}]; }\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("src").join("ReactClient.js"),
            r#"
import {useState} from './ReactHooks';
export {useState};
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("index.js"),
            "export { useState } from './src/ReactClient';\n",
        )
        .unwrap();

        let resolved = ResolvedPackage {
            root_dir: tmp.clone(),
            package_name: "react-like".to_string(),
            is_pure_source: true,
            public_names: None,
        };

        let surface = extract_javascript_api_surface(&resolved, false, None).unwrap();
        let names: Vec<&str> = surface
            .apis
            .iter()
            .map(|api| api.qualified_name.as_str())
            .collect();

        assert!(
            names.contains(&"react-like.useState"),
            "expected package-facing re-exported runtime binding, got: {:?}",
            names
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_extract_name_from_line() {
        assert_eq!(
            extract_name_from_line("function helper() {}"),
            Some("helper".to_string())
        );
        assert_eq!(
            extract_name_from_line("class Server {}"),
            Some("Server".to_string())
        );
        assert_eq!(
            extract_name_from_line("const VERSION = '1.0'"),
            Some("VERSION".to_string())
        );
        assert_eq!(extract_name_from_line("// comment"), None);
    }

    #[test]
    fn test_convert_js_params_with_jsdoc() {
        let source = "/**\n * @param {string} name\n * @param {number} age\n */\nfunction greet(name, age) {}\n";
        let raw_params = vec!["name".to_string(), "age".to_string()];
        let params = convert_js_params(&raw_params, source, 5);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].type_annotation, Some("string".to_string()));
        assert_eq!(params[1].name, "age");
        assert_eq!(params[1].type_annotation, Some("number".to_string()));
    }

    #[test]
    fn test_convert_js_params_with_defaults() {
        let source = "function greet(name = 'World') {}\n";
        let raw_params = vec!["name = 'World'".to_string()];
        let params = convert_js_params(&raw_params, source, 1);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].default, Some("'World'".to_string()));
    }

    #[test]
    fn test_convert_js_params_variadic() {
        let source = "function log(...args) {}\n";
        let raw_params = vec!["...args".to_string()];
        let params = convert_js_params(&raw_params, source, 1);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "args");
        assert!(params[0].is_variadic);
    }
}
