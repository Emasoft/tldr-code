//! Solidity-specific API surface extraction.
//!
//! solidity-surface-v1 (v0.5.0 SOL-006a): emit the public-API surface
//! for Solidity contracts / interfaces / libraries.
//!
//! # Public surface rules
//!
//! Solidity has **explicit visibility keywords** on functions and state
//! variables: `public`, `external`, `internal`, `private`. The public
//! surface (what an external caller — another contract, a wallet, or a
//! dapp — can invoke or observe) is:
//!
//! - `function foo(...) external|public` → in surface.
//! - `function foo(...) internal|private` → NOT in surface (unless
//!   `include_private`).
//! - File-scope free functions (Solidity 0.7.4+) → in surface (no
//!   visibility keyword, always externally callable).
//! - State variables declared `public` → compiler auto-generates a
//!   getter; surfaced as [`ApiKind::Property`].
//! - State variables declared `internal` / `private` (or with no
//!   visibility, which defaults to `internal` for state vars) → NOT in
//!   surface.
//! - `event` declarations → in surface (observable in transaction logs;
//!   part of the contract's ABI). Modeled as [`ApiKind::Constant`]
//!   because they have a typed parameter list but are NOT callable.
//! - `error` declarations (Solidity 0.8.4+ custom errors) → in surface
//!   (part of the contract ABI). Same kind reasoning as events.
//! - `constructor` → NOT in surface (one-time call at deployment).
//! - `fallback() external` / `receive() external payable` → in surface
//!   (entry points for raw `call` / plain Ether transfers).
//! - `modifier` declarations → NOT in surface (not externally callable;
//!   only applied by name on function declarations).
//!
//! # Adapter template
//!
//! Modeled on the Kotlin extractor template (per oracle research).
//! Solidity's `visibility` field on FunctionInfo (set by
//! `extract_solidity_function_info` in `crates/tldr-core/src/ast/extract.rs`)
//! maps 1:1 to Kotlin's `private` / `internal` modifier detection. The
//! Solidity adapter uses the structured field instead of source-line
//! string matching because the AST already classifies it deterministically.

use std::path::{Path, PathBuf};

use crate::ast::extract::extract_from_tree;
use crate::ast::parser::parse;
use crate::types::Language;
use crate::TldrResult;

use super::triggers::extract_triggers;
use super::types::{ApiEntry, ApiKind, ApiSurface, Location, Param, ResolvedPackage, Signature};

/// Extract the public Solidity API surface for a resolved package.
pub fn extract_solidity_api_surface(
    resolved: &ResolvedPackage,
    include_private: bool,
    limit: Option<usize>,
) -> TldrResult<ApiSurface> {
    let mut apis = Vec::new();

    for file_path in find_solidity_files(&resolved.root_dir) {
        apis.extend(extract_from_solidity_file(
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
        language: "solidity".to_string(),
        total,
        apis,
        files_skipped: 0,
        warnings: Vec::new(),
    })
}

/// Recursively collect `.sol` files under `dir`. If `dir` is a single
/// `.sol` file, returns just that file.
fn find_solidity_files(dir: &Path) -> Vec<PathBuf> {
    if dir.is_file() {
        return dir
            .extension()
            .and_then(|ext| ext.to_str())
            .filter(|ext| *ext == "sol")
            .map(|_| vec![dir.to_path_buf()])
            .unwrap_or_default();
    }

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Skip hidden dirs and conventional noise dirs.
                    if !name.starts_with('.')
                        && name != "node_modules"
                        && name != "out"
                        && name != "artifacts"
                        && name != "cache"
                    {
                        files.extend(find_solidity_files(&path));
                    }
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn extract_from_solidity_file(
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

    let tree = parse(&source, Language::Solidity)?;
    let module_info =
        extract_from_tree(&tree, &source, Language::Solidity, file_path, Some(root_dir))?;
    let module_path = compute_solidity_module_path(file_path, root_dir, package_name);
    let relative_path = file_path
        .strip_prefix(root_dir)
        .unwrap_or(file_path)
        .to_path_buf();

    let mut apis = Vec::new();

    // File-scope free functions. In Solidity these have no `visibility`
    // keyword in the grammar (file-scope functions are always externally
    // callable). They are part of the public surface unless we hide them.
    for func in &module_info.functions {
        if !include_private && !is_solidity_function_public(&func.visibility) {
            continue;
        }
        let params = convert_solidity_params(&func.params);
        let return_type = func.return_type.clone();
        apis.push(ApiEntry {
            qualified_name: join_qualified(&module_path, &func.name),
            kind: ApiKind::Function,
            module: module_path.clone(),
            signature: Some(Signature {
                params: params.clone(),
                return_type: return_type.clone(),
                is_async: false,
                is_generator: false,
            }),
            docstring: func.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_solidity_call_example(
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
        let class_name = if class.name.is_empty() {
            continue;
        } else {
            class.name.clone()
        };
        let qualified_name = join_qualified(&module_path, &class_name);
        let kind = determine_solidity_kind(class.kind.as_deref());

        // Surface the contract/interface/library itself.
        apis.push(ApiEntry {
            qualified_name: qualified_name.clone(),
            kind,
            module: module_path.clone(),
            signature: None,
            docstring: class.docstring.clone().map(|doc| truncate_docstring(&doc)),
            example: Some(generate_solidity_type_example(&class_name, kind)),
            triggers: extract_triggers(&class_name, class.docstring.as_deref()),
            is_property: false,
            return_type: None,
            location: Some(Location {
                file: relative_path.clone(),
                line: class.line_number as usize,
                column: None,
            }),
        });

        // Methods of the contract/interface/library.
        for method in &class.methods {
            // Constructors are not part of the post-deployment surface.
            if method.name == "constructor" {
                continue;
            }
            // fallback / receive are externally invokable; always surface
            // them. They have no visibility (always `external` by spec).
            let is_special = matches!(method.name.as_str(), "fallback" | "receive");
            if !is_special && !include_private && !is_solidity_function_public(&method.visibility) {
                continue;
            }

            let params = convert_solidity_params(&method.params);
            let return_type = method.return_type.clone();
            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, method.name),
                kind: ApiKind::Method,
                module: module_path.clone(),
                signature: Some(Signature {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    is_async: false,
                    is_generator: false,
                }),
                docstring: method.docstring.clone().map(|doc| truncate_docstring(&doc)),
                example: Some(generate_solidity_method_example(
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

        // State variables: only `public` ones get auto-getters. Constants
        // declared at contract scope (`uint256 constant FOO = 1`) are
        // visible from outside via the same getter mechanism when public;
        // we surface only those with explicit `public` visibility.
        for field in &class.fields {
            let is_public = field.visibility.as_deref() == Some("public");
            if !include_private && !is_public {
                continue;
            }
            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, field.name),
                kind: ApiKind::Property,
                module: module_path.clone(),
                signature: None,
                docstring: None,
                example: Some(format!(
                    "{}.{}()",
                    class_name.to_lowercase(),
                    field.name
                )),
                triggers: extract_triggers(&field.name, None),
                is_property: true,
                return_type: field.field_type.clone(),
                location: Some(Location {
                    file: relative_path.clone(),
                    line: field.line_number as usize,
                    column: None,
                }),
            });
        }

        // Events — observable on the contract ABI.
        for event in &class.events {
            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, event.name),
                kind: ApiKind::Constant,
                module: module_path.clone(),
                signature: None,
                docstring: None,
                example: Some(format!("event {}", event.name)),
                triggers: extract_triggers(&event.name, None),
                is_property: false,
                return_type: None,
                location: Some(Location {
                    file: relative_path.clone(),
                    line: event.line_number as usize,
                    column: None,
                }),
            });
        }

        // Custom errors (0.8.4+) — part of the contract ABI.
        for error in &class.errors {
            apis.push(ApiEntry {
                qualified_name: format!("{}.{}", qualified_name, error.name),
                kind: ApiKind::Constant,
                module: module_path.clone(),
                signature: None,
                docstring: None,
                example: Some(format!("error {}", error.name)),
                triggers: extract_triggers(&error.name, None),
                is_property: false,
                return_type: None,
                location: Some(Location {
                    file: relative_path.clone(),
                    line: error.line_number as usize,
                    column: None,
                }),
            });
            // Note: modifiers (class.modifiers) are intentionally NOT
            // surfaced — they are wrappers, not callable from outside.
        }
    }

    // File-scope constants (`uint256 constant FOO = 1` at top level).
    for constant in &module_info.constants {
        let const_qualified = join_qualified(&module_path, &constant.name);
        apis.push(ApiEntry {
            qualified_name: const_qualified.clone(),
            kind: ApiKind::Constant,
            module: module_path.clone(),
            signature: None,
            docstring: None,
            example: Some(const_qualified.clone()),
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

    Ok(apis)
}

/// Compute the module path for a Solidity file. Solidity has no module
/// system, so we use the path-as-module convention: relative directory
/// segments joined with `.`, prefixed by the package name.
///
/// v0.5.0 SOL-015a (M8): when `package_name` is empty (e.g. a target
/// path whose `file_name()` resolves to empty) we must NOT prepend a
/// leading `.` segment. Empty parts are filtered and the join skips
/// empty prefixes entirely, so a contract at the file scope of a
/// nameless target surfaces as `<ContractName>` rather than `.<Name>`
/// (or, in the qualified_name slot, `..<Name>`).
fn compute_solidity_module_path(file_path: &Path, root_dir: &Path, package_name: &str) -> String {
    let relative = file_path.strip_prefix(root_dir).unwrap_or(file_path);
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let dir_parts: Vec<String> = parent
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    let mut all_parts: Vec<&str> = Vec::new();
    let pkg = package_name.trim();
    if !pkg.is_empty() {
        all_parts.push(pkg);
    }
    for part in &dir_parts {
        if !part.is_empty() {
            all_parts.push(part.as_str());
        }
    }
    all_parts.join(".")
}

/// v0.5.0 SOL-015a (M8): join a parent qualifier and a leaf name into a
/// dotted qualified name without producing a leading `.` when the parent
/// is empty. Without this, file-scope items in nameless targets emitted
/// qualified names like `..TokenVault` (one dot from the empty
/// module_path-class join, another from a downstream concat). Mirrors
/// the Kotlin / Java surface adapters which already short-circuit on
/// empty parents.
fn join_qualified(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", parent, name)
    }
}

/// True when a Solidity function/method visibility means it's part of
/// the externally callable surface.
///
/// - `Some("public")` / `Some("external")` → true.
/// - `Some("internal")` / `Some("private")` → false.
/// - `None` → true. Two cases hit this branch:
///   1. File-scope free functions (Solidity 0.7.4+) — no visibility
///      keyword, always externally callable.
///   2. Fallback / receive — no visibility keyword in the grammar's
///      visibility field, but always `external` by spec.
///
/// Note: contract-scope methods missing a visibility keyword DO exist
/// in legacy (pre-0.5.0) Solidity, where the default was `public`. The
/// grammar's `visibility` field will be `None` in that case and we
/// treat it as public — matching historical behavior and avoiding
/// false-negative surface omissions.
fn is_solidity_function_public(visibility: &Option<String>) -> bool {
    match visibility.as_deref() {
        Some("internal") | Some("private") => false,
        _ => true,
    }
}

fn determine_solidity_kind(class_kind: Option<&str>) -> ApiKind {
    match class_kind {
        Some("interface") => ApiKind::Interface,
        // Libraries are stateless utility collections; ApiKind::Class is
        // the closest existing kind (TypeAlias / Module would mislead
        // consumers since libraries can hold callable members).
        _ => ApiKind::Class,
    }
}

fn convert_solidity_params(raw_params: &[String]) -> Vec<Param> {
    raw_params
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| Param {
            name: p.clone(),
            type_annotation: None,
            default: None,
            is_variadic: false,
            is_keyword: false,
        })
        .collect()
}

fn truncate_docstring(doc: &str) -> String {
    // Strip NatSpec leader chars (`///` or `/**` `*/`) and per-line `*`.
    let first_para = doc.split("\n\n").next().unwrap_or(doc);
    let cleaned = first_para
        .replace("/**", "")
        .replace("*/", "")
        .lines()
        .map(|line| {
            let l = line.trim();
            // Strip a leading `///` (NatSpec single-line) before the per-line `*`.
            let l = l.trim_start_matches("///").trim();
            l.trim_start_matches('*').trim()
        })
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

fn generate_solidity_call_example(module_path: &str, func_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}.{}({})", module_path, func_name, args)
}

fn generate_solidity_type_example(name: &str, kind: ApiKind) -> String {
    match kind {
        ApiKind::Interface => format!("{} value = {}(addr);", name, name),
        _ => format!("{} instance = new {}();", name, name),
    }
}

fn generate_solidity_method_example(class_name: &str, method_name: &str, params: &[Param]) -> String {
    let args = params
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}.{}({})",
        class_name.to_lowercase(),
        method_name,
        args
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_public_when_visibility_is_public_or_external() {
        assert!(is_solidity_function_public(&Some("public".to_string())));
        assert!(is_solidity_function_public(&Some("external".to_string())));
    }

    #[test]
    fn not_public_when_visibility_is_internal_or_private() {
        assert!(!is_solidity_function_public(&Some("internal".to_string())));
        assert!(!is_solidity_function_public(&Some("private".to_string())));
    }

    #[test]
    fn is_public_when_visibility_is_none() {
        // File-scope free fns + fallback/receive land here.
        assert!(is_solidity_function_public(&None));
    }

    #[test]
    fn determine_kind_interface() {
        assert_eq!(determine_solidity_kind(Some("interface")), ApiKind::Interface);
    }

    #[test]
    fn determine_kind_library_is_class() {
        assert_eq!(determine_solidity_kind(Some("library")), ApiKind::Class);
    }

    #[test]
    fn determine_kind_contract_is_class() {
        assert_eq!(determine_solidity_kind(Some("contract")), ApiKind::Class);
    }

    #[test]
    fn determine_kind_unknown_defaults_to_class() {
        assert_eq!(determine_solidity_kind(None), ApiKind::Class);
    }

    #[test]
    fn truncate_docstring_strips_natspec_leaders() {
        let doc = "/// @notice Foo\n/// @param x bar";
        let out = truncate_docstring(doc);
        assert!(out.contains("@notice Foo"));
        assert!(out.contains("@param x bar"));
        assert!(!out.contains("///"));
    }

    #[test]
    fn truncate_docstring_strips_block_natspec() {
        let doc = "/** @notice Foo\n * @dev bar\n */";
        let out = truncate_docstring(doc);
        assert!(out.contains("@notice Foo"));
        assert!(out.contains("@dev bar"));
        assert!(!out.contains("/**"));
        assert!(!out.contains("*/"));
    }

    // v0.5.0 SOL-015a (M8): empty-parent join must not produce a
    // leading `.` segment.
    #[test]
    fn join_qualified_empty_parent_emits_bare_name() {
        assert_eq!(join_qualified("", "TokenVault"), "TokenVault");
    }

    #[test]
    fn join_qualified_nonempty_parent_emits_dotted_pair() {
        assert_eq!(join_qualified("pkg", "TokenVault"), "pkg.TokenVault");
        assert_eq!(
            join_qualified("pkg.contracts", "TokenVault"),
            "pkg.contracts.TokenVault"
        );
    }

    // v0.5.0 SOL-015a (M8): compute_solidity_module_path with empty
    // package_name must not synthesize a leading-dot module path. A
    // downstream concat would otherwise turn into `..TokenVault`.
    #[test]
    fn compute_module_path_empty_package_no_leading_dot() {
        use std::path::PathBuf;
        let root = PathBuf::from("/tmp/anon");
        let file = root.join("TokenVault.sol");
        let module_path = compute_solidity_module_path(&file, &root, "");
        // With no package name and a file at the root, the module path
        // must be empty — definitely NOT ".".
        assert_eq!(module_path, "");
        let joined = join_qualified(&module_path, "TokenVault");
        assert_eq!(joined, "TokenVault");
        assert!(
            !joined.starts_with(".."),
            "qualified_name must not start with `..`, got: {:?}",
            joined
        );
        assert!(
            !joined.starts_with('.'),
            "qualified_name must not start with `.`, got: {:?}",
            joined
        );
    }

    // v0.5.0 SOL-015a (M8): even when package_name is empty but the
    // file sits in a subdirectory, the module path uses only the dir
    // parts (no spurious leading dot).
    #[test]
    fn compute_module_path_empty_package_with_subdir_has_no_leading_dot() {
        use std::path::PathBuf;
        let root = PathBuf::from("/tmp/anon");
        std::fs::create_dir_all(root.join("contracts")).ok();
        let file = root.join("contracts/TokenVault.sol");
        let module_path = compute_solidity_module_path(&file, &root, "");
        assert_eq!(module_path, "contracts");
        let joined = join_qualified(&module_path, "TokenVault");
        assert_eq!(joined, "contracts.TokenVault");
    }

    #[test]
    fn find_solidity_files_recurses_and_filters() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("contracts/token")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/oz")).unwrap();
        std::fs::write(root.join("Top.sol"), "contract Top {}").unwrap();
        std::fs::write(root.join("contracts/token/Erc20.sol"), "contract Erc20 {}").unwrap();
        // Should be skipped (noise dir).
        std::fs::write(root.join("node_modules/oz/Lib.sol"), "library Lib {}").unwrap();
        // Should be skipped (wrong extension).
        std::fs::write(root.join("README.md"), "# hi").unwrap();

        let files = find_solidity_files(root);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"Top.sol".to_string()));
        assert!(names.contains(&"Erc20.sol".to_string()));
        assert!(!names.contains(&"Lib.sol".to_string()), "should skip node_modules");
        assert!(!names.contains(&"README.md".to_string()));
    }
}
