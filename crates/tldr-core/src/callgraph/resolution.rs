//! Call Resolution Engine (Phase 6 modularization)
//!
//! This module contains the call resolution logic: strategies 0-9 for resolving
//! call sites to their target definitions, type-aware resolution, and FP guards.
//!
//! Extracted from builder_v2.rs as part of the Phase 14 modularization.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::cross_file_types::{CallSite, CallType, ClassDef, FileIR, FuncDef, VarType};
use super::import_resolver::{ReExportTracer, DEFAULT_MAX_DEPTH};
use super::type_resolver::resolve_receiver_type;
use crate::types::Language;

// From new sibling modules:
use super::imports::{ImportMap, ModuleImports};
use super::module_path::path_to_module;
use super::types::{capitalize_first, ClassEntry, ClassIndex, FuncEntry, FuncIndex};

// =============================================================================
// Phase 14e: Call Extraction and Resolution (Spec Section 14.6)
// =============================================================================

/// A resolved call target representing the location of a function/method definition.
///
/// This struct captures the final destination of a call site after import resolution,
/// re-export tracing, and type-aware method resolution.
///
/// # Example
/// ```rust,ignore
/// // For: from helper import process; process()
/// // Resolves to:
/// ResolvedTarget {
///     file: PathBuf::from("helper.py"),
///     name: "process".to_string(),
///     line: Some(5),
///     is_method: false,
///     class_name: None,
/// }
///
/// // For: user.save() where user: User
/// // Resolves to:
/// ResolvedTarget {
///     file: PathBuf::from("models.py"),
///     name: "save".to_string(),
///     line: Some(42),
///     is_method: true,
///     class_name: Some("User".to_string()),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// File path containing the definition (relative to project root).
    pub file: PathBuf,

    /// Name of the function/method.
    pub name: String,

    /// Line number of definition (1-indexed), if known.
    pub line: Option<u32>,

    /// True if this is a method of a class.
    pub is_method: bool,

    /// Containing class name if `is_method` is true.
    pub class_name: Option<String>,
}

impl ResolvedTarget {
    /// Creates a ResolvedTarget for a standalone function.
    pub fn function(file: PathBuf, name: impl Into<String>, line: Option<u32>) -> Self {
        Self {
            file,
            name: name.into(),
            line,
            is_method: false,
            class_name: None,
        }
    }

    /// Creates a ResolvedTarget for a method.
    pub fn method(
        file: PathBuf,
        name: impl Into<String>,
        class_name: impl Into<String>,
        line: Option<u32>,
    ) -> Self {
        Self {
            file,
            name: name.into(),
            line,
            is_method: true,
            class_name: Some(class_name.into()),
        }
    }

    /// Returns the qualified name (Class.method or just name).
    pub fn qualified_name(&self) -> String {
        if let Some(ref class) = self.class_name {
            format!("{}.{}", class, self.name)
        } else {
            self.name.clone()
        }
    }
}

/// Shared context required to resolve calls in a file.
pub struct ResolutionContext<'a, 'b> {
    /// Maps local names to `(module_path, original_name)`.
    pub import_map: &'a ImportMap,
    /// Maps module aliases to resolved module paths.
    pub module_imports: &'a ModuleImports,
    /// Global index of discovered functions.
    pub func_index: &'a FuncIndex,
    /// Global index of discovered classes.
    pub class_index: &'a ClassIndex,
    /// Re-export tracer used to follow package indirections.
    pub reexport_tracer: &'a mut ReExportTracer<'b>,
    /// Relative path to the file currently being resolved.
    pub current_file: &'a Path,
    /// Project root path.
    pub root: &'a Path,
    /// Language identifier used for language-specific resolution behavior.
    pub language: &'a str,
}

/// Returns candidate constructor method names for a language.
fn constructor_method_candidates(language: &str, class_name: &str) -> Vec<String> {
    match language.to_lowercase().as_str() {
        "python" => vec!["__init__".to_string()],
        "ruby" => vec!["initialize".to_string()],
        "php" => vec!["__construct".to_string()],
        "typescript" | "javascript" => vec!["constructor".to_string()],
        "swift" => vec!["init".to_string()],
        "kotlin" => vec!["init".to_string(), "constructor".to_string()],
        "java" | "csharp" | "cpp" => vec![class_name.to_string()],
        "scala" => vec![class_name.to_string()],
        _ => Vec::new(),
    }
}

/// Resolve a constructor call for a class if the constructor method is known.
pub(crate) fn resolve_constructor_target(
    class_name: &str,
    class_entry: &ClassEntry,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    for ctor_name in constructor_method_candidates(language, class_name) {
        if class_entry.methods.contains(&ctor_name) {
            let qualified = format!("{}.{}", class_name, ctor_name);
            let module = path_to_module(&class_entry.file_path, language);
            if let Some(entry) = func_index.get(&module, &qualified) {
                return Some(ResolvedTarget::method(
                    entry.file_path.clone(),
                    ctor_name,
                    class_name.to_string(),
                    Some(entry.line),
                ));
            }

            return Some(ResolvedTarget::method(
                class_entry.file_path.clone(),
                ctor_name,
                class_name.to_string(),
                Some(class_entry.line),
            ));
        }
    }

    None
}

/// Compute the import path used to resolve a call, if any.
pub(crate) fn compute_via_import(
    call_site: &CallSite,
    import_map: &ImportMap,
    module_imports: &ModuleImports,
) -> Option<String> {
    match call_site.call_type {
        CallType::Method | CallType::Attr => {
            if let Some(ref receiver) = call_site.receiver {
                if let Some(module_path) = module_imports.get(receiver) {
                    return Some(module_path.clone());
                }
                if let Some((module_path, original_name)) = import_map.get(receiver) {
                    return Some(format!("{}.{}", module_path, original_name));
                }
            }
            None
        }
        CallType::Direct | CallType::Ref | CallType::Static => {
            if let Some((module_path, _)) = import_map.get(&call_site.target) {
                return Some(module_path.clone());
            }
            None
        }
        CallType::Intra => None,
    }
}

pub(crate) fn enclosing_class_for_call(funcs: &[FuncDef], call_site: &CallSite) -> Option<String> {
    let line = call_site.line?;
    let mut best: Option<&FuncDef> = None;
    let mut best_span: u32 = u32::MAX;

    for func in funcs {
        if line < func.line || line > func.end_line {
            continue;
        }
        let span = func.end_line.saturating_sub(func.line);
        if span < best_span {
            best_span = span;
            best = Some(func);
        }
    }

    if let Some(func) = best {
        if let Some(class_name) = &func.class_name {
            return Some(class_name.clone());
        }
    }

    if let Some((class_name, _)) = call_site.caller.split_once('.') {
        return Some(class_name.to_string());
    }

    let mut unique: Option<String> = None;
    for func in funcs {
        if func.name == call_site.caller {
            if let Some(class_name) = &func.class_name {
                if let Some(ref existing) = unique {
                    if existing != class_name {
                        return None;
                    }
                } else {
                    unique = Some(class_name.clone());
                }
            }
        }
    }

    unique
}

pub(crate) fn first_base_for_class(classes: &[ClassDef], class_name: &str) -> Option<String> {
    classes
        .iter()
        .find(|class_def| class_def.name == class_name)
        .and_then(|class_def| class_def.bases.first())
        .cloned()
}

/// Apply type resolution to method/attribute calls in a FileIR.
pub fn apply_type_resolution(file_ir: &mut FileIR, source: &str, language: Language) {
    let supports_type_resolution = matches!(
        language,
        Language::Python
            | Language::TypeScript
            | Language::JavaScript
            | Language::Go
            | Language::Rust
            | Language::Java
            | Language::C
            | Language::Cpp
            | Language::Ruby
            | Language::Kotlin
            | Language::Swift
            | Language::CSharp
            | Language::Scala
            | Language::Php
            | Language::Lua
            | Language::Luau
            | Language::Elixir
            | Language::Ocaml
    );

    // FM-10 fix: borrow var_types immutably alongside mutable calls borrow
    let (funcs, classes, var_types, calls) = (
        &file_ir.funcs,
        &file_ir.classes,
        &file_ir.var_types,
        &mut file_ir.calls,
    );

    for (caller_name, call_sites) in calls.iter_mut() {
        for call_site in call_sites.iter_mut() {
            if !matches!(call_site.call_type, CallType::Method | CallType::Attr) {
                continue;
            }
            if call_site.receiver_type.is_some() {
                continue;
            }
            let receiver = match call_site.receiver.as_deref() {
                Some(r) => r,
                None => continue,
            };
            let line = match call_site.line {
                Some(l) => l,
                None => continue,
            };

            let receiver_key = receiver.trim();
            let receiver_simple = if receiver_key == "super"
                || receiver_key.starts_with("super(")
                || receiver_key.starts_with("super<")
            {
                "super"
            } else {
                receiver_key
            };

            let enclosing_class = enclosing_class_for_call(funcs, call_site);
            let base_class = enclosing_class
                .as_deref()
                .and_then(|class_name| first_base_for_class(classes, class_name));

            if supports_type_resolution {
                let (resolved, confidence) = resolve_receiver_type(
                    language,
                    source,
                    line,
                    receiver_key,
                    enclosing_class.as_deref(),
                );
                if resolved.is_some() && confidence != crate::types::Confidence::Low {
                    call_site.receiver_type = resolved;
                    continue;
                }
            }

            // VarType-driven injection: look up receiver in file_ir.var_types
            // This fills receiver_type from constructor assignments, type annotations,
            // and parameter annotations extracted by the language handler.
            // Implements "last assignment wins" with scoped priority over module-level.
            if call_site.receiver_type.is_none() && !var_types.is_empty() {
                // PHP receivers have `$` prefix (e.g. "$animal") but VarTypes store without it
                let vartype_key = receiver_key.strip_prefix('$').unwrap_or(receiver_key);
                if let Some(type_name) =
                    find_best_vartype(var_types, vartype_key, caller_name, line)
                {
                    call_site.receiver_type = Some(type_name);
                    continue;
                }
            }

            if call_site.receiver_type.is_some() {
                continue;
            }

            match receiver_simple {
                "self" | "cls" | "this" | "Self" => {
                    if let Some(class_name) = enclosing_class {
                        call_site.receiver_type = Some(class_name);
                    }
                }
                "super" | "base" => {
                    if let Some(base_name) = base_class {
                        call_site.receiver_type = Some(base_name);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Find the best matching VarType for a given receiver name and call context.
///
/// Implements:
/// - Scoped matches (same function) take priority over module-level (None scope)
/// - Among matches in the same priority tier, "last assignment wins" (highest line <= call_line)
///
/// Returns the `type_name` of the best match, or None.
fn find_best_vartype(
    var_types: &[VarType],
    receiver_name: &str,
    caller_name: &str,
    call_line: u32,
) -> Option<String> {
    let mut best_scoped: Option<&VarType> = None;
    let mut best_module: Option<&VarType> = None;

    for vt in var_types {
        if vt.var_name != receiver_name {
            continue;
        }
        if vt.line > call_line {
            continue;
        }

        match &vt.scope {
            Some(scope) if scope == caller_name => {
                // Scoped match: prefer latest line
                if best_scoped.is_none_or(|prev| vt.line > prev.line) {
                    best_scoped = Some(vt);
                }
            }
            None => {
                // Module-level match: prefer latest line
                if best_module.is_none_or(|prev| vt.line > prev.line) {
                    best_module = Some(vt);
                }
            }
            _ => {
                // Different scope, skip
            }
        }
    }

    // Scoped matches take priority over module-level
    best_scoped.or(best_module).map(|vt| vt.type_name.clone())
}

/// Resolve the best caller name for a call site, qualifying methods with class names when possible.
pub(crate) fn resolve_caller_name(file_ir: &FileIR, call_site: &CallSite) -> String {
    let line = match call_site.line {
        Some(l) => l,
        None => return call_site.caller.clone(),
    };

    let mut best: Option<&FuncDef> = None;
    let mut best_span: u32 = u32::MAX;

    for func in &file_ir.funcs {
        if line < func.line || line > func.end_line {
            continue;
        }
        let span = func.end_line.saturating_sub(func.line);
        if span <= best_span {
            best_span = span;
            best = Some(func);
        }
    }

    if let Some(func) = best {
        if func.is_method {
            if let Some(ref class_name) = func.class_name {
                return format!("{}.{}", class_name, func.name);
            }
        }
        return func.name.clone();
    }

    call_site.caller.clone()
}

fn resolve_reexported_name(
    module_path: &str,
    name: &str,
    tracer: &mut ReExportTracer<'_>,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    if language != "python" {
        return None;
    }

    let traced = tracer.trace(module_path, name, DEFAULT_MAX_DEPTH)?;
    let traced_module = path_to_module(&traced.definition_file, language);

    if let Some(entry) = func_index.get(&traced_module, &traced.qualified_name) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: traced.qualified_name.clone(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }

    if let Some(class_entry) = class_index.get(&traced.qualified_name) {
        if let Some(ctor_target) =
            resolve_constructor_target(&traced.qualified_name, class_entry, func_index, language)
        {
            return Some(ctor_target);
        }
        return Some(ResolvedTarget {
            file: class_entry.file_path.clone(),
            name: traced.qualified_name.clone(),
            line: Some(class_entry.line),
            is_method: false,
            class_name: None,
        });
    }

    None
}

fn resolve_reexported_receiver_target(
    module_path: &str,
    receiver_name: &str,
    method_name: &str,
    tracer: &mut ReExportTracer<'_>,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    if language != "python" {
        return None;
    }

    let traced = tracer.trace(module_path, receiver_name, DEFAULT_MAX_DEPTH)?;
    let traced_module = path_to_module(&traced.definition_file, language);

    if let Some(entry) = func_index.get(&traced_module, method_name) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: method_name.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }

    if let Some(class_entry) = class_index.get(method_name) {
        return Some(ResolvedTarget {
            file: class_entry.file_path.clone(),
            name: method_name.to_string(),
            line: Some(class_entry.line),
            is_method: false,
            class_name: None,
        });
    }

    None
}

/// Resolve a call site to its target definition.
///
/// This function implements the resolution priority from spec section 14.6:
/// 1. Intra-file calls (local functions/classes)
/// 2. Direct calls via import map
/// 3. Attribute calls (module.func or obj.method)
/// 4. Method calls with receiver type
///
/// # Mitigations Implemented
/// - M2.5: TYPE_CHECKING imports tagged with is_type_only (not implemented in this call,
///   but import_map should filter them if config.runtime_only is set)
/// - M2.4: Dynamic imports (__import__, importlib) - returns None with warning
///
/// # Arguments
/// * `target` - The call target name (e.g., "foo", "bar" from "obj.bar")
/// * `call_type` - Classification of the call
/// * `context` - Shared resolution indexes and state
///
/// # Returns
/// * `Some(ResolvedTarget)` if the call can be resolved
/// * `None` if the call is external, stdlib, or cannot be resolved
///
/// # Example
/// ```rust,ignore
/// // Direct call: foo()
/// let mut context = ResolutionContext {
///     import_map: &import_map,
///     module_imports: &module_imports,
///     func_index: &func_index,
///     class_index: &class_index,
///     reexport_tracer: &mut reexport_tracer,
///     current_file: Path::new("main.py"),
///     root: Path::new("/project"),
///     language: "python",
/// };
/// let target = resolve_call(
///     "foo",
///     &CallType::Direct,
///     &mut context,
/// );
/// ```
pub fn resolve_call(
    target: &str,
    call_type: &CallType,
    context: &mut ResolutionContext<'_, '_>,
) -> Option<ResolvedTarget> {
    let import_map = context.import_map;
    let func_index = context.func_index;
    let class_index = context.class_index;
    let current_file = context.current_file;
    let language = context.language;

    // M2.4: Check for dynamic import patterns - these cannot be resolved
    if target.contains("__import__") || target.contains("importlib") {
        // Dynamic import detected - log warning and return None
        return None;
    }
    if matches!(language, "javascript" | "js" | "typescript" | "tsx") && target == "import" {
        return None;
    }

    // Convert current file to module path (language-aware)
    let current_module = path_to_module(current_file, language);

    match call_type {
        CallType::Intra => {
            // Intra-file call: target is in the same file
            // Look up in func_index using current module
            if let Some(entry) = func_index.get(&current_module, target) {
                return Some(ResolvedTarget {
                    file: entry.file_path.clone(),
                    name: target.to_string(),
                    line: Some(entry.line),
                    is_method: entry.is_method,
                    class_name: entry.class_name.clone(),
                });
            }

            // Also check if it's a class name (calling constructor)
            if let Some(class_entry) = class_index.get(target) {
                // Constructor call - resolve to the actual constructor method (__init__, initialize, etc.)
                if let Some(ctor) =
                    resolve_constructor_target(target, class_entry, func_index, language)
                {
                    return Some(ctor);
                }
                // Fallback: resolve to the class itself
                return Some(ResolvedTarget {
                    file: class_entry.file_path.clone(),
                    name: target.to_string(),
                    line: Some(class_entry.line),
                    is_method: false,
                    class_name: None,
                });
            }

            None
        }

        CallType::Direct => {
            // Direct call to an imported or local name

            // First, check if it's a local function
            if let Some(entry) = func_index.get(&current_module, target) {
                return Some(ResolvedTarget {
                    file: entry.file_path.clone(),
                    name: target.to_string(),
                    line: Some(entry.line),
                    is_method: entry.is_method,
                    class_name: entry.class_name.clone(),
                });
            }

            // Check the import map for "from X import Y" style imports
            if let Some((module_path, original_name)) = import_map.get(target) {
                // BUG FIX 3: Try simple module name first, fallback to full path (CROSSFILE_SPEC.md Section 3.2.1)
                // When resolving `process()` with import_map["process"] = ("pkg.helper", "process"),
                // we need to check both ("helper", "process") and ("pkg.helper", "process").
                let simple_module = module_path.split('.').next_back().unwrap_or(module_path);

                // Normalize JS/TS module paths: strip .js/.ts extensions from import paths
                // Import strings often include .js extension (TS ESM convention)
                let stripped_ext = module_path
                    .strip_suffix(".js")
                    .or_else(|| module_path.strip_suffix(".jsx"))
                    .or_else(|| module_path.strip_suffix(".ts"))
                    .or_else(|| module_path.strip_suffix(".tsx"))
                    .or_else(|| module_path.strip_suffix(".mjs"))
                    .unwrap_or(module_path);

                // For TS/JS: func_index now uses ./prefix keys (matching ModuleIndex),
                // so try stripped_ext directly first (preserves ./ prefix).
                // For Python: try bare module (no ./ prefix) as fallback.
                let mut bare = stripped_ext;
                // Strip all leading ../ prefixes (handles ../../foo -> foo)
                while let Some(rest) = bare.strip_prefix("../") {
                    bare = rest;
                }
                // Also strip single ./ prefix
                let bare_module = bare.strip_prefix("./").unwrap_or(bare);

                // Try extension-stripped path first (preserves ./ for TS/JS)
                if stripped_ext != bare_module {
                    if let Some(entry) = func_index.get(stripped_ext, original_name) {
                        return Some(ResolvedTarget {
                            file: entry.file_path.clone(),
                            name: original_name.clone(),
                            line: Some(entry.line),
                            is_method: entry.is_method,
                            class_name: entry.class_name.clone(),
                        });
                    }
                }

                // Try bare module name (without ./ prefix) -- matches Python-style keys
                if let Some(entry) = func_index.get(bare_module, original_name) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: original_name.clone(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: entry.class_name.clone(),
                    });
                }

                // Try simple module name (last dot component)
                if let Some(entry) = func_index.get(simple_module, original_name) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: original_name.clone(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: entry.class_name.clone(),
                    });
                }
                // Fallback to full module path
                if let Some(entry) = func_index.get(module_path, original_name) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: original_name.clone(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: entry.class_name.clone(),
                    });
                }

                // It might be a class (constructor call via import)
                if let Some(class_entry) = class_index.get(original_name) {
                    // Try resolving to actual constructor method (__init__, initialize, etc.)
                    if let Some(ctor) =
                        resolve_constructor_target(original_name, class_entry, func_index, language)
                    {
                        return Some(ctor);
                    }
                    return Some(ResolvedTarget {
                        file: class_entry.file_path.clone(),
                        name: original_name.clone(),
                        line: Some(class_entry.line),
                        is_method: false,
                        class_name: None,
                    });
                }

                if let Some(resolved) = resolve_reexported_name(
                    module_path,
                    original_name,
                    context.reexport_tracer,
                    func_index,
                    class_index,
                    language,
                ) {
                    return Some(resolved);
                }
            }

            // Check if target is a class name for constructor call
            if let Some(class_entry) = class_index.get(target) {
                if let Some(ctor_target) =
                    resolve_constructor_target(target, class_entry, func_index, language)
                {
                    return Some(ctor_target);
                }

                return Some(ResolvedTarget {
                    file: class_entry.file_path.clone(),
                    name: target.to_string(),
                    line: Some(class_entry.line),
                    is_method: false,
                    class_name: None,
                });
            }

            // VAL-011: Cross-file free-function fallback for languages with
            // implicit cross-file visibility (no explicit import required).
            //
            // Languages where a top-level/free function defined in file A is
            // callable bareword from file B without an `import`:
            // - C / C++: external linkage by default; `#include` declares but
            //   the linker matches names across translation units.
            // - Kotlin / Swift: top-level functions in the same package /
            //   module are visible without an explicit import.
            // - Ruby: `require_relative` loads the file and any top-level
            //   `def` becomes globally callable.
            // - PHP: `require_once` includes the file; functions defined at
            //   file scope become globally available.
            //
            // For these languages, when local + import_map + class_index all
            // miss, search the global FuncIndex by name and accept a unique
            // free-function match.
            if matches!(
                language,
                "c" | "cpp" | "c++" | "kotlin" | "swift" | "ruby" | "php"
            ) {
                if let Some(resolved) =
                    resolve_global_free_function(target, func_index, current_file)
                {
                    return Some(resolved);
                }
            }

            // Not found - likely external/stdlib
            None
        }

        CallType::Attr => {
            // Attribute call like module.func() or obj.method()
            // The "receiver" in CallSite tells us what's before the dot
            // The "target" is the attribute name

            // This is handled in resolve_call_with_receiver since we need receiver info
            // If we get here without receiver context, we can't resolve
            None
        }

        CallType::Method => {
            // Method call with receiver like user.save()
            // Similar to Attr - needs receiver info
            // This is handled in resolve_call_with_receiver
            None
        }

        CallType::Ref => {
            // Function reference without call (higher-order)
            // Resolve like Direct
            if let Some((module_path, original_name)) = import_map.get(target) {
                if let Some(entry) = func_index.get(module_path, original_name) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: original_name.clone(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: entry.class_name.clone(),
                    });
                }
                if let Some(resolved) = resolve_reexported_name(
                    module_path,
                    original_name,
                    context.reexport_tracer,
                    func_index,
                    class_index,
                    language,
                ) {
                    return Some(resolved);
                }
            }

            // Check local
            if let Some(entry) = func_index.get(&current_module, target) {
                return Some(ResolvedTarget {
                    file: entry.file_path.clone(),
                    name: target.to_string(),
                    line: Some(entry.line),
                    is_method: entry.is_method,
                    class_name: entry.class_name.clone(),
                });
            }

            None
        }

        CallType::Static => {
            // Static method call: ClassName::staticMethod() (PHP-style)
            // The target contains "ClassName::methodName"
            if let Some(sep_pos) = target.find("::") {
                let class_name = &target[..sep_pos];
                let method_name = &target[sep_pos + 2..];

                if let Some(resolved) =
                    resolve_call_with_receiver(target, class_name, None, call_type, context)
                {
                    return Some(resolved);
                }

                if let Some(entry) = func_index.get(&current_module, target) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: target.to_string(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: entry.class_name.clone(),
                    });
                }

                let qualified_dot = format!("{}.{}", class_name, method_name);
                if let Some(entry) = func_index.get(&current_module, &qualified_dot) {
                    return Some(ResolvedTarget {
                        file: entry.file_path.clone(),
                        name: method_name.to_string(),
                        line: Some(entry.line),
                        is_method: entry.is_method,
                        class_name: Some(class_name.to_string()),
                    });
                }

                if let Some(resolved) = resolve_method_in_class(
                    class_name,
                    method_name,
                    class_index,
                    func_index,
                    language,
                )
                .or_else(|| {
                    resolve_method_in_bases(
                        class_name,
                        method_name,
                        class_index,
                        func_index,
                        language,
                    )
                }) {
                    return Some(resolved);
                }
            }
            None
        }
    }
}

/// Resolve a method lookup in a specific class via class_index and func_index.
pub(crate) fn resolve_method_in_class(
    class_name: &str,
    method_name: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    let class_entry = class_index.get(class_name)?;
    let module = path_to_module(&class_entry.file_path, language);
    let qualified = format!("{}.{}", class_name, method_name);

    if let Some(entry) = func_index.get(&module, &qualified) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: method_name.to_string(),
            line: Some(entry.line),
            is_method: true,
            class_name: Some(class_name.to_string()),
        });
    }

    if class_entry.methods.contains(&method_name.to_string()) {
        return Some(ResolvedTarget {
            file: class_entry.file_path.clone(),
            name: method_name.to_string(),
            line: Some(class_entry.line),
            is_method: true,
            class_name: Some(class_name.to_string()),
        });
    }

    None
}

/// Resolve a method by traversing base classes via BFS.
pub(crate) fn resolve_method_in_bases(
    class_name: &str,
    method_name: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();

    if let Some(entry) = class_index.get(class_name) {
        for base in &entry.bases {
            queue.push_back(base.clone());
        }
    }

    while let Some(base) = queue.pop_front() {
        if !seen.insert(base.clone()) {
            continue;
        }
        if let Some(resolved) =
            resolve_method_in_class(&base, method_name, class_index, func_index, language)
        {
            return Some(resolved);
        }
        if let Some(entry) = class_index.get(&base) {
            for parent in &entry.bases {
                if !seen.contains(parent) {
                    queue.push_back(parent.clone());
                }
            }
        }
    }

    None
}

/// The PHP magic method invoked when an inaccessible / undefined instance
/// method is called: `public function __call($name, $args)`. This is a PHP
/// *language constant* (symmetric with `__construct`), not a heuristic
/// dictionary — see `constructor_method_candidates`.
const PHP_MAGIC_CALL_METHOD: &str = "__call";

/// T4-php sub-gap 2: find the class (the receiver class itself or the nearest
/// base) that defines the PHP `__call` magic method, used to redirect a call
/// to an undefined instance method.
///
/// Returns a `ResolvedTarget` pointing at `<Owner>.__call` when an owner is
/// found, where `<Owner>` is `receiver_class` or whichever ancestor declares
/// `__call`. Uses the same BFS over `bases` as `resolve_method_in_bases` and
/// only consults the AST-extracted `methods` list (`__call` is a real declared
/// method), so this never fabricates an owner.
fn resolve_magic_call_owner(
    receiver_class: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    // Self first.
    if let Some(resolved) =
        resolve_method_in_class(receiver_class, PHP_MAGIC_CALL_METHOD, class_index, func_index, language)
    {
        return Some(resolved);
    }
    // Then bases (BFS, bounded by `seen`).
    resolve_method_in_bases(receiver_class, PHP_MAGIC_CALL_METHOD, class_index, func_index, language)
}

/// T4-php sub-gap 2: a method is "provably absent" from `receiver_class` (and
/// its bases) when neither the func_index nor the AST-extracted `methods` list
/// of the class or any reachable base declares it. This is exactly the
/// negation of `resolve_method_in_class_or_bases`, but we additionally require
/// that the class is actually KNOWN in `class_index` — if we have no class
/// entry we cannot prove absence and must stay conservative (return false).
fn method_is_provably_absent(
    receiver_class: &str,
    method_name: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> bool {
    if class_index.get(receiver_class).is_none() {
        // Unknown class: cannot prove absence.
        return false;
    }
    resolve_method_in_class_or_bases(receiver_class, method_name, class_index, func_index, language)
        .is_none()
}

/// Check if a type name is a known Python/Ruby/etc stdlib or builtin type.
///
/// These types' methods should never resolve to project-internal classes via
/// the fuzzy fallback strategies (7, 8). For example, `OrderedDict.items()`
/// should not resolve to `RequestsCookieJar.items()`.
fn is_stdlib_type(name: &str) -> bool {
    matches!(
        name,
        // Python builtins
        "dict" | "list" | "set" | "tuple" | "frozenset" | "str" | "bytes"
        | "bytearray" | "int" | "float" | "bool" | "complex" | "object"
        | "type" | "range" | "memoryview" | "slice" | "None" | "NoneType"
        // Python collections
        | "OrderedDict" | "defaultdict" | "deque" | "Counter" | "ChainMap"
        | "namedtuple" | "UserDict" | "UserList" | "UserString"
        // Python io
        | "StringIO" | "BytesIO" | "TextIOWrapper" | "BufferedReader"
        // Python pathlib
        | "Path" | "PurePath" | "PosixPath" | "WindowsPath"
        // Python typing module aliases
        | "Dict" | "List" | "Set" | "Tuple" | "FrozenSet" | "Optional"
        | "Union" | "Any" | "Callable" | "Type" | "Sequence" | "Mapping"
        | "MutableMapping" | "MutableSequence" | "MutableSet" | "Iterator"
        | "Iterable" | "Generator" | "Coroutine" | "AsyncGenerator"
        // Ruby builtins
        | "Array" | "Hash" | "String" | "Integer" | "Float" | "Symbol"
        | "Regexp" | "Proc" | "Lambda" | "IO" | "File" | "Dir"
    )
}

/// Check if a method name is commonly defined on builtin types (dict, list, str, etc.).
/// When the receiver has no inferred type, these names are too ambiguous to resolve
/// via class scanning -- they'd match project classes that happen to define the same method.
///
/// # Relationship to the cardinality gate
///
/// This is a small, fixed per-language *leaf vocabulary* of method names that
/// belong to language builtins (Python dict/list/set/str/io, Go's JSON/text
/// marshalling). It is deliberately retained ALONGSIDE the index-derived
/// [`count_unrelated_method_definers`] cardinality gate, because the two cover
/// different cases and neither subsumes the other:
///
/// * The cardinality gate declines a name defined on >1 unrelated class, but a
///   builtin name (e.g. `items`) defined on exactly ONE project class would
///   slip past it and bind — even though an untyped receiver calling `.items()`
///   is far more likely a real `dict` than that lone class. This blocklist
///   suppresses that single-definer case.
/// * Conversely, this blocklist only knows a fixed set of names; the gate
///   handles arbitrary project method names (e.g. `speak` on Animal/Robot/Plant)
///   that no hand-maintained list could enumerate.
///
/// It is NOT a structural decision over source text — it only classifies an
/// already-AST-extracted identifier against a language-builtin vocabulary, which
/// is permitted under the AST-driven mandate (named leaf tables are allowed).
fn is_builtin_method_name(name: &str) -> bool {
    matches!(
        name,
        // dict methods
        "items" | "values" | "keys" | "get" | "pop" | "update" | "setdefault"
        | "clear" | "copy" | "popitem"
        // list methods
        | "append" | "extend" | "insert" | "remove" | "sort" | "reverse" | "count" | "index"
        // set methods
        | "add" | "discard" | "union" | "intersection" | "difference"
        // str methods
        | "strip" | "split" | "join" | "replace" | "format" | "encode" | "decode"
        | "startswith" | "endswith" | "lower" | "upper" | "find"
        // io methods
        | "close" | "read" | "write" | "flush" | "seek" | "tell" | "readline"
        // Go serialization methods (safe to block -- rarely project method names)
        | "MarshalJSON" | "UnmarshalJSON" | "MarshalText" | "UnmarshalText"
        // very common names that collide across unrelated types
        | "invoke" | "call" | "run" | "execute" | "send" | "receive"
        | "start" | "stop" | "reset" | "setup" | "teardown"
    )
}

/// Count how many *mutually-unrelated* classes in the AST-built `class_index`
/// declare a method named `method_name`.
///
/// "Unrelated" means not joined by inheritance: an overriding subclass and its
/// base both declaring `speak` count as ONE definer (they are the same dispatch
/// target up the MRO), whereas `Animal`, `Robot`, and `Plant` each declaring an
/// independent `speak` count as THREE. This is the index-derived ambiguity
/// signal used by the untyped-receiver fuzzy gate: a bare method defined on >1
/// unrelated class cannot be bound without a receiver type, so the call is
/// declined rather than mis-bound to an order-dependent survivor.
///
/// Purely structural: it consults only the AST-extracted `ClassEntry.methods`
/// and `ClassEntry.bases` (via [`is_in_inheritance_chain`]); no source text or
/// name heuristics are involved.
fn count_unrelated_method_definers(method_name: &str, class_index: &ClassIndex) -> usize {
    // Classes (by name) that declare the method directly.
    let definers: Vec<&str> = class_index
        .iter()
        .filter(|(_name, entry)| entry.methods.iter().any(|m| m == method_name))
        .map(|(name, _entry)| name)
        .collect();

    // Collapse inheritance-linked definers into a single representative so a
    // base/override pair is not double-counted.
    let mut representatives: Vec<&str> = Vec::new();
    for &class in &definers {
        let linked_to_existing = representatives
            .iter()
            .any(|&rep| is_in_inheritance_chain(class, rep, class_index));
        if !linked_to_existing {
            representatives.push(class);
        }
    }
    representatives.len()
}

/// Check if `candidate_class` is in the inheritance chain of `receiver_class`.
///
/// Returns true if:
/// - candidate_class == receiver_class (same class)
/// - candidate_class is a base (parent) of receiver_class (direct or transitive)
/// - receiver_class is a base of candidate_class (child calling parent's method via self)
///
/// Uses BFS to traverse the inheritance tree up to a bounded depth.
fn is_in_inheritance_chain(
    receiver_class: &str,
    candidate_class: &str,
    class_index: &ClassIndex,
) -> bool {
    if receiver_class == candidate_class {
        return true;
    }

    // Check if candidate_class is an ancestor of receiver_class (self.method() calling parent method)
    {
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut seen: HashSet<String> = HashSet::new();

        if let Some(entry) = class_index.get(receiver_class) {
            for base in &entry.bases {
                queue.push_back(base.clone());
            }
        }

        while let Some(base) = queue.pop_front() {
            if !seen.insert(base.clone()) {
                continue;
            }
            if base == candidate_class {
                return true;
            }
            if let Some(entry) = class_index.get(&base) {
                for parent in &entry.bases {
                    if !seen.contains(parent) {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }
    }

    // Check if receiver_class is an ancestor of candidate_class (less common, but possible)
    {
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut seen: HashSet<String> = HashSet::new();

        if let Some(entry) = class_index.get(candidate_class) {
            for base in &entry.bases {
                queue.push_back(base.clone());
            }
        }

        while let Some(base) = queue.pop_front() {
            if !seen.insert(base.clone()) {
                continue;
            }
            if base == receiver_class {
                return true;
            }
            if let Some(entry) = class_index.get(&base) {
                for parent in &entry.bases {
                    if !seen.contains(parent) {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }
    }

    false
}

/// Resolve a call that has receiver information (Method or Attr calls).
///
/// This function handles calls like `receiver.target()` where we need to determine
/// whether `receiver` is a module (import) or an object instance.
///
/// # Arguments
/// * `target` - The method/attribute being called
/// * `receiver` - The receiver (what's before the dot)
/// * `receiver_type` - Inferred type of receiver, if known
/// * `call_type` - Either Method or Attr
/// * `context` - Shared resolution indexes and state
///
/// # Resolution Strategy
/// 1. If receiver is a known module import -> resolve as module.func
/// 2. If receiver_type is known -> resolve as Type.method
/// 3. If receiver is a class name -> resolve as static call
/// 4. Search class index for method name matches
pub fn resolve_call_with_receiver(
    target: &str,
    receiver: &str,
    receiver_type: Option<&str>,
    _call_type: &CallType,
    context: &mut ResolutionContext<'_, '_>,
) -> Option<ResolvedTarget> {
    let import_map = context.import_map;
    let module_imports = context.module_imports;
    let func_index = context.func_index;
    let class_index = context.class_index;
    let current_file = context.current_file;
    let language = context.language;

    let current_module = path_to_module(current_file, language);
    let bare_target = normalize_receiver_target(target, receiver);

    if let Some(resolved) = resolve_with_receiver_type(
        receiver_type,
        bare_target,
        class_index,
        func_index,
        language,
    ) {
        return Some(resolved);
    }

    // T4-php sub-gap 2: PHP `__call` magic-method redirect.
    //
    // When the receiver's type is KNOWN (a real user class) but the called
    // method is provably absent from that class and all of its bases, and the
    // class (or a base) declares `__call`, PHP routes the call through
    // `__call` at runtime. Redirect the edge to `<Owner>.__call` so the
    // dependency is captured instead of being dropped or mis-bound by the
    // permissive fuzzy fallbacks below.
    //
    // This is gated to PHP only (the shared resolver also serves Python/Ruby
    // etc., which must be unaffected). `__call` is a PHP language constant, not
    // a heuristic. It runs only AFTER `resolve_with_receiver_type` declined,
    // so a method that genuinely exists on the class/bases is never diverted.
    // Conservative by construction: `method_is_provably_absent` requires a
    // known class entry, so when the type is uncertain (e.g. unresolved trait
    // composition leaves the methods list incomplete and the class itself
    // missing) we do NOT redirect.
    if language.eq_ignore_ascii_case("php") {
        if let Some(receiver_class) = receiver_type {
            // `method_is_provably_absent` already requires a KNOWN class entry,
            // so an unknown receiver type can never trigger the redirect.
            if method_is_provably_absent(
                receiver_class,
                bare_target,
                class_index,
                func_index,
                language,
            ) {
                if let Some(resolved) =
                    resolve_magic_call_owner(receiver_class, class_index, func_index, language)
                {
                    return Some(resolved);
                }
            }
        }
    }

    if let Some(resolved) = resolve_self_receiver_in_current_file(
        receiver,
        bare_target,
        &current_module,
        func_index,
        class_index,
    ) {
        return Some(resolved);
    }

    let mut receiver_context = ReceiverLookupContext {
        func_index,
        class_index,
        reexport_tracer: context.reexport_tracer,
        language,
    };

    if let Some(resolved) = resolve_module_import_receiver(
        target,
        receiver,
        bare_target,
        module_imports,
        &mut receiver_context,
    ) {
        return Some(resolved);
    }

    if let Some(resolved) = resolve_import_map_receiver(
        target,
        receiver,
        bare_target,
        import_map,
        &mut receiver_context,
    ) {
        return Some(resolved);
    }

    if let Some(resolved) =
        resolve_method_in_class_or_bases(receiver, bare_target, class_index, func_index, language)
    {
        return Some(resolved);
    }

    if let Some(resolved) =
        resolve_local_qualified_receiver(receiver, bare_target, &current_module, func_index)
    {
        return Some(resolved);
    }

    if let Some(resolved) =
        resolve_capitalized_receiver(receiver, bare_target, class_index, func_index, language)
    {
        return Some(resolved);
    }

    // VAL-011: OCaml module-of-file resolution (no explicit imports).
    //
    // OCaml derives the module name from a file's basename with the first
    // letter capitalized (e.g. `util.ml` → module `Util`). Sibling modules
    // are visible without an `open` statement, and the canonical call
    // syntax is `Util.b_util ()`.
    //
    // The class_index doesn't help (OCaml has no classes), and
    // module_imports is empty (no `import` statement was parsed), so the
    // standard receiver-lookup chain produces nothing. We bridge that gap
    // by looking up the receiver lower-cased as a func_index module key.
    if language == "ocaml" {
        if let Some(resolved) = resolve_ocaml_module_receiver(receiver, bare_target, func_index) {
            return Some(resolved);
        }
    }

    let type_filter = receiver_type_filter(receiver_type, receiver, class_index);

    // fix-cl-3b-v1 (v0.5.0 CL-3b, IT3-rust-07 / #74): a qualified
    // `Receiver::method` whose `Receiver` is a *capitalized type spelling*
    // (e.g. `HashSet::new()`, `Vec::new()`) must NOT have its bare method
    // (`new`) fuzzy-bound to an unrelated same-file user struct's method
    // (`DepStats::new`). When the receiver is capitalized AND is not a
    // known user class (so the class-scoped resolvers above already
    // declined), it names an external/stdlib type with no user-defined
    // definition; the only acceptable fuzzy candidate is one whose
    // `class_name` actually equals that receiver. We pass the receiver as a
    // strict class gate so a mismatched-class candidate is rejected rather
    // than silently bound. Lowercase receivers (ordinary variables) keep
    // the prior permissive behavior — they are not type spellings.
    let strict_receiver_class: Option<&str> = if receiver_is_type_spelling(receiver)
        && class_index.get(receiver).is_none()
        && type_filter.is_none()
    {
        Some(receiver)
    } else {
        None
    };

    if let Some(resolved) = resolve_local_fuzzy_match(
        bare_target,
        type_filter,
        strict_receiver_class,
        func_index,
        class_index,
        current_file,
    ) {
        return Some(resolved);
    }
    if let Some(resolved) = resolve_global_fuzzy_match(
        bare_target,
        type_filter,
        strict_receiver_class,
        func_index,
        class_index,
    ) {
        return Some(resolved);
    }

    resolve_type_aware_fallback(receiver_type, bare_target, func_index, class_index)
}

/// fix-cl-3b-v1 (v0.5.0 CL-3b): a receiver token is a "type spelling" when
/// the LAST segment of its qualified path begins with an ASCII uppercase
/// letter — the convention for type / module names across Rust
/// (`HashSet`, `Vec`, `DepStats`, the fully-qualified
/// `std::collections::HashSet`), the JVM languages, Swift, and OCaml
/// modules. The last-segment test is essential: Rust constructor calls are
/// frequently spelled with a fully-qualified path whose leading segments
/// are lowercase crate/module names (`std::collections::HashSet::new()`),
/// so a naive first-char check would miss them. Ordinary value receivers
/// (locals, fields, `self`) are lowercase in their final segment and are
/// deliberately excluded so their permissive variable-receiver fuzzy
/// resolution is unchanged.
fn receiver_is_type_spelling(receiver: &str) -> bool {
    // fix-testdebt-repair-r2: a receiver that carries call-expression syntax
    // (`(`/`)`) is an *instance produced by invoking a constructor* (e.g.
    // Python `Scaffold().route(...)`, where the receiver token is
    // `Scaffold()`), NOT a bare type spelling. Such instance receivers must
    // keep the permissive method-resolution path so `.route` binds to
    // `Scaffold.route`. The cl-3b strict gate only targets bare type tokens
    // (`HashSet`, `std::collections::HashSet`) whose `::new()` call has no
    // user-defined definition — those never contain parentheses in the
    // receiver token itself. Restricting the strict gate to paren-free
    // receivers preserves the cl-3b `HashSet::new` guard while no longer
    // mis-declining instance-method calls.
    if receiver.contains('(') || receiver.contains(')') {
        return false;
    }
    let last_segment = receiver
        .rsplit("::")
        .next()
        .and_then(|s| s.rsplit('.').next())
        .unwrap_or(receiver);
    last_segment
        .chars()
        .next()
        .map(|c| c.is_ascii_uppercase())
        .unwrap_or(false)
}

fn normalize_receiver_target<'a>(target: &'a str, receiver: &str) -> &'a str {
    target
        .strip_prefix(&format!("{}.", receiver))
        .or_else(|| target.strip_prefix(&format!("{}::", receiver)))
        .or_else(|| target.strip_prefix(&format!("{}->", receiver)))
        .unwrap_or(target)
}

fn resolve_with_receiver_type(
    receiver_type: Option<&str>,
    bare_target: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    let type_name = receiver_type?;
    resolve_method_in_class_or_bases(type_name, bare_target, class_index, func_index, language)
}

fn resolve_self_receiver_in_current_file(
    receiver: &str,
    bare_target: &str,
    current_module: &str,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
) -> Option<ResolvedTarget> {
    if !matches!(receiver, "self" | "cls" | "this" | "Self") {
        return None;
    }
    if let Some(entry) = func_index.get(current_module, bare_target) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: true,
            class_name: entry.class_name.clone(),
        });
    }
    let class_entry = class_index.get(bare_target)?;
    Some(ResolvedTarget {
        file: class_entry.file_path.clone(),
        name: bare_target.to_string(),
        line: Some(class_entry.line),
        is_method: false,
        class_name: Some(bare_target.to_string()),
    })
}

struct ReceiverLookupContext<'a, 'b> {
    func_index: &'a FuncIndex,
    class_index: &'a ClassIndex,
    reexport_tracer: &'a mut ReExportTracer<'b>,
    language: &'a str,
}

fn resolve_module_import_receiver(
    target: &str,
    receiver: &str,
    bare_target: &str,
    module_imports: &ModuleImports,
    context: &mut ReceiverLookupContext<'_, '_>,
) -> Option<ResolvedTarget> {
    let module_path = module_imports.get(receiver)?;
    let simple_module = module_path.split('.').next_back().unwrap_or(module_path);

    if let Some(entry) = context.func_index.get(module_path, bare_target) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }
    if simple_module != module_path.as_str() {
        if let Some(entry) = context.func_index.get(simple_module, bare_target) {
            return Some(ResolvedTarget {
                file: entry.file_path.clone(),
                name: bare_target.to_string(),
                line: Some(entry.line),
                is_method: entry.is_method,
                class_name: entry.class_name.clone(),
            });
        }
    }
    if bare_target != target {
        if let Some(entry) = context.func_index.get(module_path, target) {
            return Some(ResolvedTarget {
                file: entry.file_path.clone(),
                name: target.to_string(),
                line: Some(entry.line),
                is_method: entry.is_method,
                class_name: entry.class_name.clone(),
            });
        }
    }

    resolve_reexported_name(
        module_path,
        bare_target,
        context.reexport_tracer,
        context.func_index,
        context.class_index,
        context.language,
    )
}

fn resolve_import_map_receiver(
    target: &str,
    receiver: &str,
    bare_target: &str,
    import_map: &ImportMap,
    context: &mut ReceiverLookupContext<'_, '_>,
) -> Option<ResolvedTarget> {
    let (module_path, original_name) = import_map.get(receiver)?;
    if let Some(resolved) = resolve_method_in_class_or_bases(
        original_name,
        bare_target,
        context.class_index,
        context.func_index,
        context.language,
    ) {
        return Some(resolved);
    }

    if let Some(entry) = context.func_index.get(module_path, bare_target) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }
    if bare_target != target {
        if let Some(entry) = context.func_index.get(module_path, target) {
            return Some(ResolvedTarget {
                file: entry.file_path.clone(),
                name: target.to_string(),
                line: Some(entry.line),
                is_method: entry.is_method,
                class_name: entry.class_name.clone(),
            });
        }
    }

    resolve_reexported_receiver_target(
        module_path,
        original_name,
        bare_target,
        context.reexport_tracer,
        context.func_index,
        context.class_index,
        context.language,
    )
}

fn resolve_method_in_class_or_bases(
    class_name: &str,
    method_name: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    resolve_method_in_class(class_name, method_name, class_index, func_index, language).or_else(
        || resolve_method_in_bases(class_name, method_name, class_index, func_index, language),
    )
}

fn resolve_local_qualified_receiver(
    receiver: &str,
    bare_target: &str,
    current_module: &str,
    func_index: &FuncIndex,
) -> Option<ResolvedTarget> {
    let qualified = format!("{}.{}", receiver, bare_target);
    let entry = func_index.get(current_module, &qualified)?;
    Some(ResolvedTarget {
        file: entry.file_path.clone(),
        name: bare_target.to_string(),
        line: Some(entry.line),
        is_method: entry.is_method,
        class_name: entry.class_name.clone(),
    })
}

fn resolve_capitalized_receiver(
    receiver: &str,
    bare_target: &str,
    class_index: &ClassIndex,
    func_index: &FuncIndex,
    language: &str,
) -> Option<ResolvedTarget> {
    let capitalized = capitalize_first(receiver);
    if capitalized == receiver {
        return None;
    }
    resolve_method_in_class_or_bases(&capitalized, bare_target, class_index, func_index, language)
}

/// VAL-011: Resolve a `Module.target` receiver call for OCaml.
///
/// OCaml requires no explicit `open` for sibling modules — `Util.b_util ()`
/// in `main.ml` directly references the `b_util` function defined in
/// `util.ml`. The func_index keys lowercase module names (`util`), so we
/// try the lowercase form, the bare receiver, and the dot-segment lower
/// transforms before giving up.
///
/// We accept the match unconditionally (no ambiguity-check) because OCaml
/// module names are file-bound: at most one `util.ml` exists per directory,
/// so `Util.b_util` cannot collide.
fn resolve_ocaml_module_receiver(
    receiver: &str,
    bare_target: &str,
    func_index: &FuncIndex,
) -> Option<ResolvedTarget> {
    let lowercase = receiver.to_ascii_lowercase();
    // Try direct lowercase ("Util" → "util")
    if let Some(entry) = func_index.get(&lowercase, bare_target) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }
    // Try bare receiver as-is (in case the index already used the
    // capitalized alias from `compute_module_aliases`)
    if let Some(entry) = func_index.get(receiver, bare_target) {
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }
    None
}

fn receiver_type_filter<'a>(
    receiver_type: Option<&'a str>,
    receiver: &str,
    class_index: &ClassIndex,
) -> Option<&'a str> {
    receiver_type.filter(|type_name| {
        if class_index.get(type_name).is_some() {
            return true;
        }
        if matches!(receiver, "self" | "cls" | "this" | "Self") {
            return true;
        }
        is_stdlib_type(type_name)
    })
}

fn resolve_local_fuzzy_match(
    bare_target: &str,
    type_filter: Option<&str>,
    strict_receiver_class: Option<&str>,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
    current_file: &Path,
) -> Option<ResolvedTarget> {
    // T4-py untyped-receiver ambiguity gate. Decline a bare method on an
    // untyped receiver when EITHER:
    //  (1) it is a well-known builtin-type method name (`items`, `append`,
    //      Go's `MarshalJSON`, ...): the receiver is far more likely a real
    //      builtin than a same-named project class, even at cardinality 1; or
    //  (2) it is declared on >1 mutually-unrelated class in the AST-built
    //      class_index: a genuinely ambiguous duck-typed dispatch with no
    //      single correct target.
    // These are complementary — (1) catches single-definer builtin names that
    // the cardinality signal (2) cannot, while (2) catches arbitrary project
    // names (e.g. `speak` across Animal/Robot/Plant) that the fixed-vocabulary
    // blocklist (1) never enumerated. See `count_unrelated_method_definers`.
    if type_filter.is_none()
        && (is_builtin_method_name(bare_target)
            || count_unrelated_method_definers(bare_target, class_index) > 1)
    {
        return None;
    }

    let local_matches: Vec<_> = func_index
        .iter()
        .filter(|((_module, func_name), entry)| {
            if *func_name != bare_target || entry.file_path != current_file {
                return false;
            }
            // fix-cl-3b-v1 (IT3-rust-07): when the call's receiver is a
            // capitalized external/stdlib type spelling (e.g. `HashSet`),
            // only accept a candidate whose `class_name` is exactly that
            // type. This blocks `HashSet::new()` from binding to a
            // same-file `DepStats::new`.
            if let Some(recv_class) = strict_receiver_class {
                match &entry.class_name {
                    Some(c) if c == recv_class => {}
                    _ => return false,
                }
            }
            if let Some(type_name) = type_filter {
                if let Some(ref candidate_class) = entry.class_name {
                    return is_in_inheritance_chain(type_name, candidate_class, class_index);
                }
            }
            true
        })
        .collect();

    if local_matches.len() == 1 || (type_filter.is_some() && !local_matches.is_empty()) {
        let (_, entry) = local_matches[0];
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: entry.is_method,
            class_name: entry.class_name.clone(),
        });
    }
    None
}

/// VAL-011: Cross-file free-function fallback for languages with implicit
/// cross-file visibility.
///
/// Searches the global FuncIndex for a non-method function named `target`
/// defined in any file other than `current_file`. Returns the unique match
/// when exactly one cross-file definition exists (avoids ambiguity).
///
/// This is the keystone of cross-file Direct call resolution for C, C++,
/// Kotlin, Swift, Ruby, and PHP — languages where bareword `foo()` in file
/// A may resolve to `foo` defined in file B without an explicit import in
/// the source.
///
/// Why "unique cross-file match" rather than "first match":
/// - If `target` is also defined in `current_file`, we already returned at
///   the local-module check earlier in `resolve_call`.
/// - If multiple cross-file definitions exist, the call is genuinely
///   ambiguous (e.g. C overload by header convention) and we decline to
///   guess; callers fall through to "unresolved" rather than picking wrong.
///
/// Note: `func_index` keys functions under multiple module aliases (e.g.
/// `util.c` AND the simple-name alias `c`), so the same function can appear
/// multiple times via `find_by_name`. We deduplicate by `(file_path, line)`
/// before deciding ambiguity.
fn resolve_global_free_function(
    target: &str,
    func_index: &FuncIndex,
    current_file: &Path,
) -> Option<ResolvedTarget> {
    let mut seen: HashSet<(PathBuf, u32)> = HashSet::new();
    let mut unique: Vec<&FuncEntry> = Vec::new();
    for entry in func_index.find_by_name(target) {
        if entry.is_method || entry.file_path == current_file {
            continue;
        }
        let key = (entry.file_path.clone(), entry.line);
        if seen.insert(key) {
            unique.push(entry);
            if unique.len() > 1 {
                // Ambiguous: multiple distinct cross-file definitions.
                return None;
            }
        }
    }

    let first = unique.into_iter().next()?;
    Some(ResolvedTarget {
        file: first.file_path.clone(),
        name: target.to_string(),
        line: Some(first.line),
        is_method: false,
        class_name: None,
    })
}

fn resolve_global_fuzzy_match(
    bare_target: &str,
    type_filter: Option<&str>,
    strict_receiver_class: Option<&str>,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
) -> Option<ResolvedTarget> {
    // T4-py untyped-receiver ambiguity gate (see `resolve_local_fuzzy_match`
    // for the full rationale): decline when the bare method is a known builtin
    // name OR is declared on >1 mutually-unrelated class. The two checks are
    // complementary; neither subsumes the other.
    if type_filter.is_none()
        && (is_builtin_method_name(bare_target)
            || count_unrelated_method_definers(bare_target, class_index) > 1)
    {
        return None;
    }

    // fix-cl-3b-v1 (IT3-rust-07): a capitalized external/stdlib receiver
    // type (e.g. `HashSet`) that is not a known user class must never
    // fuzzy-bind its bare method to an unrelated user class. There is no
    // candidate whose `class_name` equals such a receiver (it has no
    // user-defined definition), so decline outright rather than letting the
    // method-only / function-level fallbacks pick a wrong same-named target.
    if let Some(recv_class) = strict_receiver_class {
        let exact = func_index
            .find_by_name(bare_target)
            .any(|e| e.class_name.as_deref() == Some(recv_class));
        if !exact {
            return None;
        }
    }

    let mut candidates: Vec<_> = func_index
        .find_by_name(bare_target)
        .filter(|e| e.is_method)
        .collect();
    if let Some(recv_class) = strict_receiver_class {
        candidates.retain(|e| e.class_name.as_deref() == Some(recv_class));
    }
    if let Some(type_name) = type_filter {
        candidates.retain(|e| match &e.class_name {
            Some(c) => is_in_inheritance_chain(type_name, c, class_index),
            None => false,
        });
    }
    if candidates.len() == 1 {
        let entry = candidates[0];
        return Some(ResolvedTarget {
            file: entry.file_path.clone(),
            name: bare_target.to_string(),
            line: Some(entry.line),
            is_method: true,
            class_name: entry.class_name.clone(),
        });
    }
    if !candidates.is_empty() {
        return None;
    }

    // language-adapters-completeness-v1 (BUG-AGG12-7): CommonJS
    // method-on-object assignments register as plain `FuncDef::function`
    // entries (not methods), so the method-only filter above misses
    // them. When no method matched and no receiver type was supplied,
    // fall back to a unique function-level match by bare name. This is
    // what lets `app.init()` in express/lib/express.js resolve to the
    // `app.init = function init() { ... }` definition in
    // express/lib/application.js.
    if type_filter.is_none() {
        let func_candidates: Vec<_> = func_index
            .find_by_name(bare_target)
            .filter(|e| !e.is_method)
            .collect();
        if func_candidates.len() == 1 {
            let entry = func_candidates[0];
            return Some(ResolvedTarget {
                file: entry.file_path.clone(),
                name: bare_target.to_string(),
                line: Some(entry.line),
                is_method: false,
                class_name: entry.class_name.clone(),
            });
        }
    }
    None
}

fn resolve_type_aware_fallback(
    receiver_type: Option<&str>,
    bare_target: &str,
    func_index: &FuncIndex,
    class_index: &ClassIndex,
) -> Option<ResolvedTarget> {
    let type_name = receiver_type?;
    if let Some(class_entry) = class_index.get(type_name) {
        if class_entry.methods.contains(&bare_target.to_string()) {
            return Some(ResolvedTarget {
                file: class_entry.file_path.clone(),
                name: bare_target.to_string(),
                line: Some(class_entry.line),
                is_method: true,
                class_name: Some(type_name.to_string()),
            });
        }
        for base in &class_entry.bases {
            if let Some(base_entry) = class_index.get(base.as_str()) {
                if base_entry.methods.contains(&bare_target.to_string()) {
                    return Some(ResolvedTarget {
                        file: base_entry.file_path.clone(),
                        name: bare_target.to_string(),
                        line: Some(base_entry.line),
                        is_method: true,
                        class_name: Some(base.to_string()),
                    });
                }
            }
        }
    }

    for ((_module, func_name), entry) in func_index.iter() {
        if func_name == bare_target && entry.class_name.as_deref() == Some(type_name) {
            return Some(ResolvedTarget {
                file: entry.file_path.clone(),
                name: bare_target.to_string(),
                line: Some(entry.line),
                is_method: true,
                class_name: Some(type_name.to_string()),
            });
        }
    }
    None
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // From new sibling modules:
    use super::super::imports::{augment_go_module_imports, ImportMap, ModuleImports};
    use super::super::module_path::path_to_module;
    use super::super::types::{ClassEntry, ClassIndex, FuncEntry, FuncIndex};
    // From existing sibling modules:
    use crate::callgraph::cross_file_types::{CallType, ImportDef};
    use crate::callgraph::import_resolver::ReExportTracer;
    use crate::callgraph::module_index::ModuleIndex;

    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    macro_rules! resolve_call {
        (
            $target:expr,
            $call_type:expr,
            $import_map:expr,
            $module_imports:expr,
            $func_index:expr,
            $class_index:expr,
            $reexport_tracer:expr,
            $current_file:expr,
            $root:expr,
            $language:expr $(,)?
        ) => {{
            let mut context = ResolutionContext {
                import_map: $import_map,
                module_imports: $module_imports,
                func_index: $func_index,
                class_index: $class_index,
                reexport_tracer: $reexport_tracer,
                current_file: $current_file,
                root: $root,
                language: $language,
            };
            super::resolve_call($target, $call_type, &mut context)
        }};
    }

    macro_rules! resolve_call_with_receiver {
        (
            $target:expr,
            $receiver:expr,
            $receiver_type:expr,
            $call_type:expr,
            $import_map:expr,
            $module_imports:expr,
            $func_index:expr,
            $class_index:expr,
            $reexport_tracer:expr,
            $current_file:expr,
            $root:expr,
            $language:expr $(,)?
        ) => {{
            let mut context = ResolutionContext {
                import_map: $import_map,
                module_imports: $module_imports,
                func_index: $func_index,
                class_index: $class_index,
                reexport_tracer: $reexport_tracer,
                current_file: $current_file,
                root: $root,
                language: $language,
            };
            super::resolve_call_with_receiver(
                $target,
                $receiver,
                $receiver_type,
                $call_type,
                &mut context,
            )
        }};
    }

    /// Test: ResolvedTarget::function creates a function target
    #[test]
    fn test_resolved_target_function() {
        let target = ResolvedTarget::function(PathBuf::from("helper.py"), "process", Some(10));

        assert_eq!(target.file, PathBuf::from("helper.py"));
        assert_eq!(target.name, "process");
        assert_eq!(target.line, Some(10));
        assert!(!target.is_method);
        assert!(target.class_name.is_none());
        assert_eq!(target.qualified_name(), "process");
    }

    /// Test: ResolvedTarget::method creates a method target
    #[test]
    fn test_resolved_target_method() {
        let target = ResolvedTarget::method(PathBuf::from("models.py"), "save", "User", Some(42));

        assert_eq!(target.file, PathBuf::from("models.py"));
        assert_eq!(target.name, "save");
        assert_eq!(target.line, Some(42));
        assert!(target.is_method);
        assert_eq!(target.class_name, Some("User".to_string()));
        assert_eq!(target.qualified_name(), "User.save");
    }

    /// Test: resolve_call for intra-file calls
    #[test]
    fn test_resolve_call_intra() {
        // Setup: Create a func_index with a local function
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "main",
            "helper",
            FuncEntry::function(PathBuf::from("main.py"), 10, 15),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call resolve_call for an intra-file call
        let resolved = resolve_call!(
            "helper",
            &CallType::Intra,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve intra-file call");
        let target = resolved.unwrap();
        assert_eq!(target.file, PathBuf::from("main.py"));
        assert_eq!(target.name, "helper");
        assert!(!target.is_method);
    }

    /// Test: resolve_call for direct calls via import map
    #[test]
    fn test_resolve_call_direct_import() {
        // Setup: Function is in helper module, imported as 'process'
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "helper",
            "process",
            FuncEntry::function(PathBuf::from("helper.py"), 5, 10),
        );

        let mut import_map = ImportMap::new();
        import_map.insert(
            "process".to_string(),
            ("helper".to_string(), "process".to_string()),
        );

        let module_imports = ModuleImports::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call resolve_call for a direct call to imported name
        let resolved = resolve_call!(
            "process",
            &CallType::Direct,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(
            resolved.is_some(),
            "Should resolve direct call via import map"
        );
        let target = resolved.unwrap();
        assert_eq!(target.file, PathBuf::from("helper.py"));
        assert_eq!(target.name, "process");
    }

    /// Test: resolve_call returns None for external/stdlib
    #[test]
    fn test_resolve_call_external() {
        let func_index = FuncIndex::new();
        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call to something not in project
        let resolved = resolve_call!(
            "json_loads",
            &CallType::Direct,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(
            resolved.is_none(),
            "External/stdlib calls should return None"
        );
    }

    /// Test: resolve_call detects dynamic imports (M2.4)
    #[test]
    fn test_resolve_call_dynamic_import() {
        let func_index = FuncIndex::new();
        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Dynamic import pattern
        let resolved = resolve_call!(
            "__import__",
            &CallType::Direct,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_none(), "Dynamic imports should return None");
    }

    /// Test: resolve_call_with_receiver for module.func pattern
    #[test]
    fn test_resolve_call_module_func() {
        // Setup: json module with loads function
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "json",
            "loads",
            FuncEntry::function(PathBuf::from("json.py"), 100, 120),
        );

        let import_map = ImportMap::new();
        let mut module_imports = ModuleImports::new();
        module_imports.insert("json".to_string(), "json".to_string());

        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: json.loads()
        let resolved = resolve_call_with_receiver!(
            "loads",
            "json",
            None,
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve module.func pattern");
        let target = resolved.unwrap();
        assert_eq!(target.name, "loads");
    }

    /// Test: resolve_call_with_receiver for method with known receiver type
    #[test]
    fn test_resolve_call_method_with_type() {
        // Setup: User class with save method
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "models",
            "User.save",
            FuncEntry::method(PathBuf::from("models.py"), 50, 60, "User".to_string()),
        );

        let mut class_index = ClassIndex::new();
        class_index.insert(
            "User",
            ClassEntry::new(
                PathBuf::from("models.py"),
                10,
                100,
                vec!["save".to_string(), "delete".to_string()],
                vec![],
            ),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: user.save() where user: User
        let resolved = resolve_call_with_receiver!(
            "save",
            "user",
            Some("User"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve method with known type");
        let target = resolved.unwrap();
        assert_eq!(target.name, "save");
        assert!(target.is_method);
        assert_eq!(target.class_name, Some("User".to_string()));
    }

    /// Test: Ref call type resolution
    #[test]
    fn test_resolve_call_ref() {
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "utils",
            "transform",
            FuncEntry::function(PathBuf::from("utils.py"), 5, 15),
        );

        let mut import_map = ImportMap::new();
        import_map.insert(
            "transform".to_string(),
            ("utils".to_string(), "transform".to_string()),
        );

        let module_imports = ModuleImports::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Reference to transform function (passed as callback)
        let resolved = resolve_call!(
            "transform",
            &CallType::Ref,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve Ref call type");
        let target = resolved.unwrap();
        assert_eq!(target.name, "transform");
    }

    /// Test: Static call type resolution (PHP-style)
    #[test]
    fn test_resolve_call_static() {
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "models",
            "User.create",
            FuncEntry::method(PathBuf::from("models.py"), 25, 35, "User".to_string()),
        );

        let mut class_index = ClassIndex::new();
        class_index.insert(
            "User",
            ClassEntry::new(
                PathBuf::from("models.py"),
                5,
                50,
                vec!["create".to_string()],
                vec![],
            ),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Static call: User::create()
        let resolved = resolve_call!(
            "User::create",
            &CallType::Static,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.php"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve static call");
        let target = resolved.unwrap();
        assert_eq!(target.name, "create");
        assert!(target.is_method);
        assert_eq!(target.class_name, Some("User".to_string()));
    }

    /// Test: Class constructor resolution (Direct call to class name)
    #[test]
    fn test_resolve_call_constructor() {
        let mut class_index = ClassIndex::new();
        class_index.insert(
            "MyClass",
            ClassEntry::new(
                PathBuf::from("classes.py"),
                10,
                50,
                vec!["__init__".to_string()],
                vec![],
            ),
        );

        let func_index = FuncIndex::new();
        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Direct call to class (constructor): MyClass()
        let resolved = resolve_call!(
            "MyClass",
            &CallType::Direct,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve constructor call");
        let target = resolved.unwrap();
        assert_eq!(target.file, PathBuf::from("classes.py"));
        assert_eq!(target.name, "__init__");
    }

    /// Test: Imported class used for method call resolution
    #[test]
    fn test_resolve_imported_class_method() {
        // Setup: User class imported and used as User.create()
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "models",
            "User.create",
            FuncEntry::method(PathBuf::from("models.py"), 30, 40, "User".to_string()),
        );

        let mut class_index = ClassIndex::new();
        class_index.insert(
            "User",
            ClassEntry::new(
                PathBuf::from("models.py"),
                10,
                50,
                vec!["create".to_string()],
                vec![],
            ),
        );

        let mut import_map = ImportMap::new();
        import_map.insert(
            "User".to_string(),
            ("models".to_string(), "User".to_string()),
        );

        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: User.create() (calling on the class itself)
        let resolved = resolve_call_with_receiver!(
            "create",
            "User",
            None,
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        assert!(resolved.is_some(), "Should resolve imported class method");
        let target = resolved.unwrap();
        assert_eq!(target.name, "create");
        assert!(target.is_method);
    }

    #[test]
    fn test_resolve_call_typescript_module_keys_match() {
        // End-to-end test: func_index keys (from path_to_module) must match
        // import_map keys (from ModuleIndex) for TypeScript
        let mut func_index = FuncIndex::new();
        let class_index = ClassIndex::new();

        // Simulate what build_indices_parallel does with the fixed path_to_module:
        // For a TS file "errors.ts", the module should be "./errors"
        let module = path_to_module(Path::new("errors.ts"), "typescript");
        func_index.insert(
            &module,
            "ZodError",
            FuncEntry::function(PathBuf::from("errors.ts"), 10, 20),
        );

        // Simulate what import_map contains (from ModuleIndex resolution):
        // import { ZodError } from "./errors"
        let mut import_map: ImportMap = HashMap::new();
        import_map.insert(
            "ZodError".to_string(),
            ("./errors".to_string(), "ZodError".to_string()),
        );
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "typescript");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // resolve_call should find ZodError in func_index
        let result = resolve_call!(
            "ZodError",
            &CallType::Direct,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("core.ts"),
            Path::new("."),
            "typescript",
        );

        assert!(
            result.is_some(),
            "resolve_call should find ZodError when func_index key './errors' matches import_map key './errors'"
        );
        let resolved = result.unwrap();
        assert_eq!(resolved.name, "ZodError");
        assert_eq!(resolved.file, PathBuf::from("errors.ts"));
    }

    #[test]
    fn test_resolve_call_with_receiver_typescript_module_import() {
        // Test that module imports resolve correctly for TypeScript
        let mut func_index = FuncIndex::new();
        let class_index = ClassIndex::new();

        // errors module has a createZodError function
        let module = path_to_module(Path::new("errors.ts"), "typescript");
        func_index.insert(
            &module,
            "createZodError",
            FuncEntry::function(PathBuf::from("errors.ts"), 5, 15),
        );

        let import_map: ImportMap = HashMap::new();
        let mut module_imports: ModuleImports = HashMap::new();
        // import * as errors from "./errors"
        module_imports.insert("errors".to_string(), "./errors".to_string());
        let module_index = ModuleIndex::new(PathBuf::from("."), "typescript");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // errors.createZodError() should resolve
        let result = resolve_call_with_receiver!(
            "createZodError",
            "errors",
            None,
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("core.ts"),
            Path::new("."),
            "typescript",
        );

        assert!(
            result.is_some(),
            "resolve_call_with_receiver should find createZodError via module import './errors'"
        );
        let resolved = result.unwrap();
        assert_eq!(resolved.name, "createZodError");
    }

    // =========================================================================
    // Tests for Strategy 7/8 self-receiver false positive filtering
    // =========================================================================

    /// Test: Strategy 8 should NOT match a method from an unrelated class
    /// when receiver is "self" and receiver_type is set.
    ///
    /// Scenario: CaseInsensitiveDict calls self.items() internally.
    /// RequestsCookieJar also defines items(). Strategy 8 (global scan) should
    /// NOT match RequestsCookieJar.items() because self refers to
    /// CaseInsensitiveDict, not RequestsCookieJar.
    ///
    /// Setup: CaseInsensitiveDict is NOT in the class_index (simulating it being
    /// missed or external), so Strategy 0's resolve_method_in_class fails.
    /// The only func_index entry for "items" belongs to RequestsCookieJar.
    /// Strategy 8 would match it as a "unique" method -- FALSE POSITIVE.
    #[test]
    fn test_strategy8_self_receiver_filters_unrelated_class() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // RequestsCookieJar defines items() in cookies.py -- indexed with BARE name
        func_index.insert(
            "cookies",
            "items",
            FuncEntry::method(
                PathBuf::from("cookies.py"),
                80,
                90,
                "RequestsCookieJar".to_string(),
            ),
        );
        class_index.insert(
            "RequestsCookieJar",
            ClassEntry::new(
                PathBuf::from("cookies.py"),
                5,
                200,
                vec!["items".to_string(), "values".to_string()],
                vec!["cookielib.CookieJar".to_string()],
            ),
        );

        // CaseInsensitiveDict is NOT in class_index (Strategy 0 will fail to find it)
        // but receiver_type IS set (from apply_type_resolution which uses enclosing class)

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: self.items() inside CaseInsensitiveDict (file=structures.py)
        // receiver="self", receiver_type=Some("CaseInsensitiveDict")
        // Strategy 0: resolve_method_in_class("CaseInsensitiveDict", "items") fails (not in class_index)
        // Strategy 1: func_index.get("structures", "items") fails (no such entry)
        // ...
        // Strategy 8: finds "items" as unique method -- SHOULD be filtered out
        let result = resolve_call_with_receiver!(
            "items",
            "self",
            Some("CaseInsensitiveDict"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("structures.py"),
            Path::new("."),
            "python",
        );

        // Without the fix: Strategy 8 returns RequestsCookieJar.items (false positive)
        // With the fix: Strategy 8 filters it out because RequestsCookieJar is not
        // in CaseInsensitiveDict's inheritance chain
        if let Some(ref resolved) = result {
            assert_ne!(
                resolved.class_name.as_deref(),
                Some("RequestsCookieJar"),
                "self.items() in CaseInsensitiveDict must NOT resolve to RequestsCookieJar.items (false positive)"
            );
        }
    }

    /// Test: Strategy 7 (local file scan) should NOT match a method from
    /// an unrelated class when receiver is "self" and receiver_type is set.
    ///
    /// Scenario: Two classes in the same file, both define process() with bare
    /// func names. self.process() inside ClassA should NOT match ClassB.process().
    /// Uses bare func names to force past Strategies 0-6 into Strategy 7.
    #[test]
    fn test_strategy7_self_receiver_filters_unrelated_class_same_file() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // Use bare method name "process" (not "ClassA.process") to bypass Strategy 0/1.
        // Both are in the same file (module.py) to trigger Strategy 7.
        // Strategy 7 iterates func_index looking for bare_target matching in current_file.
        // With bare names, it will match the FIRST one it finds -- which could be ClassB.

        // Insert ClassB.process first (to make it the "wrong" match for Strategy 7)
        func_index.insert(
            "module_b",
            "process",
            FuncEntry::method(PathBuf::from("module.py"), 30, 40, "ClassB".to_string()),
        );
        // Insert ClassA.process second
        func_index.insert(
            "module_a",
            "process",
            FuncEntry::method(PathBuf::from("module.py"), 10, 20, "ClassA".to_string()),
        );

        class_index.insert(
            "ClassA",
            ClassEntry::new(
                PathBuf::from("module.py"),
                5,
                25,
                vec!["process".to_string()],
                vec![],
            ),
        );
        class_index.insert(
            "ClassB",
            ClassEntry::new(
                PathBuf::from("module.py"),
                26,
                45,
                vec!["process".to_string()],
                vec![],
            ),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: self.process() inside ClassA (file=module.py)
        // receiver="self", receiver_type=Some("ClassA")
        let result = resolve_call_with_receiver!(
            "process",
            "self",
            Some("ClassA"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("module.py"),
            Path::new("."),
            "python",
        );

        // With the fix: should resolve to ClassA.process, not ClassB.process
        if let Some(ref resolved) = result {
            assert_ne!(
                resolved.class_name.as_deref(),
                Some("ClassB"),
                "self.process() in ClassA must NOT resolve to ClassB.process (false positive)"
            );
        }
    }

    /// Test: Strategy 8 should still work for non-self receivers
    /// (no false-positive filtering when receiver is a variable name).
    /// Uses bare func name so find_by_name matches.
    #[test]
    fn test_strategy8_non_self_receiver_still_resolves_unique() {
        let mut func_index = FuncIndex::new();
        let class_index = ClassIndex::new();

        // Only one class defines unique_method() -- use bare func name
        func_index.insert(
            "helpers",
            "unique_method",
            FuncEntry::method(PathBuf::from("helpers.py"), 10, 20, "Helper".to_string()),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: obj.unique_method() -- obj is NOT self, and unique_method is globally unique
        let result = resolve_call_with_receiver!(
            "unique_method",
            "obj",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );

        assert!(
            result.is_some(),
            "obj.unique_method() should still resolve via Strategy 8 when unique"
        );
        let resolved = result.unwrap();
        assert_eq!(resolved.name, "unique_method");
    }

    /// Test: Strategy 8 with self receiver should resolve to base class method
    /// when the method is defined in a parent class.
    /// Uses bare func names to force into Strategy 8.
    #[test]
    fn test_strategy8_self_receiver_allows_base_class_method() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // BaseClass defines save() in base.py -- use bare func name
        func_index.insert(
            "base",
            "save",
            FuncEntry::method(PathBuf::from("base.py"), 10, 20, "BaseClass".to_string()),
        );

        // ChildClass inherits from BaseClass (defined in child.py)
        class_index.insert(
            "ChildClass",
            ClassEntry::new(
                PathBuf::from("child.py"),
                5,
                50,
                vec!["run".to_string()],
                vec!["BaseClass".to_string()],
            ),
        );
        class_index.insert(
            "BaseClass",
            ClassEntry::new(
                PathBuf::from("base.py"),
                1,
                30,
                vec!["save".to_string()],
                vec![],
            ),
        );

        // UnrelatedClass also defines save() in other.py -- bare func name
        func_index.insert(
            "other",
            "save",
            FuncEntry::method(
                PathBuf::from("other.py"),
                10,
                20,
                "UnrelatedClass".to_string(),
            ),
        );
        class_index.insert(
            "UnrelatedClass",
            ClassEntry::new(
                PathBuf::from("other.py"),
                1,
                30,
                vec!["save".to_string()],
                vec![],
            ),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: self.save() inside ChildClass (file=child.py)
        // receiver="self", receiver_type=Some("ChildClass")
        // save() is not in ChildClass but IS in BaseClass (parent)
        // Strategy 8 finds two "save" entries -- must filter to inheritance chain
        let result = resolve_call_with_receiver!(
            "save",
            "self",
            Some("ChildClass"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("child.py"),
            Path::new("."),
            "python",
        );

        assert!(
            result.is_some(),
            "self.save() in ChildClass should resolve to base class BaseClass.save"
        );
        let resolved = result.unwrap();
        assert_eq!(
            resolved.class_name.as_deref(),
            Some("BaseClass"),
            "self.save() should resolve to BaseClass.save (inherited), not {:?}",
            resolved.class_name
        );
        assert_eq!(resolved.file, PathBuf::from("base.py"));
    }

    /// Test: Strategy 8 with stdlib receiver_type should filter out project methods.
    ///
    /// Scenario: self._store.items() where _store is an OrderedDict (stdlib).
    /// The only "items" method in func_index belongs to RequestsCookieJar.
    /// Since OrderedDict is a stdlib type, items() should NOT resolve to
    /// RequestsCookieJar.items().
    #[test]
    fn test_strategy8_stdlib_receiver_type_filters_project_methods() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // RequestsCookieJar defines items() -- indexed with bare name
        func_index.insert(
            "cookies",
            "items",
            FuncEntry::method(
                PathBuf::from("cookies.py"),
                80,
                90,
                "RequestsCookieJar".to_string(),
            ),
        );
        class_index.insert(
            "RequestsCookieJar",
            ClassEntry::new(
                PathBuf::from("cookies.py"),
                5,
                200,
                vec!["items".to_string()],
                vec![],
            ),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Call: self._store.items() inside CaseInsensitiveDict
        // receiver="_store", receiver_type=Some("OrderedDict")
        // OrderedDict is a stdlib type -- not in class_index
        let result = resolve_call_with_receiver!(
            "items",
            "_store",
            Some("OrderedDict"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("structures.py"),
            Path::new("."),
            "python",
        );

        // Should NOT resolve to RequestsCookieJar.items because
        // OrderedDict.items() is a stdlib method call
        if let Some(ref resolved) = result {
            assert_ne!(
                resolved.class_name.as_deref(),
                Some("RequestsCookieJar"),
                "OrderedDict.items() must NOT resolve to RequestsCookieJar.items (false positive)"
            );
        }
    }

    /// Test: augment_go_module_imports with resolve_call_with_receiver (Strategy 2)
    ///
    /// End-to-end test: Go import creates module_imports entry,
    /// then resolve_call_with_receiver uses Strategy 2 to resolve
    /// models.NewUser() to the correct function.
    #[test]
    fn test_go_cross_package_resolve_end_to_end() {
        // Setup func_index with Go functions
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "pkg/models",
            "NewUser",
            FuncEntry::function(PathBuf::from("pkg/models/user.go"), 12, 14),
        );
        func_index.insert(
            "pkg/models",
            "NewAdmin",
            FuncEntry::function(PathBuf::from("pkg/models/user.go"), 33, 38),
        );
        func_index.insert(
            "pkg/service",
            "NewUserService",
            FuncEntry::function(PathBuf::from("pkg/service/service.go"), 10, 13),
        );

        // Build module_imports via augment_go_module_imports
        let imports = vec![
            ImportDef::simple_import("go-callgraph-test/pkg/models"),
            ImportDef::simple_import("go-callgraph-test/pkg/service"),
        ];
        let mut module_imports = ModuleImports::new();
        augment_go_module_imports(&imports, &mut module_imports, &func_index);

        let import_map = ImportMap::new();
        let class_index = ClassIndex::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "go");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // Test: models.NewUser() should resolve
        let resolved = resolve_call_with_receiver!(
            "models.NewUser",
            "models",
            None,
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.go"),
            Path::new("/project"),
            "go",
        );

        assert!(
            resolved.is_some(),
            "models.NewUser() should resolve via Strategy 2"
        );
        let target = resolved.unwrap();
        assert_eq!(target.name, "NewUser");
        assert_eq!(target.file, PathBuf::from("pkg/models/user.go"));

        // Test: service.NewUserService() should resolve
        let resolved2 = resolve_call_with_receiver!(
            "service.NewUserService",
            "service",
            None,
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.go"),
            Path::new("/project"),
            "go",
        );

        assert!(
            resolved2.is_some(),
            "service.NewUserService() should resolve via Strategy 2"
        );
        let target2 = resolved2.unwrap();
        assert_eq!(target2.name, "NewUserService");
        assert_eq!(target2.file, PathBuf::from("pkg/service/service.go"));
    }

    // =================================================================
    // T4-php sub-gap 2: PHP `__call` magic-method redirect
    //
    // When a known-typed receiver calls a method that is provably absent
    // from the class (and bases) and the class/base defines `__call`, the
    // edge must redirect to `<Owner>.__call`. It must NOT fire when the
    // method exists, when `__call` is undefined, or for non-PHP languages.
    // =================================================================

    /// Helper: a ClassIndex with a single PHP class `Proxy` that defines
    /// only `__call` and `__construct` (no `query` method).
    fn php_proxy_class_index(extra_methods: Vec<&str>) -> ClassIndex {
        let mut class_index = ClassIndex::new();
        let mut methods: Vec<String> = vec!["__construct".to_string(), "__call".to_string()];
        methods.extend(extra_methods.into_iter().map(str::to_string));
        class_index.insert(
            "Proxy",
            ClassEntry::new(PathBuf::from("Proxy.php"), 10, 100, methods, vec![]),
        );
        class_index
    }

    #[test]
    fn test_php_magic_call_redirect_fires_when_method_absent() {
        // Proxy defines __call but NOT query(); $p->query() must redirect to
        // Proxy.__call.
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "Proxy",
            "Proxy.__call",
            FuncEntry::method(PathBuf::from("Proxy.php"), 40, 50, "Proxy".to_string()),
        );
        let class_index = php_proxy_class_index(vec![]);

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "php");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let resolved = resolve_call_with_receiver!(
            "query",
            "$p",
            Some("Proxy"),
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.php"),
            Path::new("/project"),
            "php",
        );

        let target = resolved.expect("absent method on __call-defining class should redirect");
        assert_eq!(target.name, "__call", "should redirect to the __call method");
        assert_eq!(target.class_name, Some("Proxy".to_string()));
        assert!(target.is_method);
    }

    #[test]
    fn test_php_magic_call_redirect_uses_base_class_owner() {
        // Child has no __call and no query(); Base defines __call.
        // $c->query() must redirect to Base.__call.
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "Base",
            "Base.__call",
            FuncEntry::method(PathBuf::from("Base.php"), 40, 50, "Base".to_string()),
        );

        let mut class_index = ClassIndex::new();
        class_index.insert(
            "Base",
            ClassEntry::new(
                PathBuf::from("Base.php"),
                10,
                100,
                vec!["__call".to_string()],
                vec![],
            ),
        );
        class_index.insert(
            "Child",
            ClassEntry::new(
                PathBuf::from("Child.php"),
                10,
                100,
                vec!["doChildThing".to_string()],
                vec!["Base".to_string()],
            ),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "php");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let resolved = resolve_call_with_receiver!(
            "query",
            "$c",
            Some("Child"),
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.php"),
            Path::new("/project"),
            "php",
        );

        let target = resolved.expect("absent method should redirect to base __call");
        assert_eq!(target.name, "__call");
        assert_eq!(
            target.class_name,
            Some("Base".to_string()),
            "owner of __call is the base class"
        );
    }

    #[test]
    fn test_php_magic_call_does_not_fire_when_method_exists() {
        // Proxy defines a real query() method -> resolve to it, NOT __call.
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "Proxy",
            "Proxy.query",
            FuncEntry::method(PathBuf::from("Proxy.php"), 60, 70, "Proxy".to_string()),
        );
        func_index.insert(
            "Proxy",
            "Proxy.__call",
            FuncEntry::method(PathBuf::from("Proxy.php"), 40, 50, "Proxy".to_string()),
        );
        let class_index = php_proxy_class_index(vec!["query"]);

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "php");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let resolved = resolve_call_with_receiver!(
            "query",
            "$p",
            Some("Proxy"),
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.php"),
            Path::new("/project"),
            "php",
        );

        let target = resolved.expect("real method should resolve");
        assert_eq!(
            target.name, "query",
            "existing method must resolve to itself, never to __call"
        );
    }

    #[test]
    fn test_php_magic_call_does_not_fire_when_no_call_defined() {
        // Plain class with no __call and no query(): must NOT fabricate a
        // __call edge. (No fuzzy fallback exists for a single bare method
        // with a known type that has no candidates, so this stays None.)
        let func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();
        class_index.insert(
            "Plain",
            ClassEntry::new(
                PathBuf::from("Plain.php"),
                10,
                100,
                vec!["__construct".to_string(), "doThing".to_string()],
                vec![],
            ),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "php");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let resolved = resolve_call_with_receiver!(
            "query",
            "$p",
            Some("Plain"),
            &CallType::Attr,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.php"),
            Path::new("/project"),
            "php",
        );

        // "query" is absent from Plain, and Plain declares no `__call`, so the
        // magic redirect must not fire. The func_index is empty and no other
        // resolver strategy can match `query`, so the only correct result is
        // None (a fully unresolved call), NOT some fuzzy junk target.
        assert_eq!(
            resolved, None,
            "no __call defined -> call to absent `query` must stay unresolved. Got: {:?}",
            resolved
        );
    }

    #[test]
    fn test_php_magic_call_redirect_is_php_only() {
        // Same shape as the firing case but language = python. The Python
        // `__call` symbol must NOT be treated as a magic dispatch redirect.
        let mut func_index = FuncIndex::new();
        func_index.insert(
            "Proxy",
            "Proxy.__call",
            FuncEntry::method(PathBuf::from("proxy.py"), 40, 50, "Proxy".to_string()),
        );
        let mut class_index = ClassIndex::new();
        class_index.insert(
            "Proxy",
            ClassEntry::new(
                PathBuf::from("proxy.py"),
                10,
                100,
                vec!["__call".to_string()],
                vec![],
            ),
        );

        let import_map = ImportMap::new();
        let module_imports = ModuleImports::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let resolved = resolve_call_with_receiver!(
            "query",
            "p",
            Some("Proxy"),
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("/project"),
            "python",
        );

        // The PHP `__call` redirect is gated to PHP. Under Python, the only
        // declared method on Proxy is `__call` itself (the func_index holds
        // `Proxy.__call`), so a call to the absent `query` has no valid target:
        // no resolver strategy matches `query`, and the magic redirect is
        // skipped entirely. The correct result is None.
        assert_eq!(
            resolved, None,
            "Python must not get the PHP __call redirect; absent `query` stays unresolved. Got: {:?}",
            resolved
        );
    }

    // =================================================================
    // T4-py: Python duck-typing dispatch.
    //
    // ROOT CAUSE: the bare-method key (module, name) collides when several
    // classes in the same module define a method of the same name (e.g.
    // Animal.speak / Robot.speak / Plant.speak under ("x","speak")). The
    // FuncIndex MUST keep all colliding entries so the decline-on-ambiguity
    // guard (candidates.len() == 1) sees the true cardinality. The builder
    // indexes each method under BOTH its bare name (module, name) AND its
    // qualified name (module, "Class.method"); these tests mirror that exact
    // double-insert so the collision is reproduced realistically.
    // =================================================================

    /// Helper: index a method under both the bare and the qualified key,
    /// exactly as `builder_v2` does, so same-name methods collide on the
    /// bare key inside a single module.
    fn index_method_both_keys(
        func_index: &mut FuncIndex,
        module: &str,
        class: &str,
        method: &str,
        file: &str,
        line: u32,
    ) {
        let entry = FuncEntry::method(PathBuf::from(file), line, line + 5, class.to_string());
        // Bare-name key — this is where same-name methods collide.
        func_index.insert(module, method, entry.clone());
        // Qualified-name key — unique per class.
        let qualified = format!("{}.{}", class, method);
        func_index.insert(module, &qualified, entry);
    }

    /// (a) `thing.speak()` with THREE unrelated classes each defining `speak`
    /// and an untyped receiver must DECLINE (the call is genuinely ambiguous).
    /// Before the index fix the three bare-key inserts collapsed to one entry,
    /// the len()==1 guard was satisfied, and a survivor was bound — an
    /// order-dependent false positive.
    #[test]
    fn test_py_duck_typing_three_classes_untyped_receiver_declines() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // All three classes live in the SAME module "x" (this is what makes
        // the bare ("x","speak") key collide in the real builder).
        index_method_both_keys(&mut func_index, "x", "Animal", "speak", "x.py", 10);
        index_method_both_keys(&mut func_index, "x", "Robot", "speak", "x.py", 30);
        index_method_both_keys(&mut func_index, "x", "Plant", "speak", "x.py", 50);

        for (name, line) in [("Animal", 5u32), ("Robot", 25), ("Plant", 45)] {
            class_index.insert(
                name,
                ClassEntry::new(
                    PathBuf::from("x.py"),
                    line,
                    line + 15,
                    vec!["speak".to_string()],
                    vec![],
                ),
            );
        }

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `thing.speak()` — receiver "thing" is an untyped variable (no
        // receiver_type, not self/cls). Three unrelated classes define speak.
        let result = resolve_call_with_receiver!(
            "speak",
            "thing",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );

        assert_eq!(
            result, None,
            "thing.speak() with 3 unrelated classes defining speak must DECLINE (ambiguous), got {:?}",
            result
        );
    }

    /// (b) `thing.speak()` with EXACTLY ONE class defining `speak` must BIND
    /// to that class — the decline-on-ambiguity guard fires only on >1.
    #[test]
    fn test_py_duck_typing_single_class_untyped_receiver_binds() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        index_method_both_keys(&mut func_index, "x", "Animal", "speak", "x.py", 10);
        class_index.insert(
            "Animal",
            ClassEntry::new(
                PathBuf::from("x.py"),
                5,
                20,
                vec!["speak".to_string()],
                vec![],
            ),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        let result = resolve_call_with_receiver!(
            "speak",
            "thing",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );

        let resolved = result.expect("thing.speak() with exactly 1 class defining speak must BIND");
        assert_eq!(
            resolved.class_name.as_deref(),
            Some("Animal"),
            "single-class duck call must bind to Animal.speak, got {:?}",
            resolved.class_name
        );
        assert_eq!(resolved.file, PathBuf::from("x.py"));
    }

    /// (c) A Go `MarshalJSON` bare call on an untyped receiver, defined on >1
    /// unrelated (non-inheritance-linked) struct, must stay SUPPRESSED.
    ///
    /// NOTE on the two suppression mechanisms (they are COMPLEMENTARY, not
    /// subsuming): `MarshalJSON` is *both* a member of `is_builtin_method_name`
    /// AND, in this fixture, defined on two unrelated structs — so EITHER gate
    /// alone would suppress it here. That is precisely why this single test does
    /// NOT prove the cardinality gate "replaces" the blocklist: with two
    /// definers the blocklist is redundant, but the blocklist is retained for
    /// the *single-definer* builtin-name case the cardinality gate cannot reach
    /// (see `test_py_single_class_builtin_name_still_suppressed`, where exactly
    /// one project class defines a builtin name and only the blocklist suppresses
    /// it). `MarshalJSON` remains in `is_builtin_method_name` on purpose.
    #[test]
    fn test_go_marshaljson_untyped_receiver_stays_suppressed() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // Two unrelated Go structs both define MarshalJSON in the same package.
        index_method_both_keys(&mut func_index, "pkg", "User", "MarshalJSON", "user.go", 10);
        index_method_both_keys(&mut func_index, "pkg", "Order", "MarshalJSON", "order.go", 20);
        class_index.insert(
            "User",
            ClassEntry::new(
                PathBuf::from("user.go"),
                5,
                30,
                vec!["MarshalJSON".to_string()],
                vec![],
            ),
        );
        class_index.insert(
            "Order",
            ClassEntry::new(
                PathBuf::from("order.go"),
                5,
                40,
                vec!["MarshalJSON".to_string()],
                vec![],
            ),
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "go");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `v.MarshalJSON()` — untyped receiver, two unrelated definers.
        let result = resolve_call_with_receiver!(
            "MarshalJSON",
            "v",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.go"),
            Path::new("."),
            "go",
        );

        assert_eq!(
            result, None,
            "v.MarshalJSON() defined on 2 unrelated structs must stay suppressed, got {:?}",
            result
        );
    }

    /// Locks in the COMPLEMENTARY relationship between the two untyped-receiver
    /// gates: a builtin-named method (`items`) defined on exactly ONE project
    /// class must STILL be suppressed. The cardinality gate alone cannot do
    /// this (one unrelated definer => not >1), so this proves the blocklist
    /// retains coverage the gate does not — i.e. the blocklist must not be
    /// deleted in favour of the gate. Guards against a future half-deleted
    /// state.
    #[test]
    fn test_py_single_class_builtin_name_still_suppressed() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // Exactly ONE class defines the builtin-named method `items`.
        index_method_both_keys(&mut func_index, "x", "MyDict", "items", "x.py", 10);
        class_index.insert(
            "MyDict",
            ClassEntry::new(
                PathBuf::from("x.py"),
                5,
                20,
                vec!["items".to_string()],
                vec![],
            ),
        );

        // Cardinality alone would NOT suppress (only one unrelated definer).
        assert_eq!(
            count_unrelated_method_definers("items", &class_index),
            1,
            "precondition: exactly one unrelated class defines items"
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `d.items()` — untyped receiver, builtin-named method, single definer.
        let result = resolve_call_with_receiver!(
            "items",
            "d",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );

        assert_eq!(
            result, None,
            "d.items() (builtin name, single project class) must stay suppressed by the blocklist, got {:?}",
            result
        );
    }

    /// `count_unrelated_method_definers` must collapse an inheritance-linked
    /// base/override pair into ONE definer (so an overridden method is not
    /// mistaken for genuine cross-class ambiguity), while counting independent
    /// classes separately.
    #[test]
    fn test_count_unrelated_method_definers_collapses_inheritance() {
        let mut class_index = ClassIndex::new();
        // Base + override of speak -> ONE logical definer.
        class_index.insert(
            "Base",
            ClassEntry::new(
                PathBuf::from("a.py"),
                1,
                10,
                vec!["speak".to_string()],
                vec![],
            ),
        );
        class_index.insert(
            "Derived",
            ClassEntry::new(
                PathBuf::from("a.py"),
                11,
                20,
                vec!["speak".to_string()],
                vec!["Base".to_string()],
            ),
        );
        assert_eq!(
            count_unrelated_method_definers("speak", &class_index),
            1,
            "Base + Derived override of speak must count as ONE unrelated definer"
        );

        // Add an unrelated third class -> TWO logical definers.
        class_index.insert(
            "Robot",
            ClassEntry::new(
                PathBuf::from("b.py"),
                1,
                10,
                vec!["speak".to_string()],
                vec![],
            ),
        );
        assert_eq!(
            count_unrelated_method_definers("speak", &class_index),
            2,
            "Base-family + unrelated Robot must count as TWO unrelated definers"
        );
    }

    /// Direct unit test of the FuncIndex fix: same-name/different-class methods
    /// inserted under the SAME (module, bare-name) key must all survive and be
    /// returned by `find_by_name` (this is the property the ambiguity guard
    /// depends on).
    ///
    /// This test guards BOTH ends of the mechanism:
    ///   1. the index level — `find_by_name("speak")` returns all 3 entries; and
    ///   2. the DOWNSTREAM resolver — feeding the same index through
    ///      `resolve_call_with_receiver` with an EMPTY `class_index` (so the
    ///      cardinality gate is provably inert: `count_unrelated_method_definers`
    ///      reads `class_index` and returns 0, never `> 1`) makes
    ///      `resolve_global_fuzzy_match` see `candidates.len() == 3` and DECLINE.
    /// Point (2) is what falsifies a reverted index fix: if `find_by_name`
    /// collapsed the bare-key collision back to a single entry, `candidates`
    /// would be length 1, the `== 1` branch would BIND a survivor, and this
    /// assertion would fail. The empty `class_index` rules out the cardinality
    /// gate as the cause of the decline, so only the surviving index entries can
    /// explain it.
    #[test]
    fn test_func_index_same_name_methods_survive_collision() {
        let mut func_index = FuncIndex::new();
        index_method_both_keys(&mut func_index, "x", "Animal", "speak", "x.py", 10);
        index_method_both_keys(&mut func_index, "x", "Robot", "speak", "x.py", 30);
        index_method_both_keys(&mut func_index, "x", "Plant", "speak", "x.py", 50);

        let speak_methods: Vec<_> = func_index
            .find_by_name("speak")
            .filter(|e| e.is_method)
            .collect();
        assert_eq!(
            speak_methods.len(),
            3,
            "find_by_name(speak) must return all 3 colliding methods, got {}",
            speak_methods.len()
        );

        let mut classes: Vec<_> = speak_methods
            .iter()
            .filter_map(|e| e.class_name.clone())
            .collect();
        classes.sort();
        assert_eq!(classes, vec!["Animal", "Plant", "Robot"]);

        // Downstream effect: the resolver path that consumes `find_by_name`
        // must DECLINE on the surviving >1 candidates. Use an EMPTY class_index
        // so the cardinality gate cannot fire and mask the index behavior — the
        // decline must come purely from `candidates.len() != 1`.
        let class_index = ClassIndex::new();
        assert_eq!(
            count_unrelated_method_definers("speak", &class_index),
            0,
            "precondition: empty class_index => cardinality gate is inert (0, never >1)"
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `thing.speak()` — untyped receiver; three method entries survive under
        // the bare key, so the global fuzzy match has >1 candidate and declines.
        let result = resolve_call_with_receiver!(
            "speak",
            "thing",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );
        assert_eq!(
            result, None,
            "with 3 surviving same-name method entries (gate inert), the resolver \
             must DECLINE; a non-None bind here means find_by_name collapsed the \
             collision to 1 (index fix reverted). Got {:?}",
            result
        );
    }

    /// Isolates the FuncIndex Vec fix at the RESOLUTION level with the
    /// cardinality gate deliberately NEUTRALIZED, so the gate cannot mask a
    /// reverted index.
    ///
    /// Setup: `Base` and `Derived(Base)` BOTH declare `speak`. Because they are
    /// inheritance-linked, `count_unrelated_method_definers` collapses them to
    /// ONE definer (verified as a precondition below) — so the cardinality gate
    /// in `resolve_global_fuzzy_match` does NOT fire (`1` is not `> 1`). `speak`
    /// is also not a builtin name, so the blocklist gate is silent too. With
    /// BOTH untyped-receiver gates inert, the ONLY thing that can make the call
    /// decline is the index returning >1 method candidate for the bare key.
    ///
    /// The bare ("x","speak") key holds TWO method entries (Base.speak,
    /// Derived.speak). With the Vec fix, `find_by_name("speak")` yields both →
    /// `candidates.len() == 2` → `resolve_global_fuzzy_match` declines. If the
    /// index still collapsed colliding keys to a single entry (the pre-79b08e2
    /// bug), `candidates.len()` would be 1 and the `== 1` branch would BIND a
    /// survivor — so this `assert_eq!(result, None)` would FAIL. That makes the
    /// test a genuine guard for the Vec fix, independent of the cardinality gate.
    #[test]
    fn test_func_index_collision_declines_with_cardinality_gate_inert() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // Two inheritance-linked classes both define `speak`. In func_index both
        // method definitions land under the same bare ("x","speak") key.
        index_method_both_keys(&mut func_index, "x", "Base", "speak", "x.py", 10);
        index_method_both_keys(&mut func_index, "x", "Derived", "speak", "x.py", 30);

        // Base defines speak; Derived extends Base and overrides speak.
        class_index.insert(
            "Base",
            ClassEntry::new(
                PathBuf::from("x.py"),
                5,
                20,
                vec!["speak".to_string()],
                vec![],
            ),
        );
        class_index.insert(
            "Derived",
            ClassEntry::new(
                PathBuf::from("x.py"),
                25,
                40,
                vec!["speak".to_string()],
                vec!["Base".to_string()],
            ),
        );

        // Gate neutralization precondition: inheritance-linked definers collapse
        // to ONE, so the cardinality gate (>1) is inert and cannot be the cause
        // of any decline below.
        assert_eq!(
            count_unrelated_method_definers("speak", &class_index),
            1,
            "precondition: Base + Derived(override) must collapse to ONE definer \
             so the cardinality gate stays inert"
        );
        // And the blocklist gate is silent too: `speak` is not a builtin name.
        assert!(
            !is_builtin_method_name("speak"),
            "precondition: `speak` must not be a builtin-name so that gate is also inert"
        );

        // Sanity: the bare key really does hold both method entries (the property
        // the Vec fix preserves).
        let bare_methods = func_index
            .find_by_name("speak")
            .filter(|e| e.is_method)
            .count();
        assert_eq!(
            bare_methods, 2,
            "find_by_name(speak) must yield both Base.speak and Derived.speak"
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `thing.speak()` — untyped receiver. Both untyped-receiver gates are
        // inert (cardinality == 1, not a builtin), so resolution reaches the
        // global fuzzy match with 2 surviving method candidates and must DECLINE.
        let result = resolve_call_with_receiver!(
            "speak",
            "thing",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );
        assert_eq!(
            result, None,
            "both ambiguity gates are inert here, so a non-None result can ONLY \
             come from find_by_name collapsing the bare-key collision to 1 entry \
             (index fix reverted). Expected DECLINE, got {:?}",
            result
        );
    }

    /// Isolates the *cardinality gate's wiring into resolution* (the
    /// `count_unrelated_method_definers(..) > 1` clause in the fuzzy matchers),
    /// independent of the FuncIndex Vec fix and the builtin blocklist.
    ///
    /// This is the dual of `test_func_index_collision_declines_with_cardinality_gate_inert`:
    /// there the gate is neutralized so only the Vec fix can cause the decline;
    /// here the *index-collision* path is neutralized so only the gate can.
    ///
    /// Setup: TWO mutually-unrelated classes (`Animal`, `Robot`) both declare
    /// `speak` in `class_index` (=> `count_unrelated_method_definers == 2`, gate
    /// fires), but `func_index` holds the method entry for `speak` for `Animal`
    /// ONLY. So `find_by_name("speak").filter(is_method)` yields exactly ONE
    /// candidate regardless of the Vec fix — the bare-key collision that the Vec
    /// fix protects never even occurs here. `speak` is not a builtin name, so the
    /// blocklist is silent too.
    ///
    /// With the gate WIRED IN, `thing.speak()` declines (genuinely ambiguous:
    /// two classes define it, no receiver type). If the `> 1` clause were
    /// removed from the resolver, control would reach `candidates.len() == 1`
    /// and BIND `Animal.speak` — an order-/index-dependent false positive — so
    /// `assert_eq!(result, None)` would FAIL. That makes this a genuine guard
    /// for the gate's wiring: removing the clause is detectable here even though
    /// the surviving-candidates `len() != 1` decline (which masks gate removal in
    /// the 3-entry duck-typing fixtures) cannot fire with a single index entry.
    #[test]
    fn test_cardinality_gate_declines_with_single_index_entry() {
        let mut func_index = FuncIndex::new();
        let mut class_index = ClassIndex::new();

        // Only Animal.speak is present in the function index (one entry under the
        // bare ("x","speak") key). Robot declares speak in class_index but has NO
        // func_index method entry, so the bare key never collides.
        index_method_both_keys(&mut func_index, "x", "Animal", "speak", "x.py", 10);

        for (name, line) in [("Animal", 5u32), ("Robot", 25)] {
            class_index.insert(
                name,
                ClassEntry::new(
                    PathBuf::from("x.py"),
                    line,
                    line + 15,
                    vec!["speak".to_string()],
                    vec![],
                ),
            );
        }

        // Precondition 1: the gate is ARMED — two unrelated classes define speak.
        assert_eq!(
            count_unrelated_method_definers("speak", &class_index),
            2,
            "precondition: Animal + Robot are two unrelated definers (gate armed)"
        );
        // Precondition 2: the index holds exactly ONE method candidate, so the
        // Vec-fix collision path is NOT what causes the decline (a reverted Vec
        // fix would also yield 1 here). Only the gate can decline.
        let speak_methods = func_index
            .find_by_name("speak")
            .filter(|e| e.is_method)
            .count();
        assert_eq!(
            speak_methods, 1,
            "precondition: exactly one method entry for speak (no bare-key collision)"
        );
        // Precondition 3: blocklist is silent (speak is not a builtin name).
        assert!(
            !is_builtin_method_name("speak"),
            "precondition: speak is not a builtin name, so only the cardinality gate applies"
        );

        let import_map: ImportMap = HashMap::new();
        let module_imports: ModuleImports = HashMap::new();
        let module_index = ModuleIndex::new(PathBuf::from("."), "python");
        let mut reexport_tracer = ReExportTracer::new(&module_index);

        // `thing.speak()` — untyped receiver. Only ONE method candidate exists,
        // so the `len() != 1` decline cannot fire; the call must be declined
        // SOLELY by the cardinality gate.
        let result = resolve_call_with_receiver!(
            "speak",
            "thing",
            None,
            &CallType::Method,
            &import_map,
            &module_imports,
            &func_index,
            &class_index,
            &mut reexport_tracer,
            Path::new("main.py"),
            Path::new("."),
            "python",
        );
        assert_eq!(
            result, None,
            "two unrelated classes define speak but only one index entry exists, \
             so a non-None result means the cardinality gate (> 1) is no longer \
             wired into resolution — it would bind Animal.speak (false positive). \
             Expected DECLINE, got {:?}",
            result
        );
    }
}
