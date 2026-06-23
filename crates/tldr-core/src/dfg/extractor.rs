//! DFG extraction from source code
//!
//! Extracts data flow graphs from functions using tree-sitter parsing.
//!
//! # Algorithm
//! 1. Parse source with tree-sitter
//! 2. Find function by name
//! 3. Extract all variable references (defs, uses, updates)
//! 4. Build CFG for the function
//! 5. Apply reaching definitions analysis
//! 6. Connect definitions to uses via edges
//!
//! # Variable Reference Identification (M7 documentation)
//!
//! ## Definitions
//! - Assignment targets: `x = ...`
//! - For loop variables: `for x in ...`
//! - Function parameters: `def f(x):`
//! - With statement variables: `with ... as x:`
//! - Exception handlers: `except E as x:`
//!
//! ## Updates
//! - Augmented assignment: `x += ...`, `x -= ...`
//! - Method calls that mutate: `x.append(...)`, `x.clear()`
//!
//! ## Uses
//! - Expression reads: `y = x + 1`
//! - Function arguments: `f(x)`
//! - Condition checks: `if x:`
//! - Return values: `return x`

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::function_finder::{find_function_node, get_function_body};
use crate::ast::parser::parse;
use crate::cfg::get_cfg_context;
use crate::dfg::reaching::compute_reaching_definitions;
use crate::types::{CfgInfo, DataflowEdge, DfgInfo, Language, RefType, VarRef};
use crate::TldrError;
use crate::TldrResult;

/// Maximum recursion depth for nested structures
const MAX_DEPTH: usize = 50;

/// Extract DFG for a function from source code or file path
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to extract DFG for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(DfgInfo)` - DFG with variable refs, edges, and variable list
/// * `Err(FunctionNotFound)` - If function doesn't exist
///
/// # Example
/// ```ignore
/// use tldr_core::dfg::get_dfg_context;
/// use tldr_core::Language;
///
/// let dfg = get_dfg_context("def foo(x): return x + 1", "foo", Language::Python)?;
/// assert_eq!(dfg.function, "foo");
/// assert!(dfg.variables.contains(&"x".to_string()));
/// ```
pub fn get_dfg_context(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    // Determine if input is a file path or source code
    let (tree, source) = if Path::new(source_or_path).exists() {
        // Read file content
        let source = std::fs::read_to_string(Path::new(source_or_path))
            .map_err(crate::TldrError::IoError)?;
        // Parse with the provided language (not detected from extension)
        let tree = parse(&source, language)?;
        (tree, source)
    } else {
        let tree = parse(source_or_path, language)?;
        (tree, source_or_path.to_string())
    };

    // Extract DFG from the parsed tree
    extract_dfg_from_tree(&tree, &source, function_name, language)
}

/// Extract DFG from a parsed tree
///
/// (vuln-migration-v1 M3) Visibility extended from private `fn` to `pub(crate)`
/// so `vuln::scan_file_vulns` can avoid the per-function re-parse implicit in
/// `get_dfg_context(&content, ...)`. Mirrors `extract_cfg_from_tree`.
pub(crate) fn extract_dfg_from_tree(
    tree: &Tree,
    source: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    let root = tree.root_node();

    // Find the function node
    let func_node = find_function_node(root, function_name, language, source);

    match func_node {
        // AGG13-15: pass file root so the builder can collect imports.
        Some(node) => build_dfg_for_function(node, root, function_name, source, language),
        None => Err(TldrError::function_not_found(function_name)),
    }
}

/// Build DFG when the caller already has the CFG in hand (skips an internal
/// re-parse).
///
/// (vuln-migration-v1 M3 perf) `extract_dfg_from_tree`'s inner
/// `build_dfg_for_function` calls `get_cfg_context(source, ...)` for
/// reaching-defs, which unconditionally re-parses the file. In
/// `vuln::scan_file_vulns` the CFG is already in hand from the call site —
/// pass it in to skip the re-parse + re-build.
pub(crate) fn extract_dfg_from_tree_with_cfg(
    tree: &Tree,
    source: &str,
    function_name: &str,
    language: Language,
    cfg: &crate::types::CfgInfo,
) -> TldrResult<DfgInfo> {
    let root = tree.root_node();
    let func_node = find_function_node(root, function_name, language, source)
        .ok_or_else(|| TldrError::function_not_found(function_name))?;

    let mut builder = DfgBuilder::new(function_name.to_string(), source, language);
    // fix_cl5_dfg_v1 (v0.5.0 CL-5): record the analyzed function's byte span
    // so collect_imports only suppresses parameters of nested functions.
    builder.analyzed_fn_span = Some((func_node.start_byte(), func_node.end_byte()));
    // AGG13-15: pre-populate import set BEFORE extracting refs so
    // is_use_context can consult it during traversal.
    builder.collect_imports(root);
    builder.extract_parameters(func_node)?;
    let body_node = get_function_body(func_node, language);
    // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): pre-collect Ruby local-variable
    // names from the whole function node (params + body) so is_use_context
    // can tell a bare local read from a receiver-less zero-arg method call.
    if matches!(language, Language::Ruby) {
        builder.collect_ruby_local_names(func_node);
    }
    // T5 (v0.5.0 AUDIT-FIX): pre-collect language-local binding names so
    // is_use_context never suppresses a genuine local read.
    builder.collect_t5_local_names(func_node);
    if let Some(body) = body_node {
        builder.extract_refs_from_node(body, 0)?;
    }
    builder.build_def_use_chains(cfg)?;
    builder.finalize()
}

/// Build DFG for a function node
fn build_dfg_for_function(
    func_node: Node,
    root: Node,
    function_name: &str,
    source: &str,
    language: Language,
) -> TldrResult<DfgInfo> {
    let mut builder = DfgBuilder::new(function_name.to_string(), source, language);
    // fix_cl5_dfg_v1 (v0.5.0 CL-5): record the analyzed function's byte span
    // so collect_imports only suppresses parameters of nested functions.
    builder.analyzed_fn_span = Some((func_node.start_byte(), func_node.end_byte()));

    // AGG13-15: collect file-level imports so Java/C# `PageRequest`
    // / `Sort` style identifiers can be classified as not-a-use.
    builder.collect_imports(root);

    // First, extract function parameters as definitions
    builder.extract_parameters(func_node)?;

    // Get the function body and extract all variable references
    let body_node = get_function_body(func_node, language);
    // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): pre-collect Ruby local-variable
    // names so is_use_context can distinguish a bare local read from a
    // receiver-less zero-arg method call.
    if matches!(language, Language::Ruby) {
        builder.collect_ruby_local_names(func_node);
    }
    // T5 (v0.5.0 AUDIT-FIX): pre-collect language-local binding names so
    // is_use_context never suppresses a genuine local read.
    builder.collect_t5_local_names(func_node);
    if let Some(body) = body_node {
        builder.extract_refs_from_node(body, 0)?;
    }

    // Get CFG for reaching definitions analysis
    let cfg = get_cfg_context(source, function_name, language)?;

    // Build def-use chains using reaching definitions
    builder.build_def_use_chains(&cfg)?;

    builder.finalize()
}

/// Builder for constructing DFG
struct DfgBuilder<'a> {
    function_name: String,
    source: &'a str,
    language: Language,
    refs: Vec<VarRef>,
    variables: HashSet<String>,
    /// AGG13-15 (quality-metrics-and-schema-v1): file-level imported
    /// type/class names. For Java / C# the reaching-defs analyzer was
    /// flagging imported class identifiers (e.g. `PageRequest`,
    /// `Sort`) as uninitialized variable uses because every static
    /// method call `PageRequest.of(...)` exposes `PageRequest` as a
    /// bare `identifier` in the AST. Tracking the set of imported
    /// simple names lets `is_use_context` reject such identifiers
    /// when they are the receiver of a `method_invocation` /
    /// `field_access`. Empty for languages that don't need this filter.
    imported_type_names: HashSet<String>,
    /// fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): set of identifier names that
    /// are GENUINE local variables of the analyzed Ruby method — i.e. they
    /// appear as the LHS of an assignment / operator-assignment, as a block
    /// or method parameter, or as a `for`/rescue binding. In Ruby a bare
    /// `identifier` with no receiver and no argument list is syntactically
    /// AMBIGUOUS: it is a local-variable read ONLY when such a local exists
    /// in scope, otherwise it is a zero-arg method call (`target_ruby`,
    /// `target_ruby_version`). reaching-defs was flagging those method calls
    /// as definite-uninitialized variables. Populated from the AST (no regex)
    /// for Ruby only; empty for every other language.
    ruby_local_names: HashSet<String>,
    /// fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): byte span `[start, end)` of the
    /// function currently being analyzed. Used by `collect_imports` to gate
    /// TS/JS parameter collection so that ONLY parameters of functions nested
    /// INSIDE the analyzed function are added to the suppression set. A
    /// sibling/unrelated method's parameter that happens to share a name with
    /// a local of the analyzed function (NestJS `scanForModules`'s
    /// `moduleDefinition`, also a parameter of `insertOrOverrideModule`) must
    /// NOT suppress the analyzed function's reads of its own variable.
    /// `None` until set in the build path.
    analyzed_fn_span: Option<(usize, usize)>,
    /// T5 (v0.5.0 AUDIT-FIX, root cause B1): TS/JS local-variable names
    /// DECLARED anywhere inside the analyzed function (its own `const`/`let`/
    /// `var` declarations and its own parameters, including those of nested
    /// helpers). `collect_imports` adds nested-helper PARAMETER names to
    /// `imported_type_names` for not-a-use suppression, but a sibling helper's
    /// parameter can collide with a genuine local of the analyzed function
    /// (axios `mergeConfig`: sibling `mergeDeepProperties(a, b)` vs the
    /// callback's `const a`/`const b`). The position-independent suppression
    /// then dropped EVERY read of that local, so its store looked dead. An
    /// identifier that has a real local DECLARATION here must never be
    /// suppressed. Populated from the AST for TS/JS only; empty otherwise.
    ts_js_local_names: HashSet<String>,
    /// T5 (v0.5.0 AUDIT-FIX, root cause B3): OCaml names bound by a
    /// `let`/`let rec` binding or a parameter inside the analyzed function.
    /// The blanket `value_path` suppression in `is_ocaml_use_context`
    /// (added to silence module-qualified and top-level value references)
    /// also dropped the recursive references to a local `let rec inner ...`,
    /// so `inner` looked like a dead store. An UNQUALIFIED `value_path`
    /// whose name is one of these local bindings IS a genuine use. Mirrors
    /// the Ruby `ruby_local_names` precedent. Empty for non-OCaml.
    ocaml_local_names: HashSet<String>,
}

impl<'a> DfgBuilder<'a> {
    fn new(function_name: String, source: &'a str, language: Language) -> Self {
        Self {
            function_name,
            source,
            language,
            refs: Vec::new(),
            variables: HashSet::new(),
            imported_type_names: HashSet::new(),
            ruby_local_names: HashSet::new(),
            analyzed_fn_span: None,
            ts_js_local_names: HashSet::new(),
            ocaml_local_names: HashSet::new(),
        }
    }

    /// T5 (v0.5.0 AUDIT-FIX): per-language pre-pass collecting local binding
    /// names of the analyzed function so `is_use_context` never suppresses a
    /// genuine local read. Dispatches to the language-specific collector;
    /// no-op for languages that don't need it.
    fn collect_t5_local_names(&mut self, func_node: Node) {
        match self.language {
            Language::TypeScript | Language::JavaScript => {
                self.collect_ts_js_local_names(func_node);
            }
            Language::Ocaml => {
                self.collect_ocaml_local_names(func_node);
            }
            _ => {}
        }
    }

    /// fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): collect the names of genuine
    /// local variables of a Ruby method by walking its AST subtree once.
    ///
    /// A Ruby local variable is introduced by:
    ///   * `assignment` LHS — `x = ...` (`[left]` identifier, or each
    ///     identifier of a `left_assignment_list` for `a, b = ...`).
    ///   * `operator_assignment` LHS — `x += ...`.
    ///   * a `for` loop binding — `for x in ...`.
    ///   * a rescue binding — `rescue => e`.
    /// (method/block parameters are already recorded as definitions by
    /// `extract_parameters`; we add them here too so the receiver-less use
    /// of a parameter is never misread as a method call.)
    ///
    /// Everything else that surfaces as a bare `identifier` with no receiver
    /// and no argument list — `target_ruby`, `supported_versions` — is a
    /// zero-arg method call, NOT a local read.
    fn collect_ruby_local_names(&mut self, node: Node) {
        let mut cursor = node.walk();
        match node.kind() {
            "assignment" => {
                if let Some(left) = node.child_by_field_name("left") {
                    self.collect_ruby_assignment_target_names(left);
                }
            }
            "operator_assignment" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "identifier" {
                        if let Ok(t) = left.utf8_text(self.source.as_bytes()) {
                            self.ruby_local_names.insert(t.to_string());
                        }
                    }
                }
            }
            // `for x in ...` / `for a, b in ...`
            "for" => {
                if let Some(pat) = node.child_by_field_name("pattern") {
                    self.collect_ruby_assignment_target_names(pat);
                }
            }
            // block / method parameters: `do |x|`, `def f(x)`
            "block_parameters" | "method_parameters" | "parameters"
            | "lambda_parameters" => {
                let mut pc = node.walk();
                for child in node.children(&mut pc) {
                    if child.kind() == "identifier" {
                        if let Ok(t) = child.utf8_text(self.source.as_bytes()) {
                            self.ruby_local_names.insert(t.to_string());
                        }
                    } else {
                        self.collect_ruby_assignment_target_names(child);
                    }
                }
            }
            // `rescue => e`
            "exception_variable" => {
                self.collect_ruby_assignment_target_names(node);
            }
            _ => {}
        }
        for child in node.children(&mut cursor) {
            self.collect_ruby_local_names(child);
        }
    }

    /// Collect identifier names from a Ruby assignment target (handles bare
    /// identifiers, multiple-assignment lists, and splats). Member / index
    /// writes (`obj.field = ...`, `arr[i] = ...`) do NOT introduce a local
    /// of that base name, so they are intentionally not collected here.
    fn collect_ruby_assignment_target_names(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                if let Ok(t) = node.utf8_text(self.source.as_bytes()) {
                    self.ruby_local_names.insert(t.to_string());
                }
            }
            "left_assignment_list" | "rest_assignment" | "splat_parameter"
            | "destructured_parameter" | "optional_parameter"
            | "keyword_parameter" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.collect_ruby_assignment_target_names(child);
                }
            }
            _ => {}
        }
    }

    /// T5 (v0.5.0 AUDIT-FIX, root cause B1): collect the names of TS/JS
    /// local variables DECLARED inside the analyzed function subtree, so the
    /// position-independent import/param suppression in `is_use_context`
    /// never drops a read of a genuine local that happens to share a name
    /// with a sibling helper's parameter.
    ///
    /// A local name is introduced by a `variable_declarator`'s `name` field
    /// (covers `const a`, `let b`, `var c`, and destructuring identifier
    /// leaves). We collect ONLY explicit `const`/`let`/`var` declarations —
    /// NOT parameters — so the existing nested-helper-parameter suppression
    /// (which fixes a separate uninitialized-in-nested-body FP) is preserved
    /// exactly. The axios case is a genuine `const a`/`const b` collision, so
    /// declaration collection is sufficient to rescue it. We walk the whole
    /// analyzed-function subtree once.
    fn collect_ts_js_local_names(&mut self, node: Node) {
        let mut cursor = node.walk();
        if node.kind() == "variable_declarator" {
            if let Some(name) = node.child_by_field_name("name") {
                self.collect_ts_js_binding_identifiers(name);
            }
        }
        for child in node.children(&mut cursor) {
            self.collect_ts_js_local_names(child);
        }
    }

    /// Collect plain binding identifiers from a TS/JS binding pattern
    /// (identifier, object_pattern, array_pattern, rest/default wrappers).
    fn collect_ts_js_binding_identifiers(&mut self, node: Node) {
        match node.kind() {
            "identifier" | "shorthand_property_identifier_pattern"
            | "shorthand_property_identifier" => {
                if let Ok(t) = node.utf8_text(self.source.as_bytes()) {
                    if !t.is_empty() {
                        self.ts_js_local_names.insert(t.to_string());
                    }
                }
            }
            _ => {
                for child in node.children(&mut node.walk()) {
                    self.collect_ts_js_binding_identifiers(child);
                }
            }
        }
    }

    /// T5 (v0.5.0 AUDIT-FIX, root cause B3): collect OCaml local binding
    /// names (`let`/`let rec` pattern names and `parameter` value-pattern
    /// names) declared inside the analyzed function subtree.
    fn collect_ocaml_local_names(&mut self, node: Node) {
        let mut cursor = node.walk();
        match node.kind() {
            "let_binding" => {
                if let Some(pat) = node.child_by_field_name("pattern") {
                    if matches!(pat.kind(), "value_name" | "identifier") {
                        if let Ok(t) = pat.utf8_text(self.source.as_bytes()) {
                            if !t.is_empty() {
                                self.ocaml_local_names.insert(t.to_string());
                            }
                        }
                    }
                }
            }
            "parameter" => {
                // parameter -> [pattern] value_pattern (the bound name).
                for inner in node.children(&mut node.walk()) {
                    if matches!(inner.kind(), "value_pattern" | "value_name" | "identifier") {
                        if let Ok(t) = inner.utf8_text(self.source.as_bytes()) {
                            if !t.is_empty() {
                                self.ocaml_local_names.insert(t.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        for child in node.children(&mut cursor) {
            self.collect_ocaml_local_names(child);
        }
    }

    /// AGG13-15: populate `imported_type_names` from a Java/C# file root.
    /// Java `import_declaration` is `import a.b.C;` — the simple name is
    /// the last dotted segment (`C`). `import static a.b.C.method;`
    /// imports a static member; we capture the last segment as well.
    /// For other languages this is a no-op (the field stays empty).
    ///
    /// language-specific-bugs-v1 (P14.AGG14-12): also collect the names
    /// of class-level fields declared in the same file. Java DI patterns
    /// (`private final OwnerRepository owners; public OwnerController(
    /// OwnerRepository owners) { this.owners = owners; }`) make `owners`
    /// available to every method as a class field — but the per-method
    /// reaching-defs analyzer only sees the method body, so the use of
    /// `owners` looks like an undefined variable and was flagged
    /// `severity: definite`. Treating class fields the same way as
    /// imported type names (suppress them as not-a-use when they are
    /// the receiver of a `method_invocation` / `field_access`) avoids
    /// the false positive without losing precision: the field cannot be
    /// unintentionally shadowed by a local of the same name without that
    /// local also showing up as a definition.
    fn collect_imports(&mut self, root: Node) {
        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // extend AGG13-15's Java/C# collector to TS / JS / Lua / Luau /
        // OCaml + JS hoisted-function-declaration names + well-known
        // built-in globals. All of these are file-level names that the
        // identifier-vs-variable classifier was previously treating as
        // bare variable uses inside function bodies, producing many
        // false-positive uninit reports.
        match self.language {
            Language::Java | Language::CSharp => {}
            Language::TypeScript | Language::JavaScript => {
                // Built-in globals: NEVER local-variable uses. Seeding
                // the set lets `is_use_context` reject `Array.isArray`,
                // `new Error(...)`, etc. as not-a-use receivers, which
                // is how the reachability analyzer learns that
                // `Array`/`Error` are pre-defined.
                for g in JS_TS_GLOBALS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Lua | Language::Luau => {
                for g in LUA_LUAU_GLOBALS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Ocaml => {} // OCaml uses value_path-based suppression
            _ => return,
        }
        // dfg-extractor-test-sync-v1: track whether each node on the walk
        // stack was reached from file-level scope (true) or from inside a
        // function body (false). This lets the lexical_declaration /
        // variable_declaration collectors below guard against inadvertently
        // inserting function-local variable names into the suppression set.
        let mut stack: Vec<(Node, bool)> = vec![(root, true)];
        while let Some((node, is_file_level)) = stack.pop() {
            let kind = node.kind();
            // Java: import_declaration child layout is roughly
            //   "import" ("static")? scoped_identifier ("." "*")? ";"
            // The scoped_identifier holds the last identifier we want.
            // C#: using_directive child layout is
            //   "using" ("static")? qualified_name ";"
            if kind == "import_declaration" || kind == "using_directive" {
                if let Some(name) = last_identifier_text(node, self.source) {
                    self.imported_type_names.insert(name);
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // TS / JS `import_statement`:
            //   - `import { a, b as c } from "..."` -> a, c (alias takes
            //     precedence over name)
            //   - `import * as Ns from "..."` -> Ns (namespace_import)
            //   - `import Default from "..."` -> Default (the
            //     import_clause's direct identifier child)
            // Walk the import_statement subtree once and collect every
            // local-binding identifier — this is robust to the
            // grammar's nested layout (`import_clause` ->
            // `named_imports`/`namespace_import`/`identifier`).
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && kind == "import_statement"
            {
                collect_ts_js_import_bindings(
                    node,
                    self.source,
                    &mut self.imported_type_names,
                );
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // JS hoisted top-level `function foo(...) {}` makes `foo`
            // available throughout the file, including in earlier
            // function bodies. Without this collection the pre-fix
            // code flagged `tryRender(...)` inside express.render as
            // definite-uninitialized even though it is defined further
            // down the same file.
            //
            // We DO descend into nested function bodies so that
            // function-declaration names declared INSIDE another
            // function (e.g. `compareName`, `convertDomTypeToTsType`
            // inside ts-dom-gen's `emitWebIdl`) are also collected as
            // available names. The cost is a slightly over-permissive
            // suppression set when analyzing a sibling function — at
            // worst this misses a local-variable use whose name happens
            // to collide with a nested function defined elsewhere in
            // the file, which is a precision loss bounded by the
            // file's naming conventions. The win is that 100+ TS
            // false positives stop firing.
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && matches!(
                    kind,
                    "function_declaration"
                        | "function_expression"
                        | "arrow_function"
                        | "function"
                        | "generator_function_declaration"
                        | "generator_function"
                        | "method_definition"
                )
            {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): only collect the
                // parameters of functions NESTED INSIDE the analyzed function
                // (its byte span strictly contains them). Parameters of the
                // analyzed function itself are real local variables — their
                // reads are genuine uses. Parameters of unrelated sibling
                // functions must not enter the suppression set, or a name they
                // happen to share with a local of the analyzed function (e.g.
                // NestJS `moduleDefinition`, a parameter of BOTH
                // `scanForModules` and `insertOrOverrideModule`) silently drops
                // every read of that local and a benign reassignment looks like
                // a dead store.
                let collect_params = match self.analyzed_fn_span {
                    Some((start, end)) => {
                        let ns = node.start_byte();
                        let ne = node.end_byte();
                        // Strictly nested inside the analyzed function (and not
                        // the analyzed function itself, which shares neither
                        // boundary when strictly inside).
                        ns >= start && ne <= end && !(ns == start && ne == end)
                    }
                    // No analyzed span recorded — preserve prior behaviour.
                    None => true,
                };
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Also collect parameter names of every nested function.
                // When the OUTER function being analyzed has nested
                // helpers (e.g. ts-dom-gen's `emitWebIdl` -> inner
                // `convertDomTypeToTsTypeBase(obj, ...)`), the nested
                // function's parameter scope is inside the outer
                // function's CFG span. Without registering the param
                // names, identifiers like `obj`, `t`, `prefix`, `s`,
                // `i` inside those nested bodies were flagged as
                // definite-uninitialized by the outer reaching-defs
                // pass. Mirror that here by walking the parameters
                // subtree once and capturing every named binding.
                //
                // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): do NOT collect the
                // params of the function CURRENTLY BEING ANALYZED. Its own
                // parameters are real local variables of this function — their
                // reads are genuine uses. Adding them to `imported_type_names`
                // made the position-independent suppression below drop every
                // read of a parameter (e.g. NestJS `scanForModules`'s
                // destructured `moduleDefinition`), so a reassignment
                // `moduleDefinition = ... ?? moduleDefinition` looked like a
                // dead store (no recorded use). Skip the analyzed function so
                // its parameter reads survive; nested helpers are still
                // collected.
                if collect_params {
                    if let Some(params) = node.child_by_field_name("parameters") {
                        collect_ts_js_param_names(
                            params,
                            self.source,
                            &mut self.imported_type_names,
                        );
                    }
                }
                // Descend into the body so we collect names of
                // nested function declarations as well.
                // dfg-extractor-test-sync-v1: mark children as NOT
                // file-level so that lexical_declaration / variable_declaration
                // nodes found inside the function body are not mistakenly
                // added to the suppression set as file-level bindings.
                for child in node.children(&mut node.walk()) {
                    stack.push((child, false));
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // Lua/Luau file-level locals. `local m = {}` at the top of
            // a module makes `m` available to every function — but the
            // per-function reaching-defs analyzer would otherwise flag
            // it as uninitialized. We capture every `local` declared
            // name OUTSIDE function bodies. The lua/luau grammar uses
            // `variable_declaration` for `local x = ...` and
            // `function_declaration` / `local_function` for functions,
            // so we stop the walk at function entry points.
            // dfg-extractor-test-sync-v1: only collect file-level Lua locals;
            // skip `local y = ...` declarations inside function bodies
            // (is_file_level == false when reached via function-body descent).
            if matches!(self.language, Language::Lua | Language::Luau)
                && kind == "variable_declaration"
            {
                if is_file_level {
                    collect_lua_local_names(node, self.source, &mut self.imported_type_names);
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // TypeScript / JavaScript file-level `const x = ...` /
            // `let x = ...` / `var x = ...`. These are module-scoped
            // bindings visible to every function in the file. Without
            // tracking them, ts-dom-gen flagged `extendConflictsBaseTypes`,
            // `namespacesAsInterfaces`, and `sequenceTypedefMap` —
            // file-level const declarations — as uninitialized.
            //
            // We only collect bindings whose direct ancestor on the
            // walk stack is NOT a function body (the stop-at-function
            // guards earlier in this loop already handle that).
            // dfg-extractor-test-sync-v1: only collect file-level TS/JS
            // variable bindings; declarations inside function bodies
            // (is_file_level == false) are local to the function and must
            // not pollute the suppression set.
            if matches!(self.language, Language::TypeScript | Language::JavaScript)
                && matches!(kind, "lexical_declaration" | "variable_declaration")
            {
                if is_file_level {
                    collect_ts_js_variable_names(
                        node,
                        self.source,
                        &mut self.imported_type_names,
                    );
                }
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // OCaml top-level `open Foo` / `open! Foo` / `include Foo`
            // bring `Foo`'s value bindings into the module's namespace.
            // The trailing identifier of the open_module / include_module
            // is the module name (already a module ref, not a value), so
            // we don't collect it as a value-suppression name — but
            // value-path suppression in `is_ocaml_use_context` handles
            // the module-qualified case directly.
            // language-specific-bugs-v1 (P14.AGG14-12): collect class
            // field names. Java `field_declaration` carries one or more
            // `variable_declarator { name: <ident>, ... }` children directly.
            //
            // T5 (v0.5.0 AUDIT-FIX, root cause A1): tree-sitter-c-sharp does
            // NOT share the Java layout. A C# `field_declaration` wraps its
            // declarator(s) one level deeper:
            //   field_declaration
            //     modifier* variable_declaration
            //       [type] ...
            //       variable_declarator { [name]: identifier }
            //       (',' variable_declarator)*  -- for `int a, b;`
            // The pre-fix collector only looked for `variable_declarator` as a
            // DIRECT child, so NO C# field was ever registered — every bare
            // field read (`_writer.Write(...)`) was then flagged `definite`
            // uninitialized (45 FPs in BsonBinaryWriter.WriteTokenInternal).
            // Collect declarator names through any `variable_declaration`
            // wrapper, which covers both grammars.
            if kind == "field_declaration" {
                self.collect_field_declarator_names(node);
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // C# / Java: collect the name of every same-file type
            // declaration AND every method declaration so that bare-
            // identifier callees / type references (`BsonReaderState`,
            // `ReadNormalAsync`) inside a method body are classified as
            // not-a-use. Without this rule, `case BsonReaderState.X:`
            // flags `BsonReaderState`, and `t = ReadNormalAsync(...)`
            // flags `ReadNormalAsync`.
            //
            // We also explicitly collect the `name` of method/
            // constructor declarations BEFORE returning (without
            // descending into the body), so the next two early-returns
            // also serve as collectors.
            if matches!(
                self.language,
                Language::Java | Language::CSharp
            ) && matches!(
                kind,
                "class_declaration"
                    | "enum_declaration"
                    | "interface_declaration"
                    | "struct_declaration"
                    | "record_declaration"
            ) {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // continue walking — class bodies hold nested
                // fields/methods we still want to register.
            }
            if matches!(
                self.language,
                Language::Java | Language::CSharp
            ) && matches!(kind, "method_declaration" | "constructor_declaration") {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node
                        .utf8_text(self.source.as_bytes())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                // Don't descend into method bodies — fields are class-level
                // declarations, never inside a method.
                continue;
            }
            // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
            // for TS/JS/Lua/Luau, stop the walk at any function-body
            // boundary EXCEPT `function_declaration` (handled above —
            // we descend into JS/TS function bodies to collect nested
            // function-declaration names too). For other function
            // shapes (arrow_function, function_expression, etc.) the
            // contents are block-scoped expressions, NOT hoisted
            // declarations, so we stop here.
            if matches!(
                self.language,
                Language::TypeScript
                    | Language::JavaScript
                    | Language::Lua
                    | Language::Luau
            ) && matches!(
                kind,
                "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "function"
                    | "generator_function_declaration"
                    | "generator_function"
                    | "local_function"
                    | "function_definition"
            ) {
                continue;
            }
            // dfg-extractor-test-sync-v1: for Lua/Luau also stop at
            // `function_declaration` (e.g. `function foo(x) ... end`).
            // Previously only `local_function` and `function_definition`
            // were listed, so the walker descended into top-level
            // function_declaration bodies, collecting local variable names
            // as if they were file-level module locals.
            if matches!(self.language, Language::Lua | Language::Luau)
                && kind == "function_declaration"
            {
                continue;
            }
            for child in node.children(&mut node.walk()) {
                stack.push((child, is_file_level));
            }
        }
    }

    /// T5 (v0.5.0 AUDIT-FIX, root cause A1): collect every field name declared
    /// by a Java/C# `field_declaration` into `imported_type_names`.
    ///
    /// Java places `variable_declarator` directly under `field_declaration`;
    /// C# nests it under an intermediate `variable_declaration`. We collect a
    /// declarator's `name` field (or its first identifier child as a fallback)
    /// wherever it appears in the declaration subtree, descending only through
    /// the structural `variable_declaration` wrapper so we never reach into an
    /// initializer expression (a field initializer's identifiers are not field
    /// names and must not be suppressed).
    fn collect_field_declarator_names(&mut self, node: Node) {
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "variable_declarator" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node
                            .utf8_text(self.source.as_bytes())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !name.is_empty() {
                            self.imported_type_names.insert(name);
                        }
                    } else {
                        // Fallback: first identifier child of the declarator.
                        for inner in child.children(&mut child.walk()) {
                            if inner.kind() == "identifier" {
                                let name = inner
                                    .utf8_text(self.source.as_bytes())
                                    .unwrap_or("")
                                    .trim()
                                    .to_string();
                                if !name.is_empty() {
                                    self.imported_type_names.insert(name);
                                }
                                break;
                            }
                        }
                    }
                }
                // C#: `variable_declaration` wraps the declarator(s). Descend
                // one structural level (it also holds the `[type]`, which we
                // ignore — a declarator's name is what we want).
                "variable_declaration" => {
                    self.collect_field_declarator_names(child);
                }
                _ => {}
            }
        }
    }

    /// Extract function parameters as definitions
    fn extract_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        let params_node = match self.language {
            Language::Python => func_node.child_by_field_name("parameters"),
            Language::TypeScript | Language::JavaScript => {
                func_node.child_by_field_name("parameters")
            }
            Language::Go => func_node.child_by_field_name("parameters"),
            Language::Rust => func_node.child_by_field_name("parameters"),
            Language::Java => func_node.child_by_field_name("parameters"),
            Language::C | Language::Cpp => func_node
                .child_by_field_name("declarator")
                .and_then(|d| d.child_by_field_name("parameters")),
            Language::Ruby => func_node.child_by_field_name("parameters"),
            Language::Php => func_node.child_by_field_name("parameters"),
            Language::CSharp => func_node.child_by_field_name("parameters"),
            Language::Kotlin => {
                // Kotlin: function_declaration uses function_value_parameters (not "parameters" field)
                func_node.child_by_field_name("parameters").or_else(|| {
                    (0..func_node.child_count())
                        .filter_map(|i| func_node.child(i))
                        .find(|child| child.kind() == "function_value_parameters")
                })
            }
            // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala's
            // tree-sitter grammar names BOTH `[B]` (type_parameters) and
            // `(f: A => IO[B])` (parameters) with field name "parameters".
            // `child_by_field_name("parameters")` returns the FIRST match
            // (the type params), so the value-parameter node was never
            // walked. Find by kind == "parameters" explicitly.
            Language::Scala => (0..func_node.child_count())
                .filter_map(|i| func_node.child(i))
                .find(|child| child.kind() == "parameters"),
            Language::Lua | Language::Luau => func_node.child_by_field_name("parameters"),
            Language::Swift => None, // Swift parameters are direct children (handled below)
            // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): tree-sitter-solidity
            // emits `parameter` nodes as direct children of
            // `function_definition` / `constructor_definition` /
            // `modifier_definition` / `fallback_receive_definition` —
            // there is no enclosing `parameters` field. Return `None`
            // here and use `extract_solidity_parameters` (called after
            // the generic `if let Some(params) = ...` block, mirroring
            // Swift's pattern) to walk the direct children.
            Language::Solidity => None,
            _ => None,
        };

        if let Some(params) = params_node {
            self.extract_params_from_node(params)?;
        }

        // Elixir: parameters are identifiers inside the def call's arguments
        // Structure: (call "def" (arguments (call (identifier "foo") (arguments (identifier "x")))))
        if matches!(self.language, Language::Elixir) {
            self.extract_elixir_parameters(func_node)?;
        }

        // OCaml: parameters are "parameter" nodes containing "value_pattern" inside let_binding
        if matches!(self.language, Language::Ocaml) {
            self.extract_ocaml_parameters(func_node)?;
        }

        // Swift: parameters are direct "parameter" children of function_declaration
        // Each parameter has a simple_identifier child (the param name)
        if matches!(self.language, Language::Swift) {
            self.extract_swift_parameters(func_node)?;
        }

        // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): Solidity `parameter` nodes
        // are direct children of the function/modifier/constructor decl
        // (no enclosing `parameters` wrapper). Each `parameter` has a
        // `name` field whose value is an `identifier`.
        if matches!(self.language, Language::Solidity) {
            self.extract_solidity_parameters(func_node)?;
        }

        Ok(())
    }

    /// Extract parameter names from a parameters node
    fn extract_params_from_node(&mut self, params_node: Node) -> TldrResult<()> {
        let mut cursor = params_node.walk();

        for child in params_node.children(&mut cursor) {
            self.extract_param_from_child(child);
        }

        Ok(())
    }

    fn extract_param_from_child(&mut self, child: Node) {
        match self.language {
            Language::Python => self.extract_python_param(child),
            Language::TypeScript | Language::JavaScript => self.extract_ts_js_param(child),
            Language::Go => self.extract_go_param(child),
            Language::Rust => self.extract_rust_param(child),
            Language::Java | Language::CSharp => self.extract_java_csharp_param(child),
            Language::Scala => self.extract_scala_param(child),
            Language::Kotlin => self.extract_kotlin_param(child),
            Language::C | Language::Cpp => self.extract_c_cpp_param(child),
            Language::Ruby => self.extract_ruby_param(child),
            Language::Php => self.extract_php_param(child),
            Language::Lua | Language::Luau => self.extract_lua_param(child),
            Language::Swift => self.extract_swift_param(child),
            Language::Solidity => self.extract_solidity_param(child),
            _ => {}
        }
    }

    fn extract_python_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "typed_parameter" && child.kind() != "default_parameter" {
            return;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            self.add_ref_from_node(name_node, RefType::Definition);
            return;
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    fn extract_ts_js_param(&mut self, child: Node) {
        if child.kind() != "identifier" && child.kind() != "required_parameter" {
            return;
        }
        if let Some(pattern) = child.child_by_field_name("pattern") {
            self.add_ref_from_node(pattern, RefType::Definition);
        } else if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
        }
    }

    fn extract_go_param(&mut self, child: Node) {
        if child.kind() != "parameter_declaration" {
            return;
        }
        let mut inner = child.walk();
        for inner_child in child.children(&mut inner) {
            if inner_child.kind() == "identifier" {
                self.add_ref_from_node(inner_child, RefType::Definition);
            }
        }
    }

    fn extract_rust_param(&mut self, child: Node) {
        if child.kind() != "parameter" {
            return;
        }
        if let Some(pattern) = child.child_by_field_name("pattern") {
            if pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        }
    }

    fn extract_java_csharp_param(&mut self, child: Node) {
        if child.kind() != "formal_parameter"
            && child.kind() != "spread_parameter"
            && child.kind() != "parameter"
        {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
    }

    fn extract_kotlin_param(&mut self, child: Node) {
        if child.kind() != "parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
                return;
            }
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    /// cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala parameter
    /// extraction. The grammar shape is `parameters -> ( ... parameter ... )`
    /// where each `parameter` node has an `identifier` child for the param
    /// name (e.g. `f` in `def flatMap[B](f: A => IO[B])`). Without this
    /// dispatch, scala function parameters are NEVER added as Definitions
    /// and reaching-defs flags every parameter use as definite-uninitialized.
    fn extract_scala_param(&mut self, child: Node) {
        if child.kind() != "parameter" && child.kind() != "class_parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
                return;
            }
        }
        if let Some(identifier) = first_child_of_kind(child, "identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    fn extract_c_cpp_param(&mut self, child: Node) {
        if child.kind() != "parameter_declaration" {
            return;
        }
        let Some(declarator) = child.child_by_field_name("declarator") else {
            return;
        };
        if declarator.kind() == "identifier" {
            self.add_ref_from_node(declarator, RefType::Definition);
            return;
        }
        if declarator.kind() == "pointer_declarator" {
            if let Some(identifier) = first_child_of_kind(declarator, "identifier") {
                self.add_ref_from_node(identifier, RefType::Definition);
            }
        }
    }

    fn extract_ruby_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "optional_parameter"
            && child.kind() != "keyword_parameter"
            && child.kind() != "splat_parameter"
            && child.kind() != "hash_splat_parameter"
        {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
    }

    fn extract_php_param(&mut self, child: Node) {
        if child.kind() != "simple_parameter" && child.kind() != "variadic_parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            self.add_ref_from_node(name, RefType::Definition);
        }
    }

    fn extract_lua_param(&mut self, child: Node) {
        if child.kind() == "identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // tree-sitter-luau wraps each parameter in a `parameter` node
        // whose children are `type` / `vararg_expression`. The `type`
        // node, in turn, has the param identifier as its `identifier`
        // subtype child. tree-sitter-lua, by contrast, lists parameter
        // identifiers directly as children of `parameters` — so the
        // pre-fix code (above) handled lua but silently dropped every
        // luau parameter, surfacing as 9 FPs (incl. `t, na, nh`) on
        // `tldr reaching-defs tables.luau check`.
        //
        // We accept either a `parameter` wrapper (luau) or a bare
        // identifier (lua); descend at most one extra level to find the
        // first `identifier` child.
        if child.kind() == "parameter" {
            if let Some(ident) = first_descendant_identifier_under(child, "identifier") {
                self.add_ref_from_node(ident, RefType::Definition);
            }
        }
    }

    fn extract_swift_param(&mut self, child: Node) {
        if child.kind() == "simple_identifier" {
            self.add_ref_from_node(child, RefType::Definition);
            return;
        }
        if child.kind() != "parameter" {
            return;
        }
        if let Some(identifier) = first_child_of_kind(child, "simple_identifier") {
            self.add_ref_from_node(identifier, RefType::Definition);
        }
    }

    /// solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): walk direct `parameter`
    /// children of a Solidity function/constructor/modifier/fallback
    /// definition and register each parameter's `name` field as a
    /// `Definition`. Anonymous params (return-position `parameter`
    /// nodes with no `name` field) are intentionally skipped — they
    /// have no local binding.
    fn extract_solidity_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "parameter" {
                self.extract_solidity_param(child);
            }
        }
        Ok(())
    }

    /// solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): a Solidity `parameter`
    /// has the shape `(type) (data_location)? (name)?`. The `name`
    /// field — when present — is an `identifier` that introduces a
    /// local binding usable inside the function body.
    fn extract_solidity_param(&mut self, child: Node) {
        if child.kind() != "parameter" {
            return;
        }
        if let Some(name) = child.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
    }

    /// Add a variable reference from an AST node
    fn add_ref_from_node(&mut self, node: Node, ref_type: RefType) {
        let name = node
            .utf8_text(self.source.as_bytes())
            .unwrap_or("")
            .to_string();
        if name.is_empty() || is_keyword(&name, self.language) {
            return;
        }

        let line = node.start_position().row as u32 + 1; // 1-indexed
        let column = node.start_position().column as u32;

        self.variables.insert(name.clone());
        self.refs.push(VarRef {
            name,
            ref_type,
            line,
            column,
            context: None,
            group_id: None,
        });
    }

    /// Extract all variable references from an AST node
    ///
    /// This is the core multi-language dispatch. Each language has different
    /// AST node kinds for assignments, declarations, and loops. We match
    /// on all known kinds and delegate to language-specific processing.
    fn extract_refs_from_node(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if depth > MAX_DEPTH {
            return Ok(());
        }

        match node.kind() {
            // =================================================================
            // Python/Ruby assignment statements (Swift handled separately below)
            // =================================================================
            "assignment" if !matches!(self.language, Language::Swift) => {
                self.process_assignment(node, depth)?;
            }

            // Python expression_statement (may wrap assignment or other exprs)
            "expression_statement" => {
                self.process_expression_statement(node, depth)?;
            }

            // Python augmented assignment: x += 1
            "augmented_assignment" => {
                self.process_augmented_assignment(node)?;
            }

            // =================================================================
            // TypeScript/JavaScript declarations + Lua/Luau local declarations
            // =================================================================
            // JS/TS: let x = ...; const x = ...; var x = ...;
            // Lua/Luau: local x = ...
            "lexical_declaration" | "variable_declaration" => match self.language {
                Language::Lua | Language::Luau => {
                    self.process_lua_local_declaration(node, depth)?;
                }
                _ => {
                    self.process_js_ts_declaration(node, depth)?;
                }
            },

            // =================================================================
            // TypeScript/JavaScript/Java/C/C++/Rust assignment expressions
            // =================================================================
            "assignment_expression" => {
                self.process_c_style_assignment(node, depth)?;
            }

            // =================================================================
            // TypeScript/JavaScript/Java/C/C++ augmented assignment
            // =================================================================
            "augmented_assignment_expression" => {
                self.process_c_style_augmented_assignment(node, depth)?;
            }

            // =================================================================
            // PHP increment/decrement: $n++, ++$n, $n--, --$n
            //
            // m114-adapter-tail-v1 (v0.4.2 M-114): tree-sitter-php emits
            // `update_expression` with an `argument` field pointing at the
            // operand (a `variable_name` for `$n`, possibly a
            // `subscript_expression` or `member_access_expression` for
            // `$arr[$i]++`). The pre-fix extractor only walked `identifier`
            // and `variable_name` nodes for refs, treating them as USE — so
            // `$n++` registered ONE use of `$n` and ZERO defs. Reaching-defs
            // then reported every variable mutated only via `++`/`--`
            // as bound to its initial assignment.
            //
            // Emit BOTH a use (the increment reads the current value) and
            // a def (it writes back the result). Match `process_augmented_
            // assignment`'s pattern.
            // =================================================================
            "update_expression"
                if matches!(self.language, Language::Php | Language::Solidity) =>
            {
                if let Some(arg) = node.child_by_field_name("argument") {
                    match arg.kind() {
                        "variable_name" => {
                            // PHP: $n++ / ++$n
                            self.add_ref_from_node(arg, RefType::Update);
                        }
                        // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): the M-114
                        // PHP analog for Solidity. Solidity's `update_expression`
                        // has the shape `[argument] expression > identifier`
                        // (`expression` is a wrapper named child). When the
                        // operand is a bare identifier wrapped in `expression`,
                        // emit `RefType::Update` on the underlying identifier
                        // so SSA construction sees it as USE-then-DEF and
                        // emits a fresh version for the next use.
                        "identifier" => {
                            self.add_ref_from_node(arg, RefType::Update);
                        }
                        "expression" if matches!(self.language, Language::Solidity) => {
                            if let Some(ident) = solidity_unwrap_expression(arg) {
                                if ident.kind() == "identifier" {
                                    self.add_ref_from_node(ident, RefType::Update);
                                } else {
                                    // Non-identifier targets (subscript /
                                    // member access). Walk for nested uses.
                                    self.extract_refs_from_node(ident, depth + 1)?;
                                }
                            }
                        }
                        _ => {
                            // For subscript/member access targets, still walk
                            // the rhs for nested uses so analyzers see them.
                            self.extract_refs_from_node(arg, depth + 1)?;
                        }
                    }
                }
            }

            // =================================================================
            // Rust let declarations: let x = ...; let mut x = ...;
            // rust-dataflow-v1 (v0.4.2 bug-C2): `let_condition` is the AST
            // node for the `let pat = expr` form that appears INSIDE
            // `while let`, `if let`, and `let_chain` (`if let A && let B`).
            // tree-sitter-rust does NOT reuse `let_declaration` for those —
            // they share the same field layout (`pattern` / `value`), so
            // we route both kinds through `process_rust_let`. Without this
            // arm the loop binding in `while let Some(c) = self.bump()`
            // was never registered as a definition, leaving rust
            // reaching-defs with empty gen/kill sets everywhere.
            // =================================================================
            "let_declaration" | "let_condition" => {
                self.process_rust_let(node, depth)?;
            }

            // =================================================================
            // Go short var declaration: x := ...
            // =================================================================
            "short_var_declaration" => {
                self.process_go_short_var(node, depth)?;
            }

            // Go var declaration: var x = ...
            "var_declaration" => {
                self.process_go_var_declaration(node, depth)?;
            }

            // Go/Lua/Luau assignment statement: x = ...; x += ...
            "assignment_statement" => match self.language {
                Language::Lua | Language::Luau => {
                    self.process_lua_assignment_statement(node, depth)?;
                }
                _ => {
                    self.process_go_assignment(node, depth)?;
                }
            },

            // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): Luau (and Lua, which
            // shares the Luau compound-assignment extension) spells op-assigns
            // (`total += v`, `x *= 2`) as a DISTINCT `update_statement` node,
            // NOT `assignment_statement`. With no arm here the LHS target's
            // implicit READ (an op-assign reads the prior value before writing
            // back) was lost, so a backward slice of the accumulator omitted
            // the `+=` line and a prior store looked dead.
            "update_statement" if matches!(self.language, Language::Lua | Language::Luau) => {
                self.process_lua_update_statement(node, depth)?;
            }

            // =================================================================
            // Java/C# local variable declaration: int x = ...;
            // =================================================================
            "local_variable_declaration" => {
                self.process_java_local_var(node, depth)?;
            }

            // =================================================================
            // Solidity local variable declaration: `uint256 y = ...;`
            //
            // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): tree-sitter-solidity
            // wraps a local in `statement > variable_declaration_statement`
            // whose layout is:
            //   variable_declaration_statement
            //     variable_declaration       -- has [type] and [name]
            //     '='
            //     [value] expression         -- RHS, optional
            //     ';'
            // The `variable_declaration` shape is shared with state-var
            // decls, but only the `_statement` wrapper appears inside a
            // function body.
            // =================================================================
            "variable_declaration_statement"
                if matches!(self.language, Language::Solidity) =>
            {
                self.process_solidity_variable_declaration(node, depth)?;
            }

            // =================================================================
            // C/C++ declaration: int x = ...;
            // =================================================================
            "declaration" if matches!(self.language, Language::C | Language::Cpp) => {
                self.process_c_declaration(node, depth)?;
            }

            // =================================================================
            // Ruby assignment: x = ...
            // Ruby uses "assignment" (same as Python, handled above)
            // =================================================================
            // Ruby operator_assignment: x += ...
            "operator_assignment" => {
                self.process_augmented_assignment(node)?;
            }

            // =================================================================
            // Kotlin/Swift property declaration: val x = ...; var x = ...; let x = ...
            // =================================================================
            "property_declaration"
                if matches!(self.language, Language::Kotlin | Language::Swift) =>
            {
                match self.language {
                    Language::Swift => self.process_swift_property(node, depth)?,
                    _ => self.process_kotlin_property(node, depth)?,
                }
            }

            // =================================================================
            // Swift assignment: z = z + 1
            // AST: assignment -> directly_assignable_expression -> simple_identifier, =, expression
            // =================================================================
            "assignment" if matches!(self.language, Language::Swift) => {
                self.process_swift_assignment(node, depth)?;
            }

            // =================================================================
            // Scala val/var definitions
            // =================================================================
            "val_definition" | "var_definition" => {
                self.process_scala_val_var(node, depth)?;
            }

            // =================================================================
            // Scala match-arm pattern bindings.
            //
            // T5 (v0.5.0 AUDIT-FIX, root cause A6): `case Errored(e) =>
            // errored(e)` binds `e` as a pattern variable (a Definition); the
            // arm body's read `errored(e)` must resolve to it. Without a
            // `case_clause` arm the binding was never registered, so `e`/`fa`
            // (Outcome.fold) were reported as `definite` uninitialized. Extract
            // the pattern's bound identifiers as definitions, then analyze the
            // guard and body for uses.
            // =================================================================
            "case_clause" if matches!(self.language, Language::Scala) => {
                self.process_scala_case_clause(node, depth)?;
            }

            // =================================================================
            // Elixir match operator: x = ... (pattern matching assignment)
            // Elixir grammar uses binary_operator with "=" for pattern matching
            // =================================================================
            "match_operator" if matches!(self.language, Language::Elixir) => {
                self.process_elixir_match(node, depth)?;
            }

            "binary_operator" if matches!(self.language, Language::Elixir) => {
                // Check if this is an assignment (= operator)
                let is_match = node.children(&mut node.walk()).any(|c| {
                    !c.is_named() && c.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                });
                if is_match {
                    self.process_elixir_match(node, depth)?;
                } else {
                    // Other binary operators: recurse into children for uses
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }

            // =================================================================
            // OCaml let bindings: let x = ... in ...
            // =================================================================
            "let_expression" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_let_expression(node, depth)?;
            }

            "value_definition" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_value_definition(node, depth)?;
            }

            "let_binding" if matches!(self.language, Language::Ocaml) => {
                self.process_ocaml_let_binding(node, depth)?;
            }

            // =================================================================
            // For loops (loop variable is a definition)
            // =================================================================
            // The bare `for_statement` node kind is REUSED across grammars
            // with different shapes:
            //   * Python `for x in items:` — `left` (target) / `right`
            //     (iterable) / `body` fields. Handled by `process_for_loop`.
            //   * Go `for r < n { }` / `for { }` / `for i:=0; i<n; i++ { }` —
            //     no left/right; the condition is a positional child or lives
            //     in a `for_clause`. Handled by `process_go_for_statement`.
            //   * C/C++ `for (init; cond; post) { }` — `initializer` /
            //     `condition` / `update` / `body` fields. Handled by
            //     `process_c_for_statement`.
            //
            // fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 2): the
            // pre-fix code dispatched ALL `for_statement` nodes to the
            // Python-shaped `process_for_loop`, which finds no `left`/`right`/
            // `body` fields on Go/C loops and so dropped the condition uses
            // AND the entire loop body (slice go-httprouter CleanPath 61
            // returned only `[61]`). Route by language to a shape-aware
            // handler.
            "for_statement" => match self.language {
                Language::Go => self.process_go_for_statement(node, depth)?,
                Language::C | Language::Cpp => {
                    self.process_c_for_statement(node, depth)?
                }
                // T5 (v0.5.0 AUDIT-FIX, root cause A5): Lua/Luau reuse the
                // `for_statement` node kind for both numeric and generic for,
                // exposing a `[clause]` (`for_numeric_clause` /
                // `for_generic_clause`) plus a `[body]` block — NOT the
                // left/right fields the Python handler expects. Without a
                // shape-aware arm the loop variables (`issue`, `line`) were
                // never registered as definitions, so their body reads were
                // flagged `definite` uninitialized.
                Language::Lua | Language::Luau => {
                    self.process_lua_for_statement(node, depth)?
                }
                _ => self.process_for_loop(node, depth)?,
            },

            // Python/JS: for x in items / for (x in obj)
            "for_in_statement" => {
                self.process_for_loop(node, depth)?;
            }

            // Rust: for x in items { }
            "for_expression" => {
                self.process_rust_for(node, depth)?;
            }

            // JS/TS: for (const x of items) { }
            "for_of_statement" => {
                self.process_js_for_of(node, depth)?;
            }

            // Java: for (int x : items) { }
            "enhanced_for_statement" => {
                self.process_java_enhanced_for(node, depth)?;
            }

            // PHP: foreach ($arr as $key => $val) { }
            //
            // T5 (v0.5.0 AUDIT-FIX, root cause A3): C# reuses the
            // `foreach_statement` node kind but with a different shape —
            // `foreach (T x in coll) { }` exposes `[type]` / `[left]` /
            // `[right]` / `[body]` fields and has NO `as` child. The pre-fix
            // code routed ALL `foreach_statement` nodes to the PHP handler,
            // which scans for an `as` token; finding none it dropped the C#
            // loop variable (`property`, `c`), so every body read of it was
            // flagged `definite` uninitialized. Route C# to a shape-aware
            // handler. (PHP is the only other grammar using this node kind.)
            "foreach_statement" => match self.language {
                Language::CSharp => self.process_csharp_foreach(node, depth)?,
                _ => self.process_php_foreach(node, depth)?,
            },

            // Go: for i, v := range items { }
            "range_clause" => {
                self.process_go_range(node, depth)?;
            }

            // Ruby: for x in items do ... end
            "for" if matches!(self.language, Language::Ruby) => {
                self.process_for_loop(node, depth)?;
            }

            // =================================================================
            // With statements (Python-specific)
            // =================================================================
            "with_statement" => {
                self.process_with_statement(node, depth)?;
            }

            // =================================================================
            // Exception handlers (multi-language)
            // =================================================================
            "except_clause" | "catch_clause" => {
                self.process_exception_handler(node, depth)?;
            }

            // =================================================================
            // Identifiers (potential uses) - all languages
            // =================================================================
            "identifier" => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty() && !is_keyword(name, self.language) && self.is_use_context(node)
                {
                    // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): in Scala,
                    // identifiers whose first letter is uppercase are
                    // overwhelmingly type names, class names, or companion
                    // objects (Scala convention is strict: types/objects
                    // start uppercase, vars/methods start lowercase). They
                    // resolve at compile time to top-level singletons that
                    // are always available — flagging them as
                    // definite-uninitialized in reaching-defs is a false
                    // positive (e.g. `IO`, `FlatMap`, `Tracing` in
                    // `IO(FlatMap(this, f, Tracing.calculateTracingEvent(f)))`).
                    if matches!(self.language, Language::Scala) {
                        if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                            // Recurse into children so any nested identifiers
                            // (rare for an identifier node) are not lost.
                            let mut cursor = node.walk();
                            for child in node.children(&mut cursor) {
                                self.extract_refs_from_node(child, depth + 1)?;
                            }
                            return Ok(());
                        }
                    }
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // PHP variable names: $x
            "variable_name" if matches!(self.language, Language::Php) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty() && self.is_use_context(node) {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // OCaml: value_name is used instead of identifier for variable names
            "value_name" if matches!(self.language, Language::Ocaml) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty()
                    && !is_keyword(name, self.language)
                    && self.is_ocaml_use_context(node)
                {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // Swift: simple_identifier is used instead of identifier
            "simple_identifier" if matches!(self.language, Language::Swift) => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !name.is_empty()
                    && !is_keyword(name, self.language)
                    && self.is_swift_use_context(node)
                {
                    self.add_ref_from_node(node, RefType::Use);
                }
            }

            // =================================================================
            // Recurse into other nodes
            // =================================================================
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Process a Python expression_statement (may wrap assignment, augmented_assignment, etc.)
    fn process_expression_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_refs_from_node(child, depth + 1)?;
        }
        Ok(())
    }

    /// Process an assignment statement (Python "assignment", Ruby "assignment")
    fn process_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // assignment has "left" and "right" fields
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_assignment_targets(left)?;
        }

        // Process the right side for uses
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Extract assignment targets (definitions)
    fn extract_assignment_targets(&mut self, target: Node) -> TldrResult<()> {
        // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): Solidity wraps every
        // operand in a named `expression` node. The actual target
        // (identifier / array_access / member_expression / tuple) lives
        // one level deeper. Unwrap once before dispatching so the rest
        // of this function can match on the concrete kind.
        if matches!(self.language, Language::Solidity) && target.kind() == "expression" {
            if let Some(inner) = solidity_unwrap_expression(target) {
                return self.extract_assignment_targets(inner);
            }
            return Ok(());
        }
        match target.kind() {
            "identifier" => {
                self.add_ref_from_node(target, RefType::Definition);
            }
            // Python unpacking
            "tuple" | "list" | "pattern_list" => {
                let mut cursor = target.walk();
                for child in target.children(&mut cursor) {
                    self.extract_assignment_targets(child)?;
                }
            }
            // TS/JS destructuring patterns
            "object_pattern" | "array_pattern" => {
                let mut cursor = target.walk();
                for child in target.children(&mut cursor) {
                    if child.kind() == "identifier"
                        || child.kind() == "shorthand_property_identifier_pattern"
                        || child.kind() == "shorthand_property_identifier"
                    {
                        self.add_ref_from_node(child, RefType::Definition);
                    } else {
                        self.extract_assignment_targets(child)?;
                    }
                }
            }
            // Python: x.attr = ...
            "attribute" => {
                if let Some(obj) = target.child_by_field_name("object") {
                    if obj.kind() == "identifier" {
                        self.add_ref_from_node(obj, RefType::Update);
                    }
                }
            }
            // TS/JS/Java: x.field = ...
            // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): tree-sitter-solidity
            // also uses `member_expression` with `[object]` and `[property]`
            // fields, but the `[object]` child is wrapped in a named
            // `expression` node. Unwrap it before checking for the
            // identifier so Solidity `msg.sender.x = 1;` registers
            // `msg` as the Update target (matches the receiver-as-update
            // semantics of TS/JS/Java).
            "member_expression" => {
                if let Some(obj) = target.child_by_field_name("object") {
                    let obj_inner = if obj.kind() == "expression"
                        && matches!(self.language, Language::Solidity)
                    {
                        solidity_unwrap_expression(obj).unwrap_or(obj)
                    } else {
                        obj
                    };
                    if obj_inner.kind() == "identifier" {
                        self.add_ref_from_node(obj_inner, RefType::Update);
                    } else if matches!(self.language, Language::Solidity) {
                        // Nested member/array on the LHS — recurse so the
                        // outermost identifier registers.
                        self.extract_assignment_targets(obj_inner)?;
                    }
                }
            }
            // Go: x.field = ...
            "selector_expression" => {
                if let Some(operand) = target.child_by_field_name("operand") {
                    if operand.kind() == "identifier" {
                        self.add_ref_from_node(operand, RefType::Update);
                    }
                }
            }
            // Rust: x.field = ...
            "field_expression" => {
                if let Some(value) = target.child_by_field_name("value") {
                    if value.kind() == "identifier" {
                        self.add_ref_from_node(value, RefType::Update);
                    }
                }
            }
            // Python: x[i] = ...
            //
            // fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1): an
            // element write `a[idx] = ...` updates the container `a` AND
            // *reads* every variable inside the index `idx`. The pre-fix arm
            // recorded only the container and dropped the index uses, so a
            // backward slice/chop through `s[curlen+len] = '\0';` lost the
            // `curlen`/`len` data-flow edge. Handle the container (field
            // `value` for Python `subscript`) then descend into the index
            // subtree for uses — mirroring the Solidity `array_access` arm
            // below, which already does this.
            "subscript" => {
                self.record_subscript_container_and_index(
                    target, "value", "subscript",
                )?;
            }
            // TS/JS/C/C++: x[i] = ...
            //
            // fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1): the
            // field names differ by grammar:
            //   * TS/JS — container field `object`, index field `index`.
            //   * C     — container field `argument`, index field `index`.
            //   * C++   — container field `argument`, index field `indices`
            //             (an extra `subscript_argument_list` wrapper, which
            //             the index-walk descends through automatically).
            // Try each known field name in order. (The pre-fix arm hard-coded
            // container `object` / index `index`, so for C/C++ — the chop
            // c-redis target — neither the container Update nor the index uses
            // were recorded.)
            "subscript_expression" => {
                self.record_subscript_container_and_index_multi(
                    target,
                    &["object", "argument"],
                    &["index", "indices"],
                )?;
            }
            // Go: x[i] = ...
            "index_expression" => {
                self.record_subscript_container_and_index(
                    target, "operand", "index",
                )?;
            }
            // PHP variable name
            "variable_name" => {
                self.add_ref_from_node(target, RefType::Definition);
            }
            // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): Solidity uses
            // `array_access` (with `[base]` and `[index]` fields) for
            // mapping/array writes like `balances[user] = y;`. The
            // base identifier is the storage location being updated
            // (RefType::Update — read-then-write), and the index is a
            // Use (descended into below so nested identifiers register).
            //
            // fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1):
            // Java/C# ALSO emit `array_access` for `a[i] = ...`, but spell
            // the container field `array` (not Solidity's `base`). The
            // pre-fix arm only consulted `base`, so a Java/C# element-write
            // container was never recorded as an Update (the index uses were
            // still captured, because the index-walk below is unconditional).
            // Try `base` (Solidity) then `array` (Java/C#).
            "array_access" => {
                let base = target
                    .child_by_field_name("base")
                    .or_else(|| target.child_by_field_name("array"));
                if let Some(base) = base {
                    // Unwrap the `expression` wrapper (Solidity).
                    let base_inner = if base.kind() == "expression" {
                        solidity_unwrap_expression(base).unwrap_or(base)
                    } else {
                        base
                    };
                    if base_inner.kind() == "identifier" {
                        self.add_ref_from_node(base_inner, RefType::Update);
                    } else {
                        // Nested array_access / member_expression — recurse
                        // so the outermost identifier gets the Update.
                        self.extract_assignment_targets(base_inner)?;
                    }
                }
                // The index is a Use; descend into it.
                if let Some(index) = target.child_by_field_name("index") {
                    self.extract_refs_from_node(index, 1)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1): record an
    /// element-write LHS `container[index] = ...`.
    ///
    /// The element write is a read-then-write of the *container* (so the
    /// container identifier is a [`RefType::Update`]) and a *read* of every
    /// variable inside the index expression (so the index subtree is walked
    /// for [`RefType::Use`]s via the normal dispatch). When the container is
    /// itself a nested subscript / member access (`a[i][j] = ...`,
    /// `obj.buf[i] = ...`) we recurse so the outermost identifier carries the
    /// Update. Mirrors the Solidity `array_access` arm.
    ///
    /// `container_field` / `index_field` are the tree-sitter field names for
    /// this grammar's subscript node (e.g. Python `subscript` -> `value` /
    /// `subscript`, Go `index_expression` -> `operand` / `index`).
    fn record_subscript_container_and_index(
        &mut self,
        target: Node,
        container_field: &str,
        index_field: &str,
    ) -> TldrResult<()> {
        if let Some(container) = target.child_by_field_name(container_field) {
            if container.kind() == "identifier" {
                self.add_ref_from_node(container, RefType::Update);
            } else {
                // Nested subscript / member access — recurse so the outermost
                // identifier registers (and any inner index vars are walked).
                self.extract_assignment_targets(container)?;
            }
        }
        // The index is a Use; descend into it so every index variable
        // (including those inside an arithmetic index like `i + len`) is
        // recorded.
        if let Some(index) = target.child_by_field_name(index_field) {
            self.extract_refs_from_node(index, 1)?;
        }
        Ok(())
    }

    /// fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1): like
    /// [`record_subscript_container_and_index`] but tries several container /
    /// index field names in order. tree-sitter spells the fields of a
    /// `subscript_expression` differently per language — TS/JS use `object` /
    /// `index`, C uses `argument` / `index`, C++ uses `argument` / `indices`.
    fn record_subscript_container_and_index_multi(
        &mut self,
        target: Node,
        container_fields: &[&str],
        index_fields: &[&str],
    ) -> TldrResult<()> {
        let container = container_fields
            .iter()
            .find_map(|f| target.child_by_field_name(f));
        if let Some(container) = container {
            if container.kind() == "identifier" {
                self.add_ref_from_node(container, RefType::Update);
            } else {
                self.extract_assignment_targets(container)?;
            }
        }
        if let Some(index) = index_fields
            .iter()
            .find_map(|f| target.child_by_field_name(f))
        {
            self.extract_refs_from_node(index, 1)?;
        }
        Ok(())
    }

    /// Process augmented assignment (x += ...)
    fn process_augmented_assignment(&mut self, node: Node) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                // CL-13 (cl12_13_dfg_v1): an op-assign (`x += 1`, Ruby
                // `operator_assignment`, Python `augmented_assignment`)
                // BOTH reads the prior value of `x` and writes a new one.
                // Recording only the `Update` lost the implicit read, so a
                // prior store `x = 0` looked dead even though `x += 1`
                // consumes it. Emit the implicit `Use` first (it observes
                // the value live at entry to this statement) and then the
                // `Update` write-back.
                self.add_ref_from_node(left, RefType::Use);
                self.add_ref_from_node(left, RefType::Update);
            }
        }

        // The right side contains uses
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, 1)?;
        }

        Ok(())
    }

    /// Process for loop (loop variable is a definition)
    fn process_for_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Python: for_statement has "left" (loop var) and "right" (iterable)
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_assignment_targets(left)?;
        }

        // The iterable is a use
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        // Process the body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 2): Go
    /// `for_statement`.
    ///
    /// Go reuses the `for_statement` node kind for three loop shapes:
    ///   * `for { ... }`             — only a `body` field.
    ///   * `for r < n { ... }`       — a positional condition expression
    ///                                 (a non-field named child) + `body`.
    ///   * `for i := 0; i < n; i++ { ... }`
    ///                               — a `for_clause` child (carrying the
    ///                                 `initializer` / `condition` / `update`
    ///                                 sub-nodes) + `body`.
    ///   * `for i, v := range xs { ... }`
    ///                               — a `range_clause` child + `body`.
    ///
    /// In every shape the condition references variables as *reads* and the
    /// body must be analyzed. Rather than special-casing each, we recurse
    /// into every named child via the normal dispatch: the `block` body has
    /// its statements processed, a bare `binary_expression` condition yields
    /// its identifiers as uses, a `for_clause`/`range_clause` has its own
    /// init/cond/update/range handled by their respective arms. This is
    /// uniform and forward-compatible with grammar tweaks. (The pre-fix
    /// Python-shaped handler found no `left`/`right`/`body` fields here — Go's
    /// body field is also named `body`, but the condition has no field — and
    /// silently dropped both the condition and, for the bare-condition and
    /// range forms, ALL body statements.)
    fn process_go_for_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.is_named() {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    /// fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 2): C/C++
    /// `for_statement` — `for (init; cond; post) body`.
    ///
    /// tree-sitter-c exposes the clauses as named fields: `initializer`
    /// (an assignment / declaration that may DEFINE the loop variable),
    /// `condition` (a read of the loop variables), `update` (a read+write,
    /// here recorded as a read via recursion), and `body`. Each is processed
    /// through the normal dispatch so the construct-specific arms apply
    /// (`assignment_expression` -> Definition for `i = 0`, `declaration` ->
    /// Definition for `int i = 0`, identifiers -> Use in the condition, etc.).
    /// Any clause may be empty (`for (;;)`), in which case the field is
    /// absent and skipped.
    fn process_c_for_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        for field in ["initializer", "condition", "update", "body"] {
            if let Some(child) = node.child_by_field_name(field) {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Process with statement
    fn process_with_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // T5 (v0.5.0 AUDIT-FIX, root cause B2): tree-sitter-python nests the
        // `with_item`s under a `with_clause` wrapper:
        //   with_statement
        //     'with' with_clause { with_item { [value] <ctx-expr> } } ':' [body]
        // The pre-fix loop scanned only the DIRECT children of
        // `with_statement` for `with_item`, found none, and dropped the
        // context-expression reads — so a variable used ONLY as a context
        // argument (`with set_environ("k", no_proxy_arg):`) had no recorded
        // use and its prior store was flagged dead. Descend through any
        // `with_clause` wrapper while still tolerating a flat layout.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "with_item" => self.process_with_item(child, depth)?,
                "with_clause" => {
                    for item in child.children(&mut child.walk()) {
                        if item.kind() == "with_item" {
                            self.process_with_item(item, depth)?;
                        }
                    }
                }
                _ => {}
            }
        }

        // Process the body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// Process a single Python `with_item`: the context expression is a use,
    /// the optional `as <name>` alias is a definition.
    ///
    /// Two shapes occur. Without an alias the `[value]` field is the bare
    /// context expression. With `as`, tree-sitter-python wraps it as
    /// `[value] as_pattern { <ctx-expr> 'as' [alias] as_pattern_target {
    /// identifier } }` — there is NO `alias` field directly on `with_item`.
    fn process_with_item(&mut self, item: Node, depth: usize) -> TldrResult<()> {
        if let Some(value) = item.child_by_field_name("value") {
            if value.kind() == "as_pattern" {
                self.process_with_as_pattern(value, depth)?;
            } else {
                // Bare context expression: every identifier in it is a use.
                self.extract_refs_from_node(value, depth + 1)?;
            }
        }
        // Legacy flat layout: an explicit `alias` field on with_item.
        if let Some(alias) = item.child_by_field_name("alias") {
            if alias.kind() == "identifier" {
                self.add_ref_from_node(alias, RefType::Definition);
            }
        }
        Ok(())
    }

    /// Process a Python `as_pattern` (`<expr> as <target>`) used as a
    /// `with`-item value: the leading expression is a use, the
    /// `as_pattern_target` identifier is a definition.
    fn process_with_as_pattern(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        for child in node.children(&mut node.walk()) {
            match child.kind() {
                "as_pattern_target" => {
                    // The bound name(s): register identifier leaves as defs.
                    for inner in child.children(&mut child.walk()) {
                        if inner.kind() == "identifier" {
                            self.add_ref_from_node(inner, RefType::Definition);
                        } else {
                            self.extract_assignment_targets(inner)?;
                        }
                    }
                    // A bare `identifier` target with no wrapper.
                    if child.child_count() == 0 && child.kind() == "identifier" {
                        self.add_ref_from_node(child, RefType::Definition);
                    }
                }
                "as" => {}
                other if !other.is_empty() && child.is_named() => {
                    // The context expression preceding `as` — a use.
                    self.extract_refs_from_node(child, depth + 1)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Process exception handler
    fn process_exception_handler(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // except Exception as e: -> e is a definition
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // Process the body
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "block" {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // TypeScript/JavaScript processing
    // =====================================================================

    /// Process JS/TS declaration: let x = ...; const x = ...; var x = ...;
    /// AST: lexical_declaration -> variable_declarator (name, value)
    ///      variable_declaration -> variable_declarator (name, value)
    fn process_js_ts_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    } else {
                        // Could be destructuring pattern
                        self.extract_assignment_targets(name_node)?;
                    }
                }
                // "value" field is the initializer
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// Process JS/TS for-of: for (const item of items) { ... }
    fn process_js_for_of(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // left field: the loop variable declaration or identifier
        if let Some(left) = node.child_by_field_name("left") {
            // Could be a lexical_declaration like "const item"
            if left.kind() == "lexical_declaration" || left.kind() == "variable_declaration" {
                let mut cursor = left.walk();
                for child in left.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                self.add_ref_from_node(name_node, RefType::Definition);
                            }
                        }
                    }
                }
            } else if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Definition);
            }
        }

        // right field: the iterable (use)
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        // body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // C-style assignment processing (TS/JS/Java/C/C++/Rust)
    // =====================================================================

    /// Process C-style assignment expression: x = ...
    /// Used by TS/JS, Java, C, C++, Rust
    fn process_c_style_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                self.add_ref_from_node(left, RefType::Definition);
            } else {
                // Could be member expression, subscript, etc.
                self.extract_assignment_targets(left)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Process C-style augmented assignment: x += ..., x -= ...
    fn process_c_style_augmented_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                // CL-13 (cl12_13_dfg_v1): C-style op-assign (`x += 1` in
                // JS/TS/Java/C/C++/Rust) reads the prior value of `x` before
                // writing the result back. Emit the implicit `Use` so the
                // read is visible to dead-store and reaching-defs analysis,
                // then the `Update` write-back. (Member/subscript targets
                // such as `obj.f += 1` / `arr[i] += 1` are left to recursion
                // below — only bare-identifier targets carry a simple-variable
                // read.)
                self.add_ref_from_node(left, RefType::Use);
                self.add_ref_from_node(left, RefType::Update);
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Rust processing
    // =====================================================================

    /// Process Rust let declaration: let x = ...; let mut x = ...;
    /// Also handles the `let_condition` form used inside `while let` /
    /// `if let` (rust-dataflow-v1 / v0.4.2 bug-C2).
    ///
    /// AST: let_declaration -> pattern, value
    ///      let_condition   -> pattern, value (same fields)
    ///
    /// Pattern kinds recognised (each adds the bound identifier(s) as
    /// `RefType::Definition` via [`extract_rust_binding_identifiers`]):
    /// * `identifier`               — `let x = ...`
    /// * `mut_pattern`              — `let mut x = ...`
    /// * `tuple_pattern`            — `let (a, b) = ...`
    /// * `tuple_struct_pattern`     — `let Some(c) = ...`, `let Ok(v) = ...`
    /// * `reference_pattern`        — `let &x = ...`, `let &mut y = ...`,
    ///                                 also `let &Some(z) = ...` (recurses)
    /// * `or_pattern`               — `let Some(a) | None = ...` (recurses
    ///                                 into each alternative; the same
    ///                                 binding name appears in each)
    /// * `struct_pattern`           — `let Foo { field: x, y } = ...`
    ///   (handles both `field: binding` and shorthand `field`)
    /// * `_` (wildcard)             — produces no binding (intentional)
    ///
    /// Anything else falls through silently to preserve forward-compat
    /// with future tree-sitter-rust grammar updates.
    fn process_rust_let(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field contains the binding
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_rust_binding_identifiers(pattern);
        }

        // "value" field contains the initializer (a use)
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // let-else: `let Pat = expr else { diverge };` carries an `else`
        // block of arbitrary statements which may themselves declare or
        // use variables. tree-sitter exposes the block as an unnamed
        // child after the `else` keyword. Visit any block child(ren)
        // that follow the value to capture refs inside the divergence.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "block" {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Recursively descend a Rust binding pattern and register every
    /// bound identifier as `RefType::Definition`.
    ///
    /// Used by `process_rust_let` and `process_rust_for` to support the
    /// full set of pattern kinds that real Rust code uses (see
    /// `process_rust_let` doc for the matrix). The walker is a small
    /// hand-written recursive descent rather than a generic visitor
    /// because the binding/constructor distinction inside
    /// `tuple_struct_pattern` (first identifier is the constructor, not
    /// a binding) and the field-vs-binding split inside `struct_pattern`
    /// require kind-aware handling.
    fn extract_rust_binding_identifiers(&mut self, pattern: Node) {
        match pattern.kind() {
            "identifier" => {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
            "mut_pattern" => {
                // `let mut x = ...` — single inner identifier.
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        self.add_ref_from_node(child, RefType::Definition);
                        break;
                    } else if child.is_named() && child.kind() != "mutable_specifier" {
                        // Recurse into nested patterns (rare but valid).
                        self.extract_rust_binding_identifiers(child);
                        break;
                    }
                }
            }
            "tuple_pattern" => {
                // `let (a, b) = ...` — every named pattern child is a binding.
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "tuple_struct_pattern" => {
                // `let Some(c) = ...`, `let Ok(v) = ...`, `let Variant(a, b) = ...`.
                // tree-sitter shape: [identifier(ctor) | scoped_identifier(ctor),
                //                     (, <pattern>*, )].
                // The first named child is the constructor — NOT a binding —
                // every subsequent named pattern child is.
                let mut cursor = pattern.walk();
                let mut seen_ctor = false;
                for child in pattern.children(&mut cursor) {
                    if !child.is_named() {
                        continue;
                    }
                    if !seen_ctor {
                        seen_ctor = true;
                        // Constructor identifier is not a variable binding.
                        continue;
                    }
                    self.extract_rust_binding_identifiers(child);
                }
            }
            "reference_pattern" => {
                // `let &x = ...`, `let &mut y = ...`, `let &Some(z) = ...`.
                // Layout: [&, mutable_specifier?, <inner_pattern>].
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() && child.kind() != "mutable_specifier" {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "or_pattern" => {
                // `let Some(a) | None = ...` — each alternative is a pattern;
                // recurse into all of them. Rust requires every alternative
                // to bind the same identifiers, but emitting per-arm
                // definitions is harmless (the reaching-defs analyzer
                // deduplicates by name+line).
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.is_named() {
                        self.extract_rust_binding_identifiers(child);
                    }
                }
            }
            "struct_pattern" => {
                // `let Foo { field: x, y } = ...`.
                // Children: [type_identifier(or scoped), {, field_pattern*, }].
                // Each field_pattern is `[field_identifier, :, pattern]`
                // (with binding) or `[field_identifier]` (shorthand: the
                // field_identifier itself IS the binding name).
                let mut cursor = pattern.walk();
                for child in pattern.children(&mut cursor) {
                    if child.kind() == "field_pattern" {
                        let mut fcursor = child.walk();
                        let named_children: Vec<Node> =
                            child.children(&mut fcursor).filter(|c| c.is_named()).collect();
                        match named_children.len() {
                            0 => {}
                            1 => {
                                // Shorthand `{ y }` — the lone child is the
                                // field_identifier and also the binding.
                                let only = named_children[0];
                                if only.kind() == "field_identifier"
                                    || only.kind() == "identifier"
                                {
                                    self.add_ref_from_node(only, RefType::Definition);
                                }
                            }
                            _ => {
                                // `field: pattern` — the LAST named child is
                                // the binding pattern, the first is the
                                // field_identifier (which is NOT a binding).
                                let last = named_children[named_children.len() - 1];
                                self.extract_rust_binding_identifiers(last);
                            }
                        }
                    }
                }
            }
            // `_` wildcard, range_pattern, literal_pattern, etc. — no
            // identifier is bound, intentionally a no-op.
            _ => {}
        }
    }

    /// Process Rust for expression: for x in items { ... }
    /// AST: for_expression -> pattern, value, body
    ///
    /// rust-dataflow-v1: delegate the pattern walk to the shared
    /// `extract_rust_binding_identifiers` so `for &x in &items`,
    /// `for Some(c) in iter`, `for (k, v) in map`, etc. all register
    /// their bindings.
    fn process_rust_for(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field: loop variable(s)
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_rust_binding_identifiers(pattern);
        }

        // "value" field: the iterable (use)
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // "body" field: loop body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Go processing
    // =====================================================================

    /// Process Go short var declaration: x := ...
    /// AST: short_var_declaration -> left (expression_list), right (expression_list)
    fn process_go_short_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_go_lhs_identifiers(left)?;
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Process Go var declaration: var x int = 10
    /// AST: var_declaration -> var_spec (name, type, value)
    fn process_go_var_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "var_spec" {
                // "name" field contains identifier(s)
                if let Some(name) = child.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        self.add_ref_from_node(name, RefType::Definition);
                    }
                }
                // Also try iterating children for multiple names
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "identifier" {
                        // Check if this is before the type/value (it's a name)
                        let name_text = inner_child.utf8_text(self.source.as_bytes()).unwrap_or("");
                        if !name_text.is_empty() && !is_keyword(name_text, self.language) {
                            // Only add if not already added via field name
                            let already_added = self.refs.iter().any(|r| {
                                r.name == name_text
                                    && r.line == inner_child.start_position().row as u32 + 1
                                    && r.ref_type == RefType::Definition
                            });
                            if !already_added {
                                self.add_ref_from_node(inner_child, RefType::Definition);
                            }
                        }
                    }
                }
                // Process value for uses
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Process Go assignment statement: x = ...; x += ...
    fn process_go_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            // Check for operator: if it's += etc, it's an update
            let is_update = node.children(&mut node.walk()).any(|c| {
                let text = c.utf8_text(self.source.as_bytes()).unwrap_or("");
                text.ends_with('=') && text != "="
            });

            if is_update {
                // CL-13 (cl12_13_dfg_v1): Go op-assign (`x += 1`) reads the
                // prior value before writing it back. Record the implicit
                // `Use` of each bare-identifier target so the read is visible
                // to dead-store / reaching-defs analysis, then the `Update`.
                self.extract_go_lhs_identifiers_as(left, RefType::Use)?;
                self.extract_go_lhs_identifiers_as(left, RefType::Update)?;
            } else {
                self.extract_go_lhs_identifiers_as(left, RefType::Definition)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    /// Extract Go left-hand-side identifiers as definitions
    fn extract_go_lhs_identifiers(&mut self, node: Node) -> TldrResult<()> {
        self.extract_go_lhs_identifiers_as(node, RefType::Definition)
    }

    /// Extract Go left-hand-side identifiers with specified ref type
    ///
    /// fix-B4-dfg-coverage-v1 (v0.5.0 AUDIT-FIX, root cause 1): an element /
    /// field write LHS (`a[i+j] = ...`, `s.field = ...`) is NOT a bare
    /// identifier, so the pre-fix code — which only matched `identifier`
    /// children of the `expression_list` — silently dropped BOTH the container
    /// (which should be an Update) and every variable used inside the index
    /// (`i`, `j`). Such targets are routed to [`extract_assignment_targets`],
    /// whose `index_expression` / `selector_expression` arms record the
    /// container as an Update and walk the index subtree for uses. Bare
    /// identifiers keep the explicit `ref_type` (Definition / Use / Update)
    /// because a plain `x = ...` / `x += ...` carries the statement's own
    /// read/write semantics, which an element write does not.
    fn extract_go_lhs_identifiers_as(&mut self, node: Node, ref_type: RefType) -> TldrResult<()> {
        match node.kind() {
            "identifier" => {
                let name = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if name != "_" {
                    self.add_ref_from_node(node, ref_type);
                }
            }
            "expression_list" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.extract_go_lhs_identifiers_as(child, ref_type)?;
                }
            }
            // Element / field / map write target — container is an Update,
            // index vars are Uses. Delegate to the shared target extractor.
            "index_expression" | "selector_expression" => {
                self.extract_assignment_targets(node)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Process Go range clause: for i, v := range items { }
    fn process_go_range(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Range clause has "left" (expression_list with i, v) and "right" (iterable)
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_go_lhs_identifiers(left)?;
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // Java processing
    // =====================================================================

    /// Process Java local variable declaration: int x = ...;
    /// AST: local_variable_declaration -> type, declarator (variable_declarator)
    fn process_java_local_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    }
                }
                // "value" field is the initializer
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): process a Solidity
    /// local variable declaration statement.
    ///
    /// AST shape:
    /// ```text
    /// variable_declaration_statement
    ///   variable_declaration         -- [type] type_name, [name] identifier
    ///   '='                          -- optional (absent for `uint256 y;`)
    ///   [value] expression           -- optional RHS
    ///   ';'
    /// ```
    /// The `name` field of `variable_declaration` is the binding; emit it
    /// as `RefType::Definition`. The optional `[value]` field is the
    /// initializer — walk it for nested uses (calls, identifiers, ...).
    fn process_solidity_variable_declaration(
        &mut self,
        node: Node,
        depth: usize,
    ) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                if let Some(name) = child.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        self.add_ref_from_node(name, RefType::Definition);
                    }
                }
            }
        }
        // The initializer is in the `value` field on the OUTER
        // variable_declaration_statement, not on the inner declaration.
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }
        Ok(())
    }

    /// Process Java enhanced for: for (int item : items) { ... }
    /// AST: enhanced_for_statement -> type, name, value, body
    fn process_java_enhanced_for(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "name" field: loop variable
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // "value" field: the iterable
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }

        // "body" field: loop body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    // =====================================================================
    // C/C++ processing
    // =====================================================================

    /// Process C/C++ declaration: int x = ...; int x, y;
    /// AST: declaration -> type, declarator (init_declarator or identifier)
    fn process_c_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                // init_declarator has "declarator" and "value" fields
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if declarator.kind() == "identifier" {
                        self.add_ref_from_node(declarator, RefType::Definition);
                    } else if declarator.kind() == "pointer_declarator" {
                        // *x = ... -> find the identifier
                        let mut inner = declarator.walk();
                        for inner_child in declarator.children(&mut inner) {
                            if inner_child.kind() == "identifier" {
                                self.add_ref_from_node(inner_child, RefType::Definition);
                                break;
                            }
                        }
                    }
                }
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            } else if child.kind() == "identifier" {
                // Plain declaration without initializer: int x;
                let text = child.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !text.is_empty() && !is_keyword(text, self.language) {
                    self.add_ref_from_node(child, RefType::Definition);
                }
            }
        }

        Ok(())
    }

    // =====================================================================
    // PHP processing
    // =====================================================================

    /// Process PHP foreach: foreach ($arr as $key => $val) { }
    fn process_php_foreach(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Iterate children to find the loop variable(s)
        let mut cursor = node.walk();
        let mut found_as = false;
        for child in node.children(&mut cursor) {
            if child.kind() == "as" {
                found_as = true;
                continue;
            }
            if found_as && (child.kind() == "variable_name" || child.kind() == "pair") {
                if child.kind() == "variable_name" {
                    self.add_ref_from_node(child, RefType::Definition);
                } else {
                    // pair: $key => $val
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "variable_name" {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                        }
                    }
                }
                break;
            }
        }

        // Process body
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// T5 (v0.5.0 AUDIT-FIX, root cause A3): process a C#
    /// `foreach (T x in coll) { }` statement.
    ///
    /// tree-sitter-c-sharp shape:
    ///   foreach_statement
    ///     'foreach' '(' [type] [left] 'in' [right] ')' [body]
    /// `[left]` is the loop-variable binding (a Definition), `[right]` is the
    /// iterated collection (a Use), `[body]` is the loop body. C# also allows
    /// a deconstructing `foreach ((a, b) in pairs)` whose `[left]` is a
    /// `tuple_pattern`; descend through it to register each name. Mirrors
    /// `process_java_enhanced_for` (which keys off `[name]`/`[value]`).
    fn process_csharp_foreach(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_csharp_foreach_binding(left);
        }
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_refs_from_node(right, depth + 1)?;
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    /// Register the binding name(s) of a C# foreach `[left]` as definitions.
    /// Handles the simple `identifier` form and the deconstructing
    /// `tuple_pattern` / `declaration_expression` forms.
    fn extract_csharp_foreach_binding(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                self.add_ref_from_node(node, RefType::Definition);
            }
            _ => {
                // tuple_pattern / declaration_expression / parenthesized: the
                // bound names are the identifier leaves. Descend and register
                // each one (skip the element type identifiers, which appear as
                // a `[type]` field, never as a bare identifier leaf here).
                for child in node.children(&mut node.walk()) {
                    self.extract_csharp_foreach_binding(child);
                }
            }
        }
    }

    // =====================================================================
    // Scala processing
    // =====================================================================

    /// Process Scala val/var: val x = ...; var x = ...
    fn process_scala_val_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // "pattern" field contains the binding
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        }
        // Also try "name" field
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }

        // "value" or "body" field for the initializer
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_refs_from_node(value, depth + 1)?;
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }

        Ok(())
    }

    /// T5 (v0.5.0 AUDIT-FIX, root cause A6): process a Scala `case_clause`.
    ///
    /// Shape: `case_clause { case [pattern] <pat> (if [guard])? => [body] }`.
    /// The pattern binds variables (e.g. `e` in `Errored(e)`, `fa` in
    /// `Succeeded(fa)`) that the arm body reads. We register those bound
    /// identifiers as definitions, then analyze the optional guard and the
    /// body for uses.
    fn process_scala_case_clause(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_scala_pattern_bindings(pattern);
        }
        if let Some(guard) = node.child_by_field_name("guard") {
            self.extract_refs_from_node(guard, depth + 1)?;
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    /// Register the variables bound by a Scala pattern as definitions.
    ///
    /// Lower-case `identifier` leaves of a pattern are bound variables
    /// (`case Errored(e)` binds `e`). A `case_class_pattern`'s `[type]` field
    /// is a `type_identifier` (the extractor's `case_class_pattern` walk skips
    /// it because it is not a bare `identifier`), and upper-case identifier
    /// leaves are stable-identifier (constant) patterns, never bindings — so
    /// we only register lower-case identifiers. Nested patterns (tuples,
    /// nested case-class patterns, typed patterns, bindings via `@`) are
    /// handled by recursion.
    fn extract_scala_pattern_bindings(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                // Scala convention: a bound pattern variable is lower-case; an
                // upper-case identifier in pattern position is a stable
                // (constant) match, not a binding.
                if text
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                {
                    self.add_ref_from_node(node, RefType::Definition);
                }
            }
            // type_identifier is a type name in a constructor pattern; do not
            // descend (it carries no bindings).
            "type_identifier" => {}
            _ => {
                for child in node.children(&mut node.walk()) {
                    self.extract_scala_pattern_bindings(child);
                }
            }
        }
    }

    // =====================================================================
    // Elixir processing
    // =====================================================================

    /// Process Elixir match operator: x = ... (pattern matching)
    /// Handles both "match_operator" and "binary_operator" with "=" operator
    fn process_elixir_match(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Try field names first (match_operator uses "left"/"right")
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");

        if let Some(l) = left {
            if l.kind() == "identifier" {
                self.add_ref_from_node(l, RefType::Definition);
            }
        } else {
            // binary_operator: first named child is the LHS
            let mut cursor = node.walk();
            let named_children: Vec<_> = node
                .children(&mut cursor)
                .filter(|c| c.is_named())
                .collect();
            if named_children.len() >= 2 && named_children[0].kind() == "identifier" {
                self.add_ref_from_node(named_children[0], RefType::Definition);
            }
        }

        if let Some(r) = right {
            self.extract_refs_from_node(r, depth + 1)?;
        } else {
            // binary_operator: last named child is the RHS
            let mut cursor = node.walk();
            let named_children: Vec<_> = node
                .children(&mut cursor)
                .filter(|c| c.is_named())
                .collect();
            if named_children.len() >= 2 {
                self.extract_refs_from_node(*named_children.last().unwrap(), depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // Lua/Luau processing
    // =====================================================================

    /// Process Lua local declaration: local x = ...
    /// AST: variable_declaration -> local, assignment_statement -> variable_list -> identifier(s), = , expression_list
    /// Also handles simpler form: variable_declaration -> local, identifier(s)
    /// T5 (v0.5.0 AUDIT-FIX, root cause A5): process a Lua/Luau
    /// `for_statement`.
    ///
    /// Two shapes share the node kind:
    ///   * numeric — `for i = a, b, step do ... end`
    ///       for_statement [clause] for_numeric_clause { [name] identifier,
    ///         [start], [end], [step] } [body] block
    ///   * generic — `for k, v in iter do ... end`
    ///       for_statement [clause] for_generic_clause { variable_list (the
    ///         loop vars), expression_list (the iterators) } [body] block
    /// The loop variables are definitions; the bounds / iterators are uses;
    /// the body is analyzed normally.
    fn process_lua_for_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(clause) = node.child_by_field_name("clause") {
            match clause.kind() {
                "for_numeric_clause" => {
                    if let Some(name) = clause.child_by_field_name("name") {
                        if name.kind() == "identifier" {
                            self.add_ref_from_node(name, RefType::Definition);
                        }
                    }
                    // start / end / step are reads.
                    for field in ["start", "end", "step"] {
                        if let Some(bound) = clause.child_by_field_name(field) {
                            self.extract_refs_from_node(bound, depth + 1)?;
                        }
                    }
                }
                "for_generic_clause" => {
                    // variable_list -> loop-var definitions; expression_list ->
                    // iterator uses.
                    for child in clause.children(&mut clause.walk()) {
                        match child.kind() {
                            "variable_list" => {
                                for v in child.children(&mut child.walk()) {
                                    if v.kind() == "identifier" {
                                        self.add_ref_from_node(v, RefType::Definition);
                                    }
                                }
                            }
                            "expression_list" => {
                                self.extract_refs_from_node(child, depth + 1)?;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    fn process_lua_local_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                // Simple form: local x (no assignment)
                self.add_ref_from_node(child, RefType::Definition);
            } else if child.kind() == "assignment_statement" {
                // Full form: local y = x + 1
                // assignment_statement has variable_list and expression_list children
                self.process_lua_assignment_statement(child, depth)?;
            }
        }
        Ok(())
    }

    /// Process Lua assignment statement: x = expr or x, y = expr1, expr2
    /// AST: assignment_statement -> variable_list -> identifier(s), = , expression_list -> expression(s)
    fn process_lua_assignment_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_list" {
                // Extract all identifiers as definitions
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                    } else if inner_child.kind() == "dot_index_expression"
                        || inner_child.kind() == "bracket_index_expression"
                    {
                        // x.field = ... or x[i] = ... -> update
                        let mut deep = inner_child.walk();
                        for deep_child in inner_child.children(&mut deep) {
                            if deep_child.kind() == "identifier" {
                                self.add_ref_from_node(deep_child, RefType::Update);
                                break;
                            }
                        }
                    }
                }
            } else if child.kind() == "expression_list" {
                // Process the value expressions for uses
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Process a Lua/Luau compound-assignment ("update") statement:
    /// `x += expr`, `x *= expr`, `t.field -= expr`, …
    ///
    /// cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): tree-sitter-luau exposes the
    /// op-assign extension as a DISTINCT `update_statement` node (verified
    /// against tree-sitter-luau):
    /// ```text
    /// update_statement
    ///   variable_list
    ///     identifier | dot_index_expression | bracket_index_expression
    ///   += | -= | *= | /= | ^= | %= | ..=   (anonymous operator token)
    ///   expression_list
    ///     <expr…>
    /// ```
    ///
    /// Unlike a plain `assignment_statement`, a compound assignment BOTH reads
    /// the prior value of the target AND writes a new one. We mirror the CL-13
    /// op-assign treatment (`process_augmented_assignment`): emit the implicit
    /// `Use` first (it observes the value live at entry to this statement) and
    /// then the `Update` write-back, so the def reaching the op-assign is
    /// consumed and the target appears in backward slices of the result.
    fn process_lua_update_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_list" {
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    match inner_child.kind() {
                        "identifier" => {
                            // Implicit read then write-back of the scalar target.
                            self.add_ref_from_node(inner_child, RefType::Use);
                            self.add_ref_from_node(inner_child, RefType::Update);
                        }
                        "dot_index_expression" | "bracket_index_expression" => {
                            // `t.field += …` / `t[i] += …`: the base object is
                            // read and updated.
                            let mut deep = inner_child.walk();
                            for deep_child in inner_child.children(&mut deep) {
                                if deep_child.kind() == "identifier" {
                                    self.add_ref_from_node(deep_child, RefType::Use);
                                    self.add_ref_from_node(deep_child, RefType::Update);
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if child.kind() == "expression_list" {
                // The RHS contributes uses.
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    // =====================================================================
    // Kotlin processing
    // =====================================================================

    /// Process Kotlin property declaration: val x = ...; var x = ...
    /// AST: property_declaration -> (val/var) variable_declaration (identifier) = expression
    fn process_kotlin_property(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Find the variable_declaration child which contains the identifier.
        //
        // m114-adapter-tail-v1 (v0.4.2 M-114): also handle destructuring
        // declarations of the form `val (a, b) = pair`. tree-sitter-kotlin
        // emits this as `property_declaration > multi_variable_declaration >
        // variable_declaration[]` — one `variable_declaration` per name.
        // The pre-fix path only recognised a direct `variable_declaration`
        // child, so the destructured names never got a def-site and
        // reaching-defs reported them as uninitialised.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "variable_declaration" => {
                    // variable_declaration has an identifier child
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "identifier" {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                            break;
                        }
                    }
                }
                "multi_variable_declaration" => {
                    // Destructuring: emit one def-site per name.
                    let mut multi = child.walk();
                    for vd in child.children(&mut multi) {
                        if vd.kind() == "variable_declaration" {
                            let mut id_cursor = vd.walk();
                            for id_child in vd.children(&mut id_cursor) {
                                if id_child.kind() == "identifier" {
                                    self.add_ref_from_node(id_child, RefType::Definition);
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Process the value expression (after "=")
        // The value is typically the last named child after "="
        let mut cursor2 = node.walk();
        let mut found_eq = false;
        for child in node.children(&mut cursor2) {
            if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "=" {
                found_eq = true;
                continue;
            }
            if found_eq && child.is_named() {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    // =====================================================================
    // Swift processing
    // =====================================================================

    /// Process Swift property declaration: let y = ...; var z = ...
    /// AST: property_declaration -> value_binding_pattern (let/var), pattern -> simple_identifier, =, expression
    /// Also handles: property_declaration -> value_binding_pattern, typed_pattern -> pattern -> simple_identifier, type_annotation
    fn process_swift_property(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // Find the variable name: look for pattern -> simple_identifier or simple_identifier
        let mut cursor = node.walk();
        let mut found_name = false;
        let mut found_eq = false;

        for child in node.children(&mut cursor) {
            match child.kind() {
                "pattern" => {
                    // pattern -> simple_identifier
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "simple_identifier" {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                            found_name = true;
                            break;
                        }
                    }
                }
                "typed_pattern" => {
                    // typed_pattern -> pattern -> simple_identifier, type_annotation
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "pattern" {
                            let mut deep = inner_child.walk();
                            for deep_child in inner_child.children(&mut deep) {
                                if deep_child.kind() == "simple_identifier" {
                                    self.add_ref_from_node(deep_child, RefType::Definition);
                                    found_name = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                "simple_identifier" if !found_name => {
                    // Direct simple_identifier child
                    self.add_ref_from_node(child, RefType::Definition);
                    found_name = true;
                }
                _ => {
                    if !child.is_named()
                        && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                    {
                        found_eq = true;
                        continue;
                    }
                    if found_eq && child.is_named() {
                        // Process the value expression for uses
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process Swift assignment: z = z + 1
    /// AST: assignment -> directly_assignable_expression -> simple_identifier, =, expression
    fn process_swift_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        let mut found_eq = false;
        let mut processed_target = false;

        for child in node.children(&mut cursor) {
            if child.kind() == "directly_assignable_expression" {
                // Find simple_identifier inside directly_assignable_expression
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "simple_identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                        processed_target = true;
                        break;
                    }
                }
                // If no simple_identifier found, it could be a navigation_expression (member access)
                if !processed_target {
                    let mut inner2 = child.walk();
                    for inner_child in child.children(&mut inner2) {
                        if inner_child.kind() == "navigation_expression" {
                            // obj.field = ... -> obj is an Update
                            let mut deep = inner_child.walk();
                            for deep_child in inner_child.children(&mut deep) {
                                if deep_child.kind() == "simple_identifier" {
                                    self.add_ref_from_node(deep_child, RefType::Update);
                                    break;
                                }
                            }
                            processed_target = true;
                            break;
                        }
                    }
                }
            } else if !child.is_named()
                && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
            {
                found_eq = true;
            } else if found_eq && child.is_named() {
                // Process the value expression for uses
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Extract Swift function parameters as definitions
    /// Swift: function_declaration -> ... parameter (simple_identifier "x", :, user_type) ...
    /// Parameters are direct children of the function_declaration node.
    fn extract_swift_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "parameter" {
                // Find the first simple_identifier inside the parameter (the name)
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "simple_identifier" {
                        self.add_ref_from_node(inner_child, RefType::Definition);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    // =====================================================================
    // Elixir parameter extraction
    // =====================================================================

    /// Extract Elixir function parameters as definitions.
    ///
    /// Two AST shapes are recognized:
    ///
    /// 1. No guard:
    ///    `(call (identifier "def") (arguments (call (identifier "foo") (arguments (identifier "x")))))`
    /// 2. With guard (`def foo(x) when is_atom(x)`):
    ///    `(call (identifier "def")
    ///           (arguments (binary_operator
    ///                          left:  (call (identifier "foo") (arguments (identifier "x")))
    ///                          op:    "when"
    ///                          right: (guard expr))
    ///                      (do_block ...)))`
    ///
    /// Without recognizing the `binary_operator` wrapper (P11.BUG-AGG-16),
    /// guarded functions had their parameters silently dropped from the
    /// DFG which made `reaching-defs`/`slice`/`taint` unable to resolve them.
    fn extract_elixir_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        if func_node.kind() != "call" {
            return Ok(());
        }

        // Find the inner call with the function name and its arguments
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "arguments" {
                // Inside arguments, look for a call node (function name + params).
                // For guarded functions, descend through binary_operator first.
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "call" {
                        self.extract_elixir_param_idents_from_call(inner_child);
                    } else if inner_child.kind() == "binary_operator" {
                        // Guard clause `LHS when RHS`: function signature lives
                        // on the left of the binary_operator.
                        let mut bin = inner_child.walk();
                        for bin_child in inner_child.children(&mut bin) {
                            if bin_child.kind() == "call" {
                                self.extract_elixir_param_idents_from_call(bin_child);
                                // The function-call form is the LHS; the RHS
                                // is the guard expression itself, which is
                                // not a parameter source.
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Helper: given an Elixir `call` node representing the function head
    /// (`foo(x, y)`), extract each `arguments`-level identifier as a
    /// parameter definition.
    fn extract_elixir_param_idents_from_call(&mut self, call_node: Node) {
        if let Some(args) = call_node.child(1) {
            if args.kind() == "arguments" {
                let mut args_cursor = args.walk();
                for arg in args.children(&mut args_cursor) {
                    if arg.kind() == "identifier" {
                        self.add_ref_from_node(arg, RefType::Definition);
                    }
                }
            }
        }
    }

    // =====================================================================
    // OCaml processing
    // =====================================================================

    /// Extract OCaml function parameters as definitions
    /// OCaml: (let_binding (value_name "foo") (parameter (value_pattern "x")) body: ...)
    fn extract_ocaml_parameters(&mut self, func_node: Node) -> TldrResult<()> {
        // For value_definition, drill into let_binding
        let binding = if func_node.kind() == "value_definition" {
            let mut cursor = func_node.walk();
            let mut found = None;
            for child in func_node.children(&mut cursor) {
                if child.kind() == "let_binding" {
                    found = Some(child);
                    break;
                }
            }
            found
        } else if func_node.kind() == "let_binding" {
            Some(func_node)
        } else {
            None
        };

        if let Some(binding) = binding {
            let mut cursor = binding.walk();
            for child in binding.children(&mut cursor) {
                if child.kind() == "parameter" {
                    // parameter contains value_pattern with the param name
                    let mut inner = child.walk();
                    for inner_child in child.children(&mut inner) {
                        if inner_child.kind() == "value_pattern"
                            || inner_child.kind() == "value_name"
                            || inner_child.kind() == "identifier"
                        {
                            self.add_ref_from_node(inner_child, RefType::Definition);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process OCaml let_expression: let x = expr in body
    /// AST: (let_expression (value_definition (let_binding ...)) "in" body)
    fn process_ocaml_let_expression(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_refs_from_node(child, depth + 1)?;
        }
        Ok(())
    }

    /// Process OCaml value_definition: let binding(s)
    fn process_ocaml_value_definition(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "let_binding" {
                self.process_ocaml_let_binding(child, depth)?;
            }
        }
        Ok(())
    }

    /// Process OCaml let_binding: pattern = expression
    /// AST: (let_binding (value_name "y") = (expression))
    fn process_ocaml_let_binding(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // The pattern/name is the first value_name child
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if pattern.kind() == "value_name" || pattern.kind() == "identifier" {
                self.add_ref_from_node(pattern, RefType::Definition);
            }
        } else {
            // Fallback: find first value_name child (before "=")
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "value_name" {
                    self.add_ref_from_node(child, RefType::Definition);
                    break;
                }
                if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                {
                    break; // Stop before the RHS
                }
            }
        }

        // Process the body/value for uses
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        } else {
            // Fallback: process children after "=" for uses
            let mut cursor = node.walk();
            let mut found_eq = false;
            for child in node.children(&mut cursor) {
                if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                {
                    found_eq = true;
                    continue;
                }
                if found_eq && child.is_named() {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    /// Check if an OCaml value_name is in a use context
    fn is_ocaml_use_context(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                // Not a use if we're the pattern in a let_binding
                "let_binding" => {
                    if let Some(pattern) = parent.child_by_field_name("pattern") {
                        if self.node_contains(pattern, node) {
                            return false;
                        }
                    }
                    // Also check: first value_name before "=" is a definition
                    let mut cursor = parent.walk();
                    for child in parent.children(&mut cursor) {
                        if child.kind() == "value_name" && child.id() == node.id() {
                            return false; // This is the binding name
                        }
                        if !child.is_named()
                            && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                        {
                            break;
                        }
                    }
                }
                // Not a use if we're a parameter
                "parameter" => {
                    return false;
                }
                "value_definition" => {
                    return false; // Will be handled by value_definition processor
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Module-qualified value access `Io.read_file` is parsed
                // as `value_path` -> `module_path` + `value_name`. The
                // `value_name` is a name-segment of a path, not a local
                // variable reference. Without this rule, the audit on
                // `ocaml-dune/.../run_expect_test` flagged `read_file`,
                // `async`, `unlink_no_err`, `to_string`, etc. as
                // definite-uninitialized.
                //
                // We treat ANY `value_name` whose parent is `value_path`
                // as not-a-use — even an unqualified `value_path`
                // wrapping a single `value_name`. Bare unqualified
                // value references in OCaml that have no in-function
                // definition are typically top-level let bindings,
                // module-included values, or std-library functions —
                // none of which is a local-variable use in the
                // reaching-defs sense. (Function arguments and let-
                // bound names still carry their definitions, which
                // populate the reaching-defs report normally.)
                //
                // T5 (v0.5.0 AUDIT-FIX, root cause B3): EXCEPT an UNQUALIFIED
                // `value_path` (no `module_path` segment) whose name is a
                // local binding of the analyzed function — e.g. the recursive
                // references to `inner` in `let rec inner ... in inner [] l`.
                // The blanket rule dropped those uses, so the `inner` binding
                // looked like a dead store. A module-qualified path
                // (`List.rev` -> has a `module_path` child) stays not-a-use.
                "value_path" => {
                    let is_qualified = parent
                        .children(&mut parent.walk())
                        .any(|c| c.kind() == "module_path");
                    if !is_qualified {
                        let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                        if !text.is_empty() && self.ocaml_local_names.contains(text) {
                            return true;
                        }
                    }
                    return false;
                }
                // Field-of-record access `r.f`: `f` is on the RHS of
                // `field_get_expression` and is a record-field name,
                // never a local variable use.
                "field_get_expression" => {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if self.node_contains(field, node) {
                            return false;
                        }
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// Check if a Swift simple_identifier is in a use context (not assignment target)
    fn is_swift_use_context(&self, node: Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                // Not a use if we're a definition target inside property_declaration
                "pattern" => {
                    // pattern is inside property_declaration -> this is a definition
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "property_declaration"
                            || grandparent.kind() == "typed_pattern"
                        {
                            return false;
                        }
                    }
                }
                "property_declaration" => {
                    return false; // Handled by process_swift_property
                }
                // Not a use if we're the target of an assignment
                "directly_assignable_expression" => {
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "assignment" {
                            return false; // Handled by process_swift_assignment
                        }
                    }
                }
                // Not a use if we're a parameter name
                "parameter" => {
                    return false;
                }
                // Not a use if we're in a function declaration name position
                "function_declaration" => {
                    return false;
                }
                // Not a use if it's a type annotation (like Int)
                "type_identifier" | "user_type" | "type_annotation" => {
                    return false;
                }
                // Navigation expression (member access): foo.bar -> foo is a use, bar is not
                "navigation_expression" => {
                    // The suffix (after .) is not a use - only the target object is
                    if let Some(suffix) = parent.child_by_field_name("suffix") {
                        if suffix.id() == node.id() {
                            return false;
                        }
                    }
                    // Check if this is the last simple_identifier (method/field name)
                    let mut cursor = parent.walk();
                    let children: Vec<_> = parent
                        .children(&mut cursor)
                        .filter(|c| c.kind() == "simple_identifier")
                        .collect();
                    if children.len() >= 2 {
                        if let Some(last) = children.last() {
                            if last.id() == node.id() {
                                return false; // This is the field/method name, not a use
                            }
                        }
                    }
                }
                // Value binding pattern (let/var keyword) - not relevant
                "value_binding_pattern" => {
                    return false;
                }
                _ => {}
            }
        }
        // Also check grandparent for nested cases
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                // typed_pattern -> pattern -> simple_identifier (this is a definition)
                if parent.kind() == "pattern" && grandparent.kind() == "typed_pattern" {
                    return false;
                }
            }
        }
        true
    }

    /// Check if an identifier is in a "use" context (not assignment target)
    ///
    /// Multi-language: checks parent node kinds for all supported languages
    /// to determine if this identifier is a target of assignment/declaration
    /// (and therefore NOT a use).
    fn is_use_context(&self, node: Node) -> bool {
        // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala method/field
        // names on the rhs of `field_expression` (`Tracing.calculateTracingEvent`
        // -> `calculateTracingEvent`) are member references, not local
        // variable uses. They have no defining write in the function body
        // and would otherwise be flagged as definite-uninitialized.
        if matches!(self.language, Language::Scala) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "field_expression" {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Method name in `obj.method(args)` / `method(args)` —
                // call_expression's `function` field is the callee. When
                // that callee is a bare identifier (no dot), it's a
                // free-function or local-method invocation; treat the
                // callee identifier as not-a-variable-use to avoid
                // flagging compile-time-resolved methods like
                // `calculateTracingEvent` (or local DSL helpers) as
                // uninitialized.
                if parent.kind() == "call_expression" {
                    if let Some(func_field) = parent.child_by_field_name("function") {
                        if func_field.id() == node.id() {
                            return false;
                        }
                    }
                }
            }
        }
        // AGG13-15 (quality-metrics-and-schema-v1): Java/C# method-name
        // and imported-type identifiers are NOT variable uses. The
        // pre-fix output flagged `PageRequest`, `Sort`, `of`,
        // `findByLastNameStartingWith` (in `PageRequest.of(...)` and
        // `owners.findByLastNameStartingWith(...)`) as `uninitialized`
        // variables with `severity: definite`. Classify these out of
        // the use-context set so they never enter the reaching-defs
        // analyzer in the first place.
        if matches!(self.language, Language::Java | Language::CSharp) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                // Method name: `obj.method()` -> `method` is the `name`
                // field of `method_invocation` / `invocation_expression`.
                // It is never a variable reference.
                if matches!(pkind, "method_invocation" | "invocation_expression") {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // C# `member_access_expression` and Java `field_access`
                // member name. `BsonReaderState.Normal` -> `Normal` is
                // the `name` field. It's an enum-member / type-member /
                // method-group reference, never a local variable use.
                // (The receiver suppression below already handles the
                // `BsonReaderState` half via imported_type_names; the
                // `Normal` half stays flagged without this rule.)
                if matches!(pkind, "member_access_expression" | "field_access") {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // T5 (v0.5.0 AUDIT-FIX, root cause A2): the `[type]` of a
                // `new Foo(...)` / `new Foo[...]` expression is a type name,
                // never a local variable. `throw new
                // ArgumentOutOfRangeException(...)` flagged
                // `ArgumentOutOfRangeException` as `definite` uninitialized.
                // (C# `object_creation_expression` / `array_creation_expression`
                // expose the constructed type in the `[type]` field; Java uses
                // `object_creation_expression` too.)
                if matches!(
                    pkind,
                    "object_creation_expression" | "array_creation_expression"
                ) {
                    if let Some(type_field) = parent.child_by_field_name("type") {
                        if self.node_contains(type_field, node) {
                            return false;
                        }
                    }
                }
                // Field-access receiver / method-invocation receiver
                // matching an imported type name: `PageRequest.of(...)`,
                // `Sort.by(...)`. The text of the identifier matches a
                // simple name we collected from the file's
                // `import_declaration` list.
                if matches!(
                    pkind,
                    "method_invocation"
                        | "invocation_expression"
                        | "field_access"
                        | "member_access_expression"
                ) {
                    let object_field = parent
                        .child_by_field_name("object")
                        .or_else(|| parent.child_by_field_name("expression"));
                    if let Some(obj) = object_field {
                        if obj.id() == node.id() {
                            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                            if !text.is_empty() && self.imported_type_names.contains(text) {
                                return false;
                            }
                            // T5 (v0.5.0 AUDIT-FIX, root cause A2): a C#
                            // member-access / invocation RECEIVER whose name
                            // begins with an uppercase letter is, by .NET
                            // naming convention, a type / enum / namespace
                            // reference resolved from another compilation unit
                            // — never a local variable (locals and parameters
                            // are camelCase). `BsonType.Object`,
                            // `Convert.ToInt32(...)`, `CultureInfo.X`,
                            // `MathUtils.IntLength(...)` were all flagged
                            // `definite` uninitialized because they are not in
                            // any same-file import/field set. A local that
                            // shadows such a name would itself appear as a
                            // Definition (its declaration), so suppressing the
                            // receiver here cannot hide a genuine local read:
                            // the only identifiers reaching this branch with an
                            // uppercase initial AND no recorded definition are
                            // external type references. Scoped to C# to
                            // preserve Java behavior exactly.
                            if matches!(self.language, Language::CSharp)
                                && text
                                    .chars()
                                    .next()
                                    .is_some_and(|c| c.is_ascii_uppercase())
                            {
                                return false;
                            }
                        }
                    }
                }
                // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
                // Bare-identifier callee: `ReadNormalAsync(token)` ->
                // the `function` field of `invocation_expression` is a
                // bare identifier matching a same-file method
                // declaration name. When collect_imports has registered
                // the method name, the receiver-less call is a known
                // method reference, not a local variable use.
                if matches!(pkind, "method_invocation" | "invocation_expression") {
                    if let Some(func_field) = parent.child_by_field_name("function") {
                        if func_field.id() == node.id() {
                            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                            if !text.is_empty() && self.imported_type_names.contains(text) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // TypeScript / JavaScript classification rules:
        //   1. `obj.property` -> `property` (the `property` field of
        //      `member_expression`) is a member reference, not a use.
        //      This catches `Array.isArray`, `util.compute`, `Ns.frob`,
        //      `obj.method` etc. — none of which are local-variable uses.
        //   2. Receiver/callee/constructor/type-annotation suppression
        //      when the identifier matches an import / hoisted-function
        //      / built-in global (collected at file level by
        //      `collect_imports`). Position-independent so type-
        //      annotation positions (`x: Browser.Interface`) are
        //      classified as not-a-use without needing a separate per-
        //      parent rule for every TS type-position node.
        if matches!(self.language, Language::TypeScript | Language::JavaScript) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                if pkind == "member_expression" {
                    if let Some(prop) = parent.child_by_field_name("property") {
                        if prop.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Shorthand property in an object: `{ engines: engines }`
                // — only the value (right) is a use, not the key (left).
                if pkind == "pair" {
                    if let Some(key) = parent.child_by_field_name("key") {
                        if key.id() == node.id() {
                            return false;
                        }
                    }
                }
            }
            // Position-independent suppression: if the bare identifier
            // matches a file-level import / hoisted function decl /
            // built-in global, it is never a local-variable use.
            // (Locals shadowing imports are still added as defs via
            // their own declaration node, so the shadowed use is not
            // missed — the def line will simply equal the use line for
            // single-statement locals, which the reaching-defs analyzer
            // handles correctly.)
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            // T5 (v0.5.0 AUDIT-FIX, root cause B1): never suppress an
            // identifier that has a genuine `const`/`let`/`var` declaration in
            // the analyzed function. `collect_imports` adds nested-helper
            // PARAMETER names to `imported_type_names`; a sibling helper's
            // param (axios `mergeDeepProperties(a, b)`) can collide with a
            // real local (`const a`/`const b` in the `computeConfigValue`
            // callback), and the suppression below would otherwise drop every
            // read of that local — making its store look dead. Member-name
            // positions (`obj.a`) were already classified not-a-use earlier in
            // this block, so the surviving identifiers are value reads.
            if !text.is_empty()
                && self.imported_type_names.contains(text)
                && !self.ts_js_local_names.contains(text)
            {
                return false;
            }
        }

        // reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
        // Lua / Luau classification rules:
        //   1. `m.field` -> `field` (the `field` field of
        //      `dot_index_expression`) is a table-member reference,
        //      not a use. This catches `m.onWatch`, `T.querytab`.
        //   2. `{ key = value }` -> `key` (the `name` field of `field`
        //      inside `table_constructor`) is a string key, not a use.
        //      Catches `cache = {}` in `m.openMap = { cache = {} }`.
        //   3. Receiver suppression when receiver matches a file-level
        //      local / built-in global.
        if matches!(self.language, Language::Lua | Language::Luau) {
            if let Some(parent) = node.parent() {
                let pkind = parent.kind();
                if pkind == "dot_index_expression" {
                    if let Some(field) = parent.child_by_field_name("field") {
                        if field.id() == node.id() {
                            return false;
                        }
                    }
                }
                if pkind == "field" {
                    if let Some(name_field) = parent.child_by_field_name("name") {
                        if name_field.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Method invocation `m:method(...)`: `method` is on the
                // RHS of `method_index_expression`. Suppress.
                if pkind == "method_index_expression" {
                    if let Some(method) = parent.child_by_field_name("method") {
                        if method.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Identifier matches a file-level local or global —
                // suppress it as a not-a-use entirely. This handles
                // module-table receivers (`m` in `m.open`) and globals
                // like `print` / `assert`.
                let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !text.is_empty() && self.imported_type_names.contains(text) {
                    return false;
                }
                // T5 (v0.5.0 AUDIT-FIX, root cause A4): a module-table
                // receiver whose name begins with an uppercase letter
                // (`Config.builtins`, `Globals.x`, `Config:method()`) is an
                // implicit module-level global in Lua, defined in another
                // module / earlier file scope — never a function-local. Such
                // receivers were flagged `definite` uninitialized because they
                // are not in the file-level `imported_type_names` set. Suppress
                // the receiver position of a dot/method/bracket index when its
                // name is uppercase-initial (the LSP-server convention for
                // shared config tables). A genuine uppercase local would carry
                // its own Definition from its `local`/assignment site.
                if matches!(
                    pkind,
                    "dot_index_expression"
                        | "method_index_expression"
                        | "bracket_index_expression"
                ) && text.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                {
                    let recv = parent
                        .child_by_field_name("table")
                        .or_else(|| parent.child_by_field_name("object"));
                    if let Some(recv) = recv {
                        if recv.id() == node.id() {
                            return false;
                        }
                    }
                }
                // Suppress identifiers whose grandparent is a variable
                // node (lua `variable` wraps `identifier`) only when the
                // node was already filtered above. We don't need extra
                // handling here.
                let _ = pkind;
            }
        }

        // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): Ruby classification.
        //   1. `recv.method(args)` / `recv.method` -> the `method` field of a
        //      `call` node is a method name, NEVER a local-variable use. This
        //      removes the false `inspect`, `join`, `supported?`,
        //      `rubocop_version_with_support`, `supported_versions` reads.
        //   2. `raise X, msg` parses as a `call` whose `method` field is the
        //      bare `raise` identifier with an `arguments` list — same rule
        //      covers it (and any other command call with arguments).
        //   3. A receiver-less, argument-less bare `identifier` is a local
        //      read ONLY when a local of that name exists in the method
        //      (collected in `ruby_local_names`); otherwise it is a zero-arg
        //      method call (`target_ruby`, `target_ruby_version`) and must not
        //      be classified as a use.
        if matches!(self.language, Language::Ruby) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "call" {
                    // The method name of a call is never a variable use.
                    if let Some(method) = parent.child_by_field_name("method") {
                        if method.id() == node.id() {
                            return false;
                        }
                    }
                    // The receiver of `recv.method` IS a use (fall through).
                }
            }
            // Receiver-less, argument-less bare identifier: a use only if a
            // local of that name was actually declared in this method.
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if !text.is_empty() && !self.ruby_local_names.contains(text) {
                // Not a known local. It could still be a hash key / symbol /
                // call method (already handled above) — but as a bare read it
                // is a zero-arg method call. Suppress.
                if let Some(parent) = node.parent() {
                    // Only suppress when this identifier is a standalone read,
                    // i.e. its parent is not an assignment target context. The
                    // generic classifier below already rejects LHS positions,
                    // so suppressing here is safe for reads.
                    let pkind = parent.kind();
                    // Do not suppress when the identifier is itself the LHS of
                    // an assignment/operator-assignment (it would be a DEF, not
                    // reached here as a use anyway) — guard defensively.
                    let is_lhs = matches!(pkind, "assignment" | "operator_assignment")
                        && parent
                            .child_by_field_name("left")
                            .map(|l| l.id() == node.id())
                            .unwrap_or(false);
                    if !is_lhs {
                        return false;
                    }
                }
            }
        }

        // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): Solidity classification.
        // The grammar wraps every operand in a named `expression` node, so
        // standard use-context heuristics that test `parent.kind()`
        // against `assignment_expression` / `variable_declaration` /
        // `member_expression` would see only the wrapper and classify
        // every identifier as a use. Walk through the wrapper to find
        // the actual semantic parent, then suppress in the LHS / member
        // / callee / type-position cases.
        if matches!(self.language, Language::Solidity) {
            if let Some(is_use) = self.solidity_use_context(node) {
                return is_use;
            }
        }

        if let Some(parent) = node.parent() {
            if let Some(is_use) = self.parent_use_context(parent, node) {
                return is_use;
            }
        }
        if let Some(is_use) = self.expression_list_grandparent_use_context(node) {
            return is_use;
        }
        true
    }

    /// solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): centralised use-context
    /// classifier for Solidity identifiers.
    ///
    /// Returns:
    ///   * `Some(false)` — identifier is NOT a use (LHS of assignment,
    ///     member property, callee, type position, variable_declaration
    ///     name, parameter name).
    ///   * `Some(true)`  — identifier IS a use (RHS / inside expression
    ///     context that explicitly classifies as a read).
    ///   * `None`        — no Solidity-specific decision; fall through
    ///     to the generic classifier.
    fn solidity_use_context(&self, node: Node) -> Option<bool> {
        let parent = node.parent()?;
        let pkind = parent.kind();

        // member_expression: `obj.field` — `[object]` is a use, `[property]`
        // is a static field-access name and never a local variable use.
        if pkind == "member_expression" {
            if let Some(prop) = parent.child_by_field_name("property") {
                if prop.id() == node.id() {
                    return Some(false);
                }
            }
            // `[object] identifier` — the receiver IS a use.
            return None;
        }

        // variable_declaration: `[name] identifier` — Definition, not Use.
        if pkind == "variable_declaration" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        // parameter: `[name] identifier` — Definition, not Use.
        if pkind == "parameter" || pkind == "event_parameter"
            || pkind == "error_parameter"
        {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        // function_definition / modifier_definition: `[name] identifier`
        // — declaration name, never a local use.
        if matches!(
            pkind,
            "function_definition"
                | "modifier_definition"
                | "constructor_definition"
                | "event_definition"
                | "error_declaration"
                | "contract_declaration"
                | "interface_declaration"
                | "library_declaration"
                | "struct_declaration"
                | "enum_declaration"
        ) {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        // type_name / user_defined_type / primitive_type: identifiers
        // here are type references, not variable uses.
        if matches!(
            pkind,
            "type_name" | "user_defined_type" | "primitive_type"
        ) {
            return Some(false);
        }

        // The grammar wraps every operand in `expression`. Look at the
        // grandparent to learn the SEMANTIC context of this identifier.
        if pkind == "expression" {
            let grand = parent.parent()?;
            let gkind = grand.kind();

            // assignment_expression: `[left] expression > identifier` is
            // the assignment target — Definition, not Use. `[right]` is a
            // Use (None → fall through).
            if gkind == "assignment_expression"
                || gkind == "augmented_assignment_expression"
            {
                if let Some(left) = grand.child_by_field_name("left") {
                    if left.id() == parent.id() {
                        return Some(false);
                    }
                }
            }

            // update_expression: `[argument] expression > identifier` is
            // the operand — handled by the update_expression arm itself
            // (it emits an Update). Suppress here so we don't also emit
            // a duplicate Use.
            if gkind == "update_expression" {
                if let Some(arg) = grand.child_by_field_name("argument") {
                    if arg.id() == parent.id() {
                        return Some(false);
                    }
                }
            }

            // member_expression as grandparent: `[object] expression >
            // identifier` is a USE (receiver). `[property]` was handled
            // above (its grandparent is also `member_expression` but
            // through `[property] identifier` directly, not via
            // `expression`).
            if gkind == "member_expression" {
                // object is a use — leave decision to fallthrough (None).
                if let Some(obj) = grand.child_by_field_name("object") {
                    if obj.id() == parent.id() {
                        return None;
                    }
                }
            }

            // emit_statement: `[name] expression > identifier` is the
            // event name — not a local variable use.
            if gkind == "emit_statement" {
                if let Some(name) = grand.child_by_field_name("name") {
                    if name.id() == parent.id() {
                        return Some(false);
                    }
                }
            }

            // CL-12 (cl12_13_dfg_v1): revert_statement
            // `revert MyError(args)` parses as
            //   revert_statement
            //     revert
            //     [error] expression > identifier   <- the custom-error name
            //     revert_arguments ( ... )          <- args (real uses)
            // The `[error]` identifier names a custom error type, not a
            // local variable, so it must never be classified as a use (it
            // has no defining write in the function body and was being
            // reported as definite-uninitialized). The `revert_arguments`
            // operands fall through to normal use classification.
            if gkind == "revert_statement" {
                if let Some(err) = grand.child_by_field_name("error") {
                    if err.id() == parent.id() {
                        return Some(false);
                    }
                }
            }

            // call_expression: `[function] expression > identifier` is
            // the callee name. For Solidity, bare callees are typically
            // free functions, contract methods, or builtins (keccak256,
            // require, etc.) — none are local variable uses.
            if gkind == "call_expression" {
                if let Some(func) = grand.child_by_field_name("function") {
                    if func.id() == parent.id() {
                        return Some(false);
                    }
                }
            }

            // array_access: `[base] expression > identifier` IS a use
            // (the storage location being read or the storage target on
            // LHS — both register reads of the base name). `[index]` is
            // also a use. Fall through.
            if gkind == "array_access" {
                return None;
            }
        }

        None
    }

    fn parent_use_context(&self, parent: Node, node: Node) -> Option<bool> {
        let kind = parent.kind();

        if matches!(
            kind,
            "assignment" | "for_statement" | "for_in_statement" | "augmented_assignment"
        ) {
            return self
                .left_field_contains(parent, node)
                .map(|contains| !contains);
        }
        if matches!(
            kind,
            "parameters"
                | "parameter"
                | "typed_parameter"
                | "default_parameter"
                | "formal_parameters"
                | "required_parameter"
                | "optional_parameter"
                | "parameter_declaration"
                | "formal_parameter"
                | "function_value_parameters"
        ) {
            return Some(false);
        }
        if matches!(self.language, Language::Kotlin)
            && matches!(kind, "property_declaration" | "variable_declaration")
        {
            return Some(false);
        }

        if kind == "variable_declarator" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }
        if matches!(kind, "lexical_declaration" | "variable_declaration")
            && !matches!(self.language, Language::Lua | Language::Luau)
        {
            return Some(false);
        }
        if matches!(
            kind,
            "assignment_expression" | "augmented_assignment_expression"
        ) {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if kind == "let_declaration" || kind == "for_expression" {
            if let Some(pattern) = parent.child_by_field_name("pattern") {
                if self.node_contains(pattern, node) {
                    return Some(false);
                }
            }
        }
        if kind == "mut_pattern" {
            return Some(false);
        }

        if matches!(
            kind,
            "short_var_declaration" | "assignment_statement" | "range_clause"
        ) {
            if let Some(left) = parent.child_by_field_name("left") {
                if self.node_contains(left, node) {
                    return Some(false);
                }
            }
        }
        if kind == "var_spec" {
            if let Some(name) = parent.child_by_field_name("name") {
                if self.node_contains(name, node) {
                    return Some(false);
                }
            }
        }

        if kind == "local_variable_declaration" {
            return Some(false);
        }
        if kind == "enhanced_for_statement" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if kind == "declaration" && matches!(self.language, Language::C | Language::Cpp) {
            return Some(false);
        }
        if kind == "init_declarator" {
            if let Some(declarator) = parent.child_by_field_name("declarator") {
                if self.node_contains(declarator, node) {
                    return Some(false);
                }
            }
        }

        if kind == "operator_assignment" {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.id() == node.id() {
                    return Some(false);
                }
            }
        }

        if matches!(kind, "val_definition" | "var_definition") {
            if let Some(pattern) = parent.child_by_field_name("pattern") {
                if self.node_contains(pattern, node) {
                    return Some(false);
                }
            }
            if let Some(name) = parent.child_by_field_name("name") {
                if self.node_contains(name, node) {
                    return Some(false);
                }
            }
        }

        if matches!(self.language, Language::Elixir) && kind == "match_operator" {
            if let Some(left) = parent.child_by_field_name("left") {
                if self.node_contains(left, node) {
                    return Some(false);
                }
            }
        }
        if matches!(self.language, Language::Elixir)
            && kind == "binary_operator"
            && self.is_elixir_match_lhs(parent, node)
        {
            return Some(false);
        }

        None
    }

    fn expression_list_grandparent_use_context(&self, node: Node) -> Option<bool> {
        let parent = node.parent()?;
        if parent.kind() != "expression_list" {
            return None;
        }
        let grandparent = parent.parent()?;
        if !matches!(
            grandparent.kind(),
            "short_var_declaration" | "assignment_statement" | "range_clause"
        ) {
            return None;
        }
        let left = grandparent.child_by_field_name("left")?;
        Some(!self.node_contains(left, node))
    }

    fn left_field_contains(&self, node: Node, target: Node) -> Option<bool> {
        node.child_by_field_name("left")
            .map(|left| self.node_contains(left, target))
    }

    fn is_elixir_match_lhs(&self, parent: Node, node: Node) -> bool {
        let is_match = parent.children(&mut parent.walk()).any(|child| {
            !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
        });
        if !is_match {
            return false;
        }

        let mut cursor = parent.walk();
        for child in parent.children(&mut cursor) {
            if child.is_named() && child.id() == node.id() {
                return true;
            }
            if !child.is_named() && child.utf8_text(self.source.as_bytes()).unwrap_or("") == "=" {
                break;
            }
        }
        false
    }

    /// Check if ancestor node contains the target node
    fn node_contains(&self, ancestor: Node, target: Node) -> bool {
        if ancestor.id() == target.id() {
            return true;
        }
        let mut cursor = ancestor.walk();
        for child in ancestor.children(&mut cursor) {
            if self.node_contains(child, target) {
                return true;
            }
        }
        false
    }

    /// Build def-use chains using reaching definitions analysis
    fn build_def_use_chains(&mut self, cfg: &CfgInfo) -> TldrResult<()> {
        if cfg.blocks.is_empty() {
            return Ok(());
        }

        // Compute reaching definitions
        let _reaching = compute_reaching_definitions(cfg, &self.refs);

        // Build edges by connecting uses to their reaching definitions
        // (Edges will be added during finalize)

        Ok(())
    }

    /// Finalize and produce the DfgInfo
    fn finalize(self) -> TldrResult<DfgInfo> {
        // Build edges by connecting definitions to uses for the same variable
        let mut edges = Vec::new();

        // Group refs by variable
        let mut defs_by_var: HashMap<String, Vec<&VarRef>> = HashMap::new();
        let mut uses_by_var: HashMap<String, Vec<&VarRef>> = HashMap::new();

        for r in &self.refs {
            match r.ref_type {
                RefType::Definition | RefType::Update => {
                    defs_by_var.entry(r.name.clone()).or_default().push(r);
                }
                RefType::Use => {
                    uses_by_var.entry(r.name.clone()).or_default().push(r);
                }
            }
        }

        // For each variable, connect defs to uses
        // Simple heuristic: connect each def to uses that come after it
        for (var, defs) in &defs_by_var {
            if let Some(uses) = uses_by_var.get(var) {
                for def in defs {
                    for use_ref in uses {
                        // Connect if use comes after def (simple heuristic)
                        // A more sophisticated analysis would use reaching definitions
                        if use_ref.line >= def.line {
                            edges.push(DataflowEdge {
                                var: var.clone(),
                                def_line: def.line,
                                use_line: use_ref.line,
                                def_ref: (*def).clone(),
                                use_ref: (*use_ref).clone(),
                            });
                        }
                    }
                }
            }
        }

        let variables: Vec<String> = self.variables.into_iter().collect();

        Ok(DfgInfo {
            function: self.function_name,
            refs: self.refs,
            edges,
            variables,
        })
    }
}

fn first_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

/// solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): tree-sitter-solidity wraps
/// every operand in a named `expression` node whose single named child
/// carries the actual semantic content (identifier / binary_expression
/// / call_expression / array_access / etc.). Return that inner named
/// child so callers can dispatch on the real kind. Returns `None` if
/// the node has no named children.
fn solidity_unwrap_expression<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            return Some(child);
        }
    }
    None
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
/// Built-in JS / TS globals that are universally available at module
/// scope. Listing them as "imported type names" lets the use-context
/// classifier reject `Array.isArray(...)`, `new Error(...)`, etc. as
/// not-a-variable-use so they never enter the uninit detector.
///
/// We list ECMAScript built-ins, common Node.js globals, and DOM-host
/// globals (TypeScript dom-gen audit corpus). Adding a global here is
/// a precision improvement; missing one means a false positive
/// (mechanical false positive, recoverable via this list).
const JS_TS_GLOBALS: &[&str] = &[
    // ECMAScript built-ins
    "Array", "ArrayBuffer", "Atomics", "BigInt", "BigInt64Array", "BigUint64Array", "Boolean",
    "DataView", "Date", "Error", "EvalError", "Float32Array", "Float64Array", "Function",
    "Infinity", "Int16Array", "Int32Array", "Int8Array", "Intl", "JSON", "Map", "Math", "NaN",
    "Number", "Object", "Promise", "Proxy", "RangeError", "ReferenceError", "Reflect", "RegExp",
    "Set", "String", "Symbol", "SyntaxError", "TypeError", "URIError", "Uint16Array",
    "Uint32Array", "Uint8Array", "Uint8ClampedArray", "WeakMap", "WeakRef", "WeakSet",
    "decodeURI", "decodeURIComponent", "encodeURI", "encodeURIComponent", "eval", "globalThis",
    "isFinite", "isNaN", "parseFloat", "parseInt", "undefined",
    // Common Node.js globals
    "Buffer", "console", "exports", "global", "module", "process", "require",
    "setImmediate", "setInterval", "setTimeout", "clearImmediate", "clearInterval", "clearTimeout",
    "__dirname", "__filename",
    // Browser / DOM host
    "document", "window", "navigator", "self", "location", "history",
    "fetch", "XMLHttpRequest", "FormData", "URL", "URLSearchParams",
    "localStorage", "sessionStorage",
];

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032):
/// Lua / Luau standard-library globals — always pre-defined.
/// Listing them lets `m.open` etc. avoid flagging `print`, `assert`,
/// `require`, `pairs`, etc. as uninitialized.
const LUA_LUAU_GLOBALS: &[&str] = &[
    // Basic functions (Lua 5.x reference manual §6.1)
    "assert", "collectgarbage", "dofile", "error", "getmetatable", "ipairs", "load",
    "loadfile", "loadstring", "next", "pairs", "pcall", "print", "rawequal", "rawget",
    "rawlen", "rawset", "require", "select", "setmetatable", "tonumber", "tostring",
    "type", "unpack", "xpcall",
    // Std-library modules (referenced as Module.fn)
    "coroutine", "debug", "io", "math", "os", "package", "string", "table", "utf8",
    // Globals
    "_G", "_VERSION", "_ENV", "arg",
    // Luau-specific globals (Roblox / Luau runtime)
    "bit32", "buffer", "task", "vector",
];

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): walk a TS/JS
/// `import_statement` subtree and collect every local binding name.
/// Handles three import shapes:
///   - default: `import Foo from "mod"` -> Foo
///   - named: `import { a, b as c } from "mod"` -> a, c
///   - namespace: `import * as Ns from "mod"` -> Ns
/// Alias takes precedence over name in named imports.
fn collect_ts_js_import_bindings(
    import_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = Vec::new();
    let mut cursor = import_node.walk();
    for c in import_node.children(&mut cursor) {
        stack.push(c);
    }
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        match kind {
            "import_specifier" => {
                // `alias` (when present) is the local binding; else `name`.
                let bound = n
                    .child_by_field_name("alias")
                    .or_else(|| n.child_by_field_name("name"));
                if let Some(b) = bound {
                    let text = b.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
            }
            "namespace_import" => {
                // `import * as Ns from ...` — the single identifier child
                // is the namespace binding.
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    if ic.kind() == "identifier" {
                        let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                        if !text.is_empty() {
                            out.insert(text.to_string());
                        }
                    }
                }
            }
            "import_clause" => {
                // The direct `identifier` child of import_clause (NOT
                // nested inside named_imports / namespace_import) is the
                // default-import binding: `import Foo from "..."`.
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    if ic.kind() == "identifier" {
                        let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                        if !text.is_empty() {
                            out.insert(text.to_string());
                        }
                    } else {
                        // Recurse into named_imports / namespace_import.
                        stack.push(ic);
                    }
                }
            }
            _ => {
                let mut inner = n.walk();
                for ic in n.children(&mut inner) {
                    stack.push(ic);
                }
            }
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): walk a TS/JS
/// parameters subtree and collect every identifier that is a binding
/// name. Handles plain identifiers, required_parameter / optional_parameter
/// nodes, and destructuring patterns (`{ a, b: alias }`, `[x, y]`).
///
/// The walk is intentionally aggressive: we capture every identifier
/// child anywhere under the parameter list. False positives are bounded
/// by the parameter syntax — only binding sites contain identifiers.
fn collect_ts_js_param_names(
    params_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = vec![params_node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        // Skip type annotations entirely — they reference types, not
        // bindings. `function f(x: SomeType)` should bind `x` only.
        if matches!(kind, "type_annotation" | "type_identifier") {
            continue;
        }
        if kind == "identifier" {
            // Filter out the property-key half of `{ key: alias }` —
            // when parent is `pair_pattern` and node is the `key`, it's
            // a destructuring key referencing a property name, not a
            // binding. The alias (value field) is the real binding.
            if let Some(parent) = n.parent() {
                if parent.kind() == "pair_pattern" {
                    if let Some(key) = parent.child_by_field_name("key") {
                        if key.id() == n.id() {
                            continue;
                        }
                    }
                }
            }
            let text = n.utf8_text(source.as_bytes()).unwrap_or("").trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }
        let mut inner = n.walk();
        for ic in n.children(&mut inner) {
            stack.push(ic);
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): collect
/// binding identifier names from a TS/JS `lexical_declaration` or
/// `variable_declaration` subtree. The grammar layout is
///   lexical_declaration
///     variable_declarator
///       name: identifier | destructuring_pattern
///       value: ...
/// We only capture the `name` field of each `variable_declarator` to
/// avoid pulling in identifiers from the initializer expression.
fn collect_ts_js_variable_names(
    decl_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut cursor = decl_node.walk();
    for declarator in decl_node.children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        if let Some(name) = declarator.child_by_field_name("name") {
            if name.kind() == "identifier" {
                let text = name.utf8_text(source.as_bytes()).unwrap_or("").trim();
                if !text.is_empty() {
                    out.insert(text.to_string());
                }
            } else {
                // Destructuring pattern: collect every identifier
                // child of the pattern subtree.
                collect_ts_js_param_names(name, source, out);
            }
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): collect
/// identifier names defined by a top-level `variable_declaration`
/// (the lua/luau `local x = ...` form). The grammar layout is
///   variable_declaration
///     [variable_list | assignment_statement]
///       (assignment_statement.variable_list)
///         identifier+
/// We walk the subtree looking for identifiers that appear in a
/// `variable_list` context — those are the local-binding names.
fn collect_lua_local_names(
    decl_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut stack: Vec<Node> = vec![decl_node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if kind == "variable_list" {
            let mut inner = n.walk();
            for ic in n.children(&mut inner) {
                if ic.kind() == "identifier" {
                    let text = ic.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
            }
            continue;
        }
        let mut inner = n.walk();
        for ic in n.children(&mut inner) {
            stack.push(ic);
        }
    }
}

/// reaching-defs-imports-params-globals-v1 (v0.4.2 M-032): depth-first
/// search under `node` (skipping `node` itself) for the first descendant
/// whose `kind()` equals `kind`. Used by `extract_lua_param` to peel a
/// tree-sitter-luau `parameter` -> `type` -> `identifier` chain.
fn first_descendant_identifier_under<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = Vec::new();
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        stack.push(c);
    }
    while let Some(n) = stack.pop() {
        if n.kind() == kind {
            return Some(n);
        }
        let mut inner = n.walk();
        for c in n.children(&mut inner) {
            stack.push(c);
        }
    }
    None
}

/// AGG13-15 (quality-metrics-and-schema-v1): walk a node in source order
/// (depth-first, children left-to-right) and return the text of the
/// *last* `identifier` / `type_identifier` / `name` child encountered.
/// Used by `DfgBuilder::collect_imports` to peel `java.util.List` -> `List`
/// and `import a.b.C.method` -> `method`.
///
/// We deliberately use a recursive walk (not a stack) so the
/// "last identifier in source order" semantics is unambiguous.
fn last_identifier_text(node: Node, source: &str) -> Option<String> {
    fn walk(n: Node, source: &str, last: &mut Option<String>) {
        let kind = n.kind();
        if matches!(kind, "identifier" | "type_identifier" | "name") {
            *last = Some(n.utf8_text(source.as_bytes()).unwrap_or("").to_string());
        }
        for child in n.children(&mut n.walk()) {
            walk(child, source, last);
        }
    }
    let mut last = None;
    walk(node, source, &mut last);
    last.filter(|s| !s.is_empty())
}

/// Check if a name is a language keyword
fn is_keyword(name: &str, language: Language) -> bool {
    match language {
        Language::Python => matches!(
            name,
            "False"
                | "None"
                | "True"
                | "and"
                | "as"
                | "assert"
                | "async"
                | "await"
                | "break"
                | "class"
                | "continue"
                | "def"
                | "del"
                | "elif"
                | "else"
                | "except"
                | "finally"
                | "for"
                | "from"
                | "global"
                | "if"
                | "import"
                | "in"
                | "is"
                | "lambda"
                | "nonlocal"
                | "not"
                | "or"
                | "pass"
                | "raise"
                | "return"
                | "try"
                | "while"
                | "with"
                | "yield"
        ),
        Language::TypeScript | Language::JavaScript => matches!(
            name,
            "break"
                | "case"
                | "catch"
                | "class"
                | "const"
                | "continue"
                | "debugger"
                | "default"
                | "delete"
                | "do"
                | "else"
                | "enum"
                | "export"
                | "extends"
                | "false"
                | "finally"
                | "for"
                | "function"
                | "if"
                | "import"
                | "in"
                | "instanceof"
                | "let"
                | "new"
                | "null"
                | "return"
                | "static"
                | "super"
                | "switch"
                | "this"
                | "throw"
                | "true"
                | "try"
                | "typeof"
                | "undefined"
                | "var"
                | "void"
                | "while"
                | "with"
                | "yield"
        ),
        Language::Go => matches!(
            name,
            "break"
                | "case"
                | "chan"
                | "const"
                | "continue"
                | "default"
                | "defer"
                | "else"
                | "fallthrough"
                | "for"
                | "func"
                | "go"
                | "goto"
                | "if"
                | "import"
                | "interface"
                | "map"
                | "package"
                | "range"
                | "return"
                | "select"
                | "struct"
                | "switch"
                | "type"
                | "var"
                | "nil"
                | "true"
                | "false"
        ),
        Language::Rust => matches!(
            name,
            "as" | "break"
                | "const"
                | "continue"
                | "crate"
                | "else"
                | "enum"
                | "extern"
                | "false"
                | "fn"
                | "for"
                | "if"
                | "impl"
                | "in"
                | "let"
                | "loop"
                | "match"
                | "mod"
                | "move"
                | "mut"
                | "pub"
                | "ref"
                | "return"
                | "self"
                | "Self"
                | "static"
                | "struct"
                | "super"
                | "trait"
                | "true"
                | "type"
                | "unsafe"
                | "use"
                | "where"
                | "while"
                | "async"
                | "await"
                | "dyn"
        ),
        Language::Java => matches!(
            name,
            "abstract"
                | "assert"
                | "boolean"
                | "break"
                | "byte"
                | "case"
                | "catch"
                | "char"
                | "class"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "implements"
                | "import"
                | "instanceof"
                | "int"
                | "interface"
                | "long"
                | "native"
                | "new"
                | "null"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "return"
                | "short"
                | "static"
                | "strictfp"
                | "super"
                | "switch"
                | "synchronized"
                | "this"
                | "throw"
                | "throws"
                | "transient"
                | "true"
                | "try"
                | "void"
                | "volatile"
                | "while"
        ),
        Language::C | Language::Cpp => matches!(
            name,
            "auto"
                | "break"
                | "case"
                | "char"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extern"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "int"
                | "long"
                | "register"
                | "return"
                | "short"
                | "signed"
                | "sizeof"
                | "static"
                | "struct"
                | "switch"
                | "typedef"
                | "union"
                | "unsigned"
                | "void"
                | "volatile"
                | "while"
                | "NULL"
        ),
        Language::Ruby => matches!(
            name,
            "alias"
                | "and"
                | "begin"
                | "break"
                | "case"
                | "class"
                | "def"
                | "do"
                | "else"
                | "elsif"
                | "end"
                | "ensure"
                | "false"
                | "for"
                | "if"
                | "in"
                | "module"
                | "next"
                | "nil"
                | "not"
                | "or"
                | "redo"
                | "rescue"
                | "retry"
                | "return"
                | "self"
                | "super"
                | "then"
                | "true"
                | "undef"
                | "unless"
                | "until"
                | "when"
                | "while"
                | "yield"
                | "puts"
                | "print"
        ),
        Language::Php => matches!(
            name,
            "abstract"
                | "and"
                | "array"
                | "as"
                | "break"
                | "callable"
                | "case"
                | "catch"
                | "class"
                | "clone"
                | "const"
                | "continue"
                | "declare"
                | "default"
                | "die"
                | "do"
                | "echo"
                | "else"
                | "elseif"
                | "empty"
                | "enddeclare"
                | "endfor"
                | "endforeach"
                | "endif"
                | "endswitch"
                | "endwhile"
                | "eval"
                | "exit"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "fn"
                | "for"
                | "foreach"
                | "function"
                | "global"
                | "goto"
                | "if"
                | "implements"
                | "include"
                | "instanceof"
                | "interface"
                | "isset"
                | "list"
                | "match"
                | "namespace"
                | "new"
                | "null"
                | "or"
                | "print"
                | "private"
                | "protected"
                | "public"
                | "require"
                | "return"
                | "static"
                | "switch"
                | "throw"
                | "trait"
                | "true"
                | "try"
                | "unset"
                | "use"
                | "var"
                | "while"
                | "xor"
                | "yield"
        ),
        Language::Kotlin => matches!(
            name,
            "abstract"
                | "annotation"
                | "as"
                | "break"
                | "by"
                | "catch"
                | "class"
                | "companion"
                | "const"
                | "constructor"
                | "continue"
                | "crossinline"
                | "data"
                | "do"
                | "else"
                | "enum"
                | "external"
                | "false"
                | "final"
                | "finally"
                | "for"
                | "fun"
                | "if"
                | "import"
                | "in"
                | "infix"
                | "init"
                | "inline"
                | "inner"
                | "interface"
                | "internal"
                | "is"
                | "lateinit"
                | "noinline"
                | "null"
                | "object"
                | "open"
                | "operator"
                | "out"
                | "override"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "reified"
                | "return"
                | "sealed"
                | "super"
                | "suspend"
                | "this"
                | "throw"
                | "true"
                | "try"
                | "typealias"
                | "val"
                | "var"
                | "vararg"
                | "when"
                | "where"
                | "while"
        ),
        Language::Elixir => matches!(
            name,
            "after"
                | "and"
                | "case"
                | "catch"
                | "cond"
                | "def"
                | "defp"
                | "defmodule"
                | "defstruct"
                | "defprotocol"
                | "defimpl"
                | "defmacro"
                | "do"
                | "else"
                | "end"
                | "false"
                | "fn"
                | "for"
                | "if"
                | "import"
                | "in"
                | "nil"
                | "not"
                | "or"
                | "raise"
                | "receive"
                | "require"
                | "rescue"
                | "true"
                | "try"
                | "unless"
                | "use"
                | "when"
                | "with"
        ),
        Language::Ocaml => matches!(
            name,
            "and"
                | "as"
                | "assert"
                | "begin"
                | "class"
                | "constraint"
                | "do"
                | "done"
                | "downto"
                | "else"
                | "end"
                | "exception"
                | "external"
                | "false"
                | "for"
                | "fun"
                | "function"
                | "functor"
                | "if"
                | "in"
                | "include"
                | "inherit"
                | "initializer"
                | "lazy"
                | "let"
                | "match"
                | "method"
                | "mod"
                | "module"
                | "mutable"
                | "new"
                | "nonrec"
                | "object"
                | "of"
                | "open"
                | "or"
                | "private"
                | "rec"
                | "sig"
                | "struct"
                | "then"
                | "to"
                | "true"
                | "try"
                | "type"
                | "val"
                | "virtual"
                | "when"
                | "while"
                | "with"
        ),
        Language::Swift => matches!(
            name,
            "associatedtype"
                | "break"
                | "case"
                | "catch"
                | "class"
                | "continue"
                | "default"
                | "defer"
                | "deinit"
                | "do"
                | "else"
                | "enum"
                | "extension"
                | "fallthrough"
                | "false"
                | "fileprivate"
                | "for"
                | "func"
                | "guard"
                | "if"
                | "import"
                | "in"
                | "init"
                | "inout"
                | "internal"
                | "is"
                | "let"
                | "nil"
                | "open"
                | "operator"
                | "private"
                | "protocol"
                | "public"
                | "repeat"
                | "rethrows"
                | "return"
                | "self"
                | "Self"
                | "static"
                | "struct"
                | "subscript"
                | "super"
                | "switch"
                | "throw"
                | "throws"
                | "true"
                | "try"
                | "typealias"
                | "var"
                | "where"
                | "while"
                | "Int"
                | "String"
                | "Bool"
                | "Double"
                | "Float"
                | "Array"
        ),
        // cross-cutting-and-clear-fix-bugs-v1 (P18.B1): Scala keyword set so
        // `this` (and other reserved identifiers) are not flagged as
        // uninitialized variable uses by reaching-defs. Without this arm,
        // `_ => false` falls through and `this` slips through as an
        // identifier use with no defining write — definite false positive.
        Language::Scala => matches!(
            name,
            "abstract"
                | "case"
                | "catch"
                | "class"
                | "def"
                | "do"
                | "else"
                | "enum"
                | "export"
                | "extends"
                | "false"
                | "final"
                | "finally"
                | "for"
                | "forSome"
                | "given"
                | "if"
                | "implicit"
                | "import"
                | "lazy"
                | "match"
                | "new"
                | "null"
                | "object"
                | "override"
                | "package"
                | "private"
                | "protected"
                | "return"
                | "sealed"
                | "super"
                | "then"
                | "this"
                | "throw"
                | "trait"
                | "true"
                | "try"
                | "type"
                | "val"
                | "var"
                | "while"
                | "with"
                | "yield"
        ),
        // solidity-dfg-ssa-v1 (v0.5.0 SOL-006b): Solidity keyword set so
        // language tokens (`this`, `super`, type names, control-flow
        // words) are not flagged by reaching-defs as uninitialized local
        // uses. List restricted to the actual keywords reserved by the
        // Solidity grammar — `msg`/`block`/`tx` are NOT keywords (they
        // are intrinsic globals carried by `imported_type_names` policy
        // and the AST classifier handles them via the member_expression
        // receiver path). Including them here would mask legitimate
        // local-variable shadows.
        Language::Solidity => matches!(
            name,
            "abstract"
                | "address"
                | "anonymous"
                | "as"
                | "assembly"
                | "bool"
                | "break"
                | "byte"
                | "bytes"
                | "calldata"
                | "case"
                | "catch"
                | "constant"
                | "constructor"
                | "continue"
                | "contract"
                | "default"
                | "delete"
                | "do"
                | "else"
                | "emit"
                | "enum"
                | "event"
                | "external"
                | "fallback"
                | "false"
                | "final"
                | "for"
                // CL-12 (cl12_13_dfg_v1): `from` is NOT a Solidity keyword.
                // It is an ordinary identifier — the canonical
                // ERC-20/721 `transferFrom(address from, ...)` parameter
                // and a common local name (`address from = _ownerOf(id)`).
                // Listing it as a keyword silently dropped every read of a
                // variable named `from`, hiding real uses (false dead-stores)
                // and breaking def-use chains. Member-access property names,
                // callees and assignment targets named `from` are already
                // excluded by `solidity_use_context`, so removing it here
                // only records genuine variable references.
                | "function"
                | "global"
                | "if"
                | "immutable"
                | "import"
                | "indexed"
                | "interface"
                | "internal"
                | "is"
                | "library"
                | "mapping"
                | "memory"
                | "modifier"
                | "new"
                | "null"
                | "of"
                | "override"
                | "payable"
                | "pragma"
                | "private"
                | "public"
                | "pure"
                | "receive"
                | "return"
                | "returns"
                | "revert"
                | "self"
                | "Self"
                | "storage"
                | "string"
                | "struct"
                | "super"
                | "switch"
                | "this"
                | "throw"
                | "true"
                | "try"
                | "type"
                | "unchecked"
                | "using"
                | "var"
                | "view"
                | "virtual"
                | "while"
        ),
        // T5 (v0.5.0 AUDIT-FIX, root cause A2): C# CONTEXTUAL operator
        // keywords that tree-sitter-c-sharp surfaces as plain `identifier`
        // nodes (the reserved keywords `case`/`switch`/`new`/... are distinct
        // token kinds and never reach the identifier-as-use path). `nameof(x)`
        // parses as `invocation_expression > [function] identifier 'nameof'`,
        // so `nameof` was flagged `definite` uninitialized. `typeof`/`sizeof`
        // share the shape. These are operators, never local variables.
        Language::CSharp => matches!(name, "nameof" | "typeof" | "sizeof"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function() {
        let source = r#"
def foo(x):
    y = x + 1
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(dfg.variables.contains(&"x".to_string()));
        assert!(dfg.variables.contains(&"y".to_string()));
    }

    #[test]
    fn test_extracts_definitions() {
        let source = r#"
def foo():
    x = 1
    y = 2
    return x + y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .collect();

        assert!(defs.iter().any(|r| r.name == "x"));
        assert!(defs.iter().any(|r| r.name == "y"));
    }

    #[test]
    fn test_extracts_uses() {
        let source = r#"
def foo(x):
    return x + 1
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .collect();

        assert!(uses.iter().any(|r| r.name == "x"));
    }

    #[test]
    fn test_function_not_found() {
        let source = "def foo(): pass";
        let result = get_dfg_context(source, "bar", Language::Python);
        assert!(result.is_err());
    }

    #[test]
    fn test_for_loop_variable() {
        let source = r#"
def foo(items):
    for item in items:
        print(item)
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        // 'item' should be both a definition (loop var) and a use (in print)
        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();

        assert!(
            !item_defs.is_empty(),
            "for loop variable should be a definition"
        );
    }

    #[test]
    fn test_augmented_assignment() {
        let source = r#"
def foo():
    x = 0
    x += 1
    return x
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Update)
            .collect();

        assert!(
            !updates.is_empty(),
            "augmented assignment should be an update"
        );
    }

    #[test]
    fn test_def_use_edges() {
        let source = r#"
def foo():
    x = 1
    y = x + 2
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        // Should have an edge from x's definition to x's use
        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();

        assert!(!x_edges.is_empty(), "should have def-use edge for x");
    }

    // =========================================================================
    // Multi-language DFG tests
    // =========================================================================

    // --- TypeScript / JavaScript ---

    #[test]
    fn test_typescript_let_const_declaration() {
        let source = r#"
function foo(x: number) {
    let y = x + 1;
    const z = y * 2;
    return z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "should find param x"
        );
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find let y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find const z"
        );

        // y and z should be definitions
        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_typescript_assignment_expression() {
        let source = r#"
function foo() {
    let x = 0;
    x = 5;
    x += 3;
    return x;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();

        let x_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!x_defs.is_empty(), "x should have at least one definition");

        let x_updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Update)
            .collect();
        assert!(!x_updates.is_empty(), "x += 3 should produce an update ref");
    }

    #[test]
    fn test_typescript_for_of_loop() {
        let source = r#"
function foo(items: number[]) {
    for (const item of items) {
        console.log(item);
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find loop var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "for-of loop variable should be a definition"
        );
    }

    #[test]
    fn test_javascript_var_declaration() {
        let source = r#"
function foo(x) {
    var y = x + 1;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::JavaScript).unwrap();
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find var y"
        );

        let y_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "y" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!y_defs.is_empty(), "var y should be a definition");
    }

    // --- Rust ---

    #[test]
    fn test_rust_let_declaration() {
        let source = r#"
fn foo(x: i32) -> i32 {
    let y = x + 1;
    let z = y * 2;
    z
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find let y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find let z"
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_rust_assignment_expression() {
        let source = r#"
fn foo() -> i32 {
    let mut x = 0;
    x = 5;
    x += 3;
    x
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();

        // x = 5 should be a definition or update
        let x_all: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        assert!(
            x_all.len() >= 3,
            "x should have at least 3 refs (def, reassign, use), got {}",
            x_all.len()
        );
    }

    #[test]
    fn test_rust_for_expression() {
        let source = r#"
fn foo(items: Vec<i32>) {
    for item in items.iter() {
        println!("{}", item);
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find loop var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "for loop variable should be a definition"
        );
    }

    // --- Go ---

    #[test]
    fn test_go_short_var_declaration() {
        let source = r#"
func foo(x int) int {
    y := x + 1
    z := y * 2
    return z
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find y from :="
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find z from :="
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_go_var_declaration() {
        let source = r#"
func foo() int {
    var x int = 10
    var y = x + 1
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "should find var x"
        );
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find var y"
        );
    }

    #[test]
    fn test_go_assignment_statement() {
        let source = r#"
func foo() int {
    x := 0
    x = 5
    return x
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();

        let x_refs: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        // Should have: definition (:=), definition or update (=), use (return)
        assert!(
            x_refs.len() >= 3,
            "x should have at least 3 refs, got {}",
            x_refs.len()
        );
    }

    #[test]
    fn test_go_range_loop() {
        let source = r#"
func foo(items []int) {
    for i, v := range items {
        fmt.Println(i, v)
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();
        assert!(
            dfg.variables.contains(&"i".to_string()),
            "should find range var i"
        );
        assert!(
            dfg.variables.contains(&"v".to_string()),
            "should find range var v"
        );
    }

    // --- Java ---

    #[test]
    fn test_java_local_variable_declaration() {
        let source = r#"
class Foo {
    int foo(int x) {
        int y = x + 1;
        int z = y * 2;
        return z;
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find int y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find int z"
        );

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "z should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_java_assignment_expression() {
        let source = r#"
class Foo {
    void foo() {
        int x = 0;
        x = 5;
        x += 3;
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();

        let x_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "x" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!x_defs.is_empty(), "x should have at least one definition");
    }

    #[test]
    fn test_java_enhanced_for() {
        let source = r#"
class Foo {
    void foo(int[] items) {
        for (int item : items) {
            System.out.println(item);
        }
    }
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Java).unwrap();
        assert!(
            dfg.variables.contains(&"item".to_string()),
            "should find enhanced for var item"
        );

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "enhanced for variable should be a definition"
        );
    }

    // --- C ---

    #[test]
    fn test_c_declaration() {
        let source = r#"
int foo(int x) {
    int y = x + 1;
    int z = y * 2;
    return z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::C).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "should find int y"
        );
        assert!(
            dfg.variables.contains(&"z".to_string()),
            "should find int z"
        );
    }

    #[test]
    fn test_c_assignment_expression() {
        let source = r#"
void foo() {
    int x = 0;
    x = 5;
    x += 3;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::C).unwrap();

        let x_refs: Vec<_> = dfg.refs.iter().filter(|r| r.name == "x").collect();
        assert!(
            x_refs.len() >= 2,
            "x should have at least 2 refs, got {}: {:?}",
            x_refs.len(),
            x_refs
                .iter()
                .map(|r| (&r.name, &r.ref_type, r.line))
                .collect::<Vec<_>>()
        );
    }

    // --- Ruby ---

    #[test]
    fn test_ruby_assignment() {
        let source = r#"
def foo(x)
    y = x + 1
    z = y * 2
    z
end
"#;
        let dfg = get_dfg_context(source, "foo", Language::Ruby).unwrap();
        assert_eq!(dfg.function, "foo");
        assert!(dfg.variables.contains(&"y".to_string()), "should find y");
        assert!(dfg.variables.contains(&"z".to_string()), "should find z");
    }

    // --- PHP ---

    #[test]
    fn test_php_assignment() {
        let source = r#"<?php
function foo($x) {
    $y = $x + 1;
    $z = $y * 2;
    return $z;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Php).unwrap();
        assert_eq!(dfg.function, "foo");
        // PHP variables include $ prefix in tree-sitter
        assert!(
            dfg.variables.contains(&"$y".to_string()) || dfg.variables.contains(&"y".to_string()),
            "should find y variable, got: {:?}",
            dfg.variables
        );
    }

    // --- Cross-language def-use edges ---

    #[test]
    fn test_typescript_def_use_edges() {
        let source = r#"
function foo() {
    let x = 1;
    let y = x + 2;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::TypeScript).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(
            !x_edges.is_empty(),
            "should have def-use edge for x in TypeScript"
        );
    }

    #[test]
    fn test_go_def_use_edges() {
        let source = r#"
func foo() int {
    x := 1
    y := x + 2
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Go).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(!x_edges.is_empty(), "should have def-use edge for x in Go");
    }

    #[test]
    fn test_rust_def_use_edges() {
        let source = r#"
fn foo() -> i32 {
    let x = 1;
    let y = x + 2;
    y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Rust).unwrap();

        let x_edges: Vec<_> = dfg.edges.iter().filter(|e| e.var == "x").collect();
        assert!(
            !x_edges.is_empty(),
            "should have def-use edge for x in Rust"
        );
    }

    // --- Python regression tests ---

    #[test]
    fn test_python_still_works_after_multilang() {
        let source = r#"
def foo(x):
    y = x + 1
    for item in [1, 2, 3]:
        y += item
    return y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();
        assert!(dfg.variables.contains(&"x".to_string()));
        assert!(dfg.variables.contains(&"y".to_string()));
        assert!(dfg.variables.contains(&"item".to_string()));

        let y_updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "y" && r.ref_type == RefType::Update)
            .collect();
        assert!(!y_updates.is_empty(), "y += item should be an update");

        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(!item_defs.is_empty(), "for item should be a definition");
    }

    // =========================================================================
    // NOGK language fix tests - These must produce definitions
    // =========================================================================

    #[test]
    fn test_kotlin_val_extraction() {
        let source = r#"
fun foo(x: Int): Int {
    val y = x + 1
    return y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Kotlin).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Kotlin val y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "Kotlin param x should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_kotlin_var_extraction() {
        let source = r#"
fun foo(): Int {
    var count = 0
    count = count + 1
    return count
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Kotlin).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !defs.is_empty(),
            "Kotlin var count should produce definitions, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_elixir_match_extraction() {
        let source = r#"
def foo(x) do
  y = x + 1
  y
end
"#;
        let dfg = get_dfg_context(source, "foo", Language::Elixir).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Elixir y = x + 1 should produce a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_scala_val_extraction() {
        let source = r#"
def foo(x: Int): Int = {
  val y = x + 1
  y
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Scala).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Scala val y should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_cpp_declaration_extraction() {
        let source = r#"
int foo(int x) {
    int y = x + 1;
    return y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Cpp).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "C++ int y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "C++ param x should be a definition, got defs: {:?}",
            defs
        );
    }

    #[test]
    fn test_php_assignment_extraction() {
        let source = r#"<?php
function foo($x) {
    $y = $x + 1;
    return $y;
}
"#;
        let dfg = get_dfg_context(source, "foo", Language::Php).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            !defs.is_empty(),
            "PHP $y = $x + 1 should produce a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_ocaml_let_extraction() {
        let source = r#"
let foo x =
  let y = x + 1 in
  y
"#;
        let dfg = get_dfg_context(source, "foo", Language::Ocaml).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y") || defs.contains(&"x"),
            "OCaml let y = x + 1 should produce definitions, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_python_assignment_extracts_defs() {
        // Regression: Python should produce definitions in reaching-defs context
        let source = r#"
def foo(x):
    y = x + 1
    z = y * 2
    return z
"#;
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Python y should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"z"),
            "Python z should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"x"),
            "Python param x should be a definition, got defs: {:?}",
            defs
        );
    }

    // =========================================================================
    // Reaching-defs NOGK fix tests
    // These tests verify that Lua and Swift DFG extraction produces
    // definitions for local variable declarations and assignments.
    // =========================================================================

    // --- Lua ---

    #[test]
    fn test_lua_local_declaration_produces_defs() {
        // Lua: `local y = x + 1` should produce a definition for y
        // AST: variable_declaration -> assignment_statement -> variable_list -> identifier
        let source = r#"function foo(x)
    local y = x + 1
    return y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Lua local y should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_lua_assignment_produces_defs() {
        // Lua: `z = y * 2` should produce a definition for z
        // AST: assignment_statement -> variable_list -> identifier
        let source = r#"function foo(x)
    local y = x + 1
    z = y * 2
    return z
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"z"),
            "Lua z = ... should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_lua_local_declaration_uses() {
        // Lua: `local y = x + 1` should produce a use for x
        let source = r#"function foo(x)
    local y = x + 1
    return y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            uses.contains(&"x"),
            "Lua x in `local y = x + 1` should be a use, got uses: {:?}",
            uses
        );
        assert!(
            uses.contains(&"y"),
            "Lua y in `return y` should be a use, got uses: {:?}",
            uses
        );
    }

    #[test]
    fn test_lua_param_extraction() {
        // Lua: function parameters should be definitions
        let source = r#"function foo(x, y)
    return x + y
end"#;
        let dfg = get_dfg_context(source, "foo", Language::Lua).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"x"),
            "Lua param x should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"y"),
            "Lua param y should be a definition, got defs: {:?}",
            defs
        );
    }

    // --- Swift ---

    #[test]
    fn test_swift_let_declaration_produces_defs() {
        // Swift: `let y = x + 1` should produce a definition for y
        // AST: property_declaration -> pattern -> simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    let y = x + 1
    return y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"y"),
            "Swift let y should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_swift_var_declaration_produces_defs() {
        // Swift: `var z = y * 2` should produce a definition for z
        let source = r#"func foo(x: Int) -> Int {
    var z = x * 2
    z = z + 1
    return z
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"z"),
            "Swift var z should be a definition, got defs: {:?}; all refs: {:?}",
            defs,
            dfg.refs
        );
    }

    #[test]
    fn test_swift_assignment_produces_defs() {
        // Swift: `z = z + 1` should produce a definition for z
        // AST: assignment -> directly_assignable_expression -> simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    var z = x
    z = z + 1
    return z
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let z_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| {
                r.name == "z" && matches!(r.ref_type, RefType::Definition | RefType::Update)
            })
            .collect();
        // At minimum: var z = x (def) and z = z + 1 (def)
        assert!(
            z_defs.len() >= 2,
            "Swift z should have at least 2 def/update refs (var z = x; z = z + 1), got {}: {:?}",
            z_defs.len(),
            z_defs
        );
    }

    #[test]
    fn test_swift_uses_extraction() {
        // Swift: uses should be extracted via simple_identifier
        let source = r#"func foo(x: Int) -> Int {
    let y = x + 1
    return y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            uses.contains(&"x"),
            "Swift x in `let y = x + 1` should be a use, got uses: {:?}",
            uses
        );
        assert!(
            uses.contains(&"y"),
            "Swift y in `return y` should be a use, got uses: {:?}",
            uses
        );
    }

    #[test]
    fn test_swift_param_extraction() {
        // Swift: function parameters should be definitions
        let source = r#"func foo(x: Int, y: Int) -> Int {
    return x + y
}"#;
        let dfg = get_dfg_context(source, "foo", Language::Swift).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.as_str())
            .collect();
        assert!(
            defs.contains(&"x"),
            "Swift param x should be a definition, got defs: {:?}",
            defs
        );
        assert!(
            defs.contains(&"y"),
            "Swift param y should be a definition, got defs: {:?}",
            defs
        );
    }

    // =====================================================================
    // B4 (fix-B4-dfg-coverage-v1, v0.5.0 AUDIT-FIX): DFG extractor language
    // coverage for slice/chop data-flow.
    //
    // Two root causes in the Python-shaped extractor:
    //   (1) process_c_style_assignment routes a subscript/array/member LHS to
    //       extract_assignment_targets, which recorded only the container as
    //       Update and DROPPED the variables used inside the index subscript.
    //       So `arr[i+j] = x;` lost `i`, `j` as uses -> chop c-redis sdscatlen
    //       535->541 saw no data-flow path through `s[curlen+len] = '\0';`.
    //   (2) process_for_loop only understood the Python `for x in iter` shape
    //       (left/right/body fields) but is dispatched for the generic
    //       `for_statement`, which in Go (`for r < n {`) and C
    //       (`for(init;cond;post)`) has a different shape. The condition/post
    //       reference vars as USES, and the body was dropped entirely ->
    //       slice go-httprouter CleanPath 61 returned only [61].
    // =====================================================================

    /// Collect the names of refs of a given type for a function.
    fn names_of(dfg: &DfgInfo, rt: RefType) -> Vec<String> {
        dfg.refs
            .iter()
            .filter(|r| r.ref_type == rt)
            .map(|r| r.name.clone())
            .collect()
    }

    #[test]
    fn c_subscript_lhs_index_vars_are_uses() {
        // ROOT CAUSE (1): C `a[i+len] = b[k];` — the index vars `i`, `len`
        // inside the LHS subscript, plus the container `b` and index `k` on
        // the RHS, must all be recorded as uses. The container `a` is the
        // Update target.
        let source = "void f() {\n    a[i+len] = b[k];\n}";
        let dfg = get_dfg_context(source, "f", Language::C).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "len", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "C subscript LHS/RHS: `{}` should be a use, got uses: {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn cpp_subscript_lhs_index_vars_are_uses() {
        // C++ shares the C `subscript_expression` shape (field `argument`).
        let source = "void f() {\n    a[i + j] = b[k];\n}";
        let dfg = get_dfg_context(source, "f", Language::Cpp).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "j", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "C++ subscript index var `{}` should be a use, got {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn ts_subscript_lhs_index_vars_are_uses() {
        // TS `subscript_expression` uses field `object` (not `argument`).
        let source = "function f() {\n    a[i + j] = b[k];\n}";
        let dfg = get_dfg_context(source, "f", Language::TypeScript).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "j", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "TS subscript index var `{}` should be a use, got {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn java_array_access_lhs_index_vars_are_uses() {
        // Java `array_access` uses field `array` for the base, `index` for the
        // subscript.
        let source = "class C {\n    void f() {\n        a[i + j] = b[k];\n    }\n}";
        let dfg = get_dfg_context(source, "f", Language::Java).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "j", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "Java array_access index var `{}` should be a use, got {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn go_index_expression_lhs_index_vars_are_uses() {
        // Go `index_expression` uses field `operand` for the base.
        let source = "func f() {\n    a[i + j] = b[k]\n}";
        let dfg = get_dfg_context(source, "f", Language::Go).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "j", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "Go index_expression index var `{}` should be a use, got {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn python_subscript_lhs_index_vars_are_uses() {
        // Python `subscript` uses field `value` (base) and `subscript` (index).
        let source = "def f():\n    a[i + j] = b[k]";
        let dfg = get_dfg_context(source, "f", Language::Python).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for v in ["i", "j", "k", "b"] {
            assert!(
                uses.contains(&v.to_string()),
                "Python subscript index var `{}` should be a use, got {:?}",
                v,
                uses
            );
        }
    }

    #[test]
    fn c_subscript_lhs_container_is_update_not_def() {
        // Guard: `a[i+len] = ...` writes an element of `a`, so `a` is an
        // Update (read-then-write of the container), NOT a fresh Definition.
        // (Mirrors Solidity array_access / Python subscript semantics.)
        let source = "void f() {\n    a[i+len] = b[k];\n}";
        let dfg = get_dfg_context(source, "f", Language::C).unwrap();
        let a_updates: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "a" && r.ref_type == RefType::Update)
            .collect();
        assert!(
            !a_updates.is_empty(),
            "C subscript container `a` should be an Update, got refs: {:?}",
            dfg.refs
                .iter()
                .map(|r| (r.name.clone(), r.ref_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn go_condition_only_for_loop_condition_vars_are_uses() {
        // ROOT CAUSE (2): Go `for r < n { ... }` is a `for_statement` whose
        // condition is a non-field positional child. The condition vars `r`,
        // `n` must be recorded as uses, and the BODY must still be walked.
        let source = "func f() {\n    for r < n {\n        x = r\n    }\n}";
        let dfg = get_dfg_context(source, "f", Language::Go).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        assert!(
            uses.contains(&"r".to_string()),
            "Go for-condition var `r` should be a use, got uses: {:?}",
            uses
        );
        assert!(
            uses.contains(&"n".to_string()),
            "Go for-condition var `n` should be a use, got uses: {:?}",
            uses
        );
        // The body must still be visited (regression guard against dropping it).
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "Go for body var `x` should be recorded, got vars: {:?}",
            dfg.variables
        );
    }

    #[test]
    fn c_three_clause_for_loop_clause_vars_recorded() {
        // C `for (i = 0; i < n; i++) { x = i; }` — fields initializer,
        // condition, update, body. The condition/update reference vars as
        // USES, and the body must be walked.
        let source = "void f() {\n    for (i = 0; i < n; i++) {\n        x = i;\n    }\n}";
        let dfg = get_dfg_context(source, "f", Language::C).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        // `n` is referenced only in the condition; if the condition is dropped
        // it never appears.
        assert!(
            uses.contains(&"n".to_string()),
            "C for-condition var `n` should be a use, got uses: {:?}",
            uses
        );
        // `i` defined in init, used in cond/update/body.
        assert!(
            dfg.variables.contains(&"i".to_string()),
            "C for-init var `i` should be recorded, got vars: {:?}",
            dfg.variables
        );
        // body visited
        assert!(
            dfg.variables.contains(&"x".to_string()),
            "C for body var `x` should be recorded, got vars: {:?}",
            dfg.variables
        );
    }

    #[test]
    fn go_infinite_for_loop_body_walked() {
        // Go `for { ... }` (infinite) — only a `body` field. Ensure the body
        // is still visited and we don't panic.
        let source = "func f() {\n    for {\n        y = z\n    }\n}";
        let dfg = get_dfg_context(source, "f", Language::Go).unwrap();
        assert!(
            dfg.variables.contains(&"y".to_string()),
            "Go infinite-for body var `y` should be recorded, got vars: {:?}",
            dfg.variables
        );
        let uses = names_of(&dfg, RefType::Use);
        assert!(
            uses.contains(&"z".to_string()),
            "Go infinite-for body use `z` should be recorded, got uses: {:?}",
            uses
        );
    }

    #[test]
    fn python_for_in_loop_still_works() {
        // Regression guard: the Python `for x in items:` shape (left/right/
        // body fields) must be UNCHANGED by the Go/C for-loop handling.
        let source = "def foo(items):\n    for item in items:\n        print(item)";
        let dfg = get_dfg_context(source, "foo", Language::Python).unwrap();
        let item_defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "item" && r.ref_type == RefType::Definition)
            .collect();
        assert!(
            !item_defs.is_empty(),
            "Python for-loop var `item` should remain a Definition"
        );
        let uses = names_of(&dfg, RefType::Use);
        assert!(
            uses.contains(&"items".to_string()),
            "Python for iterable `items` should be a use, got {:?}",
            uses
        );
    }

    // =====================================================================
    // T5 (v0.5.0 AUDIT-FIX): reaching-defs / dead-stores false positives.
    //
    // The reaching-defs analyzer was reporting bare references to CLASS
    // FIELDS, MODULE GLOBALS, FOREACH LOOP VARS, and match-arm PATTERN
    // BINDINGS as `definite` uninitialized uses; and the dead-stores
    // analyzer was flagging locals that ARE read later (inside closures,
    // context-manager calls, and recursive bindings) as dead — both
    // because the DFG use/def extraction dropped those nodes. These tests
    // pin the corrected extraction on the production `get_dfg_context`
    // path. RED before the fix, GREEN after.
    // =====================================================================

    /// Helper: lines of refs with a given (name, ref_type).
    fn lines_of(dfg: &DfgInfo, name: &str, rt: RefType) -> Vec<u32> {
        dfg.refs
            .iter()
            .filter(|r| r.name == name && r.ref_type == rt)
            .map(|r| r.line)
            .collect()
    }

    #[test]
    fn t5_csharp_class_field_not_a_bare_use() {
        // ROOT CAUSE A1: a method reading a bare class field `_writer`
        // (declared `private readonly BinaryWriter _writer;`) must NOT be
        // collected as a local-variable use — otherwise reaching-defs flags
        // it `definite` uninitialized. The C# `field_declaration` nests its
        // `variable_declarator` under a `variable_declaration` (unlike Java),
        // so the field collector missed it.
        let source = r#"
class W
{
    private readonly BinaryWriter _writer;

    private void Write(BsonToken t)
    {
        _writer.Write(t.Size);
    }
}
"#;
        let dfg = get_dfg_context(source, "Write", Language::CSharp).unwrap();
        let writer_uses = lines_of(&dfg, "_writer", RefType::Use);
        assert!(
            writer_uses.is_empty(),
            "C# bare class field `_writer` must not be a local use, got use lines {:?}",
            writer_uses
        );
    }

    #[test]
    fn t5_csharp_type_receiver_not_a_bare_use() {
        // ROOT CAUSE A2: PascalCase type/enum receivers in member access
        // (`BsonType.Object`, `Convert.ToInt32(...)`, `CultureInfo.X`) are
        // compile-time type references resolved from other compilation
        // units, never local variables. They must not be bare uses.
        let source = r#"
class W
{
    private int Pick(BsonToken t)
    {
        switch (t.Type)
        {
            case BsonType.Object:
                return Convert.ToInt32(t.Value, CultureInfo.InvariantCulture);
            default:
                return 0;
        }
    }
}
"#;
        let dfg = get_dfg_context(source, "Pick", Language::CSharp).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for ty in ["BsonType", "Convert", "CultureInfo"] {
            assert!(
                !uses.contains(&ty.to_string()),
                "C# type receiver `{}` must not be a local use, got uses {:?}",
                ty,
                uses
            );
        }
    }

    #[test]
    fn t5_csharp_new_type_and_nameof_not_a_bare_use() {
        // ROOT CAUSE A2 (tail): `throw new ArgumentOutOfRangeException(
        // nameof(t), ...)` — the constructed type in `new T(...)` and the
        // `nameof` contextual operator both surface as bare identifiers and
        // were flagged `definite` uninitialized. Neither is a local variable.
        let source = r#"
class W
{
    private void Check(object t)
    {
        throw new ArgumentOutOfRangeException(nameof(t), "bad");
    }
}
"#;
        let dfg = get_dfg_context(source, "Check", Language::CSharp).unwrap();
        let uses = names_of(&dfg, RefType::Use);
        for n in ["ArgumentOutOfRangeException", "nameof"] {
            assert!(
                !uses.contains(&n.to_string()),
                "C# `{}` must not be a local use, got uses {:?}",
                n,
                uses
            );
        }
        // The argument `t` (a parameter) IS read by `nameof(t)`.
        assert!(
            uses.contains(&"t".to_string()),
            "C# `nameof(t)` argument `t` should be a use, got uses {:?}",
            uses
        );
    }

    #[test]
    fn t5_csharp_foreach_loop_var_is_definition() {
        // ROOT CAUSE A3: C# `foreach (BsonProperty property in value)` shares
        // the `foreach_statement` node kind with PHP but uses [left]/[right]
        // fields. The loop variable `property` is a DEFINITION and its reads
        // in the body must resolve to it (not be uninitialized).
        let source = r#"
class W
{
    private void Walk(BsonObject value)
    {
        foreach (BsonProperty property in value)
        {
            Write(property.Name);
        }
    }
}
"#;
        let dfg = get_dfg_context(source, "Walk", Language::CSharp).unwrap();
        let prop_defs = lines_of(&dfg, "property", RefType::Definition);
        assert!(
            !prop_defs.is_empty(),
            "C# foreach loop var `property` must be a Definition, got refs {:?}",
            dfg.refs
        );
        // The iterable `value` (a parameter) is read by the loop header.
        let value_uses = lines_of(&dfg, "value", RefType::Use);
        assert!(
            !value_uses.is_empty(),
            "C# foreach iterable `value` must be a use, got uses {:?}",
            names_of(&dfg, RefType::Use)
        );
    }

    #[test]
    fn t5_lua_module_global_receiver_not_uninitialized() {
        // ROOT CAUSE A4: a bare module global `Config` used as the receiver
        // of `Config.builtins` is an implicit Lua global, defined elsewhere;
        // it must not be reported as a local use / uninitialized var.
        let source = r#"
local function f()
    return Config.builtins
end
"#;
        let dfg = get_dfg_context(source, "f", Language::Lua).unwrap();
        let cfg_uses = lines_of(&dfg, "Config", RefType::Use);
        assert!(
            cfg_uses.is_empty(),
            "Lua module global `Config` must not be a local use, got use lines {:?}",
            cfg_uses
        );
    }

    #[test]
    fn t5_lua_generic_for_loop_var_is_definition() {
        // ROOT CAUSE A5: Lua `for _, issue in ipairs(t) do` uses a
        // `for_generic_clause` (variable_list / expression_list), not
        // left/right fields. The loop var `issue` is a DEFINITION.
        let source = r#"
local function f(t)
    for _, issue in ipairs(t) do
        use(issue)
    end
end
"#;
        let dfg = get_dfg_context(source, "f", Language::Lua).unwrap();
        let issue_defs = lines_of(&dfg, "issue", RefType::Definition);
        assert!(
            !issue_defs.is_empty(),
            "Lua generic-for loop var `issue` must be a Definition, got refs {:?}",
            dfg.refs
        );
    }

    #[test]
    fn t5_scala_match_arm_binding_is_definition() {
        // ROOT CAUSE A6: Scala `case Errored(e) => errored(e)` binds `e` as a
        // pattern variable (a Definition). Its read in the arm body must
        // resolve to that binding instead of being flagged uninitialized.
        let source = r#"
object O {
  def fold[B](errored: E => B, completed: F => B): B =
    this match {
      case Errored(e) => errored(e)
      case Succeeded(fa) => completed(fa)
    }
}
"#;
        let dfg = get_dfg_context(source, "fold", Language::Scala).unwrap();
        let e_defs = lines_of(&dfg, "e", RefType::Definition);
        let fa_defs = lines_of(&dfg, "fa", RefType::Definition);
        assert!(
            !e_defs.is_empty(),
            "Scala match-arm binding `e` must be a Definition, got refs {:?}",
            dfg.refs
        );
        assert!(
            !fa_defs.is_empty(),
            "Scala match-arm binding `fa` must be a Definition, got refs {:?}",
            dfg.refs
        );
    }

    #[test]
    fn t5_deadstore_ts_sibling_callback_local_read_captured() {
        // ROOT CAUSE B1: `const a = ...; const b = ...; merge(a, b, prop)`
        // inside a callback. `a`/`b` are ALSO parameter names of sibling
        // nested helpers, which were over-collected into the suppression set
        // and dropped EVERY `a`/`b` read — so the stores looked dead. A
        // local declaration's reads must survive.
        let source = r#"
function mergeConfig(config1, config2) {
  function helper(a, b) {
    return a;
  }
  forEach(keys, function compute(prop) {
    const a = config1[prop];
    const b = config2[prop];
    return merge(a, b, prop);
  });
}
"#;
        let dfg = get_dfg_context(source, "mergeConfig", Language::JavaScript).unwrap();
        let a_uses = lines_of(&dfg, "a", RefType::Use);
        let b_uses = lines_of(&dfg, "b", RefType::Use);
        assert!(
            !a_uses.is_empty(),
            "JS callback local `a` read in `merge(a, b, prop)` must be a use, got uses {:?}",
            names_of(&dfg, RefType::Use)
        );
        assert!(
            !b_uses.is_empty(),
            "JS callback local `b` read in `merge(a, b, prop)` must be a use, got uses {:?}",
            names_of(&dfg, RefType::Use)
        );
    }

    #[test]
    fn t5_deadstore_python_with_context_read_captured() {
        // ROOT CAUSE B2: `with set_environ("k", no_proxy_arg):` — the context
        // expression lives under a `with_clause` wrapper the handler skipped,
        // so the read of `no_proxy_arg` was dropped and the prior store
        // looked dead. The use must be captured.
        let source = r#"
def f(no_proxy):
    no_proxy_arg = no_proxy
    with set_environ("no_proxy", no_proxy_arg):
        do_work()
"#;
        let dfg = get_dfg_context(source, "f", Language::Python).unwrap();
        let arg_uses = lines_of(&dfg, "no_proxy_arg", RefType::Use);
        assert!(
            !arg_uses.is_empty(),
            "Python `with` context read of `no_proxy_arg` must be a use, got uses {:?}",
            names_of(&dfg, RefType::Use)
        );
    }

    #[test]
    fn t5_deadstore_ocaml_recursive_binding_read_captured() {
        // ROOT CAUSE B3: `let rec inner acc = ... in inner [] l` — the
        // recursive references to `inner` are unqualified `value_path`s that
        // the blanket value_path suppression dropped, so the binding looked
        // dead. An unqualified value_path matching a local binding IS a use.
        let source = r#"
let map_s f l =
  let rec inner acc = function
    | [] -> List.rev acc
    | hd :: tl -> inner (hd :: acc) tl
  in
  inner [] l
"#;
        let dfg = get_dfg_context(source, "map_s", Language::Ocaml).unwrap();
        let inner_uses = lines_of(&dfg, "inner", RefType::Use);
        assert!(
            !inner_uses.is_empty(),
            "OCaml recursive binding `inner` must have its calls recorded as uses, got refs {:?}",
            dfg.refs
        );
        // The module-qualified `List.rev` must still NOT be a bare use.
        let list_uses = lines_of(&dfg, "List", RefType::Use);
        assert!(
            list_uses.is_empty(),
            "OCaml module path `List` must not be a local use, got use lines {:?}",
            list_uses
        );
    }
}
