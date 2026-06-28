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
use crate::types::{CfgInfo, DataflowEdge, DfgInfo, Language, RefType, VarRef, VarRefContext};
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
    // fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): pre-collect this Go
    // function's named result identifiers so a naked `return` can synthesize
    // their implicit reads (no-op for non-Go / unnamed results).
    builder.collect_go_named_results(func_node);
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
    // fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): pre-collect this Go
    // function's named result identifiers so a naked `return` can synthesize
    // their implicit reads (no-op for non-Go / unnamed results).
    builder.collect_go_named_results(func_node);
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
    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): names DECLARED as locals
    /// (parameters, `let`/`var`/`const`/`:=` bindings, for-binders) inside the
    /// analyzed function, for the languages whose value-position file-level
    /// symbols are suppressed via `imported_type_names` (Go, Python, Rust,
    /// C/C++). A file-level macro/const/import/builtin name is only suppressed
    /// when it is NOT also one of these locals, so a local that shadows such a
    /// name keeps its genuine reads (its store never looks dead). Empty for
    /// other languages. Mirrors the `ts_js_local_names` precedent.
    generic_local_names: HashSet<String>,
    /// fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): the identifiers declared as
    /// NAMED result parameters of the analyzed Go function
    /// (`func f() (handle Handle, ps *Params, tsr bool)`). A *naked* `return`
    /// (no operands) inside such a function implicitly reads every named result,
    /// so a store `tsr = …` followed by a bare `return` is NOT dead. The DFG
    /// emits no `Use` for a naked return, so those stores were flagged dead
    /// (go-httprouter `getValue`: tsr×7, handle×1). At each operand-less Go
    /// `return_statement` we synthesize a `Use` of each name here. Empty for
    /// non-Go functions and for Go functions with unnamed results.
    go_named_results: Vec<String>,
    /// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): names
    /// bound DIRECTLY in the analyzed Lua/Luau function F's OWN lexical scope —
    /// its parameters, `local x = …` declarations, `local function g` names, and
    /// numeric/generic for-loop binders. This is the genuinely-missing
    /// "is-a-local-of-F" binder set for Lua/Luau (the `collect_t5_local_names`
    /// `_ => {}` arm previously built nothing for these languages, so an upvalue
    /// write could not be told apart from a true-local write and was wrongly
    /// flagged dead — luau-roact `createSignal`/`fire` `firing`). Because no
    /// tree-sitter node-kind distinguishes a local re-assignment from an upvalue
    /// or a global write (all are `assignment_statement > variable_list >
    /// identifier`), this set is the fast path for the common case where the
    /// write sits directly in F; the full upvalue/global classification is done
    /// per-write by `is_lua_upvalue_write`, which continues the ancestor walk
    /// past F up to the chunk so a write physically inside a NESTED closure of F
    /// is recognized as an upvalue write even though its name IS a local of F.
    /// Empty for non-Lua/Luau functions.
    lua_local_names: HashSet<String>,
    /// stmt-edge-v1 (R3-r7-cl11-rust-match-arm-cross-variable-dfg, v0.5.0
    /// CLOSEOUT): monotonic id handed to each binding/assignment STATEMENT so
    /// `finalize` can recover the statement-granular, cross-variable flow
    /// dependence (`def(LHS)` depends on every variable USED in the same
    /// statement's RHS — HRB/FOW SDG rule). The id is stamped onto a ref via
    /// `VarRef.group_id`; a fresh id is allocated per binding (per declarator
    /// for multi-declarator `let a = .., b = ..`). 0 until the first statement.
    stmt_counter: u32,
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
            generic_local_names: HashSet::new(),
            go_named_results: Vec::new(),
            lua_local_names: HashSet::new(),
            stmt_counter: 0,
        }
    }

    /// stmt-edge-v1 (R3-r7-cl11): allocate a fresh statement id for the next
    /// binding/assignment. Distinct across the whole function so two unrelated
    /// statements that happen to share a variable name never gain a spurious
    /// cross-statement edge in `finalize`.
    fn next_stmt_id(&mut self) -> u32 {
        let id = self.stmt_counter;
        self.stmt_counter = self.stmt_counter.wrapping_add(1);
        id
    }

    /// stmt-edge-v1 (R3-r7-cl11): process the RHS subtree of ONE
    /// binding/assignment and tag both ends with one statement id so
    /// `finalize` can emit the cross-variable flow-dependence edge
    /// `def(LHS) <- use(RHS-var)` (the dependency a multi-line RHS — Rust
    /// `let bytes = match s { .. value .. }`, an `if/else`, a block tail, or
    /// the C/Go/TS/Python ternary/switch analogues — otherwise drops).
    ///
    /// `def_start` is `self.refs.len()` captured *before* the caller recorded
    /// this statement's LHS definitions, so `refs[def_start..]` are exactly
    /// those LHS defs at entry. We:
    ///   1. stamp the statement id onto those LHS `Definition`/`Update` refs,
    ///   2. run the EXISTING `extract_refs_from_node` recursion on the RHS
    ///      verbatim (so `match`/`if`/block-tail shapes are covered with no
    ///      new dispatch arm), then
    ///   3. stamp the same id onto every `Use` that recursion produced whose
    ///      `group_id` is still `None`.
    ///
    /// The `is_none` guard means a NESTED binding's reads (already stamped with
    /// their own inner id while recursing) are never re-stamped by the outer
    /// statement. No ref's `line` is ever mutated — the edge is line-preserving.
    fn extract_rhs_with_stmt(
        &mut self,
        def_start: usize,
        rhs: Node,
        depth: usize,
    ) -> TldrResult<()> {
        let sid = self.next_stmt_id();
        for r in &mut self.refs[def_start..] {
            if matches!(r.ref_type, RefType::Definition | RefType::Update)
                && r.group_id.is_none()
            {
                r.group_id = Some(sid);
            }
        }
        let rhs_start = self.refs.len();
        self.extract_refs_from_node(rhs, depth + 1)?;
        for r in &mut self.refs[rhs_start..] {
            if r.ref_type == RefType::Use && r.group_id.is_none() {
                r.group_id = Some(sid);
            }
        }
        Ok(())
    }

    /// stmt-edge-v1 (R3-r7-cl11): span variant of [`Self::extract_rhs_with_stmt`]
    /// for handlers whose RHS is NOT a single field node — Kotlin/Swift
    /// `<binders> = <exprs>` (collected in a `found_eq` loop) and Lua
    /// `variable_list = expression_list`. The caller records `def_start`
    /// (refs index before the LHS binders) and `rhs_start` (refs index before
    /// the RHS reads), having already walked both. We stamp one fresh statement
    /// id onto the LHS `Definition`/`Update`s in `[def_start, rhs_start)` and
    /// the `Use`s in `[rhs_start, end)` whose `group_id` is still `None` (so a
    /// nested binding's reads, stamped during recursion, are left untouched).
    fn tag_stmt_span(&mut self, def_start: usize, rhs_start: usize) {
        let end = self.refs.len();
        if def_start >= rhs_start || rhs_start >= end {
            // No LHS def or no RHS read recorded — no cross edge is possible.
            return;
        }
        let sid = self.next_stmt_id();
        for r in &mut self.refs[def_start..rhs_start] {
            if matches!(r.ref_type, RefType::Definition | RefType::Update)
                && r.group_id.is_none()
            {
                r.group_id = Some(sid);
            }
        }
        for r in &mut self.refs[rhs_start..end] {
            if r.ref_type == RefType::Use && r.group_id.is_none() {
                r.group_id = Some(sid);
            }
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
            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): collect local
            // binding names so the file-level macro/const/import/builtin
            // suppression never drops a genuine local read that shadows one of
            // those names.
            //
            // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): C#/Java join the set so that
            // class-FIELD value reads can be suppressed (fields are collected
            // into `imported_type_names`) without ever dropping a genuine local
            // that shadows a field name (`var Power10 = ...` keeps its reads).
            Language::Go
            | Language::Python
            | Language::Rust
            | Language::C
            | Language::Cpp
            | Language::CSharp
            | Language::Java => {
                self.collect_generic_local_names(func_node);
            }
            // rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT):
            // build the genuinely-missing Lua/Luau "is-a-local-of-F" binder set.
            // Q1 (grammar sources) proves no node-kind distinguishes a local
            // re-assignment from an upvalue or a global write — all surface as
            // `assignment_statement > variable_list > identifier` — so the only
            // sound classifier is a lexical binder-resolution pass. This records
            // F's OWN direct bindings (params, `local x`, `local function g`,
            // for-binders), stopping at nested function boundaries so an inner
            // helper's locals are not mis-attributed to F.
            Language::Lua | Language::Luau => {
                let src = self.source;
                collect_lua_scope_bindings(func_node, src, &mut self.lua_local_names);
            }
            _ => {}
        }
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): walk the analyzed
    /// function once and record every name bound as a local (declarator names,
    /// pattern binders, parameter names, short-var / range binders). This is a
    /// SHADOW GUARD only — it does not change which refs are emitted, just which
    /// file-level names may be suppressed. Conservative over-collection is safe:
    /// a name in this set is simply NOT suppressed (treated as a possible local).
    fn collect_generic_local_names(&mut self, node: Node) {
        match node.kind() {
            // C/C++/Java/C#/Go declarators; Rust/JS variable_declarator.
            "init_declarator" | "variable_declarator" => {
                if let Some(d) = node
                    .child_by_field_name("declarator")
                    .or_else(|| node.child_by_field_name("name"))
                {
                    self.insert_generic_local_leaf_names(d);
                }
            }
            // Rust `let pat = ..` / for-binder pattern.
            "let_declaration" | "let_condition" | "for_expression" => {
                if let Some(p) = node.child_by_field_name("pattern") {
                    self.insert_generic_local_leaf_names(p);
                }
            }
            // Go `x := ..` / `x = ..` / `for i, v := range`.
            "short_var_declaration" | "range_clause" => {
                if let Some(l) = node.child_by_field_name("left") {
                    self.insert_generic_local_leaf_names(l);
                }
            }
            // Go `var x T` spec / parameter names across grammars.
            "var_spec" | "parameter_declaration" | "parameter" | "typed_parameter"
            | "default_parameter" => {
                if let Some(n) = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("declarator"))
                {
                    self.insert_generic_local_leaf_names(n);
                }
            }
            // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): C#/Java/Go loop-and-pattern
            // binders that do NOT surface a `variable_declarator`. Now that
            // C#/Java participate in the file-level-name suppression, a binder
            // that COLLIDES with a class field / method / type name must be in
            // the shadow guard so its in-body reads survive (e.g. `foreach (var
            // item ...)` where a field is also named `item`). C# `foreach_statement`
            // exposes the binder as `[left]`; Java `enhanced_for_statement` and Go
            // `for_range_clause` use `[name]`; C# `is T x` patterns
            // (`declaration_pattern`) and `out var x` (`declaration_expression`)
            // bind via `[name]`.
            "foreach_statement" => {
                if let Some(l) = node.child_by_field_name("left") {
                    self.insert_generic_local_leaf_names(l);
                }
            }
            "enhanced_for_statement"
            | "declaration_pattern"
            | "declaration_expression"
            | "for_range_clause" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.insert_generic_local_leaf_names(n);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_generic_local_names(child);
        }
    }

    /// Insert every leaf `identifier` under a binder node into
    /// `generic_local_names`.
    fn insert_generic_local_leaf_names(&mut self, node: Node) {
        if matches!(node.kind(), "identifier" | "shorthand_property_identifier_pattern") {
            if let Ok(t) = node.utf8_text(self.source.as_bytes()) {
                if !t.is_empty() {
                    self.generic_local_names.insert(t.to_string());
                }
            }
            return;
        }
        for child in node.children(&mut node.walk()) {
            self.insert_generic_local_leaf_names(child);
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
            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): the position-based
            // callee/member/type classifier handles `make`/`len`/`str(...)` etc.
            // (callees) and `Type::assoc` (scoped paths), but a value-position
            // READ of a file-level constant / macro / import is structurally
            // indistinguishable from a local read (`SDS_TYPE_MASK` in a
            // `binary_expression`, `stackBufSize` as a call argument, `os` as an
            // attribute object). Such names have no in-function definition and
            // were flagged `definite uninitialized`. Seed language builtins and
            // collect file-level const/macro/import names (below) so the
            // position-independent suppression in `is_use_context` can reject
            // them. A genuine local that shadows one of these still carries its
            // own Definition, so suppression cannot hide a real local read.
            Language::Go => {
                for g in GO_BUILTINS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Python => {
                for g in PYTHON_BUILTINS {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::Rust => {
                for g in RUST_PRELUDE {
                    self.imported_type_names.insert((*g).to_string());
                }
            }
            Language::C | Language::Cpp => {
                // No language-builtin name set (C has no reserved value
                // identifiers worth listing); rely on file-level macro / const
                // collection below.
            }
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
            //
            // fix-CF1-S9: Go ALSO spells its imports `import_declaration`, but its
            // binding is the package name (path tail / alias) carried by each
            // `import_spec`, not a trailing `scoped_identifier`. Exclude Go here so
            // the walk descends into the `import_spec_list` and reaches the Go
            // `import_spec` collector below (this arm would otherwise `continue`
            // past the package bindings, leaving `http` flagged uninitialized).
            if (kind == "import_declaration" && !matches!(self.language, Language::Go))
                || kind == "using_directive"
            {
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
                // fix-CF1-S9: tree-sitter-cpp models a C/C++ class data member as
                // `field_declaration { type, declarator: field_identifier }` (the
                // declarator may be wrapped in pointer_/reference_/array_/init_
                // declarators) — a layout `collect_field_declarator_names` (which
                // expects the Java/C# `variable_declarator`) does not capture. A
                // bare member read in a method body (`fd_`, `_size`) is therefore a
                // value-position identifier with no in-function definition and was
                // flagged definite-uninitialized. Collect the member name so it is
                // classified not-a-use.
                if matches!(self.language, Language::C | Language::Cpp) {
                    self.collect_cpp_member_names(node);
                }
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
            // fix-CF1-S9: a C++ constructor's member-initializer list
            // (`Ctor() : _a(x), _b(y)`) names class fields that are frequently
            // DECLARED CROSS-FILE in the header, so no in-file `field_declaration`
            // exists (e.g. tinyxml2 `_errorID`). The init list is a direct child of
            // the constructor `function_definition`, which the function-boundary
            // skip just below passes over without inspecting. Collect the
            // initialized field names here so a bare member read elsewhere in the
            // translation unit is classified not-a-use rather than
            // definite-uninitialized.
            if matches!(self.language, Language::Cpp) && kind == "function_definition" {
                self.collect_cpp_ctor_init_members(node);
            }
            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): for C/C++/Go/
            // Python/Rust we only want FILE-LEVEL symbols (macros, package
            // consts, imports). These languages previously early-returned before
            // the walk loop, so we must now STOP descending at any function
            // boundary — otherwise we (a) waste time walking every body and
            // (b) would wrongly collect function-LOCAL `const`/`var` names into
            // the file-level suppression set. (The C-family `declaration` /
            // C# `local_variable_declaration` are NOT in this list, so genuine
            // file-scope decls are still visited.)
            if matches!(
                self.language,
                Language::C
                    | Language::Cpp
                    | Language::Go
                    | Language::Python
                    | Language::Rust
            ) && matches!(
                kind,
                "function_definition"
                    | "function_declaration"
                    | "function_item"
                    | "method_declaration"
                    | "closure_expression"
                    | "lambda"
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

            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): collect file-level
            // names that read like locals in value positions but are not.
            //
            // C/C++ preprocessor macros: `#define SDS_TYPE_MASK 7` ->
            // `preproc_def` / `preproc_function_def` with `[name] identifier`.
            if matches!(self.language, Language::C | Language::Cpp)
                && matches!(kind, "preproc_def" | "preproc_function_def")
            {
                if let Some(name) = node.child_by_field_name("name") {
                    if let Ok(t) = name.utf8_text(self.source.as_bytes()) {
                        if !t.is_empty() {
                            self.imported_type_names.insert(t.to_string());
                        }
                    }
                }
                // Macros never enclose function bodies; nothing to descend.
                continue;
            }
            // Go package-level `const_spec` / `var_spec` names (only at file
            // scope — a const inside a function is a genuine local).
            if matches!(self.language, Language::Go)
                && is_file_level
                && matches!(kind, "const_spec" | "var_spec")
            {
                if let Some(name) = node.child_by_field_name("name") {
                    self.insert_identifier_names(name);
                }
            }
            // fix-CF1-S9: Go import package bindings. `import "net/http"` binds the
            // package name `http` (last `/` segment of the path); `import foo "x/y"`
            // binds the alias `foo`. A bare package qualifier — the `operand` of a
            // `selector_expression` such as `http.StatusOK` — is a compile-time
            // package reference, never a local read, but had no in-function
            // definition and was flagged definite-uninitialized. Collect the
            // binding name (mirrors the Python/TS import collectors). Blank (`_`)
            // and dot (`.`) imports introduce no usable qualifier.
            if matches!(self.language, Language::Go) && kind == "import_spec" {
                if let Some(name) = go_import_binding_name(node, self.source) {
                    if name != "_" && name != "." && !name.is_empty() {
                        self.imported_type_names.insert(name);
                    }
                }
                continue;
            }
            // fix-CF1-S9: C/C++ file-scope global variable. `int g_count;` /
            // `static Foo* g = ...;` parses as a file-level `declaration` whose
            // declarator resolves to a plain `identifier` (possibly behind
            // pointer/reference/array/init wrappers). A read of such a global inside
            // a function body is structurally identical to a local read but has no
            // in-function definition, so it was flagged definite-uninitialized.
            // Collect the global name (function PROTOTYPES, whose declarator is a
            // `function_declarator`, yield no plain-identifier leaf and are skipped).
            if matches!(self.language, Language::C | Language::Cpp)
                && is_file_level
                && kind == "declaration"
            {
                self.collect_cpp_global_decl_names(node);
            }
            // Python import bindings: `import os` / `import sys as system` /
            // `from a.b import c, d as e`.
            if matches!(self.language, Language::Python)
                && matches!(kind, "import_statement" | "import_from_statement")
            {
                self.collect_python_import_bindings(node);
                continue;
            }

            for child in node.children(&mut node.walk()) {
                stack.push((child, is_file_level));
            }
        }
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): insert every leaf
    /// `identifier` under `node` into `imported_type_names` (handles a single
    /// identifier or a Go `expression_list` of const names).
    fn insert_identifier_names(&mut self, node: Node) {
        if node.kind() == "identifier" {
            if let Ok(t) = node.utf8_text(self.source.as_bytes()) {
                if !t.is_empty() {
                    self.imported_type_names.insert(t.to_string());
                }
            }
            return;
        }
        for child in node.children(&mut node.walk()) {
            self.insert_identifier_names(child);
        }
    }

    /// fix-CF1-S9: collect the member name(s) declared by a C/C++ class
    /// `field_declaration`. The declarator is a `field_identifier`, optionally
    /// wrapped in `pointer_declarator` / `reference_declarator` / `array_declarator`
    /// / `init_declarator`. Only the declared NAME is collected (via the
    /// `declarator` chain) — never an initializer/bitfield expression, which lives
    /// under the `value`/size children and is not on that chain.
    fn collect_cpp_member_names(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(
                child.kind(),
                "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "init_declarator"
            ) {
                if let Some(name) = cpp_declarator_leaf_name(child, self.source) {
                    self.imported_type_names.insert(name);
                }
            }
        }
    }

    /// fix-CF1-S9: collect the global variable name(s) declared by a C/C++
    /// file-scope `declaration`. Same declarator-unwrapping as
    /// `collect_cpp_member_names`, but the leaf is a plain `identifier`. A
    /// `function_declarator` declarator (a prototype) has no plain-identifier leaf
    /// on its `declarator` chain and so is skipped.
    fn collect_cpp_global_decl_names(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(
                child.kind(),
                "identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "init_declarator"
            ) {
                if let Some(name) = cpp_declarator_leaf_name(child, self.source) {
                    self.imported_type_names.insert(name);
                }
            }
        }
    }

    /// fix-CF1-S9: collect the field names initialized in a C++ constructor's
    /// member-initializer list. Shape:
    /// ```text
    /// function_definition
    ///   ... (field_initializer_list
    ///          (field_initializer (field_identifier) (argument_list ...)) ...)
    /// ```
    /// Only each `field_initializer`'s `field_identifier` (the member name) is
    /// collected; the `argument_list` holds constructor-parameter reads, which are
    /// genuine locals and must not be suppressed.
    fn collect_cpp_ctor_init_members(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "field_initializer_list" {
                continue;
            }
            let mut c2 = child.walk();
            for fi in child.children(&mut c2) {
                if fi.kind() != "field_initializer" {
                    continue;
                }
                let mut c3 = fi.walk();
                for g in fi.children(&mut c3) {
                    if g.kind() == "field_identifier" {
                        if let Ok(t) = g.utf8_text(self.source.as_bytes()) {
                            if !t.is_empty() {
                                self.imported_type_names.insert(t.to_string());
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): collect the LOCAL binding
    /// names introduced by a Python `import` / `from ... import`. The bound name
    /// is the alias when present, else the FIRST segment of `import a.b.c` (`a`)
    /// or the imported name for `from m import x`.
    fn collect_python_import_bindings(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                // `import a.b.c` -> binds `a`; `from m import name` -> `name`.
                "dotted_name" => {
                    if let Some(first) = child.child(0) {
                        if first.kind() == "identifier" {
                            if let Ok(t) = first.utf8_text(self.source.as_bytes()) {
                                if !t.is_empty() {
                                    self.imported_type_names.insert(t.to_string());
                                }
                            }
                        }
                    }
                }
                // `import x as y` / `from m import x as y` -> binds the alias.
                "aliased_import" => {
                    if let Some(alias) = child.child_by_field_name("alias") {
                        if let Ok(t) = alias.utf8_text(self.source.as_bytes()) {
                            if !t.is_empty() {
                                self.imported_type_names.insert(t.to_string());
                            }
                        }
                    }
                }
                _ => {}
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
            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): a C/C++ function
            // RETURNING A POINTER/REFERENCE nests its `function_declarator`
            // (which holds the `parameters` field) inside the return-type
            // `pointer_declarator` / `reference_declarator`:
            //   function_definition
            //     [declarator] pointer_declarator        <- return-type `*`
            //       [declarator] function_declarator     <- has [parameters]
            // The pre-fix lookup read `declarator.parameters` directly, found
            // none on the `pointer_declarator`, and dropped EVERY parameter
            // (`const char* GetCharacterRef(const char* p, ...)` lost `p`), so
            // each param read was flagged `definite uninitialized`. Descend
            // through any pointer/reference wrappers to the `function_declarator`
            // before reading `parameters`.
            Language::C | Language::Cpp => func_node
                .child_by_field_name("declarator")
                .and_then(|d| Self::c_cpp_function_declarator(d))
                .and_then(|fd| fd.child_by_field_name("parameters")),
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

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): descend through any
    /// return-type `pointer_declarator` / `reference_declarator` wrappers to the
    /// `function_declarator` that actually carries the `parameters` field.
    /// Returns `node` itself when it is already a `function_declarator`.
    fn c_cpp_function_declarator(node: Node<'_>) -> Option<Node<'_>> {
        match node.kind() {
            "function_declarator" => Some(node),
            "pointer_declarator" | "reference_declarator" => node
                .child_by_field_name("declarator")
                .and_then(Self::c_cpp_function_declarator),
            _ => None,
        }
    }

    /// C1-gen-bindings (v0.5.0 BACKLOG): peel `pointer_declarator` /
    /// `array_declarator` (and nested combinations like `int **pp` /
    /// `char buf[16][8]`) down to the declared `identifier` by following the
    /// `declarator` field. Using the field — never a blind identifier search —
    /// means an array *size* identifier (`long arr[N];`) is correctly ignored:
    /// `N` lives in the `size` field, not `declarator`.
    fn c_declared_identifier(node: Node<'_>) -> Option<Node<'_>> {
        match node.kind() {
            "identifier" => Some(node),
            "pointer_declarator" | "array_declarator" | "parenthesized_declarator" => node
                .child_by_field_name("declarator")
                .and_then(Self::c_declared_identifier),
            _ => None,
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

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT): like `add_ref_from_node` but
    /// tags the ref with a `VarRefContext`. Used to mark closure / lambda /
    /// comprehension BINDERS so the uninitialized detector can treat them as
    /// micro-scoped, self-initializing bindings (their value comes from the
    /// closure call / comprehension iterator, not a prior reaching def).
    fn add_ref_with_context(&mut self, node: Node, ref_type: RefType, context: VarRefContext) {
        let name = node
            .utf8_text(self.source.as_bytes())
            .unwrap_or("")
            .to_string();
        if name.is_empty() || is_keyword(&name, self.language) {
            return;
        }
        let line = node.start_position().row as u32 + 1;
        let column = node.start_position().column as u32;
        self.variables.insert(name.clone());
        self.refs.push(VarRef {
            name,
            ref_type,
            line,
            column,
            context: Some(context),
            group_id: None,
        });
    }

    /// fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): record a `Use` of `name`
    /// at `line` that has no backing AST node — used to model the IMPLICIT read
    /// of a Go function's named results at a naked `return`. Column 0 is a
    /// sentinel (the read is not at a specific token). Only emitted for names
    /// the caller has already validated (the function's own named results), so
    /// this never invents a use of an unrelated identifier.
    fn add_synthetic_use(&mut self, name: &str, line: usize) {
        if name.is_empty() {
            return;
        }
        self.variables.insert(name.to_string());
        self.refs.push(VarRef {
            name: name.to_string(),
            ref_type: RefType::Use,
            line: line as u32,
            column: 0,
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
            // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): PHP statement-level static
            // variable declaration `static $x = ...;`.
            // Shape (verified by debug-parse):
            //   function_static_declaration
            //     static
            //     static_variable_declaration [name] variable_name ( = <value> )?
            //     (',' static_variable_declaration)*
            // Each declared `$x` is a function-local persistent binding; its
            // `variable_name` was only ever classified as a USE (it falls to the
            // default recurse arm), so reads of `$timeFormats` were flagged
            // definite-uninitialized (php-symfony-console `formatTime`). Register
            // each declared variable as a Definition and recurse into any
            // initializer for uses.
            // =================================================================
            "function_static_declaration" if matches!(self.language, Language::Php) => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "static_variable_declaration" {
                        if let Some(name) = child.child_by_field_name("name") {
                            if name.kind() == "variable_name" {
                                self.add_ref_from_node(name, RefType::Definition);
                            }
                        }
                        // The initializer (`= [...]`) is a value field whose
                        // identifiers are genuine uses.
                        if let Some(value) = child.child_by_field_name("value") {
                            self.extract_refs_from_node(value, depth + 1)?;
                        }
                    }
                }
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
            // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): a Go function-LOCAL `const`
            // declaration shares the `const_spec` shape with `var_spec`; route it
            // through the same handler so its bound name becomes a Definition.
            // (Package-level consts are pre-collected by `collect_imports`; this
            // arm only fires for declarations reached inside a function body.)
            "const_declaration" if matches!(self.language, Language::Go) => {
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

            // fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): a Go `return_statement`
            // needs special handling — a NAKED return implicitly reads the
            // function's named results. Other languages fall through to the
            // generic recursion below (their `return_statement` operands are
            // ordinary `identifier`/expression children already picked up as
            // uses), so this arm is Go-only and preserves all other behavior.
            "return_statement" if matches!(self.language, Language::Go) => {
                self.process_go_return(node, depth)?;
            }

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
            // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): Elixir `stab_clause` —
            // a `pattern -> body` arm of `case` / `fn` / `with` / `try`.
            // Shape (verified by debug-parse):
            //   stab_clause [left] arguments( <pattern> ) -> [right] body( <expr> )
            // The `[left]` arguments hold a PATTERN that BINDS variables
            // (`{:ok, cb} ->` binds `cb`); those bindings were never recorded as
            // Definitions, so reads of `cb` in the clause body were flagged
            // definite-uninitialized (elixir-phoenix `allow_jsonp`). Register the
            // pattern's bound (lower-case) identifiers as Definitions, then
            // recurse into the body for uses.
            // =================================================================
            "stab_clause" if matches!(self.language, Language::Elixir) => {
                if let Some(left) = node.child_by_field_name("left") {
                    self.extract_elixir_pattern_bindings(left);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    self.extract_refs_from_node(right, depth + 1)?;
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

            // C1-gen-bindings (v0.5.0 BACKLOG): every OCaml binding occurrence
            // is a `value_pattern` leaf — a `fun ~dir xs -> …` parameter
            // (including the labeled `~dir`), a `match` / `function` arm binder
            // (`Some y -> …`), and the leaves of destructuring `let` / tuple /
            // record patterns. Top-level `let` parameters are bound out-of-body
            // by `extract_ocaml_parameters` (they are siblings of the traversed
            // body, never revisited here), but a `fun`'s OWN parameters and
            // every match-arm binder live INSIDE the body and were never added
            // to GEN — so their reads were flagged definite-uninitialized.
            // Registering the `value_pattern` as a strong Definition closes that
            // without a generic identifier visitor: a plain OCaml value read is a
            // `value_path`/`value_name`, not a `value_pattern`, so uses are
            // untouched.
            "value_pattern" if matches!(self.language, Language::Ocaml) => {
                self.add_ref_from_node(node, RefType::Definition);
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
                // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): C# and Java
                // C-style `for (T i = 0; ...; ...)` expose the loop binding in
                // an `[initializer]` (C#) / `[init]` (Java) declaration field —
                // NOT the `left`/`right` fields the Python handler reads. The
                // pre-fix `_ => process_for_loop` arm dropped the `int i = 0`
                // declarator entirely, so every body read of `i` was flagged
                // `definite uninitialized`. Route to a shape-aware handler that
                // recurses into the declaration field (where the existing
                // `variable_declaration` / `local_variable_declaration` arms
                // record `i` as a Definition) plus condition/update/body.
                Language::CSharp | Language::Java => {
                    self.process_csharp_java_for_statement(node, depth)?
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
                // fix-R7 (cluster[11] RC4): Kotlin `for (x in iterable) body`
                // reuses the `for_statement` kind but exposes its parts as
                // POSITIONAL children (`variable_declaration` loop binder, the
                // iterable expression after `in`, and a `block`/
                // `control_structure_body`) — NONE with the `left`/`right`/`body`
                // fields the Python handler reads. The campaign added shape-aware
                // arms for Go/C/Java/Lua but left Kotlin on this broken
                // fallthrough, so the loop variable, the iterable read, AND the
                // entire loop body (loop-carried reassignments) were dropped.
                Language::Kotlin => self.process_kotlin_for_statement(node, depth)?,
                // fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): PHP / JS / TS /
                // Solidity all reuse the `for_statement` kind for a C-style
                // `for (init; cond; update) body` whose clauses are named
                // FIELDS (initialize/initializer/initial, condition,
                // update/increment, body) — NOT the `left`/`right` the Python
                // handler reads. The pre-fix `_ => process_for_loop` arm dropped
                // every header use, so a variable read only in the init/cond
                // (`for ($i = $column; $i < $column + $n; ...)`) was reported as
                // a dead store. Route through the loop-descriptor registry.
                Language::Php
                | Language::JavaScript
                | Language::TypeScript
                | Language::Solidity => self.process_loop_header(node, depth)?,
                _ => self.process_for_loop(node, depth)?,
            },

            // Python/JS: for x in items / for (x in obj)
            "for_in_statement" => {
                self.process_for_loop(node, depth)?;
            }

            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Python
            // comprehensions / generator expressions bind their loop variable
            // in a `for_in_clause` (`[left]` binder, `[right]` iterable). The
            // binder is a DEFINITION whose scope is the comprehension body; the
            // body reads it (`h` in `[h for h in items if h]`). Without
            // recording the binder as a def, every body read of `h` had no
            // reaching definition and was flagged `definite uninitialized`.
            "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression"
                if matches!(self.language, Language::Python) =>
            {
                self.process_python_comprehension(node, depth)?;
            }

            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC4 mitigation): a Python
            // NESTED function definition inside the analyzed function body. The
            // intraprocedural analysis flattens it into the outer CFG, so (a) the
            // nested function NAME (`def get_proxy`) was misclassified as a
            // variable use and (b) the nested function's PARAMETERS (`key`) were
            // never recorded as definitions — both flagged `definite
            // uninitialized`. Record the name as a Definition and each parameter
            // as a `ClosureParam`-scoped (pre-initialized) Definition, then
            // analyze the nested body. (The principled per-function sub-CFG is a
            // design-fork; this is the reaudit's recommended low-risk mitigation.)
            "function_definition" if matches!(self.language, Language::Python) => {
                self.process_python_nested_function(node, depth)?;
            }

            // Python `lambda x: expr` — the lambda parameters are micro-scoped
            // bindings; record them as `ClosureParam` defs so body reads are not
            // flagged, then analyze the lambda body.
            "lambda" if matches!(self.language, Language::Python) => {
                self.process_python_lambda(node, depth)?;
            }

            // Rust: `for x in items { }` — `[pattern]`/`[value]`/`[body]`.
            //
            // fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): Scala REUSES the
            // `for_expression` kind for its for-comprehension
            // (`for (x <- xs if g) body` / `for { ... } yield ...`), but exposes
            // an `[enumerators]` field (binder `<-` iterable + `guard`) plus
            // `[body]` — NONE of the `pattern`/`value` fields `process_rust_for`
            // reads. Routing Scala through the Rust handler dropped the
            // iterable and guard reads (a `val` used only in a guard was a false
            // dead store) and left the binder undefined. Route Scala to the
            // loop-descriptor registry; keep Rust on its shape-aware handler.
            "for_expression" => match self.language {
                Language::Scala => self.process_loop_header(node, depth)?,
                _ => self.process_rust_for(node, depth)?,
            },

            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Rust closure
            // `|a, &b| body`. The closure parameters are bindings local to the
            // closure body; without recording them as Definitions, body reads of
            // `b`/`e` (ripgrep `parse_human_readable_size`'s `take_while(|&b|
            // b...)` and `map_err(|e| ...)`) had no reaching def and were
            // flagged `definite uninitialized`. Record each binder identifier
            // (through `reference_pattern` / `mut_pattern` / tuple wrappers) as a
            // Definition, then analyze the body.
            "closure_expression" if matches!(self.language, Language::Rust) => {
                self.process_rust_closure(node, depth)?;
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

            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): Ruby block
            // parameters `do |k, v|` / `{ |k, v| ... }`. tree-sitter-ruby emits
            // a `block_parameters` node (`|k, v|`) whose identifier children are
            // the block-local bindings. They were never recorded as Definitions
            // (only `collect_ruby_local_names` saw them, which merely prevents
            // them being misread as method calls), so every body read of `k`/`v`
            // was flagged `definite uninitialized`. Record each binder as a
            // Definition. (Encountered while recursing into `do_block`/`block`.)
            "block_parameters" if matches!(self.language, Language::Ruby) => {
                self.process_ruby_block_parameters(node)?;
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
        // stmt-edge-v1 (R3-r7-cl11): Python/Ruby `bytes = value*2 if c else value`.
        let def_start = self.refs.len();
        // assignment has "left" and "right" fields
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_assignment_targets(left)?;
        }

        // Process the right side for uses
        if let Some(right) = node.child_by_field_name("right") {
            self.extract_rhs_with_stmt(def_start, right, depth)?;
        }

        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): record Ruby block
    /// parameters (`|k, v|`, including splats / optionals / destructured /
    /// keyword params) as Definitions. Mirrors the structural cases handled by
    /// `collect_ruby_assignment_target_names` but emits a `RefType::Definition`
    /// VarRef for each binder identifier.
    fn process_ruby_block_parameters(&mut self, node: Node) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.add_ruby_binder_defs(child);
        }
        Ok(())
    }

    /// Recursive helper for `process_ruby_block_parameters`: emit a Definition
    /// for every binder identifier inside a Ruby parameter node.
    fn add_ruby_binder_defs(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                self.add_ref_from_node(node, RefType::Definition);
            }
            "splat_parameter"
            | "block_parameter"
            | "optional_parameter"
            | "keyword_parameter"
            | "destructured_parameter"
            | "rest_assignment" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.add_ruby_binder_defs(child);
                }
            }
            _ => {}
        }
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
            //
            // C1-gen-bindings (v0.5.0 BACKLOG): Ruby parallel / multiple
            // assignment LHS — `a, _ = …`, `a, *rest = …`, `(x, y), z = …`.
            // tree-sitter-ruby wraps the comma-separated binders in a
            // `left_assignment_list`; a `*rest` splat is a `rest_assignment`
            // and a nested `(x, y)` is a `destructured_left_assignment`. Recurse
            // so each inner `identifier` registers as a Definition (the leading
            // `_` binds harmlessly; commas / parens / `*` are non-identifier
            // tokens that fall through). Without these arms the multiple-
            // assignment targets never entered GEN, so every later read was
            // flagged definite-uninitialized ("no definition of this variable
            // exists").
            "tuple" | "list" | "pattern_list" | "left_assignment_list"
            | "destructured_left_assignment" | "rest_assignment" => {
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
                        // rc3: field write `x.attr = …` is a WEAK (non-killing)
                        // update of the container — it does not rebind `x`.
                        self.add_ref_from_node(obj, RefType::WeakUpdate);
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
                        // rc3: field write `x.field = …` — weak (non-killing).
                        self.add_ref_from_node(obj_inner, RefType::WeakUpdate);
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
                        // rc3: Go field write `x.field = …` — weak (non-killing).
                        self.add_ref_from_node(operand, RefType::WeakUpdate);
                    }
                }
            }
            // Rust: x.field = ...
            "field_expression" => {
                if let Some(value) = target.child_by_field_name("value") {
                    if value.kind() == "identifier" {
                        // rc3: Rust field write `x.field = …` — weak (non-killing).
                        self.add_ref_from_node(value, RefType::WeakUpdate);
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
                        // rc3: element write `a[i] = …` — weak (non-killing).
                        self.add_ref_from_node(base_inner, RefType::WeakUpdate);
                    } else {
                        // Nested array_access / member_expression — recurse
                        // so the outermost identifier gets the (weak) update.
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
                // rc3: element write `container[index] = …` is a WEAK
                // (non-killing) update — it reads + may-modify the contents but
                // does not rebind `container`.
                self.add_ref_from_node(container, RefType::WeakUpdate);
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
                // rc3: element write — weak (non-killing) update of container.
                self.add_ref_from_node(container, RefType::WeakUpdate);
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
        // stmt-edge-v1 (R3-r7-cl11): see `extract_rhs_with_stmt`.
        let def_start = self.refs.len();
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
            } else {
                // rc3: compound element/field write `xs[i] += …`, `p.f += …`.
                // The LHS is a subscript/member node, not a bare identifier, so
                // route through the assignment-target dispatcher — the container
                // registers as a WeakUpdate (non-killing) and the index vars as
                // uses, exactly like the plain `xs[i] = …` case.
                self.extract_assignment_targets(left)?;
            }
        }

        // The right side contains uses
        if let Some(right) = node.child_by_field_name("right") {
            // stmt-edge-v1 (R3-r7-cl11): the LHS self-read `Use` stays in the
            // def span, so only the RHS reads link to `def(x)`.
            self.extract_rhs_with_stmt(def_start, right, 0)?;
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

    /// fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): generic loop-HEADER driver.
    ///
    /// Consumes the [`LoopHeader`] descriptor returned by
    /// [`loop_header_descriptor`] for the current `(language, node-kind)` and
    /// records the loop's header binders (Definitions) and use-sites
    /// (iterable / init RHS / condition / update / guard reads, all Uses) plus
    /// its body — every site flowing through the normal dispatch so each
    /// construct's existing def/use classification is reused. This is the
    /// single extension point for the loop-header-use symptom class: adding the
    /// next language is one row in the registry, not a new bespoke method.
    ///
    /// Several grammars route their `for`/`foreach`/for-comprehension node to a
    /// shape that the legacy Python-shaped `process_for_loop` cannot read (no
    /// `left`/`right`/`body` fields), silently dropping every header use — so a
    /// variable used ONLY in a loop header was reported as a dead store and a
    /// binder read in the body as definite-uninitialized.
    fn process_loop_header(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let Some(desc) = loop_header_descriptor(self.language, node.kind()) else {
            // Defensive: an unregistered shape — recurse all named children so
            // nothing is silently dropped.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
            return Ok(());
        };
        match desc {
            // C-style `for (init; cond; update) body`: the init is processed by
            // `process_loop_init` (binder def + RHS uses); the update by
            // `process_loop_update` (loop var as a read, not a fresh version);
            // the condition and body are recursed through normal dispatch so
            // their identifier reads become uses.
            LoopHeader::CStyle {
                init_field,
                cond_field,
                update_field,
                body_field,
            } => {
                if let Some(init) = node.child_by_field_name(init_field) {
                    self.process_loop_init(init, depth)?;
                }
                if let Some(cond) = node.child_by_field_name(cond_field) {
                    self.extract_refs_from_node(cond, depth + 1)?;
                }
                if let Some(update) = node.child_by_field_name(update_field) {
                    self.process_loop_update(update, depth)?;
                }
                if let Some(body) = node.child_by_field_name(body_field) {
                    self.extract_refs_from_node(body, depth + 1)?;
                }
            }
            // PHP `foreach (<iterable> as <binder>) body`.
            LoopHeader::ForeachAs => {
                self.process_foreach_as_header(node, depth)?;
                if let Some(body) = node.child_by_field_name("body") {
                    self.extract_refs_from_node(body, depth + 1)?;
                }
            }
            // Scala `for (<enumerators>) body`. The enumerators node is located
            // by KIND (its field name collides with the `(` `)` tokens).
            LoopHeader::Comprehension {
                enumerators_kind,
                body_fields,
            } => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == enumerators_kind {
                        self.process_comprehension_enumerators(child, depth)?;
                    }
                }
                for field in body_fields {
                    if let Some(child) = node.child_by_field_name(field) {
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: process a C-style for-loop INITIALIZER
    /// (`$i = $start`, `let i = n`, `uint i = n`).
    ///
    /// The initializer is recursed through the normal dispatch so each
    /// language's own assignment / declaration handling records the
    /// loop-variable binder as a Definition and the init RHS as uses. The
    /// binder Definition(s) just recorded are then re-tagged `ComprehensionScope`
    /// (pre-initialized) — the loop variable's value is supplied by the loop on
    /// every iteration, and the intraprocedural CFG over-segments the single
    /// `for (...)` header line so a plain def on that line does not reliably
    /// reach the condition/body reads. This mirrors the mitigation already used
    /// for C#/Java for-binders and comprehension binders, and is uniform across
    /// every C-style grammar (no per-language binder parsing). Only Definitions
    /// freshly added by THIS init (and not already context-tagged) are touched,
    /// so the init RHS uses are left untouched.
    fn process_loop_init(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let pre = self.refs.len();
        self.extract_refs_from_node(node, depth + 1)?;
        for r in self.refs[pre..].iter_mut() {
            if r.ref_type == RefType::Definition && r.context.is_none() {
                r.context = Some(VarRefContext::ComprehensionScope);
            }
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: process a C-style for-loop UPDATE clause
    /// (`++$i`, `$i++`, comma-separated `$i++, $j--`).
    ///
    /// The loop variable is recorded as a USE (a read of the current value)
    /// rather than an `Update` (read-then-write that mints a fresh SSA
    /// version). Modelling the update as a new version — while the
    /// intraprocedural CFG collapses the init, condition and update onto the
    /// single `for (...)` header line and never splits the init into a
    /// preheader — makes the loop's INIT assignment (`$i = $start`) look like a
    /// dead store. C / JS / Java for-loops never exhibit this because their
    /// `i++` falls through to the identifier-as-use arm; PHP / Solidity have a
    /// dedicated `update_expression` arm that emits `Update`. Treating the
    /// header update as a read restores parity and keeps the loop variable a
    /// single live value across the header. (Standalone `$n++;` statements
    /// outside a for-update still flow through the normal arm and remain an
    /// Update, preserving the M-114 reaching-defs fix.)
    fn process_loop_update(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        match node.kind() {
            "update_expression" => {
                if let Some(arg) = node.child_by_field_name("argument") {
                    self.record_loop_update_operand(arg, depth)?;
                }
            }
            // `$i++, $j--` — comma-separated updates.
            "comma_expression" | "sequence_expression" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.is_named() {
                        self.process_loop_update(child, depth)?;
                    }
                }
            }
            // Other update forms (`$i += 1`, `$i = $i + 1`) — recurse normally.
            _ => self.extract_refs_from_node(node, depth + 1)?,
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: record a for-loop update operand as a Use.
    /// Handles a bare `variable_name` / `identifier` and Solidity's
    /// `expression`-wrapped identifier; anything else (subscript / member
    /// targets) is recursed for its nested uses.
    fn record_loop_update_operand(&mut self, arg: Node, depth: usize) -> TldrResult<()> {
        match arg.kind() {
            "variable_name" | "identifier" => self.add_ref_from_node(arg, RefType::Use),
            "expression" if matches!(self.language, Language::Solidity) => {
                if let Some(inner) = solidity_unwrap_expression(arg) {
                    self.record_loop_update_operand(inner, depth)?;
                }
            }
            _ => self.extract_refs_from_node(arg, depth + 1)?,
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: PHP `foreach (<iterable> as [<key> =>] <value>)`.
    ///
    /// The iterable is the loop's direct named child(ren) BEFORE the `as`
    /// token — recorded as Uses through normal dispatch. The binder is the
    /// child AFTER `as` (`variable_name`, a `pair` `$k => $v`, a `by_ref`
    /// `&$v`, or a `list_literal` destructuring) — every leaf `variable_name`
    /// recorded as a Definition. The `[body]` field is skipped here (the caller
    /// processes it) so its reads are never mistaken for binders.
    fn process_foreach_as_header(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let body_id = node.child_by_field_name("body").map(|b| b.id());
        let mut cursor = node.walk();
        let mut seen_as = false;
        for child in node.children(&mut cursor) {
            if Some(child.id()) == body_id {
                continue; // body handled by the caller
            }
            if child.kind() == "as" {
                seen_as = true;
                continue;
            }
            if !child.is_named() {
                continue; // 'foreach' '(' ')' tokens
            }
            if seen_as {
                self.add_foreach_binder_defs(child);
            } else {
                // The iterated expression — a Use.
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: record the binder name(s) of a PHP foreach value
    /// position as Definitions. Handles `variable_name` (`$v`), `pair`
    /// (`$k => $v`), `by_ref` (`&$v`), and `list_literal` destructuring. The
    /// binder is tagged `ComprehensionScope` (its value is supplied by the
    /// iterator each iteration) so a body / nested-loop-header read of it is not
    /// flagged definite-uninitialized despite CFG over-segmentation.
    fn add_foreach_binder_defs(&mut self, node: Node) {
        match node.kind() {
            "variable_name" => self.add_ref_with_context(
                node,
                RefType::Definition,
                VarRefContext::ComprehensionScope,
            ),
            "pair" | "by_ref" | "list_literal" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.add_foreach_binder_defs(child);
                }
            }
            _ => {}
        }
    }

    /// fix-PW3-C2c-loopheader: Scala for-comprehension enumerators.
    ///
    /// The `[enumerators]` field holds one or more `enumerator` nodes, each
    /// `<binder> (<- | =) <iterable> [guard...]`. Each enumerator is processed
    /// so its pre-operator binder becomes a loop-scoped Definition and its
    /// iterable + guard filters become Uses.
    fn process_comprehension_enumerators(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "enumerator" {
                self.process_scala_enumerator(child, depth)?;
            } else if child.is_named() {
                // Defensive: an unexpected named child — recurse as a use.
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    /// fix-PW3-C2c-loopheader: a single Scala `enumerator`
    /// (`x <- xs`, `(a, b) <- pairs`, `y = f(x)`, optionally `if guard`).
    /// Children BEFORE the first `<-`/`=` operator are the loop binder
    /// (recorded as `ComprehensionScope`-tagged Definitions — iterator-
    /// initialized, like Python comprehension / C#-Java for binders); children
    /// AFTER it (the iterable plus any `guard`) are recursed as Uses.
    fn process_scala_enumerator(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        let mut past_op = false;
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if !past_op && (kind == "<-" || kind == "=") {
                past_op = true;
                continue;
            }
            if !child.is_named() {
                continue;
            }
            if past_op {
                self.extract_refs_from_node(child, depth + 1)?;
            } else {
                self.add_comprehension_binder_defs(child);
            }
        }
        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Python comprehension /
    /// generator-expression handler.
    ///
    /// Shape (verified by debug-parse): the container holds a `[body]`
    /// expression plus one or more `for_in_clause` children, each with a
    /// `[left]` binder and `[right]` iterable, optionally followed by
    /// `if_clause` filters. The binder is a Definition; the iterable, body and
    /// filters are uses. We record the binders FIRST so that body/filter reads
    /// of them resolve to a reaching definition (the binders precede the body
    /// textually, so line ordering in the analyzer is satisfied).
    fn process_python_comprehension(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // First pass: record every for_in_clause binder as a definition,
        // tagged ComprehensionScope so the uninit detector treats it as a
        // self-initializing micro-scoped binding (its value comes from the
        // iterator, not a prior reaching def on the same line).
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "for_in_clause" {
                if let Some(left) = child.child_by_field_name("left") {
                    self.add_comprehension_binder_defs(left);
                }
            }
        }
        // Second pass: process iterables, filters and the body as uses.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "for_in_clause" => {
                    // Only the iterable (`[right]`) is a use here; the binder
                    // was handled above and is suppressed by
                    // `generic_non_use_position`.
                    if let Some(right) = child.child_by_field_name("right") {
                        self.extract_refs_from_node(right, depth + 1)?;
                    }
                }
                _ => {
                    // `[body]` expression and `if_clause` filters.
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC4 mitigation): handle a
    /// Python NESTED function definition. Records the function name as a
    /// Definition (so callers/self-refs are not flagged), each parameter as a
    /// `ClosureParam`-scoped Definition (pre-initialized), then analyzes the
    /// body.
    fn process_python_nested_function(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(name) = node.child_by_field_name("name") {
            if name.kind() == "identifier" {
                self.add_ref_from_node(name, RefType::Definition);
            }
        }
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                self.add_python_param_scoped(child);
            }
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC4 mitigation): Python
    /// `lambda params: body`. Records lambda parameters as `ClosureParam`-scoped
    /// Definitions, then analyzes the body.
    fn process_python_lambda(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                self.add_python_param_scoped(child);
            }
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    /// Record a Python parameter node (identifier / typed / default /
    /// splat) as a `ClosureParam`-scoped Definition.
    fn add_python_param_scoped(&mut self, child: Node) {
        match child.kind() {
            "identifier" => {
                self.add_ref_with_context(child, RefType::Definition, VarRefContext::ClosureParam);
            }
            "typed_parameter" | "default_parameter" | "typed_default_parameter"
            | "list_splat_pattern" | "dictionary_splat_pattern" => {
                if let Some(name) = child.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        self.add_ref_with_context(
                            name,
                            RefType::Definition,
                            VarRefContext::ClosureParam,
                        );
                        return;
                    }
                }
                if let Some(id) = first_child_of_kind(child, "identifier") {
                    self.add_ref_with_context(id, RefType::Definition, VarRefContext::ClosureParam);
                }
            }
            _ => {}
        }
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT): record every leaf identifier
    /// of a Python comprehension binder (`x`, or `k, v` / `(a, b)` tuples) as a
    /// `ComprehensionScope`-tagged Definition.
    fn add_comprehension_binder_defs(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                self.add_ref_with_context(
                    node,
                    RefType::Definition,
                    VarRefContext::ComprehensionScope,
                );
            }
            "tuple" | "list" | "pattern_list" | "tuple_pattern" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.add_comprehension_binder_defs(child);
                }
            }
            _ => {}
        }
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

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2): C#/Java C-style
    /// `for_statement`. Grammars differ in the init field name:
    ///   * C#   uses `[initializer]` (a `variable_declaration`).
    ///   * Java uses `[init]` (a `local_variable_declaration`).
    /// Both expose `[condition]` / `[update]` / `[body]`. Recurse into whichever
    /// init field is present (the inner declaration arm records the loop-var
    /// definition) plus the rest. Falls back to recursing every named child so
    /// any positional update expressions are still analyzed.
    fn process_csharp_java_for_statement(
        &mut self,
        node: Node,
        depth: usize,
    ) -> TldrResult<()> {
        // The init declaration's binder (`int i = 0`) is the loop variable.
        // Record it with a loop-scope context (treated as pre-initialized by the
        // uninit detector) AND recurse the init for any RHS uses. The CFG
        // over-segments the single `for (...)` line into overlapping blocks, so
        // a plain def of `i` on that line does not reliably reach the
        // condition/body reads — tagging it avoids the residual FP. (RC4
        // mitigation; same approach as closures/comprehensions.)
        let init = node
            .child_by_field_name("initializer")
            .or_else(|| node.child_by_field_name("init"));
        if let Some(init) = init {
            self.process_for_init_declaration(init, depth)?;
        }
        for field in ["condition", "update", "body"] {
            if let Some(child) = node.child_by_field_name(field) {
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        if init.is_none() {
            // Defensive: unknown shape — recurse all named children.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    self.extract_refs_from_node(child, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC2/RC4): process a C#/Java
    /// for-init declaration. The loop-variable binder(s) are recorded ONCE with
    /// a `ComprehensionScope` tag (reused as a generic "loop-scoped, self-
    /// initialized" marker) so the uninit detector treats them as pre-
    /// initialized despite CFG over-segmentation of the `for (...)` header line;
    /// the initializer EXPRESSIONS (`= start`) are recursed for their uses. This
    /// avoids the double-recording a plain `extract_refs_from_node(init)` would
    /// cause (the binder + a separate tagged def). Walks
    /// `variable_declaration` / `local_variable_declaration` ->
    /// `variable_declarator` -> `[name] identifier` + `[value] expr`.
    fn process_for_init_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        match node.kind() {
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        self.add_ref_with_context(
                            name,
                            RefType::Definition,
                            VarRefContext::ComprehensionScope,
                        );
                    } else {
                        self.process_for_init_declaration(name, depth)?;
                    }
                }
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_refs_from_node(value, depth + 1)?;
                }
            }
            // Not a declaration shape (e.g. C# `i = 0` assignment as init, or a
            // bare expression) — fall back to normal extraction.
            "assignment_expression" | "expression_statement" | "comma_expression" => {
                self.extract_refs_from_node(node, depth + 1)?;
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.process_for_init_declaration(child, depth)?;
                }
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
                // stmt-edge-v1 (R3-r7-cl11): a fresh statement id PER declarator
                // so `const a = x, b = y` never links `a`->`y` or `b`->`x`.
                let def_start = self.refs.len();
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    } else {
                        // Could be destructuring pattern
                        self.extract_assignment_targets(name_node)?;
                    }
                }
                // "value" field is the initializer (JS/TS/Solidity). C# reuses
                // this `variable_declaration` -> `variable_declarator` shape but
                // exposes the initializer as an UNNAMED named-child following the
                // `=` token (there is NO `value` field), so the field lookup
                // returns None and the ENTIRE RHS — object-creation args, calls,
                // binary operands — was never descended. A C# local read living
                // ONLY in such an initializer (`new ContainerContext(type)`) was
                // therefore reported as a false dead store (fix-PW4-C4-csharp-
                // objcreation). Fall back to the `=`-anchored initializer so the
                // RHS is walked for uses identically to Java/C++ (which carry a
                // `value` field and already descend `new X(arg)`).
                if let Some(value) = child
                    .child_by_field_name("value")
                    .or_else(|| Self::declarator_initializer_after_eq(child))
                {
                    self.extract_rhs_with_stmt(def_start, value, depth)?;
                }
            }
        }
        Ok(())
    }

    /// fix-PW4-C4-csharp-objcreation (v0.5.0 BACKLOG): return the initializer
    /// expression of a `variable_declarator` whose RHS is an UNNAMED child after
    /// the `=` token rather than a `value` field — the C# shape
    /// (`local_declaration_statement > variable_declaration >
    /// variable_declarator { [name] identifier, '=', <init-expr> }`).
    ///
    /// Anchored on the `=` token: the first NAMED child appearing after it is
    /// the initializer expression (object-creation, call, conditional, binary,
    /// identifier, ...). Returns `None` for an initializer-less declarator
    /// (`int x;`, which emits no `=`), so a bare declaration never manufactures
    /// a spurious RHS walk.
    fn declarator_initializer_after_eq(declarator: Node<'_>) -> Option<Node<'_>> {
        let mut cursor = declarator.walk();
        let mut seen_eq = false;
        for child in declarator.children(&mut cursor) {
            if seen_eq {
                if child.is_named() {
                    return Some(child);
                }
            } else if !child.is_named() && child.kind() == "=" {
                seen_eq = true;
            }
        }
        None
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
        // stmt-edge-v1 (R3-r7-cl11): see `extract_rhs_with_stmt`.
        let def_start = self.refs.len();
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                // C4a-js-closure-liveness (v0.5.0 BACKLOG): a JS bare-identifier
                // assignment whose target is a captured UPVALUE — a variable
                // bound in an ENCLOSING function scope, written from inside a
                // nested closure (not a local of the write's own function, not a
                // true global) — is shared by reference with sibling/nested
                // closures through the closure cell. The intraprocedural flat
                // DFG carries no cross-closure def-use edge, so the write looks
                // dead even though a sibling closure reads the shared cell
                // (js-lodash `debounce`: `timerId`/`lastCallTime` written in
                // `leadingEdge`/`timerExpired`/`cancel`, read in
                // `debounced`/`flush`/`shouldInvoke`). Tag it `ClosureCapture`
                // so `find_dead_stores_dfg` treats it as conservatively LIVE —
                // the canonical soundness floor for captured/escaping variables
                // (mirrors the Lua/Luau rc6 path via `is_lua_upvalue_write`).
                // True locals of the write's own function and true globals are
                // emitted with `context: None`, so genuine dead stores (incl.
                // the GEN-test's never-read local) still surface.
                let nm = left.utf8_text(self.source.as_bytes()).unwrap_or("");
                if matches!(self.language, Language::JavaScript)
                    && !nm.is_empty()
                    && self.is_js_ts_upvalue_write(left, nm)
                {
                    self.add_ref_with_context(
                        left,
                        RefType::Definition,
                        VarRefContext::ClosureCapture,
                    );
                } else {
                    self.add_ref_from_node(left, RefType::Definition);
                }
            } else {
                // Could be member expression, subscript, etc.
                self.extract_assignment_targets(left)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_rhs_with_stmt(def_start, right, depth)?;
        }

        Ok(())
    }

    /// Process C-style augmented assignment: x += ..., x -= ...
    fn process_c_style_augmented_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // stmt-edge-v1 (R3-r7-cl11): the self-read `Use(x)` recorded on the LHS
        // stays in the def span (before the RHS), so it is never tagged as a
        // statement use; only genuine RHS reads link to `def(x)`.
        let def_start = self.refs.len();
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
            } else {
                // rc3: compound element/field write `arr[i] += 1`, `obj.f += 1`.
                // The LHS is a subscript/member node — route through the
                // assignment-target dispatcher so the container registers as a
                // WeakUpdate (non-killing) and the index vars as uses, mirroring
                // the plain `arr[i] = …` case.
                self.extract_assignment_targets(left)?;
            }
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_rhs_with_stmt(def_start, right, depth)?;
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
        // stmt-edge-v1 (R3-r7-cl11): mark where this statement's LHS defs begin
        // so finalize can link `def(bytes)` to the RHS-used vars (`value` reads
        // inside a `match`/`if`/block-tail) the per-variable model misses.
        let def_start = self.refs.len();
        // "pattern" field contains the binding
        if let Some(pattern) = node.child_by_field_name("pattern") {
            self.extract_rust_binding_identifiers(pattern);
        }

        // "value" field contains the initializer (a use)
        if let Some(value) = node.child_by_field_name("value") {
            self.extract_rhs_with_stmt(def_start, value, depth)?;
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

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Rust closure
    /// `|a, &b| body` — record each closure parameter as a Definition (reusing
    /// the binding-pattern walker, which handles `reference_pattern`,
    /// `mut_pattern`, tuples, etc.), then analyze the body for uses.
    fn process_rust_closure(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                if child.is_named() {
                    self.add_closure_param_defs(child);
                }
            }
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.extract_refs_from_node(body, depth + 1)?;
        }
        Ok(())
    }

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT): record every leaf identifier
    /// of a Rust closure parameter pattern as a `ClosureParam`-tagged
    /// Definition (handles `reference_pattern`, `mut_pattern`, tuple patterns).
    fn add_closure_param_defs(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                self.add_ref_with_context(node, RefType::Definition, VarRefContext::ClosureParam);
            }
            "mutable_specifier" => {}
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.add_closure_param_defs(child);
                }
            }
        }
    }

    // =====================================================================
    // Go processing
    // =====================================================================

    /// Process Go short var declaration: x := ...
    /// AST: short_var_declaration -> left (expression_list), right (expression_list)
    fn process_go_short_var(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // stmt-edge-v1 (R3-r7-cl11): `bytes := func() u64 { switch s {..value..} }()`.
        let def_start = self.refs.len();
        if let Some(left) = node.child_by_field_name("left") {
            self.extract_go_lhs_identifiers(left)?;
        }

        if let Some(right) = node.child_by_field_name("right") {
            self.extract_rhs_with_stmt(def_start, right, depth)?;
        }

        Ok(())
    }

    /// Process a Go `var_declaration` or `const_declaration`.
    /// AST: var_declaration -> var_spec (name, type, value); const_declaration ->
    /// const_spec (name, value) — same shape.
    ///
    /// fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): a `const` declared INSIDE a function
    /// body (`const stackBufSize = 128`) is a genuine local whose `const_spec`
    /// has the same `[name]` / `[value]` shape as a `var_spec`. The pre-fix
    /// dispatch only routed `var_declaration` here, so a function-local const was
    /// never recorded as a Definition and its reads were flagged
    /// definite-uninitialized (go-httprouter `CleanPath` `stackBufSize`). Package-
    /// level consts are still pre-collected by `collect_imports`; this covers the
    /// in-body case. Both `var_spec` and `const_spec` are handled identically.
    fn process_go_var_declaration(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if matches!(child.kind(), "var_spec" | "const_spec") {
                // stmt-edge-v1 (R3-r7-cl11): a fresh statement id per spec.
                let def_start = self.refs.len();
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
                    self.extract_rhs_with_stmt(def_start, value, depth)?;
                }
            }
        }

        Ok(())
    }

    /// Process Go assignment statement: x = ...; x += ...
    /// fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): populate
    /// [`Self::go_named_results`] from the `result` `parameter_list` of a Go
    /// `function_declaration` / `method_declaration`. Each named result is a
    /// `parameter_declaration` with a `name` field (`(handle Handle, ps
    /// *Params, tsr bool)`); a result list of bare types (`(int, error)`) has
    /// no `name` fields and yields an empty set, so the naked-return synthesis
    /// stays inert for unnamed-result functions. AST-driven (field names verified
    /// via tree-sitter-go: `result` → `parameter_list` → `parameter_declaration`
    /// → `name`).
    fn collect_go_named_results(&mut self, func_node: Node) {
        if !matches!(self.language, Language::Go) {
            return;
        }
        let Some(result) = func_node.child_by_field_name("result") else {
            return;
        };
        // A single named result is still wrapped in a parameter_list; a bare
        // single type (`func f() error`) is a plain `type_identifier` and has
        // no parameter_declaration children, so the walk below yields nothing.
        if result.kind() != "parameter_list" {
            return;
        }
        let mut cursor = result.walk();
        for child in result.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                // A `parameter_declaration` may declare multiple names sharing
                // one type (`(a, b int)`), each exposed under the `name` field.
                let mut pc = child.walk();
                let name_nodes: Vec<Node> = child
                    .children(&mut pc)
                    .enumerate()
                    .filter(|(i, sub)| {
                        sub.kind() == "identifier"
                            && child.field_name_for_child(*i as u32) == Some("name")
                    })
                    .map(|(_, sub)| sub)
                    .collect();
                for sub in name_nodes {
                    if let Ok(t) = sub.utf8_text(self.source.as_bytes()) {
                        if t != "_" {
                            // A Go named result is IMPLICITLY zero-initialized at
                            // function entry — record a Definition so (a)
                            // reaching-defs never flags an un-assigned named
                            // result read by the naked return as "uninitialized"
                            // (`func f() (handle Handle, ps *Params, tsr bool)`
                            // returning `handle`/`ps` un-set), and (b) it is
                            // treated like a parameter (the entry def, not a body
                            // store) by dead-stores. This is the named-result
                            // analogue of recording input parameters as defs.
                            self.add_ref_from_node(sub, RefType::Definition);
                            if !self.go_named_results.iter().any(|n| n == t) {
                                self.go_named_results.push(t.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    /// fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): handle a Go
    /// `return_statement`. A return WITH operands (`return a, b`) reads those
    /// expressions (default recursion handles it). A *naked* `return` (no
    /// `expression_list` child) implicitly reads every named result of the
    /// enclosing function, so synthesize a `Use` of each at the return's line —
    /// otherwise a store into a named result followed by a bare return looks
    /// dead.
    fn process_go_return(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let mut has_operands = false;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "expression_list" {
                // Normal return: recurse so each returned expression's reads count.
                has_operands = true;
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }
        if !has_operands {
            // Naked return: implicitly reads all named results at this line.
            let line = node.start_position().row + 1;
            for name in self.go_named_results.clone() {
                self.add_synthetic_use(&name, line);
            }
        }
        Ok(())
    }

    fn process_go_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // stmt-edge-v1 (R3-r7-cl11): see `extract_rhs_with_stmt`.
        let def_start = self.refs.len();
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
            self.extract_rhs_with_stmt(def_start, right, depth)?;
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
                // stmt-edge-v1 (R3-r7-cl11): one statement id per declarator.
                let def_start = self.refs.len();
                // "name" field is the variable name
                if let Some(name_node) = child.child_by_field_name("name") {
                    if name_node.kind() == "identifier" {
                        self.add_ref_from_node(name_node, RefType::Definition);
                    }
                }
                // "value" field is the initializer
                if let Some(value) = child.child_by_field_name("value") {
                    self.extract_rhs_with_stmt(def_start, value, depth)?;
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
        // stmt-edge-v1 (R3-r7-cl11): see `extract_rhs_with_stmt`.
        let def_start = self.refs.len();
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
            self.extract_rhs_with_stmt(def_start, value, depth)?;
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
                // stmt-edge-v1 (R3-r7-cl11): `int bytes = cond ? value : other;`
                // — one statement id per init_declarator.
                let def_start = self.refs.len();
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
                    self.extract_rhs_with_stmt(def_start, value, depth)?;
                }
            } else if child.kind() == "identifier" {
                // Plain declaration without initializer: int x;
                let text = child.utf8_text(self.source.as_bytes()).unwrap_or("");
                if !text.is_empty() && !is_keyword(text, self.language) {
                    self.add_ref_from_node(child, RefType::Definition);
                }
            } else if matches!(child.kind(), "pointer_declarator" | "array_declarator") {
                // C1-gen-bindings (v0.5.0 BACKLOG): an initializer-less pointer
                // or array declaration — `int *p;`, `char buf[16];`. The bound
                // name is the inner `identifier`; the existing `init_declarator`
                // arm already unwraps a `pointer_declarator` for the
                // *initialized* case, so mirror that for the bare case. Without
                // this the declared name never entered GEN and every later read
                // (`compute(&p)` then `*p`) was flagged definite-uninitialized.
                if let Some(ident) = Self::c_declared_identifier(child) {
                    self.add_ref_from_node(ident, RefType::Definition);
                }
            }
        }

        Ok(())
    }

    // =====================================================================
    // PHP processing
    // =====================================================================

    /// Process PHP foreach: `foreach ($arr as $key => $val) { }`.
    ///
    /// fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): delegate to the registry-driven
    /// [`Self::process_loop_header`] (descriptor [`LoopHeader::ForeachAs`]) so
    /// the iterable expression BEFORE `as` (`$arr`, or `$rows[$rowKey]`) is
    /// recorded as a Use in addition to the binder Definitions and body.
    /// Pre-fix this scanned only for the binder after `as` and dropped the
    /// iterable entirely, so a variable used solely as the foreach subject was
    /// reported as a dead store, and `&$v` by-reference binders were missed.
    fn process_php_foreach(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        self.process_loop_header(node, depth)
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
        // Resolve the LHS pattern and RHS expression. `match_operator` exposes
        // [left]/[right] fields; the `binary_operator` `=` form does not, so
        // fall back to the first / last *named* child.
        let (lhs, rhs) = match (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (Some(l), Some(r)),
            _ => {
                let named: Vec<_> = node
                    .children(&mut node.walk())
                    .filter(|c| c.is_named())
                    .collect();
                if named.len() >= 2 {
                    (named.first().copied(), named.last().copied())
                } else {
                    (None, None)
                }
            }
        };

        // C1-gen-bindings (v0.5.0 BACKLOG): the LHS is a PATTERN that may bind
        // more than a bare identifier — `%{a: a} = conn`, `%Conn{} = conn`,
        // `{:ok, v} = res`. The pre-fix code recorded ONLY a bare-`identifier`
        // LHS, so every destructured binder was dropped from GEN and flagged
        // definite-uninitialized. Route the LHS through the pin/alias/`when`-
        // aware pattern binder, which records each bound lower-case name as a
        // Definition while still skipping pinned `^x`, upper-case module aliases
        // and call/dot fragments. A plain `x = expr` LHS is a lower-case
        // `identifier`, so this binds `x` exactly as before.
        if let Some(l) = lhs {
            self.extract_elixir_pattern_bindings(l);
        }

        // The RHS is a use.
        if let Some(r) = rhs {
            self.extract_refs_from_node(r, depth + 1)?;
        }

        Ok(())
    }

    /// fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): register the variables BOUND by an
    /// Elixir pattern (a `case` / `fn` / `with` clause head) as Definitions.
    ///
    /// In Elixir a bare lower-case `identifier` in pattern position is a binding
    /// (`{:ok, cb}` binds `cb`); these node kinds are NOT bindings and are not
    /// descended into:
    ///   * `atom` (`:ok`), `string`, numbers, `keywords` — literals.
    ///   * the `[operator]` / called name of a `call` (`Foo.bar(x)` in a pattern
    ///     is a remote-call guard fragment, not a binder) — we skip the call
    ///     `target`/`function` but still descend into its `arguments`, where
    ///     sub-patterns may bind.
    ///   * a PINNED identifier `^x` (`unary_operator` with `^`) — a match against
    ///     an existing value, never a new binding.
    ///   * the right side of a `dot` (a member/function name).
    /// Nested containers (`tuple`, `list`, `map`, `binary_operator` for cons /
    /// `<>` / `when` guards) are handled by recursion.
    fn extract_elixir_pattern_bindings(&mut self, node: Node) {
        match node.kind() {
            "identifier" => {
                let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
                // A bound pattern variable is lower-case (or `_`-prefixed). An
                // upper-case identifier in pattern position is an alias/module
                // reference, never a binding.
                if text
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                {
                    self.add_ref_from_node(node, RefType::Definition);
                }
            }
            // Pinned value `^existing` — a match, not a binding. Do not descend.
            "unary_operator" => {
                let is_pin = node.children(&mut node.walk()).any(|c| {
                    !c.is_named() && c.utf8_text(self.source.as_bytes()).unwrap_or("") == "^"
                });
                if !is_pin {
                    for child in node.children(&mut node.walk()) {
                        self.extract_elixir_pattern_bindings(child);
                    }
                }
            }
            // A `when`-guarded clause head `pattern when guard`: the `[left]`
            // pattern binds; the `[right]` guard is a boolean expression over
            // already-bound names (no new bindings). For other binary operators
            // in patterns (cons `|`, concat `<>`) both sides may bind, so descend
            // into both when not a `when` guard.
            "binary_operator" => {
                let is_when = node.children(&mut node.walk()).any(|c| {
                    c.kind() == "when"
                        || (!c.is_named()
                            && c.utf8_text(self.source.as_bytes()).unwrap_or("") == "when")
                });
                if is_when {
                    if let Some(left) = node.child_by_field_name("left") {
                        self.extract_elixir_pattern_bindings(left);
                    }
                } else {
                    for child in node.children(&mut node.walk()) {
                        self.extract_elixir_pattern_bindings(child);
                    }
                }
            }
            // A remote/local call in pattern position: skip the callee name but
            // descend into its arguments (sub-patterns may bind there).
            "call" => {
                if let Some(args) = node.child_by_field_name("arguments") {
                    self.extract_elixir_pattern_bindings(args);
                }
            }
            // A `dot` (member access) names a function/field — never a binder.
            "dot" => {}
            // Literals / atoms — no bindings.
            "atom" | "string" | "charlist" | "integer" | "float" | "boolean" | "nil" => {}
            _ => {
                for child in node.children(&mut node.walk()) {
                    self.extract_elixir_pattern_bindings(child);
                }
            }
        }
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

    /// fix-R7 (cluster[11] RC4): Kotlin `for (x in iterable) body`.
    ///
    /// tree-sitter-kotlin exposes the parts as POSITIONAL children with no
    /// field names:
    ///   `for_statement` -> `for` `(` `variable_declaration` `in` <iterable>
    ///                      `)` (`block` | `control_structure_body` | <stmt>)
    /// Roles, by position relative to the `in` and `)` tokens:
    ///   * the `variable_declaration` before `in` is the loop binder — its
    ///     `identifier`(s) are DEFINITIONS (Kotlin allows destructuring
    ///     `for ((k, v) in m)` via a `multi_variable_declaration`);
    ///   * everything between `in` and `)` is the iterable expression — USES;
    ///   * everything after `)` is the loop body — analyzed normally (so its
    ///     loop-carried reassignments are recorded).
    fn process_kotlin_for_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        #[derive(PartialEq)]
        enum Phase {
            Binder,
            Iterable,
            Body,
        }
        let mut phase = Phase::Binder;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "for" | "(" => {}
                "in" => {
                    // Past the binder, now reading the iterable.
                    phase = Phase::Iterable;
                }
                ")" => {
                    // Iterable closed, the remainder is the body.
                    phase = Phase::Body;
                }
                _ => match phase {
                    Phase::Binder => {
                        // The loop binder. Register each bound identifier as a
                        // Definition. `variable_declaration` /
                        // `multi_variable_declaration` wrap the name(s); a bare
                        // identifier is tolerated defensively.
                        self.register_kotlin_for_binder(child);
                    }
                    Phase::Iterable => {
                        // Iterable expression -> uses (`b` in `1..b`, the
                        // collection in `for (x in items)`, etc.).
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                    Phase::Body => {
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                },
            }
        }
        Ok(())
    }

    /// Register the loop-variable definition(s) of a Kotlin `for` binder.
    /// Handles `variable_declaration` (single `i`, possibly typed `i: Int`) and
    /// `multi_variable_declaration` (destructuring `(k, v)`), descending to the
    /// leaf `identifier`(s).
    ///
    /// The type annotation (`user_type`/`type_identifier` subtree of `i: Int`)
    /// is NOT a binding — in this grammar a `user_type` wraps a plain
    /// `identifier` for the type name, so a naive descent would wrongly record
    /// the TYPE (`Int`) as a loop-variable definition. We therefore skip type
    /// and `:` nodes and only recurse the binder structure.
    fn register_kotlin_for_binder(&mut self, node: Node) {
        match node.kind() {
            "identifier" | "simple_identifier" => {
                self.add_ref_from_node(node, RefType::Definition);
            }
            // Type annotation and its punctuation are not bindings.
            "user_type" | "type_identifier" | "nullable_type" | "type_reference" | ":" => {}
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.register_kotlin_for_binder(child);
                }
            }
        }
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
        // stmt-edge-v1 (R3-r7-cl11): `variable_list` (defs) precedes
        // `expression_list` (RHS reads); span-tag them as one statement.
        let def_start = self.refs.len();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_list" {
                // Extract all identifiers as definitions
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    match inner_child.kind() {
                        "identifier" => {
                            // rc6-deadstores-closure-write-across-siblings
                            // (v0.5.0 CLOSEOUT): a bare-identifier write whose
                            // target is an UPVALUE captured from an enclosing
                            // function scope (not a local of the write's own
                            // function, and not a true global) is observed by
                            // sibling/nested closures through the shared cell, so
                            // it is conservatively LIVE — never a dead store
                            // intraprocedurally. Tag it `ClosureCapture` so the
                            // decision site (`find_dead_stores_dfg`) suppresses it
                            // (the flat DFG is intraprocedural-by-construction and
                            // carries no cross-closure def-use edge). True locals
                            // of F and true globals are emitted normally
                            // (`context: None`) so genuine dead stores still
                            // surface.
                            let nm = inner_child
                                .utf8_text(self.source.as_bytes())
                                .unwrap_or("");
                            let is_upvalue =
                                !nm.is_empty() && self.is_lua_upvalue_write(inner_child, nm);
                            if is_upvalue {
                                self.add_ref_with_context(
                                    inner_child,
                                    RefType::Definition,
                                    VarRefContext::ClosureCapture,
                                );
                            } else {
                                self.add_ref_from_node(inner_child, RefType::Definition);
                            }
                        }
                        // fix-R7-cl6-lua-index-use (v0.5.0 CLOSEOUT): a
                        // table-element write reads the container (Update) and,
                        // for a BRACKET index, ALSO reads every variable inside
                        // the index expression. The pre-fix code walked to the
                        // FIRST identifier (`args` in `args[nargs+1] = …`),
                        // marked it Update and `break`-ed — so `nargs` was never
                        // recorded as a Use and got flagged as a dead store
                        // (lua-luvit `adapt`). This is the same gap
                        // fix-B4-dfg-coverage-v1 closed for Py/Go/TS/C/C++/
                        // Java/Solidity via the subscript helper; migrate Lua
                        // too. tree-sitter-lua field names (verified via
                        // dump_lua_t): both index forms carry `table`
                        // (container) + `field`, but for `dot_index_expression`
                        // `field` is the STATIC member name (an `identifier`
                        // that is NOT a variable use — `t.field`), whereas for
                        // `bracket_index_expression` `field` is the index
                        // EXPRESSION (`t[k]`, `args[nargs+1]`) whose variables
                        // ARE uses. Handle the two distinctly.
                        "bracket_index_expression" => {
                            self.record_subscript_container_and_index(
                                inner_child,
                                "table",
                                "field",
                            )?;
                        }
                        "dot_index_expression" => {
                            // Container is read-modified (Update); the `field`
                            // segment is a static member name, never a use.
                            if let Some(table) = inner_child.child_by_field_name("table") {
                                if table.kind() == "identifier" {
                                    // rc3: Lua field write `t.field = …` — weak.
                                    self.add_ref_from_node(table, RefType::WeakUpdate);
                                } else {
                                    // Nested base (`a.b.c = …`): recurse so the
                                    // outermost identifier and any bracket
                                    // indices inside register.
                                    self.extract_assignment_targets(table)?;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if child.kind() == "expression_list" {
                // Process the value expressions for uses
                let rhs_start = self.refs.len();
                self.extract_refs_from_node(child, depth + 1)?;
                // stmt-edge-v1 (R3-r7-cl11): link `def`(s) to the RHS reads.
                self.tag_stmt_span(def_start, rhs_start);
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
                        "bracket_index_expression" => {
                            // `t[i] += …`: the base object is read+updated AND
                            // the index expression's variables are uses.
                            // fix-R7-cl6-lua-index-use (v0.5.0 CLOSEOUT): mirror
                            // the plain-assignment fix so `i` in `t[i] += …` is
                            // not lost (it was dropped by the find-first-then-
                            // break walk).
                            if let Some(table) = inner_child.child_by_field_name("table") {
                                if table.kind() == "identifier" {
                                    // rc3: `t[i] += …` — the container is a weak
                                    // (non-killing) update; WeakUpdate already
                                    // encodes the implicit read of the base.
                                    self.add_ref_from_node(table, RefType::WeakUpdate);
                                } else {
                                    self.extract_refs_from_node(table, 1)?;
                                }
                            }
                            if let Some(index) = inner_child.child_by_field_name("field") {
                                self.extract_refs_from_node(index, 1)?;
                            }
                        }
                        "dot_index_expression" => {
                            // `t.field += …`: the base object is read+updated;
                            // the `field` segment is a static member name.
                            if let Some(table) = inner_child.child_by_field_name("table") {
                                if table.kind() == "identifier" {
                                    // rc3: `t.field += …` — weak (non-killing)
                                    // update; WeakUpdate encodes the base read.
                                    self.add_ref_from_node(table, RefType::WeakUpdate);
                                } else {
                                    self.extract_refs_from_node(table, 1)?;
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

    /// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): classify
    /// a Lua/Luau write to the bare `identifier` `name` at `write_node` by
    /// LEXICAL SCOPE — the only sound signal, since Q1 (the grammar sources)
    /// proves a local re-assignment, an upvalue write and a true-global write
    /// are all the identical `assignment_statement > variable_list >
    /// identifier`. Walks the physical ancestor chain of the write:
    ///
    /// * the FIRST enclosing function scope `G` is the write's OWN scope. If
    ///   `name` is bound there, the write is a LOCAL write → `false`
    ///   (eligible for normal dead-store detection).
    /// * otherwise, if `name` is bound in any scope ENCLOSING `G` (an outer
    ///   function, or the file `chunk`), the write targets a captured UPVALUE →
    ///   `true`. An intraprocedural dead-store analysis must treat such a write
    ///   as conservatively LIVE: the shared closure cell may be read by a
    ///   sibling/nested closure that the intraprocedural DFG never sees (LLVM's
    ///   >30-year canonical rule for address-taken / escaping variables — a
    ///   missed dead-store report is benign, a wrongly-reported one is unsound).
    /// * if no enclosing scope binds `name`, it is a true GLOBAL write →
    ///   `false` (a genuine dead global write stays flaggable).
    ///
    /// Keying on the PHYSICAL AST location (not on which function is being
    /// analyzed) is what makes a write inside a NESTED closure of F correctly
    /// classified as an upvalue write even though `name` is a local of F — the
    /// cross-check-(1) `createSignal`/`fire` case the flat-DFG model cannot
    /// bridge with a def-use edge.
    fn is_lua_upvalue_write(&self, write_node: Node, name: &str) -> bool {
        let mut innermost_scope_seen = false;
        let mut node = write_node.parent();
        while let Some(n) = node {
            let is_fn = matches!(
                n.kind(),
                "function_declaration" | "function_definition" | "local_function"
            );
            if is_fn || n.kind() == "chunk" {
                if !innermost_scope_seen {
                    // `G`: the write's own innermost function (or chunk) scope.
                    // Reuse the precomputed `lua_local_names` when `G` IS the
                    // analyzed function F (the common case — write sits directly
                    // in F); otherwise resolve the nested closure's bindings.
                    let is_analyzed_fn = is_fn
                        && self.analyzed_fn_span.is_some_and(|(s, e)| {
                            s == n.start_byte() && e == n.end_byte()
                        });
                    let local_of_g = if is_analyzed_fn {
                        self.lua_local_names.contains(name)
                    } else {
                        let mut g_names = HashSet::new();
                        collect_lua_scope_bindings(n, self.source, &mut g_names);
                        g_names.contains(name)
                    };
                    if local_of_g {
                        return false; // local of the write's own scope
                    }
                    innermost_scope_seen = true;
                } else {
                    // A scope ENCLOSING `G` (outer function or the chunk).
                    let mut enc_names = HashSet::new();
                    collect_lua_scope_bindings(n, self.source, &mut enc_names);
                    if enc_names.contains(name) {
                        return true; // bound outside G → captured upvalue
                    }
                }
            }
            node = n.parent();
        }
        false // no enclosing binder anywhere → true global → keep flaggable
    }

    /// C4a-js-closure-liveness (v0.5.0 BACKLOG): classify a JS write to the bare
    /// `identifier` `name` at `write_node` by LEXICAL SCOPE — the JS/TS analog of
    /// [`Self::is_lua_upvalue_write`]. A plain `identifier = …`
    /// (`assignment_expression`) is syntactically identical whether it targets a
    /// local, a captured upvalue, or a global, so the only sound classifier is a
    /// lexical binder-resolution walk over the write's PHYSICAL ancestor chain:
    ///
    /// * the FIRST enclosing function scope `G` is the write's OWN scope. If
    ///   `name` is bound directly in `G` (a parameter, a `var`/`let`/`const`
    ///   declarator, a hoisted nested `function_declaration` name, a `catch`
    ///   binder, or a `for (const x of …)` binder), the write is a LOCAL write →
    ///   `false` (eligible for normal dead-store detection).
    /// * otherwise, if `name` is bound in any scope ENCLOSING `G` (an outer
    ///   function, or the `program` root), the write targets a captured UPVALUE →
    ///   `true`. An intraprocedural dead-store analysis must treat such a write
    ///   as conservatively LIVE: the shared closure cell may be read by a
    ///   sibling/nested closure the intraprocedural flat DFG never sees
    ///   (js-lodash `debounce`: `timerId`/`lastCallTime` written in
    ///   `leadingEdge`/`cancel`, read in `debounced`/`flush`/`shouldInvoke`).
    /// * if no enclosing scope binds `name`, it is a true GLOBAL write → `false`
    ///   (a genuine dead global write stays flaggable).
    ///
    /// Keying on the PHYSICAL AST location (not on which function is being
    /// analyzed) is what makes a write inside a NESTED closure of the analyzed
    /// function correctly classified as an upvalue write even though `name` is a
    /// local of that outer function — the cross-sibling read the flat-DFG model
    /// cannot bridge with a def-use edge.
    fn is_js_ts_upvalue_write(&self, write_node: Node, name: &str) -> bool {
        let mut innermost_scope_seen = false;
        let mut node = write_node.parent();
        while let Some(n) = node {
            if js_ts_is_function_scope(n.kind()) || n.kind() == "program" {
                let mut names = HashSet::new();
                collect_js_ts_scope_bindings(n, self.source, &mut names);
                if !innermost_scope_seen {
                    // `G`: the write's own innermost function (or program) scope.
                    if names.contains(name) {
                        return false; // local of the write's own scope
                    }
                    innermost_scope_seen = true;
                } else if names.contains(name) {
                    return true; // bound in an enclosing scope → captured upvalue
                }
            }
            node = n.parent();
        }
        false // no enclosing binder anywhere → true global → keep flaggable
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
        // stmt-edge-v1 (R3-r7-cl11): span-tag the binders + the `= <value>`.
        let def_start = self.refs.len();
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
        let rhs_start = self.refs.len();
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
        // stmt-edge-v1 (R3-r7-cl11): link `def(name)` to its RHS reads.
        self.tag_stmt_span(def_start, rhs_start);

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
        // stmt-edge-v1 (R3-r7-cl11): all binders precede `=`; the RHS reads
        // follow, so `rhs_start` is the refs length at the `=` token.
        let def_start = self.refs.len();
        let mut rhs_start: Option<usize> = None;
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
                        // stmt-edge-v1: RHS reads start here (all binders done).
                        rhs_start = Some(self.refs.len());
                        continue;
                    }
                    if found_eq && child.is_named() {
                        // Process the value expression for uses
                        self.extract_refs_from_node(child, depth + 1)?;
                    }
                }
            }
        }

        // stmt-edge-v1 (R3-r7-cl11): link `def(name)` to its RHS reads.
        if let Some(rs) = rhs_start {
            self.tag_stmt_span(def_start, rs);
        }

        Ok(())
    }

    /// Process Swift assignment: z = z + 1
    /// AST: assignment -> directly_assignable_expression -> simple_identifier, =, expression
    fn process_swift_assignment(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        // stmt-edge-v1 (R3-r7-cl11): span-tag target + RHS reads.
        let def_start = self.refs.len();
        let mut rhs_start: Option<usize> = None;
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
                // stmt-edge-v1: RHS reads start after the `=` token.
                rhs_start = Some(self.refs.len());
            } else if found_eq && child.is_named() {
                // Process the value expression for uses
                self.extract_refs_from_node(child, depth + 1)?;
            }
        }

        // stmt-edge-v1 (R3-r7-cl11): link `def(z)` to its RHS reads.
        if let Some(rs) = rhs_start {
            self.tag_stmt_span(def_start, rs);
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
                    match arg.kind() {
                        "identifier" => {
                            self.add_ref_from_node(arg, RefType::Definition);
                        }
                        "binary_operator" => {
                            // C1-gen-bindings (v0.5.0 BACKLOG): a `binary_operator`
                            // param is either a `=` MATCH (`%Conn{} = conn`,
                            // `{:ok, v} = res`) or a `\\` DEFAULT (`opts \\ []`).
                            //
                            // For a MATCH, BOTH sides are patterns and the bound
                            // name can be on EITHER side (`%Conn{} = conn` binds
                            // the right `conn` — the function's OWN parameter,
                            // previously flagged definite-uninitialized). Route
                            // the whole node through the pin/alias-aware pattern
                            // binder.
                            //
                            // For a DEFAULT (fix-R2-themeC, RC2: elixir-phoenix
                            // `allow_jsonp`), only the `[left]` identifier binds —
                            // the default VALUE on the right is not a parameter
                            // source — so keep the precise left-only handling.
                            let is_match = arg.children(&mut arg.walk()).any(|c| {
                                !c.is_named()
                                    && c.utf8_text(self.source.as_bytes()).unwrap_or("") == "="
                            });
                            if is_match {
                                self.extract_elixir_pattern_bindings(arg);
                            } else if let Some(left) = arg.child_by_field_name("left") {
                                if left.kind() == "identifier" {
                                    self.add_ref_from_node(left, RefType::Definition);
                                }
                            }
                        }
                        // C1-gen-bindings (v0.5.0 BACKLOG): a direct
                        // pattern-container parameter — `%{a: a}`, `%Conn{}`,
                        // `{:ok, v}`, `[h | t]`, `<<n::8>>`. Each may bind
                        // lower-case variables; route through the pattern binder
                        // (which skips atoms, literals, upper-case aliases, pins
                        // and call/dot fragments).
                        "map" | "tuple" | "list" | "struct" | "binary" => {
                            self.extract_elixir_pattern_bindings(arg);
                        }
                        _ => {}
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
                // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): the callee /
                // constructor of a `call_expression` is the FIRST child (Swift
                // has no `function` field). `Process()`, `URL(...)`, `Pipe()`
                // are type/constructor names resolved from the standard library
                // — never local-variable uses. (A genuine closure call
                // `myClosure()` would carry its own definition.)
                "call_expression" => {
                    if parent.child(0).map(|c| c.id()) == Some(node.id()) {
                        return false;
                    }
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

        // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): position-independent
        // suppression of file-level macro / const / import / builtin names for
        // the C-family + Python + Rust. These are value-position reads that are
        // structurally identical to local reads (`SDS_TYPE_MASK` in an
        // expression, `stackBufSize` as a call argument, `os` as an attribute
        // object) but resolve to a non-local symbol collected from the file
        // (or a language builtin seeded in `collect_imports`). Guarded by
        // `generic_local_names`: a local that shadows such a name is NOT
        // suppressed, so its genuine reads survive and its store never looks
        // dead. (Member-NAME and callee positions were already classified
        // not-a-use by `generic_non_use_position`, so only true value reads of
        // file-level symbols reach here.)
        //
        // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): C#/Java join this block so that a
        // bare value READ of a class FIELD (`scale + _end`, `Power10[i]`) — which
        // is structurally identical to a local read but resolves to a class-scope
        // member collected by `collect_field_declarator_names` — is classified
        // not-a-use. The earlier C#/Java block only suppressed RECEIVER and
        // member-NAME positions, so a field used as a bare operand still entered
        // the analyzer (csharp-newtonsoft-bson `_end`/`Power10`/`MaxFractionDigits`
        // flagged definite-uninitialized). Guarded by `generic_local_names`, so a
        // genuine local shadowing a field/method/type name keeps its reads.
        if matches!(
            self.language,
            Language::Go
                | Language::Python
                | Language::Rust
                | Language::C
                | Language::Cpp
                | Language::CSharp
                | Language::Java
        ) {
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if !text.is_empty()
                && self.imported_type_names.contains(text)
                && !self.generic_local_names.contains(text)
            {
                return false;
            }
            // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): C/C++ preprocessor
            // macros and enum/#define constants are conventionally
            // SCREAMING_SNAKE_CASE and are frequently defined in a HEADER, so a
            // single-file translation unit never sees their `#define` (sds.c
            // reads `SDS_TYPE_MASK` / `SDS_MAX_PREALLOC` defined in sds.h). A
            // bare ALL-UPPERCASE value-position identifier that is NOT a local
            // (locals are lower/camelCase; a genuine all-caps local constant
            // would carry its own Definition and so be in `generic_local_names`)
            // is such a macro/constant, never a local-variable use. Mirrors the
            // sanctioned uppercase-receiver heuristics already used for
            // C#/Lua/Scala. Scoped to C/C++ where the convention is near-
            // absolute.
            if matches!(self.language, Language::C | Language::Cpp)
                && !self.generic_local_names.contains(text)
                && is_screaming_snake_case(text)
            {
                return false;
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

        // fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): Solidity language globals
        // (`msg`/`block`/`tx`/`now`/`this`/`abi`/`super`) are implicitly defined
        // by the EVM, not by any declaration in the contract. A bare reference —
        // including the `[object]` receiver of `msg.sender` / `block.timestamp` —
        // is never a local variable, so it has no defining write and was flagged
        // definite-uninitialized (solidity-solmate `ERC20.transferFrom` flagged
        // `msg`). Suppress as a builtin BEFORE the receiver falls through to a
        // `None` (use) decision. A contract that declared a local literally named
        // `msg` would record that local's Definition, but such shadowing of a
        // reserved global is not valid Solidity, so suppression is sound.
        {
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if SOLIDITY_GLOBALS.contains(&text) {
                return Some(false);
            }
        }

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

    /// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): structural
    /// (position-based) NON-use classifier shared by every language that
    /// reaches the generic fallback. An identifier in one of these positions is
    /// NEVER a local-variable read, regardless of language:
    ///
    ///   * the callee / function field of a call node
    ///     (`call_expression.function`, Elixir `call.target`, Kotlin/Swift
    ///     first child of `call_expression`);
    ///   * a member / property / field NAME on the rhs of a member-access node
    ///     (`a.b -> b`): Python `attribute.attribute`, Elixir `dot` right,
    ///     Kotlin `navigation_expression` selector;
    ///   * a scoped / qualified path segment (Rust `scoped_identifier`,
    ///     C++ `qualified_identifier` / `namespace_identifier`);
    ///   * a type-name position (`type_identifier`, `primitive_type`,
    ///     `generic_type`, `scoped_type_identifier`, `type_descriptor`, ...);
    ///   * a closure / lambda binder (`closure_parameters`, `lambda_parameters`)
    ///     or a comprehension target (`for_in_clause.left`) — these are
    ///     DEFINITIONS, never uses (and are recorded as defs elsewhere).
    ///
    /// Returns `Some(false)` when `node` is in such a NON-use position, else
    /// `None` (defer to the rest of `parent_use_context`). All decisions are
    /// keyed on tree-sitter node kinds verified by debug-parse for the C-family,
    /// Python, Rust, Go, Kotlin and Elixir grammars; member fields that the
    /// grammars already model as a DISTINCT node kind (`field_identifier`,
    /// `field_expression`, Go `selector_expression.field`) never reach the
    /// `identifier` arm and so need no rule here.
    fn generic_non_use_position(&self, parent: Node, node: Node) -> Option<bool> {
        let kind = parent.kind();

        // ---- Callee / function position -------------------------------------
        // Grammars that expose a named `function` field on the call node:
        // C `call_expression`, C++ `call_expression`, Go `call_expression`,
        // Rust `call_expression`, Python `call`.
        if matches!(kind, "call_expression" | "call") {
            if let Some(func) = parent.child_by_field_name("function") {
                if func.id() == node.id() {
                    return Some(false);
                }
            }
            // Kotlin / Swift `call_expression` has NO `function` field — the
            // callee is the FIRST child (the remainder are `value_arguments` /
            // `call_suffix`). A bare-identifier first child is the callee /
            // constructor name (`foo(...)`, `DivRemResult(...)`, `Process()`),
            // never a local-variable use.
            if matches!(self.language, Language::Kotlin | Language::Swift)
                && parent.child(0).map(|c| c.id()) == Some(node.id())
            {
                return Some(false);
            }
            // Elixir: `call` exposes the callee via the `target` field — a bare
            // `identifier` target is a function/macro name (`floor(...)`).
            if matches!(self.language, Language::Elixir) {
                if let Some(target) = parent.child_by_field_name("target") {
                    if target.id() == node.id() {
                        return Some(false);
                    }
                }
            }
        }

        // ---- C++ templated callee / cast-operator name -----------------------
        // fix-PW1-C3-nonvar-tokens (v0.5.0 BACKLOG, Wave 1 row C3): a C++
        // templated invocation `name<Args>(args)` parses as
        //   call_expression { function: template_function { name: identifier,
        //                                                    arguments } }.
        // The `name` field of a `template_function` is a function / cast-operator
        // / template name — `reinterpret_cast`, `static_cast`, `const_cast`,
        // `dynamic_cast`, `make_unique`, `std::vector` — never a local-variable
        // read. (cpp-fmt `as_chars` flagged `reinterpret_cast` as definite-
        // uninitialized.) The four cast forms are C++ keywords but reach the
        // `identifier` arm here, so suppress them structurally by position rather
        // than by a keyword stoplist (which would miss `make_unique` etc.).
        if kind == "template_function" {
            if let Some(name) = parent.child_by_field_name("name") {
                if name.id() == node.id() {
                    return Some(false);
                }
            }
        }

        // ---- Kotlin infix-function operator position --------------------------
        // fix-R2-themeC (v0.5.0 CLOSEOUT, RC1): Kotlin INFIX functions
        // (`shl`/`or`/`downTo`/`shr`/`and`/`xor`/`ushr`/`until`/`step`, and any
        // user-declared `infix fun`) parse as a bare `identifier` sitting in the
        // OPERATOR slot of an `infix_expression`: `lhs OP rhs` ->
        //   infix_expression { identifier(lhs)  identifier(OP)  <rhs> }.
        // tree-sitter-kotlin emits no `[operator]` field, but the operator is
        // always a MIDDLE named child — never the first (lhs) or last (rhs)
        // operand. Such an identifier is an infix-function callee, not a local
        // variable (the kotlin-datetime `multiplyAndDivide` repro flagged `shl`,
        // `or`, `downTo` as definite-uninitialized). Suppress the non-edge
        // operand. (The lhs/rhs operands fall through and are classified
        // normally — genuine variable reads survive.)
        if matches!(self.language, Language::Kotlin) && kind == "infix_expression" {
            let named: Vec<Node> = {
                let mut cur = parent.walk();
                parent.children(&mut cur).filter(|c| c.is_named()).collect()
            };
            if named.len() >= 3 {
                let is_first = named.first().map(|c| c.id()) == Some(node.id());
                let is_last = named.last().map(|c| c.id()) == Some(node.id());
                if !is_first && !is_last {
                    return Some(false);
                }
            }
        }

        // ---- C# preprocessor `#if` / `#elif` condition symbol ----------------
        // fix-R2-themeC (v0.5.0 CLOSEOUT, RC1): a C# `#if SYMBOL` /
        // `#elif SYMBOL` condition references a COMPILE-TIME preprocessor symbol
        // (set via `/define` or `#define`), never a runtime local variable. The
        // grammar exposes it as the `[condition]` of a `preproc_if` /
        // `preproc_elif` node (`#if HAVE_CHAR_TO_LOWER_WITH_CULTURE` flagged that
        // symbol as definite-uninitialized in csharp-newtonsoft `ToSeparatedCase`).
        // The condition may be a bare identifier or a boolean expression over
        // identifiers; suppress any identifier inside the `[condition]` subtree.
        if matches!(kind, "preproc_if" | "preproc_elif") {
            if let Some(cond) = parent.child_by_field_name("condition") {
                if self.node_contains(cond, node) {
                    return Some(false);
                }
            }
        }

        // ---- Member / attribute NAME position -------------------------------
        // Python `attribute`: `[object]` is a use, `[attribute]` (an
        // `identifier`) is a member name — never a local variable.
        if kind == "attribute" {
            if let Some(attr) = parent.child_by_field_name("attribute") {
                if attr.id() == node.id() {
                    return Some(false);
                }
            }
        }
        // Elixir `dot`: `a.b` -> `[left]` is the receiver (use / `alias`),
        // `[right]` is the called/looked-up member name.
        if matches!(self.language, Language::Elixir) && kind == "dot" {
            if let Some(right) = parent.child_by_field_name("right") {
                if right.id() == node.id() {
                    return Some(false);
                }
            }
        }
        // Java / Kotlin `field_access` member NAME: `xs.length` -> the `[field]`
        // child (an `identifier`, unlike Go/Rust which use `field_identifier`)
        // is a field name, never a local-variable use. (The `[object]` receiver
        // is a genuine use and falls through.)
        if kind == "field_access" {
            if let Some(field) = parent.child_by_field_name("field") {
                if field.id() == node.id() {
                    return Some(false);
                }
            }
        }
        // Kotlin `navigation_expression`: `obj.member` — the receiver is the
        // FIRST child (a use); any later `identifier` is the member/selector
        // name and is never a local-variable use.
        if matches!(self.language, Language::Kotlin) && kind == "navigation_expression" {
            if parent.child(0).map(|c| c.id()) != Some(node.id()) {
                return Some(false);
            }
            // fix-PW1-C3-nonvar-tokens (v0.5.0 BACKLOG, Wave 1 row C3): the
            // RECEIVER itself is a NON-use when it is a type / companion-object /
            // enum reference rather than a value. Kotlin's grammar cannot
            // distinguish `DateTimeUnit.MONTH` (type receiver) from `list.size`
            // (value receiver) structurally, but the language convention is
            // strict — types, objects and companions are PascalCase while locals
            // and parameters are camelCase. A PascalCase receiver
            // (`DateTimeUnit`, `Int`, `YearMonthProgression`) is therefore a
            // compile-time-resolved reference, never a local read. Guarded by
            // `generic_local_names` so a genuine local that shadows such a name
            // (which would carry its own Definition) keeps its reads. (Mirrors
            // the sanctioned Scala/C# uppercase-receiver disambiguation already
            // used elsewhere in this analyzer.)
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            if text
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
                && !self.generic_local_names.contains(text)
            {
                return Some(false);
            }
        }

        // ---- Scoped / qualified path segments -------------------------------
        // Rust `Type::assoc` / `module::item` — both the `[path]` (a type /
        // module) and the `[name]` (an associated fn / variant) are path
        // segments, never a local-variable use.
        if kind == "scoped_identifier" || kind == "scoped_type_identifier" {
            return Some(false);
        }
        // C++ `ns::item` — `qualified_identifier` wraps `[scope]
        // namespace_identifier` + `[name]`; neither segment is a local use.
        if kind == "qualified_identifier" {
            return Some(false);
        }
        // fix-PW1-C3-nonvar-tokens (v0.5.0 BACKLOG, Wave 1 row C3): Scala
        // `pkg.Type` / `obj.Type` qualified type paths parse as
        //   stable_type_identifier { identifier(qualifier)  type_identifier(name) }.
        // EVERY segment is a package / object / type path element, never a
        // local-variable read — including the leading lowercase package
        // qualifier (`mutable.HashMap`, `immutable.TreeSet`) which the
        // uppercase-only Scala heuristic in `extract_refs_from_node` does not
        // catch (scala-zio `newMutableMap` flagged `mutable` as definite-
        // uninitialized).
        if kind == "stable_type_identifier" {
            return Some(false);
        }

        // ---- Type-name positions --------------------------------------------
        // An identifier whose parent IS a type node is a type reference, not a
        // value read. (`generic_type` wraps the base `type_identifier`;
        // `type_descriptor` is the C/C++ cast/type-operand wrapper.)
        if matches!(
            kind,
            "type_identifier"
                | "primitive_type"
                | "generic_type"
                | "type_descriptor"
                | "type_arguments"
                | "user_type"
        ) {
            return Some(false);
        }

        // ---- Closure / lambda binders & comprehension targets ---------------
        // These positions introduce a DEFINITION (recorded elsewhere), so the
        // binder identifier itself is never a use.
        if matches!(
            kind,
            "closure_parameters" | "lambda_parameters" | "closure_parameter"
        ) {
            return Some(false);
        }
        // Python comprehension / generator binding: `x for x in xs` — the
        // `[left]` of a `for_in_clause` is the loop binder.
        if kind == "for_in_clause" {
            if let Some(left) = parent.child_by_field_name("left") {
                if self.node_contains(left, node) {
                    return Some(false);
                }
            }
        }

        None
    }

    fn parent_use_context(&self, parent: Node, node: Node) -> Option<bool> {
        let kind = parent.kind();

        // fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): the generic fallback
        // historically suppressed ONLY LHS/declaration/parameter positions, so
        // the ten languages without a bespoke `is_use_context` block (C, C++,
        // Go, Rust, Python, Kotlin, Elixir, ...) recorded callee names, member/
        // attribute NAME fields, type names, scoped-path segments, and
        // closure/comprehension binders as variable Uses — all flagged
        // `definite uninitialized`. Classify these structural NON-use positions
        // first (AST-keyed on tree-sitter node kinds, verified by debug-parse).
        if let Some(non_use) = self.generic_non_use_position(parent, node) {
            return Some(non_use);
        }

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
                // rc3: a weak element/field write reads the base (a use) and
                // does NOT rebind it — it is not a killing def.
                RefType::Use | RefType::WeakUpdate => {
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

        // stmt-edge-v1 (R3-r7-cl11-rust-match-arm-cross-variable-dfg, v0.5.0
        // CLOSEOUT): SECOND pass — the missing CROSS-VARIABLE, statement-granular
        // flow-dependence edge. The per-variable loop above can only express
        // `def(v) -> use(v)` for ONE name; it therefore drops the dependency that
        // flows through a MULTI-LINE right-hand side — `let bytes = match s { ..
        // value .. }`, an `if/else`, a block tail, the C/Go/TS/Python ternary &
        // switch analogues — where `bytes` is computed FROM `value` but the
        // backward slice of `bytes` never reaches the def of `value`.
        //
        // Per the canonical PDG/SDG model (Horwitz–Reps–Binkley TOPLAS'90,
        // Ferrante–Ottenstein–Warren TOPLAS'87) a statement's DEFINITION depends
        // on EVERY variable USED in that same statement. We add exactly that edge
        // class, scoped by the defining-statement id stamped into `group_id` by
        // `extract_rhs_with_stmt` / `tag_stmt_span`. The edge runs from the used
        // var's REACHING DEF (`value`@3) to the LHS def SITE (`bytes`@4), so the
        // slice closure (slice.rs:`run_data_closure`) hops criterion -> LHS-def
        // -> used-var-def WITHOUT pulling in the scattered RHS read lines, and
        // NO read's own `line` is ever moved (line-preserving — `reaching-defs`
        // / `dead-stores` / `taint` line attributions are unchanged).
        let mut lhs_by_stmt: HashMap<u32, Vec<&VarRef>> = HashMap::new();
        let mut uses_by_stmt: HashMap<u32, Vec<&VarRef>> = HashMap::new();
        for r in &self.refs {
            if let Some(sid) = r.group_id {
                match r.ref_type {
                    RefType::Definition | RefType::Update => {
                        lhs_by_stmt.entry(sid).or_default().push(r);
                    }
                    // rc3: weak element/field write is a use of the base.
                    RefType::Use | RefType::WeakUpdate => {
                        uses_by_stmt.entry(sid).or_default().push(r);
                    }
                }
            }
        }
        // Dedup against the per-variable edges already emitted (and within this
        // pass), so a scrutinee already linked by the per-variable model
        // (`match s` -> `s`@param) is not duplicated. Net effect: a small,
        // strictly ADDITIVE set of correct cross-variable edges.
        let mut seen_cross: HashSet<(String, u32, u32)> = edges
            .iter()
            .map(|e| (e.var.clone(), e.def_line, e.use_line))
            .collect();
        for (sid, lhs_defs) in &lhs_by_stmt {
            let Some(stmt_uses) = uses_by_stmt.get(sid) else {
                continue;
            };
            // Only single-LHS statements: a parallel/tuple binding
            // (`a, b = c, d`) would mis-pair defs to uses (`a`->`d`), so we
            // conservatively skip it — additive-only, never a regression.
            let def_names: HashSet<&str> = lhs_defs.iter().map(|d| d.name.as_str()).collect();
            if def_names.len() != 1 {
                continue;
            }
            for &def in lhs_defs {
                for &u in stmt_uses {
                    // Skip the self-read of `x = x + 1` (the `Update`+`Use`
                    // path already models it); we only want CROSS-variable flow.
                    if u.name == def.name {
                        continue;
                    }
                    // Reaching def of the USED var at its use site: the def of
                    // `u.name` with the greatest line <= `u.line`. Anchoring on
                    // the used var's DEF (not its scattered RHS read line) keeps
                    // the match arms / branch bodies OUT of the slice.
                    let Some(rdef) = defs_by_var.get(&u.name).and_then(|ds| {
                        ds.iter()
                            .copied()
                            .filter(|d| d.line <= u.line)
                            .max_by_key(|d| d.line)
                    }) else {
                        continue;
                    };
                    if rdef.line == def.line {
                        // Same-line def of another var: no slicing distinction,
                        // skip the self-loop edge.
                        continue;
                    }
                    let key = (u.name.clone(), rdef.line, def.line);
                    if !seen_cross.insert(key) {
                        continue;
                    }
                    edges.push(DataflowEdge {
                        var: u.name.clone(), // label = the READ var (CPG REACHING_DEF.VARIABLE)
                        def_line: rdef.line, // source = used var's reaching def (line 3)
                        use_line: def.line,  // sink   = the LHS def site (line 4)
                        def_ref: rdef.clone(),
                        use_ref: def.clone(),
                    });
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

/// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): true when `s` is a
/// SCREAMING_SNAKE_CASE identifier — at least one ASCII letter, and every
/// character is an uppercase ASCII letter, an ASCII digit, or an underscore.
/// Used to recognize C/C++ preprocessor macros / `#define` constants (which a
/// single-file analysis cannot otherwise resolve when they live in a header).
fn is_screaming_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut has_letter = false;
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            has_letter = true;
        } else if c.is_ascii_digit() || c == '_' {
            // allowed, not a letter
        } else {
            return false;
        }
    }
    has_letter
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
    // fix-R2-themeC (v0.5.0 CLOSEOUT, RC1): the implicit per-function
    // `arguments` object is always bound inside any non-arrow function body, so
    // a read of `arguments` (`arguments.length`, `arguments[0]`) is never a free
    // variable (js-lodash `flatSpread` flagged it definite-uninitialized). A
    // genuine local literally named `arguments` would carry its own Definition
    // and be recorded in `ts_js_local_names`, so its reads still survive.
    "arguments",
    // Browser / DOM host
    "document", "window", "navigator", "self", "location", "history",
    "fetch", "XMLHttpRequest", "FormData", "URL", "URLSearchParams",
    "localStorage", "sessionStorage",
];

/// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Go predeclared identifiers
/// (the universe block — Go spec "Predeclared identifiers"). Used as builtins
/// in value/conversion/call positions (`make`, `len`, `string(b)`); none is a
/// local-variable use. Seeding them lets the value-position read of a builtin
/// (and the conversion form `string(x)`) be classified not-a-use.
const GO_BUILTINS: &[&str] = &[
    // Functions
    "append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make",
    "max", "min", "new", "panic", "print", "println", "real", "recover",
    // Types (also used as conversions: `string(b)`, `int(x)`)
    "any", "bool", "byte", "comparable", "complex64", "complex128", "error", "float32",
    "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8",
    "uint16", "uint32", "uint64", "uintptr",
    // Constants / zero value
    "true", "false", "iota", "nil",
];

/// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Python builtins (CPython
/// `builtins` module). A bare reference to one of these in a value position is
/// not a local-variable use. (Callee positions like `str(x)` are already
/// handled structurally; this catches non-call reads such as passing `len` as
/// a callback or `str` as a default.)
const PYTHON_BUILTINS: &[&str] = &[
    // Common callable builtins
    "abs", "aiter", "all", "anext", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
    "bytes", "callable", "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir",
    "divmod", "enumerate", "eval", "exec", "filter", "float", "format", "frozenset", "getattr",
    "globals", "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance",
    "issubclass", "iter", "len", "list", "locals", "map", "max", "memoryview", "min", "next",
    "object", "oct", "open", "ord", "pow", "print", "property", "range", "repr", "reversed",
    "round", "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
    "tuple", "type", "vars", "zip",
    // Constants / singletons
    "True", "False", "None", "NotImplemented", "Ellipsis", "__debug__",
    // Common exception names (used bare in `raise X` / `except (A, B)`)
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "StopIteration", "OSError", "IOError", "FileNotFoundError",
    "NotImplementedError", "ZeroDivisionError", "ArithmeticError", "ImportError",
];

/// fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT, RC1): Rust prelude value names
/// (variants / functions) that appear as bare value-position reads. Type names
/// and `Type::assoc` paths are handled structurally by
/// `generic_non_use_position`; this covers the bare variant reads (`None`,
/// `Ok`, `Err`, `Some` used without a path) that occur in value positions.
const RUST_PRELUDE: &[&str] = &[
    "Some", "None", "Ok", "Err", "Box", "Vec", "String", "Option", "Result", "Default",
    "Clone", "Copy", "drop", "Drop",
];

/// fix-R2-themeC (v0.5.0 CLOSEOUT, RC2): Solidity language-level globals — magic
/// objects the EVM injects into every function scope (Solidity docs "Units and
/// Globally Available Variables" / "Block and Transaction Properties"). A bare
/// reference to one of these is never a local variable, so it must never be
/// classified as a definite-uninitialized read.
const SOLIDITY_GLOBALS: &[&str] = &[
    "msg", "block", "tx", "now", "this", "super", "abi",
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

/// C4a-js-closure-liveness (v0.5.0 BACKLOG): true iff `kind` is a JS/TS node
/// that introduces a new function (lexical) scope. Mirrors the JS/TS arm of
/// `get_function_node_kinds`; `program` (the module root) is handled separately
/// by the caller as the outermost scope.
fn js_ts_is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
    )
}

/// C4a-js-closure-liveness (v0.5.0 BACKLOG): collect the identifier names bound
/// DIRECTLY in one JS/TS lexical scope `scope_node` — a function node (any of
/// the kinds `js_ts_is_function_scope` accepts) or the file `program` root.
/// Records the scope's `parameters`, every `var`/`let`/`const` declarator name
/// (descending through blocks/statements — `var` is function-scoped, so a `var`
/// inside a nested block belongs to this scope; treating `let`/`const` the same
/// way only ever OVER-approximates a scope's own locals, which is safe for the
/// upvalue test), every hoisted nested `function_declaration` NAME (which binds
/// in the enclosing scope), `catch` binders, and `for (const x of …)` binders.
///
/// Recursion STOPS at nested function boundaries: an inner helper's own locals
/// (and a named `function_expression`'s own name) belong to the inner scope and
/// are never mis-attributed to `scope_node`. The JS/TS analog of
/// `collect_lua_scope_bindings`.
fn collect_js_ts_scope_bindings(
    scope_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    // A function scope binds its parameters (the program root has none).
    if let Some(params) = scope_node.child_by_field_name("parameters") {
        collect_ts_js_param_names(params, source, out);
    }
    let mut stack: Vec<Node> = Vec::new();
    let mut cursor = scope_node.walk();
    for child in scope_node.children(&mut cursor) {
        stack.push(child);
    }
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if js_ts_is_function_scope(kind) {
            // Nested function: a hoisted `function_declaration` /
            // `generator_function_declaration` binds its NAME in THIS scope
            // (record it). NEVER descend into any nested function body.
            if matches!(kind, "function_declaration" | "generator_function_declaration") {
                if let Some(name) = n.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        if let Ok(t) = name.utf8_text(source.as_bytes()) {
                            let t = t.trim();
                            if !t.is_empty() {
                                out.insert(t.to_string());
                            }
                        }
                    }
                }
            }
            continue;
        }
        match kind {
            // `var`/`let`/`const x = …`: collect LHS binder names only; the
            // initializer may hold function literals with their OWN scopes, so
            // `collect_ts_js_variable_names` reads only each declarator `name`.
            "lexical_declaration" | "variable_declaration" => {
                collect_ts_js_variable_names(n, source, out);
                continue;
            }
            // `catch (e) { … }` binder is scoped to the handler/function.
            "catch_clause" => {
                if let Some(param) = n.child_by_field_name("parameter") {
                    collect_ts_js_param_names(param, source, out);
                }
            }
            // `for (const/let/var x of … | in …)` binds `x` when a declarator
            // `kind` token is present. A kind-less `for (x of …)` re-assigns an
            // existing binding and is NOT a new binder, so it is left untouched.
            "for_in_statement" => {
                if n.child_by_field_name("kind").is_some() {
                    if let Some(left) = n.child_by_field_name("left") {
                        collect_ts_js_param_names(left, source, out);
                    }
                }
            }
            _ => {}
        }
        let mut inner = n.walk();
        for child in n.children(&mut inner) {
            stack.push(child);
        }
    }
}

/// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): insert a
/// Lua/Luau `identifier` node's text into a binder set (trimmed, non-empty).
fn insert_lua_identifier(node: Node, source: &str, out: &mut std::collections::HashSet<String>) {
    if node.kind() == "identifier" {
        if let Ok(t) = node.utf8_text(source.as_bytes()) {
            let t = t.trim();
            if !t.is_empty() {
                out.insert(t.to_string());
            }
        }
    }
}

/// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): true iff a
/// Lua/Luau function node introduces a LOCAL binding for its own name in the
/// ENCLOSING scope — `local function f` (a `function_declaration` carrying a
/// `local` token) or the dedicated `local_function` node-kind. A bare
/// `function f()` / `function t.m()` binds a global / table field (not a local)
/// and an anonymous `function_definition` binds no name at all.
fn lua_function_is_local(func_node: Node) -> bool {
    if func_node.kind() == "local_function" {
        return true;
    }
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "local" {
            return true;
        }
    }
    false
}

/// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): collect the
/// parameter identifiers of a Lua/Luau `parameters` node. tree-sitter-lua lists
/// param identifiers directly; tree-sitter-luau wraps each in a `parameter`
/// node whose identifier sits one level deeper (`parameter > type? >
/// identifier`) — mirror `extract_lua_param`.
fn collect_lua_param_binder_names(
    params: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" => insert_lua_identifier(child, source, out),
            "parameter" => {
                if let Some(id) = first_descendant_identifier_under(child, "identifier") {
                    insert_lua_identifier(id, source, out);
                }
            }
            _ => {}
        }
    }
}

/// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): collect the
/// names introduced by ONE Lua/Luau `variable_declaration` (`local x = …`).
/// Only the LHS `variable_list` identifiers are bindings; the RHS
/// `expression_list` may contain function literals with their OWN scopes, so it
/// is intentionally NOT descended into.
fn collect_lua_decl_binder_names(
    decl: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        match child.kind() {
            // `local x` (no initializer) — bare identifier child.
            "identifier" => insert_lua_identifier(child, source, out),
            // `local x, y` (no initializer) — a `variable_list` child.
            "variable_list" => {
                let mut vc = child.walk();
                for v in child.children(&mut vc) {
                    insert_lua_identifier(v, source, out);
                }
            }
            // `local x = …` / `local a, b = …` — the inner assignment's LHS.
            "assignment_statement" => {
                let mut ac = child.walk();
                for a in child.children(&mut ac) {
                    if a.kind() == "variable_list" {
                        let mut vc = a.walk();
                        for v in a.children(&mut vc) {
                            insert_lua_identifier(v, source, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// rc6-deadstores-closure-write-across-siblings (v0.5.0 CLOSEOUT): collect the
/// identifiers bound DIRECTLY in one Lua/Luau lexical scope `scope_node` — a
/// function node (`function_declaration` / `function_definition` /
/// `local_function`) or the file `chunk`. Records the scope's `parameters`,
/// every `local x = …` (`variable_declaration`), every `local function g`
/// name, and numeric/generic for-loop binders. Recursion STOPS at nested
/// function boundaries: an inner helper's own locals belong to the inner scope
/// (the grammar authors' `@local.scope` model — Luau LOCALS_QUERY), so they are
/// never mis-attributed to `scope_node`. A bare `assignment_statement` target
/// is NOT a binding (it re-assigns an existing local / upvalue / global) and is
/// deliberately not collected — Q1 proves the `local` declaration wrapper is the
/// only node-kind binding marker.
fn collect_lua_scope_bindings(
    scope_node: Node,
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    // A function scope binds its parameters (the chunk has none).
    if let Some(params) = scope_node.child_by_field_name("parameters") {
        collect_lua_param_binder_names(params, source, out);
    }
    // Walk the scope's statements, descending through block / control-flow
    // scopes but never into a nested function body.
    let mut stack: Vec<Node> = Vec::new();
    let mut cursor = scope_node.walk();
    for child in scope_node.children(&mut cursor) {
        stack.push(child);
    }
    while let Some(n) = stack.pop() {
        match n.kind() {
            // Nested function: record its name when it is a `local function`
            // (the name binds in THIS scope), but do NOT descend.
            "function_declaration" | "function_definition" | "local_function" => {
                if lua_function_is_local(n) {
                    if let Some(name) = n.child_by_field_name("name") {
                        insert_lua_identifier(name, source, out);
                    }
                }
                continue;
            }
            // `local x = …`: collect LHS names only; do not descend into the RHS.
            "variable_declaration" => {
                collect_lua_decl_binder_names(n, source, out);
                continue;
            }
            // for-loop binders (numeric `for i = …` / generic `for a, b in …`).
            "for_numeric_clause" => {
                if let Some(name) = n.child_by_field_name("name") {
                    insert_lua_identifier(name, source, out);
                }
            }
            "for_generic_clause" => {
                let mut cc = n.walk();
                for c in n.children(&mut cc) {
                    if c.kind() == "variable_list" {
                        let mut vc = c.walk();
                        for v in c.children(&mut vc) {
                            insert_lua_identifier(v, source, out);
                        }
                    }
                }
            }
            _ => {}
        }
        let mut inner = n.walk();
        for child in n.children(&mut inner) {
            stack.push(child);
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

/// fix-CF1-S9: follow a C/C++ declarator's `declarator` chain down to its
/// innermost name leaf. `pointer_declarator` / `reference_declarator` /
/// `array_declarator` / `init_declarator` each expose the wrapped declarator on
/// the `declarator` field; the leaf is a `field_identifier` (class member) or an
/// `identifier` (global). A `function_declarator` declarator (a prototype) has no
/// such leaf, so `None` is returned and the prototype is skipped.
fn cpp_declarator_leaf_name(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "field_identifier" | "identifier" => node
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        "pointer_declarator"
        | "reference_declarator"
        | "array_declarator"
        | "init_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            cpp_declarator_leaf_name(inner, source)
        }
        _ => None,
    }
}

/// fix-CF1-S9: derive the local binding name introduced by a Go `import_spec`.
/// An explicit `name` field (alias / blank `_` / dot `.`) takes precedence;
/// otherwise the package name is the last `/`-separated segment of the import
/// path string (`"net/http"` -> `http`), Go's default package-binding rule.
fn go_import_binding_name(node: Node, source: &str) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return name
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
    }
    let path = node.child_by_field_name("path")?;
    let text = path.utf8_text(source.as_bytes()).ok()?;
    let trimmed = text.trim().trim_matches('"').trim_matches('`');
    let seg = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
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

/// fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): declarative descriptor of a loop
/// construct's HEADER anatomy — the loop-descriptor "registry" value consumed
/// by [`RefExtractor::process_loop_header`].
///
/// A loop header names loop-variable BINDERS (definitions) and references
/// variables in its iterable / init / condition / update / guard USE-sites.
/// Several grammars route their `for` / `foreach` / for-comprehension node to a
/// shape the legacy Python-shaped `process_for_loop` could not read (it only
/// understands the `left`/`right`/`body` fields), silently dropping every
/// header use. The registry collapses the whole class to three structural
/// shapes so one driver handles them all and the next language is a one-row
/// addition (see [`loop_header_descriptor`]).
enum LoopHeader {
    /// C-style `for (init; cond; update) body`. The `init_field` is processed
    /// by [`RefExtractor::process_loop_init`] (records the loop-variable binder
    /// as a pre-initialized Definition + the init RHS as uses); the
    /// `update_field` by [`RefExtractor::process_loop_update`] (records the
    /// loop variable as a read, not a fresh write-version); the `cond_field`
    /// and `body_field` are recursed through normal dispatch so their
    /// identifier reads become uses. Grammars name the fields differently, so
    /// the names are part of the descriptor.
    CStyle {
        init_field: &'static str,
        cond_field: &'static str,
        update_field: &'static str,
        body_field: &'static str,
    },
    /// PHP `foreach (<iterable> as <binder>) body`: the iterable is the direct
    /// named child(ren) BEFORE the `as` token (Uses); the binder is the child
    /// AFTER `as` (`variable_name` / `pair` / `by_ref`, Definitions).
    ForeachAs,
    /// Scala for-comprehension `for (<enumerators>) body`: the `enumerators_kind`
    /// child holds `enumerator` nodes (`binder <- iterable [guard]`); the
    /// pre-`<-`/`=` identifiers are loop binders, the rest are uses. (The
    /// `enumerators` FIELD name also labels the surrounding `(` `)` tokens, so
    /// the node is located by KIND, not by field.)
    Comprehension {
        enumerators_kind: &'static str,
        body_fields: &'static [&'static str],
    },
}

/// fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): the loop-descriptor registry.
///
/// Maps `(language, AST node-kind)` to the [`LoopHeader`] shape describing how
/// to collect that loop's header binders and use-sites. Only the constructs
/// whose header uses were being DROPPED are registered here; the already-
/// shape-aware Go / C / Java / C# / Kotlin / Lua handlers are left untouched
/// (blast-radius containment). Returns `None` for any unregistered node, in
/// which case the driver recurses all named children defensively.
fn loop_header_descriptor(language: Language, kind: &str) -> Option<LoopHeader> {
    match (language, kind) {
        // PHP `for ($i = $start; $i < $n; ++$i)` — fields initialize/condition/
        // update/body.
        (Language::Php, "for_statement") => Some(LoopHeader::CStyle {
            init_field: "initialize",
            cond_field: "condition",
            update_field: "update",
            body_field: "body",
        }),
        // JS/TS `for (let i = n; i < 10; i++)` — fields initializer/condition/
        // increment/body.
        (Language::JavaScript | Language::TypeScript, "for_statement") => {
            Some(LoopHeader::CStyle {
                init_field: "initializer",
                cond_field: "condition",
                update_field: "increment",
                body_field: "body",
            })
        }
        // Solidity `for (uint i = n; i < 10; i++)` — fields initial/condition/
        // update/body.
        (Language::Solidity, "for_statement") => Some(LoopHeader::CStyle {
            init_field: "initial",
            cond_field: "condition",
            update_field: "update",
            body_field: "body",
        }),
        // PHP `foreach (<iter> as [<k> =>] <v>)`.
        (Language::Php, "foreach_statement") => Some(LoopHeader::ForeachAs),
        // Scala `for (x <- xs if g) body` / `for { ... } yield ...`.
        (Language::Scala, "for_expression") => Some(LoopHeader::Comprehension {
            enumerators_kind: "enumerators",
            body_fields: &["body"],
        }),
        _ => None,
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
    // stmt-edge-v1 (R3-r7-cl11): cross-variable, statement-granular flow
    // dependence through a MULTI-LINE RHS (`let bytes = match s {..value..}`).
    // The per-variable model only emits `def(v)->use(v)`; these tests pin the
    // ADDED `def(LHS) <- use(RHS-var)` edge class in `finalize`.
    // =========================================================================

    #[test]
    fn test_stmt_edge_rust_match_arm_cross_variable() {
        // line 1 blank, 2 = signature, 3 = `let digits`, 4 = `let value`,
        // 5 = `let bytes = match s {`, 6/7 = arms reading `value`, 8 = `_ =>`,
        // 9 = `};`, 10 = `bytes`.
        let source = r#"
fn parse(s: &str) -> u64 {
    let digits = "100";
    let value: u64 = digits.parse().unwrap();
    let bytes = match s {
        "KB" => value.checked_mul(1024).unwrap(),
        "MB" => value.checked_mul(1024 * 1024).unwrap(),
        _ => value,
    };
    bytes
}
"#;
        let dfg = get_dfg_context(source, "parse", Language::Rust).unwrap();

        // The cross-variable edge: `value`'s reaching def (line 4) -> `bytes`'s
        // def SITE (line 5). This is the edge that was structurally missing.
        let has_cross = dfg
            .edges
            .iter()
            .any(|e| e.var == "value" && e.def_line == 4 && e.use_line == 5);
        assert!(
            has_cross,
            "expected cross-variable edge value(def@4) -> bytes-def-site(@5); edges = {:?}",
            dfg.edges
                .iter()
                .map(|e| (e.var.as_str(), e.def_line, e.use_line))
                .collect::<Vec<_>>()
        );

        // Regression guard: no RHS read's stored line moved — `value`'s reads
        // are still anchored at lines 6/7/8, NOT retagged to the def line.
        let value_use_lines: Vec<u32> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "value" && r.ref_type == RefType::Use)
            .map(|r| r.line)
            .collect();
        assert!(
            value_use_lines.contains(&6)
                && value_use_lines.contains(&7)
                && value_use_lines.contains(&8),
            "value reads must keep their own lines (6,7,8); got {value_use_lines:?}"
        );
    }

    #[test]
    fn test_stmt_edge_no_false_edge_across_statements() {
        // Two independent statements sharing nothing: `a = x`, `b = y`. The
        // group_id scoping must NOT manufacture an `a<->y` or `b<->x` edge.
        let source = r#"
fn n(x: u64, y: u64) -> u64 {
    let a = x;
    let b = y;
    a + b
}
"#;
        let dfg = get_dfg_context(source, "n", Language::Rust).unwrap();

        // `a` (def line 3) must never depend on `y`, and `b` (def line 4)
        // must never depend on `x`.
        let a_on_y = dfg
            .edges
            .iter()
            .any(|e| e.var == "y" && e.use_line == 3);
        let b_on_x = dfg
            .edges
            .iter()
            .any(|e| e.var == "x" && e.use_line == 4);
        assert!(!a_on_y, "spurious cross-statement edge a<-y");
        assert!(!b_on_x, "spurious cross-statement edge b<-x");
    }

    #[test]
    fn test_stmt_edge_single_line_rhs_no_extra_def_line() {
        // Single-line RHS `let bytes = value + 1`: the cross edge must connect
        // to `value`'s SAME def line the per-variable model already reaches —
        // no NEW def line is introduced (no over-inclusion).
        let source = r#"
fn f() -> u64 {
    let value: u64 = 1;
    let bytes = value + 1;
    bytes
}
"#;
        let dfg = get_dfg_context(source, "f", Language::Rust).unwrap();
        // Every `value`-labeled edge must have def_line == 3 (value's only def).
        for e in dfg.edges.iter().filter(|e| e.var == "value") {
            assert_eq!(
                e.def_line, 3,
                "single-line RHS must not invent a value def line other than 3"
            );
        }
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

    /// fix-R7-cl6-go-named-return (v0.5.0 CLOSEOUT): named results are recorded
    /// as Definitions at function entry (implicit zero-init) AND a naked
    /// `return` synthesizes a Use of each.
    #[test]
    fn test_go_named_results_def_at_entry_and_naked_return_use() {
        let source = r#"
package main

func getValue(path string) (handle int, ps string, tsr bool) {
    tsr = true
    return
}
"#;
        let dfg = get_dfg_context(source, "getValue", Language::Go).unwrap();
        // Each named result has a Definition at entry (so reaching-defs never
        // flags an un-assigned named result read by the naked return as
        // uninitialized).
        for name in ["handle", "ps", "tsr"] {
            assert!(
                dfg.refs
                    .iter()
                    .any(|r| r.name == name && matches!(r.ref_type, RefType::Definition)),
                "named result `{}` must have an entry Definition; refs={:?}",
                name,
                dfg.refs
                    .iter()
                    .filter(|r| r.name == name)
                    .map(|r| (&r.ref_type, r.line))
                    .collect::<Vec<_>>()
            );
        }
        // The naked return synthesizes a Use of each named result.
        for name in ["handle", "ps", "tsr"] {
            assert!(
                dfg.refs
                    .iter()
                    .any(|r| r.name == name && matches!(r.ref_type, RefType::Use)),
                "named result `{}` must have a Use synthesized at the naked return",
                name
            );
        }
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

    /// fix-R7 (cluster[11] RC4): Kotlin `for (i in range) { body }` —
    /// the `for_statement` node has POSITIONAL children (variable_declaration,
    /// in, iterable, block), NONE of which carry the `left`/`right`/`body`
    /// field names the Python-shaped `process_for_loop` reads. Before this fix
    /// Kotlin fell through to that handler, which found nothing, so the loop
    /// variable, the iterable read, AND the entire loop body (including
    /// loop-carried reassignments) were dropped — slices collapsed to 0 edges.
    #[test]
    fn test_kotlin_for_loop_var_iterable_and_body_captured() {
        let source = r#"
fun multiplyAndDivide(a: Int, b: Int): Int {
    var r = a
    for (i in 1..b) {
        r = r * 2
        r = r + i
    }
    return r
}
"#;
        let dfg = get_dfg_context(source, "multiplyAndDivide", Language::Kotlin).unwrap();

        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        let uses: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.ref_type == RefType::Use)
            .map(|r| r.name.as_str())
            .collect();

        // Loop variable `i` is defined by the for-binder.
        assert!(
            defs.contains(&"i"),
            "Kotlin for loop variable `i` must be a definition, got defs: {:?}",
            defs
        );
        // The iterable `1..b` reads `b`.
        assert!(
            uses.contains(&"b"),
            "Kotlin for iterable must read `b`, got uses: {:?}",
            uses
        );
        // Loop body reassignments of `r` (loop-carried) must be recorded.
        assert!(
            defs.contains(&"r"),
            "Kotlin loop body reassignment of `r` must be recorded, got defs: {:?}",
            defs
        );
        // `i` is read inside the body (`r = r + i`).
        assert!(
            uses.contains(&"i"),
            "Kotlin loop body use of `i` must be recorded, got uses: {:?}",
            uses
        );
    }

    /// fix-R7 (cluster[11] RC4): a TYPED Kotlin loop binder `for (x: Int in ..)`
    /// must record `x` as the loop variable but must NOT record the type name
    /// `Int` as a definition (the `user_type` subtree wraps a plain identifier
    /// in this grammar).
    #[test]
    fn test_kotlin_for_typed_binder_excludes_type_name() {
        let source = r#"
fun f(items: List<Int>): Int {
    var s = 0
    for (x: Int in items) {
        s = s + x
    }
    return s
}
"#;
        let dfg = get_dfg_context(source, "f", Language::Kotlin).unwrap();
        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(defs.contains(&"x"), "typed loop var `x` must be a def, got {:?}", defs);
        assert!(
            !defs.contains(&"Int"),
            "type name `Int` must NOT be recorded as a loop-variable definition, got {:?}",
            defs
        );
    }

    /// fix-R7 (cluster[11] RC4): destructuring Kotlin loop binder
    /// `for ((k, v) in map)` records both `k` and `v` as definitions.
    #[test]
    fn test_kotlin_for_destructuring_binder() {
        let source = r#"
fun f(m: Map<String, Int>): Int {
    var s = 0
    for ((k, v) in m) {
        s = s + v
    }
    return s
}
"#;
        let dfg = get_dfg_context(source, "f", Language::Kotlin).unwrap();
        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
            .map(|r| r.name.as_str())
            .collect();
        assert!(defs.contains(&"k"), "destructured `k` must be a def, got {:?}", defs);
        assert!(defs.contains(&"v"), "destructured `v` must be a def, got {:?}", defs);
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

    // ===================================================================
    // C1-gen-bindings (v0.5.0 BACKLOG): per-language binding forms that
    // were missing from GEN, causing false definite-uninitialized.
    // Symptom class: elixir, ruby, ocaml, c.
    // ===================================================================

    /// Collect the names of all `Definition` refs for a function.
    fn c1_def_names(source: &str, func: &str, lang: Language) -> Vec<String> {
        let dfg = get_dfg_context(source, func, lang).unwrap();
        dfg.refs
            .iter()
            .filter(|r| r.ref_type == RefType::Definition)
            .map(|r| r.name.clone())
            .collect()
    }

    /// Collect the names flagged `definite`-severity uninitialized by the full
    /// reaching-defs pipeline (the exact thing the symptom reports as a FP).
    fn c1_definite_uninit(source: &str, func: &str, lang: Language) -> Vec<String> {
        use std::path::PathBuf;
        let cfg = crate::get_cfg_context(source, func, lang).unwrap();
        let dfg = get_dfg_context(source, func, lang).unwrap();
        let report = crate::dfg::build_reaching_defs_report(&cfg, &dfg.refs, PathBuf::from("t"));
        report
            .uninitialized
            .iter()
            .filter(|u| u.severity == crate::dfg::UninitSeverity::Definite)
            .map(|u| u.var.clone())
            .collect()
    }

    /// GENERALIZATION (MANDATORY): EVERY language/variant in the symptom class
    /// — elixir struct/map destructure + struct-pattern param, ruby
    /// parallel/multiple assignment, ocaml `fun ~dir xs` params + match binds,
    /// c bare pointer/array decl — must enter GEN as a `Definition`, and none
    /// may be flagged definite-uninitialized. A single-variant pass is a FAIL.
    #[test]
    fn test_c1_gen_bindings_generalization_all_langs() {
        // --- Elixir: own-param `%Conn{} = conn` (HIGH) + map destructure ---
        let ex = r#"
defmodule Foo do
  def call(%Conn{} = conn, opts) do
    %{a: a} = conn
    bar(a, conn, opts)
  end
end
"#;
        let defs = c1_def_names(ex, "call", Language::Elixir);
        for name in ["conn", "a", "opts"] {
            assert!(
                defs.contains(&name.to_string()),
                "elixir: `{}` should be a Definition (GEN), got {:?}",
                name,
                defs
            );
        }
        let uninit = c1_definite_uninit(ex, "call", Language::Elixir);
        assert!(
            !uninit.contains(&"conn".to_string()),
            "elixir HIGH: own param `conn` must not be definite-uninitialized, got {:?}",
            uninit
        );
        assert!(
            !uninit.contains(&"a".to_string()),
            "elixir: map-destructure `a` must not be definite-uninitialized, got {:?}",
            uninit
        );

        // --- Ruby: parallel `a, _ = …` and multiple `x, y, z = …` ---
        let rb = r#"
def foo
  a, _ = bar()
  baz(a)
end
"#;
        let defs = c1_def_names(rb, "foo", Language::Ruby);
        assert!(
            defs.contains(&"a".to_string()),
            "ruby: `a` from `a, _ = …` should be a Definition (GEN), got {:?}",
            defs
        );
        assert!(
            !c1_definite_uninit(rb, "foo", Language::Ruby).contains(&"a".to_string()),
            "ruby: `a` must not be definite-uninitialized",
        );

        // --- OCaml: `fun ~dir xs ->` params + match-arm binder ---
        let ml = r#"
let f = fun ~dir xs -> g dir xs
"#;
        let defs = c1_def_names(ml, "f", Language::Ocaml);
        for name in ["dir", "xs"] {
            assert!(
                defs.contains(&name.to_string()),
                "ocaml: fun param `{}` should be a Definition (GEN), got {:?}",
                name,
                defs
            );
        }
        let ml_uninit = c1_definite_uninit(ml, "f", Language::Ocaml);
        for name in ["dir", "xs"] {
            assert!(
                !ml_uninit.contains(&name.to_string()),
                "ocaml: fun param `{}` must not be definite-uninitialized, got {:?}",
                name,
                ml_uninit
            );
        }
        // OCaml match-arm binder also enters GEN.
        let ml2 = r#"
let h x =
  match x with
  | Some y -> y + 1
  | None -> 0
"#;
        assert!(
            c1_def_names(ml2, "h", Language::Ocaml).contains(&"y".to_string()),
            "ocaml: match binder `y` should be a Definition (GEN)",
        );

        // --- C: bare pointer `int *p;` and array `char buf[16];` decls ---
        let c = r#"
int foo(int n) {
    int *p;
    char buf[16];
    compute(&p, buf);
    return *p + buf[0] + n;
}
"#;
        let defs = c1_def_names(c, "foo", Language::C);
        for name in ["p", "buf"] {
            assert!(
                defs.contains(&name.to_string()),
                "c: bare decl `{}` should be a Definition (GEN), got {:?}",
                name,
                defs
            );
        }
        let c_uninit = c1_definite_uninit(c, "foo", Language::C);
        for name in ["p", "buf"] {
            assert!(
                !c_uninit.contains(&name.to_string()),
                "c: bare decl `{}` must not be definite-uninitialized, got {:?}",
                name,
                c_uninit
            );
        }
        // An array declarator's SIZE identifier must NOT be mistaken for the
        // bound name (`long arr[N];` binds `arr`, not `N`).
        let c2 = r#"
int sz(int N) {
    long arr[N];
    fill(arr);
    return arr[0];
}
"#;
        let defs = c1_def_names(c2, "sz", Language::C);
        assert!(
            defs.contains(&"arr".to_string()),
            "c: `arr` should be the bound name of `long arr[N];`, got {:?}",
            defs
        );
    }

    /// PARITY: the Elixir pin/alias/`when`-guard semantics must be UNCHANGED by
    /// routing match/param LHS through `extract_elixir_pattern_bindings`.
    #[test]
    fn test_c1_elixir_pattern_parity() {
        // Pinned `^expected` is a MATCH against an existing value, never a new
        // binding; the upper-case alias `Conn` in `%Conn{}` is a module ref,
        // never a binding. `expected` and `conn` are the two parameters (each a
        // single Definition); the pin must NOT add a second `expected` binding.
        let src = r#"
defmodule M do
  def handle(expected, conn) do
    %Conn{status: ^expected} = conn
    work(conn)
  end
end
"#;
        let defs = c1_def_names(src, "handle", Language::Elixir);
        assert_eq!(
            defs.iter().filter(|d| *d == "expected").count(),
            1,
            "elixir parity: pinned `^expected` must not add a binding beyond the param, got {:?}",
            defs
        );
        assert!(
            !defs.contains(&"Conn".to_string()),
            "elixir parity: upper-case alias `Conn` must never be a Definition, got {:?}",
            defs
        );
        // `conn` is the parameter (a Definition); the match RHS reads it.
        assert!(
            defs.contains(&"conn".to_string()),
            "elixir parity: param `conn` must be a Definition, got {:?}",
            defs
        );

        // `when`-guard handling preserved: `def f(x) when is_atom(x)` binds `x`
        // once; the guard is not a binder.
        let guard = r#"
defmodule G do
  def f(x) when is_atom(x) do
    use_it(x)
  end
end
"#;
        let defs = c1_def_names(guard, "f", Language::Elixir);
        assert!(
            defs.contains(&"x".to_string()),
            "elixir parity: guarded param `x` must be a Definition, got {:?}",
            defs
        );
    }

    /// PARITY: `Definition` (strong kill) vs `WeakUpdate` (non-killing) must be
    /// preserved across the touched sites — a plain bind is a strong
    /// Definition; an element/field write is a non-killing WeakUpdate.
    #[test]
    fn test_c1_definition_vs_weakupdate_parity() {
        // Ruby: `a, _ = …` binders are strong Definitions; `arr[i] = v` is a
        // WeakUpdate of the container (must NOT be a Definition).
        let rb = r#"
def foo
  a, b = pair()
  arr[i] = a
  baz(b)
end
"#;
        let dfg = get_dfg_context(rb, "foo", Language::Ruby).unwrap();
        let kind = |name: &str, rt: RefType| {
            dfg.refs
                .iter()
                .any(|r| r.name == name && r.ref_type == rt)
        };
        assert!(
            kind("a", RefType::Definition) && kind("b", RefType::Definition),
            "ruby parity: multiple-assignment binders must be strong Definitions",
        );
        // The kill-preservation invariant my change must not break: an
        // element-write container `arr[i] = …` is never a strong (killing)
        // Definition. (Ruby `element_reference` writes are not currently wired
        // to the WeakUpdate path at all — that is a separate pre-existing gap;
        // the point here is only that my `left_assignment_list` arm did not turn
        // a subscript LHS into a kill.)
        assert!(
            !kind("arr", RefType::Definition),
            "ruby parity: element-write container `arr` must NOT be a strong Definition",
        );

        // C: bare `int *p;` is a strong Definition; `buf[i] = v` is a WeakUpdate.
        let c = r#"
int foo() {
    int *p;
    char buf[8];
    buf[0] = 1;
    return *p;
}
"#;
        let dfg = get_dfg_context(c, "foo", Language::C).unwrap();
        let ckind = |name: &str, rt: RefType| {
            dfg.refs
                .iter()
                .any(|r| r.name == name && r.ref_type == rt)
        };
        assert!(
            ckind("p", RefType::Definition) && ckind("buf", RefType::Definition),
            "c parity: bare pointer/array decls must be strong Definitions",
        );
        assert!(
            ckind("buf", RefType::WeakUpdate),
            "c parity: `buf[0] = 1` must be a non-killing WeakUpdate of the container",
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
        // Guard: `a[i+len] = ...` writes an element of `a`, so `a` is a
        // WEAK (non-killing) update of the container — a USE + may-modify of its
        // contents — NOT a fresh Definition and NOT a strong killing Update.
        // (rc3-element-write-as-killing-redefinition: element writes were
        // previously the same `Update` flavor as a whole-variable reassignment,
        // which made reaching-defs kill the prior def. They are now `WeakUpdate`.
        // Mirrors Solidity array_access / Python subscript semantics.)
        let source = "void f() {\n    a[i+len] = b[k];\n}";
        let dfg = get_dfg_context(source, "f", Language::C).unwrap();
        let a_weak: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == "a" && r.ref_type == RefType::WeakUpdate)
            .collect();
        assert!(
            !a_weak.is_empty(),
            "C subscript container `a` should be a WeakUpdate, got refs: {:?}",
            dfg.refs
                .iter()
                .map(|r| (r.name.clone(), r.ref_type))
                .collect::<Vec<_>>()
        );
        // It must NOT be a fresh Definition nor a strong killing Update.
        assert!(
            !dfg.refs.iter().any(|r| r.name == "a"
                && matches!(r.ref_type, RefType::Definition | RefType::Update)),
            "C subscript container `a` must not be a strong Definition/Update"
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

    // =====================================================================
    // fix-PW1-C3-nonvar-tokens (v0.5.0 BACKLOG, Wave 1 row C3)
    // =====================================================================
    // Non-variable tokens that share the bare-`identifier` node kind with
    // genuine local reads were mis-collected as variable USES and then
    // reported `definite uninitialized` by reaching-defs. One generic
    // structural predicate (`generic_non_use_position`) must reject all three
    // language variants in the symptom class:
    //   * C++   — a templated callee / cast keyword is the `name` field of a
    //             `template_function` (`reinterpret_cast<T>(x)`,
    //             `static_cast<T>(x)`, `make_unique<T>()`).
    //   * Kotlin— a PascalCase RECEIVER of a `navigation_expression` is a
    //             type / companion-object / enum reference (`DateTimeUnit.MONTH`,
    //             `Int.MAX_VALUE`, `YearMonthProgression.fromClosedRange(...)`).
    //   * Scala — every segment of a `stable_type_identifier` qualified type
    //             path is a package / object / type element (`mutable.HashMap`).
    //
    // GENERALIZATION GATE: this single test asserts EVERY variant in the class,
    // not one — a single-language version would be an anti-treadmill failure.
    #[test]
    fn c3_nonvar_tokens_not_recorded_as_uninitialized_uses() {
        fn uninit(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            let cfg = crate::cfg::get_cfg_context(source, func, lang).unwrap();
            let report = crate::dfg::reaching::build_reaching_defs_report(
                &cfg,
                &dfg.refs,
                std::path::PathBuf::from("test"),
            );
            report
                .uninitialized
                .iter()
                .map(|u| u.var.clone())
                .collect()
        }
        fn uses(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            dfg.refs
                .iter()
                .filter(|r| r.ref_type == RefType::Use)
                .map(|r| r.name.clone())
                .collect()
        }

        // ---- C++ : templated cast / callee name (`template_function.name`) ----
        let cpp = r#"
const char* as_chars(const unsigned char* data) {
  return reinterpret_cast<const char*>(static_cast<const void*>(data));
}
"#;
        let cpp_uses = uses(cpp, "as_chars", Language::Cpp);
        let cpp_uninit = uninit(cpp, "as_chars", Language::Cpp);
        for kw in ["reinterpret_cast", "static_cast"] {
            assert!(
                !cpp_uses.contains(&kw.to_string()),
                "C++ cast keyword `{kw}` wrongly recorded as a variable use; uses={cpp_uses:?}"
            );
            assert!(
                !cpp_uninit.contains(&kw.to_string()),
                "C++ cast keyword `{kw}` wrongly flagged uninitialized; uninit={cpp_uninit:?}"
            );
        }

        // ---- Kotlin : type / companion navigation receivers -------------------
        let kt = r#"
fun downTo(that: YearMonth): YearMonthProgression =
    YearMonthProgression.fromClosedRange(this, that, -1, DateTimeUnit.MONTH, Int.MAX_VALUE)
"#;
        let kt_uses = uses(kt, "downTo", Language::Kotlin);
        let kt_uninit = uninit(kt, "downTo", Language::Kotlin);
        for t in ["DateTimeUnit", "YearMonthProgression", "Int"] {
            assert!(
                !kt_uses.contains(&t.to_string()),
                "Kotlin type-receiver `{t}` wrongly recorded as a variable use; uses={kt_uses:?}"
            );
            assert!(
                !kt_uninit.contains(&t.to_string()),
                "Kotlin type-receiver `{t}` wrongly flagged uninitialized; uninit={kt_uninit:?}"
            );
        }
        // The genuine member selectors (`.MONTH`, `.MAX_VALUE`, `.fromClosedRange`)
        // were already suppressed; `that` (a real param read) must survive.
        assert!(
            kt_uses.contains(&"that".to_string()),
            "Kotlin genuine local read `that` lost; uses={kt_uses:?}"
        );

        // ---- Scala : qualified-type-path qualifier (`mutable`) ----------------
        let scala = r#"
def newMutableMap(n: Int): mutable.HashMap[K, V] = {
  new mutable.HashMap[K, V](n, 0.75d)
}
"#;
        let scala_uses = uses(scala, "newMutableMap", Language::Scala);
        let scala_uninit = uninit(scala, "newMutableMap", Language::Scala);
        assert!(
            !scala_uses.contains(&"mutable".to_string()),
            "Scala package qualifier `mutable` wrongly recorded as a variable use; uses={scala_uses:?}"
        );
        assert!(
            !scala_uninit.contains(&"mutable".to_string()),
            "Scala package qualifier `mutable` wrongly flagged uninitialized; uninit={scala_uninit:?}"
        );
    }

    // =====================================================================
    // fix-CF1-S9 (v0.5.0 RC CF-wave): false `definite uninitialized` reports
    // =====================================================================
    // A value-position identifier that resolves to a name bound OUTSIDE the
    // analyzed function — a C/C++ class member or file-scope global, a Go
    // imported-package qualifier, or a PHP implicit `$this` — has no in-function
    // definition and was wrongly reported `definite uninitialized` by
    // reaching-defs. The fixes are AST-keyed on tree-sitter node kinds:
    //   * C/C++ — collect class data members (`field_declaration` field_identifier
    //             + constructor `field_initializer_list`) and file-scope globals
    //             (`declaration` identifier) into the not-a-use suppression set.
    //   * Go    — collect import package bindings (`import_spec` path tail / alias)
    //             so a `selector_expression` operand package qualifier is not a use.
    //   * PHP   — seed the runtime-implicit `$this` / `self` / `static` bindings as
    //             pre-initialized in reaching-defs.
    //
    // GENERALIZATION GATE: this single test asserts EVERY language in the symptom
    // class (cpp, go, php); a single-language version is an anti-treadmill FAIL.
    // Each free name must drop OUT of the uninitialized set while a genuine local
    // read in the same function survives (no over-suppression).
    #[test]
    fn cf1_s9_free_names_not_definite_uninitialized() {
        fn uninit(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            let cfg = crate::cfg::get_cfg_context(source, func, lang).unwrap();
            let report = crate::dfg::reaching::build_reaching_defs_report(
                &cfg,
                &dfg.refs,
                std::path::PathBuf::from("test"),
            );
            report.uninitialized.iter().map(|u| u.var.clone()).collect()
        }
        fn uses(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            dfg.refs
                .iter()
                .filter(|r| r.ref_type == RefType::Use)
                .map(|r| r.name.clone())
                .collect()
        }

        // ---- C++ : class members (field_declaration + ctor init list) +
        //            file-scope global ------------------------------------------
        let cpp = r#"
int g_errno;

class Doc {
    int _errorID;
    int fd_;
public:
    Doc() : _errorID(0), fd_(0) {}
    int report() {
        int local = 7;
        return _errorID + fd_ + g_errno + local;
    }
};
"#;
        let cpp_uninit = uninit(cpp, "report", Language::Cpp);
        for free in ["_errorID", "fd_", "g_errno"] {
            assert!(
                !cpp_uninit.contains(&free.to_string()),
                "C++ member/global `{free}` wrongly flagged uninitialized; uninit={cpp_uninit:?}"
            );
        }
        assert!(
            uses(cpp, "report", Language::Cpp).contains(&"local".to_string()),
            "C++ genuine local read `local` lost to over-suppression"
        );

        // ---- Go : imported-package selector qualifiers (bare + aliased) -------
        let go = r#"
package main

import (
	"net/http"
	hx "x/y/special"
)

func handle(c int) int {
	local := c + 1
	if local > http.StatusOK {
		return hx.Code
	}
	return local
}
"#;
        let go_uninit = uninit(go, "handle", Language::Go);
        for pkg in ["http", "hx"] {
            assert!(
                !go_uninit.contains(&pkg.to_string()),
                "Go package qualifier `{pkg}` wrongly flagged uninitialized; uninit={go_uninit:?}"
            );
        }
        assert!(
            uses(go, "handle", Language::Go).contains(&"local".to_string()),
            "Go genuine local read `local` lost to over-suppression"
        );

        // ---- PHP : runtime-implicit `$this` / `self` / `static` ---------------
        let php = r#"<?php
class C {
    public function m(int $x): int {
        $y = $this->base + $x;
        return self::scale($y) + static::factor();
    }
}
"#;
        let php_uninit = uninit(php, "m", Language::Php);
        for implicit in ["$this", "self", "static"] {
            assert!(
                !php_uninit.contains(&implicit.to_string()),
                "PHP implicit binding `{implicit}` wrongly flagged uninitialized; uninit={php_uninit:?}"
            );
        }
        assert!(
            uses(php, "m", Language::Php).contains(&"$y".to_string()),
            "PHP genuine local read `$y` lost to over-suppression"
        );
    }

    // fix-PW3-C2c-loopheader (v0.5.0 BACKLOG): loop-HEADER use sites were
    // dropped for every grammar whose `for` / `foreach` / for-comprehension
    // node does not expose the Python `left`/`right`/`body` fields the legacy
    // `process_for_loop` reads. A variable used ONLY in a loop header
    // (`for ($i = $column; $i < $column + $n; ...)`, `foreach ($rows[$k] as ...)`,
    // Scala `for (x <- items if x > base)`) was therefore reported as a dead
    // store, and the loop binder read in the body as definite-uninitialized.
    //
    // GENERALIZATION GATE: this single test asserts EVERY variant in the
    // loop-header-use class — PHP C-style `for`, PHP `foreach` (key/value +
    // by-ref), JS/TS C-style `for`, Solidity C-style `for`, and the Scala
    // for-comprehension that proves the loop-descriptor registry generalizes
    // beyond the primary PHP target. A single-language version is an
    // anti-treadmill FAIL.
    #[test]
    fn c2c_loop_header_use_sites_collected() {
        fn uses(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            dfg.refs
                .iter()
                .filter(|r| r.ref_type == RefType::Use)
                .map(|r| r.name.clone())
                .collect()
        }
        fn defs(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            dfg.refs
                .iter()
                .filter(|r| r.ref_type == RefType::Definition)
                .map(|r| r.name.clone())
                .collect()
        }
        fn uninit(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            let cfg = crate::cfg::get_cfg_context(source, func, lang).unwrap();
            let report = crate::dfg::reaching::build_reaching_defs_report(
                &cfg,
                &dfg.refs,
                std::path::PathBuf::from("test"),
            );
            report.uninitialized.iter().map(|u| u.var.clone()).collect()
        }

        // ---- PHP : C-style `for` header (init RHS + condition) ----------------
        // `$column` is bound by the foreach and read ONLY in the inner for
        // header; before the fix those reads were dropped -> `$column` was a
        // false dead store. The iterable `$rows[$rowKey]` reads were also lost.
        let php = r#"<?php
function f($rows) {
    foreach ($rows[$rowKey] as $column => $cell) {
        for ($i = $column; $i < ($column + $colspan); ++$i) {
            $x = $i;
        }
        echo $cell;
    }
}
"#;
        let php_uses = uses(php, "f", Language::Php);
        let php_defs = defs(php, "f", Language::Php);
        // foreach iterable use sites
        assert!(
            php_uses.contains(&"$rows".to_string()),
            "PHP foreach iterable `$rows` use dropped; uses={php_uses:?}"
        );
        assert!(
            php_uses.contains(&"$rowKey".to_string()),
            "PHP foreach iterable index `$rowKey` use dropped; uses={php_uses:?}"
        );
        // foreach key/value binders
        assert!(
            php_defs.contains(&"$column".to_string()),
            "PHP foreach key binder `$column` not a definition; defs={php_defs:?}"
        );
        assert!(
            php_defs.contains(&"$cell".to_string()),
            "PHP foreach value binder `$cell` not a definition; defs={php_defs:?}"
        );
        // for-header reads of the foreach key (the reported dead-store FP)
        assert!(
            php_uses.contains(&"$column".to_string()),
            "PHP for-header use of `$column` dropped (the dead-store FP); uses={php_uses:?}"
        );
        assert!(
            php_uses.contains(&"$colspan".to_string()),
            "PHP for-condition use of `$colspan` dropped; uses={php_uses:?}"
        );
        // loop var binder recorded + not a false uninitialized read
        assert!(
            php_defs.contains(&"$i".to_string()),
            "PHP for loop var `$i` not a definition; defs={php_defs:?}"
        );
        let php_uninit = uninit(php, "f", Language::Php);
        assert!(
            !php_uninit.contains(&"$i".to_string()),
            "PHP for loop var `$i` wrongly flagged uninitialized; uninit={php_uninit:?}"
        );
        assert!(
            !php_uninit.contains(&"$column".to_string()),
            "PHP foreach key `$column` wrongly flagged uninitialized; uninit={php_uninit:?}"
        );

        // ---- PHP : foreach by-reference value binder `&$v` --------------------
        let php_ref = r#"<?php
function g($items) {
    foreach ($items as $k => &$v) {
        $v = $k;
    }
}
"#;
        let php_ref_uses = uses(php_ref, "g", Language::Php);
        let php_ref_defs = defs(php_ref, "g", Language::Php);
        assert!(
            php_ref_uses.contains(&"$items".to_string()),
            "PHP foreach iterable `$items` use dropped; uses={php_ref_uses:?}"
        );
        assert!(
            php_ref_defs.contains(&"$v".to_string()),
            "PHP foreach by-ref binder `$v` not a definition; defs={php_ref_defs:?}"
        );
        assert!(
            php_ref_defs.contains(&"$k".to_string()),
            "PHP foreach key binder `$k` not a definition; defs={php_ref_defs:?}"
        );

        // ---- JavaScript : C-style `for` header --------------------------------
        let js = r#"
function f(n) {
    for (let i = n; i < 10; i++) {
        g(i);
    }
}
"#;
        let js_uses = uses(js, "f", Language::JavaScript);
        let js_defs = defs(js, "f", Language::JavaScript);
        assert!(
            js_uses.contains(&"n".to_string()),
            "JS for-init use of `n` dropped; uses={js_uses:?}"
        );
        assert!(
            js_defs.contains(&"i".to_string()),
            "JS for loop var `i` not a definition; defs={js_defs:?}"
        );

        // ---- TypeScript : C-style `for` header --------------------------------
        let ts = r#"
function f(n: number) {
    for (let i = n; i < 10; i++) {
        g(i);
    }
}
"#;
        let ts_uses = uses(ts, "f", Language::TypeScript);
        assert!(
            ts_uses.contains(&"n".to_string()),
            "TS for-init use of `n` dropped; uses={ts_uses:?}"
        );

        // ---- Solidity : C-style `for` header ----------------------------------
        let sol = r#"
contract C {
    function f(uint n) public {
        for (uint i = n; i < 10; i++) {
            g(i);
        }
    }
}
"#;
        let sol_uses = uses(sol, "f", Language::Solidity);
        assert!(
            sol_uses.contains(&"n".to_string()),
            "Solidity for-init use of `n` dropped; uses={sol_uses:?}"
        );

        // ---- Scala : for-comprehension enumerators + guard --------------------
        // proves the loop-descriptor registry generalizes beyond PHP. `items`
        // (iterable) and `base` (guard) are read ONLY in the for header; `x` is
        // the binder bound by `<-`.
        let scala = r#"
def f(items: List[Int]): Int = {
  var total = 0
  val base = 10
  for (x <- items if x > base) {
    total = total + x
  }
  total
}
"#;
        let scala_uses = uses(scala, "f", Language::Scala);
        let scala_defs = defs(scala, "f", Language::Scala);
        assert!(
            scala_uses.contains(&"items".to_string()),
            "Scala for-comprehension iterable `items` use dropped; uses={scala_uses:?}"
        );
        assert!(
            scala_uses.contains(&"base".to_string()),
            "Scala for-comprehension guard use of `base` dropped; uses={scala_uses:?}"
        );
        assert!(
            scala_defs.contains(&"x".to_string()),
            "Scala for-comprehension binder `x` not a definition; defs={scala_defs:?}"
        );
        let scala_uninit = uninit(scala, "f", Language::Scala);
        assert!(
            !scala_uninit.contains(&"x".to_string()),
            "Scala comprehension binder `x` wrongly flagged uninitialized; uninit={scala_uninit:?}"
        );
    }

    // =========================================================================
    // fix-PW4-C4-csharp-objcreation (v0.5.0 BACKLOG): a C# `variable_declarator`
    // exposes its initializer as an UNNAMED child after the `=` token (there is
    // NO `value` field as in JS/TS/Java). `process_js_ts_declaration` only
    // descended `child_by_field_name("value")`, so the ENTIRE C# declaration RHS
    // — object-creation args, calls, binary expressions — was dropped, and a
    // local read ONLY in such a RHS (`new ContainerContext(type)`) was reported
    // as a false dead store. The generalization assertion below pins EVERY RHS
    // form in the symptom class (object-creation arg, call arg, binary operand),
    // plus the SAME object-creation construct in Java and C++ (which already
    // descend via their `value` field) to prove the fix is the C#-shape closure
    // of an otherwise-general behavior — not a single-variant patch.
    // =========================================================================
    #[test]
    fn test_csharp_variable_initializer_rhs_descended_objcreation_general() {
        fn uses(source: &str, func: &str, lang: Language) -> Vec<String> {
            let dfg = get_dfg_context(source, func, lang).unwrap();
            dfg.refs
                .iter()
                .filter(|r| r.ref_type == RefType::Use)
                .map(|r| r.name.clone())
                .collect()
        }

        // ---- C# : the reported symptom + every RHS variant in the class ------
        // `type` is read ONLY inside `new ContainerContext(type)` (object
        // creation arg); `seed` only inside an initializer identifier RHS; `b`
        // inside a call arg AND a binary operand; `c` inside a binary operand.
        let cs = r#"
class Reader {
    private bool ReadNormal(BsonType seed) {
        BsonType type = seed;
        ContainerContext ctx = new ContainerContext(type);
        int b = 1;
        int c = 2;
        int a = b + c;
        int d = Compute(b);
        return true;
    }
}
"#;
        let cs_uses = uses(cs, "ReadNormal", Language::CSharp);
        assert!(
            cs_uses.contains(&"type".to_string()),
            "C# object-creation arg `type` (new ContainerContext(type)) dropped; uses={cs_uses:?}"
        );
        assert!(
            cs_uses.contains(&"seed".to_string()),
            "C# initializer identifier RHS `seed` (= seed) dropped; uses={cs_uses:?}"
        );
        assert!(
            cs_uses.contains(&"b".to_string()),
            "C# initializer call-arg / binary-operand `b` dropped; uses={cs_uses:?}"
        );
        assert!(
            cs_uses.contains(&"c".to_string()),
            "C# initializer binary-operand `c` dropped; uses={cs_uses:?}"
        );

        // ---- Java : the SAME `new X(arg)` construct (generality / no regress) -
        let java = r#"
class Reader {
    boolean test(int seed) {
        Foo f = new Foo(seed);
        return true;
    }
}
"#;
        let java_uses = uses(java, "test", Language::Java);
        assert!(
            java_uses.contains(&"seed".to_string()),
            "Java object-creation arg `seed` (new Foo(seed)) dropped; uses={java_uses:?}"
        );

        // ---- C++ : the SAME `new X(arg)` construct (generality / no regress) --
        let cpp = r#"
bool test(int seed) {
    Foo* f = new Foo(seed);
    return true;
}
"#;
        let cpp_uses = uses(cpp, "test", Language::Cpp);
        assert!(
            cpp_uses.contains(&"seed".to_string()),
            "C++ object-creation arg `seed` (new Foo(seed)) dropped; uses={cpp_uses:?}"
        );
    }

    // =========================================================================
    // C4a-js-closure-liveness (v0.5.0 BACKLOG): a JS variable WRITTEN in one
    // closure and READ in a SIBLING closure must NOT be a dead store. The DFG
    // tags such a captured-upvalue write `ClosureCapture` so `find_dead_stores_
    // dfg` treats it as conservatively live (js-lodash `debounce`); a genuinely
    // never-read LOCAL of the writing function stays untagged (still flaggable).
    // The unit tests assert that root-cause signal (robust to CFG block shape).
    // =========================================================================

    /// True iff some Definition of `name` carries the `ClosureCapture` tag.
    fn has_capture_def(dfg: &DfgInfo, name: &str) -> bool {
        dfg.refs.iter().any(|r| {
            r.name == name
                && r.ref_type == RefType::Definition
                && r.context == Some(VarRefContext::ClosureCapture)
        })
    }

    /// True iff EVERY Definition of `name` is untagged (`context: None`).
    fn all_defs_plain(dfg: &DfgInfo, name: &str) -> bool {
        let defs: Vec<_> = dfg
            .refs
            .iter()
            .filter(|r| r.name == name && r.ref_type == RefType::Definition)
            .collect();
        !defs.is_empty() && defs.iter().all(|r| r.context.is_none())
    }

    #[test]
    fn test_js_closure_upvalue_var_function_declaration_siblings() {
        // debounce-shape: `timerId`/`lastCallTime` are `var`s of `debounceLike`,
        // WRITTEN in sibling `start()` and READ in sibling `tick()`. The writes
        // are captured-upvalue writes and must be tagged ClosureCapture. The
        // `deadLocal` writes are genuine locals of `start` (never read) and must
        // stay untagged so a real dead store still surfaces.
        let source = r#"
function debounceLike(wait) {
  var timerId, lastCallTime;
  function start() {
    timerId = setTimeout(tick, wait);
    lastCallTime = now();
    var deadLocal = 1;
    deadLocal = 2;
  }
  function tick() { return timerId + lastCallTime; }
  return { start: start, tick: tick };
}
"#;
        let dfg = get_dfg_context(source, "debounceLike", Language::JavaScript).unwrap();

        assert!(
            has_capture_def(&dfg, "timerId"),
            "upvalue write `timerId = …` in sibling closure must be tagged ClosureCapture; refs={:?}",
            dfg.refs
                .iter()
                .filter(|r| r.name == "timerId")
                .map(|r| (r.ref_type, r.line, r.context.clone()))
                .collect::<Vec<_>>()
        );
        assert!(
            has_capture_def(&dfg, "lastCallTime"),
            "upvalue write `lastCallTime = …` must be tagged ClosureCapture"
        );
        // A genuine never-read local of `start` is NOT an upvalue → stays plain
        // (a real dead store the analysis must still be able to report).
        assert!(
            all_defs_plain(&dfg, "deadLocal"),
            "genuine local `deadLocal` must NOT be tagged ClosureCapture; refs={:?}",
            dfg.refs
                .iter()
                .filter(|r| r.name == "deadLocal")
                .map(|r| (r.ref_type, r.line, r.context.clone()))
                .collect::<Vec<_>>()
        );
        // Sanity: the cross-sibling READ of `timerId` is recorded (it is the
        // read the flat per-function DFG carries but the per-block kill misses).
        assert!(
            dfg.refs
                .iter()
                .any(|r| r.name == "timerId" && r.ref_type == RefType::Use),
            "expected a recorded Use of `timerId` (read in sibling `tick`)"
        );
    }

    #[test]
    fn test_js_closure_upvalue_classification_independent_of_analysis_root() {
        // Same source, but analyze the INNER function `start` directly (the
        // Lua rc6 `fire` shape). The physical-ancestor walk must still classify
        // `timerId`/`lastCallTime` as captured upvalues even though they are
        // locals of the *outer* function, never bound in `start`.
        let source = r#"
function debounceLike(wait) {
  var timerId, lastCallTime;
  function start() {
    timerId = setTimeout(tick, wait);
    lastCallTime = now();
    var deadLocal = 1;
    deadLocal = 2;
  }
  function tick() { return timerId + lastCallTime; }
  return { start: start, tick: tick };
}
"#;
        let dfg = get_dfg_context(source, "start", Language::JavaScript).unwrap();
        assert!(
            has_capture_def(&dfg, "timerId") && has_capture_def(&dfg, "lastCallTime"),
            "captured-upvalue writes must be tagged regardless of which function is analyzed"
        );
        assert!(
            all_defs_plain(&dfg, "deadLocal"),
            "`deadLocal` is a local of the analyzed function `start` → stays plain"
        );
    }

    #[test]
    fn test_js_closure_upvalue_let_arrow_siblings_and_true_global() {
        // Variant: `let` capture + ARROW-function siblings, plus a TRUE GLOBAL
        // write inside a closure (bound nowhere) which must NOT be suppressed.
        let source = r#"
function makeTimer() {
  let handle = null;
  const begin = () => { handle = setInterval(poll, 5); };
  const stop = () => { clearInterval(handle); handle = null; };
  function poll() { ghostGlobal = read(handle); }
  return { begin: begin, stop: stop };
}
"#;
        let dfg = get_dfg_context(source, "makeTimer", Language::JavaScript).unwrap();

        assert!(
            has_capture_def(&dfg, "handle"),
            "`let handle` written in arrow siblings must be tagged ClosureCapture; refs={:?}",
            dfg.refs
                .iter()
                .filter(|r| r.name == "handle")
                .map(|r| (r.ref_type, r.line, r.context.clone()))
                .collect::<Vec<_>>()
        );
        // `ghostGlobal` is bound in NO enclosing scope → a true global write,
        // which stays flaggable (NOT a captured upvalue).
        assert!(
            all_defs_plain(&dfg, "ghostGlobal"),
            "true-global write `ghostGlobal = …` must NOT be tagged ClosureCapture; refs={:?}",
            dfg.refs
                .iter()
                .filter(|r| r.name == "ghostGlobal")
                .map(|r| (r.ref_type, r.line, r.context.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_js_local_reassignment_not_tagged_when_bound_in_own_scope() {
        // A bare `identifier = …` that re-assigns a variable bound in the
        // write's OWN function scope is a LOCAL write, never an upvalue: it must
        // stay untagged so genuine intra-function dead stores still surface.
        let source = r#"
function f(a) {
  let x = a;
  x = a + 1;
  return x;
}
"#;
        let dfg = get_dfg_context(source, "f", Language::JavaScript).unwrap();
        assert!(
            all_defs_plain(&dfg, "x"),
            "local re-assignment of own-scope `x` must NOT be tagged ClosureCapture; refs={:?}",
            dfg.refs
                .iter()
                .filter(|r| r.name == "x")
                .map(|r| (r.ref_type, r.line, r.context.clone()))
                .collect::<Vec<_>>()
        );
    }
}
