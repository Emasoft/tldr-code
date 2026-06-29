//! CFG extraction from source code
//!
//! Extracts control flow graphs from functions using tree-sitter parsing.
//!
//! # Algorithm
//! 1. Parse source with tree-sitter
//! 2. Find function by name
//! 3. Build basic blocks (maximal sequences without branches)
//! 4. Connect blocks via edges based on control structures
//! 5. Compute cyclomatic complexity: E - N + 2
//!
//! # Block Boundaries (M7 documentation)
//! A new block starts at:
//! - Function entry
//! - Target of a branch (if/else/elif)
//! - Loop header (for/while)
//! - After a branch rejoins
//! - Exception handler entry (except/catch)
//! - Return statements

use std::collections::HashMap;
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::ast::extract::decl_keyword_line_from_node;
use crate::ast::function_finder::{
    find_function_node_with_line, get_function_body, get_function_name,
};
use crate::ast::parser::parse;
use crate::types::{BlockType, CfgBlock, CfgEdge, CfgInfo, EdgeType, Language};
use crate::TldrResult;

/// Maximum recursion depth for nested structures (M24 mitigation)
const MAX_NESTING_DEPTH: usize = 50;

/// Extract CFG for a function from source code or file path
///
/// # Arguments
/// * `source_or_path` - Either source code string or path to a file
/// * `function_name` - Name of the function to extract CFG for
/// * `language` - Programming language
///
/// # Returns
/// * `Ok(CfgInfo)` - CFG with blocks, edges, and metrics
/// * Empty CFG if function not found (per spec Section 2.3.1)
///
/// # Example
/// ```ignore
/// use tldr_core::cfg::get_cfg_context;
/// use tldr_core::Language;
///
/// let cfg = get_cfg_context("def foo(): pass", "foo", Language::Python)?;
/// assert_eq!(cfg.function, "foo");
/// ```
pub fn get_cfg_context(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<CfgInfo> {
    get_cfg_context_with_line(source_or_path, function_name, None, language)
}

/// body-aware-fn-resolution-v1 (B1, FAN-IN slice+chop): line-aware CFG
/// extraction. When `target_line` is supplied and several definitions
/// share `function_name`, the function whose line range contains the line
/// is selected (and otherwise the first body-bearing definition). This is
/// what lets `slice`/`chop` build the CFG of the concrete implementation
/// rather than a body-less abstract declaration. With `target_line =
/// None` the behavior is identical to [`get_cfg_context`].
pub fn get_cfg_context_with_line(
    source_or_path: &str,
    function_name: &str,
    target_line: Option<u32>,
    language: Language,
) -> TldrResult<CfgInfo> {
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

    // Extract CFG from the parsed tree
    extract_cfg_from_tree_with_line(&tree, &source, function_name, target_line, language)
}

/// Extract CFG from a parsed tree
///
/// (vuln-migration-v1 M3) Visibility extended from private `fn` to `pub(crate)`
/// so `vuln::scan_file_vulns` can avoid the per-function re-parse implicit in
/// `get_cfg_context(&content, ...)` — the per-function compute_taint loop
/// passes the pre-parsed tree directly. Mirrors `extract_dfg_from_tree`.
pub(crate) fn extract_cfg_from_tree(
    tree: &Tree,
    source: &str,
    function_name: &str,
    language: Language,
) -> TldrResult<CfgInfo> {
    extract_cfg_from_tree_with_line(tree, source, function_name, None, language)
}

/// body-aware-fn-resolution-v1 (B1): line-aware variant of
/// [`extract_cfg_from_tree`]. Resolves the function node via
/// [`find_function_node_with_line`] so a supplied `target_line`
/// disambiguates same-named definitions; `None` preserves the legacy
/// name-only resolution (now itself body-aware).
pub(crate) fn extract_cfg_from_tree_with_line(
    tree: &Tree,
    source: &str,
    function_name: &str,
    target_line: Option<u32>,
    language: Language,
) -> TldrResult<CfgInfo> {
    let root = tree.root_node();

    // Find the function node
    let func_node =
        find_function_node_with_line(root, function_name, target_line, language, source);

    match func_node {
        Some(node) => build_cfg_for_function(node, function_name, source, language, 0),
        None => {
            // Return empty CFG when function not found (per spec)
            Ok(CfgInfo {
                function: function_name.to_string(),
                blocks: Vec::new(),
                edges: Vec::new(),
                entry_block: 0,
                exit_blocks: Vec::new(),
                cyclomatic_complexity: 0,
                nested_functions: HashMap::new(),
            })
        }
    }
}

/// Check if a node kind represents a control flow construct that should be
/// processed as a statement rather than iterated over as a block container.
fn is_control_flow_node(kind: &str) -> bool {
    matches!(
        kind,
        "if_statement"
            | "if_expression"
            | "for_statement"
            | "for_in_statement"
            | "for_expression"
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101) Java for-each.
            | "enhanced_for_statement"
            | "while_statement"
            | "while_expression"
            | "loop_expression"
            | "try_statement"
            | "try_expression"
            | "match_expression"
            | "return_statement"
            | "return_expression"
            | "break_statement"
            | "break_expression"
            | "continue_statement"
            | "continue_expression"
            // (cfg-per-lang-decision-edges-v1 M-103) Swift control flow.
            | "guard_statement"
            | "do_statement"
            | "switch_statement"
    )
}

/// (cfg-per-lang-decision-edges-v1 M-103) Returns the bare identifier name
/// of the target of an Elixir `call` node, if any. Used to dispatch
/// `cond do …` / `case x do …` / `try do …` constructs into branch
/// emission. Elixir's tree-sitter grammar surfaces these as ordinary
/// `call` nodes (target=identifier) with a `do_block` containing
/// `stab_clause` arms (and `rescue_block`/`catch_block`/`after_block`
/// siblings for `try`).
fn elixir_call_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    let target = node.child_by_field_name("target")?;
    if target.kind() != "identifier" {
        return None;
    }
    target.utf8_text(source.as_bytes()).ok()
}

/// (cfg-per-lang-decision-edges-v1 M-103) Quick predicate: does this
/// Elixir `call` node represent a `cond do …` / `case x do …` /
/// `try do …` control-flow construct?
fn is_elixir_control_call(node: Node, source: &str) -> bool {
    if node.kind() != "call" {
        return false;
    }
    matches!(
        elixir_call_target_name(node, source),
        Some("cond") | Some("case") | Some("try")
    )
}

/// Find a child node by its kind (for languages like OCaml that use node types
/// instead of field names for certain children like then_clause, else_clause, do_clause)
fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node().kind() == kind {
                return Some(cursor.node());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

/// solidity-cfg-v1 (v0.5.0 SOL-005b): For a Solidity `expression_statement`,
/// return `Some("require")` / `Some("assert")` if the wrapped expression is a
/// direct call to the `require` or `assert` builtin. Both are user-callable
/// intrinsics that branch on their condition and halt the function on the
/// false side — for CFG purposes they are first-class control-flow.
///
/// Returns `None` for any other call (ordinary user functions, library calls,
/// etc.) so the generic expression-statement path keeps handling them.
fn solidity_guard_call_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'static str> {
    fn find_call_target<'b>(n: Node<'b>, src: &'b str, depth: usize) -> Option<&'static str> {
        if depth > 6 {
            return None;
        }
        if n.kind() == "call_expression" {
            if let Some(func) = n.child_by_field_name("function") {
                let mut cur = func;
                for _ in 0..6 {
                    if cur.kind() == "identifier" {
                        let name = cur.utf8_text(src.as_bytes()).unwrap_or("");
                        return match name {
                            "require" => Some("require"),
                            "assert" => Some("assert"),
                            _ => None,
                        };
                    }
                    let mut walker = cur.walk();
                    let mut next = None;
                    for child in cur.children(&mut walker) {
                        if child.is_named() {
                            next = Some(child);
                            break;
                        }
                    }
                    cur = match next {
                        Some(c) => c,
                        None => return None,
                    };
                }
            }
            return None;
        }
        let mut walker = n.walk();
        for child in n.children(&mut walker) {
            if child.is_named() {
                if let Some(name) = find_call_target(child, src, depth + 1) {
                    return Some(name);
                }
            }
        }
        None
    }
    find_call_target(node, source, 0)
}

/// solidity-cfg-v1 (v0.5.0 SOL-005b): Collect both `body` field children of a
/// Solidity `if_statement`. tree-sitter-solidity reuses the `body` field name
/// for BOTH the then-branch and the else-branch (the else-branch appears as
/// a second `body=statement` child positioned after the `else` token).
///
/// `tree_sitter::Node::child_by_field_name` returns only the first match, so
/// without this helper the else-branch was invisible to `process_if_statement`.
///
/// Returns `(then, else)`. `else` is `None` when the if has no else clause.
fn solidity_if_branches<'a>(node: Node<'a>) -> (Option<Node<'a>>, Option<Node<'a>>) {
    let mut then_branch = None;
    let mut else_branch = None;
    let mut saw_else_token = false;
    for i in 0..node.child_count() {
        let child = match node.child(i) {
            Some(c) => c,
            None => continue,
        };
        if child.kind() == "else" {
            saw_else_token = true;
            continue;
        }
        let field = node.field_name_for_child(i as u32);
        if field == Some("body") {
            if !saw_else_token && then_branch.is_none() {
                then_branch = Some(child);
            } else if saw_else_token {
                else_branch = Some(child);
            }
        }
    }
    (then_branch, else_branch)
}

/// Swift `if_statement` exposes neither a `consequence` nor an `alternative`
/// field. The then-branch is an unnamed `statements` child positioned after the
/// `condition` field; the else-branch (when present) is the `statements` (or
/// nested `if_statement` for else-if chains) child that follows the bare `else`
/// token. `child_by_field_name` therefore cannot reach either branch, which
/// dropped the else-branch body from the CFG/PDG entirely (GH #80: swift
/// `_heapify` backward slice from an else-branch trailing-closure line returned
/// EMPTY because no basic block covered that line).
///
/// Returns `(then, else)`. `else` is `None` when the if has no else clause.
fn swift_if_branches<'a>(node: Node<'a>) -> (Option<Node<'a>>, Option<Node<'a>>) {
    let mut then_branch = None;
    let mut else_branch = None;
    let mut saw_else_token = false;
    for i in 0..node.child_count() {
        let child = match node.child(i) {
            Some(c) => c,
            None => continue,
        };
        let kind = child.kind();
        if kind == "else" {
            saw_else_token = true;
            continue;
        }
        // The branch bodies are `statements` blocks; an else-if chain places a
        // nested `if_statement` directly after the `else` token instead.
        let is_branch_body = kind == "statements" || kind == "if_statement";
        if !is_branch_body {
            continue;
        }
        if saw_else_token {
            if else_branch.is_none() {
                else_branch = Some(child);
            }
        } else if then_branch.is_none() {
            then_branch = Some(child);
        }
    }
    (then_branch, else_branch)
}

/// cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104): Kotlin `if_expression` has
/// no named "consequence" field (node-types.json verified). The consequence body
/// is the first named child AFTER the "condition" field's end position.
/// Returns the consequence node, or `None` if not found.
fn kotlin_if_consequence(node: Node<'_>) -> Option<Node<'_>> {
    let cond_end = node.child_by_field_name("condition")?.end_position();
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    children.find(|c| c.start_position() > cond_end)
}

/// cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104): Kotlin `if_expression` has
/// no named "alternative" field. The alternative body is the SECOND named child
/// after the "condition" field (i.e. after skipping the consequence).
fn kotlin_if_alternative(node: Node<'_>) -> Option<Node<'_>> {
    let cond_end = node.child_by_field_name("condition")?.end_position();
    let mut cursor = node.walk();
    let mut after_cond = node
        .named_children(&mut cursor)
        .filter(|c| c.start_position() > cond_end);
    after_cond.next()?; // skip consequence
    after_cond.next() // take alternative
}

/// Build CFG for a function node
fn build_cfg_for_function(
    func_node: Node,
    function_name: &str,
    source: &str,
    language: Language,
    depth: usize,
) -> TldrResult<CfgInfo> {
    // M24: Depth limit to prevent infinite loops
    if depth > MAX_NESTING_DEPTH {
        return Ok(CfgInfo {
            function: function_name.to_string(),
            blocks: Vec::new(),
            edges: Vec::new(),
            entry_block: 0,
            exit_blocks: Vec::new(),
            cyclomatic_complexity: 0,
            nested_functions: HashMap::new(),
        });
    }

    // (path-and-schema-cleanup-v3 P3.BUG-N1) Pre-seed the entry block with
    // the function's def-line range so criterion lines that fall on the
    // signature (e.g. multi-line `def __init__(\n self,\n ...)` parameter
    // rows) still resolve to a CFG block. Without this, the entry block
    // was set to body-start in `process_block`, so any slice/chop with a
    // criterion line in the signature returned an empty result.
    //
    // extract-slice-explain-decl-keyword-span-v1 (v0.4.2 M-002): use the
    // decl-keyword line rather than the raw `node.start_position()` so
    // annotation-decorated declarations (java `@Override`, kotlin
    // `@Deprecated`, scala `@deprecated`, swift `@inlinable`) don't pull
    // the leading annotation line into the CFG entry block (which then
    // surfaces as a spurious line in slice/chop output).
    let def_line = decl_keyword_line_from_node(&func_node);
    let mut builder = CfgBuilder::new(function_name.to_string(), source, language);
    builder.seed_entry_block_start(def_line);

    // Get the function body
    let body_node = get_function_body(func_node, language);

    if let Some(body) = body_node {
        builder.process_block(body, depth)?;
    }

    builder.finalize()
}

/// Builder for constructing CFG
struct CfgBuilder<'a> {
    function_name: String,
    source: &'a str,
    language: Language,
    blocks: Vec<CfgBlock>,
    edges: Vec<CfgEdge>,
    nested_functions: HashMap<String, CfgInfo>,
    current_block_id: usize,
    /// Function-exit blocks (e.g. return, end-of-function). Reaching one of
    /// these terminates the function's control flow.
    exit_blocks: Vec<usize>,
    /// Loop-exit blocks created by `process_break_statement`. Reaching one
    /// of these terminates the *loop body's* control flow but NOT the
    /// function. They are tracked separately from `exit_blocks` so that
    /// `break` statements do not pollute the function's reported exits, but
    /// are still recognised by back-edge / fallthrough guards as terminating
    /// the local control path. (Fixes parcadei/tldr-code#18.)
    loop_exit_blocks: Vec<usize>,
}

impl<'a> CfgBuilder<'a> {
    fn new(function_name: String, source: &'a str, language: Language) -> Self {
        // Create entry block
        let entry_block = CfgBlock {
            id: 0,
            block_type: BlockType::Entry,
            lines: (0, 0),
            calls: Vec::new(),
        };

        Self {
            function_name,
            source,
            language,
            blocks: vec![entry_block],
            edges: Vec::new(),
            nested_functions: HashMap::new(),
            current_block_id: 0,
            exit_blocks: Vec::new(),
            loop_exit_blocks: Vec::new(),
        }
    }

    /// Pre-seed the entry block's line range with the function's def
    /// line. (path-and-schema-cleanup-v3 P3.BUG-N1) Without this, the
    /// entry block was set to the body's first line in `process_block`,
    /// so criterion lines on the function signature (multi-line params)
    /// did not resolve to any block and slice/chop returned an empty
    /// set. Setting the start to the def line means the entry block
    /// covers the signature too.
    fn seed_entry_block_start(&mut self, def_line: u32) {
        if let Some(entry) = self.blocks.get_mut(0) {
            entry.lines = (def_line, def_line);
        }
    }

    /// Create a new basic block
    fn new_block(&mut self, block_type: BlockType, start_line: u32, end_line: u32) -> usize {
        let id = self.blocks.len();
        self.blocks.push(CfgBlock {
            id,
            block_type,
            lines: (start_line, end_line),
            calls: Vec::new(),
        });
        id
    }

    /// Add an edge between blocks
    fn add_edge(&mut self, from: usize, to: usize, edge_type: EdgeType, condition: Option<String>) {
        self.edges.push(CfgEdge {
            from,
            to,
            edge_type,
            condition,
        });
    }

    /// Process a block of statements
    fn process_block(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if depth > MAX_NESTING_DEPTH {
            return Ok(());
        }

        // Update entry block line range
        if self.blocks[0].lines == (0, 0) {
            self.blocks[0].lines = (
                node.start_position().row as u32 + 1,
                node.start_position().row as u32 + 1,
            );
        }

        // If the node itself is a control flow construct (common in expression-oriented
        // languages like OCaml where the function body IS the expression, not a block
        // containing statements), process it directly as a statement.
        if is_control_flow_node(node.kind()) {
            return self.process_statement(node, depth);
        }

        // cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104): Kotlin (tree-sitter-kotlin-ng)
        // can use a bare leaf node as the consequence of an `if_expression`:
        //   `if (x < 0) continue`  →  consequence field = `identifier [continue]`
        // When `process_block` is called with a leaf node (no children), iterating
        // its children produces nothing. Instead, dispatch the leaf itself as a
        // statement so the language-specific Kotlin guard in `process_statement`
        // can recognise it.
        if node.child_count() == 0 {
            return self.process_statement(node, depth);
        }

        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                self.process_statement(child, depth)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single statement
    fn process_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let kind = node.kind();
        let start_line = node.start_position().row as u32 + 1;
        // CF3-S3b (v0.5.0 RC): route a statement's END line through the
        // Scala-gated normaliser so that, when tree-sitter-scala folds a
        // following def's `/** ScalaDoc */` INTO this statement's own span as a
        // trailing child, the basic block stops at the real statement body
        // rather than the doc comment. No-op for every other language and for
        // Scala statements that do not absorb a trailing comment.
        let end_line = crate::ast::extract::decl_end_line_from_node(&node, self.language);

        // CF3-S3b (v0.5.0 RC): tree-sitter-scala also folds that `/** ScalaDoc */`
        // into the previous expression-bodied `def`'s `indented_block` as a
        // SEPARATE trailing child (a sibling of the body expression). Walked as
        // its own statement it would fall through to the catch-all arm and
        // stretch the enclosing CFG basic block — and thus the reaching-defs /
        // dead-stores span — into the next def's documentation. A comment is
        // never an executable statement, so for Scala it must not extend any
        // block. Gated to Scala (the only grammar that folds a sibling's doc
        // comment into the previous declaration) so every other language is
        // untouched.
        if matches!(self.language, Language::Scala)
            && matches!(kind, "comment" | "block_comment" | "line_comment")
        {
            return Ok(());
        }

        // cfg-ruby-rebuild-v1 (v0.4.2 M-102): tree-sitter-ruby emits BARE
        // kinds for control-flow constructs (`"if"`, `"while"`, `"until"`,
        // `"for"`, `"case"`, `"begin"`, `"unless"`, plus modifier forms).
        // These cognates collide with bare token / identifier text in
        // other grammars (Python uses `"if_statement"`, never bare `"if"`),
        // so they are dispatched only when `language == Ruby`. Without
        // this dispatcher every Ruby method came out flat
        // (`cyclomatic=1, num_edges=0`), which cascaded into broken
        // output for `complexity`, `slice`, `available`, `reaching-defs`,
        // `dead-stores`, `taint`, `chop`, `context`, `health`,
        // `hotspots`, `debt`.
        if matches!(self.language, Language::Ruby) {
            match kind {
                "if" | "unless" => {
                    return self.process_ruby_if(node, depth);
                }
                "if_modifier" | "unless_modifier" => {
                    return self.process_ruby_if_modifier(node, depth);
                }
                "while" | "until" => {
                    return self.process_ruby_while_until(node, depth);
                }
                "while_modifier" | "until_modifier" => {
                    return self.process_ruby_modifier_loop(node, depth);
                }
                "for" => {
                    return self.process_ruby_for(node, depth);
                }
                "case" => {
                    return self.process_ruby_case(node, depth);
                }
                "begin" => {
                    return self.process_ruby_begin(node, depth);
                }
                "break" => {
                    return self.process_break_statement(node, start_line, end_line);
                }
                "next" | "redo" | "retry" => {
                    return self.process_continue_statement(node, start_line, end_line);
                }
                "return" => {
                    return self.process_return_statement(node, start_line, end_line);
                }
                "call" => {
                    // `loop do ... end` is parsed as a `call` to `Kernel#loop`
                    // with an attached `do_block`. Lower it as an infinite
                    // loop so the CFG carries the back-edge and the
                    // loop_header decision-point. Other calls fall through
                    // to the generic call-expression handler below.
                    if crate::metrics::complexity::is_ruby_loop_call(node, self.source) {
                        return self.process_ruby_loop_call(node, depth);
                    }
                }
                _ => {}
            }
        }

        // solidity-cfg-v1 (v0.5.0 SOL-005b): tree-sitter-solidity wraps every
        // body statement in a `statement` named container whose single named
        // child is the actual `if_statement` / `for_statement` / etc. Without
        // descending through this wrapper, the generic dispatch below would
        // route `statement` into the catch-all `_` arm and the entire function
        // body would collapse to a flat entry/exit pair.
        //
        // Also dispatch Solidity-specific bare nodes:
        //   * `block_statement`  — the actual `{ ... }` container
        //     (function bodies use `function_body { statement* }`; catch /
        //     if-body / while-body wrap their contents in `block_statement`).
        //   * `unchecked_block`  — `unchecked { ... }`; transparent w.r.t.
        //     control flow but contains nested statements that must be walked.
        //   * `do_while_statement` — handled by `process_do_while_loop`
        //     (body-first loop; not covered by the generic `for/while` arms).
        //   * `revert_statement` — terminates the function (mirrors `return`).
        //   * `emit_statement`   — treated as an expression with side effects.
        if matches!(self.language, Language::Solidity) {
            match kind {
                "statement" => {
                    // The `statement` wrapper has a single named child that
                    // carries the actual control-flow / expression node.
                    let mut cursor = node.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let child = cursor.node();
                            if child.is_named() {
                                return self.process_statement(child, depth);
                            }
                            if !cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                    return Ok(());
                }
                "block_statement" | "unchecked_block" => {
                    return self.process_block(node, depth);
                }
                "do_while_statement" => {
                    return self.process_do_while_loop(node, depth);
                }
                "revert_statement" => {
                    // revert(...) halts the function. Model it as a Return-like
                    // exit so taint / reachability / cyclomatic all see the
                    // function's terminal points.
                    return self.process_return_statement(node, start_line, end_line);
                }
                "emit_statement" => {
                    return self.process_expression(node, start_line, end_line);
                }
                "expression_statement" => {
                    // Detect `require(cond, ...)` / `assert(cond)` calls. Both
                    // are intrinsic Solidity guard primitives that branch on the
                    // condition and halt the function on the false side. Model
                    // as branch + exit so cyclomatic / reachability metrics
                    // count them as decision points. Falls through to the
                    // generic expression_statement arm otherwise so ordinary
                    // calls keep their current call-extraction behaviour.
                    if let Some(guard_name) =
                        solidity_guard_call_name(node, self.source)
                    {
                        return self.process_solidity_guard_call(
                            node,
                            depth,
                            start_line,
                            end_line,
                            guard_name,
                        );
                    }
                }
                _ => {}
            }
        }

        // cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104): tree-sitter-kotlin-ng
        // emits `continue` / `break` / `return` as bare `identifier` nodes (not
        // `jump_expression` as the grammar spec suggests for newer versions).
        // Verified by `kt_full_dump` example: `if (i == 0) { continue }` produces
        // `block { identifier[continue] }`. Because `identifier` matches no arm in
        // the generic `match kind` below, Kotlin continue/break/return are silently
        // dropped. Gate on Kotlin-only to avoid false-matches in other languages
        // where `continue` / `break` would be reserved keywords, not identifiers.
        if matches!(self.language, Language::Kotlin) && kind == "identifier" {
            let text = node.utf8_text(self.source.as_bytes()).unwrap_or("");
            match text {
                "continue" => {
                    return self.process_continue_statement(node, start_line, end_line);
                }
                "break" => {
                    return self.process_break_statement(node, start_line, end_line);
                }
                "return" => {
                    return self.process_return_statement(node, start_line, end_line);
                }
                _ => {}
            }
        }

        match kind {
            // Control flow statements
            "if_statement" | "if_expression" => self.process_if_statement(node, depth)?,
            "for_statement" | "for_in_statement" | "for_expression" => {
                self.process_for_loop(node, depth)?
            }
            // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101): Java
            // for-each form `for (T x : xs) { ... }` parses as
            // `enhanced_for_statement` (distinct from `for_statement`,
            // which is the classical C-style three-part form). Iter-2
            // audit `java.md` "Layer probe: CFG" showed sumEven reporting
            // `has_loops:false` because this node had no CFG handler.
            // Route it through the same `process_for_loop` handler —
            // the `body` field lookup works identically.
            "enhanced_for_statement" => self.process_for_loop(node, depth)?,
            // cl4-cyclomatic-v1 (GH #76): C# spells its for-each construct
            // `foreach_statement` (distinct from the classical three-part
            // `for_statement`). It carries a `body` field block, so the
            // generic `process_for_loop` handler — which looks up `body` —
            // produces the loop block + back-edge correctly. Without this arm
            // the foreach fell through to the catch-all `_` branch and emitted
            // no loop structure at all (degenerate CFG).
            "foreach_statement" => self.process_for_loop(node, depth)?,
            "while_statement" | "while_expression" => self.process_while_loop(node, depth)?,
            "loop_expression" => self.process_loop_expression(node, depth)?,
            "try_statement" => self.process_try_statement(node, depth)?,
            // tree-sitter produces "try_expression" for THREE distinct shapes:
            //   * OCaml `try <expr> with <match_case>…` — carries an
            //     `expression` field (the protected expression).
            //   * Scala `try { <block> } catch { … } [finally { … }]` — carries
            //     a `body` field (the protected `block`) plus `catch_clause` /
            //     `finally_clause` siblings.
            //   * Rust `<expr>?` — neither field; just the inner expression and
            //     a `?` token.
            // fix-CF3-S12 (v0.5.0 RC CF-wave): the pre-fix code routed EVERY
            // `try_expression` lacking an `expression` field to the Rust `?`
            // handler. That swallowed the Scala try body — a `while` loop nested
            // inside the `try` was never walked, so its back-edge was missing
            // (`has_loops:false`) and every loop-carried `var` collapsed into the
            // entry block, producing spurious dead stores (scala-zio
            // `unsafeCompleteTakers`: `notifyEmptySpace`/`currentItem`). Route
            // the Scala body-bearing form through `process_try_statement`, whose
            // standard arm walks the `block`/`catch_clause`/`finally_clause`
            // children (and recurses into the loop). Only the field-less Rust `?`
            // falls through to the question-mark handler.
            "try_expression" => {
                if node.child_by_field_name("expression").is_some()
                    || node.child_by_field_name("body").is_some()
                {
                    // OCaml `try <expr> with …` / Scala `try { … } catch { … }`.
                    self.process_try_statement(node, depth)?
                } else {
                    // Rust: <expr>? — hidden branch on Result/Option
                    self.process_question_mark(node, depth)?
                }
            }
            "match_expression" => self.process_match_expression(node, depth)?,
            // (cfg-per-lang-decision-edges-v1 M-103) Swift-specific control flow.
            "guard_statement" => self.process_swift_guard(node, depth)?,
            "do_statement" => self.process_swift_do_catch(node, depth)?,
            "switch_statement" => {
                // cfg-c-java-scala-control-flow-v1 (v0.4.2 M-101): C and
                // C++ both spell their switch construct `switch_statement`,
                // with `case_statement` children directly under the
                // `body: compound_statement`. Swift also uses
                // `switch_statement` but with `switch_entry` children and
                // an `expr` scrutinee field. Gate by language so each grammar
                // gets its own per-case block emission. Pre-fix the Swift
                // handler ran on every `switch_statement` regardless of
                // language but only recognised `switch_entry`, so on C the
                // switch produced one branch+join block pair with NO
                // per-case blocks (iter-2 audit cell c21 `sdsIncrLen`:
                // `num_blocks: 2, num_edges: 0`).
                match self.language {
                    Language::Swift => self.process_swift_switch(node, depth)?,
                    Language::C | Language::Cpp => self.process_c_switch(node, depth)?,
                    // cl4-cyclomatic-v1 (GH #76): C# spells switch arms as
                    // `switch_section` children under a `switch_body` (not
                    // C's `case_statement` under a `compound_statement`, nor
                    // Swift's `switch_entry`). The Swift fallback handler only
                    // recognised `switch_entry`, so on C# the switch collapsed
                    // to a single branch+join pair with NO per-case decision
                    // edges (degenerate CFG). Dispatch to the dedicated
                    // per-section handler.
                    Language::CSharp => self.process_csharp_switch(node, depth)?,
                    _ => self.process_swift_switch(node, depth)?,
                }
            }
            // Rust uses _expression variants (return/break/continue are expressions)
            "return_statement" | "return_expression" => {
                self.process_return_statement(node, start_line, end_line)?
            }
            "break_statement" | "break_expression" => {
                self.process_break_statement(node, start_line, end_line)?
            }
            "continue_statement" | "continue_expression" => {
                self.process_continue_statement(node, start_line, end_line)?
            }

            // Nested function definitions
            "function_definition" | "function_declaration" | "arrow_function" => {
                self.process_nested_function(node, depth)?;
            }

            // Expression statements and let declarations — in expression-oriented
            // languages (Rust, OCaml) the child of an expression_statement or the
            // value of a let_declaration may itself be a control flow node (match,
            // if, try_expression/?, etc.). Scan immediate children to find them.
            "expression_statement" | "let_declaration" => {
                let mut found_cf = false;
                // RC4-4a: close the binder-line coverage hole. For a
                // `let_declaration` whose value is a control-flow expression
                // (`let value = call()?;`, `let x = match … {…}`), block
                // creation is reparented onto the inner CF node
                // (`try_expression`/`match`/`if`), whose `start_position()`
                // is the inner operand's row — NOT the `let` head row. That
                // left the binder's own source line owned by NO basic block
                // (a totality-invariant violation), which made the
                // reaching-defs uninit worklist flood the bound variable
                // with a spurious `possible` finding. Anchor the head line
                // onto the CURRENT block (the predecessor that the CF node
                // forks from, which dominates every continuation use) BEFORE
                // descending, so the binder line is always covered. We record
                // only the head row (`start_line`) — the inner CF rows are
                // already covered by the blocks the CF node creates, so
                // extending to `end_line` here would overlap them.
                if node.kind() == "let_declaration" {
                    self.update_current_block_lines(start_line, start_line);
                }
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if is_control_flow_node(child.kind()) || child.kind() == "try_expression" {
                            self.process_statement(child, depth)?;
                            found_cf = true;
                            // Don't break — there may be multiple CF nodes
                            // e.g. `let x = a?; let y = b?;` in a let chain
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                if !found_cf {
                    self.process_expression(node, start_line, end_line)?;
                }
            }

            // (cfg-per-lang-decision-edges-v1 M-103) Elixir cond/case/try are
            // surfaced by tree-sitter as bare `call` nodes whose target is an
            // identifier "cond"/"case"/"try"; the body lives in a `do_block`
            // and (for try) rescue/catch/after blocks are siblings. Without
            // this guard the generic `call` arm below would treat them as
            // ordinary expressions and add zero decision edges.
            "call"
                if self.language == Language::Elixir
                    && is_elixir_control_call(node, self.source) =>
            {
                match elixir_call_target_name(node, self.source).unwrap_or("") {
                    "try" => self.process_elixir_try(node, depth)?,
                    "case" => self.process_elixir_case(node, depth)?,
                    "cond" => self.process_elixir_cond(node, depth)?,
                    _ => {}
                }
            }

            // Bare call expressions
            "call_expression" | "call" => {
                self.process_expression(node, start_line, end_line)?;
            }

            // Container expressions that may contain control flow (OCaml let-in bindings,
            // semicolon-separated sequences, value definitions, Rust blocks inside
            // match arms or other contexts) - recurse into children.
            //
            // (cfg-per-lang-decision-edges-v1 M-103) `statements` is added for
            // Swift: tree-sitter-swift wraps every block of code (function
            // body, guard else-body, do/catch bodies, switch_entry bodies)
            // in a `statements` container. Without this arm the descent
            // stops at the container and we never reach the
            // `guard_statement`/`do_statement`/`switch_statement` children.
            "sequence_expression" | "let_expression" | "value_definition" | "block"
            | "statements" => {
                self.process_block(node, depth)?;
            }

            // fix_cl5_dfg_v1 (v0.5.0 CL-5, GH #77): a bare C/C++ block
            // `{ ... }` (`compound_statement`) that appears as a statement —
            // e.g. the body of an `else_clause` (`else { ... }`), a `case`
            // arm, or a free-standing scope — must have its children walked
            // so any NESTED control flow (an `if`/`for`/`while` inside the
            // block) is split into its own CFG blocks. Pre-fix this fell into
            // the catch-all `_` arm below, which merely stretched the current
            // block's line range over the WHOLE compound statement and never
            // descended. That collapsed a conditional re-assignment and the
            // later unconditional uses of a variable into ONE coarse basic
            // block, so reaching-defs treated the conditional store as the
            // last def before the uses and flagged the earlier (live) store as
            // a dead store (luau Parser.cpp `parseIf` -> `matchThenElse@590`).
            "compound_statement" => {
                self.process_block(node, depth)?;
            }

            // C1 GAP-2 (v0.5.0 AUDIT-FIX): Python `with` statement. The
            // context-manager header is a linear-flow prelude (no branch), but
            // the `with` BODY may contain control flow — most importantly a
            // `try/except` whose two arms must each get their own CFG block.
            // Pre-fix `with_statement` fell into the catch-all `_` arm below,
            // which (a) stretched the current block over the WHOLE `with`
            // range and (b) NEVER descended into the body — so a nested
            // try/except collapsed into one coarse block and the SSA
            // dead-store decision wrongly flagged the try-store as
            // overwritten-before-use (requests `should_bypass_proxies`:
            // `bypass`). Mirror the DFG counterpart
            // (`dfg::extractor::process_with_statement`) and the
            // `compound_statement` precedent above: record the header on the
            // current block, then descend into the body.
            "with_statement" => self.process_with_statement(node, depth)?,

            // Other statements - just update current block
            _ => {
                self.update_current_block_lines(start_line, end_line);
                // Check for function calls in the statement
                self.extract_calls_from_node(node);
            }
        }

        Ok(())
    }

    /// Process an if statement (handles both `if_statement` and OCaml `if_expression`)
    fn process_if_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Get the condition
        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        // Create branch block
        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);

        // Connect current block to branch
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );

        // Create blocks for then and else branches
        // Standard languages use "consequence"/"alternative" field names
        // OCaml uses then_clause/else_clause child node types (no field names)
        // cfg-continue-fallthrough-fix-v1 (v0.4.2 M-104): Kotlin `if_expression`
        // has NO named "consequence" field — the body is an unnamed child after the
        // closing `)` paren (node-types.json: only field is "condition").
        // Fall back to scanning named children after the condition position.
        // solidity-cfg-v1 (v0.5.0 SOL-005b): Solidity uses the SAME `body`
        // field name for both then and else children — extract via the
        // dedicated helper before falling back to the generic accessors.
        let (sol_then, sol_else) = if matches!(self.language, Language::Solidity) {
            solidity_if_branches(node)
        } else {
            (None, None)
        };
        // Swift if_statement uses neither consequence/alternative fields nor
        // then_clause/else_clause kinds — both branches are bare `statements`
        // children separated by an `else` token (GH #80 else-branch drop).
        let (swift_then, swift_else) = if matches!(self.language, Language::Swift) {
            swift_if_branches(node)
        } else {
            (None, None)
        };
        let consequence = sol_then
            .or(swift_then)
            .or_else(|| node.child_by_field_name("consequence"))
            .or_else(|| find_child_by_kind(node, "then_clause"))
            .or_else(|| kotlin_if_consequence(node));
        // RC1-A-cfg-branch (v0.5.0): an `if` may expose MORE THAN ONE
        // `alternative`-field child. Lua `if/elseif/elseif/else` and Python
        // `if/elif/elif/else` each surface every elseif/elif AND the trailing
        // else as a SEPARATE flat `[alternative]` sibling of the `if_statement`
        // (verified via dump_ast). Pre-fix this read only the FIRST alternative
        // via `child_by_field_name`, so the 2nd+ elseif/elif arm bodies (and the
        // else) fell into NO basic block — `tldr slice` on those lines returned
        // an empty slice and their reads vanished from reaching-defs. Collect
        // ALL of them. `else if`-style languages (Rust/JS/C/Java/C#) nest the
        // continuation INSIDE a single `else_clause`, so they still yield one
        // alternative (unchanged); the per-language Swift/Solidity/Kotlin/OCaml
        // fallbacks below are single-alternative by construction.
        let mut alt_cursor = node.walk();
        let field_alternatives: Vec<Node> = node
            .children_by_field_name("alternative", &mut alt_cursor)
            .collect();
        let alternatives: Vec<Node> = if let Some(single) = sol_else.or(swift_else) {
            vec![single]
        } else if !field_alternatives.is_empty() {
            field_alternatives
        } else if let Some(single) =
            find_child_by_kind(node, "else_clause").or_else(|| kotlin_if_alternative(node))
        {
            vec![single]
        } else {
            Vec::new()
        };

        // Create join block for after the if
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        // Process then branch
        if let Some(then_node) = consequence {
            let then_start = then_node.start_position().row as u32 + 1;
            let then_end = then_node.end_position().row as u32 + 1;
            let then_block = self.new_block(BlockType::Body, then_start, then_end);

            self.add_edge(branch_block, then_block, EdgeType::True, condition.clone());

            self.current_block_id = then_block;
            self.process_block(then_node, depth + 1)?;

            // Connect to join (unless we returned)
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                self.add_edge(
                    self.current_block_id,
                    join_block,
                    EdgeType::Unconditional,
                    None,
                );
            }
        }

        // Process else/elseif branches. Each alternative (elseif/elif arm or
        // the trailing else) gets its OWN body block and a False decision edge
        // off the shared branch, so every arm body is covered. For the common
        // single-alternative case this is byte-identical to the prior behavior.
        if alternatives.is_empty() {
            // No else - false edge goes directly to join
            self.add_edge(branch_block, join_block, EdgeType::False, None);
        } else {
            for else_node in alternatives {
                let else_start = else_node.start_position().row as u32 + 1;
                let else_end = else_node.end_position().row as u32 + 1;
                let else_block = self.new_block(BlockType::Body, else_start, else_end);

                self.add_edge(branch_block, else_block, EdgeType::False, None);

                self.current_block_id = else_block;

                // Handle elif/elseif by processing the arm body (and, for
                // `else if`-style languages, the nested if it contains).
                self.process_block(else_node, depth + 1)?;

                if !self.exit_blocks.contains(&self.current_block_id)
                    && !self.loop_exit_blocks.contains(&self.current_block_id)
                {
                    self.add_edge(
                        self.current_block_id,
                        join_block,
                        EdgeType::Unconditional,
                        None,
                    );
                }
            }
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process a for loop (handles `for_statement`, `for_in_statement`, OCaml `for_expression`)
    fn process_for_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Create loop header
        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);

        // Connect current to header
        self.add_edge(
            self.current_block_id,
            header_block,
            EdgeType::Unconditional,
            None,
        );

        // Create loop body block
        // Standard languages use "body" field; OCaml uses do_clause child;
        // tree-sitter-kotlin-ng's `for_statement` exposes the body as a
        // bare `block` child (no field name) so the recursive body walk
        // below would otherwise drop nested if-expressions / continue /
        // break — see iter-2 audit `kotlin.md` c15/c17 (#61 reproduces).
        // (cfg-per-lang-decision-edges-v1 M-103) Fall back to the first
        // `block` / `statement_block` child for Kotlin and any other
        // grammar that elides the `body` field.
        let body = node
            .child_by_field_name("body")
            .or_else(|| find_child_by_kind(node, "do_clause"))
            .or_else(|| find_child_by_kind(node, "block"))
            .or_else(|| find_child_by_kind(node, "statement_block"));
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(body_node) = body {
            let body_start = body_node.start_position().row as u32 + 1;
            let body_end = body_node.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, body_start, body_end);

            // True edge: enter loop
            self.add_edge(header_block, body_block, EdgeType::True, None);

            // False edge: exit loop
            self.add_edge(header_block, exit_block, EdgeType::False, None);

            self.current_block_id = body_block;
            self.process_block(body_node, depth + 1)?;

            // Back edge to header
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                self.add_edge(
                    self.current_block_id,
                    header_block,
                    EdgeType::BackEdge,
                    None,
                );
            }
        } else {
            self.add_edge(header_block, exit_block, EdgeType::False, None);
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process a while loop (handles `while_statement` and OCaml `while_expression`)
    fn process_while_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Get condition
        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        // Create loop header
        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);

        // Connect current to header
        self.add_edge(
            self.current_block_id,
            header_block,
            EdgeType::Unconditional,
            None,
        );

        // Create exit block
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        // Process body
        // Standard languages use "body" field; OCaml uses do_clause child
        let body = node
            .child_by_field_name("body")
            .or_else(|| find_child_by_kind(node, "do_clause"));
        if let Some(body_node) = body {
            let body_start = body_node.start_position().row as u32 + 1;
            let body_end = body_node.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, body_start, body_end);

            self.add_edge(header_block, body_block, EdgeType::True, condition);
            self.add_edge(header_block, exit_block, EdgeType::False, None);

            self.current_block_id = body_block;
            self.process_block(body_node, depth + 1)?;

            // Back edge
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                self.add_edge(
                    self.current_block_id,
                    header_block,
                    EdgeType::BackEdge,
                    None,
                );
            }
        } else {
            self.add_edge(header_block, exit_block, EdgeType::False, None);
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process Rust `loop { ... }` (infinite loop, exits only via break)
    fn process_loop_expression(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Create loop header
        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);

        // Connect current block to header
        self.add_edge(
            self.current_block_id,
            header_block,
            EdgeType::Unconditional,
            None,
        );

        // Create exit block (reached via break)
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        // Process body
        if let Some(body_node) = node.child_by_field_name("body") {
            let body_start = body_node.start_position().row as u32 + 1;
            let body_end = body_node.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, body_start, body_end);

            // Unconditional entry into body (infinite loop — no condition)
            self.add_edge(header_block, body_block, EdgeType::True, None);

            self.current_block_id = body_block;
            self.process_block(body_node, depth + 1)?;

            // Back edge to header
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                self.add_edge(
                    self.current_block_id,
                    header_block,
                    EdgeType::BackEdge,
                    None,
                );
            }
        }

        // The exit block is reached only via break statements inside the loop body.
        // Connect header→exit as False edge so the exit block is reachable in the CFG
        // even when break statements are not explicitly modeled as edges to exit_block.
        self.add_edge(header_block, exit_block, EdgeType::False, None);

        self.current_block_id = exit_block;
        Ok(())
    }

    /// solidity-cfg-v1 (v0.5.0 SOL-005b): Process a Solidity `do { ... } while (cond);`
    /// loop.
    ///
    /// Semantics: the body runs once unconditionally, THEN the condition is
    /// evaluated. If true the loop iterates again; if false control exits.
    ///
    /// CFG shape (body-first loop with a header at the tail):
    /// ```text
    ///   current ── unconditional ──▶ body
    ///                                 │
    ///                                 │ unconditional
    ///                                 ▼
    ///                                header (LoopHeader on the condition)
    ///                                 │       │
    ///                                 │ True  │ False
    ///                                 ▼       ▼
    ///                              (back to body)  exit
    /// ```
    fn process_do_while_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        // Header carries the condition check; placed at end-of-loop line so
        // metric tools picking up the header line surface the `while (...)` row.
        let header_block = self.new_block(BlockType::LoopHeader, end_line, end_line);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        let body = node.child_by_field_name("body");
        if let Some(body_node) = body {
            let body_start = body_node.start_position().row as u32 + 1;
            let body_end = body_node.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, body_start, body_end);

            // Unconditional entry into body (do-while body runs at least once).
            self.add_edge(
                self.current_block_id,
                body_block,
                EdgeType::Unconditional,
                None,
            );

            self.current_block_id = body_block;
            self.process_block(body_node, depth + 1)?;

            // From end-of-body, fall into the header (condition check).
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(
                    self.current_block_id,
                    header_block,
                    EdgeType::Unconditional,
                    None,
                );
            }

            // True → back-edge to the body. False → exit.
            self.add_edge(header_block, body_block, EdgeType::BackEdge, condition);
            self.add_edge(header_block, exit_block, EdgeType::False, None);
        } else {
            // Defensive: no body → degenerate flow current ⇒ exit.
            self.add_edge(
                self.current_block_id,
                exit_block,
                EdgeType::Unconditional,
                None,
            );
        }

        // Suppress the unused warning in the body=None branch.
        let _ = start_line;

        self.current_block_id = exit_block;
        Ok(())
    }

    /// solidity-cfg-v1 (v0.5.0 SOL-005b): Process a Solidity `require(cond, ...)`
    /// or `assert(cond)` call wrapped in an `expression_statement`.
    ///
    /// Both intrinsics evaluate the condition and halt the function on the
    /// false side (revert / panic). Model as a Branch block with a True edge
    /// continuing to the next statement and a False edge into a Return ⇒ Exit
    /// pair — mirrors the CFG shape that Java's `Objects.requireNonNull` /
    /// Python's `assert` would produce for any equivalent grammar that
    /// surfaced them as dedicated statement nodes.
    fn process_solidity_guard_call(
        &mut self,
        node: Node,
        _depth: usize,
        start_line: u32,
        end_line: u32,
        guard_name: &'static str,
    ) -> TldrResult<()> {
        // Surface any nested calls inside the condition arguments for the
        // call-graph / data-flow consumers BEFORE the branch is created.
        self.extract_calls_from_node(node);

        let branch_block = self.new_block(BlockType::Branch, start_line, end_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );

        // False side: condition violated → halt the function.
        let fail_block = self.new_block(BlockType::Return, start_line, end_line);
        self.add_edge(
            branch_block,
            fail_block,
            EdgeType::False,
            Some(format!("{} failed", guard_name)),
        );
        let exit_block = self.new_block(BlockType::Exit, end_line, end_line);
        self.add_edge(fail_block, exit_block, EdgeType::Unconditional, None);
        self.exit_blocks.push(exit_block);

        // True side: condition held → continue.
        let ok_block = self.new_block(BlockType::Body, start_line, end_line);
        self.add_edge(
            branch_block,
            ok_block,
            EdgeType::True,
            Some(guard_name.to_string()),
        );

        self.current_block_id = ok_block;
        Ok(())
    }

    /// Process Rust `?` operator (try_expression).
    ///
    /// The `?` creates a hidden branch in the control flow:
    /// - Ok(val)/Some(val) → unwrap and continue to next statement
    /// - Err(e)/None → early return from the function
    ///
    /// This is semantically equivalent to:
    /// ```ignore
    /// match expr {
    ///     Ok(val) => val,      // True edge → continue
    ///     Err(e) => return Err(e), // False edge → exit
    /// }
    /// ```
    fn process_question_mark(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if depth > MAX_NESTING_DEPTH {
            return Ok(());
        }

        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Process the inner expression (the part before ?) which may contain
        // nested ? operators or function calls
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "try_expression" {
                    // Nested ? — recurse
                    self.process_question_mark(child, depth + 1)?;
                } else if child.kind() != "?" {
                    // Process inner expression for calls etc.
                    self.extract_calls_from_node(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Create branch block for the ? check
        let branch_block = self.new_block(BlockType::Branch, start_line, end_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );

        // True edge: Ok/Some → continue to next statement
        let ok_block = self.new_block(BlockType::Body, start_line, end_line);
        self.add_edge(
            branch_block,
            ok_block,
            EdgeType::True,
            Some("Ok/Some".to_string()),
        );

        // False edge: Err/None → early return
        let err_block = self.new_block(BlockType::Return, start_line, end_line);
        self.add_edge(
            branch_block,
            err_block,
            EdgeType::False,
            Some("Err/None".to_string()),
        );

        // Err path exits the function
        let exit_block = self.new_block(BlockType::Exit, end_line, end_line);
        self.add_edge(err_block, exit_block, EdgeType::Unconditional, None);
        self.exit_blocks.push(exit_block);

        // Continue on the Ok path
        self.current_block_id = ok_block;
        Ok(())
    }

    /// Process try/except statement (handles `try_statement` and OCaml `try_expression`)
    fn process_try_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Create try block
        let try_block = self.new_block(BlockType::Body, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            try_block,
            EdgeType::Unconditional,
            None,
        );

        // Create exit block
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        // For OCaml try_expression, the body is the "expression" field
        // and exception handlers are match_case children
        if let Some(expr_body) = node.child_by_field_name("expression") {
            // OCaml-style: try <expression> with <match_case>...
            self.current_block_id = try_block;
            self.process_statement(expr_body, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                self.add_edge(
                    self.current_block_id,
                    exit_block,
                    EdgeType::Unconditional,
                    None,
                );
            }

            // Process match_case children as exception handlers
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "match_case" {
                        let except_start = child.start_position().row as u32 + 1;
                        let except_end = child.end_position().row as u32 + 1;
                        let except_block =
                            self.new_block(BlockType::Body, except_start, except_end);

                        self.add_edge(
                            try_block,
                            except_block,
                            EdgeType::Unconditional,
                            Some("exception".to_string()),
                        );

                        self.current_block_id = except_block;
                        self.process_block(child, depth + 1)?;

                        if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                            self.add_edge(
                                self.current_block_id,
                                exit_block,
                                EdgeType::Unconditional,
                                None,
                            );
                        }
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        } else {
            // Standard try/except/catch/finally pattern
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    match child.kind() {
                        // solidity-cfg-v1 (v0.5.0 SOL-005b): tree-sitter-solidity
                        // exposes the try-block body as `block_statement` (not
                        // `block`), as the value of the `body` field. Match it
                        // alongside the generic `block` kind so the try-body
                        // statements are walked and any nested control-flow is
                        // registered. The `catch_clause` arm below already
                        // matches the catch siblings without modification.
                        "block" | "block_statement" => {
                            // Try block body
                            self.current_block_id = try_block;
                            self.process_block(child, depth + 1)?;
                            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                                self.add_edge(
                                    self.current_block_id,
                                    exit_block,
                                    EdgeType::Unconditional,
                                    None,
                                );
                            }
                        }
                        "except_clause" | "catch_clause" => {
                            let except_start = child.start_position().row as u32 + 1;
                            let except_end = child.end_position().row as u32 + 1;
                            let except_block =
                                self.new_block(BlockType::Body, except_start, except_end);

                            // Exception edge from try block
                            self.add_edge(
                                try_block,
                                except_block,
                                EdgeType::Unconditional,
                                Some("exception".to_string()),
                            );

                            self.current_block_id = except_block;
                            self.process_block(child, depth + 1)?;

                            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                                self.add_edge(
                                    self.current_block_id,
                                    exit_block,
                                    EdgeType::Unconditional,
                                    None,
                                );
                            }
                        }
                        "finally_clause" => {
                            let finally_start = child.start_position().row as u32 + 1;
                            let finally_end = child.end_position().row as u32 + 1;
                            let finally_block =
                                self.new_block(BlockType::Body, finally_start, finally_end);

                            // Finally is always executed
                            self.add_edge(exit_block, finally_block, EdgeType::Unconditional, None);

                            self.current_block_id = finally_block;
                            self.process_block(child, depth + 1)?;

                            // Update exit block to be after finally
                            let new_exit =
                                self.new_block(BlockType::Body, finally_end, finally_end);
                            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                                self.add_edge(
                                    self.current_block_id,
                                    new_exit,
                                    EdgeType::Unconditional,
                                    None,
                                );
                            }
                            self.current_block_id = new_exit;
                            return Ok(());
                        }
                        _ => {}
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process a Python `with_statement`.
    ///
    /// C1 GAP-2 (v0.5.0 AUDIT-FIX): a `with` is linear flow — entering the
    /// context manager does not branch — but its BODY frequently contains
    /// control flow (`try/except`, `if/else`, loops) that must be split into
    /// distinct CFG blocks. The grammar (verified by debug-parse against
    /// tree-sitter-python) is:
    /// ```text
    /// with_statement
    ///   'with'
    ///   with_clause { with_item { [value] <ctx-expr> } ... }
    ///   ':'
    ///   [body] block { <statements> }
    /// ```
    /// We attribute the `with` header line (and any context-manager calls) to
    /// the CURRENT block, then descend into the `body` block via
    /// `process_block` so nested control flow is lowered normally. This mirrors
    /// the DFG counterpart `dfg::extractor::process_with_statement`, which
    /// already records the context-expression reads and walks the body — the
    /// CFG never had the matching descent, so the two graphs disagreed on block
    /// boundaries and the SSA dead-store decision saw a try-store and its
    /// except-path overwrite in ONE block.
    fn process_with_statement(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let header_line = node.start_position().row as u32 + 1;

        // Attribute the `with` header line to the current block and harvest
        // any calls in the context-manager expressions (`with f(x):`). The
        // body is handled separately below so its statements/control flow are
        // NOT swallowed into this block.
        self.update_current_block_lines(header_line, header_line);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "with_clause" | "with_item" => self.extract_calls_from_node(child),
                _ => {}
            }
        }

        // Descend into the body so nested control flow (try/except, if, loops)
        // gets its own blocks. `process_block` dispatches each body statement
        // through `process_statement` exactly as a normal block would.
        if let Some(body) = node.child_by_field_name("body") {
            self.process_block(body, depth + 1)?;
        }

        Ok(())
    }

    /// Process a match/switch expression (OCaml `match_expression`, Rust
    /// `match_expression`, Scala `match_expression`).
    fn process_match_expression(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        // Get the scrutinee expression.
        // OCaml uses "expression" field; Rust uses "value" field.
        let scrutinee = node
            .child_by_field_name("expression")
            .or_else(|| node.child_by_field_name("value"))
            .map(|n| {
                n.utf8_text(self.source.as_bytes())
                    .unwrap_or("")
                    .to_string()
            });

        // Create branch block for the match
        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);

        // Connect current block to branch
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );

        // Create join block for after the match
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        // Find the container of match arms/cases.
        // OCaml: match_case children are direct children of match_expression.
        // Rust: match_arm children are inside a match_block child (via "body" field).
        // Scala: case_clause children are inside a case_block child (via "body"
        //   field) — same container shape as Rust, different arm node-kind.
        let arms_parent = node.child_by_field_name("body").unwrap_or(node);

        // Process each match_case/match_arm/case_clause child as a separate
        // branch. RC1-A-cfg-branch (v0.5.0): Scala arms are `case_clause`; pre-fix
        // the recognizer only knew Rust `match_arm` / OCaml `match_case`, so every
        // Scala arm body fell into NO basic block (scala-zio
        // BuildHelper.extraOptions arms 134-164), erasing its refs from
        // reaching-defs and producing false dead-stores.
        let mut cursor = arms_parent.walk();
        let mut case_count = 0;
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if matches!(child.kind(), "match_case" | "match_arm" | "case_clause") {
                    let case_start = child.start_position().row as u32 + 1;
                    let case_end = child.end_position().row as u32 + 1;
                    let case_block = self.new_block(BlockType::Body, case_start, case_end);

                    let edge_type = if case_count == 0 {
                        EdgeType::True
                    } else {
                        EdgeType::False
                    };
                    self.add_edge(branch_block, case_block, edge_type, scrutinee.clone());

                    self.current_block_id = case_block;
                    self.process_block(child, depth + 1)?;

                    if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id) {
                        self.add_edge(
                            self.current_block_id,
                            join_block,
                            EdgeType::Unconditional,
                            None,
                        );
                    }
                    case_count += 1;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // If no cases were found, connect branch directly to join
        if case_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    // -- (cfg-per-lang-decision-edges-v1 M-103) -------------------------------
    //
    // Per-language CFG handlers for Elixir cond/case/try and Swift
    // guard/do-catch/switch. Each handler mirrors the
    // branch+arms+join shape used by `process_if_statement` /
    // `process_match_expression` so that downstream cyclomatic / edge-count /
    // hubs / dead-code analyses see structurally valid graphs.

    /// Process Elixir `case x do … end`.
    ///
    /// AST shape (verified via `dump_ast` example):
    /// ```text
    /// call
    ///   target: identifier "case"
    ///   arguments: <scrutinee>
    ///   do_block
    ///     do
    ///     stab_clause  (left=pattern, operator=->, right=body)
    ///     stab_clause
    ///     …
    ///     end
    /// ```
    fn process_elixir_case(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let scrutinee = node.child_by_field_name("arguments").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let do_block = find_child_by_kind(node, "do_block");
        let mut clause_count = 0usize;
        if let Some(do_block) = do_block {
            let mut cursor = do_block.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "stab_clause" {
                        self.process_elixir_stab_clause(
                            child,
                            branch_block,
                            join_block,
                            scrutinee.clone(),
                            clause_count,
                            depth,
                        )?;
                        clause_count += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        if clause_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Elixir `cond do … end`. Same shape as `case` but no
    /// scrutinee — each `stab_clause` left is itself a boolean test.
    fn process_elixir_cond(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let do_block = find_child_by_kind(node, "do_block");
        let mut clause_count = 0usize;
        if let Some(do_block) = do_block {
            let mut cursor = do_block.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "stab_clause" {
                        let cond_text = child.child_by_field_name("left").map(|n| {
                            n.utf8_text(self.source.as_bytes())
                                .unwrap_or("")
                                .to_string()
                        });
                        self.process_elixir_stab_clause(
                            child,
                            branch_block,
                            join_block,
                            cond_text,
                            clause_count,
                            depth,
                        )?;
                        clause_count += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        if clause_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Helper: emit a branch→arm-body→join slice for one `stab_clause`
    /// (used by both `process_elixir_case` and `process_elixir_cond`).
    fn process_elixir_stab_clause(
        &mut self,
        clause: Node,
        branch_block: usize,
        join_block: usize,
        condition: Option<String>,
        clause_index: usize,
        depth: usize,
    ) -> TldrResult<()> {
        let clause_start = clause.start_position().row as u32 + 1;
        let clause_end = clause.end_position().row as u32 + 1;
        let arm_block = self.new_block(BlockType::Body, clause_start, clause_end);

        let edge_type = if clause_index == 0 {
            EdgeType::True
        } else {
            EdgeType::False
        };
        self.add_edge(branch_block, arm_block, edge_type, condition);

        self.current_block_id = arm_block;

        if let Some(body) = clause.child_by_field_name("right") {
            self.process_block(body, depth + 1)?;
        }

        if !self.exit_blocks.contains(&self.current_block_id)
            && !self.loop_exit_blocks.contains(&self.current_block_id)
        {
            self.add_edge(
                self.current_block_id,
                join_block,
                EdgeType::Unconditional,
                None,
            );
        }
        Ok(())
    }

    /// Process Elixir `try do … rescue … catch … after … end`.
    ///
    /// AST shape:
    /// ```text
    /// call
    ///   target: identifier "try"
    ///   do_block
    ///     do
    ///     <try-body statements…>
    ///     rescue_block { rescue, stab_clause, … }
    ///     catch_block  { catch,  stab_clause, … }
    ///     after_block  { after,  <statements> }
    ///     end
    /// ```
    fn process_elixir_try(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let do_block = match find_child_by_kind(node, "do_block") {
            Some(b) => b,
            None => {
                self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
                self.current_block_id = join_block;
                return Ok(());
            }
        };

        // 1. Process the try-body (statements between `do` and the first
        //    rescue/catch/after sibling).
        let try_body_block = self.new_block(BlockType::Body, start_line, start_line);
        self.add_edge(branch_block, try_body_block, EdgeType::True, None);
        self.current_block_id = try_body_block;

        let mut cursor = do_block.walk();
        let mut seen_handler = false;
        let mut handlers: Vec<Node> = Vec::new();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let kind = child.kind();
                if matches!(kind, "rescue_block" | "catch_block" | "after_block") {
                    seen_handler = true;
                    handlers.push(child);
                } else if !seen_handler && !matches!(kind, "do" | "end") {
                    self.process_statement(child, depth + 1)?;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        if !self.exit_blocks.contains(&self.current_block_id)
            && !self.loop_exit_blocks.contains(&self.current_block_id)
        {
            self.add_edge(
                self.current_block_id,
                join_block,
                EdgeType::Unconditional,
                None,
            );
        }

        // 2. Emit each handler as a False-edge from the dispatch branch.
        //    For rescue/catch, each `stab_clause` child becomes its own
        //    arm so the cyclomatic count grows with arm count. For
        //    `after` the handler is a single block.
        for handler in handlers {
            let kind = handler.kind();
            let h_start = handler.start_position().row as u32 + 1;
            let h_end = handler.end_position().row as u32 + 1;

            match kind {
                "rescue_block" | "catch_block" => {
                    let mut hc = handler.walk();
                    let mut any_clause = false;
                    if hc.goto_first_child() {
                        loop {
                            let clause = hc.node();
                            if clause.kind() == "stab_clause" {
                                any_clause = true;
                                let c_start = clause.start_position().row as u32 + 1;
                                let c_end = clause.end_position().row as u32 + 1;
                                let arm_block =
                                    self.new_block(BlockType::Body, c_start, c_end);
                                self.add_edge(
                                    branch_block,
                                    arm_block,
                                    EdgeType::False,
                                    Some(kind.to_string()),
                                );
                                self.current_block_id = arm_block;
                                if let Some(body) = clause.child_by_field_name("right") {
                                    self.process_block(body, depth + 1)?;
                                }
                                if !self.exit_blocks.contains(&self.current_block_id)
                                    && !self
                                        .loop_exit_blocks
                                        .contains(&self.current_block_id)
                                {
                                    self.add_edge(
                                        self.current_block_id,
                                        join_block,
                                        EdgeType::Unconditional,
                                        None,
                                    );
                                }
                            }
                            if !hc.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                    if !any_clause {
                        let arm_block = self.new_block(BlockType::Body, h_start, h_end);
                        self.add_edge(
                            branch_block,
                            arm_block,
                            EdgeType::False,
                            Some(kind.to_string()),
                        );
                        self.current_block_id = arm_block;
                        self.process_block(handler, depth + 1)?;
                        if !self.exit_blocks.contains(&self.current_block_id)
                            && !self.loop_exit_blocks.contains(&self.current_block_id)
                        {
                            self.add_edge(
                                self.current_block_id,
                                join_block,
                                EdgeType::Unconditional,
                                None,
                            );
                        }
                    }
                }
                "after_block" => {
                    let arm_block = self.new_block(BlockType::Body, h_start, h_end);
                    self.add_edge(
                        branch_block,
                        arm_block,
                        EdgeType::False,
                        Some("after".to_string()),
                    );
                    self.current_block_id = arm_block;
                    self.process_block(handler, depth + 1)?;
                    if !self.exit_blocks.contains(&self.current_block_id)
                        && !self.loop_exit_blocks.contains(&self.current_block_id)
                    {
                        self.add_edge(
                            self.current_block_id,
                            join_block,
                            EdgeType::Unconditional,
                            None,
                        );
                    }
                }
                _ => {}
            }
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Swift `guard <conditions> else { … }`.
    ///
    /// AST shape:
    /// ```text
    /// guard_statement
    ///   guard
    ///   condition: <value_binding_pattern …>
    ///   else
    ///   statements   ← else-body (always exits)
    ///   }
    /// ```
    fn process_swift_guard(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );

        // The else-body is the `statements` child that appears AFTER the
        // `else` token.
        let mut cursor = node.walk();
        let mut seen_else = false;
        let mut else_body: Option<Node> = None;
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "else" {
                    seen_else = true;
                } else if seen_else && child.kind() == "statements" {
                    else_body = Some(child);
                    break;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        let continue_block = self.new_block(BlockType::Body, end_line, end_line);
        self.add_edge(branch_block, continue_block, EdgeType::True, None);

        if let Some(else_node) = else_body {
            let e_start = else_node.start_position().row as u32 + 1;
            let e_end = else_node.end_position().row as u32 + 1;
            let else_block = self.new_block(BlockType::Body, e_start, e_end);
            self.add_edge(branch_block, else_block, EdgeType::False, None);

            self.current_block_id = else_block;
            self.process_block(else_node, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(
                    self.current_block_id,
                    continue_block,
                    EdgeType::Unconditional,
                    None,
                );
            }
        } else {
            self.add_edge(branch_block, continue_block, EdgeType::False, None);
        }

        self.current_block_id = continue_block;
        Ok(())
    }

    /// Process Swift `do { … } catch <pattern>? { … } catch { … } …`.
    ///
    /// AST shape:
    /// ```text
    /// do_statement
    ///   do
    ///   { statements }            ← do-body
    ///   catch_block               ← 1..N catch arms
    ///     catch_keyword
    ///     <pattern?>
    ///     { statements }
    /// ```
    fn process_swift_do_catch(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let mut do_body: Option<Node> = None;
        let mut catches: Vec<Node> = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "statements" if do_body.is_none() => {
                        do_body = Some(child);
                    }
                    "catch_block" => {
                        catches.push(child);
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // do-body arm.
        let body_block = self.new_block(BlockType::Body, start_line, start_line);
        self.add_edge(branch_block, body_block, EdgeType::True, None);
        self.current_block_id = body_block;
        if let Some(body) = do_body {
            self.process_block(body, depth + 1)?;
        }
        if !self.exit_blocks.contains(&self.current_block_id)
            && !self.loop_exit_blocks.contains(&self.current_block_id)
        {
            self.add_edge(
                self.current_block_id,
                join_block,
                EdgeType::Unconditional,
                None,
            );
        }

        let had_catch = !catches.is_empty();
        for catch in catches {
            let c_start = catch.start_position().row as u32 + 1;
            let c_end = catch.end_position().row as u32 + 1;
            let catch_block = self.new_block(BlockType::Body, c_start, c_end);
            self.add_edge(
                branch_block,
                catch_block,
                EdgeType::False,
                Some("catch".to_string()),
            );
            self.current_block_id = catch_block;
            self.process_block(catch, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(
                    self.current_block_id,
                    join_block,
                    EdgeType::Unconditional,
                    None,
                );
            }
        }

        if !had_catch {
            self.add_edge(branch_block, join_block, EdgeType::False, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Swift `switch x { case … : … ; case …, … : … ; default: … }`.
    ///
    /// AST shape:
    /// ```text
    /// switch_statement
    ///   switch
    ///   expr: <scrutinee>
    ///   {
    ///   switch_entry  (case …)  ← 1..N
    ///     case|default_keyword
    ///     switch_pattern (…)
    ///     :
    ///     statements
    ///   }
    /// ```
    fn process_swift_switch(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let scrutinee = node.child_by_field_name("expr").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let mut entry_count = 0usize;
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "switch_entry" {
                    let c_start = child.start_position().row as u32 + 1;
                    let c_end = child.end_position().row as u32 + 1;
                    let arm_block = self.new_block(BlockType::Body, c_start, c_end);
                    let edge_type = if entry_count == 0 {
                        EdgeType::True
                    } else {
                        EdgeType::False
                    };
                    self.add_edge(branch_block, arm_block, edge_type, scrutinee.clone());
                    self.current_block_id = arm_block;
                    self.process_block(child, depth + 1)?;
                    if !self.exit_blocks.contains(&self.current_block_id)
                        && !self.loop_exit_blocks.contains(&self.current_block_id)
                    {
                        self.add_edge(
                            self.current_block_id,
                            join_block,
                            EdgeType::Unconditional,
                            None,
                        );
                    }
                    entry_count += 1;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        if entry_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// (cfg-c-java-scala-control-flow-v1 v0.4.2 M-101) Process a C / C++
    /// `switch_statement`. Pre-fix the Swift handler ran on every
    /// `switch_statement` regardless of language but only knew about Swift's
    /// `switch_entry` arm-kind, so C switches collapsed to one branch+join
    /// block pair with zero per-case decision edges (iter-2 audit cells
    /// c21/c47 — `sdsIncrLen` `num_blocks: 2, num_edges: 0`).
    ///
    /// Grammar shape (verified via `cargo run --example dump_ast -- c …`):
    ///
    /// ```text
    /// switch_statement
    ///   switch
    ///   condition: parenthesized_expression
    ///   body: compound_statement
    ///     {
    ///     case_statement       ← 1..N (each carries its case label + body)
    ///       case | default
    ///       value: <literal>   (absent on default)
    ///       :
    ///       <statements…>      (the case body, may include break_statement)
    ///     }
    /// ```
    ///
    /// Strategy: mirror `process_swift_switch` — create a branch block
    /// (the dispatch) and a join block (the post-switch successor), then
    /// for each `case_statement` create an arm block, wire a True/False
    /// decision edge from the branch (True for the first arm,
    /// False for subsequent — same convention as Swift), recurse into the
    /// case body, and tie a fall-through edge to the join block unless
    /// the case body itself terminated control (`break_statement` ->
    /// loop_exit_blocks, `return_statement` -> exit_blocks).
    fn process_c_switch(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let scrutinee = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        // Use a sentinel so we can still emit the synthetic join edge when
        // the switch body is empty. The break statements emitted inside
        // case bodies redirect to a synthetic loop-exit block (so the
        // back-edge guards in process_for/while don't fire), but for a
        // switch there's no surrounding loop — `break` is the natural
        // case terminator and should fall through to the join block
        // we created above. We handle that by post-processing: after
        // each case body, regardless of whether `current_block_id` is in
        // `loop_exit_blocks`, we wire an Unconditional edge to the join
        // block (the loop_exit_blocks set is purely a marker that the
        // path's local control flow ended in a break-style exit, not a
        // signal to skip the join edge).
        let body = node.child_by_field_name("body");
        let mut case_count = 0usize;
        if let Some(body_node) = body {
            let mut cursor = body_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "case_statement" {
                        let c_start = child.start_position().row as u32 + 1;
                        let c_end = child.end_position().row as u32 + 1;
                        let arm_block = self.new_block(BlockType::Body, c_start, c_end);
                        let edge_type = if case_count == 0 {
                            EdgeType::True
                        } else {
                            EdgeType::False
                        };
                        self.add_edge(branch_block, arm_block, edge_type, scrutinee.clone());

                        // Walk the case body — `case_statement` children are
                        // the `case`/`default` keyword, the optional value
                        // literal, the `:` token, and then the statements
                        // making up the case body. We dispatch every
                        // non-token child through `process_statement` so
                        // break_statement / return_statement are honoured.
                        self.current_block_id = arm_block;
                        let mut case_cursor = child.walk();
                        if case_cursor.goto_first_child() {
                            loop {
                                let case_child = case_cursor.node();
                                let ck = case_child.kind();
                                // Skip the label tokens — they carry no
                                // control-flow weight.
                                if ck != "case"
                                    && ck != "default"
                                    && ck != ":"
                                    && !case_child.is_extra()
                                    && case_child.is_named()
                                    // The value literal (e.g. `1`) of a
                                    // numeric case is named but should
                                    // not be treated as a statement.
                                    && ck != "number_literal"
                                    && ck != "identifier"
                                    && ck != "char_literal"
                                    && ck != "string_literal"
                                {
                                    self.process_statement(case_child, depth + 1)?;
                                }
                                if !case_cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                        }

                        // Wire fall-through edge to join. The break/return
                        // already redirected `current_block_id` to a
                        // synthetic loop-exit / exit block; we still want
                        // the case block itself to flow to the join in the
                        // absence of break (C fall-through). Conservative
                        // approximation: if the current block is in
                        // exit_blocks (return-terminated) skip the edge;
                        // otherwise emit it. `loop_exit_blocks` here
                        // signals break-terminated case (the
                        // process_break_statement helper creates a synthetic
                        // continue block AND pushes it into
                        // loop_exit_blocks) — that's exactly what we want
                        // tied to the join.
                        if !self.exit_blocks.contains(&self.current_block_id) {
                            self.add_edge(
                                self.current_block_id,
                                join_block,
                                EdgeType::Unconditional,
                                None,
                            );
                        }
                        case_count += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        if case_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// cl4-cyclomatic-v1 (GH #76) Process a C# `switch_statement`.
    ///
    /// Pre-fix the C# switch routed through `process_swift_switch`, which
    /// only knew about Swift's `switch_entry` arm-kind, so C# switches
    /// collapsed to one branch+join block pair with zero per-case decision
    /// edges (the same degenerate-CFG symptom the C/C++ handler fixed in
    /// cfg-c-java-scala-control-flow-v1).
    ///
    /// Grammar shape (verified via the `dump_cs_inspect` example against the
    /// `csharp-newtonsoft-bson` corpus):
    ///
    /// ```text
    /// switch_statement
    ///   switch
    ///   ( value: <expr> )
    ///   body: switch_body
    ///     {
    ///     switch_section          ← 1..N (each is one case arm)
    ///       case | default
    ///       constant_pattern | … (absent on `default`)
    ///       :
    ///       <statements…>         (the case body, may include break/return)
    ///     }
    /// ```
    ///
    /// Strategy mirrors `process_c_switch`: a branch (dispatch) block and a
    /// join (post-switch) block, then for each `switch_section` an arm block
    /// wired with a True/False decision edge, recursion into the section's
    /// body statements, and a fall-through edge to the join unless the body
    /// terminated via `return` (→ `exit_blocks`).
    fn process_csharp_switch(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let scrutinee = node.child_by_field_name("value").map(|n| {
            n.utf8_text(self.source.as_bytes())
                .unwrap_or("")
                .to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(
            self.current_block_id,
            branch_block,
            EdgeType::Unconditional,
            None,
        );
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let body = node.child_by_field_name("body");
        let mut case_count = 0usize;
        if let Some(body_node) = body {
            let mut cursor = body_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "switch_section" {
                        let c_start = child.start_position().row as u32 + 1;
                        let c_end = child.end_position().row as u32 + 1;
                        let arm_block = self.new_block(BlockType::Body, c_start, c_end);
                        let edge_type = if case_count == 0 {
                            EdgeType::True
                        } else {
                            EdgeType::False
                        };
                        self.add_edge(branch_block, arm_block, edge_type, scrutinee.clone());

                        // Walk the section's children. A `switch_section`
                        // begins with one or more `case`/`default` label
                        // groups (the `case` keyword, the pattern, and the
                        // `:` token); the remaining named children are the
                        // case body statements. Dispatch every body statement
                        // through `process_statement` so break/return are
                        // honoured.
                        self.current_block_id = arm_block;
                        let mut sec_cursor = child.walk();
                        if sec_cursor.goto_first_child() {
                            loop {
                                let sec_child = sec_cursor.node();
                                let ck = sec_child.kind();
                                // cl4r-csharp-cognitive-v1 (v0.5.0 CL-4R): a C#
                                // case body may be a bare statement list
                                // (`case X: stmt; break;`) OR a brace-wrapped
                                // `block` (`case X: { ...; break; }`). The
                                // pre-fix predicate descended ONLY into
                                // `*_statement` children, so a `block`-wrapped
                                // body — and any `foreach`/`for`/`while` loop
                                // nested inside it — was never routed through
                                // `process_statement`. No LoopHeader / back-edge
                                // was emitted and the top-level `has_loops`
                                // summary stayed false for switch-heavy
                                // functions that plainly loop. Descend into the
                                // `block` wrapper too (it is dispatched to
                                // `process_block`, which recurses into the
                                // nested loop). The case-label tokens
                                // (`case`/`default`/`:`) and the case-pattern
                                // nodes (`constant_pattern`,
                                // `relational_pattern`, …) carry no control-flow
                                // weight and are still excluded.
                                let is_case_body = sec_child.is_named()
                                    && !sec_child.is_extra()
                                    && ck != "case"
                                    && ck != "default"
                                    && ck != ":"
                                    && (ck.ends_with("_statement")
                                        || ck == "block"
                                        || ck == "compound_statement");
                                if is_case_body {
                                    self.process_statement(sec_child, depth + 1)?;
                                }
                                if !sec_cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                        }

                        // Wire fall-through edge to join unless the section
                        // body returned (→ exit_blocks). A C# `break`
                        // redirects `current_block_id` to a synthetic
                        // loop-exit block (via `process_break_statement`),
                        // which is exactly the case-terminator we want tied to
                        // the join.
                        if !self.exit_blocks.contains(&self.current_block_id) {
                            self.add_edge(
                                self.current_block_id,
                                join_block,
                                EdgeType::Unconditional,
                                None,
                            );
                        }
                        case_count += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        if case_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process return statement
    fn process_return_statement(
        &mut self,
        node: Node,
        start_line: u32,
        end_line: u32,
    ) -> TldrResult<()> {
        // Create return block
        let return_block = self.new_block(BlockType::Return, start_line, end_line);

        self.add_edge(
            self.current_block_id,
            return_block,
            EdgeType::Unconditional,
            None,
        );

        // Check for function calls in return expression
        self.extract_calls_from_node(node);

        // Create exit block
        let exit_block = self.new_block(BlockType::Exit, end_line, end_line);
        self.add_edge(return_block, exit_block, EdgeType::Unconditional, None);

        self.exit_blocks.push(exit_block);
        self.current_block_id = return_block;

        Ok(())
    }

    /// Process break statement
    fn process_break_statement(
        &mut self,
        _node: Node,
        start_line: u32,
        end_line: u32,
    ) -> TldrResult<()> {
        let break_block = self.new_block(BlockType::Body, start_line, end_line);

        self.add_edge(self.current_block_id, break_block, EdgeType::Break, None);

        // Track the break block as a loop-exit so that subsequent
        // back-edge / fallthrough guards do not synthesise spurious edges
        // out of it. See `loop_exit_blocks` field doc and #18.
        self.loop_exit_blocks.push(break_block);

        self.current_block_id = break_block;
        Ok(())
    }

    /// Process continue statement
    fn process_continue_statement(
        &mut self,
        _node: Node,
        start_line: u32,
        end_line: u32,
    ) -> TldrResult<()> {
        let continue_block = self.new_block(BlockType::Body, start_line, end_line);

        self.add_edge(
            self.current_block_id,
            continue_block,
            EdgeType::Continue,
            None,
        );

        // Track the continue block as a loop-exit so that subsequent
        // back-edge / fallthrough guards do not synthesise spurious edges
        // out of it. Mirrors `process_break_statement` (see #18). Fixes #61.
        self.loop_exit_blocks.push(continue_block);

        self.current_block_id = continue_block;
        Ok(())
    }

    /// Process nested function definition
    fn process_nested_function(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        if let Some(name) = get_function_name(node, self.language, self.source) {
            let nested_cfg =
                build_cfg_for_function(node, &name, self.source, self.language, depth + 1)?;
            self.nested_functions.insert(name, nested_cfg);
        }
        Ok(())
    }

    /// Process expression statement
    fn process_expression(&mut self, node: Node, start_line: u32, end_line: u32) -> TldrResult<()> {
        self.update_current_block_lines(start_line, end_line);
        self.extract_calls_from_node(node);
        Ok(())
    }

    /// Update current block line range
    fn update_current_block_lines(&mut self, start_line: u32, end_line: u32) {
        if let Some(block) = self.blocks.get_mut(self.current_block_id) {
            if block.lines.0 == 0 {
                block.lines.0 = start_line;
            }
            block.lines.1 = end_line.max(block.lines.1);
        }
    }

    /// Extract function calls from a node
    fn extract_calls_from_node(&mut self, node: Node) {
        let mut cursor = node.walk();
        let mut stack = vec![node];

        while let Some(current) = stack.pop() {
            // Check if this is a function call
            if current.kind() == "call" || current.kind() == "call_expression" {
                if let Some(callee) = self.get_callee_name(current) {
                    if let Some(block) = self.blocks.get_mut(self.current_block_id) {
                        if !block.calls.contains(&callee) {
                            block.calls.push(callee);
                        }
                    }
                }
            }

            // Add children
            cursor.reset(current);
            if cursor.goto_first_child() {
                loop {
                    stack.push(cursor.node());
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }

    /// Get the name of the function being called
    fn get_callee_name(&self, call_node: Node) -> Option<String> {
        let func_node = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child(0))?;

        match func_node.kind() {
            "identifier" => Some(
                func_node
                    .utf8_text(self.source.as_bytes())
                    .ok()?
                    .to_string(),
            ),
            "attribute" | "member_expression" => {
                // Get the attribute/property name
                func_node
                    .child_by_field_name("attribute")
                    .or_else(|| func_node.child_by_field_name("property"))
                    .and_then(|n| {
                        n.utf8_text(self.source.as_bytes())
                            .ok()
                            .map(|s| s.to_string())
                    })
            }
            _ => Some(
                func_node
                    .utf8_text(self.source.as_bytes())
                    .ok()?
                    .to_string(),
            ),
        }
    }

    // =========================================================================
    // cfg-ruby-rebuild-v1 (v0.4.2 M-102): Ruby control-flow handlers.
    //
    // tree-sitter-ruby uses BARE node kinds (`if`, `case`, `while`, `until`,
    // `for`, `begin`, `unless`) rather than the `_statement`-suffixed kinds
    // used by Python/JS/Rust. These handlers mirror the generic ones but
    // navigate Ruby's grammar correctly. See `process_statement` dispatch.
    // =========================================================================

    /// Process Ruby `if` / `unless` expressions.
    fn process_ruby_if(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;
        let invert = node.kind() == "unless";

        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes()).unwrap_or("").to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(self.current_block_id, branch_block, EdgeType::Unconditional, None);

        let consequence = node.child_by_field_name("consequence");
        let alternative = node.child_by_field_name("alternative");
        let (true_clause, false_clause) = if invert {
            (alternative, consequence)
        } else {
            (consequence, alternative)
        };

        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(then_node) = true_clause {
            let ts = then_node.start_position().row as u32 + 1;
            let te = then_node.end_position().row as u32 + 1;
            let then_block = self.new_block(BlockType::Body, ts, te);
            self.add_edge(branch_block, then_block, EdgeType::True, condition.clone());
            self.current_block_id = then_block;
            self.process_block(then_node, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, join_block, EdgeType::Unconditional, None);
            }
        } else {
            self.add_edge(branch_block, join_block, EdgeType::True, condition.clone());
        }

        if let Some(else_node) = false_clause {
            let es = else_node.start_position().row as u32 + 1;
            let ee = else_node.end_position().row as u32 + 1;
            let else_block = self.new_block(BlockType::Body, es, ee);
            self.add_edge(branch_block, else_block, EdgeType::False, None);
            self.current_block_id = else_block;
            // `elsif` has same shape as `if`; `else` is a body container.
            if else_node.kind() == "elsif" {
                self.process_statement(else_node, depth + 1)?;
            } else {
                self.process_block(else_node, depth + 1)?;
            }
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, join_block, EdgeType::Unconditional, None);
            }
        } else {
            self.add_edge(branch_block, join_block, EdgeType::False, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Ruby modifier-if/unless: `expr if cond`, `expr unless cond`.
    fn process_ruby_if_modifier(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;
        let invert = node.kind() == "unless_modifier";

        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes()).unwrap_or("").to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(self.current_block_id, branch_block, EdgeType::Unconditional, None);
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(body) = node.child_by_field_name("body") {
            let bs = body.start_position().row as u32 + 1;
            let be = body.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::Body, bs, be);
            let (true_target, false_target) = if invert {
                (join_block, body_block)
            } else {
                (body_block, join_block)
            };
            self.add_edge(branch_block, true_target, EdgeType::True, condition);
            self.add_edge(branch_block, false_target, EdgeType::False, None);
            self.current_block_id = body_block;
            self.process_statement(body, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, join_block, EdgeType::Unconditional, None);
            }
        } else {
            self.add_edge(branch_block, join_block, EdgeType::True, condition);
            self.add_edge(branch_block, join_block, EdgeType::False, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Ruby `while` / `until` loops.
    fn process_ruby_while_until(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;
        let invert = node.kind() == "until";

        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes()).unwrap_or("").to_string()
        });

        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);
        self.add_edge(self.current_block_id, header_block, EdgeType::Unconditional, None);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(body) = node.child_by_field_name("body") {
            let bs = body.start_position().row as u32 + 1;
            let be = body.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, bs, be);
            if invert {
                // `until`: body executes while condition is FALSE.
                self.add_edge(header_block, body_block, EdgeType::False, condition);
                self.add_edge(header_block, exit_block, EdgeType::True, None);
            } else {
                self.add_edge(header_block, body_block, EdgeType::True, condition);
                self.add_edge(header_block, exit_block, EdgeType::False, None);
            }
            self.current_block_id = body_block;
            self.process_block(body, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, header_block, EdgeType::BackEdge, None);
            }
        } else {
            self.add_edge(header_block, exit_block, EdgeType::False, condition);
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process Ruby modifier-loop: `expr while cond`, `expr until cond`.
    fn process_ruby_modifier_loop(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;
        let invert = node.kind() == "until_modifier";

        let condition = node.child_by_field_name("condition").map(|n| {
            n.utf8_text(self.source.as_bytes()).unwrap_or("").to_string()
        });

        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);
        self.add_edge(self.current_block_id, header_block, EdgeType::Unconditional, None);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(body) = node.child_by_field_name("body") {
            let bs = body.start_position().row as u32 + 1;
            let be = body.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, bs, be);
            if invert {
                self.add_edge(header_block, body_block, EdgeType::False, condition);
                self.add_edge(header_block, exit_block, EdgeType::True, None);
            } else {
                self.add_edge(header_block, body_block, EdgeType::True, condition);
                self.add_edge(header_block, exit_block, EdgeType::False, None);
            }
            self.current_block_id = body_block;
            self.process_statement(body, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, header_block, EdgeType::BackEdge, None);
            }
        } else {
            self.add_edge(header_block, exit_block, EdgeType::False, condition);
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process Ruby `for var in expr; body; end`.
    fn process_ruby_for(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);
        self.add_edge(self.current_block_id, header_block, EdgeType::Unconditional, None);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(body) = node.child_by_field_name("body") {
            let bs = body.start_position().row as u32 + 1;
            let be = body.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, bs, be);
            self.add_edge(header_block, body_block, EdgeType::True, None);
            self.add_edge(header_block, exit_block, EdgeType::False, None);
            self.current_block_id = body_block;
            self.process_block(body, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, header_block, EdgeType::BackEdge, None);
            }
        } else {
            self.add_edge(header_block, exit_block, EdgeType::False, None);
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process Ruby `case ... when ... else ... end`.
    fn process_ruby_case(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let scrutinee = node.child_by_field_name("value").map(|n| {
            n.utf8_text(self.source.as_bytes()).unwrap_or("").to_string()
        });

        let branch_block = self.new_block(BlockType::Branch, start_line, start_line);
        self.add_edge(self.current_block_id, branch_block, EdgeType::Unconditional, None);
        let join_block = self.new_block(BlockType::Body, end_line, end_line);

        let mut cursor = node.walk();
        let mut arm_count = 0;
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "when" => {
                        let cs = child.start_position().row as u32 + 1;
                        let ce = child.end_position().row as u32 + 1;
                        let arm_block = self.new_block(BlockType::Body, cs, ce);
                        let edge_type = if arm_count == 0 { EdgeType::True } else { EdgeType::False };
                        self.add_edge(branch_block, arm_block, edge_type, scrutinee.clone());
                        self.current_block_id = arm_block;
                        if let Some(body) = child.child_by_field_name("body") {
                            self.process_block(body, depth + 1)?;
                        } else {
                            self.process_block(child, depth + 1)?;
                        }
                        if !self.exit_blocks.contains(&self.current_block_id)
                            && !self.loop_exit_blocks.contains(&self.current_block_id)
                        {
                            self.add_edge(self.current_block_id, join_block, EdgeType::Unconditional, None);
                        }
                        arm_count += 1;
                    }
                    "else" => {
                        let cs = child.start_position().row as u32 + 1;
                        let ce = child.end_position().row as u32 + 1;
                        let else_block = self.new_block(BlockType::Body, cs, ce);
                        self.add_edge(branch_block, else_block, EdgeType::False, None);
                        self.current_block_id = else_block;
                        self.process_block(child, depth + 1)?;
                        if !self.exit_blocks.contains(&self.current_block_id)
                            && !self.loop_exit_blocks.contains(&self.current_block_id)
                        {
                            self.add_edge(self.current_block_id, join_block, EdgeType::Unconditional, None);
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        if arm_count == 0 {
            self.add_edge(branch_block, join_block, EdgeType::Unconditional, None);
        }

        self.current_block_id = join_block;
        Ok(())
    }

    /// Process Ruby `begin ... rescue ... ensure ... end`.
    fn process_ruby_begin(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let try_block = self.new_block(BlockType::Body, start_line, start_line);
        self.add_edge(self.current_block_id, try_block, EdgeType::Unconditional, None);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        self.current_block_id = try_block;
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            // Leading body statements (before rescue/ensure/else).
            loop {
                let child = cursor.node();
                let k = child.kind();
                if matches!(k, "rescue" | "ensure" | "else") {
                    break;
                }
                if child.is_named() {
                    self.process_statement(child, depth + 1)?;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            // Fall-through edge from try body to exit.
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, exit_block, EdgeType::Unconditional, None);
            }

            let try_block_id_for_edges = try_block;
            let mut finally_block: Option<usize> = None;
            loop {
                let child = cursor.node();
                match child.kind() {
                    "rescue" => {
                        let cs = child.start_position().row as u32 + 1;
                        let ce = child.end_position().row as u32 + 1;
                        let except_block = self.new_block(BlockType::Body, cs, ce);
                        self.add_edge(
                            try_block_id_for_edges,
                            except_block,
                            EdgeType::Unconditional,
                            Some("exception".to_string()),
                        );
                        self.current_block_id = except_block;
                        if let Some(body) = child.child_by_field_name("body") {
                            self.process_block(body, depth + 1)?;
                        }
                        if !self.exit_blocks.contains(&self.current_block_id)
                            && !self.loop_exit_blocks.contains(&self.current_block_id)
                        {
                            self.add_edge(self.current_block_id, exit_block, EdgeType::Unconditional, None);
                        }
                    }
                    "else" => {
                        let cs = child.start_position().row as u32 + 1;
                        let ce = child.end_position().row as u32 + 1;
                        let else_block = self.new_block(BlockType::Body, cs, ce);
                        self.add_edge(try_block_id_for_edges, else_block, EdgeType::Unconditional, None);
                        self.current_block_id = else_block;
                        self.process_block(child, depth + 1)?;
                        if !self.exit_blocks.contains(&self.current_block_id)
                            && !self.loop_exit_blocks.contains(&self.current_block_id)
                        {
                            self.add_edge(self.current_block_id, exit_block, EdgeType::Unconditional, None);
                        }
                    }
                    "ensure" => {
                        let cs = child.start_position().row as u32 + 1;
                        let ce = child.end_position().row as u32 + 1;
                        let fin = self.new_block(BlockType::Body, cs, ce);
                        self.add_edge(exit_block, fin, EdgeType::Unconditional, None);
                        self.current_block_id = fin;
                        self.process_block(child, depth + 1)?;
                        finally_block = Some(fin);
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            if let Some(fin) = finally_block {
                let post_finally = self.new_block(BlockType::Body, end_line, end_line);
                if !self.exit_blocks.contains(&self.current_block_id)
                    && !self.loop_exit_blocks.contains(&self.current_block_id)
                {
                    self.add_edge(fin, post_finally, EdgeType::Unconditional, None);
                }
                self.current_block_id = post_finally;
                return Ok(());
            }
        }

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Process Ruby `loop do ... end` — `Kernel#loop` with `do_block`.
    /// Semantically equivalent to `while true`: only exit is via `break`.
    fn process_ruby_loop_call(&mut self, node: Node, depth: usize) -> TldrResult<()> {
        let start_line = node.start_position().row as u32 + 1;
        let end_line = node.end_position().row as u32 + 1;

        let header_block = self.new_block(BlockType::LoopHeader, start_line, start_line);
        self.add_edge(self.current_block_id, header_block, EdgeType::Unconditional, None);
        let exit_block = self.new_block(BlockType::Body, end_line, end_line);

        if let Some(do_block) = node.child_by_field_name("block") {
            let body_node = do_block.child_by_field_name("body").unwrap_or(do_block);
            let bs = body_node.start_position().row as u32 + 1;
            let be = body_node.end_position().row as u32 + 1;
            let body_block = self.new_block(BlockType::LoopBody, bs, be);
            self.add_edge(header_block, body_block, EdgeType::True, None);
            self.current_block_id = body_block;
            self.process_block(body_node, depth + 1)?;
            if !self.exit_blocks.contains(&self.current_block_id)
                && !self.loop_exit_blocks.contains(&self.current_block_id)
            {
                self.add_edge(self.current_block_id, header_block, EdgeType::BackEdge, None);
            }
        }
        // Always emit an exit-edge so the exit block is reachable
        // (mirrors `process_loop_expression` for Rust `loop { ... }`).
        self.add_edge(header_block, exit_block, EdgeType::False, None);

        self.current_block_id = exit_block;
        Ok(())
    }

    /// Finalize the CFG and compute metrics
    fn finalize(mut self) -> TldrResult<CfgInfo> {
        // Ensure we have at least an entry and exit
        if self.blocks.is_empty() {
            self.blocks.push(CfgBlock {
                id: 0,
                block_type: BlockType::Entry,
                lines: (1, 1),
                calls: Vec::new(),
            });
        }

        // If no explicit exit blocks, the last block is an exit
        if self.exit_blocks.is_empty() && !self.blocks.is_empty() {
            let last_id = self.blocks.len() - 1;
            self.exit_blocks.push(last_id);

            // Add exit block if not present
            if self.blocks[last_id].block_type != BlockType::Exit {
                let exit_block = self.new_block(
                    BlockType::Exit,
                    self.blocks[last_id].lines.1,
                    self.blocks[last_id].lines.1,
                );
                self.add_edge(last_id, exit_block, EdgeType::Unconditional, None);
                self.exit_blocks = vec![exit_block];
            }
        } else if !self.exit_blocks.is_empty() {
            // There are explicit exit blocks (from return/break/? etc.) but the
            // normal fall-through path may also need an exit. If the current block
            // isn't already an exit block, connect it to a new exit.
            let current = self.current_block_id;
            if !self.exit_blocks.contains(&current)
                && self.blocks.get(current).is_some_and(|b| {
                    b.block_type != BlockType::Exit && b.block_type != BlockType::Return
                })
            {
                let exit_block = self.new_block(
                    BlockType::Exit,
                    self.blocks[current].lines.1,
                    self.blocks[current].lines.1,
                );
                self.add_edge(current, exit_block, EdgeType::Unconditional, None);
                self.exit_blocks.push(exit_block);
            }
        }

        // Calculate cyclomatic complexity using two methods, take the max:
        // 1. Edge formula: E - N + 2P (P = connected components, usually 1)
        //    This can undercount when multiple exit nodes inflate N without
        //    proportional edges (e.g., Rust ? operator creates separate exits).
        // 2. Decision count: number of branch/loop-header nodes + 1
        //    This is McCabe's original definition and handles all cases correctly.
        let e = self.edges.len() as u32;
        let n = self.blocks.len() as u32;
        let edge_formula = if n > 0 { e.saturating_sub(n) + 2 } else { 1 };
        let decision_points = self
            .blocks
            .iter()
            .filter(|b| matches!(b.block_type, BlockType::Branch | BlockType::LoopHeader))
            .count() as u32;
        let cyclomatic = edge_formula.max(decision_points + 1);

        Ok(CfgInfo {
            function: self.function_name,
            blocks: self.blocks,
            edges: self.edges,
            entry_block: 0,
            exit_blocks: self.exit_blocks,
            cyclomatic_complexity: cyclomatic,
            nested_functions: self.nested_functions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function() {
        let source = r#"
def simple():
    x = 1
    return x
"#;
        let cfg = get_cfg_context(source, "simple", Language::Python).unwrap();
        assert_eq!(cfg.function, "simple");
        assert!(!cfg.blocks.is_empty());
        assert!(!cfg.exit_blocks.is_empty());
    }

    #[test]
    fn test_if_statement() {
        let source = r#"
def with_if(x):
    if x > 0:
        return 1
    else:
        return -1
"#;
        let cfg = get_cfg_context(source, "with_if", Language::Python).unwrap();
        assert!(cfg.cyclomatic_complexity >= 2);

        // Should have true and false edges
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(has_true);
        assert!(has_false);
    }

    #[test]
    fn test_for_loop() {
        let source = r#"
def with_loop():
    total = 0
    for i in range(10):
        total += i
    return total
"#;
        let cfg = get_cfg_context(source, "with_loop", Language::Python).unwrap();

        // Should have loop header
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop);

        // Should have back edge
        let has_back = cfg.edges.iter().any(|e| e.edge_type == EdgeType::BackEdge);
        assert!(has_back);
    }

    #[test]
    fn test_function_not_found() {
        let source = "def foo(): pass";
        let cfg = get_cfg_context(source, "nonexistent", Language::Python).unwrap();
        assert!(cfg.blocks.is_empty());
        assert_eq!(cfg.cyclomatic_complexity, 0);
    }

    #[test]
    fn test_ocaml_if_expression() {
        let source = r#"
let compute x =
  if x > 0 then
    x + 1
  else
    x - 1
"#;
        let cfg = get_cfg_context(source, "compute", Language::Ocaml).unwrap();
        // OCaml if_expression should create branch blocks with true/false edges
        assert!(
            cfg.blocks.len() > 2,
            "OCaml if should create multiple blocks: got {}",
            cfg.blocks.len()
        );
        assert!(
            cfg.cyclomatic_complexity >= 2,
            "OCaml if should increase cyclomatic complexity: got {}",
            cfg.cyclomatic_complexity
        );
    }

    #[test]
    fn test_ocaml_match_expression() {
        let source = r#"
let classify x =
  match x with
  | 0 -> "zero"
  | _ -> "other"
"#;
        let cfg = get_cfg_context(source, "classify", Language::Ocaml).unwrap();
        // match_expression should create branch blocks
        assert!(
            cfg.blocks.len() > 2,
            "OCaml match should create multiple blocks: got {}",
            cfg.blocks.len()
        );
    }

    #[test]
    fn test_ocaml_while_expression() {
        let source = r#"
let loop_while x =
  let i = ref 0 in
  while !i < x do
    i := !i + 1
  done
"#;
        let cfg = get_cfg_context(source, "loop_while", Language::Ocaml).unwrap();
        // while_expression should create loop header with back edge
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop, "OCaml while should create a loop header block");
    }

    #[test]
    fn test_ocaml_for_expression() {
        let source = r#"
let loop_for n =
  for i = 1 to n do
    print_int i
  done
"#;
        let cfg = get_cfg_context(source, "loop_for", Language::Ocaml).unwrap();
        // for_expression should create loop header with back edge
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop, "OCaml for should create a loop header block");
    }

    #[test]
    fn test_ocaml_try_expression() {
        let source = r#"
let safe_read filename =
  try
    let chan = open_in filename in
    close_in chan
  with End_of_file ->
    ()
"#;
        let cfg = get_cfg_context(source, "safe_read", Language::Ocaml).unwrap();
        // try_expression should create multiple blocks for try body and exception handler
        assert!(
            cfg.blocks.len() > 2,
            "OCaml try should create multiple blocks: got {}",
            cfg.blocks.len()
        );
    }

    #[test]
    fn test_function_calls_tracked() {
        let source = r#"
def caller():
    foo()
    bar()
    return baz()
"#;
        let cfg = get_cfg_context(source, "caller", Language::Python).unwrap();

        // Collect all calls from all blocks
        let all_calls: Vec<&String> = cfg.blocks.iter().flat_map(|b| b.calls.iter()).collect();

        assert!(all_calls.contains(&&"foo".to_string()));
        assert!(all_calls.contains(&&"bar".to_string()));
        assert!(all_calls.contains(&&"baz".to_string()));
    }

    // =========================================================================
    // C1 GAP-2 (v0.5.0 AUDIT-FIX): Python `with`-wrapped try/except must NOT
    // collapse into one CFG block.
    //
    // A bare `try:` already splits into separate try/except blocks (handled by
    // `process_try_statement`). But when the `try` is nested inside a
    // `with_statement` — `with cm(): try: x = a() except: x = b()` — the
    // `with_statement` had no CFG handler, so it fell into the catch-all `_`
    // arm: that arm stretched the CURRENT block over the WHOLE `with` range and
    // never descended into the `with` body, so the inner try/except never got
    // its own blocks. Both the try-store line and the except-store line then
    // mapped to the SAME block, making the SSA dead-store decision flag the
    // try-store as overwritten-before-use. This test pins the structural fix:
    // the try-store line and except-store line must resolve to DIFFERENT blocks.
    // =========================================================================

    /// Map a 1-indexed source line to the id of the (last) CFG block whose
    /// inclusive line range covers it — mirrors the `line_to_block` build in
    /// `find_dead_stores_dfg`.
    fn block_id_for_line(cfg: &CfgInfo, line: u32) -> Option<usize> {
        let mut found = None;
        for block in &cfg.blocks {
            if line >= block.lines.0 && line <= block.lines.1 {
                found = Some(block.id);
            }
        }
        found
    }

    #[test]
    fn test_python_with_wrapped_try_except_splits_blocks() {
        // try-store on line 4, except-store on line 6, use on line 8.
        let source = r#"
def f(hostname, arg):
    with set_environ("no_proxy", arg):
        try:
            bypass = proxy_bypass(hostname)
        except (TypeError, ValueError):
            bypass = False

    if bypass:
        return True
    return False
"#;
        let cfg = get_cfg_context(source, "f", Language::Python).unwrap();

        let try_store_block = block_id_for_line(&cfg, 5);
        let except_store_block = block_id_for_line(&cfg, 7);

        assert!(
            try_store_block.is_some(),
            "try-store line 5 must map to a CFG block; blocks={:?}",
            cfg.blocks
                .iter()
                .map(|b| (b.id, b.lines))
                .collect::<Vec<_>>()
        );
        assert!(
            except_store_block.is_some(),
            "except-store line 7 must map to a CFG block; blocks={:?}",
            cfg.blocks
                .iter()
                .map(|b| (b.id, b.lines))
                .collect::<Vec<_>>()
        );
        assert_ne!(
            try_store_block, except_store_block,
            "`with`-wrapped try/except must split into separate CFG blocks \
             (try-store line 5 and except-store line 7 collapsed into the same \
             block {:?}); blocks={:?}",
            try_store_block,
            cfg.blocks
                .iter()
                .map(|b| (b.id, b.lines))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_python_with_body_descends_for_nested_if() {
        // A plain `if` nested directly inside a `with` body must also be split
        // out (the catch-all arm previously swallowed the whole `with`).
        let source = r#"
def g(x):
    with open("f") as fh:
        if x > 0:
            y = 1
        else:
            y = 2
    return y
"#;
        let cfg = get_cfg_context(source, "g", Language::Python).unwrap();
        // then-branch line 5 and else-branch line 7 must be in different blocks.
        let then_block = block_id_for_line(&cfg, 5);
        let else_block = block_id_for_line(&cfg, 7);
        assert_ne!(
            then_block, else_block,
            "if/else nested in a `with` body must split into separate blocks; \
             blocks={:?}",
            cfg.blocks
                .iter()
                .map(|b| (b.id, b.lines))
                .collect::<Vec<_>>()
        );
    }

    // =========================================================================
    // Rust-specific CFG tests (Phase 0)
    // =========================================================================

    #[test]
    fn test_rust_match_expression() {
        let source = r#"
fn classify(x: i32) -> &'static str {
    match x {
        0 => "zero",
        1 => "one",
        2 => "two",
        _ => "other",
    }
}
"#;
        let cfg = get_cfg_context(source, "classify", Language::Rust).unwrap();
        // 4 match arms → branch + 4 arm blocks + join = at least 6 blocks
        // (plus entry block)
        assert!(
            cfg.blocks.len() >= 6,
            "Rust match with 4 arms should produce >= 6 blocks, got {}",
            cfg.blocks.len()
        );
        // Should have true/false edges from branch to arms
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(has_true, "match should have True edge to first arm");
        assert!(has_false, "match should have False edges to other arms");
    }

    #[test]
    fn test_rust_if_let_expression() {
        let source = r#"
fn maybe_inc(val: Option<i32>) -> i32 {
    if let Some(x) = val {
        x + 1
    } else {
        0
    }
}
"#;
        let cfg = get_cfg_context(source, "maybe_inc", Language::Rust).unwrap();
        // if-let with else should create branch + then + else + join blocks
        assert!(
            cfg.blocks.len() > 2,
            "Rust if-let should create multiple blocks, got {}",
            cfg.blocks.len()
        );
        assert!(
            cfg.cyclomatic_complexity >= 2,
            "Rust if-let should increase cyclomatic complexity, got {}",
            cfg.cyclomatic_complexity
        );
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(has_true, "if-let should have True edge");
        assert!(has_false, "if-let should have False edge");
    }

    #[test]
    fn test_rust_while_let_expression() {
        let source = r#"
fn drain_sum(items: &mut Vec<Option<i32>>) -> i32 {
    let mut sum = 0;
    while let Some(Some(x)) = items.pop() {
        sum += x;
    }
    sum
}
"#;
        let cfg = get_cfg_context(source, "drain_sum", Language::Rust).unwrap();
        // while-let should create loop header with back edge
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop, "Rust while-let should create a loop header block");
        let has_back = cfg.edges.iter().any(|e| e.edge_type == EdgeType::BackEdge);
        assert!(has_back, "Rust while-let should have a back edge");
    }

    #[test]
    fn test_rust_loop_expression() {
        let source = r#"
fn count_up() -> i32 {
    let mut i = 0;
    loop {
        i += 1;
        if i > 10 {
            break;
        }
    }
    i
}
"#;
        let cfg = get_cfg_context(source, "count_up", Language::Rust).unwrap();
        // loop {} should create a loop header with a back edge
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop, "Rust loop should create a loop header block");
        let has_back = cfg.edges.iter().any(|e| e.edge_type == EdgeType::BackEdge);
        assert!(has_back, "Rust loop should have a back edge");
    }

    /// Rust `?` operator (try_expression) should create a branch in the CFG:
    /// success → continue, error → early return.
    #[test]
    fn test_rust_try_expression() {
        let source = r#"
fn parse_add(a: &str, b: &str) -> Result<i32, std::num::ParseIntError> {
    let x = a.parse::<i32>()?;
    let y = b.parse::<i32>()?;
    Ok(x + y)
}
"#;
        let cfg = get_cfg_context(source, "parse_add", Language::Rust).unwrap();
        // Each ? creates a branch (ok → continue, err → return)
        // With 2 ? operators we should have at least 2 additional branch points
        assert!(
            cfg.cyclomatic_complexity >= 3,
            "Two ? operators should give complexity >= 3, got {}",
            cfg.cyclomatic_complexity
        );
        // Should have true/false edges from the ? branches
        let true_edges = cfg
            .edges
            .iter()
            .filter(|e| e.edge_type == EdgeType::True)
            .count();
        assert!(
            true_edges >= 2,
            "Two ? operators should produce >= 2 True edges, got {}",
            true_edges
        );
    }

    /// Rust ? operator in a chain: `foo()?.bar()?` should create 2 branches
    #[test]
    fn test_rust_try_expression_chained() {
        let source = r#"
fn chained(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let val = s.parse::<i32>()?.to_string();
    Ok(val)
}
"#;
        let cfg = get_cfg_context(source, "chained", Language::Rust).unwrap();
        assert!(
            cfg.cyclomatic_complexity >= 2,
            "Chained ? should give complexity >= 2, got {}",
            cfg.cyclomatic_complexity
        );
    }

    /// Rust if-let should extract let_condition as the condition text
    #[test]
    fn test_rust_if_let_condition_extraction() {
        let source = r#"
fn check(val: Option<i32>) -> i32 {
    if let Some(x) = val {
        x + 1
    } else {
        0
    }
}
"#;
        let cfg = get_cfg_context(source, "check", Language::Rust).unwrap();
        // Verify branch block has condition info from the let_condition
        let branch_edges_with_condition: Vec<_> =
            cfg.edges.iter().filter(|e| e.condition.is_some()).collect();
        assert!(
            !branch_edges_with_condition.is_empty(),
            "if-let should have edges with condition info, edges: {:?}",
            cfg.edges
        );
    }

    /// Match with nested control flow inside arms should track inner blocks
    #[test]
    fn test_rust_match_with_nested_control_flow() {
        let source = r#"
fn nested_match(x: i32) -> i32 {
    match x {
        0 => {
            if x == 0 {
                return 42;
            }
            0
        }
        _ => x,
    }
}
"#;
        let cfg = get_cfg_context(source, "nested_match", Language::Rust).unwrap();
        // match (1 branch) + if inside arm (1 branch) = complexity >= 3
        assert!(
            cfg.cyclomatic_complexity >= 3,
            "match with nested if should have complexity >= 3, got {}",
            cfg.cyclomatic_complexity
        );
        // Should have return block from the inner `return 42`
        let has_return = cfg.blocks.iter().any(|b| b.block_type == BlockType::Return);
        assert!(
            has_return,
            "nested return inside match arm should create Return block"
        );
    }

    #[test]
    fn test_rust_for_expression() {
        let source = r#"
fn sum_items(items: &[i32]) -> i32 {
    let mut sum = 0;
    for x in items {
        sum += x;
    }
    sum
}
"#;
        let cfg = get_cfg_context(source, "sum_items", Language::Rust).unwrap();
        // for-in should create loop header with back edge
        let has_loop = cfg
            .blocks
            .iter()
            .any(|b| b.block_type == BlockType::LoopHeader);
        assert!(has_loop, "Rust for should create a loop header block");
        let has_back = cfg.edges.iter().any(|e| e.edge_type == EdgeType::BackEdge);
        assert!(has_back, "Rust for should have a back edge");
    }

    // -- RC1-A-cfg-branch (v0.5.0 RC-CAMPAIGN) --------------------------------
    //
    // Branch-arm completion for two distinct symptom variants that both left
    // arm bodies in NO basic block (refs vanished -> false dead-stores):
    //   * Scala `match` — arms are `case_clause` (the match-arm recognizer in
    //     `process_match_expression` only knew Rust `match_arm` / OCaml
    //     `match_case`).
    //   * Lua `if/elseif/elseif/else` — each elseif and the trailing else is a
    //     SEPARATE `[alternative]` field child; `process_if_statement` read
    //     only the FIRST one, dropping the rest.
    // The generalization gate requires BOTH variants to be covered here, and
    // the per-language Elixir/Swift handlers to stay structurally unchanged.

    /// Helper: is `line` covered by the line range of some basic block?
    fn line_covered(cfg: &CfgInfo, line: u32) -> bool {
        cfg.blocks
            .iter()
            .any(|b| b.lines.0 <= line && line <= b.lines.1)
    }

    #[test]
    fn test_scala_match_arms_get_cfg_blocks() {
        // Scala `match` arms are `case_clause` children of a `case_block`
        // (the `body` field of `match_expression`). Reproduced on scala-zio
        // BuildHelper.extraOptions (arms 134-164 fell in no CFG block;
        // `explain` reported num_blocks:4 = entry/branch/join/exit only).
        let source = r#"
object M {
  def classify(x: Int): String =
    x match {
      case 0 =>
        "zero"
      case 1 =>
        "one"
      case _ =>
        "other"
    }
}
"#;
        let cfg = get_cfg_context(source, "classify", Language::Scala).unwrap();
        // branch + 3 arm blocks + join (+ entry/exit) => >= 6 blocks.
        assert!(
            cfg.blocks.len() >= 6,
            "Scala match with 3 arms should produce >= 6 blocks, got {}",
            cfg.blocks.len()
        );
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(has_true, "Scala match should have a True edge to the first arm");
        assert!(has_false, "Scala match should have False edges to other arms");
        // Every arm BODY line must fall in a basic block (no vanished refs).
        for body_line in [6u32, 8, 10] {
            assert!(
                line_covered(&cfg, body_line),
                "Scala match arm body line {} must fall in a CFG block",
                body_line
            );
        }
    }

    #[test]
    fn test_lua_elseif_arms_get_cfg_blocks() {
        // Lua `if/elseif/elseif/else`: each elseif and the else is a separate
        // `[alternative]` child. Reproduced on lua-lsp setTraceLevel and on a
        // minimal repro where `tldr slice` on the 2nd elseif body returned an
        // empty slice (line_count:0 -> body in no block).
        let source = r#"
local function classify(x)
  local r = 0
  if x == 0 then
    r = 1
  elseif x == 1 then
    r = 2
  elseif x == 2 then
    r = 3
  else
    r = 4
  end
  return r
end
"#;
        let cfg = get_cfg_context(source, "classify", Language::Lua).unwrap();
        // then=5, elseif1 body=7, elseif2 body=9, else body=11 — ALL must be
        // covered (pre-fix only then=5 and elseif1 body=7 were).
        for body_line in [5u32, 7, 9, 11] {
            assert!(
                line_covered(&cfg, body_line),
                "Lua if/elseif arm body line {} must fall in a CFG block",
                body_line
            );
        }
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(has_true, "Lua if should have a True edge");
        assert!(has_false, "Lua if/elseif should have False edges to each arm");
        // then + 2 elseif + else => 4 arm blocks, with branch/join/entry/exit.
        assert!(
            cfg.blocks.len() >= 7,
            "Lua if/elseif/elseif/else should produce >= 7 blocks, got {}",
            cfg.blocks.len()
        );
    }

    #[test]
    fn test_elixir_case_cfg_unchanged_reconcile() {
        // Reconciliation guard: Elixir `case` is lowered by its OWN handler
        // (process_elixir_case via the `call` dispatch), NOT by
        // process_match_expression. Adding Scala `case_clause` to the
        // match-arm recognizer must not perturb it (baseline: 7 blocks).
        let source = r#"
defmodule M do
  def classify(x) do
    case x do
      0 -> "zero"
      1 -> "one"
      _ -> "other"
    end
  end
end
"#;
        let cfg = get_cfg_context(source, "classify", Language::Elixir).unwrap();
        assert!(
            cfg.blocks
                .iter()
                .any(|b| b.block_type == BlockType::Branch),
            "Elixir case should still produce a Branch block"
        );
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(
            has_true && has_false,
            "Elixir case should still have True/False arm edges"
        );
        assert!(
            cfg.blocks.len() >= 6,
            "Elixir case (3 arms) should stay a full branching CFG (>= 6 blocks), got {}",
            cfg.blocks.len()
        );
    }

    #[test]
    fn test_swift_switch_cfg_unchanged_reconcile() {
        // Reconciliation guard: Swift `switch` is lowered by process_swift_switch
        // (gated on Language::Swift for `switch_statement`), NOT by
        // process_match_expression. The branch recognizer change must not
        // perturb it (baseline: 7 blocks).
        let source = r#"
func classify(_ x: Int) -> String {
    switch x {
    case 0:
        return "zero"
    case 1:
        return "one"
    default:
        return "other"
    }
}
"#;
        let cfg = get_cfg_context(source, "classify", Language::Swift).unwrap();
        assert!(
            cfg.blocks
                .iter()
                .any(|b| b.block_type == BlockType::Branch),
            "Swift switch should still produce a Branch block"
        );
        let has_true = cfg.edges.iter().any(|e| e.edge_type == EdgeType::True);
        let has_false = cfg.edges.iter().any(|e| e.edge_type == EdgeType::False);
        assert!(
            has_true && has_false,
            "Swift switch should still have True/False arm edges"
        );
        assert!(
            cfg.blocks.len() >= 6,
            "Swift switch (3 arms) should stay a full branching CFG (>= 6 blocks), got {}",
            cfg.blocks.len()
        );
    }
}
