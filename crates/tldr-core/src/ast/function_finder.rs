//! Shared function finder utilities for locating functions in tree-sitter ASTs.
//!
//! This module provides the canonical implementations of function-finding logic
//! used across CFG, DFG, metrics, and quality modules. All languages supported
//! by tree-sitter grammars are handled here.

use crate::types::Language;
use tree_sitter::Node;

/// Helper to recursively search for function_definition inside a node (e.g., wrapped in function_call).
/// Searches up to `max_depth` levels deep to handle patterns like `socket.protect(function() end)`.
fn find_function_in_node<'a>(node: Node<'a>, max_depth: usize) -> Option<Node<'a>> {
    if max_depth == 0 {
        return None;
    }

    // Direct function_definition
    if node.kind() == "function_definition" {
        return Some(node);
    }

    // Recurse into children (especially for function_call -> arguments -> function_definition)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(func) = find_function_in_node(child, max_depth - 1) {
            return Some(func);
        }
    }

    None
}

/// Find a function node by name in the AST.
///
/// Accepts either a bare function name (`run`) or a qualified
/// `Class.method` form (`Flask.run`). When a qualified name is supplied:
///
/// 1. The class is located first via [`find_class_node`].
/// 2. The method is searched within the class body.
/// 3. If the class is not found, the search falls back to the bare
///    method name (the segment after the final `.`). This preserves
///    backward compatibility when the user passes a dotted name that
///    does not actually correspond to a class scope (for example, the
///    Lua/Luau dot-indexed pattern `M.request` is handled directly by
///    the bare-name branch via the existing `dot_index_expression`
///    matching below).
///
/// For overloaded methods (rare in Python but common in Java, C++,
/// Kotlin, and Scala), the FIRST match wins. To disambiguate, callers
/// should resolve ambiguity by line range or signature at a higher
/// level — this function does not attempt overload resolution.
pub fn find_function_node<'a>(
    root: Node<'a>,
    function_name: &str,
    language: Language,
    source: &str,
) -> Option<Node<'a>> {
    // Qualified `Class.method` lookup — try class-scoped resolution first.
    // We deliberately skip this for Lua/Luau because their dot-indexed
    // function form (`function Kong.init() ... end`) is matched directly
    // by the bare-name branch below using `dot_index_expression`, and
    // there is no class node to descend into.
    if function_name.contains('.') && !matches!(language, Language::Lua | Language::Luau) {
        let parts: Vec<&str> = function_name.split('.').collect();
        // Multi-component: at least one class segment + final method name.
        // Take the FIRST segment as the class to scope into; the LAST
        // segment is the method name to look up inside the class body.
        // This handles both `Class.method` and deeper nestings like
        // `Outer.Inner.method` (we descend into the leftmost class and
        // recursively re-resolve `Inner.method` inside it).
        if parts.len() >= 2 {
            let class_name = parts[0];
            let remainder = parts[1..].join(".");
            if let Some(class_node) = find_class_node(root, class_name, language, source) {
                // Search inside the class body (or the class node itself if
                // the body field isn't present for this language).
                let scope = class_node
                    .child_by_field_name("body")
                    .unwrap_or(class_node);
                if let Some(found) =
                    find_function_node_in_subtree(scope, &remainder, language, source)
                {
                    return Some(found);
                }
            }
            // Fallback: class not found, or method not found inside class —
            // try resolving the LAST component as a bare name. This is the
            // documented graceful degradation behavior.
            let last = *parts.last().unwrap();
            return find_function_node_in_subtree(root, last, language, source);
        }
    }

    // context-file-func-cross-lang-and-cpp-qualified-v1 (P14.AGG14-3):
    // Accept C++ `Class::method` qualified names so that the 8 per-function
    // commands (`reaching-defs`, `available`, `dead-stores`, `slice`,
    // `taint`, `complexity`, `contracts`, `explain`) can resolve a function
    // by its fully-qualified out-of-class definition. The C++ extractor
    // stores the bare last segment (`Parse`) for both inline class methods
    // and out-of-class definitions, so first try a direct match on the
    // qualified form (in case the extractor returned a qualified name —
    // see `find_function_node_in_subtree` C/C++ branch below), then
    // descend into the class scope (covers inline definitions inside the
    // class body), and finally fall back to the bare last segment so a
    // call like `XMLDocument::Parse` still resolves to the out-of-class
    // `void XMLDocument::Parse(...)` definition.
    //
    // rust-per-fn-qualified-name-v1 (v0.4.2 cluster M-013): extend the
    // same `::`-qualified-name handling to Rust so the 9 per-function
    // commands (`reaching-defs`, `available`, `dead-stores`, `slice`,
    // `taint`, `resources`, `complexity`, `explain`, `references`)
    // accept `Type::method` and `mod::Type::method` forms. Call-graph
    // commands like `tldr impact Type::method` already accept this via
    // `analysis::impact::names_match`; this closes the asymmetry at the
    // per-function dispatcher entry. For Rust we resolve the class
    // scope to the LAST TWO segments (`Type::method`), which handles
    // both `Type::method` (1 segment of qualifier) and module-prefixed
    // `mod::Type::method` shapes. `find_class_node` for Rust descends
    // into `impl_item` nodes whose type_identifier matches.
    if function_name.contains("::")
        && matches!(language, Language::C | Language::Cpp | Language::Rust)
    {
        // Try the full qualified form first — handles the (rare) case
        // where the extractor returned the qualified text verbatim.
        if let Some(found) = find_function_node_in_subtree(root, function_name, language, source)
        {
            return Some(found);
        }

        // p19-secondary-fixes-v1 (BUG-P19-04): cpp `XMLClass::ParseDeep`
        // overloads were previously all routed to the first `ParseDeep`
        // function in the file (XMLNode's). For out-of-class
        // definitions like `char* XMLText::ParseDeep(...)` the
        // declarator is a `qualified_identifier` whose full text is
        // `XMLText::ParseDeep`. Walk the file's `function_definition`
        // nodes and match by full qualified-identifier text BEFORE
        // falling back to the bare-name search. This disambiguates the
        // 7 ParseDeep overloads in tinyxml2.cpp. (C/C++ only — Rust
        // grammars expose method names as plain `identifier` children
        // of `function_item` nested inside the `impl_item` body, not as
        // qualified declarators.)
        if matches!(language, Language::C | Language::Cpp) {
            if let Some(found) =
                find_cpp_qualified_function_definition(root, function_name, source)
            {
                return Some(found);
            }
        }

        let parts: Vec<&str> = function_name.split("::").collect();
        if parts.len() >= 2 {
            // Class scope resolution.
            //
            // For C/C++ we keep the legacy behavior: the LEFTMOST
            // segment is the class (covers `XMLDocument::Parse`; deeper
            // shapes like `outer_ns::Inner::method` are unusual in C++).
            //
            // For Rust we pick the LAST TWO segments as `Type::method`
            // so module prefixes (`mod::Type::method`) are stripped.
            // This matches what users expect when copy/pasting a
            // qualified name from rust-analyzer / cargo docs and
            // mirrors how `analysis::impact::names_match` handles the
            // case in the call-graph layer (it accepts a candidate
            // whose qualifier ends-with the user-typed qualifier).
            let n = parts.len();
            let (class_name, remainder) = if matches!(language, Language::Rust) {
                (parts[n - 2], parts[n - 1].to_string())
            } else {
                (parts[0], parts[1..].join("::"))
            };
            if let Some(class_node) = find_class_node(root, class_name, language, source) {
                let scope = class_node
                    .child_by_field_name("body")
                    .unwrap_or(class_node);
                if let Some(found) =
                    find_function_node_in_subtree(scope, &remainder, language, source)
                {
                    return Some(found);
                }
            }
            // Graceful fallback: bare last segment (e.g. `Parse`).
            // This is what tinyxml2.cpp's out-of-class definitions are
            // stored as in the AST — `void XMLDocument::Parse() {...}`
            // appears as `function_definition` with declarator
            // `qualified_identifier`, and our extractor returns the
            // rightmost identifier (`Parse`) for both lookup and storage.
            // For Rust this also covers the case where the named
            // `impl Type` block could not be located (e.g. trait default
            // methods, generic impls whose type_identifier is shaped
            // differently).
            let last = *parts.last().unwrap();
            return find_function_node_in_subtree(root, last, language, source);
        }
    }

    find_function_node_in_subtree(root, function_name, language, source)
}

/// p19-secondary-fixes-v1 (BUG-P19-04): find a C/C++ `function_definition`
/// whose `declarator` carries the exact qualified name `Class::method`
/// (e.g. `XMLText::ParseDeep`). The 7 `ParseDeep` overloads in
/// tinyxml2.cpp all share the same bare name, so the bare-name search
/// can only return the first; this resolver matches the full qualified
/// text to disambiguate.
fn find_cpp_qualified_function_definition<'a>(
    root: Node<'a>,
    qualified_name: &str,
    source: &str,
) -> Option<Node<'a>> {
    // cpp-python-ast-issues-v1 (v0.4.2 M-106) — Issue #47.
    //
    // Pre-order DFS traversal so the FIRST matching definition in SOURCE
    // order is returned. The previous implementation used BFS
    // (`VecDeque::push_back` + `pop_front`), which returned the
    // SHALLOWEST match in AST order rather than the first source-order
    // match. When `Foo::bar` is defined deep inside `namespace outer {
    // namespace inner { ... } }` BEFORE a sibling top-level
    // `int Foo::bar()` later in the file, BFS returned the later
    // (shallower) definition, mis-routing slice / complexity / explain /
    // contracts / taint downstream.
    //
    // The fix uses an explicit stack with `Vec::push` / `Vec::pop` and
    // pushes children in REVERSE order so the FIRST child is popped
    // next (yielding pre-order traversal). This mirrors the sibling
    // helper `find_function_node_in_subtree` immediately below in this
    // file, which uses the same idiom.
    let mut stack: Vec<Node> = Vec::new();
    stack.push(root);
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(inner) = peel_to_function_declarator(declarator) {
                    if let Some(decl_name) = inner.child_by_field_name("declarator") {
                        if decl_name.kind() == "qualified_identifier" {
                            let text = decl_name
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .trim();
                            if text == qualified_name {
                                return Some(node);
                            }
                        }
                    }
                }
            }
        }
        // Push children in REVERSE so the first child is popped next —
        // gives pre-order DFS, which visits nodes in source order.
        let mut children: Vec<Node> = Vec::new();
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                children.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Peel through pointer / reference / parenthesized declarator wrappers
/// to expose the inner `function_declarator`. Returns None if no
/// `function_declarator` is reachable.
fn peel_to_function_declarator(node: Node) -> Option<Node> {
    match node.kind() {
        "function_declarator" => Some(node),
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            peel_to_function_declarator(inner)
        }
        _ => None,
    }
}

/// Internal: original bare-name function lookup. Splitting this out lets
/// `find_function_node` first try `Class.method` resolution and then
/// delegate the per-name search either to the full AST (bare-name) or
/// to a class body subtree (qualified).
fn find_function_node_in_subtree<'a>(
    root: Node<'a>,
    function_name: &str,
    language: Language,
    source: &str,
) -> Option<Node<'a>> {
    let func_kinds = get_function_node_kinds(language);

    let mut stack = vec![root];

    // elixir-multiclause-and-mix-v1 (v0.4.2 bug-E1): Elixir multi-clause
    // functions begin with an optional bodyless spec head
    // (`def send_resp(conn)`) followed by 1..N body-bearing clauses
    // (`def send_resp(%Conn{state: :unset}) do … end`). Previously the
    // first def matching the name was returned — which for canonical
    // libraries (Plug.Conn, Ecto, Phoenix) is the bodyless head with
    // zero analyzable body. All body-level analyses (slice, complexity,
    // taint, contracts, reaching-defs, dead-stores, resources, explain)
    // then ran on a single-line stub. The fix: remember a bodyless head
    // as a fallback, but keep searching for the first clause that has
    // a `do_block` (a real body) — only fall back to the head if no
    // body-bearing clause exists in the file. This matches what
    // `extract` already does (it emits all clauses) and what cognitive
    // analysis does via the canonical analyzer.
    let mut elixir_bodyless_fallback: Option<Node<'a>> = None;

    while let Some(node) = stack.pop() {
        // Check direct function nodes
        if func_kinds.contains(&node.kind()) {
            if let Some(name) = get_function_name(node, language, source) {
                if name == function_name
                    || name
                        .strip_prefix('#')
                        .is_some_and(|stripped| stripped == function_name)
                    // Lua/Luau: match short name for dot-indexed functions
                    // e.g. "Kong.init" matches search for "init"
                    || (matches!(language, Language::Lua | Language::Luau)
                        && name.contains('.')
                        && name
                            .rsplit('.')
                            .next()
                            .is_some_and(|short| short == function_name))
                {
                    // elixir-multiclause-and-mix-v1: defer bodyless heads.
                    if matches!(language, Language::Elixir)
                        && !elixir_call_has_do_block(node)
                    {
                        if elixir_bodyless_fallback.is_none() {
                            elixir_bodyless_fallback = Some(node);
                        }
                        // continue searching for a body-bearing clause
                    } else {
                        return Some(node);
                    }
                }
            }
        }

        // Check for variable declarations with arrow functions (TypeScript/JavaScript pattern)
        // Pattern: const foo = () => {}  or  const foo = function() {}
        if matches!(language, Language::TypeScript | Language::JavaScript)
            && matches!(node.kind(), "lexical_declaration" | "variable_declaration")
        {
            let mut child_cursor = node.walk();
            for child in node.children(&mut child_cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let var_name = name_node.utf8_text(source.as_bytes()).unwrap_or("");
                        if var_name == function_name {
                            // Check if the value is a function
                            if let Some(value_node) = child.child_by_field_name("value") {
                                if matches!(
                                    value_node.kind(),
                                    "arrow_function"
                                        | "function"
                                        | "function_expression"
                                        | "generator_function"
                                ) {
                                    return Some(value_node);
                                }
                            }
                        }
                    }
                }
            }
        }

        // (js-extract-function-expressions-v1) JS/TS assignment-based functions:
        //   app.use = function() {}
        //   Foo.prototype.bar = function() {}
        //   handler = () => {}
        //   { foo: function() {} } / { foo: () => {} } / { foo() {} }
        if matches!(language, Language::TypeScript | Language::JavaScript) {
            // Pattern A: assignment_expression — handle directly here. Look at
            // the LHS to extract the target name and the RHS to find the
            // function-like value.
            if node.kind() == "assignment_expression" {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                if let (Some(left), Some(right)) = (left, right) {
                    let matches_name = match left.kind() {
                        "identifier" => {
                            left.utf8_text(source.as_bytes()).unwrap_or("") == function_name
                        }
                        "member_expression" => {
                            // app.use → match "use"; Foo.prototype.bar → match "bar"
                            match left.child_by_field_name("property") {
                                Some(p) => {
                                    p.utf8_text(source.as_bytes()).unwrap_or("") == function_name
                                }
                                None => false,
                            }
                        }
                        _ => false,
                    };
                    if matches_name
                        && matches!(
                            right.kind(),
                            "arrow_function"
                                | "function_expression"
                                | "function"
                                | "generator_function"
                        )
                    {
                        return Some(right);
                    }
                }
            }

            // Pattern B: object literal pair — `{ foo: function() {} }`
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_name = match key.kind() {
                        "property_identifier" | "identifier" => {
                            key.utf8_text(source.as_bytes()).unwrap_or("").to_string()
                        }
                        "string" => key
                            .utf8_text(source.as_bytes())
                            .unwrap_or("")
                            .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                            .to_string(),
                        _ => String::new(),
                    };
                    if key_name == function_name
                        && matches!(
                            value.kind(),
                            "arrow_function"
                                | "function_expression"
                                | "function"
                                | "generator_function"
                        )
                    {
                        return Some(value);
                    }
                }
            }

            // Pattern C: object literal method shorthand — `{ foo() {} }`.
            // tree-sitter emits `method_definition` even outside class bodies;
            // it's handled by the generic kind-match above only when
            // method_definition is in `func_kinds`. JS/TS already includes it,
            // so the existing match covers this case.
        }

        // Check for Lua/Luau assignment-based functions: M.request = function() end
        if matches!(language, Language::Lua | Language::Luau)
            && matches!(node.kind(), "assignment_statement" | "variable_assignment")
        {
            let mut child_cursor = node.walk();
            let children: Vec<_> = node.children(&mut child_cursor).collect();
            // Look for field_expression or dot_index_expression on LHS, function on RHS
            for child in &children {
                if matches!(child.kind(), "variable_list" | "assignment_variable_list") {
                    let mut inner_cursor = child.walk();
                    for inner in child.children(&mut inner_cursor) {
                        if matches!(inner.kind(), "field_expression" | "dot_index_expression") {
                            let lhs_text = inner.utf8_text(source.as_bytes()).unwrap_or("");
                            // Check if the field name matches (e.g. "M.request" -> "request")
                            if let Some(field_name) = lhs_text.rsplit('.').next() {
                                if field_name == function_name || lhs_text == function_name {
                                    // Find function_definition in RHS (handles both direct and wrapped)
                                    for rhs in &children {
                                        if matches!(
                                            rhs.kind(),
                                            "expression_list" | "assignment_expression_list"
                                        ) {
                                            let mut rhs_cursor = rhs.walk();
                                            for rhs_child in rhs.children(&mut rhs_cursor) {
                                                if let Some(func) =
                                                    find_function_in_node(rhs_child, 3)
                                                {
                                                    return Some(func);
                                                }
                                            }
                                        }
                                        if let Some(func) = find_function_in_node(*rhs, 3) {
                                            return Some(func);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Add children to stack (reverse order for depth-first)
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }

    // elixir-multiclause-and-mix-v1: if we only saw bodyless heads
    // (e.g. a behaviour/protocol with a `@spec`-only declaration),
    // return the head so callers don't fail with "function not found"
    // — they'll still see a degraded but truthful single-line stub.
    if matches!(language, Language::Elixir) {
        if let Some(head) = elixir_bodyless_fallback {
            return Some(head);
        }
    }

    None
}

/// rust-per-fn-qualified-name-v1 (v0.4.2 cluster M-013): Produce the
/// fallback bare-name to try when a user-supplied qualified function
/// name fails to resolve at a per-function-command dispatcher that
/// implements its OWN function lookup (and therefore cannot share
/// [`find_function_node`]'s class-scope resolver directly).
///
/// Returns `None` when the input is already bare or when `language`
/// does not use the `::` qualifier for method paths. Returns
/// `Some(bare)` for the rightmost segment after `::` otherwise.
///
/// Concretely:
/// - `("ParserPool::parse", Rust)` -> `Some("parse")`
/// - `("mod::ParserPool::parse", Rust)` -> `Some("parse")`
/// - `("parse", Rust)` -> `None`
/// - `("ParserPool.parse", Rust)` -> `None`  (dot form already handled
///   by the per-language class-scope branch in `find_function_node`)
/// - `("Foo::bar", Python)` -> `None`  (not the canonical qualifier)
///
/// Callers should attempt the user-typed qualified name FIRST and only
/// fall back to this bare-name when the qualified lookup yields `None`.
/// This mirrors how `analysis::impact::names_match` accepts both
/// directions of qualification at the call-graph layer.
pub fn qualified_name_fallback_bare(function_name: &str, language: Language) -> Option<String> {
    // `::` is the canonical method-path separator in Rust, C and C++.
    // We deliberately do NOT include Python/JS/etc — those use `.` and
    // their dispatchers route through `find_function_node` which
    // already handles dot-qualified names via `find_class_node`.
    if !matches!(language, Language::Rust | Language::C | Language::Cpp) {
        return None;
    }
    if !function_name.contains("::") {
        return None;
    }
    function_name.rsplit("::").next().map(str::to_string)
}

/// m117-deferred-decisions-v1 (v0.4.2 M-118, D8): `--qualified` opt-in
/// pre-canonicaliser for per-function commands.
///
/// When a CLI command exposes the `--qualified` opt-in flag and the
/// user sets it, route the user-supplied function name through this
/// helper BEFORE doing the AST lookup. The helper:
///
/// 1. Returns the input unchanged when `qualified` is false (default).
/// 2. Returns the input unchanged when the language does not use the
///    `::` qualifier or the input is already bare (i.e., when
///    [`qualified_name_fallback_bare`] would return `None`).
/// 3. Otherwise returns the bare rightmost segment, which mirrors
///    what M-013 wired into `impact`/`whatbreaks` via
///    `analysis::impact::names_match`.
///
/// The default-off design preserves the existing strict-qualified
/// behaviour of the per-function dispatchers (the canonical
/// [`find_function_node`] still tries the qualified form first via
/// its `Class::method` branch); the flag only opts the caller INTO
/// the bare-name fallback when they know the input is qualified and
/// want to short-circuit any ambiguity.
pub fn resolve_qualified_function_name(
    function_name: &str,
    language: Language,
    qualified: bool,
) -> String {
    if !qualified {
        return function_name.to_string();
    }
    qualified_name_fallback_bare(function_name, language)
        .unwrap_or_else(|| function_name.to_string())
}

/// halstead-per-function-v1 (v0.4.2 cluster M-026): Find a function node
/// by BOTH name AND start line.
///
/// `find_function_node` returns the first function matching `name`, which
/// is correct for unique-name lookups but **wrong** when iterating over
/// per-function metrics where overloads or multi-clause definitions
/// share a name (Kotlin operator overloads `plus`/`minus`, Elixir
/// multi-clause `send_resp`, C++ `Foo::Parse` overloads, etc.). Reusing
/// the same first-matching node for every row causes the broadcast bug:
/// all rows emit identical metrics.
///
/// This helper walks the AST and returns the function node whose
/// 1-based start line equals `target_line` AND whose extracted name
/// (via [`get_function_name`]) equals `function_name`. Both must match so
/// that overlapping bodies (e.g. nested closures starting on the same
/// line) don't capture a wrong sibling.
///
/// For Lua/Luau dot-indexed assignments (`function M.foo()` or `M.foo =
/// function() end`), the extractor stores the bare last segment (`foo`)
/// as the function name. We match the short form too.
///
/// Returns `None` if no function matches both name and line. Callers
/// should fall back to [`find_function_node`] when this returns `None`.
pub fn find_function_node_by_name_and_line<'a>(
    root: Node<'a>,
    function_name: &str,
    target_line: u32,
    language: Language,
    source: &str,
) -> Option<Node<'a>> {
    let func_kinds = get_function_node_kinds(language);
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if func_kinds.contains(&node.kind()) {
            let node_line = node.start_position().row as u32 + 1;
            if node_line == target_line {
                if let Some(name) = get_function_name(node, language, source) {
                    let stripped = name.strip_prefix('#').unwrap_or(&name);
                    let short = name.rsplit('.').next().unwrap_or(&name);
                    if stripped == function_name
                        || name == function_name
                        || short == function_name
                    {
                        return Some(node);
                    }
                }
            }
        }

        // halstead-per-function-v1: also walk JS/TS variable/assignment
        // patterns (arrow functions, assigned function expressions) and
        // Lua/Luau dot-indexed assignments. The inner function body's
        // start line is what `extract_file` records, so we descend and
        // check the *body* node's start line.
        if matches!(language, Language::TypeScript | Language::JavaScript)
            && matches!(
                node.kind(),
                "lexical_declaration"
                    | "variable_declaration"
                    | "assignment_expression"
                    | "pair"
            )
        {
            let mut cur = node.walk();
            for child in node.children(&mut cur) {
                stack.push(child);
            }
            continue;
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }

    None
}

/// elixir-multiclause-and-mix-v1: return true if an Elixir `def`/`defp`
/// call node has a `do_block` child — i.e. has a real body. Bodyless
/// heads like `def send_resp(conn)` (used to attach `@spec` typespecs)
/// return false.
fn elixir_call_has_do_block(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "do_block" {
            return true;
        }
    }
    false
}

/// elixir-per-clause-dfg-cfg-v1 (v0.4.2 cluster M-031): metadata about a
/// single Elixir `def NAME/ARITY` clause discovered in the AST.
///
/// Multi-clause `def` definitions are routinely used in canonical Elixir
/// libraries (Plug, Ecto, Phoenix). For example,
/// `Plug.Conn.send_resp` has 5 clauses across 2 arities. Per-function
/// DFG/CFG/metrics commands need to surface every clause separately —
/// not just the first body-bearing one — so that the 9 DFG/CFG commands
/// (`reaching-defs`, `available`, `dead-stores`, `slice`, `taint`,
/// `resources`, `complexity`, `explain`, `references`) emit distinct
/// per-clause analysis instead of collapsing to clause-1.
#[derive(Debug, Clone)]
pub struct ElixirDefClause {
    /// 1-based start line of the `def NAME(...)` call node.
    pub start_line: u32,
    /// 1-based end line of the clause (inclusive). Tracks the full
    /// `def ... do ... end` span; for bodyless heads it tracks the
    /// signature line only.
    pub end_line: u32,
    /// Arity of this clause (number of argument patterns). A
    /// bodyless head like `def send_resp(conn)` has arity 1; the
    /// 3-arg clause `def send_resp(%Conn{}, status, body)` has
    /// arity 3.
    pub arity: usize,
    /// True if this clause has a `do_block` (a real body). Bodyless
    /// heads return false and are typically used to attach `@spec`
    /// typespecs.
    pub has_body: bool,
}

/// elixir-per-clause-dfg-cfg-v1 (v0.4.2 cluster M-031): iterate over
/// every Elixir `def`/`defp` clause matching `function_name` and return
/// a vector of [`ElixirDefClause`] descriptors keyed by `(start_line,
/// arity)`.
///
/// This is the multi-clause counterpart to [`find_function_node`] which
/// returns only one node per call. It walks the whole AST (no scope
/// pruning) collecting every `def NAME(...)` clause whose extracted
/// name matches `function_name`.
///
/// Returns an empty vector for non-Elixir trees or if no clause
/// matches. Bodyless heads (`def send_resp(conn)`) are included with
/// `has_body=false` so callers can distinguish them and decide whether
/// to skip body-level analysis.
///
/// The result is sorted by `start_line` ascending so callers can emit
/// stable per-clause output.
pub fn find_elixir_def_clauses(
    root: Node<'_>,
    function_name: &str,
    source: &str,
) -> Vec<ElixirDefClause> {
    let mut out: Vec<ElixirDefClause> = Vec::new();
    let mut stack: Vec<Node<'_>> = vec![root];

    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            if let Some(name) = get_function_name(node, Language::Elixir, source) {
                if name == function_name {
                    let start_line = node.start_position().row as u32 + 1;
                    let end_line = node.end_position().row as u32 + 1;
                    let has_body = elixir_call_has_do_block(node);
                    let arity = elixir_def_clause_arity(node, source);
                    out.push(ElixirDefClause {
                        start_line,
                        end_line,
                        arity,
                        has_body,
                    });
                }
            }
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }

    // Sort by start_line ascending for stable per-clause output.
    out.sort_by_key(|c| c.start_line);
    // De-duplicate exact (start_line, arity) tuples — the AST walk
    // can revisit the same node when nested under `defmodule` and the
    // tree-sitter grammar emits nested `call` nodes for the same def
    // surface form. Two clauses at the same line with the same arity
    // are the same logical clause.
    out.dedup_by(|a, b| a.start_line == b.start_line && a.arity == b.arity);
    out
}

/// elixir-per-clause-dfg-cfg-v1 (M-031): compute the arity of an Elixir
/// `def NAME(...)` clause by inspecting the `call` node's argument
/// structure. Returns 0 if the structure does not match a recognised
/// clause head shape.
///
/// Recognised shapes (mirrors `get_function_name`'s Elixir branch):
///   - `def func_name` (bare identifier, no args) -> arity 0
///   - `def func_name(a, b)` -> arity 2
///   - `def func_name(a) when guard` (binary_operator wrapper) -> arity 1
fn elixir_def_clause_arity(node: Node, source: &str) -> usize {
    // node is the outer `call` for `def`. Its child(1) is the args
    // wrapper which contains the inner `call` representing the function
    // clause head (with its own arguments) — possibly wrapped in a
    // `binary_operator` for guard clauses.
    let Some(args) = node.child(1) else {
        return 0;
    };

    // Drill to the inner `call` node representing the clause head.
    let inner_call = find_elixir_clause_head_call(args, source);

    match inner_call {
        Some(head) => {
            // The head's child(1) (if present) is its arguments wrapper.
            // If the clause has no args (`def func_name`) there's no
            // second child; return 0.
            let Some(head_args) = head.child(1) else {
                return 0;
            };
            count_elixir_clause_arguments(head_args)
        }
        None => {
            // `args` is a bare identifier (`def func_name`, no parens, no args).
            if args.kind() == "identifier" {
                0
            } else {
                0
            }
        }
    }
}

fn find_elixir_clause_head_call<'a>(args: Node<'a>, source: &str) -> Option<Node<'a>> {
    // Direct `call` child.
    if args.kind() == "call" {
        return Some(args);
    }
    // `arguments` wrapper containing a `call` or a `binary_operator`
    // (for guard clauses).
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "call" {
            return Some(child);
        }
        if child.kind() == "binary_operator" {
            // `when` guard: descend into LHS.
            let mut bin = child.walk();
            for bin_child in child.children(&mut bin) {
                if bin_child.kind() == "call" {
                    return Some(bin_child);
                }
            }
        }
        // Suppress unused-var warning for `source`; reserved for
        // future shape detection if grammar ever splits.
        let _ = source;
    }
    None
}

fn count_elixir_clause_arguments(head_args: Node) -> usize {
    // The head's args may be:
    //   - `arguments`: count its direct comma-separated argument children
    //   - `tuple`/other: treat as single arg
    // tree-sitter-elixir emits `arguments` with one child per pattern
    // (separated by `,` tokens which are anonymous).
    if head_args.kind() == "arguments" {
        let mut cursor = head_args.walk();
        let mut n = 0usize;
        for child in head_args.children(&mut cursor) {
            // Skip punctuation/anonymous tokens — count only named
            // (positional) argument nodes.
            if child.is_named() {
                n += 1;
            }
        }
        return n;
    }
    // Fallback: a single non-`arguments` head_args node represents one
    // pattern (e.g. `def foo(x)` where the grammar emits a single
    // identifier child rather than an `arguments` wrapper).
    1
}

/// Get the node kinds that represent functions in each language
pub fn get_function_node_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["function_definition"],
        Language::TypeScript | Language::JavaScript => &[
            "function_declaration",
            "arrow_function",
            "method_definition",
            "function",
            "generator_function_declaration",
            "generator_function",
        ],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Rust => &["function_item"],
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::C | Language::Cpp => &["function_definition"],
        Language::Ruby => &["method", "singleton_method"],
        Language::Php => &["function_definition", "method_declaration"],
        Language::CSharp => &["method_declaration", "constructor_declaration"],
        Language::Kotlin => &["function_declaration"],
        Language::Scala => &["function_definition", "function_declaration"],
        Language::Elixir => &["call"], // Elixir uses def/defp which are calls
        Language::Lua | Language::Luau => &[
            "function_declaration",
            "function_definition",
            "local_function",
        ],
        Language::Swift => &["function_declaration", "init_declaration"],
        Language::Ocaml => &["let_binding", "value_definition"],
    }
}

/// Get the node kinds that represent classes/structs/objects/traits in
/// each language. Used by [`find_class_node`] to scope qualified
/// `Class.method` lookups.
///
/// The selection is intentionally broad: anything that can act as a
/// container of methods is included (classes, structs with methods,
/// interfaces, traits, impls, enums with methods, objects, modules with
/// member functions). Languages where there is no dedicated class node
/// (C, OCaml, Elixir, Lua/Luau) return an empty slice — qualified
/// lookups for those languages will fall back to the bare-name search.
pub fn get_class_node_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["class_definition"],
        Language::TypeScript | Language::JavaScript => {
            &["class_declaration", "class", "interface_declaration"]
        }
        Language::Go => &["type_declaration"],
        Language::Rust => &[
            "struct_item",
            "enum_item",
            "trait_item",
            "impl_item",
            "union_item",
        ],
        Language::Java => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
        ],
        Language::Cpp => &[
            "class_specifier",
            "struct_specifier",
            "union_specifier",
        ],
        Language::C => &[],
        Language::Ruby => &["class", "module"],
        Language::Php => &[
            "class_declaration",
            "interface_declaration",
            "trait_declaration",
            "enum_declaration",
        ],
        Language::CSharp => &[
            "class_declaration",
            "struct_declaration",
            "interface_declaration",
            "record_declaration",
            "enum_declaration",
        ],
        Language::Kotlin => &["class_declaration", "object_declaration"],
        Language::Scala => &[
            "class_definition",
            "object_definition",
            "trait_definition",
        ],
        // No class container in these languages (Elixir uses defmodule but
        // the resolver here doesn't model it; Lua/Luau dotted names are
        // handled directly in the bare-name branch).
        Language::Elixir | Language::Lua | Language::Luau | Language::Ocaml => &[],
        Language::Swift => &[
            "class_declaration",
            "protocol_declaration",
            "extension_declaration",
        ],
    }
}

/// Find a class/struct/trait node by name in the AST.
///
/// Walks the tree depth-first and returns the FIRST node whose kind is
/// in [`get_class_node_kinds`] and whose name matches `class_name`. If
/// the language has no class node kinds (e.g. C, Lua), returns `None`
/// immediately.
pub fn find_class_node<'a>(
    root: Node<'a>,
    class_name: &str,
    language: Language,
    source: &str,
) -> Option<Node<'a>> {
    let class_kinds = get_class_node_kinds(language);
    if class_kinds.is_empty() {
        return None;
    }

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if class_kinds.contains(&node.kind()) {
            // Try the standard "name" field (Python, TS/JS, Java, Kotlin,
            // Scala, Swift, Ruby, PHP, C#).
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source.as_bytes()).unwrap_or("");
                if name == class_name {
                    return Some(node);
                }
            } else {
                // Fallback: scan named children for an identifier-shaped
                // name node (covers grammars where the name isn't
                // exposed as a field, e.g. Rust struct/enum/trait/impl
                // and C++ class/struct specifiers).
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if matches!(
                        child.kind(),
                        "identifier"
                            | "type_identifier"
                            | "constant"
                            | "scoped_type_identifier"
                    ) {
                        let name = child.utf8_text(source.as_bytes()).unwrap_or("");
                        // For Rust impl_item the type_identifier IS the
                        // class-equivalent name. For scoped names, only
                        // exact match counts.
                        if name == class_name {
                            return Some(node);
                        }
                        break;
                    }
                }
            }
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }

    None
}

/// Recursively extract the function name from a C/C++ declarator chain.
/// Handles: function_declarator, pointer_declarator, parenthesized_declarator,
/// identifier, field_identifier, qualified_identifier, destructor_name,
/// template_function.
fn extract_c_declarator_name(declarator: Node, source: &str) -> Option<String> {
    match declarator.kind() {
        "identifier" | "field_identifier" => {
            // field_identifier is used for methods defined inline in class bodies
            Some(
                declarator
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string(),
            )
        }
        "destructor_name" => {
            // ~ClassName - return as-is
            Some(
                declarator
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string(),
            )
        }
        "qualified_identifier" => {
            // C++ qualified name: Namespace::Class::method
            // Tree-sitter nests these recursively:
            //   qualified_identifier(Luau::Analysis::Normalizer::normalize)
            //     -> namespace_identifier(Luau), qualified_identifier(Analysis::...)
            //       -> ... -> identifier(normalize)
            // We need to find the deepest rightmost identifier.
            let mut cursor = declarator.walk();
            for child in declarator.children(&mut cursor) {
                // If there's a nested qualified_identifier, recurse into it
                if child.kind() == "qualified_identifier" {
                    return extract_c_declarator_name(child, source);
                }
            }
            // No nested qualified_identifier: look for terminal name nodes
            let mut cursor2 = declarator.walk();
            for child in declarator.children(&mut cursor2) {
                if matches!(child.kind(), "identifier" | "destructor_name") {
                    return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
                if child.kind() == "template_function" {
                    return child
                        .child_by_field_name("name")
                        .or_else(|| child.named_child(0))
                        .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
            }
            None
        }
        "template_function" => {
            // template<T> void foo() - extract identifier from template_function
            declarator
                .child_by_field_name("name")
                .or_else(|| declarator.named_child(0))
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        }
        "function_declarator" => {
            // function_declarator has a "declarator" field which is the name (identifier)
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return extract_c_declarator_name(inner, source);
            }
            None
        }
        "pointer_declarator" | "reference_declarator" => {
            // pointer_declarator wraps: * <inner_declarator>
            // reference_declarator wraps: & <inner_declarator>
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return extract_c_declarator_name(inner, source);
            }
            // Fallback: search children for function_declarator or identifier
            let mut cursor = declarator.walk();
            for child in declarator.children(&mut cursor) {
                if matches!(
                    child.kind(),
                    "function_declarator" | "identifier" | "field_identifier"
                ) {
                    return extract_c_declarator_name(child, source);
                }
            }
            None
        }
        "parenthesized_declarator" => {
            // parenthesized_declarator wraps: ( <inner_declarator> )
            let mut cursor = declarator.walk();
            for child in declarator.children(&mut cursor) {
                if child.is_named() {
                    if let Some(name) = extract_c_declarator_name(child, source) {
                        return Some(name);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract function name from a function node
pub fn get_function_name(node: Node, language: Language, source: &str) -> Option<String> {
    match language {
        Language::C | Language::Cpp => {
            // C/C++: function_definition -> declarator -> ... -> identifier
            // The declarator chain can be:
            //   function_declarator -> identifier (simple: int foo())
            //   pointer_declarator -> function_declarator -> identifier (pointer return: int *foo())
            //   identifier (rare, no parens)
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return extract_c_declarator_name(declarator, source);
            }
            None
        }
        Language::Ruby => {
            // Ruby: method node has "name" field
            node.child_by_field_name("name")
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        }
        Language::Php => {
            // PHP function_definition has "name" field
            node.child_by_field_name("name")
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        }
        Language::Elixir => {
            // Elixir: def/defp are calls. The first argument after "def" is the function clause.
            //
            // Structure (no guard):
            //   (call (identifier "def") (arguments (call (identifier "func_name") ...)))
            //
            // Structure (with guard):
            //   (call (identifier "def")
            //         (arguments (binary_operator
            //                        left:  (call (identifier "func_name") ...)
            //                        op:    "when"
            //                        right: (guard expr))
            //                    (do_block ...)))
            //
            // The DFG used to miss the guarded form because it only looked
            // for `call`/`identifier` immediately under `arguments`. When the
            // function clause is wrapped in a `binary_operator` for a `when`
            // guard, the function-name `call` is the left child of the
            // binary_operator, not a direct child of `arguments`.
            // (P11.BUG-AGG-16)
            if node.kind() == "call" {
                // First child should be "def" or "defp"
                let first_child = node.child(0)?;
                let first_text = first_child.utf8_text(source.as_bytes()).unwrap_or("");
                if first_text == "def" || first_text == "defp" {
                    // Second child: arguments containing the function name
                    if let Some(args) = node.child(1) {
                        // Could be directly an identifier or a call node
                        if args.kind() == "identifier" {
                            return Some(
                                args.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
                            );
                        }
                        if args.kind() == "arguments" || args.kind() == "call" {
                            // Find the first identifier or descend through
                            // `binary_operator` for guard clauses.
                            let mut cursor = args.walk();
                            for child in args.children(&mut cursor) {
                                if child.kind() == "identifier" {
                                    return Some(
                                        child
                                            .utf8_text(source.as_bytes())
                                            .unwrap_or("")
                                            .to_string(),
                                    );
                                }
                                if child.kind() == "call" {
                                    if let Some(name) = child.child(0) {
                                        if name.kind() == "identifier" {
                                            return Some(
                                                name.utf8_text(source.as_bytes())
                                                    .unwrap_or("")
                                                    .to_string(),
                                            );
                                        }
                                    }
                                }
                                // Guard clause: descend into binary_operator's
                                // left child to recover the function name.
                                if child.kind() == "binary_operator" {
                                    let mut bin_cursor = child.walk();
                                    for bin_child in child.children(&mut bin_cursor) {
                                        if bin_child.kind() == "call" {
                                            if let Some(name) = bin_child.child(0) {
                                                if name.kind() == "identifier" {
                                                    return Some(
                                                        name.utf8_text(source.as_bytes())
                                                            .unwrap_or("")
                                                            .to_string(),
                                                    );
                                                }
                                            }
                                        }
                                        if bin_child.kind() == "identifier" {
                                            // `def func_name when guard` (no args)
                                            // is rare but the LHS may be a bare
                                            // identifier.
                                            return Some(
                                                bin_child
                                                    .utf8_text(source.as_bytes())
                                                    .unwrap_or("")
                                                    .to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                None
            } else {
                None
            }
        }
        Language::Ocaml => {
            // OCaml: let_binding has "pattern" field (not "name")
            // Structure: (let_binding pattern: (value_name) body: ...)
            // For value_definition, it wraps let_binding(s)
            if node.kind() == "value_definition" {
                // Find the first let_binding child and recurse
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "let_binding" {
                        return get_function_name(child, language, source);
                    }
                }
                None
            } else {
                // let_binding: pattern field contains the name
                node.child_by_field_name("pattern")
                    .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
            }
        }
        Language::Swift => {
            // Swift: function_declaration has "name" field, but init_declaration does not --
            // the keyword "init" IS the name.
            if node.kind() == "init_declaration" {
                return Some("init".to_string());
            }
            node.child_by_field_name("name")
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        }
        Language::Lua | Language::Luau => {
            // Lua/Luau: function_declaration may have a dot_index_expression as name
            // e.g. function Kong.init() -> name is dot_index_expression "Kong.init"
            if let Some(name_node) = node.child_by_field_name("name") {
                let name_text = name_node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                return Some(name_text);
            }
            // Fallback for local_function or other variants: search named children
            // for identifier or dot_index_expression
            if node.kind() == "local_function" || node.kind() == "function_declaration" {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if matches!(child.kind(), "identifier" | "dot_index_expression") {
                        return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                    }
                }
            }
            // For function_definition (anonymous), no name
            None
        }
        _ => {
            // Most languages use "name" field
            node.child_by_field_name("name")
                .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        }
    }
}

/// Get the body node of a function
pub fn get_function_body(func_node: Node, language: Language) -> Option<Node> {
    match language {
        Language::Python => func_node.child_by_field_name("body"),
        Language::TypeScript | Language::JavaScript => func_node.child_by_field_name("body"),
        Language::Go => func_node.child_by_field_name("body"),
        Language::Rust => func_node.child_by_field_name("body"),
        Language::Java => func_node.child_by_field_name("body"),
        Language::C | Language::Cpp => func_node.child_by_field_name("body"),
        Language::Ruby => func_node.child_by_field_name("body"),
        Language::Php => func_node.child_by_field_name("body"),
        Language::CSharp => func_node.child_by_field_name("body"),
        Language::Kotlin => {
            // Kotlin: function_declaration has function_body as a named child (not a field).
            // function_body contains a block with the actual statements.
            func_node.child_by_field_name("body").or_else(|| {
                let mut cursor = func_node.walk();
                for child in func_node.children(&mut cursor) {
                    if child.kind() == "function_body" {
                        // function_body may contain a block or a direct expression
                        let mut inner = child.walk();
                        for inner_child in child.children(&mut inner) {
                            if inner_child.kind() == "block" {
                                return Some(inner_child);
                            }
                        }
                        return Some(child);
                    }
                }
                None
            })
        }
        Language::Scala => func_node.child_by_field_name("body"),
        Language::Elixir => {
            // Elixir def body is inside a "do" block
            // Structure: (call "def" (arguments ...) (do_block (body)))
            let mut cursor = func_node.walk();
            for child in func_node.children(&mut cursor) {
                if child.kind() == "do_block" {
                    return Some(child);
                }
            }
            func_node.child_by_field_name("body")
        }
        Language::Lua | Language::Luau => func_node.child_by_field_name("body"),
        Language::Ocaml => {
            // OCaml: func_node may be value_definition or let_binding.
            // For value_definition, drill down to let_binding first.
            // For let_binding, the body field contains the expression.
            if func_node.kind() == "value_definition" {
                // Find let_binding child, then get its body
                let child_count = func_node.child_count();
                let mut binding_body = None;
                for i in 0..child_count {
                    if let Some(child) = func_node.child(i) {
                        if child.kind() == "let_binding" {
                            binding_body = child.child_by_field_name("body");
                            break;
                        }
                    }
                }
                binding_body.or(Some(func_node))
            } else {
                // Already a let_binding
                func_node.child_by_field_name("body").or(Some(func_node))
            }
        }
        _ => func_node.child_by_field_name("body"),
    }
}

/// Convenience: get function node kinds as a Vec (for callers that need Vec<&'static str>)
pub fn get_function_node_kinds_vec(language: Language) -> Vec<&'static str> {
    get_function_node_kinds(language).to_vec()
}

/// Resolve the (start_line, end_line) bounds of a function in a parsed source.
///
/// Used by chop/slice to surface a meaningful range in `LineOutsideFunction`
/// errors instead of leaking the `u32::MAX` sentinel that previously rendered
/// as `lines 1-4294967295` in user-facing messages
/// (pdg-bounds-and-stdout-hygiene-v1, P11.BUG-AGG-5).
///
/// Returns:
/// - `Some((start, end))` if the function is found in the parsed tree. Both
///   line numbers are 1-indexed and inclusive of the function's first and
///   last source lines (signature through closing brace / `end` keyword).
/// - `None` if the function cannot be located. Callers MUST treat this as a
///   distinct case from "found but line is outside" — emit a clear "could not
///   determine function bounds" message rather than a fabricated range.
pub fn find_function_bounds(
    source: &str,
    function_name: &str,
    language: Language,
) -> Option<(u32, u32)> {
    let tree = crate::ast::parser::parse(source, language).ok()?;
    let root = tree.root_node();
    let node = find_function_node(root, function_name, language, source)?;
    let start = node.start_position().row as u32 + 1;
    let end = node.end_position().row as u32 + 1;
    if end < start {
        return None;
    }
    Some((start, end))
}

/// File-aware variant of [`find_function_bounds`] that accepts either a
/// path to a source file or a raw source string. Mirrors the
/// `source_or_path` convention used by `get_cfg_context`/`get_pdg_context`.
pub fn find_function_bounds_from_path_or_source(
    source_or_path: &str,
    function_name: &str,
    language: Language,
) -> Option<(u32, u32)> {
    let source = if std::path::Path::new(source_or_path).exists() {
        std::fs::read_to_string(source_or_path).ok()?
    } else {
        source_or_path.to_string()
    };
    find_function_bounds(&source, function_name, language)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::parser::parse;

    // -- TypeScript generator function tests --

    #[test]
    fn test_ts_generator_function_declaration() {
        let source = r#"
function* genNumbers(): Generator<number> {
    yield 1;
    yield 2;
    yield 3;
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "genNumbers", Language::TypeScript, source);
        assert!(node.is_some(), "Should find generator function declaration");
        let node = node.unwrap();
        assert_eq!(node.kind(), "generator_function_declaration");
        let name = get_function_name(node, Language::TypeScript, source);
        assert_eq!(name.as_deref(), Some("genNumbers"));
        let body = get_function_body(node, Language::TypeScript);
        assert!(body.is_some(), "Should find body of generator function");
    }

    #[test]
    fn test_ts_async_generator_function() {
        let source = r#"
async function* asyncGen(): AsyncGenerator<string> {
    yield "hello";
    yield "world";
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "asyncGen", Language::TypeScript, source);
        assert!(
            node.is_some(),
            "Should find async generator function declaration"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "generator_function_declaration");
        let name = get_function_name(node, Language::TypeScript, source);
        assert_eq!(name.as_deref(), Some("asyncGen"));
    }

    #[test]
    fn test_ts_generator_function_expression() {
        let source = r#"
const genArrow = function*(x: number): Generator<number> {
    yield x;
};
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "genArrow", Language::TypeScript, source);
        assert!(
            node.is_some(),
            "Should find generator function expression via const assignment"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "generator_function");
        let body = get_function_body(node, Language::TypeScript);
        assert!(
            body.is_some(),
            "Should find body of generator function expression"
        );
    }

    // -- JavaScript generator function tests --

    #[test]
    fn test_js_generator_function_declaration() {
        let source = r#"
function* genNumbers() {
    yield 1;
    yield 2;
}
"#;
        let tree = parse(source, Language::JavaScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "genNumbers", Language::JavaScript, source);
        assert!(
            node.is_some(),
            "Should find JS generator function declaration"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "generator_function_declaration");
    }

    #[test]
    fn test_js_async_generator_function() {
        let source = r#"
async function* asyncIter() {
    yield "a";
    yield "b";
}
"#;
        let tree = parse(source, Language::JavaScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "asyncIter", Language::JavaScript, source);
        assert!(node.is_some(), "Should find JS async generator function");
    }

    // -- TypeScript regular function tests (regression) --

    #[test]
    fn test_ts_regular_function() {
        let source = r#"
function greet(name: string): string {
    const greeting = "Hello, " + name;
    return greeting;
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "greet", Language::TypeScript, source);
        assert!(node.is_some(), "Should find regular function declaration");
        assert_eq!(node.unwrap().kind(), "function_declaration");
    }

    #[test]
    fn test_ts_arrow_function() {
        let source = r#"
const add = (a: number, b: number): number => {
    return a + b;
};
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "add", Language::TypeScript, source);
        assert!(node.is_some(), "Should find arrow function via const");
        assert_eq!(node.unwrap().kind(), "arrow_function");
    }

    #[test]
    fn test_ts_class_method() {
        let source = r#"
class MyClass {
    myMethod(x: number): number {
        return x * 2;
    }
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "myMethod", Language::TypeScript, source);
        assert!(node.is_some(), "Should find class method");
        assert_eq!(node.unwrap().kind(), "method_definition");
    }

    #[test]
    fn test_ts_exported_function() {
        let source = r#"
export function fetchData(url: string): Promise<string> {
    return fetch(url).then(r => r.text());
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "fetchData", Language::TypeScript, source);
        assert!(node.is_some(), "Should find exported function");
    }

    #[test]
    fn test_ts_exported_generator() {
        let source = r#"
export function* items(): Generator<number> {
    yield 1;
    yield 2;
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "items", Language::TypeScript, source);
        assert!(node.is_some(), "Should find exported generator function");
    }

    // -- DFG integration tests for generator functions --

    #[test]
    fn test_ts_generator_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
function* genNumbers(): Generator<number> {
    const x = 1;
    yield x;
    const y = 2;
    yield y;
}
"#;
        let result = get_dfg_context(source, "genNumbers", Language::TypeScript);
        assert!(
            result.is_ok(),
            "DFG should succeed for generator functions, got: {:?}",
            result.err()
        );
        let dfg = result.unwrap();
        assert_eq!(dfg.function, "genNumbers");
        assert!(
            !dfg.variables.is_empty(),
            "Should find variables in generator function"
        );
    }

    #[test]
    fn test_ts_async_generator_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
async function* asyncGen(): AsyncGenerator<string> {
    const msg = "hello";
    yield msg;
}
"#;
        let result = get_dfg_context(source, "asyncGen", Language::TypeScript);
        assert!(
            result.is_ok(),
            "DFG should succeed for async generator functions, got: {:?}",
            result.err()
        );
    }

    // -- CFG integration tests for generator functions --

    #[test]
    fn test_ts_generator_cfg() {
        use crate::cfg::get_cfg_context;
        let source = r#"
function* genNumbers(): Generator<number> {
    const x = 1;
    yield x;
}
"#;
        let result = get_cfg_context(source, "genNumbers", Language::TypeScript);
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert_eq!(cfg.function, "genNumbers");
        assert!(
            !cfg.blocks.is_empty(),
            "CFG should have blocks for generator function"
        );
    }

    // -- get_function_node_kinds tests --

    #[test]
    fn test_ts_node_kinds_include_generators() {
        let kinds = get_function_node_kinds(Language::TypeScript);
        assert!(
            kinds.contains(&"generator_function_declaration"),
            "TypeScript node kinds should include generator_function_declaration"
        );
        assert!(
            kinds.contains(&"generator_function"),
            "TypeScript node kinds should include generator_function"
        );
    }

    #[test]
    fn test_js_node_kinds_include_generators() {
        let kinds = get_function_node_kinds(Language::JavaScript);
        assert!(
            kinds.contains(&"generator_function_declaration"),
            "JavaScript node kinds should include generator_function_declaration"
        );
        assert!(
            kinds.contains(&"generator_function"),
            "JavaScript node kinds should include generator_function"
        );
    }

    // -- C pointer-returning function tests --

    #[test]
    fn test_c_pointer_returning_function() {
        let source = r#"
typedef struct { int x; } MyStruct;

MyStruct *createStruct(void) {
    int y = 1;
    return (MyStruct*)0;
}
"#;
        let tree = parse(source, Language::C).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "createStruct", Language::C, source);
        assert!(
            node.is_some(),
            "Should find C function with pointer return type"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "function_definition");
        let name = get_function_name(node, Language::C, source);
        assert_eq!(name.as_deref(), Some("createStruct"));
    }

    #[test]
    fn test_c_pointer_returning_function_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
typedef struct { int x; } MyStruct;

MyStruct *createStruct(int val) {
    int y = val + 1;
    return (MyStruct*)0;
}
"#;
        let result = get_dfg_context(source, "createStruct", Language::C);
        assert!(
            result.is_ok(),
            "DFG should succeed for C pointer-returning function, got: {:?}",
            result.err()
        );
        let dfg = result.unwrap();
        assert_eq!(dfg.function, "createStruct");
    }

    #[test]
    fn test_cpp_pointer_returning_function() {
        let source = r#"
struct Node { int val; };

Node *createNode(int x) {
    int temp = x * 2;
    return nullptr;
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "createNode", Language::Cpp, source);
        assert!(
            node.is_some(),
            "Should find C++ function with pointer return type"
        );
        let name = get_function_name(node.unwrap(), Language::Cpp, source);
        assert_eq!(name.as_deref(), Some("createNode"));
    }

    // -- Swift init_declaration tests --

    #[test]
    fn test_swift_init_declaration() {
        let source = r#"
class App {
    init(port: Int) {
        let x = port + 1
    }
}
"#;
        let tree = parse(source, Language::Swift).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "init", Language::Swift, source);
        assert!(node.is_some(), "Should find Swift init declaration");
    }

    #[test]
    fn test_swift_init_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
class Server {
    init(port: Int) {
        let addr = port + 1000
    }
}
"#;
        let result = get_dfg_context(source, "init", Language::Swift);
        assert!(
            result.is_ok(),
            "DFG should succeed for Swift init, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_swift_node_kinds_include_init() {
        let kinds = get_function_node_kinds(Language::Swift);
        assert!(
            kinds.contains(&"init_declaration"),
            "Swift node kinds should include init_declaration"
        );
    }

    // -- Lua dot-indexed function name tests --

    #[test]
    fn test_lua_dot_indexed_function_short_name() {
        let source = r#"
function Kong.init()
    local x = 1
    return x
end
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let root = tree.root_node();
        // Should find "init" when searching by short name
        let node = find_function_node(root, "init", Language::Lua, source);
        assert!(
            node.is_some(),
            "Should find Lua dot-indexed function by short name 'init'"
        );
    }

    #[test]
    fn test_lua_dot_indexed_function_full_name() {
        let source = r#"
function Kong.init()
    local x = 1
    return x
end
"#;
        let tree = parse(source, Language::Lua).unwrap();
        let root = tree.root_node();
        // Should also find by full qualified name
        let node = find_function_node(root, "Kong.init", Language::Lua, source);
        assert!(
            node.is_some(),
            "Should find Lua dot-indexed function by full name 'Kong.init'"
        );
    }

    #[test]
    fn test_lua_dot_indexed_function_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
function M.request(url)
    local result = url .. "/api"
    return result
end
"#;
        let result = get_dfg_context(source, "request", Language::Lua);
        assert!(
            result.is_ok(),
            "DFG should succeed for Lua dot-indexed function by short name, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_luau_dot_indexed_function_short_name() {
        let source = r#"
function Module.process(data)
    local x = data + 1
    return x
end
"#;
        let tree = parse(source, Language::Luau).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "process", Language::Luau, source);
        assert!(
            node.is_some(),
            "Should find Luau dot-indexed function by short name 'process'"
        );
    }

    // =========================================================================
    // C++ qualified method definition tests
    // =========================================================================

    #[test]
    fn test_cpp_qualified_method_definition() {
        // C++ method defined outside class body with ClassName::method syntax
        let source = r#"
class MyClass {
public:
    void externalMethod();
};

void MyClass::externalMethod() {
    int x = 1;
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "externalMethod", Language::Cpp, source);
        assert!(
            node.is_some(),
            "Should find C++ qualified method definition (ClassName::method)"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "function_definition");
        let name = get_function_name(node, Language::Cpp, source);
        assert_eq!(
            name.as_deref(),
            Some("externalMethod"),
            "get_function_name should extract bare name from qualified C++ method"
        );
    }

    #[test]
    fn test_cpp_qualified_method_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
void MyClass::compute(int a) {
    int b = a + 1;
    int c = b * 2;
}
"#;
        let result = get_dfg_context(source, "compute", Language::Cpp);
        assert!(
            result.is_ok(),
            "DFG should succeed for C++ qualified method, got: {:?}",
            result.err()
        );
        let dfg = result.unwrap();
        assert_eq!(dfg.function, "compute");
    }

    #[test]
    fn test_cpp_inline_class_method() {
        // C++ method defined inline inside class body
        let source = r#"
class MyClass {
public:
    void myMethod() {
        int x = 1;
    }
};
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "myMethod", Language::Cpp, source);
        assert!(
            node.is_some(),
            "Should find C++ inline class method (field_identifier)"
        );
        let node = node.unwrap();
        assert_eq!(node.kind(), "function_definition");
        let name = get_function_name(node, Language::Cpp, source);
        assert_eq!(
            name.as_deref(),
            Some("myMethod"),
            "get_function_name should extract name from inline C++ class method"
        );
    }

    #[test]
    fn test_cpp_inline_class_method_dfg() {
        use crate::dfg::get_dfg_context;
        let source = r#"
class Widget {
public:
    int calculate(int a, int b) {
        int sum = a + b;
        int product = a * b;
        return sum;
    }
};
"#;
        let result = get_dfg_context(source, "calculate", Language::Cpp);
        assert!(
            result.is_ok(),
            "DFG should succeed for C++ inline class method, got: {:?}",
            result.err()
        );
        let dfg = result.unwrap();
        assert_eq!(dfg.function, "calculate");
        assert!(
            !dfg.variables.is_empty(),
            "Should find variables in inline class method"
        );
    }

    #[test]
    fn test_cpp_namespace_function() {
        // C++ function inside a namespace
        let source = r#"
namespace Foo {
    void bar() {
        int x = 1;
    }
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "bar", Language::Cpp, source);
        assert!(node.is_some(), "Should find C++ function inside namespace");
    }

    #[test]
    fn test_cpp_const_qualified_method() {
        // C++ const method defined outside class
        let source = r#"
bool NormalizedStringType::isNever() const {
    return !isCofinite && singletons.empty();
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "isNever", Language::Cpp, source);
        assert!(node.is_some(), "Should find C++ const qualified method");
        let name = get_function_name(node.unwrap(), Language::Cpp, source);
        assert_eq!(name.as_deref(), Some("isNever"));
    }

    #[test]
    fn test_cpp_nested_namespace_qualified_method() {
        // C++ method with deeply nested namespace::class::method
        let source = r#"
void Luau::Analysis::Normalizer::normalize() {
    int x = 1;
}
"#;
        let tree = parse(source, Language::Cpp).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "normalize", Language::Cpp, source);
        assert!(node.is_some(), "Should find deeply qualified C++ method");
        let name = get_function_name(node.unwrap(), Language::Cpp, source);
        assert_eq!(name.as_deref(), Some("normalize"));
    }

    // =========================================================================
    // C qualified function tests (same issues apply to C with qualified names)
    // =========================================================================

    #[test]
    fn test_c_inline_struct_method_like() {
        // C doesn't have classes but let's ensure function_definition inside
        // struct declarations or other nesting still works
        let source = r#"
void process(int x) {
    int y = x + 1;
}
"#;
        let tree = parse(source, Language::C).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "process", Language::C, source);
        assert!(node.is_some(), "Should find simple C function");
    }

    // =========================================================================
    // Lua/Luau local_function tests
    // =========================================================================

    #[test]
    fn test_lua_local_function_node_kinds() {
        // Verify that local_function is included in node kinds for Lua
        // This ensures consistency with ast_utils::function_node_kinds
        let kinds = get_function_node_kinds(Language::Lua);
        // Lua tree-sitter may or may not use "local_function" - but if ast_utils
        // includes it, function_finder should too for consistency
        let ast_kinds = crate::security::ast_utils::function_node_kinds(Language::Lua);
        for kind in ast_kinds {
            assert!(
                kinds.contains(kind),
                "function_finder should include '{}' which ast_utils includes for Lua",
                kind
            );
        }
    }

    #[test]
    fn test_luau_local_function_node_kinds() {
        let kinds = get_function_node_kinds(Language::Luau);
        let ast_kinds = crate::security::ast_utils::function_node_kinds(Language::Luau);
        for kind in ast_kinds {
            assert!(
                kinds.contains(kind),
                "function_finder should include '{}' which ast_utils includes for Luau",
                kind
            );
        }
    }

    // =========================================================================
    // Class.method qualified-name lookup tests (complexity-class-method-qualified-v1)
    // =========================================================================

    #[test]
    fn test_qualified_class_method_python() {
        // Python: Flask.run-style qualified lookup must find the method
        // INSIDE the class (not the bare-name fallback).
        let source = r#"
class Flask:
    def run(self):
        x = 1
        return x

def run():
    pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "Flask.run", Language::Python, source);
        assert!(node.is_some(), "Should resolve Flask.run to class method");
        let node = node.unwrap();
        // The matched node should be inside the class body — its parent
        // chain must include a class_definition with name "Flask".
        let mut p = node.parent();
        let mut found_class = false;
        while let Some(parent) = p {
            if parent.kind() == "class_definition" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    if name_node.utf8_text(source.as_bytes()).unwrap_or("") == "Flask" {
                        found_class = true;
                        break;
                    }
                }
            }
            p = parent.parent();
        }
        assert!(
            found_class,
            "Resolved method must be lexically inside class Flask (not the bare top-level run)"
        );
    }

    #[test]
    fn test_complexity_unqualified_still_works() {
        // Regression: bare-name lookup must continue to work.
        let source = r#"
class Flask:
    def run(self):
        if True:
            pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "run", Language::Python, source);
        assert!(node.is_some(), "Bare-name 'run' must still resolve");
    }

    #[test]
    fn test_qualified_class_not_found_falls_back_to_method() {
        // When the class part doesn't exist, we should fall back to the
        // last component as a bare name.
        let source = r#"
def standalone():
    return 42
"#;
        let tree = parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let node = find_function_node(
            root,
            "NonexistentClass.standalone",
            Language::Python,
            source,
        );
        assert!(
            node.is_some(),
            "Should fall back to bare 'standalone' when class doesn't exist"
        );
    }

    #[test]
    fn test_qualified_class_method_typescript() {
        let source = r#"
class Server {
    start(): void {
        const port = 8080;
    }
}

class Logger {
    start(): void {}
}
"#;
        let tree = parse(source, Language::TypeScript).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "Server.start", Language::TypeScript, source);
        assert!(node.is_some(), "Should resolve Server.start in TS");
        // Verify lexical scope: parent class should be Server.
        let node = node.unwrap();
        let mut p = node.parent();
        let mut found = false;
        while let Some(parent) = p {
            if parent.kind() == "class_declaration" {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    if name_node.utf8_text(source.as_bytes()).unwrap_or("") == "Server" {
                        found = true;
                        break;
                    }
                }
            }
            p = parent.parent();
        }
        assert!(found, "Resolved method must be inside class Server");
    }

    #[test]
    fn test_qualified_class_method_rust_impl() {
        let source = r#"
struct Foo;

impl Foo {
    fn process(&self) -> i32 {
        let x = 1;
        x
    }
}
"#;
        let tree = parse(source, Language::Rust).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "Foo.process", Language::Rust, source);
        assert!(node.is_some(), "Should resolve Foo.process via impl block");
    }

    #[test]
    fn test_qualified_class_method_java() {
        let source = r#"
class Calculator {
    int add(int a, int b) {
        return a + b;
    }
}
"#;
        let tree = parse(source, Language::Java).unwrap();
        let root = tree.root_node();
        let node = find_function_node(root, "Calculator.add", Language::Java, source);
        assert!(node.is_some(), "Should resolve Calculator.add in Java");
    }

    #[test]
    fn test_qualified_lookup_via_complexity_python() {
        // Integration: complexity calculation through qualified name.
        use crate::metrics::calculate_complexity;
        let source = r#"
class Flask:
    def run(self, debug=False):
        if debug:
            print("debug")
        else:
            print("normal")
        return 0
"#;
        let metrics = calculate_complexity(source, "Flask.run", Language::Python).unwrap();
        // if/else => cyclomatic >= 2
        assert!(
            metrics.cyclomatic >= 2,
            "Flask.run cyclomatic should be >= 2, got {}",
            metrics.cyclomatic
        );
    }

    #[test]
    fn test_qualified_lookup_via_dfg_python() {
        // Integration: DFG (used by taint, slice, available, dead-stores,
        // reaching-defs) through qualified name.
        use crate::dfg::get_dfg_context;
        let source = r#"
class Service:
    def handler(self, req):
        x = req.data
        y = x + 1
        return y
"#;
        let result = get_dfg_context(source, "Service.handler", Language::Python);
        assert!(
            result.is_ok(),
            "DFG should succeed for Service.handler, got: {:?}",
            result.err()
        );
        let dfg = result.unwrap();
        assert_eq!(dfg.function, "Service.handler");
    }

    #[test]
    fn test_qualified_lookup_via_cfg_python() {
        // Integration: CFG (used by taint, slice, chop) through qualified name.
        use crate::cfg::get_cfg_context;
        let source = r#"
class Worker:
    def run(self):
        if True:
            return 1
        return 0
"#;
        let result = get_cfg_context(source, "Worker.run", Language::Python);
        assert!(
            result.is_ok(),
            "CFG should succeed for Worker.run, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_qualified_class_method_disambiguates_overloaded() {
        // Two classes with the same method name. Qualified lookup must
        // pick the one in the named class, not the first one in source order.
        let source = r#"
class Alpha:
    def shared(self):
        a = 1
        return a

class Beta:
    def shared(self):
        b = 2
        c = b + 1
        return c
"#;
        let tree = parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let beta_method =
            find_function_node(root, "Beta.shared", Language::Python, source).unwrap();
        // Verify it is the Beta version: walk up to enclosing class.
        let mut p = beta_method.parent();
        let mut enclosing = None;
        while let Some(parent) = p {
            if parent.kind() == "class_definition" {
                enclosing = parent
                    .child_by_field_name("name")
                    .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                break;
            }
            p = parent.parent();
        }
        assert_eq!(
            enclosing.as_deref(),
            Some("Beta"),
            "Beta.shared must resolve to the method inside class Beta"
        );
    }

    #[test]
    fn test_find_class_node_python() {
        let source = r#"
class Outer:
    pass

class Inner:
    pass
"#;
        let tree = parse(source, Language::Python).unwrap();
        let root = tree.root_node();
        let inner = find_class_node(root, "Inner", Language::Python, source);
        assert!(inner.is_some(), "Should find class Inner");
        let nonexistent = find_class_node(root, "DoesNotExist", Language::Python, source);
        assert!(
            nonexistent.is_none(),
            "Nonexistent class should return None"
        );
    }

    #[test]
    fn test_find_class_node_languages_without_classes() {
        // C, OCaml, Elixir, Lua, Luau have no class container — must
        // return None unconditionally.
        let source = "int foo() { return 0; }";
        let tree = parse(source, Language::C).unwrap();
        let root = tree.root_node();
        let result = find_class_node(root, "Anything", Language::C, source);
        assert!(result.is_none(), "C has no class kinds — must return None");
    }
}
