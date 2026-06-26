//! Dead code analysis (spec Section 2.2.3)
//!
//! Find functions that are never called (dead code).
//!
//! # Exclusion Patterns (not considered dead)
//! - App entry: main, __main__, cli, app, run, start, create_app
//! - Test: test_*, pytest_*, Test*, Benchmark*, setUp, tearDown
//! - Lifecycle: onCreate, onStart, onDestroy, init, destroy, etc.
//! - Handlers: handle*, Handle*, on_*, before_*, after_*
//! - Hooks: load, configure, request, response, invoke, call, execute
//! - HTTP: ServeHTTP, doGet, doPost, handler
//! - Dunder methods (__init__, __str__, etc.)
//! - Custom patterns from entry_points parameter
//!
//! # Performance
//! - O(E + V) where E = edges, V = functions

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::types::{DeadCodeReport, FunctionRef, ProjectCallGraph};
use crate::TldrResult;

// Re-export for convenience
#[allow(unused_imports)]
use super::refcount::is_rescued_by_refcount;

/// Analyze dead (unreachable) code.
///
/// # Arguments
/// * `call_graph` - Project call graph
/// * `all_functions` - All functions in the project
/// * `entry_points` - Optional custom entry point patterns
///
/// # Returns
/// * `Ok(DeadCodeReport)` - Dead code analysis results
pub fn dead_code_analysis(
    call_graph: &ProjectCallGraph,
    all_functions: &[FunctionRef],
    entry_points: Option<&[String]>,
) -> TldrResult<DeadCodeReport> {
    // Build set of all functions that are called
    let mut called_functions: HashSet<FunctionRef> = HashSet::new();

    for edge in call_graph.edges() {
        called_functions.insert(FunctionRef::new(
            edge.dst_file.clone(),
            edge.dst_func.clone(),
        ));
    }

    // Build set of all functions that call others (callers are entry points)
    let mut callers: HashSet<FunctionRef> = HashSet::new();
    for edge in call_graph.edges() {
        callers.insert(FunctionRef::new(
            edge.src_file.clone(),
            edge.src_func.clone(),
        ));
    }

    // Find dead functions, classifying into "definitely dead" and "possibly dead"
    let mut dead_functions: Vec<FunctionRef> = Vec::new();
    let mut possibly_dead: Vec<FunctionRef> = Vec::new();
    let mut by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for func_ref in all_functions {
        // Skip if called by anyone
        if called_functions.contains(func_ref) {
            continue;
        }

        // fix-R7-cl6-blank-name (v0.5.0 CLOSEOUT): never report a nameless
        // entity (unresolved C++ lambda / trailing-return ghost) as dead. See
        // the matching guard in `dead_code_analysis_refcount`.
        if func_ref.name.is_empty()
            || func_ref.name.rsplit('.').next().unwrap_or("").is_empty()
        {
            continue;
        }

        // Skip if matches entry point patterns
        if is_entry_point_name(&func_ref.name, entry_points) {
            continue;
        }

        // Skip dunder methods (__init__, __str__, etc.) - called implicitly by runtime
        // Check both bare name and Class.method format (also supports Lua module:method)
        let bare_name = if func_ref.name.contains('.') {
            func_ref.name.rsplit('.').next().unwrap_or(&func_ref.name)
        } else if func_ref.name.contains(':') {
            func_ref.name.rsplit(':').next().unwrap_or(&func_ref.name)
        } else {
            &func_ref.name
        };

        // PHP magic methods (leading __ without trailing __)
        // These are implicitly called by PHP runtime
        static PHP_MAGIC: &[&str] = &[
            "__construct",
            "__destruct",
            "__call",
            "__callStatic",
            "__get",
            "__set",
            "__isset",
            "__unset",
            "__sleep",
            "__wakeup",
            "__serialize",
            "__unserialize",
            "__toString",
            "__invoke",
            "__set_state",
            "__clone",
            "__debugInfo",
        ];
        if PHP_MAGIC.contains(&bare_name) {
            continue;
        }

        // fix-C5-4 (v0.5.0 AUDIT-FIX): Lua/Luau metamethods (__index, __add,
        // __tostring, …) are invoked implicitly by the VM and are never dead.
        // They start with `__` but do not end with `__`, so the dunder guard
        // below misses them. Whitelist the exact metamethod set.
        if is_lua_metamethod(bare_name) {
            continue;
        }

        if bare_name.starts_with("__") && bare_name.ends_with("__") {
            continue;
        }

        // Skip trait/interface methods (they are called implicitly by the type system)
        if func_ref.is_trait_method {
            continue;
        }

        // Skip test functions (they are called by the test runner)
        if func_ref.is_test {
            continue;
        }

        // Skip decorated/annotated functions (they are called by frameworks)
        if func_ref.has_decorator {
            continue;
        }

        // cluster-misc-v1 (M-044): C++ destructors are always invoked implicitly
        // by the runtime when an object goes out of scope or is deleted. They must
        // never be flagged as dead code. In the tree-sitter-cpp grammar, destructor
        // names are emitted from `destructor_name` nodes, which always begin with
        // `~`. No other supported language uses `~` as a function-name prefix, so
        // this is a safe cross-language guard.
        if bare_name.starts_with('~') {
            continue;
        }

        // Classify: public/exported but uncalled -> possibly dead (may be API surface)
        // Private/unenriched and uncalled -> definitely dead
        // RC6: an uncalled CLASS METHOD is reachable via dynamic dispatch / super /
        // reflection / framework runtime (Node stream `_transform`, etc.), so it is at
        // most *possibly* dead — never definitive. Only an uncalled FREE FUNCTION keeps
        // the visibility rule. (Matches Knip/Rust/ESLint confidence models — see
        // proposals/rc6-ts-underscore-method-definitive-vs-possibly-dead.md.)
        if func_ref.is_public || func_ref.is_method {
            possibly_dead.push(func_ref.clone());
            // dead-by-file-population-v1 (M-045): also bucket possibly_dead by
            // file path so `by_file` is the complete map "file -> all
            // dead-or-possibly-dead names in this file". Pre-fix only
            // dead_functions were bucketed, so consumers that read `by_file`
            // saw `{}` whenever a project had only public-but-uncalled
            // functions (the common case for libraries with exported APIs).
            by_file
                .entry(func_ref.file.clone())
                .or_default()
                .push(func_ref.name.clone());
        } else {
            dead_functions.push(func_ref.clone());
            by_file
                .entry(func_ref.file.clone())
                .or_default()
                .push(func_ref.name.clone());
        }
    }

    let total_dead = dead_functions.len();
    let total_possibly_dead = possibly_dead.len();
    let total_functions = all_functions.len();
    // med-low-schema-cleanup-v1 (N15): round percentage to 2 decimal places at
    // serialization to avoid 15-digit IEEE-754 noise in the JSON output
    // (e.g. `0.10893246187363835`). 2 decimals is the human-meaningful
    // precision for "percent dead".
    let dead_percentage = if total_functions > 0 {
        round_pct((total_dead as f64 / total_functions as f64) * 100.0)
    } else {
        0.0
    };

    Ok(DeadCodeReport {
        dead_functions,
        possibly_dead,
        by_file,
        total_dead,
        total_possibly_dead,
        total_functions,
        dead_percentage,
    })
}

/// Round a percentage value to 2 decimal places.
///
/// med-low-schema-cleanup-v1 (N15): clamps `f64` percentage fields to a
/// human-meaningful precision (`12.34`) so the JSON output is stable
/// across platforms / floating-point rounding.
#[inline]
fn round_pct(p: f64) -> f64 {
    (p * 100.0).round() / 100.0
}

/// Analyze dead (unreachable) code using reference counting instead of a call graph.
///
/// This is an alternative to `dead_code_analysis()` that uses identifier reference
/// counts to determine liveness. A function with `ref_count > 1` is considered alive
/// because it is referenced somewhere beyond its definition. A function with
/// `ref_count == 1` (only definition) is dead, subject to the same exclusion patterns
/// as the call-graph-based analysis.
///
/// Short names (< 3 characters) need a higher refcount threshold (>= 5) to be rescued,
/// since collision-prone names like `i`, `j`, `id` inflate counts artificially.
///
/// # Arguments
/// * `all_functions` - All functions in the project
/// * `ref_counts` - Map of identifier name to occurrence count across codebase
/// * `entry_points` - Optional custom entry point patterns
///
/// # Returns
/// * `Ok(DeadCodeReport)` - Dead code analysis results (backward compatible)
pub fn dead_code_analysis_refcount(
    all_functions: &[FunctionRef],
    ref_counts: &HashMap<String, usize>,
    entry_points: Option<&[String]>,
) -> TldrResult<DeadCodeReport> {
    let mut dead_functions: Vec<FunctionRef> = Vec::new();
    let mut possibly_dead: Vec<FunctionRef> = Vec::new();
    let mut by_file: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for func_ref in all_functions {
        // fix-R7-cl6-blank-name (v0.5.0 CLOSEOUT): a nameless entity can never
        // be a *named* dead function. The C++ extractor synthesizes
        // `FunctionInfo` with `name == ""` (and a malformed `() -> <fragment>`
        // signature) for declarators it cannot resolve — variable-bound lambdas
        // (`auto pop_one = [](...){...}`) and trailing-return-type templates
        // (`template<...> auto narrow(T*) -> char*`). These ghosts are
        // non-underscore so they were classified public → possibly_dead
        // (cpp-fmt: 72/180). Skip blank-named refs outright; they have no call
        // site to be "dead" relative to. (The root extractor name-resolution is
        // hardened separately, but this guard is the authoritative backstop so
        // no nameless ghost ever reaches a dead report.)
        if func_ref.name.is_empty()
            || func_ref.name.rsplit('.').next().unwrap_or("").is_empty()
        {
            continue;
        }

        // Skip if matches entry point patterns (C4)
        if is_entry_point_name(&func_ref.name, entry_points) {
            continue;
        }

        // Skip dunder methods (__init__, __str__, etc.) - called implicitly by runtime (C5)
        // Check both bare name and Class.method format (also supports Lua module:method)
        let bare_name = if func_ref.name.contains('.') {
            func_ref.name.rsplit('.').next().unwrap_or(&func_ref.name)
        } else if func_ref.name.contains(':') {
            func_ref.name.rsplit(':').next().unwrap_or(&func_ref.name)
        } else {
            &func_ref.name
        };

        // PHP magic methods (leading __ without trailing __)
        // These are implicitly called by PHP runtime
        static PHP_MAGIC: &[&str] = &[
            "__construct",
            "__destruct",
            "__call",
            "__callStatic",
            "__get",
            "__set",
            "__isset",
            "__unset",
            "__sleep",
            "__wakeup",
            "__serialize",
            "__unserialize",
            "__toString",
            "__invoke",
            "__set_state",
            "__clone",
            "__debugInfo",
        ];
        if PHP_MAGIC.contains(&bare_name) {
            continue;
        }

        // fix-C5-4 (v0.5.0 AUDIT-FIX): Lua/Luau metamethods are invoked
        // implicitly by the VM and are never dead (see `is_lua_metamethod`).
        if is_lua_metamethod(bare_name) {
            continue;
        }

        if bare_name.starts_with("__") && bare_name.ends_with("__") {
            continue;
        }

        // Skip trait/interface methods (C6)
        if func_ref.is_trait_method {
            continue;
        }

        // Skip test functions (C7)
        if func_ref.is_test {
            continue;
        }

        // Skip decorated/annotated functions (C8)
        if func_ref.has_decorator {
            continue;
        }

        // cluster-misc-v1 (M-044): C++ destructors are implicitly invoked by
        // the runtime and must not be reported as dead code. Destructor names
        // always begin with `~` in the tree-sitter-cpp `destructor_name` node
        // kind. No other supported language uses `~` as a function-name prefix.
        if bare_name.starts_with('~') {
            continue;
        }

        // Check refcount: if rescued by refcount (ref_count > 1, name >= 3 chars) -> alive (C2)
        if is_rescued_by_refcount(&func_ref.name, ref_counts) {
            continue;
        }

        // Not rescued -> classify by visibility (C9)
        // Enrich with the actual ref_count for the output
        let mut enriched = func_ref.clone();
        // Look up by bare name (for Class.method, use the bare method name for refcount)
        let lookup_name = bare_name;
        enriched.ref_count = ref_counts.get(lookup_name).copied().unwrap_or(0) as u32;

        // RC6: an uncalled CLASS METHOD is reachable via dynamic dispatch / super /
        // reflection / framework runtime (Node stream `_transform`, etc.), so it is at
        // most *possibly* dead — never definitive. Only an uncalled FREE FUNCTION keeps
        // the visibility rule. (Matches Knip/Rust/ESLint confidence models — see
        // proposals/rc6-ts-underscore-method-definitive-vs-possibly-dead.md.)
        if func_ref.is_public || func_ref.is_method {
            // dead-by-file-population-v1 (M-045): bucket possibly_dead in
            // `by_file` too so the map is the union of
            // dead_functions + possibly_dead grouped by source file. Pre-fix
            // only dead_functions populated `by_file`; library projects with
            // exported-but-uncalled APIs saw `by_file: {}` while
            // `possibly_dead` carried hundreds of entries.
            by_file
                .entry(func_ref.file.clone())
                .or_default()
                .push(func_ref.name.clone());
            possibly_dead.push(enriched);
        } else {
            by_file
                .entry(func_ref.file.clone())
                .or_default()
                .push(func_ref.name.clone());
            dead_functions.push(enriched);
        }
    }

    let total_dead = dead_functions.len();
    let total_possibly_dead = possibly_dead.len();
    let total_functions = all_functions.len();
    // med-low-schema-cleanup-v1 (N15): see `round_pct`.
    let dead_percentage = if total_functions > 0 {
        round_pct((total_dead as f64 / total_functions as f64) * 100.0)
    } else {
        0.0
    };

    Ok(DeadCodeReport {
        dead_functions,
        possibly_dead,
        by_file,
        total_dead,
        total_possibly_dead,
        total_functions,
        dead_percentage,
    })
}

/// fix-C5-4 (v0.5.0 AUDIT-FIX): the exhaustive set of Lua / Luau metamethod
/// (metatable event) names. The Lua VM invokes these implicitly when the
/// corresponding operator / table event fires (`a + b` → `__add`, `t[k]` on a
/// missing key → `__index`, `tostring(o)` → `__tostring`, etc.). A metamethod
/// is therefore *never* dead just because no explicit call site names it.
///
/// These names start with `__` but do NOT end with `__`, so the Python-dunder
/// guard (`name.starts_with("__") && name.ends_with("__")`) does not cover
/// them. We match against this exact, finite list rather than a broad
/// `starts_with("__")` so that genuinely-dead `__`-prefixed private helpers in
/// other languages are still reported. The list is the union across Lua 5.1
/// – 5.4 and Luau (see the Lua reference manual §2.4 / §8.1):
///   - arithmetic: `__add __sub __mul __div __mod __pow __unm __idiv`
///   - bitwise (5.3+): `__band __bor __bxor __bnot __shl __shr`
///   - relational: `__eq __lt __le`
///   - other operators: `__concat __len __call`
///   - table access: `__index __newindex`
///   - lifecycle / misc: `__gc __mode __close __tostring __metatable
///     __pairs __ipairs __name`
const LUA_METAMETHODS: &[&str] = &[
    "__add",
    "__sub",
    "__mul",
    "__div",
    "__mod",
    "__pow",
    "__unm",
    "__idiv",
    "__band",
    "__bor",
    "__bxor",
    "__bnot",
    "__shl",
    "__shr",
    "__eq",
    "__lt",
    "__le",
    "__concat",
    "__len",
    "__call",
    "__index",
    "__newindex",
    "__gc",
    "__mode",
    "__close",
    "__tostring",
    "__metatable",
    "__pairs",
    "__ipairs",
    "__name",
];

/// fix-C5-4: whether `bare_name` is a Lua/Luau metamethod (see
/// [`LUA_METAMETHODS`]). `bare_name` should already be stripped of any
/// `Table.` / `mt:` qualifier (the caller does this), so we compare the
/// terminal segment exactly.
fn is_lua_metamethod(bare_name: &str) -> bool {
    LUA_METAMETHODS.contains(&bare_name)
}

/// Check if a function name matches entry point patterns
fn is_entry_point_name(name: &str, custom_patterns: Option<&[String]>) -> bool {
    // Standard entry point names
    let standard_patterns = [
        // Application entry points
        "main",
        "__main__",
        "cli",
        "app",
        "run",
        "start",
        // Test setup/teardown
        "setup",
        "teardown",
        "setUp",
        "tearDown",
        // Python ASGI/WSGI
        "create_app",
        "make_app",
        // Go HTTP
        "ServeHTTP",
        "Handler",
        "handler",
        // C/system callbacks
        "OnLoad",
        "OnInit",
        "OnExit",
        // Android/Kotlin lifecycle
        "onCreate",
        "onStart",
        "onStop",
        "onResume",
        "onPause",
        "onDestroy",
        "onBind",
        "onClick",
        "onCreateView",
        // Java Servlet / Spring
        "doGet",
        "doPost",
        "doPut",
        "doDelete",
        "init",
        "destroy",
        "service",
        // Plugin/middleware hooks
        "load",
        "configure",
        "request",
        "response",
        "error",
        "invoke",
        "call",
        "execute",
        // Next.js instrumentation hooks
        "register",
        "onRequestError",
    ];

    if standard_patterns.contains(&name) {
        return true;
    }

    // Extract bare method name from "Class.method" or "module:method" format
    let bare_name = if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name)
    } else if name.contains(':') {
        name.rsplit(':').next().unwrap_or(name)
    } else {
        name
    };
    if bare_name != name && standard_patterns.contains(&bare_name) {
        return true;
    }

    // Test function patterns
    if name.starts_with("test_") || name.starts_with("pytest_") {
        return true;
    }

    // Test patterns on bare method name too
    if bare_name != name && (bare_name.starts_with("test_") || bare_name.starts_with("pytest_")) {
        return true;
    }

    // Go-style test functions (TestXxx, BenchmarkXxx, ExampleXxx)
    if name.starts_with("Test") || name.starts_with("Benchmark") || name.starts_with("Example") {
        return true;
    }

    // Java/Kotlin @Test annotation convention (methods starting with "test")
    if bare_name.starts_with("test") {
        return true;
    }

    // Prefix patterns for handlers/hooks across languages
    if bare_name.starts_with("handle") || bare_name.starts_with("Handle") {
        return true;
    }
    if bare_name.starts_with("on_")
        || bare_name.starts_with("before_")
        || bare_name.starts_with("after_")
    {
        return true;
    }

    // Check custom patterns
    if let Some(patterns) = custom_patterns {
        for pattern in patterns {
            if name == pattern {
                return true;
            }
            // Support simple glob patterns
            if pattern.ends_with('*') {
                let prefix = pattern.trim_end_matches('*');
                if name.starts_with(prefix) {
                    return true;
                }
            }
            if pattern.starts_with('*') {
                let suffix = pattern.trim_start_matches('*');
                if name.ends_with(suffix) {
                    return true;
                }
            }
        }
    }

    false
}

/// Build a human-readable signature string from function name, parameters, and return type.
///
/// Examples:
/// - `build_signature("calculate", &["x", "y"], Some("int"))` -> `"calculate(x, y) -> int"`
/// - `build_signature("helper", &[], None)` -> `"helper()"`
fn build_signature(name: &str, params: &[String], return_type: Option<&str>) -> String {
    let params_str = params.join(", ");
    match return_type {
        Some(rt) if !rt.is_empty() => format!("{}({}) -> {}", name, params_str, rt),
        _ => format!("{}({})", name, params_str),
    }
}

/// Structural method-kind / visibility markers that the per-language AST
/// extractors synthesize onto `FunctionInfo.decorators` to record *how* a
/// member is declared (instance vs static method, access level) — NOT a
/// framework/runtime-invocation annotation.
///
/// fix-R7-cl6-lua-dead (v0.5.0 CLOSEOUT): the dead-code "skip decorated
/// functions" guard (C8) exists because a genuine decorator/annotation
/// (`@app.route`, `@Override`, `@pytest.fixture`, a Rust attribute) signals the
/// function is invoked by a framework/runtime outside the call graph. But
/// several extractors also push *structural* tags that say nothing about
/// invocation:
///   - Lua/Luau table methods: `"method"` (colon form) / `"static"` (dot form)
///     — added by `lua_build_method_info` (extract.rs).
///   - Ruby singleton methods: `"self"`.
///   - PHP/C++ members: `"static"`, `"public"`, `"private"`, `"protected"`.
/// Counting these as decorators made every Lua table method (`function M.foo()`)
/// look "decorated" → skipped → `tldr dead` reported zero dead/possibly-dead for
/// idiomatic Lua modules (regression introduced by 48316dd's table-class
/// extraction). These markers must be ignored when deciding `has_decorator` for
/// dead-code analysis. Genuine annotations (anything else, e.g. `@Override`,
/// `route`, `cfg(test)`, `module`/`interface`/`trait` type tags) still count.
///
/// IMPORTANT — what is deliberately NOT in this list:
///   - `"virtual"` / `"abstract"`: these DO carry invocation semantics — a
///     C++ `virtual` method (or an abstract one) is dispatched polymorphically
///     through a base-class pointer / vtable and frequently has no direct named
///     caller, so it must stay rescued (see `cluster_misc_v1::
///     test_cpp_virtual_method_not_in_possibly_dead`). Only purely structural
///     instance/static/visibility tags belong here.
const STRUCTURAL_MODIFIER_MARKERS: &[&str] =
    &["method", "static", "self", "public", "private", "protected"];

/// Whether `decorators` contains a *genuine* invocation-implying
/// decorator/annotation, ignoring the purely structural method-kind /
/// visibility markers in [`STRUCTURAL_MODIFIER_MARKERS`]. Used to drive the
/// dead-code C8 "skip decorated functions" guard without spuriously rescuing
/// Lua/Ruby/PHP/C++ methods that merely carry a `static`/`method`/`self`/access
/// tag.
fn has_invocation_decorator(decorators: &[String]) -> bool {
    decorators
        .iter()
        .any(|d| !STRUCTURAL_MODIFIER_MARKERS.contains(&d.as_str()))
}

/// fix-R7-cl6-solidity-evm-entry (v0.5.0 CLOSEOUT): the two reserved Solidity
/// special functions invoked directly by the EVM and therefore never named at a
/// call site:
///   - `receive()`  — runs on a plain-ether transfer with empty calldata.
///   - `fallback()` — runs when no other function selector matches.
/// Both are emitted from the dedicated `fallback_receive_definition` AST node
/// (`extract_solidity_fallback_info`) with `name == "receive" | "fallback"`.
/// They are `external` (caller-visible) so the visibility fix routes them to
/// *possibly* dead, but they are genuine runtime entry points and must be
/// excluded entirely — exactly like the existing dunder / PHP-magic /
/// Lua-metamethod / C++-destructor entry-point exclusions. Gated on
/// `Language::Solidity` so a same-named method in another language (e.g. a
/// Python `receive`) is unaffected; `receive`/`fallback` are reserved keywords
/// in Solidity so there is no in-language collision.
fn is_solidity_evm_entry_point(name: &str, language: crate::types::Language) -> bool {
    matches!(language, crate::types::Language::Solidity)
        && matches!(name, "receive" | "fallback")
}

/// Extract all functions from a project for dead code analysis.
///
/// This is a helper function that can be used to gather all functions
/// from the AST extraction phase. It enriches FunctionRef with metadata
/// from the AST (decorators, visibility, test status, trait context)
/// to reduce false positives in dead code analysis.
pub fn collect_all_functions(
    module_infos: &[(PathBuf, crate::types::ModuleInfo)],
) -> Vec<FunctionRef> {
    let mut functions = Vec::new();

    for (file_path, info) in module_infos {
        let language = info.language;
        let is_test_file = is_test_file_path(file_path);
        let is_framework_entry =
            is_framework_entry_file(file_path, language) || has_framework_directive(file_path);

        // fix-R7-cl6-qualified-dedup (v0.5.0 CLOSEOUT): several languages'
        // DETAILED *functions* extractor recurses into class bodies and emits
        // every method ALSO as a top-level `info.functions` entry (bare name),
        // while the *classes* extractor emits the same method under
        // `classes[].methods` (qualified `Class.method`). `collect_all_functions`
        // then produces BOTH `getAddress` and `Owner.getAddress` for one source
        // method, and FunctionRef identity is (file, name) — so the two are
        // distinct and BOTH land in dead/possibly_dead, doubling the headline
        // counts (java-petclinic: 12 entries / 6 real; also csharp). Previously
        // only Elixir (M-045) was deduped. Generalize to ALL languages, keyed on
        // (bare_name, line_number): a top-level function whose name AND line
        // coincide with a class method in the same file IS that method's
        // double-emit and is dropped (the qualified `Class.method` form is kept).
        // Matching on the line too is essential — it guarantees a *genuine*
        // free function that merely shares a name with a method (different line)
        // is never dropped. C# additionally drops async methods from its classes
        // extractor, so an async method appears only as a bare top-level entry;
        // that bare form has NO matching (name,line) class method and is
        // therefore correctly KEPT (no qualified twin to collapse onto).
        // Only methods with a known (non-zero) line participate: a 0/unknown
        // line is not a reliable identity and could falsely collapse unrelated
        // same-named entries.
        let class_method_keys: std::collections::HashSet<(String, u32)> = info
            .classes
            .iter()
            .flat_map(|c| {
                c.methods
                    .iter()
                    .filter(|m| m.line_number != 0)
                    .map(|m| (m.name.clone(), m.line_number))
            })
            .collect();

        // Add top-level functions
        for func in &info.functions {
            // Drop the bare top-level form if the SAME (name, line) exists as a
            // class method in this file — it is the recursive-extractor
            // double-emit; the qualified `Class.fn` form is emitted in the
            // class-method loop below.
            if func.line_number != 0
                && class_method_keys.contains(&(func.name.clone(), func.line_number))
            {
                continue;
            }
            // is-public-visibility-v1 (v0.4.2 M-007): prefer explicit AST
            // visibility when the per-language extractor populated it
            // (csharp/java/kotlin/swift/go/js). Fall back to the legacy
            // name-based heuristic only when `visibility` is `None`
            // (e.g. Java package-private, Kotlin default-public).
            let is_public = explicit_or_inferred_visibility(
                func.visibility.as_deref(),
                &func.name,
                language,
                !func.decorators.is_empty(),
                &func.decorators,
            );
            let has_decorator = has_invocation_decorator(&func.decorators)
                || (is_framework_entry && is_public)
                || is_solidity_evm_entry_point(&func.name, language);
            let is_test = is_test_file
                || is_test_function_name(&func.name)
                || has_test_decorator(&func.decorators);
            let signature = build_signature(&func.name, &func.params, func.return_type.as_deref());

            functions.push(FunctionRef {
                file: file_path.clone(),
                name: func.name.clone(),
                line: func.line_number,
                signature,
                ref_count: 0,
                is_public,
                is_test,
                is_trait_method: false,
                is_method: false,
                has_decorator,
                decorator_names: func.decorators.clone(),
            });
        }

        // Add class methods
        for class in &info.classes {
            let is_trait = is_trait_or_interface(class, language);

            for method in &class.methods {
                let full_name = format!("{}.{}", class.name, method.name);
                // fix-R7-cl6-rust-trait-impl (v0.5.0 CLOSEOUT): a method carrying
                // the synthetic `"trait_impl"` decorator was defined inside an
                // `impl Trait for Type` block (Rust extractor). It is dispatched
                // through the trait, not by a free name, so it must be treated as
                // a trait method even though the receiver STRUCT is not itself a
                // trait. Per-method (not per-class) so an inherent method on the
                // same struct stays dead-checkable.
                let is_trait_impl_method = method.decorators.iter().any(|d| d == "trait_impl");
                // is-public-visibility-v1 (v0.4.2 M-007): same preference
                // ordering as top-level functions.
                let is_public = explicit_or_inferred_visibility(
                    method.visibility.as_deref(),
                    &method.name,
                    language,
                    !method.decorators.is_empty(),
                    &method.decorators,
                );
                let has_decorator = has_invocation_decorator(&method.decorators)
                    || (is_framework_entry && is_public)
                    || is_solidity_evm_entry_point(&method.name, language);
                let is_test = is_test_file
                    || is_test_function_name(&method.name)
                    || has_test_decorator(&method.decorators);
                let signature =
                    build_signature(&method.name, &method.params, method.return_type.as_deref());

                functions.push(FunctionRef {
                    file: file_path.clone(),
                    name: full_name,
                    line: method.line_number,
                    signature,
                    ref_count: 0,
                    is_public,
                    is_test,
                    is_trait_method: is_trait || is_trait_impl_method,
                    is_method: true,
                    has_decorator,
                    decorator_names: method.decorators.clone(),
                });
            }
        }
    }

    functions
}

/// Check if a file path looks like a test file
fn is_test_file_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let file_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    // Common test file patterns across languages
    file_name.starts_with("test_")
        || file_name.ends_with("_test")
        || file_name.ends_with("_tests")
        || file_name.ends_with("_spec")
        || file_name.starts_with("Test")
        || file_name.ends_with("Test")
        || file_name.ends_with("Tests")
        || file_name.ends_with("Spec")
        || path_str.contains("/test/")
        || path_str.contains("/tests/")
        || path_str.contains("/spec/")
        || path_str.contains("/__tests__/")
}

/// Check if a function name looks like a test function
fn is_test_function_name(name: &str) -> bool {
    let bare = name.rsplit('.').next().unwrap_or(name);
    bare.starts_with("test_")
        || bare.starts_with("Test")
        || bare.starts_with("Benchmark")
        || bare.starts_with("Example")
}

/// Check if any decorator indicates a test
fn has_test_decorator(decorators: &[String]) -> bool {
    decorators.iter().any(|d| {
        let lower = d.to_lowercase();
        // Direct test markers (covers Python `@pytest.mark.parametrize`, generic
        // `test`/`testXxx`, plus Rust `#[test]`).
        if lower == "test"
            || lower == "pytest.mark.parametrize"
            || lower.starts_with("test")
        {
            return true;
        }
        // Rust ecosystem test attributes: `#[tokio::test]`, `#[async_std::test]`,
        // `#[wasm_bindgen_test]`, `#[rstest]`, `#[proptest]`, `#[serial_test::serial]`,
        // and any `cfg(test)` / `cfg_attr(test, ...)` (synthesized for functions that
        // live inside `#[cfg(test)] mod tests {}` / `mod tests {}`).
        lower.contains("::test")
            || lower.starts_with("tokio::test")
            || lower.starts_with("async_std::test")
            || lower.starts_with("wasm_bindgen_test")
            || lower.starts_with("rstest")
            || lower.starts_with("proptest")
            || lower.contains("cfg(test")
            || lower.contains("cfg_attr(test")
    })
}

/// is-public-visibility-v1 (v0.4.2 M-007): combine an explicit AST
/// visibility keyword (when present) with the legacy name-based
/// heuristic. The explicit signal wins; the heuristic is only used as
/// a fallback for languages or declarations that lacked a syntactic
/// access modifier.
///
/// Returns `true` if the function is publicly visible from outside its
/// defining module / file. Mapping of explicit keywords:
///   - `"public"` / `"open"`         → public
///   - `"private"` / `"fileprivate"` → not public
///   - `"protected"`                 → not public (visible to subclass
///                                     only — treated as non-public
///                                     for dead-code reachability)
///   - `"internal"`                  → public-within-module
///                                     (treated as public, since
///                                     within-module callers count
///                                     for dead-code analysis)
fn explicit_or_inferred_visibility(
    explicit: Option<&str>,
    name: &str,
    language: crate::types::Language,
    has_decorator: bool,
    decorators: &[String],
) -> bool {
    if let Some(kw) = explicit {
        // fix-R7-cl6-solidity-external (v0.5.0 CLOSEOUT): `external` is a
        // first-class, caller-visible Solidity visibility — it is the entire
        // public ABI surface of a contract/interface (an `external` function
        // can be invoked by other contracts and off-chain callers; it simply
        // cannot be called internally without `this.`). Treating it as
        // non-public routed every `external` function into the *definitive*
        // dead bucket (e.g. openzeppelin reported 45 dead, including the whole
        // IERC777 / IERC1820Registry interface surface). An external function
        // with no in-repo caller is at most *possibly* dead, never definitive.
        return matches!(kw, "public" | "open" | "internal" | "external");
    }
    infer_visibility_from_name(name, language, has_decorator, decorators)
}

/// Infer visibility from function name based on language conventions.
///
/// This is a heuristic approach - not perfect, but vastly better than
/// treating everything as private (which causes 95-100% FP rate).
fn infer_visibility_from_name(
    name: &str,
    language: crate::types::Language,
    _has_decorator: bool,
    _decorators: &[String],
) -> bool {
    use crate::types::Language;

    let bare_name = name.rsplit('.').next().unwrap_or(name);

    match language {
        // Python: no leading underscore = public (convention)
        Language::Python => !bare_name.starts_with('_'),

        // Go: uppercase first letter = exported
        Language::Go => bare_name
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false),

        // Rust: we can't tell from name alone, but `pub` functions are
        // the majority in library crates. Without AST visibility info,
        // treat non-underscore-prefixed as possibly public.
        // The AST extraction code should set this more precisely.
        Language::Rust => !bare_name.starts_with('_'),

        // TypeScript/JavaScript: functions with decorators like @export
        // or those not starting with _ are typically public
        Language::TypeScript | Language::JavaScript => !bare_name.starts_with('_'),

        // Java/Kotlin/C#/Scala: typically all non-private methods are public.
        // Without explicit `private` keyword info, treat as public unless
        // name starts with underscore or is clearly internal.
        Language::Java | Language::Kotlin | Language::CSharp | Language::Scala => {
            !bare_name.starts_with('_')
        }

        // C/C++: static functions are private; others are public.
        // We can't tell from name, so treat as public by default.
        Language::C | Language::Cpp => true,

        // Ruby: methods after `private` keyword are private.
        // Convention: leading underscore = private.
        Language::Ruby => !bare_name.starts_with('_'),

        // PHP: has explicit public/private/protected keywords.
        // Convention: leading underscore = private.
        Language::Php => !bare_name.starts_with('_'),

        // Elixir: functions starting with _ are private (defp vs def)
        Language::Elixir => !bare_name.starts_with('_'),

        // Lua/Luau: local = private, module table = public
        // Convention: _M:method = public (module API), _prefix = private
        Language::Lua | Language::Luau => {
            // _M:method is always public — _M is the module export table
            if name.starts_with("_M:") || name.starts_with("_M.") {
                return true;
            }
            // Extract method name after : (Lua method call syntax)
            let lua_bare = if let Some(pos) = bare_name.find(':') {
                &bare_name[pos + 1..]
            } else {
                bare_name
            };
            !lua_bare.starts_with('_')
        }

        // OCaml: .mli files define public interface
        // Convention: leading underscore = private
        Language::Ocaml => !bare_name.starts_with('_'),

        // Swift: default is internal, not public
        Language::Swift => !bare_name.starts_with('_'),

        // v0.5.0 SOL-001 Solidity foundation. Solidity has explicit
        // visibility (public | external | internal | private) — see
        // oracle research. Until SOL-002 wires extract_solidity_visibility,
        // fall back to the leading-underscore convention; this aligns
        // with Solidity style guides (`_internal` for module-private
        // helpers).
        Language::Solidity => !bare_name.starts_with('_'),
    }
}

/// Check if a class looks like a trait/interface/protocol/abstract class
fn is_trait_or_interface(
    class: &crate::types::ClassInfo,
    language: crate::types::Language,
) -> bool {
    use crate::types::Language;

    let name = &class.name;

    // Check bases for common trait/interface patterns
    let has_abstract_base = class
        .bases
        .iter()
        .any(|b| b == "ABC" || b == "ABCMeta" || b == "Protocol" || b == "Interface");

    if has_abstract_base {
        return true;
    }

    // Check class decorators for abstract/interface/trait/protocol/module indicators.
    // AST extractors tag ClassInfo with these decorators:
    //   - PHP: "interface" for interfaces, "trait" for traits
    //   - Scala: "trait" for traits (via inheritance extractor)
    //   - Swift: "protocol" for protocols (via inheritance extractor)
    //   - Ruby: "module" for modules used as mixins
    //   - Rust: "trait" for trait items (when extracted by simple extractor)
    let has_type_decorator = class.decorators.iter().any(|d| {
        d == "abstract" || d == "interface" || d == "protocol" || d == "trait" || d == "module"
    });

    if has_type_decorator {
        return true;
    }

    // fix-R7-cl6-solidity-interface (v0.5.0 CLOSEOUT): the Solidity extractor
    // records the class flavor on `ClassInfo.kind` (`"contract"` | `"interface"`
    // | `"library"`), NOT as a decorator (see `build_solidity_class_info`). An
    // `interface` is a pure ABI declaration — its members are external function
    // *signatures* with no body, invoked polymorphically through implementing
    // contracts, so they are never "dead" by absence of a direct caller (the
    // openzeppelin IERC777 / IERC1820Registry surfaces were all flagged). Only
    // `"interface"` is excluded here; `"contract"`/`"library"` methods remain
    // subject to normal dead analysis. `kind` is `None` for every non-Solidity
    // language (and `Some("table")` only for Lua), so this never matches
    // unintended classes.
    if class.kind.as_deref() == Some("interface") {
        return true;
    }

    match language {
        // Rust: traits are extracted as "classes" by some AST extractor paths.
        // The decorator check above handles cases where "trait" is set.
        // Without a decorator, we cannot reliably distinguish traits from structs
        // by name alone, so return false.
        Language::Rust => false,

        // Go: interfaces follow naming conventions.
        // Common Go interfaces end in "-er" (Reader, Writer, Handler, Stringer)
        // or have explicit "Interface" suffix.
        Language::Go => {
            // Explicit "Interface" suffix
            if name.ends_with("Interface") {
                return true;
            }
            // Common Go single-method interface pattern: capitalized name ending in "er"
            // e.g., Reader, Writer, Closer, Handler, Stringer, Formatter
            // Must be at least 3 chars and start uppercase to avoid false positives
            if name.len() >= 3
                && name.ends_with("er")
                && name
                    .chars()
                    .next()
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
            {
                return true;
            }
            false
        }

        // Java/Kotlin: interfaces are common
        Language::Java | Language::Kotlin => {
            // Check for interface-like naming convention (IFoo pattern)
            name.starts_with('I')
                && name.len() > 1
                && name
                    .chars()
                    .nth(1)
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
        }

        // C#: interface naming convention (IFoo)
        Language::CSharp => {
            name.starts_with('I')
                && name.len() > 1
                && name
                    .chars()
                    .nth(1)
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
        }

        // Swift: protocols follow naming conventions.
        // Common suffixes: "Protocol", "Delegate", "DataSource", "able"/"ible"
        Language::Swift => {
            name.ends_with("Protocol")
                || name.ends_with("Delegate")
                || name.ends_with("DataSource")
                || name.ends_with("able")
                || name.ends_with("ible")
        }

        // Scala: traits use IFoo convention or end in common trait suffixes.
        // The decorator check above handles the "trait" tag from the extractor.
        Language::Scala => {
            // IFoo convention (same as Java)
            name.starts_with('I')
                && name.len() > 1
                && name
                    .chars()
                    .nth(1)
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
        }

        // PHP: interfaces and traits are tagged by the extractor with decorators
        // ("interface" or "trait"), handled by the decorator check above.
        // Additional naming convention: IFoo pattern
        Language::Php => {
            name.starts_with('I')
                && name.len() > 1
                && name
                    .chars()
                    .nth(1)
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
        }

        // Ruby: modules used as mixins/interfaces.
        // Common naming patterns: ends in "able", "ible", or includes "Mixin"
        Language::Ruby => {
            name.ends_with("able") || name.ends_with("ible") || name.contains("Mixin")
        }

        _ => false,
    }
}

/// Check if a file is a framework entry point (called by framework, not user code).
///
/// Functions in framework entry files are invoked by the framework runtime, not
/// by user code. Their absence from the call graph doesn't mean they are dead.
/// All exported/public functions in these files should be excluded from dead code analysis.
fn is_framework_entry_file(path: &Path, language: crate::types::Language) -> bool {
    use crate::types::Language;

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let path_str = path.to_string_lossy();

    match language {
        Language::TypeScript | Language::JavaScript => {
            // Next.js App Router conventions
            matches!(
                file_name,
                "page.tsx"
                    | "page.ts"
                    | "page.jsx"
                    | "page.js"
                    | "layout.tsx"
                    | "layout.ts"
                    | "layout.jsx"
                    | "layout.js"
                    | "route.tsx"
                    | "route.ts"
                    | "route.jsx"
                    | "route.js"
                    | "loading.tsx"
                    | "loading.ts"
                    | "loading.jsx"
                    | "loading.js"
                    | "error.tsx"
                    | "error.ts"
                    | "error.jsx"
                    | "error.js"
                    | "not-found.tsx"
                    | "not-found.ts"
                    | "not-found.jsx"
                    | "not-found.js"
                    | "template.tsx"
                    | "template.ts"
                    | "template.jsx"
                    | "template.js"
                    | "default.tsx"
                    | "default.ts"
                    | "default.jsx"
                    | "default.js"
                    | "middleware.ts"
                    | "middleware.js"
                    | "manifest.ts"
                    | "manifest.js"
                    | "opengraph-image.tsx"
                    | "opengraph-image.ts"
                    | "sitemap.ts"
                    | "sitemap.js"
                    | "robots.ts"
                    | "robots.js"
            )
            // SvelteKit conventions
            || matches!(
                file_name,
                "+page.svelte"
                    | "+layout.svelte"
                    | "+error.svelte"
                    | "+page.ts"
                    | "+page.js"
                    | "+page.server.ts"
                    | "+page.server.js"
                    | "+layout.ts"
                    | "+layout.js"
                    | "+layout.server.ts"
                    | "+layout.server.js"
                    | "+server.ts"
                    | "+server.js"
            )
            // Nuxt conventions (files in pages/, layouts/, middleware/ dirs)
            || (path_str.contains("/pages/") && file_name.ends_with(".vue"))
            || (path_str.contains("/layouts/") && file_name.ends_with(".vue"))
            || (path_str.contains("/middleware/")
                && (file_name.ends_with(".ts") || file_name.ends_with(".js")))
            // Remix conventions
            || path_str.contains("/routes/")
            // Astro pages
            || (path_str.contains("/pages/") && file_name.ends_with(".astro"))
        }
        Language::Python => {
            // Django conventions
            file_name == "views.py"
                || file_name == "admin.py"
                || file_name == "urls.py"
                || file_name == "models.py"
                || file_name == "forms.py"
                || file_name == "serializers.py"
                || file_name == "signals.py"
                || file_name == "apps.py"
                || file_name == "middleware.py"
                || file_name == "context_processors.py"
                // Flask/FastAPI
                || file_name == "wsgi.py"
                || file_name == "asgi.py"
                || file_name == "conftest.py"
                // Celery
                || file_name == "tasks.py"
        }
        Language::Ruby => {
            // Rails conventions
            (path_str.contains("/controllers/") && file_name.ends_with("_controller.rb"))
                || (path_str.contains("/models/") && file_name.ends_with(".rb"))
                || (path_str.contains("/helpers/") && file_name.ends_with("_helper.rb"))
                || (path_str.contains("/mailers/") && file_name.ends_with("_mailer.rb"))
                || (path_str.contains("/jobs/") && file_name.ends_with("_job.rb"))
                || (path_str.contains("/channels/") && file_name.ends_with("_channel.rb"))
                || file_name == "application.rb"
                || file_name == "routes.rb"
                || file_name == "schema.rb"
        }
        Language::Java | Language::Kotlin => {
            // Spring Boot conventions
            file_name.ends_with("Controller.java")
                || file_name.ends_with("Controller.kt")
                || file_name.ends_with("Service.java")
                || file_name.ends_with("Service.kt")
                || file_name.ends_with("Repository.java")
                || file_name.ends_with("Repository.kt")
                || file_name.ends_with("Configuration.java")
                || file_name.ends_with("Configuration.kt")
                || file_name.ends_with("Application.java")
                || file_name.ends_with("Application.kt")
                // Android
                || file_name.ends_with("Activity.java")
                || file_name.ends_with("Activity.kt")
                || file_name.ends_with("Fragment.java")
                || file_name.ends_with("Fragment.kt")
                || file_name.ends_with("ViewModel.java")
                || file_name.ends_with("ViewModel.kt")
        }
        Language::CSharp => {
            // ASP.NET conventions. VAL-018: `Program.cs` and `Startup.cs`
            // are also the conventional entry point names for non-ASP.NET
            // C# applications (console apps, libraries with a CLI driver),
            // where they are NOT framework-rescued. Disambiguate by
            // reading the file: only treat `Program.cs`/`Startup.cs` as
            // ASP.NET when they reference ASP.NET-specific APIs.
            // Without this, dead-code analysis silently rescues every
            // public method in `Program.cs` even in plain console apps,
            // hiding real dead functions.
            if file_name.ends_with("Controller.cs")
                || file_name.ends_with("Hub.cs")
                || file_name.ends_with("Middleware.cs")
                || (path_str.contains("/Pages/") && file_name.ends_with(".cshtml.cs"))
            {
                return true;
            }
            if file_name == "Program.cs" || file_name == "Startup.cs" {
                if let Ok(content) = std::fs::read_to_string(path) {
                    return content.contains("Microsoft.AspNetCore")
                        || content.contains("WebApplication")
                        || content.contains("IApplicationBuilder")
                        || content.contains("IHostBuilder")
                        || content.contains("IWebHostBuilder")
                        || content.contains("IServiceCollection");
                }
            }
            false
        }
        Language::Go => {
            // Go HTTP handlers are typically in handler files
            file_name == "main.go"
                || file_name.ends_with("_handler.go")
                || file_name.ends_with("_handlers.go")
        }
        Language::Php => {
            // Laravel conventions
            (path_str.contains("/Controllers/") && file_name.ends_with(".php"))
                || (path_str.contains("/Middleware/") && file_name.ends_with(".php"))
                || (path_str.contains("/Models/") && file_name.ends_with(".php"))
                || (path_str.contains("/Providers/") && file_name.ends_with(".php"))
                || file_name == "routes.php"
                || file_name == "web.php"
                || file_name == "api.php"
        }
        Language::Elixir => {
            // Phoenix conventions
            (path_str.contains("/controllers/") && file_name.ends_with("_controller.ex"))
                || (path_str.contains("/live/") && file_name.ends_with("_live.ex"))
                || (path_str.contains("/channels/") && file_name.ends_with("_channel.ex"))
                || file_name == "router.ex"
                || file_name == "endpoint.ex"
                // elixir-multiclause-and-mix-v1 (v0.4.2 bug-E2): `mix.exs`
                // is the build manifest. Its top-level public callbacks
                // (`project/0`, `application/0`, `deps/0`, etc.) are
                // reflection entry points invoked by the Mix build tool
                // — they have no explicit caller in project source but
                // are NEVER dead. Treating the whole file as a framework
                // entry rescues all public defs (the equivalent of
                // Python's `wsgi.py` or Django `views.py`).
                || file_name == "mix.exs"
        }
        Language::Swift => {
            // SwiftUI / iOS conventions
            file_name.ends_with("View.swift")
                || file_name.ends_with("ViewController.swift")
                || file_name.ends_with("App.swift")
                || file_name.ends_with("Delegate.swift")
        }
        Language::Scala => {
            // Play Framework conventions
            (path_str.contains("/controllers/") && file_name.ends_with(".scala"))
                || file_name == "routes"
        }
        _ => false,
    }
}

/// Check if a file contains a framework directive that makes exports externally reachable.
///
/// React Server Components use `'use server'` and `'use client'` directives at the
/// top of files. All exports from such files are framework entry points.
fn has_framework_directive(path: &Path) -> bool {
    // Only relevant for JS/TS files
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if !matches!(ext, "ts" | "tsx" | "js" | "jsx" | "mjs") {
        return false;
    }

    // Read first few lines looking for directives
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines().take(5) {
            let trimmed = line.trim();
            if trimmed == r#""use server""#
                || trimmed == r#"'use server'"#
                || trimmed == r#""use server";"#
                || trimmed == r#"'use server';"#
                || trimmed == r#""use client""#
                || trimmed == r#"'use client'"#
                || trimmed == r#""use client";"#
                || trimmed == r#"'use client';"#
            {
                return true;
            }
            // Skip empty lines and comments
            if !trimmed.is_empty()
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("/*")
                && !trimmed.starts_with('*')
            {
                // If we hit a non-directive, non-comment line, stop looking
                // (directives must be at the top of the file)
                if !trimmed.starts_with('"') && !trimmed.starts_with('\'') {
                    break;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CallEdge;

    fn create_test_graph() -> ProjectCallGraph {
        let mut graph = ProjectCallGraph::new();

        // main calls process, process calls helper
        graph.add_edge(CallEdge {
            src_file: "main.py".into(),
            src_func: "main".to_string(),
            dst_file: "main.py".into(),
            dst_func: "process".to_string(),
            call_line: None,
        });
        graph.add_edge(CallEdge {
            src_file: "main.py".into(),
            src_func: "process".to_string(),
            dst_file: "utils.py".into(),
            dst_func: "helper".to_string(),
            call_line: None,
        });

        graph
    }

    #[test]
    fn test_dead_finds_uncalled() {
        let graph = create_test_graph();
        let functions = vec![
            FunctionRef::new("main.py".into(), "main"),
            FunctionRef::new("main.py".into(), "process"),
            FunctionRef::new("utils.py".into(), "helper"),
            FunctionRef::new("utils.py".into(), "unused"),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // 'unused' should be dead
        assert!(result.dead_functions.iter().any(|f| f.name == "unused"));
        // 'main' is an entry point, so not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "main"));
        // 'process' is called, so not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "process"));
        // 'helper' is called, so not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "helper"));
    }

    #[test]
    fn test_dead_excludes_entry_points() {
        let graph = ProjectCallGraph::new(); // Empty graph
        let functions = vec![
            FunctionRef::new("main.py".into(), "main"),
            FunctionRef::new("test.py".into(), "test_something"),
            FunctionRef::new("setup.py".into(), "setup"),
            FunctionRef::new("utils.py".into(), "__init__"),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // All are entry points or dunder methods
        assert!(result.dead_functions.is_empty());
    }

    #[test]
    fn test_dead_custom_entry_points() {
        let graph = ProjectCallGraph::new();
        let functions = vec![
            FunctionRef::new("handler.py".into(), "handle_request"),
            FunctionRef::new("handler.py".into(), "process_event"),
        ];

        let custom = vec!["handle_*".to_string()];
        let result = dead_code_analysis(&graph, &functions, Some(&custom)).unwrap();

        // handle_request matches pattern
        assert!(!result
            .dead_functions
            .iter()
            .any(|f| f.name == "handle_request"));
        // process_event doesn't match
        assert!(result
            .dead_functions
            .iter()
            .any(|f| f.name == "process_event"));
    }

    #[test]
    fn test_dead_percentage() {
        let graph = ProjectCallGraph::new();
        let functions = vec![
            FunctionRef::new("a.py".into(), "dead1"),
            FunctionRef::new("a.py".into(), "dead2"),
            FunctionRef::new("a.py".into(), "main"), // entry point
            FunctionRef::new("a.py".into(), "test_x"), // entry point
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        assert_eq!(result.total_dead, 2);
        assert_eq!(result.total_functions, 4);
        assert!((result.dead_percentage - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_is_entry_point_name() {
        assert!(is_entry_point_name("main", None));
        assert!(is_entry_point_name("test_something", None));
        assert!(is_entry_point_name("setup", None));
        assert!(!is_entry_point_name("helper", None));

        let custom = vec!["handler_*".to_string()];
        assert!(is_entry_point_name("handler_request", Some(&custom)));
        assert!(!is_entry_point_name("process_request", Some(&custom)));
    }

    #[test]
    fn test_entry_point_go_patterns() {
        // Go HTTP handler
        assert!(is_entry_point_name("ServeHTTP", None));
        assert!(is_entry_point_name("Handler", None));
        // Go test conventions
        assert!(is_entry_point_name("TestUserLogin", None));
        assert!(is_entry_point_name("BenchmarkSort", None));
        assert!(is_entry_point_name("ExampleParse", None));
    }

    #[test]
    fn test_entry_point_android_lifecycle() {
        assert!(is_entry_point_name("onCreate", None));
        assert!(is_entry_point_name("onStart", None));
        assert!(is_entry_point_name("onDestroy", None));
        assert!(is_entry_point_name("onClick", None));
        assert!(is_entry_point_name("onBind", None));
    }

    #[test]
    fn test_entry_point_plugin_hooks() {
        assert!(is_entry_point_name("load", None));
        assert!(is_entry_point_name("configure", None));
        assert!(is_entry_point_name("request", None));
        assert!(is_entry_point_name("invoke", None));
        assert!(is_entry_point_name("execute", None));
    }

    #[test]
    fn test_entry_point_handler_prefix() {
        assert!(is_entry_point_name("handleRequest", None));
        assert!(is_entry_point_name("handle_event", None));
        assert!(is_entry_point_name("HandleConnection", None));
    }

    #[test]
    fn test_entry_point_hook_prefix() {
        assert!(is_entry_point_name("on_message", None));
        assert!(is_entry_point_name("before_request", None));
        assert!(is_entry_point_name("after_response", None));
    }

    #[test]
    fn test_entry_point_class_method_format() {
        // Class.method format should check bare method name
        assert!(is_entry_point_name("MyServlet.doGet", None));
        assert!(is_entry_point_name("Activity.onCreate", None));
        assert!(is_entry_point_name("Server.handleRequest", None));
        assert!(is_entry_point_name("TestSuite.test_login", None));
        // Not an entry point
        assert!(!is_entry_point_name("Utils.compute", None));
    }

    #[test]
    fn test_entry_point_java_servlet() {
        assert!(is_entry_point_name("doGet", None));
        assert!(is_entry_point_name("doPost", None));
        assert!(is_entry_point_name("init", None));
        assert!(is_entry_point_name("destroy", None));
        assert!(is_entry_point_name("service", None));
    }

    // =========================================================================
    // Tests for enriched FunctionRef metadata (dead code FP reduction)
    // =========================================================================

    /// Helper to create an enriched FunctionRef with metadata
    fn enriched_func(
        name: &str,
        is_public: bool,
        is_trait_method: bool,
        has_decorator: bool,
        decorator_names: Vec<&str>,
    ) -> FunctionRef {
        FunctionRef {
            file: PathBuf::from("test.rs"),
            name: name.to_string(),
            line: 0,
            signature: String::new(),
            ref_count: 0,
            is_public,
            is_test: false,
            is_trait_method,
            is_method: false,
            has_decorator,
            decorator_names: decorator_names.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    // RC6: helper to model an uncalled CLASS METHOD (is_method:true). Mirrors
    // `enriched_func` but flips the method axis so the split-site hedge can be
    // pinned. See proposals/rc6-ts-underscore-method-definitive-vs-possibly-dead.md.
    #[allow(clippy::too_many_arguments)]
    fn method_func(name: &str, is_public: bool) -> FunctionRef {
        FunctionRef {
            file: PathBuf::from("test.rs"),
            name: name.to_string(),
            line: 0,
            signature: String::new(),
            ref_count: 0,
            is_public,
            is_test: false,
            is_trait_method: false,
            is_method: true,
            has_decorator: false,
            decorator_names: Vec::new(),
        }
    }

    #[test]
    fn test_public_uncalled_is_possibly_dead_not_dead() {
        // A public function that is never called should NOT be in dead_functions,
        // it should be in possibly_dead instead
        let graph = ProjectCallGraph::new();
        let functions = vec![enriched_func("pub_helper", true, false, false, vec![])];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // Public uncalled function should NOT be in dead_functions
        assert!(
            !result.dead_functions.iter().any(|f| f.name == "pub_helper"),
            "Public uncalled function should not be in dead_functions"
        );
        // Should be in possibly_dead
        assert!(
            result.possibly_dead.iter().any(|f| f.name == "pub_helper"),
            "Public uncalled function should be in possibly_dead"
        );
    }

    #[test]
    fn test_private_uncalled_is_dead() {
        // A private function that is never called IS dead
        let graph = ProjectCallGraph::new();
        let functions = vec![enriched_func(
            "_private_helper",
            false,
            false,
            false,
            vec![],
        )];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_private_helper"),
            "Private uncalled function should be in dead_functions"
        );
        assert!(
            !result
                .possibly_dead
                .iter()
                .any(|f| f.name == "_private_helper"),
            "Private uncalled function should not be in possibly_dead"
        );
    }

    #[test]
    fn test_uncalled_method_is_possibly_dead_free_fn_stays_dead() {
        // RC6: an uncalled CLASS METHOD (is_method:true), even non-public
        // (`_`-prefixed Node stream override like `Stream._transform`), is
        // reachable via dynamic dispatch / super / reflection / framework
        // runtime, so it must be hedged into `possibly_dead`, NEVER the
        // definitive `dead_functions`. An uncalled non-public FREE FUNCTION
        // (`_unusedFreeFunc`, is_method:false) keeps the confident axis and
        // stays in `dead_functions`. Pinned through BOTH split sites.
        let graph = ProjectCallGraph::new();
        let functions = vec![
            method_func("Stream._transform", false),
            enriched_func("_unusedFreeFunc", false, false, false, vec![]),
        ];

        // Split site #1: dead_code_analysis (call-graph path).
        let result = dead_code_analysis(&graph, &functions, None).unwrap();
        assert!(
            result
                .possibly_dead
                .iter()
                .any(|f| f.name == "Stream._transform"),
            "uncalled method must be in possibly_dead (call-graph path)"
        );
        assert!(
            !result
                .dead_functions
                .iter()
                .any(|f| f.name == "Stream._transform"),
            "uncalled method must NOT be in dead_functions (call-graph path)"
        );
        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_unusedFreeFunc"),
            "uncalled free function must stay in dead_functions (call-graph path)"
        );

        // Split site #2: dead_code_analysis_refcount (default path).
        let ref_counts: HashMap<String, usize> = HashMap::new();
        let result2 = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();
        assert!(
            result2
                .possibly_dead
                .iter()
                .any(|f| f.name == "Stream._transform"),
            "uncalled method must be in possibly_dead (refcount path)"
        );
        assert!(
            !result2
                .dead_functions
                .iter()
                .any(|f| f.name == "Stream._transform"),
            "uncalled method must NOT be in dead_functions (refcount path)"
        );
        assert!(
            result2
                .dead_functions
                .iter()
                .any(|f| f.name == "_unusedFreeFunc"),
            "uncalled free function must stay in dead_functions (refcount path)"
        );
    }

    #[test]
    fn test_trait_method_not_dead() {
        // Trait/interface methods should never be dead (they are implementations)
        let graph = ProjectCallGraph::new();
        let functions = vec![
            enriched_func("serialize", false, true, false, vec![]),
            enriched_func("deserialize", true, true, false, vec![]),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        assert!(
            result.dead_functions.is_empty(),
            "Trait methods should never be in dead_functions"
        );
        assert!(
            result.possibly_dead.is_empty(),
            "Trait methods should never be in possibly_dead"
        );
    }

    #[test]
    fn test_decorated_function_not_dead() {
        // Decorated/annotated functions (e.g. @route, @command) should not be dead
        let graph = ProjectCallGraph::new();
        let functions = vec![
            enriched_func("index", false, false, true, vec!["route"]),
            enriched_func(
                "admin_panel",
                true,
                false,
                true,
                vec!["route", "login_required"],
            ),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        assert!(
            result.dead_functions.is_empty(),
            "Decorated functions should not be in dead_functions"
        );
        assert!(
            result.possibly_dead.is_empty(),
            "Decorated functions should not be in possibly_dead"
        );
    }

    #[test]
    fn test_test_function_not_dead() {
        // Functions marked as is_test should not be dead
        let graph = ProjectCallGraph::new();
        let functions = vec![FunctionRef {
            file: PathBuf::from("test.rs"),
            name: "unusual_test_name".to_string(),
            line: 0,
            signature: String::new(),
            ref_count: 0,
            is_public: false,
            is_test: true,
            is_trait_method: false,
            is_method: false,
            has_decorator: false,
            decorator_names: vec![],
        }];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        assert!(
            result.dead_functions.is_empty(),
            "Test functions should not be dead"
        );
    }

    #[test]
    fn test_mixed_enrichment_filtering() {
        // Test a realistic scenario with mixed public/private/trait/decorated
        let graph = ProjectCallGraph::new();
        let functions = vec![
            // Private uncalled -> dead
            enriched_func("_internal_cache", false, false, false, vec![]),
            // Public uncalled -> possibly_dead
            enriched_func("public_api_method", true, false, false, vec![]),
            // Trait method -> not dead at all
            enriched_func("Serialize.serialize", false, true, false, vec![]),
            // Decorated -> not dead
            enriched_func("handle_index", false, false, true, vec!["get"]),
            // Private + uncalled + no metadata -> dead
            enriched_func("_orphan", false, false, false, vec![]),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // Definitely dead: _internal_cache, _orphan (private, uncalled, no special metadata)
        assert_eq!(
            result.total_dead,
            2,
            "Should have exactly 2 definitely-dead functions, got: {:?}",
            result
                .dead_functions
                .iter()
                .map(|f| &f.name)
                .collect::<Vec<_>>()
        );
        assert!(result
            .dead_functions
            .iter()
            .any(|f| f.name == "_internal_cache"));
        assert!(result.dead_functions.iter().any(|f| f.name == "_orphan"));

        // Possibly dead: public_api_method (public but uncalled)
        assert_eq!(
            result.total_possibly_dead, 1,
            "Should have exactly 1 possibly-dead function"
        );
        assert!(result
            .possibly_dead
            .iter()
            .any(|f| f.name == "public_api_method"));

        // Dead percentage should be based on "definitely dead" only
        // 2 dead out of 5 total = 40%
        assert!(
            (result.dead_percentage - 40.0).abs() < 0.01,
            "Dead percentage should be 40%, got {}",
            result.dead_percentage
        );
    }

    #[test]
    fn test_unenriched_functionref_backwards_compat() {
        // FunctionRef::new() should still work and default all new fields to false/empty
        // Unenriched functions should behave like the old behavior (private by default)
        let func = FunctionRef::new("test.py".into(), "some_func");
        assert!(!func.is_public);
        assert!(!func.is_test);
        assert!(!func.is_trait_method);
        assert!(!func.has_decorator);
        assert!(func.decorator_names.is_empty());
    }

    #[test]
    fn test_dead_code_report_has_possibly_dead_field() {
        let graph = ProjectCallGraph::new();
        let functions = vec![
            enriched_func("pub_func", true, false, false, vec![]),
            enriched_func("_priv_func", false, false, false, vec![]),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // The report should have the possibly_dead and total_possibly_dead fields
        assert_eq!(result.total_possibly_dead, 1);
        assert_eq!(result.total_dead, 1);
        assert_eq!(result.total_functions, 2);
    }

    #[test]
    fn test_called_public_function_not_in_any_dead_list() {
        // If a public function IS called, it should appear in neither list
        let mut graph = ProjectCallGraph::new();
        graph.add_edge(CallEdge {
            src_file: "main.rs".into(),
            src_func: "main".to_string(),
            dst_file: "test.rs".into(), // must match enriched_func's file
            dst_func: "pub_helper".to_string(),
            call_line: None,
        });

        let functions = vec![enriched_func("pub_helper", true, false, false, vec![])];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();
        assert!(result.dead_functions.is_empty());
        assert!(result.possibly_dead.is_empty());
    }

    #[test]
    fn test_old_tests_still_pass_with_new_fields() {
        // Ensure the original test_dead_finds_uncalled logic still works.
        // FunctionRef::new creates unenriched refs (is_public=false),
        // so private uncalled functions should still be dead.
        let graph = create_test_graph();
        let functions = vec![
            FunctionRef::new("main.py".into(), "main"),
            FunctionRef::new("main.py".into(), "process"),
            FunctionRef::new("utils.py".into(), "helper"),
            FunctionRef::new("utils.py".into(), "unused"),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // 'unused' is private (default) and uncalled -> dead
        assert!(result.dead_functions.iter().any(|f| f.name == "unused"));
        // 'main' is an entry point -> not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "main"));
        // 'process' is called -> not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "process"));
        // 'helper' is called -> not dead
        assert!(!result.dead_functions.iter().any(|f| f.name == "helper"));
    }

    // =========================================================================
    // T7-T12: Refcount-based dead code analysis tests
    // (Contracts C1-C3, C4/C5/C9 via refcount path)
    //
    // These tests define expected behavior for dead_code_analysis_refcount().
    // They are #[ignore] until the function is implemented in Phase P3.
    // =========================================================================

    /// T7: A function with ref_count > 1 is rescued (alive) — not dead or possibly dead.
    /// Validates Contract C2: ref_count > 1 means ALIVE.
    #[test]
    fn test_refcount_no_cg_rescues() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("process_data".to_string(), 3);

        let functions = vec![enriched_func("process_data", false, false, false, vec![])];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        assert!(
            !result
                .dead_functions
                .iter()
                .any(|f| f.name == "process_data"),
            "Function with ref_count=3 should NOT be in dead_functions"
        );
        assert!(
            !result
                .possibly_dead
                .iter()
                .any(|f| f.name == "process_data"),
            "Function with ref_count=3 should NOT be in possibly_dead"
        );
    }

    /// T8: A private function with ref_count == 1 (only definition) is dead.
    /// Validates Contract C1: ref_count == 1 means DEAD (unless excluded).
    #[test]
    fn test_refcount_no_cg_confirms_dead() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("_unused_helper".to_string(), 1);

        let functions = vec![enriched_func("_unused_helper", false, false, false, vec![])];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_unused_helper"),
            "_unused_helper with ref_count=1 should be in dead_functions"
        );
    }

    /// T9: Entry points, dunders, and test functions with ref_count == 1 are
    /// still excluded from dead code reports.
    /// Validates Contracts C4 (entry points), C5 (dunders), C7 (test functions).
    #[test]
    fn test_refcount_exclusions_apply() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("main".to_string(), 1);
        ref_counts.insert("__init__".to_string(), 1);
        ref_counts.insert("test_something".to_string(), 1);

        let functions = vec![
            // "main" is an entry point (C4)
            enriched_func("main", false, false, false, vec![]),
            // "__init__" is a dunder method (C5)
            enriched_func("__init__", false, false, false, vec![]),
            // "test_something" matches test prefix pattern (C7 via entry point check)
            enriched_func("test_something", false, false, false, vec![]),
        ];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        assert!(
            result.dead_functions.is_empty(),
            "Entry points, dunders, and test functions should NOT be in dead_functions, got: {:?}",
            result
                .dead_functions
                .iter()
                .map(|f| &f.name)
                .collect::<Vec<_>>()
        );
        assert!(
            result.possibly_dead.is_empty(),
            "Entry points, dunders, and test functions should NOT be in possibly_dead, got: {:?}",
            result
                .possibly_dead
                .iter()
                .map(|f| &f.name)
                .collect::<Vec<_>>()
        );
    }

    /// T10: Short names (< 3 chars) with low refcount are NOT rescued (collision-prone).
    /// Short names with very high refcount (>= 5) ARE rescued (clearly genuine usage).
    #[test]
    fn test_refcount_short_name_low_count_stays_dead() {
        let mut ref_counts = HashMap::new();
        // "fn" has 3 references but is only 2 characters — needs >= 5 to rescue
        ref_counts.insert("fn".to_string(), 3);

        let functions = vec![enriched_func("fn", false, false, false, vec![])];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        assert!(
            result.dead_functions.iter().any(|f| f.name == "fn"),
            "Short name 'fn' (2 chars) with count=3 should be in dead_functions (needs >= 5)"
        );
    }

    /// T10b: Short names with high refcount (>= 5) ARE rescued — clearly not collisions.
    #[test]
    fn test_refcount_short_name_high_count_rescued() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("cn".to_string(), 50);

        let functions = vec![enriched_func("cn", false, false, false, vec![])];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        assert!(
            !result.dead_functions.iter().any(|f| f.name == "cn"),
            "Short name 'cn' (2 chars) with count=50 should NOT be dead (rescued at >= 5)"
        );
        assert!(
            !result.possibly_dead.iter().any(|f| f.name == "cn"),
            "Short name 'cn' (2 chars) with count=50 should NOT be possibly_dead"
        );
    }

    /// T11: Public uncalled functions go to possibly_dead, private uncalled go to dead.
    /// Validates Contract C9: visibility-based classification in refcount path.
    #[test]
    fn test_refcount_public_vs_private() {
        let mut ref_counts = HashMap::new();
        ref_counts.insert("public_func".to_string(), 1);
        ref_counts.insert("_private_func".to_string(), 1);

        let functions = vec![
            // Public, ref_count == 1 -> possibly_dead
            enriched_func("public_func", true, false, false, vec![]),
            // Private, ref_count == 1 -> dead_functions
            enriched_func("_private_func", false, false, false, vec![]),
        ];

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        // Public uncalled -> possibly_dead
        assert!(
            result.possibly_dead.iter().any(|f| f.name == "public_func"),
            "Public function with ref_count=1 should be in possibly_dead"
        );
        assert!(
            !result
                .dead_functions
                .iter()
                .any(|f| f.name == "public_func"),
            "Public function should NOT be in dead_functions"
        );

        // Private uncalled -> dead_functions
        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_private_func"),
            "Private function with ref_count=1 should be in dead_functions"
        );
        assert!(
            !result
                .possibly_dead
                .iter()
                .any(|f| f.name == "_private_func"),
            "Private function should NOT be in possibly_dead"
        );
    }

    /// T12: The original dead_code_analysis() with call graph still works correctly.
    /// Validates backward compatibility: refcount additions must not regress the
    /// existing call-graph-based dead code detection.
    #[test]
    fn test_backward_compat_cg() {
        let graph = create_test_graph();
        let functions = vec![
            FunctionRef::new("main.py".into(), "main"),
            FunctionRef::new("main.py".into(), "process"),
            FunctionRef::new("utils.py".into(), "helper"),
            FunctionRef::new("utils.py".into(), "_orphaned"),
            enriched_func("public_orphan", true, false, false, vec![]),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // 'main' is entry point -> not dead
        assert!(
            !result.dead_functions.iter().any(|f| f.name == "main"),
            "main should not be dead (entry point)"
        );
        // 'process' is called -> not dead
        assert!(
            !result.dead_functions.iter().any(|f| f.name == "process"),
            "process should not be dead (called)"
        );
        // 'helper' is called -> not dead
        assert!(
            !result.dead_functions.iter().any(|f| f.name == "helper"),
            "helper should not be dead (called)"
        );
        // '_orphaned' is private, not called -> dead
        assert!(
            result.dead_functions.iter().any(|f| f.name == "_orphaned"),
            "_orphaned should be in dead_functions (private, uncalled)"
        );
        // 'public_orphan' is public, not called -> possibly_dead
        assert!(
            result
                .possibly_dead
                .iter()
                .any(|f| f.name == "public_orphan"),
            "public_orphan should be in possibly_dead (public, uncalled)"
        );

        // Verify stats
        assert_eq!(
            result.total_dead, 1,
            "Should have 1 definitely dead function"
        );
        assert_eq!(
            result.total_possibly_dead, 1,
            "Should have 1 possibly dead function"
        );
        assert_eq!(result.total_functions, 5, "Should have 5 total functions");
        // 1 dead out of 5 = 20%
        assert!(
            (result.dead_percentage - 20.0).abs() < 0.01,
            "Dead percentage should be 20%, got {}",
            result.dead_percentage
        );
    }

    // =========================================================================
    // Tests for enriched output fields (line, signature, ref_count)
    // =========================================================================

    #[test]
    fn test_functionref_has_line_field() {
        // FunctionRef should have a line field for the start line number
        let func = FunctionRef::new("test.py".into(), "my_func");
        // Default should be 0 (unknown)
        assert_eq!(func.line, 0, "Default line should be 0");

        // Should be settable
        let func_with_line = FunctionRef { line: 42, ..func };
        assert_eq!(func_with_line.line, 42);
    }

    #[test]
    fn test_functionref_has_signature_field() {
        // FunctionRef should have a signature field
        let func = FunctionRef::new("test.py".into(), "my_func");
        // Default should be empty string
        assert!(
            func.signature.is_empty(),
            "Default signature should be empty"
        );

        // Should be settable
        let func_with_sig = FunctionRef {
            signature: "def my_func(x, y)".to_string(),
            ..func
        };
        assert_eq!(func_with_sig.signature, "def my_func(x, y)");
    }

    #[test]
    fn test_functionref_line_serializes_in_json() {
        // FunctionRef should include 'line' in its JSON serialization
        let func = FunctionRef {
            file: PathBuf::from("test.py"),
            name: "my_func".to_string(),
            line: 42,
            signature: String::new(),
            ref_count: 0,
            is_public: false,
            is_test: false,
            is_trait_method: false,
            is_method: false,
            has_decorator: false,
            decorator_names: vec![],
        };

        let json = serde_json::to_string(&func).unwrap();
        assert!(
            json.contains("\"line\":42"),
            "JSON should contain line field, got: {}",
            json
        );
    }

    #[test]
    fn test_functionref_signature_serializes_in_json() {
        // FunctionRef should include 'signature' in its JSON serialization when non-empty
        let func = FunctionRef {
            file: PathBuf::from("test.py"),
            name: "my_func".to_string(),
            line: 10,
            signature: "def my_func(x: int, y: int) -> int".to_string(),
            ref_count: 0,
            is_public: false,
            is_test: false,
            is_trait_method: false,
            is_method: false,
            has_decorator: false,
            decorator_names: vec![],
        };

        let json = serde_json::to_string(&func).unwrap();
        assert!(
            json.contains("\"signature\""),
            "JSON should contain signature field, got: {}",
            json
        );
        assert!(
            json.contains("my_func(x: int"),
            "JSON should contain signature content"
        );
    }

    #[test]
    fn test_collect_all_functions_carries_line_number() {
        // collect_all_functions should populate the line field from FunctionInfo.line_number
        use crate::types::{FunctionInfo, IntraFileCallGraph, Language, ModuleInfo};

        let module_infos = vec![(
            PathBuf::from("test.py"),
            ModuleInfo {
                file_path: PathBuf::from("test.py"),
                language: Language::Python,
                docstring: None,
                imports: vec![],
                functions: vec![FunctionInfo {
                    name: "my_func".to_string(),
                    params: vec!["x".to_string(), "y".to_string()],
                    return_type: Some("int".to_string()),
                    docstring: None,
                    is_method: false,
                    is_async: false,
                    decorators: vec![],
                    visibility: None,
                    line_number: 42,
                    line_end: 42,
                    state_mutability: None,
                }],
                classes: vec![],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )];

        let functions = collect_all_functions(&module_infos);
        assert_eq!(functions.len(), 1);
        assert_eq!(
            functions[0].line, 42,
            "line should be populated from FunctionInfo.line_number"
        );
    }

    #[test]
    fn test_collect_all_functions_builds_signature() {
        // collect_all_functions should build a signature string from params and return_type
        use crate::types::{FunctionInfo, IntraFileCallGraph, Language, ModuleInfo};

        let module_infos = vec![(
            PathBuf::from("test.py"),
            ModuleInfo {
                file_path: PathBuf::from("test.py"),
                language: Language::Python,
                docstring: None,
                imports: vec![],
                functions: vec![FunctionInfo {
                    name: "calculate".to_string(),
                    params: vec!["x".to_string(), "y".to_string()],
                    return_type: Some("int".to_string()),
                    docstring: None,
                    is_method: false,
                    is_async: false,
                    decorators: vec![],
                    visibility: None,
                    line_number: 10,
                    line_end: 10,
                    state_mutability: None,
                }],
                classes: vec![],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )];

        let functions = collect_all_functions(&module_infos);
        assert_eq!(functions.len(), 1);
        // Signature should contain the function name and parameters
        assert!(
            !functions[0].signature.is_empty(),
            "Signature should be populated, got empty"
        );
        assert!(
            functions[0].signature.contains("calculate"),
            "Signature should contain function name, got: {}",
            functions[0].signature
        );
        assert!(
            functions[0].signature.contains("x"),
            "Signature should contain parameter names, got: {}",
            functions[0].signature
        );
    }

    #[test]
    fn test_functionref_new_defaults_line_and_signature() {
        // FunctionRef::new should default line to 0 and signature to empty
        let func = FunctionRef::new("test.py".into(), "func");
        assert_eq!(func.line, 0);
        assert_eq!(func.signature, "");
    }

    // =========================================================================
    // Tests for is_trait_or_interface: multi-language interface detection
    // =========================================================================

    /// Helper to create a ClassInfo with given name, bases, and decorators
    fn make_class(name: &str, bases: Vec<&str>, decorators: Vec<&str>) -> crate::types::ClassInfo {
        crate::types::ClassInfo {
            name: name.to_string(),
            bases: bases.into_iter().map(|s| s.to_string()).collect(),
            docstring: None,
            methods: vec![],
            fields: vec![],
            decorators: decorators.into_iter().map(|s| s.to_string()).collect(),
            line_number: 1,
            line_end: 1,
            kind: None,
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn test_is_trait_or_interface_rust_trait_decorator() {
        // Rust traits extracted with "trait" decorator should be detected
        use crate::types::Language;
        let class = make_class("Iterator", vec![], vec!["trait"]);
        assert!(
            is_trait_or_interface(&class, Language::Rust),
            "Rust class with 'trait' decorator should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_rust_plain_struct_not_trait() {
        // A plain Rust struct should NOT be detected as an interface
        use crate::types::Language;
        let class = make_class("MyStruct", vec![], vec![]);
        assert!(
            !is_trait_or_interface(&class, Language::Rust),
            "Plain Rust struct should not be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_go_interface_suffix() {
        // Go interfaces often end with "Interface" suffix or "er" suffix
        use crate::types::Language;
        let class = make_class("Reader", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Go),
            "Go class named 'Reader' (single-method interface pattern) should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_go_non_interface() {
        // A Go struct with a regular name should NOT be detected
        use crate::types::Language;
        let class = make_class("Config", vec![], vec![]);
        assert!(
            !is_trait_or_interface(&class, Language::Go),
            "Go class named 'Config' should not be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_go_interface_decorator() {
        // Go interface explicitly tagged with decorator
        use crate::types::Language;
        let class = make_class("Handler", vec![], vec!["interface"]);
        assert!(
            is_trait_or_interface(&class, Language::Go),
            "Go class with 'interface' decorator should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_swift_protocol_decorator() {
        // Swift protocols tagged with "protocol" decorator should be detected
        use crate::types::Language;
        let class = make_class("Codable", vec![], vec!["protocol"]);
        assert!(
            is_trait_or_interface(&class, Language::Swift),
            "Swift class with 'protocol' decorator should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_swift_protocol_suffix() {
        // Swift protocols with "Protocol" suffix
        use crate::types::Language;
        let class = make_class("ViewProtocol", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Swift),
            "Swift class ending in 'Protocol' should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_swift_delegate_suffix() {
        // Swift delegates (commonly protocols) with "Delegate" suffix
        use crate::types::Language;
        let class = make_class("UITableViewDelegate", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Swift),
            "Swift class ending in 'Delegate' should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_swift_datasource_suffix() {
        // Swift data source protocols with "DataSource" suffix
        use crate::types::Language;
        let class = make_class("UITableViewDataSource", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Swift),
            "Swift class ending in 'DataSource' should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_scala_trait_decorator() {
        // Scala traits tagged with "trait" decorator
        use crate::types::Language;
        let class = make_class("Ordered", vec![], vec!["trait"]);
        assert!(
            is_trait_or_interface(&class, Language::Scala),
            "Scala class with 'trait' decorator should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_php_interface_decorator() {
        // PHP interfaces tagged with "interface" decorator by extractor
        use crate::types::Language;
        let class = make_class("Countable", vec![], vec!["interface"]);
        assert!(
            is_trait_or_interface(&class, Language::Php),
            "PHP class with 'interface' decorator should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_php_trait_decorator() {
        // PHP traits tagged with "trait" decorator by extractor
        use crate::types::Language;
        let class = make_class("Loggable", vec![], vec!["trait"]);
        assert!(
            is_trait_or_interface(&class, Language::Php),
            "PHP class with 'trait' decorator should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_ruby_module_mixin() {
        // Ruby modules used as mixins - naming convention with "able" suffix
        use crate::types::Language;
        let class = make_class("Comparable", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Ruby),
            "Ruby class named 'Comparable' should be detected as interface/mixin"
        );
    }

    #[test]
    fn test_is_trait_or_interface_ruby_module_decorator() {
        // Ruby module explicitly tagged with decorator
        use crate::types::Language;
        let class = make_class("Serializable", vec![], vec!["module"]);
        assert!(
            is_trait_or_interface(&class, Language::Ruby),
            "Ruby class with 'module' decorator should be detected as interface/mixin"
        );
    }

    #[test]
    fn test_is_trait_or_interface_typescript_interface_decorator() {
        // TypeScript interface tagged with decorator (already partly handled)
        use crate::types::Language;
        let class = make_class("UserService", vec![], vec!["interface"]);
        assert!(
            is_trait_or_interface(&class, Language::TypeScript),
            "TypeScript class with 'interface' decorator should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_java_i_prefix() {
        // Java interface with IFoo naming convention (already handled)
        use crate::types::Language;
        let class = make_class("IRepository", vec![], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Java),
            "Java class with I-prefix should be detected as interface"
        );
    }

    #[test]
    fn test_is_trait_or_interface_python_protocol_base() {
        // Python typing.Protocol base class (already handled)
        use crate::types::Language;
        let class = make_class("Comparable", vec!["Protocol"], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Python),
            "Python class with Protocol base should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_python_abc_base() {
        // Python ABC base class (already handled)
        use crate::types::Language;
        let class = make_class("AbstractHandler", vec!["ABC"], vec![]);
        assert!(
            is_trait_or_interface(&class, Language::Python),
            "Python class with ABC base should be detected"
        );
    }

    #[test]
    fn test_is_trait_or_interface_collect_functions_marks_trait_methods() {
        // Integration test: collect_all_functions should mark methods of trait classes
        use crate::types::{ClassInfo, FunctionInfo, IntraFileCallGraph, Language, ModuleInfo};

        let module_infos = vec![(
            PathBuf::from("lib.php"),
            ModuleInfo {
                file_path: PathBuf::from("lib.php"),
                language: Language::Php,
                docstring: None,
                imports: vec![],
                functions: vec![],
                classes: vec![ClassInfo {
                    name: "Cacheable".to_string(),
                    bases: vec![],
                    docstring: None,
                    methods: vec![FunctionInfo {
                        name: "cache_key".to_string(),
                        params: vec![],
                        return_type: Some("string".to_string()),
                        docstring: None,
                        is_method: true,
                        is_async: false,
                        decorators: vec![],
                        visibility: None,
                        line_number: 5,
                        line_end: 5,
                        state_mutability: None,
                    }],
                    fields: vec![],
                    decorators: vec!["interface".to_string()],
                    line_number: 3,
                    line_end: 3,
                    kind: None,
                    modifiers: Vec::new(),
                    events: Vec::new(),
                    errors: Vec::new(),
                }],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )];

        let functions = collect_all_functions(&module_infos);
        assert_eq!(functions.len(), 1);
        assert!(
            functions[0].is_trait_method,
            "Methods of a PHP interface class should have is_trait_method=true"
        );
    }

    // =========================================================================
    // Tests for framework entry point detection (false positive reduction)
    // =========================================================================

    #[test]
    fn test_framework_entry_file_nextjs() {
        use crate::types::Language;
        // Next.js App Router conventions
        assert!(
            is_framework_entry_file(Path::new("app/dashboard/page.tsx"), Language::TypeScript),
            "page.tsx should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/layout.tsx"), Language::TypeScript),
            "layout.tsx should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/api/users/route.ts"), Language::TypeScript),
            "route.ts should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/loading.tsx"), Language::TypeScript),
            "loading.tsx should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/error.tsx"), Language::TypeScript),
            "error.tsx should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/not-found.tsx"), Language::TypeScript),
            "not-found.tsx should be detected as Next.js framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("middleware.ts"), Language::TypeScript),
            "middleware.ts should be detected as Next.js framework entry"
        );
    }

    #[test]
    fn test_framework_entry_file_django() {
        use crate::types::Language;
        assert!(
            is_framework_entry_file(Path::new("myapp/views.py"), Language::Python),
            "views.py should be detected as Django framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("myapp/models.py"), Language::Python),
            "models.py should be detected as Django framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("myapp/admin.py"), Language::Python),
            "admin.py should be detected as Django framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("myapp/serializers.py"), Language::Python),
            "serializers.py should be detected as Django framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("myapp/tasks.py"), Language::Python),
            "tasks.py should be detected as Celery framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("conftest.py"), Language::Python),
            "conftest.py should be detected as pytest framework entry"
        );
    }

    #[test]
    fn test_framework_entry_file_rails() {
        use crate::types::Language;
        assert!(
            is_framework_entry_file(
                Path::new("app/controllers/users_controller.rb"),
                Language::Ruby
            ),
            "*_controller.rb in controllers/ should be detected as Rails framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("app/models/user.rb"), Language::Ruby),
            "*.rb in models/ should be detected as Rails framework entry"
        );
        assert!(
            is_framework_entry_file(
                Path::new("app/helpers/application_helper.rb"),
                Language::Ruby
            ),
            "*_helper.rb in helpers/ should be detected as Rails framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("config/routes.rb"), Language::Ruby),
            "routes.rb should be detected as Rails framework entry"
        );
    }

    #[test]
    fn test_framework_entry_file_spring() {
        use crate::types::Language;
        assert!(
            is_framework_entry_file(Path::new("src/UserController.java"), Language::Java),
            "*Controller.java should be detected as Spring framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("src/UserService.java"), Language::Java),
            "*Service.java should be detected as Spring framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("src/UserRepository.java"), Language::Java),
            "*Repository.java should be detected as Spring framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("src/AppConfiguration.java"), Language::Java),
            "*Configuration.java should be detected as Spring framework entry"
        );
        // Kotlin equivalents
        assert!(
            is_framework_entry_file(Path::new("src/UserController.kt"), Language::Kotlin),
            "*Controller.kt should be detected as Spring/Kotlin framework entry"
        );
        // Android
        assert!(
            is_framework_entry_file(Path::new("src/MainActivity.java"), Language::Java),
            "*Activity.java should be detected as Android framework entry"
        );
        assert!(
            is_framework_entry_file(Path::new("src/HomeFragment.kt"), Language::Kotlin),
            "*Fragment.kt should be detected as Android/Kotlin framework entry"
        );
    }

    #[test]
    fn test_framework_entry_file_non_framework() {
        use crate::types::Language;
        assert!(
            !is_framework_entry_file(Path::new("src/utils.ts"), Language::TypeScript),
            "utils.ts should NOT be detected as framework entry"
        );
        assert!(
            !is_framework_entry_file(Path::new("src/helpers.py"), Language::Python),
            "helpers.py should NOT be detected as framework entry"
        );
        assert!(
            !is_framework_entry_file(Path::new("lib/parser.rb"), Language::Ruby),
            "parser.rb should NOT be detected as framework entry"
        );
        assert!(
            !is_framework_entry_file(Path::new("src/Utils.java"), Language::Java),
            "Utils.java should NOT be detected as framework entry"
        );
        assert!(
            !is_framework_entry_file(Path::new("src/random.go"), Language::Go),
            "random.go should NOT be detected as framework entry"
        );
    }

    #[test]
    fn test_framework_directive_use_server() {
        // Create a temp file with 'use server' directive
        let dir = std::env::temp_dir().join("tldr_test_framework_directive");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("actions.ts");
        std::fs::write(
            &file,
            "'use server'\n\nexport async function createUser() {}\n",
        )
        .unwrap();

        assert!(
            has_framework_directive(&file),
            "File with 'use server' directive should be detected"
        );

        // Also test double-quote variant
        let file2 = dir.join("actions2.tsx");
        std::fs::write(
            &file2,
            "\"use server\";\n\nexport async function deleteUser() {}\n",
        )
        .unwrap();

        assert!(
            has_framework_directive(&file2),
            "File with \"use server\"; directive should be detected"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_framework_directive_use_client() {
        let dir = std::env::temp_dir().join("tldr_test_framework_directive_client");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("component.tsx");
        std::fs::write(
            &file,
            "'use client'\n\nimport React from 'react';\n\nexport function Button() {}\n",
        )
        .unwrap();

        assert!(
            has_framework_directive(&file),
            "File with 'use client' directive should be detected"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_framework_directive_absent() {
        let dir = std::env::temp_dir().join("tldr_test_framework_directive_absent");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("utils.ts");
        std::fs::write(
            &file,
            "import { helper } from './helper';\n\nexport function doWork() {}\n",
        )
        .unwrap();

        assert!(
            !has_framework_directive(&file),
            "File without framework directive should NOT be detected"
        );

        // Non-JS file should not be detected
        let py_file = dir.join("views.py");
        std::fs::write(&py_file, "'use server'\ndef view(): pass\n").unwrap();

        assert!(
            !has_framework_directive(&py_file),
            "Non-JS/TS file should NOT be detected even with directive-like content"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_functions_skips_framework_entries() {
        // Integration test: public functions from page.tsx should have has_decorator=true
        // so they are excluded from dead code analysis
        use crate::types::{FunctionInfo, IntraFileCallGraph, Language, ModuleInfo};

        let module_infos = vec![(
            PathBuf::from("app/dashboard/page.tsx"),
            ModuleInfo {
                file_path: PathBuf::from("app/dashboard/page.tsx"),
                language: Language::TypeScript,
                docstring: None,
                imports: vec![],
                functions: vec![
                    FunctionInfo {
                        name: "DashboardPage".to_string(),
                        params: vec![],
                        return_type: Some("JSX.Element".to_string()),
                        docstring: None,
                        is_method: false,
                        is_async: false,
                        decorators: vec![],
                        visibility: None,
                        line_number: 5,
                        line_end: 5,
                        state_mutability: None,
                    },
                    FunctionInfo {
                        name: "generateMetadata".to_string(),
                        params: vec![],
                        return_type: Some("Metadata".to_string()),
                        docstring: None,
                        is_method: false,
                        is_async: true,
                        decorators: vec![],
                        visibility: None,
                        line_number: 20,
                        line_end: 20,
                        state_mutability: None,
                    },
                    // Private function should NOT get framework treatment
                    FunctionInfo {
                        name: "_privateHelper".to_string(),
                        params: vec![],
                        return_type: None,
                        docstring: None,
                        is_method: false,
                        is_async: false,
                        decorators: vec![],
                        visibility: None,
                        line_number: 30,
                        line_end: 30,
                        state_mutability: None,
                    },
                ],
                classes: vec![],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )];

        let functions = collect_all_functions(&module_infos);
        assert_eq!(functions.len(), 3);

        // DashboardPage is public (no leading underscore) and in a framework entry file
        // -> should have has_decorator = true (framework entry treatment)
        let dashboard = functions
            .iter()
            .find(|f| f.name == "DashboardPage")
            .unwrap();
        assert!(
            dashboard.has_decorator,
            "Public function in page.tsx should have has_decorator=true (framework entry)"
        );
        assert!(dashboard.is_public, "DashboardPage should be public");

        // generateMetadata is also public in a framework entry file
        let metadata = functions
            .iter()
            .find(|f| f.name == "generateMetadata")
            .unwrap();
        assert!(
            metadata.has_decorator,
            "Public function in page.tsx should have has_decorator=true (framework entry)"
        );

        // _privateHelper is private, so framework entry treatment should NOT apply
        let private_fn = functions
            .iter()
            .find(|f| f.name == "_privateHelper")
            .unwrap();
        assert!(
            !private_fn.has_decorator,
            "Private function in page.tsx should NOT have has_decorator=true"
        );
        assert!(!private_fn.is_public, "_privateHelper should not be public");

        // Now verify that public framework entry functions are NOT reported as dead
        let graph = ProjectCallGraph::new();
        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        // DashboardPage and generateMetadata should NOT be in possibly_dead
        assert!(
            !result
                .possibly_dead
                .iter()
                .any(|f| f.name == "DashboardPage"),
            "DashboardPage (framework entry) should not be in possibly_dead"
        );
        assert!(
            !result
                .possibly_dead
                .iter()
                .any(|f| f.name == "generateMetadata"),
            "generateMetadata (framework entry) should not be in possibly_dead"
        );

        // _privateHelper SHOULD be in dead_functions (private, uncalled, no framework treatment)
        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_privateHelper"),
            "_privateHelper should be in dead_functions"
        );
    }

    // =====================================================================
    // fix-C5-4 (v0.5.0 AUDIT-FIX): Lua metamethods (__index / __add / etc.)
    // are invoked implicitly by the VM and must never be reported as dead.
    // They start with `__` but do NOT end with `__`, so the Python-dunder
    // guard (`starts_with("__") && ends_with("__")`) does not catch them.
    // =====================================================================

    /// RED→GREEN: a Lua metamethod that is uncalled by any explicit caller
    /// must not appear in dead_functions (call-graph path).
    #[test]
    fn test_dead_excludes_lua_metamethods_callgraph() {
        let graph = ProjectCallGraph::new(); // Empty graph: nothing is "called".
        let functions = vec![
            FunctionRef::new("vec.lua".into(), "Vec.__index"),
            FunctionRef::new("vec.lua".into(), "Vec.__add"),
            FunctionRef::new("vec.lua".into(), "Vec.__newindex"),
            FunctionRef::new("vec.lua".into(), "mt:__tostring"),
            FunctionRef::new("vec.lua".into(), "__eq"),
            // Control: a genuinely-private, uncalled helper SHOULD be dead.
            FunctionRef::new("vec.lua".into(), "_internal_helper"),
        ];

        let result = dead_code_analysis(&graph, &functions, None).unwrap();

        for mm in ["__index", "__add", "__newindex", "__tostring", "__eq"] {
            assert!(
                !result
                    .dead_functions
                    .iter()
                    .chain(result.possibly_dead.iter())
                    .any(|f| f.name.ends_with(mm)),
                "Lua metamethod {mm} must not be reported as dead/possibly-dead, got dead={:?} possibly={:?}",
                result.dead_functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
                result.possibly_dead.iter().map(|f| &f.name).collect::<Vec<_>>(),
            );
        }
        // Control still flagged.
        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_internal_helper"),
            "a real private uncalled helper must still be flagged dead"
        );
    }

    /// RED→GREEN: same exclusion must hold on the refcount path. Use
    /// `ref_count = 1` (definition only) so refcount rescue does not apply.
    #[test]
    fn test_dead_excludes_lua_metamethods_refcount() {
        let functions = vec![
            FunctionRef::new("vec.lua".into(), "Vec.__index"),
            FunctionRef::new("vec.lua".into(), "Vec.__add"),
            FunctionRef::new("mt:__call".into(), "mt:__call"),
            FunctionRef::new("vec.lua".into(), "_internal_helper"),
        ];
        // Every name has refcount 1 (definition only) — no rescue.
        let mut ref_counts: HashMap<String, usize> = HashMap::new();
        ref_counts.insert("__index".to_string(), 1);
        ref_counts.insert("__add".to_string(), 1);
        ref_counts.insert("__call".to_string(), 1);
        ref_counts.insert("_internal_helper".to_string(), 1);

        let result = dead_code_analysis_refcount(&functions, &ref_counts, None).unwrap();

        for mm in ["__index", "__add", "__call"] {
            assert!(
                !result
                    .dead_functions
                    .iter()
                    .chain(result.possibly_dead.iter())
                    .any(|f| f.name.ends_with(mm)),
                "Lua metamethod {mm} must not be reported as dead on the refcount path"
            );
        }
        assert!(
            result
                .dead_functions
                .iter()
                .any(|f| f.name == "_internal_helper"),
            "a real private uncalled helper must still be flagged dead (refcount path)"
        );
    }

    /// The metamethod predicate must reject lookalikes that are NOT real
    /// metamethods (e.g. a user function `__myhelper`), so we don't silently
    /// rescue arbitrary `__`-prefixed private functions.
    #[test]
    fn test_is_lua_metamethod_precise() {
        assert!(is_lua_metamethod("__index"));
        assert!(is_lua_metamethod("__newindex"));
        assert!(is_lua_metamethod("__add"));
        assert!(is_lua_metamethod("__concat"));
        assert!(is_lua_metamethod("__tostring"));
        assert!(is_lua_metamethod("__close")); // Lua 5.4 to-be-closed
        // Not metamethods:
        assert!(!is_lua_metamethod("__myhelper"));
        assert!(!is_lua_metamethod("__init__")); // Python dunder, handled elsewhere
        assert!(!is_lua_metamethod("helper"));
        assert!(!is_lua_metamethod("_private"));
    }

    // =====================================================================
    // fix-R7-cl6 (v0.5.0 CLOSEOUT) characterization tests
    // =====================================================================

    /// Build a single-file `ModuleInfo` whose one class carries the given
    /// methods, for `collect_all_functions` + dead-analysis round-trips.
    fn module_with_class(
        file: &str,
        language: crate::types::Language,
        class_name: &str,
        class_kind: Option<&str>,
        methods: Vec<crate::types::FunctionInfo>,
    ) -> Vec<(PathBuf, crate::types::ModuleInfo)> {
        use crate::types::{ClassInfo, IntraFileCallGraph, ModuleInfo};
        let class = ClassInfo {
            name: class_name.to_string(),
            bases: vec![],
            docstring: None,
            methods,
            fields: vec![],
            decorators: vec![],
            line_number: 1,
            line_end: 1,
            kind: class_kind.map(|s| s.to_string()),
            modifiers: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
        };
        vec![(
            PathBuf::from(file),
            ModuleInfo {
                file_path: PathBuf::from(file),
                language,
                docstring: None,
                imports: vec![],
                functions: vec![],
                classes: vec![class],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )]
    }

    fn method(name: &str, visibility: Option<&str>, decorators: Vec<&str>) -> crate::types::FunctionInfo {
        crate::types::FunctionInfo {
            name: name.to_string(),
            params: vec![],
            return_type: None,
            docstring: None,
            is_method: true,
            is_async: false,
            decorators: decorators.into_iter().map(|s| s.to_string()).collect(),
            visibility: visibility.map(|s| s.to_string()),
            line_number: 2,
            line_end: 3,
            state_mutability: None,
        }
    }

    /// `has_invocation_decorator` ignores purely structural method-kind /
    /// visibility markers but still reports genuine annotations.
    #[test]
    fn test_has_invocation_decorator_ignores_structural_markers() {
        // Structural kind/visibility tags → NOT an invocation decorator.
        assert!(!has_invocation_decorator(&["static".to_string()]));
        assert!(!has_invocation_decorator(&["method".to_string()]));
        assert!(!has_invocation_decorator(&["self".to_string()]));
        assert!(!has_invocation_decorator(&[
            "public".to_string(),
            "static".to_string()
        ]));
        // Genuine annotations / polymorphic markers → IS an invocation decorator.
        assert!(has_invocation_decorator(&["Override".to_string()]));
        assert!(has_invocation_decorator(&["route".to_string()]));
        assert!(has_invocation_decorator(&["virtual".to_string()])); // vtable dispatch
        assert!(has_invocation_decorator(&["abstract".to_string()]));
        // Mixed: a real annotation alongside a structural tag still counts.
        assert!(has_invocation_decorator(&[
            "static".to_string(),
            "pytest.fixture".to_string()
        ]));
    }

    /// REGRESSION (48316dd): Lua table methods (`function M.foo()`) are
    /// extracted as class methods tagged with a structural `static`/`method`
    /// decorator. Those must NOT rescue them from dead analysis — an uncalled
    /// `M.deadOne` must surface as possibly_dead.
    #[test]
    fn test_lua_table_method_with_structural_decorator_not_rescued() {
        use crate::types::Language;
        let modules = module_with_class(
            "lib.lua",
            Language::Lua,
            "M",
            None,
            vec![
                method("deadOne", None, vec!["static"]),
                method("deadTwo", None, vec!["static"]),
            ],
        );
        let funcs = collect_all_functions(&modules);
        // The structural `static` marker must not have set has_decorator.
        assert!(
            funcs.iter().all(|f| !f.has_decorator),
            "Lua table methods carry only a structural `static`/`method` tag; \
             has_decorator must be false so they are analyzed"
        );
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        let flagged: Vec<&str> = report
            .possibly_dead
            .iter()
            .chain(report.dead_functions.iter())
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            flagged.contains(&"M.deadOne") && flagged.contains(&"M.deadTwo"),
            "uncalled Lua table methods must be flagged; got {:?}",
            flagged
        );
    }

    /// Solidity `external` functions are caller-visible API → at most
    /// possibly_dead, never the definitive `dead_functions` bucket.
    #[test]
    fn test_solidity_external_is_public_not_definitive_dead() {
        use crate::types::Language;
        assert!(
            explicit_or_inferred_visibility(Some("external"), "transfer", Language::Solidity, false, &[]),
            "Solidity `external` must be treated as public"
        );
        let modules = module_with_class(
            "T.sol",
            Language::Solidity,
            "Token",
            Some("contract"),
            vec![method("orphanExternal", Some("external"), vec![])],
        );
        let funcs = collect_all_functions(&modules);
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        assert!(
            report.dead_functions.is_empty(),
            "an uncalled external fn must not be in the DEFINITIVE dead bucket; got {:?}",
            report.dead_functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert!(
            report.possibly_dead.iter().any(|f| f.name == "Token.orphanExternal"),
            "an uncalled external fn must be possibly_dead; got {:?}",
            report.possibly_dead.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    /// Solidity interface members (ABI signatures) are never dead — excluded via
    /// `ClassInfo.kind == Some("interface")` (the extractor sets `kind`, not a
    /// decorator).
    #[test]
    fn test_solidity_interface_methods_excluded() {
        use crate::types::Language;
        let iface = make_class("IERC20", vec![], vec![]);
        let mut iface = iface;
        iface.kind = Some("interface".to_string());
        assert!(
            is_trait_or_interface(&iface, Language::Solidity),
            "Solidity interface (kind=interface) must be treated as interface"
        );
        // contract/library kinds are NOT auto-excluded.
        let mut contract = make_class("Token", vec![], vec![]);
        contract.kind = Some("contract".to_string());
        assert!(!is_trait_or_interface(&contract, Language::Solidity));

        let modules = module_with_class(
            "I.sol",
            Language::Solidity,
            "IERC20",
            Some("interface"),
            vec![method("send", Some("external"), vec![])],
        );
        let funcs = collect_all_functions(&modules);
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        let flagged: Vec<&str> = report
            .possibly_dead
            .iter()
            .chain(report.dead_functions.iter())
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            !flagged.contains(&"IERC20.send"),
            "interface member must not be flagged dead; got {:?}",
            flagged
        );
    }

    /// Solidity `receive`/`fallback` are EVM entry points → excluded entirely.
    #[test]
    fn test_solidity_receive_fallback_excluded() {
        use crate::types::Language;
        assert!(is_solidity_evm_entry_point("receive", Language::Solidity));
        assert!(is_solidity_evm_entry_point("fallback", Language::Solidity));
        // Same names in another language are NOT EVM entry points.
        assert!(!is_solidity_evm_entry_point("receive", Language::Python));

        let modules = module_with_class(
            "W.sol",
            Language::Solidity,
            "WETH",
            Some("contract"),
            vec![
                method("receive", Some("external"), vec![]),
                method("fallback", Some("external"), vec![]),
            ],
        );
        let funcs = collect_all_functions(&modules);
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        let flagged: Vec<&str> = report
            .possibly_dead
            .iter()
            .chain(report.dead_functions.iter())
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            !flagged.contains(&"WETH.receive") && !flagged.contains(&"WETH.fallback"),
            "EVM entry points must be excluded entirely; got {:?}",
            flagged
        );
    }

    /// A Python method literally named `receive` must STILL be dead-checkable
    /// (the EVM guard is Solidity-gated, no cross-language collision).
    #[test]
    fn test_non_solidity_receive_still_analyzed() {
        use crate::types::Language;
        let modules = module_with_class(
            "sock.py",
            Language::Python,
            "Socket",
            None,
            vec![method("receive", None, vec![])],
        );
        let funcs = collect_all_functions(&modules);
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        assert!(
            report
                .possibly_dead
                .iter()
                .any(|f| f.name == "Socket.receive"),
            "a non-Solidity `receive` must remain dead-checkable"
        );
    }

    /// Rust trait-impl methods (tagged `"trait_impl"` by the extractor) are
    /// treated as trait methods → excluded from dead analysis, even though the
    /// receiver struct is not itself a trait. An inherent method on the same
    /// struct stays dead-checkable.
    #[test]
    fn test_rust_trait_impl_method_is_trait_method() {
        use crate::types::Language;
        let modules = module_with_class(
            "glob.rs",
            Language::Rust,
            "Glob",
            None,
            vec![
                method("eq", None, vec!["trait_impl"]),     // impl PartialEq for Glob
                method("inherent_helper", None, vec![]),    // inherent impl
            ],
        );
        let funcs = collect_all_functions(&modules);
        let eq = funcs.iter().find(|f| f.name == "Glob.eq").unwrap();
        assert!(
            eq.is_trait_method,
            "a `trait_impl`-tagged method must be marked is_trait_method"
        );
        let inherent = funcs
            .iter()
            .find(|f| f.name == "Glob.inherent_helper")
            .unwrap();
        assert!(
            !inherent.is_trait_method,
            "an inherent method must NOT be marked is_trait_method"
        );
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        let flagged: Vec<&str> = report
            .possibly_dead
            .iter()
            .chain(report.dead_functions.iter())
            .map(|f| f.name.as_str())
            .collect();
        assert!(
            !flagged.contains(&"Glob.eq"),
            "trait-impl method `eq` must not be flagged dead; got {:?}",
            flagged
        );
    }

    /// Qualified/unqualified dedup: a method surfaced both as a bare top-level
    /// `info.functions` entry AND a `Class.method` entry (same name+line — the
    /// Java/C#/Kotlin/Scala recursive-extractor double-emit) is counted ONCE
    /// (the qualified form). A genuine free function sharing a name but at a
    /// DIFFERENT line is preserved.
    #[test]
    fn test_qualified_unqualified_method_deduped() {
        use crate::types::{FunctionInfo, IntraFileCallGraph, Language, ModuleInfo};
        let bare = |name: &str, line: u32| FunctionInfo {
            name: name.to_string(),
            params: vec![],
            return_type: None,
            docstring: None,
            is_method: false,
            is_async: false,
            decorators: vec![],
            visibility: None,
            line_number: line,
            line_end: line,
            state_mutability: None,
        };
        let modules = vec![(
            PathBuf::from("Owner.java"),
            ModuleInfo {
                file_path: PathBuf::from("Owner.java"),
                language: Language::Java,
                docstring: None,
                imports: vec![],
                // double-emit: getAddress@69 (also a class method) + a genuine
                // free function freeFn@200 that shares NO line with any method.
                functions: vec![bare("getAddress", 69), bare("freeFn", 200)],
                classes: vec![crate::types::ClassInfo {
                    name: "Owner".to_string(),
                    bases: vec![],
                    docstring: None,
                    methods: vec![FunctionInfo {
                        name: "getAddress".to_string(),
                        params: vec![],
                        return_type: None,
                        docstring: None,
                        is_method: true,
                        is_async: false,
                        decorators: vec![],
                        visibility: None,
                        line_number: 69,
                        line_end: 70,
                        state_mutability: None,
                    }],
                    fields: vec![],
                    decorators: vec![],
                    line_number: 60,
                    line_end: 90,
                    kind: None,
                    modifiers: Vec::new(),
                    events: Vec::new(),
                    errors: Vec::new(),
                }],
                constants: vec![],
                call_graph: IntraFileCallGraph::default(),
                modifiers: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
            },
        )];
        let funcs = collect_all_functions(&modules);
        let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
        // The bare `getAddress` double-emit is dropped; only `Owner.getAddress` remains.
        assert!(
            names.contains(&"Owner.getAddress"),
            "qualified method must be present; got {:?}",
            names
        );
        assert!(
            !names.contains(&"getAddress"),
            "bare double-emit of getAddress must be deduped; got {:?}",
            names
        );
        // The genuine free function (different line) is preserved.
        assert!(
            names.contains(&"freeFn"),
            "a genuine free function at a different line must be kept; got {:?}",
            names
        );
    }

    /// Blank-named ghosts (unresolved C++ lambdas / trailing-return decls) are
    /// never reported as dead.
    #[test]
    fn test_blank_named_functions_skipped() {
        use crate::types::Language;
        let modules = module_with_class(
            "g.cpp",
            Language::Cpp,
            "Fmt",
            None,
            vec![
                method("", None, vec![]),         // nameless lambda ghost
                method("realMethod", None, vec![]),
            ],
        );
        let funcs = collect_all_functions(&modules);
        let report = dead_code_analysis_refcount(&funcs, &HashMap::new(), None).unwrap();
        let flagged: Vec<String> = report
            .possibly_dead
            .iter()
            .chain(report.dead_functions.iter())
            .map(|f| f.name.clone())
            .collect();
        assert!(
            !flagged.iter().any(|n| n.rsplit('.').next().unwrap_or("").is_empty()),
            "no blank-named entity may be flagged dead; got {:?}",
            flagged
        );
        // The real method is still analyzed.
        assert!(flagged.contains(&"Fmt.realMethod".to_string()));
    }
}
