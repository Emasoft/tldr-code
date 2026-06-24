//! fix-R2-themeC (v0.5.0 CLOSEOUT): characterization tests for the RESIDUAL
//! reaching-defs false positives left open after the R7 wave-1 commit
//! (`a496687`). The dominant ~18/22 reaching-defs FPs were closed there; this
//! file completes the same allow-list / missing-definition pattern for the
//! eight residual identifier classes documented in cluster 0 of
//! `reverify-results.json`:
//!
//! RC1 — use-context allow-list (identifier is NOT a variable, must not be a Use):
//!   1. Kotlin INFIX operators        (`r3 shl 32`, `... or r4`, `127 downTo 0`)
//!   2. C# `#if` preprocessor symbols (`#if HAVE_CHAR_TO_LOWER_WITH_CULTURE`)
//!   3. JS implicit `arguments` object
//!
//! RC2 — missing Definition extraction (the binding's DEF was never recorded):
//!   4. Elixir param-with-default (`opts \\ []`) + case-pattern binding (`{:ok, cb} ->`)
//!   5. C# `out` params + class fields
//!   6. Solidity language globals (`msg`/`block`/`tx`/`now`/`this`) — suppressed as builtins
//!   7. Go function-LOCAL `const` declaration
//!   8. PHP `static $var = ...;` statement-level static var
//!
//! Each test asserts on the genuine signal: either the DFG `refs` (the
//! classifier output) or the end-to-end `uninitialized` report — never log text.

use std::collections::HashSet;
use tldr_core::dfg::get_dfg_context;
use tldr_core::dfg::reaching::build_reaching_defs_report;
use tldr_core::types::{Language, RefType};

/// Names recorded as variable USES by the classifier for `function_name`.
fn use_names(source: &str, function_name: &str, lang: Language) -> HashSet<String> {
    let dfg = get_dfg_context(source, function_name, lang)
        .unwrap_or_else(|e| panic!("get_dfg_context failed for {function_name}: {e:?}"));
    dfg.refs
        .iter()
        .filter(|r| matches!(r.ref_type, RefType::Use))
        .map(|r| r.name.clone())
        .collect()
}

/// Names recorded as DEFINITIONS (or updates) by the classifier.
fn def_names(source: &str, function_name: &str, lang: Language) -> HashSet<String> {
    let dfg = get_dfg_context(source, function_name, lang)
        .unwrap_or_else(|e| panic!("get_dfg_context failed for {function_name}: {e:?}"));
    dfg.refs
        .iter()
        .filter(|r| matches!(r.ref_type, RefType::Definition | RefType::Update))
        .map(|r| r.name.clone())
        .collect()
}

/// End-to-end uninitialized-variable names reported for `function_name`, using
/// the SAME path the CLI uses (CFG + auto-detected params + safety net).
fn uninit_names(source: &str, function_name: &str, lang: Language) -> Vec<String> {
    let dfg = get_dfg_context(source, function_name, lang)
        .unwrap_or_else(|e| panic!("get_dfg_context failed for {function_name}: {e:?}"));
    let cfg = tldr_core::cfg::get_cfg_context(source, function_name, lang)
        .unwrap_or_else(|e| panic!("get_cfg_context failed for {function_name}: {e:?}"));
    let report = build_reaching_defs_report(&cfg, &dfg.refs, std::path::PathBuf::from("test"));
    report.uninitialized.iter().map(|u| u.var.clone()).collect()
}

// =============================================================================
// RC1 — use-context allow-list
// =============================================================================

#[test]
fn kotlin_infix_operators_not_uninitialized() {
    // kotlin-datetime math.kt multiplyAndDivide shape: `shl`/`or`/`downTo` are
    // infix-FUNCTION callees, never variables. They parse as bare `identifier`
    // children of `infix_expression` in the operator slot.
    let src = r#"
fun multiplyAndDivide(r3: Long, r4: Long): Long {
    val high = r3 shl 32 or r4
    val low = r4 shr 8 and r3 xor r4 ushr 2
    var acc = 0L
    for (i in 127 downTo 0) { acc = acc + i }
    for (j in 0 until 10 step 2) { acc = acc + j }
    return high + low + acc
}
"#;
    let uses = use_names(src, "multiplyAndDivide", Language::Kotlin);
    for op in ["shl", "or", "shr", "and", "xor", "ushr", "downTo", "until", "step"] {
        assert!(
            !uses.contains(op),
            "Kotlin infix operator `{op}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "multiplyAndDivide", Language::Kotlin);
    for op in ["shl", "or", "shr", "and", "xor", "ushr", "downTo", "until", "step"] {
        assert!(
            !uninit.contains(&op.to_string()),
            "Kotlin infix operator `{op}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn csharp_preproc_if_symbol_not_uninitialized() {
    // csharp-newtonsoft-json StringUtils.cs ToSeparatedCase shape: the `#if`
    // condition symbol is a compile-time preprocessor name, never a variable.
    let src = r#"
class StringUtils {
    string ToSeparatedCase(string s) {
#if HAVE_CHAR_TO_LOWER_WITH_CULTURE
        var y = s;
#endif
        return s;
    }
}
"#;
    let uses = use_names(src, "ToSeparatedCase", Language::CSharp);
    assert!(
        !uses.contains("HAVE_CHAR_TO_LOWER_WITH_CULTURE"),
        "C# `#if` symbol wrongly recorded as a variable use; uses={uses:?}"
    );
    let uninit = uninit_names(src, "ToSeparatedCase", Language::CSharp);
    assert!(
        !uninit.contains(&"HAVE_CHAR_TO_LOWER_WITH_CULTURE".to_string()),
        "C# `#if` symbol wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn js_arguments_object_not_uninitialized() {
    // js-lodash _baseConvert.js flatSpread shape: `arguments` is the implicit
    // function-local arguments object, always present, never a free variable.
    let src = r#"
function flatSpread(fn) {
    var len = arguments.length;
    return fn(arguments[0], len);
}
"#;
    let uses = use_names(src, "flatSpread", Language::JavaScript);
    assert!(
        !uses.contains("arguments"),
        "JS `arguments` wrongly recorded as a variable use; uses={uses:?}"
    );
    let uninit = uninit_names(src, "flatSpread", Language::JavaScript);
    assert!(
        !uninit.contains(&"arguments".to_string()),
        "JS `arguments` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

// =============================================================================
// RC2 — missing Definition extraction
// =============================================================================

#[test]
fn elixir_param_default_is_defined() {
    // elixir-phoenix controller.ex allow_jsonp shape: `opts \\ []` is a
    // param-with-default; the `opts` binding must be recorded as a definition.
    let src = r#"
def allow_jsonp(conn, opts \\ []) do
  callback = Keyword.get(opts, :callback)
  process(conn, callback, opts)
end
"#;
    let defs = def_names(src, "allow_jsonp", Language::Elixir);
    assert!(
        defs.contains("opts"),
        "Elixir param-default `opts` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "allow_jsonp", Language::Elixir);
    assert!(
        !uninit.contains(&"opts".to_string()),
        "Elixir param-default `opts` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn elixir_case_pattern_binding_is_defined() {
    // elixir-phoenix controller.ex allow_jsonp shape: `{:ok, cb} ->` binds `cb`
    // in the case clause pattern; reads of `cb` in the clause body must resolve.
    let src = r#"
def handle(conn) do
  case fetch(conn) do
    {:ok, cb} ->
      apply(cb, [])
      log(cb)
    :error ->
      conn
  end
end
"#;
    let defs = def_names(src, "handle", Language::Elixir);
    assert!(
        defs.contains("cb"),
        "Elixir case-pattern binding `cb` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "handle", Language::Elixir);
    assert!(
        !uninit.contains(&"cb".to_string()),
        "Elixir case-pattern binding `cb` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn csharp_out_param_is_defined() {
    // csharp-newtonsoft-bson DateTimeParser.cs ParseTime shape: `out int Hour`
    // is an out-parameter; the `Hour` binding must be recorded as a definition.
    let src = r#"
class DateTimeParser {
    bool ParseTime(out int Hour, out int Minute, out int Second) {
        Hour = ReadDigits();
        Minute = ReadDigits();
        Second = ReadDigits();
        return true;
    }
}
"#;
    let defs = def_names(src, "ParseTime", Language::CSharp);
    for name in ["Hour", "Minute", "Second"] {
        assert!(
            defs.contains(name),
            "C# out-param `{name}` not recorded as a definition; defs={defs:?}"
        );
    }
    let uninit = uninit_names(src, "ParseTime", Language::CSharp);
    for name in ["Hour", "Minute", "Second"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "C# out-param `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn csharp_class_field_read_not_uninitialized() {
    // csharp-newtonsoft-bson DateTimeParser.cs shape: a bare value read of a
    // class field (`Power10`, `MaxFractionDigits`, `_end`) inside a method is
    // not a local-variable use — the field is declared at class scope.
    // All field reads are placed in return / argument positions (which the C#
    // extractor recurses into), so this genuinely exercises the field-name
    // suppression rather than relying on any unrelated initializer gap.
    let src = r#"
class DateTimeParser {
    static int[] Power10 = new int[] { 1, 10, 100 };
    static int MaxFractionDigits = 7;
    int _end;

    int ParseFraction(int digits) {
        return System.Math.Min(MaxFractionDigits, digits) + Power10[digits] + _end;
    }
}
"#;
    let uninit = uninit_names(src, "ParseFraction", Language::CSharp);
    for name in ["Power10", "MaxFractionDigits", "_end"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "C# class field `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn solidity_language_globals_not_uninitialized() {
    // solidity-solmate ERC20.sol transferFrom shape: `msg`/`block`/`tx` are
    // language-level globals, never local variables. Suppress as builtins.
    let src = r#"
contract ERC20 {
    function transferFrom(address from, uint256 amount) public returns (bool) {
        address spender = msg.sender;
        uint256 t = block.timestamp;
        require(tx.origin == from);
        return spender != from && t > 0 && amount > 0;
    }
}
"#;
    let uninit = uninit_names(src, "transferFrom", Language::Solidity);
    for name in ["msg", "block", "tx"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Solidity global `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn go_function_local_const_is_defined() {
    // go-httprouter path.go CleanPath shape: a `const` declared INSIDE the
    // function body is a genuine local; its reads must resolve to the const def.
    let src = r#"
package p

func CleanPath(path string) string {
    const stackBufSize = 128
    buf := make([]byte, stackBufSize)
    n := stackBufSize + len(path)
    return string(buf[:n])
}
"#;
    let defs = def_names(src, "CleanPath", Language::Go);
    assert!(
        defs.contains("stackBufSize"),
        "Go function-local const `stackBufSize` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "CleanPath", Language::Go);
    assert!(
        !uninit.contains(&"stackBufSize".to_string()),
        "Go function-local const `stackBufSize` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn php_static_var_is_defined() {
    // php-symfony-console Helper.php formatTime shape: `static $timeFormats =
    // [...]` is a statement-level static var declaration; its reads must resolve.
    let src = r#"
<?php
function formatTime($secs) {
    static $timeFormats = [1, 2, 3];
    $result = 0;
    foreach ($timeFormats as $f) {
        $result += $f;
    }
    return $result + count($timeFormats);
}
"#;
    let defs = def_names(src, "formatTime", Language::Php);
    assert!(
        defs.contains("timeFormats") || defs.contains("$timeFormats"),
        "PHP static var `timeFormats` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "formatTime", Language::Php);
    for name in ["timeFormats", "$timeFormats"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "PHP static var `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

// =============================================================================
// BLAST-RADIUS GUARDS — broadening C#/Java file-level-name suppression must NOT
// (a) drop reads of a genuine local that shadows a field/method name, nor
// (b) silence a real uninitialized-variable TRUE POSITIVE.
// =============================================================================

#[test]
fn csharp_local_shadowing_field_name_is_used_not_suppressed() {
    // SHADOW GUARD for the broadened C#/Java file-level-name suppression: a
    // `foreach` binder (`item`) named the SAME as a class field MUST keep its
    // reads. We read the binder in ARGUMENT position (`WriteLine(item)`), which
    // reaches `is_use_context`; if the broadening dropped it (because the field
    // `item` is in the file-level name set), this read would vanish. The
    // `collect_generic_local_names` foreach arm puts `item` in the shadow guard,
    // so it survives.
    let src = r#"
class C {
    int item;
    void M(System.Collections.Generic.List<int> items) {
        foreach (var item in items) {
            System.Console.WriteLine(item);
        }
    }
}
"#;
    // The in-scope assertion: the broadening must NOT drop the read of a local
    // that shadows a field name. (A C# foreach binder's first-iteration uninit
    // status is separate, pre-existing RC4/CFG-modeling behavior — deferred —
    // and is identical with or without a field collision, so we do not assert on
    // it here.)
    let uses = use_names(src, "M", Language::CSharp);
    assert!(
        uses.contains("item"),
        "C# local `item` (shadowing field) wrongly suppressed; its reads must survive; uses={uses:?}"
    );
}

#[test]
fn csharp_method_named_like_field_use_still_classified() {
    // SHADOW GUARD: a genuine local parameter read in argument position must
    // survive the broadening. `amount` is a parameter (a real local); its read
    // inside `Math.Max(amount, 0)` must be recorded as a USE — the broadening
    // only suppresses names that are NOT in the local set.
    let src = r#"
class C {
    int Max;
    int M(int amount) {
        return System.Math.Max(amount, 0);
    }
}
"#;
    let uses = use_names(src, "M", Language::CSharp);
    assert!(
        uses.contains("amount"),
        "C# parameter `amount` read wrongly suppressed; uses={uses:?}"
    );
    let uninit = uninit_names(src, "M", Language::CSharp);
    assert!(
        !uninit.contains(&"amount".to_string()),
        "C# parameter `amount` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn go_local_const_shadowing_does_not_over_suppress() {
    // SHADOW GUARD for the Go function-local const: a real local read in
    // argument position must survive. `k` is the local const (resolves), and a
    // genuine parameter `p` read inside the call must remain a USE.
    let src = r#"
package p
func F(p int) int {
    const k = 10
    return add(p, k)
}
func add(a int, b int) int { return a + b }
"#;
    let uninit = uninit_names(src, "F", Language::Go);
    assert!(
        !uninit.contains(&"k".to_string()),
        "Go local const `k` wrongly flagged uninitialized; uninit={uninit:?}"
    );
    let uses = use_names(src, "F", Language::Go);
    assert!(
        uses.contains("p"),
        "Go parameter `p` read wrongly suppressed; uses={uses:?}"
    );
}
