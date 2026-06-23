//! fix-R7-reaching-defs-v1 (v0.5.0 CLOSEOUT): characterization tests for the
//! reaching-defs identifier use-context classifier (RC1) and missing-definition
//! extraction (RC2).
//!
//! ROOT CAUSE (RC1): the generic-fallback classifier `parent_use_context`
//! (dfg/extractor.rs) only suppressed LHS/declaration/parameter positions. For
//! the ten languages WITHOUT a bespoke `is_use_context` block (C, C++, Go, Rust,
//! Python, Kotlin, Swift, OCaml, Elixir, PHP) it never excluded callee positions
//! (`call_expression.function`), member/attribute NAME fields (`a.b -> b`),
//! type/constructor names, language builtins, or the `as` keyword. Those
//! identifiers entered reaching-defs as variable Uses with no Definition and were
//! reported `definite uninitialized`.
//!
//! ROOT CAUSE (RC2): several binding forms were never recorded as Definitions:
//! C#/Java for-init declarators, Ruby block params, Lua/Luau upvalues+generic-for,
//! C++ params, Scala compound-assign — so their uses looked uninitialized.
//!
//! Each test asserts on the actual DFG `refs` (the classifier output) or on the
//! `uninitialized` report — the genuine signal — NOT on log text.

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
// RC1 — callee positions must NOT be recorded as variable uses
// =============================================================================

#[test]
fn c_callees_and_macros_not_uninitialized() {
    // C c-sds sdsMakeRoomFor shape: callees sdsavail/sdslen/sdsHdrSize and the
    // macro SDS_TYPE_MASK must not be flagged.
    let src = r#"
typedef char *sds;
sds make(sds s, unsigned long addlen) {
    void *sh;
    unsigned long avail = sdsavail(s);
    unsigned long len, newlen;
    char oldtype = s[0] & SDS_TYPE_MASK;
    len = sdslen(s);
    sh = (char*)s - sdsHdrSize(oldtype);
    newlen = (len + addlen);
    memcpy(sh, s, len);
    return s;
}
"#;
    let uses = use_names(src, "make", Language::C);
    for callee in ["sdsavail", "sdslen", "sdsHdrSize", "memcpy"] {
        assert!(
            !uses.contains(callee),
            "C callee `{callee}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "make", Language::C);
    for callee in ["sdsavail", "sdslen", "sdsHdrSize", "memcpy", "SDS_TYPE_MASK"] {
        assert!(
            !uninit.contains(&callee.to_string()),
            "C `{callee}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn go_builtins_and_callees_not_uninitialized() {
    // Go go-gin cleanPath shape: make/len/string builtins, stackBufSize const,
    // bufApp callee.
    let src = r#"
package p

const stackBufSize = 128

func bufApp(buf *[]byte, s string, w int, c byte) {
}

func cleanPath(p string) string {
    if p == "" {
        return "/"
    }
    n := len(p)
    buf := make([]byte, 0, stackBufSize)
    out := string(buf)
    bufApp(&buf, p, n, '/')
    return out
}
"#;
    let uses = use_names(src, "cleanPath", Language::Go);
    for callee in ["make", "len", "string", "bufApp"] {
        assert!(
            !uses.contains(callee),
            "Go callee/builtin `{callee}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "cleanPath", Language::Go);
    for name in ["make", "len", "string", "bufApp", "stackBufSize"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Go `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn rust_variants_types_assoc_fns_closures_not_uninitialized() {
    // Rust ripgrep parse_human_readable_size shape: Ok/Err variants,
    // ParseSizeError type, format/parse assoc fns, closure params b/e.
    let src = r#"
struct ParseSizeError;
impl ParseSizeError {
    fn format(s: &str) -> ParseSizeError { ParseSizeError }
}
pub fn parse_human_readable_size(size: &str) -> Result<u64, ParseSizeError> {
    let digits: String = size.chars().take_while(|&b| b.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(ParseSizeError::format(size));
    }
    let value: u64 = digits.parse().map_err(|e| ParseSizeError::format(size))?;
    Ok(value)
}
"#;
    let uses = use_names(src, "parse_human_readable_size", Language::Rust);
    // Callees / enum variants / type / assoc-fn names are NEVER variable uses.
    for name in ["Ok", "Err", "ParseSizeError", "format", "parse"] {
        assert!(
            !uses.contains(name),
            "Rust `{name}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "parse_human_readable_size", Language::Rust);
    // None of the callees/types/closure-params may be flagged uninitialized.
    // (`b`/`e` ARE genuine reads inside the closure body, but they are closure
    // PARAMETERS — initialized by the closure invocation — so never uninit.)
    for name in ["Ok", "Err", "ParseSizeError", "format", "parse", "b", "e"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Rust `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
    // `size` IS a genuine parameter use — must still be tracked (not over-suppressed).
    assert!(
        uses.contains("size"),
        "Rust genuine param use `size` was dropped; uses={uses:?}"
    );
    // The closure body read of `b` IS a use (precision preserved), just not uninit.
    assert!(
        uses.contains("b"),
        "Rust closure-body read `b` was dropped; uses={uses:?}"
    );
}

#[test]
fn python_attrs_imports_builtins_callees_not_uninitialized() {
    // Python requests should_bypass_proxies shape (outer scope): attribute names
    // (replace/split/lstrip/endswith), imports (urlparse), builtins, callees.
    let src = r#"
import os
from urllib.parse import urlparse

def should_bypass_proxies(url, no_proxy):
    parsed = urlparse(url)
    hostname = parsed.hostname
    cleaned = no_proxy.replace(" ", "").split(",")
    host = cleaned[0].lstrip(".")
    if hostname.endswith(host):
        return True
    return False
"#;
    let uses = use_names(src, "should_bypass_proxies", Language::Python);
    // Attribute/method NAMES on the rhs of `a.b` and the import `urlparse` are
    // never variable uses. (`hostname` is EXCLUDED from this list: although it
    // appears as the attribute `parsed.hostname`, there is ALSO a genuine local
    // `hostname = parsed.hostname` whose later reads ARE uses.)
    for name in ["urlparse", "replace", "split", "lstrip", "endswith"] {
        assert!(
            !uses.contains(name),
            "Python `{name}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "should_bypass_proxies", Language::Python);
    for name in ["urlparse", "replace", "split", "lstrip", "endswith", "os"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Python `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
    // Genuine receiver / local uses must remain (precision preserved).
    for name in ["no_proxy", "parsed", "hostname"] {
        assert!(
            uses.contains(name),
            "Python genuine use `{name}` was dropped; uses={uses:?}"
        );
    }
}

#[test]
fn python_comprehension_target_is_defined() {
    // `host for host in items` — the comprehension binding `host` is a
    // definition, so the body read must not be flagged.
    let src = r#"
def f(items):
    hosts = [h for h in items if h]
    return hosts
"#;
    let uninit = uninit_names(src, "f", Language::Python);
    assert!(
        !uninit.contains(&"h".to_string()),
        "Python comprehension target `h` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn python_nested_function_name_and_params_not_uninitialized() {
    // requests should_bypass_proxies shape: a nested `def get_proxy(key)`
    // called from the outer body. The nested function NAME (callee) and its
    // PARAM `key` (read in the nested body) must not be flagged.
    let src = r#"
import os
def should_bypass_proxies(url, no_proxy):
    def get_proxy(key):
        return os.environ.get(key) or os.environ.get(key.upper())
    if no_proxy is None:
        no_proxy = get_proxy("no_proxy")
    return no_proxy
"#;
    let uninit = uninit_names(src, "should_bypass_proxies", Language::Python);
    for name in ["get_proxy", "key"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Python nested-fn `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn python_lambda_param_not_uninitialized() {
    // A lambda parameter read in the lambda body must not be flagged.
    let src = r#"
def f(items):
    g = sorted(items, key=lambda kv: kv[1])
    return g
"#;
    let uninit = uninit_names(src, "f", Language::Python);
    assert!(
        !uninit.contains(&"kv".to_string()),
        "Python lambda param `kv` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn cpp_callee_and_param_not_uninitialized() {
    // C++ tinyxml2 GetCharacterRef shape: callee strchr + param p.
    let src = r#"
const char* GetCharacterRef(const char* p, char* value, int* length) {
    if (p == 0) return 0;
    const char* found = strchr(p, ';');
    *length = 1;
    return found;
}
"#;
    let uses = use_names(src, "GetCharacterRef", Language::Cpp);
    assert!(
        !uses.contains("strchr"),
        "C++ callee `strchr` wrongly recorded as use; uses={uses:?}"
    );
    let defs = def_names(src, "GetCharacterRef", Language::Cpp);
    assert!(
        defs.contains("p"),
        "C++ parameter `p` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "GetCharacterRef", Language::Cpp);
    for name in ["strchr", "p"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "C++ `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn kotlin_ctor_and_callee_not_uninitialized() {
    // Kotlin datetime multiplyAndDivide shape: ctor DivRemResult + callee.
    let src = r#"
class DivRemResult(val q: Long, val r: Long)
fun safeMultiplyOrZero(a: Long, b: Long): Long { return a * b }
fun multiplyAndDivide(c: Long, d: Long, e: Long): DivRemResult {
    val p = safeMultiplyOrZero(c, d)
    return DivRemResult(p, e)
}
"#;
    let uses = use_names(src, "multiplyAndDivide", Language::Kotlin);
    for name in ["DivRemResult", "safeMultiplyOrZero"] {
        assert!(
            !uses.contains(name),
            "Kotlin `{name}` wrongly recorded as a variable use; uses={uses:?}"
        );
    }
    let uninit = uninit_names(src, "multiplyAndDivide", Language::Kotlin);
    for name in ["DivRemResult", "safeMultiplyOrZero"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Kotlin `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

// =============================================================================
// RC2 — missing Definition extraction
// =============================================================================

#[test]
fn csharp_for_init_declarator_is_defined() {
    // C# newtonsoft ToSeparatedCase shape: `for (int i = 0; ...)` — the for-init
    // declarator `i` must be recorded as a definition.
    let src = r#"
class C {
    string ToSeparatedCase(string s, char separator) {
        var sb = "";
        for (int i = 0; i < s.Length; i++) {
            sb += s[i];
        }
        return sb;
    }
}
"#;
    let defs = def_names(src, "ToSeparatedCase", Language::CSharp);
    assert!(
        defs.contains("i"),
        "C# for-init `i` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "ToSeparatedCase", Language::CSharp);
    assert!(
        !uninit.contains(&"i".to_string()),
        "C# for-init `i` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn java_for_init_declarator_is_defined() {
    let src = r#"
class C {
    int sum(int[] xs) {
        int total = 0;
        for (int i = 0; i < xs.length; i++) {
            total += xs[i];
        }
        return total;
    }
}
"#;
    let defs = def_names(src, "sum", Language::Java);
    assert!(
        defs.contains("i"),
        "Java for-init `i` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "sum", Language::Java);
    assert!(
        !uninit.contains(&"i".to_string()),
        "Java for-init `i` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn ruby_block_params_are_defined() {
    // Ruby block params `do |k, v|` must be recorded as definitions.
    let src = r#"
def process(hash)
  hash.each do |k, v|
    puts k
    puts v
  end
end
"#;
    let defs = def_names(src, "process", Language::Ruby);
    for name in ["k", "v"] {
        assert!(
            defs.contains(name),
            "Ruby block param `{name}` not recorded as a definition; defs={defs:?}"
        );
    }
    let uninit = uninit_names(src, "process", Language::Ruby);
    for name in ["k", "v"] {
        assert!(
            !uninit.contains(&name.to_string()),
            "Ruby block param `{name}` wrongly flagged uninitialized; uninit={uninit:?}"
        );
    }
}

#[test]
fn scala_compound_assign_is_defined() {
    // Scala ArrayStack unsafeSet shape: `i += 1` must register `i` as a def/update.
    let src = r#"
class ArrayStack {
  def unsafeSet(a: Int): Unit = {
    var i = 0
    i += 1
    val index = i
  }
}
"#;
    let defs = def_names(src, "unsafeSet", Language::Scala);
    assert!(
        defs.contains("i"),
        "Scala compound-assign `i` not recorded as a definition; defs={defs:?}"
    );
    let uninit = uninit_names(src, "unsafeSet", Language::Scala);
    assert!(
        !uninit.contains(&"i".to_string()),
        "Scala `i` wrongly flagged uninitialized; uninit={uninit:?}"
    );
}

#[test]
fn lua_generic_for_vars_are_defined() {
    // Lua generic-for: `for k, v in pairs(t)` — loop vars must be definitions.
    let src = r#"
local function process(t)
    for k, v in pairs(t) do
        print(k)
        print(v)
    end
end
"#;
    let defs = def_names(src, "process", Language::Lua);
    for name in ["k", "v"] {
        assert!(
            defs.contains(name),
            "Lua generic-for var `{name}` not recorded as a definition; defs={defs:?}"
        );
    }
}
